"""A3 — CFG/DFG-augmented context. The model reads a control-/data-flow sketch
instead of raw source.

Structural augmentation: an AST still spells out every token;
a control-flow graph collapses straight-line code into blocks and
makes branching/looping explicit as edges, and a data-flow list
makes "where did this variable come from" explicit as def/use pairs.

It is built with one AST walk per function using tree-sitter's field names
(``condition`` / ``consequence`` / ``alternative`` / ``body``
shared across the official grammars this module targets), not points-to or alias analysis:

- **CFG**: basic blocks split at ``if``/loop/``try`` boundaries, edges labeled
  ``true``/``false``/``loop``/``back``/``catch``. ``switch``/``case`` collapses to
  one block (branching there is rarer in the CWE classes this benchmark scores).
- **DFG**: every ``identifier`` node is one def-or-use event, name-based and
  intra-procedural — a def site is a variable/parameter *declaration* target or an
  assignment's left-hand side; everything else (including a called method's own
  name) counts as a use. No scope/shadowing resolution: two variables named ``x``
  in different blocks share one entry.

"""

from __future__ import annotations

from typing import Any

from ..corpus import Target
from ..models import Usage
from ..schema import Finding, Location, benchmark_case_of
from . import ast_support
from .base import Condition, ConditionContext, ConditionResult, Knob
from .llm_common import OUTPUT_CONTRACT, SYSTEM_PROMPT, parse_findings
from .source_files import (
    SAMPLE_KNOBS,
    SCAN_KNOBS,
    iter_source_files,
    read_capped,
    sampled_paths_for,
)

_FUNC_TYPES = {
    "method_declaration", "constructor_declaration",   # java
    "function_declaration", "function_definition",     # python / js / ts / php / go
    "method_definition", "method",                      # js / ts / ruby
}
_LOOP_TYPES = {
    "for_statement", "while_statement", "do_statement",
    "enhanced_for_statement", "for_in_statement", "foreach_statement",
}
_BLOCK_TYPES = {"block", "compound_statement", "statement_block"}
_DEF_PARENT_TYPES = {"variable_declarator", "formal_parameter", "catch_formal_parameter"}


class A3CFGDFGContext(Condition):
    id = "A3"
    label = "CFG/DFG-augmented context"
    needs_model = True
    needs_source = True
    knobs = SCAN_KNOBS + SAMPLE_KNOBS + (
        Knob("cfg_max_bytes", "int", 60_000,
             help="truncate each file's rendered CFG/DFG text past this many characters"),
    )

    def run(self, target: Target, ctx: ConditionContext) -> ConditionResult:
        assert ctx.model is not None
        max_files = int(self.cfg(ctx, "max_files")) or None
        max_bytes = int(self.cfg(ctx, "max_file_bytes"))
        cfg_max_chars = int(self.cfg(ctx, "cfg_max_bytes"))
        # --sample overrides max_files: the smoke slice *is* the file set.
        paths = sampled_paths_for(self, ctx, target.source_path)
        if paths is None:
            paths = iter_source_files(target.source_path, max_files)

        findings: list[Finding] = []
        usage = Usage()
        scanned = 0
        truncated: list[str] = []
        fallback: list[str] = []
        scored_cases: set[str] = set()
        for path in paths:
            tc = benchmark_case_of(path)
            if tc is not None:
                scored_cases.add(tc)  # in scope even if the model finds nothing in it
            code, _ = read_capped(path, max_bytes)
            if not code:
                continue

            body, was_truncated, used_fallback = self._structural_view(
                path, code, cfg_max_chars
            )
            if was_truncated:
                truncated.append(path)
            if used_fallback:
                fallback.append(path)

            messages = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": _user_prompt(path, body, used_fallback)},
            ]
            completion = ctx.model.complete(messages)
            usage = usage + completion.usage
            for f in parse_findings(completion.text, self.id):
                if f.location.file is None:
                    f.location = Location.source(file=path, line=f.location.line)
                findings.append(f)
            scanned += 1

        return ConditionResult(
            findings=findings,
            usage=usage,
            trace={
                "files_scanned": scanned,
                "model": ctx.model.name,
                "truncated_files": len(truncated),
                "cfg_fallback_files": len(fallback),
                "cfg_max_bytes": cfg_max_chars,
            },
            scored_cases=scored_cases or None,
        )

    def _structural_view(
        self, path: str, code: str, max_chars: int
    ) -> tuple[str, bool, bool]:
        """The CFG/DFG text for ``path``, or raw ``code`` if it can't be parsed.

        Returns ``(text, truncated, used_fallback)``. A tree that parses but
        yields no CFG text (e.g. a file with no function-like nodes at all)
        also falls back to raw source
        """
        tree = ast_support.parse_tree(path, code)
        if tree is None:
            truncated = len(code) > max_chars
            return (code[:max_chars] if truncated else code), truncated, True
        text, truncated = build_cfg_dfg(tree, max_chars)
        if not text:
            truncated = len(code) > max_chars
            return (code[:max_chars] if truncated else code), truncated, True
        return text, truncated, False


def _user_prompt(path: str, body: str, used_fallback: bool) -> str:
    if used_fallback:
        kind = "raw source (no control-/data-flow sketch is available for this file)"
    else:
        kind = (
            "control-flow graph (blocks + branch/loop/catch edges) and a data-flow "
            "def/use list, one per function — not the plain source text"
        )
    return (
        f"Analyze this source file for security vulnerabilities. You are shown its "
        f"{kind}.\n\nFile: {path}\n```\n{body}\n```\n\n{OUTPUT_CONTRACT}"
    )


# ---------------------------------------------------------------------------
# CFG/DFG construction
# ---------------------------------------------------------------------------

def build_cfg_dfg(tree: Any, max_chars: int) -> tuple[str, bool]:
    """Render every function-scope CFG + DFG in ``tree`` as one text block.

    A file with no function-like node (a script, a config-style file) falls
    back to treating the whole file as one implicit scope, so top-level code
    still gets a sketch. Returns ``(text, truncated)`` like :func:`ast_support
    .render_ast`.
    """
    scopes = _find_scopes(tree.root_node)
    if not scopes:
        scopes = [("MODULE", tree.root_node)]

    blocks_out: list[str] = []
    for name, scope_node in scopes:
        body_node = scope_node.child_by_field_name("body") or scope_node
        stmts = _statements(body_node)
        builder = _CFGBuilder()
        builder.build_sequence(stmts)
        if not builder.blocks:
            continue  # an empty body has nothing to sketch
        start = scope_node.start_point[0] + 1
        end = scope_node.end_point[0] + 1
        blocks_out.append(f"FUNCTION {name} (L{start}-L{end})")
        for b in builder.blocks:
            blocks_out.append(f"  B{b['id']} [{b['kind']} L{b['line']}] {b['text']}")
        for src, dst, label in builder.edges:
            tag = f" [{label}]" if label else ""
            blocks_out.append(f"  B{src} -> B{dst}{tag}")
        dfg = _render_dfg(scope_node)
        if dfg:
            blocks_out.append("  DFG:")
            blocks_out.extend(f"    {line}" for line in dfg)

    text = "\n".join(blocks_out)
    if len(text) > max_chars:
        return text[:max_chars], True
    return text, False


def _find_scopes(node: Any) -> list[tuple[str, Any]]:
    """Every function-like node in ``node``'s subtree, as ``(name, node)`` pairs."""
    out: list[tuple[str, Any]] = []
    for child in node.children:
        if child.type in _FUNC_TYPES:
            name_node = child.child_by_field_name("name")
            name = name_node.text.decode("utf-8", "replace") if name_node else "<anonymous>"
            out.append((name, child))
        out.extend(_find_scopes(child))
    return out


def _statements(block_node: Any) -> list[Any]:
    """The statement sequence of a body node (unwraps a ``block``/... wrapper)."""
    if block_node.type in _BLOCK_TYPES:
        return list(block_node.named_children)
    return [block_node]


#: Longest block label. Matches ast_support._MAX_LEAF_CHARS so A2 and A3 truncate a
#: statement at the same width, and the two conditions stay comparable on prompt size.
_MAX_BLOCK_CHARS = ast_support._MAX_LEAF_CHARS


def _summary(node: Any) -> str:
    """A short one-line label for a block: the statement's source, flattened.

    Flattened rather than first-line-only: OWASP Benchmark is google-java-formatted,
    so sink calls wrap as a rule, and keeping ``splitlines()[0]`` dropped exactly the
    part that carries the vulnerability — ``println(`` without its argument. Same
    reasoning, and the same treatment, as :func:`ast_support._leaf_text`.
    """
    text = node.text.decode("utf-8", "replace") if node.text else ""
    flat = " ".join(text.split())
    if len(flat) > _MAX_BLOCK_CHARS:
        return flat[:_MAX_BLOCK_CHARS] + "…"
    return flat


class _CFGBuilder:
    """Builds a simplified basic-block CFG from a statement sequence.
    """

    def __init__(self) -> None:
        self.blocks: list[dict] = []
        self.edges: list[tuple[int, int, str]] = []
        self._next_id = 1

    def _new_block(self, kind: str, node: Any) -> int:
        bid = self._next_id
        self._next_id += 1
        self.blocks.append(
            {"id": bid, "kind": kind, "line": node.start_point[0] + 1, "text": _summary(node)}
        )
        return bid

    def _edge(self, src: int | None, dst: int | None, label: str = "") -> None:
        if src is not None and dst is not None:
            self.edges.append((src, dst, label))

    def build_sequence(self, stmts: list[Any]) -> tuple[int | None, list[int]]:
        """Build blocks/edges for a straight-line statement list.

        Returns ``(entry_id, exit_ids)`` — ``entry_id`` is where control enters
        this sequence (``None`` for an empty one), ``exit_ids`` is every block
        control can leave the sequence from (more than one after a branch).
        """
        entry: int | None = None
        prev_exits: list[int] = []
        for stmt in stmts:
            kind = stmt.type
            if kind == "if_statement":
                new_entry, new_exits = self._build_if(stmt)
            elif kind in _LOOP_TYPES:
                new_entry, new_exits = self._build_loop(stmt)
            elif kind == "try_statement":
                new_entry, new_exits = self._build_try(stmt)
            else:
                bid = self._new_block("STMT", stmt)
                new_entry, new_exits = bid, [bid]

            if entry is None:
                entry = new_entry
            for pe in prev_exits:
                self._edge(pe, new_entry)
            prev_exits = new_exits
        return entry, prev_exits

    def _build_if(self, node: Any) -> tuple[int, list[int]]:
        cond_id = self._new_block("IF", node)
        exits: list[int] = []
        consequence = node.child_by_field_name("consequence")
        then_entry, then_exits = (
            self.build_sequence(_statements(consequence)) if consequence else (None, [])
        )
        if then_entry is not None:
            self._edge(cond_id, then_entry, "true")
            exits.extend(then_exits)
        else:
            exits.append(cond_id)  # empty/absent branch falls through as-is

        alternative = node.child_by_field_name("alternative")
        else_entry, else_exits = (
            self.build_sequence(_statements(alternative)) if alternative else (None, [])
        )
        if else_entry is not None:
            self._edge(cond_id, else_entry, "false")
            exits.extend(else_exits)
        else:
            exits.append(cond_id)  # no else: control also falls through on false
        return cond_id, exits

    def _build_loop(self, node: Any) -> tuple[int, list[int]]:
        loop_id = self._new_block("LOOP", node)
        body = node.child_by_field_name("body")
        body_entry, body_exits = self.build_sequence(_statements(body)) if body else (None, [])
        if body_entry is not None:
            self._edge(loop_id, body_entry, "loop")
            for be in body_exits:
                self._edge(be, loop_id, "back")
        return loop_id, [loop_id]  # loop exits when the condition is false

    def _build_try(self, node: Any) -> tuple[int, list[int]]:
        body = node.child_by_field_name("body")
        try_entry, try_exits = self.build_sequence(_statements(body)) if body else (None, [])
        try_id = try_entry if try_entry is not None else self._new_block("TRY", node)
        exits = list(try_exits) if try_entry is not None else [try_id]

        for clause in node.named_children:
            if clause.type != "catch_clause":
                continue
            c_body = clause.child_by_field_name("body")
            c_entry, c_exits = self.build_sequence(_statements(c_body)) if c_body else (None, [])
            cid = c_entry if c_entry is not None else self._new_block("CATCH", clause)
            self._edge(try_id, cid, "catch")
            exits.extend(c_exits if c_entry is not None else [cid])
        return try_id, exits


def _render_dfg(scope_node: Any) -> list[str]:
    """Per-variable def/use line lists for every ``identifier`` in ``scope_node``."""
    by_name: dict[str, dict[str, list[int]]] = {}

    def walk(node: Any) -> None:
        if node.type == "identifier":
            name = node.text.decode("utf-8", "replace") if node.text else ""
            if name:
                entry = by_name.setdefault(name, {"def": [], "use": []})
                line = node.start_point[0] + 1
                bucket = entry["def"] if _is_def_site(node) else entry["use"]
                if line not in bucket:
                    bucket.append(line)
        for child in node.children:
            walk(child)

    walk(scope_node)
    out = []
    for name in sorted(by_name):
        d, u = by_name[name]["def"], by_name[name]["use"]
        d_txt = ",".join(f"L{n}" for n in sorted(d)) or "-"
        u_txt = ",".join(f"L{n}" for n in sorted(u)) or "-"
        out.append(f"{name}: def={d_txt} use={u_txt}")
    return out


def _is_def_site(node: Any) -> bool:
    parent = node.parent
    if parent is None:
        return False
    if parent.type in _DEF_PARENT_TYPES:
        name = parent.child_by_field_name("name")
        return name is not None and name.id == node.id
    if parent.type == "assignment_expression":
        left = parent.child_by_field_name("left")
        return left is not None and left.id == node.id
    return False
