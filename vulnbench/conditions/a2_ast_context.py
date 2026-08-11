"""A2 — AST-augmented context. The model reads a parsed AST instead of raw source.

Structural augmentation: a flat token stream hides syntactic boundaries
— block scope, call vs. declaration, conditional nesting —
that a parsed AST makes explicit. This condition swaps B3's raw-file prompt for
the file's AST rendered as compact indented text (:func:`ast_support.render_ast`)
and otherwise runs the same flat per-file pass as B3, so any difference in the
scorecard is attributable to the AST swap alone.

A file whose language has no tree-sitter grammar available (extension unmapped,
or the ``structural`` extra isn't installed) falls back to raw source rather than
being skipped, and the fallback is counted in ``trace["ast_fallback_files"]`` —
an observable limitation, not a silent gap in the run.
"""

from __future__ import annotations

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


class A2ASTContext(Condition):
    id = "A2"
    label = "AST-augmented context"
    needs_model = True
    needs_source = True
    knobs = SCAN_KNOBS + SAMPLE_KNOBS + (
        Knob("ast_max_bytes", "int", 60_000,
             help="truncate each file's rendered AST text past this many characters"),
    )

    def run(self, target: Target, ctx: ConditionContext) -> ConditionResult:
        assert ctx.model is not None
        max_files = int(self.cfg(ctx, "max_files")) or None
        max_bytes = int(self.cfg(ctx, "max_file_bytes"))
        ast_max_chars = int(self.cfg(ctx, "ast_max_bytes"))

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
                path, code, ast_max_chars
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
                # Pin the location to the file we actually scanned.
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
                "ast_fallback_files": len(fallback),
                "ast_max_bytes": ast_max_chars,
            },
            # Score only over what we actually looked at (respects max_files).
            scored_cases=scored_cases or None,
        )

    def _structural_view(
        self, path: str, code: str, max_chars: int
    ) -> tuple[str, bool, bool]:
        """The AST text for ``path``, or raw ``code`` if it can't be parsed.

        Returns ``(text, truncated, used_fallback)``. Split out from :meth:`run`
        so a test can monkeypatch :mod:`ast_support` without touching the loop.
        """
        tree = ast_support.parse_tree(path, code)
        if tree is None:
            truncated = len(code) > max_chars
            return (code[:max_chars] if truncated else code), truncated, True
        text, truncated = ast_support.render_ast(tree, max_chars)
        return text, truncated, False


def _user_prompt(path: str, body: str, used_fallback: bool) -> str:
    if used_fallback:
        kind = "raw source (no AST parser is available for this file type)"
    else:
        kind = (
            "abstract syntax tree — one line per AST node as `type [Lline]`, "
            "indented by nesting depth, not the plain source text"
        )
    return (
        f"Analyze this source file for security vulnerabilities. You are shown its "
        f"{kind}.\n\nFile: {path}\n```\n{body}\n```\n\n{OUTPUT_CONTRACT}"
    )
