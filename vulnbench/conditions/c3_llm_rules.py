"""C3 — LLM-authored Semgrep rules. The "LLM improves the tool" condition.

Unlike the triage conditions (C1/C2), where the model judges a scanner's output at
scan time, here the model's work is paid **once, offline**: it writes custom Semgrep
YAML rules from example vulnerable code, and then Semgrep runs those rules
deterministically and reproducibly over the scored target. This tests whether an LLM
can make the existing static tool *better* rather than replace it.

Two phases, split exactly like :class:`TriageCondition`'s scan/triage but inverted —
author, then scan:

    rules_out PATH   author rules from ``--source`` and write the YAML to PATH, then
                     stop (phase 1; needs a model).
    rules_in  PATH   load an authored rules file, run Semgrep with it over
                     ``--source`` and score; no model involved (phase 2).

With neither knob, ``run`` authors *and* scans in one pass over the same source. That
is convenient for a smoke test but is textbook benchmark-gaming — the rules are tuned
on the very files they are scored on — so the trace flags it. The honest workflow is
the phased one: author on a tuning split, score on a held-out split::

    # phase 1 — author on the tuning split
    vulnbench run --condition C3 --source tuning/ --model local:... \
        --config '{"rules_out": "rules.yaml"}'
    # phase 2 — score on the held-out split, deterministically, no model
    vulnbench run --condition C3 --source heldout/ --kind benchmark \
        --ground-truth expectedresults-1.2.csv --config '{"rules_in": "rules.yaml"}'
"""

from __future__ import annotations

import os
import tempfile

from ..corpus import Target, TargetKind
from ..models import Usage
from ..scanners import run_semgrep, validate_rules
from ..schema import benchmark_case_of
from ..scoring import benchmark_cases_in_tree
from ..scoring.owasp_benchmark import load_expected_results
from .b3_llm import _iter_source_files, _read
from .base import Condition, ConditionContext, ConditionResult, Knob

#: Keep authored YAML off the prompt budget: a few small examples beat one huge file.
DEFAULT_AUTHOR_FILES = 8
DEFAULT_AUTHOR_BYTES = 4_000

_AUTHOR_SYSTEM = (
    "You are a senior Semgrep rules engineer. You write valid, general Semgrep rules "
    "in YAML that detect classes of security vulnerabilities. Semgrep patterns are "
    "written in the TARGET LANGUAGE'S OWN SYNTAX with metavariables — they are NOT "
    "regular expressions and NOT a procedural script. You output only a valid Semgrep "
    "YAML document and nothing else."
)

# A heavily worked contract: the 8B-class models fail by inventing a procedural DSL
# (let/if/report) and writing regex instead of code-shaped patterns, so we show one
# complete valid rule and explicitly forbid the failure modes we have observed.
_AUTHOR_CONTRACT = """\
Now write a Semgrep ruleset that detects these vulnerability classes. Output ONLY a
valid Semgrep YAML document — no markdown fences, no prose before or after.

HOW SEMGREP PATTERNS WORK (read carefully):
- A `pattern` is a snippet of real code in the target language with holes.
- `$X`, `$SINK`, `$INPUT` are metavariables — they match any single expression and
  bind it; reusing the same name means "the same code".
- `...` (ellipsis) matches any sequence of arguments, statements, or characters.
- `<... X ...>` is the deep-expression operator: it matches when expression X appears
  ANYWHERE inside a larger expression. This is the cleanest way to say "a tainted
  value reaches this sink", e.g. `$STMT.executeQuery(<... $REQ.getParameter(...) ...>)`.
- Patterns are matched against the program's syntax tree, NOT as text/regex.
- Keep each `pattern` to a SINGLE expression or statement. Multi-statement `pattern: |`
  blocks are fragile and often fail to parse — prefer `<... ... ...>` instead.

ALLOWED keys only: id, languages, message, severity, metadata (with `cwe`), and the
pattern operators: pattern, patterns, pattern-either, pattern-inside, pattern-not,
pattern-not-inside, metavariable-pattern.

STRICTLY FORBIDDEN (these are NOT Semgrep and will be rejected):
- Regular expressions inside `pattern` (e.g. `getParameter\\(\\s*"..."\\)`).
- Any procedural/imperative directive: `on-pattern-matches`, `let`, `if`, `report`,
  `return`, assignments, or pseudo-code. Semgrep rules are declarative only.
- `metavariable-regex` unless you genuinely need to constrain a metavariable by regex.

A COMPLETE, VALID EXAMPLE (copy this structure exactly — note the indentation, and how
the sink uses the deep-expression operator so it matches any tainted argument):
rules:
  - id: sql-injection-from-request-param
    languages: [java]
    severity: ERROR
    message: User-controlled request input flows into a SQL query.
    metadata:
      cwe: "CWE-89: Improper Neutralization of Special Elements used in an SQL Command"
    patterns:
      - pattern-either:
          - pattern: $STMT.executeQuery(<... $REQ.getParameter(...) ...>)
          - pattern: $STMT.executeQuery(<... $REQ.getHeader(...) ...>)
          - pattern: $STMT.executeQuery("..." + $P + "...")

REQUIREMENTS:
- Generalize from the examples: match the dangerous data-flow shape (tainted input
  reaching a sink), not one file or one literal variable name.
- Set metadata.cwe to the CORRECT CWE id and its real name — the harness scores on the
  numeric id, so a wrong id scores as a miss. Do not paste an unrelated CWE's text.
- Emit one rule per distinct vulnerability class present in the examples.
- Use single-expression patterns only; never emit a multi-statement `pattern: |` block.
- Re-read your output and ensure it is syntactically valid YAML before finishing."""


class C3LLMRules(Condition):
    id = "C3"
    label = "LLM-authored Semgrep rules (LLM improves the tool)"
    needs_model = True  # to author; the rules_in (score-only) phase overrides this
    needs_source = True
    tools = ("semgrep",)  # the authored rules are still executed by Semgrep
    knobs = (
        Knob("author_files", "int", DEFAULT_AUTHOR_FILES,
             help="source files shown to the model as examples when authoring rules"),
        Knob("author_max_bytes", "int", DEFAULT_AUTHOR_BYTES,
             help="bytes read from each example file"),
        Knob("semgrep_timeout", "float", 1800.0,
             help="timeout for the Semgrep scan with the authored rules, in seconds"),
        Knob("rules_out", "path", None, advanced=True,
             help="author rules, write them here, and stop before scanning"),
        Knob("rules_in", "path", None, advanced=True,
             help="skip authoring; scan with the ruleset loaded from here (needs no model)"),
    )

    def validate(self, target: Target, ctx: ConditionContext) -> None:
        # rules_in is deterministic Semgrep with no model; everything else authors.
        if not self.cfg(ctx, "rules_in") and ctx.model is None:
            raise ValueError(
                f"Condition {self.id} requires a model backend (--model) to author "
                "rules. Pass --config '{\"rules_in\": PATH}' to score an existing "
                "ruleset without one."
            )
        self._require(target, ctx, model=False, source=self.needs_source, url=self.needs_url)

    def run(self, target: Target, ctx: ConditionContext) -> ConditionResult:
        rules_in = self.cfg(ctx, "rules_in")
        if rules_in:
            return self._scan(rules_in, target, ctx, authored_from=None)

        rules_text, usage, valid, message = self._author(target, ctx)

        rules_out = self.cfg(ctx, "rules_out")
        if rules_out:  # phase 1: author and stop, no scan
            _write(rules_out, rules_text)
            return ConditionResult(
                findings=[],
                usage=usage,
                trace={
                    "phase": "author",
                    "rules_out": rules_out,
                    "rules_valid": valid,
                    "validation_message": message,
                    "model": ctx.model.name if ctx.model else None,
                },
            )

        # Single pass: author to a temp file, then scan the same source (overfit).
        fd, tmp = tempfile.mkstemp(suffix=".yaml", prefix="c3-rules-")
        os.close(fd)
        try:
            _write(tmp, rules_text)
            result = self._scan(tmp, target, ctx, authored_from=target.source_path)
        finally:
            os.unlink(tmp)
        result.usage = result.usage + usage
        result.trace = {
            **result.trace,
            "phase": "author+scan",
            "rules_valid": valid,
            "validation_message": message,
            "overfit_warning": "rules authored and scored on the same source",
            "model": ctx.model.name if ctx.model else None,
        }
        return result

    # -- phases ----------------------------------------------------------------

    def _author(
        self, target: Target, ctx: ConditionContext
    ) -> tuple[str, Usage, bool, str]:
        """Have the model write Semgrep YAML from a sample of the source files."""
        assert ctx.model is not None
        n = int(self.cfg(ctx, "author_files"))
        max_bytes = int(self.cfg(ctx, "author_max_bytes"))
        cwes = self._cwe_by_case(target)

        examples: list[str] = []
        for path in _iter_source_files(target.source_path, n):
            code, _ = _read(path, max_bytes)
            if not code:
                continue
            tc = benchmark_case_of(path)
            label = f" (expected {cwes[tc]})" if tc and tc in cwes else ""
            examples.append(f"File: {os.path.basename(path)}{label}\n```\n{code}\n```")

        prompt = (
            "Here are example source files that contain web vulnerabilities. Study the "
            "dangerous patterns, then author Semgrep rules that would catch them.\n\n"
            + "\n\n".join(examples)
            + f"\n\n{_AUTHOR_CONTRACT}"
        )
        completion = ctx.model.complete(
            [
                {"role": "system", "content": _AUTHOR_SYSTEM},
                {"role": "user", "content": prompt},
            ]
        )
        rules_text = _extract_yaml(completion.text)
        valid, message = _validate(rules_text)
        return rules_text, completion.usage, valid, message

    def _scan(
        self,
        rules_path: str,
        target: Target,
        ctx: ConditionContext,
        authored_from: str | None,
    ) -> ConditionResult:
        """Run Semgrep deterministically with the authored rules and score it."""
        semgrep = run_semgrep(
            target.source_path,
            config=rules_path,
            source_condition=self.id,
            timeout=float(self.cfg(ctx, "semgrep_timeout")),
        )
        scored_cases = None
        if target.kind is TargetKind.BENCHMARK:
            scored_cases = benchmark_cases_in_tree(target.source_path) or None
        return ConditionResult(
            findings=semgrep.findings,
            trace={
                "rules_in": rules_path if authored_from is None else None,
                "semgrep_version": semgrep.version,
                "semgrep_raw_findings": len(semgrep.findings),
            },
            scored_cases=scored_cases,
        )

    def _cwe_by_case(self, target: Target) -> dict[str, str]:
        """Map test-case id -> 'CWE-NN (category)' from ground truth, if available."""
        if target.kind is not TargetKind.BENCHMARK or not target.ground_truth:
            return {}
        try:
            expected = load_expected_results(target.ground_truth)
        except OSError:
            return {}
        return {
            tc: f"CWE-{e.cwe} ({e.category})" for tc, e in expected.items() if e.is_real
        }


def _validate(rules_text: str) -> tuple[bool, str]:
    """Validate authored YAML via ``semgrep --validate`` (best-effort).

    A missing Semgrep is not fatal here — authoring (e.g. a ``rules_out`` phase on a
    machine without Semgrep) should still succeed; the scan phase will surface the
    install hint. Validation simply reports unknown in that case.
    """
    fd, tmp = tempfile.mkstemp(suffix=".yaml", prefix="c3-validate-")
    os.close(fd)
    try:
        _write(tmp, rules_text)
        try:
            return validate_rules(tmp)
        except FileNotFoundError:
            return False, "semgrep not installed; validation skipped"
    finally:
        os.unlink(tmp)


def _extract_yaml(text: str) -> str:
    """Strip Markdown code fences a model may wrap the YAML in; else return as-is."""
    text = text.strip()
    if "```" not in text:
        return text
    start = text.find("```")
    # Skip the opening fence line (handles ```yaml and a bare ```).
    newline = text.find("\n", start)
    if newline == -1:
        return text
    end = text.find("```", newline)
    inner = text[newline + 1 : end if end != -1 else len(text)]
    return inner.strip()


def _write(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
        if not text.endswith("\n"):
            fh.write("\n")
