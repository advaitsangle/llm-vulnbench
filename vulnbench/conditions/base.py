"""The Condition contract.

A condition is a function from a :class:`Target` to a list of normalized
:class:`Finding` plus the run's resource usage. Keeping every cell behind the same
``run`` signature is what lets the harness loop over the matrix uniformly and what
makes cost/latency a first-class, per-condition measurement.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from ..corpus import Target
from ..models import ModelBackend, Usage
from ..schema import Finding, dump_findings, load_findings


@dataclass
class ConditionContext:
    """Everything a condition needs beyond the target.

    ``model`` is ``None`` for pure-scanner baselines (B1, B2). ``config`` holds
    frozen knobs (ruleset name, prompt variant) so scored runs are reproducible.
    """

    model: ModelBackend | None = None
    config: dict = field(default_factory=dict)


@dataclass
class ConditionResult:
    findings: list[Finding]
    usage: Usage = field(default_factory=Usage)
    #: Diagnostics for the run log (commands issued, prompt ids, agent steps...).
    trace: dict = field(default_factory=dict)


class Condition(ABC):
    #: Stable id used across the matrix and scorecards, e.g. ``"C1"``.
    id: str = "?"
    #: One-line human label.
    label: str = ""
    #: Whether this condition requires a ``model`` in the context.
    needs_model: bool = False

    def validate(self, target: Target, ctx: ConditionContext) -> None:
        """Fail fast with an actionable message before doing expensive work."""
        if self.needs_model and ctx.model is None:
            raise ValueError(f"Condition {self.id} requires a model backend (--model).")

    @abstractmethod
    def run(self, target: Target, ctx: ConditionContext) -> ConditionResult: ...


class TriageCondition(Condition):
    """A condition that runs a scanner, then has the model triage its output.

    The two phases are split so they can run *separately*. This matters on a
    RAM-bound machine: the scan phase may need a heavy running stack (a deployed
    app + the ZAP daemon in Docker) while the triage phase needs the very RAM
    that stack occupies for a large local model. Running them back-to-back in one
    process forces both resident at once and OOMs. Splitting lets you scan with
    the stack up, tear it down, then triage with the full machine free.

    The scan artifact is just the normalized :class:`Finding` list — identical to
    what the corresponding raw-scanner baseline (B1/B2) emits — so one scan can
    feed triage with several different models or prompts without re-scanning.

    Config knobs:

        scan_out  PATH  run only the scanner, write its findings to PATH, and
                        skip the model entirely (phase 1).
        scan_in   PATH  skip the scanner, load findings from PATH, and run only
                        the model triage over them (phase 2).

    With neither knob, ``run`` does both phases in one pass (the default).
    Subclasses implement :meth:`scan` and :meth:`triage`; this base wires the
    phasing, validation, and trace-merging around them.
    """

    @abstractmethod
    def scan(self, target: Target, ctx: ConditionContext) -> tuple[list[Finding], dict]:
        """Phase 1: run the scanner, returning its findings and a trace dict."""
        ...

    @abstractmethod
    def triage(
        self, scanner_findings: list[Finding], target: Target, ctx: ConditionContext
    ) -> ConditionResult:
        """Phase 2: have the model triage the scanner's findings."""
        ...

    def _scan_only(self, ctx: ConditionContext) -> bool:
        """True when configured to scan and stop (no triage, no model)."""
        return bool(ctx.config.get("scan_out")) and not ctx.config.get("scan_in")

    def validate(self, target: Target, ctx: ConditionContext) -> None:
        # A model is only required for the triage phase; a scan-only run needs none.
        if self.needs_model and not self._scan_only(ctx) and ctx.model is None:
            raise ValueError(f"Condition {self.id} requires a model backend (--model).")

    def run(self, target: Target, ctx: ConditionContext) -> ConditionResult:
        scan_in = ctx.config.get("scan_in")
        if scan_in:
            scanner_findings = load_findings(scan_in)
            trace = {"scan_in": scan_in, "loaded_findings": len(scanner_findings)}
        else:
            scanner_findings, trace = self.scan(target, ctx)

        if self._scan_only(ctx):
            scan_out = ctx.config["scan_out"]
            dump_findings(scanner_findings, scan_out)
            return ConditionResult(
                findings=scanner_findings,
                trace={**trace, "phase": "scan", "scan_out": scan_out},
            )

        result = self.triage(scanner_findings, target, ctx)
        result.trace = {**trace, **result.trace, "phase": "triage" if scan_in else "full"}
        return result
