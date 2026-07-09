"""The Condition contract.

A condition is a function from a :class:`Target` to a list of normalized
:class:`Finding` plus the run's resource usage. Keeping every cell behind the same
``run`` signature is what lets the harness loop over the matrix uniformly and what
makes cost/latency a first-class, per-condition measurement.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Literal

from ..corpus import Target
from ..models import ModelBackend, Usage
from ..schema import Finding, dump_findings, load_findings

#: How a knob's value is rendered/parsed by an interactive front-end. ``path`` is a
#: ``str`` that names a file, which lets the wizard offer completion and existence checks;
#: ``list`` is entered comma-separated.
KnobType = Literal["int", "float", "bool", "str", "path", "list"]


@dataclass(frozen=True)
class Knob:
    """One declared, discoverable config option of a condition.

    Declaring knobs (rather than reading ``ctx.config.get(name, default)`` ad hoc) is
    what lets a front-end enumerate a condition's options without knowing the condition:
    the interactive wizard renders whatever the ladder happens to declare, so adding a
    new condition never means editing the wizard. The declared ``default`` is the *only*
    default — conditions read it back through :meth:`Condition.cfg`, so the value a
    front-end shows and the value the condition uses cannot drift apart.
    """

    name: str
    type: KnobType
    default: Any
    help: str = ""
    #: When set, the value must be one of these (renders as a picker, not a free field).
    choices: tuple[Any, ...] | None = None
    #: Phase/plumbing knobs (file handoff between stages) are hidden from the wizard's
    #: "tune this condition" step; they are wiring, not experimental variables.
    advanced: bool = False

    def parse(self, raw: str) -> Any:
        """Coerce a string typed by a user into this knob's type."""
        raw = raw.strip()
        if self.type == "bool":
            if raw.lower() in ("y", "yes", "true", "1", "on"):
                return True
            if raw.lower() in ("n", "no", "false", "0", "off"):
                return False
            raise ValueError(f"{self.name}: expected yes/no, got {raw!r}")
        if self.type == "int":
            return int(raw)
        if self.type == "float":
            return float(raw)
        if self.type == "list":
            return [tok.strip() for tok in raw.split(",") if tok.strip()]
        return raw  # str / path


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
    #: Benchmark test-case ids this run actually examined, so a partial run is
    #: scored only over what it looked at. ``None`` means a full sweep (score
    #: against every case). Only consumed by the Benchmark scorer.
    scored_cases: set[str] | None = None


class Condition(ABC):
    #: Stable id used across the matrix and scorecards, e.g. ``"C1"``.
    id: str = "?"
    #: One-line human label.
    label: str = ""
    #: Whether this condition requires a ``model`` in the context.
    needs_model: bool = False
    #: Config options this condition understands. A subclass declares only its *own*;
    #: :meth:`all_knobs` merges in those inherited from its bases.
    knobs: tuple[Knob, ...] = ()

    @classmethod
    def all_knobs(cls) -> tuple[Knob, ...]:
        """Every knob this condition accepts, base classes first, subclass wins by name.

        Walking the MRO means a mixin like :class:`TriageCondition` contributes its
        phasing knobs to every subclass without each one restating them.
        """
        merged: dict[str, Knob] = {}
        for klass in reversed(cls.__mro__):
            for knob in vars(klass).get("knobs", ()):
                merged[knob.name] = knob
        return tuple(merged.values())

    @classmethod
    def knob(cls, name: str) -> Knob:
        for k in cls.all_knobs():
            if k.name == name:
                return k
        raise KeyError(f"{cls.id} declares no knob named {name!r}")

    def cfg(self, ctx: ConditionContext, name: str) -> Any:
        """Read a knob: the user's value if set, else the knob's declared default.

        Going through here (rather than ``ctx.config.get(name, 60_000)``) keeps the
        default in exactly one place — the :class:`Knob` declaration.
        """
        if name in ctx.config:
            return ctx.config[name]
        return self.knob(name).default

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

    knobs = (
        Knob("scan_out", "path", None, advanced=True,
             help="run only the scanner, write its findings here, and skip the model"),
        Knob("scan_in", "path", None, advanced=True,
             help="skip the scanner; triage the findings loaded from here"),
    )

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

    def scope(self, target: Target, ctx: ConditionContext) -> set[str] | None:
        """Benchmark test cases this run examined, for honest subset scoring.

        Default ``None`` scores against the full ground truth. Subclasses whose
        scan covers a knowable slice (e.g. C1's Semgrep over a source tree)
        override this; see :attr:`ConditionResult.scored_cases`.
        """
        return None

    def _scan_only(self, ctx: ConditionContext) -> bool:
        """True when configured to scan and stop (no triage, no model)."""
        return bool(self.cfg(ctx, "scan_out")) and not self.cfg(ctx, "scan_in")

    def validate(self, target: Target, ctx: ConditionContext) -> None:
        # A model is only required for the triage phase; a scan-only run needs none.
        if self.needs_model and not self._scan_only(ctx) and ctx.model is None:
            raise ValueError(f"Condition {self.id} requires a model backend (--model).")

    def run(self, target: Target, ctx: ConditionContext) -> ConditionResult:
        scan_in = self.cfg(ctx, "scan_in")
        if scan_in:
            scanner_findings = load_findings(scan_in)
            trace = {"scan_in": scan_in, "loaded_findings": len(scanner_findings)}
        else:
            scanner_findings, trace = self.scan(target, ctx)

        if self._scan_only(ctx):
            scan_out = self.cfg(ctx, "scan_out")
            dump_findings(scanner_findings, scan_out)
            return ConditionResult(
                findings=scanner_findings,
                trace={**trace, "phase": "scan", "scan_out": scan_out},
                scored_cases=self.scope(target, ctx),
            )

        result = self.triage(scanner_findings, target, ctx)
        result.trace = {**trace, **result.trace, "phase": "triage" if scan_in else "full"}
        if result.scored_cases is None:
            result.scored_cases = self.scope(target, ctx)
        return result
