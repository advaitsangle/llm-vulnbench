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
from ..schema import Finding


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
