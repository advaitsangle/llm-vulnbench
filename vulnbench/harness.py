"""The end-to-end harness: run a condition on a target and score it.

One pass of the pipeline:

    1. (target already deployed: source tree on disk and/or base_url up)
    2. run the condition           -> normalized Findings + Usage
    3. score against ground truth  -> Benchmark CSV or realistic-app list
    4. record metrics + cost (tokens) + latency (wall-clock) + provenance

A :class:`RunRecord` is the unit logged per (target, condition); :func:`run_matrix`
sweeps the cartesian product for a full matrix run.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime

from . import __version__
from .conditions import ConditionContext, get_condition
from .corpus import Target, TargetKind
from .models import ModelBackend
from .schema import Finding
from .scoring import score_benchmark
from .scoring.benchmark import load_expected_results
from .scoring.listmatch import load_vuln_list, score_list


@dataclass
class RunRecord:
    target: str
    condition: str
    model: str | None
    metrics: dict | None              # None if no ground truth was supplied
    input_tokens: int
    output_tokens: int
    seconds: float                    # total wall-clock for the condition
    model_seconds: float              # subset spent inside the model backend
    n_findings: int
    provenance: dict = field(default_factory=dict)
    trace: dict = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def _provenance(config: dict | None) -> dict:
    """Capture what produced a scorecard so a scored run is reproducible.

    Records the harness version, a UTC timestamp, and the frozen config. The
    scanner/model versions are recorded per condition in ``trace`` (e.g. Semgrep
    stamps its version there), so provenance + trace together pin a run.
    """
    return {
        "vulnbench_version": __version__,
        "timestamp_utc": datetime.now(UTC).isoformat(timespec="seconds"),
        "config": dict(config or {}),
    }


def run_one(
    target: Target,
    condition_id: str,
    model: ModelBackend | None = None,
    config: dict | None = None,
    *,
    ground_truth_cache: dict | None = None,
    debug: bool = False,
) -> tuple[RunRecord, list[Finding]]:
    """Run a single condition on a single target and score it.

    ``debug=True`` re-raises condition errors instead of capturing them, so
    programming bugs surface during development rather than hiding in ``error``.
    """
    cls = get_condition(condition_id)
    condition = cls()
    ctx = ConditionContext(model=model, config=config or {})
    prov = _provenance(config)

    start = time.perf_counter()
    try:
        condition.validate(target, ctx)
        result = condition.run(target, ctx)
    except Exception as exc:  # surface as a record, don't crash the whole matrix
        if debug:
            raise
        record = RunRecord(
            target=target.name,
            condition=condition_id,
            model=model.name if model else None,
            metrics=None,
            input_tokens=0,
            output_tokens=0,
            seconds=time.perf_counter() - start,
            model_seconds=0.0,
            n_findings=0,
            provenance=prov,
            error=f"{type(exc).__name__}: {exc}",
        )
        return record, []

    wall = time.perf_counter() - start
    metrics = _score(target, result.findings, ground_truth_cache, result.scored_cases)
    record = RunRecord(
        target=target.name,
        condition=condition_id,
        model=model.name if model else None,
        metrics=metrics.to_dict() if metrics else None,
        input_tokens=result.usage.input_tokens,
        output_tokens=result.usage.output_tokens,
        seconds=wall,                        # authoritative total latency
        model_seconds=result.usage.seconds,  # model-only subset of that latency
        n_findings=len(result.findings),
        provenance=prov,
        trace=result.trace,
    )
    return record, result.findings


def _load_ground_truth(target: Target, cache: dict | None):
    """Load (and optionally cache) a target's ground truth.

    Caching keyed on the ground-truth path avoids re-parsing a 2740-row CSV once
    per matrix cell.
    """
    if cache is not None and target.ground_truth in cache:
        return cache[target.ground_truth]
    if target.kind is TargetKind.BENCHMARK:
        gt: object = load_expected_results(target.ground_truth)
    else:
        gt = load_vuln_list(target.ground_truth)
    if cache is not None:
        cache[target.ground_truth] = gt
    return gt


def _score(
    target: Target,
    findings: list[Finding],
    cache: dict | None = None,
    scored_cases: set[str] | None = None,
):
    """Pick the scorer by target kind; return None if no ground truth is set.

    ``scored_cases`` (when a condition reports it) restricts Benchmark scoring to
    the cases the run examined, so partial runs report honest recall rather than
    counting every un-scanned case as a miss.
    """
    if not target.ground_truth:
        return None
    gt = _load_ground_truth(target, cache)
    if target.kind is TargetKind.BENCHMARK:
        return score_benchmark(findings, gt, scored_cases)  # type: ignore[arg-type]
    return score_list(findings, gt)  # type: ignore[arg-type]


def run_matrix(
    targets: list[Target],
    condition_ids: list[str],
    model: ModelBackend | None = None,
    config: dict | None = None,
    *,
    debug: bool = False,
) -> list[RunRecord]:
    """Sweep every (target, condition) pair. Errors are captured per cell."""
    records: list[RunRecord] = []
    ground_truth_cache: dict = {}  # shared across cells; ground truth is read-only
    for target in targets:
        for cid in condition_ids:
            record, _ = run_one(
                target, cid, model=model, config=config,
                ground_truth_cache=ground_truth_cache, debug=debug,
            )
            records.append(record)
    return records
