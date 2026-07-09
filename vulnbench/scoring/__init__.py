"""Scoring: turn normalized findings + ground truth into metrics."""

from .metrics_unifier import Metrics, confusion_to_metrics
from .owasp_benchmark import benchmark_cases_in_tree, load_expected_results, score_benchmark

__all__ = [
    "Metrics",
    "confusion_to_metrics",
    "score_benchmark",
    "load_expected_results",
    "benchmark_cases_in_tree",
]
