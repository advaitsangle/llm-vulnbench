"""Scoring: turn normalized findings + ground truth into metrics."""

from .benchmark import load_expected_results, score_benchmark
from .metrics import Metrics, confusion_to_metrics

__all__ = ["Metrics", "confusion_to_metrics", "score_benchmark", "load_expected_results"]
