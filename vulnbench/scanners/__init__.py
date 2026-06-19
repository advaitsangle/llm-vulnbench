"""Wrappers that run real scanners and normalize their output to Findings."""

from .semgrep_runner import SemgrepResult, run_semgrep

__all__ = ["SemgrepResult", "run_semgrep"]
