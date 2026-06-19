"""A target application a condition is evaluated against.

Two kinds matter for scoring (``claude.md``):

* ``BENCHMARK`` — OWASP Benchmark: auto-scored against ``expectedresults-1.2.csv``.
  Has both a source tree (for SAST/LLM) and, when deployed, a running URL (DAST).
* ``REALISTIC`` — Juice Shop / WebGoat / DVWA: scored by fuzzy list-matching
  against a curated per-app ground-truth list. Qualitative by design.

A target carries whichever coordinates a condition needs: ``source_path`` for
static/LLM conditions, ``base_url`` for dynamic conditions, and a pointer to its
ground-truth artifact for scoring.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class TargetKind(StrEnum):
    BENCHMARK = "benchmark"
    REALISTIC = "realistic"


@dataclass
class Target:
    name: str
    kind: TargetKind
    #: Local path to the application source (for SAST / B3 / C-conditions).
    source_path: str | None = None
    #: Base URL of the running app (for DAST / agentic conditions).
    base_url: str | None = None
    #: Ground truth: a Benchmark expectedresults CSV, or a realistic-app vuln list.
    ground_truth: str | None = None
    #: Free-form, e.g. {"language": "java", "version": "1.2"}.
    meta: dict | None = None
