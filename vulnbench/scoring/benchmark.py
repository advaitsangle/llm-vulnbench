"""Score findings against the OWASP Benchmark ground truth.

The Benchmark ships ``expectedresults-1.2.csv`` with one row per test case::

    # test name, category, real vulnerability, cwe
    BenchmarkTest00001,pathtraver,true,22

A test case is *detected* when the tool reports a finding in that test case's file
whose CWE equals the test case's expected CWE. Per OWASP Benchmark scoring, each
test case then contributes exactly one cell of the confusion matrix:

    real & detected      -> TP        real & not detected  -> FN
    not real & detected  -> FP        not real & not det.  -> TN

This is the apples-to-apples path: SAST, DAST, and every LLM condition are scored
the same way against the same labels (the methodology linchpin in ``claude.md``).
"""

from __future__ import annotations

import csv
import os
from collections.abc import Iterable
from dataclasses import dataclass

from ..schema import Finding, benchmark_case_of
from .metrics import Metrics, confusion_to_metrics


@dataclass
class ExpectedCase:
    test_case: str
    category: str
    is_real: bool
    cwe: int


def load_expected_results(csv_path: str) -> dict[str, ExpectedCase]:
    """Parse an ``expectedresults-*.csv`` into ``{test_case: ExpectedCase}``."""
    expected: dict[str, ExpectedCase] = {}
    with open(csv_path, newline="", encoding="utf-8") as fh:
        for row in csv.reader(fh):
            if not row or row[0].lstrip().startswith("#"):
                continue  # skip the header/comment line
            name = row[0].strip()
            if not name:
                continue
            expected[name] = ExpectedCase(
                test_case=name,
                category=row[1].strip(),
                is_real=row[2].strip().lower() == "true",
                cwe=int(row[3]),
            )
    return expected


def _detected_cwes(findings: Iterable[Finding]) -> dict[str, set[int]]:
    """Map each test case to the set of CWEs the tool reported in it."""
    detected: dict[str, set[int]] = {}
    for f in findings:
        tc = f.benchmark_test_case()
        if tc is not None:
            detected.setdefault(tc, set()).add(f.vuln_class)
    return detected


def benchmark_cases_in_tree(root: str) -> set[str]:
    """The Benchmark test-case ids present as files under a source tree.

    This is the *in-scope* set for a source-based condition: every case whose
    file the scanner/LLM could have looked at. Pointing ``--source`` at a slice
    of the Benchmark (a handful of files) yields just those cases, which is what
    lets :func:`score_benchmark` score a partial run honestly.
    """
    cases: set[str] = set()
    for _dirpath, _dirs, files in os.walk(root):
        for name in files:
            tc = benchmark_case_of(name)
            if tc is not None:
                cases.add(tc)
    return cases


def score_benchmark(
    findings: list[Finding],
    expected: dict[str, ExpectedCase],
    scanned: set[str] | None = None,
) -> Metrics:
    """Compute the confusion matrix + metrics for one condition's findings.

    ``scanned`` restricts scoring to the test cases the condition actually
    examined. Without it, a subset run (``max_files``, or a sliced ``--source``)
    counts every un-scanned real case as a false negative — burying recall and
    making partial runs look far worse than they are. ``None`` means a full sweep
    where every case was in scope (the historical behaviour).
    """
    if scanned is not None:
        expected = {tc: exp for tc, exp in expected.items() if tc in scanned}
    detected = _detected_cwes(findings)
    tp = fp = fn = tn = 0
    for tc, exp in expected.items():
        # A test case is detected only when the *expected* CWE is reported in it.
        flagged = exp.cwe in detected.get(tc, set())
        if exp.is_real and flagged:
            tp += 1
        elif exp.is_real and not flagged:
            fn += 1
        elif not exp.is_real and flagged:
            fp += 1
        else:
            tn += 1
    return confusion_to_metrics(tp, fp, fn, tn)
