"""Score findings against a curated realistic-app vuln list (fuzzy matching).

For Juice Shop / WebGoat / DVWA there is no Benchmark CSV. We
curate a one-time ground-truth list per app and match findings to it on
``(vuln_class, location)`` with fuzzy location matching. Numbers are approximate by
design — this is the qualitative path, kept deliberately separate from the
auto-scored Benchmark path. There is no true-negative universe here, so FPR/TN are
not computed; precision/recall/F1 are.

Ground-truth list format (JSON)::

    [{"cwe": 89, "location": "POST /rest/products/search [q]"}, ...]

A finding matches an expected item when the CWE is equal and the location keys
overlap (same endpoint/param, or same file/region). This module is a deliberate
stub: the matching policy is intentionally conservative and meant to be tuned with
spot-checks once a real app is wired up.
"""

from __future__ import annotations

import json

from ..schema import Finding
from .metrics import Metrics


def load_vuln_list(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _loc_overlap(finding_key: str, expected_loc: str) -> bool:
    """Coarse overlap: shared, non-trivial token between the two location keys."""
    a = {t for t in finding_key.replace(":", " ").split() if len(t) > 2}
    b = {t for t in expected_loc.replace(":", " ").split() if len(t) > 2}
    return bool(a & b)


def score_list(findings: list[Finding], expected: list[dict]) -> Metrics:
    """Precision/recall/F1 against the curated list. TN is left 0 (no universe)."""
    matched_expected: set[int] = set()
    matched_findings: set[int] = set()
    for fi, f in enumerate(findings):
        for ei, exp in enumerate(expected):
            if int(exp.get("cwe", -1)) != f.vuln_class:
                continue
            if _loc_overlap(f.location.key(), str(exp.get("location", ""))):
                matched_expected.add(ei)
                matched_findings.add(fi)

    tp = len(matched_expected)
    fn = len(expected) - tp
    fp = len(findings) - len(matched_findings)
    return Metrics(tp=tp, fp=fp, fn=fn, tn=0)
