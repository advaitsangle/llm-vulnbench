"""The common finding schema.

Every condition — a static scanner, a dynamic scanner, or an LLM — emits its
results as a list of :class:`Finding`. Normalizing to one schema is what lets a
SAST result (``file:line``) and a DAST result (``url + method + param``) land in
the same scorecard. The schema follows the design pinned in ``claude.md``:

    { vuln_class (CWE id), location, confidence, verdict, evidence,
      source_condition }

The verdict/evidence fields borrow the Gaikwad et al. (`webllm`) JSON contract so
LLM conditions can return grounded, auditable judgements rather than bare labels.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class LocationKind(StrEnum):
    """Where a finding points. SAST points into source; DAST points at the wire."""

    SOURCE = "source"        # file:line[:col] in the application's code
    ENDPOINT = "endpoint"    # url + method + param on the running app
    TEST_CASE = "test_case"  # an OWASP Benchmark test-case id (ground truth pins this)


class Verdict(StrEnum):
    """An LLM's stance on whether a candidate vulnerability is real.

    Mirrors the constrained webllm contract: a model must commit to one of these
    rather than emitting free text, which is what makes triage scorable.
    """

    CONFIRMED = "confirmed"
    CANDIDATE = "candidate"
    NOT_SUPPORTED = "not_supported"


@dataclass(frozen=True)
class Location:
    """A normalized pointer to where a vulnerability lives.

    Exactly one *kind* of coordinate is meaningful per finding, but we keep all
    fields on one type so matching code can stay uniform.
    """

    kind: LocationKind
    # SOURCE
    file: str | None = None
    line: int | None = None
    column: int | None = None
    # ENDPOINT
    url: str | None = None
    method: str | None = None
    param: str | None = None
    # TEST_CASE
    test_case: str | None = None

    @classmethod
    def source(cls, file: str, line: int | None = None, column: int | None = None) -> Location:
        return cls(kind=LocationKind.SOURCE, file=file, line=line, column=column)

    @classmethod
    def endpoint(cls, url: str, method: str | None = None, param: str | None = None) -> Location:
        return cls(kind=LocationKind.ENDPOINT, url=url, method=method, param=param)

    @classmethod
    def for_test_case(cls, test_case: str) -> Location:
        # NB: named for_test_case, not test_case, to avoid shadowing the
        # ``test_case`` field — a same-named classmethod becomes the field's
        # default and every Location ends up storing a bound method.
        return cls(kind=LocationKind.TEST_CASE, test_case=test_case)

    def key(self) -> str:
        """A coarse string key for fuzzy list-matching on realistic apps."""
        if self.kind is LocationKind.SOURCE:
            return f"{self.file}:{self.line if self.line is not None else '*'}"
        if self.kind is LocationKind.ENDPOINT:
            return f"{self.method or '*'} {self.url} [{self.param or '*'}]"
        return self.test_case or ""

    def __str__(self) -> str:  # human-friendly, used in reports
        return self.key()


# Map an OWASP Benchmark test-case file (e.g. BenchmarkTest00001) to its id.
_BENCHMARK_TESTCASE_RE = re.compile(r"BenchmarkTest\d{5}")


def benchmark_case_of(text: str | None) -> str | None:
    """Return the Benchmark test-case id mentioned in ``text`` (path/url), if any."""
    if not text:
        return None
    m = _BENCHMARK_TESTCASE_RE.search(text)
    return m.group(0) if m else None


@dataclass
class Finding:
    """One normalized vulnerability finding.

    ``vuln_class`` is a CWE id (the shared vocabulary across scanners, the OWASP
    Benchmark ground truth, and the LLM). ``confidence`` is in [0, 1]. ``verdict``
    and the evidence fields are populated by LLM conditions and left ``None`` by
    raw scanners.
    """

    vuln_class: int                       # CWE id, e.g. 89 for SQL injection
    location: Location
    source_condition: str                 # which condition produced it, e.g. "B1"
    confidence: float = 1.0
    verdict: Verdict | None = None
    evidence: str | None = None
    counter_evidence: str | None = None
    remediation: str | None = None
    requires_human_review: bool = False
    rule_id: str | None = None            # scanner rule that fired, if any
    message: str | None = None            # raw scanner/LLM message
    extra: dict[str, Any] = field(default_factory=dict)

    def benchmark_test_case(self) -> str | None:
        """Resolve this finding to a Benchmark test-case id, if it maps to one.

        For SAST the test case is encoded in the file path; for DAST it is
        encoded in the request URL (the running Benchmark exposes each case at a
        URL like ``/benchmark/sqli-00/BenchmarkTest00001``); for an explicit
        TEST_CASE location it is the id directly. This is what lets a ZAP alert
        (B2/C2) score against the same ``expectedresults`` CSV as Semgrep.
        """
        if self.location.kind is LocationKind.TEST_CASE:
            return self.location.test_case
        coordinate = None
        if self.location.kind is LocationKind.SOURCE:
            coordinate = self.location.file
        elif self.location.kind is LocationKind.ENDPOINT:
            coordinate = self.location.url
        if coordinate:
            m = _BENCHMARK_TESTCASE_RE.search(coordinate)
            if m:
                return m.group(0)
        return None

    # ---- serialization -------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["location"]["kind"] = self.location.kind.value
        d["verdict"] = self.verdict.value if self.verdict else None
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Finding:
        loc = dict(d["location"])
        loc["kind"] = LocationKind(loc["kind"])
        verdict = d.get("verdict")
        return cls(
            vuln_class=int(d["vuln_class"]),
            location=Location(**loc),
            source_condition=d["source_condition"],
            confidence=float(d.get("confidence", 1.0)),
            verdict=Verdict(verdict) if verdict else None,
            evidence=d.get("evidence"),
            counter_evidence=d.get("counter_evidence"),
            remediation=d.get("remediation"),
            requires_human_review=bool(d.get("requires_human_review", False)),
            rule_id=d.get("rule_id"),
            message=d.get("message"),
            extra=d.get("extra", {}),
        )


def dump_findings(findings: Iterable[Finding], path: str) -> None:
    """Persist findings as a JSON array (one run's normalized output)."""
    with open(path, "w", encoding="utf-8") as fh:
        json.dump([f.to_dict() for f in findings], fh, indent=2)


def load_findings(path: str) -> list[Finding]:
    with open(path, encoding="utf-8") as fh:
        return [Finding.from_dict(d) for d in json.load(fh)]
