from vulnbench.schema import Finding, Location
from vulnbench.scoring.benchmark import ExpectedCase, score_benchmark


def _expected():
    return {
        "BenchmarkTest00001": ExpectedCase("BenchmarkTest00001", "sqli", True, 89),
        "BenchmarkTest00002": ExpectedCase("BenchmarkTest00002", "sqli", False, 89),
        "BenchmarkTest00003": ExpectedCase("BenchmarkTest00003", "xss", True, 79),
    }


def _finding(tc: str, cwe: int):
    return Finding(
        vuln_class=cwe,
        location=Location.source(f"org/owasp/benchmark/testcode/{tc}.java", 10),
        source_condition="B1",
    )


def test_perfect_detector():
    findings = [_finding("BenchmarkTest00001", 89), _finding("BenchmarkTest00003", 79)]
    m = score_benchmark(findings, _expected())
    assert (m.tp, m.fp, m.fn, m.tn) == (2, 0, 0, 1)
    assert m.recall == 1.0
    assert m.precision == 1.0


def test_false_positive_and_miss():
    # Flags the non-vuln case (FP), misses the xss case (FN).
    findings = [_finding("BenchmarkTest00001", 89), _finding("BenchmarkTest00002", 89)]
    m = score_benchmark(findings, _expected())
    assert (m.tp, m.fp, m.fn, m.tn) == (1, 1, 1, 0)


def test_wrong_cwe_does_not_count_as_detection():
    # Reports a CWE in the right file but the wrong class -> not detected.
    findings = [_finding("BenchmarkTest00001", 79)]
    m = score_benchmark(findings, _expected())
    assert m.tp == 0
    # Both real cases (00001 wrong-CWE, 00003 unflagged) count as misses.
    assert m.fn == 2
    assert m.fp == 0  # CWE-79 in 00001 is not the expected class, so not an FP either
