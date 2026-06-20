from vulnbench.schema import Finding, Location
from vulnbench.scoring.webapps_benchmark import score_webapp


def _expected():
    return [
        {"cwe": 89, "location": "POST /rest/products/search [q]"},
        {"cwe": 79, "location": "GET /search [term]"},
    ]


def test_match_endpoint_finding():
    findings = [
        Finding(89, Location.endpoint("/rest/products/search", "POST", "q"), "C2"),
    ]
    m = score_webapp(findings, _expected())
    assert m.tp == 1
    assert m.fn == 1   # the xss item went undetected
    assert m.fp == 0


def test_wrong_cwe_is_a_false_positive_not_a_match():
    findings = [
        Finding(22, Location.endpoint("/rest/products/search", "POST", "q"), "C2"),
    ]
    m = score_webapp(findings, _expected())
    assert m.tp == 0
    assert m.fp == 1
    assert m.fn == 2


def test_precision_recall_computation():
    findings = [
        Finding(89, Location.endpoint("/rest/products/search", "POST", "q"), "C2"),
        Finding(79, Location.endpoint("/search", "GET", "term"), "C2"),
    ]
    m = score_webapp(findings, _expected())
    assert m.precision == 1.0
    assert m.recall == 1.0
    assert m.f1 == 1.0
