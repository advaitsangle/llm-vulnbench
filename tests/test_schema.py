from vulnbench.schema import Finding, Location, Verdict


def test_source_finding_resolves_benchmark_test_case():
    f = Finding(
        vuln_class=89,
        location=Location.source("src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00042.java", 17),
        source_condition="B1",
    )
    assert f.benchmark_test_case() == "BenchmarkTest00042"


def test_non_benchmark_path_has_no_test_case():
    f = Finding(vuln_class=79, location=Location.source("app/views/home.py", 3), source_condition="B3")
    assert f.benchmark_test_case() is None


def test_location_fields_default_to_none_not_methods():
    # Regression: a factory named after a field used to overwrite the field's
    # default with a bound method, breaking JSON serialization.
    loc = Location.source("a.java", 3)
    assert loc.test_case is None
    assert loc.url is None
    tc = Location.for_test_case("BenchmarkTest00007")
    assert tc.test_case == "BenchmarkTest00007"


def test_findings_json_dump_roundtrip(tmp_path):
    from vulnbench.schema import dump_findings, load_findings

    findings = [
        Finding(89, Location.source("x/BenchmarkTest00001.java", 5), "B1"),
        Finding(79, Location.endpoint("http://x/p", "GET", "q"), "C2"),
    ]
    path = tmp_path / "f.json"
    dump_findings(findings, str(path))
    back = load_findings(str(path))
    assert back[0].vuln_class == 89
    assert back[1].location.param == "q"


def test_roundtrip_serialization():
    f = Finding(
        vuln_class=22,
        location=Location.endpoint("http://x/login", method="POST", param="user"),
        source_condition="C2",
        verdict=Verdict.CONFIRMED,
        confidence=0.8,
        evidence="reflected input",
    )
    again = Finding.from_dict(f.to_dict())
    assert again.vuln_class == 22
    assert again.location.url == "http://x/login"
    assert again.verdict is Verdict.CONFIRMED
    assert again.confidence == 0.8
