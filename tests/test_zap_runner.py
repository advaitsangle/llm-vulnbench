"""Unit tests for the ZAP runner — parser + orchestration, no live ZAP."""

import pytest

from vulnbench.conditions import get_condition
from vulnbench.conditions.base import ConditionContext
from vulnbench.corpus import Target, TargetKind
from vulnbench.scanners.benchmark_crawl import load_crawler_requests
from vulnbench.scanners.zap_runner import (
    SeedRequest,
    _confidence,
    _parse_cwe,
    findings_from_zap_alerts,
    run_zap,
)
from vulnbench.schema import Finding, Location, LocationKind

# One realistic ZAP alert as returned by core/view/alerts, pointing at a deployed
# Benchmark test case (the id lives in the URL, as on the real app).
SQLI_ALERT = {
    "alert": "SQL Injection",
    "description": "SQL injection may be possible.",
    "cweid": "89",
    "url": "https://localhost:8443/benchmark/sqli-00/BenchmarkTest00008",
    "method": "POST",
    "param": "username",
    "risk": "High",
    "confidence": "Medium",
    "pluginId": "40018",
    "attack": "' OR '1'='1",
    "evidence": "syntax error",
}


def test_parse_cwe_handles_missing_and_unmapped():
    assert _parse_cwe("89") == 89
    assert _parse_cwe(89) == 89
    assert _parse_cwe("-1") == 0   # ZAP's "no CWE" sentinel
    assert _parse_cwe("") == 0
    assert _parse_cwe(None) == 0


def test_confidence_label_mapping():
    assert _confidence("High") == 0.9
    assert _confidence("Medium") == 0.6
    assert _confidence("Confirmed") == 1.0
    assert _confidence("False Positive") == 0.1
    assert _confidence("weird") == 0.7  # unknown -> neutral default


def test_empty_alerts_yields_no_findings():
    assert findings_from_zap_alerts([]) == []


def test_finding_from_alert_is_endpoint_located():
    [f] = findings_from_zap_alerts([SQLI_ALERT], source_condition="B2")
    assert f.vuln_class == 89
    assert f.location.kind is LocationKind.ENDPOINT
    assert f.location.method == "POST"
    assert f.location.param == "username"
    assert f.confidence == 0.6
    assert f.rule_id == "40018"
    assert f.source_condition == "B2"
    assert f.extra["risk"] == "High"
    assert "SQL Injection" in f.message


def test_endpoint_finding_resolves_benchmark_test_case():
    # The DAST->scoring bridge: a URL-located finding must score like a SAST one.
    [f] = findings_from_zap_alerts([SQLI_ALERT])
    assert f.benchmark_test_case() == "BenchmarkTest00008"


def test_non_benchmark_url_has_no_test_case():
    f = Finding(79, Location.endpoint("https://example.com/login", "GET", "q"), "B2")
    assert f.benchmark_test_case() is None


class _FakeZap:
    """Drives run_zap through one spider + active-scan + alerts cycle."""

    def __init__(self, alerts):
        self._alerts = alerts
        self.calls = []

    def version(self):
        return "2.15.0"

    def spider(self, base_url):
        self.calls.append(("spider", base_url))
        return "0"

    def spider_status(self, scan_id):
        return 100

    def active_scan(self, base_url, recurse=True):
        self.calls.append(("ascan", base_url, recurse))
        return "1"

    def active_scan_status(self, scan_id):
        return 100

    def alerts(self, base_url, start=0, count=0):
        return self._alerts

    def send_request(self, raw_request, follow_redirects=True):
        self.calls.append(("send", raw_request))
        return {}


def test_run_zap_orchestrates_and_normalizes():
    fake = _FakeZap([SQLI_ALERT])
    result = run_zap("https://localhost:8443/benchmark/", client=fake, poll_interval=0)
    assert result.version == "2.15.0"
    assert len(result.findings) == 1
    assert result.trace["alert_count"] == 1
    assert ("spider", "https://localhost:8443/benchmark/") in fake.calls


def test_run_zap_seeded_flow_skips_spider_and_replays_requests():
    fake = _FakeZap([SQLI_ALERT])
    seeds = [SeedRequest(url="https://benchmark:8443/benchmark/x", params={"q": ""})]
    result = run_zap(
        "https://benchmark:8443/benchmark/", seed_requests=seeds, client=fake, poll_interval=0
    )
    kinds = [c[0] for c in fake.calls]
    assert "send" in kinds and "spider" not in kinds  # seeded, not spidered
    assert result.trace["seeded_requests"] == 1
    assert len(result.findings) == 1


def test_seed_request_to_raw_get_with_params_and_cookie():
    raw = SeedRequest(
        url="https://benchmark:8443/benchmark/sqli-00/BenchmarkTest00026",
        method="GET",
        params={"username": "foo"},
        cookies={"BenchmarkTest00026": "bar"},
    ).to_raw()
    assert raw.startswith("GET https://benchmark:8443/benchmark/sqli-00/BenchmarkTest00026?username=foo HTTP/1.1")
    assert "Host: benchmark:8443" in raw
    assert "Cookie: BenchmarkTest00026=bar" in raw


def test_seed_request_to_raw_post_sets_body_and_length():
    raw = SeedRequest(
        url="https://benchmark:8443/benchmark/sqli-00/BenchmarkTest00099",
        method="POST",
        form={"BenchmarkTest00099": "bar"},
    ).to_raw()
    head, _, body = raw.partition("\r\n\r\n")
    assert head.startswith("POST ")
    assert "Content-Type: application/x-www-form-urlencoded" in head
    assert f"Content-Length: {len(body.encode())}" in head
    assert body == "BenchmarkTest00099=bar"


def test_load_crawler_requests_parses_methods_and_retargets(tmp_path):
    xml = tmp_path / "crawler.xml"
    xml.write_text(
        '<?xml version="1.0"?>\n'
        '<benchmarkSuite testsuite="benchmark" version="1.2">'
        '  <benchmarkTest URL="https://localhost:8443/benchmark/sqli-00/BenchmarkTest00026" tcName="BenchmarkTest00026">'
        '    <getparam name="username" value="" />'
        '  </benchmarkTest>'
        '  <benchmarkTest URL="https://localhost:8443/benchmark/crypto-00/BenchmarkTest00019" tcName="BenchmarkTest00019">'
        '    <formparam name="BenchmarkTest00019" value="someSecret" />'
        '  </benchmarkTest>'
        '</benchmarkSuite>'
    )
    reqs = load_crawler_requests(str(xml), base_url="https://benchmark:8443/")
    assert [r.method for r in reqs] == ["GET", "POST"]   # getparam->GET, formparam->POST
    assert all(r.url.startswith("https://benchmark:8443/") for r in reqs)  # retargeted off localhost
    assert reqs[0].params == {"username": ""}
    assert reqs[1].form == {"BenchmarkTest00019": "someSecret"}


def test_load_crawler_requests_respects_limit(tmp_path):
    xml = tmp_path / "c.xml"
    body = "".join(
        f'<benchmarkTest URL="https://localhost:8443/benchmark/t/BenchmarkTest{i:05d}" tcName="t{i}">'
        '<getparam name="a" value="" /></benchmarkTest>'
        for i in range(5)
    )
    xml.write_text(f'<benchmarkSuite>{body}</benchmarkSuite>')
    assert len(load_crawler_requests(str(xml), limit=2)) == 2


def test_b2_condition_requires_base_url():
    target = Target(name="bench", kind=TargetKind.BENCHMARK, source_path="/tmp")
    with pytest.raises(ValueError, match="base_url"):
        get_condition("B2")().validate(target, ConditionContext())
