from vulnbench.conditions.llm_common import parse_findings
from vulnbench.schema import LocationKind, Verdict


def test_parse_clean_json():
    text = '{"findings": [{"cwe": 89, "file": "a.java", "line": 12, ' \
           '"verdict": "confirmed", "confidence": 0.9, "evidence": "concat"}]}'
    findings = parse_findings(text, "B3")
    assert len(findings) == 1
    f = findings[0]
    assert f.vuln_class == 89
    assert f.location.file == "a.java"
    assert f.location.line == 12
    assert f.verdict is Verdict.CONFIRMED
    assert f.source_condition == "B3"


def test_parse_json_in_markdown_fence_with_preamble():
    text = "Sure, here you go:\n```json\n{\"findings\": [{\"cwe\": 79, " \
           "\"url\": \"http://x/p\", \"param\": \"q\", \"verdict\": \"candidate\"}]}\n```"
    findings = parse_findings(text, "C2")
    assert len(findings) == 1
    assert findings[0].vuln_class == 79
    assert findings[0].location.kind is LocationKind.ENDPOINT
    assert findings[0].location.param == "q"


def test_parse_empty_findings():
    assert parse_findings('{"findings": []}', "B3") == []


def test_parse_unparseable_returns_empty():
    assert parse_findings("the model refused and wrote prose only", "B3") == []
    assert parse_findings("", "B3") == []


def test_confidence_is_clamped():
    text = '{"findings": [{"cwe": 1, "file": "a", "confidence": 5.0}, ' \
           '{"cwe": 2, "file": "b", "confidence": -1}]}'
    findings = parse_findings(text, "B3")
    assert findings[0].confidence == 1.0
    assert findings[1].confidence == 0.0


def test_invalid_verdict_becomes_none():
    text = '{"findings": [{"cwe": 1, "file": "a", "verdict": "definitely-real"}]}'
    assert parse_findings(text, "B3")[0].verdict is None


def test_missing_cwe_defaults_to_zero():
    text = '{"findings": [{"file": "a", "verdict": "confirmed"}]}'
    assert parse_findings(text, "B3")[0].vuln_class == 0
