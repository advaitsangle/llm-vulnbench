from vulnbench.scanners.semgrep_runner import (
    _confidence,
    findings_from_semgrep_json,
    parse_cwe,
)


def test_parse_cwe_from_string_and_list():
    assert parse_cwe({"cwe": "CWE-89: SQL Injection"}) == 89
    assert parse_cwe({"cwe": ["CWE-79: XSS"]}) == 79
    assert parse_cwe({}) == 0
    assert parse_cwe({"cwe": None}) == 0


def test_confidence_label_mapping():
    assert _confidence("HIGH") == 0.9
    assert _confidence("MEDIUM") == 0.6
    assert _confidence("LOW") == 0.3
    assert _confidence(None) == 0.7  # unknown -> neutral default


def test_empty_results_yields_no_findings():
    assert findings_from_semgrep_json({"results": []}, "B1") == []
    assert findings_from_semgrep_json({}, "B1") == []


def test_findings_from_semgrep_json():
    doc = {
        "results": [
            {
                "check_id": "java.lang.security.audit.sqli",
                "path": "src/BenchmarkTest00001.java",
                "start": {"line": 12, "col": 4},
                "extra": {
                    "message": "Possible SQL injection",
                    "metadata": {"cwe": "CWE-89: SQL Injection", "confidence": "HIGH"},
                },
            }
        ]
    }
    findings = findings_from_semgrep_json(doc, "B1")
    assert len(findings) == 1
    f = findings[0]
    assert f.vuln_class == 89
    assert f.location.file == "src/BenchmarkTest00001.java"
    assert f.location.line == 12
    assert f.confidence == 0.9
    assert f.source_condition == "B1"
