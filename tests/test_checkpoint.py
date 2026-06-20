import json

from vulnbench.checkpoint import Checkpoint, default_path, signature
from vulnbench.harness import RunRecord
from vulnbench.schema import Finding, Location


def _sig(**over):
    base = dict(
        target_name="t", kind="benchmark", source="./src", url=None,
        ground_truth="gt.csv", model="mock", config={},
    )
    base.update(over)
    return signature(**base)


def _record(cid="B3"):
    return RunRecord(
        target="t", condition=cid, model="mock", metrics={"f1": 0.5},
        input_tokens=1, output_tokens=2, seconds=0.1, model_seconds=0.0, n_findings=1,
    )


def _finding():
    return Finding(vuln_class=89, location=Location.for_test_case("BenchmarkTest00001"),
                   source_condition="B3")


def test_put_get_roundtrip(tmp_path):
    path = tmp_path / "ckpt.json"
    ck = Checkpoint(path, _sig())
    ck.put("B3", _record(), [_finding()])

    # Fresh handle over the same file resumes the saved cell.
    ck2 = Checkpoint(path, _sig())
    assert ck2.resumed == 1
    got = ck2.get("B3")
    assert got is not None
    record, findings = got
    assert record.condition == "B3" and record.metrics["f1"] == 0.5
    assert findings[0].vuln_class == 89


def test_signature_mismatch_starts_fresh(tmp_path):
    path = tmp_path / "ckpt.json"
    Checkpoint(path, _sig()).put("B3", _record(), [])
    # A different model is a different run: the old cells must not be reused.
    ck = Checkpoint(path, _sig(model="api:anthropic:x"))
    assert ck.resumed == 0
    assert ck.get("B3") is None


def test_resume_false_ignores_existing(tmp_path):
    path = tmp_path / "ckpt.json"
    Checkpoint(path, _sig()).put("B3", _record(), [])
    ck = Checkpoint(path, _sig(), resume=False)
    assert ck.resumed == 0


def test_corrupt_checkpoint_is_ignored(tmp_path):
    path = tmp_path / "ckpt.json"
    path.write_text("{ not json")
    ck = Checkpoint(path, _sig())
    assert ck.resumed == 0


def test_flush_is_atomic_and_valid_json(tmp_path):
    path = tmp_path / "ckpt.json"
    ck = Checkpoint(path, _sig())
    ck.put("B3", _record(), [_finding()])
    data = json.loads(path.read_text())
    assert data["signature"] == _sig()
    assert "B3" in data["cells"]
    assert not path.with_suffix(path.suffix + ".tmp").exists()  # temp file cleaned up


def test_default_path_is_stable_and_under_runs():
    p1 = default_path(_sig())
    p2 = default_path(_sig())
    assert p1 == p2
    assert p1.parent.name == "runs"
    assert default_path(_sig(model="other")) != p1
