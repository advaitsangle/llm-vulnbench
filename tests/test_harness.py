import pytest

from vulnbench.corpus import Target, TargetKind
from vulnbench.harness import run_one
from vulnbench.models import MockBackend


def _benchmark(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "BenchmarkTest00001.java").write_text("int x = 1;\n")
    csv = tmp_path / "expectedresults-1.2.csv"
    csv.write_text("# header\nBenchmarkTest00001,sqli,false,89\n")
    return Target("fix", TargetKind.BENCHMARK, source_path=str(src), ground_truth=str(csv))


def test_record_carries_provenance(tmp_path):
    record, _ = run_one(_benchmark(tmp_path), "B3", model=MockBackend(), config={"max_files": 1})
    assert record.provenance["vulnbench_version"]
    assert record.provenance["timestamp_utc"].endswith("+00:00")
    assert record.provenance["config"] == {"max_files": 1}


def test_total_latency_is_at_least_model_latency(tmp_path):
    record, _ = run_one(_benchmark(tmp_path), "B3", model=MockBackend())
    assert record.seconds >= record.model_seconds


def test_debug_reraises_instead_of_capturing(tmp_path):
    # B1 without a source path fails validation (raises ValueError).
    target = Target("nosrc", TargetKind.BENCHMARK, ground_truth=str(tmp_path / "gt.csv"))
    with pytest.raises(ValueError):
        run_one(target, "B1", debug=True)
    # Without debug, the error is captured into the record.
    record, _ = run_one(target, "B1", debug=False)
    assert record.error is not None


def test_ground_truth_cache_is_populated(tmp_path):
    target = _benchmark(tmp_path)
    cache: dict = {}
    run_one(target, "B3", model=MockBackend(), ground_truth_cache=cache)
    assert target.ground_truth in cache


def test_no_ground_truth_skips_metrics(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "BenchmarkTest00001.java").write_text("int x = 1;\n")
    target = Target("nogt", TargetKind.BENCHMARK, source_path=str(src))
    record, _ = run_one(target, "B3", model=MockBackend())
    assert record.metrics is None
