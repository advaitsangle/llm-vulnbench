from vulnbench.schema import Finding, Location
from vulnbench.scoring.owasp_benchmark import ExpectedCase, score_benchmark


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


def test_scanned_restricts_scope_for_partial_runs():
    # A run that only examined case 00001 should be scored over just that case,
    # not penalized as a miss for the unscanned real case 00003.
    findings = [_finding("BenchmarkTest00001", 89)]
    m = score_benchmark(findings, _expected(), scanned={"BenchmarkTest00001"})
    assert (m.tp, m.fp, m.fn, m.tn) == (1, 0, 0, 0)
    assert m.recall == 1.0  # without the scope, 00003 would drag recall to 0.5


def test_unscanned_real_case_still_counts_without_scope():
    # Same findings, but no scope -> the unscanned real case 00003 is a miss.
    findings = [_finding("BenchmarkTest00001", 89)]
    m = score_benchmark(findings, _expected())
    assert m.fn == 1
    assert m.recall == 0.5


def test_malformed_ground_truth_row_reports_file_and_line(tmp_path):
    import pytest

    from vulnbench.scoring.owasp_benchmark import load_expected_results

    gt = tmp_path / "gt.csv"
    gt.write_text("# header\nBenchmarkTest00001,sqli,true,not-a-number\n")
    with pytest.raises(ValueError, match=r"gt\.csv:2.*not-a-number"):
        load_expected_results(str(gt))
    gt.write_text("BenchmarkTest00001,sqli\n")  # too few columns
    with pytest.raises(ValueError, match=r"gt\.csv:1"):
        load_expected_results(str(gt))


def test_sample_source_files_is_seeded_and_reproducible(tmp_path):
    from vulnbench.conditions.source_files import sample_source_files

    for i in range(20):
        (tmp_path / f"BenchmarkTest{i:05d}.java").write_text("class X {}")
    a = sample_source_files(str(tmp_path), 5, seed=42)
    b = sample_source_files(str(tmp_path), 5, seed=42)
    c = sample_source_files(str(tmp_path), 5, seed=7)
    assert len(a) == 5
    assert a == b            # same seed => same slice, on any machine or re-run
    assert a != c            # a different seed picks different files
    assert a == sorted(a)    # deterministic downstream iteration order


def test_sample_larger_than_the_tree_returns_every_file(tmp_path):
    from vulnbench.conditions.source_files import sample_source_files

    (tmp_path / "a.java").write_text("x")
    (tmp_path / "b.java").write_text("y")
    assert len(sample_source_files(str(tmp_path), 99, seed=1)) == 2


def test_sample_rejects_a_negative_size(tmp_path):
    import pytest

    from vulnbench.conditions.source_files import sample_source_files

    with pytest.raises(ValueError, match="must not be negative"):
        sample_source_files(str(tmp_path), -5, seed=1)
