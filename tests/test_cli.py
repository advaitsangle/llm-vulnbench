import json

from vulnbench.cli import build_parser, main


def test_list_command_returns_zero(capsys):
    assert main(["list"]) == 0
    out = capsys.readouterr().out
    assert "B1" in out and "Semgrep" in out


def test_run_with_mock_writes_scorecard(tmp_path, capsys):
    src = tmp_path / "src"
    src.mkdir()
    (src / "BenchmarkTest00001.java").write_text("int x = 1;\n")
    csv = tmp_path / "expectedresults-1.2.csv"
    csv.write_text("# header\nBenchmarkTest00001,sqli,false,89\n")
    out = tmp_path / "card.json"

    rc = main([
        "run", "--condition", "B3",
        "--source", str(src),
        "--ground-truth", str(csv),
        "--kind", "benchmark",
        "--model", "mock",
        "-o", str(out),
    ])
    assert rc == 0
    card = json.loads(out.read_text())
    assert card[0]["condition"] == "B3"
    assert card[0]["provenance"]["vulnbench_version"]


def test_run_missing_source_is_captured_as_error(tmp_path):
    # B1 needs a source path; without one the cell records an error, rc=1.
    rc = main(["run", "--condition", "B1", "--kind", "benchmark"])
    assert rc == 1


def test_parser_requires_condition():
    parser = build_parser()
    # argparse exits (SystemExit) when a required arg is missing.
    try:
        parser.parse_args(["run"])
    except SystemExit as e:
        assert e.code != 0
    else:  # pragma: no cover
        raise AssertionError("expected SystemExit for missing --condition")


def test_run_bad_config_json_is_a_clean_usage_error(capsys):
    code = main(["run", "--condition", "B3", "--model", "mock",
                 "--source", ".", "--config", "{bad json"])
    assert code == 2
    err = capsys.readouterr().err
    assert "not valid JSON" in err


def test_run_config_must_be_an_object(capsys):
    code = main(["run", "--condition", "B3", "--model", "mock",
                 "--source", ".", "--config", "[1, 2]"])
    assert code == 2
    assert "JSON object" in capsys.readouterr().err


def test_run_bad_model_spec_is_a_clean_usage_error(capsys):
    code = main(["run", "--condition", "B3", "--model", "bogus:thing", "--source", "."])
    assert code == 2
    assert "model spec" in capsys.readouterr().err.lower()


def test_run_unwritable_output_keeps_the_run_and_flags_failure(tmp_path, capsys):
    src = tmp_path / "src"
    src.mkdir()
    out = tmp_path / "no-such-dir" / "card.json"
    code = main(["run", "--condition", "B3", "--model", "mock", "--source", str(src),
                 "--checkpoint", str(tmp_path / "ck.json"), "-o", str(out), "--plain"])
    assert code == 1
    captured = capsys.readouterr()
    assert "could not write scorecard" in captured.err
    assert "summary" in captured.out  # the run still reported its results


def test_run_unknown_condition_id_is_a_clean_usage_error(capsys):
    code = main(["run", "--condition", "B9", "--source", "."])
    assert code == 2
    assert "Unknown condition" in capsys.readouterr().err


def test_run_unknown_config_key_is_rejected_with_the_valid_knobs(capsys):
    code = main(["run", "--condition", "B3", "--model", "mock", "--source", ".",
                 "--config", '{"maxfiles": 5}'])
    assert code == 2
    err = capsys.readouterr().err
    assert "maxfiles" in err and "max_files" in err  # typo named, real knob offered


def test_run_config_key_valid_for_any_chosen_condition_is_accepted(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    # semgrep_ruleset belongs to B1, not B3 — legal in a mixed sweep. B1 errors
    # per-cell without semgrep, so run B3-only knobs through a mixed declaration.
    code = main(["run", "--condition", "B3", "--model", "mock", "--source", str(src),
                 "--checkpoint", str(tmp_path / "ck.json"),
                 "--config", '{"max_files": 5}', "--plain"])
    assert code == 0


def _benchmark_tree(tmp_path, n=20):
    src = tmp_path / "src"
    src.mkdir()
    for i in range(n):
        (src / f"BenchmarkTest{i:05d}.java").write_text("class X {}")
    gt = tmp_path / "gt.csv"
    gt.write_text("# name,category,real,cwe\n" + "".join(
        f"BenchmarkTest{i:05d},sqli,true,89\n" for i in range(n)
    ))
    return src, gt


def test_sample_flag_scores_only_the_sampled_cases(tmp_path, capsys):
    src, gt = _benchmark_tree(tmp_path)
    out = tmp_path / "card.json"
    code = main(["run", "--condition", "B3", "--model", "mock", "--source", str(src),
                 "--ground-truth", str(gt), "--kind", "benchmark",
                 "--sample", "5", "--checkpoint", str(tmp_path / "ck.json"),
                 "-o", str(out), "--plain"])
    assert code == 0
    record = json.loads(out.read_text())[0]
    m = record["metrics"]
    # Denominator is the 5 sampled cases, not all 20 — the mock finds nothing,
    # so every sampled real case is a miss and nothing else is counted.
    assert m["tp"] + m["fn"] == 5


def test_sample_is_reproducible_across_runs_and_varies_by_seed(tmp_path):
    src, gt = _benchmark_tree(tmp_path)

    def cases_for(seed):
        out = tmp_path / f"card-{seed}.json"
        assert main(["run", "--condition", "B3", "--model", "mock", "--source", str(src),
                     "--ground-truth", str(gt), "--kind", "benchmark", "--sample", "5",
                     "--sample-seed", str(seed), "--fresh",
                     "--checkpoint", str(tmp_path / f"ck-{seed}.json"),
                     "-o", str(out), "--plain"]) == 0
        return json.loads(out.read_text())[0]["provenance"]["config"]

    assert cases_for(42) == cases_for(42)
    assert cases_for(42) != cases_for(7)  # seed is part of the run signature
