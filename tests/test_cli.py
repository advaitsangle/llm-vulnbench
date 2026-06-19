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
