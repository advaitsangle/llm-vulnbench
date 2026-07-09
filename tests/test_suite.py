import pytest

from vulnbench import suite
from vulnbench.cli import main
from vulnbench.suite import (
    App,
    clone_command,
    is_installed,
    load_manifest,
    load_registry,
    parse_numeric_selection,
    pull_command,
    resolved_path,
)


def _app(key="x", path="x", repo="https://example.test/x.git"):
    return App(key=key, name=key, repo=repo, path=path, language="L", description="d")


def _seq(values):
    """A fake _prompt that returns queued answers, falling back to the supplied default."""
    it = iter(values)

    def fake(question, default=""):
        try:
            return next(it)
        except StopIteration:
            return default

    return fake


def test_manifest_ships_and_includes_known_apps():
    keys = {a.key for a in load_manifest()}
    assert {"juice-shop", "dvwa", "webgoat", "benchmark"} <= keys


def test_parse_numeric_selection_filters_and_dedups():
    assert parse_numeric_selection("1 3 3 9", count=4) == [0, 2]  # 9 out of range, dup dropped
    assert parse_numeric_selection("2,1", count=4) == [0, 1]      # commas, sorted
    assert parse_numeric_selection("nope", count=4) == []


def test_command_builders():
    app = _app(path="myapp", repo="https://example.test/r.git")
    dest = "/t/myapp"
    assert clone_command(app, dest) == ["git", "clone", "--depth", "1", app.repo, dest]
    assert pull_command(dest) == ["git", "-C", dest, "pull", "--depth", "1", "--ff-only"]


def test_resolved_path_prefers_registry_then_default(tmp_path):
    app = _app(path="myapp")
    reg = {}
    # nothing anywhere -> unlinked
    assert resolved_path(app, tmp_path, reg) is None
    # a clone at the default location is auto-recognized
    (tmp_path / "myapp").mkdir()
    assert resolved_path(app, tmp_path, reg) == tmp_path / "myapp"
    # an explicit reference wins over the default
    elsewhere = tmp_path / "somewhere" / "juice"
    elsewhere.mkdir(parents=True)
    reg = {"x": str(elsewhere)}
    assert resolved_path(app, tmp_path, reg) == elsewhere
    # a broken reference falls back to the default
    reg = {"x": str(tmp_path / "gone")}
    assert resolved_path(app, tmp_path, reg) == tmp_path / "myapp"


def test_is_installed_reflects_link(tmp_path):
    app = _app(path="myapp")
    assert not is_installed(app, root=tmp_path)
    (tmp_path / "myapp").mkdir()
    assert is_installed(app, root=tmp_path)


def test_resolve_installs_fresh_when_unlinked_batch(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(suite.subprocess, "run", lambda cmd, **kw: calls.append(cmd))
    monkeypatch.setattr(suite, "_is_interactive", lambda: False)
    app = _app(path="myapp")
    reg = {}
    status = suite._resolve_app(app, tmp_path, reg, update=False)
    assert "installed" in status
    assert calls and calls[0][:2] == ["git", "clone"]
    assert reg["x"] == str(tmp_path / "myapp")  # reference recorded


def test_resolve_point_to_existing_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(suite, "_is_interactive", lambda: True)
    existing = tmp_path / "i_already_have_juice"
    existing.mkdir()
    # answer "e" then the path to the copy I have lying around
    monkeypatch.setattr(suite, "_prompt", _seq(["e", str(existing)]))
    ran = []
    monkeypatch.setattr(suite.subprocess, "run", lambda cmd, **kw: ran.append(cmd))
    app = _app(path="myapp")
    reg = {}
    status = suite._resolve_app(app, tmp_path, reg, update=False)
    assert "linked" in status
    assert reg["x"] == str(existing.resolve())
    assert ran == []  # pointing at an existing copy clones nothing


def test_resolve_point_to_missing_dir_skips(tmp_path, monkeypatch):
    monkeypatch.setattr(suite, "_is_interactive", lambda: True)
    monkeypatch.setattr(suite, "_prompt", _seq(["e", str(tmp_path / "nope")]))
    app = _app(path="myapp")
    reg = {}
    status = suite._resolve_app(app, tmp_path, reg, update=False)
    assert "skipped" in status
    assert "x" not in reg


def test_resolve_update_pulls_a_git_link(tmp_path, monkeypatch):
    (tmp_path / "myapp" / ".git").mkdir(parents=True)
    ran = []
    monkeypatch.setattr(suite.subprocess, "run", lambda cmd, **kw: ran.append(cmd))
    app = _app(path="myapp")
    reg = {}
    status = suite._resolve_app(app, tmp_path, reg, update=True)
    assert "updated" in status
    assert ran and ran[0][:2] == ["git", "-C"]


def test_cli_targets_list(capsys):
    assert main(["targets", "--list"]) == 0
    out = capsys.readouterr().out
    # Assert on the app *keys*, which `--list` always prints. The capitalized
    # "WebGoat" only appears via a "linked → …/WebGoat" path, so asserting it
    # coupled the test to local link state (green locally, red on a clean CI
    # checkout where nothing is linked).
    assert "juice-shop" in out and "webgoat" in out


def test_cli_targets_path_lookup(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("VULNBENCH_TARGETS_DIR", str(tmp_path))
    key = load_manifest()[0].key
    # unlinked -> error
    assert main(["targets", "--path", key]) == 1
    # link it, then it prints the path
    suite.save_registry({key: str(tmp_path / "here")}, tmp_path)
    (tmp_path / "here").mkdir()
    assert main(["targets", "--path", key]) == 0
    assert str(tmp_path / "here") in capsys.readouterr().out


def test_cli_targets_non_interactive_requires_all(monkeypatch, capsys):
    monkeypatch.setattr(suite.sys.stdin, "isatty", lambda: False, raising=False)
    monkeypatch.setattr(suite.sys.stdout, "isatty", lambda: False, raising=False)
    assert main(["targets"]) == 2
    assert "Non-interactive" in capsys.readouterr().err


def test_cli_targets_all_yes_installs_and_records(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("VULNBENCH_TARGETS_DIR", str(tmp_path))
    ran = []
    monkeypatch.setattr(suite.subprocess, "run", lambda cmd, **kw: ran.append(cmd))
    assert main(["targets", "--all", "--yes"]) == 0
    apps = load_manifest()
    assert len(ran) == len(apps)
    assert all(c[:2] == ["git", "clone"] for c in ran)
    reg = load_registry(tmp_path)               # references persisted to registry.json
    assert {a.key for a in apps} <= set(reg)


def test_cli_targets_interactive_install(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("VULNBENCH_TARGETS_DIR", str(tmp_path))
    monkeypatch.setattr(suite, "_is_interactive", lambda: True)
    apps = load_manifest()
    monkeypatch.setattr(suite, "_interactive_select", lambda *a, **k: [apps[0]])
    monkeypatch.setattr(suite, "_prompt_yes_no", lambda *a, **k: True)
    monkeypatch.setattr(suite, "_prompt", lambda q, default="": default)  # take all defaults -> install
    ran = []
    monkeypatch.setattr(suite.subprocess, "run", lambda cmd, **kw: ran.append(cmd))

    assert main(["targets"]) == 0
    out = capsys.readouterr().out
    assert "Linked testing apps" in out and "nothing linked yet" in out
    assert "Available to add" in out
    assert len(ran) == 1 and ran[0][:2] == ["git", "clone"]
    assert "installed" in out


def test_cli_targets_gate_no_exits(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("VULNBENCH_TARGETS_DIR", str(tmp_path))
    monkeypatch.setattr(suite, "_is_interactive", lambda: True)
    monkeypatch.setattr(suite, "_prompt_yes_no", lambda *a, **k: False)
    assert main(["targets"]) == 0
    assert "Exited." in capsys.readouterr().out


def test_cli_targets_ctrl_c_is_clean(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("VULNBENCH_TARGETS_DIR", str(tmp_path))
    monkeypatch.setattr(suite, "_is_interactive", lambda: True)
    monkeypatch.setattr(suite, "_prompt_yes_no", lambda *a, **k: True)

    def boom(*a, **k):
        raise KeyboardInterrupt

    monkeypatch.setattr(suite, "_interactive_select", boom)
    assert main(["targets"]) == 130
    assert "Cancelled." in capsys.readouterr().out


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
