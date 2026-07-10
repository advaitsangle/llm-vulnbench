"""Unit tests for the external-tool preflight registry (no real installs, no daemons)."""

from __future__ import annotations

import pytest

from vulnbench import tools
from vulnbench.conditions import REGISTRY
from vulnbench.tools import TOOLS, Tool, get_tool, missing_tools, run_install


def _tool(key="t", available=True, install_cmd=None, startup_wait=0.0):
    return Tool(
        key=key, label=key.title(), hint="do it yourself",
        check=lambda _cfg: available, install_cmd=install_cmd, install_note="note",
        startup_wait=startup_wait,
    )


def test_every_condition_declares_known_tool_keys():
    """A typo'd key would only surface as a KeyError mid-preflight."""
    for cls in REGISTRY.values():
        for key in cls.all_tools():
            assert key in TOOLS, f"{cls.id} declares unknown tool {key!r}"


def test_semgrep_backed_conditions_declare_semgrep():
    for cid in ("B1", "C1", "C3"):
        assert "semgrep" in REGISTRY[cid].all_tools()


def test_zap_backed_conditions_declare_zap():
    for cid in ("B2", "C2"):
        assert "zap" in REGISTRY[cid].all_tools()


def test_pure_llm_conditions_need_no_external_tool():
    for cid in ("B3", "A1"):
        assert REGISTRY[cid].all_tools() == ()


def test_get_unknown_tool_raises():
    with pytest.raises(KeyError, match="Unknown tool"):
        get_tool("nope")


def test_missing_tools_reports_only_the_unavailable(monkeypatch):
    monkeypatch.setitem(TOOLS, "up", _tool("up", available=True))
    monkeypatch.setitem(TOOLS, "down", _tool("down", available=False))
    assert [t.key for t in missing_tools(["up", "down"], {})] == ["down"]


def test_missing_tools_dedups_repeated_keys(monkeypatch):
    """Two conditions can name the same scanner; the user should be asked once."""
    monkeypatch.setitem(TOOLS, "down", _tool("down", available=False))
    assert len(missing_tools(["down", "down"], {})) == 1


def test_zap_check_follows_the_zap_url_knob(monkeypatch):
    seen = []
    monkeypatch.setattr(tools, "_http_ok", lambda url, timeout=1.0: seen.append(url) or False)
    tools.ZAP.available({"zap_url": "http://example.test:1234"})
    assert seen == ["http://example.test:1234/JSON/core/view/version/"]


def test_run_install_without_a_command_is_a_no_op():
    assert run_install(_tool(install_cmd=None)) is False


def test_run_install_reports_failure_when_the_tool_is_still_absent(monkeypatch):
    """A install command that exits 0 but installs nothing must not report success."""
    monkeypatch.setattr(tools.subprocess, "run", lambda *a, **k: None)
    assert run_install(_tool(available=False, install_cmd=("true",))) is False


def test_run_install_succeeds_when_the_tool_appears(monkeypatch):
    monkeypatch.setattr(tools.subprocess, "run", lambda *a, **k: None)
    assert run_install(_tool(available=True, install_cmd=("true",))) is True


def test_run_install_survives_a_failing_command(monkeypatch):
    def boom(*a, **k):
        raise OSError("no such binary")

    monkeypatch.setattr(tools.subprocess, "run", boom)
    assert run_install(_tool(install_cmd=("nope",))) is False


def test_run_install_forwards_config_to_the_probe(monkeypatch):
    """ZAP must be verified at the zap_url the run will use, not at its default."""
    seen: list[dict] = []
    tool = Tool(key="z", label="z", hint="h", check=lambda cfg: seen.append(cfg) or True,
                install_cmd=("true",))
    monkeypatch.setattr(tools.subprocess, "run", lambda *a, **k: None)
    run_install(tool, {"zap_url": "http://x:1"})
    assert seen == [{"zap_url": "http://x:1"}]


def test_wait_until_available_polls_a_daemon_that_starts_late(monkeypatch):
    """`docker compose up -d` returns before ZAP binds its port; one probe would miss it."""
    monkeypatch.setattr(tools, "_POLL_INTERVAL", 0)
    attempts = iter([False, False, True])
    tool = Tool(key="z", label="z", hint="h", check=lambda _c: next(attempts),
                install_cmd=("true",), startup_wait=60.0)
    monkeypatch.setattr(tools.subprocess, "run", lambda *a, **k: None)
    assert run_install(tool) is True


def test_wait_until_available_gives_up_at_the_deadline(monkeypatch):
    monkeypatch.setattr(tools, "_POLL_INTERVAL", 0)
    tool = _tool(available=False, install_cmd=("true",), startup_wait=0.01)
    monkeypatch.setattr(tools.subprocess, "run", lambda *a, **k: None)
    assert run_install(tool) is False


def test_zap_declares_a_startup_wait_and_semgrep_does_not():
    """A pip install is usable the moment pip exits; a container is not."""
    assert tools.ZAP.startup_wait > 0
    assert tools.SEMGREP.startup_wait == 0


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))


def test_install_command_static_and_factory():
    assert _tool(install_cmd=("true",)).install_command() == ("true",)
    assert _tool().install_command() is None
    # A factory is consulted at ask time, so its answer can change after import.
    docker_up = {"present": False}
    tool = Tool(key="t", label="t", hint="h", check=lambda _c: False,
                install_cmd_factory=lambda: ("up",) if docker_up["present"] else None)
    assert tool.install_command() is None
    docker_up["present"] = True
    assert tool.install_command() == ("up",)


def test_run_install_uses_factory_command():
    tool = Tool(key="t", label="t", hint="h", check=lambda _c: True,
                install_cmd_factory=lambda: None)
    assert run_install(tool) is False  # nothing to run right now
