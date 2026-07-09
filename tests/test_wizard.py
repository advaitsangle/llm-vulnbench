"""Unit tests for the interactive session: the sweep plan, preflight, and file output.

The menus themselves are the shared widget (tested in test_tui.py); here we cover the
logic that turns selections into cells and the two paths that used to end in a
traceback: a missing scanner and a bad scorecard path.
"""

from __future__ import annotations

import json

import pytest

from vulnbench import wizard
from vulnbench.conditions import get_condition
from vulnbench.corpus import Target, TargetKind
from vulnbench.harness import RunRecord
from vulnbench.tools import TOOLS, Tool
from vulnbench.wizard import (
    plan_configs,
    required_inputs,
    required_tools,
    tunable_knobs,
    wiring_needed,
)


def _target(name="bench", **kw):
    kw.setdefault("kind", TargetKind.BENCHMARK)
    return Target(name=name, **kw)


def _record(condition="B1", error=None):
    return RunRecord(
        target="t", condition=condition, model=None, metrics=None, input_tokens=0,
        output_tokens=0, seconds=0.0, model_seconds=0.0, n_findings=0, error=error,
    )


# --- the plan -------------------------------------------------------------------

def test_plan_is_the_cartesian_product_for_model_driven_conditions():
    t1, t2 = _target("a"), _target("b")
    cfgs = plan_configs([t1, t2], ["B3", "C1"], ["mock", "local:x"])
    assert len(cfgs) == 2 * 2 * 2
    assert {(c.target.name, c.condition_id, c.model_spec) for c in cfgs} == {
        (t, c, m) for t in ("a", "b") for c in ("B3", "C1") for m in ("mock", "local:x")
    }


def test_scanner_only_conditions_run_once_per_target_not_once_per_model():
    """B1 ignores the model, so sweeping it across models would rescan for nothing."""
    cfgs = plan_configs([_target("a")], ["B1"], ["mock", "local:x", "api:anthropic:y"])
    assert len(cfgs) == 1
    assert cfgs[0].model_spec is None
    assert cfgs[0].model_name == "—"


def test_mixed_plan_dedups_only_the_scanner_only_cells():
    # 1 target x (B1 once) + (C1 x 2 models) = 3, not 1x2x2 = 4.
    cfgs = plan_configs([_target("a")], ["B1", "C1"], ["mock", "local:x"])
    assert len(cfgs) == 3
    assert sum(1 for c in cfgs if c.condition_id == "B1") == 1
    assert sum(1 for c in cfgs if c.condition_id == "C1") == 2


def test_plan_is_target_major_then_model():
    """Matches the grouping the comparative matrix collapses on."""
    cfgs = plan_configs([_target("a"), _target("b")], ["C1"], ["m1", "m2"])
    assert [(c.target.name, c.model_spec) for c in cfgs] == [
        ("a", "m1"), ("a", "m2"), ("b", "m1"), ("b", "m2"),
    ]


def test_plan_with_only_scanner_conditions_ignores_models_entirely():
    assert len(plan_configs([_target()], ["B1"], [])) == 1


def test_plan_with_no_models_drops_model_driven_conditions():
    cfgs = plan_configs([_target()], ["B1", "C1"], [])
    assert [c.condition_id for c in cfgs] == ["B1"]


# --- what a sweep needs ---------------------------------------------------------

def test_required_inputs_unions_across_conditions():
    assert required_inputs(["B1"]) == (True, False)       # source only
    assert required_inputs(["B2"]) == (False, True)       # url only
    assert required_inputs(["B1", "B2"]) == (True, True)  # both


def test_required_tools_covers_conditions_and_local_models():
    assert required_tools(["B1"], ["mock"]) == ["semgrep"]
    assert required_tools(["B3"], ["mock"]) == []
    assert required_tools(["B3"], ["local:qwen"]) == ["ollama"]
    assert required_tools(["B1", "C1"], ["local:qwen"]) == ["semgrep", "ollama"]  # deduped


def test_required_tools_ignores_api_models():
    assert required_tools(["B3"], ["api:anthropic:claude-opus-4-8"]) == []


def test_required_tools_treats_a_bare_local_spec_as_ollama():
    """`local` (no colon) is a valid spec meaning the default Ollama model."""
    assert required_tools(["B3"], ["local"]) == ["ollama"]


# --- knob prompting -------------------------------------------------------------

def test_knob_with_a_none_default_reads_as_unset_not_the_word_none():
    knob = get_condition("B2").knob("zap_seed_limit")
    assert wizard._default_text(knob) == "unset"


def test_blank_on_an_optional_knob_leaves_it_out_of_the_config(monkeypatch):
    """Pressing <enter> on a None-default knob must not inject None-ish junk.

    Echoing str(None) back would make an int knob raise on every <enter> forever, and
    make a path knob resolve to the literal file "None".
    """
    monkeypatch.setattr(wizard, "prompt", lambda q, default="": default)
    for name in ("zap_seed_limit", "zap_seed_crawler"):
        knob = get_condition("B2").knob(name)
        assert wizard._prompt_knob(knob) is wizard._UNSET


def test_blank_on_a_required_knob_takes_its_declared_default(monkeypatch):
    monkeypatch.setattr(wizard, "prompt", lambda q, default="": default)
    knob = get_condition("B3").knob("max_file_bytes")
    assert wizard._prompt_knob(knob) == 60_000


def test_prompt_knob_reprompts_until_the_value_parses(monkeypatch, capsys):
    answers = iter(["not-a-number", "12"])
    monkeypatch.setattr(wizard, "prompt", lambda q, default="": next(answers))
    assert wizard._prompt_knob(get_condition("B3").knob("max_files")) == 12
    assert "invalid literal" in capsys.readouterr().out


def test_choose_knobs_accepting_every_default_never_injects_none_ish_junk(monkeypatch):
    """Select every knob, press <enter> on each: the config must stay usable."""
    monkeypatch.setattr(wizard, "prompt_yes_no", lambda q, default: True)
    monkeypatch.setattr(wizard, "select",
                        lambda rows, pre=None: list(range(len(rows))))
    monkeypatch.setattr(wizard, "prompt", lambda q, default="": default)

    config = wizard._choose_knobs(["B2"])
    assert None not in config.values()
    assert "None" not in config.values()
    # Optional knobs (default None) are left out entirely, so the condition's own
    # default applies rather than a stringified sentinel.
    for name, (knob, _) in tunable_knobs(["B2"]).items():
        if knob.default is None:
            assert name not in config
    # An int knob accepting its default round-trips as an int, not as text.
    assert wizard._choose_knobs(["B3"])["max_file_bytes"] == 60_000


def test_tunable_knobs_maps_each_knob_to_its_conditions():
    knobs = tunable_knobs(["B1", "C1"])
    assert knobs["semgrep_ruleset"][1] == ["B1", "C1"]   # both read it


def test_tunable_knobs_hides_advanced_phasing_knobs():
    """scan_out/scan_in wire two runs together; they don't parameterize one sweep."""
    assert "scan_in" not in tunable_knobs(["C1"])
    assert "scan_out" not in tunable_knobs(["C1"])


def test_wiring_needed_only_when_a_coordinate_is_missing():
    complete = _target(source_path="/s", ground_truth="/g")
    assert not wiring_needed([complete], ["B1"])
    assert wiring_needed([_target(ground_truth="/g")], ["B1"])            # no source
    assert wiring_needed([_target(source_path="/s")], ["B1"])             # no ground truth
    # B1 wants no URL, so a missing base_url is not a gap.
    assert not wiring_needed([complete], ["B1"])


# --- preflight ------------------------------------------------------------------

def _fake_tool(key, available, install_cmd=None):
    return Tool(key=key, label=key, hint="hint", check=lambda _c: available,
                install_cmd=install_cmd, install_note="note")


def test_preflight_passes_when_nothing_is_missing(monkeypatch):
    monkeypatch.setitem(TOOLS, "semgrep", _fake_tool("semgrep", True))
    assert wizard._preflight(["B1"], ["mock"], {}) is True


def test_preflight_offers_install_and_proceeds_on_success(monkeypatch, capsys):
    monkeypatch.setitem(TOOLS, "semgrep", _fake_tool("semgrep", False, install_cmd=("x",)))
    monkeypatch.setattr(wizard, "prompt_yes_no", lambda q, default: True)
    # Simulate the install working: the tool is available on the re-check afterwards.
    def install(_tool, _config=None):
        TOOLS["semgrep"] = _fake_tool("semgrep", True)
        return True

    monkeypatch.setattr(wizard, "run_install", install)
    assert wizard._preflight(["B1"], ["mock"], {}) is True
    assert "installed" in capsys.readouterr().out


def test_preflight_aborts_when_user_declines_to_continue(monkeypatch, capsys):
    monkeypatch.setitem(TOOLS, "zap", _fake_tool("zap", False))
    monkeypatch.setattr(wizard, "prompt_yes_no", lambda q, default: False)
    assert wizard._preflight(["B2"], ["mock"], {}) is False
    assert "Still unavailable" in capsys.readouterr().out


def test_preflight_can_continue_without_the_tool(monkeypatch):
    # No install_cmd, so the only question asked is "continue anyway?".
    monkeypatch.setitem(TOOLS, "zap", _fake_tool("zap", False))
    monkeypatch.setattr(wizard, "prompt_yes_no", lambda q, default: True)
    assert wizard._preflight(["B2"], ["mock"], {}) is True


def test_preflight_does_not_offer_an_install_it_cannot_perform(monkeypatch):
    asked: list[str] = []
    monkeypatch.setitem(TOOLS, "zap", _fake_tool("zap", False))  # install_cmd=None
    monkeypatch.setattr(wizard, "prompt_yes_no",
                        lambda q, default: asked.append(q) or False)
    wizard._preflight(["B2"], ["mock"], {})
    assert not any("Install now" in q for q in asked)


def test_preflight_failed_install_falls_back_to_the_hint(monkeypatch, capsys):
    monkeypatch.setitem(TOOLS, "semgrep", _fake_tool("semgrep", False, install_cmd=("x",)))
    monkeypatch.setattr(wizard, "prompt_yes_no", lambda q, default: "Install" in q)
    monkeypatch.setattr(wizard, "run_install", lambda _t, _cfg=None: False)
    assert wizard._preflight(["B1"], ["mock"], {}) is False
    out = capsys.readouterr().out
    assert "install failed" in out and "hint" in out


def test_preflight_shows_the_hint_when_no_install_command_exists(monkeypatch, capsys):
    monkeypatch.setitem(TOOLS, "ollama", Tool(
        key="ollama", label="Ollama", hint="install from ollama.com", check=lambda _c: False))
    monkeypatch.setattr(wizard, "prompt_yes_no", lambda q, default: False)
    wizard._preflight(["B3"], ["local:qwen"], {})
    assert "install from ollama.com" in capsys.readouterr().out


# --- scorecard output -----------------------------------------------------------

def test_write_scorecard_skips_on_blank(monkeypatch):
    monkeypatch.setattr(wizard, "prompt", lambda q, default="": "")
    assert wizard._write_scorecard([_record()], []) == {}


def test_write_scorecard_reprompts_on_a_directory(monkeypatch, tmp_path, capsys):
    good = tmp_path / "card.json"
    answers = iter([str(tmp_path), str(good)])   # first a dir, then a real file
    monkeypatch.setattr(wizard, "prompt", lambda q, default="": next(answers))
    paths = wizard._write_scorecard([_record()], [])
    assert paths["scorecard"] == str(good)
    assert "is a directory" in capsys.readouterr().out
    assert json.loads(good.read_text())[0]["condition"] == "B1"


def test_write_scorecard_reprompts_on_a_missing_parent(monkeypatch, tmp_path, capsys):
    good = tmp_path / "card.json"
    answers = iter([str(tmp_path / "nope" / "deep.json"), str(good)])
    monkeypatch.setattr(wizard, "prompt", lambda q, default="": next(answers))
    wizard._write_scorecard([_record()], [])
    assert "no such directory" in capsys.readouterr().out


def test_write_scorecard_also_writes_a_findings_file(monkeypatch, tmp_path):
    card = tmp_path / "card.json"
    monkeypatch.setattr(wizard, "prompt", lambda q, default="": str(card))
    paths = wizard._write_scorecard([_record()], [])
    assert (tmp_path / "card.findings.json").is_file()
    assert "0 findings" in paths


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
