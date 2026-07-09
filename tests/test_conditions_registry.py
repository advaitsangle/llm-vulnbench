"""Cross-checks on the condition registry — a 'different angle' integrity test."""

import inspect
import re
from pathlib import Path

import pytest

from vulnbench.conditions import REGISTRY, get_condition
from vulnbench.conditions.base import Condition, ConditionContext, Knob, TriageCondition
from vulnbench.corpus import Target, TargetKind
from vulnbench.models import MockBackend


def test_registry_keys_match_class_ids():
    for key, cls in REGISTRY.items():
        assert cls.id == key, f"{cls.__name__}.id={cls.id!r} but registered as {key!r}"


def test_every_condition_has_a_label_and_is_a_condition():
    for cls in REGISTRY.values():
        assert issubclass(cls, Condition)
        assert cls.label, f"{cls.__name__} has no label"


def test_get_condition_is_case_insensitive():
    assert get_condition("b1") is get_condition("B1")


def test_get_unknown_condition_raises():
    with pytest.raises(KeyError):
        get_condition("Z9")


def test_model_requiring_conditions_validate_model_presence():
    target = Target(name="t", kind=TargetKind.BENCHMARK, source_path="/tmp")
    for cls in REGISTRY.values():
        if cls.needs_model:
            with pytest.raises(ValueError):
                cls().validate(target, ConditionContext(model=None))


# --- declared requirements ------------------------------------------------------
# The wizard reads these flags to decide what to prompt for, so they must agree with
# what validate() actually enforces. Otherwise it prompts for the wrong coordinate.

def test_needs_source_flag_matches_validate():
    model = MockBackend()
    for cls in REGISTRY.values():
        # A target with a URL but no source tree.
        target = Target(name="t", kind=TargetKind.BENCHMARK, base_url="http://x")
        if cls.needs_source:
            with pytest.raises(ValueError, match="source_path"):
                cls().validate(target, ConditionContext(model=model))


def test_needs_url_flag_matches_validate():
    model = MockBackend()
    for cls in REGISTRY.values():
        # A target with a source tree but no deployed URL.
        target = Target(name="t", kind=TargetKind.BENCHMARK, source_path="/tmp")
        if cls.needs_url:
            with pytest.raises(ValueError, match="base_url"):
                cls().validate(target, ConditionContext(model=model))


def test_every_condition_declares_at_least_one_input():
    """A condition that needs neither source nor URL has nothing to analyze."""
    for cls in REGISTRY.values():
        assert cls.needs_source or cls.needs_url, f"{cls.id} declares no input"


def test_triage_scan_in_relaxes_the_scanner_input_requirement():
    """Phase 2 works off saved findings, so it needs neither source tree nor URL."""
    bare = Target(name="t", kind=TargetKind.BENCHMARK)
    ctx = ConditionContext(model=MockBackend(), config={"scan_in": "/tmp/x.json"})
    for cls in REGISTRY.values():
        if issubclass(cls, TriageCondition):
            cls().validate(bare, ctx)  # must not raise


# --- declared knobs -------------------------------------------------------------
# The wizard renders whatever a condition declares, so these guard the contract that
# lets a new condition appear in the UI without the UI knowing about it.

def test_knob_names_are_unique_per_condition():
    for cls in REGISTRY.values():
        names = [k.name for k in cls.all_knobs()]
        assert len(names) == len(set(names)), f"{cls.id} declares a duplicate knob"


def test_triage_conditions_inherit_phasing_knobs():
    """scan_out/scan_in come from TriageCondition, not from each subclass restating them."""
    for cls in REGISTRY.values():
        if issubclass(cls, TriageCondition):
            names = {k.name for k in cls.all_knobs()}
            assert {"scan_out", "scan_in"} <= names, f"{cls.id} lost the phasing knobs"
            # ...and the subclass itself does not redeclare them.
            assert not {"scan_out", "scan_in"} & {k.name for k in vars(cls).get("knobs", ())}


def test_cfg_prefers_user_config_over_declared_default():
    cond = get_condition("B3")()
    assert cond.cfg(ConditionContext(), "max_file_bytes") == 60_000
    ctx = ConditionContext(config={"max_file_bytes": 5})
    assert cond.cfg(ctx, "max_file_bytes") == 5


def test_cfg_on_undeclared_knob_raises():
    cond = get_condition("B1")()
    with pytest.raises(KeyError, match="no knob named"):
        cond.cfg(ConditionContext(), "not_a_knob")


def test_every_cfg_read_names_a_declared_knob():
    """Catch a condition reading a knob it forgot to declare (its default would vanish)."""
    seen = 0
    for cid, cls in REGISTRY.items():
        src = Path(inspect.getsourcefile(cls)).read_text()
        declared = {k.name for k in cls.all_knobs()}
        used = set(re.findall(r"""self\.cfg\(ctx,\s*["'](\w+)["']""", src))
        seen += len(used)
        assert used <= declared, f"{cid} reads undeclared knob(s): {sorted(used - declared)}"
    assert seen, "regex matched nothing — the test would pass vacuously"


@pytest.mark.parametrize(
    ("ktype", "raw", "expected"),
    [
        ("int", "12", 12),
        ("float", "0.5", 0.5),
        ("bool", "yes", True),
        ("bool", "off", False),
        ("str", " p/java ", "p/java"),
        ("list", "40026, 40012", ["40026", "40012"]),
    ],
)
def test_knob_parse_coerces_user_text(ktype, raw, expected):
    assert Knob("k", ktype, None).parse(raw) == expected


def test_knob_parse_rejects_non_boolean():
    with pytest.raises(ValueError, match="expected yes/no"):
        Knob("k", "bool", True).parse("maybe")
