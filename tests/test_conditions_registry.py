"""Cross-checks on the condition registry — a 'different angle' integrity test."""

import pytest

from vulnbench.conditions import REGISTRY, get_condition
from vulnbench.conditions.base import Condition, ConditionContext
from vulnbench.conditions.stubs import _Planned
from vulnbench.corpus import Target, TargetKind


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


def test_planned_stubs_raise_not_implemented():
    target = Target(name="t", kind=TargetKind.REALISTIC, source_path="/tmp")
    for cls in REGISTRY.values():
        if issubclass(cls, _Planned):
            with pytest.raises(NotImplementedError):
                cls().run(target, ConditionContext())


def test_model_requiring_conditions_validate_model_presence():
    target = Target(name="t", kind=TargetKind.BENCHMARK, source_path="/tmp")
    for cls in REGISTRY.values():
        if cls.needs_model:
            with pytest.raises(ValueError):
                cls().validate(target, ConditionContext(model=None))
