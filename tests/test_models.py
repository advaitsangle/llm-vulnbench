import pytest

from vulnbench.models import Usage, build_backend
from vulnbench.models import MockBackend


def test_build_mock():
    b = build_backend("mock")
    assert isinstance(b, MockBackend)
    assert b.name == "mock"


def test_build_local_does_not_touch_network():
    # Constructing an Ollama backend must not require a running daemon.
    b = build_backend("local:qwen3-coder:14b")
    assert b.name == "local:qwen3-coder:14b"
    assert b.model == "qwen3-coder:14b"


def test_build_local_default_model():
    b = build_backend("local")
    assert b.model == "qwen3-coder:14b"


def test_build_unknown_provider_raises():
    with pytest.raises(ValueError):
        build_backend("api:openai:gpt-4")


def test_build_garbage_spec_raises():
    with pytest.raises(ValueError):
        build_backend("not-a-spec")


def test_mock_completion_is_schema_valid_json():
    b = MockBackend()
    c = b.complete([{"role": "user", "content": "hi"}])
    assert c.text == '{"findings": []}'
    # complete() must stamp latency onto usage.
    assert c.usage.seconds >= 0.0


def test_usage_addition():
    total = Usage(1, 2, 0.5) + Usage(3, 4, 1.5)
    assert (total.input_tokens, total.output_tokens, total.seconds) == (4, 6, 2.0)
