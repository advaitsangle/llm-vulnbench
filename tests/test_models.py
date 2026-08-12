import json

import pytest

from vulnbench.models import MockBackend, Usage, build_backend, ollama_backend
from vulnbench.models.ollama_backend import DEFAULT_NUM_CTX, DEFAULT_SEED, OllamaBackend


def test_build_mock():
    b = build_backend("mock")
    assert isinstance(b, MockBackend)
    assert b.name == "mock"


def test_build_local_does_not_touch_network():
    # Constructing an Ollama backend must not require a running daemon.
    b = build_backend("local:qwen2.5-coder:14b")
    assert b.name == "local:qwen2.5-coder:14b"
    assert b.model == "qwen2.5-coder:14b"


def test_build_local_default_model():
    b = build_backend("local")
    assert b.model == "qwen2.5-coder:14b"


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


def _capture_ollama_payload(monkeypatch, backend) -> dict:
    """Run one completion against a stubbed daemon; return the request body sent."""
    sent: dict = {}

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return b'{"message": {"content": "{}"}}'

    def _fake_urlopen(req, timeout=None):
        sent.update(json.loads(req.data.decode("utf-8")))
        return _Resp()

    monkeypatch.setattr(ollama_backend.urllib.request, "urlopen", _fake_urlopen)
    backend.complete([{"role": "user", "content": "hi"}])
    return sent


def test_ollama_requests_an_explicit_context_window(monkeypatch):
    # Ollama silently truncates past its own small default, which would show up as
    # an accuracy difference between conditions rather than as an error. The window
    # must be stated on every request, never left to the daemon.
    payload = _capture_ollama_payload(monkeypatch, OllamaBackend())
    assert payload["options"]["num_ctx"] == DEFAULT_NUM_CTX


def test_ollama_context_window_is_overridable(monkeypatch):
    payload = _capture_ollama_payload(monkeypatch, OllamaBackend(num_ctx=8192))
    assert payload["options"]["num_ctx"] == 8192


def test_ollama_pins_the_sampling_seed(monkeypatch):
    # Left unset, Ollama seeds the sampler from the clock, so re-running a scored
    # condition draws a different completion and the number cannot be checked. The
    # seed must be on every request, not only on the ones that pass it explicitly.
    payload = _capture_ollama_payload(monkeypatch, OllamaBackend())
    assert payload["options"]["seed"] == DEFAULT_SEED


def test_ollama_seed_is_overridable(monkeypatch):
    # Varying the seed across otherwise identical runs is how run-to-run spread
    # gets measured, so it has to be settable per backend.
    payload = _capture_ollama_payload(monkeypatch, OllamaBackend(seed=7))
    assert payload["options"]["seed"] == 7
