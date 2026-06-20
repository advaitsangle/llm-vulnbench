"""Parse a ``--model`` spec into a backend.

Spec grammar::

    local:<ollama-model>        e.g. local:qwen3-coder:14b   (scored default)
    api:anthropic:<model>       e.g. api:anthropic:claude-opus-4-8  (ceiling)
    mock                        a deterministic offline backend for tests/dev

The ``mock`` backend lets the whole pipeline run without a model server, which is
how the test suite and a fresh checkout exercise the LLM conditions.
"""

from __future__ import annotations

from .base import Completion, ModelBackend, Usage


class MockBackend(ModelBackend):
    """Offline, deterministic backend. Echoes a canned, schema-valid reply.

    It returns a single ``not_supported`` verdict so LLM conditions produce
    parseable output end-to-end without a live model. Override ``scripted`` to
    drive specific test scenarios.
    """

    def __init__(self, scripted: str | None = None) -> None:
        self.name = "mock"
        self.scripted = scripted or '{"findings": []}'

    def _complete(self, messages, tools=None, **kwargs) -> Completion:  # noqa: ANN001
        return Completion(text=self.scripted, usage=Usage(input_tokens=0, output_tokens=0))


def build_backend(spec: str) -> ModelBackend:
    """Construct a backend from a ``--model`` string."""
    spec = spec.strip()
    if spec == "mock":
        return MockBackend()

    kind, _, rest = spec.partition(":")
    if kind == "local":
        from .ollama_backend import OllamaBackend

        model = rest or "qwen3-coder:14b"
        return OllamaBackend(model=model)
    if kind == "api":
        provider, _, model = rest.partition(":")
        if provider == "anthropic":
            from .anthropic_backend import AnthropicBackend

            return AnthropicBackend(model=model or "claude-opus-4-8")
        raise ValueError(f"Unknown API provider: {provider!r} (supported: anthropic)")

    raise ValueError(
        f"Unrecognized model spec: {spec!r}. "
        "Use local:<model>, api:anthropic:<model>, or mock."
    )
