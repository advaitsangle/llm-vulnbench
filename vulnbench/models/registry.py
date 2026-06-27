"""Parse a ``--model`` spec into a backend.

Spec grammar::

    local:<ollama-model>        e.g. local:qwen2.5-coder:14b   (scored default)
    api:anthropic:<model>       e.g. api:anthropic:claude-opus-4-8  (ceiling)
    mock                        a deterministic offline backend for tests/dev
"""

from __future__ import annotations

from .anthropic_backend import AnthropicBackend
from .base import ModelBackend
from .mock_backend import MockBackend
from .ollama_backend import OllamaBackend


def build_backend(spec: str) -> ModelBackend:
    """Construct a backend from a ``--model`` string."""
    spec = spec.strip()
    if spec == "mock":
        return MockBackend()

    kind, _, rest = spec.partition(":")
    if kind == "local":
        model = rest or "qwen2.5-coder:14b"
        return OllamaBackend(model=model)
    if kind == "api":
        provider, _, model = rest.partition(":")
        if provider == "anthropic":
            return AnthropicBackend(model=model or "claude-opus-4-8")
        raise ValueError(f"Unknown API provider: {provider!r} (supported: anthropic)")

    raise ValueError(
        f"Unrecognized model spec: {spec!r}. "
        "Use local:<model>, api:anthropic:<model>, or mock."
    )
