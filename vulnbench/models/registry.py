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


def is_valid_spec(spec: str) -> bool:
    """True when ``spec`` matches the ``--model`` grammar.

    A pure syntax check — no backend is constructed, so it needs no daemon, API
    key, or optional package. Front-ends use it to reject a typo at entry time
    instead of letting :func:`build_backend` raise mid-sweep.
    """
    spec = spec.strip()
    if spec == "mock":
        return True
    kind, _, rest = spec.partition(":")
    if kind == "local":
        return True  # a bare "local" falls back to the default model
    if kind == "api":
        return rest.partition(":")[0] == "anthropic"
    return False


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
