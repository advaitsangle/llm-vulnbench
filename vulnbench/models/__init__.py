"""Pluggable model backends behind one ``complete(prompt, tools?)`` interface."""

from .anthropic_backend import AnthropicBackend
from .base import Completion, ModelBackend, ToolSpec, Usage
from .mock_backend import MockBackend
from .ollama_backend import OllamaBackend
from .registry import build_backend, is_valid_spec

__all__ = [
    "AnthropicBackend",
    "Completion",
    "ModelBackend",
    "MockBackend",
    "OllamaBackend",
    "ToolSpec",
    "Usage",
    "build_backend",
    "is_valid_spec",
]
