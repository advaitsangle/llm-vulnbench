"""Pluggable model backends behind one ``complete(prompt, tools?)`` interface."""

from .base import Completion, ModelBackend, ToolSpec, Usage
from .mock_backend import MockBackend
from .registry import build_backend

__all__ = ["Completion", "ModelBackend", "MockBackend", "ToolSpec", "Usage", "build_backend"]
