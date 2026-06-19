"""Frontier model backend via the Anthropic API.

This is the *ceiling* backend per ``claude.md``: used to show frontier headroom,
reported separately from the scored local-model runs. Requires API credits and the
``anthropic`` extra (``pip install vulnbench[anthropic]``); the harness core does
not depend on it.
"""

from __future__ import annotations

import os
from typing import Any

from .base import Completion, ModelBackend, ToolCall, ToolSpec, Usage


class AnthropicBackend(ModelBackend):
    """Talks to the Anthropic Messages API. Latest models default to Opus 4.8."""

    def __init__(
        self,
        model: str = "claude-opus-4-8",
        temperature: float = 0.1,
        max_tokens: int = 4096,
        api_key: str | None = None,
    ) -> None:
        try:
            import anthropic
        except ImportError as exc:  # pragma: no cover - optional dep
            raise RuntimeError(
                "AnthropicBackend needs the `anthropic` package. "
                "Install with: pip install 'vulnbench[anthropic]'"
            ) from exc

        key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            raise RuntimeError("Set ANTHROPIC_API_KEY or pass api_key=...")
        self._client = anthropic.Anthropic(api_key=key)
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.name = f"api:anthropic:{model}"

    def _complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[ToolSpec] | None = None,
        **kwargs: Any,
    ) -> Completion:
        # Anthropic takes the system prompt out-of-band; split it off if present.
        system = None
        convo: list[dict[str, Any]] = []
        for m in messages:
            if m["role"] == "system":
                system = m["content"]
            else:
                convo.append(m)

        req: dict[str, Any] = {
            "model": self.model,
            "max_tokens": kwargs.get("max_tokens", self.max_tokens),
            "temperature": kwargs.get("temperature", self.temperature),
            "messages": convo,
        }
        if system:
            req["system"] = system
        if tools:
            req["tools"] = [
                {"name": t.name, "description": t.description, "input_schema": t.parameters}
                for t in tools
            ]

        resp = self._client.messages.create(**req)

        text_parts, tool_calls = [], []
        for block in resp.content:
            if block.type == "text":
                text_parts.append(block.text)
            elif block.type == "tool_use":
                tool_calls.append(
                    ToolCall(name=block.name, arguments=block.input, call_id=block.id)
                )

        usage = Usage(
            input_tokens=resp.usage.input_tokens,
            output_tokens=resp.usage.output_tokens,
        )
        return Completion(
            text="".join(text_parts),
            tool_calls=tool_calls,
            usage=usage,
            raw=resp,
        )
