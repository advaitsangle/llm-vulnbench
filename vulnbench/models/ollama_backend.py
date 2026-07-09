"""Local model backend via the Ollama HTTP API.

This is the *scored* backend by default: a local Qwen-Coder ~14B is the
single fixed model for all officially scored runs (free, reproducible). We use
``urllib`` so the harness has no hard third-party dependency just to talk to a
local server.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from .base import Completion, ModelBackend, ToolCall, ToolSpec, Usage

#: Where a stock Ollama daemon listens. Shared with the tool preflight and the
#: wizard's model discovery so the address is stated once.
DEFAULT_HOST = "http://localhost:11434"


class OllamaBackend(ModelBackend):
    """Talks to ``/api/chat`` on a local Ollama daemon."""

    def __init__(
        self,
        model: str = "qwen2.5-coder:14b",
        host: str = DEFAULT_HOST,
        temperature: float = 0.1,
        timeout: float = 600.0,
    ) -> None:
        self.model = model
        self.host = host.rstrip("/")
        self.temperature = temperature
        self.timeout = timeout
        self.name = f"local:{model}"

    def _complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[ToolSpec] | None = None,
        **kwargs: Any,
    ) -> Completion:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": kwargs.get("temperature", self.temperature)},
        }
        if tools:
            payload["tools"] = [
                {
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.parameters,
                    },
                }
                for t in tools
            ]

        req = urllib.request.Request(
            f"{self.host}/api/chat",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except urllib.error.URLError as exc:  # pragma: no cover - network path
            raise RuntimeError(
                f"Ollama request to {self.host} failed: {exc}. "
                "Is the daemon running (`ollama serve`) and the model pulled "
                f"(`ollama pull {self.model}`)?"
            ) from exc

        msg = body.get("message", {})
        tool_calls = [
            ToolCall(
                name=tc["function"]["name"],
                arguments=tc["function"].get("arguments", {}),
            )
            for tc in msg.get("tool_calls", []) or []
        ]
        usage = Usage(
            input_tokens=int(body.get("prompt_eval_count", 0)),
            output_tokens=int(body.get("eval_count", 0)),
        )
        return Completion(
            text=msg.get("content", ""),
            tool_calls=tool_calls,
            usage=usage,
            raw=body,
        )
