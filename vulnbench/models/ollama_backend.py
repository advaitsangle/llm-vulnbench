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

#: Context window to request, in tokens. Ollama does *not* default to the model's
#: full window — it loads a much smaller one and silently drops whatever overflows,
#: with no error and nothing in the response to say it happened. That turns "this
#: condition sends more context" into "this condition gets truncated", which would
#: read as a real accuracy difference between conditions. So it is set explicitly.
#:
#: 16384 rather than qwen2.5-coder:14b's full 32768: the KV cache is ~192 KiB/token
#: (48 layers x 8 KV heads x 128 dim, fp16), so 32k costs ~6.3 GiB on top of the
#: ~9 GiB Q4_K_M weights — over the 16 GB budget the scored runs have to fit in.
#: 16k costs ~3.1 GiB, leaving headroom. Raise it if the machine grows.
DEFAULT_NUM_CTX = 16384

#: Sampling seed. Fixes the RNG the sampler draws from, so the same prompt against
#: the same model returns the same completion on a re-run. It does *not* change how
#: the model behaves: temperature stays where it is and sampling still happens, the
#: draw is just repeatable. That keeps a scored number checkable — a condition can be
#: re-run to confirm a result rather than taking one sample on faith, and a gap
#: between two conditions is attributable to the prompt rather than to the dice.
#:
#: 42 for no reason beyond convention, and because SAMPLE_KNOBS already uses it.
#:
#: Per-machine only. Identical inputs on different hardware still diverge (float
#: addition is not associative), so this makes a run repeatable, not portable.
DEFAULT_SEED = 42


class OllamaBackend(ModelBackend):
    """Talks to ``/api/chat`` on a local Ollama daemon."""

    def __init__(
        self,
        model: str = "qwen2.5-coder:14b",
        host: str = DEFAULT_HOST,
        temperature: float = 0.1,
        timeout: float = 600.0,
        num_ctx: int = DEFAULT_NUM_CTX,
        seed: int = DEFAULT_SEED,
    ) -> None:
        self.model = model
        self.host = host.rstrip("/")
        self.temperature = temperature
        self.timeout = timeout
        self.num_ctx = num_ctx
        self.seed = seed
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
            "options": {
                "temperature": kwargs.get("temperature", self.temperature),
                "num_ctx": kwargs.get("num_ctx", self.num_ctx),
                "seed": kwargs.get("seed", self.seed),
            },
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
