"""External dependencies a condition needs, and how to satisfy them.

Some conditions can't run without something the harness doesn't ship: B1/C1/C3 shell
out to Semgrep, B2/C2 talk to a running OWASP ZAP daemon, and ``local:`` models need
an Ollama daemon. Discovering that *after* a user has configured a sweep — as a
traceback from deep inside a scanner — is a bad trade for a check that costs
milliseconds up front.

Conditions name what they need via :attr:`~vulnbench.conditions.Condition.tools`
(plain string keys), and this module owns the answers: how to detect each tool, how
to install or start it, and what to tell the user when we can't. Keeping the keys on
the condition and the mechanics here means a new condition declares ``tools =
("semgrep",)`` and the wizard's preflight picks it up with no edit.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from .models.ollama_backend import DEFAULT_HOST as OLLAMA_HOST
from .scanners.semgrep_runner import _resolve_semgrep
from .scanners.zap_runner import DEFAULT_ZAP_URL

_PKG_DIR = Path(__file__).resolve().parent
_COMPOSE_FILE = _PKG_DIR.parent / "deploy" / "docker-compose.yml"

#: How often :meth:`Tool.wait_until_available` re-probes a starting daemon.
_POLL_INTERVAL = 1.0


def _http_ok(url: str, timeout: float = 1.0) -> bool:
    """True when ``url`` answers at all — used to detect a daemon, not to fetch."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310
            return 200 <= resp.status < 400
    except (urllib.error.URLError, OSError, ValueError, TimeoutError):
        return False


def _semgrep_available(_config: dict) -> bool:
    return _resolve_semgrep() is not None


def _zap_available(config: dict) -> bool:
    # Honor a zap_url knob the user set, so we probe the daemon they'll actually use.
    base = str(config.get("zap_url") or DEFAULT_ZAP_URL).rstrip("/")
    return _http_ok(f"{base}/JSON/core/view/version/")


def _ollama_available(_config: dict) -> bool:
    return _http_ok(f"{OLLAMA_HOST}/api/tags")


def _docker_available() -> bool:
    return shutil.which("docker") is not None


@dataclass(frozen=True)
class Tool:
    """One external dependency: how to see it, how to get it, what to say otherwise."""

    key: str
    label: str
    #: Manual instructions, always shown when the tool is missing and we can't fix it.
    hint: str
    #: Probe. Takes the run config so a knob like ``zap_url`` can redirect it.
    check: Callable[[dict], bool] = field(compare=False, repr=False)
    #: A command we can offer to run. ``None`` means "we can't do this for you".
    install_cmd: tuple[str, ...] | None = None
    #: Lazy alternative to ``install_cmd``, consulted first: re-derives the command at
    #: ask time, so a prerequisite that appeared *after* import (Docker started, a file
    #: created) is noticed. Returning ``None`` means the command is currently unavailable.
    install_cmd_factory: Callable[[], tuple[str, ...] | None] | None = field(
        default=None, compare=False, repr=False
    )
    #: Plain-English description of what ``install_cmd`` will do, shown before running.
    install_note: str = ""
    #: Seconds to keep re-probing after ``install_cmd`` returns. A package install is
    #: usable the moment pip exits, but `docker compose up -d` returns as soon as the
    #: container is *created* — ZAP needs a few more seconds to bind its port, and
    #: probing once would report a false "install failed".
    startup_wait: float = 0.0

    def available(self, config: dict | None = None) -> bool:
        return self.check(config or {})

    def install_command(self) -> tuple[str, ...] | None:
        """The command to offer right now, or ``None`` when there is nothing to run."""
        if self.install_cmd_factory is not None:
            return self.install_cmd_factory()
        return self.install_cmd

    def wait_until_available(self, config: dict | None = None) -> bool:
        """Poll :meth:`available` for up to :attr:`startup_wait` seconds."""
        deadline = time.monotonic() + self.startup_wait
        while True:
            if self.available(config):
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(_POLL_INTERVAL)


def _zap_install_cmd() -> tuple[str, ...] | None:
    """Start just the ZAP daemon from the bundled compose file, if both exist.

    ``--no-deps`` keeps this to the daemon: the full compose file also builds and
    boots BenchmarkJava, which is a multi-minute Maven build the user may not want
    (their target might be a different app entirely).
    """
    if not _COMPOSE_FILE.is_file() or not _docker_available():
        return None
    return ("docker", "compose", "-f", str(_COMPOSE_FILE), "up", "-d", "--no-deps", "zap")


SEMGREP = Tool(
    key="semgrep",
    label="Semgrep (SAST engine)",
    check=_semgrep_available,
    install_cmd=(sys.executable, "-m", "pip", "install", "semgrep"),
    install_note=f"pip install semgrep into {sys.executable}",
    hint="Install with `pip install semgrep`, `pipx install semgrep`, or `brew install semgrep`.",
)

ZAP = Tool(
    key="zap",
    label="OWASP ZAP daemon",
    check=_zap_available,
    install_cmd_factory=_zap_install_cmd,
    install_note=f"docker compose up the zap service from {_COMPOSE_FILE}",
    startup_wait=60.0,  # the container is created long before ZAP binds its port
    hint=(
        "Start ZAP in daemon mode — `zap.sh -daemon -host 0.0.0.0 -port 8090 "
        "-config api.disablekey=true` — or, from a repo checkout, bring up "
        "deploy/docker-compose.yml. If it listens elsewhere, set the zap_url knob."
    ),
)

OLLAMA = Tool(
    key="ollama",
    label="Ollama daemon (for local: models)",
    check=_ollama_available,
    install_cmd=None,  # installing a model runtime is not ours to do silently
    hint="Install from https://ollama.com, then `ollama serve` and `ollama pull <model>`.",
)

TOOLS: dict[str, Tool] = {t.key: t for t in (SEMGREP, ZAP, OLLAMA)}


def get_tool(key: str) -> Tool:
    try:
        return TOOLS[key]
    except KeyError:
        raise KeyError(f"Unknown tool {key!r}. Known: {', '.join(sorted(TOOLS))}") from None


def missing_tools(keys: list[str], config: dict | None = None) -> list[Tool]:
    """The subset of ``keys`` that isn't usable right now, in declaration order.

    Keys are de-duplicated before probing: B2 and C2 both name ZAP, and each probe of
    an absent daemon costs a connection timeout.
    """
    missing: list[Tool] = []
    for key in dict.fromkeys(keys):
        tool = get_tool(key)
        if not tool.available(config):
            missing.append(tool)
    return missing


def run_install(tool: Tool, config: dict | None = None) -> bool:
    """Run a tool's install command. True only if it ran *and* the tool then appears.

    ``config`` is forwarded to the probe so a tool reached over the network (ZAP) is
    verified at the address the run will actually use, not at its default.
    """
    cmd = tool.install_command()
    if cmd is None:
        return False
    try:
        subprocess.run(cmd, check=True)
    except (subprocess.CalledProcessError, OSError):
        return False
    return tool.wait_until_available(config)


__all__ = [
    "OLLAMA",
    "SEMGREP",
    "TOOLS",
    "ZAP",
    "Tool",
    "get_tool",
    "missing_tools",
    "run_install",
]
