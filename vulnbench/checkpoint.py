"""Crash-safe run checkpointing so a sweep can be paused and resumed.

A matrix run is a loop over conditions, each of which can be slow (a 14B local
model triaging hundreds of files). If the machine sleeps, runs out of RAM, or the
user hits Ctrl-C, we don't want to redo the conditions that already finished. This
module persists each completed cell to disk *the moment it finishes*, keyed by a
signature of the run inputs. Re-invoking the same command picks up where it left
off; changing the target, model, or config invalidates the checkpoint and starts
fresh.

The unit of resumption is one condition (one matrix cell). A condition that was
interrupted mid-flight simply re-runs — cells are all-or-nothing.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .harness import RunRecord
from .schema import Finding


def signature(
    *,
    target_name: str,
    kind: str,
    source: str | None,
    url: str | None,
    ground_truth: str | None,
    model: str | None,
    config: dict | None,
) -> dict:
    """The identity of a run: same signature ⇒ resumable, different ⇒ start fresh."""
    return {
        "target": target_name,
        "kind": kind,
        "source": source,
        "url": url,
        "ground_truth": ground_truth,
        "model": model,
        "config": dict(config or {}),
    }


def default_path(sig: dict, root: str = "runs") -> Path:
    """A stable, gitignored checkpoint path derived from the run signature."""
    digest = hashlib.sha256(
        json.dumps(sig, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()[:8]
    return Path(root) / f"checkpoint-{digest}.json"


class Checkpoint:
    """Stores completed cells and flushes atomically after every ``put``."""

    def __init__(self, path: str | Path, sig: dict, *, resume: bool = True) -> None:
        self.path = Path(path)
        self.signature = sig
        self.cells: dict[str, dict] = {}
        self.resumed = 0
        if resume and self.path.exists():
            self._load()

    def _load(self) -> None:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return  # corrupt/partial checkpoint: ignore it and start fresh
        if data.get("signature") == self.signature:
            self.cells = data.get("cells", {})
            self.resumed = len(self.cells)

    def has(self, condition_id: str) -> bool:
        return condition_id in self.cells

    def get(self, condition_id: str) -> tuple[RunRecord, list[Finding]] | None:
        cell = self.cells.get(condition_id)
        if cell is None:
            return None
        record = RunRecord(**cell["record"])
        findings = [Finding.from_dict(f) for f in cell["findings"]]
        return record, findings

    def put(self, condition_id: str, record: RunRecord, findings: list[Finding]) -> None:
        self.cells[condition_id] = {
            "record": record.to_dict(),
            "findings": [f.to_dict() for f in findings],
        }
        self._flush()

    def _flush(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(
            json.dumps({"signature": self.signature, "cells": self.cells}, indent=2),
            encoding="utf-8",
        )
        tmp.replace(self.path)  # atomic on POSIX: a crash never leaves a half file

    def clear(self) -> None:
        self.path.unlink(missing_ok=True)
