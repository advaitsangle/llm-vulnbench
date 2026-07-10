"""Walking and reading a target's source tree, shared by the source-based conditions.

Every condition that reads code off disk (B3's flat pass, A1's scout/hunter, C1's
triage, C3's rule author) needs the same three things: a deterministic file
iterator, a byte-capped reader, and the pair of knobs that control them. They live
here — a real shared module — rather than as private helpers inside whichever
condition happened to need them first.
"""

from __future__ import annotations

import os
import random

from .base import Knob

#: Source extensions worth scanning; keeps the model off assets and configs.
CODE_EXTS = {".java", ".py", ".js", ".ts", ".php", ".rb", ".go"}

#: Shared by every condition that walks a source tree file-by-file (B3, A1).
SCAN_KNOBS = (
    Knob("max_files", "int", 0,
         help="cap on source files read (0 = no cap); a reproducible sorted subset"),
    Knob("max_file_bytes", "int", 60_000,
         help="truncate each file past this many bytes"),
)


#: The smoke-test sample, surfaced as the ``--sample`` CLI flag (advanced: it is set
#: by that flag, not tuned per condition in the wizard). Every source-based condition
#: declares these so one flag restricts a whole sweep to the same random slice.
SAMPLE_KNOBS = (
    Knob("sample_files", "int", 0, advanced=True,
         help="smoke test: examine only this many randomly sampled source files (0 = off)"),
    Knob("sample_seed", "int", 42, advanced=True,
         help="RNG seed for sample_files, so a smoke run is reproducible"),
)


def sample_source_files(root: str, k: int, seed: int) -> list[str]:
    """A seeded random sample of ``k`` code files under ``root`` (all, if fewer).

    Seeded so the "random" slice is the *same* slice on every machine and re-run —
    a smoke result must be reproducible, and a resumed checkpoint must be comparing
    against the same files. Sorted afterwards so downstream iteration order (and
    therefore prompts, traces, and diffs) stays deterministic too.
    """
    if k < 0:
        raise ValueError(f"sample size must not be negative, got {k}")
    paths = list(iter_source_files(root, None))
    if k >= len(paths):
        return paths
    return sorted(random.Random(seed).sample(paths, k))


def sampled_paths_for(condition, ctx, root: str) -> list[str] | None:
    """The smoke-test slice for this run, or ``None`` when sampling is off.

    Reads the :data:`SAMPLE_KNOBS` values through the condition so the knob names
    live in one place; every condition applies the same seed to the same walk and
    therefore examines the same files.
    """
    k = int(condition.cfg(ctx, "sample_files"))
    if not k:
        return None
    return sample_source_files(root, k, int(condition.cfg(ctx, "sample_seed")))


def iter_source_files(root: str, cap: int | None):
    """Yield the code files under ``root``, deterministically ordered, up to ``cap``.

    Both directories and files are sorted so a capped subset is the *same* subset
    on every machine — required for reproducible (and fair) scored runs.
    """
    count = 0
    for dirpath, dirnames, files in os.walk(root):
        dirnames.sort()
        for name in sorted(files):
            if os.path.splitext(name)[1].lower() in CODE_EXTS:
                yield os.path.join(dirpath, name)
                count += 1
                if cap and count >= cap:
                    return


def read_capped(path: str, max_bytes: int) -> tuple[str, bool]:
    """Read up to ``max_bytes`` of ``path``; return ``(text, truncated)``.

    Truncation is surfaced (not silent) so a vuln past the cap is an observable
    limitation, recorded per run rather than disappearing. An unreadable file
    reads as empty — the caller skips it rather than failing the sweep.
    """
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            chunk = fh.read(max_bytes + 1)
    except OSError:
        return "", False
    if len(chunk) > max_bytes:
        return chunk[:max_bytes], True
    return chunk, False
