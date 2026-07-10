"""Walking and reading a target's source tree, shared by the source-based conditions.

Every condition that reads code off disk (B3's flat pass, A1's scout/hunter, C1's
triage, C3's rule author) needs the same three things: a deterministic file
iterator, a byte-capped reader, and the pair of knobs that control them. They live
here — a real shared module — rather than as private helpers inside whichever
condition happened to need them first.
"""

from __future__ import annotations

import os

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
