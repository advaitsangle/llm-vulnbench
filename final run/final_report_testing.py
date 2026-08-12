#!/usr/bin/env python3
"""Run a condition against the pinned 100-case slice.

Run from the repo root; the folder name has a space, so keep the quotes::

    python "final run/final_report_testing.py" A5
    python "final run/final_report_testing.py" A2 A3
"""

import csv
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

FINAL_RUN = Path(__file__).resolve().parent
REPO = FINAL_RUN.parent
CORPUS = REPO / "targets" / "BenchmarkJava"
SRC = CORPUS / "src/main/java/org/owasp/benchmark/testcode"
# Outputs land here rather than in whatever directory the script was called from,
# so a card is committed alongside the results row it backs.
SCORECARDS = FINAL_RUN / "scorecards"

conds = sys.argv[1:]
if not conds:
    sys.exit(__doc__)

names = [row["name"] for row in csv.DictReader((FINAL_RUN / "final-100.csv").open())]
SCORECARDS.mkdir(parents=True, exist_ok=True)
# Every condition run, plus a timestamp, so re-runs never overwrite each other.
tag = "-".join(conds) + datetime.now().strftime("-%Y%m%d-%H%M%S")

# Staged outside the repo: semgrep skips gitignored paths, so a slice inside it
# would leave B1/C1/C3 scanning nothing and scoring zero without an error.
with tempfile.TemporaryDirectory() as tmp:
    for name in names:
        shutil.copy2(SRC / f"{name}.java", Path(tmp) / f"{name}.java")
    sys.exit(subprocess.call([
        sys.executable, "-m", "vulnbench.cli", "run",
        "--condition", *conds,
        "--source", tmp,
        "--ground-truth", str(CORPUS / "expectedresults-1.2.csv"),
        "--kind", "benchmark",
        "--model", "local:qwen2.5-coder:14b",
        "-o", str(SCORECARDS / f"card-{tag}.json"),
        "--findings-out", str(SCORECARDS / f"fn-{tag}.json"),
    ]))
