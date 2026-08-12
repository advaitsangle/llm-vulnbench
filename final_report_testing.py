#!/usr/bin/env python3
"""Run a condition against the pinned 100-case slice.

    python final_report_testing.py A5
    python final_report_testing.py A2 A3
"""

import csv
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

REPO = Path(__file__).resolve().parent
CORPUS = REPO / "targets" / "BenchmarkJava"
SRC = CORPUS / "src/main/java/org/owasp/benchmark/testcode"

conds = sys.argv[1:]
if not conds:
    sys.exit(__doc__)

names = [row["name"] for row in csv.DictReader((REPO / "final run" / "final-100.csv").open())]
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
        "-o", f"card-{tag}.json",
        "--findings-out", f"fn-{tag}.json",
    ]))
