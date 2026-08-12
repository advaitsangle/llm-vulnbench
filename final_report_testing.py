#!/usr/bin/env python3
"""Build the pinned 100-case slice everyone runs the final-report sweep against.

Reads `slices/final-100.csv` (the manifest) and copies exactly those files out of a
BenchmarkJava checkout into `slices/final-100/`, then prints the command to run.

Why a copy rather than `--sample 100 --sample-seed 42`: the seeded sample re-derives
the slice at run time from the sorted file list, so it only lands on the same 100 if
every teammate's corpus is byte-identical *and* their CPython's `random.sample` behaves
the same. The manifest names the files outright and this script fails loudly if any is
missing, so nobody silently measures a different slice.

    python final_report_testing.py --condition A5
    python final_report_testing.py --condition A2 A3 --model local:qwen2.5-coder:14b

Stdlib only, like the rest of the harness — no need to install anything to run it.
"""

from __future__ import annotations

import argparse
import csv
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent
MANIFEST = REPO / "slices" / "final-100.csv"
SLICE_DIR = REPO / "slices" / "final-100"
DEFAULT_CORPUS = REPO / "targets" / "BenchmarkJava"
GROUND_TRUTH = "expectedresults-1.2.csv"
TESTCODE = Path("src/main/java/org/owasp/benchmark/testcode")


def read_manifest(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        sys.exit(f"manifest not found: {path}\nAre you on the cs453 branch?")
    with path.open(newline="") as fh:
        rows = list(csv.DictReader(fh))
    if not rows:
        sys.exit(f"manifest is empty: {path}")
    return rows


def build_slice(corpus: Path, rows: list[dict[str, str]]) -> Path:
    """Copy the manifest's cases out of ``corpus``; abort if any is missing."""
    src = corpus / TESTCODE
    if not src.is_dir():
        sys.exit(f"no testcode directory under {corpus}\nExpected: {src}")

    missing = [r["name"] for r in rows if not (src / f"{r['name']}.java").is_file()]
    if missing:
        sys.exit(
            f"corpus is missing {len(missing)} of {len(rows)} cases "
            f"(e.g. {', '.join(missing[:3])}).\n"
            "That means your BenchmarkJava is not v1.2 — fix the checkout rather "
            "than running a different slice from everyone else."
        )

    if SLICE_DIR.exists():
        shutil.rmtree(SLICE_DIR)
    SLICE_DIR.mkdir(parents=True)
    for row in rows:
        shutil.copy2(src / f"{row['name']}.java", SLICE_DIR / f"{row['name']}.java")
    return SLICE_DIR


def summarise(rows: list[dict[str, str]]) -> str:
    real = sum(1 for r in rows if r["real"] == "true")
    cats: dict[str, int] = {}
    for r in rows:
        cats[r["category"]] = cats.get(r["category"], 0) + 1
    spread = ", ".join(f"{k} {v}" for k, v in sorted(cats.items(), key=lambda kv: -kv[1]))
    return f"{len(rows)} cases · {real} real / {len(rows) - real} safe · {spread}"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--condition", nargs="+", metavar="ID",
                    help="condition id(s) you are responsible for, e.g. A5")
    ap.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS,
                    help=f"BenchmarkJava checkout (default: {DEFAULT_CORPUS})")
    ap.add_argument("--model", default="local:qwen2.5-coder:14b",
                    help="model spec for the printed command")
    args = ap.parse_args()

    rows = read_manifest(MANIFEST)
    out = build_slice(args.corpus, rows)
    print(f"built {out.relative_to(REPO)}")
    print(f"  {summarise(rows)}")

    gt = args.corpus / GROUND_TRUTH
    if not gt.is_file():
        print(f"\nwarning: ground truth not found at {gt}", file=sys.stderr)
    # Relative where possible: an absolute path containing a space (as this repo's
    # does) silently breaks the printed command when pasted.
    gt_arg = gt.relative_to(REPO) if gt.is_relative_to(REPO) else gt
    if " " in str(gt_arg):
        gt_arg = f"'{gt_arg}'"

    conds = " ".join(args.condition) if args.condition else "<YOUR CONDITION>"
    tag = (args.condition[0] if args.condition else "COND")
    print("\nrun it with:\n")
    print(f"  .venv/bin/python -m vulnbench.cli run \\\n"
          f"      --condition {conds} \\\n"
          f"      --source {out.relative_to(REPO)} \\\n"
          f"      --ground-truth {gt_arg} --kind benchmark \\\n"
          f"      --model {args.model} \\\n"
          f"      -o card-{tag}.json --findings-out fn-{tag}.json\n")
    print("then check card-*.json before sending it on:")
    print("  files_scanned == 100, truncated_files == 0, and whichever fallback")
    print("  counter your condition has (ast_fallback_files / cfg_fallback_files /")
    print("  files_full_fallback / candidate_parse_failures) at or near zero —")
    print("  a high one means the condition quietly ran as plain B3.")


if __name__ == "__main__":
    main()
