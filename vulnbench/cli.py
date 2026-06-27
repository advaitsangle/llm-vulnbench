"""Command-line entry point for the harness.

Examples
--------
List the condition matrix::

    vulnbench list

Run the SAST baseline on a Benchmark checkout and score it::

    vulnbench run --condition B1 \\
        --source ./targets/BenchmarkJava/src/main/java \\
        --ground-truth ./targets/BenchmarkJava/expectedresults-1.2.csv \\
        --kind benchmark

Run the scanner-assisted LLM cell with the scored local model::

    vulnbench run --condition C1 --source ./src --model local:qwen2.5-coder:14b \\
        --ground-truth ./expectedresults-1.2.csv --kind benchmark

Sweep several conditions and write a scorecard::

    vulnbench run --condition B1 C1 --source ./src --model mock \\
        --ground-truth ./expectedresults-1.2.csv -o scorecard.json
"""

from __future__ import annotations

import argparse
import json
import sys

from .checkpoint import Checkpoint, default_path, signature
from .conditions import REGISTRY
from .corpus import Target, TargetKind
from .harness import run_one
from .models import build_backend
from .report import Reporter
from .schema import dump_findings
from .suite import cmd_targets


class _BannerParser(argparse.ArgumentParser):
    """ArgumentParser that prints the mascot banner before any --help output."""

    def print_help(self, file=None) -> None:
        print()
        Reporter(pretty=sys.stdout.isatty()).banner()
        super().print_help(file)


def _cmd_list(_: argparse.Namespace) -> int:
    if sys.stdout.isatty():
        Reporter(pretty=True).banner()
        print()
    print("Condition matrix:\n")
    for cid in sorted(REGISTRY):
        cls = REGISTRY[cid]
        needs = "model" if cls.needs_model else "scanner-only"
        print(f"  {cid:3} {cls.label}  [{needs}]")
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    target = Target(
        name=args.name or (args.source or args.url or "target"),
        kind=TargetKind(args.kind),
        source_path=args.source,
        base_url=args.url,
        ground_truth=args.ground_truth,
    )
    model = build_backend(args.model) if args.model else None
    config = json.loads(args.config) if args.config else {}
    # Phased triage (C1/C2): --scan-out runs only the scanner and saves its
    # findings; --scan-in skips the scanner and triages those saved findings.
    if args.scan_out:
        config["scan_out"] = args.scan_out
    if args.scan_in:
        config["scan_in"] = args.scan_in

    # Pretty (rich) when attached to a TTY and not suppressed; plain otherwise.
    pretty = not args.plain and sys.stdout.isatty()
    reporter = Reporter(pretty=pretty)
    reporter.banner()

    # Checkpointing is on by default: each finished condition is flushed to disk so
    # an interrupted sweep (sleep / OOM / Ctrl-C) resumes instead of redoing work.
    sig = signature(
        target_name=target.name, kind=args.kind, source=args.source, url=args.url,
        ground_truth=args.ground_truth, model=args.model, config=config,
    )
    ckpt_path = args.checkpoint or default_path(sig)
    ckpt = Checkpoint(ckpt_path, sig, resume=not args.fresh)

    records = []           # RunRecord objects (for the reporter)
    records_json = []      # serialized (for the scorecard file + exit code)
    all_findings = []
    gt_cache: dict = {}
    reused = 0             # cells served from the checkpoint this run
    with reporter.track(len(args.condition)) as tracker:
        for cid in args.condition:
            tracker.start(cid, target.name)
            cached = ckpt.get(cid)
            if cached is not None:
                record, findings = cached
                reused += 1
                reporter.line(record, resumed=True)
            else:
                record, findings = run_one(
                    target, cid, model=model, config=config,
                    ground_truth_cache=gt_cache, debug=args.debug,
                )
                if record.error is None:
                    ckpt.put(cid, record, findings)  # only checkpoint clean cells
                reporter.line(record)
            tracker.advance()
            records.append(record)
            records_json.append(record.to_dict())
            all_findings.extend(findings)

    detail_paths: dict[str, str] = {}
    if reused:
        detail_paths[f"resumed {reused} cell(s) from"] = str(ckpt_path)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(records_json, fh, indent=2)
        detail_paths["scorecard"] = args.output
    if args.findings_out:
        # Raw normalized findings, for auditing which cases were TP/FP/FN.
        dump_findings(all_findings, args.findings_out)
        detail_paths[f"{len(all_findings)} findings"] = args.findings_out

    reporter.summary(records, target.name, detail_paths)
    return 0 if all(r.error is None for r in records) else 1


_TOP_EPILOG = """\
conditions:
  B1 Semgrep (SAST)   B2 ZAP (DAST)   B3 LLM only
  C1 LLM+Semgrep   C2 LLM+ZAP   C3 LLM-authored rules   A1 multi-agent
  (run `vulnbench list` for the live matrix)

models (--model):
  mock                       offline, deterministic; no server needed
  local:<name>               an Ollama model, e.g. local:qwen2.5-coder:14b
  api:anthropic:<name>       an Anthropic model, e.g. api:anthropic:claude-opus-4-8

examples:
  vulnbench list
  vulnbench targets                 # opt-in: pick vulnerable apps to clone
  vulnbench run --condition B1 --source ./src --ground-truth gt.csv
  vulnbench run --condition B3 C1 --source ./src --ground-truth gt.csv \\
                --model local:qwen2.5-coder:14b -o card.json
"""

_RUN_EPILOG = """\
notes:
  Finished conditions are checkpointed to runs/checkpoint-<hash>.json and reused
  on the next identical run; pass --fresh to re-run, --checkpoint to relocate it.

  C1/C2 can be split to avoid holding the scanner and the model in RAM at once:
    1. --scan-out alerts.json   (stack up)   run the scanner, save its alerts
    2. --scan-in  alerts.json   (stack down) triage those alerts with the model

examples:
  # SAST baseline, scored (no model, no services)
  vulnbench run --condition B1 --source ./src --ground-truth gt.csv

  # scanner-assisted LLM triage, write scorecard + findings audit
  vulnbench run --condition C1 --source ./src --ground-truth gt.csv \\
                --model local:qwen2.5-coder:14b -o card.json --findings-out fn.json
"""


def build_parser() -> argparse.ArgumentParser:
    p = _BannerParser(
        prog="vulnbench",
        description="Benchmark LLM-augmented web vulnerability detection: run SAST, DAST, "
        "LLM, and combined conditions on a target and score them the same way.",
        epilog=_TOP_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = p.add_subparsers(dest="command", required=True, metavar="{list,run,targets}",
                           parser_class=_BannerParser)

    sub.add_parser("list", help="print the condition matrix and exit").set_defaults(func=_cmd_list)

    t = sub.add_parser(
        "targets",
        help="opt-in: download/update the optional vulnerable-app testing suite",
        description="Interactively pick vulnerable web apps to clone into the gitignored "
        "targets/ directory (arrow keys + space to select). They never ship with the repo; "
        "this is how a user opts in. Re-run with --update to pull each to latest upstream.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    t.add_argument("--list", action="store_true", help="list available apps and exit")
    t.add_argument("--path", metavar="KEY",
                   help="print the resolved directory for one app and exit (for scripting)")
    t.add_argument("--all", action="store_true", help="select every app (skip the menu)")
    t.add_argument("--update", action="store_true",
                   help="pull already-installed selections to the latest upstream version")
    t.add_argument("--yes", action="store_true",
                   help="skip confirmation prompts (assume yes)")
    t.add_argument("--plain", action="store_true", help="disable colored output / banner")
    t.set_defaults(func=cmd_targets)

    r = sub.add_parser(
        "run",
        help="run condition(s) on a target and score them",
        description="Run one or more conditions on a single target and score the findings "
        "against ground truth. Results stream to the terminal; full data goes to --output.",
        epilog=_RUN_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    # --- what to run -------------------------------------------------------
    r.add_argument("--condition", nargs="+", required=True, metavar="ID",
                   help="condition id(s) to run, e.g. B1 C1 (see `vulnbench list`)")
    r.add_argument("--source", metavar="PATH", help="path to the target's source tree (SAST)")
    r.add_argument("--url", metavar="URL", help="base URL of the running target (DAST)")
    r.add_argument("--ground-truth", metavar="FILE",
                   help="expectedresults CSV (benchmark) or vuln-list JSON (realistic)")
    r.add_argument("--kind", default="benchmark", choices=[k.value for k in TargetKind],
                   help="ground-truth/scoring shape (default: benchmark)")
    r.add_argument("--model", metavar="SPEC",
                   help="model spec: mock | local:<name> | api:anthropic:<name>")
    r.add_argument("--name", metavar="NAME", help="display name for the target")
    r.add_argument("--config", metavar="JSON",
                   help='per-condition knobs as JSON, e.g. \'{"max_files": 20}\'')
    # --- phased C1/C2 (split scanner from model) ---------------------------
    r.add_argument("--scan-out", metavar="FILE",
                   help="phased C1/C2: run only the scanner, save findings here, skip the model")
    r.add_argument("--scan-in", metavar="FILE",
                   help="phased C1/C2: skip the scanner, triage findings loaded from here")
    # --- output ------------------------------------------------------------
    r.add_argument("-o", "--output", metavar="FILE", help="write the scorecard JSON here")
    r.add_argument("--findings-out", metavar="FILE",
                   help="write raw normalized findings JSON (for FP/FN audit)")
    # --- resume / display --------------------------------------------------
    r.add_argument("--checkpoint", metavar="FILE",
                   help="resume from / write to this checkpoint (default: runs/checkpoint-*.json)")
    r.add_argument("--fresh", action="store_true",
                   help="ignore any existing checkpoint and re-run every condition")
    r.add_argument("--plain", action="store_true", help="disable colored/animated output")
    r.add_argument("--debug", action="store_true",
                   help="re-raise condition errors instead of capturing them")
    r.set_defaults(func=_cmd_run)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        # Clean Ctrl-C: no traceback, conventional 130 exit code.
        print("\nInterrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
