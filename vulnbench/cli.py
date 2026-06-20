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

    vulnbench run --condition C1 --source ./src --model local:qwen3-coder:14b \\
        --ground-truth ./expectedresults-1.2.csv --kind benchmark

Sweep several conditions and write a scorecard::

    vulnbench run --condition B1 C1 --source ./src --model mock \\
        --ground-truth ./expectedresults-1.2.csv -o scorecard.json
"""

from __future__ import annotations

import argparse
import json
import sys

from .conditions import REGISTRY
from .corpus import Target, TargetKind
from .harness import run_one
from .models import build_backend
from .report import Reporter
from .schema import dump_findings


def _cmd_list(_: argparse.Namespace) -> int:
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

    records = []           # RunRecord objects (for the reporter)
    records_json = []      # serialized (for the scorecard file + exit code)
    all_findings = []
    gt_cache: dict = {}
    for cid in args.condition:
        with reporter.running(cid, target.name):
            record, findings = run_one(
                target, cid, model=model, config=config,
                ground_truth_cache=gt_cache, debug=args.debug,
            )
        records.append(record)
        records_json.append(record.to_dict())
        all_findings.extend(findings)
        reporter.line(record)

    detail_paths: dict[str, str] = {}
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


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="vulnbench", description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="list the condition matrix").set_defaults(func=_cmd_list)

    r = sub.add_parser("run", help="run condition(s) on a target")
    r.add_argument("--condition", nargs="+", required=True, help="condition id(s), e.g. B1 C1")
    r.add_argument("--source", help="path to target source tree")
    r.add_argument("--url", help="base URL of the running target (DAST)")
    r.add_argument("--ground-truth", help="expectedresults CSV or realistic-app vuln-list JSON")
    r.add_argument("--kind", default="benchmark", choices=[k.value for k in TargetKind])
    r.add_argument("--model", help="model spec: local:<m> | api:anthropic:<m> | mock")
    r.add_argument("--name", help="display name for the target")
    r.add_argument("--config", help="JSON string of per-condition config knobs")
    r.add_argument(
        "--scan-out",
        help="phased C1/C2: run only the scanner, save its findings here, skip the model "
        "(do this with the Docker stack up)",
    )
    r.add_argument(
        "--scan-in",
        help="phased C1/C2: skip the scanner, load findings from here, run only the model "
        "triage (do this with the stack down, RAM free for the model)",
    )
    r.add_argument("-o", "--output", help="write scorecard JSON here")
    r.add_argument("--findings-out", help="write raw normalized findings JSON (for FP/FN audit)")
    r.add_argument("--plain", action="store_true", help="disable colored/animated output")
    r.add_argument("--debug", action="store_true", help="re-raise condition errors (don't capture)")
    r.set_defaults(func=_cmd_run)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
