"""The no-argument ``vulnbench`` entry point: build a comparative run interactively.

Running ``vulnbench`` with no subcommand walks the user through the axes of a sweep —
models, targets, conditions, and whichever knobs the chosen conditions happen to
declare — then runs the cartesian product and prints one comparative matrix.

Nothing here enumerates conditions, knobs, or apps by name. The condition ladder is
read from :data:`vulnbench.conditions.REGISTRY`, each condition's options from its
declared :class:`~vulnbench.conditions.Knob` list and its ``needs_*`` flags, and the
apps from ``targets.toml``. Adding a condition or an app therefore changes the menus
without touching this file.

One deliberate asymmetry: a scanner-only condition (``needs_model = False``, e.g. the
Semgrep baseline) produces identical output for every model, so it is run *once* per
target rather than once per (target, model). Sweeping it across models would burn a
full scan per model to recompute the same numbers.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from .checkpoint import Checkpoint, default_path, signature
from .conditions import REGISTRY, Knob, get_condition
from .corpus import Target
from .harness import RunRecord, run_one
from .models import ModelBackend, build_backend, is_valid_spec
from .models.ollama_backend import DEFAULT_HOST as OLLAMA_HOST
from .report import Reporter
from .schema import Finding, dump_findings
from .suite import (
    _resolve_app,
    app_target,
    load_manifest,
    load_registry,
    resolved_path,
    save_registry,
    targets_root,
)
from .theme import make_console, paint, print_banner
from .tools import missing_tools, run_install
from .tui import is_interactive, prompt, prompt_yes_no, select

#: Anthropic models offered in the menu. The API key is read from the environment by
#: the backend itself; we only surface whether it is present.
_ANTHROPIC_MODELS = ("claude-opus-4-8", "claude-sonnet-5", "claude-haiku-4-5")


# --- model discovery --------------------------------------------------------------

def discover_ollama_models(host: str = OLLAMA_HOST, timeout: float = 1.0) -> list[str]:
    """Names of models a local Ollama daemon has pulled; empty if it isn't running.

    Best-effort: a missing daemon is the normal case for someone who only wants the
    API backends, so every failure here is silent rather than fatal.
    """
    try:
        with urllib.request.urlopen(f"{host}/api/tags", timeout=timeout) as resp:
            data = json.load(resp)
    except (urllib.error.URLError, OSError, ValueError, TimeoutError):
        return []
    return sorted(m["name"] for m in data.get("models", []) if m.get("name"))


def _has_anthropic_key() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


# --- the plan (pure: no I/O, so the product logic is testable on its own) ----------

@dataclass(frozen=True)
class RunConfig:
    """One cell of the sweep: a condition run against a target with a given model."""

    target: Target
    condition_id: str
    model_spec: str | None  # None for scanner-only conditions

    @property
    def model_name(self) -> str:
        return self.model_spec or "—"


def plan_configs(
    targets: list[Target], condition_ids: list[str], model_specs: list[str]
) -> list[RunConfig]:
    """Expand the chosen axes into the cells to run.

    Conditions that need no model are emitted once per target (with ``model_spec``
    None) instead of once per (target, model): the model cannot change their output,
    so re-running them per model would only pay the scan cost again.

    Cells are ordered target-major then model, which is the grouping the comparative
    matrix collapses on.
    """
    scanner_only = [c for c in condition_ids if not get_condition(c).needs_model]
    model_driven = [c for c in condition_ids if get_condition(c).needs_model]

    configs: list[RunConfig] = []
    for target in targets:
        for cid in scanner_only:
            configs.append(RunConfig(target, cid, None))
        if not model_driven:
            continue
        for spec in model_specs:
            for cid in model_driven:
                configs.append(RunConfig(target, cid, spec))
    return configs


def required_inputs(condition_ids: list[str]) -> tuple[bool, bool]:
    """(needs a source tree, needs a running URL) across the chosen conditions."""
    classes = [get_condition(c) for c in condition_ids]
    return (
        any(c.needs_source for c in classes),
        any(c.needs_url for c in classes),
    )


def tunable_knobs(condition_ids: list[str]) -> dict[str, tuple[Knob, list[str]]]:
    """Knobs the chosen conditions expose, mapped to the conditions that read them.

    Advanced (file-handoff / phasing) knobs are omitted: they wire two runs together
    rather than parameterizing one, so they have no place in a single sweep.
    """
    out: dict[str, tuple[Knob, list[str]]] = {}
    for cid in condition_ids:
        for knob in get_condition(cid).all_knobs():
            if knob.advanced:
                continue
            if knob.name in out:
                out[knob.name][1].append(cid)
            else:
                out[knob.name] = (knob, [cid])
    return out


# --- the interactive steps --------------------------------------------------------

def _pick(title: str, rows: list[str], keys: list, preselected: set[int] | None = None):
    """Render a titled multi-select; returns chosen keys, or None if cancelled."""
    print(f"\n{paint(title, 'blue', bold=True)}")
    idx = select(rows, preselected)
    if idx is None:
        return None
    return [keys[i] for i in idx]


def _choose_models() -> list[str] | None:
    """Pick model specs. Locals are discovered; Anthropic ids are a fixed shortlist."""
    keys: list[str] = ["mock"]
    rows: list[str] = [
        f"{paint('mock', bold=True)}  {paint('offline, deterministic; no server needed', dim=True)}"
    ]
    for name in discover_ollama_models():
        keys.append(f"local:{name}")
        rows.append(f"{paint('local:' + name, bold=True)}  {paint('(Ollama)', dim=True)}")

    has_key = _has_anthropic_key()
    note = "(Anthropic API)" if has_key else "(Anthropic API — ANTHROPIC_API_KEY not set)"
    for name in _ANTHROPIC_MODELS:
        keys.append(f"api:anthropic:{name}")
        rows.append(f"{paint('api:anthropic:' + name, bold=True)}  {paint(note, dim=True)}")

    keys.append("__custom__")
    rows.append(paint("custom…  (type a model spec by hand)", dim=True))

    chosen = _pick("1. Select models", rows, keys, preselected={0})
    if chosen is None:
        return None
    if "__custom__" in chosen:
        chosen = [c for c in chosen if c != "__custom__"]
        chosen.extend(_prompt_custom_specs())
    # Fail here rather than after the user has configured an entire sweep.
    if not has_key and any(c.startswith("api:anthropic:") for c in chosen):
        print(paint("  ! ANTHROPIC_API_KEY is not set; those cells would fail.", "red"))
        if not prompt_yes_no("  Continue anyway?", default=False):
            return None
    return chosen


def _prompt_custom_specs() -> list[str]:
    """Read hand-typed model specs, re-prompting until every one parses.

    A typo here used to surface as a crash mid-sweep, hours after this prompt;
    checking the grammar now costs one retry instead of a lost run. Blank = none.
    """
    while True:
        raw = prompt("  model spec(s), space-separated: ")
        specs = raw.split()
        bad = [s for s in specs if not is_valid_spec(s)]
        if not bad:
            return specs
        print(paint(
            f"    unrecognized spec(s): {', '.join(bad)} — "
            "use mock, local:<model>, or api:anthropic:<model>", "red",
        ))


def _choose_targets() -> list[Target] | None:
    """Pick apps; anything unlinked goes through the same point-or-install flow as
    ``vulnbench targets``, so the wizard never dead-ends on a missing checkout."""
    apps = load_manifest()
    root = targets_root()
    registry = load_registry(root)
    resolved = {a.key: resolved_path(a, root, registry) for a in apps}

    rows = []
    for app in apps:
        path = resolved[app.key]
        state = paint("linked", "green") if path else paint("not linked", dim=True)
        rows.append(
            f"{paint(app.name, bold=True)}  {paint('(' + app.language + ')', dim=True)} — {state}"
        )
    chosen = _pick("2. Select targets", rows, apps)
    if chosen is None:
        return None

    targets: list[Target] = []
    for app in chosen:
        path = resolved[app.key]
        if path is None:
            # Same point-or-install prompt `vulnbench targets` uses.
            status = _resolve_app(app, root, registry, update=False)
            print(f"  {paint('✓', 'green')} {paint(app.name, bold=True)}: {status}")
            save_registry(registry, root)
            path = resolved_path(app, root, registry)
            if path is None:
                print(paint(f"  skipping {app.name} (not linked)", dim=True))
                continue
        targets.append(app_target(app, path))
    return targets


def _choose_conditions() -> list[str] | None:
    ids = sorted(REGISTRY)
    rows = []
    for cid in ids:
        cls = REGISTRY[cid]
        needs = "model" if cls.needs_model else "scanner-only"
        rows.append(f"{paint(cid, bold=True)}  {cls.label}  {paint('[' + needs + ']', dim=True)}")
    return _pick("3. Select testing scenarios (conditions)", rows, ids)


def _choose_knobs(condition_ids: list[str]) -> dict | None:
    """Offer the union of the chosen conditions' declared knobs; return overrides."""
    available = tunable_knobs(condition_ids)
    if not available:
        return {}
    print(f"\n{paint('4. Optional knobs', 'blue', bold=True)}")
    if not prompt_yes_no("  Tune any condition knobs?", default=False):
        return {}

    names = list(available)
    rows = []
    for name in names:
        knob, users = available[name]
        who = ",".join(users)
        rows.append(
            f"{paint(name, bold=True)} {paint('=' + _default_text(knob), 'amber')}  "
            f"{paint(knob.help, dim=True)} {paint('[' + who + ']', dim=True)}"
        )
    idx = select(rows)
    if idx is None:
        return None

    config: dict = {}
    for i in idx:
        knob, _ = available[names[i]]
        value = _prompt_knob(knob)
        if value is not _UNSET:
            config[knob.name] = value
    return config


#: Sentinel: the user left a knob alone, so it must not enter the config at all.
_UNSET = object()


def _default_text(knob: Knob) -> str:
    """How a knob's default reads in the menu. ``None`` means 'off', not the word None."""
    return "unset" if knob.default is None else str(knob.default)


def _prompt_knob(knob: Knob):
    """Read one knob's value, re-prompting on a parse error. ``_UNSET`` = leave alone.

    A knob whose default is None (an optional file, an absent cap) has no sensible
    text to echo back: offering "None" would either be parsed as the literal string
    "None" (a path that does not exist) or fail int() forever on every <enter>.
    """
    optional = knob.default is None
    while True:
        raw = prompt(f"  {knob.name} [{_default_text(knob)}]: ",
                     default="" if optional else str(knob.default))
        if not raw:
            return _UNSET  # blank on an optional knob: keep the declared default
        try:
            return knob.parse(raw)
        except ValueError as exc:
            print(paint(f"    {exc}", "red"))


def wiring_needed(targets: list[Target], condition_ids: list[str]) -> bool:
    """True when some chosen target is missing a coordinate the chosen conditions want."""
    want_source, want_url = required_inputs(condition_ids)
    return any(
        (want_source and not t.source_path)
        or (want_url and not t.base_url)
        or not t.ground_truth
        for t in targets
    )


def _fill_target_inputs(target: Target, condition_ids: list[str]) -> None:
    """Prompt in place for whatever the conditions need and the manifest didn't supply."""
    want_source, want_url = required_inputs(condition_ids)
    if want_source and not target.source_path:
        raw = prompt(f"  source tree for {target.name} (blank = skip those cells): ")
        target.source_path = str(Path(raw).expanduser()) if raw else None
    if want_url and not target.base_url:
        raw = prompt(f"  base URL for a running {target.name} (blank = skip those cells): ")
        target.base_url = raw or None
    if not target.ground_truth:
        print(paint(f"  {target.name}: no ground truth — metrics will be blank.", dim=True))
        raw = prompt("  ground-truth file (blank = unscored): ")
        target.ground_truth = str(Path(raw).expanduser()) if raw else None


def _is_local_spec(spec: str) -> bool:
    """True for ``local`` and ``local:<model>`` — both are served by Ollama."""
    return spec.partition(":")[0] == "local"


def required_tools(condition_ids: list[str], model_specs: list[str]) -> list[str]:
    """External tool keys this sweep depends on, from the conditions and the models."""
    keys: list[str] = []
    for cid in condition_ids:
        keys.extend(get_condition(cid).all_tools())
    if any(_is_local_spec(spec) for spec in model_specs):
        keys.append("ollama")  # a local spec is served by the Ollama daemon
    return list(dict.fromkeys(keys))  # de-dup, keep declaration order


def _preflight(condition_ids: list[str], model_specs: list[str], config: dict) -> bool:
    """Check external tools up front; offer to install what we can. False = abort.

    A missing scanner is otherwise discovered as a traceback from deep inside a run,
    after the user has configured the whole sweep.
    """
    missing = missing_tools(required_tools(condition_ids, model_specs), config)
    if not missing:
        return True

    print(f"\n{paint('Missing dependencies', 'blue', bold=True)}")
    for tool in missing:
        print(f"  {paint('✗', 'red')} {paint(tool.label, bold=True)}")
        if tool.install_command() and prompt_yes_no(f"    Install now? ({tool.install_note})",
                                                    default=True):
            if run_install(tool, config):
                print(f"    {paint('✓ installed', 'green')}")
                continue
            print(paint("    install failed", "red"))
        print(f"    {paint(tool.hint, dim=True)}")

    still = missing_tools(required_tools(condition_ids, model_specs), config)
    if not still:
        return True
    names = ", ".join(t.label for t in still)
    print(paint(f"\n  Still unavailable: {names}", "red"))
    print(paint("  Cells that need them will fail; the rest of the sweep still runs.", dim=True))
    return prompt_yes_no("  Continue anyway?", default=False)


def _confirm(configs: list[RunConfig], config: dict, n_models: int) -> bool:
    print(f"\n{paint('5. Plan', 'blue', bold=True)}")
    for c in configs:
        print(f"  {paint(c.condition_id, bold=True):16} {c.target.name}  "
              f"{paint(c.model_name, dim=True)}")
    if config:
        print(f"  {paint('knobs:', dim=True)} {json.dumps(config)}")
    print(f"\n  {len(configs)} cell(s) to run.")
    # Explain the row count when it isn't the naive product the user picked.
    shared = sum(1 for c in configs if c.model_spec is None)
    if shared and n_models > 1:
        print(paint(
            f"  ({shared} scanner-only cell(s) run once — no model can change their output)",
            dim=True,
        ))
    return prompt_yes_no("  Run them?", default=True)


# --- execution --------------------------------------------------------------------

def _checkpoint_for(cfg: RunConfig, config: dict, cache: dict[Path, Checkpoint],
                    *, fresh: bool) -> Checkpoint:
    """The checkpoint holding this cell, keyed by the signature of its run inputs.

    Keying the cache on the derived path rather than on ``(target.name, model)`` means
    two targets that happen to share a name but point at different sources can never
    read each other's cells.
    """
    sig = signature(
        target_name=cfg.target.name, kind=str(cfg.target.kind),
        source=cfg.target.source_path, url=cfg.target.base_url,
        ground_truth=cfg.target.ground_truth, model=cfg.model_spec, config=config,
    )
    path = default_path(sig)
    if path not in cache:
        cache[path] = Checkpoint(path, sig, resume=not fresh)
    return cache[path]


def _run_configs(configs: list[RunConfig], config: dict, reporter: Reporter,
                 *, fresh: bool) -> tuple[list[RunRecord], list[Finding], int]:
    """Run every cell, checkpointing per (target, model) so a long sweep can resume."""
    records: list[RunRecord] = []
    all_findings: list[Finding] = []
    gt_cache: dict = {}
    backends: dict[str, ModelBackend] = {}
    backend_errors: dict[str, str] = {}
    checkpoints: dict[Path, Checkpoint] = {}
    reused = 0

    with reporter.track(len(configs)) as tracker:
        for cfg in configs:
            spec = cfg.model_spec
            ckpt = _checkpoint_for(cfg, config, checkpoints, fresh=fresh)

            # Consult the checkpoint before announcing the cell, so a cached one
            # doesn't claim to be running.
            cached = ckpt.get(cfg.condition_id)
            tracker.start(cfg.condition_id, cfg.target.name, resumed=cached is not None)
            if cached is not None:
                record, findings = cached
                reused += 1
                reporter.line(record, resumed=True)
            else:
                # Build each backend once and share it across the cells that use it.
                # A backend that can't be built (missing API key or optional package)
                # fails those cells only — the rest of the sweep still runs.
                if spec is not None and spec not in backends and spec not in backend_errors:
                    try:
                        backends[spec] = build_backend(spec)
                    except (ValueError, RuntimeError) as exc:
                        backend_errors[spec] = f"{type(exc).__name__}: {exc}"
                if spec in backend_errors:
                    record, findings = RunRecord.failed(
                        cfg.target.name, cfg.condition_id, spec, backend_errors[spec],
                    ), []
                else:
                    record, findings = run_one(
                        cfg.target, cfg.condition_id,
                        model=backends[spec] if spec is not None else None,
                        config=config, ground_truth_cache=gt_cache,
                    )
                if record.error is None:
                    ckpt.put(cfg.condition_id, record, findings)
                reporter.line(record)
            tracker.advance()
            records.append(record)
            all_findings.extend(findings)
    return records, all_findings, reused


def _write_scorecard(records: list[RunRecord], all_findings: list) -> dict[str, str]:
    """Ask where to save results, re-prompting until a path works or the user skips.

    A bad path (a directory, a missing parent, no write permission) is a typo, not a
    reason to lose a sweep that may have taken hours — so we say what's wrong and ask
    again rather than letting the OSError escape.
    """
    while True:
        raw = prompt("\n  write scorecard to (blank = skip): ")
        if not raw:
            return {}
        path = Path(raw).expanduser()
        if path.is_dir():
            print(paint(f"    {path} is a directory — give a file path, e.g. "
                        f"{path / 'scorecard.json'}", "red"))
            continue
        if not path.parent.exists():
            print(paint(f"    no such directory: {path.parent}", "red"))
            continue

        findings_path = path.with_suffix(".findings.json")
        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump([r.to_dict() for r in records], fh, indent=2)
            dump_findings(all_findings, str(findings_path))
        except OSError as exc:
            print(paint(f"    could not write: {exc}", "red"))
            continue
        return {
            "scorecard": str(path),
            f"{len(all_findings)} findings": str(findings_path),
        }


def cmd_wizard(args) -> int:
    """`vulnbench` with no subcommand — build and run a comparative sweep."""
    try:
        return _run_wizard(args)
    except KeyboardInterrupt:
        print(paint("\nCancelled.", dim=True))
        return 130


def _cancelled() -> int:
    print(paint("Cancelled.", dim=True))
    return 0


def _run_wizard(args) -> int:
    if not is_interactive():
        print(
            "vulnbench with no arguments starts an interactive session, which needs a "
            "terminal.\nIn a script, use `vulnbench run` (see `vulnbench --help`).",
            file=sys.stderr,
        )
        return 2

    print_banner(make_console(True))

    models = _choose_models()
    if models is None:
        return _cancelled()
    targets = _choose_targets()
    if targets is None:
        return _cancelled()
    conditions = _choose_conditions()
    if conditions is None:
        return _cancelled()
    if not (models and targets and conditions):
        print(paint("Nothing selected.", dim=True))
        return 0

    config = _choose_knobs(conditions)
    if config is None:
        return _cancelled()

    # Knobs first: zap_url may redirect where we look for the ZAP daemon.
    if not _preflight(conditions, models, config):
        return _cancelled()

    if wiring_needed(targets, conditions):
        print(f"\n{paint('Target wiring', 'blue', bold=True)}")
        for target in targets:
            _fill_target_inputs(target, conditions)

    configs = plan_configs(targets, conditions, models)
    if not _confirm(configs, config, len(models)):
        return _cancelled()

    reporter = Reporter(pretty=sys.stdout.isatty())
    records, all_findings, reused = _run_configs(
        configs, config, reporter, fresh=getattr(args, "fresh", False)
    )

    detail_paths: dict[str, str] = {}
    if reused:
        detail_paths["resumed cells"] = str(reused)
    detail_paths.update(_write_scorecard(records, all_findings))

    reporter.matrix(records, detail_paths)
    return 0 if all(r.error is None for r in records) else 1
