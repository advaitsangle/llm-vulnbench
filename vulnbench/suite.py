"""Optional vulnerable-app testing suite: an opt-in, point-or-install manager.

The harness ships *without* the heavy, intentionally-insecure web apps it tests against.
This module lets a user wire them up, two ways per app:

* **point** at a copy they already have sitting around (any directory — no clone needed), or
* **install** a fresh shallow clone into a location they choose.

Either way the resolved location is saved as a *reference* in a small gitignored registry
(``targets/registry.json``), so the path is data, not hard-coded. A clone at the default
``targets/<name>`` is still auto-recognized, so existing checkouts keep working untouched.

The menu itself is the shared widget in :mod:`vulnbench.tui`, which the wizard reuses.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

from .corpus import Target, TargetKind
from .theme import make_console, paint, print_banner, set_plain
from .tui import is_interactive as _is_interactive
from .tui import prompt as _prompt
from .tui import prompt_yes_no as _prompt_yes_no
from .tui import select as _select

_PKG_DIR = Path(__file__).resolve().parent
_MANIFEST = _PKG_DIR / "targets.toml"
_REGISTRY_NAME = "registry.json"


@dataclass(frozen=True)
class App:
    """One entry in the testing suite (a row of ``targets.toml``)."""

    key: str
    name: str
    repo: str
    path: str          # default subdir name under targets/ when installing fresh
    language: str
    description: str
    #: Also selects the scorer: realistic apps are fuzzy-matched against a curated
    #: vuln list, synthetic ones auto-scored against a labelled CSV.
    realistic: bool = True
    #: Run-wiring hints (all optional — see the comment block atop targets.toml).
    #: Path under the app's root to the source tree, for SAST/LLM conditions.
    source_subpath: str | None = None
    #: Path under the app's root to the ground-truth file, if one is curated.
    ground_truth_subpath: str | None = None
    #: Default URL of a locally-deployed instance, for DAST/agentic conditions.
    base_url: str | None = None

    @property
    def kind(self) -> TargetKind:
        return TargetKind.REALISTIC if self.realistic else TargetKind.BENCHMARK


def load_manifest(path: Path | None = None) -> list[App]:
    """Parse ``targets.toml`` into App rows (the stored list of options)."""
    with open(path or _MANIFEST, "rb") as fh:
        data = tomllib.load(fh)
    return [
        App(
            key=row["key"],
            name=row["name"],
            repo=row["repo"],
            path=row["path"],
            language=row["language"],
            description=row["description"],
            realistic=row.get("realistic", True),
            source_subpath=row.get("source_subpath"),
            ground_truth_subpath=row.get("ground_truth_subpath"),
            base_url=row.get("base_url"),
        )
        for row in data.get("app", [])
    ]


def targets_root() -> Path:
    """Default home for fresh clones.

    ``$VULNBENCH_TARGETS_DIR`` wins; next comes ``<repo>/targets`` when running from
    a checkout. When the package is pip-installed, its parent is ``site-packages`` —
    multi-gigabyte app clones must not land there (and can't, on system installs) —
    so fall back to a per-user directory instead.
    """
    env = os.environ.get("VULNBENCH_TARGETS_DIR")
    if env:
        return Path(env)
    repo_root = _PKG_DIR.parent
    if (repo_root / "pyproject.toml").is_file():  # running from a repo checkout
        return repo_root / "targets"
    return Path.home() / ".vulnbench" / "targets"


# --- registry: app key -> resolved path on disk (the "reference") -----------------

def registry_file(root: Path | None = None) -> Path:
    return (root or targets_root()) / _REGISTRY_NAME


def load_registry(root: Path | None = None) -> dict[str, str]:
    try:
        with open(registry_file(root), encoding="utf-8") as fh:
            data = json.load(fh)
        return {str(k): str(v) for k, v in data.items()}
    except (OSError, ValueError):
        return {}


def save_registry(reg: dict[str, str], root: Path | None = None) -> None:
    path = registry_file(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(reg, fh, indent=2, sort_keys=True)


def resolved_path(app: App, root: Path, registry: dict[str, str]) -> Path | None:
    """Where this app lives, or None if unlinked.

    Explicit reference wins; otherwise fall back to the default ``targets/<name>`` if a
    clone happens to be there (so existing checkouts need no migration).
    """
    ref = registry.get(app.key)
    if ref and Path(ref).exists():
        return Path(ref)
    default = root / app.path
    if default.exists():
        return default
    return None


def app_target(app: App, installed_at: Path) -> Target:
    """Build a :class:`~vulnbench.corpus.Target` from an app's run-wiring fields.

    Subpaths that don't exist on disk are left ``None`` rather than guessed at, so a
    caller (e.g. the wizard) can prompt for them instead of silently pointing a
    condition at nothing.
    """
    source = installed_at / app.source_subpath if app.source_subpath else None
    gt = installed_at / app.ground_truth_subpath if app.ground_truth_subpath else None
    return Target(
        name=app.key,
        kind=app.kind,
        source_path=str(source) if source and source.is_dir() else None,
        ground_truth=str(gt) if gt and gt.is_file() else None,
        base_url=app.base_url,
        meta={"language": app.language},
    )


def is_installed(app: App, root: Path | None = None,
                 registry: dict[str, str] | None = None) -> bool:
    """True if the app is linked to an existing directory.

    Pass a pre-loaded ``registry`` when checking many apps so the file is read once.
    """
    root = root or targets_root()
    registry = load_registry(root) if registry is None else registry
    return resolved_path(app, root, registry) is not None


# --- git plumbing (pure command builders, kept separate for testability) ----------

def clone_command(app: App, dest: Path) -> list[str]:
    """Shallow-clone keeps disk + time small; a later pull still advances it."""
    return ["git", "clone", "--depth", "1", app.repo, str(dest)]


def pull_command(dest: Path) -> list[str]:
    """Advance a shallow clone to the latest upstream commit without unshallowing."""
    return ["git", "-C", str(dest), "pull", "--depth", "1", "--ff-only"]


def clone(app: App, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(clone_command(app, dest), check=True)


def pull(dest: Path) -> None:
    subprocess.run(pull_command(dest), check=True)


# --- selection: render App rows, then defer to the shared widget ------------------

def _state_label(path: Path | None) -> str:
    if path is not None:
        return paint(f"linked → {path}", "green")
    return paint("not linked", dim=True)


def _row(app: App, path: Path | None) -> str:
    name = paint(app.name, bold=True)
    lang = paint(f"({app.language})", dim=True)
    return f"{name}  {lang} — {_state_label(path)}"


def _interactive_select(
    apps: list[App], preselected: set[int], resolved: dict[str, Path | None]
) -> list[App] | None:
    """Multi-select over the apps. Returns the chosen ones, or None if cancelled."""
    # Link state can't change while the menu is open, so render each row once up front.
    rows = [_row(app, resolved[app.key]) for app in apps]
    idx = _select(rows, preselected)
    return None if idx is None else [apps[i] for i in idx]


# --- per-app resolution (point at existing, or install fresh) ----------------------

def resolve_app(app: App, root: Path, registry: dict[str, str], *, update: bool) -> str:
    """Bring one selected app to a usable state, mutating ``registry``. Returns a status line.

    Already linked  → optionally pull; otherwise leave it.
    Unlinked, TTY   → ask: point at an existing dir, install fresh, or skip.
    Unlinked, batch → install fresh at the default location.
    """
    path = resolved_path(app, root, registry)
    if path is not None:
        if update and (path / ".git").is_dir():
            pull(path)
            registry[app.key] = str(path)
            return paint(f"updated → {path}", "green")
        if update:
            return paint(f"linked → {path} (not a git checkout; skipped update)", dim=True)
        registry[app.key] = str(path)  # promote a default-location clone to an explicit ref
        return paint(f"already linked → {path}", "green")

    default_dest = root / app.path
    if not _is_interactive():
        clone(app, default_dest)
        registry[app.key] = str(default_dest)
        return paint(f"installed → {default_dest}", "green")

    print(f"\n{paint(app.name, bold=True)} {paint(f'({app.language})', dim=True)} "
          "is not linked.")
    print(f"  {paint(app.description, dim=True)}")
    choice = _prompt(
        "  (e) point to a copy you already have · (i) install a fresh clone · (s) skip  [i] ",
        default="i",
    ).lower()[:1]

    if choice == "s":
        return paint("skipped", dim=True)

    if choice == "e":
        raw = _prompt("  path to your existing copy: ")
        if not raw:
            return paint("skipped (no path given)", dim=True)
        target = Path(raw).expanduser()
        if not target.is_dir():
            return paint(f"skipped (not a directory: {target})", "red")
        registry[app.key] = str(target.resolve())
        return paint(f"linked → {target.resolve()}", "green")

    # install fresh, letting them choose where (default: targets/<name>)
    raw = _prompt(f"  install location [{default_dest}]: ", default=str(default_dest))
    dest = Path(raw).expanduser()
    clone(app, dest)
    registry[app.key] = str(dest.resolve())
    return paint(f"installed → {dest.resolve()}", "green")


# --- command entry point ----------------------------------------------------------

def _print_overview(apps: list[App], resolved: dict[str, Path | None]) -> None:
    """What's already linked (and where), or a note that nothing is yet."""
    linked = [(a, resolved[a.key]) for a in apps if resolved[a.key] is not None]
    print(paint("Linked testing apps", "blue", bold=True))
    if linked:
        for app, path in linked:
            print(f"  {paint('✓', 'green')} {app.name}  {paint(f'→ {path}', dim=True)}")
    else:
        print(paint("  nothing linked yet", dim=True))


def _print_defaults(apps: list[App], resolved: dict[str, Path | None],
                    preselected: set[int]) -> None:
    """The default options offered to add (the suggested, not-yet-linked apps)."""
    print("\n" + paint("Available to add", "blue", bold=True))
    available = [(i, a) for i, a in enumerate(apps) if resolved[a.key] is None]
    if not available:
        print(paint("  everything is linked — re-run with --update to refresh clones", dim=True))
        return
    for i, app in available:
        star = paint("●", "amber") if i in preselected else " "
        print(f"  {star} {paint(app.name, bold=True)} {paint(f'({app.language})', dim=True)}")
        print(f"    {paint(app.description, dim=True)}")
    print(paint("  ● = selected by default · you'll choose point-vs-install per app", dim=True))


def cmd_targets(args) -> int:
    """`vulnbench targets` — opt-in manager for the vulnerable-app testing suite."""
    try:
        return _run_targets(args)
    except KeyboardInterrupt:
        print(paint("\nCancelled.", dim=True))
        return 130


def _run_targets(args) -> int:
    set_plain(getattr(args, "plain", False))  # one switch governs rich + ANSI color
    apps = load_manifest()
    root = targets_root()
    registry = load_registry(root)
    console = make_console(True)
    # Resolve every app's location once; reused for display, preselection, and the menu.
    resolved = {a.key: resolved_path(a, root, registry) for a in apps}

    # Scripting hook: print the resolved path for one app (e.g. for `run --source`).
    if getattr(args, "path", None):
        if args.path not in resolved:
            print(f"unknown app: {args.path}", file=sys.stderr)
            return 2
        if resolved[args.path] is None:
            print(f"{args.path} is not linked", file=sys.stderr)
            return 1
        print(resolved[args.path])
        return 0

    if args.list:
        print_banner(console)
        for app in apps:
            print(f"  {paint(app.key, bold=True):12} {_state_label(resolved[app.key])}")
            print(f"               {paint(app.description, dim=True)}")
        return 0

    # Default preselection: the realistic apps that aren't linked yet.
    preselected = {i for i, a in enumerate(apps) if a.realistic and resolved[a.key] is None}

    # 1) Decide which apps to act on.
    if args.all:
        chosen: list[App] | None = list(apps)
    elif not _is_interactive():
        print("Non-interactive shell: pass --all (every app) or --list, or run in a terminal "
              "to pick interactively.", file=sys.stderr)
        return 2
    else:
        print_banner(console)
        _print_overview(apps, resolved)
        _print_defaults(apps, resolved, preselected)
        print()
        if not args.yes and not _prompt_yes_no(
            "Manage the testing suite?", default=False
        ):
            print(paint("Exited.", dim=True))
            return 0
        print()
        chosen = _interactive_select(apps, preselected, resolved)
        if chosen is None:
            print(paint("Cancelled.", dim=True))
            return 0

    if not chosen:
        print(paint("Nothing selected.", dim=True))
        return 0

    # 2) Resolve each (point-or-install per app), saving references as we go.
    print()
    failed = 0
    for app in chosen:
        try:
            status = resolve_app(app, root, registry, update=args.update)
            print(f"  {paint('✓', 'green')} {paint(app.name, bold=True)}: {status}")
        except (subprocess.CalledProcessError, OSError) as exc:
            failed += 1
            print(f"  {paint('✗', 'red')} {app.name}: {exc}", file=sys.stderr)
    save_registry(registry, root)
    return 1 if failed else 0
