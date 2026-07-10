"""Presentation layer: a colorful, lightly animated CLI summary.

The harness produces :class:`~vulnbench.harness.RunRecord` objects; this module
renders the *highlight* (a banner, a live progress bar across the condition
sweep, and a color-coded metrics table) to the terminal, while the full detail
goes to JSON files. It uses ``rich`` when available and degrades to plain text
otherwise, so the core harness never hard-depends on it (install with
``pip install 'vulnbench[pretty]'``).

The shared look (palette, mascot banner, rich detection) lives in :mod:`vulnbench.theme`
so every command renders as the same tool; this module only adds the run-specific
progress bar and metrics table.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import TYPE_CHECKING

from .theme import PALETTE, make_console, metric_color, print_banner

if TYPE_CHECKING:
    from .harness import RunRecord

try:  # rich is an optional extra
    from rich.box import ROUNDED
    from rich.panel import Panel
    from rich.progress import (
        BarColumn,
        MofNCompleteColumn,
        Progress,
        SpinnerColumn,
        TextColumn,
        TimeElapsedColumn,
    )
    from rich.table import Table
    from rich.text import Text
except ImportError:  # pragma: no cover - exercised only without the extra
    pass


def _best_f1(records: list[RunRecord]) -> int | None:
    """Index of the highest-F1 scored cell, or None if nothing was scored.

    Ties go to the first cell, which is the cheapest configuration reached in sweep
    order — the honest pick when two configurations detect equally well.
    """
    scored = [(i, r.metrics["f1"]) for i, r in enumerate(records) if r.metrics and not r.error]
    if not scored:
        return None
    return max(scored, key=lambda pair: pair[1])[0]


def _matrix_cells(record: RunRecord) -> list[str]:
    """One matrix row as plain strings: target, model, cond, then the metrics.

    The best-F1 marker is *not* folded in here — it gets its own column, so a wide
    glyph can never push the F1 value onto a second line or skew a fixed-width field.
    """
    head = [record.target, record.model or "—", record.condition]
    if record.error:
        return [*head, "error", "—", "—", "—", "—", "—", "—"]
    tokens = record.input_tokens + record.output_tokens
    tail = [f"{record.seconds:.1f}s", str(tokens)]
    m = record.metrics
    if not m:
        return [*head, str(record.n_findings), "—", "—", "—", "—", *tail]
    return [
        *head, str(record.n_findings), f"{m['precision']:.2f}", f"{m['recall']:.2f}",
        f"{m['f1']:.2f}", f"{m['fpr']:.2f}", *tail,
    ]


class _Tracker:
    """Drives a live progress bar across the condition sweep (rich mode)."""

    def __init__(self, progress: Progress, task_id) -> None:
        self._progress = progress
        self._task = task_id

    def start(self, condition_id: str, target: str, *, resumed: bool = False) -> None:
        verb = "resuming" if resumed else "running"
        color = PALETTE["amber"] if resumed else PALETTE["blue"]
        self._progress.update(
            self._task,
            description=f"[{color}]{verb} [bold]{condition_id}[/bold] on {target}",
        )

    def advance(self) -> None:
        self._progress.advance(self._task)


class _PlainTracker:
    """No-op-ish tracker for plain mode: prints one line as each condition starts."""

    def start(self, condition_id: str, target: str, *, resumed: bool = False) -> None:
        verb = "resumed" if resumed else "running"
        print(f"… {verb} {condition_id} on {target}")

    def advance(self) -> None:
        pass


class Reporter:
    """Renders run progress and a final summary. Pretty when rich is present."""

    def __init__(self, pretty: bool = True) -> None:
        self.console = make_console(pretty)
        self.pretty = self.console is not None

    def banner(self) -> None:
        """Print the mascot banner once at the top of a run."""
        print_banner(self.console)

    @contextmanager
    def track(self, total: int):
        """Yield a tracker driving a live progress bar over ``total`` conditions."""
        if self.pretty:
            progress = Progress(
                SpinnerColumn(style=PALETTE["blue"]),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(
                    complete_style=PALETTE["blue"],
                    finished_style=PALETTE["pink"],
                    pulse_style=PALETTE["amber"],
                ),
                MofNCompleteColumn(),
                TimeElapsedColumn(),
                console=self.console,
            )
            with progress:
                task = progress.add_task("starting…", total=total)
                yield _Tracker(progress, task)
        else:
            yield _PlainTracker()

    def line(self, record: RunRecord, *, resumed: bool = False) -> None:
        """Print a one-line result the moment a condition finishes (live feel)."""
        if not self.pretty:
            return  # plain mode prints the full block in summary instead
        tag = f"[{PALETTE['amber']}](resumed)[/] " if resumed else ""
        if record.error:
            self.console.print(f"  [red]✗[/red] {tag}{record.condition}  [red]{record.error}[/red]")
            return
        m = record.metrics
        if m:
            f1 = Text(f"F1 {m['f1']:.2f}", style=metric_color(m["f1"]))
            self.console.print(
                f"  [green]✓[/green] {tag}[bold]{record.condition}[/bold]  "
                f"{record.n_findings} findings  ",
                f1,
                f"  [dim]{record.seconds:.1f}s[/dim]",
            )
        else:
            self.console.print(
                f"  [green]✓[/green] {tag}[bold]{record.condition}[/bold]  "
                f"{record.n_findings} findings  [dim]no ground truth[/dim]"
            )

    def summary(
        self, records: list[RunRecord], target: str, detail_paths: dict[str, str]
    ) -> None:
        """Render the highlight table + where the detailed files went."""
        if self.pretty:
            self._summary_rich(records, target, detail_paths)
        else:
            self._summary_plain(records, target, detail_paths)

    # ---- comparative matrix (target x model x condition) --------------------
    def matrix(self, records: list[RunRecord], detail_paths: dict[str, str]) -> None:
        """Render a sweep that varies target and/or model, not just condition.

        :meth:`summary` assumes one target and one model and so omits both columns.
        A wizard run is a cartesian product, and the whole point is comparing across
        it, so every cell needs to say which (target, model, condition) it is.
        """
        best = _best_f1(records)
        if self.pretty:
            self._matrix_rich(records, detail_paths, best)
        else:
            self._matrix_plain(records, detail_paths, best)

    def _matrix_rich(self, records, detail_paths, best):  # noqa: ANN001
        table = Table(
            title="vulnbench · comparative run",
            caption=None if best is None else "★ best F1",
            box=ROUNDED,
            header_style=f"bold {PALETTE['blue']}",
            title_style=f"bold {PALETTE['amber']}",
            border_style=PALETTE["navy"],
            expand=False,
        )
        table.add_column("", width=1, no_wrap=True)  # best-F1 marker
        for col in ("Target", "Model", "Cond"):
            table.add_column(col, style="bold" if col == "Cond" else None, no_wrap=True)
        for col in ("Findings", "Prec", "Recall", "F1", "FPR", "Latency", "Tokens"):
            table.add_column(col, justify="right", no_wrap=True)

        # Repeat a target/model label only when it changes, so the eye tracks the
        # variable that actually differs down a block of rows.
        prev: tuple[str, str] | None = None
        for i, r in enumerate(records):
            cells = _matrix_cells(r)
            group = (r.target, r.model or "—")
            if group == prev:
                cells[0] = cells[1] = ""
            elif prev is not None:  # divider between blocks, but not under the header
                table.add_section()
            prev = group
            marker = Text("★", style=PALETTE["amber"]) if i == best else ""
            # Mirror _matrix_cells: an errored cell renders "—", which has no F1 to color.
            scored = r.metrics and not r.error
            f1 = Text(cells[6], style=metric_color(r.metrics["f1"])) if scored else cells[6]
            table.add_row(marker, *cells[:6], f1, *cells[7:])

        self.console.print()
        self.console.print(table)
        if detail_paths:
            body = "\n".join(f"[bold]{k}[/bold] → {v}" for k, v in detail_paths.items())
            self.console.print(
                Panel(body, title="detailed output", border_style=PALETTE["navy"], expand=False)
            )

    def _matrix_plain(self, records, detail_paths, best):  # noqa: ANN001
        print("\n=== vulnbench comparative run ===")
        print(f"  {'Target':14} {'Model':22} {'Cond':5} {'Find':>5} {'Prec':>5} "
              f"{'Rec':>5} {'F1':>5} {'FPR':>5} {'Lat':>8} {'Tokens':>8}")
        for i, r in enumerate(records):
            target, model, cond, find, prec, rec, f1, fpr, lat, tok = _matrix_cells(r)
            marker = "*" if i == best else " "
            print(f"{marker} {target:14.14} {model:22.22} {cond:5} {find:>5} {prec:>5} "
                  f"{rec:>5} {f1:>5} {fpr:>5} {lat:>8} {tok:>8}")
        if best is not None:
            print("  (* = best F1)")
        for k, v in detail_paths.items():
            print(f"  {k} -> {v}")

    # ---- rich rendering ----------------------------------------------------
    def _summary_rich(self, records, target, detail_paths):  # noqa: ANN001
        table = Table(
            title=f"vulnbench · {target}",
            box=ROUNDED,
            header_style=f"bold {PALETTE['blue']}",
            title_style=f"bold {PALETTE['amber']}",
            border_style=PALETTE["navy"],
            expand=False,
        )
        table.add_column("Cond", style="bold")
        table.add_column("Findings", justify="right")
        table.add_column("Prec", justify="right")
        table.add_column("Recall", justify="right")
        table.add_column("F1", justify="right")
        table.add_column("FPR", justify="right")
        table.add_column("Latency", justify="right")
        table.add_column("Tokens", justify="right")

        for r in records:
            if r.error:
                table.add_row(r.condition, Text("error", style="red"), "—", "—", "—", "—", "—", "—")
                continue
            m = r.metrics
            if m:
                table.add_row(
                    r.condition,
                    str(r.n_findings),
                    f"{m['precision']:.2f}",
                    f"{m['recall']:.2f}",
                    Text(f"{m['f1']:.2f}", style=metric_color(m["f1"])),
                    f"{m['fpr']:.2f}",
                    f"{r.seconds:.1f}s",
                    str(r.input_tokens + r.output_tokens),
                )
            else:
                table.add_row(
                    r.condition, str(r.n_findings), "—", "—", "—", "—",
                    f"{r.seconds:.1f}s", str(r.input_tokens + r.output_tokens),
                )

        self.console.print()
        self.console.print(table)
        if detail_paths:
            body = "\n".join(f"[bold]{k}[/bold] → {v}" for k, v in detail_paths.items())
            self.console.print(
                Panel(body, title="detailed output", border_style=PALETTE["navy"], expand=False)
            )

    # ---- plain fallback ----------------------------------------------------
    def _summary_plain(self, records, target, detail_paths):  # noqa: ANN001
        print(f"\n=== vulnbench summary · {target} ===")
        header = f"{'Cond':5} {'Find':>5} {'Prec':>5} {'Rec':>5} {'F1':>5} {'FPR':>5} {'Lat':>7}"
        print(header)
        for r in records:
            if r.error:
                print(f"{r.condition:5} {'ERROR':>5}  {r.error}")
                continue
            m = r.metrics
            if m:
                print(
                    f"{r.condition:5} {r.n_findings:>5} {m['precision']:>5.2f} "
                    f"{m['recall']:>5.2f} {m['f1']:>5.2f} {m['fpr']:>5.2f} {r.seconds:>6.1f}s"
                )
            else:
                print(f"{r.condition:5} {r.n_findings:>5} {'—':>5} {'—':>5} {'—':>5} "
                      f"{'—':>5} {r.seconds:>6.1f}s")
        for k, v in detail_paths.items():
            print(f"  {k} -> {v}")
