"""Presentation layer: a colorful, lightly animated CLI summary.

The harness produces :class:`~vulnbench.harness.RunRecord` objects; this module
renders the *highlight* (a banner, a live progress bar across the condition
sweep, and a color-coded metrics table) to the terminal, while the full detail
goes to JSON files. It uses ``rich`` when available and degrades to plain text
otherwise, so the core harness never hard-depends on it (install with
``pip install 'vulnbench[pretty]'``).

The palette is sampled from the project's pixel-art mascot, so the banner and the
CLI accents share one set of colors.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .harness import RunRecord

try:  # rich is an optional extra
    from rich.box import ROUNDED
    from rich.console import Console
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

    _RICH = True
except ImportError:  # pragma: no cover - exercised only without the extra
    _RICH = False


def rich_available() -> bool:
    return _RICH


# Palette sampled from the mascot sprite (a Stardew-style pixel character on an
# amber field). These exact hexes theme both the banner and the CLI accents.
PALETTE = {
    "amber": "#e5a23a",     # accent dot
    "blue": "#3d5cc8",      # wordmark / progress bar
    "navy": "#1a2a66",      # table borders
    "pink": "#e64c72",      # heart
    "pinkhi": "#f4a7c0",    # heart highlight / tagline
    "magenta": "#9e3566",   # heart outline
}

# A pixel heart; rows are rendered two-at-a-time with the upper-half-block trick
# so the art stays compact (6 rows -> 3 terminal lines).
_HEART = [
    ".mm.mm.",
    "mpphppm",
    "mpppppm",
    ".mpppm.",
    "..mpm..",
    "...m...",
]
_GLYPHS = {"m": "magenta", "p": "pink", "h": "pinkhi"}


def _color_of(glyph: str) -> str | None:
    return PALETTE.get(_GLYPHS.get(glyph, ""))


def _render_sprite(grid: list[str]):  # -> list[Text]
    """Render a pixel grid into half-height terminal lines via ``▀``/``▄``."""
    width = max(len(r) for r in grid)
    rows = [r.ljust(width) for r in grid]
    if len(rows) % 2:
        rows.append(" " * width)
    lines = []
    for i in range(0, len(rows), 2):
        line = Text()
        for top, bot in zip(rows[i], rows[i + 1], strict=True):
            tc, bc = _color_of(top), _color_of(bot)
            if tc and bc:
                line.append("▀", style=f"{tc} on {bc}")
            elif tc:
                line.append("▀", style=tc)
            elif bc:
                line.append("▄", style=bc)
            else:
                line.append(" ")
        lines.append(line)
    return lines


def _banner_text() -> Text:
    """A pixel heart with the colored ``vulnbench`` wordmark beside it."""
    heart = _render_sprite(_HEART)  # 3 lines
    wordmark = [
        Text(),
        Text.assemble(
            ("vulnbench", f"bold {PALETTE['blue']}"),
            ("  ·  ", PALETTE["amber"]),
            ("LLM-augmented web vulnerability detection", PALETTE["pinkhi"]),
        ),
        Text(),
    ]
    out = Text()
    for i, hline in enumerate(heart):
        out.append("  ")
        out.append_text(hline)
        out.append("   ")
        out.append_text(wordmark[i])
        out.append("\n")
    return out


# F1 thresholds for the green / yellow / red color bands.
def _metric_color(value: float) -> str:
    if value >= 0.7:
        return "bold green"
    if value >= 0.5:
        return "yellow"
    return "red"


class _Tracker:
    """Drives a live progress bar across the condition sweep (rich mode)."""

    def __init__(self, progress: Progress, task_id) -> None:
        self._progress = progress
        self._task = task_id

    def start(self, condition_id: str, target: str) -> None:
        self._progress.update(
            self._task,
            description=f"[{PALETTE['blue']}]running [bold]{condition_id}[/bold] on {target}",
        )

    def advance(self) -> None:
        self._progress.advance(self._task)


class _PlainTracker:
    """No-op-ish tracker for plain mode: prints one line as each condition starts."""

    def start(self, condition_id: str, target: str) -> None:
        print(f"… running {condition_id} on {target}")

    def advance(self) -> None:
        pass


class Reporter:
    """Renders run progress and a final summary. Pretty when rich is present."""

    def __init__(self, pretty: bool = True) -> None:
        self.pretty = pretty and _RICH
        self.console = Console() if self.pretty else None

    def banner(self) -> None:
        """Print the mascot banner once at the top of a run."""
        if self.pretty:
            self.console.print(_banner_text())
        else:
            print("vulnbench — LLM-augmented web vulnerability detection")

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
            f1 = Text(f"F1 {m['f1']:.2f}", style=_metric_color(m["f1"]))
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
                    Text(f"{m['f1']:.2f}", style=_metric_color(m["f1"])),
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
