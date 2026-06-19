"""Presentation layer: a colorful, lightly animated CLI summary.

The harness produces :class:`~vulnbench.harness.RunRecord` objects; this module
renders the *highlight* (a colored metrics table with a live spinner while each
condition runs) to the terminal, while the full detail goes to JSON files. It uses
``rich`` when available and degrades to plain text otherwise, so the core harness
never hard-depends on it (install with ``pip install 'vulnbench[pretty]'``).
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
    from rich.table import Table
    from rich.text import Text

    _RICH = True
except ImportError:  # pragma: no cover - exercised only without the extra
    _RICH = False


def rich_available() -> bool:
    return _RICH


# F1 thresholds for the green / yellow / red color bands.
def _metric_color(value: float) -> str:
    if value >= 0.7:
        return "bold green"
    if value >= 0.5:
        return "yellow"
    return "red"


class Reporter:
    """Renders run progress and a final summary. Pretty when rich is present."""

    def __init__(self, pretty: bool = True) -> None:
        self.pretty = pretty and _RICH
        self.console = Console() if self.pretty else None

    @contextmanager
    def running(self, condition_id: str, target: str):
        """Show an animated spinner while a condition runs."""
        if self.pretty:
            with self.console.status(
                f"[cyan]Running [bold]{condition_id}[/bold] on [bold]{target}[/bold]…",
                spinner="dots",
            ):
                yield
        else:
            print(f"… running {condition_id} on {target}")
            yield

    def line(self, record: RunRecord) -> None:
        """Print a one-line result the moment a condition finishes (live feel)."""
        if not self.pretty:
            return  # plain mode prints the full block in summary instead
        if record.error:
            self.console.print(f"  [red]✗[/red] {record.condition}  [red]{record.error}[/red]")
            return
        m = record.metrics
        if m:
            f1 = Text(f"F1 {m['f1']:.2f}", style=_metric_color(m["f1"]))
            self.console.print(
                f"  [green]✓[/green] [bold]{record.condition}[/bold]  "
                f"{record.n_findings} findings  ",
                f1,
                f"  [dim]{record.seconds:.1f}s[/dim]",
            )
        else:
            self.console.print(
                f"  [green]✓[/green] [bold]{record.condition}[/bold]  "
                f"{record.n_findings} findings  [dim]no ground truth[/dim]"
            )

    def summary(self, records: list[RunRecord], target: str, detail_paths: dict[str, str]) -> None:
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
            header_style="bold magenta",
            title_style="bold cyan",
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
                Panel(body, title="detailed output", border_style="dim", expand=False)
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
