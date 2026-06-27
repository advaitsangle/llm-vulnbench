"""Shared CLI look-and-feel: one mascot, one palette, one banner.

Every command (`run`, `targets`, …) should look like the same tool, so the colors,
the pixel-heart banner, and the rich/plain degradation live here once and are imported
wherever they're needed — instead of each command re-deriving its own styling.

Two styling front-ends share the same :data:`PALETTE`:
- **rich** (when the optional extra is installed) for tables/panels/banner — via
  :func:`make_console` / :func:`print_banner`.
- **raw ANSI** (stdlib only) for hand-drawn UI like the interactive menu — via
  :func:`paint`, honoring ``NO_COLOR`` and non-TTY output.
"""

from __future__ import annotations

import os
import sys

try:  # rich is an optional extra ('vulnbench[pretty]')
    from rich.console import Console
    from rich.text import Text

    _RICH = True
except ImportError:  # pragma: no cover - exercised only without the extra
    _RICH = False


# Palette sampled from the mascot sprite (a Stardew-style pixel character on an
# amber field). These exact hexes theme the banner, tables, and CLI accents.
PALETTE = {
    "amber": "#e5a23a",     # accent dot
    "blue": "#3d5cc8",      # wordmark / progress bar
    "navy": "#1a2a66",      # table borders
    "pink": "#e64c72",      # heart
    "pinkhi": "#f4a7c0",    # heart highlight / tagline
    "magenta": "#9e3566",   # heart outline
    "green": "#3aa657",     # success
    "red": "#d23f3f",       # error
}

TAGLINE = "LLM-augmented web vulnerability detection"

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


# --- raw-ANSI styling (stdlib only) -----------------------------------------------

_RESET = "\x1b[0m"
_BOLD = "\x1b[1m"
_DIM = "\x1b[2m"

# Commands can force plain output (e.g. a `--plain` flag); this governs both the
# rich front-end (via make_console) and the raw-ANSI one (via paint), so a single
# switch turns off all color.
_PLAIN = False


def set_plain(plain: bool) -> None:
    """Force plain (no-color) output regardless of TTY, for a ``--plain`` flag."""
    global _PLAIN
    _PLAIN = plain


def use_color() -> bool:
    """True when ANSI color is appropriate: not forced plain, a TTY, ``NO_COLOR`` unset."""
    return not _PLAIN and sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _rgb(hex_color: str) -> tuple[int, int, int]:
    h = hex_color.lstrip("#")
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


def _ansi(color: str) -> str:
    """Truecolor escape for a PALETTE key (or a raw ``#rrggbb``)."""
    r, g, b = _rgb(PALETTE.get(color, color))
    return f"\x1b[38;2;{r};{g};{b}m"


def paint(text: str, color: str | None = None, *, bold: bool = False, dim: bool = False) -> str:
    """Wrap ``text`` in ANSI styling (no-op when color is disabled)."""
    if not use_color():
        return text
    prefix = ""
    if bold:
        prefix += _BOLD
    if dim:
        prefix += _DIM
    if color:
        prefix += _ansi(color)
    return f"{prefix}{text}{_RESET}" if prefix else text


# --- rich styling -----------------------------------------------------------------

def make_console(pretty: bool = True):
    """A rich Console when pretty + rich available and not forced plain, else ``None``."""
    return Console() if (pretty and _RICH and not _PLAIN) else None


def _banner_text():  # -> rich Text
    """A pixel heart with the colored ``vulnbench`` wordmark beside it (rich)."""
    heart = _render_sprite(_HEART)  # 3 lines
    wordmark = [
        Text(),
        Text.assemble(
            ("vulnbench", f"bold {PALETTE['blue']}"),
            ("  ·  ", PALETTE["amber"]),
            (TAGLINE, PALETTE["pinkhi"]),
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


def print_banner(console=None) -> None:
    """Print the mascot banner: rich heart when a console is given, else plain text."""
    if console is not None:
        console.print(_banner_text())
    else:
        print(f"vulnbench — {TAGLINE}")


# F1 thresholds for the green / yellow / red color bands.
def metric_color(value: float) -> str:
    if value >= 0.7:
        return "bold green"
    if value >= 0.5:
        return "yellow"
    return "red"
