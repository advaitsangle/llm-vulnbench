"""Reusable terminal input widgets: a multi-select menu and small prompts.

Stdlib only (the project's core has zero third-party deps): the menu is a small
raw-terminal reader via ``termios``/``tty``, with a numbered-prompt fallback whenever
stdin/stdout isn't a TTY (pipes, CI). Both front-ends return the same thing — the
indices the user chose — so a caller never cares which one ran.

This lives apart from its callers because two of them need it: ``vulnbench targets``
picks apps to install, and the ``vulnbench`` wizard picks models, targets, and
conditions. The widget knows nothing about either; it takes pre-rendered rows.
"""

from __future__ import annotations

import sys

from .theme import paint

#: Returned by :func:`select` when the user cancels (q / ESC / empty input).
CANCELLED = None


def is_interactive() -> bool:
    """True when we can drive a raw-terminal menu (both ends are a TTY)."""
    return sys.stdin.isatty() and sys.stdout.isatty()


def prompt(question: str, default: str = "") -> str:
    try:
        resp = input(question).strip()
    except EOFError:
        return default
    return resp or default


def prompt_yes_no(question: str, default: bool) -> bool:
    suffix = "[Y/n]" if default else "[y/N]"
    resp = prompt(f"{question} {suffix} ").lower()
    if not resp:
        return default
    return resp in ("y", "yes")


def parse_numeric_selection(text: str, count: int) -> list[int]:
    """Parse "1 3 4" / "1,3" into sorted unique 0-based indices in range; ignore junk."""
    out: set[int] = set()
    for tok in text.replace(",", " ").split():
        if tok.isdigit():
            i = int(tok) - 1
            if 0 <= i < count:
                out.add(i)
    return sorted(out)


def _read_key(stream) -> str:
    """Translate one keypress into a token: up/down/space/enter/quit or a literal char."""
    ch = stream.read(1)
    if ch == "\x1b":  # ESC — start of an arrow-key sequence (ESC [ A/B) or a lone ESC
        if stream.read(1) == "[":
            return {"A": "up", "B": "down"}.get(stream.read(1), "other")
        return "quit"
    if ch in ("\r", "\n"):
        return "enter"
    if ch == " ":
        return "space"
    if ch == "\x03":  # Ctrl-C
        raise KeyboardInterrupt
    return ch.lower()


def _interactive_select(rows: list[str], preselected: set[int]) -> list[int] | None:
    """Raw-terminal multi-select over pre-rendered ``rows``. None if cancelled."""
    import termios
    import tty

    selected = set(preselected)
    cursor = 0
    print(paint("  ↑/↓ move · space toggle · a toggle-all · enter confirm · q cancel\n", dim=True))

    def draw(first: bool) -> None:
        if not first:
            sys.stdout.write(f"\x1b[{len(rows)}A")  # cursor up to the first row
        for i, row in enumerate(rows):
            pointer = paint("›", "amber", bold=True) if i == cursor else " "
            box = paint("◉", "pink") if i in selected else paint("○", dim=True)
            sys.stdout.write(f"\r\x1b[K {pointer} {box} {row}\n")
        sys.stdout.flush()

    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    draw(first=True)
    try:
        tty.setcbreak(fd)
        while True:
            key = _read_key(sys.stdin)
            if key == "up":
                cursor = (cursor - 1) % len(rows)
            elif key == "down":
                cursor = (cursor + 1) % len(rows)
            elif key == "space":
                selected.symmetric_difference_update({cursor})
            elif key == "a":
                selected = set() if len(selected) == len(rows) else set(range(len(rows)))
            elif key == "enter":
                break
            elif key in ("q", "quit"):
                return None
            else:
                continue
            draw(first=False)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
    return sorted(selected)


def _text_select(rows: list[str], preselected: set[int]) -> list[int] | None:
    """Numbered-prompt fallback for non-TTY stdin (pipes/CI)."""
    print("Available options:")
    for i, row in enumerate(rows, 1):
        mark = "*" if (i - 1) in preselected else " "
        print(f"  {i}.{mark} {row}")
    resp = prompt("Select numbers (e.g. 1 3), 'all', or blank to cancel: ").lower()
    if not resp:
        return None
    if resp == "all":
        return list(range(len(rows)))
    return parse_numeric_selection(resp, len(rows))


def select(rows: list[str], preselected: set[int] | None = None) -> list[int] | None:
    """Multi-select over ``rows``; returns chosen 0-based indices, or ``CANCELLED``.

    Picks the raw-terminal menu when possible and the numbered prompt otherwise, so a
    caller works the same under a terminal, a pipe, and CI.
    """
    if not rows:
        return []
    pre = preselected or set()
    front_end = _interactive_select if is_interactive() else _text_select
    return front_end(rows, pre)
