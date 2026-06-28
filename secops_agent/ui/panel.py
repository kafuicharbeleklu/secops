"""
Reusable interactive terminal panels.
"""

from __future__ import annotations

import shutil
import sys
import termios
import tty
from dataclasses import dataclass
from typing import Callable

from secops_agent.ui.overlay import read_terminal_key
from secops_agent.ui.theme import ANSI_RESET, ansi


@dataclass(frozen=True)
class PanelRow:
    value: str
    label: str
    status: str = ""
    description: str = ""
    accent: bool = False


@dataclass(frozen=True)
class PanelResult:
    action: str
    value: str


def _fit(text: str, width: int) -> str:
    if width <= 0:
        return ""
    if len(text) <= width:
        return text
    if width == 1:
        return "…"
    return text[: width - 1] + "…"


def _window_start(selected: int, total: int, visible_count: int) -> int:
    if total <= visible_count:
        return 0
    half = visible_count // 2
    return min(max(0, selected - half), max(0, total - visible_count))


def build_panel_lines(
    title: str,
    rows: list[PanelRow],
    detail_lines: list[str] | None = None,
    *,
    selected: int = 0,
    width: int = 96,
    height: int = 28,
    footer: str = "",
    empty_message: str = "",
) -> list[str]:
    """Build a bounded plain-text panel layout for rendering and tests."""
    width = max(1, width - 1)
    height = max(10, height)
    detail_lines = detail_lines or []
    divider = "─" * width
    lines = [divider, f"  {_fit(title, width - 4)}", divider]

    content_height = max(5, height - 6)
    if not rows:
        lines.append("")
        lines.append(f"  {_fit(empty_message or 'No items.', width - 4)}")
        while len(lines) < height - 2:
            lines.append("")
        lines.append(divider)
        lines.append(f"  {_fit(footer, width - 4)}" if footer else divider)
        return [_fit(line, width) for line in lines[:height]]

    selected = min(max(0, selected), len(rows) - 1)
    list_width = min(46, max(8, width // 2))
    gap_width = 2
    detail_width = max(1, width - list_width - gap_width - 2)
    start = _window_start(selected, len(rows), content_height)

    for offset in range(content_height):
        row_index = start + offset
        if row_index < len(rows):
            row = rows[row_index]
            cursor = "›" if row_index == selected else " "
            status = f" {row.status}" if row.status else ""
            description = f"  {row.description}" if row.description else ""
            left = f"{cursor} {row.label}{status}{description}"
            left = _fit(left, list_width)
        else:
            left = ""

        right = _fit(detail_lines[offset], detail_width) if offset < len(detail_lines) else ""
        lines.append(f"  {left:<{list_width}}{' ' * gap_width}{right}")

    lines.append(divider)
    lines.append(f"  {_fit(footer, width - 4)}" if footer else divider)
    return [_fit(line, width) for line in lines[:height]]


def choose_panel(
    title: str,
    rows: list[PanelRow],
    detail_provider: Callable[[PanelRow], list[str]] | None = None,
    *,
    footer: str = "Keyboard: ↑/↓ Navigate  enter Select  esc Go Back",
    empty_message: str = "",
) -> PanelResult | None:
    """Open an alternate-screen list/detail panel and return the chosen action."""
    if not sys.stdin.isatty() or not rows:
        return None

    selected = 0
    c_accent = ansi("accent", bold=True)
    c_text = ansi("text")
    c_muted = ansi("text_muted")
    c_dim = ansi("text_dim")
    reset = ANSI_RESET

    def read_key() -> str:
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            key = read_terminal_key(fd)
            if key == "mouse_up":
                return "up"
            if key == "mouse_down":
                return "down"
            if key in {"up", "down", "pgup", "pgdn", "home", "end", "esc"}:
                return key
            if key == "enter":
                return "open"
            return key
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

    def render() -> None:
        width, height = shutil.get_terminal_size((96, 28))
        selected_row = rows[selected]
        details = detail_provider(selected_row) if detail_provider else []
        lines = build_panel_lines(
            title,
            rows,
            details,
            selected=selected,
            width=width,
            height=height,
            footer=footer,
            empty_message=empty_message,
        )

        sys.stdout.write("\x1b[H\x1b[2J")
        for index, line in enumerate(lines):
            if index in {0, 2, len(lines) - 2}:
                color = c_dim
            elif index == 1:
                color = c_accent
            elif line.startswith("  ›"):
                color = c_accent
            elif index == len(lines) - 1:
                color = c_muted
            else:
                color = c_text
            sys.stdout.write(f"{color}{line}{reset}\n")
        sys.stdout.flush()

    try:
        sys.stdout.write("\x1b[?1049h\x1b[?25l")
        sys.stdout.flush()
        render()
        while True:
            key = read_key()
            if key == "up":
                selected = (selected - 1) % len(rows)
                render()
            elif key == "down":
                selected = (selected + 1) % len(rows)
                render()
            elif key == "pgup":
                selected = max(0, selected - 8)
                render()
            elif key == "pgdn":
                selected = min(len(rows) - 1, selected + 8)
                render()
            elif key == "home":
                selected = 0
                render()
            elif key == "end":
                selected = len(rows) - 1
                render()
            elif key == "open":
                return PanelResult(key, rows[selected].value)
            elif key == "esc":
                return None
    finally:
        sys.stdout.write("\x1b[?1049l\x1b[?25h")
        sys.stdout.flush()
