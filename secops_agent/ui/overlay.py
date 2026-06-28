"""
Shared overlay surfaces for command panels and choice lists.
"""

from __future__ import annotations

import os
import shutil
import select
import sys
import termios
import tty
from dataclasses import dataclass
from typing import Callable, Iterable, Optional

from rich.console import Console

from secops_agent.ui.theme import ANSI_RESET, COLORS, ansi


@dataclass(frozen=True)
class OverlayRow:
    label: str
    value: str = ""
    description: str = ""
    accent: bool = False


@dataclass(frozen=True)
class OverlayChoice:
    value: str
    label: str
    description: str = ""
    current: bool = False


CHOICE_OVERLAY_FOOTER = "Keyboard: ↑/↓ Navigate  enter Select  esc Go Back"
CHOICE_LIST_VISIBLE_ITEMS = 10
LOG_OVERLAY_CONTROLS = "↑/↓ Scroll · pgup/pgdn Page · home/end Start/End · esc Close"


def _escape_sequence_complete(sequence: bytes) -> bool:
    if sequence.startswith(b"\x1b[M"):
        return len(sequence) >= 6
    if sequence.startswith(b"\x1b[<"):
        return len(sequence) >= 6 and sequence[-1:] in {b"M", b"m"}
    if sequence.startswith(b"\x1b["):
        return len(sequence) >= 3 and 0x40 <= sequence[-1] <= 0x7E
    if sequence.startswith(b"\x1bO"):
        return len(sequence) >= 3
    return len(sequence) >= 2


def terminal_key_from_sequence(sequence: bytes | str) -> str:
    """Map raw terminal escape sequences to semantic keys.

    Mouse wheels and touchpad scrolls often arrive as xterm mouse sequences.
    Unknown escape sequences are ignored instead of being treated as bare Esc.
    """
    if isinstance(sequence, str):
        raw = sequence.encode("utf-8", errors="ignore")
    else:
        raw = bytes(sequence)

    key_map = {
        b"\x1b[A": "up",
        b"\x1b[B": "down",
        b"\x1b[C": "right",
        b"\x1b[D": "left",
        b"\x1b[1;2A": "pgup",
        b"\x1b[1;2B": "pgdn",
        b"\x1b[1;5H": "home",
        b"\x1b[1;5F": "end",
        b"\x1bOA": "up",
        b"\x1bOB": "down",
        b"\x1bOC": "right",
        b"\x1bOD": "left",
        b"\x1b[5~": "pgup",
        b"\x1b[5;2~": "pgup",
        b"\x1b[6~": "pgdn",
        b"\x1b[6;2~": "pgdn",
        b"\x1b[H": "home",
        b"\x1b[1~": "home",
        b"\x1b[7~": "home",
        b"\x1bOH": "home",
        b"\x1b[F": "end",
        b"\x1b[4~": "end",
        b"\x1b[8~": "end",
        b"\x1bOF": "end",
        b"\x1b[3~": "delete",
        b"\x1b[3;5~": "ctrl+delete",
    }
    if raw in key_map:
        return key_map[raw]

    if raw.startswith(b"\x1b[<") and raw[-1:] in {b"M", b"m"}:
        try:
            payload = raw[3:-1].decode("ascii", errors="ignore")
            code = int(payload.split(";", 1)[0])
        except (ValueError, IndexError):
            return "ignore"
        if code & 64:
            button = code & 3
            if button == 0:
                return "mouse_up"
            if button == 1:
                return "mouse_down"
        return "mouse"

    if raw.startswith(b"\x1b[M") and len(raw) >= 6:
        code = raw[3] - 32
        if code & 64:
            button = code & 3
            if button == 0:
                return "mouse_up"
            if button == 1:
                return "mouse_down"
        return "mouse"

    return "ignore"


def read_terminal_key(
    fd: int | None = None,
    *,
    input_timeout: float | None = None,
    escape_timeout: float = 0.05,
) -> str:
    """Read one semantic terminal key from raw mode."""
    fd = fd if fd is not None else sys.stdin.fileno()
    if input_timeout is not None:
        ready, _, _ = select.select([fd], [], [], input_timeout)
        if not ready:
            return "timeout"

    try:
        first = os.read(fd, 1)
    except BlockingIOError:
        return "ignore"
    if not first:
        return "ignore"

    if first != b"\x1b":
        try:
            ch = first.decode("utf-8", errors="ignore")
        except UnicodeDecodeError:
            return "ignore"
        if ch == "\x03":
            raise KeyboardInterrupt
        if ch == "\x04":
            return "ctrl+d"
        if ch == "\t":
            return "tab"
        if ch in ("\r", "\n"):
            return "enter"
        return ch

    ready, _, _ = select.select([fd], [], [], escape_timeout)
    if not ready:
        return "esc"

    sequence = bytearray(first)
    while len(sequence) < 64:
        try:
            chunk = os.read(fd, 1)
        except BlockingIOError:
            break
        if not chunk:
            break
        sequence.extend(chunk)
        if _escape_sequence_complete(bytes(sequence)):
            break
        ready, _, _ = select.select([fd], [], [], 0.01)
        if not ready:
            break

    return terminal_key_from_sequence(bytes(sequence))


def _fit(text: str, width: int) -> str:
    if width <= 0:
        return ""
    if len(text) <= width:
        return text
    if width == 1:
        return "…"
    return text[: width - 1] + "…"


def _choice_window_start(selected: int, total: int, visible_count: int) -> int:
    if total <= visible_count:
        return 0
    return max(0, min(selected - visible_count // 2, total - visible_count))


def _choice_statusline(left: str, right: str, width: int) -> str:
    if not right:
        return _fit(left, width)
    right = _fit(right, max(10, width - len(left) - 2))
    return f"{left}{' ' * max(1, width - len(left) - len(right) - 1)}{right}"


def _transient_content_height(terminal_height: int, *, prompt_frame: bool = False) -> int:
    """Reserve rows for prompt chrome and the cancel/model statusline."""
    overhead = (3 if prompt_frame else 0) + 2
    return max(5, terminal_height - overhead)


def build_choice_overlay_lines(
    title: str,
    choices: list[OverlayChoice],
    detail_lines: list[str] | None = None,
    *,
    selected: int = 0,
    width: int = 96,
    height: int = 28,
    footer: str = CHOICE_OVERLAY_FOOTER,
    show_descriptions: bool = False,
    current_marker_column: int | None = None,
    visible_items: int | None = None,
) -> list[str]:
    """Build the plain-text choice overlay used by the interactive renderer."""
    width = max(1, width - 1)
    height = max(10, height)
    detail_lines = detail_lines or []
    if not choices:
        return [_fit(line, width) for line in ["", title, "", "  No choices.", "", footer]]

    selected = min(max(0, selected), len(choices) - 1)
    visible_limit = CHOICE_LIST_VISIBLE_ITEMS if visible_items is None else max(1, int(visible_items))
    visible_count = min(visible_limit, max(1, height - 8 - min(len(detail_lines), 4)))
    start = _choice_window_start(selected, len(choices), visible_count)
    visible = choices[start:start + visible_count]

    lines = ["", _fit(title, width), ""]
    hidden_above = start
    hidden_below = max(0, len(choices) - start - len(visible))
    if hidden_above:
        lines.append(f"  ↑ {hidden_above} more")

    label_width = 0
    if show_descriptions:
        label_width = min(24, max((len(item.label) for item in visible), default=12) + 6)
    for index, item in enumerate(visible, start=start):
        cursor = "> " if index == selected else "  "
        suffix = "   (current)" if item.current else ""
        if show_descriptions and item.description:
            current = "(current)  " if item.current else ""
            description_width = max(8, width - len(cursor) - label_width - len(current))
            label = _fit(item.label, label_width).ljust(label_width)
            lines.append(f"{cursor}{label}{current}{_fit(item.description, description_width)}")
        else:
            row_width = max(1, width - len(cursor))
            if item.current and current_marker_column is not None:
                label = _fit(item.label, max(1, row_width - len("(current)") - 1))
                spaces = " " * max(3, current_marker_column - len(label))
                text = f"{label}{spaces}(current)"
            else:
                text = f"{item.label}{suffix}"
            lines.append(f"{cursor}{_fit(text, row_width)}")

    if hidden_below:
        lines.append(f"  ↓ {hidden_below} more")

    if detail_lines:
        lines.append("")
        for line in detail_lines[:4]:
            lines.append(f"  {_fit(line, max(24, width - 4))}")

    lines.append("")
    lines.append(_fit(footer, width))
    return [_fit(line, width) for line in lines]


def render_overlay(
    console: Console,
    title: str,
    rows: Iterable[OverlayRow],
    empty_message: str = "",
    footer: str = "",
) -> None:
    """Render a compact command panel using one consistent style."""
    width = max(1, (min(console.size.width, shutil.get_terminal_size((console.size.width, 24)).columns) if sys.stdout.isatty() else console.size.width) - 1)
    divider = "─" * width
    materialized = list(rows)

    console.print()
    console.print(f"[{COLORS['text_dim']}]{divider}[/]")
    console.print(f"  [{COLORS['accent']} bold]{title}[/]")
    console.print(f"[{COLORS['text_dim']}]{divider}[/]")

    if not materialized:
        if empty_message:
            console.print(f"  [{COLORS['text_dim']}]{empty_message}[/]")
    else:
        label_width = min(22, max(len(row.label) for row in materialized) + 2)
        value_width = max(12, width - label_width - 6)
        for row in materialized:
            color = COLORS["accent"] if row.accent else COLORS["text"]
            label = _fit(row.label, max(1, label_width - 1)).ljust(label_width)
            value = _fit(row.value, value_width)
            console.print(
                f"  [{COLORS['text_muted']}]{label}[/]"
                f"[{color}]{value}[/]"
            )
            if row.description:
                console.print(f"    [{COLORS['text_dim']}]{_fit(row.description, width - 4)}[/]")

    if footer:
        console.print(f"[{COLORS['text_dim']}]{divider}[/]")
        console.print(f"  [{COLORS['text_muted']}]{_fit(footer, width - 4)}[/]")
    console.print()


def _format_legend(line: str, c_key: str, c_muted: str, reset: str) -> str:
    text = line
    replacements = [
        ("↑/↓", f"{c_key}↑/↓{c_muted}"),
        ("enter", f"{c_key}enter{c_muted}"),
        ("ctrl+delete", f"{c_key}ctrl+delete{c_muted}"),
        ("esc", f"{c_key}esc{c_muted}"),
    ]
    for old, new in replacements:
        text = text.replace(old, new)
    return f"{c_muted}{text}{reset}"


def _is_choice_more_indicator(line: str) -> bool:
    return line.strip().startswith(("↑ ", "↓ "))


def choose_overlay(
    title: str,
    choices: list[OverlayChoice],
    detail_provider: Optional[Callable[[OverlayChoice], list[str]]] = None,
    status_right: str = "",
    prompt_frame: bool = False,
    show_descriptions: bool = False,
    footer: str = CHOICE_OVERLAY_FOOTER,
    current_marker_column: int | None = None,
    on_delete: Optional[Callable[[str], bool]] = None,
    visible_items: int | None = None,
) -> str | None:
    """Interactive inline choice list matching Antigravity's command picker."""
    if not sys.stdin.isatty() or not choices:
        return None

    selected = next((index for index, item in enumerate(choices) if item.current), 0)
    c_accent = ansi("accent", bold=True)
    c_text = ansi("text")
    c_muted = ansi("text_muted")
    c_warning = ansi("warning", bold=True)
    reset = ANSI_RESET

    def read_key() -> str:
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            key = read_terminal_key(fd, escape_timeout=0.2)
            if key in {"up", "mouse_up"}:
                return "up"
            if key in {"down", "mouse_down"}:
                return "down"
            if key in {"pgup", "pgdn", "home", "end"}:
                return key
            if key == "enter":
                return "enter"
            return key
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

    rendered_lines = 0
    confirm_delete = False

    def render() -> int:
        nonlocal rendered_lines
        width, height = shutil.get_terminal_size((96, 28))
        content_height = _transient_content_height(height, prompt_frame=prompt_frame)
        selected_choice = choices[selected]
        details = detail_provider(selected_choice) if detail_provider else []
        lines = build_choice_overlay_lines(
            title,
            choices,
            details,
            selected=selected,
            width=width,
            height=content_height,
            footer=footer,
            show_descriptions=show_descriptions,
            current_marker_column=current_marker_column,
            visible_items=visible_items,
        )
        if prompt_frame and lines and lines[0] == "":
            lines = lines[1:]
        if prompt_frame:
            divider = "─" * max(1, width - 1)
            lines = [divider, ">", divider, *lines]
        if lines and lines[-1] != "":
            lines.append("")
        if confirm_delete:
            lines.append(_choice_statusline(f"Delete session '{selected_choice.label}'? [y/N]", "", max(1, width - 1)))
        else:
            lines.append(_choice_statusline("esc to cancel", status_right, max(1, width - 1)))

        if rendered_lines:
            sys.stdout.write(f"\x1b[{rendered_lines}A\x1b[J")
        for line in lines:
            if line.startswith("> "):
                sys.stdout.write(f"{c_accent}{line}{reset}\n")
            elif line == title:
                sys.stdout.write(f"{c_text}{line}{reset}\n")
            elif line.startswith("Delete session"):
                sys.stdout.write(f"{c_warning}{line}{reset}\n")
            elif "Keyboard:" in line:
                c_key = ansi("accent_bright", bold=True)
                sys.stdout.write(f"{_format_legend(line, c_key, c_muted, reset)}\n")
            elif _is_choice_more_indicator(line):
                sys.stdout.write(f"{ansi('accent_bright', bold=True)}{line}{reset}\n")
            elif line.startswith(CHOICE_OVERLAY_FOOTER) or line.startswith("esc to cancel"):
                sys.stdout.write(f"{c_muted}{line}{reset}\n")
            else:
                sys.stdout.write(f"{c_text}{line}{reset}\n")
        sys.stdout.flush()
        rendered_lines = len(lines)
        return rendered_lines

    def clear_rendered() -> None:
        nonlocal rendered_lines
        if rendered_lines:
            sys.stdout.write(f"\x1b[{rendered_lines}A\x1b[J")
            rendered_lines = 0
        sys.stdout.write("\x1b[?25h")
        sys.stdout.flush()

    try:
        sys.stdout.write("\x1b[?25l")
        sys.stdout.flush()
        render()
        while True:
            key = read_key()
            if confirm_delete:
                if key.lower() in ("y", "enter"):
                    target_value = choices[selected].value
                    if on_delete and on_delete(target_value):
                        choices.pop(selected)
                        if not choices:
                            clear_rendered()
                            return None
                        selected = min(selected, len(choices) - 1)
                    confirm_delete = False
                    render()
                else:
                    confirm_delete = False
                    render()
                continue

            if key == "up":
                selected = (selected - 1) % len(choices)
                render()
            elif key == "down":
                selected = (selected + 1) % len(choices)
                render()
            elif key == "pgup":
                terminal_rows = shutil.get_terminal_size((96, 28)).lines
                page = visible_items or max(5, _transient_content_height(terminal_rows, prompt_frame=prompt_frame) - 8)
                selected = max(0, selected - page)
                render()
            elif key == "pgdn":
                terminal_rows = shutil.get_terminal_size((96, 28)).lines
                page = visible_items or max(5, _transient_content_height(terminal_rows, prompt_frame=prompt_frame) - 8)
                selected = min(len(choices) - 1, selected + page)
                render()
            elif key == "home":
                selected = 0
                render()
            elif key == "end":
                selected = len(choices) - 1
                render()
            elif key in ("delete", "ctrl+delete", "ctrl+d"):
                if on_delete:
                    confirm_delete = True
                    render()
            elif key == "enter":
                clear_rendered()
                return choices[selected].value
            elif key == "esc":
                clear_rendered()
                return None
    finally:
        clear_rendered()


import re
_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")

def _strip_ansi(text: str) -> str:
    """Helper to remove ANSI escape codes for width/wrapping calculations."""
    return _ANSI_ESCAPE_RE.sub("", text)


def view_logs_overlay(title: str, content: str, *, initial_search: str = "") -> None:
    """Affichage interactif plein écran (alternate screen) des journaux d'exécution avec défilement."""
    if not sys.stdin.isatty():
        return

    import termios
    import tty
    import shutil

    # Dimensions initiales du terminal
    width, height = shutil.get_terminal_size((96, 28))

    def wrap_content(w: int) -> list[str]:
        """Wrap dynamiquement le contenu des logs pour s'adapter à la largeur w du terminal."""
        lines = []
        for raw_line in content.splitlines():
            if not raw_line.strip():
                lines.append("")
                continue
            # Wrapper à w - 6 pour garder une marge visuelle élégante sur les côtés
            target_w = max(20, w - 6)
            words = raw_line.split(" ")
            current_line = []
            current_len = 0
            for word in words:
                word_clean = _strip_ansi(word)
                word_len = len(word_clean)
                space_len = 1 if current_line else 0
                if current_len + word_len + space_len <= target_w:
                    current_line.append(word)
                    current_len += word_len + space_len
                else:
                    if current_line:
                        lines.append(" ".join(current_line))
                    current_line = [word]
                    current_len = word_len
            if current_line:
                lines.append(" ".join(current_line))
        return lines

    c_accent = ansi("accent", bold=True)
    c_muted = ansi("text_muted")
    c_dim = ansi("text_dim")
    reset = ANSI_RESET

    # Calcul initial des lignes emballées
    wrapped_lines = wrap_content(width)
    selected = 0  # Ligne supérieure du viewport d'affichage
    if initial_search:
        needle = initial_search.casefold()
        for index, line in enumerate(wrapped_lines):
            if needle in _strip_ansi(line).casefold():
                selected = max(0, index - 2)
                break

    def read_key() -> str:
        """Lecture synchrone non bloquante des entrées claviers du pager."""
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
            return key
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

    def render() -> None:
        """Redessine le pager interactif à l'écran."""
        nonlocal wrapped_lines, selected
        w, h = shutil.get_terminal_size((96, 28))
        
        # Recalculer l'emballage en cas de redimensionnement dynamique
        wrapped_lines = wrap_content(w)
        
        line_width = max(1, w - 1)
        divider = f"{c_dim}{'─' * line_width}{reset}\n"
        sys.stdout.write("\x1b[H\x1b[2J")
        sys.stdout.write(divider)
        sys.stdout.write(f"  {c_accent}{title}{reset}\n")
        sys.stdout.write(divider)
        sys.stdout.write("\n")

        # Calculer la hauteur de la zone d'affichage utile (h - 7 lignes)
        content_height = max(5, h - 7)
        
        max_scroll = max(0, len(wrapped_lines) - content_height)
        if selected > max_scroll:
            selected = max_scroll
        if selected < 0:
            selected = 0

        visible = wrapped_lines[selected:selected + content_height]
        for line in visible:
            sys.stdout.write(f"  {line}{reset}\n")
        
        # Remplir de lignes vides pour garder l'alignement de la bordure du bas
        if len(visible) < content_height:
            for _ in range(content_height - len(visible)):
                sys.stdout.write("\n")

        sys.stdout.write("\n")
        sys.stdout.write(divider)
        
        # Bottom status bar with keyboard controls and progress
        pct = 100 if len(wrapped_lines) <= content_height else int((selected / max_scroll) * 100)
        status = f"Line {selected + 1} - {selected + len(visible)} of {len(wrapped_lines)} ({pct}%)"
        controls = LOG_OVERLAY_CONTROLS
        
        status = _fit(status, max(8, line_width // 3))
        controls = _fit(controls, max(8, line_width - len(status) - 4))
        spaces = line_width - len(status) - len(controls) - 2
        if spaces < 2:
            spaces = 2
        
        sys.stdout.write(f"  {c_muted}{controls}{' ' * spaces}{status}{reset}\n")
        sys.stdout.write(divider)
        sys.stdout.flush()

    try:
        # Passage sur écran alternatif (alternate buffer) et masquage du curseur
        sys.stdout.write("\x1b[?1049h\x1b[?25l")
        sys.stdout.flush()
        while True:
            render()
            key = read_key()
            w, h = shutil.get_terminal_size((96, 28))
            content_height = max(5, h - 7)
            max_scroll = max(0, len(wrapped_lines) - content_height)
            
            if key == "up":
                if selected > 0:
                    selected -= 1
            elif key == "down":
                if selected < max_scroll:
                    selected += 1
            elif key == "pgup":
                selected = max(0, selected - content_height)
            elif key == "pgdn":
                selected = min(max_scroll, selected + content_height)
            elif key == "home":
                selected = 0
            elif key == "end":
                selected = max_scroll
            elif key == "esc":
                break
    finally:
        # Retour à l'écran principal et réactivation du curseur
        sys.stdout.write("\x1b[?1049l\x1b[?25h")
        sys.stdout.flush()
