"""
Streaming renderer matching Antigravity CLI style exactly.

Key patterns from Antigravity CLI:
  ▸ Thought for Xs
    Brief thinking content preview...

  Agent narrative text is indented with 2 spaces.

  ● ToolName(arg_summary) (ctrl+o to expand)

  ⚠ Error or warning message

  ✦ prefix only on final consolidated response (optional).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import re
import select
import shutil
import subprocess
import sys
import termios
import threading
import time
import tty
import io
from dataclasses import dataclass
from pathlib import Path
from typing import AsyncIterator, List, Any

from rich.console import Console
from rich.markdown import Markdown
from rich.live import Live
from rich.markup import escape
from rich.padding import Padding

from secops_agent import __version__
from secops_agent.ui.theme import rich_theme, COLORS, friendly_model_name
from secops_agent.ui.commands import iter_commands
from secops_agent.ui.animations import ThinkingSpinner, ToolExecutionSpinner
from secops_agent.ui.overlay import OverlayRow, build_choice_overlay_lines, read_terminal_key, render_overlay
from secops_agent.ui.panel import PanelRow, choose_panel
from secops_agent.ui.runtime import RuntimeState
from secops_agent.ui.tool_display import (
    ToolCallBox, ToolResultBox, ApprovalPrompt, format_duration, format_tool_call_text,
    summarize_output, _looks_like_tool_failure, _tool_call_markup, _tool_status_color,
    _tool_result_log_reference_line,
)
from secops_agent.ui.spool_display import spool_reference, supervised_detail_text
from secops_agent.ui.error_display import ErrorRenderer
from secops_agent.core.agent import (
    AgentEvent, ThinkingEvent, TextEvent,
    ToolCallEvent, ToolStartEvent, ToolProgressEvent, ToolResultEvent, ErrorEvent, StatusEvent,
    ApprovalRequestEvent, SudoAuthenticationRequestEvent, TokenUsageEvent, SuggestedActionsEvent,
)
from secops_agent.core.tools import ToolResult
from secops_agent.ui.sudo_prompt import request_sudo_authentication

# Throttle: re-render Markdown at most every 50ms to prevent flashing
_RENDER_INTERVAL = 0.05  # seconds

_TOOL_TASK_TRACKING_NAMES = {
    "run_shell",
    "nmap_scan",
    "dir_brute",
    "nikto_scan",
    "sql_injection_test",
}
_MIN_REVIEWABLE_TOOL_SECONDS = 2.0

_MARKDOWN_HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*#*\s*$")
_MARKDOWN_HRULE_RE = re.compile(r"^ {0,3}([-*_])(?:\s*\1){2,}\s*$")
_MARKDOWN_SETEXT_RE = re.compile(r"^ {0,3}(=+|-+)\s*$")
_ORDERED_LIST_LINE_RE = re.compile(r"^(\s{0,8})(\d{1,2})(?:[.)]\s+|\s+)(\S.*)$")

# Bug 2.1: Detect [Archived tool call: ...] markers the LLM emits as text
# instead of issuing a real function call.
_ARCHIVED_CALL_RE = re.compile(
    r'\[Archived tool (?:call|result):\s*(\w+)\s*(?:\{[^}]*\})?\]',
    re.IGNORECASE,
)

_HELP_VIEWS = ("General", "Commands", "Shortcuts")
_HELP_CATEGORY_ORDER = ("Core", "Configuration", "Tasks", "Session", "Extensions", "Workspace", "Tools")
_LONG_LIST_VISIBLE_ITEMS = 10
_HELP_LIST_VISIBLE_ITEMS = _LONG_LIST_VISIBLE_ITEMS
SETTINGS_FOOTER = "↑/↓ Navigate · enter Edit · Esc Clear Search/Exit"
ARTIFACT_FOOTER = "Keyboard: ↑/↓ Navigate  p preview  enter open  esc dismiss"
AGENTS_FOOTER = "Keyboard: ↑/↓ Navigate  enter Select / Toggle  k Kill Active Subagent  esc Go Back"
HOOK_EVENT_ROWS: tuple[tuple[str, str, str], ...] = (
    ("before_tool", "PreToolUse", "Before tool execution"),
    ("after_tool", "PostToolUse", "After tool execution"),
    ("on_error", "OnError", "When tool execution fails"),
)
MCP_FOOTER = "Keyboard: ↑/↓ Navigate  enter Actions"
SKILLS_FOOTER = "Keyboard: ↑/↓ Navigate  enter Actions"
_HELP_ROW_RE = re.compile(r"^([> ] )(.+?)( {2,})(\S.*)$")
_HELP_DETAIL_LINES = {
    "SecOps CLI helps plan authorized security assessments, collect evidence,",
    "and run approved tools from your terminal.",
}
_HELP_SHORTCUTS = (
    ("/", "Open slash commands"),
    ("\\ + enter", "Insert newline fallback"),
    ("alt+enter, ctrl+j, shift+enter", "Insert newline"),
    ("alt+j", "Manage subagent"),
    ("ctrl+_, ctrl+shift+-", "Undo"),
    ("ctrl+c, esc", "Go back / dismiss"),
    ("ctrl+d", "Exit"),
    ("ctrl+end", "Go to bottom"),
    ("ctrl+g", "Open prompt in $EDITOR"),
    ("ctrl+home", "Go to top"),
    ("ctrl+l", "Clear CLI screen"),
    ("ctrl+o", "Toggle trajectory view"),
    ("ctrl+r", "Review artifact"),
    ("ctrl+shift+z", "Redo"),
    ("ctrl+v", "Paste or attach evidence"),
    ("ctrl+y", "Yank (paste from kill ring)"),
    ("ctrl+z", "Suspend CLI"),
    ("down", "Move down"),
    ("e", "Edit command"),
    ("enter", "Send message or confirm"),
    ("left", "Switch help tab left"),
    ("pgdn, shift+down", "Page down"),
    ("pgup, shift+up", "Page up"),
    ("right, tab", "Switch help tab right"),
    ("tab", "Complete highlighted slash command"),
    ("up", "Move up"),
    ("?", "Open this help"),
)
_HELP_SHORTCUT_LABELS = {label for label, _ in _HELP_SHORTCUTS}


@dataclass(frozen=True)
class SettingsItem:
    label: str
    value: str
    description: str
    editable: bool = False
    options: tuple[str, ...] = ()


@dataclass(frozen=True)
class SettingsSelection:
    item: SettingsItem
    value: str | None = None


@dataclass(frozen=True)
class AgentProfileSummary:
    name: str
    description: str
    source: str
    path: Path


@dataclass(frozen=True)
class AgentViewEntry:
    value: str
    label: str
    status: str
    description: str
    kind: str


@dataclass(frozen=True)
class _MCPViewItem:
    label: str
    detail: str
    kind: str = "server"


@dataclass(frozen=True)
class _SkillViewItem:
    label: str
    detail: str
    kind: str = "skill"


def _turn_separator(width: int) -> str:
    """Return a transcript separator that avoids terminal-edge wrapping."""
    return "─" * max(1, width - 1)


def _surface_width(console: Console | None = None, default: int = 80) -> int:
    width = console.size.width if console is not None else default
    if sys.stdout.isatty():
        width = min(width, shutil.get_terminal_size((width or default, 24)).columns)
    return max(1, width)


def _surface_height(console: Console | None = None, default: int = 24) -> int:
    height = console.size.height if console is not None else default
    if console is None or bool(getattr(console, "is_terminal", False)) or sys.stdout.isatty():
        try:
            height = min(height, shutil.get_terminal_size((80, height or default)).lines)
        except Exception:
            pass
    return max(1, height)


def _ctrl_o_output_visible_limit(console: Console | None = None, *, default: int = 40) -> int:
    """Keep ctrl+o detail surfaces short enough to clear in-place."""
    return max(1, min(default, _surface_height(console, 24) - 8))


def _display_path(path: Path) -> str:
    text = str(path.expanduser())
    home = str(Path.home())
    if text.startswith(home):
        return "~" + text[len(home):]
    return text


def agent_profile_template_paths(*, cwd: Path | None = None, home: Path | None = None) -> tuple[Path, Path]:
    base_cwd = cwd or Path.cwd()
    base_home = home or Path.home()
    return (
        base_cwd / ".agents" / "agents" / "{agent_name}" / "agent.json",
        base_home / ".secops_agent" / "agents" / "{agent_name}" / "agent.json",
    )


def load_agent_profiles(*, cwd: Path | None = None, home: Path | None = None) -> list[AgentProfileSummary]:
    """Load display-only SecOps agent profile definitions from real JSON files."""
    base_cwd = cwd or Path.cwd()
    base_home = home or Path.home()
    roots = [
        ("workspace", base_cwd / ".agents" / "agents"),
        ("user", base_home / ".secops_agent" / "agents"),
    ]
    profiles: list[AgentProfileSummary] = []
    seen: set[tuple[str, Path]] = set()

    for source, root in roots:
        if not root.exists() or not root.is_dir():
            continue
        for profile_path in sorted(root.glob("*/agent.json")):
            key = (source, profile_path)
            if key in seen:
                continue
            seen.add(key)
            try:
                data = json.loads(profile_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(data, dict):
                continue
            name = str(data.get("name") or profile_path.parent.name).strip() or profile_path.parent.name
            description = (
                data.get("description")
                or data.get("role")
                or data.get("summary")
                or "SecOps agent profile"
            )
            description = " ".join(str(description).split())
            profiles.append(
                AgentProfileSummary(
                    name=name,
                    description=description,
                    source=source,
                    path=profile_path,
                )
            )

    return profiles


def _tool_output_lines(result: Any) -> list[str]:
    output = str(getattr(result, "output", "") or getattr(result, "error", "") or "(no output)")
    output = supervised_detail_text(getattr(result, "metadata", None), output)
    return [line.rstrip() for line in output.splitlines() if line.strip()] or ["(no output)"]


def _tool_result_status(result: Any) -> str:
    if result is None:
        return "running"
    output = str(getattr(result, "output", "") or "")
    text_failure = bool(getattr(result, "success", False)) and _looks_like_tool_failure(output)
    return "success" if getattr(result, "success", False) and not text_failure else "error"


def _build_collapsed_tool_result_lines(result: Any, *, width: int) -> list[str]:
    text_failure = bool(getattr(result, "success", False)) and _looks_like_tool_failure(str(getattr(result, "output", "") or ""))
    log_line = _tool_result_log_reference_line(result, max_width=width)
    if getattr(result, "success", False) and not text_failure:
        output = str(getattr(result, "output", "") or "")
        summary = summarize_output(
            output,
            max_lines=4,
            max_width=max(24, min(120, width - 8)),
        )
        elapsed = format_duration(getattr(result, "execution_time", 0.0)) if getattr(result, "execution_time", 0.0) > 0 else ""
        use_single_line = (
            summary["visible_lines"] == 1
            and summary["hidden_lines"] == 0
            and summary["truncated_lines"] == 0
            and len(summary["lines"][0]) <= max(20, width - 8)
        )
        if use_single_line:
            lines = [f"  [{COLORS['text_muted']}]⎿  {escape(summary['lines'][0])}[/{COLORS['text_muted']}]"]
            return lines

        metrics = []
        if elapsed:
            metrics.append(elapsed)
        if summary["chars"]:
            line_label = "line" if summary["total_lines"] == 1 else "lines"
            metrics.append(f"{summary['total_lines']:,} {line_label}")
            metrics.append(f"{summary['chars']:,} chars")
        details = " · ".join(metrics) if metrics else "done"
        lines = [
            f"  [{COLORS['text_muted']}]⎿  {escape(details)}[/{COLORS['text_muted']}]"
            f" [{COLORS['text_dim']}](ctrl+o to expand)[/{COLORS['text_dim']}]"
        ]
        if summary["lines"]:
            lines.extend(f"     [{COLORS['text_dim']}]{escape(line)}[/{COLORS['text_dim']}]" for line in summary["lines"])
            if summary["hidden_lines"]:
                lines.append(
                    f"     [{COLORS['text_dim']}]... {summary['hidden_lines']:,} more lines hidden[/{COLORS['text_dim']}]"
                )
            elif summary["truncated_lines"]:
                lines.append(f"     [{COLORS['text_dim']}]... truncated to terminal width[/{COLORS['text_dim']}]")
        elif not summary["chars"]:
            lines.append(f"     [{COLORS['text_dim']}]no output[/{COLORS['text_dim']}]")
        else:
            lines.append(f"     [{COLORS['text_dim']}]no printable lines[/{COLORS['text_dim']}]")
        return lines

    error_msg = str(getattr(result, "error", "") or getattr(result, "output", "") or "Unknown error")
    if len(error_msg) > 120:
        error_msg = error_msg[:117] + "..."
    elapsed = f" ({format_duration(getattr(result, 'execution_time', 0.0))})" if getattr(result, "execution_time", 0.0) > 0 else ""
    lines = [f"  [{COLORS['error']}]⎿  {escape(error_msg)}{elapsed}[/{COLORS['error']}]"]
    if log_line:
        lines.append(f"[{COLORS['text_dim']}]{escape(log_line)}[/{COLORS['text_dim']}]")
    return lines


def _build_expanded_tool_result_lines(result: Any, *, width: int) -> list[str]:
    output_lines = _tool_output_lines(result)
    first = _fit_cell(output_lines[0], max(16, width - 34))
    lines = [f"  [{COLORS['text_muted']}]⎿  {escape(first)} (ctrl+o to collapse)[/{COLORS['text_muted']}]"]
    if len(output_lines) > 1:
        visible_limit = _ctrl_o_output_visible_limit()
        visible_lines = output_lines[:visible_limit]
        lines.append("")
        lines.append(f"  [{COLORS['text_muted']}]Output:[/{COLORS['text_muted']}]")
        lines.extend(
            f"    [{COLORS['text_dim']}]{escape(_fit_cell(line, max(16, width - 6)))}[/{COLORS['text_dim']}]"
            for line in visible_lines
        )
        if len(output_lines) > len(visible_lines):
            lines.append(f"    [{COLORS['text_dim']}]... {len(output_lines) - len(visible_lines):,} more lines hidden[/{COLORS['text_dim']}]")
    return lines


def _build_tool_transcript_block_lines(
    item: dict[str, Any],
    *,
    expanded: bool,
    width: int,
    show_expand_tag: bool = True,
) -> list[str]:
    call_markup = _tool_call_markup(item.get("name", ""), item.get("arguments", {}))
    result = item.get("result")
    expand_suffix = (
        f" [{COLORS['text_muted']}](ctrl+o to expand)[/{COLORS['text_muted']}]"
        if show_expand_tag else ""
    )
    if result is None:
        # agy: tool rows are always a solid ● — running state is shown by colour
        # (yellow) and the spinner, not by an empty circle.
        indicator_color = _tool_status_color(status="running")
        return [
            f"[{indicator_color}]●[/{indicator_color}] {call_markup}{expand_suffix}"
        ]

    indicator_color = _tool_status_color(status=_tool_result_status(result))
    if expanded:
        return [
            f"[{indicator_color}]●[/{indicator_color}] {call_markup}",
            *_build_expanded_tool_result_lines(result, width=width),
        ]
    return [
        f"[{indicator_color}]●[/{indicator_color}] {call_markup}{expand_suffix}",
        *_build_collapsed_tool_result_lines(result, width=width),
    ]


def _build_text_transcript_lines(content: str, *, width: int) -> list[str]:
    rendered = Console(
        width=width,
        record=True,
        force_terminal=False,
        color_system=None,
        file=io.StringIO(),
    )
    rendered.print(Padding(Markdown(normalize_agent_markdown(content), code_theme="ansi_dark"), (0, 0, 0, 2)))
    return [line.rstrip() for line in rendered.export_text().splitlines()]


def _build_ctrl_o_transcript_lines(items: list[dict[str, Any]], *, expanded: bool, width: int) -> list[str]:
    latest_tool_index = -1
    for index, item in enumerate(items):
        if item.get("kind") == "tool":
            latest_tool_index = index
    if latest_tool_index < 0:
        return []

    # Pre-compute which tool items are the last in a consecutive group.
    # Per verified agy behaviour the (ctrl+o to expand) tag only appears on
    # the *last* tool of a consecutive run.
    slice_items = items[latest_tool_index:]
    _last_tool_in_group: set[int] = set()
    for si, sitem in enumerate(slice_items):
        if sitem.get("kind") == "tool":
            next_si = si + 1
            next_is_tool = (
                next_si < len(slice_items)
                and slice_items[next_si].get("kind") == "tool"
            )
            if not next_is_tool:
                _last_tool_in_group.add(latest_tool_index + si)

    lines: list[str] = []
    for index, item in enumerate(slice_items, start=latest_tool_index):
        kind = item.get("kind")
        if kind == "thought":
            if lines:
                lines.append("")
            duration = item.get("duration", "?")
            lines.append(
                f"[{COLORS['accent']}]▸[/{COLORS['accent']}] "
                f"[{COLORS['text_muted']}]Thought for {duration}s[/{COLORS['text_muted']}]"
            )
            preview = str(item.get("content", "") or "").strip().replace("\n", " ")
            if preview:
                if len(preview) > 120:
                    preview = preview[:117] + "..."
                lines.append(f"  [{COLORS['text_dim']}]{escape(preview)}[/{COLORS['text_dim']}]")
        elif kind == "tool":
            lines.append("")
            result = item.get("result")
            is_expanded_tool = expanded and index == latest_tool_index and result is not None
            is_last_in_group = index in _last_tool_in_group
            lines.extend(_build_tool_transcript_block_lines(
                item,
                expanded=is_expanded_tool,
                width=width,
                show_expand_tag=is_last_in_group,
            ))
        elif kind == "text":
            content = str(item.get("content", "") or "").strip()
            if content:
                lines.extend(_build_text_transcript_lines(content, width=width))
                lines.append("")
    return lines


def _transient_content_height(terminal_height: int, *, prompt_frame: bool = False) -> int:
    """Reserve rows for inline prompt chrome and the cancel/model statusline."""
    overhead = (3 if prompt_frame else 0) + 2
    return max(5, terminal_height - overhead)


def _fit_cell(text: str, width: int) -> str:
    if width <= 0:
        return ""
    if len(text) <= width:
        return text
    if width == 1:
        return "…"
    return text[: width - 1] + "…"


def _settings_window_start(selected: int, total: int, visible_count: int) -> int:
    if total <= visible_count:
        return 0
    return max(0, min(selected - visible_count // 2, total - visible_count))


def _filtered_settings_items(items: list[SettingsItem], search_query: str) -> list[SettingsItem]:
    query = search_query.strip().lower()
    if not query:
        return items
    return [
        item for item in items
        if query in item.label.lower()
        or query in item.value.lower()
        or query in item.description.lower()
    ]


def build_settings_view_lines(
    items: list[SettingsItem],
    *,
    selected: int = 0,
    search_query: str = "",
    editing_index: int | None = None,
    edit_selected: int = 0,
    width: int = 96,
    height: int = 28,
    footer: str = SETTINGS_FOOTER,
) -> list[str]:
    """Build the AGY-like settings/config surface from real SecOps settings."""
    width = max(1, width - 1)
    height = max(12, height)
    filtered_items = _filtered_settings_items(items, search_query)
    selected = min(max(0, selected), max(0, len(filtered_items) - 1))
    visible_count = min(len(filtered_items), max(5, height - 10))
    start = _settings_window_start(selected, len(filtered_items), visible_count)
    visible = filtered_items[start:start + visible_count]
    label_width = min(24, max((len(item.label) for item in visible), default=12) + 2)
    value_width = max(8, width - label_width - 4)

    search_label = f"  Search: {search_query}" if search_query else "  Search:"
    lines = ["", "Settings", "", search_label, " ────────────────────", ""]
    if not filtered_items:
        lines.append("  No settings match.")
    for index, item in enumerate(visible, start=start):
        cursor = "> " if index == selected else "  "
        label = _fit_cell(item.label, label_width).ljust(label_width)
        if editing_index == index:
            lines.append(f"  {_fit_cell(item.label, label_width).rstrip()}")
            options = item.options or (item.value,)
            for option_index, option in enumerate(options):
                option_cursor = "  > " if option_index == edit_selected else "    "
                suffix = " (current)" if option == item.value else ""
                lines.append(f"{option_cursor}{_fit_cell(option + suffix, max(8, width - 6))}")
        else:
            lines.append(f"{cursor}{label}{_fit_cell(item.value, value_width)}")

    if len(filtered_items) > visible_count:
        hidden_above = start
        hidden_below = max(0, len(filtered_items) - start - len(visible))
        if hidden_above:
            lines.append(f"  ↑ {hidden_above} more")
        if hidden_below:
            lines.append(f"  ↓ {hidden_below} more")

    if filtered_items:
        lines.append("")
        lines.append(f"  {_fit_cell(filtered_items[selected].description, max(24, width - 4))}")

    lines.append("")
    active_footer = "↑/↓ Navigate · enter Select" if editing_index is not None else footer
    lines.append(_fit_cell(active_footer, width))
    return [_fit_cell(line, width) for line in lines]


def _context_budget_for_model(model: str) -> int:
    normalized = (model or "").casefold()
    if "gemini-2.5" in normalized:
        return 1_000_000
    if "gemma" in normalized:
        return 128_000
    return 128_000


def _format_token_compact(value: int) -> str:
    if value >= 1_000_000:
        return f"{value / 1_000_000:.1f}M"
    if value >= 1_000:
        return f"{value / 1_000:.1f}k"
    return str(value)


def _context_grid(percent: float, cells: int = 24) -> str:
    filled = min(cells, max(0, round(cells * percent / 100)))
    return " ".join("■" if index < filled else "□" for index in range(cells))


def _role_token_estimate(estimated_tokens: int, role_messages: int, total_messages: int) -> int:
    if estimated_tokens <= 0 or role_messages <= 0 or total_messages <= 0:
        return 0
    return round(estimated_tokens * (role_messages / total_messages))


def build_context_usage_lines(
    model: str,
    *,
    total_messages: int,
    user_messages: int,
    assistant_messages: int,
    tool_messages: int,
    estimated_tokens: int,
    tools_count: int,
    width: int = 96,
) -> list[str]:
    """Build an AGY-like context usage visualization from available memory stats."""
    width = max(1, width - 1)
    friendly = friendly_model_name(model)
    budget = max(1, _context_budget_for_model(model))
    used = max(0, estimated_tokens)
    percent = min(100.0, used / budget * 100)
    free = max(0, budget - used)
    total_for_split = max(0, total_messages)
    user_tokens = _role_token_estimate(used, user_messages, total_for_split)
    assistant_tokens = _role_token_estimate(used, assistant_messages, total_for_split)
    tool_tokens = max(0, used - user_tokens - assistant_tokens) if tool_messages else 0
    if tool_messages and total_for_split:
        tool_tokens = _role_token_estimate(used, tool_messages, total_for_split)

    def pct(value: int) -> str:
        return f"{(value / budget * 100):.1f}%"

    grid = _context_grid(percent)
    right_lines = [
        f"{friendly} · {_format_token_compact(used)}/{_format_token_compact(budget)} tokens",
        f"({percent:.1f}%)",
        "Estimated usage (awaiting generation)",
        f"◉ User messages: {_format_token_compact(user_tokens)} tokens ({pct(user_tokens)})",
        f"◉ Agent responses: {_format_token_compact(assistant_tokens)} tokens ({pct(assistant_tokens)})",
        f"◉ Tool calls: {_format_token_compact(tool_tokens)} tokens ({pct(tool_tokens)})",
        f"□ Free space: {_format_token_compact(free)} ({pct(free)})",
    ]
    lines = ["", "└ Context Usage"]
    lines.extend(_fit_cell(f"{grid}     {line}", width) for line in right_lines)
    lines.append("")
    lines.append(_fit_cell("Related: /artifact · /skills · /rewind", width))
    return lines


def build_hooks_view_lines(
    hook_manager: Any,
    *,
    selected: int = 0,
    width: int = 96,
    footer: str = "↑/↓ Navigate · enter Select",
) -> list[str]:
    """Build an inline AGY-like hooks surface backed by SecOps hook events."""
    width = max(1, width - 1)
    hooks = list(getattr(hook_manager, "hooks", []) or [])
    errors = list(getattr(hook_manager, "errors", []) or [])
    last_runs = list(getattr(hook_manager, "last_runs", []) or [])
    enabled = [hook for hook in hooks if getattr(hook, "enabled", False)]
    selected = min(max(0, selected), len(HOOK_EVENT_ROWS) - 1)

    by_event = {event: 0 for event, _, _ in HOOK_EVENT_ROWS}
    enabled_by_event = {event: 0 for event, _, _ in HOOK_EVENT_ROWS}
    for hook in hooks:
        event = str(getattr(hook, "event", ""))
        if event in by_event:
            by_event[event] += 1
            if getattr(hook, "enabled", False):
                enabled_by_event[event] += 1

    lines = ["", " Hooks", f"   {len(HOOK_EVENT_ROWS)} hook types"]
    lines.append("")
    label_width = max(len(label) for _, label, _ in HOOK_EVENT_ROWS) + 2
    for index, (event, label, description) in enumerate(HOOK_EVENT_ROWS):
        cursor = " > " if index == selected else "   "
        status = ""
        if by_event[event]:
            status = f" ({enabled_by_event[event]}/{by_event[event]} enabled)"
        lines.append(_fit_cell(f"{cursor}{label.ljust(label_width)}{description}{status}", width))

    status_lines: list[str] = []
    if hooks:
        status_lines.append(f"   Configured: {len(enabled)}/{len(hooks)} enabled")
    if errors:
        status_lines.append(_fit_cell(f"   Config errors: {len(errors)} · {str(errors[0])}", width))
    elif last_runs:
        latest = last_runs[-1]
        status_lines.append(_fit_cell(f"   Last run: {latest.hook.name} · {latest.status} · rc {latest.returncode}", width))

    if status_lines:
        lines.append("")
        lines.extend(status_lines)
    lines.append("")
    lines.append(_fit_cell(f"   {footer}", width))
    return [_fit_cell(line, width) for line in lines]


def _compact_mcp_path(path: Any) -> str:
    try:
        resolved = Path(path).expanduser()
        cwd = Path.cwd()
        if resolved.is_absolute() and resolved.is_relative_to(cwd):
            return str(resolved.relative_to(cwd))
        return str(resolved).replace(str(Path.home()), "~", 1)
    except Exception:
        return str(path)


def _mcp_source_label(source: str, path: Path) -> str:
    compact = _compact_mcp_path(path)
    if source == "workspace":
        return f"Workspace ({compact})"
    return f"Global config ({compact})"


def _compact_mcp_error(message: str) -> str:
    home = os.path.expanduser("~")
    return str(message).replace(home, "~")[:180]


def _mcp_server_status(server: Any, mcp_runtime: Any | None) -> str:
    if getattr(server, "disabled", False):
        return "disabled"
    trust_status = str(getattr(server, "trust_status", "trusted") or "trusted")
    if trust_status != "trusted":
        return trust_status.replace("_", " ")
    if mcp_runtime:
        return str(mcp_runtime.server_status(server.name))
    return "configured"


def _mcp_server_detail(server: Any) -> str:
    args = " ".join(getattr(server, "args", []) or [])
    detail = f"{getattr(server, 'command', '')} {args}".strip()
    env = getattr(server, "env", {}) or {}
    if env:
        detail = f"{detail} · {len(env)} env"
    source = getattr(server, "source", "") or "config"
    path = _compact_mcp_path(getattr(server, "path", ""))
    return f"{detail} · {source} · {path}" if path else f"{detail} · {source}"


def _mcp_view_items(mcp_state: Any, mcp_runtime: Any | None) -> list[_MCPViewItem]:
    items: list[_MCPViewItem] = []
    servers = list(getattr(mcp_state, "servers", []) or [])
    state_errors = list(getattr(mcp_state, "errors", []) or [])
    runtime_errors = list(getattr(mcp_runtime, "errors", []) or []) if mcp_runtime else []
    tool_bindings = getattr(mcp_runtime, "tool_bindings", {}) or {} if mcp_runtime else {}

    if servers:
        for server in servers:
            status = _mcp_server_status(server, mcp_runtime)
            items.append(
                _MCPViewItem(
                    label=f"{server.name} ({status})",
                    detail=_mcp_server_detail(server),
                    kind="server",
                )
            )
    elif not state_errors and not runtime_errors and not tool_bindings:
        try:
            from secops_agent.core.mcp import discover_mcp_files

            sources = discover_mcp_files()
        except Exception:
            sources = []
        source, path = next(
            ((source, path) for source, path in sources if source == "workspace"),
            sources[0] if sources else ("workspace", Path.cwd() / ".agents" / "mcp_config.json"),
        )
        items.append(
            _MCPViewItem(
                label=_mcp_source_label(source, path),
                detail="No MCP servers configured.",
                kind="source",
            )
        )

    for error in state_errors:
        items.append(_MCPViewItem("Config error", _compact_mcp_error(error), "error"))

    if mcp_runtime:
        for error in runtime_errors:
            items.append(_MCPViewItem("Runtime error", _compact_mcp_error(error), "error"))
        for tool_name, binding in sorted(tool_bindings.items()):
            items.append(
                _MCPViewItem(
                    label=f"Tool {tool_name}",
                    detail=f"{binding.server_name}.{binding.remote_name}",
                    kind="tool",
                )
            )

    if not items:
        items.append(_MCPViewItem("MCP Configs", "No MCP servers configured.", "source"))
    return items


def build_mcp_view_lines(
    mcp_state: Any,
    mcp_runtime: Any | None = None,
    *,
    selected: int = 0,
    width: int = 96,
    height: int = 28,
    footer: str = MCP_FOOTER,
) -> list[str]:
    """Build an inline AGY-like MCP surface backed by real SecOps MCP state."""
    width = max(1, width - 1)
    height = max(12, height)
    items = _mcp_view_items(mcp_state, mcp_runtime)
    selected = min(max(0, selected), len(items) - 1)
    servers = list(getattr(mcp_state, "servers", []) or [])
    enabled = list(getattr(mcp_state, "enabled_servers", []) or [])
    running = len(getattr(mcp_runtime, "running_servers", []) or []) if mcp_runtime else 0
    tools = len(getattr(mcp_runtime, "tool_bindings", {}) or {}) if mcp_runtime else 0
    show_summary = bool(servers or getattr(mcp_state, "errors", None) or (mcp_runtime and (getattr(mcp_runtime, "errors", None) or tools)))

    fixed_rows = 5 + (2 if show_summary else 0)
    visible_count = min(len(items), max(1, height - fixed_rows))
    start = _settings_window_start(selected, len(items), visible_count)
    visible = items[start:start + visible_count]

    lines = ["", "MCP Servers", ""]
    if show_summary:
        lines.append(f"  {len(servers)} configured · {len(enabled)} enabled · {running} running · {tools} tools")
        lines.append("")

    for index, item in enumerate(visible, start=start):
        cursor = "> " if index == selected else "  "
        lines.append(_fit_cell(f"{cursor}{item.label}", width))
        if item.detail:
            lines.append(_fit_cell(f"  {item.detail}", width))

    if len(items) > visible_count:
        hidden_above = start
        hidden_below = max(0, len(items) - start - len(visible))
        if hidden_above:
            lines.append(f"  ↑ {hidden_above} more")
        if hidden_below:
            lines.append(f"  ↓ {hidden_below} more")

    lines.append("")
    lines.append(_fit_cell(footer, width))
    return [_fit_cell(line, width) for line in lines]


def _compact_skill_path(path: Any) -> str:
    try:
        resolved = Path(path).expanduser()
        cwd = Path.cwd()
        if resolved.is_absolute() and resolved.is_relative_to(cwd):
            return str(resolved.relative_to(cwd))
        return str(resolved).replace(str(Path.home()), "~", 1)
    except Exception:
        return str(path)


def _skill_source_label(source: str, path: Path) -> str:
    compact = _compact_skill_path(path)
    if source == "workspace":
        return f"Workspace ({compact})"
    return f"Global skills ({compact})"


def _skill_view_items(skills: list[Any]) -> list[_SkillViewItem]:
    items: list[_SkillViewItem] = []
    for skill in skills:
        title = getattr(skill, "title", "") or getattr(skill, "name", "Skill")
        source = getattr(skill, "source", "") or "config"
        path = _compact_skill_path(getattr(skill, "path", ""))
        detail = f"{title} · {source} · {path}" if path else f"{title} · {source}"
        trust_status = str(getattr(skill, "trust_status", "") or "").replace("_", " ")
        if trust_status and trust_status != "trusted":
            detail = f"{detail} · {trust_status}"
        items.append(
            _SkillViewItem(
                label=str(getattr(skill, "name", title)),
                detail=detail,
                kind="skill",
            )
        )

    if items:
        return items

    try:
        from secops_agent.core.extensions import discover_skill_dirs

        sources = discover_skill_dirs()
    except Exception:
        sources = []
    source, path = next(
        ((source, path) for source, path in sources if source == "workspace"),
        sources[0] if sources else ("workspace", Path.cwd() / ".agents" / "skills"),
    )
    items.append(
        _SkillViewItem(
            label=_skill_source_label(source, path),
            detail="No workspace or global skills loaded.",
            kind="source",
        )
    )

    if not items:
        items.append(_SkillViewItem("Skill directories", "No workspace or global skills loaded.", "source"))
    return items


def build_skills_view_lines(
    skills: list[Any],
    *,
    selected: int = 0,
    width: int = 96,
    height: int = 28,
    footer: str = SKILLS_FOOTER,
) -> list[str]:
    """Build an inline AGY-like skills surface backed by active SecOps skills."""
    width = max(1, width - 1)
    height = max(12, height)
    items = _skill_view_items(skills)
    selected = min(max(0, selected), len(items) - 1)
    workspace_count = len([skill for skill in skills if getattr(skill, "source", "") == "workspace"])
    global_count = len(skills) - workspace_count
    show_summary = bool(skills)

    fixed_rows = 5 + (2 if show_summary else 0)
    visible_count = min(len(items), max(1, height - fixed_rows))
    start = _settings_window_start(selected, len(items), visible_count)
    visible = items[start:start + visible_count]

    lines = ["", "Skills", ""]
    if show_summary:
        lines.append(f"  {len(skills)} loaded · {workspace_count} workspace · {global_count} global")
        lines.append("")

    for index, item in enumerate(visible, start=start):
        cursor = "> " if index == selected else "  "
        lines.append(_fit_cell(f"{cursor}{item.label}", width))
        if item.detail:
            lines.append(_fit_cell(f"  {item.detail}", width))

    if len(items) > visible_count:
        hidden_above = start
        hidden_below = max(0, len(items) - start - len(visible))
        if hidden_above:
            lines.append(f"  ↑ {hidden_above} more")
        if hidden_below:
            lines.append(f"  ↓ {hidden_below} more")

    lines.append("")
    lines.append(_fit_cell(footer, width))
    return [_fit_cell(line, width) for line in lines]


def _artifact_source_label(artifact: Any) -> str:
    source = str(getattr(artifact, "source", "") or "").strip()
    return source or "-"


def _artifact_content_lines(artifact: Any, *, max_lines: int = 10) -> list[str]:
    content = str(getattr(artifact, "content", "") or "(empty)")
    content = supervised_detail_text(getattr(artifact, "metadata", None), content)
    lines = content.splitlines() or ["(empty)"]
    if getattr(artifact, "kind", "") == "attachment":
        lines = [
            line for line in lines
            if line != "Attachment" and not line.startswith(("SHA256:", "Path:"))
        ]
    visible = lines[:max_lines]
    if len(lines) > max_lines:
        visible.append(f"... {len(lines) - max_lines} more line(s)")
    return visible


def _artifact_row_detail(artifact: Any) -> str:
    parts = [
        str(getattr(artifact, "kind", "") or "artifact"),
        _artifact_source_label(artifact),
    ]
    preview = str(getattr(artifact, "preview", "") or "").strip()
    if not (getattr(artifact, "kind", "") == "attachment" and preview == "Attachment"):
        parts.append(preview)
    return " · ".join(part for part in parts if part)


def _artifact_preview_line(artifact: Any) -> str:
    preview = str(getattr(artifact, "preview", "") or "").strip()
    if getattr(artifact, "kind", "") == "attachment" and preview == "Attachment":
        return ""
    return preview


def build_artifacts_view_lines(
    runtime: RuntimeState,
    *,
    artifacts: list[Any] | None = None,
    title: str = "Artifacts",
    empty_message: str = "No artifacts",
    selected: int = 0,
    detail_mode: str = "",
    width: int = 96,
    height: int = 28,
    footer: str = ARTIFACT_FOOTER,
) -> list[str]:
    """Build an inline AGY-like artifacts/evidence review surface."""
    width = max(1, width - 1)
    height = max(12, height)
    artifacts = list(artifacts if artifacts is not None else (getattr(runtime, "artifacts", []) or []))
    selected = min(max(0, selected), max(0, len(artifacts) - 1))
    has_detail = bool(artifacts and detail_mode in {"preview", "open"})
    fixed_rows = 5 + (7 if has_detail else 0)
    visible_count = min(len(artifacts), max(1, height - fixed_rows))
    start = _settings_window_start(selected, len(artifacts), visible_count)
    visible = artifacts[start:start + visible_count]

    lines = ["", title]
    if not artifacts:
        lines.append(f"  {empty_message}")
    else:
        lines.append("")
        for index, artifact in enumerate(visible, start=start):
            cursor = "> " if index == selected else "  "
            lines.append(_fit_cell(f"{cursor}{artifact.id:<6} {artifact.title}", width))
            lines.append(_fit_cell(f"  {_artifact_row_detail(artifact)}", width))

        if len(artifacts) > visible_count:
            hidden_above = start
            hidden_below = max(0, len(artifacts) - start - len(visible))
            if hidden_above:
                lines.append(f"  ↑ {hidden_above} more")
            if hidden_below:
                lines.append(f"  ↓ {hidden_below} more")

    if has_detail:
        artifact = artifacts[selected]
        if detail_mode == "preview":
            preview_line = _artifact_preview_line(artifact)
            lines.extend(
                [
                    "",
                    f"Preview: {artifact.id} · {artifact.title}",
                    f"  Kind: {artifact.kind}",
                    f"  Source: {_artifact_source_label(artifact)}",
                ]
            )
            if preview_line:
                lines.append(f"  {preview_line}")
        else:
            lines.extend(
                [
                    "",
                    f"Open: {artifact.id} · {artifact.title}",
                    f"  Kind: {artifact.kind}",
                    f"  Source: {_artifact_source_label(artifact)}",
                    "",
                    "  Content:",
                ]
            )
            lines.extend(_fit_cell(f"    {line}", width) for line in _artifact_content_lines(artifact, max_lines=12))

    lines.append("")
    lines.append(_fit_cell(footer, width))
    return [_fit_cell(line, width) for line in lines[:height]]


def build_attachments_view_lines(
    runtime: RuntimeState,
    *,
    selected: int = 0,
    detail_mode: str = "",
    width: int = 96,
    height: int = 28,
    footer: str = ARTIFACT_FOOTER,
) -> list[str]:
    """Build the evidence attachment review surface using the artifact grammar."""
    return build_artifacts_view_lines(
        runtime,
        artifacts=runtime.attachment_artifacts(),
        title="Attachments",
        empty_message="No attachments",
        selected=selected,
        detail_mode=detail_mode,
        width=width,
        height=height,
        footer=footer,
    )


def _agent_view_entries(
    runtime: RuntimeState,
    profiles: list[AgentProfileSummary] | None = None,
) -> list[AgentViewEntry]:
    profiles = profiles if profiles is not None else load_agent_profiles()
    entries = [
        AgentViewEntry(
            value="primary",
            label="primary",
            status=runtime.agent_state,
            description="SecOps Agent · foreground session",
            kind="primary",
        )
    ]
    for task in runtime.running_tasks():
        detail = task.name
        if task.detail:
            detail += f" · {task.detail}"
        entries.append(
            AgentViewEntry(
                value=task.id,
                label=task.id,
                status=task.status,
                description=detail,
                kind="task",
            )
        )
    for profile in profiles:
        entries.append(
            AgentViewEntry(
                value=str(profile.path),
                label=profile.name,
                status="profile",
                description=f"{profile.description} · {profile.source} · {_display_path(profile.path)}",
                kind="profile",
            )
        )
    return entries


def build_agents_view_lines(
    runtime: RuntimeState,
    *,
    selected: int = 0,
    expanded: bool = False,
    profiles: list[AgentProfileSummary] | None = None,
    cwd: Path | None = None,
    home: Path | None = None,
    width: int = 96,
    height: int = 28,
    footer: str = AGENTS_FOOTER,
) -> list[str]:
    """Build an inline AGY-like agents surface backed by SecOps runtime state."""
    width = max(1, width - 1)
    height = max(12, height)
    workspace_template, user_template = agent_profile_template_paths(cwd=cwd, home=home)
    entries = _agent_view_entries(runtime, profiles=profiles)
    active_task_count = len([entry for entry in entries if entry.kind == "task"])
    profile_count = len([entry for entry in entries if entry.kind == "profile"])
    total_selectable = 1 + (len(entries) if expanded else 0)
    selected = min(max(0, selected), max(0, total_selectable - 1))

    lines = [
        "",
        "Create New Agents",
        f"  Workspace: {_display_path(workspace_template)}",
        _display_path(user_template),
        "",
    ]
    section_cursor = "> " if selected == 0 else "  "
    section_marker = "▾" if expanded else "▸"
    lines.append(f"{section_cursor}{section_marker} Available Agents")

    if expanded:
        fixed_rows = len(lines) + 4
        visible_count = min(len(entries), max(1, height - fixed_rows))
        entry_selected = max(0, selected - 1)
        start = _settings_window_start(entry_selected, len(entries), visible_count)
        visible_entries = entries[start:start + visible_count]
        if visible_entries:
            for index, entry in enumerate(visible_entries, start=start):
                cursor = "> " if selected == index + 1 else "  "
                line = f"{cursor}{entry.label:<12} {entry.status:<10} {entry.description}"
                lines.append(_fit_cell(line, width))
        if len(entries) > visible_count:
            hidden_above = start
            hidden_below = max(0, len(entries) - start - len(visible_entries))
            if hidden_above:
                lines.append(f"  ↑ {hidden_above} more")
            if hidden_below:
                lines.append(f"  ↓ {hidden_below} more")
        if active_task_count == 0:
            lines.extend(["", "  No background subagents are active."])
        if profile_count == 0:
            lines.append("  No configured agent profiles.")

    lines.append("")
    lines.append(_fit_cell(footer, width))
    return [_fit_cell(line, width) for line in lines[:height]]


def _ordered_help_categories(groups: dict[str, list[Any]]) -> list[str]:
    ordered = [category for category in _HELP_CATEGORY_ORDER if category in groups]
    ordered.extend(sorted(category for category in groups if category not in ordered))
    return ordered


def _package_version() -> str:
    return __version__


def _short_workspace(path: Path) -> str:
    text = str(path)
    home = str(Path.home())
    if text == home:
        return "~"
    if text.startswith(home + os.sep):
        return "~" + text[len(home):]
    return text


def _help_view_index(initial_view: str | int = 0) -> int:
    if isinstance(initial_view, int):
        return min(max(0, initial_view), len(_HELP_VIEWS) - 1)

    normalized = str(initial_view).strip().lower()
    for index, view in enumerate(_HELP_VIEWS):
        if view.lower() == normalized:
            return index
    return 0


def _help_command_specs(groups: dict[str, list[Any]]) -> list[Any]:
    order = {spec.name: index for index, spec in enumerate(iter_commands())}
    specs = [spec for category in _ordered_help_categories(groups) for spec in groups.get(category, [])]
    return sorted(specs, key=lambda spec: order.get(getattr(spec, "name", ""), len(order)))


def _help_command_label(spec: Any) -> str:
    label = str(getattr(spec, "name", getattr(spec, "display_name", "")))
    alias = getattr(spec, "alias", None)
    if alias:
        label = f"{label} ({str(alias).lstrip('/')})"
    return label


def _help_list_row(
    label: str,
    value: str,
    *,
    selected: bool = False,
    label_width: int = 32,
    width: int = 96,
) -> str:
    cursor = "> " if selected else "  "
    description_width = max(8, width - len(cursor) - label_width - 1)
    return (
        f"{cursor}"
        f"{_fit_cell(label, label_width - 1).ljust(label_width)}"
        f"{_fit_cell(value, description_width)}"
    )


def _split_help_row(line: str) -> tuple[str, str, str, str] | None:
    match = _HELP_ROW_RE.match(line)
    if not match:
        return None
    return match.group(1), match.group(2), match.group(3), match.group(4)


def _is_detail_help_line(line: str) -> bool:
    return line.strip() in _HELP_DETAIL_LINES


def _is_shortcut_help_label(active_view: int, label: str) -> bool:
    return _HELP_VIEWS[_help_view_index(active_view)] == "Shortcuts" and label.strip() in _HELP_SHORTCUT_LABELS


def _help_prefix_lines(active_view: int) -> int:
    view = _HELP_VIEWS[_help_view_index(active_view)]
    if view == "Commands":
        return 2
    if view == "Shortcuts":
        return 3
    return 0


def _help_list_total(groups: dict[str, list[Any]], active_view: int) -> int:
    view = _HELP_VIEWS[_help_view_index(active_view)]
    if view == "Commands":
        return len(_help_command_specs(groups))
    if view == "Shortcuts":
        return len(_HELP_SHORTCUTS)
    return 0


def _help_view_items(
    groups: dict[str, list[Any]],
    active_view: int,
    width: int,
    *,
    selected_item: int = 0,
) -> list[str]:
    active_view = _help_view_index(active_view)
    if _HELP_VIEWS[active_view] == "General":
        command_count = sum(len(specs) for specs in groups.values())
        workspace = Path.cwd()
        return [
            "SecOps CLI helps plan authorized security assessments, collect evidence,",
            "and run approved tools from your terminal.",
            "",
            f"Version {_package_version()}",
            f"Workspace:    {_short_workspace(workspace)}",
            f"Project:      {workspace}",
            "",
            "Quick Reference",
            _help_list_row("/", "Type / to see available commands", width=width),
            _help_list_row("/permissions", "Review tool approval policy", width=width),
            _help_list_row("Tools", f"{command_count} slash commands available", width=width),
        ]

    if _HELP_VIEWS[active_view] == "Shortcuts":
        rows = [
            "Keyboard Shortcuts",
            _help_list_row("/keybindings", "Open shortcuts view", width=width),
            "",
        ]
        rows.extend(
            _help_list_row(
                key,
                description,
                selected=index == selected_item,
                width=width,
            )
            for index, (key, description) in enumerate(_HELP_SHORTCUTS)
        )
        return rows

    specs = _help_command_specs(groups)
    label_width = min(48, max(24, max((len(_help_command_label(spec)) for spec in specs), default=12) + 4))
    rows = ["Available Commands", ""]
    for index, spec in enumerate(specs):
        planned = "  planned" if not getattr(spec, "implemented", True) else ""
        rows.append(
            _help_list_row(
                _help_command_label(spec),
                str(getattr(spec, "description", "")) + planned,
                selected=index == selected_item,
                label_width=label_width,
                width=width,
            )
        )
    return rows


def _help_visible_count(total_items: int, height: int, active_view: str | int = 0) -> int:
    content_height = max(3, height - 5)
    view = _HELP_VIEWS[_help_view_index(active_view)]
    capped = False
    if view == "Commands":
        cap = _HELP_LIST_VISIBLE_ITEMS + _help_prefix_lines(active_view)
        capped = content_height >= cap
        content_height = min(content_height, cap)
    elif view == "Shortcuts":
        cap = _HELP_LIST_VISIBLE_ITEMS + 3
        capped = content_height >= cap
        content_height = min(content_height, cap)
    if capped and total_items > content_height:
        return content_height
    if total_items > content_height:
        return max(1, content_height - 1)
    return content_height


def _help_max_scroll(groups: dict[str, list[Any]], active_view: int, width: int, height: int) -> int:
    total = len(_help_view_items(groups, active_view, width))
    visible = _help_visible_count(total, height, active_view)
    return max(0, total - visible)


def _help_scroll_for_selection(
    groups: dict[str, list[Any]],
    active_view: int,
    width: int,
    height: int,
    selected_item: int,
    scroll_offset: int,
) -> int:
    prefix_lines = _help_prefix_lines(active_view)
    if not prefix_lines:
        return min(max(0, scroll_offset), _help_max_scroll(groups, active_view, width, height))

    total = len(_help_view_items(groups, active_view, width, selected_item=selected_item))
    visible = _help_visible_count(total, height, active_view)
    max_offset = max(0, total - visible)
    selected_line = prefix_lines + selected_item
    offset = min(max(0, scroll_offset), max_offset)
    if selected_line < offset:
        offset = selected_line
    elif selected_line >= offset + visible:
        offset = selected_line - visible + 1
    return min(max(0, offset), max_offset)


def _help_count_window(
    active_view: int,
    offset: int,
    visible_count: int,
    total_lines: int,
) -> tuple[int, int, int] | None:
    view = _HELP_VIEWS[_help_view_index(active_view)]
    if view == "Commands":
        prefix_lines = _help_prefix_lines(active_view)
    elif view == "Shortcuts":
        prefix_lines = 3
    else:
        return None

    total_items = max(0, total_lines - prefix_lines)
    if total_items <= _HELP_LIST_VISIBLE_ITEMS:
        return None

    start = max(1, offset - prefix_lines + 1)
    end = min(total_items, offset + visible_count - prefix_lines)
    if end < start:
        end = start
    return start, end, total_items


def _tool_category_value(tool: Any) -> str:
    category = getattr(tool, "category", "")
    return str(getattr(category, "value", category) or "uncategorized").lower()


def _tools_tabs(tools_list: list[Any]) -> list[str]:
    categories = sorted({_tool_category_value(tool) for tool in tools_list})
    return ["all", *categories]


def _tools_view_index(tools_list: list[Any], active_view: str | int = 0) -> int:
    tabs = _tools_tabs(tools_list)
    if isinstance(active_view, int):
        return min(max(0, active_view), max(0, len(tabs) - 1))

    normalized = str(active_view).strip().lower()
    for index, tab in enumerate(tabs):
        if tab == normalized:
            return index
    return 0


def _tools_for_view(tools_list: list[Any], active_view: str | int = 0) -> list[Any]:
    tabs = _tools_tabs(tools_list)
    active_index = _tools_view_index(tools_list, active_view)
    active_tab = tabs[active_index] if tabs else "all"
    items = list(tools_list)
    if active_tab != "all":
        items = [tool for tool in items if _tool_category_value(tool) == active_tab]
    return sorted(items, key=lambda tool: (_tool_category_value(tool), getattr(tool, "name", "")))


def _tools_tab_line(tabs: list[str], active_index: int, width: int, *, framed: bool = False) -> str:
    prefix = "  SecOps Tools   " if framed else "SecOps Tools   "
    suffix = "   (←/→ or tab to cycle)"
    available = max(8, width - len(prefix) - len(suffix))
    if available < 22:
        suffix = ""
        available = max(8, width - len(prefix))

    def label(index: int) -> str:
        tab = tabs[index]
        return f"[{tab}]" if framed and index == active_index else tab

    start = 0
    end = len(tabs)
    while end - start > 1:
        candidate = "    ".join(label(index) for index in range(start, end))
        extra = (2 if start > 0 else 0) + (2 if end < len(tabs) else 0)
        if len(candidate) + extra <= available:
            break
        if active_index - start > end - active_index - 1:
            start += 1
        else:
            end -= 1

    tab_text = "    ".join(label(index) for index in range(start, end))
    if start > 0:
        tab_text = "‹ " + tab_text
    if end < len(tabs):
        tab_text = tab_text + " ›"
    return _fit_cell(prefix + tab_text + suffix, width)


def _tools_window_start(selected: int, total: int, visible_count: int) -> int:
    if total <= visible_count:
        return 0
    half = visible_count // 2
    return min(max(0, selected - half), max(0, total - visible_count))


def build_tools_view_lines(
    tools_list: list[Any],
    active_view: str | int = 0,
    *,
    selected_tool: int = 0,
    width: int = 96,
    height: int = 28,
    framed: bool = True,
    fill: bool = True,
) -> list[str]:
    """Build an Antigravity-style tabbed tools browser."""
    width = max(1, width - 1)
    height = max(12, height)
    divider = _turn_separator(width + 1)
    tabs = _tools_tabs(tools_list)
    active_index = _tools_view_index(tools_list, active_view)
    rows = _tools_for_view(tools_list, active_index)
    selected_tool = min(max(0, selected_tool), max(0, len(rows) - 1))

    lines = [_tools_tab_line(tabs, active_index, width, framed=framed)]
    if framed:
        lines = [divider, _fit_cell(lines[0], width), divider]

    lines.append("Tools")

    visible_count = min(_LONG_LIST_VISIBLE_ITEMS, max(3, height - (8 if framed else 5)))
    label_width = min(30, max((len(getattr(tool, "name", "")) for tool in rows), default=10) + 4)
    start = _tools_window_start(selected_tool, len(rows), visible_count)
    visible = rows[start : start + visible_count]

    if not rows:
        lines.append("  No tools registered.")
    else:
        active_tab = tabs[active_index] if tabs else "all"
        for index, tool in enumerate(visible, start=start):
            cursor = "> " if index == selected_tool else "  "
            name = _fit_cell(getattr(tool, "name", ""), label_width - 1).ljust(label_width)
            description = str(getattr(tool, "description", ""))
            if active_tab == "all":
                description = f"{_tool_category_value(tool)} · {description}"
            if getattr(tool, "dangerous", False):
                description = f"{description}  dangerous"
            description_width = max(8, width - len(cursor) - label_width - 1)
            lines.append(f"{cursor}{name}{_fit_cell(description, description_width)}")

    if len(rows) > visible_count:
        end = start + len(visible)
        lines.append(f"  [{start + 1}-{end} of {len(rows)} tools]")

    while fill and len(lines) < height - 2:
        lines.append("")
    if framed:
        lines.append(divider)
    lines.append("Keyboard: ↑/↓ Navigate  ←/→ Switch View  esc Close")
    return [_fit_cell(line, width) for line in lines[:height]]


def build_help_view_lines(
    groups: dict[str, list[Any]],
    active_view: str | int = 0,
    *,
    scroll_offset: int = 0,
    selected_item: int = 0,
    width: int = 96,
    height: int = 28,
    framed: bool = True,
    fill: bool = True,
) -> list[str]:
    """Build the Antigravity-style help view shared by ?, /help and /keybindings."""
    width = max(1, width - 1)
    height = max(12, height)
    divider = _turn_separator(width + 1)
    active_index = _help_view_index(active_view)
    if framed:
        tab_parts = [
            f"[{view}]" if index == active_index else view
            for index, view in enumerate(_HELP_VIEWS)
        ]
    else:
        tab_parts = [view.lower() for view in _HELP_VIEWS]
    tab_prefix = "  SecOps CLI" if framed else "SecOps CLI"
    tab_line = tab_prefix + "   " + "    ".join(tab_parts) + "   (←/→ or tab to cycle)"

    item_total = _help_list_total(groups, active_index)
    selected_item = min(max(0, selected_item), max(0, item_total - 1))
    items = _help_view_items(groups, active_index, width, selected_item=selected_item)
    total = len(items)
    visible_count = _help_visible_count(total, height, active_index)
    offset = _help_scroll_for_selection(
        groups,
        active_index,
        width,
        height,
        selected_item,
        scroll_offset,
    )
    visible_items = items[offset : offset + visible_count]

    lines = [_fit_cell(tab_line, width)]
    if framed:
        lines = [
            divider,
            _fit_cell(tab_line, width),
            divider,
        ]
    lines.extend(_fit_cell(item, width) for item in visible_items)
    count_window = _help_count_window(active_index, offset, len(visible_items), total)
    if count_window:
        start, end, count_total = count_window
        lines.append(f"  [{start}-{end} of {count_total} items]")
    elif total > visible_count:
        start = offset + 1
        end = offset + len(visible_items)
        lines.append(f"  [{start}-{end} of {total} items]")

    while fill and len(lines) < height - 2:
        lines.append("")
    if framed:
        lines.append(divider)
    lines.append("  Keyboard: ↑/↓ Navigate  ←/→ Switch View  esc Close")
    return [_fit_cell(line, width) for line in lines[:height]]


def _sanitize_archived_calls(text: str) -> str:
    """Replace raw [Archived tool call: ...] markers with a visible warning.

    Bug 2.1: The LLM sometimes emits these markers as plain text instead of
    issuing a real function_call.  Rather than letting the raw bracket text
    bleed into the narrative, replace each occurrence with a compact,
    clearly-labelled warning so the user knows something went wrong.
    """
    if not _ARCHIVED_CALL_RE.search(text):
        return text
    return _ARCHIVED_CALL_RE.sub(
        r'⚠ \1 was referenced from history (not executed this turn)',
        text,
    )


def normalize_agent_markdown(text: str) -> str:
    """Keep model output visually stable before Rich Markdown renders it."""
    if not text:
        return text

    # Bug 2.1 safety net: sanitize archived-call markers before rendering.
    text = _sanitize_archived_calls(text)

    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    normalized: list[str] = []
    in_code_fence = False
    skip_next = False
    ordered_next: int | None = None

    def next_ordered_number(start: int) -> int | None:
        for candidate in lines[start:]:
            if not candidate.strip():
                continue
            match = _ORDERED_LIST_LINE_RE.match(candidate.rstrip())
            if not match:
                return None
            return int(match.group(2))
        return None

    for index, line in enumerate(lines):
        if skip_next:
            skip_next = False
            continue

        stripped = line.strip()
        if stripped.startswith("```"):
            ordered_next = None
            in_code_fence = not in_code_fence
            normalized.append(line.rstrip())
            continue

        if in_code_fence:
            normalized.append(line.rstrip())
            continue

        heading = _MARKDOWN_HEADING_RE.match(line)
        if heading:
            ordered_next = None
            title = heading.group(2).strip()
            if title:
                normalized.append(f"**{title}**")
            continue

        next_line = lines[index + 1] if index + 1 < len(lines) else ""
        if stripped and _MARKDOWN_SETEXT_RE.match(next_line.strip()):
            ordered_next = None
            normalized.append(f"**{stripped}**")
            skip_next = True
            continue

        if _MARKDOWN_HRULE_RE.match(line):
            ordered_next = None
            if normalized and normalized[-1] != "":
                normalized.append("")
            continue

        if stripped == "":
            ordered_next = None
            if normalized and normalized[-1] != "":
                normalized.append("")
            continue

        ordered_match = _ORDERED_LIST_LINE_RE.match(line.rstrip())
        if ordered_match:
            number = int(ordered_match.group(2))
            following = next_ordered_number(index + 1)
            is_sequence = (
                ordered_next == number
                or (number == 1 and following == 2)
                or (following == number + 1)
            )
            if is_sequence:
                indent = ordered_match.group(1)
                body = ordered_match.group(3).rstrip()
                normalized.append(f"{indent}{number}\\. {body}  ")
                ordered_next = number + 1
                continue

        ordered_next = None
        normalized.append(line.rstrip())

    while normalized and normalized[0] == "":
        normalized.pop(0)
    while normalized and normalized[-1] == "":
        normalized.pop()

    return "\n".join(normalized)


_RESET_SECONDS_RE = re.compile(r'(?:retry[_-]?after|reset(?:s? in)?)\s*[:=]?\s*(\d+)', re.IGNORECASE)
_RESET_HMS_RE = re.compile(r'(\d+)h(\d+)m(\d+)s', re.IGNORECASE)


def _extract_reset_seconds(error_text: str) -> int | None:
    """Try to extract a reset/retry-after countdown (in seconds) from an error.

    Returns None if no parseable value is found.
    """
    # Check for an already-formatted XhYmZs string first.
    hms = _RESET_HMS_RE.search(error_text)
    if hms:
        return int(hms.group(1)) * 3600 + int(hms.group(2)) * 60 + int(hms.group(3))
    # Check for a bare integer seconds value (e.g. "retry_after: 3600").
    bare = _RESET_SECONDS_RE.search(error_text)
    if bare:
        value = int(bare.group(1))
        if 1 <= value <= 604800:  # up to 7 days
            return value
    return None


def _compact_agent_error(message: str) -> str:
    """Collapse noisy provider exceptions into one Antigravity-style warning."""
    text = str(message or "").strip()
    lowered = text.casefold()

    if "resource_exhausted" in lowered or "429" in lowered:
        # ✅ Verified agy wording (Antigravity surfaces 429/quota saturation as a
        # high-traffic notice). Try to extract a reset/retry-after hint from the
        # raw error text (some providers include seconds or a timestamp).
        reset_hint = _extract_reset_seconds(text)
        if reset_hint is not None:
            h, rem = divmod(int(reset_hint), 3600)
            m, s = divmod(rem, 60)
            return f"Our servers are experiencing high traffic right now. Try again in {h}h{m}m{s}s."
        return "Our servers are experiencing high traffic right now, please try again in a minute."
    if "api_key" in lowered or "api key" in lowered or "gemini_api_key" in lowered:
        return "GEMINI_API_KEY is missing or invalid. Configure it, then try again."
    if "permission_denied" in lowered or "403" in lowered:
        return "Model access was denied. Check the API key, project permissions, or selected model."
    if "not_found" in lowered or "404" in lowered:
        return "The selected model is unavailable. Switch models with /model and try again."
    if "deadline" in lowered or "timeout" in lowered or "timed out" in lowered:
        return "The model request timed out. Try again or switch to a faster model."
    if "unavailable" in lowered or "capacity" in lowered or "overloaded" in lowered:
        return "The model service is temporarily unavailable. Try again shortly."

    # Provider exceptions often append huge JSON dictionaries. Keep only the
    # human-readable lead and cap it so the warning never dominates the turn.
    compact = text.replace("\r\n", "\n").replace("\r", "\n").splitlines()[0]
    if "{'error':" in compact:
        compact = compact.split("{'error':", 1)[0].rstrip(" :")
    if '{"error":' in compact:
        compact = compact.split('{"error":', 1)[0].rstrip(" :")
    if len(compact) > 180:
        compact = compact[:177] + "..."
    return compact or "The model request failed."


class _EscInterruptMonitor:
    """Small raw-key watcher used only while the agent is generating."""

    def __init__(self):
        self.event: asyncio.Event = asyncio.Event()
        self.expand_event: asyncio.Event = asyncio.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        if not sys.stdin.isatty():
            return
        self._stop.clear()
        self._loop = asyncio.get_running_loop()
        self._thread = threading.Thread(target=self._read_loop, daemon=True)
        self._thread.start()

    async def stop(self) -> None:
        self._stop.set()
        thread = self._thread
        self._thread = None
        if thread and thread.is_alive():
            deadline = time.monotonic() + 0.25
            while thread.is_alive() and time.monotonic() < deadline:
                await asyncio.sleep(0.01)

    def clear(self) -> None:
        if self.event.is_set():
            self.event = asyncio.Event()
        if self.expand_event.is_set():
            self.expand_event = asyncio.Event()

    def _trigger(self) -> None:
        if self._loop and not self._loop.is_closed():
            self._loop.call_soon_threadsafe(self.event.set)

    def _trigger_expand(self) -> None:
        if self._loop and not self._loop.is_closed():
            self._loop.call_soon_threadsafe(self.expand_event.set)

    def _read_loop(self) -> None:
        fd = sys.stdin.fileno()
        old_settings = None
        try:
            old_settings = termios.tcgetattr(fd)
            tty.setcbreak(fd)
            while not self._stop.is_set():
                ready, _, _ = select.select([fd], [], [], 0.1)
                if not ready:
                    continue
                data = os.read(fd, 32)
                if not data:
                    return
                if b"\x0f" in data:
                    self._trigger_expand()
                    continue
                if b"\x1b" in data or b"\x03" in data:
                    self._trigger()
                    return
        except Exception:
            return
        finally:
            if old_settings is not None:
                try:
                    termios.tcsetattr(fd, termios.TCSANOW, old_settings)
                except Exception:
                    pass


class _AgentStreamInterrupted(Exception):
    """Raised internally when esc/c Ctrl-C interrupts generation."""


class _TranscriptToggleRequest:
    """Internal event emitted when ctrl+o is pressed during active streaming."""


async def _interruptible_events(
    event_stream: AsyncIterator[AgentEvent],
    interrupt: _EscInterruptMonitor,
) -> AsyncIterator[AgentEvent | _TranscriptToggleRequest]:
    iterator = event_stream.__aiter__()
    next_task = asyncio.create_task(iterator.__anext__())
    while True:
        interrupt_task = asyncio.create_task(interrupt.event.wait())
        expand_task = asyncio.create_task(interrupt.expand_event.wait())
        done, pending = await asyncio.wait(
            {next_task, interrupt_task, expand_task},
            return_when=asyncio.FIRST_COMPLETED,
        )

        if interrupt_task in done:
            next_task.cancel()
            expand_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await expand_task
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await next_task
            aclose = getattr(iterator, "aclose", None)
            if aclose:
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await aclose()
            raise _AgentStreamInterrupted

        if expand_task in done:
            interrupt.clear()
            for task in (interrupt_task, expand_task):
                if not task.done():
                    task.cancel()
                    with contextlib.suppress(asyncio.CancelledError, Exception):
                        await task
            yield _TranscriptToggleRequest()
            continue

        for task in (interrupt_task, expand_task):
            if not task.done():
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task

        try:
            event = next_task.result()
        except StopAsyncIteration:
            break
        yield event
        next_task = asyncio.create_task(iterator.__anext__())


class Renderer:
    """Antigravity-style terminal renderer."""

    def __init__(self):
        self.console = Console(theme=rich_theme)
        self._thinking_start: float | None = None
        self._thinking_content: str = ""
        self._thinking_spinner: ThinkingSpinner | None = None
        self._tool_start: float | None = None
        self._current_tool_name: str = ""
        self._current_tool_arguments: dict[str, Any] = {}
        self._tool_spinner: ToolExecutionSpinner | None = None
        self._latest_thought_duration: int | float | None = None
        self._latest_thought_content: str = ""
        self._latest_tool_name: str = ""
        self._latest_tool_arguments: dict[str, Any] = {}
        self._latest_tool_result: Any | None = None
        self._latest_transcript_expanded: bool = False
        self._latest_transcript_rendered_lines: int = 0
        self._pending_tool_call_lines: int = 0
        self._running_tool_row_lines: int = 0
        # §5.7 — display preferences from settings.json
        try:
            from secops_agent.core.preferences import load_display_preferences
            self._display_prefs: dict[str, Any] = load_display_preferences()
        except Exception:
            self._display_prefs = {}

    # ── Static Renders ────────────────────────────────────────────────

    def render_welcome(self):
        """Minimal welcome message."""
        self.console.print(
            f"[{COLORS['text_muted']}]Type a prompt to begin. "
            f"/help for commands.[/{COLORS['text_muted']}]"
        )

    def render_user_input(self, text: str, *, trailing_blank: bool = True, separator: bool = True):
        """Echo a completed prompt once after prompt_toolkit erases redraws."""
        lines = str(text).splitlines() or [""]
        input_color = COLORS["accent_bright"]
        width = _surface_width(self.console)
        if separator:
            self.console.print(f"[{COLORS['text_dim']}]{_turn_separator(width)}[/]")
        self.console.print(
            f"[{COLORS['accent']}]>[/{COLORS['accent']}] "
            f"[{input_color} bold]{escape(lines[0])}[/]"
        )
        for line in lines[1:]:
            self.console.print(f"  [{input_color} bold]{escape(line)}[/]")
        if trailing_blank:
            self.console.print()

    def render_empty_prompt_frame(self):
        """Render the idle prompt frame before inline shortcut overlays."""
        separator = _turn_separator(_surface_width(self.console))
        self.console.print(f"[{COLORS['text_dim']}]{separator}[/]")
        self.console.print(f"[{COLORS['accent']}]>[/{COLORS['accent']}]")
        self.console.print(f"[{COLORS['text_dim']}]{separator}[/]")

    def _inline_statusline(self, left: str, right: str, width: int) -> str:
        if not right:
            return _fit_cell(left, width)
        right = _fit_cell(right, max(10, width - len(left) - 2))
        return f"{left}{' ' * max(1, width - len(left) - len(right) - 1)}{right}"

    def _view_inline_lines(
        self,
        lines: list[str],
        *,
        status_right: str = "",
        footer: str = "Keyboard: esc Close",
        prompt_frame: bool = True,
    ) -> None:
        """Show a transient inline command surface and clear it on escape."""
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            for line in lines:
                self.console.print(f"[{COLORS['text_muted']}]{escape(line)}[/]")
            return

        import shutil
        import termios
        import tty
        from secops_agent.ui.theme import ansi, ANSI_RESET

        c_accent = ansi("accent", bold=True)
        c_text = ansi("text")
        c_muted = ansi("text_muted")
        c_dim = ansi("text_dim")
        reset = ANSI_RESET
        rendered_lines = 0

        def read_key() -> str:
            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            try:
                tty.setraw(fd)
                key = read_terminal_key(fd)
                if key == "esc":
                    return "esc"
                return key
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

        def render() -> None:
            nonlocal rendered_lines
            width, height = shutil.get_terminal_size((96, 28))
            content_width = max(1, width - 1)
            footer_rows = 3 if footer else 1
            available_lines = max(
                1,
                _transient_content_height(height, prompt_frame=prompt_frame) - footer_rows,
            )
            divider = _turn_separator(width)
            display = []
            if prompt_frame:
                display.extend([divider, ">", divider])
            display.extend(_fit_cell(line, content_width) for line in lines[:available_lines])
            if footer:
                display.extend(["", _fit_cell(footer, content_width)])
            display.append("")
            display.append(self._inline_statusline("esc to cancel", status_right, content_width))

            if rendered_lines:
                sys.stdout.write(f"\x1b[{rendered_lines}A\x1b[J")
            for line in display:
                stripped = line.strip()
                if line.startswith("─"):
                    color = c_dim
                elif line == ">" or stripped in {"Agents", "Artifacts"}:
                    color = c_accent
                elif stripped.startswith(("Keyboard:", "esc to cancel")):
                    color = c_muted
                else:
                    color = c_text
                sys.stdout.write(f"{color}{line}{reset}\n")
            sys.stdout.flush()
            rendered_lines = len(display)

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
            while read_key() != "esc":
                pass
        finally:
            clear_rendered()


    def render_help(
        self,
        initial_view: str | int = "general",
        status_right: str = "",
        prompt_frame: bool = False,
    ):
        """Render shared help in Antigravity-style top-level tabs."""
        groups: dict[str, list[Any]] = {}
        for spec in iter_commands():
            groups.setdefault(spec.category, []).append(spec)
        selected = _help_view_index(initial_view)

        if sys.stdin.isatty() and sys.stdout.isatty():
            self._render_help_tabs(
                groups,
                selected,
                status_right=status_right,
                prompt_frame=prompt_frame,
            )
            return

        lines = build_help_view_lines(
            groups,
            active_view=selected,
            width=self.console.size.width,
            height=min(28, max(12, self.console.size.height)),
        )
        self.console.print()
        for line in lines:
            if line.startswith("─"):
                self.console.print(f"[{COLORS['text_dim']}]{line}[/]")
            elif _is_detail_help_line(line):
                self.console.print(f"[{COLORS['text_muted']}]{escape(line)}[/]")
            elif line.strip() in {"Quick Reference", "Available Commands", "Keyboard Shortcuts"}:
                self.console.print(f"[{COLORS['text']}]{escape(line)}[/]")
            elif line.strip().startswith("Keyboard:"):
                self.console.print(f"[{COLORS['text_muted']}]{escape(line)}[/]")
            elif help_row := _split_help_row(line):
                marker, label, spacing, description = help_row
                marker_style = COLORS["text"] if marker.strip() == ">" else COLORS["text_muted"]
                label_style = COLORS["accent"] if _is_shortcut_help_label(selected, label) else COLORS["text"]
                self.console.print(
                    f"[{marker_style}]{escape(marker)}[/]"
                    f"[{label_style}]{escape(label)}[/]"
                    f"{spacing}"
                    f"[{COLORS['text_muted']}]{escape(description)}[/]"
                )
            else:
                self.console.print(f"[{COLORS['text_muted']}]{escape(line)}[/]")
        self.console.print()

    def _render_help_tabs(
        self,
        groups: dict[str, list[Any]],
        selected: int = 0,
        status_right: str = "",
        prompt_frame: bool = False,
    ) -> None:
        """Open a transient inline tabbed help view controlled with arrows or tab."""
        import shutil
        import termios
        import tty
        from secops_agent.ui.theme import ansi, ANSI_RESET

        selected = _help_view_index(selected)
        scroll_offset = 0
        selected_items = [0 for _ in _HELP_VIEWS]
        c_shortcut = ansi("accent")
        c_text = ansi("text")
        c_muted = ansi("text_muted")
        c_dim = ansi("text_dim")
        reset = ANSI_RESET

        def read_key() -> str:
            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            try:
                tty.setraw(fd)
                key = read_terminal_key(fd, escape_timeout=0.2)
                if key == "mouse_up":
                    return "up"
                if key == "mouse_down":
                    return "down"
                if key == "tab":
                    return "right"
                if key in {"left", "right", "up", "down", "pgup", "pgdn", "home", "end", "esc"}:
                    return key
                return key
            finally:
                termios.tcsetattr(fd, termios.TCSANOW, old_settings)

        rendered_lines = 0

        def statusline(left: str, right: str, width: int) -> str:
            if not right:
                return _fit_cell(left, width)
            right = _fit_cell(right, max(10, width - len(left) - 2))
            return f"{left}{' ' * max(1, width - len(left) - len(right) - 1)}{right}"

        def write_tab_line(line: str) -> None:
            active = _HELP_VIEWS[selected].lower()
            start = line.find(active, len("SecOps CLI"))
            if start < 0:
                sys.stdout.write(f"{c_text}{line}{reset}\n")
                return
            end = start + len(active)
            sys.stdout.write(
                f"{c_text}{line[:start]}{reset}"
                f"{c_text}{line[start:end]}{reset}"
                f"{c_muted}{line[end:]}{reset}\n"
            )

        def write_help_row(line: str) -> bool:
            help_row = _split_help_row(line)
            if not help_row:
                return False
            marker, label, spacing, description = help_row
            marker_color = c_text if marker.strip() == ">" else c_muted
            label_color = c_shortcut if _is_shortcut_help_label(selected, label) else c_text
            sys.stdout.write(
                f"{marker_color}{marker}{reset}"
                f"{label_color}{label}{reset}"
                f"{spacing}"
                f"{c_muted}{description}{reset}\n"
            )
            return True

        def render() -> None:
            nonlocal rendered_lines, scroll_offset
            columns, rows = shutil.get_terminal_size((96, 28))
            content_height = _transient_content_height(rows, prompt_frame=prompt_frame)
            scroll_offset = _help_scroll_for_selection(
                groups,
                selected,
                columns,
                content_height,
                selected_items[selected],
                scroll_offset,
            )
            lines = build_help_view_lines(
                groups,
                active_view=selected,
                scroll_offset=scroll_offset,
                selected_item=selected_items[selected],
                width=columns,
                height=content_height,
                framed=False,
                fill=False,
            )
            if prompt_frame:
                separator = _turn_separator(columns)
                lines = [separator, ">", separator, *lines]
            if lines and lines[-1] != "":
                lines.append("")
            lines.append(statusline("esc to cancel", status_right, columns))

            if rendered_lines:
                sys.stdout.write(f"\x1b[{rendered_lines}A\x1b[J")
            for line in lines:
                stripped = line.strip()
                if stripped.startswith("SecOps CLI   "):
                    write_tab_line(line)
                    continue
                if _is_detail_help_line(line):
                    color = c_muted
                elif line.startswith("─"):
                    color = c_dim
                elif line == ">":
                    color = c_text
                elif stripped in {"Quick Reference", "Available Commands", "Keyboard Shortcuts"}:
                    color = c_text
                elif stripped.startswith("Keyboard:"):
                    color = c_muted
                elif stripped.startswith("esc to cancel"):
                    color = c_muted
                elif write_help_row(line):
                    continue
                elif any(f"[{view}]" in line for view in _HELP_VIEWS):
                    color = c_text
                else:
                    color = c_muted
                sys.stdout.write(f"{color}{line}{reset}\n")
            sys.stdout.flush()
            rendered_lines = len(lines)

        def clear_rendered() -> None:
            nonlocal rendered_lines
            if rendered_lines:
                sys.stdout.write(f"\x1b[{rendered_lines}A\x1b[J")
                rendered_lines = 0
            sys.stdout.write("\x1b[?25h")
            sys.stdout.flush()

        sys.stdout.write("\x1b[?25l")
        sys.stdout.flush()
        try:
            while True:
                render()
                key = read_key()
                if key == "left":
                    selected = (selected - 1) % len(_HELP_VIEWS)
                    scroll_offset = 0
                elif key == "right":
                    selected = (selected + 1) % len(_HELP_VIEWS)
                    scroll_offset = 0
                elif key == "up":
                    item_total = _help_list_total(groups, selected)
                    if item_total:
                        selected_items[selected] = (selected_items[selected] - 1) % item_total
                    else:
                        scroll_offset = max(0, scroll_offset - 1)
                elif key == "down":
                    item_total = _help_list_total(groups, selected)
                    if item_total:
                        selected_items[selected] = (selected_items[selected] + 1) % item_total
                    else:
                        columns, rows = shutil.get_terminal_size((96, 28))
                        content_height = _transient_content_height(rows, prompt_frame=prompt_frame)
                        max_scroll = _help_max_scroll(groups, selected, columns, content_height)
                        scroll_offset = min(max_scroll, scroll_offset + 1)
                elif key == "pgup":
                    columns, rows = shutil.get_terminal_size((96, 28))
                    content_height = _transient_content_height(rows, prompt_frame=prompt_frame)
                    visible = _help_visible_count(
                        len(_help_view_items(groups, selected, columns, selected_item=selected_items[selected])),
                        content_height,
                        selected,
                    )
                    item_total = _help_list_total(groups, selected)
                    if item_total:
                        selected_items[selected] = max(0, selected_items[selected] - max(1, visible - _help_prefix_lines(selected)))
                    else:
                        scroll_offset = max(0, scroll_offset - visible)
                elif key == "pgdn":
                    columns, rows = shutil.get_terminal_size((96, 28))
                    content_height = _transient_content_height(rows, prompt_frame=prompt_frame)
                    visible = _help_visible_count(
                        len(_help_view_items(groups, selected, columns, selected_item=selected_items[selected])),
                        content_height,
                        selected,
                    )
                    item_total = _help_list_total(groups, selected)
                    if item_total:
                        page = max(1, visible - _help_prefix_lines(selected))
                        selected_items[selected] = min(item_total - 1, selected_items[selected] + page)
                    else:
                        max_scroll = _help_max_scroll(groups, selected, columns, content_height)
                        scroll_offset = min(max_scroll, scroll_offset + visible)
                elif key == "home":
                    if _help_list_total(groups, selected):
                        selected_items[selected] = 0
                    else:
                        scroll_offset = 0
                elif key == "end":
                    item_total = _help_list_total(groups, selected)
                    if item_total:
                        selected_items[selected] = item_total - 1
                    else:
                        columns, rows = shutil.get_terminal_size((96, 28))
                        content_height = _transient_content_height(rows, prompt_frame=prompt_frame)
                        scroll_offset = _help_max_scroll(groups, selected, columns, content_height)
                elif key == "esc":
                    break
        finally:
            clear_rendered()

    def render_keybindings(self, status_right: str = "", prompt_frame: bool = False):
        """Show the shortcuts tab of the shared help surface."""
        self.render_help(
            initial_view="shortcuts",
            status_right=status_right,
            prompt_frame=prompt_frame,
        )

    def render_trajectory(self, memory: Any, runtime: RuntimeState):
        """Open or print the session trajectory."""
        from secops_agent.ui.session_review import build_trajectory_text, view_trajectory

        messages = list(getattr(memory, "messages", []) or [])
        artifacts = list(getattr(runtime, "artifacts", []) or [])
        attachments = list(runtime.attachment_artifacts())
        tasks = list(getattr(runtime, "tasks", []) or [])
        has_content = bool(messages or artifacts or attachments or tasks)

        if has_content and sys.stdin.isatty() and sys.stdout.isatty():
            view_trajectory(memory, runtime)
            return

        rows = [
            OverlayRow("Messages", str(len(messages)), accent=True),
            OverlayRow("Artifacts", str(len(artifacts))),
            OverlayRow("Attachments", str(len(attachments))),
            OverlayRow("Tasks", str(len(tasks))),
        ]
        footer = ""
        if has_content:
            text = build_trajectory_text(memory, runtime)
            for line in [line for line in text.splitlines() if line.strip()][:16]:
                rows.append(OverlayRow("Trace", line))
            footer = "ctrl+o toggles latest transcript  ·  /trajectory opens this full session view"
        else:
            rows.append(OverlayRow("Status", "No messages yet."))
        render_overlay(
            self.console,
            "Trajectory",
            rows,
            footer=footer,
        )

    def render_artifacts(
        self,
        runtime: RuntimeState,
        artifact_id: str = "",
        *,
        transient: bool = False,
        status_right: str = "",
    ):
        """Review generated artifacts or list the artifact registry."""
        from secops_agent.ui.session_review import build_artifact_text, view_artifact_review

        requested = artifact_id.strip()
        force_list = requested.lower() in {"list", "ls"}
        list_only = requested == "" or force_list
        if transient and not requested and sys.stdin.isatty() and sys.stdout.isatty():
            self._render_artifacts_view(
                runtime,
                status_right=status_right,
            )
            return

        if not runtime.artifacts:
            lines = build_artifacts_view_lines(runtime, width=self.console.size.width)
            self.console.print()
            for line in lines:
                stripped = line.strip()
                if stripped == "Artifacts":
                    self.console.print(f"[{COLORS['text']}]{escape(line)}[/]")
                elif stripped.startswith(("No artifacts", "Keyboard:")):
                    self.console.print(f"[{COLORS['text_muted']}]{escape(line)}[/]")
                else:
                    self.console.print(f"[{COLORS['text']}]{escape(line)}[/]")
            self.console.print()
            return

        if not list_only:
            artifact = runtime.get_artifact(requested)
            if not artifact:
                self.render_error(f"Artifact not found: {requested}")
                return
        else:
            artifact = None

        if artifact and sys.stdin.isatty() and sys.stdout.isatty():
            view_artifact_review(runtime, artifact.id)
            return

        if artifact:
            content_lines = [line for line in build_artifact_text(artifact).splitlines() if line.strip()]
            rows = [
                OverlayRow("ID", artifact.id, accent=True),
                OverlayRow("Kind", artifact.kind),
                OverlayRow("Source", artifact.source or "-"),
            ]
            rows.extend(OverlayRow("Content", line[:180]) for line in content_lines[:16])
            render_overlay(
                self.console,
                f"Artifact {artifact.id}",
                rows,
            )
            return

        lines = build_artifacts_view_lines(runtime, selected=len(runtime.artifacts) - 1, width=self.console.size.width)
        self.console.print()
        for line in lines:
            stripped = line.strip()
            if stripped == "Artifacts":
                self.console.print(f"[{COLORS['text']}]{escape(line)}[/]")
            elif line.startswith("> "):
                self.console.print(f"[{COLORS['accent']}]{escape(line)}[/]")
            elif stripped.startswith(("No artifacts", "Keyboard:", "↑ ", "↓ ")):
                self.console.print(f"[{COLORS['text_muted']}]{escape(line)}[/]")
            else:
                self.console.print(f"[{COLORS['text']}]{escape(line)}[/]")
        self.console.print()

    def _render_artifacts_view(
        self,
        runtime: RuntimeState,
        *,
        title: str = "Artifacts",
        artifacts: list[Any] | None = None,
        empty_message: str = "No artifacts",
        status_right: str = "",
    ) -> None:
        from secops_agent.ui.theme import ansi, ANSI_RESET

        current_artifacts = list(artifacts if artifacts is not None else (getattr(runtime, "artifacts", []) or []))
        selected = max(0, len(current_artifacts) - 1)
        detail_mode = ""
        c_accent = ansi("accent")
        c_text = ansi("text")
        c_muted = ansi("text_muted")
        c_dim = ansi("text_dim")
        reset = ANSI_RESET
        rendered_lines = 0

        def read_key() -> str:
            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            try:
                tty.setraw(fd)
                key = read_terminal_key(fd, escape_timeout=0.2)
                if key in {"up", "down", "esc", "enter"}:
                    return key
                if key == "mouse_up":
                    return "up"
                if key == "mouse_down":
                    return "down"
                if len(key) == 1 and key.lower() == "p":
                    return "preview"
                return key
            finally:
                termios.tcsetattr(fd, termios.TCSANOW, old_settings)

        def statusline(left: str, right: str, width: int) -> str:
            if not right:
                return _fit_cell(left, width)
            right = _fit_cell(right, max(10, width - len(left) - 2))
            return f"{left}{' ' * max(1, width - len(left) - len(right) - 1)}{right}"

        def render() -> None:
            nonlocal rendered_lines
            columns, rows = shutil.get_terminal_size((96, 28))
            content_height = _transient_content_height(rows, prompt_frame=True)
            current_artifacts = list(artifacts if artifacts is not None else (getattr(runtime, "artifacts", []) or []))
            lines = build_artifacts_view_lines(
                runtime,
                artifacts=current_artifacts,
                title=title,
                empty_message=empty_message,
                selected=selected,
                detail_mode=detail_mode,
                width=columns,
                height=content_height,
            )
            if lines and lines[0] == "":
                lines = lines[1:]
            separator = _turn_separator(columns)
            lines = [separator, ">", separator, *lines]
            if lines and lines[-1] != "":
                lines.append("")
            lines.append(statusline("? for shortcuts", status_right, columns))

            if rendered_lines:
                sys.stdout.write(f"\x1b[{rendered_lines}A\x1b[J")
            for line in lines:
                stripped = line.strip()
                if line.startswith("> ") or stripped.startswith(("Preview:", "Open:")):
                    color = c_accent
                elif stripped == title or line == ">":
                    color = c_text
                elif line.startswith("─"):
                    color = c_dim
                elif stripped.startswith(("No artifacts", "No attachments", "Keyboard:", "↑ ", "↓ ", "? for shortcuts")):
                    color = c_muted
                else:
                    color = c_text
                sys.stdout.write(f"{color}{line}{reset}\n")
            sys.stdout.flush()
            rendered_lines = len(lines)

        def clear_rendered() -> None:
            nonlocal rendered_lines
            if rendered_lines:
                sys.stdout.write(f"\x1b[{rendered_lines}A\x1b[J")
                rendered_lines = 0
            sys.stdout.write("\x1b[?25h")
            sys.stdout.flush()

        sys.stdout.write("\x1b[?25l")
        sys.stdout.flush()
        try:
            while True:
                current_artifacts = list(artifacts if artifacts is not None else (getattr(runtime, "artifacts", []) or []))
                item_count = max(1, len(current_artifacts))
                selected = min(max(0, selected), item_count - 1)
                render()
                key = read_key()
                if key == "up":
                    selected = (selected - 1) % item_count
                elif key == "down":
                    selected = (selected + 1) % item_count
                elif key == "preview" and current_artifacts:
                    detail_mode = "" if detail_mode == "preview" else "preview"
                elif key == "enter" and current_artifacts:
                    detail_mode = "" if detail_mode == "open" else "open"
                elif key == "esc":
                    break
        finally:
            clear_rendered()

    def render_attachments(
        self,
        runtime: RuntimeState,
        *,
        transient: bool = False,
        status_right: str = "",
    ):
        """List evidence attachments captured in the session."""
        attachments = runtime.attachment_artifacts()
        if transient and sys.stdin.isatty() and sys.stdout.isatty():
            self._render_artifacts_view(
                runtime,
                title="Attachments",
                artifacts=attachments,
                empty_message="No attachments",
                status_right=status_right,
            )
            return

        lines = build_attachments_view_lines(
            runtime,
            selected=len(attachments) - 1,
            width=self.console.size.width,
        )
        self.console.print()
        for line in lines:
            stripped = line.strip()
            if stripped == "Attachments":
                self.console.print(f"[{COLORS['text']}]{escape(line)}[/]")
            elif line.startswith("> "):
                self.console.print(f"[{COLORS['accent']}]{escape(line)}[/]")
            elif stripped.startswith(("No attachments", "Keyboard:", "↑ ", "↓ ")):
                self.console.print(f"[{COLORS['text_muted']}]{escape(line)}[/]")
            else:
                self.console.print(f"[{COLORS['text']}]{escape(line)}[/]")
        self.console.print()

    def _settings_items(self, model: str, timeout: int, max_tokens: int, log_file: str, runtime: RuntimeState) -> list[SettingsItem]:
        workspace_value = f"{len(runtime.workspace_dirs)} configured" if runtime.workspace_dirs else "current directory"
        from secops_agent.core.model_catalog import selectable_models

        model_options = tuple(friendly_model_name(model_name) for model_name in selectable_models())
        return [
            SettingsItem("Response Profile", "fast" if runtime.fast_mode else "standard", "Fast profile lowers loop count and restores standard reasoning when off", editable=True, options=("standard", "fast")),
            SettingsItem("Model", friendly_model_name(model), "Active model profile for assistant responses", editable=True, options=model_options),
            SettingsItem("Tool Permission", runtime.permission_mode, "Approval mode for tools and terminal commands", editable=True, options=("request-review", "proceed-in-sandbox", "always-proceed", "strict")),
            SettingsItem("Sandbox Mode", "on" if runtime.sandbox_enabled else "off", "Session command guard before subprocess execution", editable=True, options=("on", "off")),
            SettingsItem("Tool Timeout", f"{timeout}s", "Maximum runtime for local tool execution"),
            SettingsItem("Max Output Tokens", f"{max_tokens:,}", "Model response token ceiling from environment configuration"),
            SettingsItem("Rendering Mode", "native terminal (inline)", "Render overlays inside the current terminal transcript"),
            SettingsItem("Workspace Access", workspace_value, "Directories available as explicit workspace context"),
            SettingsItem("Log File", log_file, "Structured log destination"),
            SettingsItem("Config Source", ".env / environment", "Runtime configuration source loaded at startup"),
        ]

    def render_config(
        self,
        model: str,
        timeout: int,
        max_tokens: int,
        log_file: str,
        runtime: RuntimeState,
        *,
        transient: bool = False,
        status_right: str = "",
        prompt_frame: bool = False,
    ) -> SettingsSelection | None:
        """Render active runtime configuration as an AGY-like settings surface."""
        items = self._settings_items(model, timeout, max_tokens, log_file, runtime)
        if transient and sys.stdin.isatty() and sys.stdout.isatty():
            return self._render_settings_view(items, status_right=status_right, prompt_frame=prompt_frame)

        lines = build_settings_view_lines(
            items,
            width=self.console.size.width,
            height=min(28, max(12, self.console.size.height)),
        )
        self.console.print()
        for line in lines:
            stripped = line.strip()
            if stripped == "Settings":
                self.console.print(f"[{COLORS['text']}]{escape(line)}[/]")
            elif line.startswith("> "):
                self.console.print(f"[{COLORS['accent']}]{escape(line)}[/]")
            elif stripped.startswith("↑/↓") or stripped in {"Search:"} or line.startswith(" ─"):
                self.console.print(f"[{COLORS['text_muted']}]{escape(line)}[/]")
            else:
                self.console.print(f"[{COLORS['text']}]{escape(line)}[/]")
        self.console.print()
        return None

    def _render_settings_view(
        self,
        items: list[SettingsItem],
        *,
        status_right: str = "",
        prompt_frame: bool = False,
    ) -> SettingsSelection | None:
        """Open a transient inline settings view controlled with arrows."""
        from secops_agent.ui.theme import ansi, ANSI_RESET

        selected = 0
        search_query = ""
        editing_index: int | None = None
        edit_selected = 0
        selected_item: SettingsSelection | None = None
        c_accent = ansi("accent")
        c_text = ansi("text")
        c_muted = ansi("text_muted")
        c_dim = ansi("text_dim")
        reset = ANSI_RESET
        rendered_lines = 0

        def read_key() -> str:
            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            try:
                tty.setraw(fd)
                key = read_terminal_key(fd, escape_timeout=0.2)
                if key in {"up", "down", "esc", "enter"}:
                    return key
                if key == "mouse_up":
                    return "up"
                if key == "mouse_down":
                    return "down"
                return key
            finally:
                termios.tcsetattr(fd, termios.TCSANOW, old_settings)

        def statusline(left: str, right: str, width: int) -> str:
            if not right:
                return _fit_cell(left, width)
            right = _fit_cell(right, max(10, width - len(left) - 2))
            return f"{left}{' ' * max(1, width - len(left) - len(right) - 1)}{right}"

        def render() -> None:
            nonlocal rendered_lines, selected, edit_selected
            columns, rows = shutil.get_terminal_size((96, 28))
            content_height = _transient_content_height(rows, prompt_frame=prompt_frame)
            filtered_count = len(_filtered_settings_items(items, search_query))
            selected = min(max(0, selected), max(0, filtered_count - 1))
            filtered_items = _filtered_settings_items(items, search_query)
            if editing_index is not None and filtered_items:
                item = filtered_items[min(selected, filtered_count - 1)]
                option_count = max(1, len(item.options or (item.value,)))
                edit_selected = min(max(0, edit_selected), option_count - 1)
            lines = build_settings_view_lines(
                items,
                selected=selected,
                search_query=search_query,
                editing_index=editing_index,
                edit_selected=edit_selected,
                width=columns,
                height=content_height,
            )
            if prompt_frame and lines and lines[0] == "":
                lines = lines[1:]
            if prompt_frame:
                separator = _turn_separator(columns)
                lines = [separator, ">", separator, *lines]
            if lines and lines[-1] != "":
                lines.append("")
            lines.append(statusline("esc to cancel", status_right, columns))

            if rendered_lines:
                sys.stdout.write(f"\x1b[{rendered_lines}A\x1b[J")
            for line in lines:
                stripped = line.strip()
                if line.startswith("> "):
                    color = c_accent
                elif stripped == "Settings" or line == ">":
                    color = c_text
                elif line.startswith("─") or line.startswith(" ─"):
                    color = c_dim
                elif stripped.startswith(("Search:", "↑/↓", "esc to cancel")) or stripped.startswith(("↑ ", "↓ ")):
                    color = c_muted
                else:
                    color = c_text
                sys.stdout.write(f"{color}{line}{reset}\n")
            sys.stdout.flush()
            rendered_lines = len(lines)

        def clear_rendered() -> None:
            nonlocal rendered_lines
            if rendered_lines:
                sys.stdout.write(f"\x1b[{rendered_lines}A\x1b[J")
                rendered_lines = 0
            sys.stdout.write("\x1b[?25h")
            sys.stdout.flush()

        sys.stdout.write("\x1b[?25l")
        sys.stdout.flush()
        try:
            while True:
                render()
                key = read_key()
                filtered_items = _filtered_settings_items(items, search_query)
                filtered_count = len(filtered_items)
                if editing_index is not None:
                    active_item = filtered_items[min(selected, filtered_count - 1)] if filtered_items else None
                    option_count = max(1, len((active_item.options if active_item else ()) or ((active_item.value,) if active_item else ("",))))
                    if key == "up":
                        edit_selected = (edit_selected - 1) % option_count
                    elif key == "down":
                        edit_selected = (edit_selected + 1) % option_count
                    elif key == "enter" and active_item:
                        options = active_item.options or (active_item.value,)
                        selected_item = SettingsSelection(active_item, options[min(edit_selected, len(options) - 1)])
                        break
                    elif key == "esc":
                        editing_index = None
                        edit_selected = 0
                    continue

                if key == "up":
                    selected = (selected - 1) % max(1, filtered_count)
                elif key == "down":
                    selected = (selected + 1) % max(1, filtered_count)
                elif key in {"\x7f", "\b"}:
                    search_query = search_query[:-1]
                    selected = 0
                elif key == "esc" and search_query:
                    search_query = ""
                    selected = 0
                elif key == "enter":
                    if filtered_items:
                        active_item = filtered_items[min(selected, filtered_count - 1)]
                        if active_item.editable:
                            options = active_item.options or (active_item.value,)
                            current_index = options.index(active_item.value) if active_item.value in options else 0
                            editing_index = selected
                            edit_selected = current_index
                            continue
                        selected_item = SettingsSelection(active_item)
                    break
                elif key == "esc":
                    break
                elif len(key) == 1 and key.isprintable():
                    search_query += key
                    selected = 0
        finally:
            clear_rendered()
        return selected_item

    def render_permissions(
        self,
        tools_list: List[Any],
        permissions: Any | None = None,
        *,
        current_mode: str = "request-review",
    ):
        """Render the AGY-like active permission mode list."""
        from secops_agent.ui.permissions_menu import _permission_choices

        choices = _permission_choices(current_mode)
        selected = next((index for index, choice in enumerate(choices) if choice.current), 0)
        lines = build_choice_overlay_lines(
            "Active Permissions",
            choices,
            selected=selected,
            width=self.console.size.width,
            height=min(18, max(10, self.console.size.height)),
            footer="Keyboard: ↑/↓ Navigate  enter Select  esc Close",
            show_descriptions=True,
        )
        self.console.print()
        for line in lines:
            stripped = line.strip()
            if stripped == "Active Permissions":
                self.console.print(f"[{COLORS['text']}]{escape(line)}[/]")
            elif line.startswith("> "):
                self.console.print(f"[{COLORS['accent']}]{escape(line)}[/]")
            elif stripped.startswith("Keyboard:"):
                self.console.print(f"[{COLORS['text_muted']}]{escape(line)}[/]")
            else:
                self.console.print(f"[{COLORS['text']}]{escape(line)}[/]")
        self.console.print()

    def render_statusline(self, model: str, turn_count: int, estimated_tokens: int, tools_count: int, runtime: RuntimeState, permissions: Any | None = None):
        """Preview status line fields."""
        cwd = os.getcwd().replace(os.path.expanduser("~"), "~")
        summary = permissions.summary() if permissions else {"allow": [], "ask": [], "deny": []}
        rule_count = sum(len(rules) for rules in summary.values())
        permission_text = "perm default" if rule_count == 0 else f"perm {rule_count} rules"
        preview_fields = [
            friendly_model_name(model),
            cwd,
            f"turn {turn_count}",
            f"~{estimated_tokens:,} tokens",
            f"{tools_count} tools",
            f"{len(runtime.workspace_dirs)} dirs",
            f"{len(runtime.running_tasks())} tasks",
            "sandbox" if runtime.sandbox_enabled else "no sandbox",
            "fast" if runtime.fast_mode else "standard",
            permission_text,
            runtime.agent_state,
        ]
        rows = [
            OverlayRow("Prompt", " · ".join(preview_fields), accent=True),
            OverlayRow("Model", friendly_model_name(model)),
            OverlayRow("State", runtime.agent_state),
            OverlayRow("CWD", cwd),
            OverlayRow("Turn", str(turn_count)),
            OverlayRow("Tokens", f"~{estimated_tokens:,}"),
            OverlayRow("Tools", str(tools_count)),
            OverlayRow("Dirs", str(len(runtime.workspace_dirs))),
            OverlayRow("Tasks", str(len(runtime.running_tasks()))),
            OverlayRow("Mode", "fast" if runtime.fast_mode else "standard"),
            OverlayRow("Sandbox", "enabled" if runtime.sandbox_enabled else "disabled", accent=runtime.sandbox_enabled),
            OverlayRow("Permissions", permission_text),
        ]
        render_overlay(
            self.console,
            "Statusline",
            rows,
        )

    def render_sandbox(self, runtime: RuntimeState):
        """Render sandbox state and limitations."""
        status = "enabled" if runtime.sandbox_enabled else "disabled"
        render_overlay(
            self.console,
            "Sandbox",
            [
                OverlayRow("Status", status, accent=runtime.sandbox_enabled),
                OverlayRow("Scope", "command guard before subprocess execution"),
                OverlayRow("Blocks", "destructive executables, fork bombs, disk overwrite patterns, write redirection"),
            ],
            footer="This is not OS isolation. Use it as a safety gate.",
        )

    def render_diff(self):
        """Render a compact workspace diff summary with a bounded patch preview."""
        def _git(args: list[str], timeout: int = 5) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                ["git", *args],
                cwd=os.getcwd(),
                text=True,
                capture_output=True,
                timeout=timeout,
            )

        def _append_lines(rows: list[OverlayRow], label: str, text: str, limit: int) -> None:
            added = 0
            for raw_line in text.expandtabs(4).splitlines():
                line = raw_line.rstrip()
                if not line:
                    continue
                rows.append(OverlayRow(label, line[:180]))
                added += 1
                if added >= limit:
                    remaining = len([item for item in text.splitlines() if item.strip()]) - added
                    if remaining > 0:
                        rows.append(OverlayRow(label, f"{remaining} more line(s) hidden"))
                    return

        def _render_agy_diff_fallback(result: subprocess.CompletedProcess[str]) -> None:
            lines = [
                "Diff (git)  All Changes  Per Turn  Commit Tree",
                "",
                f"   ⚠ git: git diff: exit status {result.returncode}",
            ]
            output = (result.stderr or result.stdout or "").expandtabs(4).splitlines()
            lines.extend(line.rstrip() for line in output[:32])
            if len(output) > 32:
                lines.append(f"... {len(output) - 32} more line(s)")

            self.console.print()
            for line in lines:
                stripped = line.strip()
                if stripped.startswith("⚠"):
                    self.console.print(f"[{COLORS['warning']}]{escape(line)}[/]")
                elif stripped.startswith("Diff (git)"):
                    self.console.print(f"[{COLORS['text']}]{escape(line)}[/]")
                elif stripped:
                    self.console.print(f"[{COLORS['text_muted']}]{escape(line)}[/]")
                else:
                    self.console.print()
            self.console.print()

        try:
            inside = _git(["rev-parse", "--is-inside-work-tree"])
            if inside.returncode != 0:
                diff = _git(["diff", "--color=never"], timeout=5)
                _render_agy_diff_fallback(diff)
                return

            status = _git(["status", "--short"])
            if status.returncode != 0:
                self.render_error(status.stderr.strip() or "Unable to read git status.")
                return

            if not status.stdout.strip():
                render_overlay(self.console, "Diff", [], empty_message="No workspace changes.")
                return

            rows: list[OverlayRow] = []
            status_lines = [line for line in status.stdout.splitlines() if line.strip()]
            rows.append(OverlayRow("Summary", f"{len(status_lines)} changed path(s)", accent=True))
            _append_lines(rows, "Status", status.stdout, limit=12)

            staged_stat = _git(["diff", "--cached", "--stat", "--"])
            unstaged_stat = _git(["diff", "--stat", "--"])
            if staged_stat.stdout.strip():
                _append_lines(rows, "Staged", staged_stat.stdout, limit=6)
            if unstaged_stat.stdout.strip():
                _append_lines(rows, "Unstaged", unstaged_stat.stdout, limit=6)

            staged_diff = _git(["diff", "--cached", "--color=never", "--unified=3", "--"], timeout=8)
            unstaged_diff = _git(["diff", "--color=never", "--unified=3", "--"], timeout=8)
            preview = "\n".join(
                part for part in (staged_diff.stdout, unstaged_diff.stdout) if part.strip()
            )
            if preview.strip():
                _append_lines(rows, "Patch", preview, limit=18)

            render_overlay(
                self.console,
                "Diff",
                rows,
                footer="Shows status, stats, and a bounded patch preview for tracked files.",
            )
        except Exception as exc:
            self.render_error(f"Unable to read diff: {exc}")

    def render_tasks(self, runtime: RuntimeState, interactive: bool = True):
        """Render background task state."""
        self._render_orchestration(runtime, mode="tasks", interactive=interactive)

    def _render_tasks_static(self, runtime: RuntimeState):
        rows = []
        if not runtime.tasks:
            rows = []
        else:
            counts = {
                "running": len([task for task in runtime.tasks if task.status == "running"]),
                "done": len([task for task in runtime.tasks if task.status == "done"]),
                "failed": len([task for task in runtime.tasks if task.status == "failed"]),
                "cancelled": len([task for task in runtime.tasks if task.status == "cancelled"]),
            }
            summary = " · ".join(f"{count} {status}" for status, count in counts.items() if count)
            rows.append(OverlayRow("Summary", summary or f"{len(runtime.tasks)} tasks", accent=bool(counts["running"])))
            for task in runtime.tasks[-12:]:
                elapsed = format_duration(task.elapsed)
                detail_parts = [task.name, elapsed]
                if task.detail:
                    detail_parts.append(task.detail)
                rows.append(
                    OverlayRow(
                        task.id,
                        task.status,
                        " · ".join(detail_parts),
                        accent=task.status == "running",
                    )
                )
        render_overlay(
            self.console,
            "Tasks",
            rows,
            empty_message="No background tasks yet.",
        )

    def _render_orchestration(self, runtime: RuntimeState, mode: str, interactive: bool = True):
        panel_rows = self._orchestration_panel_rows(runtime, mode)
        has_subagents = any(row.value != "primary" for row in panel_rows)
        should_open_panel = interactive and panel_rows and sys.stdin.isatty()
        if mode == "agents":
            should_open_panel = should_open_panel and has_subagents

        if should_open_panel:
            title = "Tasks" if mode == "tasks" else "Agents"
            result = choose_panel(
                title,
                panel_rows,
                detail_provider=lambda row: self._orchestration_panel_detail(runtime, row),
                footer="Keyboard: ↑/↓ Navigate  enter Select  esc Go Back",
                empty_message="No background tasks yet." if mode == "tasks" else "No background subagents are active.",
            )
            self._handle_orchestration_result(runtime, result)
            return

        if mode == "agents":
            self._render_agents_static(runtime)
        else:
            self._render_tasks_static(runtime)

    def _orchestration_panel_rows(self, runtime: RuntimeState, mode: str) -> list[PanelRow]:
        rows: list[PanelRow] = []
        if mode == "agents":
            rows.append(
                PanelRow(
                    value="primary",
                    label="primary",
                    status=runtime.agent_state,
                    description="SecOps Agent · foreground session",
                    accent=True,
                )
            )
            tasks = runtime.running_tasks()
        else:
            tasks = runtime.tasks[-30:]

        for task in tasks:
            rows.append(self._task_panel_row(task))
        return rows

    def _task_panel_row(self, task: Any) -> PanelRow:
        elapsed = format_duration(task.elapsed)
        detail_parts = [task.name, elapsed]
        if task.detail:
            detail_parts.append(task.detail)
        return PanelRow(
            value=task.id,
            label=task.id,
            status=task.status,
            description=" · ".join(detail_parts),
            accent=task.status == "running",
        )

    def _orchestration_panel_detail(self, runtime: RuntimeState, row: PanelRow) -> list[str]:
        if row.value == "primary":
            return [
                "primary  foreground",
                "Name: SecOps Agent",
                f"State: {runtime.agent_state}",
                f"Background tasks: {len(runtime.running_tasks())}",
                f"Workspace dirs: {len(runtime.workspace_dirs)}",
                "",
                "Use the prompt for the main conversation.",
            ]

        task = runtime.get_task(row.value)
        if not task:
            return ["Task not found."]
        return self._task_panel_detail(task)

    def _handle_orchestration_result(self, runtime: RuntimeState, result: Any | None):
        if not result:
            return
        if result.value == "primary":
            self._render_primary_agent_detail(runtime)
            return

        task = runtime.get_task(result.value)
        if not task:
            self.render_error(f"Task not found: {result.value}")
            return
        if result.action == "logs":
            from secops_agent.ui.overlay import view_logs_overlay
            view_logs_overlay(f"Journaux de la tâche {task.id}", self._task_transcript_for_panel(task))
        else:
            self.render_task_detail(task)

    def _task_panel_detail(self, task: Any | None) -> list[str]:
        if not task:
            return ["Task not found."]

        lines = [
            f"{task.id}  {task.status}",
            f"Name: {task.name}",
            f"Elapsed: {format_duration(task.elapsed)}",
        ]
        if task.detail:
            lines.append(f"Detail: {task.detail}")
        log_path = spool_reference(getattr(task, "metadata", None))
        if log_path:
            lines.append(f"Log: {log_path}")
        if task.query:
            lines.extend(["", "Query:", task.query])
        if task.error:
            lines.extend(["", "Error:", task.error])

        content = task.output or "\n".join(task.log)
        if content:
            content = supervised_detail_text(getattr(task, "metadata", None), content)
        if content:
            lines.extend(["", "Output:"])
            visible = [line for line in content.splitlines() if line.strip()]
            lines.extend(visible[:10])
            if len(visible) > 10:
                lines.append(f"... {len(visible) - 10} more line(s)")
        else:
            lines.extend(["", "No output yet."])
        return lines

    def _task_transcript_for_panel(self, task: Any) -> str:
        sections = [
            f"Task: {task.id} {task.name}",
            f"Status: {task.status}",
            f"Elapsed: {format_duration(task.elapsed)}",
        ]
        if task.query:
            sections.extend(["", "Query:", task.query])
        if task.detail:
            sections.extend(["", "Detail:", task.detail])
        log_path = spool_reference(getattr(task, "metadata", None))
        if log_path:
            sections.extend(["", "Log file:", log_path])
        if task.error:
            sections.extend(["", "Error:", task.error])
        if task.output:
            sections.extend(["", "Output:", supervised_detail_text(getattr(task, "metadata", None), task.output)])
        if task.log:
            sections.extend(["", "Log:", *task.log])
        return "\n".join(sections)

    def render_agents(
        self,
        runtime: RuntimeState,
        interactive: bool = True,
        *,
        transient: bool = False,
        status_right: str = "",
    ):
        """Render active agent sessions."""
        if transient and sys.stdin.isatty() and sys.stdout.isatty():
            self._render_agents_view(runtime, status_right=status_right)
            return
        self._render_orchestration(runtime, mode="agents", interactive=interactive)

    def _render_agents_view(self, runtime: RuntimeState, *, status_right: str = "") -> None:
        from secops_agent.ui.theme import ansi, ANSI_RESET

        selected = 0
        expanded = False
        c_accent = ansi("accent")
        c_text = ansi("text")
        c_muted = ansi("text_muted")
        c_dim = ansi("text_dim")
        reset = ANSI_RESET
        rendered_lines = 0

        def entries() -> list[AgentViewEntry]:
            return _agent_view_entries(runtime)

        def read_key() -> str:
            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            try:
                tty.setraw(fd)
                key = read_terminal_key(fd, escape_timeout=0.2)
                if key in {"up", "down", "esc", "enter"}:
                    return key
                if key == "mouse_up":
                    return "up"
                if key == "mouse_down":
                    return "down"
                if len(key) == 1 and key.lower() == "k":
                    return "kill"
                return key
            finally:
                termios.tcsetattr(fd, termios.TCSANOW, old_settings)

        def statusline(left: str, right: str, width: int) -> str:
            if not right:
                return _fit_cell(left, width)
            right = _fit_cell(right, max(10, width - len(left) - 2))
            return f"{left}{' ' * max(1, width - len(left) - len(right) - 1)}{right}"

        def render() -> None:
            nonlocal rendered_lines
            columns, rows = shutil.get_terminal_size((96, 28))
            content_height = _transient_content_height(rows, prompt_frame=True)
            lines = build_agents_view_lines(
                runtime,
                selected=selected,
                expanded=expanded,
                width=columns,
                height=content_height,
            )
            if lines and lines[0] == "":
                lines = lines[1:]
            separator = _turn_separator(columns)
            lines = [separator, ">", separator, *lines]
            if lines and lines[-1] != "":
                lines.append("")
            lines.append(statusline("? for shortcuts", status_right, columns))

            if rendered_lines:
                sys.stdout.write(f"\x1b[{rendered_lines}A\x1b[J")
            for line in lines:
                stripped = line.strip()
                if line.startswith("> "):
                    color = c_accent
                elif stripped in {"Create New Agents", "Available Agents"} or line == ">":
                    color = c_text
                elif line.startswith("─"):
                    color = c_dim
                elif stripped.startswith(("Keyboard:", "No background", "No configured", "↑ ", "↓ ", "? for shortcuts")):
                    color = c_muted
                else:
                    color = c_text
                sys.stdout.write(f"{color}{line}{reset}\n")
            sys.stdout.flush()
            rendered_lines = len(lines)

        def clear_rendered() -> None:
            nonlocal rendered_lines
            if rendered_lines:
                sys.stdout.write(f"\x1b[{rendered_lines}A\x1b[J")
                rendered_lines = 0
            sys.stdout.write("\x1b[?25h")
            sys.stdout.flush()

        sys.stdout.write("\x1b[?25l")
        sys.stdout.flush()
        try:
            while True:
                item_count = 1 + (len(entries()) if expanded else 0)
                selected = min(max(0, selected), max(0, item_count - 1))
                render()
                key = read_key()
                if key == "up":
                    selected = (selected - 1) % max(1, item_count)
                elif key == "down":
                    selected = (selected + 1) % max(1, item_count)
                elif key == "enter" and selected == 0:
                    expanded = not expanded
                    selected = 0
                elif key == "kill" and expanded and selected > 0:
                    entry = entries()[selected - 1]
                    if entry.kind == "task":
                        task = runtime.cancel_task(entry.value)
                        if task and task.status == "running":
                            task.detail = "cancelling"
                elif key == "esc":
                    break
        finally:
            clear_rendered()

    def _render_agents_static(self, runtime: RuntimeState):
        lines = build_agents_view_lines(
            runtime,
            width=self.console.size.width,
            height=min(28, max(12, self.console.size.height)),
        )
        self.console.print()
        for line in lines:
            stripped = line.strip()
            if line.startswith("> "):
                self.console.print(f"[{COLORS['accent']}]{escape(line)}[/]")
            elif stripped.startswith(("Keyboard:", "No background", "No configured")):
                self.console.print(f"[{COLORS['text_muted']}]{escape(line)}[/]")
            else:
                self.console.print(f"[{COLORS['text']}]{escape(line)}[/]")
        self.console.print()

    def _agent_panel_rows(self, runtime: RuntimeState) -> list[PanelRow]:
        return self._orchestration_panel_rows(runtime, "agents")

    def _agent_panel_detail(self, runtime: RuntimeState, row: PanelRow) -> list[str]:
        return self._orchestration_panel_detail(runtime, row)

    def _render_primary_agent_detail(self, runtime: RuntimeState):
        render_overlay(
            self.console,
            "Agent",
            [
                OverlayRow("ID", "primary", accent=True),
                OverlayRow("Name", "SecOps Agent"),
                OverlayRow("State", runtime.agent_state),
                OverlayRow("Tasks", str(len(runtime.running_tasks()))),
                OverlayRow("Workspace dirs", str(len(runtime.workspace_dirs))),
            ],
            footer="The primary agent is the foreground conversation.",
        )

    def render_task_detail(self, task: Any):
        """Render a single background task detail view."""
        rows = [
            OverlayRow("ID", task.id, accent=True),
            OverlayRow("Name", task.name),
            OverlayRow("Status", task.status, accent=task.status == "running"),
            OverlayRow("Elapsed", format_duration(task.elapsed)),
        ]
        if task.detail:
            rows.append(OverlayRow("Detail", task.detail))
        log_path = spool_reference(getattr(task, "metadata", None))
        if log_path:
            rows.append(OverlayRow("Log", log_path))
        if task.query:
            rows.append(OverlayRow("Query", task.query[:160]))
        if task.error:
            rows.append(OverlayRow("Error", task.error[:180]))

        content = task.output or "\n".join(task.log)
        if content:
            content = supervised_detail_text(getattr(task, "metadata", None), content)
        if content:
            lines = [line for line in content.splitlines() if line.strip()]
            for line in lines[:8]:
                rows.append(OverlayRow("Output", line[:160]))
            if len(lines) > 8:
                rows.append(OverlayRow("Output", f"{len(lines) - 8} more lines available"))

        render_overlay(
            self.console,
            "Task",
            rows,
        )

    def render_workspace_dirs(self, paths: list[Path]):
        rows = [OverlayRow("Directory", str(path)) for path in paths]
        render_overlay(self.console, "Workspace", rows, empty_message="No extra workspace directories added.")

    def render_extensions(self, title: str, paths: list[Path], empty_message: str):
        found = [path for path in paths if path.exists()]
        rows = [
            OverlayRow("dir" if path.is_dir() else "file", str(path), accent=path.is_dir())
            for path in found
        ]
        render_overlay(self.console, title, rows, empty_message=empty_message)

    def render_skills(
        self,
        skills: list[Any],
        *,
        transient: bool = False,
        status_right: str = "",
        prompt_frame: bool = False,
    ):
        if transient and sys.stdin.isatty() and sys.stdout.isatty():
            self._render_skills_view(
                skills,
                status_right=status_right,
                prompt_frame=prompt_frame,
            )
            return

        lines = build_skills_view_lines(skills, width=self.console.size.width)
        self.console.print()
        for line in lines:
            stripped = line.strip()
            if stripped == "Skills":
                self.console.print(f"[{COLORS['text']}]{escape(line)}[/]")
            elif line.startswith("> "):
                self.console.print(f"[{COLORS['accent']}]{escape(line)}[/]")
            elif stripped.startswith(("No workspace", "Keyboard:", "↑ ", "↓ ")):
                self.console.print(f"[{COLORS['text_muted']}]{escape(line)}[/]")
            else:
                self.console.print(f"[{COLORS['text']}]{escape(line)}[/]")
        self.console.print()

    def _render_skills_view(
        self,
        skills: list[Any],
        *,
        status_right: str = "",
        prompt_frame: bool = False,
    ) -> None:
        from secops_agent.ui.theme import ansi, ANSI_RESET

        selected = 0
        c_accent = ansi("accent")
        c_text = ansi("text")
        c_muted = ansi("text_muted")
        c_dim = ansi("text_dim")
        reset = ANSI_RESET
        rendered_lines = 0

        def read_key() -> str:
            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            try:
                tty.setraw(fd)
                key = read_terminal_key(fd, escape_timeout=0.2)
                if key in {"up", "down", "esc", "enter"}:
                    return key
                if key == "mouse_up":
                    return "up"
                if key == "mouse_down":
                    return "down"
                return key
            finally:
                termios.tcsetattr(fd, termios.TCSANOW, old_settings)

        def statusline(left: str, right: str, width: int) -> str:
            if not right:
                return _fit_cell(left, width)
            right = _fit_cell(right, max(10, width - len(left) - 2))
            return f"{left}{' ' * max(1, width - len(left) - len(right) - 1)}{right}"

        def render() -> None:
            nonlocal rendered_lines
            columns, rows = shutil.get_terminal_size((96, 28))
            content_height = _transient_content_height(rows, prompt_frame=prompt_frame)
            lines = build_skills_view_lines(
                skills,
                selected=selected,
                width=columns,
                height=content_height,
            )
            if prompt_frame and lines and lines[0] == "":
                lines = lines[1:]
            if prompt_frame:
                separator = _turn_separator(columns)
                lines = [separator, ">", separator, *lines]
            if lines and lines[-1] != "":
                lines.append("")
            lines.append(statusline("esc to cancel", status_right, columns))

            if rendered_lines:
                sys.stdout.write(f"\x1b[{rendered_lines}A\x1b[J")
            for line in lines:
                stripped = line.strip()
                if line.startswith("> "):
                    color = c_accent
                elif stripped == "Skills" or line == ">":
                    color = c_text
                elif line.startswith("─"):
                    color = c_dim
                elif stripped.startswith(("No workspace", "Keyboard:", "↑ ", "↓ ", "esc to cancel")):
                    color = c_muted
                else:
                    color = c_text
                sys.stdout.write(f"{color}{line}{reset}\n")
            sys.stdout.flush()
            rendered_lines = len(lines)

        def clear_rendered() -> None:
            nonlocal rendered_lines
            if rendered_lines:
                sys.stdout.write(f"\x1b[{rendered_lines}A\x1b[J")
                rendered_lines = 0
            sys.stdout.write("\x1b[?25h")
            sys.stdout.flush()

        sys.stdout.write("\x1b[?25l")
        sys.stdout.flush()
        try:
            while True:
                render()
                item_count = len(_skill_view_items(skills))
                key = read_key()
                if key == "up":
                    selected = (selected - 1) % item_count
                elif key == "down":
                    selected = (selected + 1) % item_count
                elif key == "esc":
                    break
        finally:
            clear_rendered()

    def render_hooks(
        self,
        hook_manager: Any,
        *,
        transient: bool = False,
        status_right: str = "",
        prompt_frame: bool = False,
    ):
        if transient and sys.stdin.isatty() and sys.stdout.isatty():
            self._render_hooks_view(hook_manager, status_right=status_right, prompt_frame=prompt_frame)
            return

        lines = build_hooks_view_lines(hook_manager, width=self.console.size.width)
        self.console.print()
        for line in lines:
            stripped = line.strip()
            if stripped == "Hooks":
                self.console.print(f"[{COLORS['text']}]{escape(line)}[/]")
            elif line.startswith(" > "):
                self.console.print(f"[{COLORS['accent']}]{escape(line)}[/]")
            elif stripped.startswith(("No hooks", "Configured:", "Config errors:", "Last run:", "↑/↓")):
                self.console.print(f"[{COLORS['text_muted']}]{escape(line)}[/]")
            else:
                self.console.print(f"[{COLORS['text']}]{escape(line)}[/]")
        self.console.print()

    def _render_hooks_view(
        self,
        hook_manager: Any,
        *,
        status_right: str = "",
        prompt_frame: bool = False,
    ) -> None:
        from secops_agent.ui.theme import ansi, ANSI_RESET

        selected = 0
        c_accent = ansi("accent")
        c_text = ansi("text")
        c_muted = ansi("text_muted")
        c_dim = ansi("text_dim")
        reset = ANSI_RESET
        rendered_lines = 0

        def read_key() -> str:
            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            try:
                tty.setraw(fd)
                key = read_terminal_key(fd, escape_timeout=0.2)
                if key in {"up", "down", "esc", "enter"}:
                    return key
                if key == "mouse_up":
                    return "up"
                if key == "mouse_down":
                    return "down"
                return key
            finally:
                termios.tcsetattr(fd, termios.TCSANOW, old_settings)

        def statusline(left: str, right: str, width: int) -> str:
            if not right:
                return _fit_cell(left, width)
            right = _fit_cell(right, max(10, width - len(left) - 2))
            return f"{left}{' ' * max(1, width - len(left) - len(right) - 1)}{right}"

        def render() -> None:
            nonlocal rendered_lines
            columns, _ = shutil.get_terminal_size((96, 28))
            lines = build_hooks_view_lines(hook_manager, selected=selected, width=columns)
            if prompt_frame and lines and lines[0] == "":
                lines = lines[1:]
            if prompt_frame:
                separator = _turn_separator(columns)
                lines = [separator, ">", separator, *lines]
            if lines and lines[-1] != "":
                lines.append("")
            lines.append(statusline("esc to cancel", status_right, columns))

            if rendered_lines:
                sys.stdout.write(f"\x1b[{rendered_lines}A\x1b[J")
            for line in lines:
                stripped = line.strip()
                if line.startswith(" > "):
                    color = c_accent
                elif stripped == "Hooks" or line == ">":
                    color = c_text
                elif line.startswith("─"):
                    color = c_dim
                elif stripped.startswith(("No hooks", "Configured:", "Config errors:", "Last run:", "↑/↓", "esc to cancel")):
                    color = c_muted
                else:
                    color = c_text
                sys.stdout.write(f"{color}{line}{reset}\n")
            sys.stdout.flush()
            rendered_lines = len(lines)

        def clear_rendered() -> None:
            nonlocal rendered_lines
            if rendered_lines:
                sys.stdout.write(f"\x1b[{rendered_lines}A\x1b[J")
                rendered_lines = 0
            sys.stdout.write("\x1b[?25h")
            sys.stdout.flush()

        sys.stdout.write("\x1b[?25l")
        sys.stdout.flush()
        try:
            while True:
                render()
                key = read_key()
                if key == "up":
                    selected = (selected - 1) % len(HOOK_EVENT_ROWS)
                elif key == "down":
                    selected = (selected + 1) % len(HOOK_EVENT_ROWS)
                elif key == "esc":
                    break
        finally:
            clear_rendered()

    def render_mcp(
        self,
        mcp_state: Any,
        mcp_runtime: Any | None = None,
        *,
        transient: bool = False,
        status_right: str = "",
        prompt_frame: bool = False,
    ):
        if transient and sys.stdin.isatty() and sys.stdout.isatty():
            self._render_mcp_view(
                mcp_state,
                mcp_runtime,
                status_right=status_right,
                prompt_frame=prompt_frame,
            )
            return

        lines = build_mcp_view_lines(mcp_state, mcp_runtime, width=self.console.size.width)
        self.console.print()
        for line in lines:
            stripped = line.strip()
            if stripped == "MCP Servers":
                self.console.print(f"[{COLORS['text']}]{escape(line)}[/]")
            elif line.startswith("> "):
                self.console.print(f"[{COLORS['accent']}]{escape(line)}[/]")
            elif stripped.startswith(("No MCP", "Keyboard:", "Config error", "Runtime error", "↑ ", "↓ ")):
                self.console.print(f"[{COLORS['text_muted']}]{escape(line)}[/]")
            else:
                self.console.print(f"[{COLORS['text']}]{escape(line)}[/]")
        self.console.print()

    def _render_mcp_view(
        self,
        mcp_state: Any,
        mcp_runtime: Any | None = None,
        *,
        status_right: str = "",
        prompt_frame: bool = False,
    ) -> None:
        from secops_agent.ui.theme import ansi, ANSI_RESET

        selected = 0
        c_accent = ansi("accent")
        c_text = ansi("text")
        c_muted = ansi("text_muted")
        c_dim = ansi("text_dim")
        reset = ANSI_RESET
        rendered_lines = 0

        def read_key() -> str:
            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            try:
                tty.setraw(fd)
                key = read_terminal_key(fd, escape_timeout=0.2)
                if key in {"up", "down", "esc", "enter"}:
                    return key
                if key == "mouse_up":
                    return "up"
                if key == "mouse_down":
                    return "down"
                return key
            finally:
                termios.tcsetattr(fd, termios.TCSANOW, old_settings)

        def statusline(left: str, right: str, width: int) -> str:
            if not right:
                return _fit_cell(left, width)
            right = _fit_cell(right, max(10, width - len(left) - 2))
            return f"{left}{' ' * max(1, width - len(left) - len(right) - 1)}{right}"

        def render() -> None:
            nonlocal rendered_lines
            columns, rows = shutil.get_terminal_size((96, 28))
            content_height = _transient_content_height(rows, prompt_frame=prompt_frame)
            lines = build_mcp_view_lines(
                mcp_state,
                mcp_runtime,
                selected=selected,
                width=columns,
                height=content_height,
            )
            if prompt_frame and lines and lines[0] == "":
                lines = lines[1:]
            if prompt_frame:
                separator = _turn_separator(columns)
                lines = [separator, ">", separator, *lines]
            if lines and lines[-1] != "":
                lines.append("")
            lines.append(statusline("esc to cancel", status_right, columns))

            if rendered_lines:
                sys.stdout.write(f"\x1b[{rendered_lines}A\x1b[J")
            for line in lines:
                stripped = line.strip()
                if line.startswith("> "):
                    color = c_accent
                elif stripped == "MCP Servers" or line == ">":
                    color = c_text
                elif line.startswith("─"):
                    color = c_dim
                elif stripped.startswith(("No MCP", "Keyboard:", "Config error", "Runtime error", "↑ ", "↓ ", "esc to cancel")):
                    color = c_muted
                else:
                    color = c_text
                sys.stdout.write(f"{color}{line}{reset}\n")
            sys.stdout.flush()
            rendered_lines = len(lines)

        def clear_rendered() -> None:
            nonlocal rendered_lines
            if rendered_lines:
                sys.stdout.write(f"\x1b[{rendered_lines}A\x1b[J")
                rendered_lines = 0
            sys.stdout.write("\x1b[?25h")
            sys.stdout.flush()

        sys.stdout.write("\x1b[?25l")
        sys.stdout.flush()
        try:
            while True:
                render()
                item_count = len(_mcp_view_items(mcp_state, mcp_runtime))
                key = read_key()
                if key == "up":
                    selected = (selected - 1) % item_count
                elif key == "down":
                    selected = (selected + 1) % item_count
                elif key == "esc":
                    break
        finally:
            clear_rendered()

    def render_planned_command(self, command: str, description: str):
        """Render a useful response for known commands not implemented yet."""
        render_overlay(
            self.console,
            command,
            [OverlayRow("Status", "planned"), OverlayRow("Description", description)],
            footer="This command is planned but not implemented in SecOps_v2 yet.",
        )

    def render_tool_detail(self, tool_def: Any):
        """Show a registered SecOps tool as an executable slash-discovery target."""
        category = getattr(getattr(tool_def, "category", ""), "value", str(getattr(tool_def, "category", "")))
        parameters = getattr(tool_def, "parameters", {}) or {}
        rows = [
            OverlayRow("Name", getattr(tool_def, "name", "-"), accent=True),
            OverlayRow("Category", category or "-"),
            OverlayRow("Risk", "dangerous" if getattr(tool_def, "dangerous", False) else "standard"),
            OverlayRow("Description", getattr(tool_def, "description", "") or "-"),
        ]
        if parameters:
            for name, spec in parameters.items():
                if isinstance(spec, dict):
                    required = "required" if spec.get("required") else "optional"
                    default = spec.get("default")
                    detail = f"{spec.get('type', 'value')} · {required}"
                    if default is not None:
                        detail = f"{detail} · default {default}"
                else:
                    detail = str(spec)
                rows.append(OverlayRow(str(name), detail))
        render_overlay(
            self.console,
            "Tool",
            rows,
            footer="The agent invokes tools from natural-language requests.",
        )

    def render_tools(
        self,
        tools_list: List[Any],
        *,
        transient: bool = False,
        status_right: str = "",
        prompt_frame: bool = False,
    ):
        """List tools in an Antigravity-style tabbed browser."""
        if transient and sys.stdin.isatty() and sys.stdout.isatty():
            self._render_tools_tabs(
                tools_list,
                status_right=status_right,
                prompt_frame=prompt_frame,
            )
            return

        lines = build_tools_view_lines(
            tools_list,
            width=self.console.size.width,
            height=min(28, max(12, self.console.size.height)),
            framed=True,
        )
        self.console.print()
        for line in lines:
            stripped = line.strip()
            if line.startswith("─"):
                self.console.print(f"[{COLORS['text_dim']}]{line}[/]")
            elif stripped == "Tools" or stripped.startswith("SecOps Tools"):
                self.console.print(f"[{COLORS['accent']} bold]{escape(line)}[/]")
            elif line.startswith("> "):
                self.console.print(f"[{COLORS['accent_bright']} bold]{escape(line)}[/]")
            elif stripped.startswith("Keyboard:"):
                self.console.print(f"[{COLORS['text_muted']}]{escape(line)}[/]")
            else:
                self.console.print(f"[{COLORS['text_muted']}]{escape(line)}[/]")
        self.console.print()

    def _render_tools_tabs(
        self,
        tools_list: List[Any],
        *,
        selected: int = 0,
        status_right: str = "",
        prompt_frame: bool = False,
    ) -> None:
        """Open a transient inline tabbed tools view controlled with arrows or tab."""
        import shutil
        import termios
        import tty
        from secops_agent.ui.theme import ansi, ANSI_RESET

        active_view = _tools_view_index(tools_list, selected)
        selected_tool = 0
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
                key = read_terminal_key(fd, escape_timeout=0.2)
                if key == "mouse_up":
                    return "up"
                if key == "mouse_down":
                    return "down"
                if key == "tab":
                    return "right"
                if key in {"left", "right", "up", "down", "pgup", "pgdn", "home", "end", "esc"}:
                    return key
                return key
            finally:
                termios.tcsetattr(fd, termios.TCSANOW, old_settings)

        rendered_lines = 0

        def statusline(left: str, right: str, width: int) -> str:
            if not right:
                return _fit_cell(left, width)
            right = _fit_cell(right, max(10, width - len(left) - 2))
            return f"{left}{' ' * max(1, width - len(left) - len(right) - 1)}{right}"

        def write_tab_line(line: str) -> None:
            tabs = _tools_tabs(tools_list)
            active = tabs[active_view] if tabs else "all"
            start = line.find(active, len("SecOps Tools"))
            if start < 0:
                sys.stdout.write(f"{c_accent}{line}{reset}\n")
                return
            end = start + len(active)
            sys.stdout.write(
                f"{c_text}{line[:start]}{reset}"
                f"{c_accent}{line[start:end]}{reset}"
                f"{c_muted}{line[end:]}{reset}\n"
            )

        def render() -> None:
            nonlocal rendered_lines
            columns, rows = shutil.get_terminal_size((96, 28))
            content_height = _transient_content_height(rows, prompt_frame=prompt_frame)
            lines = build_tools_view_lines(
                tools_list,
                active_view=active_view,
                selected_tool=selected_tool,
                width=columns,
                height=content_height,
                framed=False,
                fill=False,
            )
            if prompt_frame:
                separator = _turn_separator(columns)
                lines = [separator, ">", separator, *lines]
            if lines and lines[-1] != "":
                lines.append("")
            lines.append(statusline("esc to cancel", status_right, columns))

            if rendered_lines:
                sys.stdout.write(f"\x1b[{rendered_lines}A\x1b[J")
            for line in lines:
                stripped = line.strip()
                if stripped.startswith("SecOps Tools"):
                    write_tab_line(line)
                    continue
                if line.startswith("─"):
                    color = c_dim
                elif line == ">" or stripped == "Tools":
                    color = c_accent
                elif line.startswith("> "):
                    color = c_accent
                elif stripped.startswith("Keyboard:") or stripped.startswith("esc to cancel"):
                    color = c_muted
                else:
                    color = c_muted
                sys.stdout.write(f"{color}{line}{reset}\n")
            sys.stdout.flush()
            rendered_lines = len(lines)

        def clear_rendered() -> None:
            nonlocal rendered_lines
            if rendered_lines:
                sys.stdout.write(f"\x1b[{rendered_lines}A\x1b[J")
                rendered_lines = 0
            sys.stdout.write("\x1b[?25h")
            sys.stdout.flush()

        sys.stdout.write("\x1b[?25l")
        sys.stdout.flush()
        try:
            while True:
                render()
                key = read_key()
                if key == "left":
                    active_view = (active_view - 1) % len(_tools_tabs(tools_list))
                    selected_tool = 0
                elif key == "right":
                    active_view = (active_view + 1) % len(_tools_tabs(tools_list))
                    selected_tool = 0
                elif key == "up":
                    rows = _tools_for_view(tools_list, active_view)
                    if rows:
                        selected_tool = (selected_tool - 1) % len(rows)
                elif key == "down":
                    rows = _tools_for_view(tools_list, active_view)
                    if rows:
                        selected_tool = (selected_tool + 1) % len(rows)
                elif key == "pgup":
                    rows = _tools_for_view(tools_list, active_view)
                    if rows:
                        terminal_rows = shutil.get_terminal_size((96, 28)).lines
                        page = max(3, _transient_content_height(terminal_rows, prompt_frame=prompt_frame) - 8)
                        selected_tool = max(0, selected_tool - page)
                elif key == "pgdn":
                    rows = _tools_for_view(tools_list, active_view)
                    if rows:
                        terminal_rows = shutil.get_terminal_size((96, 28)).lines
                        page = max(3, _transient_content_height(terminal_rows, prompt_frame=prompt_frame) - 8)
                        selected_tool = min(len(rows) - 1, selected_tool + page)
                elif key == "home":
                    selected_tool = 0
                elif key == "end":
                    rows = _tools_for_view(tools_list, active_view)
                    if rows:
                        selected_tool = len(rows) - 1
                elif key == "esc":
                    break
        finally:
            clear_rendered()

    def render_error(self, message: str, tool_name: str = ""):
        """Render a structured error with auto-classification and suggestions."""
        ErrorRenderer.render(
            self.console,
            message=message,
            tool_name=tool_name,
        )

    def render_agent_error(self, message: str):
        """Render a model/server error as an Antigravity-style warning line.

        For API/quota errors, also shows a compact retry hint (❌ proposition
        from spec §5.2, independent of agy — good UX practice).
        """
        compact = _compact_agent_error(message)
        self.console.print(f"[{COLORS['error']} bold]⚠ {escape(compact)}[/]")
        # ❌ §5.2: show retry hint for transient API errors
        lowered = str(message or "").casefold()
        is_transient = any(k in lowered for k in (
            "resource_exhausted", "429", "unavailable", "capacity",
            "overloaded", "timeout", "timed out", "deadline",
        ))
        if is_transient and self._display_prefs.get("auto_retry_api", True):
            self.console.print(
                f"  [{COLORS['text_muted']}]Retry the same prompt, or /model to switch models.[/{COLORS['text_muted']}]"
            )
        self.console.print()

    def render_warning(self, message: str):
        """Render a compact command warning."""
        self.console.print(f"  [{COLORS['warning']}]⎿  {message}[/{COLORS['warning']}]")
        self.console.print()

    def render_status(self, message: str):
        self.console.print(f"  [{COLORS['text_muted']}]⎿  {message}[/{COLORS['text_muted']}]")
        self.console.print()

    def render_success(self, message: str):
        self.console.print(f"  [{COLORS['success']}]⎿  {message}[/{COLORS['success']}]")
        self.console.print()

    def render_command_result(self, message: str):
        self.console.print(f"  [{COLORS['text_muted']}]⎿  {message}[/{COLORS['text_muted']}]")
        self.console.print()

    def render_session_transcript(self, memory: Any, *, max_messages: int | None = None) -> None:
        """Replay a loaded session in the visible terminal transcript."""
        if hasattr(memory, "get_all_messages"):
            messages = list(memory.get_all_messages())
        else:
            messages = list(getattr(memory, "messages", []) or [])
        if max_messages is not None:
            messages = messages[-max(0, int(max_messages)):]

        if not messages:
            self.render_status("Session has no visible transcript.")
            return

        pending_tool_calls: list[dict[str, Any]] = []

        def display_user_content(content: str) -> str:
            marker = "\n\n[SecOps attached evidence]\n"
            return str(content or "").split(marker, 1)[0]

        def display_tool_content(content: str) -> str:
            text = str(content or "")
            match = re.match(r"^── TOOL DATA \[[^\]]+\] ──\n(?P<body>.*)\n── END TOOL DATA ──$", text, flags=re.S)
            return match.group("body") if match else text

        def pop_tool_call(name: str) -> dict[str, Any]:
            for index, call in enumerate(pending_tool_calls):
                if str(call.get("name", "")) == name:
                    return pending_tool_calls.pop(index)
            return {"name": name, "arguments": {}}

        def replay_tool_result(name: str, content: str) -> None:
            call = pop_tool_call(name)
            output = display_tool_content(content)
            failed = _looks_like_tool_failure(output)
            result = ToolResult(
                success=not failed,
                output="" if failed else output,
                error=output if failed else None,
                execution_time=0.0,
            )
            ToolCallBox.render(
                self.console,
                str(call.get("name") or name),
                dict(call.get("arguments") or {}),
                status="failed" if failed else "done",
                leading_blank=False,
            )
            ToolResultBox.render(self.console, name, result)

        for msg in messages:
            role = str(getattr(msg, "role", "") or "")
            if role == "user":
                self.render_user_input(display_user_content(getattr(msg, "content", "")), trailing_blank=False)
            elif role == "model":
                content = str(getattr(msg, "content", "") or "").strip()
                if content:
                    self.console.print(
                        Padding(
                            Markdown(normalize_agent_markdown(content), code_theme="ansi_dark"),
                            (0, 0, 0, 2),
                        )
                    )
                    self.console.print()
                for call in getattr(msg, "tool_calls", []) or []:
                    if isinstance(call, dict):
                        pending_tool_calls.append(dict(call))
            elif role == "tool":
                for stored_result in getattr(msg, "tool_results", []) or []:
                    if not isinstance(stored_result, dict):
                        continue
                    name = str(stored_result.get("name") or "tool")
                    replay_tool_result(name, str(stored_result.get("content") or ""))

        for call in pending_tool_calls:
            ToolCallBox.render(
                self.console,
                str(call.get("name") or "tool"),
                dict(call.get("arguments") or {}),
                status="warning",
                leading_blank=False,
            )
        self.console.print()

    def render_context(
        self,
        model: str,
        total_messages: int,
        user_messages: int,
        assistant_messages: int,
        tool_messages: int,
        estimated_tokens: int,
        tools_count: int,
        *,
        transient: bool = False,
        status_right: str = "",
        prompt_frame: bool = False,
    ):
        if transient and sys.stdin.isatty() and sys.stdout.isatty():
            self._render_context_usage_view(
                model,
                total_messages=total_messages,
                user_messages=user_messages,
                assistant_messages=assistant_messages,
                tool_messages=tool_messages,
                estimated_tokens=estimated_tokens,
                tools_count=tools_count,
                status_right=status_right,
                prompt_frame=prompt_frame,
            )
            return

        lines = build_context_usage_lines(
            model,
            total_messages=total_messages,
            user_messages=user_messages,
            assistant_messages=assistant_messages,
            tool_messages=tool_messages,
            estimated_tokens=estimated_tokens,
            tools_count=tools_count,
            width=self.console.size.width,
        )
        self.console.print()
        for line in lines:
            if line.strip().startswith("└ Context Usage"):
                self.console.print(f"[{COLORS['text']}]{escape(line)}[/]")
            elif "■" in line:
                self.console.print(f"[{COLORS['accent']}]{escape(line)}[/]")
            elif line.strip().startswith("Related:"):
                self.console.print(f"[{COLORS['text_muted']}]{escape(line)}[/]")
            else:
                self.console.print(f"[{COLORS['text']}]{escape(line)}[/]")
        self.console.print()

    def _render_context_usage_view(
        self,
        model: str,
        *,
        total_messages: int,
        user_messages: int,
        assistant_messages: int,
        tool_messages: int,
        estimated_tokens: int,
        tools_count: int,
        status_right: str = "",
        prompt_frame: bool = False,
    ) -> None:
        from secops_agent.ui.theme import ansi, ANSI_RESET

        c_text = ansi("text")
        c_muted = ansi("text_muted")
        c_accent = ansi("accent")
        reset = ANSI_RESET
        rendered_lines = 0

        def read_key() -> str:
            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            try:
                tty.setraw(fd)
                key = read_terminal_key(fd, escape_timeout=0.2)
                if key == "esc":
                    return key
                return key
            finally:
                termios.tcsetattr(fd, termios.TCSANOW, old_settings)

        def statusline(left: str, right: str, width: int) -> str:
            if not right:
                return _fit_cell(left, width)
            right = _fit_cell(right, max(10, width - len(left) - 2))
            return f"{left}{' ' * max(1, width - len(left) - len(right) - 1)}{right}"

        def render() -> None:
            nonlocal rendered_lines
            columns, _ = shutil.get_terminal_size((96, 28))
            lines = build_context_usage_lines(
                model,
                total_messages=total_messages,
                user_messages=user_messages,
                assistant_messages=assistant_messages,
                tool_messages=tool_messages,
                estimated_tokens=estimated_tokens,
                tools_count=tools_count,
                width=columns,
            )
            if prompt_frame and lines and lines[0] == "":
                lines = lines[1:]
            if prompt_frame:
                separator = _turn_separator(columns)
                lines = [separator, ">", separator, *lines]
            if lines and lines[-1] != "":
                lines.append("")
            lines.append(statusline("esc to cancel", status_right, columns))

            if rendered_lines:
                sys.stdout.write(f"\x1b[{rendered_lines}A\x1b[J")
            for line in lines:
                stripped = line.strip()
                if "■" in line:
                    color = c_accent
                elif stripped.startswith(("Related:", "esc to cancel")):
                    color = c_muted
                else:
                    color = c_text
                sys.stdout.write(f"{color}{line}{reset}\n")
            sys.stdout.flush()
            rendered_lines = len(lines)

        def clear_rendered() -> None:
            nonlocal rendered_lines
            if rendered_lines:
                sys.stdout.write(f"\x1b[{rendered_lines}A\x1b[J")
                rendered_lines = 0
            sys.stdout.write("\x1b[?25h")
            sys.stdout.flush()

        sys.stdout.write("\x1b[?25l")
        sys.stdout.flush()
        try:
            render()
            while True:
                if read_key() == "esc":
                    break
        finally:
            clear_rendered()

    def render_sessions_list(self, sessions: List[str]):
        rows = [OverlayRow("Session", s.replace(".json", "")) for s in sessions]
        render_overlay(self.console, "Sessions", rows, empty_message="No saved sessions.")

    def render_token_usage(self, input_tokens: int, output_tokens: int):
        total = input_tokens + output_tokens
        self.console.print(
            f"[{COLORS['text_dim']}]"
            f"tokens: {input_tokens:,} in / {output_tokens:,} out ({total:,} total)"
            f"[/{COLORS['text_dim']}]"
        )

    def _print_wrapped_muted_lines(self, text: str, *, indent: str = "  ", max_lines: int = 40) -> None:
        width = max(24, _surface_width(self.console) - len(indent) - 2)
        lines = [line.rstrip() for line in str(text).splitlines() if line.strip()]
        if not lines:
            lines = ["(no output)"]
        for line in lines[:max_lines]:
            while len(line) > width:
                self.console.print(f"{indent}[{COLORS['text_muted']}]{escape(line[:width])}[/{COLORS['text_muted']}]")
                line = line[width:]
            self.console.print(f"{indent}[{COLORS['text_muted']}]{escape(line)}[/{COLORS['text_muted']}]")
        if len(lines) > max_lines:
            self.console.print(f"{indent}[{COLORS['text_dim']}]... {len(lines) - max_lines:,} more lines hidden[/{COLORS['text_dim']}]")

    def _render_inline_tool_expansion(self) -> bool:
        if not self._latest_tool_name:
            return False

        call_text = format_tool_call_text(self._latest_tool_name, self._latest_tool_arguments)
        result = self._latest_tool_result
        indicator_color = _tool_status_color(status=_tool_result_status(result))
        self.console.print()
        collapse_hint = (
            f" [{COLORS['text_muted']}](ctrl+o to collapse)[/{COLORS['text_muted']}]"
            if result is None else ""
        )
        self.console.print(
            f"[{indicator_color}]●[/{indicator_color}] "
            f"[{COLORS['text']}]{escape(call_text)}[/{COLORS['text']}]{collapse_hint}",
            no_wrap=True,
            overflow="ellipsis",
        )

        rendered_lines = 2
        if result is None:
            self._latest_transcript_expanded = True
            self._latest_transcript_rendered_lines = rendered_lines
            return True

        output = str(getattr(result, "output", "") or getattr(result, "error", "") or "(no output)")
        output = supervised_detail_text(getattr(result, "metadata", None), output)
        lines = [line.rstrip() for line in output.splitlines() if line.strip()] or ["(no output)"]
        first_line = _fit_cell(lines[0], max(16, _surface_width(self.console) - 34))
        self.console.print(
            f"  [{COLORS['text_muted']}]⎿  {escape(first_line)} "
            f"(ctrl+o to collapse)[/{COLORS['text_muted']}]",
            no_wrap=True,
            overflow="ellipsis",
        )
        rendered_lines += 1
        if len(lines) > 1:
            self.console.print()
            self.console.print(f"  [{COLORS['text_muted']}]Output:[/{COLORS['text_muted']}]")
            rendered_lines += 2
            visible_limit = _ctrl_o_output_visible_limit(self.console)
            visible_lines = lines[:visible_limit]
            output_width = max(16, _surface_width(self.console) - 6)
            for line in visible_lines:
                self.console.print(
                    f"    [{COLORS['text_dim']}]{escape(_fit_cell(line, output_width))}[/{COLORS['text_dim']}]",
                    no_wrap=True,
                    overflow="ellipsis",
                )
            rendered_lines += len(visible_lines)
            if len(lines) > len(visible_lines):
                self.console.print(
                    f"    [{COLORS['text_dim']}]... {len(lines) - len(visible_lines):,} more lines hidden[/{COLORS['text_dim']}]",
                    no_wrap=True,
                    overflow="ellipsis",
                )
                rendered_lines += 1
        self._latest_transcript_expanded = True
        self._latest_transcript_rendered_lines = rendered_lines
        return True

    def _render_inline_thought_expansion(self) -> bool:
        if not self._latest_thought_content:
            return False
        duration = self._latest_thought_duration if self._latest_thought_duration is not None else "?"
        self.console.print()
        self.console.print(
            f"[{COLORS['accent']}]▾[/{COLORS['accent']}] "
            f"[{COLORS['text_muted']}]Thought for {duration}s[/{COLORS['text_muted']}]"
        )
        self._print_wrapped_muted_lines(self._latest_thought_content, indent="  ")
        self._latest_transcript_expanded = True
        return True

    def _render_latest_transcript_expansion(self) -> bool:
        if self._render_inline_tool_expansion():
            return True
        return self._render_inline_thought_expansion()

    def _render_inline_tool_collapse(self) -> bool:
        if not self._latest_tool_name:
            return False
        rendered_lines = self._latest_transcript_rendered_lines
        cleared = self._clear_terminal_lines(rendered_lines)
        if cleared:
            self._latest_transcript_rendered_lines = 0
            self._latest_transcript_expanded = False
            return True
        if bool(getattr(self.console, "is_terminal", False)) and rendered_lines > 0:
            return True
        self._latest_transcript_rendered_lines = 0
        self._latest_transcript_expanded = False
        if not cleared:
            status = _tool_result_status(self._latest_tool_result)
            ToolCallBox.render(self.console, self._latest_tool_name, self._latest_tool_arguments, status=status)
        return True

    def _render_inline_thought_collapse(self) -> bool:
        if not self._latest_thought_content:
            return False
        duration = self._latest_thought_duration if self._latest_thought_duration is not None else "?"
        self.console.print()
        self.console.print(
            f"[{COLORS['accent']}]▸[/{COLORS['accent']}] "
            f"[{COLORS['text_muted']}]Thought for {duration}s[/{COLORS['text_muted']}]"
        )
        preview = self._latest_thought_content.strip().replace("\n", " ")
        if len(preview) > 120:
            preview = preview[:117] + "..."
        if preview:
            self.console.print(f"  [{COLORS['text_dim']}]{escape(preview)}[/{COLORS['text_dim']}]")
        self._latest_transcript_expanded = False
        return True

    def _render_latest_transcript_collapse(self) -> bool:
        if self._render_inline_tool_collapse():
            return True
        return self._render_inline_thought_collapse()

    def _toggle_latest_transcript(self) -> bool:
        if self._latest_transcript_expanded:
            if self._render_latest_transcript_collapse():
                return True
            self._latest_transcript_expanded = False
        return self._render_latest_transcript_expansion()

    # ── Thinking Display ──────────────────────────────────────────────

    def _start_thinking(self, status_right: str = ""):
        """Record thinking start time."""
        self._thinking_start = time.monotonic()
        self._thinking_content = ""
        self._thinking_spinner = ThinkingSpinner(
            "Generating...",
            console=self.console,
            status_right=status_right,
        )
        self._thinking_spinner.start()

    def _finish_thinking(self):
        """Render '▸ Thought for Xs' with optional content preview."""
        if self._thinking_start is None:
            return
        if self._thinking_spinner:
            self._thinking_spinner.stop()
            self._thinking_spinner = None

        elapsed = time.monotonic() - self._thinking_start
        duration = int(elapsed) if elapsed >= 1 else round(elapsed, 1)
        self._latest_thought_duration = duration
        self._latest_thought_content = self._thinking_content.strip()
        self._latest_transcript_expanded = False

        # §5.7: respect show_thought preference
        if not self._display_prefs.get("show_thought", True):
            self._thinking_start = None
            self._thinking_content = ""
            return

        self.console.print()

        # agy format: "▸ Thought for Xs" with a brief content preview.
        # (Real Antigravity transcripts render e.g. "▸ Thought for 2s … <summary>".)
        self.console.print(
            f"[{COLORS['accent']}]▸[/{COLORS['accent']}] "
            f"[{COLORS['text_muted']}]Thought for {duration}s[/{COLORS['text_muted']}]"
        )
        if self._latest_thought_content:
            self._print_wrapped_muted_lines(self._latest_thought_content, indent="  ")

        self._thinking_start = None
        self._thinking_content = ""

    def _cancel_thinking(self):
        if self._thinking_spinner:
            self._thinking_spinner.stop()
            self._thinking_spinner = None
        self._thinking_start = None
        self._thinking_content = ""

    def _start_tool_feedback(self, tool_name: str, status_right: str = ""):
        """Show live feedback while a tool is actually executing."""
        self._stop_tool_feedback()
        self._tool_start = time.monotonic()
        self._current_tool_name = tool_name
        self._tool_spinner = ToolExecutionSpinner(tool_name, console=self.console, status_right=status_right)
        self._tool_spinner.start()

    def _clear_terminal_lines(self, count: int) -> bool:
        if count <= 0 or not bool(getattr(self.console, "is_terminal", False)):
            return False
        if count > max(1, _surface_height(self.console) - 1):
            return False
        output = getattr(self.console, "file", None)
        if output is None:
            return False
        output.write("\r\x1b[K")
        for _ in range(count):
            output.write("\x1b[1A\x1b[K")
        output.write("\r")
        with contextlib.suppress(Exception):
            output.flush()
        return True

    def _clear_running_tool_row(self) -> bool:
        if self._running_tool_row_lines <= 0:
            return False
        cleared = self._clear_terminal_lines(self._running_tool_row_lines)
        if cleared:
            self._running_tool_row_lines = 0
        return cleared

    def _clear_pending_tool_call_row(self) -> bool:
        if self._pending_tool_call_lines <= 0:
            return False
        cleared = self._clear_terminal_lines(self._pending_tool_call_lines)
        if cleared:
            self._pending_tool_call_lines = 0
        return cleared

    def _stop_tool_feedback(self):
        """Stop any active tool progress indicator."""
        if self._tool_spinner:
            try:
                self._tool_spinner.stop()
            except Exception:
                pass
        self._tool_spinner = None
        self._tool_start = None
        self._current_tool_name = ""
        self._current_tool_arguments = {}

    def _update_tool_feedback(self, phase: str, detail: str = "", percent: float | None = None):
        """Update the active tool spinner with structured progress."""
        if not self._tool_spinner:
            return
        self._tool_spinner.update_phase(phase, detail, percent)

    def _render_suggested_actions(self, actions: list[Any]) -> None:
        """Render numbered suggestion list.

        Per architecture §5 (argued suggestions), each item carries a concise
        ``Lesson:`` reason drawn from cross-mission experience so the agent
        explains *why* it proposes an action. The verbose ``Match:`` / ``Missing:``
        learning internals stay hidden. The ``show_experience`` display
        preference (default on) can suppress the reason line.
        """
        if not actions:
            return
        max_show = int(self._display_prefs.get("max_suggestions", 5))
        self.console.print()
        self.console.print(f"  [{COLORS['text']}]Suggested next actions:[/{COLORS['text']}]")
        for index, action in enumerate(actions[:max_show], 1):
            tool_name = str(getattr(action, "tool_name", "") or "").strip()
            arguments = dict(getattr(action, "arguments", {}) or {})
            target = (
                arguments.get("url")
                or arguments.get("target")
                or arguments.get("domain")
                or arguments.get("query")
                or arguments.get("cve_id")
                or ""
            )
            detail_parts = []
            if tool_name:
                detail_parts.append(tool_name)
            if target:
                detail_parts.append(str(target))
            risk = str(getattr(action, "risk", "") or "").strip()
            if risk:
                detail_parts.append(risk)
            detail = f" [{COLORS['text_muted']}]· {escape(' · '.join(detail_parts))}[/{COLORS['text_muted']}]" if detail_parts else ""
            title = escape(str(getattr(action, "title", "") or "Next action"))
            self.console.print(f"  {index}. [{COLORS['text']}]{title}[/{COLORS['text']}]{detail}")
            # §5: one concise experience reason per suggestion; verbose
            # Match:/Missing: learning internals stay hidden.
            if self._display_prefs.get("show_experience", True):
                experience = [
                    str(item).strip()
                    for item in (getattr(action, "experience", []) or [])
                    if str(item).strip()
                ]
                if experience:
                    self.console.print(
                        f"     [{COLORS['text_muted']}]Lesson: {escape(experience[0])}[/{COLORS['text_muted']}]"
                    )
        self.console.print(f"  [{COLORS['text_muted']}]Reply with a number or describe what to do next.[/{COLORS['text_muted']}]")

    # ── Agent Stream Rendering ────────────────────────────────────────

    async def render_agent_stream(
        self,
        event_stream: AsyncIterator[AgentEvent],
        status_right: str = "",
        *,
        memory: Any | None = None,
        runtime: RuntimeState | None = None,
    ):
        """
        Antigravity-style streaming:
        - ▸ Thought for Xs (with content preview)
        - 2-space indented narrative text
        - ● ToolName(args) collapsed
        - ⚠ for errors/warnings
        """
        text_accumulator = ""
        live_display: Live | None = None
        last_render_time: float = 0.0
        is_thinking = False
        interrupt = _EscInterruptMonitor()
        turn_items: list[dict[str, Any]] = []
        turn_tools: dict[str, dict[str, Any]] = {}
        tool_tasks: dict[str, Any] = {}
        latest_tool_tail_lines = 0
        count_tail_after_latest_tool = False

        def _record_latest_thought() -> None:
            turn_items.append({
                "kind": "thought",
                "duration": self._latest_thought_duration if self._latest_thought_duration is not None else "?",
                "content": self._latest_thought_content,
            })

        def _build_display(text: str):
            """Build Antigravity-style indented Markdown display."""
            return Padding(
                Markdown(normalize_agent_markdown(text), code_theme="ansi_dark"),
                (0, 0, 0, 2),
            )

        def _advance_ctrl_o_tail(lines: int) -> None:
            nonlocal latest_tool_tail_lines
            if count_tail_after_latest_tool:
                latest_tool_tail_lines += max(0, int(lines or 0))
            if runtime is not None:
                runtime.advance_ctrl_o_anchor_lines(lines)

        def _text_render_line_count(text: str) -> int:
            if not str(text or "").strip():
                return 0
            return len(_build_text_transcript_lines(text, width=_surface_width(self.console)))

        def _thought_render_line_count() -> int:
            return 2 + (1 if self._latest_thought_content else 0)

        def _finish_active_thinking() -> None:
            nonlocal is_thinking
            if not is_thinking:
                return
            self._finish_thinking()
            _advance_ctrl_o_tail(_thought_render_line_count())
            _record_latest_thought()
            is_thinking = False

        def _flush_live_text() -> None:
            """Stop live streaming and write the final transcript text once."""
            nonlocal live_display, text_accumulator
            if live_display:
                live_display.stop()
                live_display = None
            if text_accumulator:
                turn_items.append({"kind": "text", "content": text_accumulator})
                _advance_ctrl_o_tail(_text_render_line_count(text_accumulator))
                self.console.print(_build_display(text_accumulator))
                text_accumulator = ""

        def _tool_task_for_event(event: Any) -> Any | None:
            if runtime is None or str(getattr(event, "name", "") or "") not in _TOOL_TASK_TRACKING_NAMES:
                return None
            task = tool_tasks.get(str(getattr(event, "id", "") or ""))
            if task is not None:
                return task
            arguments = dict(getattr(event, "arguments", None) or self._latest_tool_arguments or {})
            task = runtime.add_task(
                format_tool_call_text(event.name, arguments),
                "running",
                "starting",
                kind="tool-execution",
            )
            task.append_log(f"started {event.name}")
            tool_tasks[event.id] = task
            return task

        def _compact_task_output(result: Any) -> str:
            content = str(getattr(result, "output", "") or getattr(result, "error", "") or "")
            metadata = getattr(result, "metadata", None)
            if isinstance(metadata, dict) and metadata.get("spool_path"):
                content = content.rstrip() + f"\n\nSpool: {metadata['spool_path']}"
            if len(content) <= 20_000:
                return content
            return content[:20_000].rstrip() + "\n\n... task output truncated for review ..."

        def _finish_tool_task(event: ToolResultEvent) -> None:
            task = tool_tasks.get(event.id)
            if task is None:
                return
            result = event.result
            output = _compact_task_output(result)
            text_failure = bool(getattr(result, "success", False)) and _looks_like_tool_failure(str(getattr(result, "output", "") or ""))
            succeeded = bool(getattr(result, "success", False)) and not text_failure
            elapsed = float(getattr(result, "execution_time", 0.0) or 0.0)
            metadata = getattr(result, "metadata", None)
            keep_for_review = (
                not succeeded
                or elapsed >= _MIN_REVIEWABLE_TOOL_SECONDS
                or (isinstance(metadata, dict) and bool(metadata.get("timeout_reason")))
                or "[Output truncated in memory;" in str(getattr(result, "output", "") or "")
            )
            if not keep_for_review and runtime is not None:
                with contextlib.suppress(ValueError):
                    runtime.tasks.remove(task)
                tool_tasks.pop(event.id, None)
                return
            status = "done" if succeeded else "failed"
            if isinstance(metadata, dict):
                task.metadata = dict(metadata)
            task.finish(status, output=output, detail=f"{event.name} {status}")
            task.append_log(f"finished {event.name} ({format_duration(elapsed)})")

        def _cancel_active_tool_tasks() -> None:
            for task in list(tool_tasks.values()):
                if getattr(task, "status", "") == "running":
                    task.finish("cancelled", detail="cancelled by user")
                    task.append_log("interrupted by user")

        async def _show_transcript_surface() -> None:
            """Toggle the latest ctrl+o transcript while generation/tool execution continues."""
            nonlocal live_display
            live_was_active = live_display is not None
            if live_display:
                with contextlib.suppress(Exception):
                    live_display.stop()
                live_display = None

            thinking_was_active = bool(self._thinking_spinner and self._thinking_spinner.is_running)
            if thinking_was_active and self._thinking_spinner:
                self._thinking_spinner.stop()
                self._thinking_spinner = None

            tool_name = self._current_tool_name if self._tool_spinner else ""
            tool_was_active = bool(self._tool_spinner)
            if tool_was_active:
                self._stop_tool_feedback()

            await interrupt.stop()
            try:
                if self._toggle_latest_transcript():
                    pass
                else:
                    self.render_status("Nothing to expand yet.")
            finally:
                interrupt.clear()
                interrupt.start()

            if thinking_was_active and is_thinking and self._thinking_start is not None:
                self._thinking_spinner = ThinkingSpinner(
                    "Generating...",
                    console=self.console,
                    status_right=status_right,
                )
                self._thinking_spinner.start()
            if tool_was_active and tool_name:
                self._start_tool_feedback(tool_name, status_right=status_right)
            if live_was_active:
                live_display = Live(
                    _build_display(text_accumulator),
                    console=self.console,
                    auto_refresh=False,
                    transient=True,
                    vertical_overflow="visible",
                )
                live_display.start()

        try:
            interrupt.start()
            async for event in _interruptible_events(event_stream, interrupt):

                if isinstance(event, _TranscriptToggleRequest):
                    await _show_transcript_surface()

                elif isinstance(event, StatusEvent):
                    if is_thinking:
                        pass  # Don't interrupt thinking display for status
                    else:
                        self.console.print(
                            f"  [{COLORS['text_muted']}]{event.message}[/{COLORS['text_muted']}]"
                        )

                elif isinstance(event, ThinkingEvent):
                    if not is_thinking:
                        is_thinking = True
                        self._start_thinking(status_right=status_right)

                    # Accumulate thinking content
                    if event.content and event.content != "Thinking...":
                        self._thinking_content += event.content

                elif isinstance(event, TextEvent):
                    # First text event after thinking → finish thinking display
                    if is_thinking:
                        _finish_active_thinking()

                    if not event.done and not live_display:
                        text_accumulator = ""
                        live_display = Live(
                            _build_display(text_accumulator),
                            console=self.console,
                            auto_refresh=False,
                            transient=True,
                            vertical_overflow="visible",
                        )
                        live_display.start()
                        last_render_time = time.monotonic()

                    if event.done:
                        _flush_live_text()
                        self.console.print()
                        _advance_ctrl_o_tail(1)
                    else:
                        text_accumulator += event.content
                        # Throttled re-render: max ~20fps
                        if live_display:
                            now = time.monotonic()
                            if (now - last_render_time) >= _RENDER_INTERVAL:
                                live_display.update(_build_display(text_accumulator))
                                live_display.refresh()
                                last_render_time = now

                elif isinstance(event, ToolCallEvent):
                    count_tail_after_latest_tool = False
                    latest_tool_tail_lines = 0
                    # Finish thinking if still active
                    if is_thinking:
                        _finish_active_thinking()

                    # Stop live text display if active
                    if live_display:
                        _flush_live_text()

                    self._latest_tool_name = event.name
                    self._latest_tool_arguments = dict(event.arguments or {})
                    self._latest_tool_result = None
                    self._latest_transcript_expanded = False
                    self._current_tool_name = event.name
                    self._current_tool_arguments = dict(event.arguments or {})
                    tool_item = {
                        "kind": "tool",
                        "name": event.name,
                        "arguments": dict(event.arguments or {}),
                        "result": None,
                    }
                    turn_items.append(tool_item)
                    turn_tools[event.id] = tool_item

                    self._clear_pending_tool_call_row()

                elif isinstance(event, ApprovalRequestEvent):
                    if is_thinking:
                        _finish_active_thinking()

                    if live_display:
                        _flush_live_text()

                    self._stop_tool_feedback()
                    await interrupt.stop()

                    approved = await ApprovalPrompt.request_approval(
                        self.console, event.tool_name, event.arguments, event.resource,
                    )
                    interrupt.clear()
                    interrupt.start()
                    if event.approval_future and not event.approval_future.done():
                        event.approval_future.set_result(approved)

                elif isinstance(event, SudoAuthenticationRequestEvent):
                    if is_thinking:
                        _finish_active_thinking()

                    if live_display:
                        _flush_live_text()

                    self._stop_tool_feedback()
                    await interrupt.stop()
                    decision = await request_sudo_authentication(
                        self.console,
                        command=event.command,
                        reason=event.reason,
                    )
                    interrupt.clear()
                    interrupt.start()
                    if event.authentication_future and not event.authentication_future.done():
                        event.authentication_future.set_result(decision)

                elif isinstance(event, ToolStartEvent):
                    count_tail_after_latest_tool = False
                    latest_tool_tail_lines = 0
                    if self._latest_tool_name != event.name:
                        self._latest_tool_arguments = {}
                    self._latest_tool_name = event.name
                    if getattr(event, "arguments", None):
                        self._latest_tool_arguments = dict(event.arguments or {})
                        self._current_tool_arguments = dict(event.arguments or {})
                    self._latest_transcript_expanded = False
                    self._clear_pending_tool_call_row()
                    self._running_tool_row_lines = ToolCallBox.render_running(
                        self.console,
                        event.name,
                        self._latest_tool_arguments,
                        leading_blank=False,
                    )
                    self._start_tool_feedback(event.name, status_right=status_right)
                    if getattr(event, "arguments", None):
                        self._current_tool_arguments = dict(event.arguments or {})
                    task = _tool_task_for_event(event)
                    if task is not None:
                        task.detail = f"running {event.name}"

                elif isinstance(event, ToolProgressEvent):
                    self._update_tool_feedback(event.phase, event.detail, event.percent)
                    task = tool_tasks.get(event.id)
                    if task is not None:
                        detail = event.phase
                        if event.detail:
                            detail += f" · {event.detail}"
                        task.detail = detail
                        task.append_log(detail)

                elif isinstance(event, ToolResultEvent):
                    count_tail_after_latest_tool = False
                    latest_tool_tail_lines = 0
                    if self._latest_tool_name != event.name:
                        self._latest_tool_arguments = {}
                    self._latest_tool_name = event.name
                    self._latest_tool_result = event.result
                    if event.id in turn_tools:
                        turn_tools[event.id]["result"] = event.result
                    else:
                        turn_items.append({
                            "kind": "tool",
                            "name": event.name,
                            "arguments": dict(self._latest_tool_arguments or {}),
                            "result": event.result,
                        })
                    keep_result_expanded = (
                        self._latest_transcript_expanded
                        and self._latest_tool_name == event.name
                        and self._latest_transcript_rendered_lines > 0
                    )
                    self._stop_tool_feedback()
                    self._clear_running_tool_row()
                    expanded_surface_cleared = True
                    if keep_result_expanded:
                        expanded_surface_cleared = self._clear_terminal_lines(self._latest_transcript_rendered_lines)
                        if expanded_surface_cleared:
                            self._latest_transcript_rendered_lines = 0
                    self._latest_transcript_expanded = False
                    had_pending_call = self._pending_tool_call_lines > 0
                    pending_call_cleared = self._clear_pending_tool_call_row()
                    result_status = _tool_result_status(event.result)
                    if keep_result_expanded and expanded_surface_cleared:
                        self._render_inline_tool_expansion()
                    elif keep_result_expanded and bool(getattr(self.console, "is_terminal", False)):
                        self._latest_transcript_expanded = True
                    elif not had_pending_call or pending_call_cleared:
                        # ✅ agy grouping: suppress (ctrl+o) on the ● line when the
                        # ⎿ result summary below carries it. Error results render
                        # inline without that affordance, so the ● line keeps it.
                        ToolCallBox.render(
                            self.console,
                            event.name,
                            self._latest_tool_arguments,
                            status=result_status,
                            leading_blank=False,
                            show_expand_tag=(result_status == "error"),
                        )
                    if not keep_result_expanded:
                        ToolResultBox.render(self.console, event.name, event.result)
                    _finish_tool_task(event)
                    self._tool_start = None
                    count_tail_after_latest_tool = True

                elif isinstance(event, SuggestedActionsEvent):
                    if is_thinking:
                        _finish_active_thinking()
                    if live_display:
                        _flush_live_text()
                    self._render_suggested_actions(event.actions)

                elif isinstance(event, TokenUsageEvent):
                    self.render_token_usage(event.input_tokens, event.output_tokens)

                elif isinstance(event, ErrorEvent):
                    if is_thinking:
                        _finish_active_thinking()

                    if live_display:
                        _flush_live_text()

                    self._stop_tool_feedback()
                    self._clear_running_tool_row()
                    self._clear_pending_tool_call_row()

                    self.render_agent_error(event.error)

            if runtime is not None and turn_items:
                width = _surface_width(self.console)
                collapsed_lines = _build_ctrl_o_transcript_lines(turn_items, expanded=False, width=width)
                expanded_lines = _build_ctrl_o_transcript_lines(turn_items, expanded=True, width=width)
                if collapsed_lines and expanded_lines:
                    runtime.ctrl_o_transcript_collapsed = "\n".join(collapsed_lines)
                    runtime.ctrl_o_transcript_expanded = "\n".join(expanded_lines)
                    runtime.ctrl_o_transcript_is_expanded = False
                    runtime.ctrl_o_transcript_rendered_lines = 0

                latest_tool_item = next(
                    (item for item in reversed(turn_items) if item.get("kind") == "tool" and item.get("result") is not None),
                    None,
                )
                if latest_tool_item is not None:
                    runtime.set_ctrl_o_anchor(
                        _build_tool_transcript_block_lines(latest_tool_item, expanded=False, width=width),
                        _build_tool_transcript_block_lines(latest_tool_item, expanded=True, width=width),
                        tail_lines=latest_tool_tail_lines,
                    )

        except _AgentStreamInterrupted:
            interrupted_tool = self._current_tool_name if self._tool_spinner else ""
            interrupted_tool_args = dict(self._current_tool_arguments or {})
            _cancel_active_tool_tasks()
            if is_thinking:
                self._cancel_thinking()
            if live_display:
                with contextlib.suppress(Exception):
                    live_display.stop()
            self._stop_tool_feedback()
            self._clear_running_tool_row()
            self._clear_pending_tool_call_row()
            if interrupted_tool:
                self.render_status(
                    f"Interrupted · stopped {format_tool_call_text(interrupted_tool, interrupted_tool_args)} · "
                    "What should SecOps CLI do instead?"
                )
            else:
                self.render_status("Interrupted · What should SecOps CLI do instead?")
        except Exception as e:
            if is_thinking:
                self._cancel_thinking()
            if live_display:
                try:
                    live_display.stop()
                except Exception:
                    pass
            self._stop_tool_feedback()
            self._clear_running_tool_row()
            self._clear_pending_tool_call_row()
            self.render_agent_error(f"Stream error: {str(e)}")
        finally:
            await interrupt.stop()
