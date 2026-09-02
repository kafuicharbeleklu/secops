"""
Streaming renderer matching Antigravity CLI style exactly.

Key patterns from Antigravity CLI:
  ▸ Thought for Xs
    Brief thinking content preview...

  Agent narrative text is indented with 2 spaces.

  ⏺ ToolName(arg_summary) (ctrl+o to expand)

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

from rich.console import Console, RenderableType
from rich.markdown import Markdown
from rich.live import Live
from rich.markup import escape
from rich.padding import Padding
from rich.segment import Segment
from rich.table import Table
from rich.text import Text

from secops_agent import __version__
from secops_agent.ui.theme import rich_theme, COLORS, friendly_model_name, reduced_motion
from secops_agent.ui.commands import iter_commands
from secops_agent.ui.animations import ThinkingSpinner, ToolExecutionSpinner, thinking_label_for_phase
from secops_agent.ui.overlay import (
    OverlayRow,
    build_choice_overlay_lines,
    build_theme_picker_lines,
    read_terminal_key,
    render_overlay,
)
from secops_agent.ui.panel import PanelRow, choose_panel
from secops_agent.ui.runtime import RuntimeState
from secops_agent.ui.tool_display import (
    ToolCallBox, ToolResultBox, ApprovalPrompt, format_duration, format_tool_call_text,
    summarize_output, _looks_like_tool_failure, _tool_call_markup, _tool_status_color,
    _tool_result_log_reference_line, build_collapsed_result_lines,
)
from secops_agent.ui.spool_display import spool_reference, supervised_detail_text
from secops_agent.ui.error_display import ErrorRenderer
from secops_agent.core.agent import (
    AgentEvent, ThinkingEvent, TextEvent,
    ToolCallEvent, ToolStartEvent, ToolProgressEvent, ToolResultEvent, ErrorEvent, StatusEvent,
    ApprovalRequestEvent, SudoAuthenticationRequestEvent, TokenUsageEvent, SuggestedActionsEvent,
    PlanPreviewEvent, PlanDivergenceEvent,
)
from secops_agent.core.tools import ToolResult
from secops_agent.ui.sudo_prompt import request_sudo_authentication

# Throttle: re-render Markdown at most every 50ms to prevent flashing
_RENDER_INTERVAL = 0.05  # seconds

# Fenced code blocks get vivid, truecolor, per-token syntax highlighting (like
# Claude Code) instead of the flat ANSI palette, whose dark-blue keywords are
# near-invisible on a dark ground. Override via SECOPS_CODE_THEME (any Pygments
# theme name, e.g. dracula / one-dark / nord).
_CODE_THEME = os.environ.get("SECOPS_CODE_THEME", "").strip() or "monokai"

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

# View builders/primitives live in secops_agent.ui.views; re-exported
# here so existing imports and Renderer methods resolve unchanged.
from secops_agent.ui import layout
from secops_agent.ui import typography
from secops_agent.ui.typography import Boundary
from secops_agent.ui.views.common import (
    SettingsItem,
    SettingsSelection,
    AgentProfileSummary,
    AgentViewEntry,
    _MCPViewItem,
    _SkillViewItem,
    _turn_separator,
    _surface_width,
    _surface_height,
    _ctrl_o_output_visible_limit,
    _display_path,
    agent_profile_template_paths,
    load_agent_profiles,
    _transient_content_height,
    _fit_cell,
)
from secops_agent.ui.views.panels import (
    HOOK_EVENT_ROWS,
    _settings_window_start,
    _filtered_settings_items,
    build_settings_view_lines,
    _context_budget_for_model,
    _format_token_compact,
    _context_grid,
    _role_token_estimate,
    build_context_usage_lines,
    build_hooks_view_lines,
    _compact_mcp_path,
    _mcp_source_label,
    _compact_mcp_error,
    _mcp_server_status,
    _mcp_server_detail,
    _mcp_view_items,
    build_mcp_view_lines,
    _compact_skill_path,
    _skill_source_label,
    _skill_view_items,
    build_skills_view_lines,
    _artifact_source_label,
    _artifact_content_lines,
    _artifact_row_detail,
    _artifact_preview_line,
    build_artifacts_view_lines,
    build_attachments_view_lines,
    _agent_view_entries,
    build_agents_view_lines,
    _ordered_help_categories,
    _package_version,
    _short_workspace,
    _help_view_index,
    _help_command_specs,
    _help_command_label,
    _help_list_row,
    _split_help_row,
    _is_detail_help_line,
    _is_shortcut_help_label,
    _help_prefix_lines,
    _help_list_total,
    _help_view_items,
    _help_visible_count,
    _help_max_scroll,
    _help_scroll_for_selection,
    _help_count_window,
    _tool_category_value,
    _tools_tabs,
    _tools_view_index,
    _tools_for_view,
    _tools_tab_line,
    _tools_window_start,
    build_tools_view_lines,
    build_help_view_lines,
    _HELP_VIEWS,
    _HELP_CATEGORY_ORDER,
    _LONG_LIST_VISIBLE_ITEMS,
    _HELP_LIST_VISIBLE_ITEMS,
    SETTINGS_FOOTER,
    ARTIFACT_FOOTER,
    AGENTS_FOOTER,
    MCP_FOOTER,
    SKILLS_FOOTER,
    _HELP_ROW_RE,
    _HELP_DETAIL_LINES,
    _HELP_SHORTCUTS,
    _HELP_SHORTCUT_LABELS,
)




def _user_turn_bg() -> str:
    """A very faint band behind the user's own turn (Claude-Code style).

    A hair lighter than the dark ground / a hair darker than the light ground —
    just enough to read as "my input" without competing with tool cards. The fg
    colours (accent / accent_bright) stay well above 4.5:1 on either tint.
    """
    return COLORS["input_frame_bg"]  # ground-appropriate tint from the active palette (P4)


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
    """Épuré collapsed result block (one key-fact line + a discreet meta line).

    Delegates to the shared builder in ``tool_display`` so the live result row
    and this ctrl+o transcript cache stay byte-for-byte identical, and so the
    legibility contract (readable text_muted/text_secondary, never text_dim as
    text) lives in exactly one place."""
    return build_collapsed_result_lines(result, width=width)


def _result_headline(result: Any, fallback: str) -> str:
    """Headline for a tool result: the parsed structured fact when present,
    otherwise the given fallback. Keeps collapse and expand headlines in sync."""
    metadata = getattr(result, "metadata", None) or {}
    parsed = str(metadata.get("parsed_summary") or "").strip()
    if parsed:
        return parsed.splitlines()[0]
    return fallback


_SEARCH_ARG_KEYS = ("query", "pattern", "search", "term", "keyword", "cve_id")


def _search_terms_from_arguments(arguments: dict[str, Any] | None) -> list[str]:
    """Highlightable search terms from a tool's arguments (query/pattern/…), so a
    grep/search result can emphasise what was actually matched."""
    terms: list[str] = []
    for key in _SEARCH_ARG_KEYS:
        value = str((arguments or {}).get(key, "") or "").strip()
        if value:
            terms.extend(token for token in re.split(r"\s+", value) if len(token) >= 2)
    return sorted(set(terms), key=len, reverse=True)[:6]


def _match_highlight_style() -> str:
    """A search-hit style: dark text on the theme's warning (amber) background,
    like Claude Code's matched-term highlight."""
    return f"bold {COLORS['on_warning']} on {COLORS['warning']}"


def highlight_terms(text: str, terms: list[str], style: str) -> str:
    """Rich markup for *text* (escaped) with each case-insensitive occurrence of
    any term wrapped in *style* — the matched-term background highlight."""
    escaped = escape(text)
    valid = [term for term in terms if term and len(term) >= 2]
    if not valid:
        return escaped
    pattern = re.compile("|".join(re.escape(escape(term)) for term in valid), re.IGNORECASE)
    return pattern.sub(lambda match: f"[{style}]{match.group(0)}[/{style}]", escaped)


def _build_expanded_tool_result_lines(result: Any, *, width: int, terms: list[str] | None = None) -> list[str]:
    output_lines = _tool_output_lines(result)
    first = _fit_cell(_result_headline(result, output_lines[0]), max(16, width - 34))
    lines = [f"{layout.INDENT_STR}[{COLORS['text_muted']}]⎿  {escape(first)} (ctrl+o to collapse)[/{COLORS['text_muted']}]"]
    if len(output_lines) > 1:
        visible_limit = _ctrl_o_output_visible_limit()
        visible_lines = output_lines[:visible_limit]
        match_style = _match_highlight_style()

        def _render(line: str) -> str:
            fitted = _fit_cell(line, max(16, width - 6))
            return highlight_terms(fitted, terms, match_style) if terms else escape(fitted)

        lines.append("")
        lines.append(f"{layout.INDENT_STR}[{COLORS['text_muted']}]Output:[/{COLORS['text_muted']}]")
        lines.extend(
            f"{layout.INDENT_STR * 2}[{COLORS['text_muted']}]{_render(line)}[/{COLORS['text_muted']}]"
            for line in visible_lines
        )
        if len(output_lines) > len(visible_lines):
            lines.append(f"{layout.INDENT_STR * 2}[{COLORS['text_muted']}]... {len(output_lines) - len(visible_lines):,} more lines hidden[/{COLORS['text_muted']}]")
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
        # Claude Code parity: tool rows are always a ⏺ turn bullet — running
        # state is shown by colour (yellow) and the spinner, not by the glyph.
        indicator_color = _tool_status_color(status="running")
        return [
            f"[{indicator_color}]⏺[/{indicator_color}] {call_markup}{expand_suffix}"
        ]

    indicator_color = _tool_status_color(status=_tool_result_status(result))
    if expanded:
        terms = _search_terms_from_arguments(item.get("arguments"))
        return [
            f"[{indicator_color}]⏺[/{indicator_color}] {call_markup}",
            *_build_expanded_tool_result_lines(result, width=width, terms=terms),
        ]
    return [
        f"[{indicator_color}]⏺[/{indicator_color}] {call_markup}{expand_suffix}",
        *_build_collapsed_tool_result_lines(result, width=width),
    ]


class _StripTrailingWhitespace:
    """Render wrapper that drops right-side padding whitespace from every line (#6).

    Rich pads block renderables (Markdown, Padding) to the full console width, so
    the streamed answer carries trailing spaces into scrollback and copy-paste.
    This renders the inner renderable to un-padded segment lines and rstrips the
    trailing *unstyled* whitespace only: line count and styling are preserved, and
    a styled background fill (e.g. a code-block background) keeps its padding.
    """

    def __init__(self, renderable: Any) -> None:
        self._renderable = renderable

    def __rich_console__(self, console: "Console", options: Any):
        for line in console.render_lines(self._renderable, options, pad=False):
            segs = list(line)
            while segs:
                last = segs[-1]
                style = last.style
                if last.control or (style is not None and style.bgcolor is not None):
                    break
                stripped = last.text.rstrip()
                if stripped == last.text:
                    break
                if stripped:
                    segs[-1] = Segment(stripped, style, last.control)
                    break
                segs.pop()
            yield from segs
            yield Segment.line()


def _agent_markdown(content: str, *, width: int, bullet: bool = False) -> RenderableType:
    """Indented agent-prose Markdown, width-capped on wide terminals (P2).

    Left-indent of 2 matches the assistant narrative; on a terminal wider than
    ``layout.TEXT_MAX_WIDTH`` the prose column is capped (extra space becomes
    right padding, later stripped) so full-width text never sprawls illegibly.

    When *bullet* is set, a single ⏺ turn bullet (``glyph.turn_bullet``,
    ``color.accent`` at rest — DESIGN_SPEC §1/§4.2) is hung at column 0 on the
    first physical line while the prose and every continuation line stay at
    column 2 (``line.hang_alignment``, via a two-column ``Table.grid`` whose
    gutter renders once and top-aligns). Set it only for the full committed /
    replayed turn, never the streaming live tail — once the tail is truncated its
    first visible line is no longer the turn start, so a bullet there would float
    mid-message."""
    left = layout.INDENT  # DESIGN_SPEC indent.narrative / bullet_content (single source)
    inner = min(max(1, int(width) - left), layout.TEXT_MAX_WIDTH)
    right = max(0, int(width) - left - inner)
    body = Markdown(normalize_agent_markdown(content), code_theme=_CODE_THEME)
    if not bullet:
        return Padding(body, (0, right, 0, left))
    grid = Table.grid(padding=0)
    grid.add_column(width=left, no_wrap=True)  # "⏺ " gutter → content lands at col 2
    grid.add_column(width=inner)               # prose column, width-capped
    grid.add_row(Text("⏺ ", style=COLORS["accent"]), body)
    return Padding(grid, (0, right, 0, 0)) if right else grid


def _build_text_transcript_lines(content: str, *, width: int, bullet: bool = True) -> list[str]:
    rendered = Console(
        width=width,
        record=True,
        force_terminal=False,
        color_system=None,
        file=io.StringIO(),
    )
    rendered.print(_agent_markdown(content, width=width, bullet=bullet))
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
                lines.append(f"{layout.INDENT_STR}[{COLORS['text_dim']}]{escape(preview)}[/{COLORS['text_dim']}]")
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


_BULLET_LINE_RE = re.compile(r"^\s{0,8}[-*+]\s+\S")
# The ordered-list lines this module emits are escaped ("1\. body  "), so match
# the backslash-dot form, not a raw "1. ".
_ORDERED_DISPLAY_RE = re.compile(r"^\s{0,8}\d+\\\.\s")


def _line_block_kind(line: str) -> str:
    """Classify a normalized line as 'bullet', 'ordered', or 'para' so block
    boundaries can be detected."""
    if _BULLET_LINE_RE.match(line):
        return "bullet"
    if _ORDERED_DISPLAY_RE.match(line):
        return "ordered"
    return "para"


def _separate_list_blocks(lines: list[str]) -> list[str]:
    """Insert a blank line wherever the block kind changes (paragraph ↔ bullet ↔
    numbered list).

    Rich Markdown treats a list with no blank line before/after it as lazily
    continuing into the adjacent block, so ``- 443/tcp`` followed by
    ``Prochaines étapes:`` — or an intro line followed by ``1. …`` — renders as
    one run-on line. A single blank separator makes each a distinct block; lines
    of the same kind stay together and fenced code is left untouched."""
    out: list[str] = []
    in_fence = False
    prev_kind = ""
    for line in lines:
        if line.strip().startswith("```"):
            in_fence = not in_fence
            out.append(line)
            prev_kind = ""
            continue
        if in_fence:
            out.append(line)
            continue
        if line.strip():
            kind = _line_block_kind(line)
            # Any kind change involves a list (para↔para cannot "differ"), so a
            # single blank separates the two blocks.
            if out and out[-1].strip() and prev_kind and kind != prev_kind:
                out.append("")
            prev_kind = kind
        else:
            prev_kind = ""
        out.append(line)
    return out


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
            level = len(heading.group(1))
            title = heading.group(2).strip()
            if title:
                # Keep h2/h3 as real (left-aligned, accented) headings for
                # structure; downgrade a heavy centred h1 to h2; flatten deep
                # h4+ to bold to avoid noisy micro-headers.
                if level <= 1:
                    normalized.append(f"## {title}")
                elif level <= 3:
                    normalized.append(f"{'#' * level} {title}")
                else:
                    normalized.append(f"**{title}**")
            continue

        next_line = lines[index + 1] if index + 1 < len(lines) else ""
        if stripped and _MARKDOWN_SETEXT_RE.match(next_line.strip()):
            ordered_next = None
            normalized.append(f"## {stripped}")
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

    normalized = _separate_list_blocks(normalized)
    # The blank-line rule (no leading/trailing blank, no ≥2 consecutive) lives once
    # in typography.collapse_blank_lines — reused here so it is not re-implemented.
    normalized = typography.collapse_blank_lines(normalized)
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


def _streaming_tail(text: str, viewport_height: int) -> str:
    """Example F: return only the last N lines of streaming text so the transient
    Live region never approaches the viewport height. A render taller than the
    screen scrolls its top into scrollback that cursor-up cannot reach, so each
    redraw restacks it (the 5-6x cascade). The complete answer is written once on
    the done event by _flush_live_text, so nothing is lost by cropping the tail."""
    limit = max(4, (viewport_height or 28) - 6)
    # Walk back over the last `limit` newlines instead of splitting the whole
    # (ever-growing) accumulator on every 50ms tick — O(limit) per tick, not O(n),
    # so a long streamed answer stays smooth instead of degrading quadratically.
    cut = len(text)
    for _ in range(limit):
        newline = text.rfind("\n", 0, cut)
        if newline == -1:
            return text  # fewer than `limit` lines — nothing to crop
        cut = newline
    return text[cut + 1:]


def _classify_stream_key_chunk(data: bytes) -> str:
    """Classify a raw stdin chunk read while the agent streams.

    Returns 'expand' (Ctrl-O), 'interrupt' (Esc / Ctrl-C), or 'text' (anything
    else — typed-ahead input for the next turn). Ctrl-O / interrupt keep their
    existing precedence over plain text.
    """
    if b"\x0f" in data:
        return "expand"
    if b"\x1b" in data or b"\x03" in data:
        return "interrupt"
    return "text"


# Bracketed-paste delimiters (DEC private mode 2004). A multi-line message pasted
# while the agent streams must stay ONE instruction (Example H) instead of being
# split per line like several distinct typed-ahead instructions (Example E).
_PASTE_START = "\x1b[200~"
_PASTE_END = "\x1b[201~"
_PASTE_START_B = _PASTE_START.encode()
_PASTE_END_B = _PASTE_END.encode()
_ENABLE_BRACKETED_PASTE = "\x1b[?2004h"
_DISABLE_BRACKETED_PASTE = "\x1b[?2004l"


def _write_terminal(seq: str) -> None:
    """Best-effort write of a terminal control sequence to stdout."""
    try:
        if sys.stdout.isatty():
            sys.stdout.write(seq)
            sys.stdout.flush()
    except Exception:
        pass


def _split_typed_lines(text: str) -> list[str]:
    """Split typed-ahead text into complete instructions on CR/LF, dropping
    empties and any fragment still carrying control/escape bytes (stray arrow
    keys etc.)."""
    lines: list[str] = []
    for chunk in re.split(r"[\r\n]+", text):
        stripped = chunk.strip()
        if not stripped:
            continue
        if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in stripped):
            continue
        lines.append(stripped)
    return lines


def _coalesce_paste_block(block: str) -> str:
    """Collapse the body of a bracketed paste into a single instruction: keep its
    non-blank lines (a multi-line message is ONE instruction) joined with
    newlines. Returns '' if nothing printable remains."""
    kept = [ln.strip() for ln in re.split(r"[\r\n]+", block) if ln.strip()]
    return "\n".join(kept).strip()


def _parse_typeahead_lines(raw: bytes) -> list[str]:
    """Turn captured typed-ahead bytes into complete, submittable instructions.

    Input arrives in cbreak mode, so Enter is CR. Typed lines split on CR/LF —
    several instructions typed ahead stay several instructions (Example E). A
    bracketed-paste block (ESC[200~ … ESC[201~) is coalesced into ONE instruction
    so a single multi-line paste is not fragmented (Example H). A trailing
    fragment with no terminator is held back by the drain cut, not here.
    """
    if not raw:
        return []
    text = raw.decode("utf-8", "ignore")
    out: list[str] = []
    while True:
        start = text.find(_PASTE_START)
        if start == -1:
            out.extend(_split_typed_lines(text))
            break
        out.extend(_split_typed_lines(text[:start]))
        end = text.find(_PASTE_END, start + len(_PASTE_START))
        if end == -1:
            break  # unterminated paste (held back by the drain cut)
        pasted = _coalesce_paste_block(text[start + len(_PASTE_START):end])
        if pasted:
            out.append(pasted)
        text = text[end + len(_PASTE_END):]
    return out


def _typeahead_cut_index(raw: bytes) -> int:
    """Byte offset up to which the type-ahead buffer holds only *complete* units
    (Enter-terminated lines and closed paste blocks). An in-progress paste — or a
    trailing unterminated line before it — is held back for the next drain."""
    last_start = raw.rfind(_PASTE_START_B)
    last_end = raw.rfind(_PASTE_END_B)
    if last_start != -1 and (last_end == -1 or last_end < last_start):
        # a paste is open: hold it and any unterminated line right before it
        prior = max(raw.rfind(b"\r", 0, last_start), raw.rfind(b"\n", 0, last_start))
        return prior + 1 if prior != -1 else 0
    cr = max(raw.rfind(b"\r"), raw.rfind(b"\n"))
    pe = last_end + len(_PASTE_END_B) if last_end != -1 else -1
    cut = max(cr + 1 if cr != -1 else -1, pe)
    return cut if cut != -1 else 0


class _EscInterruptMonitor:
    """Small raw-key watcher used only while the agent is generating."""

    def __init__(self):
        self.event: asyncio.Event = asyncio.Event()
        self.expand_event: asyncio.Event = asyncio.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        # R1 / Example E: instructions typed while the agent streams are captured
        # here (instead of being discarded) so the loop can queue them.
        self._typed = bytearray()
        self._buffer_lock = threading.Lock()
        # Example H: track an in-progress bracketed paste so its content is kept
        # as one instruction and its ESC-bearing end marker never trips interrupt.
        self._in_paste = False
        self._paste_carry = b""

    def _capture(self, data: bytes) -> None:
        with self._buffer_lock:
            self._typed.extend(data)

    def drain_typeahead(self) -> list[str]:
        """Return complete typed-ahead instructions captured during the turn,
        holding back any trailing unterminated fragment (or in-progress paste)
        for the next drain."""
        with self._buffer_lock:
            raw = bytes(self._typed)
            cut = _typeahead_cut_index(raw)
            terminated, tail = raw[:cut], raw[cut:]
            self._typed = bytearray(tail)
            return _parse_typeahead_lines(terminated)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        if not sys.stdin.isatty():
            return
        self._stop.clear()
        self._in_paste = False
        self._paste_carry = b""
        # Example H: enable bracketed paste on the MAIN thread only — never from
        # the reader thread, where a mid-frame write would corrupt Rich's escape
        # stream. Terminals that ignore it degrade to per-line typed-ahead.
        _write_terminal(_ENABLE_BRACKETED_PASTE)
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
        _write_terminal(_DISABLE_BRACKETED_PASTE)

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

    def _dispatch_read(self, data: bytes) -> str:
        """Classify one raw stdin read during streaming, updating paste state and
        capturing typed-ahead/paste bytes. Returns 'expand', 'interrupt' or
        'consumed'. Ctrl-C always interrupts (a safety valve, even mid-paste);
        Ctrl-O / Esc keep their precedence only when *not* inside a paste, so a
        paste's ESC-bearing end marker can never trip interrupt (Example H)."""
        if b"\x03" in data:  # Ctrl-C — always abort, even mid-paste
            return "interrupt"
        if self._in_paste:
            self._capture(data)
            combined = self._paste_carry + data
            if _PASTE_END_B in combined:
                self._in_paste = False
                self._paste_carry = b""
            else:
                self._paste_carry = combined[-(len(_PASTE_END_B) - 1):]
            return "consumed"
        if _PASTE_START_B in data:
            self._in_paste = True
            self._capture(data)
            after = data.split(_PASTE_START_B, 1)[1]
            if _PASTE_END_B in after:  # whole paste arrived in one read
                self._in_paste = False
                self._paste_carry = b""
            else:
                self._paste_carry = after[-(len(_PASTE_END_B) - 1):]
            return "consumed"
        action = _classify_stream_key_chunk(data)
        if action == "expand":
            return "expand"
        if action == "interrupt":
            return "interrupt"
        # Any other bytes are instructions typed while the agent works —
        # capture them for the loop to queue instead of discarding (G3).
        self._capture(data)
        return "consumed"

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
                action = self._dispatch_read(data)
                if action == "expand":
                    self._trigger_expand()
                    continue
                if action == "interrupt":
                    self._trigger()
                    return
                # "consumed": typed-ahead text or paste bytes captured for the queue.
        except Exception:
            return
        finally:
            self._in_paste = False
            self._paste_carry = b""
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


def _osc_progress_sequence(percent: float | None) -> str:
    """OSC 9;4 sequence (ANIM-02): state 1 (normal) at ``percent``, or clear."""
    if percent is None:
        return "\x1b]9;4;0;0\x07"
    pct = max(0, min(100, int(round(percent))))
    return f"\x1b]9;4;1;{pct}\x07"


class Renderer:
    """Antigravity-style terminal renderer."""

    def __init__(self):
        # Read the LIVE module theme (not this module's import-time binding, which
        # set_theme rebinds only on theme.py) so any Renderer built mid-session —
        # e.g. the transient one behind ctrl+r — starts on the current palette.
        from secops_agent.ui import theme as _theme_mod
        self.console = Console(theme=_theme_mod.rich_theme)
        self._theme_pushed = False
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

    def apply_console_theme(self, rich_theme_obj: Any) -> None:
        """Swap the console's active theme to *rich_theme_obj* without growing the
        theme stack. push_theme() stacks, so repeated /theme switches would pile up
        layers (top wins, but the stack leaks). Pop our previous push first, then
        push the current palette, so the stack stays [base, current]."""
        try:
            if getattr(self, "_theme_pushed", False):
                self.console.pop_theme()
                self._theme_pushed = False
            self.console.push_theme(rich_theme_obj)
            self._theme_pushed = True
        except Exception:
            pass

    # ── Static Renders ────────────────────────────────────────────────

    def render_welcome(self):
        """Minimal welcome message."""
        self.console.print(
            f"[{COLORS['text_muted']}]Type a prompt to begin. "
            f"/help for commands.[/{COLORS['text_muted']}]"
        )

    def render_user_input(self, text: str, *, trailing_blank: bool = True, separator: bool = True):
        """Echo a completed prompt once after prompt_toolkit erases redraws.

        Claude-Code style: the user's turn sits on a faint full-width band so the
        eye separates *what I asked* from *what the agent answered* at a glance.
        """
        lines = str(text).splitlines() or [""]
        input_color = COLORS["accent_bright"]
        width = _surface_width(self.console)
        bg = _user_turn_bg()
        if separator:
            self.console.print(f"[{COLORS['text_dim']}]{_turn_separator(width)}[/]")

        def _band(marker: str, body: str) -> None:
            # A faint tint hugs the text (no full-width padding — trailing spaces
            # would pollute scrollback / copy-paste in a real terminal).
            self.console.print(
                f"[{COLORS['accent']} on {bg}]{marker}[/]"
                f"[{input_color} bold on {bg}] {escape(body)}[/]",
                highlight=False,
            )

        _band(">", lines[0])
        for line in lines[1:]:
            _band(" ", line)
        if trailing_blank:
            typography.emit(self.console, Boundary.AFTER_USER_TURN)

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
            SettingsItem("Tool Permission", runtime.permission_mode, "Approval mode for tools and terminal commands", editable=True, options=("plan", "request-review", "proceed-in-sandbox", "always-proceed", "strict")),
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

    def render_theme_picker(
        self,
        *,
        active: str = "",
        status_right: str = "",
        prompt_frame: bool = False,
    ) -> str | None:
        """Interactive theme picker with a live, coloured preview of the pointed
        palette (FMT-05b+). Returns the chosen palette name, or None if cancelled
        or when the surface is not an interactive TTY."""
        if not (sys.stdin.isatty() and sys.stdout.isatty()):
            return None
        from secops_agent.ui import theme as _theme

        names = list(_theme.available_themes())
        if not names:
            return None
        selected = names.index(active) if active in names else 0
        rendered_lines = 0
        chosen: str | None = None

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
            lines = build_theme_picker_lines(
                selected, width=columns, height=content_height, active=active
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
                sys.stdout.write(line + "\n")
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
                    selected = (selected - 1) % len(names)
                elif key == "down":
                    selected = (selected + 1) % len(names)
                elif key == "enter":
                    chosen = names[selected]
                    break
                elif key == "esc":
                    break
        finally:
            clear_rendered()
        return chosen

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

            render_overlay(
                self.console,
                "Diff",
                rows,
                footer="Shows status, stats, and a bounded patch preview for tracked files.",
            )
            # Patch preview with Claude-Code diff colouring: additions on a green
            # background, removals on a red background, hunk/file headers muted.
            if preview.strip():
                self._render_patch_preview(preview, limit=18)
        except Exception as exc:
            self.render_error(f"Unable to read diff: {exc}")

    def _render_patch_preview(self, patch: str, limit: int = 18) -> None:
        """Print a bounded git-patch preview with Claude-Code-style diff colouring:
        + lines on a green background, - lines on a red background, hunk (@@) and
        file headers in muted/accent tones, context lines dim. Within a paired
        -/+ modification the WORDS that actually changed are emphasised (bold) over
        the line's background, so the exact edit stands out."""
        from secops_agent.ui.tool_display import _diff_bg

        add_bg, del_bg = _diff_bg(True), _diff_bg(False)
        pad_w = max(24, min(120, _surface_width(self.console) - 6))
        raw = [line.rstrip() for line in patch.expandtabs(4).splitlines() if line.strip()]
        self.console.print(f"{layout.INDENT_STR}[{COLORS['text_muted']}]Patch preview[/]")

        def _kind(line: str) -> str:
            if line.startswith(("+++", "---", "diff --git", "index ", "new file", "deleted file")):
                return "header"
            if line.startswith("@@"):
                return "hunk"
            if line.startswith("+"):
                return "plus"
            if line.startswith("-"):
                return "minus"
            return "context"

        emitted = 0
        index = 0
        total = len(raw)
        truncated = False
        while index < total and emitted < limit:
            line = raw[index]
            kind = _kind(line)
            if kind == "minus":
                minus_run: list[str] = []
                while index < total and _kind(raw[index]) == "minus":
                    minus_run.append(raw[index])
                    index += 1
                plus_run: list[str] = []
                while index < total and _kind(raw[index]) == "plus":
                    plus_run.append(raw[index])
                    index += 1
                for offset, m_line in enumerate(minus_run):
                    if emitted >= limit:
                        truncated = True
                        break
                    counterpart = plus_run[offset] if offset < len(plus_run) else None
                    self.console.print(self._diff_word_line(m_line, counterpart, minus=True, add_bg=add_bg, del_bg=del_bg, width=pad_w), no_wrap=True, overflow="ellipsis")
                    emitted += 1
                for offset, p_line in enumerate(plus_run):
                    if emitted >= limit:
                        truncated = True
                        break
                    counterpart = minus_run[offset] if offset < len(minus_run) else None
                    self.console.print(self._diff_word_line(p_line, counterpart, minus=False, add_bg=add_bg, del_bg=del_bg, width=pad_w), no_wrap=True, overflow="ellipsis")
                    emitted += 1
                continue
            body = escape(line[:180])
            if kind == "header":
                style = COLORS["text_muted"]
            elif kind == "hunk":
                style = f"bold {COLORS['accent']}"
            elif kind == "plus":
                style = f"{COLORS['success']} on {add_bg}"
            else:
                style = COLORS["text_dim"]
            self.console.print(f"{layout.INDENT_STR}[{style}]{body}[/]", no_wrap=True, overflow="ellipsis")
            emitted += 1
            index += 1

        if truncated or index < total:
            hidden = len([line for line in raw[index:] if line.strip()]) if index < total else 0
            self.console.print(f"{layout.INDENT_STR}[{COLORS['text_dim']}]... {max(hidden, 1):,} more line(s) hidden[/]")

    def _diff_word_line(self, line, counterpart, *, minus, add_bg, del_bg, width):
        """Build a Rich Text for one +/- diff line. When a counterpart line is
        present, the words that differ (vs the counterpart) are bold so the exact
        change pops over the green/red background; unchanged words stay plain."""
        import difflib
        import re as _re
        from rich.text import Text

        bg = del_bg if minus else add_bg
        fg = COLORS["error"] if minus else COLORS["success"]
        base = f"{fg} on {bg}"
        strong = f"bold {fg} on {bg}"
        marker = "- " if minus else "+ "
        body = line[1:]

        text = Text(layout.INDENT_STR)  # indent carries no background
        text.append(marker, style=base)
        if counterpart is None:
            text.append(body, style=base)
        else:
            def _toks(value: str) -> list[str]:
                return _re.findall(r"\s+|\S+", value)
            mine = _toks(body)
            theirs = _toks(counterpart[1:])
            a, b = (mine, theirs) if minus else (theirs, mine)
            matcher = difflib.SequenceMatcher(a=a, b=b, autojunk=False)
            for op, i1, i2, j1, j2 in matcher.get_opcodes():
                segment = "".join((a[i1:i2] if minus else b[j1:j2]))
                if segment:
                    text.append(segment, style=base if op == "equal" else strong)
        pad = width - text.cell_len
        if pad > 0:
            text.append(" " * pad, style=base)  # extend the background to a bar
        return text

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

    def render_plan(self, plan: Any) -> None:
        """Render the mission plan as a distinct, reviewable block (audit item #7).

        The plan is a trust artifact — its own titled block (scope, numbered steps
        with risk labels, which need approval), never folded into reasoning text.
        """
        steps = list(getattr(plan, "steps", []) or [])
        scope = list(getattr(plan, "scope_snapshot", []) or [])
        rows: List[OverlayRow] = [
            OverlayRow(
                "Scope",
                ", ".join(scope) if scope else "unrestricted (no explicit in-scope target)",
                accent=True,
            )
        ]
        if not steps:
            rows.append(OverlayRow("Steps", "no candidate steps proposed"))
        for idx, step in enumerate(steps, start=1):
            detail = getattr(step, "title", "") or getattr(step, "tool_name", "") or "step"
            markers = [getattr(step, "risk_label", "") or "recon"]
            if getattr(step, "needs_approval", False):
                markers.append("needs approval")
            status = getattr(step, "status", "planned")
            if status and status != "planned":
                markers.append(status)
            rows.append(
                OverlayRow(str(idx), f"{detail}  ·  {'  ·  '.join(markers)}",
                           accent=bool(getattr(step, "active", False)))
            )
        divergences = list(getattr(plan, "divergences", []) or [])
        if divergences:
            rows.append(OverlayRow("Diverged", ", ".join(divergences)))
        if getattr(plan, "acknowledged", False):
            footer = "Plan acknowledged — each step is still gated individually by the permission engine."
        else:
            footer = "Acknowledge once to run the recon chain unattended; each high-risk step still prompts. (/plan to review)"
        render_overlay(self.console, "Mission Plan", rows, footer=footer)

    def _request_plan_acknowledgment(self, timeout: float = 60.0) -> bool:
        """Compact one-key confirm for a mission plan preview. ``enter``/``y``/``a``
        acknowledge; ``esc``/``n``/``d``/timeout decline. Non-TTY declines (the
        print path resolves the acknowledgment on its own side)."""
        import sys
        import termios
        import tty

        if not sys.stdin.isatty():
            return False
        self.console.print(
            f"{layout.INDENT_STR}[{COLORS['text_muted']}]Acknowledge this plan?  "
            f"[{COLORS['accent']}]enter[/] proceed   "
            f"[{COLORS['text_muted']}]esc[/] decline[/]"
        )
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            key = read_terminal_key(fd, input_timeout=timeout)
        finally:
            termios.tcsetattr(fd, termios.TCSANOW, old_settings)
        if key == "enter":
            return True
        return len(key) == 1 and key.lower() in {"y", "a"}

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
                f"{layout.INDENT_STR}[{COLORS['text_muted']}]Retry the same prompt, or /model to switch models.[/{COLORS['text_muted']}]"
            )
        typography.emit(self.console, Boundary.SECTION_BREAK)

    def render_warning(self, message: str):
        """Render a compact command warning."""
        self.console.print(f"{layout.INDENT_STR}[{COLORS['warning']}]⎿  {message}[/{COLORS['warning']}]")
        typography.emit(self.console, Boundary.SECTION_BREAK)

    def render_status(self, message: str):
        self.console.print(f"{layout.INDENT_STR}[{COLORS['text_muted']}]⎿  {message}[/{COLORS['text_muted']}]")
        typography.emit(self.console, Boundary.SECTION_BREAK)

    def render_success(self, message: str):
        self.console.print(f"{layout.INDENT_STR}[{COLORS['success']}]⎿  {message}[/{COLORS['success']}]")
        typography.emit(self.console, Boundary.SECTION_BREAK)

    def render_command_result(self, message: str):
        self.console.print(f"{layout.INDENT_STR}[{COLORS['text_muted']}]⎿  {message}[/{COLORS['text_muted']}]")
        typography.emit(self.console, Boundary.SECTION_BREAK)

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
                        _StripTrailingWhitespace(
                            _agent_markdown(content, width=_surface_width(self.console), bullet=True)
                        )
                    )
                    # text↔tool boundary — same rhythm token as the streaming path.
                    typography.emit(self.console, Boundary.BEFORE_TOOL_GROUP)
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
        typography.emit(self.console, Boundary.SECTION_BREAK)

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

    def _print_wrapped_muted_lines(self, text: str, *, indent: str = layout.INDENT_STR, max_lines: int = 40) -> None:
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

        # Clear the currently-drawn collapsed block so the expansion replaces it
        # in place, rather than stacking below and leaving leftover preview
        # lines (e.g. a dangling "── OS ──"). No-op when already cleared.
        if bool(getattr(self.console, "is_terminal", False)) and self._latest_transcript_rendered_lines > 0:
            if self._clear_terminal_lines(self._latest_transcript_rendered_lines):
                self._latest_transcript_rendered_lines = 0

        call_text = format_tool_call_text(self._latest_tool_name, self._latest_tool_arguments)
        result = self._latest_tool_result
        indicator_color = _tool_status_color(status=_tool_result_status(result))
        typography.emit(self.console, Boundary.SECTION_BREAK)
        collapse_hint = (
            f" [{COLORS['text_muted']}](ctrl+o to collapse)[/{COLORS['text_muted']}]"
            if result is None else ""
        )
        self.console.print(
            f"[{indicator_color}]⏺[/{indicator_color}] "
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
        first_line = _fit_cell(_result_headline(result, lines[0]), max(16, _surface_width(self.console) - 34))
        self.console.print(
            f"{layout.INDENT_STR}[{COLORS['text_muted']}]⎿  {escape(first_line)} "
            f"(ctrl+o to collapse)[/{COLORS['text_muted']}]",
            no_wrap=True,
            overflow="ellipsis",
        )
        rendered_lines += 1
        if len(lines) > 1:
            typography.emit(self.console, Boundary.SECTION_BREAK)
            self.console.print(f"{layout.INDENT_STR}[{COLORS['text_muted']}]Output:[/{COLORS['text_muted']}]")
            rendered_lines += 2
            # Streaming ctrl+o expands *inline* with plain print + cursor-up clear.
            # If the block is taller than the room below the cursor, printing it
            # scrolls older rows into scrollback that cursor-up can never re-enter,
            # so every toggle restacks a copy (the 5-6x cascade the streaming-text
            # path was hardened against). Keep the inline preview to ~half the
            # viewport so the block always clears in place; the full output stays
            # one keystroke away via the post-turn ctrl+o surface / /trajectory.
            surface_height = _surface_height(self.console)
            visible_limit = max(
                4,
                min(_ctrl_o_output_visible_limit(self.console), surface_height // 2 - 4),
            )
            visible_lines = lines[:visible_limit]
            output_width = max(16, _surface_width(self.console) - 6)
            for line in visible_lines:
                self.console.print(
                    f"{layout.INDENT_STR * 2}[{COLORS['text_dim']}]{escape(_fit_cell(line, output_width))}[/{COLORS['text_dim']}]",
                    no_wrap=True,
                    overflow="ellipsis",
                )
            rendered_lines += len(visible_lines)
            if len(lines) > len(visible_lines):
                self.console.print(
                    f"{layout.INDENT_STR * 2}[{COLORS['text_dim']}]... {len(lines) - len(visible_lines):,} more lines hidden[/{COLORS['text_dim']}]",
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
        typography.emit(self.console, Boundary.SECTION_BREAK)
        self.console.print(
            f"[{COLORS['accent']}]▾[/{COLORS['accent']}] "
            f"[{COLORS['text_muted']}]Thought for {duration}s[/{COLORS['text_muted']}]"
        )
        self._print_wrapped_muted_lines(self._latest_thought_content, indent=layout.INDENT_STR)
        self._latest_transcript_expanded = True
        return True

    def _render_latest_transcript_expansion(self) -> bool:
        if self._render_inline_tool_expansion():
            return True
        return self._render_inline_thought_expansion()

    def _draw_collapsed_result(self) -> int:
        """Draw the collapsed ⏺ + ⎿ result block; return the lines printed."""
        status = _tool_result_status(self._latest_tool_result)
        n = ToolCallBox.render(
            self.console,
            self._latest_tool_name,
            self._latest_tool_arguments,
            status=status,
            leading_blank=False,
            show_expand_tag=(status == "error"),
        )
        if self._latest_tool_result is not None:
            n += ToolResultBox.render(self.console, self._latest_tool_name, self._latest_tool_result)
        return n

    def _render_inline_tool_collapse(self) -> bool:
        if not self._latest_tool_name:
            return False
        rendered_lines = self._latest_transcript_rendered_lines
        cleared = self._clear_terminal_lines(rendered_lines)
        if cleared:
            # Redraw the collapsed block in place of the cleared expansion so
            # the toggle replaces (rather than stacks) the view.
            self._latest_transcript_expanded = False
            self._latest_transcript_rendered_lines = self._draw_collapsed_result()
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
        typography.emit(self.console, Boundary.SECTION_BREAK)
        self.console.print(
            f"[{COLORS['accent']}]▸[/{COLORS['accent']}] "
            f"[{COLORS['text_muted']}]Thought for {duration}s[/{COLORS['text_muted']}]"
        )
        preview = self._latest_thought_content.strip().replace("\n", " ")
        if len(preview) > 120:
            preview = preview[:117] + "..."
        if preview:
            self.console.print(f"{layout.INDENT_STR}[{COLORS['text_dim']}]{escape(preview)}[/{COLORS['text_dim']}]")
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

    def _start_thinking(self, status_right: str = "", mission_phase: str = ""):
        """Record thinking start time."""
        # Defensively stop a spinner still running from a prior thinking phase so
        # two Live displays never stack (mirrors _start_tool_feedback → R2 latent).
        if self._thinking_spinner is not None:
            with contextlib.suppress(Exception):
                self._thinking_spinner.stop()
            self._thinking_spinner = None
        self._thinking_start = time.monotonic()
        self._thinking_content = ""
        self._thinking_spinner = ThinkingSpinner(
            thinking_label_for_phase(mission_phase),
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

        typography.emit(self.console, Boundary.SECTION_BREAK)

        # agy renders the collapsed thought as "▸ Thought for Xs" then its content on
        # the next indented line (verified against live agy 2026-07-05), not inline.
        self.console.print(
            f"[{COLORS['accent']}]▸[/{COLORS['accent']}] "
            f"[{COLORS['text_muted']}]Thought for {duration}s[/{COLORS['text_muted']}]"
        )
        if self._latest_thought_content:
            self._print_wrapped_muted_lines(self._latest_thought_content, indent=layout.INDENT_STR)

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
        self._emit_terminal_progress(None)

    def _emit_terminal_progress(self, percent: float | None) -> None:
        """ANIM-02: mirror scan progress to the host terminal's taskbar/tab via
        OSC 9;4 (WezTerm, Windows Terminal, ConEmu...).  No-op off a TTY or under
        reduced motion; percent=None clears it."""
        if not bool(getattr(self.console, "is_terminal", False)) or reduced_motion():
            return
        output = getattr(self.console, "file", None)
        if output is None:
            return
        with contextlib.suppress(Exception):
            output.write(_osc_progress_sequence(percent))
            output.flush()

    def _update_tool_feedback(self, phase: str, detail: str = "", percent: float | None = None):
        """Update the active tool spinner with structured progress."""
        if not self._tool_spinner:
            return
        self._tool_spinner.update_phase(phase, detail, percent)
        if percent is not None:
            self._emit_terminal_progress(percent)

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
        typography.emit(self.console, Boundary.SECTION_BREAK)
        self.console.print(f"{layout.INDENT_STR}[{COLORS['text']}]Suggested next actions:[/{COLORS['text']}]")
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
            self.console.print(f"{layout.INDENT_STR}{index}. [{COLORS['text']}]{title}[/{COLORS['text']}]{detail}")
            # §5 (mission anchor): ground each suggestion in current mission
            # state — lead with the rationale, append the concrete discovered
            # fact (evidence) that motivated it. This is distinct from the
            # cross-mission "Lesson:" line below.
            if self._display_prefs.get("show_rationale", True):
                rationale = str(getattr(action, "rationale", "") or "").strip()
                evidence_items = [
                    str(item).strip()
                    for item in (getattr(action, "evidence", []) or [])
                    if str(item).strip()
                ]
                anchor = rationale if rationale and rationale != title else ""
                if evidence_items:
                    anchor = f"{anchor} — {evidence_items[0]}" if anchor else evidence_items[0]
                if anchor:
                    self.console.print(
                        f"{layout.RESULT_INDENT_STR}[{COLORS['text_muted']}]Why: {escape(anchor)}[/{COLORS['text_muted']}]"
                    )
            # §5: one concise experience reason per suggestion; verbose
            # Match:/Missing: learning internals stay hidden.
            if self._display_prefs.get("show_experience", True):
                # Only surface real cross-mission lessons; skip internal
                # "suggestion learning" telemetry that also rides on .experience.
                lessons = [
                    text
                    for text in (str(item).strip() for item in (getattr(action, "experience", []) or []))
                    if text and not text.lower().startswith("suggestion learning")
                ]
                if lessons:
                    self.console.print(
                        f"{layout.RESULT_INDENT_STR}[{COLORS['text_muted']}]Lesson: {escape(lessons[0])}[/{COLORS['text_muted']}]"
                    )
        self.console.print(f"{layout.INDENT_STR}[{COLORS['text_muted']}]Reply with a number or describe what to do next.[/{COLORS['text_muted']}]")

    # ── Agent Stream Rendering ────────────────────────────────────────

    async def render_agent_stream(
        self,
        event_stream: AsyncIterator[AgentEvent],
        status_right: str = "",
        mission_phase: str = "",
        *,
        memory: Any | None = None,
        runtime: RuntimeState | None = None,
    ):
        """
        Antigravity-style streaming:
        - ▸ Thought for Xs (with content preview)
        - 2-space indented narrative text
        - ⏺ ToolName(args) collapsed
        - ⚠ for errors/warnings
        """
        text_accumulator = ""
        live_display: Live | None = None
        last_render_time: float = 0.0
        is_thinking = False
        turn_start = time.monotonic()
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
            """Build Antigravity-style indented Markdown display (P2: prose
            width-capped on wide terminals via the shared helper)."""
            return _agent_markdown(text, width=_surface_width(self.console))

        def _live_tail(text: str) -> str:
            try:
                height = int(getattr(self.console.size, "height", 0) or 0)
            except Exception:
                height = 0
            return _streaming_tail(text, height)

        def _on_resize() -> None:
            # Debounced SIGWINCH (P2): re-wrap the active live frame at the new
            # terminal width immediately, without waiting for the next streamed
            # token — so a mid-stream resize (or a stalled stream) never leaves a
            # stale-width frame on screen. Rebuilt from the accumulator so it
            # reflows correctly; committed scrollback relies on terminal reflow.
            if live_display is not None:
                with contextlib.suppress(Exception):
                    live_display.update(_build_display(_live_tail(text_accumulator)))
                    live_display.refresh()

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
                # Committed turn (not the live tail) → hang the ⏺ turn bullet.
                self.console.print(_StripTrailingWhitespace(
                    _agent_markdown(text_accumulator, width=_surface_width(self.console), bullet=True)
                ))
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
                    thinking_label_for_phase(mission_phase),
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
                    # Example F: cap the Live to the viewport. With "visible", a render
                    # taller than the screen scrolls into scrollback that cursor-up
                    # cannot reach, so each redraw restacks it (the 5-6x cascade).
                    vertical_overflow="crop",
                )
                live_display.start()

        resize_debouncer = layout.ResizeDebouncer(_on_resize)
        with contextlib.suppress(Exception):
            resize_debouncer.install(asyncio.get_running_loop())
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
                            f"{layout.INDENT_STR}[{COLORS['text_muted']}]{event.message}[/{COLORS['text_muted']}]"
                        )

                elif isinstance(event, ThinkingEvent):
                    if not is_thinking:
                        is_thinking = True
                        self._start_thinking(status_right=status_right, mission_phase=mission_phase)

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
                            vertical_overflow="crop",  # Example F: see note above
                        )
                        live_display.start()
                        last_render_time = time.monotonic()

                    if event.done:
                        _flush_live_text()
                        # text↔tool boundary — single-sourced via the rhythm token
                        # (same rule the replay path uses); the printed-blank count
                        # drives ctrl+o line-accounting.
                        _advance_ctrl_o_tail(
                            typography.emit(self.console, Boundary.BEFORE_TOOL_GROUP)
                        )
                    else:
                        text_accumulator += event.content
                        # Throttled re-render: max ~20fps
                        if live_display:
                            now = time.monotonic()
                            if (now - last_render_time) >= _RENDER_INTERVAL:
                                live_display.update(_build_display(_live_tail(text_accumulator)))
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

                elif isinstance(event, PlanPreviewEvent):
                    if is_thinking:
                        _finish_active_thinking()

                    if live_display:
                        _flush_live_text()

                    self._stop_tool_feedback()
                    self.render_plan(event.plan)
                    # acknowledgment_future is None when the plan was auto-acknowledged
                    # (SANDBOX / print): render the block for the record, no prompt.
                    future = event.acknowledgment_future
                    if future is not None and not future.done():
                        await interrupt.stop()
                        acknowledged = self._request_plan_acknowledgment()
                        interrupt.clear()
                        interrupt.start()
                        if not future.done():
                            future.set_result(acknowledged)

                elif isinstance(event, PlanDivergenceEvent):
                    reason = f" — {escape(event.reason)}" if event.reason else ""
                    self.console.print(
                        f"{layout.INDENT_STR}[{COLORS['warning']}]⚠ unplanned step: {escape(event.tool_name)}[/]"
                        f"[{COLORS['text_dim']}]{reason}[/]"
                    )

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
                    # In a TTY the animated spinner (which now carries the tool
                    # name) is the sole running indicator — skip the static ⏺
                    # row to avoid a redundant double indicator and a premature
                    # "(ctrl+o to expand)" tag. In a non-TTY (pipes, CI, captured
                    # transcript) the spinner does not animate, so print the
                    # static row there to keep the running tool visible.
                    if bool(getattr(self.console, "is_terminal", False)):
                        self._running_tool_row_lines = 0
                    else:
                        self._running_tool_row_lines = ToolCallBox.render_running(
                            self.console,
                            event.name,
                            self._latest_tool_arguments,
                            leading_blank=False,
                            show_expand_tag=False,
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
                    collapsed_line_count = 0
                    if keep_result_expanded and expanded_surface_cleared:
                        self._render_inline_tool_expansion()
                    elif keep_result_expanded and bool(getattr(self.console, "is_terminal", False)):
                        self._latest_transcript_expanded = True
                    elif not had_pending_call or pending_call_cleared:
                        # ✅ agy grouping: suppress (ctrl+o) on the ⏺ line when the
                        # ⎿ result summary below carries it. Error results render
                        # inline without that affordance, so the ⏺ line keeps it.
                        collapsed_line_count += ToolCallBox.render(
                            self.console,
                            event.name,
                            self._latest_tool_arguments,
                            status=result_status,
                            leading_blank=False,
                            show_expand_tag=(result_status == "error"),
                        )
                    if not keep_result_expanded:
                        # Track the collapsed block's exact line count so the
                        # ctrl+o toggle can clear it before drawing the
                        # expansion (no leftover preview lines).
                        collapsed_line_count += ToolResultBox.render(
                            self.console, event.name, event.result
                        )
                        self._latest_transcript_rendered_lines = collapsed_line_count
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

            # Sobre end-of-turn marker: a single discreet line, shown only for a
            # turn that did real work AND fully succeeded (≥1 tool, none failed) —
            # a plain answer is its own completion, and a failure is already spelled
            # out on its ⎿ line, so neither prints a ✓. Static text (no motion),
            # counted into the ctrl+o tail so an in-place expand stays aligned.
            tool_statuses = [
                _tool_result_status(item.get("result"))
                for item in turn_items
                if item.get("kind") == "tool" and item.get("result") is not None
            ]
            all_succeeded = bool(tool_statuses) and all(status == "success" for status in tool_statuses)
            if all_succeeded and not self._display_prefs.get("hide_turn_summary"):
                elapsed = time.monotonic() - turn_start
                count = len(tool_statuses)
                label = f"{count} tool" + ("s" if count != 1 else "")
                tail = f" · {format_duration(elapsed)}" if elapsed >= 0.1 else ""
                self.console.print(
                    f"{layout.INDENT_STR}[{COLORS['success']}]✓[/] [{COLORS['text_muted']}]{label}{tail}[/{COLORS['text_muted']}]"
                )
                _advance_ctrl_o_tail(1)

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
            with contextlib.suppress(Exception):
                resize_debouncer.uninstall()
        # Instructions typed while the agent was streaming, for the loop to queue.
        return interrupt.drain_typeahead()
