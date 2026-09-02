"""Panel/view line builders (extracted from renderer.py).

Pure functions that turn state into terminal line lists for the settings,
context, hooks, MCP, skills, artifacts, attachments, agents, tools, and help
overlays. No dependency on the Renderer class.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from rich.markup import escape

from secops_agent import __version__
from secops_agent.ui.theme import COLORS, friendly_model_name
from secops_agent.ui.commands import iter_commands
from secops_agent.ui.runtime import RuntimeState
from secops_agent.ui import layout
from secops_agent.ui.spool_display import supervised_detail_text
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
    ("shift+tab", "Cycle permission mode"),
    ("tab", "Complete highlighted slash command"),
    ("up", "Move up"),
    ("?", "Open this help"),
)
_HELP_SHORTCUT_LABELS = {label for label, _ in _HELP_SHORTCUTS}

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

    search_label = f"{layout.INDENT_STR}Search: {search_query}" if search_query else f"{layout.INDENT_STR}Search:"
    lines = ["", "Settings", "", search_label, " ────────────────────", ""]
    if not filtered_items:
        lines.append(f"{layout.INDENT_STR}No settings match.")
    for index, item in enumerate(visible, start=start):
        cursor = "> " if index == selected else "  "
        label = _fit_cell(item.label, label_width).ljust(label_width)
        if editing_index == index:
            lines.append(f"{layout.INDENT_STR}{_fit_cell(item.label, label_width).rstrip()}")
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
            lines.append(f"{layout.INDENT_STR}↑ {hidden_above} more")
        if hidden_below:
            lines.append(f"{layout.INDENT_STR}↓ {hidden_below} more")

    if filtered_items:
        lines.append("")
        lines.append(f"{layout.INDENT_STR}{_fit_cell(filtered_items[selected].description, max(24, width - 4))}")

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
        lines.append(f"{layout.INDENT_STR}{len(servers)} configured · {len(enabled)} enabled · {running} running · {tools} tools")
        lines.append("")

    for index, item in enumerate(visible, start=start):
        cursor = "> " if index == selected else "  "
        lines.append(_fit_cell(f"{cursor}{item.label}", width))
        if item.detail:
            lines.append(_fit_cell(f"{layout.INDENT_STR}{item.detail}", width))

    if len(items) > visible_count:
        hidden_above = start
        hidden_below = max(0, len(items) - start - len(visible))
        if hidden_above:
            lines.append(f"{layout.INDENT_STR}↑ {hidden_above} more")
        if hidden_below:
            lines.append(f"{layout.INDENT_STR}↓ {hidden_below} more")

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
        lines.append(f"{layout.INDENT_STR}{len(skills)} loaded · {workspace_count} workspace · {global_count} global")
        lines.append("")

    for index, item in enumerate(visible, start=start):
        cursor = "> " if index == selected else "  "
        lines.append(_fit_cell(f"{cursor}{item.label}", width))
        if item.detail:
            lines.append(_fit_cell(f"{layout.INDENT_STR}{item.detail}", width))

    if len(items) > visible_count:
        hidden_above = start
        hidden_below = max(0, len(items) - start - len(visible))
        if hidden_above:
            lines.append(f"{layout.INDENT_STR}↑ {hidden_above} more")
        if hidden_below:
            lines.append(f"{layout.INDENT_STR}↓ {hidden_below} more")

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

    # Findings lead (audit item #7 / T2.2): a discovery-ordered digest of the
    # `finding` artifacts, above the raw evidence registry. Additive summary only —
    # it does not reorder or renumber the nav index below, which still spans every
    # artifact.
    finding_artifacts = [a for a in artifacts if getattr(a, "kind", "") == "finding"]
    finding_summary: list[str] = []
    if finding_artifacts:
        finding_summary.append("")
        finding_summary.append(f"{layout.INDENT_STR}Findings ({len(finding_artifacts)})")
        for artifact in finding_artifacts[:6]:
            severity = str((getattr(artifact, "metadata", {}) or {}).get("severity", "")).strip()
            tag = f"[{severity}] " if severity else ""
            finding_summary.append(_fit_cell(f"{layout.INDENT_STR * 2}• {tag}{artifact.title}", width))
        if len(finding_artifacts) > 6:
            finding_summary.append(f"{layout.INDENT_STR * 2}… and {len(finding_artifacts) - 6} more")

    fixed_rows = 5 + (7 if has_detail else 0) + len(finding_summary)
    visible_count = min(len(artifacts), max(1, height - fixed_rows))
    start = _settings_window_start(selected, len(artifacts), visible_count)
    visible = artifacts[start:start + visible_count]

    lines = ["", title]
    lines.extend(finding_summary)
    if not artifacts:
        lines.append(f"{layout.INDENT_STR}{empty_message}")
    else:
        lines.append("")
        for index, artifact in enumerate(visible, start=start):
            cursor = "> " if index == selected else "  "
            lines.append(_fit_cell(f"{cursor}{artifact.id:<6} {artifact.title}", width))
            lines.append(_fit_cell(f"{layout.INDENT_STR}{_artifact_row_detail(artifact)}", width))

        if len(artifacts) > visible_count:
            hidden_above = start
            hidden_below = max(0, len(artifacts) - start - len(visible))
            if hidden_above:
                lines.append(f"{layout.INDENT_STR}↑ {hidden_above} more")
            if hidden_below:
                lines.append(f"{layout.INDENT_STR}↓ {hidden_below} more")

    if has_detail:
        artifact = artifacts[selected]
        if detail_mode == "preview":
            preview_line = _artifact_preview_line(artifact)
            lines.extend(
                [
                    "",
                    f"Preview: {artifact.id} · {artifact.title}",
                    f"{layout.INDENT_STR}Kind: {artifact.kind}",
                    f"{layout.INDENT_STR}Source: {_artifact_source_label(artifact)}",
                ]
            )
            if preview_line:
                lines.append(f"{layout.INDENT_STR}{preview_line}")
        else:
            lines.extend(
                [
                    "",
                    f"Open: {artifact.id} · {artifact.title}",
                    f"{layout.INDENT_STR}Kind: {artifact.kind}",
                    f"{layout.INDENT_STR}Source: {_artifact_source_label(artifact)}",
                    "",
                    f"{layout.INDENT_STR}Content:",
                ]
            )
            lines.extend(_fit_cell(f"{layout.INDENT_STR * 2}{line}", width) for line in _artifact_content_lines(artifact, max_lines=12))

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
        f"{layout.INDENT_STR}Workspace: {_display_path(workspace_template)}",
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
                lines.append(f"{layout.INDENT_STR}↑ {hidden_above} more")
            if hidden_below:
                lines.append(f"{layout.INDENT_STR}↓ {hidden_below} more")
        if active_task_count == 0:
            lines.extend(["", f"{layout.INDENT_STR}No background subagents are active."])
        if profile_count == 0:
            lines.append(f"{layout.INDENT_STR}No configured agent profiles.")

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
    prefix = f"{layout.INDENT_STR}SecOps Tools   " if framed else "SecOps Tools   "
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
        lines.append(f"{layout.INDENT_STR}No tools registered.")
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
        lines.append(f"{layout.INDENT_STR}[{start + 1}-{end} of {len(rows)} tools]")

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
    tab_prefix = f"{layout.INDENT_STR}SecOps CLI" if framed else "SecOps CLI"
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
        lines.append(f"{layout.INDENT_STR}[{start}-{end} of {count_total} items]")
    elif total > visible_count:
        start = offset + 1
        end = offset + len(visible_items)
        lines.append(f"{layout.INDENT_STR}[{start}-{end} of {total} items]")

    while fill and len(lines) < height - 2:
        lines.append("")
    if framed:
        lines.append(divider)
    lines.append(f"{layout.INDENT_STR}Keyboard: ↑/↓ Navigate  ←/→ Switch View  esc Close")
    return [_fit_cell(line, width) for line in lines[:height]]


