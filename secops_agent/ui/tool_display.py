"""
Tool display components matching Antigravity CLI style exactly.
Uses ⏺ prefix, compact single-line format, collapsed results.
"""

from __future__ import annotations

import re
from typing import Dict, Any

from rich.console import Console
from rich.markup import escape

from secops_agent.core.tools import ToolResult, ToolRiskClass, registry as tool_registry
from secops_agent.core.permissions import ApprovalDecision, ApprovalScope, PermissionResource
from secops_agent.ui.theme import COLORS
from secops_agent.ui import layout
from secops_agent.ui.spool_display import should_show_spool_reference, spool_reference

__all__ = [
    "ToolCallBox", "ToolResultBox", "ApprovalPrompt",
    "format_duration", "format_tool_call_text", "truncate_output", "summarize_output",
    "reset_session_permissions", "_tool_result_log_reference_line",
    "build_collapsed_result_lines",
]


_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def reset_session_permissions():
    """Backward-compatible no-op; permissions live in PermissionEngine now."""
    return None


# ── Helpers ───────────────────────────────────────────────────────────

def format_duration(seconds: float) -> str:
    if seconds < 0.001:
        return "<1ms"
    if seconds < 1.0:
        return f"{seconds * 1000:.0f}ms"
    if seconds < 60:
        return f"{seconds:.2f}s"
    minutes = int(seconds // 60)
    secs = seconds % 60
    return f"{minutes}m {secs:.1f}s"


def truncate_output(text: str, max_chars: int = 2000) -> str:
    """Truncate long output with head + tail preservation."""
    if not text or len(text) <= max_chars:
        return text

    head_budget = int(max_chars * 0.8)
    tail_budget = max_chars - head_budget
    hidden = len(text) - max_chars

    head = text[:head_budget]
    tail = text[-tail_budget:]

    return (
        f"{head}\n\n"
        f"  ... (+{hidden:,} chars hidden) ...\n\n"
        f"{tail}"
    )


def _strip_ansi(text: str) -> str:
    """Remove terminal control sequences before rendering compact previews."""
    return _ANSI_ESCAPE_RE.sub("", text)


def _fit_display(text: str, width: int) -> str:
    """Cell-accurate truncation (P2); delegates to the central layout layer
    (which strips ANSI and collapses newlines before measuring)."""
    return layout.fit_cell(text, width)


_DECORATION_CHARS = frozenset(
    "=-_~*#.+| "
    "─━│┃┌┐└┘├┤┬┴┼╔╗╚╝═║╠╣╦╩╬▔▁▎▏"
)


def _is_noise_line(line: str) -> bool:
    """A purely decorative line (separator, banner rule, TOOL DATA marker).

    Such lines carry no result content; leading the collapsed preview with
    them buries the key fact, so they are skipped when substance exists.
    """
    stripped = line.strip()
    if not stripped:
        return True
    if "TOOL DATA" in stripped.upper():
        return True
    if all(ch in _DECORATION_CHARS for ch in stripped):
        return True
    # Section rule around a short label, e.g. "── Network ──".
    core = stripped.strip("─-=_~ ").strip()
    if core != stripped and len(core) <= 16:
        return True
    # Emoji/symbol banner with no value, e.g. "🖥️ System Information".
    if ":" not in stripped and not stripped[:1].isascii():
        return True
    return False


def summarize_output(text: str, max_lines: int = 6, max_width: int = 110) -> Dict[str, Any]:
    """Build a compact, stable preview while keeping the full output elsewhere.

    Leads with the first substantive line: decorative separators, banner rules,
    and TOOL DATA markers are skipped so the fold opens on the key fact rather
    than on noise (only falling back to them when no substance exists).
    """
    if not text:
        return {
            "lines": [],
            "total_lines": 0,
            "visible_lines": 0,
            "hidden_lines": 0,
            "chars": 0,
            "truncated_lines": 0,
        }

    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    raw_lines = normalized.splitlines()
    non_empty_lines = []
    for raw_line in raw_lines:
        line = _strip_ansi(raw_line).expandtabs(4).rstrip()
        if line.strip():
            non_empty_lines.append(line)

    substantive = [line for line in non_empty_lines if not _is_noise_line(line)]
    preview_lines = substantive or non_empty_lines

    visible = []
    truncated_lines = 0
    safe_width = max(24, max_width)
    for line in preview_lines[:max_lines]:
        if len(line) > safe_width:
            line = line[: safe_width - 3] + "..."
            truncated_lines += 1
        visible.append(line)

    return {
        "lines": visible,
        "total_lines": len(raw_lines),
        "visible_lines": len(visible),
        "hidden_lines": max(0, len(preview_lines) - len(visible)),
        "chars": len(text),
        "truncated_lines": truncated_lines,
    }


def _looks_like_tool_failure(text: str) -> bool:
    """Detect tool functions that signal failure in text instead of raising."""
    first_line = str(text or "").lstrip().splitlines()[0] if str(text or "").strip() else ""
    lowered = first_line.casefold()
    if first_line.startswith(("❌", "✗")):
        return True
    if lowered.startswith(
        (
            "error:",
            "failed:",
            "failure:",
            "permission denied",
            "sandbox blocked",
            "command timed out",
        )
    ):
        return True
    return bool(re.match(r"^[a-z][a-z0-9 _./-]{0,80}\s+failed:", lowered))


def _is_passive_tool(tool_name: str) -> bool:
    """Check if a tool is passive using TOOL_TIERS or dynamic fallback."""
    try:
        from secops_agent.core.permissions import TOOL_TIERS, ActionTier
        tier = TOOL_TIERS.get(tool_name)
        if tier == ActionTier.PASSIVE:
            return True
    except Exception:
        pass

    try:
        from secops_agent.core.tools import registry, ToolRiskClass
        tool_def = registry.get_tool(tool_name)
        if tool_def:
            rc = tool_def.risk_class
            if rc in (
                ToolRiskClass.PURE_LOCAL_COMPUTATION,
                ToolRiskClass.LOCAL_OBSERVATION,
                ToolRiskClass.NETWORK_OBSERVATION,
                ToolRiskClass.LOCAL_FILE_ACCESS
            ):
                return True
    except Exception:
        pass
    return False


def _tool_risk_badge(tool_name: str) -> str:
    """Return a compact, always-visible risk class for transcript rows.

    Approval dialogs already show a verbose risk label, but the normal stream is
    where an operator scans many actions quickly.  Resolve against the live
    registry so dynamically registered MCP tools retain their r7 distinction.
    """
    try:
        tool_def = tool_registry.get_tool(tool_name)
        risk_class = getattr(tool_def, "risk_class", None) if tool_def else None
        value = str(getattr(risk_class, "value", risk_class) or "")
        match = re.match(r"r([0-8])_", value)
        if match:
            return f"R{match.group(1)}"
    except Exception:
        pass
    return "R?"


# ── FMT-01: severity-tiered risk badge colour ───────────────────
# The R0-R8 badge is rendered on every transcript row; colour it by tier so a
# destructive action (R6-R8) is not visually identical to a passive observation
# (R0-R2). The ramp stays inside the theme's "colour austerity": quiet grey for
# passive tiers, amber for active/privileged, red for offensive/remote.
_RISK_BADGE_COLOR_KEY = {
    0: "text_muted",
    1: "text_muted",
    2: "text_muted",
    3: "warning",
    4: "warning",
    5: "warning",
    6: "danger",
    7: "danger",
    8: "danger_bright",
}


def _risk_badge_markup(tool_name: str) -> str:
    """Return the risk badge (e.g. ``R5``) wrapped in severity-tiered Rich
    markup (FMT-01).  Unknown/unresolved tiers keep the muted grey the badge
    used before, so nothing regresses when a tier cannot be resolved."""
    badge = _tool_risk_badge(tool_name)
    match = re.match(r"R([0-8])$", badge)
    if not match:
        return f"[{COLORS['text_dim']}]{badge}[/]"
    tier = int(match.group(1))
    color = COLORS[_RISK_BADGE_COLOR_KEY[tier]]
    weight = "bold " if tier >= 8 else ""
    return f"[{weight}{color}]{badge}[/]"


# ── Tool Name Mapping ────────────────────────────────────────────────
# Map snake_case tool names to Antigravity-style display names

_TOOL_DISPLAY_NAMES = {
    "run_shell": "Bash",
    "nmap_scan": "Nmap",
    "dns_lookup": "DnsLookup",
    "whois_lookup": "Whois",
    "ping_host": "Ping",
    "traceroute": "Traceroute",
    "port_scan": "PortScan",
    "http_request": "HttpRequest",
    "web_crawl": "WebCrawl",
    "url_scan": "UrlScan",
    "ssl_check": "SslCheck",
    "ssl_audit": "SslAudit",
    "dir_brute": "DirBrute",
    "dir_bruteforce": "DirBruteforce",
    "nikto_scan": "Nikto",
    "sql_injection_test": "Sqlmap",
    "xss_test": "XssTest",
    "subdomain_enum": "SubdomainEnum",
    "tech_detect": "TechDetect",
    "osint_lookup": "OsintLookup",
    "shodan_search": "ShodanSearch",
    "email_lookup": "EmailLookup",
    "hash_lookup": "HashLookup",
    "exploit_search": "ExploitSearch",
    "hash_crack": "HashCrack",
    "encode_decode": "EncodeDecode",
    "file_analysis": "FileAnalysis",
    "metadata_extract": "MetadataExtract",
    "log_analysis": "LogAnalysis",
    "memory_dump": "MemoryDump",
    "vpn_status": "VpnStatus",
    "disconnect_vpn": "DisconnectVpn",
}


def _friendly_tool_name(tool_name: str) -> str:
    """Convert snake_case tool name to PascalCase display name."""
    if tool_name in _TOOL_DISPLAY_NAMES:
        return _TOOL_DISPLAY_NAMES[tool_name]
    # Auto-convert: nmap_scan -> NmapScan
    return "".join(word.capitalize() for word in tool_name.split("_"))


def _compact_args_summary(tool_name: str, arguments: Dict[str, Any]) -> str:
    """Create a compact args summary like Antigravity: ToolName(first_arg_value).

    Examples:
        Nmap(192.168.1.1)
        Read(/home/user/file.py)
        Bash(cd /home && ls)
    """
    if not arguments:
        return ""

    # Pick the most meaningful argument value
    # Priority: target/path-like values > command/query > descriptive values > first value.
    priority_keys = [
        "target",
        "host",
        "config_path",
        "filepath",
        "path",
        "directory",
        "url",
        "command",
        "query",
        "name",
        "domain",
    ]
    value = None
    for key in priority_keys:
        if key in arguments:
            value = str(arguments[key])
            break

    if value is None:
        # Fall back to first argument value
        value = str(next(iter(arguments.values())))

    # Truncate long values
    if len(value) > 80:
        value = value[:77] + "..."

    return value


def _tool_status_color(status: str = "", permission: str = "", is_dangerous: bool = False) -> str:
    normalized = (status or permission or "").strip().lower()
    if normalized in {"success", "succeeded", "done", "completed", "complete", "allow", "allowed"}:
        return COLORS["success"]
    if normalized in {"error", "failed", "failure", "cancelled", "canceled", "interrupted", "deny", "denied"}:
        return COLORS["error"]
    if normalized in {"pending", "running", "started", "warning", "ask", "review", "approval"} or is_dangerous:
        return COLORS["warning"]
    return COLORS["accent"]


def _tool_status_marker(status: str = "", permission: str = "", is_dangerous: bool = False) -> str:
    # Claude Code parity (DESIGN_SPEC `glyph.turn_bullet` = ⏺ U+23FA): tool rows
    # always use the record bullet "⏺". State is encoded by COLOUR, not by the
    # glyph — yellow while pending/running, green on success, red on error — with
    # an animated spinner shown separately during active execution.
    return "⏺"


def _tool_call_markup(tool_name: str, arguments: Dict[str, Any]) -> str:
    display_name = _friendly_tool_name(tool_name)
    arg_summary = _compact_args_summary(tool_name, arguments)
    args = f"({arg_summary})" if arg_summary else "()"
    # G4 (DESIGN_SPEC `line.tool_call.name_style`): the tool name is `bold` +
    # `color.text`, NOT accent — colour is a signal reserved for the state bullet
    # and headings (§4 `color.principle`), so the name must not compete with them.
    return (
        f"[bold {COLORS['text']}]{escape(display_name)}[/]"
        f"[dim]{escape(args)}[/dim]"
    )


def format_tool_call_text(tool_name: str, arguments: Dict[str, Any] | None = None) -> str:
    """Return the plain AGY-style tool call label used in ctrl+o surfaces."""
    arguments = arguments or {}
    display_name = _friendly_tool_name(tool_name)
    arg_summary = _compact_args_summary(tool_name, arguments)
    return f"{display_name}({arg_summary})" if arg_summary else display_name


_COMMAND_COMPOSITION_MARKERS = ("&&", "||", ";", "|", "$(", "`", ">", "<", "\n", "\r")
_EXACT_COMMAND_SESSION_DENYLIST = {
    "apt",
    "apt-get",
    "chattr",
    "chmod",
    "chown",
    "dd",
    "fdisk",
    "mkfs",
    "mount",
    "reboot",
    "rm",
    "rmdir",
    "shutdown",
    "sudo",
    "systemctl",
    "truncate",
    "umount",
}
_SHELL_TOOL_SESSION_ONLY = {
    "connect_vpn_config",
    "disconnect_vpn",
    "dir_brute",
    "generate_payload",
    "nikto_scan",
    "nmap_scan",
    "run_shell",
    "sql_injection_test",
    "subdomain_enum",
    "waf_detect",
    "xss_test",
}
_LOW_RISK_COMMAND_PREFIX_PERSISTENT = {"date", "hostname", "id", "pwd", "uname", "whoami"}


def _is_compound_command(command: str) -> bool:
    return any(marker in str(command or "") for marker in _COMMAND_COMPOSITION_MARKERS)


def _first_command_word(command: str) -> str:
    try:
        import shlex

        tokens = shlex.split(str(command or ""))
    except ValueError:
        tokens = str(command or "").split()
    return tokens[0].rsplit("/", 1)[-1] if tokens else ""


def _allows_persistent_command_prefix(command: str) -> bool:
    try:
        import shlex

        tokens = shlex.split(str(command or ""))
    except ValueError:
        tokens = str(command or "").split()
    if len(tokens) != 1:
        return False
    executable = tokens[0].rsplit("/", 1)[-1]
    return executable in _LOW_RISK_COMMAND_PREFIX_PERSISTENT


def _tool_result_log_reference_line(result: ToolResult, *, max_width: int) -> str:
    fallback = "\n".join(part for part in (result.output, result.error or "") if part)
    if not should_show_spool_reference(
        result.metadata,
        fallback,
        execution_time=result.execution_time,
    ):
        return ""
    reference = spool_reference(result.metadata)
    if not reference:
        return ""
    return f"     log: {_fit_display(reference, max(10, max_width - 11))}"


_RISK_LABELS = {
    ToolRiskClass.PURE_LOCAL_COMPUTATION: "R0 pure local computation",
    ToolRiskClass.LOCAL_OBSERVATION: "R1 local observation",
    ToolRiskClass.NETWORK_OBSERVATION: "R2 network observation",
    ToolRiskClass.ACTIVE_ENUMERATION: "R3 active enumeration",
    ToolRiskClass.LOCAL_FILE_ACCESS: "R4 local file access",
    ToolRiskClass.PRIVILEGED_LOCAL_ACTION: "R5 privileged local action",
    ToolRiskClass.OFFENSIVE_PAYLOAD_OR_EXPLOIT_ASSISTANCE: "R6 exploit assistance",
    ToolRiskClass.EXTENSION_SUPPLY_CHAIN_EXECUTION: "R7 extension execution",
    ToolRiskClass.CREDENTIALED_REMOTE_OR_IDENTITY_ACTION: "R8 credentialed remote action",
}


_SHELL_NETWORK_TOOLS = frozenset({
    "curl", "wget", "ping", "dig", "nslookup", "host", "whois", "traceroute",
})
_SHELL_LOCAL_READ = frozenset({
    "ls", "cat", "head", "tail", "grep", "find", "id", "whoami", "pwd", "date",
    "uname", "which", "file", "wc", "stat", "env", "echo",
})


def _shell_command_risk_label(command: str) -> str | None:
    """Command-aware risk for a run_shell approval, or None to keep the tool's
    static (conservative) risk. Only downgrades for an unambiguous single-
    executable read command; anything privileged/destructive/compound/unknown
    keeps the conservative label so risk is never understated. Display only -
    the PermissionEngine still gates the tool and the command (#2a)."""
    cmd = str(command or "").strip()
    if not cmd or any(op in cmd for op in ("&&", "||", ";", "|", "`", "$(", ">", "<")):
        return None
    word = _first_command_word(cmd)
    if word in _SHELL_NETWORK_TOOLS:
        return _RISK_LABELS[ToolRiskClass.NETWORK_OBSERVATION]
    if word in _SHELL_LOCAL_READ:
        return _RISK_LABELS[ToolRiskClass.LOCAL_OBSERVATION]
    return None


def _approval_context_line(
    tool_name: str,
    arguments: Dict[str, Any],
    resource: PermissionResource,
) -> str:
    risk_label = _approval_risk_label(tool_name, resource, arguments)
    feasibility = _approval_feasibility_label(arguments, resource)
    parts = [f"Resource: {resource.value}", f"Risk: {risk_label}"]
    if feasibility:
        parts.append(feasibility)
    return " · ".join(parts)


def _approval_risk_label(
    tool_name: str,
    resource: PermissionResource,
    arguments: Dict[str, Any] | None = None,
) -> str:
    if resource.kind == "tool":
        if resource.name == "run_shell" or tool_name == "run_shell":
            command_label = _shell_command_risk_label(_editable_command(arguments or {}))
            if command_label:
                return command_label
        tool_def = tool_registry.get_tool(resource.name) or tool_registry.get_tool(tool_name)
        risk_class = getattr(tool_def, "risk_class", None)
        if isinstance(risk_class, ToolRiskClass):
            return _RISK_LABELS.get(risk_class, risk_class.value)
        return "tool execution"
    if resource.kind == "read_file":
        return _RISK_LABELS[ToolRiskClass.LOCAL_FILE_ACCESS]
    if resource.kind == "write_file":
        return "local file write"
    if resource.kind in {"command", "command_exact", "command_prefix"}:
        command_word = _first_command_word(resource.name)
        if command_word == "sudo":
            return _RISK_LABELS[ToolRiskClass.PRIVILEGED_LOCAL_ACTION]
        return "command execution"
    return "resource access"


def _approval_risk_tier(tool_name: str, resource: PermissionResource) -> int | None:
    """Numeric risk tier (0-8) for a tool approval, or None for a non-tool
    resource or an unresolved risk class (PROC-03)."""
    if resource.kind != "tool":
        return None
    tool_def = tool_registry.get_tool(resource.name) or tool_registry.get_tool(tool_name)
    value = str(getattr(getattr(tool_def, "risk_class", None), "value", "") or "")
    match = re.match(r"r([0-8])_", value)
    return int(match.group(1)) if match else None


_HIGH_RISK_APPROVAL_TIER = 6


def _is_high_risk_approval(tool_name: str, resource: PermissionResource) -> bool:
    """PROC-03: R6-R8 tools (exploit assistance, extension execution, credentialed
    remote action) are offensive/irreversible.  Their approval must not default to
    'Allow once' and is confirmed by typing the tool name."""
    tier = _approval_risk_tier(tool_name, resource)
    return tier is not None and tier >= _HIGH_RISK_APPROVAL_TIER


def _approval_default_index(
    tool_name: str, resource: PermissionResource, options: list[tuple[str, str]]
) -> int:
    """Initially highlighted option.  High-risk approvals start on 'No' so a
    reflexive Enter denies instead of authorising an offensive action."""
    if _is_high_risk_approval(tool_name, resource):
        for index, (code, _label) in enumerate(options):
            if code == "DENY_ONCE":
                return index
    return 0


def _typed_confirmation_token(tool_name: str, resource: PermissionResource) -> str:
    """The token an operator must type to confirm a high-risk approval."""
    if resource.kind == "tool":
        return resource.name or tool_name
    return tool_name


def _typed_confirmation_matches(expected: str, typed: str) -> bool:
    return str(typed).strip().casefold() == str(expected).strip().casefold()


def _approval_feasibility_label(arguments: Dict[str, Any], resource: PermissionResource) -> str:
    if resource.kind in {"command", "command_exact", "command_prefix"}:
        return "sandbox/sudo checked before run"
    if resource.kind in {"read_file", "write_file"}:
        return "path checked before access"
    if resource.kind == "tool" and _editable_command(arguments):
        return "command checked before run"
    if resource.kind == "tool":
        return "scope/resource checked before run"
    return ""


def _is_write_tool(tool_name: str) -> bool:
    return tool_name in {"write_file", "create_file", "WriteFile", "Create"} or any(
        alias in tool_name for alias in ("write_file", "create")
    )


def _write_file_diff_preview_lines(arguments: Dict[str, Any], width: int) -> list[str]:
    """Pre-execution diff preview for write/create tools.

    The operator approves against the actual content that will be written (numbered
    ``+`` lines under an ``Added N lines`` summary) — the same agy-verified diff style
    the result box uses, but shown BEFORE the write, at the approval gate. Without this
    the diff only rendered on the result, i.e. after the write was irreversible (audit
    T1.1; ASI09 Human-Agent Trust).
    """
    args = arguments or {}
    content = str(args.get("content", "") or "")
    path = str(args.get("path") or args.get("filepath") or "").strip()
    content_lines = content.splitlines()
    if not content_lines and not path:
        return []
    n_lines = len(content_lines)
    line_label = "line" if n_lines == 1 else "lines"
    summary = f"Added {n_lines} {line_label}"
    if path:
        summary = f"{summary} to {path}"
    preview = [f"  ⎿  {summary}"]
    safe_width = max(24, min(120, width - 14))
    max_display = min(6, len(content_lines))
    for idx, content_line in enumerate(content_lines[:max_display]):
        display_line = content_line.rstrip()
        if len(display_line) > safe_width:
            display_line = display_line[: safe_width - 3] + "..."
        preview.append(f"     {idx + 1:>4} +    {display_line}")
    if len(content_lines) > max_display:
        preview.append(f"     ... {len(content_lines) - max_display:,} more lines")
    return preview


def _approval_lines(
    tool_name: str,
    arguments: Dict[str, Any],
    resource: PermissionResource,
    selected: int,
    options: list[tuple[str, str]],
    width: int,
) -> list[str]:
    """Build plain approval prompt lines for rendering and regression tests."""
    safe_width = max(1, width - 1)
    display_name = _friendly_tool_name(tool_name)
    arg_summary = _compact_args_summary(tool_name, arguments)
    if resource.kind in {"command", "command_exact", "command_prefix"}:
        call_text = _editable_command(arguments) or resource.name
        title = "Command"
    else:
        call_text = f"{display_name}({arg_summary})" if arg_summary else f"{display_name}()"
        title = "Permission"

    separator = "─" * safe_width

    lines = [
        title,
        separator,
        f"  {_fit_display('Requesting permission for: ' + call_text, max(1, safe_width - 4))}",
        f"  {_fit_display(_approval_context_line(tool_name, arguments, resource), max(1, safe_width - 4))}",
    ]

    # PROC-03: an offensive/irreversible R6+ action is confirmed by typing its
    # name; surface that at the gate so approval is deliberate, not reflexive.
    if _is_high_risk_approval(tool_name, resource):
        confirm_hint = "Type '" + _typed_confirmation_token(tool_name, resource) + "' to confirm; default is No."
        lines.append("  " + _fit_display("⚠ High-risk, irreversible action.", max(1, safe_width - 4)))
        lines.append("  " + _fit_display(confirm_hint, max(1, safe_width - 4)))

    # Reviewable artifact BEFORE the gate: for write/create tools, show the diff the
    # operator is about to approve — not just a prose summary rendered post-write (T1.1).
    if _is_write_tool(tool_name):
        for preview_line in _write_file_diff_preview_lines(arguments, safe_width):
            lines.append(_fit_display(preview_line, safe_width))

    lines.extend(["", "Do you want to proceed?"])

    for index, (_, label) in enumerate(options):
        cursor = ">" if index == selected else " "
        lines.append(f"{cursor} {index + 1}. {_fit_display(label, max(1, safe_width - 6))}")
    lines.append("")
    is_command_resource = resource.kind in {"command", "command_exact", "command_prefix"}
    if is_command_resource and _editable_command(arguments):
        lines.append("  ↑/↓ Navigate · tab Amend · e edit command")
    else:
        lines.append("  ↑/↓ Navigate · enter Select")
    return lines


def _approval_options(resource: PermissionResource) -> list[tuple[str, str]]:
    """Permission choices with descriptive labels (⚠️ §5.1).

    DELIBERATE SECOPS DIVERGENCE FROM AGY (R11): Antigravity itself offers
    "Always Allow / Persist" for every command and relies on a separate
    ``alwaysDeny`` list for safety. For an offensive-security agent that is
    considered too risky, so this hybrid policy only offers "Persist to
    settings.json" for low-risk resources. Sensitive tools
    (``_SHELL_TOOL_SESSION_ONLY``), exact commands, and non-low-risk command
    prefixes stay session-only; compound commands keep no "always allow" scope
    at all — only allow-once/deny. This is intentionally stricter than agy.
    """
    options = [("ALLOW_ONCE", "Allow once")]

    if resource.kind == "tool":
        options.append(("ALLOW_SESSION", f"Always allow tool '{resource.name}' in this conversation"))
        if resource.name not in _SHELL_TOOL_SESSION_ONLY:
            options.append(("ALLOW_PERSISTENT", f"Always allow tool '{resource.name}' (Persist to settings.json)"))
    elif resource.kind == "command_exact":
        if not _is_compound_command(resource.name):
            options.append(("ALLOW_SESSION", "Always allow this command in this conversation"))
    elif resource.kind == "command_prefix":
        options.append(("ALLOW_SESSION", f"Always allow commands matching '{resource.name}' in this conversation"))
        if _allows_persistent_command_prefix(resource.name):
            options.append(("ALLOW_PERSISTENT", f"Always allow commands matching '{resource.name}' (Persist to settings.json)"))
    else:
        options.append(("ALLOW_SESSION", f"Always allow '{resource.name}' in this conversation"))

    options.append(("DENY_ONCE", "No"))
    return options


def _editable_command(arguments: Dict[str, Any]) -> str:
    command = arguments.get("command")
    if command is None:
        return ""
    return str(command).strip()


def _normalize_command_prefix(command: str) -> str:
    return " ".join(str(command or "").strip().split())


def _clear_rendered_lines(count: int):
    if count <= 0:
        return
    import sys

    sys.stdout.write("\r\x1b[K")
    for _ in range(count):
        sys.stdout.write("\x1b[1A\x1b[K")
    sys.stdout.write("\r")


# ── Tool Call Display ─────────────────────────────────────────────────

class ToolCallBox:
    """Renders tool call in Antigravity CLI style:
        ⏺ ToolName(arg_summary) (ctrl+o to expand)

    The ``show_expand_tag`` parameter controls whether the ``(ctrl+o to
    expand)`` label is appended.  Per verified agy behaviour, the tag should
    appear only on the **last** tool call of a consecutive group.
    """

    @staticmethod
    def render(
        console: Console,
        tool_name: str,
        arguments: Dict[str, Any],
        is_dangerous: bool = False,
        permission: str = "",
        status: str = "",
        leading_blank: bool = True,
        show_expand_tag: bool = True,
    ) -> int:
        indicator_color = _tool_status_color(
            status=status,
            permission=permission,
            is_dangerous=is_dangerous,
        )
        indicator_marker = _tool_status_marker(
            status=status,
            permission=permission,
            is_dangerous=is_dangerous,
        )
        call_markup = _tool_call_markup(tool_name, arguments)
        risk_badge = _risk_badge_markup(tool_name)
        expand_tag = (
            f" [{COLORS['text_muted']}](ctrl+o to expand)[/{COLORS['text_muted']}]"
            if show_expand_tag else ""
        )

        prefix = "\n" if leading_blank else ""
        console.print(
            f"{prefix}[{indicator_color}]{indicator_marker}[/{indicator_color}] "
            f"{call_markup}{expand_tag} {risk_badge}",
            no_wrap=True,
            overflow="ellipsis",
        )
        return 2 if leading_blank else 1

    @staticmethod
    def render_permission_request(
        console: Console,
        tool_name: str,
        arguments: Dict[str, Any],
    ):
        """Render a permission request in Antigravity style:
            ⏺ Requested Permission: write_file(/path) (ctrl+o to expand)
        """
        call_markup = _tool_call_markup(tool_name, arguments)
        risk_badge = _risk_badge_markup(tool_name)

        console.print(
            f"\n[{COLORS['warning']}]⏺[/{COLORS['warning']}] "
            f"{call_markup} {risk_badge} "
            f"[{COLORS['text_muted']}](ctrl+o to expand)[/{COLORS['text_muted']}]"
        )

    @staticmethod
    def render_running(
        console: Console,
        tool_name: str,
        arguments: Dict[str, Any],
        leading_blank: bool = True,
        show_expand_tag: bool = True,
    ) -> int:
        """Render the active tool execution row like AGY's running transcript."""
        call_markup = _tool_call_markup(tool_name, arguments)
        risk_badge = _risk_badge_markup(tool_name)
        indicator_color = _tool_status_color(status="running")
        expand_tag = (
            f" [{COLORS['text_muted']}](ctrl+o to expand)[/{COLORS['text_muted']}]"
            if show_expand_tag else ""
        )
        prefix = "\n" if leading_blank else ""
        console.print(
            f"{prefix}[{indicator_color}]⏺[/{indicator_color}] "
            f"{call_markup}{expand_tag} {risk_badge}",
            no_wrap=True,
            overflow="ellipsis",
        )
        return 2 if leading_blank else 1


# ── Tool Result Display ───────────────────────────────────────────────

def _diff_bg(added: bool) -> str:
    """Theme-aware background for a diff line (Claude-Code style): green for an
    addition, red for a removal — a dark tint on the dark palettes, a light tint
    on the light theme so the foreground stays readable."""
    from secops_agent.ui.theme import active_theme_name, is_light_theme

    if is_light_theme(active_theme_name()):
        return "#dcfce7" if added else "#fee2e2"
    return "#14311f" if added else "#3a1414"


def _drop_trailing_zero_exit(output: str) -> str:
    """Drop a trailing ``[Exit Code: 0]`` trailer for the collapsed summary.

    Our tools append this marker so a successful single-line command (``pwd``,
    ``date``) would otherwise count as two lines and read as ``2 lines`` instead
    of its actual output. A non-zero exit code is diagnostic and kept."""
    lines = output.splitlines()
    if lines and lines[-1].strip() == "[Exit Code: 0]":
        return "\n".join(lines[:-1])
    return output


def build_collapsed_result_lines(result: ToolResult, *, width: int) -> list[str]:
    """Build the épuré collapsed result block as Rich-markup lines.

    Claude-Code-style legibility: one key-fact line, plus at most one discreet
    meta line (``+N lines · ctrl+o to expand``); the raw body lives under ctrl+o.
    Contrast is the point — the fact renders in ``text_secondary`` and the corner
    / meta in ``text_muted``, never ``text_dim`` (a rule colour that is illegible
    as text on the dark ground, the cause of the old unreadable ⎿ previews).

    Shared by ``ToolResultBox.render`` (live row) and the renderer's ctrl+o
    transcript builder so both surfaces stay byte-for-byte in sync."""
    corner = COLORS["text_muted"]
    fact = COLORS["text_secondary"]
    meta = COLORS["text_muted"]

    text_failure = result.success and _looks_like_tool_failure(result.output)
    log_line = _tool_result_log_reference_line(result, max_width=width)

    if not result.success or text_failure:
        raw = result.error or result.output or "Unknown error"
        error_msg = raw.strip().splitlines()[0] if raw.strip() else "Unknown error"
        if len(error_msg) > 120:
            error_msg = error_msg[:117] + "..."
        elapsed = f" ({format_duration(result.execution_time)})" if result.execution_time > 0 else ""
        lines = [f"  [{COLORS['error']}]⎿  {escape(error_msg)}{elapsed}[/{COLORS['error']}]"]
        if log_line:
            lines.append(f"[{meta}]{escape(log_line)}[/{meta}]")
        return lines

    output = _drop_trailing_zero_exit(str(result.output or ""))
    metadata = result.metadata or {}
    parsed_summary = str(metadata.get("parsed_summary") or "").strip()
    summary = summarize_output(output, max_lines=4, max_width=max(24, min(120, width - 8)))
    elapsed = format_duration(result.execution_time) if result.execution_time > 0 else ""
    hint = f"[{meta}](ctrl+o to expand)[/{meta}]"
    nonempty = [ln for ln in output.splitlines() if ln.strip()]

    # 0) A non-zero exit trailer survived the drop → surface it. It is the whole
    # point of the row (a soft failure), so it must never be buried under a
    # metrics summary. Lead with the command's own text, keep the code on meta.
    if nonempty:
        exit_match = re.match(r"^\[Exit Code:\s*(-?\d+)\]$", nonempty[-1].strip())
        if exit_match and exit_match.group(1) != "0":
            body = [ln for ln in nonempty if not ln.strip().startswith("[Exit Code:")]
            headline = _fit_display(body[0] if body else f"exit {exit_match.group(1)}", max(20, width - 8))
            return [
                f"  [{corner}]⎿  [/{corner}][{fact}]{escape(headline)}[/{fact}]",
                f"     [{meta}][Exit Code: {exit_match.group(1)}] · [/{meta}]{hint}",
            ]

    # 1) Structured key fact from a parser → lead with it; detail under ctrl+o.
    if parsed_summary:
        headline = _fit_display(parsed_summary.splitlines()[0], max(20, width - 8))
        lines = [f"  [{corner}]⎿  [/{corner}][{fact}]{escape(headline)}[/{fact}]"]
        if nonempty:
            lines.append(f"     [{meta}]+{len(nonempty):,} lines · [/{meta}]{hint}")
        return lines

    # 2) Single meaningful line → render it directly on the corner.
    if summary["total_lines"] <= 1 and summary["lines"]:
        line = _fit_display(summary["lines"][0], max(20, width - 6))
        lines = [f"  [{corner}]⎿  [/{corner}][{fact}]{escape(line)}[/{fact}]"]
        if log_line:
            lines.append(f"[{meta}]{escape(log_line)}[/{meta}]")
        return lines

    # 3) Multiline without a parser → concise metrics headline; body under ctrl+o.
    metrics = []
    if elapsed:
        metrics.append(elapsed)
    if summary["chars"]:
        line_label = "line" if summary["total_lines"] == 1 else "lines"
        metrics.append(f"{summary['total_lines']:,} {line_label}")
        metrics.append(f"{summary['chars']:,} chars")
    details = " · ".join(metrics) if metrics else ("no output" if not summary["chars"] else "done")
    lines = [f"  [{corner}]⎿  [/{corner}][{fact}]{escape(details)}[/{fact}] {hint}"]
    if log_line:
        lines.append(f"[{meta}]{escape(log_line)}[/{meta}]")
    return lines


class ToolResultBox:
    """Renders tool result collapsed (Antigravity style).
    Success: appends (ctrl+o to expand) to the tool call line.
    Failure: shows error inline.

    For write_file / create tools: uses agy-verified diff style with
    ``Added N lines`` summary and numbered ``+`` prefixed content lines.
    """

    _WRITE_TOOL_NAMES = {"write_file", "create_file", "WriteFile", "Create"}

    @staticmethod
    def render(console: Console, tool_name: str, result: ToolResult) -> int:
        """Render the collapsed result block. Returns the number of lines
        printed so the ctrl+o toggle can clear it before drawing the expansion."""
        printed = 0

        def emit(*args: Any, **kwargs: Any) -> None:
            nonlocal printed
            console.print(*args, **kwargs)
            printed += 1

        text_failure = result.success and _looks_like_tool_failure(result.output)
        log_line = _tool_result_log_reference_line(result, max_width=console.width)

        # ── agy-verified diff rendering for write/create tools (kept verbatim) ──
        if result.success and not text_failure:
            is_write = tool_name in ToolResultBox._WRITE_TOOL_NAMES or \
                any(alias in tool_name for alias in ("write_file", "create"))
            metadata = result.metadata or {}
            written_content = str(metadata.get("content", "") or "")
            lines_written = metadata.get("lines_added") or metadata.get("lines_written")

            if is_write and (written_content or lines_written):
                content_lines = written_content.splitlines() if written_content else []
                n_lines = int(lines_written) if lines_written else len(content_lines)
                summary_verb = "Added" if n_lines > 0 else "Wrote"
                line_label = "line" if n_lines == 1 else "lines"
                emit(
                    f"  [{COLORS['text_muted']}]⎿  {summary_verb} {n_lines} {line_label}[/{COLORS['text_muted']}]"
                )
                # Show up to 6 content lines with real line numbers and a "+" prefix
                # on a green background (Claude-Code diff style).
                max_display = min(6, len(content_lines))
                safe_width = max(24, min(120, console.width - 14))
                add_style = f"{COLORS['success']} on {_diff_bg(True)}"
                for idx, content_line in enumerate(content_lines[:max_display]):
                    line_no = idx + 1
                    display_line = content_line.rstrip()
                    if len(display_line) > safe_width:
                        display_line = display_line[:safe_width - 3] + "..."
                    pad = " " * max(0, safe_width - len(display_line))
                    emit(
                        f"     [{COLORS['text_muted']}]{line_no:>4}[/{COLORS['text_muted']}] "
                        f"[{add_style}]+  {escape(display_line)}{pad}[/]"
                    )
                if len(content_lines) > max_display:
                    emit(
                        f"     [{COLORS['text_muted']}]... {len(content_lines) - max_display:,} more lines[/{COLORS['text_muted']}]"
                    )
                if log_line:
                    emit(f"[{COLORS['text_muted']}]{escape(log_line)}[/{COLORS['text_muted']}]")
                return printed

        # ── Standard / parsed / single-line / error → shared épuré builder ──
        for line in build_collapsed_result_lines(result, width=console.width):
            emit(line)
        return printed


# ── Approval Prompt ───────────────────────────────────────────────────

class ApprovalPrompt:
    """Granular confirmation prompt for dangerous tools using interactive arrow keys."""

    @staticmethod
    async def request_approval(
        console: Console,
        tool_name: str,
        arguments: Dict[str, Any],
        resource: PermissionResource,
        timeout: float = 60.0,
    ) -> ApprovalDecision:
        import sys
        import termios
        import tty
        import shutil
        from secops_agent.ui.theme import ansi, ANSI_RESET
        from secops_agent.ui.overlay import read_terminal_key

        if not sys.stdin.isatty():
            return ApprovalDecision(allowed=False)

        command = _editable_command(arguments)
        if resource.kind == "command" and command:
            resource = PermissionResource(kind="command_exact", name=_normalize_command_prefix(command))

        options = _approval_options(resource)
        # PROC-03: high-risk (R6+) approvals start on "No" so a reflexive Enter
        # denies; other approvals keep Antigravity's first-action default.
        high_risk = _is_high_risk_approval(tool_name, resource)
        selected = _approval_default_index(tool_name, resource, options)
        amended_arguments: Dict[str, Any] | None = None

        c_success = ansi("success", bold=True)
        c_error = ansi("error", bold=True)
        c_muted = ansi("text_muted")
        c_dim = ansi("text_dim")
        c_text = ansi("text")
        reset = ANSI_RESET
        rendered_lines = 0

        def render_prompt():
            nonlocal selected, rendered_lines
            width = shutil.get_terminal_size((80, 24)).columns
            lines = _approval_lines(tool_name, arguments, resource, selected, options, width)

            _clear_rendered_lines(rendered_lines)
            for index, line in enumerate(lines):
                if line.strip() == "Command":
                    sys.stdout.write(f"{c_text}{line}{reset}\n")
                elif line.startswith("─"):
                    sys.stdout.write(f"{c_dim}{line}{reset}\n")
                elif line.startswith(">"):
                    color = c_success if "ALLOW" in options[selected][0] else c_error
                    sys.stdout.write(f"{color}{line}{reset}\n")
                elif "Navigate" in line:
                    sys.stdout.write(f"{c_muted}{line}{reset}\n")
                elif line.strip() == "Do you want to proceed?":
                    sys.stdout.write(f"{c_text}{line}{reset}\n")
                else:
                    sys.stdout.write(f"{c_muted}{line}{reset}\n")
            rendered_lines = len(lines)
            sys.stdout.flush()

        def read_key() -> str:
            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            try:
                tty.setraw(fd)
                key = read_terminal_key(fd, input_timeout=timeout)
                if key == "timeout":
                    return "timeout"
                if key in {"up", "mouse_up"}:
                    return "up"
                if key in {"down", "mouse_down"}:
                    return "down"
                if key == "tab":
                    return "amend"
                if key == "enter":
                    return "enter"
                if len(key) == 1 and key.lower() == "e":
                    return "edit"
                if key == "esc":
                    return "esc"
                return key
            finally:
                termios.tcsetattr(fd, termios.TCSANOW, old_settings)

        def run_tui():
            nonlocal selected, rendered_lines, amended_arguments

            def prompt_for_command_edit() -> bool:
                nonlocal rendered_lines, amended_arguments
                command = _editable_command(arguments)
                if not command:
                    return False

                _clear_rendered_lines(rendered_lines)
                rendered_lines = 0
                sys.stdout.write("\x1b[?25h")
                sys.stdout.flush()
                sys.stdout.write(f"  Current command: {command}\n")
                sys.stdout.write("  Edit command: ")
                sys.stdout.flush()
                edited = sys.stdin.readline().strip()
                if not edited or edited == command:
                    sys.stdout.write("\x1b[?25l\n")
                    sys.stdout.flush()
                    return False
                amended_arguments = dict(arguments)
                amended_arguments["command"] = edited
                sys.stdout.write("\x1b[?25h")
                sys.stdout.flush()
                return True

            def prompt_for_high_risk_confirmation() -> bool:
                nonlocal rendered_lines
                token = _typed_confirmation_token(tool_name, resource)
                tier = _approval_risk_tier(tool_name, resource)
                _clear_rendered_lines(rendered_lines)
                rendered_lines = 0
                sys.stdout.write("\x1b[?25h")
                sys.stdout.flush()
                label = f"R{tier} " if tier is not None else ""
                sys.stdout.write(f"  ⚠ {label}high-risk. Type '{token}' to confirm (blank cancels): ")
                sys.stdout.flush()
                typed = sys.stdin.readline().strip()
                sys.stdout.write("\x1b[?25l")
                sys.stdout.flush()
                return _typed_confirmation_matches(token, typed)

            sys.stdout.write("\x1b[?25l")
            sys.stdout.flush()
            try:
                while True:
                    render_prompt()
                    key = read_key()
                    if key == "up":
                        selected = (selected - 1) % len(options)
                    elif key == "down":
                        selected = (selected + 1) % len(options)
                    elif key == "enter":
                        code = options[selected][0]
                        if high_risk and code.startswith("ALLOW") and not prompt_for_high_risk_confirmation():
                            continue
                        _clear_rendered_lines(rendered_lines)
                        rendered_lines = 0
                        sys.stdout.write("\x1b[?25h")
                        sys.stdout.flush()
                        return code
                    elif key in {"amend", "edit"}:
                        if prompt_for_command_edit():
                            return "AMEND_COMMAND"
                    elif key == "esc":
                        _clear_rendered_lines(rendered_lines)
                        rendered_lines = 0
                        sys.stdout.write("\x1b[?25h")
                        sys.stdout.flush()
                        return "INTERRUPT"
                    elif key == "timeout":
                        _clear_rendered_lines(rendered_lines)
                        rendered_lines = 0
                        sys.stdout.write("\x1b[?25h")
                        sys.stdout.flush()
                        return "DENY_ONCE"
            except Exception:
                _clear_rendered_lines(rendered_lines)
                sys.stdout.write("\x1b[?25h")
                sys.stdout.flush()
                raise

        decision_code = run_tui()

        # Print the final result in the prompt
        if decision_code == "ALLOW_ONCE":
            console.print(f"  [{COLORS['success']}]⎿  Allowed once[/{COLORS['success']}]")
            return ApprovalDecision(allowed=True)
        elif decision_code == "ALLOW_SESSION":
            console.print(f"  [{COLORS['success']}]⎿  Allowed for session[/{COLORS['success']}]")
            return ApprovalDecision(allowed=True, scope=ApprovalScope.SESSION)
        elif decision_code == "ALLOW_PERSISTENT":
            console.print(f"  [{COLORS['success']}]⎿  Allowed persistently[/{COLORS['success']}]")
            return ApprovalDecision(allowed=True, scope=ApprovalScope.PERSISTENT)
        elif decision_code == "AMEND_COMMAND" and amended_arguments:
            console.print(f"  [{COLORS['text_muted']}]⎿  Command amended; requesting permission again[/{COLORS['text_muted']}]")
            return ApprovalDecision(allowed=False, amended_arguments=amended_arguments)
        elif decision_code == "INTERRUPT":
            console.print(f"  [{COLORS['error']}]✖ Refused · tool non exécuté[/{COLORS['error']}]")
            return ApprovalDecision(allowed=False, interrupted=True)
        else:
            console.print(f"  [{COLORS['error']}]✖ Refused · tool non exécuté[/{COLORS['error']}]")
            return ApprovalDecision(allowed=False)
