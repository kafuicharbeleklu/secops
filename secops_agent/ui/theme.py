"""
Theme and visual identity for the SecOps Agent TUI.
Single source of truth for ALL styling across Rich, prompt_toolkit, and raw ANSI.
Follows Antigravity CLI aesthetic: minimal, clean, professional — "Color Austerity".
"""

from __future__ import annotations

import os
from typing import Any

from secops_agent import __version__
from secops_agent.core.model_catalog import model_display_name
from rich.theme import Theme

# ── Color Palette — Professional and restrained ──────────────────────
# Rule: Color is a signal, not decoration.
# Use white/gray for content, color only for state indicators.

COLORS = {
    # Primary SecOps gold (used sparingly — logo, prompt, active states)
    "accent": "#FFCD11",
    "accent_bright": "#FFE27A",
    # Functional — deliberately desaturated for professional feel
    "success": "#86efac",       # Soft green (was #4ade80 — too vivid)
    "error": "#fca5a5",         # Soft red (was #f87171 — too vivid)
    "warning": "#fde68a",       # Soft amber (was #fbbf24 — too vivid)
    # Text hierarchy (unchanged — already good)
    "text": "#e4e4e7",
    "text_secondary": "#a1a1aa",
    "text_muted": "#71717a",
    "text_dim": "#3f3f46",
    # Tool styling — gray, not blue (color austerity)
    "tool_border": "#52525b",
    "tool_name": "#e4e4e7",     # White — not blue
    # Permission / danger
    "danger": "#fca5a5",
    "danger_bright": "#f87171",
}

# ── Rich Theme ────────────────────────────────────────────────────────

RICH_STYLES = {
    "agent_name": f"bold {COLORS['accent']}",
    "user_prompt": f"bold {COLORS['text']}",
    "thinking": f"italic {COLORS['text_muted']}",
    "tool_call": f"bold {COLORS['tool_border']}",
    "tool_result": f"bold {COLORS['success']}",
    "error": f"bold {COLORS['error']}",
    "success": f"bold {COLORS['success']}",
    "info": f"bold {COLORS['accent']}",
    "muted": COLORS["text_muted"],
    "dim": COLORS["text_dim"],
    "warning": f"bold {COLORS['warning']}",
    "markdown.code": f"bold {COLORS['accent_bright']}",
    "markdown.code_block": COLORS["text"],
    "markdown.strong": f"bold {COLORS['accent_bright']}",
}

rich_theme = Theme(RICH_STYLES)

# ── ANSI Escape Helpers (for raw terminal output: menu.py, etc.) ─────

ANSI_RESET = "\x1b[m"


def _hex_to_rgb(hex_color: str) -> tuple[int, int, int]:
    """Convert hex color string to RGB tuple."""
    h = hex_color.lstrip("#")
    return int(h[:2], 16), int(h[2:4], 16), int(h[4:], 16)


def ansi(color_key: str, bold: bool = False) -> str:
    """Convert a theme color key to a TrueColor ANSI escape sequence."""
    r, g, b = _hex_to_rgb(COLORS[color_key])
    if bold:
        return f"\x1b[1;38;2;{r};{g};{b}m"
    return f"\x1b[38;2;{r};{g};{b}m"


def ansi_hex(hex_color: str, bold: bool = False) -> str:
    """Convert a raw hex color to a TrueColor ANSI escape sequence."""
    r, g, b = _hex_to_rgb(hex_color)
    if bold:
        return f"\x1b[1;38;2;{r};{g};{b}m"
    return f"\x1b[38;2;{r};{g};{b}m"


# ── prompt_toolkit Style Dict ────────────────────────────────────────

def pt_style_dict() -> dict:
    """Generate prompt_toolkit Style.from_dict() input from theme colors.

    This ensures the prompt, toolbar, and completion menu are
    always in sync with the theme palette.
    """
    plain_surface = "bg:default noinherit noreverse"
    return {
        "prompt": f"noinherit noreverse {COLORS['accent']}",
        "prompt_border": f"{plain_surface} {COLORS['text_muted']}",
        "toolbar_left": f"{plain_surface} {COLORS['text_muted']}",
        "toolbar_right": f"{plain_surface} {COLORS['text_muted']}",
        "toolbar_spaces": f"{plain_surface} {COLORS['text_muted']}",
        "toolbar_key": f"{plain_surface} {COLORS['accent_bright']} bold",
        "toolbar_action": f"{plain_surface} {COLORS['text_muted']}",
        "bottom-toolbar": plain_surface,
        "completion-menu": plain_surface,
        "completion-menu.completion": f"{plain_surface} {COLORS['text']}",
        "completion-menu.completion.current": f"{plain_surface} {COLORS['accent_bright']} bold",
        "completion-menu.meta.completion": f"{plain_surface} {COLORS['text_muted']}",
        "completion-menu.meta.completion.current": f"{plain_surface} {COLORS['text_secondary']}",
        "status-bar.vpn-active": f"{plain_surface} fg:{COLORS['success']}",
        "status-bar.vpn-off": f"{plain_surface} fg:{COLORS['error']}",
        "status-bar.phase": f"{plain_surface} fg:{COLORS['accent']}",
    }


# ── Friendly Model Names ─────────────────────────────────────────────

def friendly_model_name(model_name: str) -> str:
    """Return a user-friendly display name for a model identifier."""
    return model_display_name(model_name)


# ── Header Banner ────────────────────────────────────────────────────

SECOPS_MONOGRAM = (
    "███████╗███████╗ ██████╗  ██████╗ ██████╗ ███████╗",
    "██╔════╝██╔════╝██╔════╝ ██╔═══██╗██╔══██╗██╔════╝",
    "███████╗█████╗  ██║      ██║   ██║██████╔╝███████╗",
    "╚════██║██╔══╝  ██║      ██║   ██║██╔═══╝ ╚════██║",
    "███████║███████╗╚██████╗ ╚██████╔╝██║     ███████║",
    "╚══════╝╚══════╝ ╚═════╝  ╚═════╝ ╚═╝     ╚══════╝",
)


def _fit_text(text: str, width: int) -> str:
    if width <= 0:
        return ""
    if len(text) <= width:
        return text
    if width == 1:
        return "…"
    return text[: width - 1] + "…"


def get_header_banner(model_name: str = "gemini-2.5-flash") -> str:
    """
    SecOps CLI banner with a gold terminal-native monogram and metadata.
    """
    import shutil
    cwd = os.getcwd().replace(os.path.expanduser("~"), "~")

    friendly = friendly_model_name(model_name)

    reset = ANSI_RESET
    title = f"SecOps CLI {__version__}"
    session_label = "Pentest agent"

    width, _ = shutil.get_terminal_size((80, 24))
    logo_width = max(len(row) for row in SECOPS_MONOGRAM)

    if width < logo_width:
        divider = f"{ansi('text_dim')}{'─' * max(1, width - 1)}{reset}"
        banner = (
            f"  {ansi('accent', bold=True)}SECOPS{reset} {ansi('accent', bold=True)}{title}{reset}\n"
            f"{divider}\n"
            f"  Modèle  : {ansi('text_muted')}{_fit_text(friendly, max(1, width - 12))}{reset}\n"
            f"  Session : {ansi('text_muted')}{_fit_text(session_label, max(1, width - 12))}{reset}\n"
            f"  CWD     : {ansi('text_muted')}{_fit_text(cwd, max(1, width - 12))}{reset}\n"
            f"{divider}"
        )
        return banner

    gap = "  "
    meta_width = max(0, width - logo_width - len(gap))
    metadata = [
        (title, "accent", True),
        (session_label, "text_muted", False),
        (friendly, "text_muted", False),
        (cwd, "text_muted", False),
        ("", "text_muted", False),
        ("", "text_muted", False),
    ]

    rows = []
    for logo_row, (meta_text, color, bold) in zip(SECOPS_MONOGRAM, metadata):
        logo = f"{ansi('accent', bold=True)}{logo_row}{reset}"
        if meta_width <= 0 or not meta_text:
            rows.append(logo)
            continue
        rows.append(f"{logo}{gap}{ansi(color, bold=bold)}{_fit_text(meta_text, meta_width)}{reset}")

    return "\n".join(rows)


def get_mission_box(mission: Any, model_name: str) -> str:
    """
    Renders the mission context box: target, phase, vpn, ports, scope, model.
    """
    target = getattr(mission, "target", "") or ""
    phase = str(getattr(mission, "phase", "scoping")).upper()

    vpn_active = False
    try:
        net_dir = "/sys/class/net"
        if os.path.exists(net_dir):
            for dev in os.listdir(net_dir):
                if dev.startswith("tun"):
                    operstate_path = os.path.join(net_dir, dev, "operstate")
                    if os.path.exists(operstate_path):
                        with open(operstate_path, "r") as f:
                            state = f.read().strip().lower()
                        if state in {"up", "unknown"}:
                            vpn_active = True
                            break
    except Exception:
        pass
    vpn_status = f"vpn  {ansi('success')}● active{ANSI_RESET}" if vpn_active else f"vpn  {ansi('error')}○ off{ANSI_RESET}"

    ports_list = []
    services = getattr(mission, "services", []) or []
    for s in services:
        port = getattr(s, "port", None)
        name = getattr(s, "name", None)
        if port and name:
            ports_list.append(f"{port}/{name}")
        elif port:
            ports_list.append(str(port))
    ports_str = " · ".join(ports_list) if ports_list else "none"

    scope_obj = getattr(mission, "scope", None)
    scope_str = "none"
    if scope_obj:
        in_scope = getattr(scope_obj, "in_scope", []) or []
        if in_scope:
            scope_str = ", ".join(in_scope)

    friendly_model = friendly_model_name(model_name)

    def display_len(text: str) -> int:
        import re
        ansi_escape = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
        return len(ansi_escape.sub("", text))

    def pad_to_display_width(text: str, width: int) -> str:
        d_len = display_len(text)
        if d_len < width:
            return text + " " * (width - d_len)
        return text[:width]

    line1_left = pad_to_display_width(f" target  {target}", 26)
    line1_mid = pad_to_display_width(f"phase  {phase}", 26)
    line1_right = pad_to_display_width(vpn_status, 24)
    line1 = f"│{line1_left}{line1_mid}{line1_right}│"

    line2_left = pad_to_display_width(f" ports   {ports_str}", 26)
    line2_mid = pad_to_display_width(f"scope  {scope_str}", 26)
    line2_right = pad_to_display_width(f"model  {friendly_model}", 24)
    line2 = f"│{line2_left}{line2_mid}{line2_right}│"

    border_top = "┌─ MISSION " + "─" * 65 + "┐"
    border_bottom = "└" + "─" * 76 + "┘"

    return "\n".join([border_top, line1, line2, border_bottom])
