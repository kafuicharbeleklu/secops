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

# ── Palettes ─────────────────────────────────────────────────────────
# Rule: Color is a signal, not decoration. Each palette maps four signal hues
# (accent / success / warning / error) onto a terminal ground. The dark palettes
# share light text greys (_TEXT); the light palette flips to dark text (_TEXT_LIGHT)
# for a light terminal. Select with SECOPS_THEME or /theme.

# Dark-ground text greys (light-on-dark).
_TEXT = {
    "text": "#e4e4e7", "text_secondary": "#a1a1aa", "text_muted": "#82828b",
    "text_dim": "#3f3f46", "tool_name": "#e4e4e7",
}
# Light-ground text greys (dark-on-light) for a light terminal.
_TEXT_LIGHT = {
    "text": "#18181b", "text_secondary": "#3f3f46", "text_muted": "#52525b",
    "text_dim": "#a1a1aa", "tool_name": "#18181b",
}

# Reference grounds used to reason about (and test) contrast per palette.
_DARK_GROUND = "#18181b"
_LIGHT_GROUND = "#ffffff"

_PALETTES = {
    # Spicy Paprika — warm, grounded: steel accent, olive/orange/paprika signals.
    "paprika": {
        **_TEXT, "accent": "#669bbc", "accent_bright": "#8fbdd8",
        "success": "#a8c686", "warning": "#f3a712",
        "error": "#e4572e", "danger": "#e4572e", "danger_bright": "#ff6f42",
        "tool_border": "#3b4668",
    },
    # Ocean — cool, calm: sky accent, teal/yellow/pumpkin signals.
    "ocean": {
        **_TEXT, "accent": "#3da5d9", "accent_bright": "#6fc0e8",
        "success": "#73bfb8", "warning": "#fec601",
        "error": "#ea7317", "danger": "#ea7317", "danger_bright": "#ff9440",
        "tool_border": "#2364aa",
    },
    # Vivid — bold: teal accent, fern/saffron and an unambiguous red for danger.
    "vivid": {
        **_TEXT, "accent": "#08bdbd", "accent_bright": "#43d6d6",
        "success": "#29bf12", "warning": "#ff9914",
        "error": "#f21b3f", "danger": "#f21b3f", "danger_bright": "#ff4864",
        "tool_border": "#2a6b6b",
    },
    # Reef — balanced, diverse (from the 7-colour set): seagrass accent, a fern
    # success, gold warning and a coral red. Every signal >= 4.5 on the dark ground.
    "reef": {
        **_TEXT, "accent": "#43aa8b", "accent_bright": "#76c893",
        "success": "#90be6d", "warning": "#f9c74f",
        "error": "#f94144", "danger": "#f94144", "danger_bright": "#ff6b6b",
        "tool_border": "#3a5560",
    },
    # Neon — bold synthwave (from the turquoise/yellow/pink set): cyan accent, a
    # neon-green success, electric yellow warning and a hot-pink error/danger.
    "neon": {
        **_TEXT, "accent": "#41ead4", "accent_bright": "#87f5e8",
        "success": "#50fa7b", "warning": "#fbff12",
        "error": "#ff206e", "danger": "#ff206e", "danger_bright": "#ff5c94",
        "tool_border": "#3a2f5c",
    },
    # Light — for a light terminal: dark text, deeper signals. Warm/green signals
    # cannot reach 4.5 on white, so they sit at WCAG non-text 3:1 as bold glyphs;
    # accent (>=4.5) and error (>=4.0) stay text-grade, and body text is >= 7:1.
    "light": {
        **_TEXT_LIGHT, "accent": "#1a759f", "accent_bright": "#1e6091",
        "success": "#0a9396", "warning": "#ca6702",
        "error": "#d62828", "danger": "#d62828", "danger_bright": "#9d0208",
        "tool_border": "#457b9d",
    },
}
_DEFAULT_THEME = "paprika"

# Ground each palette is tuned for (contrast reference + light/dark awareness).
_PALETTE_GROUND = {
    "paprika": _DARK_GROUND, "ocean": _DARK_GROUND, "vivid": _DARK_GROUND,
    "reef": _DARK_GROUND, "neon": _DARK_GROUND, "light": _LIGHT_GROUND,
}


def resolve_theme_name() -> str:
    """Resolve the active theme: SECOPS_THEME selects a named palette
    (see available_themes()); anything else falls back to the default."""
    pref = os.environ.get("SECOPS_THEME", "").strip().lower()
    return pref if pref in _PALETTES else _DEFAULT_THEME


def ground_for(name: str) -> str:
    """The reference background a palette is tuned against."""
    return _PALETTE_GROUND.get(str(name or "").strip().lower(), _DARK_GROUND)


def is_light_theme(name: str) -> bool:
    """True if *name* is a light-terminal palette (dark text on a light ground)."""
    return ground_for(name) == _LIGHT_GROUND


# COLORS is a *live* dict: ansi()/pt_style_dict() read it at call time, so a
# runtime set_theme() is reflected without re-importing.
COLORS = dict(_PALETTES[resolve_theme_name()])

# Name of the palette currently in COLORS (updated by set_theme).
_active_theme: str = resolve_theme_name()


def _build_rich_styles(colors: dict) -> dict:
    return {
        "agent_name": f"bold {colors['accent']}",
        "user_prompt": f"bold {colors['text']}",
        "thinking": f"italic {colors['text_muted']}",
        "tool_call": f"bold {colors['tool_border']}",
        "tool_result": f"bold {colors['success']}",
        "error": f"bold {colors['error']}",
        "success": f"bold {colors['success']}",
        "info": f"bold {colors['accent']}",
        "muted": colors["text_muted"],
        "dim": colors["text_dim"],
        "warning": f"bold {colors['warning']}",
        "markdown.code": f"bold {colors['accent_bright']}",
        "markdown.code_block": colors["text"],
        "markdown.strong": f"bold {colors['accent_bright']}",
        "markdown.h1": f"bold {colors['accent_bright']}",
        "markdown.h2": f"bold {colors['accent']}",
        "markdown.h3": f"bold {colors['accent']}",
    }


RICH_STYLES = _build_rich_styles(COLORS)
rich_theme = Theme(RICH_STYLES)


def set_theme(name: str) -> str:
    """Switch the active palette at runtime (FMT-05). Updates COLORS in place so
    ansi()/pt_style_dict() reflect it immediately, and rebuilds RICH_STYLES /
    rich_theme. Returns the resolved theme name; a caller holding a Console must
    push the new rich_theme for its rich output to update live."""
    global RICH_STYLES, rich_theme
    requested = str(name or "").strip().lower()
    resolved = requested if requested in _PALETTES else resolve_theme_name()
    global _active_theme
    COLORS.clear()
    COLORS.update(_PALETTES[resolved])
    RICH_STYLES = _build_rich_styles(COLORS)
    rich_theme = Theme(RICH_STYLES)
    _active_theme = resolved
    return resolved


def available_themes() -> tuple[str, ...]:
    """The selectable palette names, in display order."""
    return tuple(_PALETTES)


def is_known_theme(name: str) -> bool:
    """True if *name* is a selectable palette."""
    return str(name or "").strip().lower() in _PALETTES


def active_theme_name() -> str:
    """The palette currently loaded in COLORS."""
    return _active_theme

# ── ANSI Escape Helpers (for raw terminal output: menu.py, etc.) ─────

ANSI_RESET = "\x1b[m"


def _hex_to_rgb(hex_color: str) -> tuple[int, int, int]:
    """Convert hex color string to RGB tuple."""
    h = hex_color.lstrip("#")
    return int(h[:2], 16), int(h[2:4], 16), int(h[4:], 16)


def color_enabled() -> bool:
    """Honour the NO_COLOR / CLICOLOR conventions for raw-ANSI output (X-02).

    Rich already strips colour under NO_COLOR for its own rendering; this covers
    the raw-ANSI surfaces (approval prompt, menus, sudo prompt) that build escape
    codes directly through ``ansi()`` / ``ansi_hex()``.
    """
    if os.environ.get("CLICOLOR_FORCE", "") not in ("", "0"):
        return True
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("CLICOLOR") == "0":
        return False
    return True


def reduced_motion() -> bool:
    """Honour a 'less animation' preference (SSH, slow terminals, accessibility).

    Set ``SECOPS_REDUCED_MOTION=1`` to swap the animated spinner for a static
    indicator and suppress host-terminal progress signalling (X-02 / ANIM-05).
    """
    return os.environ.get("SECOPS_REDUCED_MOTION", "").strip().lower() in {"1", "true", "yes", "on"}


def ansi(color_key: str, bold: bool = False) -> str:
    """Convert a theme color key to a TrueColor ANSI escape sequence."""
    if not color_enabled():
        return ""
    r, g, b = _hex_to_rgb(COLORS[color_key])
    if bold:
        return f"\x1b[1;38;2;{r};{g};{b}m"
    return f"\x1b[38;2;{r};{g};{b}m"


def ansi_hex(hex_color: str, bold: bool = False) -> str:
    """Convert a raw hex color to a TrueColor ANSI escape sequence."""
    if not color_enabled():
        return ""
    r, g, b = _hex_to_rgb(hex_color)
    if bold:
        return f"\x1b[1;38;2;{r};{g};{b}m"
    return f"\x1b[38;2;{r};{g};{b}m"


def ansi_bg_hex(hex_color: str) -> str:
    """Convert a raw hex color to a TrueColor ANSI *background* escape sequence."""
    if not color_enabled():
        return ""
    r, g, b = _hex_to_rgb(hex_color)
    return f"\x1b[48;2;{r};{g};{b}m"


def hyperlink(label: str, url: str) -> str:
    """Rich markup for an OSC 8 terminal hyperlink (X-03).  Rich emits the escape
    only where the terminal supports links and otherwise renders the label
    plainly, so this is safe to embed anywhere that goes through the console."""
    return f"[link={url}]{label}[/link]"


def file_link(path: Any, label: str | None = None) -> str:
    """OSC 8 hyperlink to a local file (X-03).  Falls back to plain text when the
    path cannot be expressed as a file URI."""
    from pathlib import Path as _Path

    display = str(path) if label is None else label
    try:
        uri = _Path(path).resolve().as_uri()
    except (ValueError, OSError):
        return display
    return hyperlink(display, uri)


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
        "toolbar_hint": f"{plain_surface} {COLORS['warning']} bold",
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

    # The compact (stacked) layout shows the full metadata; the monogram layout
    # only has room for it once the terminal is wide enough for the 50-col logo
    # plus a readable metadata column. Below that, prefer readable metadata over a
    # logo flanked by 12-char truncations (responsive banner).
    gap = "  "
    _MIN_META = 20
    if width < logo_width + len(gap) + _MIN_META:
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
