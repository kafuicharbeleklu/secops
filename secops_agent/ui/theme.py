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
from secops_agent.ui import layout

# ── Palettes ─────────────────────────────────────────────────────────
# Rule: Color is a signal, not decoration. Each palette maps four signal hues
# (accent / success / warning / error) onto a terminal ground. The dark palettes
# share light text greys (_TEXT); the light palette flips to dark text (_TEXT_LIGHT)
# for a light terminal. Select with SECOPS_THEME or /theme.

# Dark-ground text greys (light-on-dark) + ground-derived signal tints. The tints
# (diff line backgrounds, input-frame fill, and the dark fg used over the warning
# highlight) depend only on the ground, so they live here and spread into every
# dark palette — no colour literal is left at the call site (P4).
_TEXT = {
    "text": "#e4e4e7", "text_secondary": "#a1a1aa", "text_muted": "#82828b",
    "text_dim": "#3f3f46", "tool_name": "#e4e4e7",
    "diff_add_bg": "#14311f", "diff_remove_bg": "#3a1414",
    "input_frame_bg": "#1f1f27", "on_warning": "#18181b",
}
# Light-ground text greys (dark-on-light) + tints for a light terminal.
_TEXT_LIGHT = {
    "text": "#18181b", "text_secondary": "#3f3f46", "text_muted": "#52525b",
    "text_dim": "#a1a1aa", "tool_name": "#18181b",
    "diff_add_bg": "#dcfce7", "diff_remove_bg": "#fee2e2",
    "input_frame_bg": "#eceef3", "on_warning": "#18181b",
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
    # ── Warm palettes (Material 3-derived: accent at ~tone 80 on the dark
    # surface; every signal verified >= 4.5 on the dark ground). ──
    # Ember — burnt-orange accent, gold warning, warm red. Cosy and energetic.
    "ember": {
        **_TEXT, "accent": "#f2884e", "accent_bright": "#ff9f6b",
        "success": "#a3c77d", "warning": "#f4cf5e",
        "error": "#ef5a4c", "danger": "#ef5a4c", "danger_bright": "#ff7060",
        "tool_border": "#4a3f36",
    },
    # Sunset — vivid peach/orange accent, gold warning, coral red.
    "sunset": {
        **_TEXT, "accent": "#ff9e64", "accent_bright": "#ffb98a",
        "success": "#b0c877", "warning": "#ffd166",
        "error": "#f2635a", "danger": "#f2635a", "danger_bright": "#ff7d70",
        "tool_border": "#4a3b34",
    },
    # Amber — warm gold accent, amber warning, warm red. Bright and inviting.
    "amber": {
        **_TEXT, "accent": "#e8b04b", "accent_bright": "#ffcf6d",
        "success": "#9fc46b", "warning": "#f2b134",
        "error": "#ef6a4d", "danger": "#ef6a4d", "danger_bright": "#ff8163",
        "tool_border": "#4a4234",
    },
    # Terracotta — earthy clay accent, ochre warning, brick red. Muted and warm.
    "terracotta": {
        **_TEXT, "accent": "#e69a6b", "accent_bright": "#f2b085",
        "success": "#9bb168", "warning": "#e6b450",
        "error": "#e06a52", "danger": "#e06a52", "danger_bright": "#ff8468",
        "tool_border": "#4d4038",
    },
    # Rose — warm pink accent (very distinct from the gold warning / red error),
    # sage success. Warm without reading as orange.
    "rose": {
        **_TEXT, "accent": "#f2879b", "accent_bright": "#ffa5b4",
        "success": "#a7c98a", "warning": "#f4c56a",
        "error": "#ef5470", "danger": "#ef5470", "danger_bright": "#ff6f88",
        "tool_border": "#4d3a40",
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
    "paprika": _DARK_GROUND,
    "ember": _DARK_GROUND, "sunset": _DARK_GROUND, "amber": _DARK_GROUND,
    "terracotta": _DARK_GROUND, "rose": _DARK_GROUND,
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
        # **bold** is a plain bold attribute with no colour, matching Claude Code
        # (colour is a signal reserved for headings / code / status, not emphasis).
        "markdown.strong": "bold",
        "markdown.emph": "italic",
        "markdown.item.bullet": f"bold {colors['accent']}",
        "markdown.item.number": f"bold {colors['accent']}",
        "markdown.block_quote": colors["text_muted"],
        "markdown.hr": colors["text_dim"],
        "markdown.link": colors["accent"],
        "markdown.link_url": f"underline {colors['text_muted']}",
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


def _srgb_linear(channel: int) -> float:
    """Linearize one 0-255 sRGB channel (WCAG 2.1 relative-luminance step)."""
    c = channel / 255.0
    return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4


def relative_luminance(hex_color: str) -> float:
    """WCAG 2.1 relative luminance of a hex colour (0.0 black .. 1.0 white)."""
    r, g, b = _hex_to_rgb(hex_color)
    return 0.2126 * _srgb_linear(r) + 0.7152 * _srgb_linear(g) + 0.0722 * _srgb_linear(b)


def contrast_ratio(fg: str, bg: str) -> float:
    """WCAG 2.1 contrast ratio between two hex colours (1.0 .. 21.0). Symmetric.

    Thresholds used across the theme: >= 4.5 for normal text, >= 3.0 for large text
    / non-text UI (glyphs, borders). See scratch/contrast_report.py for the report
    across every palette on its tuned ground (dark and light)."""
    l1, l2 = relative_luminance(fg), relative_luminance(bg)
    lighter, darker = max(l1, l2), min(l1, l2)
    return (lighter + 0.05) / (darker + 0.05)


def color_enabled() -> bool:
    """Honour the NO_COLOR / FORCE_COLOR / CLICOLOR conventions for raw-ANSI output
    (X-02 / P4), matching Rich's behaviour on the main Console so the raw-ANSI
    surfaces (approval prompt, menus, sudo prompt) that build escape codes directly
    through ``ansi()`` / ``ansi_hex()`` agree with the Rich-rendered transcript.

    Precedence: CLICOLOR_FORCE / FORCE_COLOR force colour on; a NON-EMPTY NO_COLOR
    (per no-color.org — ``NO_COLOR=`` empty does not disable) or ``CLICOLOR=0``
    disable it; otherwise colour is on.
    """
    # Force flags win first (CLICOLOR spec: CLICOLOR_FORCE overrides NO_COLOR;
    # FORCE_COLOR mirrors Rich's force on the main Console).
    if os.environ.get("CLICOLOR_FORCE", "") not in ("", "0"):
        return True
    if os.environ.get("FORCE_COLOR", "") not in ("", "0"):
        return True
    # NO_COLOR disables colour only for a NON-EMPTY value (no-color.org / Rich):
    # `NO_COLOR=` (empty) does NOT disable, matching Rich's main-Console behaviour.
    if os.environ.get("NO_COLOR", "") != "":
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
    """Cell-accurate truncation (P2); delegates to the central layout layer."""
    return layout.fit_cell(text, width)


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
            f"{layout.INDENT_STR}{ansi('accent', bold=True)}SECOPS{reset} {ansi('accent', bold=True)}{title}{reset}\n"
            f"{divider}\n"
            f"{layout.INDENT_STR}Modèle  : {ansi('text_muted')}{_fit_text(friendly, max(1, width - 12))}{reset}\n"
            f"{layout.INDENT_STR}Session : {ansi('text_muted')}{_fit_text(session_label, max(1, width - 12))}{reset}\n"
            f"{layout.INDENT_STR}CWD     : {ansi('text_muted')}{_fit_text(cwd, max(1, width - 12))}{reset}\n"
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


def get_mission_box(mission: Any, model_name: str, width: int | None = None) -> str:
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

    # Responsive geometry (P2): everything derives from the current terminal
    # width. Cell-accurate padding via the central layout layer keeps CJK / emoji
    # columns aligned; the box is capped so it does not sprawl on ultra-wide
    # terminals and collapses to a single column when too narrow for the grid.
    if width is None:
        width, _ = layout.terminal_size()
    width = max(1, int(width))
    box_w = max(24, min(width, layout.FRAME_MAX_WIDTH))

    if layout.classify(width) is layout.Breakpoint.NARROW:
        # Single column; secondary metadata (ports / scope / model) hidden.
        head = "── MISSION "
        rows = [head + "─" * max(1, box_w - layout.cell_len(head))]
        for text in (f"target  {target}", f"phase  {phase}", vpn_status):
            rows.append(text if layout.cell_len(text) <= box_w else layout.fit_cell(text, box_w))
        return "\n".join(rows)

    # Medium / wide: bordered 3-column, 2-row grid derived from the box width.
    inner = box_w - 2
    base = inner // 3
    w1, w2, w3 = base, base, inner - 2 * base
    line1 = (
        "│" + layout.pad_cell(f" target  {target}", w1)
        + layout.pad_cell(f"phase  {phase}", w2)
        + layout.pad_cell(vpn_status, w3) + "│"
    )
    line2 = (
        "│" + layout.pad_cell(f" ports   {ports_str}", w1)
        + layout.pad_cell(f"scope  {scope_str}", w2)
        + layout.pad_cell(f"model  {friendly_model}", w3) + "│"
    )
    title = "┌─ MISSION "
    border_top = title + "─" * max(1, box_w - layout.cell_len(title) - 1) + "┐"
    border_bottom = "└" + "─" * (box_w - 2) + "┘"

    return "\n".join([border_top, line1, line2, border_bottom])
