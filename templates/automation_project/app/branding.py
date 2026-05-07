from colorama import Fore

from app.shell_template import ShellChromeConfig, ShellPalette


PROJECT_NAME = "SECOPS"
PROJECT_SUBTITLE = "agent pentest"
PROMPT_BRAND = "secops"
INPUT_HINT = "parle a secops ou utilise /help"

PROJECT_OWNER = "SECOPS TEAM"
PROJECT_SLUG = "secops-agent"


def _hex_to_rgb(hex_color):
    value = str(hex_color).strip().lstrip("#")
    return int(value[0:2], 16), int(value[2:4], 16), int(value[4:6], 16)


def _rgb_to_hex(rgb):
    return "#{:02x}{:02x}{:02x}".format(*rgb)


def _relative_luminance(rgb):
    def channel(value):
        value = value / 255
        if value <= 0.03928:
            return value / 12.92
        return ((value + 0.055) / 1.055) ** 2.4

    red, green, blue = (channel(value) for value in rgb)
    return 0.2126 * red + 0.7152 * green + 0.0722 * blue


def _blend(top, base, alpha):
    return tuple(round((top[index] * alpha) + (base[index] * (1 - alpha))) for index in range(3))


def _user_message_bg(background_hex):
    background = _hex_to_rgb(background_hex)
    if _relative_luminance(background) > 0.5:
        return _rgb_to_hex(_blend((0, 0, 0), background, 0.04))
    return _rgb_to_hex(_blend((255, 255, 255), background, 0.12))


TERMINAL_PALETTE = ShellPalette(
    theme_name="dark",
    prompt_brand_hex="#FFCD11",
    prompt_path_hex="#f8fafc",
    prompt_sep_hex="#6b7280",
    background_hex="#111111",
    completion_meta_hex="#a1a1aa",
    toolbar_text_hex="#f8fafc",
    toolbar_key_fg_hex="#111111",
    toolbar_key_bg_hex="#FFCD11",
    toolbar_sep_hex="#737373",
    toolbar_label_hex="#f5f5f5",
    toolbar_meta_hex="#d4d4d8",
    input_bg_hex="#111111",
    selection_bg_hex="#333333",
    user_message_bg_hex=_user_message_bg("#111111"),
    info_badge_bg_hex="#f8fafc",
    inactive_badge_bg_hex="#52525b",
    active_badge_bg_hex="#f59e0b",
    success_badge_bg_hex="#86efac",
    danger_badge_bg_hex="#b91c1c",
    risk_badge_bg_hex="#ef4444",
)

GRAPHITE_TERMINAL_PALETTE = ShellPalette(
    theme_name="graphite",
    accent_ansi=Fore.LIGHTMAGENTA_EX,
    text_ansi=Fore.LIGHTWHITE_EX,
    muted_ansi=Fore.LIGHTBLACK_EX,
    info_ansi=Fore.LIGHTWHITE_EX,
    success_ansi=Fore.LIGHTGREEN_EX,
    warn_ansi=Fore.LIGHTYELLOW_EX,
    error_ansi=Fore.LIGHTRED_EX,
    risk_ansi=Fore.LIGHTRED_EX,
    tip_ansi=Fore.LIGHTCYAN_EX,
    path_ansi=Fore.WHITE,
    prompt_brand_hex="#C061CB",
    prompt_path_hex="#E6E7EA",
    prompt_sep_hex="#6B7280",
    background_hex="#101113",
    completion_meta_hex="#A4ABB6",
    toolbar_text_hex="#E6E7EA",
    toolbar_key_fg_hex="#101113",
    toolbar_key_bg_hex="#06B6D4",
    toolbar_sep_hex="#66707A",
    toolbar_label_hex="#DCE0E5",
    toolbar_meta_hex="#A4ABB6",
    input_bg_hex="#101113",
    selection_bg_hex="#183A3F",
    user_message_bg_hex=_user_message_bg("#101113"),
    info_badge_bg_hex="#DCE0E5",
    inactive_badge_bg_hex="#66707A",
    active_badge_bg_hex="#06B6D4",
    success_badge_bg_hex="#22C55E",
    danger_badge_bg_hex="#EF4444",
    risk_badge_bg_hex="#EF4444",
)

ACCESSIBLE_TERMINAL_PALETTE = ShellPalette(
    theme_name="accessible",
    accent_ansi=Fore.LIGHTYELLOW_EX,
    text_ansi=Fore.LIGHTWHITE_EX,
    muted_ansi=Fore.LIGHTBLACK_EX,
    info_ansi=Fore.LIGHTWHITE_EX,
    success_ansi=Fore.CYAN,
    warn_ansi=Fore.LIGHTYELLOW_EX,
    error_ansi=Fore.LIGHTRED_EX,
    risk_ansi=Fore.LIGHTMAGENTA_EX,
    tip_ansi=Fore.LIGHTYELLOW_EX,
    path_ansi=Fore.WHITE,
    prompt_brand_hex="#E69F00",
    prompt_path_hex="#F2F1E8",
    prompt_sep_hex="#8A8577",
    background_hex="#161514",
    completion_meta_hex="#B8B09F",
    toolbar_text_hex="#F2F1E8",
    toolbar_key_fg_hex="#161514",
    toolbar_key_bg_hex="#E69F00",
    toolbar_sep_hex="#7D776B",
    toolbar_label_hex="#E8E3D5",
    toolbar_meta_hex="#B8B09F",
    input_bg_hex="#161514",
    selection_bg_hex="#243642",
    user_message_bg_hex=_user_message_bg("#161514"),
    info_badge_bg_hex="#F2F1E8",
    inactive_badge_bg_hex="#7D776B",
    active_badge_bg_hex="#56B4E9",
    success_badge_bg_hex="#009E73",
    danger_badge_bg_hex="#D55E00",
    risk_badge_bg_hex="#CC79A7",
)

ANSI_TERMINAL_PALETTE = ShellPalette(
    theme_name="ansi",
    accent_ansi=Fore.MAGENTA,
    text_ansi=Fore.LIGHTWHITE_EX,
    muted_ansi=Fore.LIGHTBLACK_EX,
    info_ansi=Fore.LIGHTWHITE_EX,
    success_ansi=Fore.GREEN,
    warn_ansi=Fore.CYAN,
    error_ansi=Fore.RED,
    risk_ansi=Fore.RED,
    tip_ansi=Fore.CYAN,
    path_ansi=Fore.WHITE,
    prompt_brand_hex="#AF5FFF",
    prompt_path_hex="#E5E5E5",
    prompt_sep_hex="#808080",
    background_hex="#101010",
    completion_meta_hex="#A8A8A8",
    toolbar_text_hex="#E5E5E5",
    toolbar_key_fg_hex="#101010",
    toolbar_key_bg_hex="#00AFAF",
    toolbar_sep_hex="#808080",
    toolbar_label_hex="#D7D7D7",
    toolbar_meta_hex="#A8A8A8",
    input_bg_hex="#101010",
    selection_bg_hex="#303030",
    user_message_bg_hex=_user_message_bg("#101010"),
    info_badge_bg_hex="#D7D7D7",
    inactive_badge_bg_hex="#808080",
    active_badge_bg_hex="#00AFAF",
    success_badge_bg_hex="#5FAF5F",
    danger_badge_bg_hex="#D75F5F",
    risk_badge_bg_hex="#D75F5F",
)

THEME_PALETTES = {
    "dark": TERMINAL_PALETTE,
    "graphite": GRAPHITE_TERMINAL_PALETTE,
    "accessible": ACCESSIBLE_TERMINAL_PALETTE,
    "ansi": ANSI_TERMINAL_PALETTE,
}

SHELL_CHROME = ShellChromeConfig(
    app_name=PROJECT_NAME,
    subtitle=PROJECT_SUBTITLE,
    prompt_brand=PROMPT_BRAND,
    help_command="/help",
    input_hint=INPUT_HINT,
    reserve_space_for_menu=7,
)
