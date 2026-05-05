from app.shell_template import ShellChromeConfig, ShellPalette


PROJECT_NAME = "SECOPS"
PROJECT_SUBTITLE = "agent pentest"
PROMPT_BRAND = "secops"
INPUT_HINT = "parle a secops ou utilise /help"

PROJECT_OWNER = "SECOPS TEAM"
PROJECT_SLUG = "secops-agent"

TERMINAL_PALETTE = ShellPalette(
    prompt_brand_hex="#fdc910",
    prompt_path_hex="#f8fafc",
    prompt_sep_hex="#6b7280",
    background_hex="#111111",
    completion_meta_hex="#a1a1aa",
    toolbar_text_hex="#f8fafc",
    toolbar_key_fg_hex="#111111",
    toolbar_key_bg_hex="#fdc910",
    toolbar_sep_hex="#737373",
    toolbar_label_hex="#f5f5f5",
    toolbar_meta_hex="#d4d4d8",
    inactive_badge_bg_hex="#52525b",
    active_badge_bg_hex="#fde047",
    success_badge_bg_hex="#86efac",
    danger_badge_bg_hex="#b91c1c",
)

SHELL_CHROME = ShellChromeConfig(
    app_name=PROJECT_NAME,
    subtitle=PROJECT_SUBTITLE,
    prompt_brand=PROMPT_BRAND,
    help_command="/help",
    input_hint=INPUT_HINT,
)
