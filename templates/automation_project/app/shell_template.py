import html
import json
import os
import re
import shlex
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

from colorama import Fore, Style as AnsiStyle, init
from prompt_toolkit import PromptSession
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.history import FileHistory
from prompt_toolkit.styles import Style as PTStyle


if os.name == "nt":
    init(autoreset=True, convert=True)
else:
    init(autoreset=True)

if getattr(sys.stdout, "encoding", "").lower() != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def safe_split(text):
    try:
        return shlex.split(text, posix=False)
    except ValueError:
        return text.split()


@dataclass(frozen=True)
class ShellPalette:
    accent_ansi: str = Fore.YELLOW
    text_ansi: str = Fore.LIGHTWHITE_EX
    muted_ansi: str = Fore.LIGHTBLACK_EX
    info_ansi: str = Fore.YELLOW
    success_ansi: str = Fore.LIGHTGREEN_EX
    warn_ansi: str = Fore.LIGHTYELLOW_EX
    error_ansi: str = Fore.LIGHTRED_EX
    tip_ansi: str = Fore.YELLOW
    path_ansi: str = Fore.WHITE
    prompt_brand_hex: str = "#fdc910"
    prompt_path_hex: str = "#f8fafc"
    prompt_sep_hex: str = "#6b7280"
    background_hex: str = "#111111"
    completion_meta_hex: str = "#a1a1aa"
    toolbar_text_hex: str = "#f8fafc"
    toolbar_key_fg_hex: str = "#111111"
    toolbar_key_bg_hex: str = "#fdc910"
    toolbar_sep_hex: str = "#737373"
    toolbar_label_hex: str = "#f5f5f5"
    toolbar_meta_hex: str = "#d4d4d8"
    inactive_badge_bg_hex: str = "#52525b"
    active_badge_bg_hex: str = "#fde047"
    success_badge_bg_hex: str = "#86efac"
    danger_badge_bg_hex: str = "#b91c1c"

    def prompt_style_dict(self):
        return {
            "prompt.brand": f"fg:{self.prompt_brand_hex} bold",
            "prompt.path": f"fg:{self.prompt_path_hex}",
            "prompt.sep": f"fg:{self.prompt_sep_hex}",
            "completion-menu.completion": (
                f"bg:{self.background_hex} fg:{self.toolbar_text_hex}"
            ),
            "completion-menu.completion.current": (
                f"bg:{self.prompt_brand_hex} fg:{self.toolbar_key_fg_hex}"
            ),
            "completion-menu.meta.completion": (
                f"bg:{self.background_hex} fg:{self.completion_meta_hex}"
            ),
            "completion-menu.meta.completion.current": (
                f"bg:{self.prompt_brand_hex} fg:{self.toolbar_sep_hex}"
            ),
            "bottom-toolbar": f"fg:{self.toolbar_text_hex} noinherit noreverse",
            "toolbar.key": (
                f"fg:{self.toolbar_key_fg_hex} bg:{self.toolbar_key_bg_hex} bold"
            ),
            "toolbar.sep": f"fg:{self.toolbar_sep_hex} noinherit noreverse",
            "toolbar.label": f"fg:{self.toolbar_label_hex} noinherit noreverse",
            "toolbar.meta": f"fg:{self.toolbar_meta_hex} noinherit noreverse",
            "toolbar.value.info": f"fg:{self.toolbar_label_hex} noinherit noreverse",
            "toolbar.value.success": f"fg:{self.success_badge_bg_hex} noinherit noreverse",
            "toolbar.value.warn": f"fg:{self.active_badge_bg_hex} noinherit noreverse",
            "toolbar.value.error": f"fg:{self.danger_badge_bg_hex} noinherit noreverse",
            "prompt.placeholder": f"fg:{self.toolbar_sep_hex} italic",
        }

    def tone_ansi(self, tone):
        return {
            "neutral": self.accent_ansi,
            "info": self.info_ansi,
            "success": self.success_ansi,
            "warn": self.warn_ansi,
            "error": self.error_ansi,
            "muted": self.muted_ansi,
            "path": self.path_ansi,
        }.get(tone, self.text_ansi)

    def badge_colors(self, tone):
        return {
            "neutral": (self.toolbar_key_fg_hex, self.prompt_brand_hex),
            "info": (self.toolbar_key_fg_hex, self.prompt_brand_hex),
            "success": (self.toolbar_key_fg_hex, self.success_badge_bg_hex),
            "warn": (self.toolbar_key_fg_hex, self.active_badge_bg_hex),
            "error": ("#ffffff", self.danger_badge_bg_hex),
            "muted": ("#ffffff", self.inactive_badge_bg_hex),
            "path": (self.toolbar_key_fg_hex, self.active_badge_bg_hex),
        }.get(tone, ("#ffffff", self.inactive_badge_bg_hex))


@dataclass(frozen=True)
class ShellChromeConfig:
    app_name: str
    subtitle: str
    prompt_brand: str = "shell"
    help_command: str = "/help"
    input_hint: str = "commande ou code"
    history_file_name: str = "history.txt"
    state_file_name: str = "session_state.json"
    min_box_width: int = 56
    max_box_width: int = 68
    reserve_space_for_menu: int = 8


@dataclass(frozen=True)
class StatusEntry:
    label: str
    value: str
    tone: str = "info"


@dataclass(frozen=True)
class ActionChip:
    label: str
    tone: str = "info"


@dataclass
class PanelState:
    title: str = "Bienvenue"
    lines: list[str] = field(default_factory=list)
    tone: str = "info"
    variant: str = "panel"


class TemplateShellCompleter(Completer):
    def __init__(
        self,
        command_specs,
        command_aliases,
        keyword_provider,
        keyword_commands,
    ):
        self.command_specs = command_specs
        self.command_aliases = command_aliases
        self.keyword_provider = keyword_provider
        self.keyword_commands = set(keyword_commands)

    def _yield_command_completions(self, prefix):
        for command, description in self.command_specs.items():
            if command.startswith(prefix):
                yield Completion(
                    command,
                    start_position=-len(prefix),
                    display_meta=description,
                )

    def _yield_keyword_completions(self, prefix):
        catalog = self.keyword_provider()
        for token, description in catalog.items():
            if token.casefold().startswith(prefix.casefold()):
                yield Completion(
                    token,
                    start_position=-len(prefix),
                    display_meta=description,
                )

    def get_completions(self, document, complete_event):
        text = document.text_before_cursor.lstrip()
        if not text:
            return

        parts = safe_split(text)
        if text.endswith(" "):
            parts.append("")
        if not parts:
            return

        head = parts[0].lower()
        current = parts[-1]

        if len(parts) == 1 and not text.endswith(" "):
            yield from self._yield_command_completions(parts[0].lower())
            if not parts[0].startswith("/"):
                yield from self._yield_keyword_completions(parts[0])
            return

        if head in self.keyword_commands:
            yield from self._yield_keyword_completions(current)


class BaseTerminalShell:
    def __init__(
        self,
        *,
        base_dir,
        chrome,
        command_specs,
        command_aliases=None,
        legacy_aliases=None,
        tips=None,
        palette=None,
        keyword_completion_commands=None,
    ):
        self.base_dir = Path(base_dir).resolve()
        self.chrome = chrome
        self.command_specs = dict(command_specs)
        self.command_aliases = dict(command_aliases or {})
        self.legacy_aliases = dict(legacy_aliases or {})
        self.tips = list(tips or [])
        self.palette = palette or ShellPalette()
        self.keyword_completion_commands = tuple(
            keyword_completion_commands
            or ("/add", "/remove", "/find", "/run", "add", "remove", "find", "run")
        )

        self.config_dir = self.base_dir / "config"
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.history_file = self.config_dir / self.chrome.history_file_name
        self.state_file = self.config_dir / self.chrome.state_file_name

        self.panel = PanelState(
            "Bienvenue",
            ["Shell pret.", "Definis maintenant tes commandes et ton moteur metier."],
            "info",
        )
        self.tip_index = 0
        self.session = None
        self.completer = TemplateShellCompleter(
            self.command_specs,
            self.command_aliases,
            self.get_keyword_catalog,
            self.keyword_completion_commands,
        )
        self.prompt_style = PTStyle.from_dict(self.palette.prompt_style_dict())
        self.load_state()

    def get_keyword_catalog(self):
        return {}

    def get_highlight_tokens(self):
        return tuple(self.get_keyword_catalog().keys())

    def build_state_payload(self):
        return {}

    def apply_state_payload(self, payload):
        return None

    def initialize_interactive(self):
        return None

    def get_status_entries(self):
        return []

    def get_next_action_hint(self):
        if not self.tips:
            return ""
        return self.tips[self.tip_index % len(self.tips)]

    def get_context_actions(self):
        return []

    def get_last_run_meta(self):
        return None

    def get_prompt_context_label(self):
        return "."

    def resolve_bare_tokens(self, tokens):
        return None

    def handle_unresolved_text(self, raw_text):
        self.set_panel(
            "Commande inconnue",
            [raw_text, f"Tape {self.chrome.help_command} pour voir les commandes."],
            tone="error",
        )
        return True

    def dispatch_command(self, command, args):
        raise NotImplementedError

    def clear_screen(self):
        os.system("cls" if os.name == "nt" else "clear")

    def display_path(self, path):
        path = Path(path)
        try:
            return str(path.resolve().relative_to(self.base_dir.resolve()))
        except Exception:
            return str(path)

    def persistable_path(self, path):
        path = Path(path)
        try:
            return str(path.resolve().relative_to(self.base_dir.resolve()))
        except Exception:
            return str(path.resolve())

    def load_state(self):
        if not self.state_file.exists():
            return

        try:
            payload = json.loads(self.state_file.read_text(encoding="utf-8"))
        except Exception:
            return

        if isinstance(payload, dict):
            self.apply_state_payload(payload)

    def save_state(self):
        payload = self.build_state_payload()
        try:
            self.state_file.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except Exception:
            pass

    def set_panel(self, title, lines, tone="info", max_lines=None, variant="panel"):
        normalized_lines = list(lines)
        if max_lines is not None:
            normalized_lines = normalized_lines[:max_lines]
        self.panel = PanelState(title, normalized_lines, tone, variant)

    def advance_tip(self):
        if self.tips:
            self.tip_index = (self.tip_index + 1) % len(self.tips)

    def _box_width(self):
        columns = shutil.get_terminal_size(fallback=(92, 24)).columns
        return max(
            self.chrome.min_box_width,
            min(self.chrome.max_box_width, columns - 12),
        )

    def _fit_ansi(self, text, width):
        visible = ANSI_RE.sub("", text)
        if len(visible) > width:
            return visible[:width]
        return text + (" " * (width - len(visible)))

    def _colorize_inline(self, text):
        if not text:
            return text

        colored = re.sub(
            r"\b[^\s]+\.(xlsx|xls|csv|json|log|txt|md)\b",
            lambda match: (
                f"{self.palette.path_ansi}{match.group(0)}"
                f"{AnsiStyle.RESET_ALL}{self.palette.text_ansi}"
            ),
            text,
            flags=re.IGNORECASE,
        )

        colored = re.sub(
            r"(?<!\w)(/[\w-]+)",
            lambda match: (
                f"{self.palette.accent_ansi}{AnsiStyle.BRIGHT}{match.group(1)}"
                f"{AnsiStyle.RESET_ALL}{self.palette.text_ansi}"
            ),
            colored,
        )

        for token in sorted(self.get_highlight_tokens(), key=len, reverse=True):
            colored = re.sub(
                rf"\b{re.escape(token)}\b",
                (
                    f"{self.palette.warn_ansi}{AnsiStyle.BRIGHT}{token}"
                    f"{AnsiStyle.RESET_ALL}{self.palette.text_ansi}"
                ),
                colored,
            )

        return colored

    _PORT_PATTERN = re.compile(r"\d+/(tcp|udp)\s+open\s+")
    _RETURNCODE_PATTERN = re.compile(r"(?:code retour|returncode):\s*[1-9]")
    _CRED_PATTERN = re.compile(r"(password|credential|hydra://|login:)", re.IGNORECASE)

    def _semantic_line_color(self, line):
        """Return an ANSI color for a line based on its semantic content."""
        stripped = line.strip()
        if stripped.startswith("◦ "):
            return self.palette.muted_ansi
        if stripped.startswith("│ "):
            if "stderr:" in stripped or "erreur" in stripped:
                return self.palette.warn_ansi
            return self.palette.muted_ansi
        if self._RETURNCODE_PATTERN.search(stripped):
            return self.palette.error_ansi
        if self._CRED_PATTERN.search(stripped):
            return f"{self.palette.error_ansi}{AnsiStyle.BRIGHT}"
        if self._PORT_PATTERN.search(stripped):
            return self.palette.success_ansi
        return self.palette.text_ansi

    def _format_status_row(self, entries):
        parts = []
        for entry in entries:
            parts.append(
                f"{self.palette.muted_ansi}{entry.label}{AnsiStyle.RESET_ALL} "
                f"{self.palette.tone_ansi(entry.tone)}{entry.value}{AnsiStyle.RESET_ALL}"
            )
        return f"{self.palette.accent_ansi} • {AnsiStyle.RESET_ALL}".join(parts)

    def _status_rows(self):
        entries = [entry for entry in self.get_status_entries() if entry.value]
        rows = []
        for index in range(0, min(len(entries), 6), 2):
            rows.append(self._format_status_row(entries[index : index + 2]))
        return rows

    def _normalize_action(self, action):
        if isinstance(action, ActionChip):
            return action
        label, tone = action
        return ActionChip(label=label, tone=tone)

    def _command_chip(self, action):
        action = self._normalize_action(action)
        color = self.palette.tone_ansi(action.tone)
        return (
            f"{color}[{AnsiStyle.BRIGHT}{action.label}{AnsiStyle.RESET_ALL}{color}]"
            f"{AnsiStyle.RESET_ALL}"
        )

    def _render_actions(self):
        actions = self.get_context_actions()
        if not actions:
            return
        chips = [self._command_chip(action) for action in actions]
        joiner = f" {self.palette.muted_ansi}·{AnsiStyle.RESET_ALL} "
        print(f"{self.palette.muted_ansi}actions{AnsiStyle.RESET_ALL} {joiner.join(chips)}")

    def _render_last_run_meta(self):
        meta = self.get_last_run_meta()
        if not meta:
            return
        print(
            f"{self.palette.muted_ansi}last run{AnsiStyle.RESET_ALL} "
            f"{self.palette.accent_ansi}{meta}{AnsiStyle.RESET_ALL}"
        )

    def _print_box(self, lines, width=72, tone="neutral"):
        color = self.palette.tone_ansi(tone)
        top = f"{color}╭{'─' * (width + 2)}╮{AnsiStyle.RESET_ALL}"
        side = f"{color}│{AnsiStyle.RESET_ALL}"
        bottom = f"{color}╰{'─' * (width + 2)}╯{AnsiStyle.RESET_ALL}"
        print(top)
        for line in lines:
            fitted = self._fit_ansi(line, width)
            print(f"{side} {fitted} {color}│{AnsiStyle.RESET_ALL}")
        print(bottom)

    def render_dashboard(self):
        self.clear_screen()

        self.render_shell_header()
        self.render_panel_state()

    def render_shell_header(self):
        box_lines = [
            (
                f"{self.palette.accent_ansi}{AnsiStyle.BRIGHT}{self.chrome.app_name}"
                f"{AnsiStyle.RESET_ALL}"
            ),
            (
                f"{self.palette.text_ansi}{self.chrome.subtitle}{AnsiStyle.RESET_ALL}"
                f"{self.palette.muted_ansi}  ·  {self.chrome.help_command}"
                f"{AnsiStyle.RESET_ALL}"
            ),
            "",
            *self._status_rows(),
        ]

        self._print_box(box_lines, width=self._box_width(), tone="neutral")
        print()

        self._render_actions()
        self._render_last_run_meta()
        print()

    def render_panel_state(self):
        panel_icon = {
            "info": "●",
            "success": "✓",
            "warn": "!",
            "error": "✕",
        }.get(self.panel.tone, "•")
        tone_color = self.palette.tone_ansi(self.panel.tone)
        if self.panel.variant == "plain":
            if not self.panel.lines:
                return
            for line in self.panel.lines:
                print(
                    f"{tone_color}{self._colorize_inline(line)}{AnsiStyle.RESET_ALL}"
                )
            print()
            return
        if self.panel.variant == "transcript":
            if not self.panel.lines:
                print()
                return
            for line in self.panel.lines:
                if not line:
                    print()
                    continue
                line_color = self._semantic_line_color(line)
                stripped = line.lstrip()
                if stripped.startswith("◦ "):
                    # Thought line — render dim without extra bullet
                    print(
                        f"  {line_color}{self._colorize_inline(line)}"
                        f"{AnsiStyle.RESET_ALL}"
                    )
                elif stripped.startswith("• ") or stripped.startswith("└ ") or stripped.startswith("│ "):
                    # Tool activity — keep as-is
                    print(
                        f"{line_color}{self._colorize_inline(line)}"
                        f"{AnsiStyle.RESET_ALL}"
                    )
                else:
                    # Regular text (answer, etc)
                    print(
                        f"{line_color}{self._colorize_inline(line)}"
                        f"{AnsiStyle.RESET_ALL}"
                    )
            print()
            return
        if not self.panel.title:
            if not self.panel.lines:
                return
            for line in self.panel.lines:
                print(
                    f"{tone_color}{self._colorize_inline(line)}{AnsiStyle.RESET_ALL}"
                )
            print()
            return
        print(f"{tone_color}{AnsiStyle.BRIGHT}{panel_icon} {self.panel.title}{AnsiStyle.RESET_ALL}")
        for line in self.panel.lines:
            print(
                f"  {tone_color}•{AnsiStyle.RESET_ALL} "
                f"{self.palette.text_ansi}{self._colorize_inline(line)}{AnsiStyle.RESET_ALL}"
            )
        print()

    def _toolbar(self):
        statuses = self.get_status_entries()[:2]
        parts = [
            "<bottom-toolbar> </bottom-toolbar>",
            "<toolbar.key> Tab </toolbar.key>",
            "<toolbar.label> autocomplete </toolbar.label>",
            "<toolbar.sep> │ </toolbar.sep>",
            "<toolbar.key> ↑↓ </toolbar.key>",
            "<toolbar.label> history </toolbar.label>",
        ]

        for entry in statuses:
            fg_hex, bg_hex = self.palette.badge_colors(entry.tone)
            parts.extend(
                [
                    "<toolbar.sep> │ </toolbar.sep>",
                    f"<toolbar.meta>{html.escape(entry.label)}</toolbar.meta>",
                    "<bottom-toolbar> </bottom-toolbar>",
                    (
                        f"<style fg='{fg_hex}' bg='{bg_hex}'> "
                        f"{html.escape(entry.value)} "
                        "</style>"
                    ),
                ]
            )

        parts.extend(
            [
                "<toolbar.sep> │ </toolbar.sep>",
                f"<toolbar.label>{html.escape(self.chrome.input_hint)}</toolbar.label>",
                "<bottom-toolbar> </bottom-toolbar>",
            ]
        )
        return HTML("".join(parts))

    def prompt(self):
        if self.session is None:
            self.session = PromptSession(history=FileHistory(str(self.history_file)))

        prompt_label = html.escape(self.get_prompt_context_label())
        hint = self.get_next_action_hint()
        placeholder = HTML(f"<prompt.placeholder>{html.escape(hint)}</prompt.placeholder>") if hint else None

        return self.session.prompt(
            HTML(
                f"<prompt.brand>{html.escape(self.chrome.prompt_brand)}</prompt.brand>"
                "<prompt.sep> • </prompt.sep>"
                f"<prompt.path>{prompt_label}</prompt.path>"
                "<prompt.sep> &gt; </prompt.sep>"
            ),
            completer=self.completer,
            complete_while_typing=True,
            auto_suggest=AutoSuggestFromHistory(),
            bottom_toolbar=self._toolbar,
            style=self.prompt_style,
            reserve_space_for_menu=self.chrome.reserve_space_for_menu,
            placeholder=placeholder,
        )

    def process_input(self, raw_text):
        tokens = safe_split(raw_text.strip())
        if not tokens:
            return True

        if not tokens[0].startswith("/"):
            return self.handle_unresolved_text(raw_text)

        return self.dispatch_command(tokens[0].lower(), tokens[1:])

    def interactive_loop(self):
        self.initialize_interactive()
        while True:
            self.render_dashboard()
            try:
                raw_text = self.prompt()
            except (EOFError, KeyboardInterrupt):
                print("\n")
                return

            if not raw_text.strip():
                continue

            keep_running = self.process_input(raw_text)
            self.advance_tip()
            if not keep_running:
                print()
                return
