import importlib
import json
import os
import platform
import pydoc
import re
import shlex
import shutil
import subprocess
import sys
import textwrap
import threading
import time
import tomllib
import html
from datetime import datetime
from dataclasses import asdict, replace
from pathlib import Path

from colorama import Style as AnsiStyle
from prompt_toolkit import PromptSession as BasePromptSession
from prompt_toolkit.application import Application
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.filters import Condition, is_done, renderer_height_is_known
from prompt_toolkit.formatted_text import HTML, to_formatted_text
from prompt_toolkit.history import FileHistory
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.key_binding.key_processor import KeyPress
from prompt_toolkit.keys import Keys
from prompt_toolkit.layout import ConditionalContainer, HSplit, Layout, Window
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.layout.dimension import Dimension
from prompt_toolkit.widgets import Box, Label, RadioList, TextArea

from app.agent_loop import AgentLoop
from app.branding import SHELL_CHROME, TERMINAL_PALETTE, THEME_PALETTES
from app.gemini_client import (
    GeminiClientError,
    GeminiConfigurationError,
    GeminiDependencyError,
    GeminiClient,
)
from app.jobs import JobTracker
from app.knowledge_store import KnowledgeStore
from app.learning_journal import LearningJournal
from app.llm_client import ToolCallingLLMClient
from app.shell_template import BaseTerminalShell, StatusEntry, safe_split
from app.settings import (
    DEFAULT_WORKSPACE_DIR,
    get_gemini_api_env_hint,
    get_gemini_runtime_config,
    load_project_env,
)
from app.terminal_renderer import TerminalRenderer
from app.tool_executor import (
    InteractiveAdminRequired,
    MissingTargetError,
    PermissionDenied,
    ScopeViolationError,
    ToolExecutionError,
    ToolExecutor,
    ToolMissingError,
)
from app.tool_policy import ToolPolicyError
from app.target_context import Target, detect_targets, build_target_context, merge_findings
from app.tool_registry import ToolRegistry
from app.methodology import EngagementState, PentestPhase, parse_phase, PHASE_METADATA
from app.findings import FindingsStore
from app.model_router import (
    DEFAULT_MODEL,
    MODEL_PRESETS,
    get_model_profile,
    resolve_model_name,
    route_model,
)
from app.report_generator import generate_pentest_report
from app.audit_logger import AuditLogger
from app.attack_planner import format_plan_display
from app.session_state import (
    SessionState,
    save_session,
    load_session,
    list_sessions,
)


COMMAND_SPECS = {
    "/help": "Afficher les commandes disponibles",
    "/doctor": "Verifier la configuration locale de SECOPS",
    "/status": "Afficher l'etat courant de la session",
    "/stats": "Afficher les statistiques de la session",
    "/case": "Lister, afficher ou activer un cas memoire",
    "/target": "Lister, afficher ou definir la cible",
    "/phase": "Afficher ou changer la phase pentest",
    "/model": "Afficher ou changer le modele LLM de la session",
    "/theme": "Afficher ou changer le theme du terminal",
    "/reasoning": "Afficher ou changer l'affichage du raisonnement",
    "/profile": "Afficher ou changer le profil UX",
    "/statusline": "Configurer les champs de la statusline",
    "/notify": "Configurer les notifications de fin de tache",
    "/scope": "Definir ou afficher le scope autorise (IPs/CIDRs/domaines/URLs)",
    "/permissions": "Afficher ou changer le mode d'autorisation des commandes",
    "/compact": "Compacter le contexte agent pour reduire les tokens",
    "/side": "Poser une question laterale sans modifier le contexte agent",
    "/btw": "Poser une question laterale ephemere sans modifier le contexte agent",
    "/view": "Afficher le dernier output complet ou le log d'un job",
    "/copy": "Copier ou sauvegarder le dernier panneau affiche",
    "/tools": "Lister ou installer les outils pentest disponibles",
    "/jobs": "Afficher ou annuler les taches en attente, en cours ou terminees",
    "/learn": "Afficher les apprentissages recents de la session",
    "/findings": "Afficher les decouvertes accumulees",
    "/plan": "Afficher le plan d'attaque genere depuis les findings",
    "/export": "Exporter les decouvertes (json, md ou les deux)",
    "/report": "Generer un rapport de pentest structure",
    "/session": "Sauvegarder ou lister une session pentest",
    "/resume": "Reprendre une session sauvegardee",
    "/rewind": "Restaurer le dernier checkpoint de securite",
    "/workflow": "Lister ou executer un workflow pentest",
    "/clear": "Effacer l'ecran et reafficher le header",
    "/quit": "Quitter le shell",
}

TIPS = [
    "Decris ton objectif, une cible, un service ou une action locale.",
    "Exemple: nmap 10.10.10.10, analyse SMB, ou mets a jour le systeme local.",
    "Utilise /case list puis /case <slug> pour activer une memoire de lab si utile.",
    "Utilise /phase pour voir ou changer la phase pentest (recon, enum, exploit...).",
    "Utilise /tools pour voir les outils pentest disponibles sur cette machine.",
    "Tape / seul pour ouvrir la palette de commandes sans polluer l'historique.",
    "Utilise @findings, @target, @case ou @log:last pour injecter un contexte precis.",
]

TEXT_TARGET_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
INSTALL_CONFIRM_RE = re.compile(
    r"^\s*(oui|o|ok|okay|yes|yep|vas-y|vas y|go)\b",
    re.IGNORECASE,
)
INSTALL_DECLINE_RE = re.compile(
    r"^\s*(non|n|annule|stop|pas maintenant|laisse tomber)\b",
    re.IGNORECASE,
)
LOCAL_SYSTEM_RE = re.compile(
    r"(?:\bapt(?:-get)?\b|\bsudo\b|\bupgrade\b|\bfull-upgrade\b|\bdist-upgrade\b|"
    r"\bautoremove\b|mise\s+à?\s+jour|mettre\s+à?\s+jour)",
    re.IGNORECASE,
)
CASE_RELEVANT_RE = re.compile(
    r"(?:\btryhackme\b|\bhackthebox\b|\bhtb\b|\bthm\b|\blab\b|\broom\b|\brooms\b|"
    r"\bscan\b|\benumeration\b|\bénumération\b|\brecon\b|\breconnaissance\b|"
    r"\bexploit(?:ation)?\b|\bvuln(?:erabilite|érabilité)?s?\b|\bservice\b|\bport\b|"
    r"\bsmb\b|\bssh\b|\bftp\b|\bhttp\b|\bweb\b|\bcible\b|\btarget\b)",
    re.IGNORECASE,
)
TRACKED_TOOL_JOBS = {
    "scan_target",
    "enumerate_web",
    "search_exploit",
    "analyze_service",
    "execute_command",
    "execute_admin_command",
}
RISKY_TOOL_EVENTS = {
    "execute_admin_command",
    "execute_parallel",
    "exploit_workflow",
    "test_credentials",
}
RISKY_COMMAND_EXECUTABLES = {
    "bash",
    "hashcat",
    "hydra",
    "john",
    "msfconsole",
    "nc",
    "netcat",
    "perl",
    "python",
    "python3",
    "ruby",
    "searchsploit",
    "sh",
    "sqlmap",
}
TRACKED_COMMAND_EXECUTABLES = {
    "dirb",
    "enum4linux",
    "ffuf",
    "gobuster",
    "hydra",
    "john",
    "masscan",
    "nikto",
    "nmap",
    "searchsploit",
    "sqlmap",
    "whatweb",
    "wpscan",
}
TRANSIENT_COMMANDS = {
    "/model",
    "/phase",
    "/scope",
    "/permissions",
    "/compact",
    "/btw",
    "/theme",
    "/reasoning",
    "/profile",
    "/statusline",
    "/notify",
    "/help",
    "/doctor",
    "/clear",
    "/__transcript",
    "/__history_search",
}
PANEL_TRANSIENT_COMMANDS = {
    "/case",
    "/findings",
    "/jobs",
    "/learn",
    "/plan",
    "/rewind",
    "/session",
    "/stats",
    "/status",
    "/target",
    "/workflow",
}
REASONING_MODES = {"hidden", "summary", "full"}
UX_PROFILES = {"quiet", "ops", "debug"}
STATUSLINE_FIELDS = ("model", "target", "phase", "scope", "findings", "jobs", "context")
DEFAULT_STATUSLINE_FIELDS = ("phase", "target", "findings", "jobs")
NOTIFICATION_MODES = {"off", "bell", "title", "all"}
THINKING_LEVELS = ("default", "off", "minimal", "low", "medium", "high", "max")
EXPLICIT_THINKING_LEVELS = tuple(level for level in THINKING_LEVELS if level != "default")
MODEL_PICKER_EFFORT_LEVELS = ("low", "medium", "high", "max")
MODEL_PICKER_NAME_WIDTH = 49
CODEX_PERMISSION_CHOICES = (
    (
        "ask",
        "Default",
        "Codex can read and edit files in the current workspace, and run commands. "
        "Approval is required to access the internet or edit other files.",
    ),
    (
        "auto-low-risk",
        "Auto-review",
        "Same workspace-write permissions as Default, but eligible `on-request` approvals "
        "are routed through the auto-reviewer subagent.",
    ),
    (
        "session",
        "Full Access",
        "Codex can edit files outside this workspace and access the internet without asking "
        "for approval. Exercise caution when using.",
    ),
)
COMMAND_MENU_ENTRIES = (
    {"command": "/model", "shortcut": "m", "description": "Choix du modele LLM"},
    {"command": "/permissions", "shortcut": "a", "description": "Autorisations commandes"},
    {"command": "/theme", "shortcut": "h", "description": "Theme dark graphite accessible ansi"},
    {"command": "/reasoning", "shortcut": "th", "description": "Affichage du raisonnement"},
    {"command": "/profile", "shortcut": "u", "description": "Profil UX quiet ops debug"},
    {"command": "/statusline", "shortcut": "z", "description": "Champs de la statusline"},
    {"command": "/notify", "shortcut": "b", "description": "Notifications fin de tache"},
    {"command": "/status", "shortcut": "s", "description": "Etat courant de la session"},
    {"command": "/doctor", "shortcut": "d", "description": "Diagnostic local et prerequis"},
    {"command": "/stats", "shortcut": "t", "description": "Statistiques de session"},
    {"command": "/phase", "shortcut": "p", "description": "Phase pentest active"},
    {"command": "/scope", "shortcut": "o", "description": "Scope autorise"},
    {"command": "/compact", "shortcut": "k", "description": "Compacter le contexte agent"},
    {"command": "/btw", "shortcut": "g", "description": "Question laterale ephemere"},
    {"command": "/target", "shortcut": "c", "description": "Cible active"},
    {"command": "/case", "shortcut": "e", "description": "Cas memoire"},
    {"command": "/tools", "shortcut": "i", "description": "Inventaire outils pentest"},
    {"command": "/jobs", "shortcut": "j", "description": "Jobs et annulation"},
    {"command": "/view", "shortcut": "v", "description": "Logs et outputs complets"},
    {"command": "/copy", "shortcut": "y", "description": "Copier ou sauvegarder"},
    {"command": "/findings", "shortcut": "f", "description": "Decouvertes accumulees"},
    {"command": "/plan", "shortcut": "l", "description": "Plan d'attaque"},
    {"command": "/export", "shortcut": "x", "description": "Export findings ou transcript"},
    {"command": "/session", "shortcut": "n", "description": "Sauvegarde et liste sessions"},
    {"command": "/resume", "shortcut": "r", "description": "Reprendre une session"},
    {"command": "/rewind", "shortcut": "w", "description": "Restaurer le dernier checkpoint"},
    {"command": "/workflow", "shortcut": "q", "description": "Workflows recon-web smb-enum"},
    {"command": "/help", "shortcut": "?", "description": "Aide commandes"},
)
PROMPT_PERMISSION_MODE_CYCLE = ("ask", "auto-low-risk", "read-only", "session")
CHOICE_LIST_VISIBLE_OPTIONS = 6
_PROMPT_MODULE = importlib.import_module("prompt_toolkit.shortcuts.prompt")


def command_completion_specs():
    ordered = {}
    for entry in COMMAND_MENU_ENTRIES:
        command = entry["command"]
        if command in COMMAND_SPECS:
            ordered[command] = entry["description"]
    for command, description in COMMAND_SPECS.items():
        ordered.setdefault(command, description)
    return ordered


class PromptSession(BasePromptSession):
    def _create_layout(self):
        original_completions_menu = _PROMPT_MODULE.CompletionsMenu

        def limited_completions_menu(*args, **kwargs):
            requested_height = kwargs.get("max_height")
            if requested_height is None:
                requested_height = CHOICE_LIST_VISIBLE_OPTIONS
            kwargs["max_height"] = min(int(requested_height), CHOICE_LIST_VISIBLE_OPTIONS)
            return original_completions_menu(*args, **kwargs)

        _PROMPT_MODULE.CompletionsMenu = limited_completions_menu
        try:
            return super()._create_layout()
        finally:
            _PROMPT_MODULE.CompletionsMenu = original_completions_menu


class CommandAwareAutoSuggest(AutoSuggestFromHistory):
    def get_suggestion(self, buffer, document):
        text = str(getattr(document, "text_before_cursor", "") or "")
        if text.lstrip().startswith("/"):
            return None
        return super().get_suggestion(buffer, document)


class ClaudeStyleRadioList(RadioList):
    def __init__(
        self,
        *args,
        max_visible_options=CHOICE_LIST_VISIBLE_OPTIONS,
        detail_style="class:menu.detail",
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.detail_style = detail_style
        visible_options = min(len(self.values), max(1, int(max_visible_options or len(self.values))))
        self.window.height = Dimension(preferred=visible_options, max=visible_options)

    @staticmethod
    def _split_option_label(label):
        if not isinstance(label, str):
            return None
        match = re.match(r"^(.+?)(\s{2,})(\S.*)$", label)
        if not match:
            return None
        return match.groups()

    def _get_text_fragments(self):
        result = []
        for index, value in enumerate(self.values):
            if self.multiple_selection:
                checked = value[0] in self.current_values
            else:
                checked = value[0] == self.current_value
            selected = index == self._selected_index

            style = self.selected_style if selected else self.default_style

            result.append((style, self.open_character))
            if selected:
                result.append(("[SetCursorPosition]", ""))
            result.append((style, self.select_character if checked else " "))
            result.append((style, self.close_character))
            result.append((style, " "))

            if self.show_numbers:
                number_style = style if selected else self.number_style
                result.append((number_style, f"{index + 1}. "))

            split_label = self._split_option_label(value[1])
            if split_label:
                label, spacing, description = split_label
                result.append((style, f"{label}{spacing}"))
                description_style = style if selected else (self.detail_style or style)
                result.append((description_style, description))
            else:
                result.extend(to_formatted_text(value[1], style=style))
            result.append(("", "\n"))

        result.pop()
        return result


class ActivitySpinner:
    def __init__(self, message):
        self.message = message
        self._stop_event = threading.Event()
        self._thread = None

    def start(self):
        if not sys.stdout.isatty() or self._thread is not None:
            return

        def _run():
            frames = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")
            index = 0
            while not self._stop_event.is_set():
                sys.stdout.write(f"\r{self.message} {frames[index % len(frames)]}")
                sys.stdout.flush()
                index += 1
                time.sleep(0.1)

        self._thread = threading.Thread(target=_run, daemon=True)
        self._thread.start()

    def stop(self):
        if self._thread is None:
            return
        self._stop_event.set()
        self._thread.join(timeout=0.3)
        sys.stdout.write("\r" + (" " * (len(self.message) + 4)) + "\r")
        sys.stdout.flush()
        self._thread = None


class AutomationProjectShell(BaseTerminalShell):
    def __init__(self):
        base_dir = Path(__file__).resolve().parents[1]
        load_project_env()
        self.repo_root = base_dir.parents[1]
        self.knowledge_root = self.repo_root / "knowledge"
        self.knowledge_store = KnowledgeStore.load(self.knowledge_root)
        self.gemini_runtime = get_gemini_runtime_config()
        self.model_auto_routing = False
        self.model_thinking_overrides = {}
        self.theme_name = "dark"
        self.reasoning_mode = "summary"
        self.ux_profile = "ops"
        self.statusline_fields = []
        self.notification_mode = "off"
        self.workspace = base_dir / DEFAULT_WORKSPACE_DIR
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.current_target = ""
        self.last_gemini_error = None
        self.active_case = None
        self._active_case_slug = ""
        self.conversation_history = []
        self._jobs_state_path = self.workspace / "jobs_state.json"
        self.jobs = JobTracker.load_state(self._jobs_state_path)
        self.learning_journal = LearningJournal(self.workspace / "learning" / "attempt_journal.jsonl")
        self._active_tool_jobs = {}
        self._last_active_tool_job_id = None
        self.live_agent_stream = True
        self.pending_tool_install = None
        self.pending_tool_retry = None
        self.pending_admin_command = None
        self._header_rendered = False
        self._stream_rendered_panel = False
        self._suppress_transient_result_once = False
        self._live_stream_state = None
        self._session_start = time.time()
        self._last_output_full = ""
        self._last_output_visible = ""
        self._last_output_log_path = ""
        self._transcript_entries = []
        self._prompt_draft = ""
        self.command_permission_mode = (
            os.getenv("SECOPS_COMMAND_MODE", "ask").strip().lower() or "ask"
        ).replace("_", "-")
        if self.command_permission_mode not in {
            "ask",
            "session",
            "deny",
            "read-only",
            "auto-low-risk",
        }:
            self.command_permission_mode = "ask"
        self.renderer = TerminalRenderer()
        self.tool_registry = ToolRegistry()
        self._findings_state_path = self.workspace / "findings_state.json"
        self.findings_store = FindingsStore.load_state(self._findings_state_path)
        self.engagement = EngagementState()
        self.targets: list[Target] = []
        self.active_target: Target | None = None
        self.tool_executor = ToolExecutor(
            workspace=self.workspace,
            knowledge_root=self.knowledge_root,
            knowledge_store=self.knowledge_store,
            permission_callback=self._request_tool_permission,
            command_permission_mode=self.command_permission_mode,
            allowed_commands=None,
            tool_registry=self.tool_registry,
            findings_store=self.findings_store,
            progress_callback=self._handle_tool_progress,
        )
        self.audit_logger = AuditLogger(self.workspace)
        self.llm_client = ToolCallingLLMClient(
            self._call_gemini_text,
            native_decision_runner=self._call_gemini_tool_decision,
        )
        self._apply_model_profile()
        self.agent_loop = AgentLoop(
            self.llm_client,
            self.tool_executor,
            audit_logger=self.audit_logger,
            learning_journal=self.learning_journal,
        )
        self.agent_loop.findings_store = self.findings_store
        self.agent_loop.engagement = self.engagement
        self.agent_loop.targets = self.targets
        self.agent_loop.active_target = self.active_target

        super().__init__(
            base_dir=base_dir,
            chrome=SHELL_CHROME,
            command_specs=command_completion_specs(),
            command_aliases={},
            legacy_aliases={},
            tips=TIPS,
            palette=THEME_PALETTES.get(self.theme_name, TERMINAL_PALETTE),
            keyword_completion_commands=("/case",),
        )

        self.set_panel("", [], tone="muted", variant="plain")

    def get_keyword_catalog(self):
        catalog = self.knowledge_store.catalog()
        catalog.update(
            {
                "@target": "cible active",
                "@findings": "decouvertes accumulees",
                "@case": "cas memoire actif",
                "@jobs": "taches recentes",
                "@log:last": "dernier log de commande",
            }
        )
        for tool in self.tool_registry.installed_tools:
            catalog[tool.name] = tool.description
        for target in self.targets:
            catalog[target.address] = target.target_type.value
        for entry in self._latest_history_entries()[:20]:
            command = str(entry).strip()
            if command.startswith("!") and len(command) > 1:
                catalog[command] = "commande shell recente"
        return catalog

    def _set_plain_panel(self, lines, tone="info", max_lines=None):
        self.set_panel("", lines, tone=tone, max_lines=max_lines, variant="plain")

    def _set_transcript_panel(
        self,
        title,
        lines,
        tone="info",
        max_lines=None,
        *,
        full_text=None,
        log_path="",
        source="panel",
    ):
        self.set_panel(
            title,
            lines,
            tone=tone,
            max_lines=max_lines,
            variant="transcript",
        )
        self._record_output_snapshot(
            title,
            self.panel.lines,
            full_text=full_text,
            log_path=log_path,
            source=source,
        )

    def _summarize_gemini_failure(self, failure_reason):
        text = (failure_reason or "").strip()
        lowered = text.casefold()
        if "resource_exhausted" in lowered or "quota exceeded" in lowered:
            return "Gemini indisponible temporairement, quota atteint."
        if "503" in lowered or "'status': 'unavailable'" in lowered or "unavailable" in lowered:
            return "Gemini indisponible temporairement (503)."
        if "403" in lowered:
            return "Acces Gemini refuse."
        if "api key" in lowered or "configuration" in lowered:
            return "Gemini non configure."
        return "Gemini indisponible."

    def _permission_toolbar(self):
        return HTML(
            "<toolbar.meta>↑↓ choisir</toolbar.meta>"
            "<toolbar.sep> · </toolbar.sep>"
            "<toolbar.meta>Tab option</toolbar.meta>"
            "<toolbar.sep> · </toolbar.sep>"
            "<toolbar.meta>Entrée valider</toolbar.meta>"
            "<toolbar.sep> · </toolbar.sep>"
            "<toolbar.meta>Y/N oui/non</toolbar.meta>"
            "<toolbar.sep> · </toolbar.sep>"
            "<toolbar.meta>Shift+Tab mode</toolbar.meta>"
            "<toolbar.sep> · </toolbar.sep>"
            "<toolbar.meta>Esc annuler</toolbar.meta>"
        )

    def _choose_permission_option(self, heading, fields, options, *, default=None):
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            return None

        body_lines = []
        for label, value in fields:
            if value:
                body_lines.append(f"{label:<8}: {value}")

        def permission_bindings(bindings, _radio_list):
            @bindings.add("tab")
            def _tab_next(event):
                event.key_processor.feed(KeyPress(Keys.Down), first=True)

            @bindings.add("space")
            def _space_accept(event):
                event.key_processor.feed(KeyPress(Keys.Enter), first=True)

            @bindings.add("y")
            @bindings.add("Y")
            def _accept_shortcut(event):
                event.app.exit(result="once", style="class:accepted")

            @bindings.add("n")
            @bindings.add("N")
            def _decline_shortcut(event):
                event.app.exit(result="deny", style="class:aborting")

            @bindings.add("s-tab")
            def _cycle_mode(event):
                self._cycle_prompt_permission_mode()
                event.app.invalidate()

        try:
            return self._run_inline_choice(
                heading,
                body_lines,
                options,
                default=default,
                select_character="›",
                extra_key_bindings=permission_bindings,
                footer_control=self._permission_toolbar,
            )
        except (EOFError, KeyboardInterrupt):
            return None

    def _erase_permission_prompt(self, message_line_count, option_count):
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            return
        # prompt_toolkit.choice leaves a compact menu in the scrollback; clear it
        # so the transcript only shows the action result, not the selection UI.
        lines_to_clear = message_line_count + option_count + 2
        sys.stdout.write(f"\x1b[{lines_to_clear}A\x1b[J")
        sys.stdout.flush()

    def _resolve_direct_target(self, prompt):
        self._capture_target_from_text(prompt)
        detected_target = self._extract_target_from_text(prompt)
        return detected_target or self.current_target

    def _reply_target_required(self, prompt, action_label):
        reply = f"J'ai besoin d'une cible IP ou d'un host pour {action_label}."
        self._remember_exchange(prompt, reply)
        self._set_transcript_panel("Agent", [reply], tone="warn")
        return True

    def build_state_payload(self):
        return {
            "workspace": self.persistable_path(self.workspace),
            "model": self.gemini_runtime.model,
            "model_auto_routing": self.model_auto_routing,
            "model_thinking_overrides": dict(self.model_thinking_overrides),
            "theme": self.theme_name,
            "reasoning": self.reasoning_mode,
            "profile": self.ux_profile,
            "statusline": list(self.statusline_fields),
            "notifications": self.notification_mode,
        }

    def apply_state_payload(self, payload):
        workspace = payload.get("workspace")
        if workspace:
            candidate = Path(workspace)
            self.workspace = candidate if candidate.is_absolute() else self.base_dir / candidate
            self.workspace.mkdir(parents=True, exist_ok=True)
            self._jobs_state_path = self.workspace / "jobs_state.json"
            self.jobs = JobTracker.load_state(self._jobs_state_path)
            self.learning_journal = LearningJournal(self.workspace / "learning" / "attempt_journal.jsonl")
            if hasattr(self, "agent_loop") and self.agent_loop:
                self.agent_loop.learning_journal = self.learning_journal
        theme = payload.get("theme")
        if theme in THEME_PALETTES:
            self._apply_theme(theme)
        reasoning = payload.get("reasoning")
        if reasoning in REASONING_MODES:
            self.reasoning_mode = reasoning
        profile = payload.get("profile")
        if profile in UX_PROFILES:
            self.ux_profile = profile
        statusline = payload.get("statusline")
        if isinstance(statusline, list):
            fields = [str(field).strip().casefold() for field in statusline]
            self.statusline_fields = [field for field in fields if field in STATUSLINE_FIELDS]
        notifications = payload.get("notifications")
        if notifications in NOTIFICATION_MODES:
            self.notification_mode = notifications
        model = payload.get("model")
        resolved_model = resolve_model_name(model) if isinstance(model, str) else ""
        if resolved_model and resolved_model != "auto":
            self.gemini_runtime = replace(self.gemini_runtime, model=resolved_model)
        self.model_auto_routing = bool(payload.get("model_auto_routing", self.model_auto_routing))
        overrides = payload.get("model_thinking_overrides")
        if isinstance(overrides, dict):
            self.model_thinking_overrides = {
                str(key): str(value)
                for key, value in overrides.items()
                if str(value) in THINKING_LEVELS
            }
        self._apply_model_profile()

    def get_status_entries(self):
        gemini_value = "hors ligne"
        gemini_tone = "warn"
        if self.gemini_runtime.api_key_present:
            gemini_value = self.gemini_runtime.model
            gemini_tone = "success"
        if self.last_gemini_error:
            gemini_value = "erreur api"
            gemini_tone = "error"

        entries = [
            StatusEntry("profil", self.ux_profile, "info"),
            StatusEntry("gemini", gemini_value, gemini_tone),
            StatusEntry(
                "phase",
                self.engagement.phase_label,
                "success",
            ),
            StatusEntry(
                "cas",
                self.active_case.slug if self.active_case else "aucun",
                "info" if self.active_case else "muted",
            ),
            StatusEntry(
                "cible",
                self.active_target.label if self.active_target else (self.current_target or "aucune"),
                "success" if self.active_target else ("info" if self.current_target else "muted"),
            ),
            StatusEntry(
                "findings",
                str(self.findings_store.count),
                "success" if self.findings_store.count else "muted",
            ),
            StatusEntry(
                "prompt",
                self._last_prompt_size_label(),
                "info" if getattr(self.llm_client, "last_prompt_chars", 0) else "muted",
            ),
            StatusEntry(
                "memoire",
                f"{self.knowledge_store.case_count} cas",
                "success" if self.knowledge_store.case_count else "muted",
            ),
            StatusEntry(
                "outils",
                f"{len(self.tool_registry.installed_tools)} pentest",
                "success" if self.tool_registry.installed_tools else "muted",
            ),
            StatusEntry(
                "jobs",
                str(self.jobs.active_count),
                "warn" if self.jobs.active_count else "muted",
            ),
        ]
        return entries

    def _last_prompt_size_label(self):
        size = int(getattr(self.llm_client, "last_prompt_chars", 0) or 0)
        if not size:
            return "aucun"
        if size >= 1000:
            return f"{size / 1000:.1f}k car."
        return f"{size} car."

    def _apply_model_profile(self):
        profile = get_model_profile(self.gemini_runtime.model)
        override = self.model_thinking_overrides.get(self.gemini_runtime.model)
        if override is not None:
            thinking_level = "high" if override == "max" else override
            profile = replace(
                profile,
                thinking_level="" if thinking_level == "off" else thinking_level,
            )
        self.llm_client.configure_profile(profile)
        return profile

    def _can_use_transient_page(self):
        return sys.stdin.isatty() and sys.stdout.isatty()

    def _is_transient_command(self, raw_text):
        stripped = str(raw_text or "").strip()
        if stripped == "/":
            return True
        tokens = safe_split(stripped)
        if not tokens:
            return False
        if (
            tokens[0].lower() == "/session"
            and len(tokens) == 2
            and tokens[1].lower() == "resume"
        ):
            return True
        if tokens[0].lower() == "/resume" and len(tokens) == 1:
            return True
        if tokens[0].lower() == "/tools" and len(tokens) == 1:
            return True
        if self._is_panel_transient_command(stripped):
            return True
        return tokens[0].lower() in TRANSIENT_COMMANDS

    def _is_panel_transient_command(self, raw_text):
        tokens = safe_split(str(raw_text or "").strip())
        if not tokens:
            return False
        command = tokens[0].lower()
        args = [str(arg).casefold() for arg in tokens[1:]]
        if command not in PANEL_TRANSIENT_COMMANDS:
            return False
        if command in {"/status", "/stats", "/learn", "/plan", "/findings", "/rewind"}:
            return not args
        if command in {"/case", "/target", "/jobs", "/workflow", "/session"}:
            return not args or args[0] in {"ls", "list"}
        return False

    def _transient_command_result_message(self, raw_text):
        stripped = str(raw_text or "").strip()
        if stripped == "/":
            return "Command palette dismissed"
        tokens = safe_split(stripped)
        if not tokens:
            return ""
        command = tokens[0].lower()
        if command == "/session" and len(tokens) > 1 and tokens[1].lower() == "resume":
            command = "/resume"
        messages = {
            "/help": "Help dialog dismissed",
            "/doctor": "SECOPS diagnostics dismissed",
            "/tools": "Tools dialog dismissed",
            "/model": "Model dialog dismissed",
            "/theme": "Theme dialog dismissed",
            "/phase": "Phase dialog dismissed",
            "/permissions": "Permissions dialog dismissed",
            "/scope": "Scope dialog dismissed",
            "/profile": "Profile dialog dismissed",
            "/reasoning": "Reasoning dialog dismissed",
            "/notify": "Notifications dialog dismissed",
            "/statusline": "Statusline dialog dismissed",
            "/compact": "Compact dialog dismissed",
            "/btw": "Side question dismissed",
            "/resume": "Resume dialog dismissed",
            "/status": "Status dialog dismissed",
            "/stats": "Stats dialog dismissed",
            "/case": "Case dialog dismissed",
            "/target": "Target dialog dismissed",
            "/learn": "Learning dialog dismissed",
            "/plan": "Plan dialog dismissed",
            "/session": "Session dialog dismissed",
            "/rewind": "Rewind dialog dismissed",
            "/workflow": "Workflow dialog dismissed",
            "/findings": "Findings dialog dismissed",
            "/jobs": "Jobs dialog dismissed",
            "/clear": "",
            "/__transcript": "Transcript viewer dismissed",
            "/__history_search": "History search dismissed",
        }
        return messages.get(command, "Command dismissed")

    def _print_transient_command_result(self, raw_text):
        if self._suppress_transient_result_once:
            self._suppress_transient_result_once = False
            return
        message = self._transient_command_result_message(raw_text)
        if not message:
            return
        print(f"  {self.palette.muted_ansi}⎿  {message}{AnsiStyle.RESET_ALL}")

    def _clear_transient_screen(self):
        if sys.stdout.isatty():
            sys.stdout.write("\x1b[2J\x1b[3J\x1b[H")
            sys.stdout.flush()
            return
        self.clear_screen()

    def _return_to_main_page(self, previous_panel):
        self.panel = previous_panel
        self._clear_transient_screen()
        self.render_shell_header()
        self._header_rendered = True
        self.render_panel_state()

    def _restore_inline_panel(self, previous_panel):
        self.panel = previous_panel

    def _transient_toolbar(self):
        return HTML(
            "<toolbar.meta>↑↓ choisir</toolbar.meta>"
            "<toolbar.sep> · </toolbar.sep>"
            "<toolbar.meta>Entrée valider</toolbar.meta>"
            "<toolbar.sep> · </toolbar.sep>"
            "<toolbar.meta>Esc retour</toolbar.meta>"
        )

    def _menu_toolbar(self):
        return HTML(
            "<toolbar.meta>Tab completions</toolbar.meta>"
            "<toolbar.sep> · </toolbar.sep>"
            "<toolbar.meta>Entrée ouvrir</toolbar.meta>"
            "<toolbar.sep> · </toolbar.sep>"
            "<toolbar.meta>Esc retour</toolbar.meta>"
            "<toolbar.sep> · </toolbar.sep>"
            "<toolbar.meta>ex: cible, logs, debug, s</toolbar.meta>"
        )

    def _menu_detail_style(self):
        return "class:menu.detail"

    def _menu_line_style(self, line):
        return self._menu_detail_style() if str(line).startswith("    ") else ""

    def _session_resume_toolbar(self):
        return HTML(
            "<toolbar.meta>↑/↓ select</toolbar.meta>"
            "<toolbar.sep> · </toolbar.sep>"
            "<toolbar.meta>type search</toolbar.meta>"
            "<toolbar.sep> · </toolbar.sep>"
            "<toolbar.meta>←/→ sort</toolbar.meta>"
            "<toolbar.sep> · </toolbar.sep>"
            "<toolbar.meta>Ctrl+E details</toolbar.meta>"
            "<toolbar.sep> · </toolbar.sep>"
            "<toolbar.meta>Enter</toolbar.meta>"
            "<toolbar.sep> · </toolbar.sep>"
            "<toolbar.meta>Esc</toolbar.meta>"
        )

    def _choice_key_bindings(
        self,
        *,
        cancel_result="cancel",
        accept_result=None,
        decline_result=None,
        cycle_permission_mode=False,
        space_accept=False,
        toggle_explanation=None,
        toggle_debug=None,
    ):
        bindings = KeyBindings()

        @bindings.add("escape")
        def _cancel(event):
            event.app.exit(result=cancel_result, style="class:aborting")

        @bindings.add("c-p")
        @bindings.add("k")
        def _previous(event):
            event.key_processor.feed(KeyPress(Keys.Up), first=True)

        @bindings.add("c-n")
        @bindings.add("j")
        def _next(event):
            event.key_processor.feed(KeyPress(Keys.Down), first=True)

        @bindings.add("tab")
        def _tab_next(event):
            event.key_processor.feed(KeyPress(Keys.Down), first=True)

        if space_accept:
            @bindings.add("space")
            def _space_accept(event):
                event.key_processor.feed(KeyPress(Keys.Enter), first=True)

        if toggle_explanation is not None:
            @bindings.add("c-e")
            def _toggle_explanation(event):
                toggle_explanation()
                event.app.invalidate()

        if toggle_debug is not None:
            @bindings.add("c-d")
            def _toggle_debug(event):
                toggle_debug()
                event.app.invalidate()

        if accept_result is not None:
            @bindings.add("y")
            @bindings.add("Y")
            def _accept_shortcut(event):
                event.app.exit(result=accept_result, style="class:accepted")

        if decline_result is not None:
            @bindings.add("n")
            @bindings.add("N")
            def _decline_shortcut(event):
                event.app.exit(result=decline_result, style="class:aborting")

        if cycle_permission_mode:
            @bindings.add("s-tab")
            @bindings.add("escape", "m")
            def _cycle_mode(event):
                self._cycle_prompt_permission_mode()
                event.app.invalidate()

        return bindings

    def _inline_choice_footer_toolbar(self):
        return HTML("<toolbar.meta>Press enter to confirm or esc to go back</toolbar.meta>")

    def _inline_selected_style(self):
        return "class:selected-option"

    def _inline_option_text(self, label, description, *, current=False, width=28):
        current_marker = " (current)" if current else ""
        return f"{label + current_marker:<{width}}{description}"

    def _run_inline_choice(
        self,
        title,
        body_lines,
        options,
        *,
        default=None,
        select_character="›",
        extra_key_bindings=None,
        footer_control=None,
    ):
        radio_list = ClaudeStyleRadioList(
            values=options,
            default=default,
            select_on_focus=True,
            open_character="",
            select_character=select_character,
            close_character="",
            show_cursor=False,
            show_numbers=True,
            container_style="class:input-selection",
            default_style="class:option",
            selected_style=self._inline_selected_style(),
            checked_style="",
            number_style="class:number",
            show_scrollbar=False,
        )
        message = [title]
        message.extend(body_lines or [])
        footer = footer_control or self._inline_choice_footer_toolbar
        show_footer = Condition(lambda: True) & ~is_done
        container = HSplit(
            [
                Box(
                    Label(text="\n".join(message).rstrip() + "\n", dont_extend_height=True),
                    padding_top=0,
                    padding_left=1,
                    padding_right=1,
                    padding_bottom=0,
                ),
                Box(
                    radio_list,
                    padding_top=0,
                    padding_left=0,
                    padding_right=1,
                    padding_bottom=0,
                    style="class:input-selection",
                ),
                ConditionalContainer(Window(), filter=show_footer),
                ConditionalContainer(
                    Window(
                        FormattedTextControl(
                            footer,
                            style="class:bottom-toolbar.text",
                        ),
                        style="class:bottom-toolbar",
                        dont_extend_height=True,
                        height=Dimension(min=1),
                    ),
                    filter=show_footer,
                ),
            ]
        )

        bindings = KeyBindings()

        @bindings.add("enter", eager=True)
        def _accept(event):
            event.app.exit(result=radio_list.current_value, style="class:accepted")

        @bindings.add("escape")
        @bindings.add("c-c", eager=True)
        @bindings.add("c-d")
        def _cancel(event):
            event.app.exit(result="cancel", style="class:aborting")

        @bindings.add("c-p")
        @bindings.add("k")
        def _previous(event):
            event.key_processor.feed(KeyPress(Keys.Up), first=True)

        @bindings.add("c-n")
        @bindings.add("j")
        def _next(event):
            event.key_processor.feed(KeyPress(Keys.Down), first=True)

        if extra_key_bindings is not None:
            extra_key_bindings(bindings, radio_list)

        return Application(
            layout=Layout(container, focused_element=radio_list),
            full_screen=False,
            erase_when_done=True,
            mouse_support=False,
            key_bindings=bindings,
            style=self.prompt_style,
        ).run()

    def _run_transient_choice_page(self, title, body_lines, options, *, default=None):
        try:
            return self._run_inline_choice(title, body_lines, options, default=default)
        except (EOFError, KeyboardInterrupt):
            return "cancel"

    def _run_transient_notice_page(self, title, lines, *, tone="info", previous_panel=None):
        previous = previous_panel if previous_panel is not None else self.panel
        self._clear_transient_screen()
        self.render_shell_header()
        current_panel = self.panel
        self.set_panel(title, lines, tone=tone)
        self.render_panel_state()
        self.panel = current_panel
        try:
            input("Entrée pour revenir ")
        except (EOFError, KeyboardInterrupt):
            pass
        self._return_to_main_page(previous)

    def _route_model_if_auto(self, prompt):
        if not self.model_auto_routing:
            return
        model = route_model(prompt, self.engagement.phase.value)
        if model == self.gemini_runtime.model:
            return
        self.gemini_runtime = replace(self.gemini_runtime, model=model)
        self._apply_model_profile()

    def get_next_action_hint(self):
        if not self.gemini_runtime.api_key_present:
            return f"Configure {get_gemini_api_env_hint()} pour activer Gemini."
        if self.last_gemini_error:
            return "Gemini est indisponible. SECOPS repond via la memoire locale."
        if self.active_case:
            return "Decris l'objectif, la cible ou le prochain service a analyser."
        return "Decris une cible, un objectif pentest, ou tape /help."

    def get_context_actions(self):
        if self.active_case:
            return [
                ("/case list", "info"),
                (f"/case {self.active_case.slug}", "success"),
                ("/case off", "warn"),
                ("/quit", "info"),
            ]
        if self.knowledge_store.case_count:
            return [("/case list", "info"), ("/help", "info"), ("/quit", "info")]
        return [("/help", "info"), ("/quit", "info")]

    def get_prompt_context_label(self):
        return self._shell_directory_label()

    def process_input(self, raw_text):
        stripped = (raw_text or "").strip()
        if stripped == "?":
            self._print_keyboard_help()
            return True
        if stripped == "/":
            return self._run_command_palette()
        if stripped.startswith("!") and not stripped.startswith("!="):
            return self._handle_shell_command(stripped[1:].strip())
        return super().process_input(raw_text)

    def handle_unresolved_text(self, raw_text):
        if self._handle_pending_admin_command(raw_text):
            return True
        if self._handle_pending_tool_install(raw_text):
            return True
        if self._handle_pending_tool_retry(raw_text):
            return True
        self._ask_agent(raw_text)
        return True

    def _resolve_case_arg(self, raw_query):
        case, matches = self.knowledge_store.resolve_case(raw_query)
        if case:
            return case, None
        if matches:
            return None, f"Cas ambigu: {', '.join(item.slug for item in matches[:5])}"
        return None, f"Aucun cas ne correspond a '{raw_query}'."

    def _relative_to_repo(self, path):
        try:
            return str(Path(path).resolve().relative_to(self.repo_root.resolve()))
        except Exception:
            return str(path)

    def _print_cases(self):
        cases = self.knowledge_store.cases
        if not cases:
            self.set_panel("Cas", ["Aucun cas memoire trouve."], tone="warn")
            return
        lines = []
        for case in cases[:10]:
            prefix = "actif" if self.active_case and case.slug == self.active_case.slug else "case"
            summary = case.summary or "Aucun resume."
            lines.append(f"{prefix:<5} {case.slug:<18} {case.platform} - {summary}")
        self.set_panel("Memoire de lab", lines, tone="info")

    def _print_targets(self):
        if not self.targets:
            self.set_panel("Cibles", ["Aucune cible detectee. Mentionne une IP, un domaine ou une URL."], tone="warn")
        else:
            lines = []
            for t in self.targets:
                prefix = "actif" if t is self.active_target else "cible"
                lines.append(f"{prefix:<5} {t.label:<22} {t.target_type.value}")
            self.set_panel("Cibles detectees", lines[:15], tone="info")

    def _prepare_tools_install(self, raw_tools):
        names = []
        seen = set()
        for value in raw_tools:
            for item in re.split(r"[\s,]+", str(value).strip()):
                name = self.tool_registry.normalize_name(item)
                if not name or name in seen:
                    continue
                names.append(name)
                seen.add(name)

        if not names:
            self.set_panel(
                "Installation outil",
                ["Usage: /tools install hydra dirb john traceroute whois sqlmap"],
                tone="warn",
            )
            return

        self.tool_registry.refresh()
        unknown = [name for name in names if not self.tool_registry.is_known(name)]
        installed = [name for name in names if self.tool_registry.is_installed(name)]
        missing = [name for name in names if self.tool_registry.is_known(name) and not self.tool_registry.is_installed(name)]

        lines = []
        if installed:
            lines.append(f"deja installe(s): {', '.join(installed)}")
        if unknown:
            lines.append(f"inconnu(s): {', '.join(unknown)}")
        if missing:
            lines.append(f"a installer: {', '.join(missing)}")

        if unknown and not missing:
            self.set_panel("Installation outil", lines, tone="warn")
            return
        if not missing:
            self.set_panel("Installation outil", lines or ["Tous les outils demandes sont deja installes."], tone="success")
            return

        self.pending_tool_install = {
            "name": "install_pentest_tools",
            "executable": missing[0],
            "executables": missing,
            "installed": installed,
            "arguments": {"tool_names": names},
            "thought": "Installation explicite demandee via /tools install.",
        }
        self._attach_install_job(self.pending_tool_install)
        lines.append("Reponds oui pour lancer l'installation groupee ou non pour annuler.")
        lines.append(f"job: #{self.pending_tool_install['job_id']}")
        self.set_panel("Installation outil", lines, tone="warn" if unknown else "info")

    def _attach_install_job(self, pending):
        if not pending or pending.get("job_id"):
            return pending
        executables = self._pending_install_executables(pending)
        if not executables:
            return pending
        installed = pending.get("installed") or []
        details = []
        if installed:
            details.append(f"deja installe(s): {', '.join(installed)}")
        details.append(f"a installer: {', '.join(executables)}")
        job = self.jobs.create(
            "install",
            self._install_label(executables),
            details=details,
            status="pending",
        )
        pending["job_id"] = job.job_id
        return pending

    def _update_pending_job(self, pending, *, status, result="", append_detail=None):
        job_id = (pending or {}).get("job_id")
        if not job_id:
            return None
        return self.jobs.update(
            job_id,
            status=status,
            result=result,
            append_detail=append_detail,
        )

    def _print_jobs(self):
        jobs = self.jobs.recent(limit=12)
        if not jobs:
            self.set_panel(
                "Jobs",
                ["Aucune tache enregistree."],
                tone="muted",
            )
            return

        lines = []
        for job in jobs:
            lines.append(job.display_line())
            for detail in job.details[-3:]:
                lines.append(f"  {detail}")
            if job.result:
                lines.append(f"  resultat: {job.result}")
        self.set_panel("Jobs", lines[:30], tone="warn" if self.jobs.active_count else "info")

    def _job_command(self, job):
        for detail in job.details:
            detail = str(detail)
            if detail.startswith("commande: "):
                return detail.removeprefix("commande: ").strip()
        return ""

    def _job_log_path(self, job):
        values = list(job.details)
        if job.result:
            values.append(job.result)
        for value in values:
            match = re.search(
                r"(?:log complet|log partiel|log):\s*([^;\n]+)",
                str(value),
                flags=re.IGNORECASE,
            )
            if match:
                return match.group(1).strip()
        return ""

    def _view_job_output(self, job_id, *, pager=False):
        job = self.jobs.get(job_id)
        if not job:
            self.set_panel("Vue job", [f"Job introuvable: #{job_id}"], tone="warn")
            return

        log_path = self._job_log_path(job)
        text = ""
        if log_path:
            try:
                text = Path(log_path).read_text(encoding="utf-8")
            except OSError:
                text = ""
        if not text:
            parts = [job.display_line()]
            parts.extend(str(detail) for detail in job.details)
            if job.result:
                parts.append(f"resultat: {job.result}")
            text = "\n".join(parts)

        if pager:
            pydoc.pager(text)
            lines = [f"Job #{job_id} ouvert dans le pager."]
            if log_path:
                lines.append(f"Log partiel: {log_path}")
            self.set_panel("Vue job", lines, tone="info")
            return

        lines = self.renderer._split_text(text)
        visible = lines[:40]
        if len(lines) > len(visible):
            visible.append(f"... {len(lines) - len(visible)} ligne(s) supplementaire(s). Utilise /view {job_id} --pager.")
        if log_path:
            visible.insert(0, f"Log partiel: {log_path}")
        self.set_panel("Vue job", visible, tone="info")

    def _handle_jobs(self, args):
        normalized = [arg.casefold() for arg in (args or [])]
        if not normalized or normalized[0] in {"ls", "list"}:
            self._print_jobs()
            return
        if normalized[0] in {"cancel", "annuler"}:
            self._cancel_job(args[1:])
            return
        self.set_panel("Jobs", ["Usage: /jobs [cancel <id_job>]"], tone="warn")

    def _cancel_job(self, args):
        if not args:
            self.set_panel("Jobs", ["Usage: /jobs cancel <id_job>"], tone="warn")
            return
        try:
            job_id = int(str(args[0]).strip().lstrip("#"))
        except (TypeError, ValueError):
            self.set_panel("Jobs", [f"ID de job invalide: {args[0]}"], tone="warn")
            return

        job = self.jobs.get(job_id)
        if not job:
            self.set_panel("Jobs", [f"Job introuvable: #{job_id}"], tone="warn")
            return
        if not job.is_active:
            self.set_panel("Jobs", [f"Job #{job_id} deja termine ({job.status})."], tone="info")
            return

        command = self._job_command(job)
        cancel_result = {"cancelled": False, "log_path": ""}
        if command:
            cancel_result = self.tool_executor.cancel_command(command)
        log_path = cancel_result.get("log_path") or self._job_log_path(job)
        result = f"log partiel: {log_path}" if log_path else "annule; aucun log partiel disponible"
        self.jobs.cancel(job_id, result=result, append_detail="annule par utilisateur")

        for key, active_job_id in list(self._active_tool_jobs.items()):
            if active_job_id == job_id:
                self._active_tool_jobs.pop(key, None)
        if self._last_active_tool_job_id == job_id:
            self._last_active_tool_job_id = None

        lines = [f"⚠ Job {job_id} annulé — log partiel disponible : /view {job_id}"]
        if not cancel_result.get("cancelled") and command:
            lines.append("Processus actif non retrouve; le job a ete marque annule.")
        if log_path:
            lines.append(f"Log partiel: {log_path}")
        self.set_panel("Jobs", lines, tone="warn")

    def _checkpoint_dir(self):
        path = self.workspace / "checkpoints"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _last_checkpoint_pointer_path(self):
        return self._checkpoint_dir() / "last_checkpoint.json"

    def _active_log_paths(self):
        paths = []
        candidates = [
            self._last_output_log_path,
            getattr(self.tool_executor, "_last_command_log_path", ""),
        ]
        for job in self.jobs.recent(limit=20):
            if job.is_active:
                candidates.append(self._job_log_path(job))
        for path in candidates:
            path = str(path or "").strip()
            if path and path not in paths:
                paths.append(path)
        return paths

    def _checkpoint_session_state(self):
        state = SessionState(
            target_summary=self.active_target.label if self.active_target else (self.current_target or ""),
            phase=self.engagement.phase.value,
            tools_used=list(self.engagement.tools_used),
            scope=sorted(self.tool_executor.authorized_scope),
            active_case_slug=self.active_case.slug if self.active_case else self._active_case_slug,
            findings_count=self.findings_store.count,
        )
        if hasattr(self, "agent_loop") and self.agent_loop:
            agent_state = self.agent_loop.export_state()
            state.targets = agent_state.get("targets", [])
            state.conversation_summary = agent_state.get("conversation_summary", "")
            if not state.target_summary:
                state.target_summary = agent_state.get("active_target", "")
        return state

    def _save_checkpoint(self, reason, *, trigger):
        try:
            checkpoint_dir = self._checkpoint_dir()
            checkpoint_id = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            state = self._checkpoint_session_state()
            findings_path = checkpoint_dir / f"findings_{checkpoint_id}.json"
            self.findings_store.save_state(findings_path)
            checkpoint_path = checkpoint_dir / f"checkpoint_{checkpoint_id}.json"
            payload = {
                "version": 1,
                "checkpoint_id": checkpoint_id,
                "created_at": datetime.now().isoformat(timespec="seconds"),
                "reason": str(reason or "checkpoint de securite"),
                "trigger": str(trigger or "manual"),
                "checkpoint_path": str(checkpoint_path),
                "session": asdict(state),
                "findings_path": str(findings_path),
                "active_logs": self._active_log_paths(),
            }
            text = json.dumps(payload, ensure_ascii=False, indent=2)
            checkpoint_path.write_text(text, encoding="utf-8")
            self._last_checkpoint_pointer_path().write_text(text, encoding="utf-8")
            return checkpoint_path
        except OSError:
            return None

    def _load_last_checkpoint_payload(self):
        paths = [self._last_checkpoint_pointer_path()]
        try:
            paths.extend(sorted(self._checkpoint_dir().glob("checkpoint_*.json"), reverse=True))
        except OSError:
            return None
        seen = set()
        for path in paths:
            if path in seen or not path.exists():
                continue
            seen.add(path)
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue
            if isinstance(payload, dict) and payload.get("session"):
                return payload
        return None

    def _restore_checkpoint_payload(self, payload):
        session_data = payload.get("session") or {}
        known_fields = set(SessionState.__dataclass_fields__.keys())
        state = SessionState(**{key: value for key, value in session_data.items() if key in known_fields})

        phase = parse_phase(state.phase)
        if phase:
            self.engagement.phase = phase
        self.engagement.tools_used = list(state.tools_used)
        self.engagement.phase_history = []
        self.tool_executor.set_scope(state.scope)

        if hasattr(self, "agent_loop") and self.agent_loop:
            self.agent_loop.import_state(
                {
                    "phase": state.phase,
                    "tools_used": state.tools_used,
                    "targets": state.targets,
                    "active_target": state.target_summary,
                }
            )
            self.targets = self.agent_loop.targets
            self.active_target = self.agent_loop.active_target
        self.current_target = self.active_target.label if self.active_target else (state.target_summary or self.current_target)

        findings_path = Path(payload.get("findings_path") or "")
        self.findings_store = FindingsStore.load_state(findings_path)
        self.tool_executor.findings_store = self.findings_store
        if hasattr(self, "agent_loop") and self.agent_loop:
            self.agent_loop.findings_store = self.findings_store
        self._findings_state_path = self.workspace / "findings_state.json"
        self.findings_store.save_state(self._findings_state_path)

        if state.active_case_slug:
            case = self.knowledge_store.get_case(state.active_case_slug)
            if case:
                self.active_case = case
                self._active_case_slug = case.slug
                self.agent_loop.active_case_label = case.label
            else:
                self.active_case = None
                self._active_case_slug = ""
                self.agent_loop.active_case_label = ""
        else:
            self.active_case = None
            self._active_case_slug = ""
            self.agent_loop.active_case_label = ""

        logs = [str(path) for path in payload.get("active_logs", []) if str(path).strip()]
        self._last_output_log_path = logs[-1] if logs else ""
        self.save_state()
        return state

    def _handle_rewind(self, args):
        payload = self._load_last_checkpoint_payload()
        if not payload:
            self.set_panel(
                "Rewind",
                ["Aucun checkpoint disponible."],
                tone="warn",
            )
            return
        state = self._restore_checkpoint_payload(payload)
        lines = [
            f"Checkpoint restaure: {payload.get('checkpoint_id', '-')}",
            f"Raison: {payload.get('reason', '-')}",
            f"Phase: {state.phase}",
            f"Cible: {state.target_summary or '-'}",
            f"Scope: {len(state.scope)} entree(s)",
            f"Findings: {self.findings_store.count}",
        ]
        logs = payload.get("active_logs") or []
        if logs:
            lines.append(f"Logs actifs: {len(logs)} chemin(s)")
        self.set_panel("Rewind", lines, tone="success")

    def _workflow_dir(self):
        return self.base_dir / "config" / "workflows"

    def _workflow_files(self):
        workflow_dir = self._workflow_dir()
        try:
            return sorted(workflow_dir.glob("*.toml"))
        except OSError:
            return []

    def _load_workflow_file(self, path):
        try:
            with Path(path).open("rb") as handle:
                payload = tomllib.load(handle)
        except (tomllib.TOMLDecodeError, OSError):
            return None
        if not isinstance(payload, dict):
            return None
        slug = str(payload.get("slug") or Path(path).stem).strip()
        steps = payload.get("steps")
        if not slug or not isinstance(steps, list) or not steps:
            return None
        workflow = dict(payload)
        workflow["slug"] = slug
        workflow["path"] = str(path)
        return workflow

    def _workflow_catalog(self):
        workflows = {}
        for path in self._workflow_files():
            workflow = self._load_workflow_file(path)
            if workflow:
                workflows[workflow["slug"]] = workflow
        return workflows

    def _active_workflow_target(self):
        if self.active_target:
            return self.active_target.address
        return self.current_target

    def _workflow_context(self):
        target = str(self._active_workflow_target() or "").strip()
        return {
            "target": shlex.quote(target),
            "target_raw": target,
            "scope": shlex.quote(" ".join(sorted(self.tool_executor.authorized_scope))),
        }

    def _format_workflow_command(self, template, context):
        try:
            return str(template).format_map(context)
        except (KeyError, ValueError):
            return str(template)

    def _workflow_requires_scope(self, workflow):
        return bool(workflow.get("requires_scope", True))

    def _workflow_requires_target(self, workflow):
        return bool(workflow.get("requires_target", True))

    def _print_workflows(self):
        workflows = self._workflow_catalog()
        if not workflows:
            self.set_panel(
                "Workflows",
                [f"Aucun workflow TOML trouve dans {self._workflow_dir()}"],
                tone="warn",
            )
            return
        lines = []
        for workflow in workflows.values():
            title = workflow.get("title") or workflow["slug"]
            description = workflow.get("description") or ""
            lines.append(f"{workflow['slug']:<12} {title}")
            if description:
                lines.append(f"  {description}")
        lines.append("Execution: /workflow <slug>")
        self.set_panel("Workflows", lines, tone="info")

    def _handle_workflow(self, args):
        if not args or args[0].casefold() in {"ls", "list"}:
            self._print_workflows()
            return

        slug = args[0].strip()
        workflows = self._workflow_catalog()
        workflow = workflows.get(slug)
        if not workflow:
            self.set_panel(
                "Workflow",
                [
                    f"Workflow inconnu: {slug}",
                    "Utilise /workflow list pour voir les workflows disponibles.",
                ],
                tone="warn",
            )
            return

        if self._workflow_requires_scope(workflow) and not self.tool_executor.authorized_scope:
            self.set_panel(
                "Workflow",
                [
                    f"Scope requis avant execution: {workflow['slug']}",
                    "Definis d'abord le perimetre autorise avec /scope <ip|cidr|domaine|url>.",
                ],
                tone="warn",
            )
            return

        context = self._workflow_context()
        if self._workflow_requires_target(workflow) and not context["target_raw"]:
            self.set_panel(
                "Workflow",
                [
                    f"Cible requise avant execution: {workflow['slug']}",
                    "Definis d'abord la cible active avec /target <ip|url>.",
                ],
                tone="warn",
            )
            return

        events = []
        stopped = False
        for index, step in enumerate(workflow.get("steps", []), start=1):
            if not isinstance(step, dict):
                continue
            command = self._format_workflow_command(step.get("command", ""), context).strip()
            if not command:
                continue
            reason = step.get("reason") or f"Workflow {workflow['slug']} etape {index}"
            events.append(
                {
                    "type": "tool_start",
                    "name": "execute_command",
                    "args": {"command": command},
                }
            )
            try:
                result = self.tool_executor.execute_command(command, reason)
            except PermissionDenied as exc:
                events.append({"type": "tool_denied", "name": "execute_command", "error": str(exc)})
                stopped = True
                break
            except (MissingTargetError, ScopeViolationError, ToolExecutionError, ToolMissingError) as exc:
                events.append({"type": "tool_error", "name": "execute_command", "error": str(exc)})
                stopped = True
                break
            events.append(
                {
                    "type": "tool_success",
                    "name": "execute_command",
                    "result": result,
                }
            )

        rendered = self.renderer.render(events, model_label=self.gemini_runtime.model)
        full_text, log_path = self._full_output_from_events(events, rendered)
        header = [
            f"Workflow: {workflow.get('title') or workflow['slug']}",
            f"Cible: {context['target_raw'] or '-'}",
            f"Scope: {self._scope_summary_label()}",
        ]
        header.append("Etat: interrompu" if stopped else "Etat: termine")
        lines = header + ([""] if rendered["lines"] else []) + rendered["lines"]
        self._set_transcript_panel(
            "Workflow",
            lines,
            tone=rendered["tone"] if rendered["lines"] else "info",
            full_text=full_text,
            log_path=log_path,
            source=f"workflow:{workflow['slug']}",
        )

    def _print_learning_journal(self):
        attempts = self.learning_journal.recent(limit=12)
        if not attempts:
            self.set_panel(
                "Apprentissage",
                ["Aucune tentative journalisee pour cette session."],
                tone="muted",
            )
            return

        lines = []
        for attempt in attempts:
            target = f" | cible {attempt.target}" if attempt.target else ""
            case = f" | cas {attempt.case_label}" if attempt.case_label else ""
            lines.append(
                f"{attempt.timestamp} | {attempt.status} | {attempt.tool_name}{target}{case}"
            )
            if attempt.result_summary:
                lines.append(f"  resultat: {attempt.result_summary[:140]}")
            if attempt.findings:
                lines.append(f"  findings: {', '.join(attempt.findings[:3])}")
            if attempt.retry_hint:
                lines.append(f"  piste: {attempt.retry_hint}")
        self.set_panel("Apprentissage", lines[:30], tone="info")

    def _print_status(self):
        gemini_status = (
            f"{self.gemini_runtime.model} via {self.gemini_runtime.api_key_env_var}"
            if self.gemini_runtime.api_key_present
            else f"non configure ({get_gemini_api_env_hint()})"
        )
        target_label = self.active_target.label if self.active_target else (self.current_target or "aucune")
        case_label = self.active_case.slug if self.active_case else "aucun"
        lines = [
            f"Modele: {gemini_status}",
            f"Profil UX: {self.ux_profile}",
            f"Statusline: {', '.join(self.statusline_fields) if self.statusline_fields else 'profil actif'}",
            f"Notifications: {self.notification_mode}",
            f"Routage modele: {'auto' if self.model_auto_routing else 'manuel'}",
            f"Function calling: {'natif' if self.llm_client.use_native_tools else 'json'}",
            f"Raisonnement: {self.reasoning_mode}",
            f"Repertoire: {self._shell_directory_label()}",
            f"Commandes: {self._command_mode_label()}",
            f"Phase: {self.engagement.phase_label}",
            f"Cible: {target_label}",
            f"Scope: {self._scope_summary_label()}",
            f"Memoire: {self.knowledge_store.case_count} cas | actif: {case_label}",
            f"Findings: {self.findings_store.count} | jobs actifs: {self.jobs.active_count}",
            f"Dernier prompt: {self._last_prompt_size_label()}",
        ]
        self.set_panel("Status", lines, tone="info")

    def _shell_output_excerpt(self, result, *, limit=20):
        lines = []
        stdout = result.get("stdout", "") if isinstance(result, dict) else ""
        stderr = result.get("stderr", "") if isinstance(result, dict) else ""
        stdout_lines = self.renderer._split_text(stdout)[:limit]
        stderr_lines = self.renderer._split_text(stderr)[: max(0, limit - len(stdout_lines))]
        if stdout_lines:
            lines.append("  sortie:")
            lines.extend(f"    {line}" for line in stdout_lines)
        if stderr_lines:
            lines.append("  stderr:")
            lines.extend(f"    {line}" for line in stderr_lines)
        total_stdout = len(self.renderer._split_text(stdout))
        total_stderr = len(self.renderer._split_text(stderr))
        shown = len(stdout_lines) + len(stderr_lines)
        total = total_stdout + total_stderr
        if total > shown:
            lines.append(f"    ... {total - shown} ligne(s) supplementaire(s) dans le log")
        return lines

    def _audit_shell_command(self, command, result, *, success=True):
        target = self.active_target.label if self.active_target else (self.current_target or "")
        try:
            self.audit_logger.log_tool_call(
                "execute_command",
                {"command": command, "source": "shell"},
                result,
                target=target,
                phase=self.engagement.phase.value,
                success=success,
            )
        except Exception:
            return

    def _handle_shell_command(self, command):
        if not command:
            self.set_panel(
                "Shell",
                ["Usage: !<commande>", "Exemple: !pwd ou !ls workspace/logs"],
                tone="warn",
            )
            return True

        events = [{"type": "tool_start", "name": "execute_command", "args": {"command": command}}]
        try:
            result = self.tool_executor.execute_command(
                command,
                "Commande shell explicite via !",
            )
            events.append(
                {
                    "type": "tool_success",
                    "name": "execute_command",
                    "result": result,
                }
            )
            rendered = self.renderer.render(events, model_label=self.gemini_runtime.model)
            lines = list(rendered["lines"])
            lines.extend(self._shell_output_excerpt(result))
            tone = "success" if result.get("returncode", 0) == 0 else "warn"
            self._audit_shell_command(command, result, success=result.get("returncode", 0) == 0)
            full_text, log_path = self._full_output_from_events(events, rendered)
            self._set_transcript_panel(
                "Shell",
                lines,
                tone=tone,
                full_text=full_text,
                log_path=log_path,
                source="shell",
            )
            return True
        except PermissionDenied as exc:
            events.append({"type": "tool_denied", "name": "execute_command", "error": str(exc)})
            self._audit_shell_command(command, {"error": str(exc)}, success=False)
        except (MissingTargetError, ScopeViolationError, ToolExecutionError, ToolMissingError) as exc:
            events.append({"type": "tool_error", "name": "execute_command", "error": str(exc)})
            self._audit_shell_command(command, {"error": str(exc)}, success=False)

        rendered = self.renderer.render(events, model_label=self.gemini_runtime.model)
        full_text, log_path = self._full_output_from_events(events, rendered)
        self._set_transcript_panel(
            "Shell",
            rendered["lines"],
            tone="warn",
            full_text=full_text,
            log_path=log_path,
            source="shell",
        )
        return True

    def _print_stats(self):
        elapsed = int(time.time() - self._session_start)
        minutes, seconds = divmod(elapsed, 60)
        messages = list(getattr(self.agent_loop, "messages", []) or [])
        prompt_chars = int(getattr(self.llm_client, "last_prompt_chars", 0) or 0)
        tool_count = int(getattr(self.llm_client, "last_tool_count", 0) or 0)
        lines = [
            f"Duree: {minutes} min {seconds:02d} s",
            f"Echanges retenus: {len(self.conversation_history)}",
            f"Messages agent: {len(messages)}",
            f"Dernier prompt: {self._last_prompt_size_label()}",
            f"Outils proposes au modele: {tool_count}",
            f"Findings: {self.findings_store.count}",
            f"Jobs: {self.jobs.total_count} total | {self.jobs.active_count} actif(s)",
            f"Audit: {self.audit_logger.count} entree(s)",
            f"Commandes autorisees session: {len(getattr(self.tool_executor, '_session_allow_commands', set()))}",
        ]
        if prompt_chars and messages:
            avg = prompt_chars / max(1, len(messages))
            lines.append(f"Prompt moyen par message retenu: {avg:.0f} car.")
        self.set_panel("Statistiques", lines, tone="info")

    def _doctor_git_commit(self):
        git_dirs = []
        git_marker = self.repo_root / ".git"
        if git_marker.is_file():
            try:
                marker_text = git_marker.read_text(encoding="utf-8").strip()
            except OSError:
                marker_text = ""
            if marker_text.startswith("gitdir:"):
                git_dirs.append((self.repo_root / marker_text.split(":", 1)[1].strip()).resolve())
        elif git_marker.is_dir():
            git_dirs.append(git_marker)
        git_dirs.append(self.repo_root / ".git-local")

        for git_dir in git_dirs:
            head_path = git_dir / "HEAD"
            try:
                head = head_path.read_text(encoding="utf-8").strip()
            except OSError:
                continue
            if head.startswith("ref:"):
                ref_path = git_dir / head.split(" ", 1)[1].strip()
                try:
                    commit = ref_path.read_text(encoding="utf-8").strip()
                except OSError:
                    commit = ""
            else:
                commit = head
            if commit:
                return commit[:12]
        return "non disponible"

    def _horizontal_separator(self, width=None, *, min_width=40):
        columns = width if width is not None else shutil.get_terminal_size(fallback=(120, 30)).columns
        return "─" * max(min_width, min(int(columns), 180))

    def _doctor_terminal_separator(self):
        return self._horizontal_separator()

    def _doctor_section_lines(self, title, rows):
        lines = [f"  {title}"]
        for index, (label, value) in enumerate(rows):
            branch = "└" if index == len(rows) - 1 else "├"
            lines.append(f"  {branch} {label}: {value}")
        return lines

    def _doctor_status_value(self, ok, detail, warn_detail):
        return detail if ok else warn_detail

    def _doctor_tabs(self):
        return ("diagnostics", "updates", "locks")

    def _doctor_tab_label(self, tab):
        labels = {
            "diagnostics": "diagnostics",
            "updates": "updates",
            "locks": "locks",
        }
        return labels.get(tab, str(tab or "diagnostics"))

    def _doctor_header(self, active_tab):
        rendered_tabs = []
        for tab in self._doctor_tabs():
            label = self._doctor_tab_label(tab)
            rendered_tabs.append(label.upper() if tab == active_tab else label)
        return f"SECOPS doctor  {'   '.join(rendered_tabs)}"

    def _doctor_header_fragments(self, active_tab):
        fragments = [("class:prompt.brand", "SECOPS doctor")]
        for tab in self._doctor_tabs():
            label = self._doctor_tab_label(tab)
            fragments.append(("", "   "))
            if tab == active_tab:
                fragments.append((self._help_active_tab_style(), f" {label} "))
            else:
                fragments.append(("", label))
        fragments.append(("", "\n"))
        return fragments

    def _doctor_sections(self):
        self.tool_registry.refresh()
        project_venv = self.base_dir / ".venv"
        critical_tools = ("nmap", "gobuster", "nikto", "searchsploit")
        missing_tools = [
            tool for tool in critical_tools
            if not self.tool_registry.is_installed(tool)
        ]
        workspace_ok = self.workspace.exists() and os.access(self.workspace, os.W_OK)
        python_ok = sys.version_info >= (3, 14)
        api_ok = bool(self.gemini_runtime.api_key_present)
        venv_ok = project_venv.exists()
        memory_ok = self.knowledge_store.case_count > 0
        tools_ok = not missing_tools
        permissions_ok = self.command_permission_mode != "deny"
        scope_ok = bool(self.tool_executor.authorized_scope)

        diagnostics = [
            ("Currently running", "SECOPS TUI (local Python)"),
            ("Commit", self._doctor_git_commit()),
            ("Platform", f"{sys.platform}-{platform.machine() or 'unknown'}"),
            ("Path", str(self.base_dir)),
            ("Config install method", "entrypoints scripts"),
            (
                "Python",
                self._doctor_status_value(
                    python_ok,
                    sys.version.split()[0],
                    f"{sys.version.split()[0]} (attendu 3.14+)",
                ),
            ),
            (
                "Gemini",
                self._doctor_status_value(
                    api_ok,
                    f"{self.gemini_runtime.model} via {self.gemini_runtime.api_key_env_var}",
                    f"non configure ({get_gemini_api_env_hint()})",
                ),
            ),
            (
                "Workspace",
                self._doctor_status_value(
                    workspace_ok,
                    str(self.workspace),
                    f"non inscriptible: {self.workspace}",
                ),
            ),
            (
                "Venv",
                self._doctor_status_value(
                    venv_ok,
                    str(project_venv),
                    f"absent: {project_venv}",
                ),
            ),
            (
                "Memoire",
                self._doctor_status_value(
                    memory_ok,
                    f"{self.knowledge_store.case_count} cas",
                    "aucun cas charge",
                ),
            ),
            (
                "Outils pentest",
                self._doctor_status_value(
                    tools_ok,
                    f"{len(self.tool_registry.installed_tools)} detecte(s)",
                    "manquants: " + ", ".join(missing_tools),
                ),
            ),
            ("Search", "OK (catalogue local)"),
        ]
        updates = [
            ("Auto-updates", "disabled"),
            ("Auto-update channel", "local workspace"),
            ("Stable version", "not packaged"),
            ("Latest version", "not checked"),
        ]
        version_locks = [
            ("SECOPS workspace", f"PID {os.getpid()} (running)"),
            (
                "Permissions",
                self._doctor_status_value(
                    permissions_ok,
                    self._command_mode_label(),
                    "execution bloquee",
                ),
            ),
            (
                "Scope",
                self._doctor_status_value(
                    scope_ok,
                    self._scope_summary_label(),
                    "non defini",
                ),
            ),
            ("Jobs", f"{self.jobs.active_count} active / {self.jobs.total_count} total"),
            ("Findings", f"{self.findings_store.count} decouverte(s)"),
        ]

        ok = all(
            (
                python_ok,
                api_ok,
                workspace_ok,
                venv_ok,
                memory_ok,
                tools_ok,
                permissions_ok,
                scope_ok,
            )
        )
        sections = {
            "diagnostics": ("Diagnostics", diagnostics),
            "updates": ("Updates", updates),
            "locks": ("Version locks", version_locks),
        }
        return sections, "success" if ok else "warn"

    def _doctor_lines(self, *, include_prompt=False, tab="overview"):
        sections, tone = self._doctor_sections()
        tab = tab if tab == "all" or tab in sections else "diagnostics"
        active_tab = "diagnostics" if tab == "all" else tab
        selected_sections = (
            ("diagnostics", "updates", "locks")
            if tab == "all"
            else (tab,)
        )

        lines = [self._doctor_header(active_tab), self._doctor_terminal_separator()]
        for index, section_key in enumerate(selected_sections):
            title, rows = sections[section_key]
            if index:
                lines.append("")
            lines.extend(self._doctor_section_lines(title, rows))
        lines.extend(
            [
                "",
                "  Still having issues? Run /help for commands or /tools for local tool status.",
            ]
        )
        if include_prompt:
            lines.extend(["", "  Press Enter to continue"])

        return lines, tone

    def _doctor_body_fragments(self, tab):
        lines, _tone = self._doctor_lines(include_prompt=True, tab=tab)
        if not lines:
            return []
        fragments = self._doctor_header_fragments(tab)
        for line in lines[1:]:
            fragments.append(("", f"{line}\n"))
        return fragments

    def _doctor_toolbar(self):
        return HTML(
            "<toolbar.meta>←/→ tabs</toolbar.meta>"
            "<toolbar.sep> · </toolbar.sep>"
            "<toolbar.meta>Tab onglet</toolbar.meta>"
            "<toolbar.sep> · </toolbar.sep>"
            "<toolbar.meta>1-3 aller</toolbar.meta>"
            "<toolbar.sep> · </toolbar.sep>"
            "<toolbar.meta>Enter continuer</toolbar.meta>"
            "<toolbar.sep> · </toolbar.sep>"
            "<toolbar.meta>Esc cancel</toolbar.meta>"
        )

    def _run_doctor_view(self):
        tabs = self._doctor_tabs()
        state = {"tab_index": 0}

        def active_tab():
            return tabs[state["tab_index"]]

        def body_text():
            return self._doctor_body_fragments(active_tab())

        def move_tab(delta):
            state["tab_index"] = (state["tab_index"] + delta) % len(tabs)

        bindings = KeyBindings()

        @bindings.add("enter", eager=True)
        def _continue(event):
            event.app.exit(result="continue", style="class:accepted")

        @bindings.add("escape")
        @bindings.add("c-c", eager=True)
        @bindings.add("q")
        def _close(event):
            event.app.exit(result="cancel", style="class:aborting")

        @bindings.add("right")
        @bindings.add("l")
        @bindings.add("tab")
        def _next_tab(event):
            move_tab(1)
            event.app.invalidate()

        @bindings.add("left")
        @bindings.add("h")
        @bindings.add("s-tab")
        def _previous_tab(event):
            move_tab(-1)
            event.app.invalidate()

        for key, tab_index in (("1", 0), ("2", 1), ("3", 2)):
            @bindings.add(key)
            def _switch_tab(event, tab_index=tab_index):
                state["tab_index"] = tab_index
                event.app.invalidate()

        container = HSplit(
            [
                Window(
                    FormattedTextControl(body_text),
                    wrap_lines=False,
                    always_hide_cursor=True,
                ),
                Window(
                    FormattedTextControl(self._doctor_toolbar, style="class:bottom-toolbar.text"),
                    style="class:bottom-toolbar",
                    dont_extend_height=True,
                    height=Dimension(min=1, max=1),
                ),
            ]
        )
        return Application(
            layout=Layout(container),
            key_bindings=bindings,
            full_screen=False,
            erase_when_done=True,
            mouse_support=False,
            style=self.prompt_style,
        ).run()

    def _set_doctor_panel(self, *, include_prompt=False, tab="overview"):
        lines, tone = self._doctor_lines(include_prompt=include_prompt, tab=tab)
        self.set_panel("Diagnostic", lines, tone=tone, variant="plain")
        return lines, tone

    def _run_doctor(self):
        if not self._can_use_transient_page():
            self._set_doctor_panel(tab="all")
            return
        try:
            self._run_doctor_view()
        except (EOFError, KeyboardInterrupt):
            pass
        self._stream_rendered_panel = True

    def _panel_dialog_lines(self, panel):
        width = max(60, shutil.get_terminal_size(fallback=(100, 30)).columns - 2)
        separator = self._horizontal_separator(width, min_width=60)
        lines = ["", separator, f"  {panel.title}", ""]
        for raw_line in panel.lines:
            if not raw_line:
                lines.append("")
                continue
            wrapped = textwrap.wrap(
                str(raw_line),
                width=max(40, width - 4),
                subsequent_indent="  ",
                replace_whitespace=False,
                drop_whitespace=False,
            ) or [str(raw_line)]
            for item in wrapped:
                lines.append(f"  {item}")
        lines.append("")
        return lines

    def _panel_dialog_fragments(self, lines, offset, height):
        visible = lines[offset : offset + height]
        fragments = []
        for index, line in enumerate(visible):
            stripped = line.strip()
            if index == 1 and stripped.startswith("─"):
                style = ""
            elif not stripped:
                style = ""
            elif line.startswith("    ") or stripped.startswith(("- ", "resultat:", "phases:", "targets:")):
                style = self._menu_detail_style()
            else:
                style = ""
            fragments.append((style, line))
            fragments.append(("", "\n"))
        return fragments

    def _panel_dialog_toolbar(self):
        return "↑/↓ scroll · PageUp/PageDown · Enter to continue · Esc to cancel"

    def _run_panel_dialog(self, panel):
        lines = self._panel_dialog_lines(panel)
        state = {"offset": 0}

        def viewport_height():
            rows = shutil.get_terminal_size(fallback=(100, 30)).lines
            return max(8, rows - 2)

        def max_offset():
            return max(0, len(lines) - viewport_height())

        def clamp_offset():
            state["offset"] = max(0, min(state["offset"], max_offset()))

        def body_text():
            clamp_offset()
            return self._panel_dialog_fragments(lines, state["offset"], viewport_height())

        bindings = KeyBindings()

        @bindings.add("enter", eager=True)
        def _continue(event):
            event.app.exit(result="continue", style="class:accepted")

        @bindings.add("escape")
        @bindings.add("c-c", eager=True)
        @bindings.add("q")
        def _close(event):
            event.app.exit(result="cancel", style="class:aborting")

        @bindings.add("down")
        @bindings.add("j")
        @bindings.add("c-n")
        def _down(event):
            state["offset"] += 1
            clamp_offset()
            event.app.invalidate()

        @bindings.add("up")
        @bindings.add("k")
        @bindings.add("c-p")
        def _up(event):
            state["offset"] -= 1
            clamp_offset()
            event.app.invalidate()

        @bindings.add("pagedown")
        def _page_down(event):
            state["offset"] += max(1, viewport_height() - 3)
            clamp_offset()
            event.app.invalidate()

        @bindings.add("pageup")
        def _page_up(event):
            state["offset"] -= max(1, viewport_height() - 3)
            clamp_offset()
            event.app.invalidate()

        @bindings.add("c-home")
        def _top(event):
            state["offset"] = 0
            event.app.invalidate()

        @bindings.add("c-end")
        def _bottom(event):
            state["offset"] = max_offset()
            event.app.invalidate()

        container = HSplit(
            [
                Window(
                    FormattedTextControl(body_text),
                    wrap_lines=False,
                    always_hide_cursor=True,
                    style="class:input-selection",
                ),
                Window(
                    FormattedTextControl(
                        self._panel_dialog_toolbar,
                        style="class:bottom-toolbar.text",
                    ),
                    style="class:bottom-toolbar",
                    dont_extend_height=True,
                    height=Dimension(min=1, max=1),
                ),
            ]
        )
        return Application(
            layout=Layout(container),
            key_bindings=bindings,
            full_screen=False,
            erase_when_done=True,
            mouse_support=False,
            style=self.prompt_style,
        ).run()

    def _show_panel_command_transient(self, raw_text, previous_panel):
        if not self._can_use_transient_page():
            return False
        if not self._is_panel_transient_command(raw_text):
            return False
        panel = self.panel
        if panel is previous_panel or (not panel.title and not panel.lines):
            return False
        try:
            self._run_panel_dialog(panel)
        except (EOFError, KeyboardInterrupt):
            pass
        self.panel = previous_panel
        self._stream_rendered_panel = True
        return True

    def _current_panel_text(self):
        lines = []
        if self.panel.title:
            lines.append(self.panel.title)
        lines.extend(self.panel.lines or [])
        return "\n".join(str(line) for line in lines if str(line).strip())

    def _last_output_full_path(self):
        return self.workspace / "last_output_full.txt"

    def _record_output_snapshot(self, title, visible_lines, *, full_text=None, log_path="", source="panel"):
        visible_lines = [str(line) for line in (visible_lines or [])]
        visible_text = "\n".join(line for line in ([title] if title else []) + visible_lines if line.strip())
        full_text = str(full_text if full_text is not None else visible_text)
        self._last_output_visible = visible_text
        self._last_output_full = full_text
        self._last_output_log_path = str(log_path or "")
        try:
            path = self._last_output_full_path()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(full_text + ("\n" if full_text and not full_text.endswith("\n") else ""), encoding="utf-8")
        except OSError:
            pass
        self._transcript_entries.append(
            {
                "timestamp": datetime.now().isoformat(timespec="seconds"),
                "title": str(title or ""),
                "visible": visible_text,
                "full": full_text,
                "log_path": self._last_output_log_path,
                "source": source,
            }
        )

    def _full_output_from_events(self, events, rendered):
        visible_text = "\n".join(rendered.get("lines", []) or [])
        for event in reversed(events or []):
            result = event.get("result") if isinstance(event, dict) else None
            if not isinstance(result, dict):
                continue
            log_path = result.get("log_path", "")
            log_text = ""
            if log_path:
                try:
                    log_text = Path(log_path).read_text(encoding="utf-8")
                except OSError:
                    log_text = ""
            elif result.get("stdout") or result.get("stderr"):
                log_text = "\n".join(
                    [
                        f"command: {result.get('command', '')}",
                        f"returncode: {result.get('returncode', '')}",
                        "",
                        "## stdout",
                        result.get("stdout", "") or "",
                        "",
                        "## stderr",
                        result.get("stderr", "") or "",
                    ]
                )
            if log_text:
                full_text = visible_text
                if visible_text:
                    full_text += "\n\n"
                full_text += "## Log complet\n" + log_text
                return full_text, str(log_path or "")
        return visible_text, ""

    def _last_output_text(self, *, full=False):
        if full:
            if self._last_output_full:
                return self._last_output_full
            path = self._last_output_full_path()
            if path.exists():
                try:
                    return path.read_text(encoding="utf-8")
                except OSError:
                    return ""
        return self._last_output_visible or self._current_panel_text()

    def _copy_to_clipboard(self, text):
        commands = []
        if os.name == "nt":
            commands.append(["clip"])
        elif sys.platform == "darwin":
            commands.append(["pbcopy"])
        else:
            commands.extend(
                [
                    ["wl-copy"],
                    ["xclip", "-selection", "clipboard"],
                    ["xsel", "--clipboard", "--input"],
                ]
            )
        for command in commands:
            if not shutil.which(command[0]):
                continue
            try:
                subprocess.run(
                    command,
                    input=text,
                    text=True,
                    timeout=3,
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                return True
            except (OSError, subprocess.SubprocessError):
                continue
        return False

    def _handle_copy(self, args):
        normalized = [arg.casefold() for arg in (args or [])]
        if normalized and normalized[0] == "last":
            full = "--full" in normalized or "full" in normalized
            text = self._last_output_text(full=full)
            if not text:
                self.set_panel("Copie", ["Aucun dernier output disponible."], tone="warn")
                return
            copy_path = self._last_output_full_path() if full else self.workspace / "last_output.txt"
            copy_path.parent.mkdir(parents=True, exist_ok=True)
            copy_path.write_text(text + ("\n" if not text.endswith("\n") else ""), encoding="utf-8")
            clipboard_ok = self._copy_to_clipboard(text)
            lines = [
                f"Contenu sauvegarde: {copy_path}",
                f"Presse-papiers: {'oui' if clipboard_ok else 'indisponible'}",
            ]
            if self._last_output_log_path:
                lines.append(f"Log complet: {self._last_output_log_path}")
            self.set_panel("Copie", lines, tone="success" if clipboard_ok else "info")
            return

        text = self._current_panel_text()
        if not text:
            self.set_panel("Copie", ["Aucun contenu affiche a copier."], tone="warn")
            return

        copy_path = self.workspace / "last_output.txt"
        copy_path.parent.mkdir(parents=True, exist_ok=True)
        copy_path.write_text(text + "\n", encoding="utf-8")
        clipboard_ok = self._copy_to_clipboard(text)
        lines = [
            f"Contenu sauvegarde: {copy_path}",
            f"Presse-papiers: {'oui' if clipboard_ok else 'indisponible'}",
        ]
        self.set_panel("Copie", lines, tone="success" if clipboard_ok else "info")

    def _transcript_text(self, *, show_all=False):
        if not self._transcript_entries:
            text = self._last_output_text(full=show_all)
            return text or self._current_panel_text() or "Aucun transcript disponible."

        blocks = []
        for entry in self._transcript_entries:
            title = entry.get("title") or entry.get("source") or "session"
            timestamp = entry.get("timestamp") or "-"
            body = (
                entry.get("full")
                if show_all
                else entry.get("visible")
            ) or entry.get("visible") or ""
            if show_all and entry.get("log_path"):
                body = f"{body}\n\nLog complet: {entry['log_path']}".strip()
            blocks.append(f"## {timestamp} - {title}\n{body}".strip())
        return "\n\n".join(blocks).strip() or "Aucun transcript disponible."

    def _transcript_viewer_toolbar(self, show_all):
        mode = "tout" if show_all else "resume"
        return HTML(
            f"<toolbar.meta>mode {html.escape(mode)}</toolbar.meta>"
            "<toolbar.sep> · </toolbar.sep>"
            "<toolbar.meta>PageUp/PageDown scroll</toolbar.meta>"
            "<toolbar.sep> · </toolbar.sep>"
            "<toolbar.meta>Ctrl+E tout</toolbar.meta>"
            "<toolbar.sep> · </toolbar.sep>"
            "<toolbar.meta>[ scrollback</toolbar.meta>"
            "<toolbar.sep> · </toolbar.sep>"
            "<toolbar.meta>v editeur</toolbar.meta>"
            "<toolbar.sep> · </toolbar.sep>"
            "<toolbar.meta>q/Esc retour</toolbar.meta>"
        )

    def _write_transcript_editor_file(self):
        timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        path = self.workspace / f"transcript_view_{timestamp}.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self._transcript_text(show_all=True) + "\n", encoding="utf-8")
        return path

    def _open_transcript_in_editor(self):
        path = self._write_transcript_editor_file()
        editor = os.getenv("VISUAL") or os.getenv("EDITOR")
        if editor and sys.stdin.isatty() and sys.stdout.isatty():
            try:
                subprocess.run(
                    [*safe_split(editor), str(path)],
                    check=False,
                )
            except (OSError, ValueError):
                pass
        self.set_panel("Transcript", [f"Transcript exporte: {path}"], tone="info")

    def _run_transcript_viewer(self):
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            self.set_panel(
                "Transcript",
                self.renderer._split_text(self._transcript_text(show_all=False))[:40],
                tone="info",
            )
            return

        state = {"offset": 0, "show_all": False}

        def current_lines():
            text = self._transcript_text(show_all=state["show_all"])
            return self.renderer._split_text(text) or ["Aucun transcript disponible."]

        def viewport_height():
            return max(6, shutil.get_terminal_size(fallback=(80, 24)).lines - 3)

        def clamp_offset():
            max_offset = max(0, len(current_lines()) - viewport_height())
            state["offset"] = max(0, min(state["offset"], max_offset))

        def body_text():
            lines = current_lines()
            clamp_offset()
            height = viewport_height()
            visible = lines[state["offset"] : state["offset"] + height]
            return "\n".join(visible)

        def toolbar_text():
            return self._transcript_viewer_toolbar(state["show_all"])

        bindings = KeyBindings()

        @bindings.add("q")
        @bindings.add("escape")
        @bindings.add("c-c", eager=True)
        def _exit(event):
            event.app.exit(result="close")

        @bindings.add("c-e")
        def _toggle_show_all(event):
            state["show_all"] = not state["show_all"]
            clamp_offset()
            event.app.invalidate()

        @bindings.add("pageup")
        def _page_up(event):
            state["offset"] -= max(1, viewport_height() // 2)
            clamp_offset()
            event.app.invalidate()

        @bindings.add("pagedown")
        def _page_down(event):
            state["offset"] += max(1, viewport_height() // 2)
            clamp_offset()
            event.app.invalidate()

        @bindings.add("c-home")
        def _top(event):
            state["offset"] = 0
            event.app.invalidate()

        @bindings.add("c-end")
        def _bottom(event):
            state["offset"] = max(0, len(current_lines()) - viewport_height())
            event.app.invalidate()

        @bindings.add("[")
        def _dump_scrollback(event):
            event.app.exit(result="dump")

        @bindings.add("v")
        def _editor(event):
            event.app.exit(result="editor")

        container = HSplit(
            [
                Window(
                    FormattedTextControl(body_text),
                    wrap_lines=False,
                    always_hide_cursor=True,
                ),
                Window(
                    FormattedTextControl(toolbar_text),
                    style="class:bottom-toolbar",
                    dont_extend_height=True,
                    height=Dimension(min=1, max=1),
                ),
            ]
        )
        result = Application(
            layout=Layout(container),
            key_bindings=bindings,
            full_screen=True,
            mouse_support=False,
            style=self.prompt_style,
        ).run()

        if result == "dump":
            print(self._transcript_text(show_all=True))
        elif result == "editor":
            self._open_transcript_in_editor()

    def _handle_view(self, args):
        normalized = [arg.casefold() for arg in (args or [])]
        if not normalized:
            self.set_panel("Vue", ["Usage: /view last|<id_job> [--pager]"], tone="warn")
            return
        if normalized[0] in {"transcript", "viewer"}:
            self._run_transcript_viewer()
            return
        pager = "--pager" in normalized or "pager" in normalized
        if normalized[0] != "last":
            try:
                job_id = int(str(args[0]).strip().lstrip("#"))
            except (TypeError, ValueError):
                self.set_panel("Vue", ["Usage: /view last|<id_job> [--pager]"], tone="warn")
                return
            self._view_job_output(job_id, pager=pager)
            return

        text = self._last_output_text(full=True)
        if not text:
            self.set_panel("Vue", ["Aucun dernier output disponible."], tone="warn")
            return

        if pager:
            pydoc.pager(text)
            lines = ["Dernier output ouvert dans le pager."]
            if self._last_output_log_path:
                lines.append(f"Log complet: {self._last_output_log_path}")
            self.set_panel("Vue", lines, tone="info")
            return

        lines = self.renderer._split_text(text)
        visible = lines[:40]
        if len(lines) > len(visible):
            visible.append(f"... {len(lines) - len(visible)} ligne(s) supplementaire(s). Utilise /view last --pager.")
        if self._last_output_log_path:
            visible.insert(0, f"Log complet: {self._last_output_log_path}")
        self.set_panel("Vue", visible, tone="info")

    def _split_model_args(self, args):
        args = list(args or [])
        if not args:
            return "", None
        tail = args[-1].strip().casefold()
        if len(args) == 1 and tail in {"default", "defaut"}:
            return tail, None
        if tail in THINKING_LEVELS:
            return " ".join(args[:-1]), tail
        return " ".join(args), None

    def _model_supports_thinking(self, model):
        profile = get_model_profile(model)
        return bool(profile.native_tool_calling or profile.thinking_level)

    def _model_effective_thinking_label(self, model):
        override = self.model_thinking_overrides.get(model)
        if override is not None:
            return override or "off"
        profile = get_model_profile(model)
        return profile.thinking_level or "off"

    def _model_picker_default_value(self):
        if self.model_auto_routing:
            routed = route_model("", self.engagement.phase.value)
            for alias, model, _description in MODEL_PRESETS:
                if model == routed:
                    return alias
            return "default"
        if self.gemini_runtime.model == DEFAULT_MODEL:
            return "default"
        for alias, model, _description in MODEL_PRESETS:
            if alias == "auto":
                continue
            if model != self.gemini_runtime.model:
                continue
            return alias
        return "default"

    def _model_picker_options(self):
        options = []
        default_active = not self.model_auto_routing and self.gemini_runtime.model == DEFAULT_MODEL
        default_label = "Default" + (" ✔" if default_active else "")
        default_name = self._model_display_name(DEFAULT_MODEL)
        options.append(
            (
                "default",
                f"{default_label:<{MODEL_PICKER_NAME_WIDTH}}Use the default model (currently {default_name})",
            )
        )
        for alias, model, description in MODEL_PRESETS:
            if alias == "auto":
                continue
            active = (
                not self.model_auto_routing
                and model == self.gemini_runtime.model
                and model != DEFAULT_MODEL
            )
            model_label = model + (" ✔" if active else "")
            options.append(
                (
                    alias,
                    f"{model_label:<{MODEL_PICKER_NAME_WIDTH}}Custom {get_model_profile(model).name.title()} model",
                )
            )
        return options

    def _model_display_name(self, model):
        aliases = {
            DEFAULT_MODEL: "Gemini 2.5 Flash",
            "gemma-4-26b-a4b-it": "Gemma 4 26B",
            "gemma-4-31b-it": "Gemma 4 31B",
        }
        return aliases.get(model, model)

    def _model_picker_toolbar(self, effort_label=None):
        effort_label = effort_label or self._model_picker_effort_label("high")
        return HTML(
            f"<toolbar.meta>{html.escape(effort_label)} ← → to adjust</toolbar.meta>"
        )

    def _model_picker_instruction_toolbar(self):
        return self._inline_choice_footer_toolbar()

    def _model_picker_default_effort(self):
        override = self.model_thinking_overrides.get(self.gemini_runtime.model)
        if override in MODEL_PICKER_EFFORT_LEVELS:
            return override
        return "high"

    def _model_picker_effort_label(self, effort, selected_model=None):
        labels = {
            "low": "○ Low effort",
            "medium": "◐ Medium effort",
            "high": "● High effort (default)",
            "max": "◈ Max effort",
        }
        return labels.get(effort, labels["high"])

    def _move_model_picker_effort(self, state, direction):
        current = state.get("effort", "default")
        try:
            index = MODEL_PICKER_EFFORT_LEVELS.index(current)
        except ValueError:
            index = 0
        next_index = max(0, min(len(MODEL_PICKER_EFFORT_LEVELS) - 1, index + direction))
        state["effort"] = MODEL_PICKER_EFFORT_LEVELS[next_index]

    def _run_model_picker_choice(self, title, body_lines, options, *, default=None):
        state = {"effort": self._model_picker_default_effort()}
        radio_list = ClaudeStyleRadioList(
            values=options,
            default=default,
            select_on_focus=True,
            open_character="",
            select_character="›",
            close_character="",
            show_cursor=False,
            show_numbers=False,
            container_style="class:input-selection",
            default_style="class:option",
            selected_style=self._inline_selected_style(),
            checked_style="",
            number_style="class:number",
            show_scrollbar=False,
        )

        def selected_model():
            value = radio_list.current_value
            if value == "default":
                return DEFAULT_MODEL
            model = resolve_model_name(value)
            return model if model and model != "auto" else self.gemini_runtime.model

        def effort_toolbar():
            return self._model_picker_toolbar(
                self._model_picker_effort_label(state["effort"], selected_model())
            )

        message = [title]
        message.extend(body_lines or [])
        show_bottom_toolbar = Condition(lambda: True) & ~is_done
        container = HSplit(
            [
                Box(
                    Label(text="\n".join(message).rstrip() + "\n", dont_extend_height=True),
                    padding_top=0,
                    padding_left=1,
                    padding_right=1,
                    padding_bottom=0,
                ),
                Box(
                    radio_list,
                    padding_top=0,
                    padding_left=0,
                    padding_right=1,
                    padding_bottom=0,
                    style="class:input-selection",
                ),
                ConditionalContainer(Window(), filter=show_bottom_toolbar),
                ConditionalContainer(
                    Window(
                        FormattedTextControl(
                            effort_toolbar,
                            style="class:bottom-toolbar.text",
                        ),
                        style="class:bottom-toolbar",
                        dont_extend_height=True,
                        height=Dimension(min=1),
                    ),
                    filter=show_bottom_toolbar,
                ),
                ConditionalContainer(
                    Window(
                        FormattedTextControl(
                            self._model_picker_instruction_toolbar,
                            style="class:bottom-toolbar.text",
                        ),
                        style="class:bottom-toolbar",
                        dont_extend_height=True,
                        height=Dimension(min=1),
                    ),
                    filter=show_bottom_toolbar,
                ),
            ]
        )

        bindings = KeyBindings()

        @bindings.add("enter", eager=True)
        def _accept(event):
            event.app.exit(
                result=(radio_list.current_value, state["effort"]),
                style="class:accepted",
            )

        @bindings.add("escape")
        @bindings.add("c-c", eager=True)
        @bindings.add("c-d")
        def _cancel(event):
            event.app.exit(result="cancel", style="class:aborting")

        @bindings.add("c-p")
        @bindings.add("k")
        def _previous(event):
            event.key_processor.feed(KeyPress(Keys.Up), first=True)

        @bindings.add("c-n")
        @bindings.add("j")
        def _next(event):
            event.key_processor.feed(KeyPress(Keys.Down), first=True)

        @bindings.add("left")
        def _decrease_effort(event):
            self._move_model_picker_effort(state, -1)
            event.app.invalidate()

        @bindings.add("right")
        def _increase_effort(event):
            self._move_model_picker_effort(state, 1)
            event.app.invalidate()

        return Application(
            layout=Layout(container, focused_element=radio_list),
            full_screen=False,
            erase_when_done=True,
            mouse_support=False,
            key_bindings=bindings,
            style=self.prompt_style,
        ).run()

    def _apply_model_picker_selection(self, selection):
        if not selection or selection == "cancel":
            return
        effort = "default"
        if isinstance(selection, tuple):
            selection, effort = selection

        if selection == "default":
            model = DEFAULT_MODEL
        else:
            model = resolve_model_name(selection)

        if not model or model == "auto":
            return

        if effort == "default":
            self.model_thinking_overrides.pop(model, None)
            self._activate_model(model, auto=False)
            return
        self._activate_model(model, auto=False, thinking_level=effort)

    def _handle_model(self, args):
        if args and args[0].casefold() in {"set", "use", "utilise", "choisir"}:
            args = args[1:]

        if not args and self._can_use_transient_page():
            self._run_model_menu_page()
            return

        if args and args[0].casefold() in {"bench", "benchmark"}:
            if self._can_use_transient_page():
                previous_panel = self.panel
                self._benchmark_model_routing()
                self._return_to_main_page(previous_panel)
                return
            self._benchmark_model_routing()
            return

        if not args or args[0].casefold() in {"list", "ls", "show", "current", "actuel"}:
            profile = get_model_profile(self.gemini_runtime.model)
            lines = [
                f"Modele actif: {self.gemini_runtime.model}",
                f"Effort: {self._model_effective_thinking_label(self.gemini_runtime.model)}",
                f"Routage auto: {'actif' if self.model_auto_routing else 'inactif'}",
                f"Function calling natif: {'actif' if self.llm_client.use_native_tools else 'inactif'}",
                "Changement applique a cette session et aux prochaines sessions SECOPS.",
                "",
                "Modeles disponibles:",
                (
                    f"  {'default (current)' if self.gemini_runtime.model == DEFAULT_MODEL else 'default':<18}"
                    f"{DEFAULT_MODEL:<28} Use the default model"
                ),
            ]
            for alias, model, description in MODEL_PRESETS:
                if alias == "auto":
                    continue
                label = f"{alias} (current)" if model == self.gemini_runtime.model else alias
                lines.append(f"  {label:<18}{model:<28} {description}")
            lines.append("Exemples: /model gemma, /model gemma high, /model default, /model auto")
            self.set_panel("Modele LLM", lines, tone="info")
            return

        raw_model, requested_thinking = self._split_model_args(args)
        if raw_model.strip().casefold() in {"default", "defaut"}:
            model = DEFAULT_MODEL
        else:
            model = resolve_model_name(raw_model)
        if not model:
            self.set_panel(
                "Modele LLM",
                [
                    f"Modele inconnu: {raw_model}",
                    "Utilise /model pour voir les profils disponibles.",
                    "Les identifiants gemini-* et gemma-* sont acceptes.",
                ],
                tone="warn",
            )
            return

        if model == "auto":
            if requested_thinking:
                self.set_panel(
                    "Modele LLM",
                    ["Le routage auto utilise le profil thinking du modele choisi automatiquement."],
                    tone="warn",
                )
                return
            routed = route_model("", self.engagement.phase.value)
            self.model_thinking_overrides.pop(routed, None)
            previous, profile = self._activate_model(routed, auto=True)
            if self._can_use_transient_page():
                self._restore_inline_panel(self.panel)
                return
            self.set_panel(
                "Modele LLM",
                [
                    "Routage automatique actif.",
                    f"Modele courant: {routed}",
                    f"Ancien modele: {previous}",
                    f"Function calling natif: {'actif' if profile.native_tool_calling else 'inactif'}",
                ],
                tone="success",
            )
            return

        if requested_thinking and not self._model_supports_thinking(model):
            self.set_panel(
                "Modele LLM",
                [
                    f"Thinking non disponible pour {model}.",
                    "Choisis gemma, gemma-31b ou laisse le profil par defaut.",
                ],
                tone="warn",
            )
            return

        if requested_thinking == "default":
            self.model_thinking_overrides.pop(model, None)
            thinking_level = None
        else:
            thinking_level = requested_thinking

        previous, profile = self._activate_model(model, auto=False, thinking_level=thinking_level)
        if self._can_use_transient_page():
            self._restore_inline_panel(self.panel)
            return
        self.set_panel(
            "Modele LLM",
            [
                f"Modele actif: {model}",
                f"Ancien modele: {previous}",
                f"Function calling natif: {'actif' if profile.native_tool_calling else 'inactif'}",
                f"Thinking: {profile.thinking_level or 'off'}",
                "Le prochain appel agent utilisera ce modele via la Gemini API.",
            ],
            tone="success",
        )

    def _apply_theme(self, theme_name):
        palette = THEME_PALETTES[theme_name]
        self.apply_palette(palette)
        self.theme_name = theme_name

    def _redraw_after_theme_change(self):
        if not self._can_use_transient_page():
            return
        self._clear_transient_screen()
        self.render_shell_header()
        self._header_rendered = True
        self.render_panel_state()
        self._stream_rendered_panel = True
        self._suppress_transient_result_once = True

    def _theme_picker_options(self):
        descriptions = {
            "dark": "Theme sombre par defaut pour terminal fonce.",
            "graphite": "Palette sobre: texte neutre, accent magenta, statuts cyan/vert/rouge.",
            "accessible": "Theme sombre daltonise: statuts distinguables sans rouge/vert seuls.",
            "ansi": "Theme sombre proche ANSI 16 couleurs pour palettes terminal personnalisees.",
        }
        options = []
        for theme_name in THEME_PALETTES:
            options.append(
                (
                    theme_name,
                    self._inline_option_text(
                        theme_name.title(),
                        descriptions[theme_name],
                        current=self.theme_name == theme_name,
                    ),
                )
            )
        return options

    def _theme_names_label(self):
        return ", ".join(THEME_PALETTES)

    def _run_theme_menu_page(self):
        previous_panel = self.panel
        try:
            selected = self._run_inline_choice(
                "Choisir le theme",
                ["Changer les couleurs du terminal pour cette session."],
                self._theme_picker_options(),
                default=self.theme_name if self.theme_name in THEME_PALETTES else "dark",
            )
        except (EOFError, KeyboardInterrupt):
            selected = "cancel"
        if selected not in (None, "cancel") and selected in THEME_PALETTES:
            self._apply_theme(selected)
            self.save_state()
            self.panel = previous_panel
            self._redraw_after_theme_change()
            return
        self._restore_inline_panel(previous_panel)

    def _handle_theme(self, args):
        if not args:
            if self._can_use_transient_page():
                self._run_theme_menu_page()
                return
            lines = [
                f"Theme actif: {self.theme_name}",
                f"Themes disponibles: {self._theme_names_label()}",
            ]
            if os.getenv("NO_COLOR") is not None:
                lines.append("NO_COLOR actif: les couleurs ANSI et prompt_toolkit sont desactivees.")
            self.set_panel("Theme", lines, tone="info")
            return

        if args[0].casefold() in {"show", "current", "actuel"}:
            lines = [
                f"Theme actif: {self.theme_name}",
                f"Themes disponibles: {self._theme_names_label()}",
            ]
            if os.getenv("NO_COLOR") is not None:
                lines.append("NO_COLOR actif: les couleurs ANSI et prompt_toolkit sont desactivees.")
            self.set_panel("Theme", lines, tone="info")
            return

        theme_name = args[0].casefold()
        if theme_name not in THEME_PALETTES:
            self.set_panel(
                "Theme",
                [
                    f"Theme inconnu: {args[0]}",
                    f"Themes valides: {self._theme_names_label()}",
                ],
                tone="warn",
            )
            return

        self._apply_theme(theme_name)
        self.save_state()
        lines = [f"Theme actif: {theme_name}"]
        if os.getenv("NO_COLOR") is not None:
            lines.append("NO_COLOR actif: rendu sans couleur conserve.")
        self.set_panel("Theme", lines, tone="success")
        self._redraw_after_theme_change()

    def _handle_reasoning(self, args):
        if not args:
            if self._can_use_transient_page():
                self._run_reasoning_menu_page()
                return
            self.set_panel(
                "Raisonnement",
                [
                    f"Mode actif: {self.reasoning_mode}",
                    "Modes disponibles: hidden, summary, full",
                    "summary affiche uniquement une intention synthetique avant les outils.",
                ],
                tone="info",
            )
            return

        if args[0].casefold() in {"show", "current", "actuel"}:
            self.set_panel(
                "Raisonnement",
                [
                    f"Mode actif: {self.reasoning_mode}",
                    "Modes disponibles: hidden, summary, full",
                    "summary affiche uniquement une intention synthetique avant les outils.",
                ],
                tone="info",
            )
            return

        mode = args[0].casefold()
        if mode not in REASONING_MODES:
            self.set_panel(
                "Raisonnement",
                [
                    f"Mode inconnu: {args[0]}",
                    "Modes valides: hidden, summary, full",
                ],
                tone="warn",
            )
            return

        self.reasoning_mode = mode
        self.save_state()
        self.set_panel(
            "Raisonnement",
            [f"Mode actif: {mode}"],
            tone="success",
        )

    def _reasoning_picker_options(self):
        descriptions = {
            "hidden": "Hide reasoning summaries and show only actions/results.",
            "summary": "Show a concise intent before tool actions.",
            "full": "Show the full reasoning stream available to the UI.",
        }
        options = []
        for mode in ("hidden", "summary", "full"):
            options.append(
                (
                    mode,
                    self._inline_option_text(
                        mode.title(),
                        descriptions[mode],
                        current=self.reasoning_mode == mode,
                    ),
                )
            )
        return options

    def _run_reasoning_menu_page(self):
        previous_panel = self.panel
        try:
            selected = self._run_inline_choice(
                "Select reasoning display",
                ["Choose how much reasoning SECOPS shows while working."],
                self._reasoning_picker_options(),
                default=self.reasoning_mode if self.reasoning_mode in REASONING_MODES else "summary",
            )
        except (EOFError, KeyboardInterrupt):
            selected = "cancel"
        if selected not in (None, "cancel") and selected in REASONING_MODES:
            self.reasoning_mode = selected
            self.save_state()
        self._restore_inline_panel(previous_panel)

    def _handle_profile(self, args):
        if not args:
            if self._can_use_transient_page():
                self._run_profile_menu_page()
                return
            self.set_panel(
                "Profil UX",
                [
                    f"Profil actif: {self.ux_profile}",
                    "Profils disponibles: quiet, ops, debug",
                    "quiet: masque les progressions verbeuses.",
                    "ops: garde cible, phase et findings dans la toolbar.",
                    "debug: ajoute modele, tokens estimes et chemins de logs.",
                    f"Config: {self.state_file}",
                ],
                tone="info",
            )
            return

        if args[0].casefold() in {"show", "current", "actuel"}:
            self.set_panel(
                "Profil UX",
                [
                    f"Profil actif: {self.ux_profile}",
                    "Profils disponibles: quiet, ops, debug",
                    "quiet: masque les progressions verbeuses.",
                    "ops: garde cible, phase et findings dans la toolbar.",
                    "debug: ajoute modele, tokens estimes et chemins de logs.",
                    f"Config: {self.state_file}",
                ],
                tone="info",
            )
            return

        profile = args[0].casefold()
        if profile not in UX_PROFILES:
            self.set_panel(
                "Profil UX",
                [
                    f"Profil inconnu: {args[0]}",
                    "Profils valides: quiet, ops, debug",
                ],
                tone="warn",
            )
            return

        self.ux_profile = profile
        self.save_state()
        self.set_panel(
            "Profil UX",
            [
                f"Profil actif: {profile}",
                f"Config: {self.state_file}",
            ],
            tone="success",
        )

    def _profile_picker_options(self):
        descriptions = {
            "quiet": "Reduce verbose progress and keep the interface compact.",
            "ops": "Keep target, phase, findings and jobs visible for operations.",
            "debug": "Add model, token estimates and log paths for diagnostics.",
        }
        options = []
        for profile in ("quiet", "ops", "debug"):
            options.append(
                (
                    profile,
                    self._inline_option_text(
                        profile.title(),
                        descriptions[profile],
                        current=self.ux_profile == profile,
                    ),
                )
            )
        return options

    def _run_profile_menu_page(self):
        previous_panel = self.panel
        try:
            selected = self._run_inline_choice(
                "Select UX profile",
                ["Choose how much session context SECOPS keeps visible."],
                self._profile_picker_options(),
                default=self.ux_profile if self.ux_profile in UX_PROFILES else "ops",
            )
        except (EOFError, KeyboardInterrupt):
            selected = "cancel"
        if selected not in (None, "cancel") and selected in UX_PROFILES:
            self.ux_profile = selected
            self.save_state()
        self._restore_inline_panel(previous_panel)

    def _parse_statusline_fields(self, args):
        raw = " ".join(args or "").replace(",", " ")
        fields = []
        invalid = []
        for value in raw.split():
            field = value.strip().casefold()
            if not field:
                continue
            if field not in STATUSLINE_FIELDS:
                invalid.append(field)
                continue
            if field not in fields:
                fields.append(field)
        return fields, invalid

    def _handle_statusline(self, args):
        normalized = [arg.casefold() for arg in (args or [])]
        if not normalized:
            if self._can_use_transient_page():
                self._run_statusline_menu_page()
                return
            active = self.statusline_fields or list(DEFAULT_STATUSLINE_FIELDS)
            source = "personnalisee" if self.statusline_fields else f"profil {self.ux_profile}"
            self.set_panel(
                "Statusline",
                [
                    f"Champs actifs: {', '.join(active)}",
                    f"Source: {source}",
                    f"Champs disponibles: {', '.join(STATUSLINE_FIELDS)}",
                    "Usage: /statusline model,target,phase,scope,findings,jobs,context",
                    "Reset: /statusline default",
                ],
                tone="info",
            )
            return

        if normalized[0] in {"show", "current", "actuel"}:
            active = self.statusline_fields or list(DEFAULT_STATUSLINE_FIELDS)
            source = "personnalisee" if self.statusline_fields else f"profil {self.ux_profile}"
            self.set_panel(
                "Statusline",
                [
                    f"Champs actifs: {', '.join(active)}",
                    f"Source: {source}",
                    f"Champs disponibles: {', '.join(STATUSLINE_FIELDS)}",
                    "Usage: /statusline model,target,phase,scope,findings,jobs,context",
                    "Reset: /statusline default",
                ],
                tone="info",
            )
            return

        if normalized[0] in {"default", "reset", "profil", "profile"}:
            self.statusline_fields = []
            self.save_state()
            self.set_panel(
                "Statusline",
                [
                    f"Statusline restauree sur le profil {self.ux_profile}.",
                    f"Champs: {', '.join(DEFAULT_STATUSLINE_FIELDS)}",
                ],
                tone="success",
            )
            return

        fields, invalid = self._parse_statusline_fields(args)
        if invalid or not fields:
            lines = [
                "Champs invalides: " + (", ".join(invalid) if invalid else "aucun champ valide"),
                f"Champs disponibles: {', '.join(STATUSLINE_FIELDS)}",
            ]
            self.set_panel("Statusline", lines, tone="warn")
            return

        self.statusline_fields = fields
        self.save_state()
        self.set_panel(
            "Statusline",
            [
                f"Champs actifs: {', '.join(fields)}",
                "Configuration enregistree.",
            ],
            tone="success",
        )

    def _statusline_current_preset(self):
        if not self.statusline_fields:
            return "profile"
        if tuple(self.statusline_fields) == tuple(DEFAULT_STATUSLINE_FIELDS):
            return "compact"
        if tuple(self.statusline_fields) == tuple(STATUSLINE_FIELDS):
            return "full"
        return "custom"

    def _statusline_picker_options(self):
        current_preset = self._statusline_current_preset()
        presets = [
            ("profile", "Profile default", f"Use the active UX profile fields ({', '.join(DEFAULT_STATUSLINE_FIELDS)})."),
            ("compact", "Compact", f"Pin {', '.join(DEFAULT_STATUSLINE_FIELDS)}."),
            ("full", "Full", f"Pin {', '.join(STATUSLINE_FIELDS)}."),
        ]
        if current_preset == "custom":
            presets.append(("custom", "Custom", f"Keep current fields: {', '.join(self.statusline_fields)}."))
        options = []
        for value, label, description in presets:
            options.append(
                (
                    value,
                    self._inline_option_text(label, description, current=current_preset == value),
                )
            )
        return options

    def _apply_statusline_preset(self, preset):
        if preset == "profile":
            self.statusline_fields = []
        elif preset == "compact":
            self.statusline_fields = list(DEFAULT_STATUSLINE_FIELDS)
        elif preset == "full":
            self.statusline_fields = list(STATUSLINE_FIELDS)
        elif preset == "custom":
            return
        else:
            return
        self.save_state()

    def _run_statusline_menu_page(self):
        previous_panel = self.panel
        try:
            selected = self._run_inline_choice(
                "Select statusline",
                ["Choose which context fields stay visible in the prompt footer."],
                self._statusline_picker_options(),
                default=self._statusline_current_preset(),
            )
        except (EOFError, KeyboardInterrupt):
            selected = "cancel"
        if selected not in (None, "cancel"):
            self._apply_statusline_preset(selected)
        self._restore_inline_panel(previous_panel)

    def _handle_notify(self, args):
        if not args:
            if self._can_use_transient_page():
                self._run_notify_menu_page()
                return
            self.set_panel(
                "Notifications",
                [
                    f"Mode actif: {self.notification_mode}",
                    "Modes disponibles: off, bell, title, all",
                    "bell: signal sonore terminal; title: titre terminal OSC; all: les deux.",
                ],
                tone="info",
            )
            return

        if args[0].casefold() in {"show", "current", "actuel"}:
            self.set_panel(
                "Notifications",
                [
                    f"Mode actif: {self.notification_mode}",
                    "Modes disponibles: off, bell, title, all",
                    "bell: signal sonore terminal; title: titre terminal OSC; all: les deux.",
                ],
                tone="info",
            )
            return

        mode_aliases = {
            "on": "all",
            "oui": "all",
            "yes": "all",
            "off": "off",
            "non": "off",
            "no": "off",
            "none": "off",
            "bell": "bell",
            "beep": "bell",
            "title": "title",
            "titre": "title",
            "all": "all",
            "tout": "all",
        }
        requested = args[0].casefold()
        mode = mode_aliases.get(requested, requested)
        if mode not in NOTIFICATION_MODES:
            self.set_panel(
                "Notifications",
                [
                    f"Mode inconnu: {args[0]}",
                    "Modes valides: off, bell, title, all",
                ],
                tone="warn",
            )
            return

        self.notification_mode = mode
        self.save_state()
        self.set_panel(
            "Notifications",
            [
                f"Mode actif: {mode}",
                "Les notifications sont emises a la fin des jobs outil.",
            ],
            tone="success",
        )

    def _notification_picker_options(self):
        descriptions = {
            "off": "Do not emit terminal notifications after jobs.",
            "bell": "Ring the terminal bell after a job finishes.",
            "title": "Update the terminal title after a job finishes.",
            "all": "Use both terminal bell and title notifications.",
        }
        options = []
        for mode in ("off", "bell", "title", "all"):
            options.append(
                (
                    mode,
                    self._inline_option_text(
                        mode.title(),
                        descriptions[mode],
                        current=self.notification_mode == mode,
                    ),
                )
            )
        return options

    def _run_notify_menu_page(self):
        previous_panel = self.panel
        try:
            selected = self._run_inline_choice(
                "Select notifications",
                ["Choose how SECOPS notifies when tool jobs finish."],
                self._notification_picker_options(),
                default=self.notification_mode if self.notification_mode in NOTIFICATION_MODES else "off",
            )
        except (EOFError, KeyboardInterrupt):
            selected = "cancel"
        if selected not in (None, "cancel") and selected in NOTIFICATION_MODES:
            self.notification_mode = selected
            self.save_state()
        self._restore_inline_panel(previous_panel)

    def _activate_model(self, model, *, auto=False, thinking_level=None):
        previous = self.gemini_runtime.model
        self.model_auto_routing = auto
        if thinking_level is not None:
            self.model_thinking_overrides[model] = thinking_level
        self.gemini_runtime = replace(self.gemini_runtime, model=model)
        profile = self._apply_model_profile()
        self.last_gemini_error = None
        self.save_state()
        return previous, profile

    def _run_model_menu_page(self):
        previous_panel = self.panel
        try:
            selected = self._run_model_picker_choice(
                "Select model",
                [
                    "Switch between SECOPS models. Applies to this session and future SECOPS sessions.",
                    "For other/previous model names, specify with GEMINI_MODEL or /model <name>.",
                ],
                self._model_picker_options(),
                default=self._model_picker_default_value(),
            )
        except (EOFError, KeyboardInterrupt):
            selected = "cancel"
        self._apply_model_picker_selection(selected)
        self._restore_inline_panel(previous_panel)

    def _choose_model_thinking_page(self, model):
        profile = get_model_profile(model)
        if not profile.native_tool_calling and not profile.thinking_level:
            return None
        default_level = self.model_thinking_overrides.get(model, profile.thinking_level or "off")
        options = [
            ("default", f"Profil par defaut ({profile.thinking_level or 'off'})"),
            ("off", "Off - pas de thinking explicite"),
            ("minimal", "Minimal"),
            ("low", "Low"),
            ("medium", "Medium"),
            ("high", "High"),
        ]
        selected = self._run_transient_choice_page(
            "Thinking",
            [f"Modele: {model}", "Choisis le niveau de thinking."],
            options,
            default=default_level if default_level in {"off", "minimal", "low", "medium", "high"} else "default",
        )
        if selected in (None, "default"):
            self.model_thinking_overrides.pop(model, None)
            return None
        return selected

    def _benchmark_model_routing(self):
        scenarios = (
            ("scan", "recon", "Scan 10.10.10.10 et donne le nombre de ports ouverts"),
            ("web", "enumeration", "Find directories on the web server using gobuster"),
            ("pivot", "exploitation", "Pivote apres cet echec et propose la prochaine action"),
            ("rapport", "reporting", "Genere un rapport synthetique de l'engagement"),
        )
        rows = []
        for label, phase, prompt in scenarios:
            model = route_model(prompt, phase)
            profile = get_model_profile(model)
            tools = self.tool_executor.available_tools_for_context(
                phase=phase,
                prompt=prompt,
                findings_store=self.findings_store,
            )
            rows.append(
                {
                    "scenario": label,
                    "phase": phase,
                    "model": model,
                    "native_tool_calling": profile.native_tool_calling,
                    "thinking_level": profile.thinking_level or "off",
                    "tool_count": len(tools),
                    "tools": [tool.name for tool in tools],
                }
            )

        benchmark_dir = self.workspace / "model_benchmarks"
        benchmark_dir.mkdir(parents=True, exist_ok=True)
        path = benchmark_dir / f"routing_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        path.write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")

        lines = ["Benchmark de routage sans appel API:"]
        for row in rows:
            native = "natif" if row["native_tool_calling"] else "json"
            lines.append(
                f"{row['scenario']}: {row['model']} | {native} | thinking {row['thinking_level']} | {row['tool_count']} outil(s)"
            )
        lines.append(f"Resultat: {path}")
        self.set_panel("Benchmark modele", lines, tone="info")

    def _command_executable(self, command):
        try:
            parts = shlex.split(command)
        except ValueError:
            parts = command.split()
        if not parts:
            return ""
        return Path(parts[0]).name

    def _should_track_tool_job(self, name, args):
        if name not in TRACKED_TOOL_JOBS:
            return False
        if name in {"execute_command", "execute_admin_command"}:
            executable = self._command_executable((args or {}).get("command", ""))
            return executable in TRACKED_COMMAND_EXECUTABLES
        return True

    def _is_risky_tool_event(self, name, args):
        args = args or {}
        if name in RISKY_TOOL_EVENTS:
            return True
        if name == "execute_command":
            executable = self._command_executable(args.get("command", ""))
            return (
                executable in RISKY_COMMAND_EXECUTABLES
                or EngagementState.is_guarded_phase(self.engagement.phase)
            )
        return False

    def _tool_job_key(self, name, args):
        if name in {"execute_command", "execute_admin_command"}:
            return f"{name}:{(args or {}).get('command', '')}"
        return name

    def _tool_job_title(self, name, args):
        args = args or {}
        if name in {"execute_command", "execute_admin_command"}:
            command = args.get("command", "")
            return command[:96] + ("..." if len(command) > 96 else "")
        if name == "scan_target":
            target = args.get("target", "?")
            mode = args.get("mode", "quick")
            return f"scan {target} ({mode})"
        if name == "enumerate_web":
            target = args.get("target", "?")
            port = args.get("port", "80")
            return f"enum web {target}:{port}"
        if name == "search_exploit":
            return f"searchsploit {args.get('query', '?')}"
        if name == "analyze_service":
            service = args.get("service", "?")
            version = args.get("version", "")
            return f"analyse {service} {version}".strip()
        return name

    def _start_tool_job(self, event):
        name = event.get("name", "")
        args = event.get("args", {}) or {}
        checkpoint_path = None
        if self._is_risky_tool_event(name, args):
            checkpoint_path = self._save_checkpoint(
                f"avant outil risque: {name}",
                trigger=f"tool:{name}",
            )
        if not self._should_track_tool_job(name, args):
            return None
        key = self._tool_job_key(name, args)
        if key in self._active_tool_jobs:
            return self._active_tool_jobs[key]
        details = []
        command = args.get("command", "")
        if command:
            details.append(f"commande: {command}")
        if checkpoint_path:
            details.append(f"checkpoint: {checkpoint_path}")
        job = self.jobs.create(
            "tool",
            self._tool_job_title(name, args),
            details=details,
            status="running",
            result="execution en cours",
        )
        self._active_tool_jobs[key] = job.job_id
        self._last_active_tool_job_id = job.job_id
        event["job_id"] = job.job_id
        return job.job_id

    def _terminal_is_tty(self):
        return sys.stdout.isatty()

    def _terminal_write(self, text):
        sys.stdout.write(text)
        sys.stdout.flush()

    def _notification_status_label(self, status):
        return {
            "success": "termine",
            "failed": "echec",
            "cancelled": "annule",
        }.get(status, status or "termine")

    def _emit_terminal_notification(self, summary):
        if self.notification_mode == "off" or not self._terminal_is_tty():
            return
        if self.notification_mode in {"bell", "all"}:
            self._terminal_write("\a")
        if self.notification_mode in {"title", "all"}:
            title = re.sub(r"[\x00-\x1f\x7f]", " ", f"SECOPS - {summary}")[:120]
            self._terminal_write(f"\033]0;{title}\a")

    def _notify_job_completion(self, job_id, status, result_label, event):
        if self.notification_mode == "off":
            return
        status_label = self._notification_status_label(status)
        summary = f"Job #{job_id} {status_label}: {result_label or '-'}"
        event["notification"] = summary
        self._emit_terminal_notification(summary)

    def _finish_tool_job(self, event):
        name = event.get("name", "")
        result = event.get("result", {}) if isinstance(event.get("result", {}), dict) else {}
        args = event.get("args") or event.get("arguments") or {}
        if not args and name in {"execute_command", "execute_admin_command"}:
            args = {"command": result.get("command", "")}
        key = self._tool_job_key(name, args)
        job_id = self._active_tool_jobs.pop(key, None)
        if not job_id and self._last_active_tool_job_id:
            job_id = self._last_active_tool_job_id
        if not job_id:
            return

        event_type = event.get("type")
        if event_type == "tool_success":
            if result.get("cancelled"):
                label = "annule"
                if result.get("log_path"):
                    label += f"; log partiel: {result['log_path']}"
                self.jobs.cancel(job_id, result=label)
                self._notify_job_completion(job_id, "cancelled", label, event)
                if self._last_active_tool_job_id == job_id:
                    self._last_active_tool_job_id = None
                return
            returncode = result.get("returncode")
            if returncode is None:
                status = "success"
                label = "termine"
            else:
                status = "success" if returncode == 0 else "failed"
                label = f"code {returncode}"
            if result.get("log_path"):
                label += f"; log: {result['log_path']}"
            self.jobs.update(job_id, status=status, result=label)
        elif event_type == "tool_denied":
            status = "cancelled"
            label = "permission refusee"
            self.jobs.update(job_id, status=status, result=label)
        elif event_type == "tool_policy_blocked":
            remediation = event.get("remediation") or event.get("error", "")
            status = "cancelled"
            label = remediation[:180]
            self.jobs.update(job_id, status=status, result=label)
        elif event_type == "tool_error":
            status = "failed"
            label = str(event.get("error", ""))
            self.jobs.update(job_id, status=status, result=label)
        else:
            status = ""
            label = ""

        if status:
            self._notify_job_completion(job_id, status, label, event)

        if self._last_active_tool_job_id == job_id:
            self._last_active_tool_job_id = None

    def _update_tool_job_progress(self, event):
        command = event.get("command", "")
        job_id = None
        if command:
            job_id = self._active_tool_jobs.get(f"execute_command:{command}")
        if not job_id:
            job_id = self._last_active_tool_job_id
        if not job_id:
            return
        content = str(event.get("content", "")).strip()
        if content:
            self.jobs.update(job_id, status="running", result=content[:180])

    def _show_case(self, case, activated=False):
        title = "Cas actif" if activated else "Cas memoire"
        lines = [
            f"{case.title} ({case.platform})",
            f"dossier: {self._relative_to_repo(case.case_dir)}",
        ]
        if case.summary:
            lines.append(f"resume: {case.summary}")
        if case.signals:
            lines.append(f"signal: {case.signals[0]}")
        if case.source_files:
            lines.append(f"source: {self._relative_to_repo(case.source_files[0])}")
        self.set_panel(title, lines[:12], tone="success" if activated else "info")

    def _activate_case(self, raw_query):
        case, error = self._resolve_case_arg(raw_query)
        if error:
            self.set_panel("Cas", [error], tone="error")
            return
        self.active_case = case
        self._active_case_slug = case.slug
        self.agent_loop.active_case_label = case.label
        self.save_state()
        self._show_case(case, activated=True)

    def _deactivate_case(self):
        self.active_case = None
        self._active_case_slug = ""
        self.agent_loop.active_case_label = ""
        self.save_state()
        self.set_panel(
            "Cas",
            [
                "Aucun cas actif.",
                "La base de connaissance reste disponible a la demande via query_knowledge ou /case list.",
            ],
            tone="warn",
        )

    def _command_mode_label(self):
        return {
            "read-only": "lecture seule",
            "ask": "validation",
            "auto-low-risk": "auto faible risque",
            "session": "session",
            "deny": "desactive",
        }.get(self.command_permission_mode, self.command_permission_mode)

    def _set_command_permission_mode(self, mode):
        normalized = (mode or "").strip().casefold()
        aliases = {
            "read-only": "read-only",
            "readonly": "read-only",
            "read": "read-only",
            "lecture": "read-only",
            "lecture-seule": "read-only",
            "lecture_seule": "read-only",
            "plan": "read-only",
            "plan-mode": "read-only",
            "plan_mode": "read-only",
            "default": "ask",
            "validation": "ask",
            "ask": "ask",
            "demande": "ask",
            "auto-review": "auto-low-risk",
            "auto_review": "auto-low-risk",
            "autoreview": "auto-low-risk",
            "accept-edits": "auto-low-risk",
            "accept_edits": "auto-low-risk",
            "acceptedits": "auto-low-risk",
            "auto": "auto-low-risk",
            "auto-low-risk": "auto-low-risk",
            "auto_low_risk": "auto-low-risk",
            "low-risk": "auto-low-risk",
            "faible-risque": "auto-low-risk",
            "session": "session",
            "full-access": "session",
            "full_access": "session",
            "fullaccess": "session",
            "allow": "session",
            "autorise": "session",
            "autoriser": "session",
            "bypass": "session",
            "bypasspermissions": "session",
            "bypass-permissions": "session",
            "bypass_permissions": "session",
            "deny": "deny",
            "refuse": "deny",
            "refuser": "deny",
            "off": "deny",
        }
        mode = aliases.get(normalized, "")
        if not mode:
            return False
        self.command_permission_mode = mode
        self.tool_executor.command_permission_mode = mode
        if mode != "session":
            self.tool_executor._session_allow_commands.clear()
        self.save_state()
        return True

    def _scope_summary_label(self):
        if not self.tool_executor.authorized_scope:
            return "non defini"
        if len(self.tool_executor.authorized_scope) == 1:
            return next(iter(self.tool_executor.authorized_scope))
        return f"{len(self.tool_executor.authorized_scope)} entrees"

    def _session_snapshot_segments(self):
        target_label = self.active_target.label if self.active_target else (self.current_target or "aucune")
        return [
            ("phase", self.engagement.phase_label, "success"),
            ("cible", target_label, "info" if target_label != "aucune" else "muted"),
            ("findings", str(self.findings_store.count), "success" if self.findings_store.count else "muted"),
            ("scope", self._scope_summary_label(), "info" if self.tool_executor.authorized_scope else "muted"),
            ("jobs", str(self.jobs.active_count), "warn" if self.jobs.active_count else "muted"),
        ]

    def _build_home_panel_lines(self):
        return [
            "Ecran efface.",
            "Decris une cible ou un objectif, ou tape /status pour voir le contexte courant.",
        ]

    def _build_case_context(self):
        if not self.active_case:
            parts = ["Aucun cas memoire actif."]
        else:
            parts = [f"Cas actif: {self.active_case.title} ({self.active_case.platform})"]
            if self.active_case.summary:
                parts.append(f"Resume: {self.active_case.summary}")
            if self.active_case.signals:
                parts.append("Signaux connus:")
                parts.extend(f"- {item}" for item in self.active_case.signals[:6])
            if self.active_case.techniques:
                parts.append("Techniques applicables:")
                parts.extend(f"- {item}" for item in self.active_case.techniques[:5])
            if self.active_case.services:
                parts.append("Services connus:")
                parts.extend(f"- {item}" for item in self.active_case.services[:5])
            if self.active_case.hypotheses:
                parts.append("Hypotheses memoire:")
                parts.extend(f"- {item}" for item in self.active_case.hypotheses[:4])
            if self.active_case.actions:
                parts.append("Actions recommandees:")
                parts.extend(f"- {item}" for item in self.active_case.actions[:4])
            if self.active_case.pivots:
                parts.append("Pivots deja memorises:")
                parts.extend(f"- {item}" for item in self.active_case.pivots[:3])
            if self.active_case.lessons:
                parts.append("Lecons transferables:")
                parts.extend(f"- {item}" for item in self.active_case.lessons[:3])
            if self.active_case.artifacts:
                parts.append("Artefacts attendus:")
                parts.extend(f"- {item}" for item in self.active_case.artifacts[:3])

        if self.current_target:
            parts.append(f"Cible courante: {self.current_target}")
        return "\n".join(parts)

    def _build_memory_candidates_context(self, raw_prompt):
        if not self._should_use_knowledge_memory(raw_prompt):
            return ""

        suggestions = self.knowledge_store.suggest(raw_prompt, limit=2)
        if not suggestions:
            return (
                "MEMOIRE CANDIDATE:\n"
                "Aucun cas analogue fort trouve. Continue avec la methodologie pentest standard."
            )

        lines = [
            "MEMOIRE CANDIDATE:",
            "Ces elements sont des pistes transferables, pas des faits valides sur la cible courante.",
            "Confirme chaque port, service, chemin, utilisateur ou credential par observation outil avant de conclure.",
        ]
        for suggestion in suggestions:
            case = suggestion.case
            lines.append(f"- {case.label} | score {suggestion.score} | {case.summary or case.title}")
            signals = suggestion.matched_signals or case.signals[:2]
            actions = suggestion.matched_actions or case.actions[:2]
            pivots = suggestion.matched_pivots or case.pivots[:1]
            if signals:
                lines.append(f"  signaux utiles: {'; '.join(signals[:2])}")
            if actions:
                lines.append(f"  actions candidates: {'; '.join(actions[:2])}")
            if pivots:
                lines.append(f"  pivot: {pivots[0]}")
        return "\n".join(lines)

    def _active_case_matches_prompt(self, raw_prompt):
        if not self.active_case:
            return False

        lowered = raw_prompt.casefold()
        tokens = {
            self.active_case.slug.casefold(),
            self.active_case.platform.casefold(),
            self.active_case.title.casefold(),
        }
        return any(token and token in lowered for token in tokens)

    def _should_use_knowledge_memory(self, raw_prompt):
        prompt = (raw_prompt or "").strip()
        if not prompt:
            return False
        if self._is_local_system_request(prompt):
            return False
        if self._active_case_matches_prompt(prompt):
            return True
        if TEXT_TARGET_RE.search(prompt):
            return True
        if self.current_target and CASE_RELEVANT_RE.search(prompt):
            return True
        return bool(CASE_RELEVANT_RE.search(prompt))

    def _should_apply_case_context(self, raw_prompt):
        return bool(self.active_case and self._should_use_knowledge_memory(raw_prompt))

    def _is_local_system_request(self, raw_text):
        prompt = (raw_text or "").strip()
        if not prompt:
            return False

        lowered = prompt.casefold()
        if LOCAL_SYSTEM_RE.search(prompt):
            return True

        update_terms = ("mise a jour", "mise à jour", "mettre a jour", "mettre à jour")
        host_terms = (
            "systeme",
            "système",
            "machine",
            "locale",
            "local",
            "ubuntu",
            "debian",
            "paquet",
            "package",
        )
        return any(term in lowered for term in update_terms) and any(
            term in lowered for term in host_terms
        )

    def _build_agent_context(self, raw_prompt):
        if self._is_local_system_request(raw_prompt):
            return "\n".join(
                [
                    "Contexte local: la demande concerne la machine actuelle de SECOPS.",
                    "Ignore le cas memoire actif si la demande parle d'apt, sudo, paquets ou maintenance systeme.",
                    "N'exige pas d'IP cible pour une action locale sur cette machine.",
                    f"Repertoire courant: {self._shell_directory_label()}",
                ]
            )
        if self._should_apply_case_context(raw_prompt):
            return "\n".join(
                [
                    "Contexte cible: la demande semble concerner un lab, une cible ou un service a analyser.",
                    "La memoire de cas active peut servir de cadre de travail principal pour cette demande.",
                    "Les faits de la memoire doivent etre revalides sur la cible courante avant reponse finale.",
                    self._build_case_context(),
                ]
            )
        if self._should_use_knowledge_memory(raw_prompt):
            memory_context = self._build_memory_candidates_context(raw_prompt)
            return "\n".join(
                [
                    "Contexte cible: la demande ressemble a une tache de pentest ou de lab.",
                    "Utilise la base de connaissance locale comme experience de terrain, sans supposer que le lab est identique.",
                    memory_context,
                    f"Repertoire courant: {self._shell_directory_label()}",
                ]
            )
        return "\n".join(
            [
                "Contexte general: reponds d'abord a la demande presente sans supposer qu'elle concerne un lab precis.",
                "La base de connaissance locale est optionnelle et ne doit etre consultee que si un precedent est utile.",
                (
                    "Un cas memoire peut etre actif en interface, mais il ne doit pas cadrer cette demande."
                    if self.active_case
                    else "Aucun cas memoire actif ne doit contraindre cette demande."
                ),
                f"Repertoire courant: {self._shell_directory_label()}",
            ]
        )

    def _extract_target_from_text(self, raw_text):
        match = TEXT_TARGET_RE.search(raw_text)
        if not match:
            return ""
        return match.group(0)

    def _should_capture_target_context(self, raw_text):
        prompt = (raw_text or "").strip()
        if not prompt or self._is_local_system_request(prompt):
            return False
        if not TEXT_TARGET_RE.search(prompt):
            return False
        lowered = prompt.casefold()
        target_terms = ("cible", "target", "scan", "service", "port", "lab", "room")
        return self._active_case_matches_prompt(prompt) or any(term in lowered for term in target_terms)

    def _capture_target_from_text(self, raw_text):
        if not self._should_capture_target_context(raw_text):
            return ""
        detected = detect_targets(raw_text)
        if not detected:
            return ""

        target = detected[0]
        existing = None
        for known in self.targets:
            if known.address == target.address and known.target_type == target.target_type:
                existing = known
                break
        if existing is None:
            existing = target
            self.targets.append(existing)

        self.active_target = existing
        self.agent_loop.targets = self.targets
        self.agent_loop.active_target = self.active_target

        candidate = existing.address
        if not candidate or candidate == self.current_target:
            return ""
        self.current_target = candidate
        self.save_state()
        return candidate

    def _is_target_declaration_only(self, raw_text):
        if not self._extract_target_from_text(raw_text):
            return False
        prompt = (raw_text or "").strip()
        if not prompt or "?" in prompt:
            return False
        lowered = prompt.casefold()
        action_terms = (
            "analyse", "analyze", "cherche", "combien", "directory", "directories",
            "enum", "enumerate", "find", "gobuster", "how many", "lance",
            "nmap", "open", "port", "scan", "service", "trouve", "version",
            "what", "which",
        )
        if any(term in lowered for term in action_terms):
            return False

        remainder = prompt
        for target in detect_targets(prompt):
            remainder = remainder.replace(target.raw, " ")
            remainder = remainder.replace(target.address, " ")
        remainder = re.sub(
            r"\b(target|ip|address|adresse|cible|host|hote|url|is|est)\b",
            " ",
            remainder,
            flags=re.IGNORECASE,
        )
        remainder = re.sub(r"[\s:;,\-=]+", "", remainder)
        return not remainder

    def _reply_target_registered(self, raw_prompt, target_label):
        reply_lines = [
            f"Cible active definie: {target_label}.",
            "Aucune commande lancee. Demande un scan explicitement quand tu veux demarrer la reconnaissance.",
        ]
        self._remember_exchange(raw_prompt, "\n".join(reply_lines))
        self._set_transcript_panel("Cible active", reply_lines, tone="info")

    def _remember_exchange(self, user_text, agent_text):
        self.conversation_history.append(
            {
                "user": user_text,
                "agent": agent_text[:500],
            }
        )
        if len(self.conversation_history) > 10:
            self.conversation_history = self.conversation_history[-10:]

    def _display_shell_path(self, path):
        path = Path(path).resolve()
        home = Path.home().resolve()
        try:
            relative = path.relative_to(home)
            return f"~/{relative}" if str(relative) != "." else "~"
        except ValueError:
            return str(path)

    def _shell_directory_label(self):
        return self._display_shell_path(Path.cwd())

    def _current_model_label(self):
        if self.last_gemini_error:
            return "gemini indisponible"
        if self.gemini_runtime.api_key_present:
            prefix = "auto:" if self.model_auto_routing else ""
            return f"{prefix}{self.gemini_runtime.model}"
        return "hors ligne"

    def get_footer_context(self):
        return f"{self._current_model_label()} · {self._shell_directory_label()}"

    def _reasoning_summary_for_tool(self, name, args):
        args = args or {}
        if name == "query_knowledge":
            return "Consultation de la memoire pertinente..."
        if name in {"read_file", "list_findings"}:
            return "Lecture du contexte disponible..."
        if name == "write_file":
            return "Preparation d'un artefact de travail..."
        if name in {"install_pentest_tool", "install_pentest_tools", "suggest_pentest_tools"}:
            return "Verification des outils requis..."
        if name in {"scan_target", "execute_command", "execute_admin_command"}:
            command = str(args.get("command", "") or "")
            executable = ""
            if command:
                tokens = safe_split(command)
                executable = Path(tokens[0]).name if tokens else ""
            if name == "scan_target" or executable in {"nmap", "masscan"}:
                return "Analyse des ports ouverts..."
            if executable in {"gobuster", "ffuf", "dirb", "feroxbuster", "nikto", "wpscan"}:
                return "Enumeration de la surface web..."
            if executable in {"enum4linux", "smbclient", "smbmap"}:
                return "Enumeration des services SMB..."
            if executable in {"hydra", "john", "hashcat"}:
                return "Verification controlee des identifiants..."
            if name == "execute_admin_command":
                return "Preparation d'une action admin controlee..."
            return "Preparation d'une commande locale..."
        if name == "enumerate_web":
            return "Enumeration de la surface web..."
        if name == "analyze_service":
            return "Analyse du service detecte..."
        if name == "search_exploit":
            return "Recherche d'exploits publics..."
        return "Preparation de l'action outil..."

    def _append_reasoning_summary_for_tool(self, event):
        summary = self._reasoning_summary_for_tool(event.get("name", ""), event.get("args", {}))
        if not summary:
            return
        self._append_live_stream_event(
            {
                "type": "reasoning_summary",
                "content": summary,
                "tool_name": event.get("name", ""),
            }
        )

    def _append_live_stream_event(self, event, *, replace_last=False):
        state = self._live_stream_state
        if not state:
            return

        events = state["events"]
        if event["type"] == "tool_start":
            self._start_tool_job(event)
        elif event["type"] in {"tool_success", "tool_error", "tool_denied", "tool_policy_blocked"}:
            self._finish_tool_job(event)
        if (
            event["type"] in {"tool_success", "tool_error", "tool_denied", "tool_policy_blocked"}
            and events
            and events[-1].get("type") == "tool_progress"
            and events[-1].get("ephemeral")
        ):
            events.pop()
        if replace_last and events:
            events[-1] = event
        else:
            events.append(event)

        if not state["stream_progress"]:
            return

        rendered = self.renderer.render(events, model_label=self.gemini_runtime.model)
        if not rendered["lines"]:
            return

        snapshot = (
            rendered["title"],
            tuple(rendered["lines"]),
            rendered["tone"],
        )
        if snapshot == state["last_snapshot"]:
            return

        panel_lines = self._incremental_panel_lines(state["last_snapshot"], rendered)
        self._set_transcript_panel(
            rendered["title"],
            panel_lines,
            tone=rendered["tone"],
        )
        self._render_live_panel_update()
        state["last_snapshot"] = snapshot

    def _handle_tool_progress(self, event):
        state = self._live_stream_state
        if not state or not state["stream_progress"]:
            return

        content = str(event.get("content", "")).strip()
        if not content:
            return
        self._update_tool_job_progress(event)
        if self.ux_profile == "quiet" and event.get("progress_kind") not in {"finding", "warning", "timeout"}:
            return

        rendered_event = {
            "type": "tool_progress",
            "name": "execute_command",
            "stream": event.get("stream", "status"),
            "content": content,
            "command": event.get("command", ""),
        }
        for key in (
            "tool",
            "progress_kind",
            "phase",
            "percent",
            "eta",
            "elapsed",
            "elapsed_label",
            "timeout",
            "detail",
        ):
            if key in event:
                rendered_event[key] = event[key]
        if event.get("ephemeral"):
            rendered_event["ephemeral"] = True

        last_event = state["events"][-1] if state["events"] else None
        if (
            last_event
            and last_event.get("type") == "tool_progress"
            and last_event.get("stream") == rendered_event["stream"]
            and last_event.get("content") == rendered_event["content"]
        ):
            return

        replace_last = bool(
            rendered_event.get("ephemeral")
            and last_event
            and last_event.get("type") == "tool_progress"
            and last_event.get("ephemeral")
        )
        self._append_live_stream_event(rendered_event, replace_last=replace_last)

    def _render_live_panel_update(self):
        self._stream_rendered_panel = True
        self.render_panel_state()

    def _incremental_panel_lines(self, previous_snapshot, current_rendered):
        if not previous_snapshot:
            return list(current_rendered["lines"])

        previous_lines = list(previous_snapshot[1])
        current_lines = list(current_rendered["lines"])
        if (
            current_rendered["title"] == previous_snapshot[0]
            and len(current_lines) == len(previous_lines)
            and current_lines[:-1] == previous_lines[:-1]
            and current_lines[-1:] != previous_lines[-1:]
        ):
            return current_lines[-1:]
        if (
            current_rendered["title"] == previous_snapshot[0]
            and len(current_lines) >= len(previous_lines)
            and current_lines[: len(previous_lines)] == previous_lines
        ):
            delta_lines = current_lines[len(previous_lines) :]
            return delta_lines or current_lines[-1:]
        return current_lines

    def _split_text_excerpt(self, text, limit=4):
        lines = self.renderer._split_text(text)
        return lines[:limit]

    def _pending_install_executables(self, pending):
        pending = pending or {}
        values = []
        if pending.get("executables"):
            values.extend(pending.get("executables") or [])
            tool_names = None
        else:
            arguments = pending.get("arguments") or {}
            tool_names = arguments.get("tool_names")
        if tool_names:
            tool_names = arguments.get("tool_names")
            if isinstance(tool_names, str):
                values.extend(re.split(r"[\s,]+", tool_names.strip()))
            else:
                values.extend(tool_names)
        if pending.get("executable"):
            values.append(pending.get("executable"))

        names = []
        seen = set()
        for value in values:
            name = self.tool_registry.normalize_name(str(value))
            if not name or name in seen:
                continue
            names.append(name)
            seen.add(name)
        return names

    def _install_label(self, executables):
        if len(executables) == 1:
            return executables[0]
        return f"{len(executables)} outils ({', '.join(executables)})"

    def _handle_pending_tool_install(self, raw_text):
        if not self.pending_tool_install:
            return False

        prompt = raw_text.strip()
        if not prompt:
            return False

        if self._matches_install_decline(prompt):
            executables = self._pending_install_executables(self.pending_tool_install)
            executable = self._install_label(executables)
            self._update_pending_job(
                self.pending_tool_install,
                status="cancelled",
                result="annule par l'utilisateur",
            )
            self.pending_tool_install = None
            reply = (
                f"Installation de {executable} annulee. "
                "Donne une autre piste ou installe-le manuellement."
            )
            self._remember_exchange(prompt, reply)
            self._set_transcript_panel("Installation outil", [reply], tone="warn")
            return True

        if self._matches_install_confirmation(prompt):
            self._run_pending_tool_install(prompt)
            return True

        executables = self._pending_install_executables(self.pending_tool_install)
        executable = self._install_label(executables)
        reminder = [
            f"{executable} attend confirmation.",
            "Reponds oui pour lancer l'installation ou non pour annuler.",
        ]
        if "sudo " in prompt.casefold() or "apt-get" in prompt.casefold():
            reminder.append("Ne tape pas la commande ici, SECOPS gerera sudo dans le terminal.")
        self._set_transcript_panel("Installation outil", reminder, tone="warn")
        return True

    def _handle_pending_tool_retry(self, raw_text):
        if not self.pending_tool_retry:
            return False

        prompt = raw_text.strip()
        if not prompt:
            return False

        if self._matches_install_decline(prompt):
            executable = self.pending_tool_retry["name"]
            self.pending_tool_retry = None
            reply = f"Relance de {executable} annulee."
            self._remember_exchange(prompt, reply)
            self._set_transcript_panel("Relance outil", [reply], tone="warn")
            return True

        if self._matches_install_confirmation(prompt):
            self._run_pending_tool_retry(prompt)
            return True

        executable = self.pending_tool_retry["name"]
        self._set_transcript_panel(
            "Relance outil",
            [
                f"{executable} attend confirmation.",
                "Reponds oui pour retenter la commande ou non pour annuler.",
            ],
            tone="warn",
        )
        return True

    def _handle_pending_admin_command(self, raw_text):
        if not self.pending_admin_command:
            return False

        prompt = raw_text.strip()
        if not prompt:
            return False

        if self._matches_install_decline(prompt):
            command = (self.pending_admin_command.get("arguments") or {}).get("command", "")
            self.pending_admin_command = None
            reply = f"Execution admin annulee pour {command or 'la commande en attente'}."
            self._remember_exchange(prompt, reply)
            self._set_transcript_panel("Commande admin", [reply], tone="warn")
            return True

        if self._matches_install_confirmation(prompt):
            self._run_pending_admin_command(prompt)
            return True

        command = (self.pending_admin_command.get("arguments") or {}).get("command", "")
        self._set_transcript_panel(
            "Commande admin",
            [
                f"{command or 'commande admin'} attend confirmation.",
                "Reponds oui pour lancer sudo interactif ou non pour annuler.",
            ],
            tone="warn",
        )
        return True

    def _matches_install_confirmation(self, prompt):
        if INSTALL_CONFIRM_RE.match(prompt):
            return True
        if not self.pending_tool_install:
            return False

        lowered = prompt.casefold()
        executables = self._pending_install_executables(self.pending_tool_install)
        install_terms = ("installe", "installer", "installation", "autorise", "autoriser")
        return (
            any(executable.casefold() in lowered for executable in executables)
            and any(term in lowered for term in install_terms)
        )

    def _matches_install_decline(self, prompt):
        return bool(INSTALL_DECLINE_RE.match(prompt))

    def _request_install_permission(self, executable, manual_command):
        if sys.stdin.isatty() and sys.stdout.isatty():
            return self._inline_confirm(
                f"Installer {executable} ? ({manual_command})"
            )
        return False

    def _request_interactive_sudo_permission(self, executable):
        if sys.stdin.isatty() and sys.stdout.isatty():
            return self._inline_confirm(
                f"Lancer sudo interactif pour {executable} ? (le mot de passe sera saisi dans ce terminal)"
            )
        return False

    def _inline_confirm(self, message):
        """Simple inline yes/no prompt without modal dialog."""
        try:
            reply = input(
                f"{self.palette.warn_ansi}{message}{AnsiStyle.RESET_ALL}"
                f" {self.palette.muted_ansi}[o/n]{AnsiStyle.RESET_ALL} "
            ).strip().lower()
            return reply in {"o", "oui", "y", "yes", "ok", "go"}
        except (EOFError, KeyboardInterrupt):
            return False

    def _retry_pending_tool(self, pending, *, interactive=False, skip_permission=False):
        pending = pending or {}
        tool_name = pending.get("name") or pending.get("tool_name")
        arguments = dict(pending.get("arguments") or {})
        command = (arguments.get("command") or "").strip()
        if not tool_name:
            return None

        result = None
        events = [
            {
                "type": "tool_start",
                "name": tool_name,
                "args": arguments,
            }
        ]

        try:
            if tool_name == "execute_command":
                reason = (
                    arguments.get("reason")
                    or "Relance automatique apres installation de l'outil requis."
                )
                result = self.tool_executor.execute_command(command, reason)
            elif tool_name == "execute_admin_command":
                reason = arguments.get("reason") or "Execution admin locale approuvee."
                result = self.tool_executor.execute_admin_command(
                    command,
                    reason,
                    interactive=interactive,
                    skip_permission=skip_permission,
                )
            else:
                result = self.tool_executor.dispatch(tool_name, arguments)
            events.append(
                {
                    "type": "tool_success",
                    "name": tool_name,
                    "result": result,
                }
            )
        except InteractiveAdminRequired as exc:
            events.append(
                {
                    "type": "tool_admin_required",
                    "name": tool_name,
                    "arguments": arguments,
                    "message": str(exc),
                    "command": exc.command,
                    "manual_command": exc.manual_command,
                }
            )
        except PermissionDenied as exc:
            events.append(
                {
                    "type": "tool_denied",
                    "name": tool_name,
                    "result": {"error": f"Permission refusee: {exc}"},
                }
            )
        except ToolPolicyError as exc:
            events.append(
                {
                    "type": "tool_policy_blocked",
                    "name": tool_name,
                    "error": str(exc),
                    "remediation": exc.remediation,
                    "policy_code": exc.code,
                    "result": {
                        "error": str(exc),
                        "remediation": exc.remediation,
                        "policy_code": exc.code,
                    },
                }
            )
        except (MissingTargetError, ToolMissingError, ToolExecutionError) as exc:
            events.append(
                {
                    "type": "tool_error",
                    "name": tool_name,
                    "error": str(exc),
                    "result": {"error": str(exc)},
                }
            )

        event_type = events[-1]["type"]
        return {
            "status": (
                "success"
                if event_type == "tool_success"
                else (
                    "denied"
                    if event_type == "tool_denied"
                    else "admin_required" if event_type == "tool_admin_required" else "error"
                )
            ),
            "result": result if event_type == "tool_success" else None,
            "rendered": self.renderer.render(events, model_label=self.gemini_runtime.model),
            "event": events[-1],
        }

    def _continue_agent_after_tool_result(self, pending, retry_outcome, user_prompt):
        if not retry_outcome or retry_outcome.get("status") != "success":
            return False

        try:
            self.agent_loop.active_case_label = self.active_case.label if self.active_case else ""
            events = self._collect_agent_stream(
                self.agent_loop.resume_after_external_tool(
                    pending.get("case_context") or self._build_case_context(),
                    result=retry_outcome["result"],
                    tool_name=pending.get("name"),
                    arguments=pending.get("arguments", {}),
                    thought=pending.get("thought", ""),
                )
            )
        except RuntimeError:
            return False

        rendered = self.renderer.render(events, model_label=self.gemini_runtime.model)
        answer_text = rendered["answer"] or "\n".join(rendered["lines"])
        self._remember_exchange(user_prompt, answer_text)
        full_text, log_path = self._full_output_from_events(events, rendered)
        self._set_transcript_panel(
            rendered["title"],
            rendered["lines"],
            tone=rendered["tone"],
            full_text=full_text,
            log_path=log_path,
            source="agent",
        )
        return True

    def _run_pending_tool_retry(self, user_prompt):
        pending = self.pending_tool_retry or {}
        self.pending_tool_retry = None

        retry_outcome = self._retry_pending_tool(pending)
        if self._continue_agent_after_tool_result(pending, retry_outcome, user_prompt):
            return

        retry_rendered = retry_outcome["rendered"] if retry_outcome else None
        if not retry_rendered:
            reply = "Aucune relance disponible."
            self._remember_exchange(user_prompt, reply)
            self._set_transcript_panel("Relance outil", [reply], tone="warn")
            return

        self._remember_exchange(
            user_prompt,
            retry_rendered["answer"] or "\n".join(retry_rendered["lines"]),
        )
        self._set_transcript_panel(
            "Relance outil",
            retry_rendered["lines"],
            tone=retry_rendered["tone"],
        )

    def _run_pending_tool_install(self, user_prompt):
        pending = self.pending_tool_install or {}
        self._attach_install_job(pending)
        executables = self._pending_install_executables(pending)
        label = self._install_label(executables)
        is_batch = len(executables) > 1
        self.pending_tool_install = None

        try:
            if is_batch:
                plan = self.tool_executor.build_install_batch_plan(executables)
            else:
                plan = self.tool_executor.build_install_plan(executables[0] if executables else "")
        except RuntimeError as exc:
            self._update_pending_job(pending, status="failed", result=str(exc))
            reply = str(exc)
            self._remember_exchange(user_prompt, reply)
            self._set_transcript_panel("Installation outil", [reply], tone="warn")
            return

        if not self._request_install_permission(label, plan["manual_command"]):
            self._update_pending_job(
                pending,
                status="cancelled",
                result="validation refusee",
            )
            reply = f"Installation de {label} annulee."
            self._remember_exchange(user_prompt, reply)
            self._set_transcript_panel("Installation outil", [reply], tone="warn")
            return
        self._update_pending_job(
            pending,
            status="running",
            result="validation acceptee",
        )

        if self.live_agent_stream and sys.stdout.isatty():
            self._set_transcript_panel(
                "Installation outil",
                [
                    f"installation outil(s): {label}",
                    f"commande: {plan['manual_command']}",
                ],
                tone="info",
            )
            self._render_live_panel_update()

        try:
            if is_batch:
                result = self.tool_executor.install_tools(executables)
            else:
                result = self.tool_executor.install_tool(executables[0])
        except RuntimeError as exc:
            self._update_pending_job(pending, status="failed", result=str(exc))
            reply = f"L'installation de {label} a echoue: {exc}"
            self._remember_exchange(user_prompt, reply)
            self._set_transcript_panel("Installation outil", [reply], tone="error")
            return

        interactive_retry = None
        if result["status"] == "manual_required":
            if self._request_interactive_sudo_permission(label):
                print()
                print(f"• Validation sudo pour {label}, puis installation silencieuse...")
                try:
                    if is_batch:
                        result = self.tool_executor.install_tools(executables, interactive=True)
                    else:
                        result = self.tool_executor.install_tool(executables[0], interactive=True)
                except RuntimeError as exc:
                    self._update_pending_job(pending, status="failed", result=str(exc))
                    reply = f"L'installation interactive de {label} a echoue: {exc}"
                    self._remember_exchange(user_prompt, reply)
                    self._set_transcript_panel("Installation outil", [reply], tone="error")
                    return
                interactive_retry = True
            else:
                interactive_retry = False

        result_executables = result.get("executables") or [result.get("executable", label)]
        lines = [f"installation outil(s): {', '.join(result_executables)}"]
        if pending.get("installed"):
            lines.append(f"deja installe(s): {', '.join(pending['installed'])}")
        for step in result["steps"]:
            lines.append(f"commande: {step['command']}")
            if step["returncode"] == 0:
                lines.append("etat: ok")
                continue
            lines.append(f"etat: echec (code {step['returncode']})")
            lines.extend(self._split_text_excerpt(step.get("stderr", "")))

        if result["status"] in {"installed", "partial"}:
            installed = result.get("installed") or result_executables
            if installed:
                lines.append(f"disponible(s): {', '.join(installed)}")
            if result.get("missing"):
                lines.append(f"encore absent(s): {', '.join(result['missing'])}")
            job_status = "success" if result["status"] == "installed" else "failed"
            job_result = (
                f"disponible(s): {', '.join(installed)}"
                if installed
                else result["status"]
            )
            if result.get("missing"):
                job_result += f"; absent(s): {', '.join(result['missing'])}"
            self._update_pending_job(pending, status=job_status, result=job_result)
            if interactive_retry:
                lines.append("sudo interactif termine.")
            retry_outcome = self._retry_pending_tool(pending)
            if self._continue_agent_after_tool_result(pending, retry_outcome, user_prompt):
                return
            retry_rendered = retry_outcome["rendered"] if retry_outcome else None
            if retry_rendered:
                lines.append("relance automatique:")
                lines.extend(retry_rendered["lines"][:12])
                if retry_rendered["tone"] in {"warn", "error"}:
                    tone = retry_rendered["tone"]
                else:
                    tone = "success"
            else:
                tone = "success"
        elif result["status"] == "manual_required":
            lines.append(
                "SECOPS ne peut pas saisir le mot de passe admin du prompt sudo."
            )
            lines.append(f"commande manuelle: {result['manual_command']}")
            self._update_pending_job(
                pending,
                status="waiting",
                result="sudo interactif requis",
                append_detail=f"commande manuelle: {result['manual_command']}",
            )
            retry_command = (pending.get("arguments") or {}).get("command", "")
            if retry_command:
                lines.append(f"puis relance: {retry_command}")
            tone = "warn"
        else:
            lines.append(f"L'installation automatique de {label} a echoue.")
            lines.append(f"commande manuelle: {result['manual_command']}")
            self._update_pending_job(
                pending,
                status="failed",
                result=f"status: {result['status']}",
                append_detail=f"commande manuelle: {result['manual_command']}",
            )
            tone = "error"

        visible_lines = lines[:20]
        self._remember_exchange(user_prompt, "\n".join(visible_lines))
        self._set_transcript_panel("Installation outil", visible_lines, tone=tone)

    def _run_pending_admin_command(self, user_prompt):
        pending = self.pending_admin_command or {}
        command = (pending.get("arguments") or {}).get("command", "")
        self.pending_admin_command = None

        if not self._request_interactive_sudo_permission(command or "commande admin"):
            reply = f"Execution admin annulee pour {command or 'la commande en attente'}."
            self._remember_exchange(user_prompt, reply)
            self._set_transcript_panel("Commande admin", [reply], tone="warn")
            return

        if self.live_agent_stream and sys.stdout.isatty():
            self._set_transcript_panel(
                "Commande admin",
                [
                    f"commande admin: {command}",
                    "sudo interactif en cours...",
                ],
                tone="info",
            )
            self._render_live_panel_update()

        retry_outcome = self._retry_pending_tool(
            pending,
            interactive=True,
            skip_permission=True,
        )
        if self._continue_agent_after_tool_result(pending, retry_outcome, user_prompt):
            return

        retry_rendered = retry_outcome["rendered"] if retry_outcome else None
        if not retry_rendered:
            reply = "Aucune execution admin disponible."
            self._remember_exchange(user_prompt, reply)
            self._set_transcript_panel("Commande admin", [reply], tone="warn")
            return

        self._remember_exchange(
            user_prompt,
            retry_rendered["answer"] or "\n".join(retry_rendered["lines"]),
        )
        self._set_transcript_panel(
            "Commande admin",
            retry_rendered["lines"],
            tone=retry_rendered["tone"],
        )

    def _collect_agent_stream(self, event_stream):
        spinner = None
        events = []
        stream_progress = self.live_agent_stream and sys.stdout.isatty()
        self._live_stream_state = {
            "events": events,
            "stream_progress": stream_progress,
            "last_snapshot": None,
        }

        try:
            while True:
                event = next(event_stream)
                event_type = event["type"]

                if event_type == "thinking_start":
                    spinner = ActivitySpinner("SECOPS reflechit...")
                    spinner.start()
                    continue

                if event_type == "thinking_end":
                    if spinner:
                        spinner.stop()
                        spinner = None
                    continue

                if event_type == "thought":
                    if self.reasoning_mode == "full":
                        self._append_live_stream_event(event)
                    continue

                if event_type == "tool_start" and self.reasoning_mode == "summary":
                    self._append_reasoning_summary_for_tool(event)

                self._append_live_stream_event(event)
        except StopIteration:
            pass
        finally:
            if spinner:
                spinner.stop()
            self._live_stream_state = None

        return events

    def _collect_agent_events(self, prompt):
        case_context = self._build_agent_context(prompt)
        return self._collect_agent_stream(
            self.agent_loop.run(prompt, case_context)
        )

    def _call_gemini(self, prompt):
        try:
            profile = self._apply_model_profile()
            client = GeminiClient(model=self.gemini_runtime.model)
            result = client.generate_text(
                prompt,
                temperature=profile.temperature,
                max_output_tokens=profile.max_output_tokens,
                thinking_level=profile.thinking_level,
            )
            self.last_gemini_error = None
            return result
        except GeminiConfigurationError as exc:
            self.last_gemini_error = str(exc)
            return None
        except GeminiDependencyError as exc:
            self.last_gemini_error = str(exc)
            return None
        except GeminiClientError as exc:
            self.last_gemini_error = str(exc)
            return None

    def _call_gemini_text(self, prompt):
        result = self._call_gemini(prompt)
        if not result:
            raise RuntimeError(self.last_gemini_error or "Gemini indisponible.")
        return result.text

    def _call_gemini_tool_decision(self, prompt, system_prompt, tool_specs):
        try:
            profile = self._apply_model_profile()
            client = GeminiClient(model=self.gemini_runtime.model)
            result = client.generate_tool_decision(
                prompt,
                system_prompt=system_prompt,
                tool_specs=tool_specs,
                temperature=profile.temperature,
                max_output_tokens=profile.max_output_tokens,
                thinking_level=profile.thinking_level,
            )
            self.last_gemini_error = None
            return result
        except GeminiConfigurationError as exc:
            self.last_gemini_error = str(exc)
            raise RuntimeError(str(exc)) from exc
        except GeminiDependencyError as exc:
            self.last_gemini_error = str(exc)
            raise RuntimeError(str(exc)) from exc
        except GeminiClientError as exc:
            self.last_gemini_error = str(exc)
            raise RuntimeError(str(exc)) from exc

    def _request_tool_permission(self, *, tool_name, details, reason=""):
        selection = self._choose_permission_option(
            "Permission requise",
            [
                ("outil", tool_name),
                ("details", details),
                ("raison", reason),
            ],
            options=[
                ("once", "Autoriser une fois"),
                ("session", "Autoriser pour la session"),
                ("deny", "Refuser"),
            ],
            default="once",
        )
        if selection is None:
            return False
        if selection == "session":
            self.command_permission_mode = "session"
            self.tool_executor.command_permission_mode = "session"
            self.save_state()
            return "session"
        return selection == "once"

    def _reply_from_memory(self, raw_prompt, failure_reason=None):
        prompt = raw_prompt.strip()
        if not prompt:
            self._set_transcript_panel(
                "Agent local",
                ["Pose une question ou decris ton objectif."],
                tone="warn",
            )
            return

        detected_target = self._capture_target_from_text(prompt)
        use_memory = self._should_use_knowledge_memory(prompt)
        suggestions = self.knowledge_store.suggest(prompt, limit=2) if use_memory else []
        show_target_context = use_memory or self._should_capture_target_context(prompt)

        lines = []
        if failure_reason:
            lines.append(f"[!] {self._summarize_gemini_failure(failure_reason)}")
            lines.append("Mode local: reponse basee sur la memoire disponible.")
        if detected_target and show_target_context:
            lines.append(f"• Cible détectée: {detected_target}")
        elif self.current_target and show_target_context:
            lines.append(f"• Cible active: {self.current_target}")

        if suggestions:
            top = suggestions[0]
            lines.append(f"• Cas analogue: {top.case.slug} ({top.case.platform})")
            if top.case.summary:
                lines.append(f"• Lecture: {top.case.summary}")
            hypotheses = top.matched_hypotheses or top.case.hypotheses
            actions = top.matched_actions or top.case.actions
            pivots = top.matched_pivots or top.case.pivots
            if hypotheses:
                lines.append(f"• Hypothèse: {hypotheses[0]}")
            if actions:
                lines.append(f"• Prochaine piste: {actions[0]}")
            if pivots:
                lines.append(f"• Pivot: {pivots[0]}")
            visible_lines = lines[:20]
            self._set_transcript_panel(
                "Agent local",
                visible_lines,
                tone="warn" if failure_reason else "success",
            )
            self._remember_exchange(prompt, "\n".join(visible_lines))
            return

        lines.extend(
            [
                "Je peux aider sur des questions SECOPS, des labs, ou des actions locales selon les outils disponibles.",
                (
                    "Decris un objectif, une cible, un service, un symptome, ou une action systeme locale."
                    if not self.active_case
                    else "Si tu veux exploiter la memoire de lab, mentionne la cible, le service ou le cas concerne."
                ),
            ]
        )
        visible_lines = lines[:20]
        self._set_transcript_panel(
            "Agent local",
            visible_lines,
            tone="warn" if failure_reason else "info",
        )
        self._remember_exchange(prompt, "\n".join(visible_lines))

    def _ask_agent(self, raw_prompt):
        prompt = raw_prompt.strip()
        if not prompt:
            self._set_transcript_panel(
                "Agent",
                ["Pose une question ou decris ton objectif."],
                tone="warn",
            )
            return
        if not prompt:
            return

        detected_target = self._capture_target_from_text(prompt)
        if detected_target and self._is_target_declaration_only(prompt):
            self._reply_target_registered(prompt, detected_target)
            return
        self._route_model_if_auto(prompt)
        agent_prompt = self._expand_prompt_references(prompt)
        case_context = self._build_agent_context(prompt)
        self.agent_loop.active_case_label = self.active_case.label if self.active_case else ""
        try:
            events = self._collect_agent_stream(
                self.agent_loop.run(agent_prompt, case_context)
            )
        except KeyboardInterrupt:
            self._set_transcript_panel("Agent", ["Operation annulee."], tone="warn")
            return
        except RuntimeError:
            self._reply_from_memory(prompt, failure_reason=self.last_gemini_error)
            return

        missing_tool_event = None
        admin_command_event = None
        denied_tool_event = None
        for event in reversed(events):
            if event["type"] == "tool_missing":
                missing_tool_event = event
                break
            if event["type"] == "tool_admin_required":
                admin_command_event = event
                break
            if event["type"] == "tool_denied" and denied_tool_event is None:
                denied_tool_event = event
        if missing_tool_event:
            missing_tool_event = dict(missing_tool_event)
            missing_tool_event["case_context"] = case_context
            self._attach_install_job(missing_tool_event)
        if admin_command_event:
            admin_command_event = dict(admin_command_event)
            admin_command_event["case_context"] = case_context
        if denied_tool_event:
            denied_tool_event = dict(denied_tool_event)
            denied_tool_event["case_context"] = case_context

        self.pending_tool_install = missing_tool_event
        self.pending_admin_command = admin_command_event if not missing_tool_event else None
        self.pending_tool_retry = (
            denied_tool_event if not missing_tool_event and not admin_command_event else None
        )

        rendered = self.renderer.render(events, model_label=self.gemini_runtime.model)
        answer_text = rendered["answer"] or "\n".join(rendered["lines"])
        self._remember_exchange(prompt, answer_text)
        full_text, log_path = self._full_output_from_events(events, rendered)
        self._set_transcript_panel(
            rendered["title"],
            rendered["lines"],
            tone=rendered["tone"],
            full_text=full_text,
            log_path=log_path,
            source="agent",
        )

    def _phase_status_lines(self):
        meta = PHASE_METADATA.get(self.engagement.phase, {})
        return [
            f"Phase: {self.engagement.phase_label}",
            f"Objectif: {meta.get('objective', '')}",
            f"Outils typiques: {', '.join(meta.get('typical_tools', ()))}",
            f"Passer quand: {meta.get('advance_when', '')}",
        ]

    def _change_phase(self, phase, *, confirmed=False, previous_panel=None):
        guard_message = self.engagement.phase_guard_message(
            phase,
            has_scope=bool(self.tool_executor.authorized_scope),
            confirmed=confirmed,
        )
        if guard_message:
            lines = [guard_message, "Exemple: /phase exploit confirm"]
            if self._can_use_transient_page():
                self._run_transient_notice_page(
                    "Phase",
                    lines,
                    tone="warn",
                    previous_panel=previous_panel,
                )
                return
            self.set_panel("Phase", lines, tone="warn")
            return

        checkpoint_path = None
        if phase != self.engagement.phase and EngagementState.is_guarded_phase(phase):
            checkpoint_path = self._save_checkpoint(
                f"avant transition vers {PHASE_METADATA[phase]['label']}",
                trigger=f"phase:{phase.value}",
            )

        self.engagement.set_phase(phase, "Changement manuel via /phase.")
        if self._can_use_transient_page():
            self._restore_inline_panel(previous_panel or self.panel)
            return
        lines = [f"Phase changee: {self.engagement.phase_label}"]
        if checkpoint_path:
            lines.append(f"Checkpoint: {checkpoint_path}")
        self.set_panel("Phase", lines, tone="success")

    def _run_phase_menu_page(self):
        previous_panel = self.panel
        options = []
        for phase, meta in PHASE_METADATA.items():
            options.append(
                (
                    phase.value,
                    self._inline_option_text(
                        meta.get("label", phase.value),
                        meta.get("objective", ""),
                        current=phase == self.engagement.phase,
                    ),
                )
            )
        selected = self._run_transient_choice_page(
            "Phase pentest",
            [
                f"Phase actuelle: {self.engagement.phase_label}",
                "Choisis la phase operationnelle de la session.",
            ],
            options,
            default=self.engagement.phase.value,
        )
        if selected in (None, "cancel"):
            self._restore_inline_panel(previous_panel)
            return
        phase = parse_phase(selected)
        if not phase:
            self._restore_inline_panel(previous_panel)
            return
        self._change_phase(phase, confirmed=True, previous_panel=previous_panel)

    def _handle_phase(self, args):
        previous_panel = self.panel
        if not args:
            if self._can_use_transient_page():
                self._run_phase_menu_page()
                return
            self.set_panel("Phase pentest", self._phase_status_lines(), tone="info")
            return

        confirm = False
        normalized_args = []
        for arg in args:
            lowered = arg.strip().lower()
            if lowered in {"confirm", "confirmer"}:
                confirm = True
                continue
            normalized_args.append(arg)
        phase = parse_phase(" ".join(normalized_args))
        if not phase:
            lines = ["Phase inconnue. Valides: recon, enum, exploit, post, rapport."]
            if self._can_use_transient_page():
                self._run_transient_notice_page(
                    "Phase",
                    lines,
                    tone="warn",
                    previous_panel=previous_panel,
                )
                return
            self.set_panel("Phase", lines, tone="warn")
            return
        self._change_phase(phase, confirmed=confirm, previous_panel=previous_panel)

    def _scope_status_lines(self):
        scope = self.tool_executor.authorized_scope
        if scope:
            lines = [f"Scope autorise ({len(scope)} entree(s)):"]
            lines.extend(f"  {entry}" for entry in sorted(scope))
            return lines
        return ["Aucun scope defini. Toutes les cibles sont autorisees."]

    def _apply_scope_entries(self, entries, *, previous_panel=None):
        entries = [entry.strip() for entry in entries if entry.strip()]
        self.tool_executor.set_scope(entries)
        self.audit_logger.log_scope_change(entries)
        if not entries:
            lines = ["Scope desactive. Toutes les cibles sont autorisees."]
            tone = "warn"
        else:
            lines = [f"Scope defini ({len(entries)} entree(s)):"]
            lines.extend(f"  {entry}" for entry in entries)
            lines.append("Les commandes ciblant des IPs, domaines ou URLs hors scope seront bloquees.")
            tone = "success"
        if self._can_use_transient_page():
            self._restore_inline_panel(previous_panel or self.panel)
            return
        self.set_panel("Scope", lines, tone=tone)

    def _run_scope_menu_page(self):
        previous_panel = self.panel
        target_label = self.active_target.label if self.active_target else self.current_target
        options = []
        if target_label:
            options.append(("target", f"Utiliser la cible active: {target_label}"))
        options.append(("manual", "Saisir une ou plusieurs entrees"))
        if self.tool_executor.authorized_scope:
            options.append(("clear", "Desactiver le scope"))
        selected = self._run_transient_choice_page(
            "Scope autorise",
            self._scope_status_lines(),
            options,
            default="target" if target_label else "manual",
        )
        if selected in (None, "cancel"):
            self._restore_inline_panel(previous_panel)
            return
        if selected == "target" and target_label:
            self._apply_scope_entries([target_label], previous_panel=previous_panel)
            return
        if selected == "clear":
            self._apply_scope_entries([], previous_panel=previous_panel)
            return
        if selected == "manual":
            try:
                raw_entries = input("Scope autorise (separe par espaces ou virgules): ")
            except (EOFError, KeyboardInterrupt):
                raw_entries = ""
            entries = [item for item in re.split(r"[\s,]+", raw_entries.strip()) if item]
            if entries:
                self._apply_scope_entries(entries, previous_panel=previous_panel)
            else:
                self._restore_inline_panel(previous_panel)

    def _handle_permissions(self, args):
        previous_panel = self.panel
        if not args:
            if self._can_use_transient_page():
                self._run_permissions_menu_page()
                return
            lines = self._permissions_status_lines()
            self.set_panel("Permissions", lines, tone="info")
            return

        mode = args[0]
        if not self._set_command_permission_mode(mode):
            lines = ["Mode inconnu. Valides: read-only, ask, auto-low-risk, session, deny."]
            if self._can_use_transient_page():
                self._run_transient_notice_page(
                    "Permissions",
                    lines,
                    tone="warn",
                    previous_panel=previous_panel,
                )
                return
            self.set_panel("Permissions", lines, tone="warn")
            return
        lines = [
            f"Mode commandes: {self._command_mode_label()}",
            "read-only=observation locale, ask=validation, auto-low-risk=auto local, session=autorisation globale, deny=execution bloquee.",
        ]
        if self._can_use_transient_page():
            self._restore_inline_panel(previous_panel)
            return
        self.set_panel("Permissions", lines, tone="success")

    def _permissions_status_lines(self):
        allowed = sorted(getattr(self.tool_executor, "_session_allow_commands", set()))
        lines = [
            f"Mode commandes: {self._command_mode_label()}",
            "read-only: seules les commandes locales d'observation sont autorisees",
            "ask: validation interactive avant execution",
            "auto-low-risk: commandes locales faibles risques sans validation, validation pour le reste",
            "session: executions autorisees pour la session",
            "deny: aucune commande outil n'est executee",
        ]
        if allowed:
            lines.append(f"Executables autorises: {', '.join(allowed)}")
        return lines

    def _permissions_picker_default(self):
        if self.command_permission_mode in {mode for mode, _label, _description in CODEX_PERMISSION_CHOICES}:
            return self.command_permission_mode
        return "ask"

    def _permissions_picker_options(self):
        options = []
        for mode, label, description in CODEX_PERMISSION_CHOICES:
            options.append(
                (
                    mode,
                    self._inline_option_text(
                        label,
                        description,
                        current=self.command_permission_mode == mode,
                    ),
                )
            )
        return options

    def _run_permissions_inline_choice(self):
        return self._run_inline_choice(
            "Update Model Permissions",
            [],
            self._permissions_picker_options(),
            default=self._permissions_picker_default(),
            select_character="›",
        )

    def _run_permissions_menu_page(self):
        try:
            selected = self._run_permissions_inline_choice()
        except (EOFError, KeyboardInterrupt):
            selected = "cancel"
        if selected not in (None, "cancel"):
            self._set_command_permission_mode(selected)

    def _handle_compact(self, args):
        previous_panel = self.panel
        messages = list(getattr(self.agent_loop, "messages", []) or [])
        old_count = len(messages)
        old_chars = sum(len(str(message.get("content", ""))) for message in messages)
        if not messages:
            lines = ["Aucun contexte agent a compacter."]
            if self._can_use_transient_page():
                self._run_transient_notice_page(
                    "Compactage",
                    lines,
                    tone="muted",
                    previous_panel=previous_panel,
                )
                return
            self.set_panel("Compactage", lines, tone="muted")
            return

        keep = 4
        if args:
            try:
                keep = max(0, min(10, int(args[0])))
            except ValueError:
                keep = 4
        summary = self.agent_loop._build_conversation_summary(messages)
        compact_messages = []
        if summary:
            compact_messages.append(
                {
                    "role": "system",
                    "content": f"RESUME DES ECHANGES PRECEDENTS:\n{summary}",
                }
            )
        if keep:
            compact_messages.extend(messages[-keep:])
        self.agent_loop.messages = compact_messages
        if len(self.conversation_history) > 3:
            self.conversation_history = self.conversation_history[-3:]
        new_chars = sum(len(str(message.get("content", ""))) for message in compact_messages)
        lines = [
            f"Messages agent: {old_count} -> {len(compact_messages)}",
            f"Contexte approx.: {old_chars} -> {new_chars} caracteres",
            "La memoire operationnelle, les findings et les jobs sont conserves.",
        ]
        if self._can_use_transient_page():
            self._return_to_main_page(previous_panel)
            return
        self.set_panel("Compactage", lines, tone="success")

    def _side_context(self):
        target = self.active_target.label if self.active_target else (self.current_target or "aucune")
        lines = [
            f"Phase: {self.engagement.phase_label}",
            f"Cible: {target}",
            f"Scope: {self._scope_summary_label()}",
            f"Findings: {self.findings_store.count}",
        ]
        summary = self.findings_store.summary()
        if summary:
            lines.append("Synthese findings:")
            lines.extend(summary.splitlines()[:8])
        if self.active_case:
            lines.append(f"Cas actif: {self.active_case.slug} - {self.active_case.summary}")
        return "\n".join(lines)

    _PROMPT_REFERENCE_RE = re.compile(r"(?<!\w)@([A-Za-z0-9_./:-]+)")

    def _expand_prompt_references(self, prompt):
        text = str(prompt or "")
        matches = []
        seen = set()
        for match in self._PROMPT_REFERENCE_RE.finditer(text):
            token = match.group(1).strip()
            if not token or token in seen:
                continue
            seen.add(token)
            matches.append(token)
            if len(matches) >= 5:
                break

        blocks = []
        for token in matches:
            resolved = self._resolve_prompt_reference(token)
            if resolved:
                blocks.append(resolved)

        if not blocks:
            return text

        return "\n\n".join(
            [
                text,
                "REFERENCES UTILISATEUR:",
                "\n\n".join(blocks),
            ]
        )

    def _reference_block(self, label, content, *, limit=3000):
        content = str(content or "").strip()
        if len(content) > limit:
            content = content[:limit].rstrip() + "\n...[reference tronquee]"
        return f"[{label}]\n{content}" if content else ""

    def _resolve_prompt_reference(self, token):
        lowered = token.casefold()
        if lowered == "target":
            target = self.active_target.summary if self.active_target else (self.current_target or "")
            return self._reference_block("@target", target or "Aucune cible active.")
        if lowered == "scope":
            return self._reference_block("@scope", self._scope_summary_label())
        if lowered in {"findings", "finding"}:
            summary = self.findings_store.structured_summary() or self.findings_store.summary()
            return self._reference_block("@findings", summary or "Aucune decouverte accumulee.")
        if lowered.startswith("finding:"):
            return self._resolve_finding_reference(token.split(":", 1)[1])
        if lowered == "case":
            if not self.active_case:
                return self._reference_block("@case", "Aucun cas memoire actif.")
            return self._reference_block("@case", self._format_case_reference(self.active_case))
        if lowered.startswith("case:"):
            slug = token.split(":", 1)[1].strip()
            case = self.knowledge_store.get_case(slug)
            if not case:
                return self._reference_block(f"@case:{slug}", "Cas introuvable.")
            return self._reference_block(f"@case:{slug}", self._format_case_reference(case))
        if lowered == "jobs":
            lines = []
            for job in self.jobs.recent(limit=8):
                lines.append(job.display_line())
                if job.result:
                    lines.append(f"  resultat: {job.result}")
            return self._reference_block("@jobs", "\n".join(lines) or "Aucun job recent.")
        if lowered.startswith("job:"):
            return self._resolve_job_reference(token.split(":", 1)[1])
        if lowered == "log:last":
            path = getattr(self.tool_executor, "_last_command_log_path", "") or ""
            return self._read_reference_file(path, label="@log:last") if path else self._reference_block("@log:last", "Aucun log de commande recent.")
        if lowered.startswith("log:"):
            return self._resolve_log_reference(token.split(":", 1)[1])
        if lowered.startswith("workspace/"):
            return self._read_reference_file(token.split("/", 1)[1], label=f"@{token}")
        if lowered.startswith("file:"):
            return self._read_reference_file(token.split(":", 1)[1], label=f"@{token}")
        if "/" in token or "." in token:
            return self._read_reference_file(token, label=f"@{token}")
        return ""

    def _format_case_reference(self, case):
        lines = [f"{case.title} ({case.platform})"]
        if case.summary:
            lines.append(f"resume: {case.summary}")
        if case.signals:
            lines.append("signaux: " + "; ".join(case.signals[:4]))
        if case.hypotheses:
            lines.append("hypotheses: " + "; ".join(case.hypotheses[:3]))
        if case.actions:
            lines.append("actions: " + "; ".join(case.actions[:3]))
        return "\n".join(lines)

    def _resolve_finding_reference(self, raw_index):
        try:
            index = int(str(raw_index).strip()) - 1
        except ValueError:
            return self._reference_block(f"@finding:{raw_index}", "Indice invalide.")
        findings = self.findings_store.all
        if index < 0 or index >= len(findings):
            return self._reference_block(f"@finding:{raw_index}", "Finding introuvable.")
        finding = findings[index]
        lines = [
            f"type: {finding.finding_type.value}",
            f"valeur: {finding.value}",
            f"source: {finding.source_tool}",
            f"confidence: {finding.confidence}",
        ]
        if finding.severity:
            lines.append(f"severity: {finding.severity}")
        if finding.target_ref:
            lines.append(f"cible: {finding.target_ref}")
        if finding.attributes:
            lines.append("attributs: " + json.dumps(finding.attributes, ensure_ascii=False))
        if finding.raw_output:
            lines.append("sortie: " + finding.raw_output[:1000])
        return self._reference_block(f"@finding:{raw_index}", "\n".join(lines))

    def _resolve_job_reference(self, raw_job_id):
        try:
            job_id = int(str(raw_job_id).strip().lstrip("#"))
        except ValueError:
            return self._reference_block(f"@job:{raw_job_id}", "ID de job invalide.")
        job = self.jobs.get(job_id)
        if not job:
            return self._reference_block(f"@job:{raw_job_id}", "Job introuvable.")
        lines = [job.display_line()]
        lines.extend(f"detail: {detail}" for detail in job.details)
        if job.result:
            lines.append(f"resultat: {job.result}")
        return self._reference_block(f"@job:{job_id}", "\n".join(lines))

    def _resolve_log_reference(self, raw_value):
        value = str(raw_value).strip().lstrip("#")
        if value.isdigit():
            job = self.jobs.get(int(value))
            if job:
                text = "\n".join([job.result, *job.details])
                match = re.search(r"log:\s*([^;\s]+)", text)
                if match:
                    return self._read_reference_file(match.group(1), label=f"@log:{value}")
        return self._read_reference_file(value, label=f"@log:{value}")

    def _read_reference_file(self, path, *, label):
        path = str(path or "").strip()
        if not path:
            return self._reference_block(label, "Chemin vide.")
        blocked_parts = {".env", ".git", ".venv", "__pycache__"}
        if any(part in blocked_parts for part in Path(path).parts):
            return self._reference_block(label, "Reference refusee: chemin sensible ou interne.")
        try:
            result = self.tool_executor.read_file(path)
        except (OSError, ToolExecutionError) as exc:
            return self._reference_block(label, f"Lecture impossible: {exc}")
        content = result.get("content", "")
        return self._reference_block(label, content, limit=4000)

    def _run_dismissible_overlay(self, title, lines, *, tone="info", previous_panel=None):
        previous = previous_panel if previous_panel is not None else self.panel
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            self.set_panel(title, lines, tone=tone)
            return

        self._clear_transient_screen()
        self.render_shell_header()
        current_panel = self.panel
        self.set_panel(title, lines, tone=tone)
        self.render_panel_state()
        self.panel = current_panel

        bindings = KeyBindings()

        @bindings.add("space")
        @bindings.add("enter")
        @bindings.add("escape")
        @bindings.add("c-c", eager=True)
        def _dismiss(event):
            event.app.exit(result=True)

        Application(
            layout=Layout(
                Window(
                    FormattedTextControl("Espace/Entrée/Esc pour revenir"),
                    height=Dimension(min=1, max=1),
                )
            ),
            key_bindings=bindings,
            full_screen=False,
            mouse_support=False,
            style=self.prompt_style,
        ).run()
        self._return_to_main_page(previous)

    def _handle_side(self, args, *, dismissible=False):
        prompt = " ".join(args).strip()
        if not prompt:
            self.set_panel(
                "Question laterale",
                ["Usage: /side <question> ou /btw <question>", "La question n'est pas ajoutee au contexte agent."],
                tone="warn",
            )
            return

        expanded_prompt = self._expand_prompt_references(prompt)
        side_prompt = "\n".join(
            [
                "Tu es SECOPS en mode question laterale.",
                "Reponds directement et brievement.",
                "Ne choisis pas d'outil, ne planifie pas d'execution, ne modifie pas la session.",
                "Cette reponse ne sera pas injectee dans la memoire conversationnelle de l'agent.",
                "",
                "CONTEXTE LOCAL:",
                self._side_context(),
                "",
                f"QUESTION: {expanded_prompt}",
            ]
        )
        try:
            answer = self._call_gemini_text(side_prompt)
        except RuntimeError:
            lines = [
                f"[!] {self._summarize_gemini_failure(self.last_gemini_error)}",
                "Question laterale non ajoutee au contexte agent.",
                "Contexte disponible:",
            ]
            lines.extend(self._side_context().splitlines()[:12])
            if dismissible:
                self._run_dismissible_overlay("Question laterale", lines, tone="warn")
            else:
                self._set_transcript_panel("Question laterale", lines, tone="warn")
            return
        lines = answer.splitlines() or [answer]
        if dismissible:
            self._run_dismissible_overlay("Question laterale", lines, tone="info")
            return
        self._set_transcript_panel("Question laterale", lines, tone="info")

    def _format_menu_entry(self, entry):
        return f"{entry['shortcut']:<2} {entry['command']:<13} {entry['description']}"

    def _command_menu_entries(self):
        entries = []
        seen = set()
        for entry in COMMAND_MENU_ENTRIES:
            command = entry["command"]
            entries.append(entry)
            seen.add(command)
        for command, description in COMMAND_SPECS.items():
            if command in seen:
                continue
            entries.append(
                {
                    "command": command,
                    "shortcut": "",
                    "description": description,
                }
            )
        return entries

    @staticmethod
    def _is_fuzzy_subsequence(needle, haystack):
        iterator = iter(haystack)
        return all(character in iterator for character in needle)

    def _menu_match_score(self, query, entry):
        query = str(query or "").strip().casefold()
        if not query:
            return 0
        searchable = " ".join(
            [
                entry["command"].casefold(),
                entry["shortcut"].casefold(),
                entry["description"].casefold(),
            ]
        )
        score = 0
        for term in query.split():
            if term == entry["shortcut"].casefold():
                score += 120
            elif entry["command"].casefold().startswith(term):
                score += 100
            elif term in entry["command"].casefold():
                score += 80
            elif term in entry["description"].casefold():
                score += 60
            elif self._is_fuzzy_subsequence(term, searchable):
                score += 25
            else:
                return -1
        return score

    def _menu_matches(self, query, *, limit=None):
        entries = self._command_menu_entries()
        if str(query or "").strip():
            scored = [
                (self._menu_match_score(query, entry), index, entry)
                for index, entry in enumerate(entries)
            ]
            entries = [
                entry for score, _index, entry in sorted(scored, key=lambda item: (-item[0], item[1]))
                if score >= 0
            ]
        if limit is not None:
            return entries[:limit]
        return entries

    def _menu_entry_from_query(self, query):
        query = str(query or "").strip()
        if not query:
            return None
        lowered = query.casefold()
        for entry in self._command_menu_entries():
            if lowered in {entry["command"].casefold(), entry["shortcut"].casefold()}:
                return entry
        matches = self._menu_matches(query, limit=1)
        return matches[0] if matches else None

    def _menu_overlay_options(self):
        entries = self._command_menu_entries()
        command_width = max(
            18,
            min(28, max(len(entry["command"]) for entry in entries) + 4),
        )
        return [
            (
                entry["command"],
                f"{entry['command']:<{command_width}}{entry['description']}",
            )
            for entry in entries
        ]

    def _run_menu_overlay(self):
        radio_list = ClaudeStyleRadioList(
            values=self._menu_overlay_options(),
            default="/model",
            select_on_focus=True,
            open_character="",
            select_character="›",
            close_character="",
            show_cursor=False,
            show_numbers=False,
            container_style="class:input-selection",
            default_style="class:option",
            selected_style=self._inline_selected_style(),
            checked_style="",
            number_style="class:number",
            show_scrollbar=False,
            detail_style=None,
        )

        bindings = KeyBindings()

        @bindings.add("escape")
        @bindings.add("c-c", eager=True)
        def _cancel(event):
            event.app.exit(result=None, style="class:aborting")

        @bindings.add("enter", eager=True)
        def _accept(event):
            event.app.exit(result=radio_list.current_value, style="class:accepted")

        @bindings.add("k")
        @bindings.add("c-p")
        def _previous(event):
            event.key_processor.feed(KeyPress(Keys.Up), first=True)

        @bindings.add("j")
        @bindings.add("c-n")
        def _next(event):
            event.key_processor.feed(KeyPress(Keys.Down), first=True)

        container = HSplit(
            [
                Box(
                    Label(text="Select command\n", dont_extend_height=True),
                    padding_top=0,
                    padding_left=1,
                    padding_right=1,
                    padding_bottom=0,
                ),
                Box(
                    radio_list,
                    padding_top=0,
                    padding_left=0,
                    padding_right=1,
                    padding_bottom=0,
                    style="class:input-selection",
                ),
            ]
        )
        return Application(
            layout=Layout(container, focused_element=radio_list),
            key_bindings=bindings,
            full_screen=False,
            erase_when_done=True,
            mouse_support=False,
            style=self.prompt_style,
        ).run()

    def _run_command_palette(self):
        previous_panel = self.panel
        if not self._can_use_transient_page():
            lines = [
                "Recherche fuzzy disponible en terminal interactif.",
                "Raccourcis: tape la lettre, la commande ou un mot-cle.",
                "",
            ]
            lines.extend(self._format_menu_entry(entry) for entry in self._command_menu_entries())
            self.set_panel("Palette", lines, tone="info")
            return True

        selected = self._run_menu_overlay()
        if selected is None:
            self._restore_inline_panel(previous_panel)
            return True
        if selected in TRANSIENT_COMMANDS:
            return self.dispatch_command(selected, [])

        keep_running = self.dispatch_command(selected, [])
        if not keep_running:
            return False
        self._run_transient_notice_page(
            self.panel.title or selected,
            list(self.panel.lines),
            tone=self.panel.tone,
            previous_panel=previous_panel,
        )
        return True

    def _tools_tabs(self):
        return ("overview", "installed", "missing", "recon", "enumeration", "exploitation", "utility")

    def _tools_tab_label(self, tab):
        labels = {
            "overview": "overview",
            "installed": "installed",
            "missing": "missing",
            "recon": "recon",
            "enumeration": "enum",
            "exploitation": "exploit",
            "utility": "util",
        }
        return labels.get(tab, str(tab or "tools"))

    def _tools_header(self, active_tab):
        rendered_tabs = []
        for tab in self._tools_tabs():
            label = self._tools_tab_label(tab)
            rendered_tabs.append(label.upper() if tab == active_tab else label)
        return f"SECOPS tools  {'   '.join(rendered_tabs)}"

    def _tools_header_fragments(self, active_tab):
        fragments = [("class:prompt.brand", "SECOPS tools")]
        for tab in self._tools_tabs():
            label = self._tools_tab_label(tab)
            fragments.append(("", "   "))
            if tab == active_tab:
                fragments.append((self._help_active_tab_style(), f" {label} "))
            else:
                fragments.append(("", label))
        fragments.append(("", "\n"))
        return fragments

    def _tools_common_footer_lines(self):
        return [
            "",
            "",
            "Installer un outil manquant: /tools install <name>",
            "",
            "Esc to cancel",
        ]

    def _tools_for_tab(self, tab):
        tools = list(self.tool_registry.all_tools)
        if tab == "installed":
            tools = [tool for tool in tools if tool.installed]
        elif tab == "missing":
            tools = [tool for tool in tools if not tool.installed]
        elif tab not in {"overview", "all"}:
            tools = [tool for tool in tools if tool.category.value == tab]
        return sorted(tools, key=lambda tool: (tool.category.value, tool.name))

    def _tool_status_label(self, tool):
        return "installe" if tool.installed else "absent"

    def _tool_category_label(self, category):
        labels = {
            "recon": "recon",
            "enumeration": "enumeration",
            "exploitation": "exploitation",
            "post_exploitation": "post-exploitation",
            "utility": "utility",
        }
        value = getattr(category, "value", str(category or ""))
        return labels.get(value, value)

    def _tools_overview_lines(self):
        tools = list(self.tool_registry.all_tools)
        installed = [tool for tool in tools if tool.installed]
        missing = [tool for tool in tools if not tool.installed]
        lines = [
            self._tools_header("overview"),
            "",
            "",
            "Inventaire local des outils pentest connus par SECOPS.",
            "",
            f"Installed: {len(installed)} / {len(tools)}",
            f"Missing: {len(missing)}",
            f"Permission mode: {self._command_mode_label()}",
            "",
            "Categories",
        ]
        for tab in ("recon", "enumeration", "exploitation", "utility"):
            category_tools = self._tools_for_tab(tab)
            category_installed = [tool for tool in category_tools if tool.installed]
            lines.append(
                f"{self._tools_tab_label(tab):<14} {len(category_installed):>2}/{len(category_tools):<2} installed"
            )
        lines.append("")
        if missing:
            sample = ", ".join(tool.name for tool in missing[:6])
            if len(missing) > 6:
                sample += ", ..."
            lines.extend(
                self._help_wrap_text(f"Missing quick install: /tools install {sample}")
            )
        else:
            lines.append("Tous les outils connus sont installes.")
        lines.extend(self._tools_common_footer_lines())
        return lines

    def _tools_list_lines(self, tab, selected_index):
        tools = self._tools_for_tab(tab)
        selected_index = max(0, min(selected_index, len(tools) - 1)) if tools else 0
        terminal_lines = shutil.get_terminal_size(fallback=(100, 30)).lines
        visible_count = max(4, min(CHOICE_LIST_VISIBLE_OPTIONS, (terminal_lines - 12) // 3))
        start = max(0, min(selected_index - visible_count // 2, len(tools) - visible_count)) if tools else 0
        end = min(len(tools), start + visible_count)
        title = {
            "installed": "Browse installed tools:",
            "missing": "Browse missing tools:",
            "recon": "Browse recon tools:",
            "enumeration": "Browse enumeration tools:",
            "exploitation": "Browse exploitation tools:",
            "utility": "Browse utility tools:",
        }.get(tab, "Browse tools:")
        lines = [
            self._tools_header(tab),
            "",
            "",
            title,
            "",
        ]
        if not tools:
            lines.append("Aucun outil dans cet onglet.")
            lines.extend(self._tools_common_footer_lines())
            return lines
        if start > 0:
            lines.append(f"↑ {tools[start - 1].name}")
        for index in range(start, end):
            tool = tools[index]
            marker = "›" if index == selected_index else " "
            category = self._tool_category_label(tool.category)
            status = self._tool_status_label(tool)
            lines.append(f"{marker} {tool.name:<16} {status:<8} [{category:<13}] package: {tool.package}")
            lines.extend(self._help_wrap_text(tool.description, indent="    "))
            lines.append(f"    phases: {', '.join(tool.phases)}")
            lines.append(f"    targets: {', '.join(tool.target_types)}")
        if end < len(tools):
            lines.append(f"↓ {tools[end].name}")
        lines.extend(self._tools_common_footer_lines())
        return lines

    def _tools_lines_for_tab(self, tab, state):
        if tab == "overview":
            return self._tools_overview_lines()
        return self._tools_list_lines(tab, state["indices"].get(tab, 0))

    def _tools_body_fragments(self, tab, state):
        lines = self._tools_lines_for_tab(tab, state)
        if not lines:
            return []
        fragments = self._tools_header_fragments(tab)
        for line in lines[1:]:
            fragments.append((self._menu_line_style(line), f"{line}\n"))
        return fragments

    def _tools_toolbar(self):
        return HTML(
            "<toolbar.meta>←/→ tabs</toolbar.meta>"
            "<toolbar.sep> · </toolbar.sep>"
            "<toolbar.meta>Tab onglet</toolbar.meta>"
            "<toolbar.sep> · </toolbar.sep>"
            "<toolbar.meta>↑/↓ parcourir</toolbar.meta>"
            "<toolbar.sep> · </toolbar.sep>"
            "<toolbar.meta>/tools install &lt;name&gt;</toolbar.meta>"
            "<toolbar.sep> · </toolbar.sep>"
            "<toolbar.meta>Esc cancel</toolbar.meta>"
        )

    def _run_tools_view(self):
        self.tool_registry.refresh()
        tabs = self._tools_tabs()
        state = {"tab_index": 0, "indices": {tab: 0 for tab in tabs}}

        def active_tab():
            return tabs[state["tab_index"]]

        def body_text():
            return self._tools_body_fragments(active_tab(), state)

        def move_tab(delta):
            state["tab_index"] = (state["tab_index"] + delta) % len(tabs)

        def move_selection(delta):
            tab = active_tab()
            if tab == "overview":
                return
            tools = self._tools_for_tab(tab)
            if not tools:
                state["indices"][tab] = 0
                return
            state["indices"][tab] = max(
                0,
                min(len(tools) - 1, state["indices"].get(tab, 0) + delta),
            )

        bindings = KeyBindings()

        @bindings.add("escape")
        @bindings.add("c-c", eager=True)
        @bindings.add("q")
        def _close(event):
            event.app.exit(result="cancel", style="class:aborting")

        @bindings.add("right")
        @bindings.add("l")
        @bindings.add("tab")
        def _next_tab(event):
            move_tab(1)
            event.app.invalidate()

        @bindings.add("left")
        @bindings.add("h")
        @bindings.add("s-tab")
        def _previous_tab(event):
            move_tab(-1)
            event.app.invalidate()

        for key, tab_index in (
            ("1", 0),
            ("2", 1),
            ("3", 2),
            ("4", 3),
            ("5", 4),
            ("6", 5),
            ("7", 6),
        ):
            @bindings.add(key)
            def _switch_tab(event, tab_index=tab_index):
                state["tab_index"] = tab_index
                event.app.invalidate()

        @bindings.add("down")
        @bindings.add("j")
        @bindings.add("c-n")
        def _down(event):
            move_selection(1)
            event.app.invalidate()

        @bindings.add("up")
        @bindings.add("k")
        @bindings.add("c-p")
        def _up(event):
            move_selection(-1)
            event.app.invalidate()

        @bindings.add("pagedown")
        def _page_down(event):
            move_selection(5)
            event.app.invalidate()

        @bindings.add("pageup")
        def _page_up(event):
            move_selection(-5)
            event.app.invalidate()

        container = HSplit(
            [
                Window(
                    FormattedTextControl(body_text),
                    wrap_lines=False,
                    always_hide_cursor=True,
                ),
                Window(
                    FormattedTextControl(self._tools_toolbar, style="class:bottom-toolbar.text"),
                    style="class:bottom-toolbar",
                    dont_extend_height=True,
                    height=Dimension(min=1, max=1),
                ),
            ]
        )
        return Application(
            layout=Layout(container),
            key_bindings=bindings,
            full_screen=False,
            erase_when_done=True,
            mouse_support=False,
            style=self.prompt_style,
        ).run()

    def _print_tools(self):
        self.tool_registry.refresh()
        tools = list(self.tool_registry.all_tools)
        if not tools:
            self.set_panel("Outils pentest", ["Aucun outil pentest connu."], tone="warn")
            return
        installed = [tool for tool in tools if tool.installed]
        missing = [tool for tool in tools if not tool.installed]
        lines = [
            f"Installes: {len(installed)} / {len(tools)}",
            f"Manquants: {len(missing)}",
            "Onglets TTY: overview, installed, missing, recon, enumeration, exploitation, utility",
            "",
        ]
        for tab in ("recon", "enumeration", "exploitation", "utility"):
            category_tools = self._tools_for_tab(tab)
            if not category_tools:
                continue
            lines.append(self._tools_tab_label(tab))
            for tool in category_tools:
                lines.append(
                    f"  {tool.name:<16} [{self._tool_status_label(tool)}] {tool.description}"
                )
        self.set_panel("Outils pentest", lines, tone="info")

    def _help_header(self, active_tab):
        tabs = ("general", "commands", "custom-commands")
        rendered_tabs = []
        for tab in tabs:
            rendered_tabs.append(tab.upper() if tab == active_tab else tab)
        return f"SECOPS TUI  {'   '.join(rendered_tabs)}"

    def _help_active_tab_style(self):
        if self.palette.no_color:
            return "reverse bold"
        return f"bg:{self.palette.prompt_brand_hex} fg:{self.palette.toolbar_key_fg_hex} bold"

    def _help_header_fragments(self, active_tab):
        fragments = [("class:prompt.brand", "SECOPS TUI")]
        for tab in ("general", "commands", "custom-commands"):
            fragments.append(("", "   "))
            if tab == active_tab:
                fragments.append((self._help_active_tab_style(), f" {tab} "))
            else:
                fragments.append(("", tab))
        fragments.append(("", "\n"))
        return fragments

    def _help_common_footer_lines(self):
        lines = [
            "",
            "",
        ]
        lines.extend(
            self._help_wrap_text(
                "Pour plus d'aide: audit/NAV_AUDIT.md et templates/automation_project/docs/PROJECT_MAP.md"
            )
        )
        lines.append("")
        lines.extend(
            self._help_wrap_text(
                "Autre chose? Utilise /doctor pour diagnostiquer la configuration locale."
            )
        )
        lines.extend(
            [
            "",
            "Esc to cancel",
            ]
        )
        return lines

    def _help_text_width(self):
        columns = shutil.get_terminal_size(fallback=(100, 30)).columns
        return max(60, min(96, columns - 4))

    def _help_wrap_text(self, text, *, indent=""):
        return textwrap.wrap(
            str(text or ""),
            width=self._help_text_width(),
            initial_indent=indent,
            subsequent_indent=indent,
            break_long_words=False,
            break_on_hyphens=False,
        ) or [indent.rstrip()]

    def _help_general_lines(self):
        lines = [
            self._help_header("general"),
            "",
            "",
        ]
        lines.extend(
            self._help_wrap_text(
                "SECOPS comprend le contexte pentest autorise, garde la memoire de lab, execute des outils avec permission et te laisse piloter la session depuis le terminal."
            )
        )
        lines.append("")
        lines.extend(
            self._help_wrap_text(
                "Nouveau ici? Tape / pour explorer les commandes et /workflow list pour voir les workflows locaux."
            )
        )
        lines.extend(["", "", "Shortcuts"])
        shortcuts = [
            ("! mode shell", "Tab complete puis valide", "Ctrl+C/Ctrl+D quitter"),
            ("/ commandes", "Shift+Tab mode permissions", "Ctrl+T taches"),
            ("@ references SECOPS", "Ctrl+O transcript", "Alt+P modele"),
            ("/btw question laterale", "\\ + Entree nouvelle ligne", "Ctrl+G editeur"),
            ("? raccourcis clavier", "Ctrl+R historique", "Esc annuler"),
        ]
        for left, middle, right in shortcuts:
            lines.append(f"{left:<24}{middle:<30}{right}")
        lines.extend(self._help_common_footer_lines())
        return lines

    def _help_command_description(self, entry):
        command = entry["command"]
        if command == "/model":
            return f"Choisir le modele LLM SECOPS (actuel {self.gemini_runtime.model})."
        if command == "/permissions":
            return "Gerer les autorisations d'execution et le niveau de validation."
        if command == "/session":
            return "Sauvegarder ou lister les sessions SECOPS."
        if command == "/resume":
            return "Reprendre une session sauvegardee avec le selecteur Codex-like."
        if command == "/workflow":
            workflows = ", ".join(sorted(self._workflow_catalog().keys())[:4]) or "aucun workflow"
            return f"Executer un workflow TOML local ({workflows})."
        return entry["description"]

    def _help_command_lines(self, selected_index):
        entries = list(COMMAND_MENU_ENTRIES)
        selected_index = max(0, min(selected_index, len(entries) - 1))
        terminal_lines = shutil.get_terminal_size(fallback=(100, 30)).lines
        visible_count = max(5, min(CHOICE_LIST_VISIBLE_OPTIONS, (terminal_lines - 12) // 2))
        start = max(0, min(selected_index - visible_count // 2, len(entries) - visible_count))
        end = min(len(entries), start + visible_count)
        lines = [
            self._help_header("commands"),
            "",
            "",
            "Browse default commands:",
            "",
        ]
        if start > 0:
            lines.append(f"↑ {entries[start - 1]['command']}")
        for index in range(start, end):
            entry = entries[index]
            marker = "›" if index == selected_index else " "
            lines.append(f"{marker} {entry['command']}")
            lines.extend(self._help_wrap_text(self._help_command_description(entry), indent="    "))
        if end < len(entries):
            lines.append(f"↓ {entries[end]['command']}")
        lines.extend(self._help_common_footer_lines())
        return lines

    def _help_custom_command_entries(self):
        entries = []
        for slug, workflow in sorted(self._workflow_catalog().items()):
            title = workflow.get("title") or slug
            description = workflow.get("description") or "Workflow TOML local."
            entries.append((f"/workflow {slug}", f"{title}. {description}"))
        return entries

    def _help_custom_command_lines(self, selected_index=0):
        entries = self._help_custom_command_entries()
        selected_index = max(0, min(selected_index, len(entries) - 1)) if entries else 0
        terminal_lines = shutil.get_terminal_size(fallback=(100, 30)).lines
        visible_count = max(4, min(CHOICE_LIST_VISIBLE_OPTIONS, (terminal_lines - 12) // 2))
        start = max(0, min(selected_index - visible_count // 2, len(entries) - visible_count)) if entries else 0
        end = min(len(entries), start + visible_count)
        lines = [
            self._help_header("custom-commands"),
            "",
            "",
            "Browse custom commands:",
            "",
            "",
        ]
        lines.extend(
            self._help_wrap_text(
                "Les commandes custom SECOPS sont les workflows TOML dans config/workflows."
            )
        )
        lines.append("")
        if not entries:
            lines.append("Aucun workflow TOML trouve.")
        else:
            if start > 0:
                lines.append(f"↑ {entries[start - 1][0]}")
            for index in range(start, end):
                command, description = entries[index]
                marker = "›" if index == selected_index else " "
                lines.append(f"{marker} {command}")
                lines.extend(self._help_wrap_text(description, indent="    "))
            if end < len(entries):
                lines.append(f"↓ {entries[end][0]}")
        lines.extend(self._help_common_footer_lines())
        return lines

    def _help_lines_for_tab(self, tab, state):
        if tab == "commands":
            return self._help_command_lines(state["command_index"])
        if tab == "custom-commands":
            return self._help_custom_command_lines(state["custom_index"])
        return self._help_general_lines()

    def _help_body_fragments(self, tab, state):
        lines = self._help_lines_for_tab(tab, state)
        if not lines:
            return []
        fragments = self._help_header_fragments(tab)
        for line in lines[1:]:
            fragments.append((self._menu_line_style(line), f"{line}\n"))
        return fragments

    def _help_toolbar(self):
        return HTML(
            "<toolbar.meta>←/→ tabs</toolbar.meta>"
            "<toolbar.sep> · </toolbar.sep>"
            "<toolbar.meta>Tab onglet</toolbar.meta>"
            "<toolbar.sep> · </toolbar.sep>"
            "<toolbar.meta>↑/↓ parcourir</toolbar.meta>"
            "<toolbar.sep> · </toolbar.sep>"
            "<toolbar.meta>1/2/3 aller</toolbar.meta>"
            "<toolbar.sep> · </toolbar.sep>"
            "<toolbar.meta>Esc cancel</toolbar.meta>"
        )

    def _run_help_view(self):
        tabs = ("general", "commands", "custom-commands")
        state = {"tab_index": 0, "command_index": 0, "custom_index": 0}
        for index, entry in enumerate(COMMAND_MENU_ENTRIES):
            if entry["command"] == "/model":
                state["command_index"] = index
                break

        def active_tab():
            return tabs[state["tab_index"]]

        def body_text():
            return self._help_body_fragments(active_tab(), state)

        def move_tab(delta):
            state["tab_index"] = (state["tab_index"] + delta) % len(tabs)

        def move_selection(delta):
            if active_tab() == "commands":
                state["command_index"] = max(
                    0,
                    min(len(COMMAND_MENU_ENTRIES) - 1, state["command_index"] + delta),
                )
            elif active_tab() == "custom-commands":
                entries = self._help_custom_command_entries()
                if entries:
                    state["custom_index"] = max(
                        0,
                        min(len(entries) - 1, state["custom_index"] + delta),
                    )

        bindings = KeyBindings()

        @bindings.add("escape")
        @bindings.add("c-c", eager=True)
        @bindings.add("q")
        def _close(event):
            event.app.exit(result="cancel", style="class:aborting")

        @bindings.add("right")
        @bindings.add("l")
        @bindings.add("tab")
        def _next_tab(event):
            move_tab(1)
            event.app.invalidate()

        @bindings.add("left")
        @bindings.add("h")
        @bindings.add("s-tab")
        def _previous_tab(event):
            move_tab(-1)
            event.app.invalidate()

        @bindings.add("1")
        def _general_tab(event):
            state["tab_index"] = 0
            event.app.invalidate()

        @bindings.add("2")
        def _commands_tab(event):
            state["tab_index"] = 1
            event.app.invalidate()

        @bindings.add("3")
        def _custom_tab(event):
            state["tab_index"] = 2
            event.app.invalidate()

        @bindings.add("down")
        @bindings.add("j")
        @bindings.add("c-n")
        def _down(event):
            move_selection(1)
            event.app.invalidate()

        @bindings.add("up")
        @bindings.add("k")
        @bindings.add("c-p")
        def _up(event):
            move_selection(-1)
            event.app.invalidate()

        @bindings.add("pagedown")
        def _page_down(event):
            move_selection(5)
            event.app.invalidate()

        @bindings.add("pageup")
        def _page_up(event):
            move_selection(-5)
            event.app.invalidate()

        container = HSplit(
            [
                Window(
                    FormattedTextControl(body_text),
                    wrap_lines=False,
                    always_hide_cursor=True,
                ),
                Window(
                    FormattedTextControl(self._help_toolbar, style="class:bottom-toolbar.text"),
                    style="class:bottom-toolbar",
                    dont_extend_height=True,
                    height=Dimension(min=1, max=1),
                ),
            ]
        )
        return Application(
            layout=Layout(container),
            key_bindings=bindings,
            full_screen=False,
            erase_when_done=True,
            mouse_support=False,
            style=self.prompt_style,
        ).run()

    def _print_help(self):
        if self._can_use_transient_page():
            try:
                self._run_help_view()
            except (EOFError, KeyboardInterrupt):
                pass
            return
        self.set_panel(
            "Help",
            self._help_general_lines()
            + ["", "Browse default commands:"]
            + [
                f"{entry['command']:<14} {self._help_command_description(entry)}"
                for entry in COMMAND_MENU_ENTRIES
            ],
            tone="info",
        )

    def _print_keyboard_help(self):
        self.set_panel(
            "Raccourcis clavier",
            [
                "Entrée: envoyer | \\ + Entrée ou Ctrl+J: nouvelle ligne",
                "Tab: completer, puis envoyer si la commande est complete | ↑↓: historique ou selection",
                "Ctrl+L: redessiner l'écran sans effacer la saisie",
                "Ctrl+R: rechercher dans l'historique | Ctrl+O: transcript",
                "Alt+P: modèle | Alt+T: thinking | Shift+Tab/Alt+M: mode permissions",
                "Ctrl+G ou Ctrl+X Ctrl+E: ouvrir l'éditeur externe",
                "Ctrl+C/Ctrl+D: quitter proprement | Esc: annuler la saisie ou fermer une vue",
            ],
            tone="info",
        )

    def dispatch_command(self, command, args):
        if command == "/quit":
            self._print_session_summary()
            return False

        if command == "/__transcript":
            self._run_transcript_viewer()
            return True

        if command == "/__history_search":
            self._run_history_search_page()
            return True

        if command == "/help":
            self._print_help()
            return True

        if command == "/status":
            self._print_status()
            return True

        if command == "/doctor":
            self._run_doctor()
            return True

        if command == "/stats":
            self._print_stats()
            return True

        if command == "/copy":
            self._handle_copy(args)
            return True

        if command == "/view":
            self._handle_view(args)
            return True

        if command == "/clear":
            self.clear_screen()
            self._header_rendered = False
            self.render_shell_header()
            self._header_rendered = True
            self.set_panel("", [], tone="muted", variant="plain")
            return True

        if command == "/case":
            if not args:
                if self.active_case:
                    self._show_case(self.active_case)
                else:
                    self._print_cases()
                return True
            if args[0].casefold() in {"ls", "list"}:
                self._print_cases()
                return True
            if args[0].casefold() in {"off", "none", "aucun", "clear"}:
                self._deactivate_case()
                return True
            self._activate_case(" ".join(args))
            return True

        if command == "/target":
            if not args:
                if self.active_target:
                    lines = [self.active_target.summary]
                    # Cross-reference findings for this target
                    target_findings = self._findings_for_active_target()
                    if target_findings:
                        lines.extend(target_findings)
                    self.set_panel("Cible active", lines, tone="success")
                elif self.current_target:
                    self.set_panel("Cible", [f"IP courante: {self.current_target}"], tone="info")
                else:
                    self._print_targets()
                return True
            if args[0].casefold() in {"ls", "list"}:
                self._print_targets()
                return True
            raw = " ".join(args)
            detected = detect_targets(raw)
            if detected:
                self.active_target = detected[0]
                self.agent_loop.active_target = self.active_target
                if detected[0] not in self.targets:
                    self.targets.append(detected[0])
                self.current_target = detected[0].address
                self.save_state()
                self.set_panel("Cible active", [detected[0].summary], tone="success")
            else:
                self.set_panel("Cible", [f"Impossible de detecter une cible dans: {raw}"], tone="warn")
            return True

        if command == "/phase":
            self._handle_phase(args)
            return True

        if command == "/model":
            self._handle_model(args)
            return True

        if command == "/theme":
            self._handle_theme(args)
            return True

        if command == "/reasoning":
            self._handle_reasoning(args)
            return True

        if command == "/profile":
            self._handle_profile(args)
            return True

        if command == "/statusline":
            self._handle_statusline(args)
            return True

        if command == "/notify":
            self._handle_notify(args)
            return True

        if command == "/permissions":
            self._handle_permissions(args)
            return True

        if command == "/compact":
            self._handle_compact(args)
            return True

        if command == "/side":
            self._handle_side(args)
            return True

        if command == "/btw":
            self._handle_side(args, dismissible=True)
            return True

        if command == "/tools":
            if args and args[0].casefold() in {"install", "installer"}:
                self._prepare_tools_install(args[1:])
                return True
            if self._can_use_transient_page():
                try:
                    self._run_tools_view()
                except (EOFError, KeyboardInterrupt):
                    pass
                return True
            self._print_tools()
            return True

        if command == "/jobs":
            self._handle_jobs(args)
            return True

        if command == "/learn":
            self._print_learning_journal()
            return True

        if command == "/findings":
            summary = self.findings_store.summary()
            lines = summary.split("\n") if summary else ["Aucune decouverte."]
            lines.insert(0, f"Total: {self.findings_store.count} decouverte(s)")
            self.set_panel("Decouvertes", lines[:20], tone="info" if self.findings_store.count else "warn")
            return True

        if command == "/plan":
            self._show_attack_plan()
            return True

        if command == "/export":
            self._handle_export(args)
            return True

        if command == "/report":
            self._generate_report(args)
            return True

        if command == "/scope":
            self._handle_scope(args)
            return True

        if command == "/resume":
            return self._handle_resume(args)

        if command == "/session":
            result = self._handle_session(args)
            return True if result is None else result

        if command == "/rewind":
            self._handle_rewind(args)
            return True

        if command == "/workflow":
            self._handle_workflow(args)
            return True

        self.set_panel(
            "Commande inconnue",
            [f"{command} n'est pas reconnue.", "Tape /help pour voir les commandes."],
            tone="error",
        )
        return True

    def _handle_export(self, args):
        args = list(args or [])
        if args and args[0].casefold() == "transcript":
            self._export_transcript(args[1:])
            return
        self._export_findings(args)

    def _export_transcript(self, args):
        if not self._transcript_entries:
            self.set_panel("Export", ["Aucun transcript a exporter."], tone="warn")
            return

        requested_format = ""
        args = list(args or [])
        index = 0
        while index < len(args):
            arg = args[index].strip().lower()
            if arg == "--format" and index + 1 < len(args):
                requested_format = args[index + 1].strip().lower()
                index += 2
                continue
            if arg.startswith("--format="):
                requested_format = arg.split("=", 1)[1].strip().lower()
            elif arg in {"txt", "json"}:
                requested_format = arg
            index += 1

        export_format = requested_format or "txt"
        if export_format not in {"txt", "json"}:
            self.set_panel("Export", ["Format transcript invalide. Valides: txt, json."], tone="warn")
            return

        timestamp = datetime.now().strftime("%Y-%m-%d_%H%M")
        path = self.workspace / f"transcript_{timestamp}.{export_format}"
        path.parent.mkdir(parents=True, exist_ok=True)
        if export_format == "json":
            path.write_text(
                json.dumps(self._transcript_entries, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        else:
            blocks = []
            for entry in self._transcript_entries:
                header = f"## {entry['timestamp']} — {entry['title'] or entry['source']}"
                body = entry.get("full") or entry.get("visible") or ""
                if entry.get("log_path"):
                    body += f"\n\nLog complet: {entry['log_path']}"
                blocks.append(f"{header}\n{body}".strip())
            path.write_text("\n\n".join(blocks) + "\n", encoding="utf-8")

        self.set_panel(
            "Export",
            [f"Transcript exporte: {path}", f"Format: {export_format}"],
            tone="success",
        )

    def _export_findings(self, args):
        if not self.findings_store.count:
            self.set_panel("Export", ["Aucune decouverte a exporter."], tone="warn")
            return

        timestamp = datetime.now().strftime("%Y-%m-%d_%H%M")
        formats = set()
        for arg in args:
            normalized = arg.strip().lower()
            if normalized in {"json"}:
                formats.add("json")
            elif normalized in {"md", "markdown"}:
                formats.add("md")
        if not formats:
            formats = {"json", "md"}

        exported = []
        if "json" in formats:
            path = self.workspace / f"findings_{timestamp}.json"
            self.findings_store.export_json(path)
            exported.append(str(path))
        if "md" in formats:
            path = self.workspace / f"findings_{timestamp}.md"
            self.findings_store.export_markdown(path)
            exported.append(str(path))

        lines = [f"{self.findings_store.count} decouverte(s) exportee(s):"]
        lines.extend(f"  {p}" for p in exported)
        self.set_panel("Export", lines, tone="success")

    def _show_attack_plan(self):
        """Generate and display the attack plan from current findings."""
        plan = self.agent_loop.refresh_plan(force=False)
        lines = format_plan_display(plan)
        self.set_panel("Plan d'attaque", lines[:25], tone="info")

    def _session_datetime(self, value):
        value = str(value or "").strip()
        if not value:
            return None
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None

    def _session_timestamp(self, value):
        parsed = self._session_datetime(value)
        if parsed is None:
            return 0
        try:
            return parsed.timestamp()
        except (OSError, OverflowError, ValueError):
            return 0

    def _session_relative_time(self, value, *, now=None):
        parsed = self._session_datetime(value)
        if parsed is None:
            return "-"
        if now is None:
            now = datetime.now(parsed.tzinfo) if parsed.tzinfo else datetime.now()
        elif parsed.tzinfo and now.tzinfo is None:
            now = now.replace(tzinfo=parsed.tzinfo)
        seconds = max(0, int((now - parsed).total_seconds()))
        units = (
            (365 * 24 * 60 * 60, "year"),
            (30 * 24 * 60 * 60, "month"),
            (24 * 60 * 60, "day"),
            (60 * 60, "hour"),
            (60, "minute"),
            (1, "second"),
        )
        for unit_seconds, label in units:
            if seconds >= unit_seconds or label == "second":
                count = max(1 if label == "second" else 0, seconds // unit_seconds)
                plural = "" if count == 1 else "s"
                return f"{count} {label}{plural} ago"
        return "just now"

    def _session_conversation_label(self, summary, state=None):
        summary_text = getattr(state, "conversation_summary", "") if state else ""
        candidates = [
            summary_text,
            getattr(summary, "target", ""),
            f"Phase {getattr(summary, 'phase', '')}" if getattr(summary, "phase", "") else "",
            getattr(summary, "session_id", ""),
        ]
        for candidate in candidates:
            cleaned = " ".join(str(candidate or "").split())
            if cleaned:
                return cleaned
        return "-"

    def _session_resume_rows(self, query="", sort_mode="updated"):
        terms = [term.casefold() for term in str(query or "").split() if term.strip()]
        rows = []
        for summary in list_sessions(self.workspace):
            state = load_session(self.workspace, summary.session_id)
            conversation = self._session_conversation_label(summary, state)
            branch = "-"
            searchable = " ".join(
                str(value or "")
                for value in [
                    summary.session_id,
                    summary.target,
                    summary.phase,
                    summary.started_at,
                    summary.last_active,
                    branch,
                    conversation,
                ]
            ).casefold()
            if terms and not all(term in searchable for term in terms):
                continue
            rows.append(
                {
                    "summary": summary,
                    "state": state,
                    "branch": branch,
                    "conversation": conversation,
                }
            )
        sort_field = "started_at" if sort_mode == "created" else "last_active"
        rows.sort(
            key=lambda row: self._session_timestamp(getattr(row["summary"], sort_field)),
            reverse=True,
        )
        return rows

    def _run_session_resume_overlay(self):
        state = {
            "query": "",
            "selected_index": 0,
            "sort": "updated",
            "expanded_ids": set(),
        }

        def rows():
            items = self._session_resume_rows(state["query"], state["sort"])
            if not items:
                state["selected_index"] = 0
                return []
            state["selected_index"] = max(0, min(state["selected_index"], len(items) - 1))
            return items

        def visible_window(items):
            terminal_lines = shutil.get_terminal_size(fallback=(100, 30)).lines
            visible_count = max(4, min(CHOICE_LIST_VISIBLE_OPTIONS, terminal_lines - 8))
            start = max(0, min(state["selected_index"] - visible_count // 2, len(items) - visible_count))
            end = min(len(items), start + visible_count)
            return start, end

        def sort_label():
            return "Created" if state["sort"] == "created" else "Updated"

        def expanded_lines(row):
            saved_state = row.get("state")
            summary = row["summary"]
            details = [
                f"    id: {summary.session_id}",
                f"    phase: {summary.phase or '-'}",
                f"    target: {summary.target or '-'}",
            ]
            if saved_state:
                tools = ", ".join(saved_state.tools_used[:6]) or "-"
                scope = ", ".join(saved_state.scope[:4]) or "-"
                details.append(f"    tools: {tools}")
                details.append(f"    scope: {scope}")
                if saved_state.active_case_slug:
                    details.append(f"    case: {saved_state.active_case_slug}")
            return details

        def body_fragments():
            items = rows()
            columns = shutil.get_terminal_size(fallback=(100, 30)).columns
            created_width = 13
            updated_width = 15
            branch_width = 8
            fixed_width = 2 + created_width + 2 + updated_width + 2 + branch_width
            conversation_width = max(24, columns - fixed_width - 2)
            fragments = []

            def add(style, text=""):
                fragments.append((style, text + "\n"))

            add("class:toolbar.meta", f"Resume a previous session  Sort: {sort_label()}")
            add("", "")
            add("class:toolbar.meta", f"Search: {state['query']}" if state["query"] else "Type to search")
            add("", "")
            add(
                "class:toolbar.meta",
                f"  {'Created':<{created_width}}  {'Updated':<{updated_width}}  {'Branch':<{branch_width}}Conversation",
            )
            if not items:
                add("", "  No saved sessions.")
                add("", "  Use /session save <name> to create one.")
                return fragments

            start, end = visible_window(items)
            if start > 0:
                add("", "↑")
            for index in range(start, end):
                row = items[index]
                summary = row["summary"]
                marker = "›" if index == state["selected_index"] else " "
                conversation = self._truncate_toolbar_text(row["conversation"], conversation_width)
                line = (
                    f"{marker} "
                    f"{self._session_relative_time(summary.started_at):<{created_width}}  "
                    f"{self._session_relative_time(summary.last_active):<{updated_width}}  "
                    f"{row['branch']:<{branch_width}}"
                    f"{conversation}"
                )
                add("class:selected-option" if index == state["selected_index"] else "", line)
                if summary.session_id in state["expanded_ids"]:
                    for detail in expanded_lines(row):
                        add(self._menu_detail_style(), detail)
            if end < len(items):
                add("", "↓")
            return fragments

        def selected_session_id():
            items = rows()
            if not items:
                return None
            return items[state["selected_index"]]["summary"].session_id

        def move_selection(delta):
            items = rows()
            if not items:
                return
            state["selected_index"] = max(0, min(len(items) - 1, state["selected_index"] + delta))

        def toggle_sort():
            state["sort"] = "created" if state["sort"] == "updated" else "updated"
            state["selected_index"] = 0

        def toggle_expanded():
            items = rows()
            if not items:
                return
            session_id = items[state["selected_index"]]["summary"].session_id
            if session_id in state["expanded_ids"]:
                state["expanded_ids"].remove(session_id)
            else:
                state["expanded_ids"].add(session_id)

        bindings = KeyBindings()

        @bindings.add("escape")
        def _escape(event):
            if state["query"]:
                state["query"] = ""
                state["selected_index"] = 0
                event.app.invalidate()
                return
            event.app.exit(result=None, style="class:aborting")

        @bindings.add("c-c", eager=True)
        def _quit(event):
            event.app.exit(result="__quit__", style="class:aborting")

        @bindings.add("enter", eager=True)
        def _accept(event):
            event.app.exit(result=selected_session_id(), style="class:accepted")

        @bindings.add("down")
        @bindings.add("j")
        @bindings.add("c-n")
        @bindings.add("tab")
        def _down(event):
            move_selection(1)
            event.app.invalidate()

        @bindings.add("up")
        @bindings.add("k")
        @bindings.add("c-p")
        @bindings.add("s-tab")
        def _up(event):
            move_selection(-1)
            event.app.invalidate()

        @bindings.add("pagedown")
        def _page_down(event):
            move_selection(8)
            event.app.invalidate()

        @bindings.add("pageup")
        def _page_up(event):
            move_selection(-8)
            event.app.invalidate()

        @bindings.add("home")
        def _home(event):
            state["selected_index"] = 0
            event.app.invalidate()

        @bindings.add("end")
        def _end(event):
            items = rows()
            if items:
                state["selected_index"] = len(items) - 1
            event.app.invalidate()

        @bindings.add("escape", "s")
        @bindings.add("c-s")
        @bindings.add("left")
        @bindings.add("right")
        def _sort(event):
            toggle_sort()
            event.app.invalidate()

        @bindings.add("c-e")
        def _expand(event):
            toggle_expanded()
            event.app.invalidate()

        @bindings.add("backspace")
        @bindings.add("c-h")
        def _backspace(event):
            if state["query"]:
                state["query"] = state["query"][:-1]
                state["selected_index"] = 0
            event.app.invalidate()

        @bindings.add("c-u")
        def _clear_query(event):
            state["query"] = ""
            state["selected_index"] = 0
            event.app.invalidate()

        @bindings.add(Keys.Any)
        def _search_text(event):
            data = event.key_sequence[-1].data
            if data and len(data) == 1 and data.isprintable():
                state["query"] += data
                state["selected_index"] = 0
                event.app.invalidate()

        container = HSplit(
            [
                Window(
                    FormattedTextControl(body_fragments),
                    wrap_lines=False,
                    always_hide_cursor=True,
                    style="class:input-selection",
                ),
                Window(
                    FormattedTextControl(
                        self._session_resume_toolbar,
                        style="class:bottom-toolbar.text",
                    ),
                    style="class:bottom-toolbar",
                    dont_extend_height=True,
                    height=Dimension(min=1, max=1),
                ),
            ]
        )
        return Application(
            layout=Layout(container),
            key_bindings=bindings,
            full_screen=False,
            erase_when_done=True,
            mouse_support=False,
            style=self.prompt_style,
        ).run()

    def _restore_saved_session(self, session_id):
        state = load_session(self.workspace, session_id)
        if not state:
            self.set_panel("Session", [f"Session '{session_id}' introuvable."], tone="error")
            return False
        phase = parse_phase(state.phase)
        if phase:
            self.engagement.set_phase(phase, "Restauration de session.")
        for tool in state.tools_used:
            self.engagement.record_tool_use(tool)
        self.tool_executor.set_scope(state.scope)
        if hasattr(self, "agent_loop") and self.agent_loop:
            agent_state = {
                "phase": state.phase,
                "tools_used": state.tools_used,
                "targets": state.targets,
                "active_target": state.target_summary,
            }
            self.agent_loop.import_state(agent_state)
            self.targets = self.agent_loop.targets
            self.active_target = self.agent_loop.active_target
            self.current_target = self.active_target.label if self.active_target else self.current_target
        findings_path = self.workspace / "findings_state.json"
        if findings_path.exists():
            self.findings_store = FindingsStore.load_state(findings_path)
            self.tool_executor.findings_store = self.findings_store
            if hasattr(self, "agent_loop") and self.agent_loop:
                self.agent_loop.findings_store = self.findings_store
        if state.active_case_slug:
            case = self.knowledge_store.get_case(state.active_case_slug)
            if case:
                self.active_case = case
                self._active_case_slug = case.slug
                self.agent_loop.active_case_label = case.label
            else:
                self.active_case = None
                self._active_case_slug = ""
                self.agent_loop.active_case_label = ""
        else:
            self.active_case = None
            self._active_case_slug = ""
            self.agent_loop.active_case_label = ""

        self.set_panel(
            "Session restauree",
            [
                f"ID: {state.session_id}",
                f"Phase: {state.phase}",
                f"Cible: {state.target_summary or '-'}",
                f"Findings: {state.findings_count}",
                f"Cas actif: {self.active_case.slug if self.active_case else '-'}",
            ],
            tone="success",
        )
        return True

    def _handle_resume(self, args):
        args = list(args or [])
        if args:
            requested = args[0].strip()
            if requested in {"--last", "last", "latest", "recent"}:
                rows = self._session_resume_rows("", "updated")
                if not rows:
                    self.set_panel("Resume", ["Aucune session sauvegardee."], tone="warn")
                    return True
                self._restore_saved_session(rows[0]["summary"].session_id)
                return True
            self._restore_saved_session(requested)
            return True

        previous_panel = self.panel
        if self._can_use_transient_page():
            try:
                session_id = self._run_session_resume_overlay()
            except (EOFError, KeyboardInterrupt):
                session_id = None
            if session_id == "__quit__":
                self._print_session_summary()
                return False
            if not session_id:
                self._restore_inline_panel(previous_panel)
                self._stream_rendered_panel = True
                return True
            restored = self._restore_saved_session(session_id)
            if restored:
                self.render_panel_state()
                self._stream_rendered_panel = True
            return True

        rows = self._session_resume_rows("", "updated")
        lines = [
            "Usage: /resume [id|--last]",
            "En terminal interactif, /resume ouvre le selecteur de sessions.",
        ]
        if rows:
            lines.extend(["", "Sessions recentes:"])
            for row in rows[:5]:
                summary = row["summary"]
                lines.append(
                    f"  {summary.session_id:<18} {summary.last_active or '-'}  {row['conversation']}"
                )
        else:
            lines.append("Aucune session sauvegardee.")
        self.set_panel("Resume", lines, tone="info" if rows else "warn")
        return True

    def _handle_session(self, args):
        """Handle /session command: save, list, resume, or show current."""
        if not args:
            # Show current session info
            phase = self.engagement.phase_label
            target = self.active_target.label if self.active_target else "aucune"
            findings = self.findings_store.count
            tools = len(self.engagement.tools_used)
            lines = [
                f"Phase: {phase}",
                f"Cible: {target}",
                f"Findings: {findings}",
                f"Outils utilises: {tools}",
            ]
            self.set_panel("Session courante", lines, tone="info")
            return

        subcommand = args[0].lower()

        if subcommand == "save":
            name = args[1] if len(args) > 1 else ""
            state = SessionState(
                session_id=name or "",
                target_summary=self.active_target.label if self.active_target else "",
                phase=self.engagement.phase.value,
                tools_used=list(self.engagement.tools_used),
                scope=list(self.tool_executor.authorized_scope),
                active_case_slug=self.active_case.slug if self.active_case else self._active_case_slug,
                findings_count=self.findings_store.count,
            )
            # Export agent state if available
            if hasattr(self, "agent_loop") and self.agent_loop:
                agent_state = self.agent_loop.export_state()
                state.targets = agent_state.get("targets", [])
                state.conversation_summary = agent_state.get("conversation_summary", "")
            path = save_session(self.workspace, state)
            self.set_panel(
                "Session sauvegardee",
                [f"ID: {state.session_id}", f"Fichier: {path}"],
                tone="success",
            )
            return

        if subcommand == "list":
            sessions = list_sessions(self.workspace)
            if not sessions:
                self.set_panel("Sessions", ["Aucune session sauvegardee."], tone="warn")
                return
            lines = []
            for s in sessions[:10]:
                lines.append(
                    f"  {s.session_id} | {s.target or '-'} | {s.phase} | "
                    f"{s.findings_count} findings | {s.last_active}"
                )
            self.set_panel("Sessions sauvegardees", lines, tone="info")
            return

        if subcommand == "resume":
            return self._handle_resume(args[1:])

        self.set_panel(
            "Session",
            ["Usage: /session [save [nom]|list]", "Utilise /resume pour reprendre une session."],
            tone="warn",
        )

    def _findings_for_active_target(self):
        """Cross-reference findings with active target for enriched display."""
        if not self.active_target:
            return []
        lines = []
        vulns = self.findings_store.vulnerabilities
        if vulns:
            lines.append(f"vulns: {len(vulns)} trouvee(s)")
            for v in vulns[:3]:
                lines.append(f"  {v.value[:60]}")
        creds = self.findings_store.credentials
        if creds:
            lines.append(f"credentials: {len(creds)} trouvee(s)")
            for c in creds[:2]:
                lines.append(f"  {c.value[:60]}")
        paths = [f for f in self.findings_store.all if f.finding_type.value == "path"]
        if paths:
            lines.append(f"chemins: {len(paths)} decouverts")
            for p in paths[:3]:
                lines.append(f"  {p.value[:60]}")
        return lines

    def _generate_report(self, args=None):
        """Generate a structured pentest report from current session data."""
        if not self.findings_store.count:
            self.set_panel("Rapport", ["Aucune decouverte a inclure dans le rapport."], tone="warn")
            return

        # Check for --pdf flag
        want_pdf = False
        if args:
            for arg in args:
                if arg.strip().lower() in ("pdf", "--pdf"):
                    want_pdf = True

        timestamp = datetime.now().strftime("%Y-%m-%d_%H%M")
        output_path = self.workspace / f"rapport_pentest_{timestamp}.md"

        target_summary = "Aucune cible"
        if self.active_target:
            target_summary = self.active_target.summary
        elif self.current_target:
            target_summary = self.current_target

        elapsed = time.time() - self._session_start
        minutes = int(elapsed // 60)
        attack_plan = self.agent_loop.refresh_plan(force=False)

        try:
            report_path = generate_pentest_report(
                target_summary=target_summary,
                findings_store=self.findings_store,
                engagement_state=self.engagement,
                session_duration_minutes=minutes,
                output_path=output_path,
                audit_logger=self.audit_logger,
                attack_plan=attack_plan,
            )
            lines = [
                f"Rapport Markdown genere: {report_path.name}",
                f"Chemin: {report_path}",
                f"Findings inclus: {self.findings_store.count}",
                f"Phase finale: {self.engagement.phase_label}",
                f"Etapes plan: {len(attack_plan.steps)}",
            ]

            # Generate PDF if requested
            if want_pdf:
                try:
                    from app.pdf_report import generate_pdf_report
                    pdf_path = self.workspace / f"rapport_pentest_{timestamp}.pdf"
                    generate_pdf_report(
                        target_summary=target_summary,
                        findings_store=self.findings_store,
                        engagement_state=self.engagement,
                        session_duration_minutes=minutes,
                        output_path=pdf_path,
                        audit_logger=self.audit_logger,
                        attack_plan=attack_plan,
                    )
                    lines.append(f"Rapport PDF genere: {pdf_path.name}")
                    lines.append(f"Chemin PDF: {pdf_path}")
                except ImportError:
                    lines.append("PDF indisponible: installe fpdf2 (pip install fpdf2).")
                except OSError as exc:
                    lines.append(f"Erreur PDF: {exc}")

            self.set_panel("Rapport pentest", lines, tone="success")
        except OSError as exc:
            self.set_panel("Rapport", [f"Erreur lors de la generation: {exc}"], tone="error")

    def _handle_scope(self, args):
        """Handle /scope command — show, set, or clear the authorized scope."""
        previous_panel = self.panel
        if not args:
            if self._can_use_transient_page():
                self._run_scope_menu_page()
                return
            scope = self.tool_executor.authorized_scope
            self.set_panel("Scope", self._scope_status_lines(), tone="info" if scope else "warn")
            return

        if args[0].casefold() in {"off", "clear", "none", "reset"}:
            self._apply_scope_entries([], previous_panel=previous_panel)
            return

        entries = [a.strip() for a in args if a.strip()]
        self._apply_scope_entries(entries, previous_panel=previous_panel)

    def _print_session_summary(self):
        """Print a session summary before quitting."""
        elapsed = time.time() - self._session_start
        minutes = int(elapsed // 60)
        lines = []
        lines.append(f"Phase: {self.engagement.phase_label}")
        if self.active_target:
            lines.append(f"Cible: {self.active_target.label} ({len(self.active_target.ports)} ports, {len(self.active_target.services)} services)")
        elif self.current_target:
            lines.append(f"Cible: {self.current_target}")
        lines.append(f"Findings: {self.findings_store.count} decouverte(s)")
        if self.engagement.tools_used:
            lines.append(f"Outils: {', '.join(self.engagement.tools_used[-8:])}")
        lines.append(f"Duree: {minutes} min" if minutes else "Duree: <1 min")
        if self.findings_store.count:
            lines.append("Utilise /export avant de quitter pour sauvegarder les decouvertes.")
        self.set_panel("Session terminee", lines, tone="info")
        self.render_panel_state()
        # Suggestion #12: Auto-save findings state for session persistence
        if self.findings_store.count:
            try:
                self.findings_store.save_state(self._findings_state_path)
            except OSError:
                pass

    def initialize_interactive(self):
        self.live_agent_stream = True
        self._header_rendered = False
        self._stream_rendered_panel = False
        self._suppress_transient_result_once = False

    def _render_session_snapshot(self):
        parts = []
        for label, value, tone in self._session_snapshot_segments():
            parts.append(
                f"{self.palette.muted_ansi}{label}{AnsiStyle.RESET_ALL} "
                f"{self.palette.tone_ansi(tone)}{value}{AnsiStyle.RESET_ALL}"
            )
        joiner = f" {self.palette.muted_ansi}•{AnsiStyle.RESET_ALL} "
        print(joiner.join(parts))

    def _render_interaction_separator(self):
        cols = shutil.get_terminal_size(fallback=(80, 24)).columns
        line = self._horizontal_separator(max(24, cols - 2), min_width=24)
        print()
        print(line)
        print()

    def _should_render_submitted_user_message(self, raw_text):
        stripped = str(raw_text or "").strip()
        if not stripped:
            return False
        return not stripped.startswith(("/", "!", "?"))

    def _submitted_user_message_lines(self, raw_text):
        lines = str(raw_text or "").splitlines() or [""]
        rendered = []
        for index, line in enumerate(lines):
            prefix = "› " if index == 0 else "  "
            rendered.append(f"{prefix}{line}")
        return rendered

    def _submitted_user_message_row_count(self, lines):
        columns = shutil.get_terminal_size(fallback=(80, 24)).columns
        rows = 0
        for line in lines:
            rows += max(1, (len(line) + max(1, columns) - 1) // max(1, columns))
        return rows

    def _render_submitted_user_message(self, raw_text):
        if not sys.stdout.isatty() or not self._should_render_submitted_user_message(raw_text):
            return
        lines = self._submitted_user_message_lines(raw_text)
        rows = self._submitted_user_message_row_count(lines)
        bg = self.palette.bg_ansi(self.palette.user_message_bg_hex)
        fg = self.palette.text_ansi
        reset = AnsiStyle.RESET_ALL
        if not bg and not fg:
            return

        if rows > 0:
            sys.stdout.write(f"\x1b[{rows}A")
            for index in range(rows):
                sys.stdout.write("\r\x1b[2K")
                if index < rows - 1:
                    sys.stdout.write("\x1b[1B")
            if rows > 1:
                sys.stdout.write(f"\x1b[{rows - 1}A")
            sys.stdout.write("\r")

        for line in lines:
            sys.stdout.write(f"{bg}{fg}{line}{reset}\n")
        sys.stdout.flush()

    def render_shell_header(self):
        model_label = self._current_model_label()
        directory_label = self._shell_directory_label()
        help_hint = "/help"

        raw_lines = [
            f">_ {self.chrome.app_name}",
            "",
            f"model: {model_label}   {help_hint}",
            f"directory: {directory_label}",
        ]
        colored_lines = [
            f"{self.palette.accent_ansi}{AnsiStyle.BRIGHT}>_ {self.chrome.app_name}{AnsiStyle.RESET_ALL}",
            "",
            (
                f"{self.palette.muted_ansi}model:{AnsiStyle.RESET_ALL} "
                f"{self.palette.text_ansi}{model_label}{AnsiStyle.RESET_ALL}   "
                f"{self.palette.muted_ansi}{help_hint}{AnsiStyle.RESET_ALL}"
            ),
            (
                f"{self.palette.muted_ansi}directory:{AnsiStyle.RESET_ALL} "
                f"{self.palette.text_ansi}{directory_label}{AnsiStyle.RESET_ALL}"
            ),
        ]
        width = max(43, min(72, max(len(line) for line in raw_lines)))
        self._print_box(colored_lines, width=width, tone="neutral")
        print()

    def _truncate_toolbar_text(self, text, max_width):
        text = str(text or "")
        if max_width <= 0:
            return ""
        if len(text) <= max_width:
            return text
        if max_width <= 3:
            return text[:max_width]
        return f"{text[:max_width - 3]}..."

    def _last_token_label(self):
        prompt_chars = int(getattr(self.llm_client, "last_prompt_chars", 0) or 0)
        if not prompt_chars:
            return "0"
        approx_tokens = max(1, round(prompt_chars / 4))
        if approx_tokens >= 1000:
            return f"~{approx_tokens / 1000:.1f}k"
        return f"~{approx_tokens}"

    def _debug_log_paths_label(self):
        paths = []
        for path in (
            self._last_output_log_path,
            getattr(self.tool_executor, "_last_command_log_path", ""),
        ):
            path = str(path or "")
            if path and path not in paths:
                paths.append(path)
        return " | ".join(paths) if paths else "aucun"

    def _statusline_segment(self, field):
        target_label = self.active_target.label if self.active_target else (self.current_target or "aucune")
        if field == "model":
            return ("model", self.gemini_runtime.model, "success" if self.gemini_runtime.api_key_present else "warn")
        if field == "target":
            return ("cible", target_label, "success" if target_label != "aucune" else "muted")
        if field == "phase":
            return ("phase", self.engagement.phase_label, "success")
        if field == "scope":
            return ("scope", self._scope_summary_label(), "info" if self.tool_executor.authorized_scope else "muted")
        if field == "findings":
            return ("findings", str(self.findings_store.count), "success" if self.findings_store.count else "muted")
        if field == "jobs":
            return ("jobs", str(self.jobs.active_count), "warn" if self.jobs.active_count else "muted")
        if field == "context":
            return ("context", self.get_footer_context(), "info")
        return None

    def _custom_statusline_segments(self):
        if not self.statusline_fields:
            return None
        segments = []
        for field in self.statusline_fields:
            segment = self._statusline_segment(field)
            if segment:
                segments.append(segment)
        return segments

    def _toolbar_context_segments(self):
        custom_segments = self._custom_statusline_segments()
        if custom_segments is not None:
            return custom_segments
        target_label = self.active_target.label if self.active_target else (self.current_target or "aucune")
        findings_count = str(self.findings_store.count)
        if self.ux_profile == "quiet":
            context = [("profil", "quiet", "muted")]
            if self.jobs.active_count:
                context.append(("jobs", str(self.jobs.active_count), "warn"))
            return context
        if self.ux_profile == "debug":
            log_paths = self._debug_log_paths_label()
            context = [
                ("model", self.gemini_runtime.model, "info"),
                ("tokens", self._last_token_label(), "success" if getattr(self.llm_client, "last_prompt_chars", 0) else "muted"),
                ("logs", log_paths, "warn" if log_paths != "aucun" else "muted"),
            ]
            if self.jobs.active_count:
                context.append(("jobs", str(self.jobs.active_count), "warn"))
            return context
        context = [
            ("phase", self.engagement.phase_label, "success"),
            ("cible", target_label, "success" if target_label != "aucune" else "muted"),
            ("findings", findings_count, "success" if self.findings_store.count else "muted"),
        ]
        if self.jobs.active_count:
            context.append(("jobs", str(self.jobs.active_count), "warn"))
        return context

    def _cycle_prompt_permission_mode(self):
        current = self.command_permission_mode
        try:
            index = PROMPT_PERMISSION_MODE_CYCLE.index(current)
        except ValueError:
            next_mode = "ask"
        else:
            next_mode = PROMPT_PERMISSION_MODE_CYCLE[
                (index + 1) % len(PROMPT_PERMISSION_MODE_CYCLE)
            ]
        self._set_command_permission_mode(next_mode)
        return next_mode

    def _toggle_current_model_thinking(self):
        model = self.gemini_runtime.model
        if not self._model_supports_thinking(model):
            return False
        if self.model_thinking_overrides.get(model) == "off":
            self.model_thinking_overrides.pop(model, None)
        else:
            self.model_thinking_overrides[model] = "off"
        self._apply_model_profile()
        return True

    def _latest_history_entries(self):
        if self.session is not None and getattr(self.session, "history", None):
            entries = list(reversed(self.session.history.get_strings()))
            if entries:
                return entries
        try:
            return list(FileHistory(str(self.history_file)).load_history_strings())
        except OSError:
            return []

    def _find_history_match(self, query, current_text=""):
        query = str(query or "").casefold()
        current_text = str(current_text or "")
        for entry in self._latest_history_entries():
            if entry == current_text:
                continue
            if not query or query in entry.casefold():
                return entry
        return ""

    def _history_search_entries(self, scope):
        if scope == "session":
            entries = [
                str(item.get("user", "")).strip()
                for item in reversed(self.conversation_history)
                if str(item.get("user", "")).strip()
            ]
        else:
            entries = [str(item).strip() for item in self._latest_history_entries()]

        seen = set()
        unique_entries = []
        for entry in entries:
            if not entry or entry in seen:
                continue
            seen.add(entry)
            unique_entries.append(entry)
        return unique_entries

    def _run_history_search_page(self):
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            match = self._find_history_match(self._prompt_draft, current_text=self._prompt_draft)
            self._prompt_draft = match or self._prompt_draft
            return

        original = self._prompt_draft
        scopes = ("session", "projet", "partout")
        state = {"scope_index": 0, "selected": 0}
        search = TextArea(
            text=original,
            height=1,
            multiline=False,
            prompt="history> ",
        )

        def scope_name():
            return scopes[state["scope_index"]]

        def matches():
            query = search.text.strip().casefold()
            entries = self._history_search_entries(scope_name())
            if not query:
                return entries
            return [entry for entry in entries if query in entry.casefold()]

        def current_match():
            found = matches()
            if not found:
                return ""
            state["selected"] %= len(found)
            return found[state["selected"]]

        def match_text():
            found = matches()
            if not found:
                return "Aucun resultat.\nCtrl+C annuler"
            match = current_match()
            return "\n".join(
                [
                    f"{state['selected'] + 1}/{len(found)} [{scope_name()}]",
                    match,
                    "",
                    "Ctrl+R suivant · Ctrl+S portée · Tab/Esc éditer · Entrée exécuter · Ctrl+C annuler",
                ]
            )

        bindings = KeyBindings()

        @bindings.add("c-r")
        def _next_match(event):
            state["selected"] += 1
            event.app.invalidate()

        @bindings.add("c-s")
        def _cycle_scope(event):
            state["scope_index"] = (state["scope_index"] + 1) % len(scopes)
            state["selected"] = 0
            event.app.invalidate()

        @bindings.add("tab")
        @bindings.add("escape")
        def _accept(event):
            event.app.exit(result=("accept", current_match()))

        @bindings.add("enter", eager=True)
        def _execute(event):
            event.app.exit(result=("execute", current_match()))

        @bindings.add("c-c", eager=True)
        def _cancel(event):
            event.app.exit(result=("cancel", original))

        container = HSplit(
            [
                search,
                Window(
                    FormattedTextControl(match_text),
                    height=Dimension(min=5),
                    wrap_lines=True,
                ),
            ]
        )
        result = Application(
            layout=Layout(container, focused_element=search),
            key_bindings=bindings,
            full_screen=False,
            erase_when_done=True,
            mouse_support=False,
            style=self.prompt_style,
        ).run() or ("cancel", original)
        action, value = result

        if action == "cancel":
            self._prompt_draft = original
            return
        if not value:
            self._prompt_draft = original
            return
        if action == "accept":
            self._prompt_draft = value
            return

        self._prompt_draft = ""
        transient = self._is_transient_command(value)
        if not transient:
            self._render_interaction_separator()
        previous_panel = self.panel
        self._stream_rendered_panel = False
        keep_running = self.process_input(value)
        if not keep_running:
            return
        if transient:
            self._show_panel_command_transient(value, previous_panel)
            self._print_transient_command_result(value)
        elif not self._stream_rendered_panel:
            self.render_panel_state()

    def _exit_prompt_with_command(self, event, command):
        draft = event.current_buffer.text
        if draft.strip():
            self._prompt_draft = draft
        event.app.exit(result=command)

    def _prompt_tab_should_submit(self, text):
        stripped = str(text or "").strip()
        if not stripped:
            return False
        tokens = safe_split(stripped)
        if not tokens:
            return False
        command = tokens[0].lower()
        if command not in COMMAND_SPECS and command not in TRANSIENT_COMMANDS:
            return False
        return stripped == command

    def _prompt_enter_should_submit(self, text):
        return bool(str(text or "").strip())

    def _prompt_key_bindings(self):
        bindings = KeyBindings()

        @bindings.add("enter")
        def _submit_or_newline(event):
            buffer = event.current_buffer
            if not self._prompt_enter_should_submit(buffer.text):
                event.app.invalidate()
                return
            if buffer.document.text_before_cursor.endswith("\\"):
                buffer.delete_before_cursor(1)
                buffer.insert_text("\n")
                return
            buffer.validate_and_handle()

        @bindings.add("c-j")
        def _insert_newline(event):
            event.current_buffer.insert_text("\n")

        @bindings.add("c-l")
        def _redraw_screen(event):
            renderer = getattr(event.app, "renderer", None)
            if renderer and hasattr(renderer, "clear"):
                renderer.clear()
            event.app.invalidate()

        @bindings.add("c-g")
        def _open_external_editor(event):
            event.current_buffer.open_in_editor(validate_and_handle=False)

        @bindings.add("c-d")
        def _exit_session(event):
            event.app.exit(result="/quit")

        @bindings.add("c-c", eager=True)
        def _quit_session(event):
            event.app.exit(result="/quit")

        @bindings.add("escape")
        def _escape_input(event):
            buffer = event.current_buffer
            if getattr(buffer, "complete_state", None) is not None:
                buffer.cancel_completion()
                return
            if str(getattr(buffer, "text", "") or ""):
                buffer.reset()
            event.app.invalidate()

        @bindings.add("tab")
        def _complete_or_submit(event):
            buffer = event.current_buffer
            if self._prompt_tab_should_submit(buffer.text):
                buffer.validate_and_handle()
                return
            if getattr(buffer, "complete_state", None) is not None:
                buffer.complete_next()
                return
            buffer.start_completion(select_first=True)

        @bindings.add("/")
        def _open_slash_completion(event):
            buffer = event.current_buffer
            had_text = bool(str(getattr(buffer, "text", "") or ""))
            buffer.insert_text("/")
            if had_text:
                return
            if hasattr(buffer, "start_completion"):
                buffer.start_completion(select_first=False)

        @bindings.add("c-r")
        def _reverse_history_search(event):
            self._exit_prompt_with_command(event, "/__history_search")

        @bindings.add("s-tab")
        @bindings.add("escape", "m")
        def _cycle_permission_mode(event):
            self._cycle_prompt_permission_mode()
            event.app.invalidate()

        @bindings.add("c-t")
        def _open_jobs(event):
            self._exit_prompt_with_command(event, "/jobs")

        @bindings.add("c-o")
        def _open_transcript(event):
            self._exit_prompt_with_command(event, "/__transcript")

        @bindings.add("escape", "p")
        def _open_model_picker(event):
            self._exit_prompt_with_command(event, "/model")

        @bindings.add("escape", "t")
        def _toggle_thinking(event):
            self._toggle_current_model_thinking()
            event.app.invalidate()

        return bindings

    def _toolbar(self):
        columns = shutil.get_terminal_size(fallback=(80, 24)).columns
        budget = max(20, columns - 1)
        max_value_width = max(8, min(24, columns // 4))
        context = self._toolbar_context_segments()

        segments = []
        for label, value, tone in context:
            value = self._truncate_toolbar_text(value, max_value_width)
            visible_text = f" | {label} {value}"
            segments.append((label, value, tone, len(visible_text)))

        min_footer_width = 4 if self.ux_profile == "debug" else 10
        while segments and 1 + min_footer_width + sum(item[3] for item in segments) > budget:
            segments.pop()

        footer_width = budget - 1 - sum(item[3] for item in segments)
        footer_context = self._truncate_toolbar_text(self.get_footer_context(), footer_width)
        parts = [
            "<bottom-toolbar> </bottom-toolbar>",
            f"<toolbar.label>{html.escape(footer_context)}</toolbar.label>",
        ]
        for label, value, tone, _visible_width in segments:
            value_class = f"toolbar.value.{tone}"
            parts.extend(
                [
                    "<toolbar.sep> | </toolbar.sep>",
                    f"<toolbar.meta>{html.escape(label)}</toolbar.meta>",
                    "<bottom-toolbar> </bottom-toolbar>",
                    f"<{value_class}>{html.escape(value)}</{value_class}>",
                ]
            )
        parts.append("<bottom-toolbar> </bottom-toolbar>")
        return HTML("".join(parts))

    def prompt(self):
        if self.session is None:
            self.session = PromptSession(history=FileHistory(str(self.history_file)))

        hint = self.get_next_action_hint()
        placeholder = HTML(f"<prompt.placeholder>{html.escape(hint)}</prompt.placeholder>") if hint else None
        default_text = self._prompt_draft
        self._prompt_draft = ""

        return self.session.prompt(
            HTML("<prompt.brand>›</prompt.brand> "),
            completer=self.completer,
            complete_while_typing=True,
            auto_suggest=CommandAwareAutoSuggest(),
            multiline=True,
            key_bindings=self._prompt_key_bindings(),
            bottom_toolbar=self._toolbar,
            style=self.prompt_style,
            reserve_space_for_menu=self.chrome.reserve_space_for_menu,
            placeholder=placeholder,
            enable_open_in_editor=True,
            default=default_text,
        )

    def interactive_loop(self):
        self.initialize_interactive()
        self.render_shell_header()
        self._header_rendered = True
        self.render_panel_state()
        while True:
            try:
                raw_text = self.prompt()
            except (EOFError, KeyboardInterrupt):
                print("\n")
                return

            if not raw_text.strip():
                continue

            transient_command = self._is_transient_command(raw_text)
            self._render_submitted_user_message(raw_text)
            if not transient_command:
                self._render_interaction_separator()
            previous_panel = self.panel
            self._stream_rendered_panel = False
            keep_running = self.process_input(raw_text)
            self.advance_tip()
            if not keep_running:
                print()
                return
            if transient_command:
                self._show_panel_command_transient(raw_text, previous_panel)
                self._print_transient_command_result(raw_text)
            if not self._stream_rendered_panel and not transient_command:
                self.render_panel_state()
