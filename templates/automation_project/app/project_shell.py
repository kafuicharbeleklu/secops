import json
import os
import re
import shlex
import shutil
import sys
import threading
import time
import html
from datetime import datetime
from dataclasses import replace
from pathlib import Path

from colorama import Style as AnsiStyle
from prompt_toolkit import PromptSession
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.history import FileHistory
from prompt_toolkit.shortcuts import choice

from app.agent_loop import AgentLoop
from app.branding import SHELL_CHROME, TERMINAL_PALETTE
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
    "/status": "Afficher l'etat courant de la session",
    "/case": "Lister, afficher ou activer un cas memoire",
    "/target": "Lister, afficher ou definir la cible",
    "/phase": "Afficher ou changer la phase pentest",
    "/model": "Afficher ou changer le modele LLM de la session",
    "/scope": "Definir ou afficher le scope autorise (IPs/CIDRs/domaines/URLs)",
    "/permissions": "Afficher ou changer le mode d'autorisation des commandes",
    "/compact": "Compacter le contexte agent pour reduire les tokens",
    "/side": "Poser une question laterale sans modifier le contexte agent",
    "/menu": "Ouvrir la palette de commandes",
    "/tools": "Lister ou installer les outils pentest disponibles",
    "/jobs": "Afficher les taches en attente, en cours ou terminees",
    "/learn": "Afficher les apprentissages recents de la session",
    "/findings": "Afficher les decouvertes accumulees",
    "/plan": "Afficher le plan d'attaque genere depuis les findings",
    "/export": "Exporter les decouvertes (json, md ou les deux)",
    "/report": "Generer un rapport de pentest structure",
    "/session": "Sauvegarder, lister ou reprendre une session pentest",
    "/clear": "Effacer l'ecran et reafficher le header",
    "/quit": "Quitter le shell",
}

TIPS = [
    "Decris ton objectif, une cible, un service ou une action locale.",
    "Exemple: nmap 10.10.10.10, analyse SMB, ou mets a jour le systeme local.",
    "Utilise /case list puis /case <slug> pour activer une memoire de lab si utile.",
    "Utilise /phase pour voir ou changer la phase pentest (recon, enum, exploit...).",
    "Utilise /tools pour voir les outils pentest disponibles sur cette machine.",
    "Utilise /menu pour ouvrir la palette de commandes sans polluer l'historique.",
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
    "/menu",
}


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
        self._live_stream_state = None
        self._session_start = time.time()
        self.command_permission_mode = (
            os.getenv("SECOPS_COMMAND_MODE", "ask").strip().lower() or "ask"
        )
        if self.command_permission_mode not in {"ask", "session", "deny"}:
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
            command_specs=COMMAND_SPECS,
            command_aliases={},
            legacy_aliases={},
            tips=TIPS,
            palette=TERMINAL_PALETTE,
            keyword_completion_commands=("/case",),
        )

        self.set_panel("", [], tone="muted", variant="plain")

    def get_keyword_catalog(self):
        catalog = self.knowledge_store.catalog()
        for tool in self.tool_registry.installed_tools:
            catalog[tool.name] = tool.description
        for target in self.targets:
            catalog[target.address] = target.target_type.value
        return catalog

    def _set_plain_panel(self, lines, tone="info", max_lines=None):
        self.set_panel("", lines, tone=tone, max_lines=max_lines, variant="plain")

    def _set_transcript_panel(self, title, lines, tone="info", max_lines=None):
        self.set_panel(
            title,
            lines,
            tone=tone,
            max_lines=max_lines,
            variant="transcript",
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
            "<toolbar.meta>Entrée valider</toolbar.meta>"
            "<toolbar.sep> · </toolbar.sep>"
            "<toolbar.meta>Esc annuler</toolbar.meta>"
        )

    def _choose_permission_option(self, heading, fields, options, *, default=None):
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            return None

        message_lines = [heading]
        for label, value in fields:
            if value:
                message_lines.append(f"  {label:<8}: {value}")

        try:
            selection = choice(
                "\n".join(message_lines) + "\n",
                options=options,
                default=default,
                style=self.prompt_style,
                symbol="›",
                bottom_toolbar=self._permission_toolbar(),
                show_frame=False,
            )
            self._erase_permission_prompt(len(message_lines), len(options))
            return selection
        except (EOFError, KeyboardInterrupt):
            self._erase_permission_prompt(len(message_lines), len(options))
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
            profile = replace(
                profile,
                thinking_level="" if override == "off" else override,
            )
        self.llm_client.configure_profile(profile)
        return profile

    def _can_use_transient_page(self):
        return sys.stdin.isatty() and sys.stdout.isatty()

    def _is_transient_command(self, raw_text):
        tokens = safe_split(raw_text.strip())
        return bool(tokens and tokens[0].lower() in TRANSIENT_COMMANDS)

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

    def _transient_toolbar(self):
        return HTML(
            "<toolbar.meta>↑↓ choisir</toolbar.meta>"
            "<toolbar.sep> · </toolbar.sep>"
            "<toolbar.meta>Entrée valider</toolbar.meta>"
            "<toolbar.sep> · </toolbar.sep>"
            "<toolbar.meta>Esc retour</toolbar.meta>"
        )

    def _run_transient_choice_page(self, title, body_lines, options, *, default=None):
        self._clear_transient_screen()
        self.render_shell_header()
        message = [title]
        message.extend(body_lines or [])
        try:
            return choice(
                "\n".join(message).rstrip() + "\n",
                options=options,
                default=default,
                style=self.prompt_style,
                symbol="›",
                bottom_toolbar=self._transient_toolbar(),
                show_frame=False,
            )
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
            f"Routage modele: {'auto' if self.model_auto_routing else 'manuel'}",
            f"Function calling: {'natif' if self.llm_client.use_native_tools else 'json'}",
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
                f"Routage auto: {'actif' if self.model_auto_routing else 'inactif'}",
                f"Function calling natif: {'actif' if self.llm_client.use_native_tools else 'inactif'}",
                f"Thinking: {profile.thinking_level or 'off'}",
                "Changement pour cette session uniquement.",
                "Pour persister: definir GEMINI_MODEL dans .env.",
                "",
                "Profils disponibles:",
            ]
            for alias, model, description in MODEL_PRESETS:
                marker = "*" if model == self.gemini_runtime.model or (alias == "auto" and self.model_auto_routing) else "-"
                lines.append(f"  {marker} {alias:<10} {model} - {description}")
            lines.append("Exemple: /model gemma")
            self.set_panel("Modele LLM", lines, tone="info")
            return

        raw_model = " ".join(args)
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
            routed = route_model("", self.engagement.phase.value)
            previous, profile = self._activate_model(routed, auto=True)
            if self._can_use_transient_page():
                self._return_to_main_page(self.panel)
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

        previous, profile = self._activate_model(model, auto=False)
        if self._can_use_transient_page():
            self._return_to_main_page(self.panel)
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

    def _activate_model(self, model, *, auto=False, thinking_level=None):
        previous = self.gemini_runtime.model
        self.model_auto_routing = auto
        if thinking_level is not None:
            self.model_thinking_overrides[model] = thinking_level
        self.gemini_runtime = replace(self.gemini_runtime, model=model)
        profile = self._apply_model_profile()
        self.last_gemini_error = None
        return previous, profile

    def _run_model_menu_page(self):
        previous_panel = self.panel
        options = []
        for alias, model, description in MODEL_PRESETS:
            options.append((alias, f"{alias:<10} {model} - {description}"))
        options.append(("cancel", "Annuler"))
        selected = self._run_transient_choice_page(
            "Modele LLM",
            ["Choisis le modele a utiliser pour cette session."],
            options,
            default="auto" if self.model_auto_routing else "gemma",
        )
        if selected and selected != "cancel":
            model = resolve_model_name(selected)
            if model == "auto":
                model = route_model("", self.engagement.phase.value)
                self._activate_model(model, auto=True)
            elif model:
                thinking_level = self._choose_model_thinking_page(model)
                self._activate_model(model, auto=False, thinking_level=thinking_level)
        self._return_to_main_page(previous_panel)

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
        if not self._should_track_tool_job(name, args):
            return None
        key = self._tool_job_key(name, args)
        if key in self._active_tool_jobs:
            return self._active_tool_jobs[key]
        details = []
        command = args.get("command", "")
        if command:
            details.append(f"commande: {command}")
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
            self.jobs.update(job_id, status="cancelled", result="permission refusee")
        elif event_type == "tool_policy_blocked":
            remediation = event.get("remediation") or event.get("error", "")
            self.jobs.update(job_id, status="cancelled", result=remediation[:180])
        elif event_type == "tool_error":
            self.jobs.update(job_id, status="failed", result=str(event.get("error", "")))

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
            "ask": "validation",
            "session": "session",
            "deny": "desactive",
        }.get(self.command_permission_mode, self.command_permission_mode)

    def _set_command_permission_mode(self, mode):
        normalized = (mode or "").strip().casefold()
        aliases = {
            "validation": "ask",
            "ask": "ask",
            "demande": "ask",
            "session": "session",
            "allow": "session",
            "autorise": "session",
            "autoriser": "session",
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

        if event["type"] == "thought":
            return
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
        self._set_transcript_panel(
            rendered["title"],
            rendered["lines"],
            tone=rendered["tone"],
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
        case_context = self._build_agent_context(prompt)
        self.agent_loop.active_case_label = self.active_case.label if self.active_case else ""
        try:
            events = self._collect_agent_stream(
                self.agent_loop.run(prompt, case_context)
            )
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
        self._set_transcript_panel(
            rendered["title"],
            rendered["lines"],
            tone=rendered["tone"],
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

        self.engagement.set_phase(phase, "Changement manuel via /phase.")
        if self._can_use_transient_page():
            self._return_to_main_page(previous_panel or self.panel)
            return
        self.set_panel("Phase", [f"Phase changee: {self.engagement.phase_label}"], tone="success")

    def _run_phase_menu_page(self):
        previous_panel = self.panel
        options = []
        for phase, meta in PHASE_METADATA.items():
            marker = "*" if phase == self.engagement.phase else " "
            options.append(
                (
                    phase.value,
                    f"{marker} {meta.get('label', phase.value):<18} {meta.get('objective', '')}",
                )
            )
        options.append(("cancel", "Retour"))
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
            self._return_to_main_page(previous_panel)
            return
        phase = parse_phase(selected)
        if not phase:
            self._return_to_main_page(previous_panel)
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
            self._return_to_main_page(previous_panel or self.panel)
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
        options.append(("cancel", "Retour"))
        selected = self._run_transient_choice_page(
            "Scope autorise",
            self._scope_status_lines(),
            options,
            default="target" if target_label else "manual",
        )
        if selected in (None, "cancel"):
            self._return_to_main_page(previous_panel)
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
                self._return_to_main_page(previous_panel)

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
            lines = ["Mode inconnu. Valides: ask, session, deny."]
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
            "ask=validation, session=autorisation globale pour la session, deny=execution bloquee.",
        ]
        if self._can_use_transient_page():
            self._return_to_main_page(previous_panel)
            return
        self.set_panel("Permissions", lines, tone="success")

    def _permissions_status_lines(self):
        allowed = sorted(getattr(self.tool_executor, "_session_allow_commands", set()))
        lines = [
            f"Mode commandes: {self._command_mode_label()}",
            "ask: validation interactive avant execution",
            "session: executions autorisees pour la session",
            "deny: aucune commande outil n'est executee",
        ]
        if allowed:
            lines.append(f"Executables autorises: {', '.join(allowed)}")
        return lines

    def _run_permissions_menu_page(self):
        previous_panel = self.panel
        options = [
            ("ask", "Validation a chaque commande"),
            ("session", "Autoriser les commandes pour la session"),
            ("deny", "Bloquer l'execution de commandes"),
            ("cancel", "Retour"),
        ]
        selected = self._run_transient_choice_page(
            "Permissions",
            self._permissions_status_lines(),
            options,
            default=self.command_permission_mode,
        )
        if selected not in (None, "cancel"):
            self._set_command_permission_mode(selected)
        self._return_to_main_page(previous_panel)

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

    def _handle_side(self, args):
        prompt = " ".join(args).strip()
        if not prompt:
            self.set_panel(
                "Question laterale",
                ["Usage: /side <question>", "La question n'est pas ajoutee au contexte agent."],
                tone="warn",
            )
            return

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
                f"QUESTION: {prompt}",
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
            self._set_transcript_panel("Question laterale", lines, tone="warn")
            return
        lines = answer.splitlines() or [answer]
        self._set_transcript_panel("Question laterale", lines, tone="info")

    def _run_command_palette(self):
        previous_panel = self.panel
        palette_commands = [
            ("/status", "Etat courant"),
            ("/model", "Choix du modele"),
            ("/phase", "Choix de phase"),
            ("/scope", "Scope autorise"),
            ("/permissions", "Permissions commandes"),
            ("/compact", "Compacter le contexte"),
            ("/target", "Cible active"),
            ("/case", "Cas memoire"),
            ("/tools", "Inventaire outils"),
            ("/jobs", "Jobs"),
            ("/learn", "Apprentissage"),
            ("/findings", "Decouvertes"),
            ("/plan", "Plan d'attaque"),
            ("/session", "Session courante"),
            ("/help", "Aide"),
        ]
        if not self._can_use_transient_page():
            lines = [f"{command:<14} {description}" for command, description in palette_commands]
            self.set_panel("Palette", lines, tone="info")
            return

        options = [(command, f"{command:<14} {description}") for command, description in palette_commands]
        options.append(("cancel", "Retour"))
        selected = self._run_transient_choice_page(
            "Palette de commandes",
            ["Choisis une vue ou une configuration a ouvrir."],
            options,
            default="/status",
        )
        if selected in (None, "cancel"):
            self._return_to_main_page(previous_panel)
            return
        if selected in TRANSIENT_COMMANDS and selected != "/menu":
            self.dispatch_command(selected, [])
            return

        self.dispatch_command(selected, [])
        self._run_transient_notice_page(
            self.panel.title or selected,
            list(self.panel.lines),
            tone=self.panel.tone,
            previous_panel=previous_panel,
        )

    def _print_help(self):
        self.set_panel(
            "Commandes",
            [
                "/case [list|slug]     lister, afficher ou activer un cas memoire",
                "/status               afficher l'etat courant",
                "/case off             desactiver le cas",
                "/target [list|ip/url] lister, afficher ou definir la cible",
                "/phase [nom]          afficher ou changer la phase pentest",
                "/model [nom|auto|bench] afficher, router ou benchmarker le modele LLM",
                "/scope [ip/cidr/domaine/url|off]  definir ou afficher le scope autorise",
                "/permissions [ask|session|deny] gerer les autorisations outils",
                "/compact [n]          compacter le contexte agent, garder n messages recents",
                "/side <question>      question laterale sans memoire agent",
                "/menu                 ouvrir la palette de commandes",
                "/tools                lister les outils",
                "/tools install <...>  installer plusieurs outils avec validation unique",
                "/jobs                 afficher les taches",
                "/learn                afficher les apprentissages recents",
                "/findings             afficher les decouvertes accumulees",
                "/plan                 afficher le plan d'attaque",
                "/export [json|md]     exporter les decouvertes",
                "/report               generer un rapport pentest",
                "/session [save|list|resume] gerer les sessions",
                "/clear                effacer l'ecran",
                "/help                 afficher cette aide",
                "/quit                 quitter le shell",
                "texte libre           parler directement a SECOPS",
            ],
            tone="info",
        )

    def dispatch_command(self, command, args):
        if command == "/quit":
            self._print_session_summary()
            return False

        if command == "/help":
            self._print_help()
            return True

        if command == "/status":
            self._print_status()
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

        if command == "/permissions":
            self._handle_permissions(args)
            return True

        if command == "/compact":
            self._handle_compact(args)
            return True

        if command == "/side":
            self._handle_side(args)
            return True

        if command == "/menu":
            self._run_command_palette()
            return True

        if command == "/tools":
            if args and args[0].casefold() in {"install", "installer"}:
                self._prepare_tools_install(args[1:])
                return True
            inv = self.tool_registry.format_inventory()
            lines = inv.split("\n") if inv else ["Aucun outil pentest connu."]
            self.set_panel("Outils pentest", lines[:20], tone="info")
            return True

        if command == "/jobs":
            self._print_jobs()
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
            self._export_findings(args)
            return True

        if command == "/report":
            self._generate_report(args)
            return True

        if command == "/scope":
            self._handle_scope(args)
            return True

        if command == "/session":
            self._handle_session(args)
            return True

        self.set_panel(
            "Commande inconnue",
            [f"{command} n'est pas reconnue.", "Tape /help pour voir les commandes."],
            tone="error",
        )
        return True

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
            if len(args) < 2:
                self.set_panel("Session", ["Usage: /session resume <id>"], tone="warn")
                return
            session_id = args[1]
            state = load_session(self.workspace, session_id)
            if not state:
                self.set_panel("Session", [f"Session '{session_id}' introuvable."], tone="error")
                return
            # Restore engagement state
            from app.methodology import parse_phase
            phase = parse_phase(state.phase)
            if phase:
                self.engagement.set_phase(phase, "Restauration de session.")
            for tool in state.tools_used:
                self.engagement.record_tool_use(tool)
            # Restore scope
            self.tool_executor.set_scope(state.scope)
            # Restore agent loop state if available
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
            # Restore findings state from file if it exists
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
            return

        self.set_panel(
            "Session",
            ["Usage: /session [save [nom]|list|resume <id>]"],
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
        now = datetime.now().strftime("%H:%M")
        cols = shutil.get_terminal_size(fallback=(80, 24)).columns
        label = f" {now} "
        usable_width = max(24, cols - 2)
        side = max(4, (usable_width - len(label)) // 2)
        line = f"{self.palette.muted_ansi}{'\u2500' * side}{label}{'\u2500' * side}{AnsiStyle.RESET_ALL}"
        print()
        print(line)
        print()

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

    def _toolbar(self):
        context = [
            ("phase", self.engagement.phase_label, "success"),
        ]
        target_label = self.active_target.label if self.active_target else (self.current_target or "")
        if target_label:
            context.append(("cible", target_label, "info"))
        if self.findings_store.count:
            context.append(("findings", str(self.findings_store.count), "success"))
        if self.jobs.active_count:
            context.append(("jobs", str(self.jobs.active_count), "warn"))

        parts = [
            "<bottom-toolbar> </bottom-toolbar>",
            f"<toolbar.label>{html.escape(self.get_footer_context())}</toolbar.label>",
        ]
        for label, value, tone in context:
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

        return self.session.prompt(
            HTML("<prompt.brand>›</prompt.brand> "),
            completer=self.completer,
            complete_while_typing=True,
            auto_suggest=AutoSuggestFromHistory(),
            bottom_toolbar=self._toolbar,
            style=self.prompt_style,
            reserve_space_for_menu=self.chrome.reserve_space_for_menu,
            placeholder=placeholder,
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
            if not transient_command:
                self._render_interaction_separator()
            self._stream_rendered_panel = False
            keep_running = self.process_input(raw_text)
            self.advance_tip()
            if not keep_running:
                print()
                return
            if not self._stream_rendered_panel and not transient_command:
                self.render_panel_state()
