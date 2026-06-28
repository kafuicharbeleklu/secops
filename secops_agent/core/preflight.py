"""
Preflight router for the SecOps agent.

Intercepts user input before the LLM round-trip and returns tool calls
directly for well-recognised local intents (VPN, lab setup, directory
brute-force, suggestion selection, local system queries).  If no pattern
matches, returns an empty list and the normal agent loop takes over.

Extracting this logic from SecOpsAgent keeps agent.py focused on the
core ReAct orchestration and makes the routing rules easier to test.
"""

from __future__ import annotations

import platform
import re
import socket
import subprocess
import unicodedata
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any

from secops_agent.core.llm import ToolCallChunk
from secops_agent.core.request_context import RequestDecision, TechnicalGoal

if TYPE_CHECKING:
    from secops_agent.core.tools import ToolRegistry


# ---------------------------------------------------------------------------
# Text normalisation helpers (mirrored from SecOpsAgent)
# ---------------------------------------------------------------------------

def plain_text(user_input: str) -> str:
    """Lower-case, strip accents, collapse whitespace."""
    text = str(user_input or "").lower()
    text = "".join(
        ch
        for ch in unicodedata.normalize("NFD", text)
        if unicodedata.category(ch) != "Mn"
    )
    return " ".join(text.split())


def prefers_french(user_input: str) -> bool:
    """Heuristic: return True when the prompt appears to be in French."""
    text = plain_text(user_input)
    return any(
        marker in text
        for marker in (
            "quelle",
            "quel ",
            "quels ",
            "quelles ",
            "mon systeme",
            "mon système",
            "adresse ip",
            "c'est quoi",
            "explique",
        )
    )


# ---------------------------------------------------------------------------
# System query helpers
# ---------------------------------------------------------------------------

def os_release_pretty_name() -> str:
    path = Path("/etc/os-release")
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("PRETTY_NAME="):
                return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return platform.platform()


def local_ip_addresses() -> list[str]:
    addresses: list[str] = []
    try:
        completed = subprocess.run(
            ["hostname", "-I"],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
        for item in completed.stdout.split():
            if item and item not in addresses:
                addresses.append(item)
    except (OSError, subprocess.SubprocessError):
        pass

    if not addresses:
        try:
            hostname = socket.gethostname()
            for item in socket.gethostbyname_ex(hostname)[2]:
                if item and not item.startswith("127.") and item not in addresses:
                    addresses.append(item)
        except OSError:
            pass
    return addresses


# ---------------------------------------------------------------------------
# URL / target extraction helpers
# ---------------------------------------------------------------------------

def prompt_web_url(user_input: str) -> str:
    url_match = re.search(r"\bhttps?://[^\s\"'<>]+", user_input or "", re.IGNORECASE)
    if url_match:
        return url_match.group(0).rstrip(".,;)")
    ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", user_input or "")
    if ip_match:
        return f"http://{ip_match.group(0)}"
    return ""


def prompt_target_value(user_input: str) -> str:
    url_match = re.search(r"\bhttps?://[^\s\"'<>]+", user_input or "", re.IGNORECASE)
    if url_match:
        return url_match.group(0).rstrip(".,;)")
    ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", user_input or "")
    if ip_match:
        return ip_match.group(0)
    return ""


def url_from_service(service: Any) -> str:
    host = str(getattr(service, "host", "") or "").strip()
    if not host:
        return ""
    try:
        port = int(getattr(service, "port", 0) or 0)
    except (TypeError, ValueError):
        port = 0

    descriptor = " ".join(
        str(getattr(service, attr, "") or "")
        for attr in ("service", "version", "banner")
    ).casefold()
    is_https = port in {443, 8443} or "https" in descriptor or "ssl/http" in descriptor
    is_http = is_https or port in {80, 8000, 8008, 8080, 8081, 8888} or "http" in descriptor
    if not is_http:
        return ""

    scheme = "https" if is_https else "http"
    if (scheme == "http" and port in {0, 80}) or (scheme == "https" and port == 443):
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


def single_download_vpn_config() -> str:
    root = Path("~/Downloads").expanduser()
    try:
        if not root.exists() or not root.is_dir():
            return ""
        configs = sorted(
            path
            for path in root.iterdir()
            if path.is_file() and path.suffix.lower() in {".ovpn", ".conf"}
        )
    except OSError:
        return ""
    return str(configs[0]) if len(configs) == 1 else ""


def lab_provider_from_prompt(user_input: str) -> str:
    text = plain_text(user_input)
    provider_markers = (
        ("tryhackme", ("tryhackme", "try hack me", "thm")),
        ("hackthebox", ("hackthebox", "hack the box", "htb")),
        ("rootme", ("rootme", "root-me")),
        ("portswigger", ("portswigger", "port swigger", "web security academy")),
        ("picoctf", ("picoctf", "pico ctf")),
        ("overthewire", ("overthewire", "over the wire")),
        ("vulnhub", ("vulnhub",)),
        ("ctf", ("ctf", "capture the flag", "challenge")),
    )
    for provider, markers in provider_markers:
        if any(marker in text for marker in markers):
            return provider
    return "lab"


# ---------------------------------------------------------------------------
# PreflightRouter
# ---------------------------------------------------------------------------

class PreflightRouter:
    """Routes well-known user intents to tool calls without an LLM round-trip.

    Call :meth:`local_answer` first for zero-tool text responses (time, IP,
    OS), then :meth:`route` for tool-call shortcuts.  Return values of ``""``
    / ``[]`` mean "no match — let the agent loop handle it normally".

    Parameters
    ----------
    registry:
        The live :class:`ToolRegistry` used to gate tool availability checks.
    structured_memory:
        The agent's :class:`StructuredMemory` (optional).  Used to read the
        known mission state for URL/service lookups.
    last_suggested_actions:
        Mutable reference to the agent's ``_last_suggested_actions`` list.
    suggestion_actions_by_call_id:
        Mutable dict where suggestion-linked calls are registered.
    attempted_action_keys:
        Set of action keys already attempted this session.
    last_suggestion_batch_id:
        Current suggestion batch identifier.
    record_suggestion_selection_fn:
        Callback to record which suggestion indices were selected.
    """

    def __init__(
        self,
        registry: "ToolRegistry",
        structured_memory: Any = None,
        last_suggested_actions: list[Any] | None = None,
        suggestion_actions_by_call_id: dict[str, Any] | None = None,
        attempted_action_keys: set[str] | None = None,
        last_suggestion_batch_id: str = "",
        record_suggestion_selection_fn: Any = None,
        single_download_vpn_config_fn: Any = None,
    ) -> None:
        self._registry = registry
        self._structured_memory = structured_memory
        self._last_suggested_actions: list[Any] = (
            last_suggested_actions if last_suggested_actions is not None else []
        )
        self._suggestion_actions_by_call_id: dict[str, Any] = (
            suggestion_actions_by_call_id if suggestion_actions_by_call_id is not None else {}
        )
        self._attempted_action_keys: set[str] = (
            attempted_action_keys if attempted_action_keys is not None else set()
        )
        self._last_suggestion_batch_id = last_suggestion_batch_id
        self._record_suggestion_selection = record_suggestion_selection_fn
        self._single_download_vpn_config_fn = (
            single_download_vpn_config_fn or single_download_vpn_config
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def local_answer(self, user_input: str, decision: RequestDecision) -> str:
        """Return an instant text answer for LOCAL_SYSTEM queries, or empty string."""
        if decision.technical_goal != TechnicalGoal.LOCAL_SYSTEM:
            return ""

        text = plain_text(user_input)
        french = prefers_french(user_input)

        import datetime

        if any(marker in text for marker in ("what time", "quelle heure", "il est quelle heure", "system time")):
            now = datetime.datetime.now().astimezone()
            stamp = now.strftime("%a %b %d %I:%M:%S %p %Z %Y")
            return f"Il est actuellement {stamp}." if french else f"The current system time is {stamp}."

        if any(
            marker in text
            for marker in (
                "os version",
                "version os",
                "operating system",
                "systeme d'exploitation",
                "système d'exploitation",
                "kernel",
                "uname",
            )
        ):
            os_name = os_release_pretty_name()
            kernel = platform.release()
            arch = platform.machine()
            if french:
                return f"Le système exécute {os_name} avec le noyau {kernel} sur {arch}."
            return f"The system is running {os_name} with kernel {kernel} on {arch}."

        local_ip_intent = any(
            marker in text
            for marker in (
                "my ip",
                "my ip address",
                "mon ip",
                "mon adresse ip",
                "mes adresses ip",
                "adresse ip locale",
                "adresses ip locales",
            )
        )
        target_ip_context = any(
            marker in text
            for marker in ("target ip", "target ip address", "ip cible", "adresse ip cible")
        )
        if local_ip_intent and not target_ip_context:
            addresses = local_ip_addresses()
            if not addresses:
                return (
                    "Je n'ai pas pu déterminer d'adresse IP locale."
                    if french
                    else "I could not determine a local IP address."
                )
            joined = ", ".join(addresses)
            return f"Vos adresses IP locales sont: {joined}." if french else f"Local IP addresses: {joined}."

        if "hostname" in text:
            hostname = socket.gethostname()
            return f"Le nom d'hôte est {hostname}." if french else f"The hostname is {hostname}."

        return ""

    def route(self, user_input: str, decision: RequestDecision) -> list[ToolCallChunk]:
        """Return shortcut tool calls for well-known intents, or empty list."""
        if self._looks_like_context_paste(user_input):
            return []

        # 1. Suggestion selection (highest priority)
        suggestion_calls = self._suggestion_preflight(user_input)
        if suggestion_calls:
            return suggestion_calls

        # 2. Explicit ping / connectivity test (must precede lab check)
        ping_calls = self._ping_preflight(user_input)
        if ping_calls:
            return ping_calls

        # 3. Initial target service discovery
        scan_calls = self._scan_preflight(user_input)
        if scan_calls:
            return scan_calls

        # 4. Web directory discovery
        web_dir_calls = self._web_directory_preflight(user_input)
        if web_dir_calls:
            return web_dir_calls

        # 5. VPN / lab setup
        return self._lab_vpn_preflight(user_input, decision)

    # ------------------------------------------------------------------
    # Private sub-routers
    # ------------------------------------------------------------------

    @staticmethod
    def _looks_like_context_paste(user_input: str) -> bool:
        raw = str(user_input or "")
        if len(raw) < 1200 and raw.count("\n") < 8:
            return False
        text = plain_text(raw)
        context_markers = (
            "this can help",
            "voici",
            "transcript",
            "walkthrough",
            "video",
            "00:",
            "copy and paste",
        )
        return any(marker in text for marker in context_markers)

    def _suggestion_preflight(self, user_input: str) -> list[ToolCallChunk]:
        if not self._last_suggested_actions:
            return []

        raw = str(user_input or "").strip()
        text = plain_text(raw)
        selected_indices: list[int] = []

        continue_patterns = (
            r"^(continue|continuer|next|suivant)$",
            r"^(run|execute|executer|exécuter|lance|lancer|fais|do)\s+(the\s+)?(next|suivant|prochain)(\s+step|\s+etape|\s+étape)?$",
        )
        if any(re.fullmatch(pattern, text) for pattern in continue_patterns):
            for index, action in enumerate(self._last_suggested_actions):
                if str(getattr(action, "method", "")) == "missing_tool_install":
                    continue
                if str(getattr(action, "risk", "")).casefold() == "high":
                    continue
                selected_indices = [index]
                break
        else:
            all_pattern = r"(?:all|tout|tous|toutes)"
            except_match = re.fullmatch(
                rf"(?:run\s+|execute\s+|executer\s+|exécuter\s+|lance\s+|lancer\s+|fais\s+|do\s+)?{all_pattern}\s+(?:except|sauf)\s+(.+)",
                text,
            )
            all_match = re.fullmatch(
                rf"(?:run\s+|execute\s+|executer\s+|exécuter\s+|lance\s+|lancer\s+|fais\s+|do\s+)?{all_pattern}",
                text,
            )
            if except_match:
                excluded = {int(m) - 1 for m in re.findall(r"\b\d+\b", except_match.group(1))}
                selected_indices = [
                    i for i in range(len(self._last_suggested_actions)) if i not in excluded
                ]
            elif all_match:
                selected_indices = list(range(len(self._last_suggested_actions)))
            else:
                numbers = [int(m) for m in re.findall(r"\b\d+\b", text)]
                single_match = re.fullmatch(
                    r"(?:#|option\s+|choice\s+|choix\s+|action\s+)?(\d+)[\).]?",
                    text,
                )
                batch_intent = any(
                    token in text
                    for token in ("run", "execute", "executer", "exécuter", "lance", "lancer", "fais", "do")
                )
                if single_match:
                    selected_indices = [int(single_match.group(1)) - 1]
                elif len(numbers) == 1 and batch_intent:
                    selected_indices = [numbers[0] - 1]
                elif len(numbers) > 1:
                    selected_indices = [n - 1 for n in numbers]

        valid = {i for i in selected_indices if 0 <= i < len(self._last_suggested_actions)}
        if valid and self._record_suggestion_selection:
            self._record_suggestion_selection(valid)

        calls: list[ToolCallChunk] = []
        seen_keys: set[str] = set()
        for index in selected_indices:
            if index < 0 or index >= len(self._last_suggested_actions):
                continue
            action = self._last_suggested_actions[index]
            if (
                not action.tool_name
                or action.key in self._attempted_action_keys
                or action.key in seen_keys
            ):
                continue
            if not self._registry.get_tool(action.tool_name):
                continue
            call = ToolCallChunk(
                name=action.tool_name,
                arguments=dict(action.arguments),
                id=f"{action.tool_name}_{uuid.uuid4().hex[:8]}",
            )
            calls.append(call)
            self._suggestion_actions_by_call_id[call.id] = (
                action,
                index + 1,
                self._last_suggestion_batch_id,
            )
            seen_keys.add(action.key)
        return calls

    def _ping_preflight(self, user_input: str) -> list[ToolCallChunk]:
        """Route 'ping / test de connectivité <ip>' directly to ping_host."""
        if not self._registry.get_tool("ping_host"):
            return []
        text = plain_text(user_input)
        ping_intent = any(
            token in text
            for token in (
                "ping",
                "test de connectivite",
                "test de connectivité",
                "test connectivity",
                "check connectivity",
                "reachable",
                "joignable",
                "alive",
                "est-il actif",
                "est il actif",
            )
        )
        if not ping_intent:
            return []
        # Need an IP or hostname target
        target = prompt_target_value(user_input)
        if not target:
            return []
        return [
            ToolCallChunk(
                name="ping_host",
                arguments={"target": target},
                id=f"ping_host_{uuid.uuid4().hex[:8]}",
            )
        ]

    def _scan_preflight(self, user_input: str) -> list[ToolCallChunk]:
        """Route explicit target discovery prompts directly to nmap_scan."""
        if not self._registry.get_tool("nmap_scan"):
            return []

        target = prompt_target_value(user_input)
        if not target:
            return []

        text = plain_text(user_input)
        scan_intent = any(
            token in text
            for token in (
                "scan the machine",
                "scan machine",
                "scan open ports",
                "scan des ports",
                "open ports",
                "ports open",
                "how many ports",
                "combien de ports",
                "port scan",
                "nmap",
            )
        )
        service_intent = any(
            token in text
            for token in (
                "service version",
                "service versions",
                "version apache",
                "what version of apache",
                "apache is running",
                "what service",
                "service is running",
                "port 22",
                "banner",
                "fingerprint",
            )
        )
        guided_lab_questions = (
            "answer the questions" in text
            and "target ip" in text
            and any(token in text for token in ("scan", "ports", "service", "apache"))
        )
        if not (scan_intent or service_intent or guided_lab_questions):
            return []

        arguments: dict[str, Any] = {"target": target}
        if service_intent or guided_lab_questions:
            arguments["scan_type"] = "version"
        return [
            ToolCallChunk(
                name="nmap_scan",
                arguments=arguments,
                id=f"nmap_scan_{uuid.uuid4().hex[:8]}",
            )
        ]

    def _web_directory_preflight(self, user_input: str) -> list[ToolCallChunk]:
        text = plain_text(user_input)
        explicit_tool = any(token in text for token in ("gobuster", "go buster", "dirb", "ffuf"))
        directory_intent = (
            any(token in text for token in ("find directories", "find directory", "hidden directory"))
            or ("director" in text and "web" in text)
            or ("repertoire" in text and "web" in text)
        )
        if not (explicit_tool or directory_intent):
            return []
        if not self._registry.get_tool("dir_brute"):
            return []

        url = self._known_web_url(user_input)
        if not url:
            return []
        return [
            ToolCallChunk(
                name="dir_brute",
                arguments={"url": url},
                id=f"dir_brute_{uuid.uuid4().hex[:8]}",
            )
        ]

    def _lab_vpn_preflight(
        self, user_input: str, decision: RequestDecision
    ) -> list[ToolCallChunk]:
        text = plain_text(user_input)
        provider = lab_provider_from_prompt(user_input)
        target = prompt_target_value(user_input)

        has_vpn_context = any(token in text for token in ("vpn", "openvpn", ".ovpn"))
        wants_vpn_disconnect = has_vpn_context and any(
            token in text
            for token in (
                "deactivate", "desactivate", "désactive", "désactiver",
                "disconnect", "stop", "arret", "arrêt", "arrete", "arrête",
                "kill", "shutdown",
            )
        )
        wants_vpn_status = has_vpn_context and (
            any(
                token in text
                for token in (
                    "still active", "still activate", "vpn still",
                    "status", "statut", "etat", "état",
                    "connected", "connecte", "connecté",
                )
            )
            or bool(re.search(
                r"\b(?:is|est|reste|toujours)\b.*\bvpn\b.*\b(?:active|actif|connecte|connecté)\b",
                text,
            ))
            or bool(re.search(
                r"\bvpn\b.*\b(?:is|est|reste|toujours)\b.*\b(?:active|actif|connecte|connecté)\b",
                text,
            ))
        )

        if wants_vpn_disconnect and self._registry.get_tool("disconnect_vpn"):
            return [
                ToolCallChunk(
                    name="disconnect_vpn",
                    arguments={},
                    id=f"disconnect_vpn_{uuid.uuid4().hex[:8]}",
                )
            ]
        if wants_vpn_status and self._registry.get_tool("vpn_status"):
            return [
                ToolCallChunk(
                    name="vpn_status",
                    arguments={},
                    id=f"vpn_status_{uuid.uuid4().hex[:8]}",
                )
            ]

        has_config_context = any(
            token in text
            for token in ("config", "configuration", "download", "downloads", "telecharge")
        )
        has_lab_context = provider != "lab" or any(
            token in text
            for token in ("ctf", "challenge", "lab", "room", "box", "machine", "target", "cible")
        )
        has_readiness_context = any(
            token in text
            for token in (
                "setup", "prepare", "preparer", "préparer", "ready", "readiness",
                "verifie", "vérifie", "environnement", "environment",
                "wordlist", "wordlists", "tools", "tooling", "outils", "vpn", "openvpn",
            )
        )
        is_lab_readiness = decision.technical_goal == TechnicalGoal.LAB_READINESS

        if not (
            (has_vpn_context and has_config_context)
            or (has_lab_context and has_readiness_context)
            or (is_lab_readiness and has_lab_context)
        ):
            return []

        wants_connect = any(
            token in text
            for token in (
                "active", "activer", "activate", "activation",
                "connecte", "connecter", "demarre", "démarre",
                "execute", "executer", "exécute", "lance", "lancer", "start",
            )
        )
        has_authorized_lab = has_lab_context or provider != "lab"
        if wants_connect and (has_authorized_lab or (has_vpn_context and has_config_context)):
            arguments: dict[str, Any] = {"directory": "~/Downloads"}
            config_path = self._single_download_vpn_config_fn()
            if config_path:
                arguments["config_path"] = config_path
            return [
                ToolCallChunk(
                    name="connect_vpn_config",
                    arguments=arguments,
                    id=f"connect_vpn_config_{uuid.uuid4().hex[:8]}",
                )
            ]

        return [
            ToolCallChunk(
                name="lab_setup_check",
                arguments={
                    "provider": provider,
                    "directory": "~/Downloads",
                    **({} if not target else {"target": target}),
                },
                id=f"lab_setup_check_{uuid.uuid4().hex[:8]}",
            )
        ]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _known_web_url(self, user_input: str = "") -> str:
        prompt_url = prompt_web_url(user_input)
        if prompt_url:
            return prompt_url

        mission = (
            getattr(self._structured_memory, "mission", None)
            if self._structured_memory
            else None
        )
        if not mission:
            return ""

        for target in getattr(mission, "targets", []) or []:
            value = str(getattr(target, "value", "") or "").strip()
            if value.startswith(("http://", "https://")):
                return value

        for value in getattr(getattr(mission, "scope", None), "in_scope", []) or []:
            scoped = str(value or "").strip()
            if scoped.startswith(("http://", "https://")):
                return scoped

        for service in getattr(mission, "services", []) or []:
            url = url_from_service(service)
            if url:
                return url

        for host in getattr(mission, "hosts", []) or []:
            for service in getattr(host, "services", []) or []:
                url = url_from_service(service)
                if url:
                    return url

        return ""
