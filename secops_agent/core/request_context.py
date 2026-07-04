"""
Deterministic request classification for SecOps agent orchestration.

This module separates the technical shape of a request from the environment
where it happens. A CTF, a private hypervisor lab, and an authorized client
assessment can all ask the same narrow question, so environment hints must not
drive tool chaining decisions by themselves.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class TechnicalGoal(str, Enum):
    UNKNOWN = "unknown"
    LOCAL_SYSTEM = "local_system"
    RECONNAISSANCE = "reconnaissance"
    PORT_SCAN = "port_scan"
    SERVICE_ENUM = "service_enum"
    WEB_DIR_ENUM = "web_dir_enum"
    API_ENUM = "api_enum"
    VULN_VALIDATION = "vuln_validation"
    EXPLOIT_STEP = "exploit_step"
    PRIV_ESC = "priv_esc"
    LAB_READINESS = "lab_readiness"
    REPORT = "report"


class UserIntent(str, Enum):
    UNKNOWN = "unknown"
    SOCIAL = "social"
    ANSWER_QUESTION = "answer_question"
    RUN_SINGLE_TOOL = "run_single_tool"
    PROPOSE_PLAN = "propose_plan"
    APPROVED_BATCH = "approved_batch"
    EXECUTE_SELECTED = "execute_selected"


class RequestRisk(str, Enum):
    PASSIVE = "passive"
    ACTIVE_LOW = "active_low"
    ACTIVE_HIGH = "active_high"
    EXPLOIT = "exploit"
    DESTRUCTIVE = "destructive"


class ScopeStatus(str, Enum):
    MISSING = "missing"
    EXPLICIT = "explicit"
    INFERRED_FROM_SESSION = "inferred_from_session"
    OUT_OF_SCOPE = "out_of_scope"


class EnvironmentHint(str, Enum):
    UNKNOWN = "unknown"
    CTF_ONLINE = "ctf_online"
    PRIVATE_LAB = "private_lab"
    AUTHORIZED_ORG = "authorized_org"


@dataclass(frozen=True)
class RequestDecision:
    technical_goal: TechnicalGoal = TechnicalGoal.UNKNOWN
    user_intent: UserIntent = UserIntent.UNKNOWN
    risk: RequestRisk = RequestRisk.PASSIVE
    scope_status: ScopeStatus = ScopeStatus.MISSING
    environment_hint: EnvironmentHint = EnvironmentHint.UNKNOWN
    target: str = ""
    reasons: tuple[str, ...] = field(default_factory=tuple)

    @property
    def should_suppress_followups(self) -> bool:
        """Return true for narrow answer turns where proposals would add noise.

        Covers focused factual questions and pure social turns (greetings,
        thanks): in both cases tool suggestions would be off-topic noise.
        """
        return self.user_intent in (UserIntent.ANSWER_QUESTION, UserIntent.SOCIAL)

    def to_context(self) -> dict[str, str | bool]:
        return {
            "technical_goal": self.technical_goal.value,
            "user_intent": self.user_intent.value,
            "risk": self.risk.value,
            "scope_status": self.scope_status.value,
            "environment_hint": self.environment_hint.value,
            "target": self.target,
            "focused_answer_turn": self.should_suppress_followups,
        }


@dataclass(frozen=True)
class ToolSchemaSelection:
    """Minimal provider tool exposure for the current technical goal."""

    tool_names: tuple[str, ...]
    reason: str = ""


class ToolSchemaSelector:
    """Select a small, goal-specific tool schema for the provider.

    This is intentionally environment-agnostic. CTF/private-lab/client labels
    should not decide tool availability; the current technical goal should.
    """

    _TOOLS_BY_GOAL: dict[TechnicalGoal, tuple[str, ...]] = {
        TechnicalGoal.LOCAL_SYSTEM: (),
        TechnicalGoal.LAB_READINESS: (
            "lab_setup_check",
            "vpn_status",
            "connect_vpn_config",
            "disconnect_vpn",
            "sysinfo",
        ),
        TechnicalGoal.PORT_SCAN: (
            "ping_host",
            "port_check",
            "nmap_scan",
            "traceroute",
        ),
        TechnicalGoal.RECONNAISSANCE: (
            "dns_lookup",
            "whois_lookup",
            "subdomain_enum",
            "ping_host",
            "nmap_scan",
            "http_headers",
            "tech_detect",
        ),
        TechnicalGoal.SERVICE_ENUM: (
            "nmap_scan",
            "http_headers",
            "tech_detect",
            "ssl_check",
            "ssl_audit",
            "searchsploit",
        ),
        TechnicalGoal.WEB_DIR_ENUM: (
            "dir_brute",
        ),
        TechnicalGoal.API_ENUM: (
            "http_headers",
            "tech_detect",
            "dir_brute",
        ),
        TechnicalGoal.VULN_VALIDATION: (
            "cve_lookup",
            "searchsploit",
            "exploit_info",
            "nikto_scan",
            "sql_injection_test",
            "xss_test",
            "waf_detect",
            "ssl_audit",
        ),
        TechnicalGoal.REPORT: (),
        TechnicalGoal.EXPLOIT_STEP: (
            "http_request",
            "fetch_url",
            "write_file",
            "start_listener",
            "webshell_exec",
            "generate_payload",
            "run_shell",
            "searchsploit",
            "exploit_info",
        ),
        TechnicalGoal.PRIV_ESC: (
            "run_shell",
            "webshell_exec",
            "fetch_url",
            "write_file",
            "find_files",
            "file_analyze",
        ),
        TechnicalGoal.UNKNOWN: (),
    }

    def select(self, decision: RequestDecision) -> ToolSchemaSelection:
        names = self._TOOLS_BY_GOAL.get(decision.technical_goal, ())
        # Only DESTRUCTIVE risk blanks out schemas; EXPLOIT risk is gated
        # per-tool by the PermissionEngine approval flow.
        if decision.risk == RequestRisk.DESTRUCTIVE:
            names = ()
        return ToolSchemaSelection(
            tool_names=tuple(names),
            reason=f"goal:{decision.technical_goal.value};risk:{decision.risk.value}",
        )


def classify_request(user_input: str, mission: Any | None = None) -> RequestDecision:
    raw = str(user_input or "")
    text = _plain(raw)
    target = _extract_target(raw)
    reasons: list[str] = []

    environment_hint = _environment_hint(text)
    if environment_hint != EnvironmentHint.UNKNOWN:
        reasons.append(f"environment:{environment_hint.value}")

    technical_goal = _technical_goal(text)
    if technical_goal != TechnicalGoal.UNKNOWN:
        reasons.append(f"goal:{technical_goal.value}")

    user_intent = _user_intent(text, technical_goal)
    if user_intent != UserIntent.UNKNOWN:
        reasons.append(f"intent:{user_intent.value}")

    risk = _risk(technical_goal, text)
    if risk != RequestRisk.PASSIVE:
        reasons.append(f"risk:{risk.value}")

    scope_status = _scope_status(target, mission)
    if scope_status != ScopeStatus.MISSING:
        reasons.append(f"scope:{scope_status.value}")

    return RequestDecision(
        technical_goal=technical_goal,
        user_intent=user_intent,
        risk=risk,
        scope_status=scope_status,
        environment_hint=environment_hint,
        target=target,
        reasons=tuple(reasons),
    )


def _plain(text: str) -> str:
    normalized = unicodedata.normalize("NFKD", text or "")
    return "".join(ch for ch in normalized if not unicodedata.combining(ch)).casefold()


def _contains_any(text: str, markers: tuple[str, ...]) -> bool:
    return any(marker in text for marker in markers)


def _extract_target(raw: str) -> str:
    url_match = re.search(r"\bhttps?://[^\s\"'<>]+", raw or "", re.IGNORECASE)
    if url_match:
        return url_match.group(0).rstrip(".,;)")

    cidr_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b", raw or "")
    if cidr_match:
        return cidr_match.group(0)

    ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw or "")
    if ip_match:
        return ip_match.group(0)

    domain_match = re.search(
        r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}\b",
        raw or "",
    )
    if domain_match:
        return domain_match.group(0).rstrip(".")

    return ""


def _mission_has_scope(mission: Any | None) -> bool:
    if not mission:
        return False
    if getattr(mission, "targets", None):
        return True
    scope = getattr(mission, "scope", None)
    if scope and getattr(scope, "in_scope", None):
        return True
    if getattr(mission, "hosts", None) or getattr(mission, "services", None):
        return True
    return False


def _scope_status(target: str, mission: Any | None) -> ScopeStatus:
    if target:
        return ScopeStatus.EXPLICIT
    if _mission_has_scope(mission):
        return ScopeStatus.INFERRED_FROM_SESSION
    return ScopeStatus.MISSING


def _environment_hint(text: str) -> EnvironmentHint:
    private_lab_markers = (
        "virtualbox",
        "vmware",
        "proxmox",
        "hyperviseur",
        "hypervisor",
        "kvm",
        "qemu",
        "homelab",
        "home lab",
        "lab prive",
        "lab privee",
        "reseau virtuel",
        "infrastructure virtuelle",
        "environnement virtuel",
        "virtual env",
        "vm ",
        "ma vm",
        "mes vm",
    )
    if _contains_any(text, private_lab_markers):
        return EnvironmentHint.PRIVATE_LAB

    ctf_markers = (
        "tryhackme",
        "try hack me",
        "hackthebox",
        "hack the box",
        "htb",
        "rootme",
        "root-me",
        "portswigger",
        "port swigger",
        "web security academy",
        "picoctf",
        "pico ctf",
        "overthewire",
        "over the wire",
        "vulnhub",
        "capture the flag",
        "ctf",
        "user.txt",
        "root.txt",
        "flag",
        "room",
    )
    if _contains_any(text, ctf_markers):
        return EnvironmentHint.CTF_ONLINE

    authorized_markers = (
        "audit",
        "assessment",
        "client",
        "interne",
        "internal",
        "staging",
        "production",
        "preprod",
        "pre-production",
        "entreprise",
        "company",
        "authorized",
        "autorise",
        "autorisee",
        "autorise",
        "autorisee",
    )
    if _contains_any(text, authorized_markers):
        return EnvironmentHint.AUTHORIZED_ORG

    return EnvironmentHint.UNKNOWN


def _technical_goal(text: str) -> TechnicalGoal:
    if _contains_any(
        text,
        (
            "what time",
            "quelle heure",
            "il est quelle heure",
            "system time",
            "unix timestamp",
            "unix time",
            "epoch time",
            "epoch",
            "current timestamp",
            "today's date",
            "todays date",
            "date today",
            "current date",
            "date and time",
            "what date",
            "quelle date",
            "la date",
            "date du jour",
            "aujourd'hui",
            "date systeme",
            "date système",
            "os version",
            "version os",
            "operating system",
            "what os",
            "which os",
            "systeme d'exploitation",
            "système d'exploitation",
            "my ip",
            "my ip address",
            "local ip",
            "public ip",
            "external ip",
            "wan ip",
            "mon ip",
            "mon adresse ip",
            "mes adresses ip",
            "adresse ip locale",
            "adresses ip locales",
            "ip publique",
            "ip externe",
            "hostname",
            "kernel",
            "uname",
            "cpu load",
            "cpu usage",
            "load average",
            "loadavg",
            "charge cpu",
            "charge du cpu",
            "charge processeur",
            "charge du processeur",
            "utilisation cpu",
            "utilisation du cpu",
            # D10: disk-space queries (accent-stripped by _plain)
            "disk space",
            "disk usage",
            "disk free",
            "free disk",
            "free space",
            "storage space",
            "espace disque",
            "disque disponible",
            "espace disponible",
            "espace de stockage",
            "stockage disponible",
            # RC-α residual: RAM/memory queries (accent-stripped by _plain)
            "how much ram",
            "how much memory",
            "ram usage",
            "memory usage",
            "free memory",
            "available memory",
            "free ram",
            "available ram",
            "combien de ram",
            "memoire vive",
            "memoire disponible",
            "ram disponible",
            "is installed",
            "tools installed",
            "tools are installed",
            "which tools",
            "what tools",
            # French (accent-stripped by _plain): "quels outils … sont installés"
            "outils installes",
            "sont installes",
            "est installe",
            "outils offensifs",
        ),
    ):
        return TechnicalGoal.LOCAL_SYSTEM
    if _contains_any(text, ("rapport", "report", "resume executif", "executive summary")):
        return TechnicalGoal.REPORT
    if _contains_any(
        text,
        (
            "vpn",
            ".ovpn",
            "openvpn",
            "wordlist",
            "wordlists",
            "setup",
            "readiness",
            "prepare",
            "preparer",
            "environnement",
            "environment",
            "connectivite",
            "connectivity",
        ),
    ):
        return TechnicalGoal.LAB_READINESS
    if _contains_any(text, ("suid", "privilege", "privileges", "escalat", "root.txt")):
        return TechnicalGoal.PRIV_ESC
    if _contains_any(
        text,
        (
            "reverse shell",
            "webshell",
            "web shell",
            "payload",
            "exploit",
            "upload shell",
            "obtenir un shell",
            "get a shell",
        ),
    ):
        return TechnicalGoal.EXPLOIT_STEP
    if _contains_any(
        text,
        (
            "gobuster",
            "go buster",
            "dirb",
            "ffuf",
            "feroxbuster",
            "hidden directory",
            "directories",
            "directory",
            "repertoires",
            "repertoire",
            "dossiers",
        ),
    ):
        return TechnicalGoal.WEB_DIR_ENUM
    if _contains_any(text, ("api", "endpoint", "graphql", "swagger", "openapi")):
        return TechnicalGoal.API_ENUM
    if _contains_any(
        text,
        ("nikto", "sqlmap", "cve", "vulnerabilite", "vulnerability", "failles", "weakness"),
    ):
        return TechnicalGoal.VULN_VALIDATION
    if _contains_any(
        text,
        (
            "service actif",
            "services actifs",
            "what service",
            "quel service",
            "version apache",
            "what version",
            "quelle version",
            "banner",
            "fingerprint",
        ),
    ):
        return TechnicalGoal.SERVICE_ENUM
    if _contains_any(
        text,
        (
            "port ouvert",
            "ports ouverts",
            "port est ouvert",
            "ports sont ouverts",
            "port actif",
            "ports actifs",
            "open ports",
            "how many ports",
            "combien de ports",
            "nmap",
            "scan des ports",
            "port scan",
        ),
    ):
        return TechnicalGoal.PORT_SCAN
    if _contains_any(text, ("reconnaissance", "recon", "enumeration", "enumere", "enumerer")):
        return TechnicalGoal.RECONNAISSANCE
    return TechnicalGoal.UNKNOWN


_SOCIAL_WORDS = frozenset(
    {
        "bonjour",
        "bonsoir",
        "salut",
        "coucou",
        "hello",
        "hi",
        "hey",
        "yo",
        "merci",
        "thanks",
        "thx",
        "ciao",
        "bye",
    }
)

_SOCIAL_PHRASES = (
    "thank you",
    "comment vas",
    "how are you",
    "good morning",
    "good evening",
    "good afternoon",
    "bonne journee",
    "bonne soiree",
    "au revoir",
    "a plus",
    "ca va",
)


def _is_social(text: str) -> bool:
    """Pure greeting/courtesy turn with no technical task attached.

    Token matching (not substring) avoids false hits like 'hi' inside 'this'.
    A short length cap keeps a greeting prefix on a real task ('salut, scanne
    10.0.0.5 en profondeur') from being misread as small talk.
    """
    tokens = re.findall(r"[a-z']+", text)
    if not tokens or len(tokens) > 8:
        return False
    if any(token in _SOCIAL_WORDS for token in tokens):
        return True
    return _contains_any(text, _SOCIAL_PHRASES)


def _user_intent(text: str, technical_goal: TechnicalGoal) -> UserIntent:
    if re.fullmatch(r"(?:#?\d+[\s,;]*)+", text) or re.fullmatch(
        r"(?:all|tout|tous|toutes)(?:\s+(?:except|sauf)\s+.+)?",
        text,
    ):
        return UserIntent.EXECUTE_SELECTED

    if technical_goal == TechnicalGoal.UNKNOWN and _is_social(text):
        return UserIntent.SOCIAL

    guided_batch_markers = (
        "answer the questions below",
        "target ip address",
        "user.txt",
        "root.txt",
    )
    if (
        technical_goal != TechnicalGoal.LOCAL_SYSTEM
        and _contains_any(text, guided_batch_markers)
        and _contains_any(text, ("scan", "ports", "service", "directory", "directories", "gobuster"))
    ):
        return UserIntent.APPROVED_BATCH

    if _contains_any(
        text,
        (
            "plan",
            "strategie",
            "strategy",
            "comment proceder",
            "comment on procede",
            "que proposes",
            "propose",
        ),
    ):
        return UserIntent.PROPOSE_PLAN

    if _contains_any(
        text,
        (
            "complete",
            "complet",
            "comprehensive",
            "full",
            "toute la reconnaissance",
            "reconnaissance complete",
            "lance la phase",
            "enchaîne",
            "enchaine",
            "tout scanner",
        ),
    ):
        return UserIntent.APPROVED_BATCH

    narrow_question_markers = (
        "combien",
        "how many",
        "quel ",
        "quelle ",
        "quels ",
        "quelles ",
        "what ",
        "which ",
        "who ",
        "where ",
        "version",
        "hidden directory",
        "repertoire cache",
    )
    if technical_goal != TechnicalGoal.UNKNOWN and _contains_any(text, narrow_question_markers):
        return UserIntent.ANSWER_QUESTION

    single_tool_markers = (
        "fais ",
        "lance ",
        "execute ",
        "executer ",
        "exécute ",
        "run ",
        "scan ",
        "find ",
        "search ",
        "cherche ",
        "trouve ",
    )
    if technical_goal != TechnicalGoal.UNKNOWN and _contains_any(text, single_tool_markers):
        return UserIntent.RUN_SINGLE_TOOL

    if technical_goal != TechnicalGoal.UNKNOWN and text.strip().endswith("?"):
        return UserIntent.ANSWER_QUESTION

    return UserIntent.UNKNOWN


def _risk(goal: TechnicalGoal, text: str) -> RequestRisk:
    if _contains_any(text, ("rm -rf", "shutdown", "wipe", "format disk", "delete all")):
        return RequestRisk.DESTRUCTIVE
    if goal in {TechnicalGoal.EXPLOIT_STEP, TechnicalGoal.PRIV_ESC}:
        return RequestRisk.EXPLOIT
    if goal in {TechnicalGoal.WEB_DIR_ENUM, TechnicalGoal.VULN_VALIDATION, TechnicalGoal.PORT_SCAN}:
        return RequestRisk.ACTIVE_HIGH if _contains_any(text, ("bruteforce", "brute force", "nikto", "sqlmap")) else RequestRisk.ACTIVE_LOW
    if goal in {TechnicalGoal.SERVICE_ENUM, TechnicalGoal.API_ENUM, TechnicalGoal.RECONNAISSANCE}:
        return RequestRisk.ACTIVE_LOW
    return RequestRisk.PASSIVE
