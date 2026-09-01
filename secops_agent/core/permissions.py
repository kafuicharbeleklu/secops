"""
Granular Permission Policy Engine for the SecOps Agent.
Supports allow/ask/deny states for commands, tools, and file actions.
"""

from __future__ import annotations

import os
import json
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, Any, List, Optional

from secops_agent.core.shell_analysis import (
    analyze_shell_command,
    extract_shell_executables,
    shell_tokens,
)

class PermissionDecision(str, Enum):
    ALLOW = "allow"
    ASK = "ask"
    DENY = "deny"


class ActionTier(str, Enum):
    PASSIVE = "passive"      # Allowed automatically (ALLOW)
    ACTIVE = "active"       # Triggers ASK (confirmation)
    DESTRUCTIVE = "destructive"  # Triggers DENY (blocked)


TOOL_TIERS: Dict[str, ActionTier] = {
    # Passive / Observation (Scans & Reading) -> ALLOW by default
    "ping_host": ActionTier.PASSIVE,
    "traceroute": ActionTier.PASSIVE,
    "port_check": ActionTier.PASSIVE,
    "dns_lookup": ActionTier.PASSIVE,
    "whois_lookup": ActionTier.PASSIVE,
    "http_headers": ActionTier.PASSIVE,
    "tech_detect": ActionTier.PASSIVE,
    "ssl_check": ActionTier.PASSIVE,
    "ssl_audit": ActionTier.PASSIVE,
    "file_analyze": ActionTier.PASSIVE,
    "log_analyze": ActionTier.PASSIVE,
    "find_files": ActionTier.PASSIVE,
    "searchsploit": ActionTier.PASSIVE,
    "exploit_info": ActionTier.PASSIVE,
    "cve_lookup": ActionTier.PASSIVE,
    "hash_identify": ActionTier.PASSIVE,
    "hash_generate": ActionTier.PASSIVE,
    "password_strength": ActionTier.PASSIVE,
    "sysinfo": ActionTier.PASSIVE,
    "lab_setup_check": ActionTier.PASSIVE,
    "vpn_status": ActionTier.PASSIVE,

    # Active enumeration (r3) hits a real target -> ASK by default. These carry
    # risk_class=ACTIVE_ENUMERATION; the tier MUST agree with the risk class so the
    # permission gate does not follow the laxer taxonomy (audit T2.7).
    "nmap_scan": ActionTier.ACTIVE,
    "subdomain_enum": ActionTier.ACTIVE,

    # Active (Exploitation, Brute-Force, Environment Modification) -> ASK by default
    "dir_brute": ActionTier.ACTIVE,
    "nikto_scan": ActionTier.ACTIVE,
    "ffuf_scan": ActionTier.ACTIVE,
    "nuclei_scan": ActionTier.ACTIVE,
    "sql_injection_test": ActionTier.ACTIVE,
    "xss_test": ActionTier.ACTIVE,
    "waf_detect": ActionTier.ACTIVE,
    "generate_payload": ActionTier.ACTIVE,
    "run_shell": ActionTier.ACTIVE,
    "connect_vpn_config": ActionTier.ACTIVE,
    "disconnect_vpn": ActionTier.ACTIVE,

    # Exploitation tools → ACTIVE (approval required)
    "http_request": ActionTier.ACTIVE,
    "write_file": ActionTier.ACTIVE,
    "start_listener": ActionTier.ACTIVE,
    "webshell_exec": ActionTier.ACTIVE,

    # Exploitation observation → PASSIVE
    "fetch_url": ActionTier.PASSIVE,
}


class ApprovalScope(str, Enum):
    ONCE = "once"
    SESSION = "session"
    PERSISTENT = "persistent"


@dataclass
class ApprovalDecision:
    allowed: bool
    scope: ApprovalScope = ApprovalScope.ONCE
    amended_arguments: Dict[str, Any] | None = None
    interrupted: bool = False


@dataclass(frozen=True)
class PermissionResource:
    kind: str
    name: str

    @property
    def value(self) -> str:
        return f"{self.kind}({self.name})"


def _default_settings_path() -> Path:
    configured = os.getenv("SECOPS_SETTINGS_FILE")
    if configured:
        return Path(configured).expanduser()
    return Path.home() / ".secops_agent" / "settings.json"


class PermissionEngine:
    def __init__(self, settings_path: Path | None = None):
        # Default policies matching high-end SecOps requirements
        self.rules = {
            "command": {
                "apt": PermissionDecision.ASK,
                "apt-get": PermissionDecision.ASK,
                "chattr": PermissionDecision.DENY,
                "chmod": PermissionDecision.DENY,
                "chown": PermissionDecision.DENY,
                "dd": PermissionDecision.DENY,
                "fdisk": PermissionDecision.DENY,
                "ping": PermissionDecision.ALLOW,
                "host": PermissionDecision.ALLOW,
                "dig": PermissionDecision.ALLOW,
                "nslookup": PermissionDecision.ALLOW,
                "nmap": PermissionDecision.ASK,
                "sqlmap": PermissionDecision.ASK,
                "hydra": PermissionDecision.ASK,
                "mkfs": PermissionDecision.DENY,
                "mount": PermissionDecision.DENY,
                "msfconsole": PermissionDecision.ASK,
                "reboot": PermissionDecision.DENY,
                "rm": PermissionDecision.DENY,
                "rmdir": PermissionDecision.DENY,
                "shutdown": PermissionDecision.DENY,
                "sudo": PermissionDecision.ASK,
                "systemctl": PermissionDecision.ASK,
                "truncate": PermissionDecision.DENY,
                "umount": PermissionDecision.DENY,
            },
            "command_exact": {},  # Backward-compatible lookup for older saved rules.
            "command_prefix": {},  # AGY-style remembered full-command prefix approvals.
            "tool": {
                "ping_host": PermissionDecision.ALLOW,
                "dns_lookup": PermissionDecision.ALLOW,
                "whois_lookup": PermissionDecision.ALLOW,
                # nmap_scan and subdomain_enum are r3 active enumeration: they hit a
                # real target and route through approval via the ACTIVE tier — no
                # explicit ALLOW override here (audit T2.7).
                "dir_brute": PermissionDecision.ASK,
                "searchsploit": PermissionDecision.ALLOW,
                "hash_identify": PermissionDecision.ALLOW,
            },
            "read_file": {
                "/etc/shadow": PermissionDecision.DENY,
                "/etc/passwd": PermissionDecision.ASK,
                "~/.ssh": PermissionDecision.DENY,
            },
            "write_file": {
                "/etc": PermissionDecision.DENY,
                "/bin": PermissionDecision.DENY,
                "/usr": PermissionDecision.DENY,
            }
        }
        self.default_decision = PermissionDecision.ASK
        self.session_rules: Dict[str, PermissionDecision] = {}
        self.settings_path = settings_path or _default_settings_path()
        self.persistent_rules: Dict[str, PermissionDecision] = self._load_persistent_rules()

    def parse_resource(self, resource_text: str) -> Optional[PermissionResource]:
        """Parse resource notation such as tool(nmap_scan) or command(nmap)."""
        text = resource_text.strip()
        if not text:
            return None

        if "(" in text and text.endswith(")"):
            kind, _, remainder = text.partition("(")
            name = remainder[:-1].strip()
            kind = kind.strip()
            if kind in self.rules and name:
                return PermissionResource(kind=kind, name=name)
            return None

        if text in self.rules["tool"]:
            return PermissionResource(kind="tool", name=text)
        if text in self.rules["command"]:
            return PermissionResource(kind="command", name=text)
        return None

    def summary(self) -> Dict[str, List[str]]:
        """Return remembered overrides grouped by decision."""
        grouped: Dict[str, List[str]] = {"allow": [], "ask": [], "deny": []}
        for resource, decision in sorted(self.persistent_rules.items()):
            grouped[decision.value].append(f"{resource} (settings)")
        for resource, decision in sorted(self.session_rules.items()):
            grouped[decision.value].append(resource)
        return grouped

    def reset_session(self):
        """Clear per-session permission overrides."""
        self.session_rules.clear()

    def remember(self, resource: PermissionResource, decision: PermissionDecision):
        """Remember an allow/ask/deny override for the current session."""
        self.session_rules[resource.value] = decision

    def remember_persistent(self, resource: PermissionResource, decision: PermissionDecision):
        """Persist an allow/ask/deny override to settings.json."""
        self.persistent_rules[resource.value] = decision
        self._write_persistent_rules()

    def rule_requires_confirmation(
        self,
        resource: PermissionResource,
        decision: PermissionDecision,
    ) -> bool:
        """Whether a ``/permissions`` rule is high-impact enough to need an explicit
        second confirmation before it is applied.

        Mirrors the approval UI's intentional divergence (R11 /
        ``_SHELL_TOOL_SESSION_ONLY``): a blanket ``allow`` on a privileged/exploit
        tool (r5+) or on a compound shell command must never be granted on the same
        one-liner that allows a recon tool like nmap_scan. The two permission-granting
        paths must not disagree (audit T2.8).
        """
        if decision != PermissionDecision.ALLOW:
            return False
        if resource.kind == "tool":
            return _tool_risk_level(resource.name) >= _HIGH_RISK_RULE_FLOOR
        if resource.kind in ("command", "command_exact", "command_prefix"):
            return _command_rule_is_high_risk(resource.name)
        return False

    def tool_resource(self, tool_name: str) -> PermissionResource:
        return PermissionResource(kind="tool", name=tool_name)

    def command_resource(self, executable: str) -> PermissionResource:
        return PermissionResource(kind="command", name=executable)

    def command_prefix_resource(self, command: str) -> PermissionResource:
        return PermissionResource(kind="command_prefix", name=_normalize_command_prefix(command))

    def command_exact_resource(self, command: str) -> PermissionResource:
        return PermissionResource(kind="command_exact", name=_normalize_command_prefix(command))

    def command_approval_resource(self, command: str) -> PermissionResource:
        """Choose the resource shape shown and saved for a shell approval prompt."""
        normalized = _normalize_command_prefix(command)
        contextual_prefix = _contextual_command_prefix(normalized)
        if contextual_prefix:
            return self.command_prefix_resource(contextual_prefix)
        return self.command_exact_resource(normalized)

    def shell_command_resources(self, command: str) -> List[PermissionResource]:
        """Extract command resources from shell text for granular approval."""
        return [
            self.command_resource(executable)
            for executable in _extract_shell_executables(command)
        ]

    def _session_decision(self, resource: PermissionResource) -> Optional[PermissionDecision]:
        exact = self.session_rules.get(resource.value)
        wildcard = self.session_rules.get(f"{resource.kind}(*)")
        # A session-wide DENY is an execution lock (used by plan-only mode), not
        # a default that a later narrow ALLOW may accidentally bypass.
        if wildcard == PermissionDecision.DENY:
            return wildcard
        if exact:
            return exact
        if wildcard:
            return wildcard
        return None

    def _persistent_decision(self, resource: PermissionResource) -> Optional[PermissionDecision]:
        exact = self.persistent_rules.get(resource.value)
        if exact:
            return exact
        wildcard = self.persistent_rules.get(f"{resource.kind}(*)")
        if wildcard:
            return wildcard
        return None

    def _remembered_decision(self, resource: PermissionResource) -> Optional[PermissionDecision]:
        return self._session_decision(resource) or self._persistent_decision(resource)

    def _remembered_command_prefix_decision(self, command_text: str) -> Optional[PermissionDecision]:
        """Return a remembered AGY-style command prefix decision, if safely applicable."""
        matches: list[tuple[int, PermissionDecision]] = []
        for rules in (self.session_rules, self.persistent_rules):
            for resource_text, decision in rules.items():
                resource = self.parse_resource(resource_text)
                if not resource or resource.kind != "command_prefix":
                    continue
                if _command_prefix_matches(resource.name, command_text):
                    matches.append((len(resource.name), decision))
            if matches:
                matches.sort(key=lambda item: item[0], reverse=True)
                return matches[0][1]
        return None

    def _load_persistent_rules(self) -> Dict[str, PermissionDecision]:
        try:
            data = json.loads(self.settings_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}

        raw_rules = data.get("permissions", {}) if isinstance(data, dict) else {}
        if not isinstance(raw_rules, dict):
            return {}

        loaded: Dict[str, PermissionDecision] = {}
        for resource, value in raw_rules.items():
            try:
                loaded[str(resource)] = PermissionDecision(str(value))
            except ValueError:
                continue
        return loaded

    def _write_persistent_rules(self) -> None:
        try:
            self.settings_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                data = json.loads(self.settings_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                data = {}
            if not isinstance(data, dict):
                data = {}
            data["permissions"] = {
                resource: decision.value
                for resource, decision in sorted(self.persistent_rules.items())
            }
            self.settings_path.write_text(
                json.dumps(data, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        except OSError:
            pass

    def get_action_tier(self, tool_name: str, dangerous: bool = False) -> ActionTier:
        """Get the action tier for a tool."""
        tier = TOOL_TIERS.get(tool_name)
        if tier:
            return tier

        # Fallback via registry / risk class
        try:
            from secops_agent.core.tools import registry, ToolRiskClass
            tool_def = registry.get_tool(tool_name)
            if tool_def:
                rc = tool_def.risk_class
                if rc in (
                    ToolRiskClass.PURE_LOCAL_COMPUTATION,
                    ToolRiskClass.LOCAL_OBSERVATION,
                    ToolRiskClass.NETWORK_OBSERVATION,
                    ToolRiskClass.LOCAL_FILE_ACCESS
                ):
                    return ActionTier.PASSIVE
                dangerous = getattr(tool_def, "dangerous", dangerous)
        except Exception:
            pass

        return ActionTier.ACTIVE if dangerous else ActionTier.PASSIVE

    def evaluate_tool(self, tool_name: str, dangerous: bool = False) -> PermissionDecision:
        """Evaluate runtime policy for an agent tool call."""
        resource = self.tool_resource(tool_name)
        remembered = self._remembered_decision(resource)
        if remembered:
            return remembered

        # Check explicit rules dictionary overrides first
        if tool_name in self.rules["tool"]:
            return self.rules["tool"][tool_name]

        tier = self.get_action_tier(tool_name, dangerous)
        if tier == ActionTier.PASSIVE:
            return PermissionDecision.ALLOW
        elif tier == ActionTier.DESTRUCTIVE:
            return PermissionDecision.DENY
        else:
            return PermissionDecision.ASK

    def check_tool_permission(self, tool_name: str, arguments: Dict[str, Any]) -> PermissionDecision:
        """Evaluate permission for a core tool execution."""
        decision, _ = self.evaluate_tool_arguments(tool_name, arguments)
        return decision

    def evaluate_tool_arguments(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
    ) -> tuple[PermissionDecision, PermissionResource | None]:
        """Evaluate argument-sensitive resources before a tool executes."""
        argument_decision, argument_resource = self.evaluate_tool_argument_resource(
            tool_name,
            arguments,
        )
        if argument_resource and argument_decision != PermissionDecision.ALLOW:
            return argument_decision, argument_resource

        remembered = self._remembered_decision(self.tool_resource(tool_name))
        if remembered:
            return remembered, self.tool_resource(tool_name)

        # Direct tool rule. Argument-sensitive resources (read_file/write_file)
        # are handled above via evaluate_tool_argument_resource; that path is the
        # only place file heuristics run — do not re-add an unreachable branch here.
        decision = self.evaluate_tool(tool_name)
        return decision, self.tool_resource(tool_name)

    def evaluate_tool_argument_resource(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
    ) -> tuple[PermissionDecision, PermissionResource | None]:
        """Evaluate only the resource implied by a tool's arguments."""
        argument_resource = self.tool_argument_resource(tool_name, arguments)
        if not argument_resource:
            return PermissionDecision.ALLOW, None

        remembered_argument = self._remembered_decision(argument_resource)
        if remembered_argument:
            return remembered_argument, argument_resource
        if argument_resource.kind == "read_file":
            if (
                tool_name == "find_files"
                and os.path.abspath(os.path.expanduser(argument_resource.name)) == "/"
            ):
                return PermissionDecision.ASK, argument_resource
            return self.check_read_permission(argument_resource.name), argument_resource
        if argument_resource.kind == "write_file":
            decision = self.check_write_permission(argument_resource.name)
            # Only a categorical DENY (system paths /etc, /bin, /usr) blocks at the
            # argument level; any other path defers to the tool-level ASK so
            # write_file prompts exactly once (audit R3.5).
            if decision == PermissionDecision.DENY:
                return decision, argument_resource
            return PermissionDecision.ALLOW, argument_resource
        return PermissionDecision.ALLOW, argument_resource

    def tool_argument_resource(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
    ) -> PermissionResource | None:
        """Return the sensitive resource implied by a tool's arguments, if any."""
        args = arguments or {}
        if tool_name == "file_analyze":
            path = str(args.get("filepath") or args.get("path") or "").strip()
            return PermissionResource(kind="read_file", name=path) if path else None
        if tool_name == "log_analyze":
            path = str(args.get("logfile") or args.get("filepath") or args.get("path") or "").strip()
            return PermissionResource(kind="read_file", name=path) if path else None
        if tool_name == "find_files":
            path = str(args.get("path") or "/").strip() or "/"
            return PermissionResource(kind="read_file", name=path)
        if tool_name in ("write_file", "save_file", "export"):
            # Routes the /etc, /bin, /usr write_file DENY (rules["write_file"]) through
            # check_write_permission instead of leaving it as dead code (audit R3.5).
            path = str(args.get("path") or args.get("filepath") or "").strip()
            return PermissionResource(kind="write_file", name=path) if path else None
        return None

    def check_command_permission(self, cmd: List[str], command_text: str = "") -> PermissionDecision:
        """Evaluate permission for executing an external shell command."""
        if not cmd:
            return PermissionDecision.DENY

        if command_text:
            remembered_exact = self._remembered_decision(self.command_exact_resource(command_text))
            if remembered_exact:
                return remembered_exact
            remembered_prefix = self._remembered_command_prefix_decision(command_text)
            if remembered_prefix:
                return remembered_prefix

        executable = cmd[0].rsplit("/", 1)[-1]
        remembered = self._remembered_decision(self.command_resource(executable))
        if remembered:
            return remembered
        
        # Check rule by executable name
        if executable in self.rules["command"]:
            return self.rules["command"][executable]

        # Fallback security rules
        if executable in ("apt", "apt-get", "systemctl", "sudo"):
            return PermissionDecision.ASK
        if executable in ("chmod", "chown"):
            return PermissionDecision.DENY

        return self.default_decision

    def check_read_permission(self, path: str) -> PermissionDecision:
        """Evaluate if reading a file path is permitted."""
        resolved = os.path.abspath(os.path.expanduser(path))

        # Check explicit path rules using proper prefix comparison
        for prefix, decision in self.rules["read_file"].items():
            ref_path = os.path.abspath(os.path.expanduser(prefix))
            # Ensure we compare full path components, not substrings.
            # Append '/' to directory refs so /etc/shadow doesn't match /etc/shadow_backup.
            if resolved == ref_path or resolved.startswith(ref_path.rstrip('/') + '/'):
                return decision

        return PermissionDecision.ALLOW

    def check_write_permission(self, path: str) -> PermissionDecision:
        """Evaluate if writing to a file path is permitted."""
        resolved = os.path.abspath(os.path.expanduser(path))

        # Check explicit path rules using proper prefix comparison
        for prefix, decision in self.rules["write_file"].items():
            ref_path = os.path.abspath(os.path.expanduser(prefix))
            if resolved == ref_path or resolved.startswith(ref_path.rstrip('/') + '/'):
                return decision

        return PermissionDecision.ASK


# Global permission engine instance
permissions_engine = PermissionEngine()


_SHELL_SEPARATORS = {";", "&&", "||", "|", "(", ")"}
_REDIRECT_TOKENS = {"<", ">", ">>", "2>", "2>>", "&>", "&>>"}
_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$")
_SHELLS = {"bash", "sh", "zsh"}


# r5+ (privileged local action, exploit assistance, extension execution, credentialed
# remote / identity action) is high-impact; a blanket allow on such a tool needs a
# second explicit confirmation via /permissions (audit T2.8).
_HIGH_RISK_RULE_FLOOR = 5


def _risk_class_level(risk_class) -> int:
    """Numeric r-level from a ToolRiskClass value like 'r5_privileged_local_action'."""
    try:
        return int(str(getattr(risk_class, "value", risk_class)).split("_", 1)[0].lstrip("r"))
    except (ValueError, AttributeError):
        return 0


def _tool_risk_level(tool_name: str) -> int:
    """Best-effort r-level for a tool via the live registry, then the static map."""
    try:
        from secops_agent.core.tools import _BUILTIN_TOOL_RISK_CLASSES, registry

        tool_def = registry.get_tool(tool_name)
        risk_class = getattr(tool_def, "risk_class", None) if tool_def else None
        if risk_class is None:
            risk_class = _BUILTIN_TOOL_RISK_CLASSES.get(tool_name)
        if risk_class is not None:
            return _risk_class_level(risk_class)
    except Exception:
        pass
    return 0


def _normalize_command_prefix(command: str) -> str:
    return re.sub(r"\s+", " ", str(command or "").strip())


_UNSAFE_PREFIX_EXTENSION_MARKERS = ("&&", "||", ";", "|", "$(", "`", ">", "<", "\n", "\r")
_PREFIX_FRIENDLY_COMMANDS = {"nmap"}
_LOW_RISK_PREFIX_COMMANDS = {"date", "hostname", "id", "pwd", "uname", "whoami"}
_EXACT_ONLY_COMMANDS = {
    "apt",
    "apt-get",
    "chattr",
    "chmod",
    "chown",
    "dd",
    "fdisk",
    "mkfs",
    "mount",
    "reboot",
    "rm",
    "rmdir",
    "shutdown",
    "sudo",
    "systemctl",
    "truncate",
    "umount",
}


def _command_rule_is_high_risk(command: str) -> bool:
    """A compound/chained command, or one whose executable the default policy treats
    as exact-only (rm, chmod, sudo, …), must not receive a blanket allow via
    /permissions without a second confirmation (audit T2.8)."""
    text = _normalize_command_prefix(command)
    if not text:
        return False
    if any(marker in text for marker in _UNSAFE_PREFIX_EXTENSION_MARKERS):
        return True
    executable = text.split(" ", 1)[0].rsplit("/", 1)[-1]
    return executable in _EXACT_ONLY_COMMANDS


def _command_prefix_matches(prefix: str, command: str) -> bool:
    """Match AGY-style command prefixes without letting appended shell chains through."""
    normalized_prefix = _normalize_command_prefix(prefix)
    normalized_command = _normalize_command_prefix(command)
    if not normalized_prefix or not normalized_command:
        return False
    if normalized_command == normalized_prefix:
        return True
    if not normalized_command.startswith(normalized_prefix + " "):
        return False
    if analyze_shell_command(command).unsafe_extension:
        return False
    return True


def _contextual_command_prefix(command: str) -> str:
    """Return a useful command prefix, or empty string when exact is safer."""
    normalized = _normalize_command_prefix(command)
    if not normalized:
        return ""
    if analyze_shell_command(command).unsafe_extension:
        return ""

    tokens = _shell_tokens(normalized)
    if not tokens:
        return ""

    executable = tokens[0].rsplit("/", 1)[-1]
    if executable in _EXACT_ONLY_COMMANDS or executable in _SHELLS:
        return ""

    if executable in _LOW_RISK_PREFIX_COMMANDS and len(tokens) == 1:
        return executable

    if executable not in _PREFIX_FRIENDLY_COMMANDS:
        return ""

    # Prefix approvals are only useful when the remembered prefix ends on a
    # target-like operand, e.g. "nmap 127.0.0.1" can later cover extra flags.
    if not tokens[1].startswith("-"):
        return f"{executable} {tokens[1]}"

    return ""


def _extract_shell_executables(command: str) -> List[str]:
    """Best-effort shell executable extraction without executing the command."""
    return extract_shell_executables(command)


def _shell_tokens(command: str) -> list[str]:
    tokens, _ = shell_tokens(command)
    return tokens


def _nested_shell_command(tokens: list[str], shell_index: int) -> str:
    index = shell_index + 1
    while index < len(tokens):
        token = tokens[index]
        if token in _SHELL_SEPARATORS:
            return ""
        if token in {"-c", "-lc", "-ic"}:
            return tokens[index + 1] if index + 1 < len(tokens) else ""
        index += 1
    return ""


def _append_unique(items: list[str], value: str):
    if value not in items:
        items.append(value)
