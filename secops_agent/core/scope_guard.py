"""
Scope guardrails for tool calls and shell commands.

The guard extracts target-like values from tool arguments, checks them against
the mission scope, and returns a deterministic deny reason before execution.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Iterable
from urllib.parse import urlparse

from secops_agent.core.mission import MissionContext
from secops_agent.core.shell_analysis import analyze_shell_command, shell_tokens


@dataclass(frozen=True)
class ScopeGuardResult:
    allowed: bool
    reason: str = ""
    values: tuple[str, ...] = ()


_TARGET_ARGUMENT_KEYS = {
    "target",
    "targets",
    "url",
    "urls",
    "domain",
    "domains",
    "host",
    "hosts",
    "hostname",
    "ip",
}

_REFERENCE_ONLY_TOOLS = {
    "cve_lookup",
    "exploit_info",
    "generate_payload",
    "hash_generate",
    "hash_identify",
    "password_strength",
    "searchsploit",
}

_NETWORK_SHELL_COMMANDS = {
    "curl",
    "dig",
    "dirb",
    "ffuf",
    "gobuster",
    "host",
    "nc",
    "ncat",
    "nikto",
    "nmap",
    "nslookup",
    "openssl",
    "ping",
    "sqlmap",
    "subfinder",
    "tracepath",
    "traceroute",
    "wget",
    "whois",
}

_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\.?$"
)
_URL_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")


class ScopeGuard:
    """Evaluate whether tool targets are allowed by the mission scope."""

    def __init__(self, mission: MissionContext):
        self.mission = mission

    def check_tool_call(self, tool_name: str, arguments: dict[str, Any]) -> ScopeGuardResult:
        return self.check_values(tool_target_values(tool_name, arguments))

    def check_values(self, values: Iterable[str]) -> ScopeGuardResult:
        unique_values = _dedupe(value for value in values if str(value or "").strip())
        if not unique_values:
            return ScopeGuardResult(allowed=True)

        scope = self.mission.scope
        for value in unique_values:
            if scope.is_in_scope(value):
                continue
            if scope.matches_out_of_scope(value):
                reason = f"Out-of-scope target blocked: {value}"
            elif scope.has_explicit_in_scope():
                reason = f"Target is outside authorized scope: {value}"
            else:
                reason = f"Target is not authorized by mission scope: {value}"
            return ScopeGuardResult(
                allowed=False,
                reason=reason,
                values=tuple(unique_values),
            )
        return ScopeGuardResult(allowed=True, values=tuple(unique_values))


def tool_target_values(tool_name: str, arguments: dict[str, Any]) -> list[str]:
    if tool_name in _REFERENCE_ONLY_TOOLS:
        return []
    if tool_name == "run_shell":
        return shell_command_targets(str(arguments.get("command") or ""))

    values: list[str] = []
    for key, value in arguments.items():
        if str(key).lower() not in _TARGET_ARGUMENT_KEYS:
            continue
        values.extend(_flatten_target_value(value))
    return _dedupe(values)


def shell_command_targets(command: str) -> list[str]:
    if not str(command or "").strip():
        return []

    analysis = analyze_shell_command(command)
    executables = {exe.rsplit("/", 1)[-1] for exe in analysis.executables}
    if not executables.intersection(_NETWORK_SHELL_COMMANDS):
        return []

    values: list[str] = []
    for token in analysis.tokens:
        values.extend(_target_candidates_from_token(token))
    return _dedupe(values)


def _flatten_target_value(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, dict):
        values: list[str] = []
        for item in value.values():
            values.extend(_flatten_target_value(item))
        return values
    if isinstance(value, (list, tuple, set)):
        values: list[str] = []
        for item in value:
            values.extend(_flatten_target_value(item))
        return values

    text = str(value).strip()
    if not text:
        return []
    candidates = _target_candidates_from_token(text)
    return candidates or [text]


def _target_candidates_from_token(token: str) -> list[str]:
    text = str(token or "").strip().strip("'\"")
    if not text:
        return []
    if any(sep.isspace() for sep in text):
        values: list[str] = []
        parts, _ = shell_tokens(text)
        for part in parts:
            if part != text:
                values.extend(_target_candidates_from_token(part))
        return values

    if text.startswith("@"):
        return []
    if text.startswith("-") and "=" not in text:
        return []
    if text.startswith("-") and "=" in text:
        text = text.split("=", 1)[1].strip()
    if not text:
        return []

    if _URL_RE.match(text):
        return [text]

    if "/" in text and not _looks_like_network(text):
        return []

    host = _host_from_token(text)
    if _looks_like_network(host):
        return [host]
    return []


def _host_from_token(token: str) -> str:
    text = token.strip().strip(",;")
    if _URL_RE.match(text):
        parsed = urlparse(text)
        return parsed.hostname or text
    if text.startswith("[") and "]" in text:
        return text[1:text.index("]")]
    if text.count(":") == 1 and text.rsplit(":", 1)[-1].isdigit():
        return text.rsplit(":", 1)[0]
    return text.rstrip(".")


def _looks_like_network(value: str) -> bool:
    text = str(value or "").strip().strip("[]").rstrip(".")
    if not text:
        return False
    try:
        ipaddress.ip_network(text, strict=False)
        return True
    except ValueError:
        pass
    return bool(_DOMAIN_RE.match(text))


def _dedupe(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text:
            continue
        key = text.casefold()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(text)
    return deduped
