"""
Session-local execution sandbox policy.

This is a lightweight command guard, not OS-level isolation. It blocks obvious
destructive commands and shell writes before subprocess execution.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

from secops_agent.core.shell_analysis import analyze_shell_command


_SANDBOX_ENABLED = False

_DESTRUCTIVE_EXECUTABLES = {
    "apt",
    "apt-get",
    "chattr",
    "chmod",
    "chown",
    "dd",
    "docker",
    "fdisk",
    "mkfs",
    "mount",
    "mv",
    "reboot",
    "rm",
    "rmdir",
    "service",
    "shutdown",
    "su",
    "sudo",
    "systemctl",
    "tee",
    "truncate",
    "umount",
}

_DESTRUCTIVE_PATTERNS = (
    re.compile(r":\(\)\{:\|:&\};:"),  # fork bomb
    re.compile(r"\brm\s+-[^;\n]*[rf][^;\n]*\s+/(?:\s|$)"),
    re.compile(r"\bdd\s+if=/dev/(?:zero|random|urandom)\b"),
    re.compile(r"\bmkfs(?:\.[a-z0-9]+)?\b"),
)


@dataclass(frozen=True)
class SandboxCheck:
    allowed: bool
    reason: str = ""


def set_sandbox_enabled(enabled: bool) -> None:
    global _SANDBOX_ENABLED
    _SANDBOX_ENABLED = enabled


def is_sandbox_enabled() -> bool:
    return _SANDBOX_ENABLED


def validate_exec_command(cmd: list[str]) -> SandboxCheck:
    if not _SANDBOX_ENABLED:
        return SandboxCheck(True)
    if not cmd:
        return SandboxCheck(False, "empty command")

    executable = cmd[0].rsplit("/", 1)[-1]
    if executable in {"bash", "sh", "zsh"} and len(cmd) >= 3 and "c" in cmd[1].lstrip("-"):
        return validate_shell_command(cmd[2])

    if executable in _DESTRUCTIVE_EXECUTABLES:
        return SandboxCheck(False, f"'{executable}' is blocked in sandbox mode")

    joined = " ".join(shlex.quote(part) for part in cmd)
    return _validate_command_text(joined)


def validate_shell_command(command: str) -> SandboxCheck:
    if not _SANDBOX_ENABLED:
        return SandboxCheck(True)
    return _validate_command_text(command)


def _validate_command_text(command: str) -> SandboxCheck:
    text = command.strip()
    if not text:
        return SandboxCheck(False, "empty command")

    lowered = text.lower()
    for pattern in _DESTRUCTIVE_PATTERNS:
        if pattern.search(lowered):
            return SandboxCheck(False, "destructive shell pattern is blocked in sandbox mode")

    if _has_output_write(lowered):
        return SandboxCheck(False, "filesystem write redirection is blocked in sandbox mode")

    analysis = analyze_shell_command(text)
    if analysis.parse_error:
        return SandboxCheck(False, f"unable to parse shell command: {analysis.parse_error}")

    for executable in analysis.executables:
        if executable in _DESTRUCTIVE_EXECUTABLES:
            return SandboxCheck(False, f"'{executable}' is blocked in sandbox mode")

    return SandboxCheck(True)


def _has_output_write(command: str) -> bool:
    redirections = re.finditer(r"(?P<fd>\d*)>>?\s*(?P<target>\S+)", command)
    for match in redirections:
        fd = match.group("fd")
        target = match.group("target").strip("'\"")
        if fd == "2" and target == "/dev/null":
            continue
        return True
    return False
