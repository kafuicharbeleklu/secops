"""Pure parsing helpers for the `/sandbox` slash command."""

from __future__ import annotations

from dataclasses import dataclass


SANDBOX_USAGE = "Usage: /sandbox [on|off|status]"
SANDBOX_ON_ACTIONS = frozenset({"on", "enable", "enabled", "true"})
SANDBOX_OFF_ACTIONS = frozenset({"off", "disable", "disabled", "false"})


@dataclass(frozen=True)
class SandboxArgument:
    action: str = "status"
    enabled: bool | None = None
    error: str = ""


def parse_sandbox_argument(argument: str) -> SandboxArgument:
    action = str(argument or "").strip().lower() or "status"
    if action in SANDBOX_ON_ACTIONS:
        return SandboxArgument(action="on", enabled=True)
    if action in SANDBOX_OFF_ACTIONS:
        return SandboxArgument(action="off", enabled=False)
    if action == "status":
        return SandboxArgument(action="status")
    return SandboxArgument(action=action, error=SANDBOX_USAGE)
