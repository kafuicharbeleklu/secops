"""Pure parsing helpers for the `/permissions` slash command."""

from __future__ import annotations

from dataclasses import dataclass


PERMISSIONS_USAGE = "Usage: /permissions [allow|ask|deny|clear] <resource>"
PERMISSIONS_RULE_USAGE = "Usage: /permissions allow|ask|deny tool(name)"
PERMISSION_RULE_ACTIONS = frozenset({"allow", "ask", "deny"})
PERMISSION_MODES = (
    "plan",
    "request-review",
    "proceed-in-sandbox",
    "always-proceed",
    "strict",
)


@dataclass(frozen=True)
class PermissionArgument:
    kind: str
    action: str = ""
    resource_text: str = ""
    error: str = ""
    confirmed: bool = False


@dataclass(frozen=True)
class PermissionCommandPlan:
    action: str
    argument: PermissionArgument
    render_policy: bool


def parse_permission_argument(argument: str) -> PermissionArgument:
    text = str(argument or "").strip()
    if not text:
        return PermissionArgument(kind="show")

    action, separator, resource_text = text.partition(" ")
    action = action.lower()
    resource_text = resource_text.strip() if separator else ""

    if action == "clear":
        return PermissionArgument(kind="clear", action=action)
    if action in PERMISSION_RULE_ACTIONS and resource_text:
        # A trailing `confirm` token is the explicit second confirmation required to
        # grant a blanket allow on a high-risk (r5+/compound) resource (audit T2.8).
        confirmed = False
        if not resource_text.endswith(")"):
            head, _, tail = resource_text.rpartition(" ")
            if head and tail.lower() == "confirm":
                confirmed = True
                resource_text = head.strip()
        return PermissionArgument(
            kind="rule",
            action=action,
            resource_text=resource_text,
            confirmed=confirmed,
        )
    return PermissionArgument(kind="invalid", action=action, error=PERMISSIONS_USAGE)


def plan_permission_command(argument: str, *, interactive_surface: bool) -> PermissionCommandPlan:
    parsed = parse_permission_argument(argument)
    if parsed.kind == "show" and interactive_surface:
        return PermissionCommandPlan(action="menu", argument=parsed, render_policy=False)
    if parsed.kind == "show":
        return PermissionCommandPlan(action="show", argument=parsed, render_policy=True)
    if parsed.kind in {"clear", "rule"}:
        return PermissionCommandPlan(action=parsed.kind, argument=parsed, render_policy=False)
    return PermissionCommandPlan(action="invalid", argument=parsed, render_policy=False)


def normalize_permission_mode(
    mode: str | None,
    *,
    dangerously_skip_permissions: bool = False,
) -> str:
    if dangerously_skip_permissions:
        return "always-proceed"
    if not mode:
        return "request-review"
    normalized = mode.strip().lower()
    if normalized not in PERMISSION_MODES:
        choices = ", ".join(PERMISSION_MODES)
        raise ValueError(f"Unknown permission mode '{mode}'. Use one of: {choices}.")
    return normalized


def next_permission_mode(current: str) -> str:
    """Return the next permission mode in cycle order (PROC-02, Shift+Tab)."""
    try:
        index = PERMISSION_MODES.index(current)
    except ValueError:
        return PERMISSION_MODES[0]
    return PERMISSION_MODES[(index + 1) % len(PERMISSION_MODES)]
