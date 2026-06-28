"""Slash-command surface selection helpers."""

from __future__ import annotations


INTERACTIVE_SURFACE_COMMANDS = frozenset({
    "/agents",
    "/artifact",
    "/attach",
    "/config",
    "/context",
    "/help",
    "/hooks",
    "/keybindings",
    "/mcp",
    "/model",
    "/permissions",
    "/resume",
    "/skills",
    "/tool",
    "/tools",
})


def should_use_interactive_surface(
    canonical_command: str,
    argument: str,
    *,
    stdin_isatty: bool,
    stdout_isatty: bool,
) -> bool:
    return (
        bool(stdin_isatty)
        and bool(stdout_isatty)
        and not str(argument or "").strip()
        and str(canonical_command or "").strip().lower() in INTERACTIVE_SURFACE_COMMANDS
    )
