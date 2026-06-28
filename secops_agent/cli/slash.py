"""Pure slash-command parsing helpers."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class SlashCommandInvocation:
    raw: str
    command: str
    argument: str
    canonical_command: str
    spec: Any = None


def parse_slash_command(
    text: str,
    resolve_command: Callable[[str], Any] | None = None,
) -> SlashCommandInvocation:
    raw = str(text or "").strip()
    if not raw.startswith("/"):
        raise ValueError("Slash command input must start with '/'.")

    command_text, separator, argument = raw.partition(" ")
    command = command_text.lower()
    argument = argument.strip() if separator else ""
    spec = resolve_command(command) if resolve_command else None
    canonical = str(getattr(spec, "name", "") or command)
    return SlashCommandInvocation(
        raw=raw,
        command=command,
        argument=argument,
        canonical_command=canonical,
        spec=spec,
    )
