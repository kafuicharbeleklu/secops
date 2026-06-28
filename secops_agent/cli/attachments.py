"""Pure parsing helpers for attachment slash commands."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AttachArgument:
    action: str
    argument: str = ""


def parse_attach_argument(argument: str) -> AttachArgument:
    text = str(argument or "").strip()
    if not text or text.lower() in {"list", "ls"}:
        return AttachArgument(action="list")
    return AttachArgument(action="attach", argument=text)
