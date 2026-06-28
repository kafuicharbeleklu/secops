"""Pure parsing helpers for the `/cancel` slash command."""

from __future__ import annotations

from dataclasses import dataclass


CANCEL_USAGE = "Usage: /cancel <id>"


@dataclass(frozen=True)
class CancelArgument:
    task_id: str = ""
    error: str = ""


def parse_cancel_argument(argument: str) -> CancelArgument:
    task_id = str(argument or "").strip()
    if not task_id:
        return CancelArgument(error=CANCEL_USAGE)
    return CancelArgument(task_id=task_id)
