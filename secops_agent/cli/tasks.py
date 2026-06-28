"""Pure parsing helpers for task-related slash commands."""

from __future__ import annotations

from dataclasses import dataclass


TASK_USAGE = "Usage: /task <id> [logs]"
TASK_LOG_ACTIONS = frozenset({"log", "logs", "output", "open"})


@dataclass(frozen=True)
class TaskArgument:
    task_id: str = ""
    action: str = "detail"
    error: str = ""


def parse_task_argument(argument: str) -> TaskArgument:
    text = str(argument or "").strip()
    if not text:
        return TaskArgument(error=TASK_USAGE)

    task_id, separator, action_text = text.partition(" ")
    action = action_text.strip().lower() if separator else ""
    if action in TASK_LOG_ACTIONS:
        return TaskArgument(task_id=task_id, action="logs")
    return TaskArgument(task_id=task_id, action="detail")
