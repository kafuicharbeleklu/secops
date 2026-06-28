"""Pure parsing helpers for tool slash commands."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ToolArgument:
    action: str
    tool_name: str = ""


def parse_tool_argument(argument: str) -> ToolArgument:
    tool_name = str(argument or "").strip()
    if not tool_name:
        return ToolArgument(action="list")
    return ToolArgument(action="detail", tool_name=tool_name)
