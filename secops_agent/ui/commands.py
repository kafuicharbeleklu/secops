"""
Slash command metadata shared by the prompt completer and help renderer.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class CommandSpec:
    name: str
    description: str
    category: str
    alias: str | None = None
    usage: str | None = None
    implemented: bool = True

    @property
    def display_name(self) -> str:
        return self.usage or self.name


COMMANDS: tuple[CommandSpec, ...] = (
    CommandSpec("/add-dir", "Add a directory to the active workspace", "Workspace", usage="/add-dir <path>"),
    CommandSpec("/agents", "Show the agent orchestration view", "Tasks"),
    CommandSpec("/artifact", "Review generated artifacts", "Session", alias="/artifacts", usage="/artifact [id|list]"),
    CommandSpec("/attach", "Attach an evidence file to this session", "Session", alias="/attachments", usage="/attach <path> [note]"),
    CommandSpec("/auto", "Toggle automatic execution of the planner", "Configuration", usage="/auto [on|off]"),
    CommandSpec("/btw", "Ask a side question without changing the main flow", "Tasks", usage="/btw <query>"),
    CommandSpec("/cancel", "Cancel a running background task", "Tasks", usage="/cancel <id>"),
    CommandSpec("/clear", "Clear the terminal and conversation context", "Core"),
    CommandSpec("/config", "Show current runtime configuration", "Configuration", alias="/settings"),
    CommandSpec("/context", "Show model, message, token, and tool context", "Core"),
    CommandSpec("/diff", "Show workspace changes", "Workspace"),
    CommandSpec("/exit", "Exit the TUI session", "Core"),
    CommandSpec("/export", "Export the current session to Markdown", "Session", usage="/export <name>"),
    CommandSpec("/fast", "Toggle fast-response profile", "Configuration"),
    CommandSpec("/help", "Show slash command reference", "Core"),
    CommandSpec("/history", "Show session statistics", "Session"),
    CommandSpec("/hooks", "Show tool execution hooks", "Extensions"),
    CommandSpec("/keybindings", "Show keyboard shortcuts", "Configuration"),
    CommandSpec("/load", "Load a saved session", "Session", usage="/load <name>"),
    CommandSpec("/mcp", "Show MCP server runtime", "Extensions"),
    CommandSpec("/lessons", "Review and validate cross-mission lessons", "Session", usage="/lessons [list | review <id> <reviewed|blocked|deprecated> [note]]"),
    CommandSpec("/model", "Switch the active model", "Configuration", usage="/model [auto|gemini|gemma|gemma-high|gemma-31b-off|gemma-31b]"),
    CommandSpec("/permissions", "Show or edit tool approval policy", "Configuration", alias="/permission", usage="/permissions [allow|ask|deny|clear] <resource>"),
    CommandSpec("/resume", "Resume a previous conversation", "Session"),
    CommandSpec("/rewind", "Restore an earlier checkpoint", "Session"),
    CommandSpec("/sandbox", "Show or toggle restricted command execution", "Configuration", usage="/sandbox [on|off|status]"),
    CommandSpec("/save", "Save the current session", "Session", usage="/save <name>"),
    CommandSpec("/sessions", "List saved sessions", "Session"),
    CommandSpec("/skills", "Show active workspace/global skills", "Extensions"),
    CommandSpec("/statusline", "Show status line fields and state payload", "Configuration"),
    CommandSpec("/task", "Show background task details", "Tasks", usage="/task <id> [logs]"),
    CommandSpec("/tasks", "Show the task-filtered orchestration view", "Tasks"),
    CommandSpec("/trajectory", "Open the full conversation and tool timeline", "Session"),
    CommandSpec("/tool", "Show registered SecOps tool details", "Tools", usage="/tool <name>"),
    CommandSpec("/tools", "List registered SecOps tools", "Tools"),
)


ALIASES: dict[str, str] = {
    spec.alias: spec.name for spec in COMMANDS if spec.alias
}


def iter_commands(include_aliases: bool = False) -> Iterable[CommandSpec]:
    yield from COMMANDS
    if include_aliases:
        for alias, target in ALIASES.items():
            target_spec = get_command(target)
            if target_spec:
                yield CommandSpec(
                    alias,
                    f"Alias for {target}",
                    target_spec.category,
                    implemented=target_spec.implemented,
                )


def get_command(name: str) -> CommandSpec | None:
    canonical = ALIASES.get(name, name)
    return next((spec for spec in COMMANDS if spec.name == canonical), None)
