"""
Structured error display for the SecOps Agent TUI.
Categorizes errors and provides actionable suggestions.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from rich.console import Console
from rich.markup import escape

from secops_agent.ui.theme import COLORS
from secops_agent.ui import layout


class ErrorCategory(str, Enum):
    """Error categories for structured display."""
    NETWORK = "network"
    AUTH = "authentication"
    TOOL = "tool"
    LLM = "llm"
    PERMISSION = "permission"
    TIMEOUT = "timeout"
    INPUT = "input"
    SYSTEM = "system"


# Suggestion templates keyed by (category, keyword-in-message)
_SUGGESTIONS: dict[tuple[ErrorCategory, str], str] = {
    (ErrorCategory.AUTH, "api"): "Check your GEMINI_API_KEY in .env or pass via --api-key.",
    (ErrorCategory.AUTH, "key"): "Check your GEMINI_API_KEY in .env or pass via --api-key.",
    (ErrorCategory.TIMEOUT, ""): "Increase timeout with TOOL_TIMEOUT env var, or try a faster scan profile.",
    (ErrorCategory.NETWORK, "unreachable"): "Verify the target is online and reachable from this host.",
    (ErrorCategory.NETWORK, "connection"): "Check network connectivity and firewall rules.",
    (ErrorCategory.LLM, "capacity"): "The model is at capacity. Try again shortly or switch models with /model.",
    (ErrorCategory.LLM, "rate"): "Rate limited by the API. Waiting before retry.",
    (ErrorCategory.LLM, "failed"): "LLM request failed. Check your API key and network.",
    (ErrorCategory.PERMISSION, "denied"): "Tool execution was denied. Re-run and approve when prompted.",
    (ErrorCategory.TOOL, "not found"): "This tool is not installed on the system. Install it first.",
    (ErrorCategory.TOOL, "not registered"): "Unknown tool name. Open the tools list to see available tools.",
    (ErrorCategory.INPUT, "usage"): "Check the command syntax with /help.",
}


def _find_suggestion(category: ErrorCategory, message: str) -> str:
    """Find the best matching suggestion for an error."""
    msg_lower = message.lower()
    # Try specific keyword match first
    for (cat, keyword), suggestion in _SUGGESTIONS.items():
        if cat == category and keyword and keyword in msg_lower:
            return suggestion
    # Fall back to category-only match
    for (cat, keyword), suggestion in _SUGGESTIONS.items():
        if cat == category and not keyword:
            return suggestion
    return ""


def classify_error(message: str) -> ErrorCategory:
    """Auto-classify an error message into a category."""
    msg_lower = message.lower()
    if any(k in msg_lower for k in ("usage", "invalid", "missing")):
        return ErrorCategory.INPUT
    if any(k in msg_lower for k in ("api_key", "api key", "apikey", "unauthorized", "authentication")):
        return ErrorCategory.AUTH
    if any(k in msg_lower for k in ("timeout", "timed out")):
        return ErrorCategory.TIMEOUT
    if any(k in msg_lower for k in ("connection", "unreachable", "network", "dns", "socket")):
        return ErrorCategory.NETWORK
    if any(k in msg_lower for k in ("denied", "permission", "approval")):
        return ErrorCategory.PERMISSION
    if any(k in msg_lower for k in ("llm", "gemini", "model", "capacity", "rate limit")):
        return ErrorCategory.LLM
    if any(k in msg_lower for k in ("not found", "not registered", "not installed")):
        return ErrorCategory.TOOL
    return ErrorCategory.SYSTEM


class ErrorRenderer:
    """Renders structured, categorized error messages with suggestions."""

    @staticmethod
    def render(
        console: Console,
        message: str,
        category: Optional[ErrorCategory] = None,
        tool_name: str = "",
        suggestion: str = "",
    ):
        """Render a structured error message.

        Args:
            console: Rich console instance.
            message: The error message.
            category: Error category (auto-detected if None).
            tool_name: Tool name context (optional).
            suggestion: Override suggestion text (auto-found if empty).
        """
        if category is None:
            category = classify_error(message)

        prefix = f"{tool_name}: " if tool_name else ""
        console.print(f"{layout.INDENT_STR}[{COLORS['error']}]⎿  {escape(prefix + message)}[/{COLORS['error']}]")

        # Find and display suggestion
        if not suggestion:
            suggestion = _find_suggestion(category, message)
        if suggestion:
            console.print(
                f"{layout.RESULT_INDENT_STR}[{COLORS['text_muted']}]{suggestion}[/{COLORS['text_muted']}]"
            )

    @staticmethod
    def render_tool_error(
        console: Console,
        tool_name: str,
        message: str,
        execution_time: float = 0.0,
    ):
        """Render a tool-specific error with timing info."""
        from secops_agent.ui.tool_display import format_duration

        time_str = f" ({format_duration(execution_time)})" if execution_time > 0 else ""
        console.print(
            f"{layout.INDENT_STR}[{COLORS['error']}]⎿  {tool_name} failed{time_str}: {message}[/{COLORS['error']}]"
        )

        suggestion = _find_suggestion(classify_error(message), message)
        if suggestion:
            console.print(
                f"{layout.RESULT_INDENT_STR}[{COLORS['text_muted']}]{suggestion}[/{COLORS['text_muted']}]"
            )
