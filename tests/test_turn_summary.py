"""Sobre end-of-turn marker.

A turn that ran at least one tool and fully succeeded prints a single discreet
``✓ N tool(s)`` line. A plain answer (no tools) or a turn with any tool failure
prints no marker — the answer is its own completion and a failure is already
spelled out on its ⎿ line.
"""
from __future__ import annotations

import asyncio
import io
import unittest

from rich.console import Console

from secops_agent.core.agent import (
    ToolCallEvent,
    ToolResultEvent,
    ToolStartEvent,
    TextEvent,
)
from secops_agent.core.tools import ToolResult
from secops_agent.ui.renderer import Renderer


def _run(events_factory) -> str:
    renderer = Renderer()
    renderer.console = Console(width=88, record=True, force_terminal=False, file=io.StringIO())
    asyncio.run(renderer.render_agent_stream(events_factory()))
    return renderer.console.export_text()


class TurnSummaryMarkerTests(unittest.TestCase):
    def test_successful_tool_turn_prints_the_marker(self):
        async def events():
            yield ToolCallEvent("run_shell", {"command": "pwd"}, "c1", permission="allow")
            yield ToolStartEvent("run_shell", {"command": "pwd"}, "c1")
            yield ToolResultEvent(
                "run_shell",
                ToolResult(success=True, output="/home/x\n[Exit Code: 0]", execution_time=0.02),
                "c1",
            )
            yield TextEvent("Voilà le répertoire courant.")
            yield TextEvent("", done=True)

        self.assertIn("✓ 1 tool", _run(events))

    def test_plain_answer_turn_prints_no_marker(self):
        async def events():
            yield TextEvent("Réponse sans outil.")
            yield TextEvent("", done=True)

        self.assertNotIn("✓", _run(events))

    def test_failed_tool_turn_prints_no_marker(self):
        async def events():
            yield ToolCallEvent("run_shell", {"command": "false"}, "c1", permission="allow")
            yield ToolResultEvent(
                "run_shell",
                ToolResult(success=False, output="", error="boom", execution_time=0.02),
                "c1",
            )
            yield TextEvent("", done=True)

        self.assertNotIn("✓", _run(events))


if __name__ == "__main__":
    unittest.main()
