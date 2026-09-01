"""Switching theme must not leave stale-coloured ctrl+o content to replay.

The ctrl+o anchor/transcript caches store Rich markup with the palette's hex
baked in at build time. After a theme switch, replaying a pre-switch cache would
mix old colours into the new flow, so the /theme handler drops those caches
(runtime.reset_ctrl_o_surface(clear_anchor=True)). This test reproduces the leak
and verifies the reset removes it.
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
from secops_agent.ui import theme as T
from secops_agent.ui.renderer import Renderer
from secops_agent.ui.runtime import RuntimeState


class ThemeSwitchCtrlOTests(unittest.TestCase):
    def setUp(self):
        self._original = T.active_theme_name()

    def tearDown(self):
        T.set_theme(self._original)

    def _render_turn(self, renderer, runtime):
        async def events():
            yield ToolCallEvent("nmap_scan", {"target": "10.0.0.1"}, "c1", permission="allow")
            yield ToolStartEvent("nmap_scan", {"target": "10.0.0.1"}, "c1")
            yield ToolResultEvent(
                "nmap_scan",
                ToolResult(success=True, output="22/tcp open", execution_time=0.4,
                           metadata={"parsed_summary": "1 service"}),
                "c1",
            )
            yield TextEvent("Un service.")
            yield TextEvent("", done=True)

        asyncio.run(renderer.render_agent_stream(events(), runtime=runtime))

    def test_theme_switch_reset_drops_stale_coloured_anchor(self):
        T.set_theme("paprika")
        paprika_accent = T._PALETTES["paprika"]["accent_bright"].lower()

        renderer = Renderer()
        renderer.console = Console(theme=T.rich_theme, force_terminal=True,
                                   color_system="truecolor", file=io.StringIO(), width=80)
        runtime = RuntimeState()
        self._render_turn(renderer, runtime)

        # The pre-switch anchor has paprika hex baked in — the leak source.
        self.assertIn(paprika_accent, runtime.ctrl_o_anchor_collapsed.lower())

        # The /theme handler switches the palette and drops the caches.
        T.set_theme("neon")
        runtime.reset_ctrl_o_surface(clear_anchor=True)

        # Nothing stale is left to replay into the newly themed flow.
        self.assertEqual(runtime.ctrl_o_anchor_collapsed, "")
        self.assertEqual(runtime.ctrl_o_anchor_expanded, "")
        self.assertEqual(runtime.ctrl_o_transcript_collapsed, "")
        self.assertEqual(runtime.ctrl_o_transcript_expanded, "")


if __name__ == "__main__":
    unittest.main()
