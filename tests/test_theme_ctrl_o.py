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
        # The tool status bullet carries a palette-specific hex (the name is now
        # neutral `text` after G4, so track `success` — the success-tool bullet —
        # which differs across palettes where text/text_muted are shared neutrals).
        paprika_success = T._PALETTES["paprika"]["success"].lower()

        renderer = Renderer()
        renderer.console = Console(theme=T.rich_theme, force_terminal=True,
                                   color_system="truecolor", file=io.StringIO(), width=80)
        runtime = RuntimeState()
        self._render_turn(renderer, runtime)

        # The pre-switch anchor has paprika hex baked in — the leak source.
        self.assertIn(paprika_success, runtime.ctrl_o_anchor_collapsed.lower())

        # The /theme handler switches the palette and drops the caches.
        T.set_theme("neon")
        runtime.reset_ctrl_o_surface(clear_anchor=True)

        # Nothing stale is left to replay into the newly themed flow.
        self.assertEqual(runtime.ctrl_o_anchor_collapsed, "")
        self.assertEqual(runtime.ctrl_o_anchor_expanded, "")
        self.assertEqual(runtime.ctrl_o_transcript_collapsed, "")
        self.assertEqual(runtime.ctrl_o_transcript_expanded, "")


class ThemeSwitchConsoleTests(unittest.TestCase):
    def setUp(self):
        self._original = T.active_theme_name()

    def tearDown(self):
        T.set_theme(self._original)

    def _stack_depth(self, renderer):
        return len(getattr(renderer.console._theme_stack, "_entries", [None]))

    def test_apply_console_theme_does_not_grow_the_stack(self):
        T.set_theme("paprika")
        renderer = Renderer()
        start = self._stack_depth(renderer)
        for name in ("neon", "ember", "sunset", "reef", "paprika"):
            T.set_theme(name)
            renderer.apply_console_theme(T.rich_theme)
        # Bounded: pop-then-push keeps [base, current], never piling up per switch.
        self.assertLessEqual(self._stack_depth(renderer), start + 1)

    def test_renderer_built_after_switch_uses_current_palette(self):
        # A Renderer created mid-session (e.g. the transient one behind ctrl+r)
        # must start on the live palette, not this module's import-time theme.
        T.set_theme("paprika")
        T.set_theme("neon")
        renderer = Renderer()
        heading = renderer.console.get_style("markdown.h2")
        triplet = heading.color.get_truecolor()
        neon = T._PALETTES["neon"]["accent"].lstrip("#")
        self.assertEqual(
            (triplet.red, triplet.green, triplet.blue),
            (int(neon[0:2], 16), int(neon[2:4], 16), int(neon[4:6], 16)),
        )


if __name__ == "__main__":
    unittest.main()
