"""FMT-01 (severity-tiered risk badge) and FMT-06 (operational context in the
streaming/tool footer), from docs/UX_RESEARCH_PROPOSAL_2026-09-01.md.

Both surfaces render context that already existed but was invisible at the
critical moment: the R0-R8 badge was shown in flat grey (an R8 looked like an
R0), and the streaming footer carried only the model name while the input
statusline was off-screen.
"""
from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from rich.console import Console

import secops_agent.main as main_module
from secops_agent.ui.theme import COLORS, friendly_model_name
from secops_agent.ui.tool_display import ToolCallBox, _risk_badge_markup


class RiskBadgeColourTests(unittest.TestCase):
    """FMT-01: the R0-R8 badge is coloured by severity tier."""

    def _markup_for(self, token: str) -> str:
        with patch("secops_agent.ui.tool_display._tool_risk_badge", return_value=token):
            return _risk_badge_markup("any_tool")

    def test_high_tiers_use_danger_colours(self):
        r8 = self._markup_for("R8")
        self.assertIn(COLORS["danger_bright"], r8)
        self.assertIn("bold", r8)
        self.assertIn("R8", r8)
        r6 = self._markup_for("R6")
        self.assertIn(COLORS["danger"], r6)
        self.assertIn("R6", r6)

    def test_mid_tiers_use_warning_colour(self):
        for token in ("R3", "R4", "R5"):
            self.assertIn(COLORS["warning"], self._markup_for(token))

    def test_passive_tiers_stay_muted(self):
        # R0-R2 (passive band) share the quiet muted grey - legible, not near-invisible
        self.assertIn(COLORS["text_muted"], self._markup_for("R0"))
        self.assertIn(COLORS["text_muted"], self._markup_for("R1"))
        self.assertIn(COLORS["text_muted"], self._markup_for("R2"))

    def test_unknown_tier_falls_back_to_muted(self):
        markup = self._markup_for("R?")
        self.assertIn(COLORS["text_dim"], markup)
        self.assertIn("R?", markup)

    def test_tool_call_row_emits_severity_colour(self):
        # End-to-end: ToolCallBox.render paints the badge with the tier colour,
        # not the old flat text_dim wrapper.
        console = Console(force_terminal=True, color_system="truecolor", width=100)
        with patch("secops_agent.ui.tool_display._tool_risk_badge", return_value="R8"):
            with console.capture() as cap:
                ToolCallBox.render(console, "generate_payload", {"target": "x"})
        out = cap.get()
        r, g, b = (int(COLORS["danger_bright"][i:i + 2], 16) for i in (1, 3, 5))
        self.assertIn(f"{r};{g};{b}", out)


class StatusRightFooterTests(unittest.TestCase):
    """FMT-06: the streaming/tool footer carries operational context."""

    def _status_right(self, payload: dict) -> str:
        agent = SimpleNamespace(llm=SimpleNamespace(model_name="gemini-2.5-flash"))
        with patch.object(main_module, "_statusline_payload", return_value=payload):
            return main_module._status_right(agent, runtime=object())

    def test_footer_includes_permission_autonomy_sandbox_phase(self):
        text = self._status_right(
            {
                "permissions": "proceed-in-sandbox",
                "autonomy": "auto",
                "sandbox": True,
                "phase": "recon",
            }
        )
        self.assertIn("proceed-in-sandbox", text)
        self.assertIn("auto:auto", text)
        self.assertIn("sandbox", text)
        self.assertIn("phase:recon", text)

    def test_model_leads_the_footer(self):
        text = self._status_right({"permissions": "perm default"})
        self.assertTrue(text.startswith(friendly_model_name("gemini-2.5-flash")))

    def test_empty_optional_segments_are_omitted(self):
        text = self._status_right(
            {"permissions": "", "autonomy": "", "sandbox": False, "phase": ""}
        )
        self.assertEqual(text, friendly_model_name("gemini-2.5-flash"))


if __name__ == "__main__":
    unittest.main()
