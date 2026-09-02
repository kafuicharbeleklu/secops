"""ANIM-03 (elapsed-based warming of the wait indicator) and X-03 (OSC 8
hyperlinks), from docs/UX_RESEARCH_PROPOSAL_2026-09-01.md.

ANIM-03: a long turn should visibly read as "still working" — the wait label
warms from muted grey to amber (~10s) to gold (~30s).
X-03: file paths / URLs / CVE refs become clickable where the terminal supports
OSC 8 links, and degrade to plain text where it does not.
"""
from __future__ import annotations

import io
import unittest

from rich.console import Console

from secops_agent.ui.animations import format_wait_message, wait_urgency_color
from secops_agent.ui.theme import COLORS, file_link, hyperlink


class WaitUrgencyTests(unittest.TestCase):
    def test_color_thresholds(self):
        # The wait ramp stays in the accent family so it never reads as a
        # different theme: muted grey → accent → brighter accent.
        self.assertEqual(wait_urgency_color(0), COLORS["text_muted"])
        self.assertEqual(wait_urgency_color(9.9), COLORS["text_muted"])
        self.assertEqual(wait_urgency_color(10), COLORS["accent"])          # boundary
        self.assertEqual(wait_urgency_color(29.9), COLORS["accent"])
        self.assertEqual(wait_urgency_color(30), COLORS["accent_bright"])   # boundary

    def test_message_colour_follows_elapsed(self):
        early = format_wait_message("Running", 5, include_tip=False)
        warm = format_wait_message("Running", 15, include_tip=False)
        urgent = format_wait_message("Running", 35, include_tip=False)
        self.assertIn(COLORS["text_muted"], early)
        self.assertIn(COLORS["accent"], warm)
        self.assertIn(COLORS["accent_bright"], urgent)
        # the message text survives the recolouring
        self.assertIn("Running", warm)

    def test_tip_branch_still_warms(self):
        warm = format_wait_message("Running", 15, include_tip=True)
        self.assertIn(COLORS["accent"], warm)
        self.assertIn("Tip:", warm)


class HyperlinkTests(unittest.TestCase):
    def test_hyperlink_markup(self):
        self.assertEqual(
            hyperlink("CVE-2021-44228", "https://example.test/x"),
            "[link=https://example.test/x]CVE-2021-44228[/link]",
        )

    def test_file_link_structure(self):
        self.assertRegex(file_link("/tmp/report.md"), r"^\[link=file://.*\]/tmp/report\.md\[/link\]$")

    def test_file_link_custom_label(self):
        link = file_link("/tmp/report.md", label="report.md")
        self.assertTrue(link.endswith("]report.md[/link]"))

    def test_file_link_emits_osc8_on_a_tty(self):
        buf = io.StringIO()
        console = Console(file=buf, force_terminal=True)
        console.print(file_link("/tmp/report.md"))
        out = buf.getvalue()
        self.assertIn("\x1b]8;", out)
        self.assertIn("report.md", out)

    def test_file_link_never_raises(self):
        self.assertIsInstance(file_link(""), str)


if __name__ == "__main__":
    unittest.main()
