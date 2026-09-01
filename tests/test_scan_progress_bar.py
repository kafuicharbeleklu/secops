"""ANIM-01 — determinate progress bar for long scans, from
docs/UX_RESEARCH_PROPOSAL_2026-09-01.md.

Tools already emit ``ToolProgressEvent(percent=...)`` (nmap 5→100, VPN handshake,
recon); the tool spinner showed the percentage as bare text.  ANIM-01 renders a
visual determinate bar when a percentage is present, and leaves the
indeterminate spinner untouched when it is not.
"""
from __future__ import annotations

import unittest

from secops_agent.ui.animations import ToolExecutionSpinner, _render_progress_bar
from secops_agent.ui.theme import COLORS


class ProgressBarTests(unittest.TestCase):
    def test_bar_width_is_constant_across_fill(self):
        for pct in (0, 25, 50, 100):
            bar = _render_progress_bar(pct, width=10)
            self.assertEqual(bar.count("━"), 10)
            self.assertIn(f"{pct:.0f}%", bar)

    def test_running_fill_uses_accent_completion_uses_success(self):
        self.assertIn(COLORS["accent"], _render_progress_bar(50, width=10))
        self.assertIn(COLORS["success"], _render_progress_bar(100, width=10))

    def test_half_fill_splits_evenly(self):
        bar = _render_progress_bar(50, width=10)
        # 5 filled cells in the accent segment, 5 dim cells in the remainder
        accent_seg = bar.split("[/]")[0]
        self.assertEqual(accent_seg.count("━"), 5)

    def test_percentage_is_clamped(self):
        self.assertIn("100%", _render_progress_bar(150, width=8))
        self.assertIn("0%", _render_progress_bar(-20, width=8))


class SpinnerMessageTests(unittest.TestCase):
    def test_spinner_renders_bar_when_percent_present(self):
        spinner = ToolExecutionSpinner("nmap_scan")
        spinner._phase = "running port scan"
        spinner._percent = 58.0
        message = spinner._format_message(3.0)
        self.assertIn("━", message)
        self.assertIn("58%", message)

    def test_spinner_has_no_bar_without_percent(self):
        spinner = ToolExecutionSpinner("dns_lookup")
        spinner._phase = "resolving"
        spinner._percent = None
        message = spinner._format_message(3.0)
        self.assertNotIn("━", message)


if __name__ == "__main__":
    unittest.main()
