"""Cleaner tool-result output: a meaningful sysinfo summary and a collapsed
preview that skips decorative noise (emoji banners, `── section ──` rules).

Regression for the `⎿` block that read `sysinfo: (no system facts found)`
followed by leaked `🖥️ System Information` / `── Network ──` decoration.
"""
from __future__ import annotations

import unittest

from secops_agent.core.result_parsers.local import parse_sysinfo_output
from secops_agent.ui.tool_display import _is_noise_line, summarize_output


class SysinfoSummaryTests(unittest.TestCase):
    def test_network_without_hostname_leads_with_a_real_fact(self):
        raw = (
            "🖥️  System Information\n\n"
            "── Network ──\n"
            "  Default Gateway: default via 10.1.1.1 dev ens33\n"
            "  DNS: nameserver 127.0.0.53\n"
        )
        parsed = parse_sysinfo_output(raw, {"category": "network"})
        self.assertNotIn("no system facts found", parsed.summary)
        self.assertIn("Default Gateway", parsed.summary)
        self.assertIn("10.1.1.1", parsed.summary)

    def test_hostname_still_leads(self):
        parsed = parse_sysinfo_output("  Hostname: ubuntu\n  OS: Ubuntu 26.04\n", {})
        self.assertEqual(parsed.summary, "Hostname: ubuntu")

    def test_empty_output_is_not_claimed_as_facts(self):
        parsed = parse_sysinfo_output("   \n  \n", {})
        self.assertNotIn("no system facts found", parsed.summary)
        self.assertIn("no output", parsed.summary)


class NoiseFilterTests(unittest.TestCase):
    def test_decoration_is_noise(self):
        for line in ("🖥️  System Information", "── Network ──", "──────────", "   "):
            self.assertTrue(_is_noise_line(line), f"{line!r} should be noise")

    def test_real_content_is_not_noise(self):
        for line in ("Default Gateway: 10.1.1.1", "ens33  UP  10.1.1.98/24", "lo  127.0.0.1/8"):
            self.assertFalse(_is_noise_line(line), f"{line!r} should be content")

    def test_preview_skips_banner_and_rule(self):
        out = "🖥️  System Information\n── Network ──\nDefault Gateway: 10.1.1.1\nDNS: 127.0.0.53\n"
        joined = " | ".join(summarize_output(out, max_lines=4)["lines"])
        self.assertNotIn("System Information", joined)
        self.assertNotIn("── Network ──", joined)
        self.assertIn("Default Gateway: 10.1.1.1", joined)




if __name__ == "__main__":
    unittest.main()
