"""Regression tests for RC-α / D1, D1b, D5-leak (gap G1).

The parser's collapsed-preview trailer ("<lead>  (+N more line(s))") is a
display hint for the Ctrl+O view — it must NEVER reach the user-facing answer
channel. Both leak sites (the local-preflight turn and the A5 synthesis-failure
fallback) route through SecOpsAgent._format_tool_answer_summary, so that helper
must (a) give vpn_status / lab_setup_check clean bespoke sentences and (b) strip
the collapse trailer from any other tool's summary.
"""
from __future__ import annotations

import unittest

from secops_agent.core.agent import SecOpsAgent
from secops_agent.core.memory import ConversationMemory
from secops_agent.core.permissions import PermissionEngine
from secops_agent.core.result_parsers.base import ParsedResult
from secops_agent.core.tools import ToolRegistry


class _StubLLM:
    model_name = "stub"

    def prepare_for_prompt(self, prompt: str, **kwargs):
        return None

    async def stream_chat(self, *args, **kwargs):  # pragma: no cover - never called
        raise AssertionError("LLM must not be called by _format_tool_answer_summary")
        yield  # pragma: no cover


VPN_DISCONNECTED_RAW = (
    "VPN status: disconnected\n"
    "Conclusion: No active VPN tunnel or OpenVPN process was detected.\n"
    "\n"
    "TUN interfaces:\n"
    "  none\n"
    "\n"
    "OpenVPN processes:\n"
    "  none"
)

VPN_CONNECTED_RAW = (
    "VPN status: connected\n"
    "Conclusion: VPN tunnel is active and usable.\n"
    "\n"
    "TUN interfaces:\n"
    "  - tun0: UP · active · 10.8.0.2\n"
    "\n"
    "OpenVPN processes:\n"
    "  - openvpn --config lab.ovpn"
)

LAB_SETUP_RAW = (
    "Local Lab Setup: Authorized lab\n"
    "\n"
    "Platform:\n"
    "  Key: lab\n"
    "  Hint: Use only authorized targets.\n"
    "\n"
    "OS:\n"
    '  PRETTY_NAME="Ubuntu 24.04 LTS"\n'
    "\n"
    "VPN configs:\n"
    "  Search directory: /home/x/Downloads\n"
    "  No .ovpn/.conf files found in the search directory.\n"
    "\n"
    "Tools:\n"
    "  nmap: /usr/bin/nmap\n"
    "  nikto: /usr/bin/nikto\n"
    "  ffuf: not installed\n"
    "  sqlmap: not installed\n"
    "  searchsploit: not installed\n"
    "  sudo: ready for non-interactive use\n"
    "\n"
    "Wordlists:\n"
    "  Status: available\n"
)


class AnswerSummaryLeakTests(unittest.TestCase):
    def setUp(self) -> None:
        self.agent = SecOpsAgent(
            llm=_StubLLM(),
            registry=ToolRegistry(),
            memory=ConversationMemory(),
            permissions=PermissionEngine(),
        )

    def _summary(self, tool_name: str, raw: str, collapse: str) -> str:
        parsed = ParsedResult(tool_name=tool_name, raw_output=raw, summary=collapse)
        return self.agent._format_tool_answer_summary(tool_name, {}, parsed)

    def test_vpn_status_disconnected_is_clean_french(self) -> None:
        answer = self._summary(
            "vpn_status",
            VPN_DISCONNECTED_RAW,
            "VPN status: disconnected  (+5 more line(s))",
        )
        self.assertNotIn("(+", answer)
        self.assertNotIn("more line(s)", answer)
        self.assertIn("Non", answer)
        self.assertIn("VPN", answer)

    def test_vpn_status_connected_reports_active(self) -> None:
        answer = self._summary(
            "vpn_status",
            VPN_CONNECTED_RAW,
            "VPN status: connected  (+6 more line(s))",
        )
        self.assertNotIn("(+", answer)
        self.assertIn("Oui", answer)

    def test_lab_setup_lists_installed_and_missing_tools(self) -> None:
        answer = self._summary(
            "lab_setup_check",
            LAB_SETUP_RAW,
            "Local Lab Setup: Authorized lab  (+32 more line(s))",
        )
        self.assertNotIn("(+", answer)
        self.assertNotIn("more line(s)", answer)
        # installed tools present, missing tools present, sudo excluded
        self.assertIn("nmap", answer)
        self.assertIn("ffuf", answer)
        self.assertNotIn("sudo", answer)
        self.assertIn("Outils installés", answer)

    def test_generic_tool_summary_strips_collapse_trailer(self) -> None:
        answer = self._summary(
            "sysinfo",
            "Hostname: box\nUptime: 3h\nCPU: 8 cores\n(+ more)",
            "Hostname: box  (+7 more line(s))",
        )
        self.assertEqual(answer, "Hostname: box")


if __name__ == "__main__":
    unittest.main()
