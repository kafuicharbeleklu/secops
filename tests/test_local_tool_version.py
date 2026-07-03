"""Regression tests for A7: "what version of <tool> is installed" / "what tools
are installed" are LOCAL questions and must be answered locally — while remote
service-version questions must stay SERVICE_ENUM (not hijacked)."""
from __future__ import annotations

import unittest
from unittest.mock import patch

from secops_agent.core.preflight import PreflightRouter, describe_local_tools
from secops_agent.core.request_context import TechnicalGoal, classify_request
from secops_agent.core.tools import ToolRegistry


class LocalToolVersionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.router = PreflightRouter(registry=ToolRegistry())

    def _answer(self, prompt: str) -> str:
        return self.router.local_answer(prompt, classify_request(prompt))

    def test_local_tool_version_classifies_local(self) -> None:
        self.assertEqual(
            classify_request("what version of nmap is installed?").technical_goal,
            TechnicalGoal.LOCAL_SYSTEM,
        )

    def test_remote_service_version_stays_service_enum(self) -> None:
        # guard: a remote target's service version must not be hijacked to local
        decision = classify_request("what version of apache is running on 10.10.10.5?")
        self.assertEqual(decision.technical_goal, TechnicalGoal.SERVICE_ENUM)

    def test_local_tool_version_answer_names_tool(self) -> None:
        answer = self._answer("what version of nmap is installed?")
        self.assertTrue(answer)
        self.assertIn("nmap", answer.lower())

    def test_what_tools_installed_is_answered(self) -> None:
        self.assertEqual(
            classify_request("what tools are installed?").technical_goal,
            TechnicalGoal.LOCAL_SYSTEM,
        )
        self.assertTrue(self._answer("what tools are installed?"))


class FrenchSingleToolWordingTests(unittest.TestCase):
    """D8: a French question about one tool must read as a natural French
    sentence, not the English 'sqlmap: not installed' status line."""

    def test_french_single_tool_not_installed_is_clean_sentence(self) -> None:
        with patch("secops_agent.core.preflight.shutil.which", return_value=None):
            answer = describe_local_tools("quelle version de sqlmap est installée ?")
        self.assertEqual(answer, "sqlmap n'est pas installé.")

    def test_english_single_tool_keeps_status_format(self) -> None:
        with patch("secops_agent.core.preflight.shutil.which", return_value=None):
            answer = describe_local_tools("what version of sqlmap is installed?")
        self.assertIn("sqlmap", answer)
        self.assertIn("not installed", answer)


if __name__ == "__main__":
    unittest.main()
