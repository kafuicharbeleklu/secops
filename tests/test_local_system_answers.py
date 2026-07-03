"""Regression tests for A3 (targeted): common phrasings for local IP and OS must
classify as LOCAL_SYSTEM and get a deterministic answer, instead of falling
through to the LLM."""
from __future__ import annotations

import unittest

from secops_agent.core.preflight import PreflightRouter
from secops_agent.core.request_context import TechnicalGoal, classify_request
from secops_agent.core.tools import ToolRegistry


class LocalSystemPhrasingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.router = PreflightRouter(registry=ToolRegistry())

    def _answer(self, prompt: str) -> str:
        return self.router.local_answer(prompt, classify_request(prompt))

    def test_local_ip_phrasings(self) -> None:
        for prompt in ("what is my local IP address?", "what's my local ip"):
            with self.subTest(prompt=prompt):
                self.assertEqual(
                    classify_request(prompt).technical_goal, TechnicalGoal.LOCAL_SYSTEM
                )
                self.assertTrue(self._answer(prompt))

    def test_os_phrasings(self) -> None:
        for prompt in ("what OS am I running?", "which OS is this?"):
            with self.subTest(prompt=prompt):
                self.assertEqual(
                    classify_request(prompt).technical_goal, TechnicalGoal.LOCAL_SYSTEM
                )
                answer = self._answer(prompt)
                self.assertTrue(answer)
                self.assertIn("kernel", answer.lower())

    def test_french_tools_installed_phrasings_classify_local(self) -> None:
        """D1b / D9: the French phrasings for "which tools are installed" must
        classify as LOCAL_SYSTEM (they fell through to UNKNOWN → the LLM →
        wrong tool)."""
        for prompt in (
            "quels outils offensifs sont installés ?",
            "quels outils sont installés ?",
            "quel outil est installé ?",
        ):
            with self.subTest(prompt=prompt):
                self.assertEqual(
                    classify_request(prompt).technical_goal, TechnicalGoal.LOCAL_SYSTEM
                )

    def test_french_tools_answer_is_french_and_lists_tools(self) -> None:
        answer = self._answer("quels outils offensifs sont installés ?")
        self.assertTrue(answer, "no deterministic answer for the French tools query")
        # French output, not the English "Local tooling / Installed / Not found".
        self.assertIn("install", answer.lower())
        self.assertNotIn("Local tooling", answer)
        self.assertNotIn("Not found", answer)
        # nmap is present on this host's common set; the overview must name it.
        self.assertIn("nmap", answer)


if __name__ == "__main__":
    unittest.main()
