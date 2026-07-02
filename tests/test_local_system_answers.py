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


if __name__ == "__main__":
    unittest.main()
