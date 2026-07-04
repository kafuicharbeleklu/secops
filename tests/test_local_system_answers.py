"""Regression tests for A3 (targeted): common phrasings for local IP and OS must
classify as LOCAL_SYSTEM and get a deterministic answer, instead of falling
through to the LLM."""
from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

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


class PublicIpAnswerTests(unittest.TestCase):
    """D4 / RC-β: 'mon adresse ip' is a substring of 'mon adresse ip publique',
    so a public-IP query wrongly returned the local interface, and the English
    'public IP' missed the LOCAL_SYSTEM classifier entirely."""

    def setUp(self) -> None:
        self.router = PreflightRouter(registry=ToolRegistry())

    def _answer(self, prompt: str) -> str:
        return self.router.local_answer(prompt, classify_request(prompt))

    def test_public_ip_english_classifies_local(self) -> None:
        for prompt in ("what is my public IP?", "what's my external ip address?"):
            with self.subTest(prompt=prompt):
                self.assertEqual(
                    classify_request(prompt).technical_goal, TechnicalGoal.LOCAL_SYSTEM
                )

    def test_public_ip_query_fetches_public_not_local(self) -> None:
        with patch(
            "secops_agent.core.preflight.public_ip_address", return_value="203.0.113.7"
        ), patch(
            "secops_agent.core.preflight.public_ip_lookup_enabled", return_value=True
        ):
            answer = self._answer("quelle est mon adresse IP publique ?")
        self.assertIn("203.0.113.7", answer)
        self.assertIn("publique", answer.lower())
        self.assertNotIn("192.168", answer)
        self.assertNotIn("locale", answer.lower())

    def test_public_ip_fetch_failure_is_clean_message(self) -> None:
        with patch(
            "secops_agent.core.preflight.public_ip_address", return_value=""
        ), patch(
            "secops_agent.core.preflight.public_ip_lookup_enabled", return_value=True
        ):
            answer = self._answer("quelle est mon adresse IP publique ?")
        self.assertTrue(answer)
        self.assertIn("publique", answer.lower())
        self.assertNotIn("192.168", answer)

    def test_public_ip_lookup_gate_disabled_does_not_fetch(self) -> None:
        with patch(
            "secops_agent.core.preflight.public_ip_lookup_enabled", return_value=False
        ), patch("secops_agent.core.preflight.public_ip_address") as fetch:
            answer = self._answer("quelle est mon adresse IP publique ?")
        fetch.assert_not_called()
        self.assertTrue(answer)
        self.assertNotIn("192.168", answer)

    def test_local_ip_query_still_returns_local(self) -> None:
        answer = self._answer("quelle est mon adresse IP locale ?")
        self.assertIn("locale", answer.lower())


class CpuLoadAnswerTests(unittest.TestCase):
    """D7: 'quelle est la charge CPU actuelle ?' returned a static core count
    (or fell through to the LLM). It must report the real load average."""

    def setUp(self) -> None:
        self.router = PreflightRouter(registry=ToolRegistry())

    def _answer(self, prompt: str) -> str:
        return self.router.local_answer(prompt, classify_request(prompt))

    def test_cpu_load_phrasings_classify_local(self) -> None:
        for prompt in (
            "quelle est la charge CPU actuelle ?",
            "what is the current CPU load?",
            "utilisation du cpu",
        ):
            with self.subTest(prompt=prompt):
                self.assertEqual(
                    classify_request(prompt).technical_goal, TechnicalGoal.LOCAL_SYSTEM
                )

    def test_cpu_load_answer_reports_load_average(self) -> None:
        answer = self._answer("quelle est la charge CPU actuelle ?")
        self.assertTrue(answer, "no deterministic CPU-load answer")
        self.assertIn("charge", answer.lower())
        # the three load-average figures, e.g. "0.52"
        self.assertRegex(answer, r"\d+\.\d{2}")


class DiskSpaceAnswerTests(unittest.TestCase):
    """D10 (2026-07-04 audit delta): 'combien d'espace disque disponible ?'
    leaked a raw sysinfo line ('CPU cores: 8') — the wrong field *and* a
    raw-summary leak (RC-α/RC-β: no French disk matcher, sysinfo has no bespoke
    answer formatter). It must classify LOCAL_SYSTEM and return a deterministic
    disk-space answer, never the CPU line."""

    def setUp(self) -> None:
        self.router = PreflightRouter(registry=ToolRegistry())

    def _answer(self, prompt: str) -> str:
        return self.router.local_answer(prompt, classify_request(prompt))

    def test_disk_space_phrasings_classify_local(self) -> None:
        for prompt in (
            "combien d'espace disque disponible ?",
            "quel espace disque me reste-t-il ?",
            "how much disk space is left?",
            "disk usage",
        ):
            with self.subTest(prompt=prompt):
                self.assertEqual(
                    classify_request(prompt).technical_goal, TechnicalGoal.LOCAL_SYSTEM
                )

    def test_disk_space_answer_reports_free_space_not_cpu(self) -> None:
        answer = self._answer("combien d'espace disque disponible ?")
        self.assertTrue(answer, "no deterministic disk-space answer")
        # D10 regression: the raw sysinfo line must never leak as the answer.
        self.assertNotIn("CPU cores", answer)
        self.assertNotIn("(+", answer)  # no parser collapse trailer
        # French answer, expressed in Go, with a figure.
        self.assertIn("Go", answer)
        self.assertRegex(answer, r"\d")

    def test_disk_space_english_answer(self) -> None:
        answer = self._answer("how much disk space is left?")
        self.assertTrue(answer)
        self.assertIn("GB", answer)
        self.assertNotIn("CPU cores", answer)


class MemoryAnswerTests(unittest.TestCase):
    """RC-α residual (2026-07-04): 'combien de mémoire vive disponible ?' shared
    D10's leak class — no classifier marker, no local_answer block → routed to
    sysinfo and leaked its first line. Must classify LOCAL_SYSTEM and report RAM,
    never the CPU line."""

    def setUp(self) -> None:
        self.router = PreflightRouter(registry=ToolRegistry())

    def _answer(self, prompt: str) -> str:
        return self.router.local_answer(prompt, classify_request(prompt))

    def test_memory_phrasings_classify_local(self) -> None:
        for prompt in (
            "combien de mémoire vive disponible ?",
            "how much RAM is available?",
            "memory usage",
        ):
            with self.subTest(prompt=prompt):
                self.assertEqual(
                    classify_request(prompt).technical_goal, TechnicalGoal.LOCAL_SYSTEM
                )

    def test_memory_answer_reports_ram_not_cpu(self) -> None:
        if not Path("/proc/meminfo").exists():
            self.skipTest("no /proc/meminfo on this platform")
        answer = self._answer("combien de mémoire vive disponible ?")
        self.assertTrue(answer, "no deterministic memory answer")
        self.assertNotIn("CPU cores", answer)
        self.assertNotIn("(+", answer)  # no parser collapse trailer
        self.assertIn("Go", answer)  # French
        self.assertRegex(answer, r"\d")

    def test_memory_english_answer(self) -> None:
        if not Path("/proc/meminfo").exists():
            self.skipTest("no /proc/meminfo on this platform")
        answer = self._answer("how much RAM is available?")
        self.assertTrue(answer)
        self.assertIn("GB", answer)
        self.assertNotIn("CPU cores", answer)


class TransientNoticeLanguageParityTests(unittest.TestCase):
    """RC-β: the transient-error notice used a *separate* prefers_french that
    missed 'combien', so a French question got an English notice. The agent's
    detector is now unified with the preflight one."""

    def test_agent_prefers_french_matches_preflight(self) -> None:
        from secops_agent.core.agent import SecOpsAgent

        self.assertTrue(SecOpsAgent._prefers_french("combien de mémoire vive disponible ?"))
        self.assertTrue(SecOpsAgent._prefers_french("quelle heure est-il ?"))
        self.assertFalse(SecOpsAgent._prefers_french("how much RAM is available?"))


if __name__ == "__main__":
    unittest.main()
