"""Regression tests for deterministic local date/time answers.

A1 (P0): date/time queries such as "what's today's date?" must be answered from
the system clock via the preflight local answer, never left to the LLM (which
hallucinates a training-data date). Covers both halves of the bug:
  * the request must classify as LOCAL_SYSTEM, and
  * PreflightRouter.local_answer must return a real, clock-derived answer.
"""
from __future__ import annotations

import datetime
import unittest

from secops_agent.core.preflight import PreflightRouter
from secops_agent.core.request_context import TechnicalGoal, classify_request
from secops_agent.core.tools import ToolRegistry


class LocalDateTimeAnswerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.router = PreflightRouter(registry=ToolRegistry())

    def _answer(self, prompt: str) -> str:
        return self.router.local_answer(prompt, classify_request(prompt))

    def test_date_phrasings_classify_as_local_system(self) -> None:
        for prompt in (
            "what's today's date?",
            "what is the current date and time?",
            "what is the date today",
            "quelle est la date aujourd'hui",
        ):
            with self.subTest(prompt=prompt):
                self.assertEqual(
                    classify_request(prompt).technical_goal,
                    TechnicalGoal.LOCAL_SYSTEM,
                )

    def test_date_query_answered_from_system_clock(self) -> None:
        year = str(datetime.datetime.now().year)
        for prompt in (
            "what's today's date?",
            "what is the current date and time?",
        ):
            with self.subTest(prompt=prompt):
                answer = self._answer(prompt)
                self.assertTrue(answer, f"no deterministic answer for {prompt!r}")
                self.assertIn(year, answer)


class TimezoneAnswerTests(unittest.TestCase):
    """Regression tests for A2: a requested timezone must actually be applied,
    not silently answered with the local system timezone."""

    def setUp(self) -> None:
        self.router = PreflightRouter(registry=ToolRegistry())

    def _answer(self, prompt: str) -> str:
        return self.router.local_answer(prompt, classify_request(prompt))

    def test_resolve_known_timezones(self) -> None:
        from secops_agent.core.preflight import resolve_requested_timezone

        zone, label = resolve_requested_timezone("what time is it in Tokyo?")
        self.assertIsNotNone(zone)
        self.assertEqual(label, "Tokyo")

        zone_utc, label_utc = resolve_requested_timezone("what time is it in UTC?")
        self.assertIsNotNone(zone_utc)
        self.assertEqual(label_utc, "UTC")

        zone_none, label_none = resolve_requested_timezone("what time is it?")
        self.assertIsNone(zone_none)
        self.assertEqual(label_none, "")

    def test_resolve_country_names_french_and_english(self) -> None:
        """D2/RC-β: the resolver is French-first, so countries named in either
        language (and French city spellings) must map to the right IANA zone —
        not fall through to the host timezone."""
        from secops_agent.core.preflight import resolve_requested_timezone

        cases = [
            ("quelle heure est-il en France ?", "Europe/Paris", "France"),
            ("what time is it in France?", "Europe/Paris", "France"),
            ("quelle heure est-il au Japon ?", "Asia/Tokyo", "Japon"),
            ("quelle heure au Royaume-Uni ?", "Europe/London", "Royaume-Uni"),
            ("il est quelle heure à Londres ?", "Europe/London", "Londres"),
        ]
        for prompt, iana, label_expected in cases:
            with self.subTest(prompt=prompt):
                zone, label = resolve_requested_timezone(prompt)
                self.assertIsNotNone(zone, f"no zone resolved for {prompt!r}")
                self.assertEqual(str(zone), iana)
                self.assertEqual(label, label_expected)

    def test_resolve_country_family_coverage(self) -> None:
        """E1 (live re-audit 2026-07-04): the two most common English names for
        the UK and the US ("UK", "US", "United Kingdom", "England", "Britain",
        "America") fell through to the host timezone. The fix is family-level:
        every common EN/FR country name/abbreviation must resolve, not just the
        one reported. This closes the whole time/timezone family."""
        from secops_agent.core.preflight import resolve_requested_timezone

        cases = [
            # United Kingdom family
            ("what time is it in the UK?", "Europe/London"),
            ("what time is it in the United Kingdom?", "Europe/London"),
            ("what time is it in England?", "Europe/London"),
            ("what time is it in Britain?", "Europe/London"),
            ("what time is it in Great Britain?", "Europe/London"),
            # United States family
            ("what time is it in the US?", "America/New_York"),
            ("what time is it in the USA?", "America/New_York"),
            ("what time is it in the United States?", "America/New_York"),
            ("what time is it in America?", "America/New_York"),
            # neighbours added for family completeness
            ("what time is it in Mexico?", "America/Mexico_City"),
            ("quelle heure est-il au Mexique ?", "America/Mexico_City"),
            ("what time is it in the Netherlands?", "Europe/Amsterdam"),
            # guards: existing coverage must not regress
            ("what time is it in Germany?", "Europe/Berlin"),
            ("quelle heure au Royaume-Uni ?", "Europe/London"),
        ]
        for prompt, iana in cases:
            with self.subTest(prompt=prompt):
                zone, label = resolve_requested_timezone(prompt)
                self.assertIsNotNone(zone, f"no zone resolved for {prompt!r}")
                self.assertEqual(str(zone), iana, f"{prompt!r} -> {zone}")
                self.assertTrue(label, f"empty label for {prompt!r}")

    def test_uk_time_answer_uses_london_zone_not_host(self) -> None:
        """E1 end-to-end: 'in the UK' must render Europe/London (GMT/BST),
        proving it no longer falls back to the host clock."""
        answer = self._answer("what time is it in the UK?")
        self.assertTrue("GMT" in answer or "BST" in answer, answer)
        self.assertNotIn("The current system time is", answer)

    def test_france_time_answer_renders_paris_zone(self) -> None:
        answer = self._answer("quelle heure est-il en France ?")
        self.assertIn("France", answer)
        # %Z for Europe/Paris renders CET/CEST (season-dependent); its presence
        # proves the stamp was rendered in Europe/Paris, not the host zone.
        self.assertTrue("CET" in answer or "CEST" in answer, answer)

    def test_tokyo_time_uses_tokyo_zone(self) -> None:
        answer = self._answer("what time is it in Tokyo?")
        self.assertIn("Tokyo", answer)
        # %Z for Asia/Tokyo renders JST year-round; its presence proves the
        # answer was rendered in Asia/Tokyo, not the local zone.
        self.assertIn("JST", answer)

    def test_plain_time_query_stays_local(self) -> None:
        answer = self._answer("what time is it on my system?")
        self.assertIn("The current system time is", answer)


class TimestampAnswerTests(unittest.TestCase):
    """Regression tests for A6: unix-timestamp requests get a real epoch answer."""

    def setUp(self) -> None:
        self.router = PreflightRouter(registry=ToolRegistry())

    def _answer(self, prompt: str) -> str:
        return self.router.local_answer(prompt, classify_request(prompt))

    def test_timestamp_classifies_as_local_system(self) -> None:
        self.assertEqual(
            classify_request("give me a unix timestamp").technical_goal,
            TechnicalGoal.LOCAL_SYSTEM,
        )

    def test_timestamp_answer_contains_epoch(self) -> None:
        import re

        answer = self._answer("give me a unix timestamp")
        self.assertTrue(answer)
        self.assertRegex(answer, r"\b\d{10}\b")


if __name__ == "__main__":
    unittest.main()
