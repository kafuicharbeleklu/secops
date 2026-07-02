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
