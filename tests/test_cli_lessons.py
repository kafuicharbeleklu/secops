"""Tests for the /lessons command (Phase 3.2 — human validation of lessons).

The store-side ``review_lesson`` is already covered by test_experience_memory;
these tests pin the CLI parsing/formatting that exposes it to the operator.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from secops_agent.cli.lessons import (  # noqa: E402
    LESSONS_USAGE,
    VALID_REVIEW_STATUSES,
    format_lessons_for_review,
    parse_lessons_command,
)
from secops_agent.core.experience import CaseLesson  # noqa: E402


class ParseLessonsCommandTests(unittest.TestCase):
    def test_empty_argument_defaults_to_list(self):
        self.assertEqual(parse_lessons_command("").action, "list")

    def test_list_keyword(self):
        self.assertEqual(parse_lessons_command("  list ").action, "list")

    def test_review_parses_id_status_and_multiword_note(self):
        cmd = parse_lessons_command("review a1b2c3d4 reviewed confirmed manually, true positive")
        self.assertEqual(cmd.action, "review")
        self.assertEqual(cmd.lesson_id, "a1b2c3d4")
        self.assertEqual(cmd.status, "reviewed")
        self.assertEqual(cmd.note, "confirmed manually, true positive")

    def test_review_without_note_is_valid(self):
        cmd = parse_lessons_command("review a1b2c3d4 blocked")
        self.assertEqual(cmd.action, "review")
        self.assertEqual(cmd.status, "blocked")
        self.assertEqual(cmd.note, "")

    def test_review_rejects_unknown_status(self):
        cmd = parse_lessons_command("review a1b2c3d4 bogus")
        self.assertEqual(cmd.action, "error")
        self.assertIn("status", cmd.error.lower())

    def test_review_requires_id_and_status(self):
        cmd = parse_lessons_command("review a1b2c3d4")
        self.assertEqual(cmd.action, "error")
        self.assertIn(LESSONS_USAGE, cmd.error)

    def test_unknown_subcommand_is_error_with_usage(self):
        cmd = parse_lessons_command("frobnicate")
        self.assertEqual(cmd.action, "error")
        self.assertIn(LESSONS_USAGE, cmd.error)

    def test_valid_statuses_are_the_human_decisions(self):
        self.assertEqual(set(VALID_REVIEW_STATUSES), {"reviewed", "blocked", "deprecated"})


class FormatLessonsForReviewTests(unittest.TestCase):
    def test_lists_id_status_and_flags_unreviewed_first(self):
        reviewed = CaseLesson(title="nmap finds apache 2.4.49", outcome="success",
                              review_status="reviewed", id="aaaa1111")
        unreviewed = CaseLesson(title="ffuf hidden /admin", outcome="success",
                                review_status="unreviewed", id="bbbb2222")
        out = format_lessons_for_review([reviewed, unreviewed])
        self.assertIn("aaaa1111", out)
        self.assertIn("bbbb2222", out)
        self.assertIn("unreviewed", out)
        # Unreviewed lessons are the ones needing action — surface them first.
        self.assertLess(out.index("bbbb2222"), out.index("aaaa1111"))

    def test_empty_store_has_a_message(self):
        self.assertTrue(format_lessons_for_review([]).strip())


if __name__ == "__main__":
    unittest.main()
