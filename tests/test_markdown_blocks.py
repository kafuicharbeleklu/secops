"""Model answers keep list blocks distinct.

A bullet or numbered list with no blank line before/after it makes Rich Markdown
lazily merge the adjacent paragraph into the list, producing a run-on line such
as ``- 443/tcp (TLS) Prochaines étapes: 1. …``. ``normalize_agent_markdown``
inserts a single blank at every block boundary so each renders on its own.
"""
from __future__ import annotations

import unittest

from secops_agent.ui.renderer import normalize_agent_markdown


class MarkdownBlockSeparationTests(unittest.TestCase):
    def test_bullet_list_is_separated_from_following_paragraph(self):
        text = "- 22/tcp ssh\n- 80/tcp http\nProchaines étapes:"
        lines = normalize_agent_markdown(text).split("\n")

        self.assertIn("- 22/tcp ssh", lines)
        idx_last_bullet = lines.index("- 80/tcp http")
        idx_para = lines.index("Prochaines étapes:")
        self.assertEqual(lines[idx_last_bullet + 1], "")
        self.assertLess(idx_last_bullet, idx_para)

    def test_paragraph_is_separated_from_numbered_list(self):
        text = "Prochaines étapes:\n1. scan\n2. enum"
        out = normalize_agent_markdown(text)
        # The intro line is followed by a blank before the numbered block.
        self.assertIn("Prochaines étapes:\n\n1", out)

    def test_consecutive_bullets_stay_together(self):
        text = "- a\n- b\n- c"
        out = normalize_agent_markdown(text)
        self.assertNotIn("\n\n", out)

    def test_no_triple_blank_lines_are_introduced(self):
        text = "intro\n\n- a\n- b\n\nafter"
        out = normalize_agent_markdown(text)
        self.assertNotIn("\n\n\n", out)

    def test_fenced_code_is_left_untouched(self):
        text = "intro\n```bash\n- not a list\necho hi\n```\nafter"
        out = normalize_agent_markdown(text)
        self.assertIn("- not a list", out)
        # No spurious blank inserted inside the fence.
        self.assertNotIn("```bash\n\n", out)


if __name__ == "__main__":
    unittest.main()
