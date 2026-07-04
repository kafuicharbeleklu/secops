"""Regression tests for Example F (streaming text duplication).

A synthesized answer taller than the terminal viewport was re-rendered in full on
every stream chunk, so Rich's Live restacked it into scrollback that cursor-up
cannot reach — the 5-6x cascade the user sees. The fix caps the streaming Live to
the last N lines (`_streaming_tail`) plus `vertical_overflow="crop"`; the complete
answer is written once by `_flush_live_text` on the done event.

The end-to-end no-cascade reproduction through a real PTY lives in
`scratch/tui_smoke.py` (run_streaming_overflow_smoke); these lock the pure logic.
"""
from __future__ import annotations

import unittest

from secops_agent.ui.renderer import _streaming_tail


class StreamingTailTests(unittest.TestCase):
    def test_short_text_is_unchanged(self) -> None:
        text = "line1\nline2\nline3"
        self.assertEqual(_streaming_tail(text, 28), text)

    def test_tall_text_is_capped_to_the_tail(self) -> None:
        lines = [f"l{i}" for i in range(100)]
        out = _streaming_tail("\n".join(lines), 28).split("\n")
        # viewport-6 = 22 lines, and it keeps the TAIL (newest content)
        self.assertEqual(len(out), 22)
        self.assertEqual(out[-1], "l99")
        self.assertEqual(out[0], "l78")

    def test_never_below_a_small_floor(self) -> None:
        body = "\n".join(f"l{i}" for i in range(50))
        # unknown viewport (0) falls back to a sane default, tiny viewport floors at 4
        self.assertGreaterEqual(len(_streaming_tail(body, 0).split("\n")), 4)
        self.assertGreaterEqual(len(_streaming_tail(body, 3).split("\n")), 4)

    def test_tail_preserves_retained_line_content(self) -> None:
        body = "\n".join(f"unique-{i}" for i in range(40))
        out = _streaming_tail(body, 28)
        self.assertIn("unique-39", out)
        self.assertNotIn("unique-0", out)


if __name__ == "__main__":
    unittest.main()
