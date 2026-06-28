from __future__ import annotations

import unittest

from scratch.tui_smoke import terminal_screen_text


class TUISmokeCaptureTests(unittest.TestCase):
    def test_terminal_screen_text_applies_carriage_return_overwrite(self):
        text = terminal_screen_text(b"abcdef\rXY", rows=4, cols=20)

        self.assertIn("XYcdef", text)

    def test_terminal_screen_text_handles_clear_screen(self):
        text = terminal_screen_text(b"stale\x1b[H\x1b[2Jfresh", rows=4, cols=20)

        self.assertIn("fresh", text)
        self.assertNotIn("stale", text)
        self.assertNotIn("H", text)
        self.assertNotIn("J", text)

    def test_terminal_screen_text_clear_below_keeps_existing_header(self):
        text = terminal_screen_text(b"header\nprompt\x1b[Jfooter", rows=4, cols=20)

        self.assertIn("header", text)
        self.assertIn("promptfooter", text)

    def test_terminal_screen_text_ignores_sgr_sequences(self):
        text = terminal_screen_text(b"\x1b[31mred\x1b[0m", rows=4, cols=20)

        self.assertEqual(text, "red")

    def test_terminal_screen_text_tracks_alternate_screen_lifecycle(self):
        active_alt = terminal_screen_text(b"main\x1b[?1049h\x1b[H\x1b[2Jhelp", rows=4, cols=20)
        restored_main = terminal_screen_text(
            b"main\x1b[?1049h\x1b[H\x1b[2Jhelp\x1b[?1049l",
            rows=4,
            cols=20,
        )

        self.assertIn("help", active_alt)
        self.assertNotIn("main", active_alt)
        self.assertIn("main", restored_main)
        self.assertNotIn("help", restored_main)


if __name__ == "__main__":
    unittest.main()
