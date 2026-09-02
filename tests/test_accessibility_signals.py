"""X-02 (NO_COLOR / reduced motion) and ANIM-02 (OSC 9;4 host-terminal progress),
from docs/UX_RESEARCH_PROPOSAL_2026-09-01.md.

X-02: rich already strips colour under NO_COLOR for its own rendering; these tests
cover the raw-ANSI surfaces (``theme.ansi``) and the reduced-motion spinner swap.
ANIM-02: the scan percentage is mirrored to the host terminal's taskbar/tab.
"""
from __future__ import annotations

import contextlib
import io
import os
import unittest
from unittest.mock import patch

from rich.console import Console

from secops_agent.ui.animations import _spinner_name, _spinner_refresh
from secops_agent.ui.renderer import Renderer, _osc_progress_sequence
from secops_agent.ui.theme import ansi, ansi_hex, color_enabled, reduced_motion


@contextlib.contextmanager
def env(**overrides):
    """Isolate the accessibility env vars, then apply overrides (restored on exit)."""
    keys = ("NO_COLOR", "FORCE_COLOR", "CLICOLOR", "CLICOLOR_FORCE", "SECOPS_REDUCED_MOTION")
    with patch.dict(os.environ, {}, clear=False):
        for key in keys:
            os.environ.pop(key, None)
        for key, value in overrides.items():
            os.environ[key] = value
        yield


class ColorConventionTests(unittest.TestCase):
    def test_color_on_by_default(self):
        with env():
            self.assertTrue(color_enabled())
            self.assertTrue(ansi("success"))
            self.assertTrue(ansi_hex("#ffffff"))

    def test_no_color_disables_raw_ansi(self):
        with env(NO_COLOR="1"):
            self.assertFalse(color_enabled())
            self.assertEqual(ansi("success"), "")
            self.assertEqual(ansi_hex("#ffffff"), "")

    def test_clicolor_zero_disables(self):
        with env(CLICOLOR="0"):
            self.assertFalse(color_enabled())

    def test_clicolor_force_overrides_no_color(self):
        with env(NO_COLOR="1", CLICOLOR_FORCE="1"):
            self.assertTrue(color_enabled())
            self.assertTrue(ansi("success"))

    def test_force_color_enables_and_overrides_no_color(self):
        # P4: FORCE_COLOR mirrors Rich's force on the main Console for raw-ANSI too.
        with env(FORCE_COLOR="1"):
            self.assertTrue(color_enabled())
        with env(NO_COLOR="1", FORCE_COLOR="1"):
            self.assertTrue(color_enabled())

    def test_empty_no_color_does_not_disable(self):
        # no-color.org / Rich: NO_COLOR must be NON-EMPTY to disable colour.
        with env(NO_COLOR=""):
            self.assertTrue(color_enabled())


class NeverColorOnlyTests(unittest.TestCase):
    """P4: state must never be carried by colour alone — the tool bullet falls back
    to a distinct glyph per state when colour is disabled."""

    def test_bullet_is_record_glyph_when_colour_enabled(self):
        from secops_agent.ui.tool_display import _tool_status_marker
        with env():
            for status in ("success", "error", "running", ""):
                self.assertEqual(_tool_status_marker(status=status), "⏺")

    def test_bullet_glyph_encodes_state_when_colour_disabled(self):
        from secops_agent.ui.tool_display import _tool_status_marker
        with env(NO_COLOR="1"):
            success = _tool_status_marker(status="success")
            error = _tool_status_marker(status="error")
            running = _tool_status_marker(status="running")
            idle = _tool_status_marker(status="")
        # Each state gets a DISTINCT non-⏺ glyph, so success/error/running are
        # distinguishable without any colour.
        glyphs = {success, error, running, idle}
        self.assertEqual(len(glyphs), 4)
        self.assertNotIn("⏺", glyphs)


class SemanticColourTokenTests(unittest.TestCase):
    """P4: the colour literals that used to be hardcoded are now palette tokens."""

    def test_new_tokens_present_in_every_palette(self):
        from secops_agent.ui import theme as T
        for name in T.available_themes():
            palette = T._PALETTES[name]
            for token in ("diff_add_bg", "diff_remove_bg", "input_frame_bg", "on_warning"):
                with self.subTest(palette=name, token=token):
                    self.assertIn(token, palette)
                    self.assertRegex(palette[token], r"^#[0-9a-fA-F]{6}$")


class ReducedMotionTests(unittest.TestCase):
    def test_default_is_animated(self):
        with env():
            self.assertFalse(reduced_motion())
            self.assertEqual(_spinner_name(), "agy_dots")
            self.assertEqual(_spinner_refresh(), 12)

    def test_reduced_motion_uses_static_spinner(self):
        for value in ("1", "true", "yes", "on"):
            with env(SECOPS_REDUCED_MOTION=value):
                self.assertTrue(reduced_motion())
                self.assertEqual(_spinner_name(), "none")
                self.assertEqual(_spinner_refresh(), 2)


class OscProgressTests(unittest.TestCase):
    def test_sequence_builder(self):
        self.assertEqual(_osc_progress_sequence(42), "\x1b]9;4;1;42\x07")
        self.assertEqual(_osc_progress_sequence(None), "\x1b]9;4;0;0\x07")
        self.assertEqual(_osc_progress_sequence(150), "\x1b]9;4;1;100\x07")
        self.assertEqual(_osc_progress_sequence(-5), "\x1b]9;4;1;0\x07")

    def _emit(self, *, terminal: bool, reduced: str | None) -> str:
        buf = io.StringIO()
        renderer = Renderer()
        renderer.console = Console(file=buf, force_terminal=terminal)
        overrides = {"SECOPS_REDUCED_MOTION": reduced} if reduced else {}
        with env(**overrides):
            renderer._emit_terminal_progress(58)
        return buf.getvalue()

    def test_emits_on_a_tty(self):
        self.assertIn("\x1b]9;4;1;58\x07", self._emit(terminal=True, reduced=None))

    def test_suppressed_off_tty(self):
        self.assertEqual(self._emit(terminal=False, reduced=None), "")

    def test_suppressed_under_reduced_motion(self):
        self.assertEqual(self._emit(terminal=True, reduced="1"), "")


if __name__ == "__main__":
    unittest.main()
