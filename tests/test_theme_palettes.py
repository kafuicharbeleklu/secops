"""FMT-05: named dark/light palettes, startup resolution (SECOPS_THEME /
COLORFGBG), and runtime set_theme. The light palette must stay WCAG-AA on a
white terminal background.
"""
from __future__ import annotations

import os
import unittest
from unittest.mock import patch

import secops_agent.ui.theme as theme


def _contrast(fg: str, bg: str = "#ffffff") -> float:
    def rgb(h):
        h = h.lstrip("#")
        return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))

    def lin(c):
        c /= 255
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4

    def lum(h):
        r, g, b = rgb(h)
        return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b)

    a, b = lum(fg), lum(bg)
    return (max(a, b) + 0.05) / (min(a, b) + 0.05)


class ThemeResolutionTests(unittest.TestCase):
    def _resolve(self, env: dict) -> str:
        with patch.dict(os.environ, {}, clear=False):
            for key in ("SECOPS_THEME", "COLORFGBG"):
                os.environ.pop(key, None)
            os.environ.update(env)
            return theme.resolve_theme_name()

    def test_default_is_dark(self):
        self.assertEqual(self._resolve({}), "dark")

    def test_colorfgbg_detects_light_background(self):
        self.assertEqual(self._resolve({"COLORFGBG": "0;15"}), "light")
        self.assertEqual(self._resolve({"COLORFGBG": "15;0"}), "dark")

    def test_explicit_env_overrides_detection(self):
        self.assertEqual(self._resolve({"SECOPS_THEME": "light", "COLORFGBG": "15;0"}), "light")
        self.assertEqual(self._resolve({"SECOPS_THEME": "dark", "COLORFGBG": "0;15"}), "dark")


class PaletteTests(unittest.TestCase):
    def tearDown(self):
        theme.set_theme("dark")  # never leak a non-default palette to other tests

    def test_palettes_have_identical_keys(self):
        self.assertEqual(set(theme._DARK_PALETTE), set(theme._LIGHT_PALETTE))

    def test_set_theme_updates_live_colors(self):
        self.assertEqual(theme.set_theme("light"), "light")
        self.assertEqual(theme.COLORS["text"], "#18181b")
        self.assertEqual(theme.set_theme("dark"), "dark")
        self.assertEqual(theme.COLORS["text"], "#e4e4e7")

    def test_light_palette_is_AA_on_white(self):
        functional = [
            "accent", "accent_bright", "success", "error", "warning",
            "text", "text_secondary", "text_muted", "tool_border", "danger", "danger_bright",
        ]
        for key in functional:
            self.assertGreaterEqual(
                _contrast(theme._LIGHT_PALETTE[key]), 4.5,
                f"{key} {theme._LIGHT_PALETTE[key]} fails AA on white",
            )


if __name__ == "__main__":
    unittest.main()
