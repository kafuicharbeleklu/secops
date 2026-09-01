"""Named colour palettes (paprika / ocean / vivid), theme resolution, and runtime
set_theme. Each palette's four signal hues stay readable on the terminal ground.
"""
from __future__ import annotations

import os
import unittest
from unittest.mock import patch

import secops_agent.ui.theme as theme


def _contrast(fg: str, bg: str = "#18181b") -> float:
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
    def _resolve(self, value=None) -> str:
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SECOPS_THEME", None)
            if value is not None:
                os.environ["SECOPS_THEME"] = value
            return theme.resolve_theme_name()

    def test_default_is_paprika(self):
        self.assertEqual(self._resolve(), "paprika")

    def test_env_selects_named_palette(self):
        self.assertEqual(self._resolve("ocean"), "ocean")
        self.assertEqual(self._resolve("vivid"), "vivid")

    def test_unknown_falls_back_to_default(self):
        self.assertEqual(self._resolve("bogus"), "paprika")


class PaletteTests(unittest.TestCase):
    def tearDown(self):
        theme.set_theme("paprika")  # restore the default for other tests

    def test_three_named_palettes(self):
        self.assertEqual(set(theme._PALETTES), {"paprika", "ocean", "vivid"})

    def test_all_palettes_share_keys(self):
        keysets = [frozenset(p) for p in theme._PALETTES.values()]
        self.assertEqual(len(set(keysets)), 1, "every palette must define the same keys")

    def test_set_theme_switches_live(self):
        self.assertEqual(theme.set_theme("vivid"), "vivid")
        self.assertEqual(theme.COLORS["accent"], "#08bdbd")
        self.assertEqual(theme.set_theme("paprika"), "paprika")
        self.assertEqual(theme.COLORS["accent"], "#669bbc")

    def test_signal_colours_readable_on_ground(self):
        for name, palette in theme._PALETTES.items():
            for role in ("accent", "success", "warning"):
                self.assertGreaterEqual(
                    _contrast(palette[role]), 4.5, f"{name}.{role} {palette[role]} below AA on ground"
                )
            self.assertGreaterEqual(
                _contrast(palette["error"]), 4.0, f"{name}.error {palette['error']} too low"
            )

    def test_vivid_has_a_true_red_danger(self):
        r, g, b = (int(theme._PALETTES["vivid"]["danger"].lstrip("#")[i:i + 2], 16) for i in (0, 2, 4))
        self.assertTrue(r > g and r > b, "vivid danger should be an unambiguous red")


if __name__ == "__main__":
    unittest.main()
