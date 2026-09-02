"""P4 — WCAG contrast enforcement across every palette on its tuned ground.

Regression guard behind scratch/contrast_report.py: every information-carrying
token (body/secondary/muted text, the colour signals, the warning highlight and
the diff-line tints) must meet its role threshold on BOTH the dark and the light
ground. Purely decorative chrome (text_dim dividers, tool_border) is WCAG
non-text-exempt and intentionally sub-threshold, so it is reported but not gated.
"""

import unittest

from secops_agent.ui import theme as T

# Dark-ground signal tokens that must stay text-grade (>= 4.5).
_TEXT_GRADE_SIGNALS = ("accent", "error", "danger")
# Signals allowed to drop to the WCAG non-text floor (3.0) on the light ground,
# where the palette documents warm/green hues cannot reach 4.5 on white.
_WARM_SIGNALS = ("success", "warning", "accent_bright", "danger_bright")


class ContrastTests(unittest.TestCase):
    def _ratio(self, palette, token, ground):
        return T.contrast_ratio(palette[token], ground)

    def test_body_and_meta_text_meet_thresholds_on_every_palette(self):
        for name in T.available_themes():
            palette, ground = T._PALETTES[name], T.ground_for(name)
            with self.subTest(palette=name):
                self.assertGreaterEqual(self._ratio(palette, "text", ground), 7.0)
                self.assertGreaterEqual(self._ratio(palette, "text_secondary", ground), 4.5)
                self.assertGreaterEqual(self._ratio(palette, "text_muted", ground), 4.5)

    def test_core_signals_stay_text_grade_on_every_palette(self):
        for name in T.available_themes():
            palette, ground = T._PALETTES[name], T.ground_for(name)
            for token in _TEXT_GRADE_SIGNALS:
                with self.subTest(palette=name, token=token):
                    self.assertGreaterEqual(self._ratio(palette, token, ground), 4.5)

    def test_warm_signals_meet_text_grade_on_dark_and_nontext_floor_on_light(self):
        for name in T.available_themes():
            palette, ground = T._PALETTES[name], T.ground_for(name)
            floor = 3.0 if T.is_light_theme(name) else 4.5
            for token in _WARM_SIGNALS:
                with self.subTest(palette=name, token=token):
                    self.assertGreaterEqual(self._ratio(palette, token, ground), floor)

    def test_warning_highlight_foreground_is_readable(self):
        # _match_highlight_style renders on_warning over the warning background.
        for name in T.available_themes():
            palette = T._PALETTES[name]
            with self.subTest(palette=name):
                self.assertGreaterEqual(
                    T.contrast_ratio(palette["on_warning"], palette["warning"]), 4.5)

    def test_diff_line_foreground_stays_legible_over_its_tint(self):
        # Success/error text sits over the diff add/remove background tints.
        for name in T.available_themes():
            palette = T._PALETTES[name]
            with self.subTest(palette=name):
                self.assertGreaterEqual(
                    T.contrast_ratio(palette["success"], palette["diff_add_bg"]), 3.0)
                self.assertGreaterEqual(
                    T.contrast_ratio(palette["error"], palette["diff_remove_bg"]), 3.0)

    def test_contrast_ratio_math(self):
        # Anchors: black-on-white is 21:1, identical colours are 1:1, symmetric.
        self.assertAlmostEqual(T.contrast_ratio("#000000", "#ffffff"), 21.0, places=1)
        self.assertAlmostEqual(T.contrast_ratio("#777777", "#777777"), 1.0, places=3)
        self.assertAlmostEqual(
            T.contrast_ratio("#123456", "#abcdef"),
            T.contrast_ratio("#abcdef", "#123456"), places=6)


if __name__ == "__main__":
    unittest.main()
