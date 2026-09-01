"""Named colour palettes (paprika / ocean / vivid), theme resolution, and runtime
set_theme. Each palette's four signal hues stay readable on the terminal ground.
"""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
import unittest.mock
from unittest.mock import patch

import secops_agent.ui.theme as theme
from secops_agent.core import preferences


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


class ThemeHelperTests(unittest.TestCase):
    def tearDown(self):
        theme.set_theme("paprika")

    def test_available_themes_lists_the_three_palettes(self):
        self.assertEqual(set(theme.available_themes()), {"paprika", "ocean", "vivid"})

    def test_is_known_theme(self):
        self.assertTrue(theme.is_known_theme("Ocean"))   # case-insensitive
        self.assertFalse(theme.is_known_theme("bogus"))
        self.assertFalse(theme.is_known_theme(""))

    def test_active_theme_name_tracks_set_theme(self):
        theme.set_theme("vivid")
        self.assertEqual(theme.active_theme_name(), "vivid")
        theme.set_theme("paprika")
        self.assertEqual(theme.active_theme_name(), "paprika")


class ThemePersistenceTests(unittest.TestCase):
    """FMT-05b: /theme choice persists to settings.json across launches."""

    def _settings(self):
        tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        tmp.close()
        return Path(tmp.name)

    def test_save_then_load_roundtrip(self):
        path = self._settings()
        try:
            preferences.save_theme_preference("Ocean", path=path)
            self.assertEqual(preferences.load_theme_preference(path=path), "ocean")
        finally:
            path.unlink(missing_ok=True)

    def test_load_default_is_empty(self):
        path = self._settings()
        try:
            self.assertEqual(preferences.load_theme_preference(path=path), "")
        finally:
            path.unlink(missing_ok=True)

    def test_saving_theme_preserves_other_preferences(self):
        path = self._settings()
        try:
            preferences.save_model_preference("gemma", resolved_model="gemma-4-26b-a4b-it", path=path)
            preferences.save_theme_preference("vivid", path=path)
            self.assertEqual(preferences.load_theme_preference(path=path), "vivid")
            self.assertEqual(preferences.load_model_preference(path=path)["raw_model"], "gemma")
        finally:
            path.unlink(missing_ok=True)


class StartupThemeApplicationTests(unittest.TestCase):
    """main._apply_startup_theme: saved palette applies unless SECOPS_THEME overrides."""

    def setUp(self):
        theme.set_theme("paprika")
        self.renderer = unittest.mock.MagicMock()
        self.handler = unittest.mock.MagicMock()

    def tearDown(self):
        theme.set_theme("paprika")

    def _run(self, saved, env_theme=None):
        import secops_agent.main as main
        tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        tmp.close()
        path = Path(tmp.name)
        try:
            if saved:
                preferences.save_theme_preference(saved, path=path)
            env = {"SECOPS_SETTINGS_FILE": str(path)}
            with patch.dict(os.environ, env, clear=False):
                os.environ.pop("SECOPS_THEME", None)
                if env_theme is not None:
                    os.environ["SECOPS_THEME"] = env_theme
                main._apply_startup_theme(self.renderer, self.handler)
            return theme.active_theme_name()
        finally:
            path.unlink(missing_ok=True)

    def test_saved_theme_is_applied_at_startup(self):
        self.assertEqual(self._run("vivid"), "vivid")
        self.handler.refresh_theme.assert_called_once()

    def test_env_var_overrides_saved_theme(self):
        # SECOPS_THEME is the explicit override -> saved pref is ignored (early return)
        self.assertEqual(self._run("vivid", env_theme="ocean"), "paprika")
        self.handler.refresh_theme.assert_not_called()

    def test_no_saved_theme_leaves_default(self):
        self.assertEqual(self._run(None), "paprika")
        self.handler.refresh_theme.assert_not_called()


if __name__ == "__main__":
    unittest.main()
