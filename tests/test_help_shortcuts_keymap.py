"""X-01 — the `?` shortcuts overlay documents the real key bindings.

A full context-sensitive-per-surface help overlay (approval / pager / streaming)
would be invasive for little gain; the `?` overlay already lists the shortcuts.
The concrete value is keeping that keymap accurate, so a newly added binding
(e.g. Shift+Tab for the permission-mode cycle) does not silently go undocumented.
This guard fails if a notable binding is missing from the overlay.
"""
from __future__ import annotations

import unittest

from secops_agent.ui.views.panels import _HELP_SHORTCUTS


class HelpShortcutsKeymapTests(unittest.TestCase):
    def _documented_keys(self) -> set[str]:
        keys: set[str] = set()
        for label, _description in _HELP_SHORTCUTS:
            for part in label.split(","):
                keys.add(part.strip())
        return keys

    def test_shift_tab_permission_cycle_is_documented(self):
        entries = dict(_HELP_SHORTCUTS)
        self.assertIn("shift+tab", entries)
        self.assertIn("permission", entries["shift+tab"].lower())

    def test_notable_bindings_are_documented(self):
        keys = self._documented_keys()
        # bindings a user needs to discover from the `?` overlay
        for key in ("shift+tab", "ctrl+o", "ctrl+r", "ctrl+g", "ctrl+l", "?"):
            self.assertIn(key, keys, f"{key} is missing from the ? shortcuts overlay")

    def test_no_duplicate_shortcut_labels(self):
        labels = [label for label, _ in _HELP_SHORTCUTS]
        self.assertEqual(len(labels), len(set(labels)))


if __name__ == "__main__":
    unittest.main()
