"""The model picker returns (model, reasoning) and drives reasoning with ←/→."""
from __future__ import annotations

import io
import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from secops_agent.core.model_catalog import DEFAULT_MODEL, GEMINI_25_PRO
from secops_agent.ui.menu import switch_model_menu


def _drive(keys, current_model=DEFAULT_MODEL, current_thinking=""):
    """Run switch_model_menu feeding a scripted key sequence to the overlay."""
    it = iter(keys)
    stream = io.StringIO()
    fake_stdin = SimpleNamespace(isatty=lambda: True, fileno=lambda: 0)
    with patch("sys.stdin", fake_stdin), patch("sys.stdout", stream), patch(
        "secops_agent.ui.overlay.read_terminal_key", side_effect=lambda *a, **k: next(it)
    ), patch("secops_agent.ui.overlay.termios.tcgetattr", return_value=[]), patch(
        "secops_agent.ui.overlay.termios.tcsetattr"
    ), patch("secops_agent.ui.overlay.tty.setraw"), patch(
        "secops_agent.ui.overlay.shutil.get_terminal_size",
        return_value=os.terminal_size((96, 24)),
    ):
        from secops_agent.core.model_catalog import selectable_models

        return switch_model_menu(
            selectable_models(),
            current_model,
            current_thinking=current_thinking,
        )


class ModelPickerInteractionTests(unittest.TestCase):
    def test_enter_on_current_model_returns_model_and_reasoning(self):
        # Gemini 2.5 Flash has no thinking → reasoning None.
        result = _drive(["enter"])
        self.assertEqual(result, (DEFAULT_MODEL, None))

    def test_right_arrow_cycles_reasoning_on_a_thinking_model(self):
        # Move down to Gemini 2.5 Pro, step reasoning off → low, select.
        result = _drive(["down", "right", "enter"])
        self.assertEqual(result, (GEMINI_25_PRO, "low"))

    def test_left_arrow_wraps_reasoning(self):
        # Pro starts at "off"; ← wraps to the top of the ramp ("high").
        result = _drive(["down", "left", "enter"])
        self.assertEqual(result, (GEMINI_25_PRO, "high"))

    def test_escape_returns_none(self):
        self.assertIsNone(_drive(["esc"]))


if __name__ == "__main__":
    unittest.main()
