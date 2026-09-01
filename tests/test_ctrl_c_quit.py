"""Claude-Code-style Ctrl+C on the prompt.

A typed line is cleared on the first press; on an EMPTY prompt the first press
arms an exit (with a visible hint) and a second press within the window quits
the CLI by returning ``InputHandler.QUIT_REQUEST``.
"""
from __future__ import annotations

import unittest

from prompt_toolkit.keys import Keys

from secops_agent.ui.input_handler import InputHandler


class _FakeDocument:
    def __init__(self, text: str):
        self.text_before_cursor = text


class _FakeBuffer:
    def __init__(self, text: str = ""):
        self.text = text
        self.cursor_position = len(text)
        self.document = _FakeDocument(text)
        self.completion_cancelled = False

    def reset(self):
        self.text = ""
        self.cursor_position = 0
        self.document = _FakeDocument("")

    def start_completion(self, **_):
        pass

    def cancel_completion(self):
        self.completion_cancelled = True


class _FakeApp:
    def __init__(self):
        self.invalidated = 0
        self.exit_result = None
        self.exited = False

    def invalidate(self):
        self.invalidated += 1

    def exit(self, result=None):
        self.exited = True
        self.exit_result = result


class _FakeEvent:
    def __init__(self, buffer: _FakeBuffer, app: _FakeApp):
        self.current_buffer = buffer
        self.app = app


def _ctrl_c_handler(handler: InputHandler):
    bindings = handler.bindings.get_bindings_for_keys((Keys.ControlC,))
    assert bindings, "no Ctrl+C binding registered"
    return bindings[-1].handler


class CtrlCQuitTests(unittest.TestCase):
    def test_ctrl_c_clears_typed_line_without_quitting(self):
        handler = InputHandler()
        binding = _ctrl_c_handler(handler)
        buffer = _FakeBuffer("nmap 10.10.10.5")
        app = _FakeApp()

        binding(_FakeEvent(buffer, app))

        self.assertEqual(buffer.text, "")
        self.assertFalse(app.exited)
        self.assertFalse(handler._ctrl_c_armed)
        self.assertEqual(handler._interrupt_hint, "")

    def test_double_ctrl_c_on_empty_prompt_quits(self):
        handler = InputHandler()
        binding = _ctrl_c_handler(handler)
        app = _FakeApp()

        binding(_FakeEvent(_FakeBuffer(""), app))
        self.assertTrue(handler._ctrl_c_armed)
        self.assertIn("again", handler._interrupt_hint.lower())
        self.assertFalse(app.exited)

        binding(_FakeEvent(_FakeBuffer(""), app))
        self.assertTrue(app.exited)
        self.assertEqual(app.exit_result, InputHandler.QUIT_REQUEST)
        self.assertFalse(handler._ctrl_c_armed)

    def test_typing_after_arm_disarms_the_quit(self):
        handler = InputHandler()
        binding = _ctrl_c_handler(handler)
        app = _FakeApp()

        binding(_FakeEvent(_FakeBuffer(""), app))
        self.assertTrue(handler._ctrl_c_armed)

        # A press with text present clears the line and disarms, rather than
        # quitting on the (now second) press.
        binding(_FakeEvent(_FakeBuffer("whoami"), app))
        self.assertFalse(handler._ctrl_c_armed)
        self.assertFalse(app.exited)


if __name__ == "__main__":
    unittest.main()
