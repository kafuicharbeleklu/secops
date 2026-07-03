"""Regression tests for R1 / Example E (gap G3): instructions typed while the
agent is streaming must be captured and queued, not silently dropped.

Root cause: the streaming key-watcher (_EscInterruptMonitor) put the tty in
cbreak mode and read stdin to catch Ctrl-O / Esc / Ctrl-C, discarding every
other byte — including a user's typed-ahead instructions. The fix accumulates
non-control input and exposes it as complete lines for the loop to enqueue.

These cover the deterministic capture/parse core; the end-to-end wiring (the
main loop draining the queue) is exercised against a live streaming turn.
"""
from __future__ import annotations

import unittest

from secops_agent.ui.renderer import (
    _EscInterruptMonitor,
    _classify_stream_key_chunk,
    _parse_typeahead_lines,
)


class TypeaheadParseTests(unittest.TestCase):
    def test_splits_cr_terminated_lines(self) -> None:
        self.assertEqual(
            _parse_typeahead_lines(b"quel est le hostname\rquelle heure est-il ?\r"),
            ["quel est le hostname", "quelle heure est-il ?"],
        )

    def test_keeps_accented_french(self) -> None:
        self.assertEqual(
            _parse_typeahead_lines("quelle heure est-il en France ?\r".encode()),
            ["quelle heure est-il en France ?"],
        )

    def test_ignores_empty_and_whitespace(self) -> None:
        self.assertEqual(_parse_typeahead_lines(b"\r\r  \rhostname\r"), ["hostname"])

    def test_drops_lines_with_stray_escape_sequences(self) -> None:
        # A stray arrow-key sequence must not become a queued instruction.
        self.assertEqual(_parse_typeahead_lines(b"\x1b[Bfoo\rbar\r"), ["bar"])

    def test_empty_input(self) -> None:
        self.assertEqual(_parse_typeahead_lines(b""), [])


class StreamKeyClassifyTests(unittest.TestCase):
    def test_ctrl_o_is_expand(self) -> None:
        self.assertEqual(_classify_stream_key_chunk(b"\x0f"), "expand")

    def test_esc_is_interrupt(self) -> None:
        self.assertEqual(_classify_stream_key_chunk(b"\x1b"), "interrupt")

    def test_ctrl_c_is_interrupt(self) -> None:
        self.assertEqual(_classify_stream_key_chunk(b"\x03"), "interrupt")

    def test_plain_text_is_text(self) -> None:
        self.assertEqual(_classify_stream_key_chunk(b"hostname\r"), "text")

    def test_ctrl_o_takes_precedence_over_text(self) -> None:
        # Existing precedence must be preserved: expand/interrupt win.
        self.assertEqual(_classify_stream_key_chunk(b"ab\x0f"), "expand")


class MonitorCaptureTests(unittest.TestCase):
    def test_drain_returns_captured_lines_then_clears(self) -> None:
        monitor = _EscInterruptMonitor()
        monitor._capture(b"quel est le hostname\r")
        monitor._capture(b"quelle heure est-il en France ?\r")
        self.assertEqual(
            monitor.drain_typeahead(),
            ["quel est le hostname", "quelle heure est-il en France ?"],
        )
        # buffer is cleared after draining
        self.assertEqual(monitor.drain_typeahead(), [])

    def test_partial_line_without_newline_is_held(self) -> None:
        monitor = _EscInterruptMonitor()
        monitor._capture(b"quel est le ")
        monitor._capture(b"hostname\r")
        self.assertEqual(monitor.drain_typeahead(), ["quel est le hostname"])


if __name__ == "__main__":
    unittest.main()
