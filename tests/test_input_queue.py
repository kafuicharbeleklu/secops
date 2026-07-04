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
    _PASTE_END,
    _PASTE_START,
    _EscInterruptMonitor,
    _classify_stream_key_chunk,
    _coalesce_paste_block,
    _parse_typeahead_lines,
    _typeahead_cut_index,
)

_PS = _PASTE_START.encode()
_PE = _PASTE_END.encode()


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


class BracketedPasteParseTests(unittest.TestCase):
    """Example H: a single multi-line message pasted while the agent streams must
    stay ONE instruction, not be fragmented per line like several typed-ahead
    instructions (Example E)."""

    def test_single_paste_is_one_instruction(self) -> None:
        raw = _PS + b"cible 10.0.0.5\rliste les ports\rlance nmap" + _PE
        self.assertEqual(
            _parse_typeahead_lines(raw),
            ["cible 10.0.0.5\nliste les ports\nlance nmap"],
        )

    def test_typed_lines_still_split(self) -> None:
        # Example E must be preserved: separate Enter-terminated lines stay separate.
        self.assertEqual(
            _parse_typeahead_lines(b"hostname\rwhoami\r"),
            ["hostname", "whoami"],
        )

    def test_typed_line_then_paste_then_typed_line(self) -> None:
        raw = b"avant\r" + _PS + b"bloc colle\rsur deux lignes" + _PE + b"apres\r"
        self.assertEqual(
            _parse_typeahead_lines(raw),
            ["avant", "bloc colle\nsur deux lignes", "apres"],
        )

    def test_coalesce_drops_blank_lines(self) -> None:
        self.assertEqual(_coalesce_paste_block("a\r\r  \rb\r"), "a\nb")

    def test_empty_paste_yields_nothing(self) -> None:
        self.assertEqual(_parse_typeahead_lines(_PS + _PE), [])


class TypeaheadCutTests(unittest.TestCase):
    """The drain cut must hold an *in-progress* paste (or an unterminated line
    before it) so it is never split, then release it once closed."""

    def test_plain_lines_cut_at_last_newline(self) -> None:
        self.assertEqual(_typeahead_cut_index(b"a\rb\r"), 4)
        self.assertEqual(_typeahead_cut_index(b"a\rb"), 2)  # trailing "b" held

    def test_closed_paste_is_fully_drainable(self) -> None:
        raw = _PS + b"x" + _PE
        self.assertEqual(_typeahead_cut_index(raw), len(raw))

    def test_open_paste_is_held(self) -> None:
        raw = b"done\r" + _PS + b"partial"
        cut = _typeahead_cut_index(raw)
        self.assertEqual(raw[:cut], b"done\r")  # only the complete line drains
        self.assertIn(_PS, raw[cut:])  # the open paste is held

    def test_drain_holds_open_paste_then_releases(self) -> None:
        monitor = _EscInterruptMonitor()
        monitor._capture(_PS + b"multi\rline")  # paste opened, not yet closed
        self.assertEqual(monitor.drain_typeahead(), [])  # held, not fragmented
        monitor._capture(b" more" + _PE)  # paste now closed
        self.assertEqual(monitor.drain_typeahead(), ["multi\nline more"])


class DispatchReadTests(unittest.TestCase):
    """The per-read state machine must preserve the P0-5 interrupt/expand
    contract while treating a bracketed paste as inert text."""

    def setUp(self) -> None:
        self.monitor = _EscInterruptMonitor()

    def test_ctrl_c_interrupts_when_idle(self) -> None:
        self.assertEqual(self.monitor._dispatch_read(b"\x03"), "interrupt")

    def test_esc_interrupts_when_not_pasting(self) -> None:
        self.assertEqual(self.monitor._dispatch_read(b"\x1b"), "interrupt")

    def test_ctrl_o_expands_when_not_pasting(self) -> None:
        self.assertEqual(self.monitor._dispatch_read(b"\x0f"), "expand")

    def test_plain_text_is_consumed_and_captured(self) -> None:
        self.assertEqual(self.monitor._dispatch_read(b"hostname\r"), "consumed")
        self.assertEqual(self.monitor.drain_typeahead(), ["hostname"])

    def test_paste_end_marker_does_not_interrupt(self) -> None:
        # The ESC in ESC[201~ must NOT be read as an interrupt mid-paste (Example H).
        self.assertEqual(self.monitor._dispatch_read(_PS + b"scan"), "consumed")
        self.assertTrue(self.monitor._in_paste)
        self.assertEqual(self.monitor._dispatch_read(_PE + b"\r"), "consumed")
        self.assertFalse(self.monitor._in_paste)
        self.assertEqual(self.monitor.drain_typeahead(), ["scan"])

    def test_ctrl_c_still_aborts_mid_paste(self) -> None:
        self.assertEqual(self.monitor._dispatch_read(_PS + b"scan"), "consumed")
        self.assertTrue(self.monitor._in_paste)
        # safety valve: Ctrl-C interrupts even inside a paste
        self.assertEqual(self.monitor._dispatch_read(b"\x03"), "interrupt")

    def test_whole_paste_in_one_read_closes(self) -> None:
        self.assertEqual(
            self.monitor._dispatch_read(_PS + b"one shot" + _PE + b"\r"), "consumed"
        )
        self.assertFalse(self.monitor._in_paste)
        self.assertEqual(self.monitor.drain_typeahead(), ["one shot"])

    def test_end_marker_split_across_reads_still_closes(self) -> None:
        self.monitor._dispatch_read(_PS + b"hello")
        self.assertTrue(self.monitor._in_paste)
        self.monitor._dispatch_read(b"\x1b[20")  # first half of ESC[201~
        self.assertTrue(self.monitor._in_paste)  # not closed yet
        self.monitor._dispatch_read(b"1~")  # second half — carry bridges the split
        self.assertFalse(self.monitor._in_paste)
        self.assertEqual(self.monitor.drain_typeahead(), ["hello"])


if __name__ == "__main__":
    unittest.main()
