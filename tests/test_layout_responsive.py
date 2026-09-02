"""P2 — responsivité au redimensionnement du terminal.

Acceptance tests for the centralized layout layer (secops_agent/ui/layout.py)
and its integration points, exercised at the five target widths 40/60/80/120/200:

* cell-accurate width measurement (CJK / emoji / ZWJ / combining / ANSI),
* breakpoints (narrow / medium / wide) and their per-breakpoint behaviour,
* no parasitic wrapping / no cut line at any width (mission box + prose),
* text-width cap on ultra-wide terminals,
* debounced resize coalescing,
* degraded modes (non-TTY / unknown / zero width → safe fallback).
"""

from __future__ import annotations

import io
import unittest

from rich.console import Console

from secops_agent.ui import layout as L
from secops_agent.ui import theme
from secops_agent.ui.renderer import _agent_markdown

WIDTHS = (40, 60, 80, 120, 200)


# ── Test fixtures ──────────────────────────────────────────────────────

class _FakeSize:
    def __init__(self, w, h):
        self.width = w
        self.height = h


class _FakeConsole:
    """Minimal stand-in exposing .size and .is_terminal like rich.Console."""
    def __init__(self, w, h, is_terminal=True, raise_size=False):
        self._w, self._h, self._raise = w, h, raise_size
        self.is_terminal = is_terminal

    @property
    def size(self):
        if self._raise:
            raise RuntimeError("no size")
        return _FakeSize(self._w, self._h)


class _Svc:
    def __init__(self, port, name):
        self.port, self.name = port, name


class _Scope:
    def __init__(self, in_scope):
        self.in_scope = in_scope


class _Mission:
    """A populated mission with CJK + emoji in the target (cell-width stressor)."""
    target = "世界-lab.例え.com 🚀"
    phase = "recon"
    services = [_Svc(80, "http"), _Svc(443, "https")]
    scope = _Scope(["10.0.0.0/24", "192.168.1.0/24"])


def _render_prose_lines(text, width):
    con = Console(width=width, record=True, force_terminal=False,
                  color_system=None, file=io.StringIO())
    con.print(_agent_markdown(text, width=width))
    return [ln.rstrip() for ln in con.export_text().splitlines()]


# ── Cell-accurate measurement ──────────────────────────────────────────

class CellLenTests(unittest.TestCase):
    def test_ascii(self):
        self.assertEqual(L.cell_len("hello"), 5)

    def test_cjk_is_two_cells(self):
        self.assertEqual(L.cell_len("世界"), 4)

    def test_emoji_is_two_cells(self):
        self.assertEqual(L.cell_len("🚀"), 2)

    def test_zwj_sequence_collapses(self):
        # A ZWJ family emoji is one grapheme → 2 cells, not the sum of its parts.
        self.assertEqual(L.cell_len("👨‍👩‍👧"), 2)

    def test_combining_mark_is_zero_width(self):
        self.assertEqual(L.cell_len("é"), 1)  # e + combining acute

    def test_ansi_is_stripped_before_measuring(self):
        self.assertEqual(L.cell_len("\x1b[31mred\x1b[0m"), 3)

    def test_osc8_hyperlink_is_stripped(self):
        self.assertEqual(L.cell_len("\x1b]8;;http://x\x07lbl\x1b]8;;\x07"), 3)

    def test_empty(self):
        self.assertEqual(L.cell_len(""), 0)


class FitCellTests(unittest.TestCase):
    def test_never_exceeds_width_across_widths(self):
        samples = ["hello world", "世界世界世界", "a世b世c", "🚀🚀🚀", "plain",
                   "\x1b[31mcoloured text here\x1b[0m", "ééé"]
        for w in (0, 1, 2, 3, 4, 5, 8, *WIDTHS):
            for s in samples:
                out = L.fit_cell(s, w)
                self.assertLessEqual(L.cell_len(out), w, f"{s!r} @ {w} -> {out!r}")

    def test_fits_exactly_untouched(self):
        self.assertEqual(L.fit_cell("hello", 5), "hello")

    def test_truncation_adds_ellipsis(self):
        self.assertEqual(L.fit_cell("hello world", 8), "hello w…")

    def test_width_one_is_ellipsis(self):
        self.assertEqual(L.fit_cell("hello", 1), "…")

    def test_wide_char_not_split_at_boundary(self):
        out = L.fit_cell("世界世界", 5)
        self.assertLessEqual(L.cell_len(out), 5)
        self.assertTrue(out.endswith("…"))


class PadCellTests(unittest.TestCase):
    def test_exact_cell_width_for_complex_text(self):
        for s in ("hi", "世界", "🚀x", "é", "\x1b[31mred\x1b[0m"):
            for w in (1, 4, 8, 20):
                self.assertEqual(L.cell_len(L.pad_cell(s, w)), w, f"{s!r}@{w}")

    def test_align_right_and_center(self):
        self.assertEqual(L.pad_cell("hi", 5, align="right"), "   hi")
        self.assertEqual(L.pad_cell("hi", 6, align="center"), "  hi  ")

    def test_overflow_truncates(self):
        self.assertLessEqual(L.cell_len(L.pad_cell("hello world", 4)), 4)


# ── Breakpoints & Layout ───────────────────────────────────────────────

class BreakpointTests(unittest.TestCase):
    def test_classification_at_target_widths(self):
        self.assertEqual(L.classify(40), L.Breakpoint.NARROW)
        self.assertEqual(L.classify(60), L.Breakpoint.MEDIUM)
        self.assertEqual(L.classify(80), L.Breakpoint.MEDIUM)
        self.assertEqual(L.classify(120), L.Breakpoint.WIDE)
        self.assertEqual(L.classify(200), L.Breakpoint.WIDE)

    def test_boundaries(self):
        self.assertEqual(L.classify(L.NARROW_MAX), L.Breakpoint.NARROW)
        self.assertEqual(L.classify(L.NARROW_MAX + 1), L.Breakpoint.MEDIUM)
        self.assertEqual(L.classify(L.WIDE_MIN - 1), L.Breakpoint.MEDIUM)
        self.assertEqual(L.classify(L.WIDE_MIN), L.Breakpoint.WIDE)

    def test_text_width_capped_only_when_wide(self):
        self.assertEqual(L.Layout(40, 10, True, True, L.classify(40)).text_width, 40)
        self.assertEqual(L.Layout(80, 24, True, True, L.classify(80)).text_width, 80)
        self.assertEqual(L.Layout(200, 50, True, True, L.classify(200)).text_width, L.TEXT_MAX_WIDTH)

    def test_frame_width_capped(self):
        self.assertEqual(L.Layout(200, 50, True, True, L.classify(200)).frame_width, L.FRAME_MAX_WIDTH)

    def test_narrow_hides_metadata_and_abbreviates_hints(self):
        lay = L.Layout(40, 10, True, True, L.classify(40))
        self.assertTrue(lay.hide_metadata)
        self.assertTrue(lay.abbreviated_hints)
        wide = L.Layout(120, 40, True, True, L.classify(120))
        self.assertFalse(wide.hide_metadata)
        self.assertFalse(wide.abbreviated_hints)

    def test_rule_is_width_minus_one_and_never_negative(self):
        for w in WIDTHS:
            lay = L.Layout(w, 24, True, True, L.classify(w))
            self.assertEqual(L.cell_len(lay.rule()), w - 1)
        self.assertEqual(L.Layout(1, 1, False, False, L.classify(1)).rule(), "─")


# ── Terminal size resolution / degraded modes ──────────────────────────

class TerminalSizeTests(unittest.TestCase):
    def test_safe_fallback_when_no_console_and_not_tty(self):
        orig = L._stdout_isatty
        L._stdout_isatty = lambda: False
        try:
            self.assertEqual(L.terminal_size(None), (L.SAFE_WIDTH, L.SAFE_HEIGHT))
        finally:
            L._stdout_isatty = orig

    def test_honours_console_size_when_piped(self):
        orig = L._stdout_isatty
        L._stdout_isatty = lambda: False
        try:
            self.assertEqual(L.terminal_size(_FakeConsole(133, 42)), (133, 42))
        finally:
            L._stdout_isatty = orig

    def test_zero_or_negative_width_falls_back(self):
        orig = L._stdout_isatty
        L._stdout_isatty = lambda: False
        try:
            w, h = L.terminal_size(_FakeConsole(0, 0))
            self.assertGreaterEqual(w, 1)
            self.assertGreaterEqual(h, 1)
            self.assertEqual((w, h), (L.SAFE_WIDTH, L.SAFE_HEIGHT))
        finally:
            L._stdout_isatty = orig

    def test_console_that_raises_falls_back(self):
        orig = L._stdout_isatty
        L._stdout_isatty = lambda: False
        try:
            w, h = L.terminal_size(_FakeConsole(0, 0, raise_size=True))
            self.assertEqual((w, h), (L.SAFE_WIDTH, L.SAFE_HEIGHT))
        finally:
            L._stdout_isatty = orig

    def test_always_clamped_positive(self):
        self.assertGreaterEqual(L.terminal_size(_FakeConsole(-5, -9))[0], 1)


class DegradedModeTests(unittest.TestCase):
    def test_no_color_env_disables_colour(self):
        import os
        prev = os.environ.get("NO_COLOR")
        os.environ["NO_COLOR"] = "1"
        try:
            self.assertFalse(L.color_enabled())
        finally:
            if prev is None:
                os.environ.pop("NO_COLOR", None)
            else:
                os.environ["NO_COLOR"] = prev

    def test_strip_ansi_removes_csi_and_osc(self):
        self.assertEqual(L.strip_ansi("\x1b[1;31mX\x1b[0m"), "X")
        self.assertEqual(L.strip_ansi("\x1b]8;;u\x07L\x1b]8;;\x07"), "L")


# ── Integration: mission box responsive at every width ─────────────────

class MissionBoxResponsiveTests(unittest.TestCase):
    def test_no_line_exceeds_width_at_any_target_width(self):
        for w in WIDTHS:
            box = theme.get_mission_box(_Mission(), "gemini-2.5-flash", width=w)
            for line in box.splitlines():
                self.assertLessEqual(
                    L.cell_len(line), w,
                    f"mission box line exceeds width {w}: {line!r}")

    def test_medium_and_wide_are_bordered_boxes_of_exact_width(self):
        for w in (60, 80, 120):
            box = theme.get_mission_box(_Mission(), "gemini-2.5-flash", width=w)
            lines = box.splitlines()
            box_w = min(w, L.FRAME_MAX_WIDTH)
            self.assertTrue(lines[0].startswith("┌"))
            self.assertTrue(lines[-1].startswith("└"))
            for line in lines:
                self.assertEqual(L.cell_len(line), box_w, f"@{w}: {line!r}")

    def test_wide_is_capped_at_frame_max(self):
        box = theme.get_mission_box(_Mission(), "gemini-2.5-flash", width=200)
        for line in box.splitlines():
            self.assertEqual(L.cell_len(line), L.FRAME_MAX_WIDTH)

    def test_narrow_is_single_column_no_side_borders(self):
        box = theme.get_mission_box(_Mission(), "gemini-2.5-flash", width=40)
        lines = box.splitlines()
        # single column → no vertical box borders
        self.assertFalse(any(line.startswith("│") for line in lines))
        self.assertIn("MISSION", lines[0])

    def test_narrow_hides_secondary_metadata(self):
        box = theme.get_mission_box(_Mission(), "gemini-2.5-flash", width=40)
        # ports / scope / model are secondary metadata hidden in the narrow layout
        self.assertNotIn("scope", box)
        self.assertNotIn("model", box)
        # primary fields remain
        self.assertIn("target", box)
        self.assertIn("phase", box)


# ── Integration: prose width cap ───────────────────────────────────────

_PARA = (
    "Ceci est un long paragraphe de prose destiné à vérifier que la largeur du "
    "texte est plafonnée sur un terminal très large afin de rester lisible et de "
    "ne jamais s'étaler sur toute la largeur de deux cents colonnes entières ici, "
    "ce qui serait pénible à lire pour n'importe quel opérateur humain normal."
)


class ProseWidthCapTests(unittest.TestCase):
    def test_no_prose_line_exceeds_width_at_any_target(self):
        for w in WIDTHS:
            for line in _render_prose_lines(_PARA, w):
                self.assertLessEqual(L.cell_len(line), w, f"prose overflow @ {w}: {line!r}")

    def test_capped_on_ultra_wide(self):
        lines = _render_prose_lines(_PARA, 200)
        longest = max((L.cell_len(ln) for ln in lines if ln.strip()), default=0)
        # left indent (2) + capped text column
        self.assertLessEqual(longest, L.TEXT_MAX_WIDTH + 2)
        self.assertGreater(longest, 60, "prose should still fill the capped column")

    def test_uses_full_width_when_narrow_or_medium(self):
        # At width 80 the prose should wrap near the full width (cap does not bite).
        lines = _render_prose_lines(_PARA, 80)
        longest = max((L.cell_len(ln) for ln in lines if ln.strip()), default=0)
        self.assertGreater(longest, 80 - 12)


# ── Integration: holistic "no parasitic wrap / no cut line" ────────────

class HolisticNoOverflowTests(unittest.TestCase):
    def test_combined_frame_has_no_line_over_width(self):
        for w in WIDTHS:
            lay = L.Layout(w, 24, True, True, L.classify(w))
            block = []
            block.append(lay.rule())
            block.extend(theme.get_mission_box(_Mission(), "gemini-2.5-flash", width=w).splitlines())
            block.extend(_render_prose_lines(_PARA, w))
            for line in block:
                self.assertLessEqual(
                    L.cell_len(line), w,
                    f"combined frame overflow @ {w}: {line!r}")


# ── Debounced resize (deterministic, fake loop) ────────────────────────

class _FakeHandle:
    def __init__(self, cb):
        self.cb, self.cancelled = cb, False

    def cancel(self):
        self.cancelled = True


class _FakeLoop:
    def __init__(self):
        self.handlers, self.timers, self.removed = {}, [], []

    def add_signal_handler(self, sig, cb):
        self.handlers[sig] = cb

    def remove_signal_handler(self, sig):
        self.removed.append(sig)
        self.handlers.pop(sig, None)

    def call_later(self, delay, cb):
        h = _FakeHandle(cb)
        self.timers.append(h)
        return h


class ResizeDebouncerTests(unittest.TestCase):
    def test_install_registers_sigwinch(self):
        loop = _FakeLoop()
        d = L.ResizeDebouncer(lambda: None)
        self.assertTrue(d.install(loop))
        import signal
        self.assertIn(signal.SIGWINCH, loop.handlers)

    def test_burst_coalesces_to_single_fire(self):
        loop = _FakeLoop()
        calls = {"n": 0}
        d = L.ResizeDebouncer(lambda: calls.__setitem__("n", calls["n"] + 1))
        d.install(loop)
        import signal
        handler = loop.handlers[signal.SIGWINCH]
        for _ in range(10):          # a drag-resize burst
            handler()
        # every re-arm cancels the previous timer; only the last is live
        live = [t for t in loop.timers if not t.cancelled]
        self.assertEqual(len(live), 1)
        self.assertEqual(calls["n"], 0)   # not fired yet
        live[0].cb()                       # settle
        self.assertEqual(calls["n"], 1)   # exactly one redraw

    def test_uninstall_removes_handler_and_no_ops_after(self):
        loop = _FakeLoop()
        calls = {"n": 0}
        d = L.ResizeDebouncer(lambda: calls.__setitem__("n", calls["n"] + 1))
        d.install(loop)
        d.uninstall()
        import signal
        self.assertIn(signal.SIGWINCH, loop.removed)
        d._on_signal()                     # must not re-arm after uninstall
        self.assertFalse([t for t in loop.timers if not t.cancelled])


class AbbreviatedHintsTests(unittest.TestCase):
    """Narrow terminals show abbreviated keyboard hints, cell-fit to width."""

    def test_narrow_uses_short_tip_set(self):
        from secops_agent.ui.animations import wait_tip_for_elapsed, WAIT_TIPS_SHORT
        tip = wait_tip_for_elapsed(4.0, short=True)
        self.assertIn(tip, WAIT_TIPS_SHORT)

    def test_narrow_tip_line_fits_width(self):
        from secops_agent.ui.animations import format_wait_message
        # elapsed past the tip delay so a tip is emitted
        for w in (30, 40):
            msg = format_wait_message("Running", 6.0, include_tip=True, width=w)
            tip_line = msg.splitlines()[-1]
            # strip rich markup before measuring the visible tip text
            import re
            visible = re.sub(r"\[/?[^\]]+\]", "", tip_line)
            self.assertLessEqual(L.cell_len(visible), w - 1, f"tip overflow @ {w}: {visible!r}")

    def test_medium_uses_full_tip_set(self):
        from secops_agent.ui.animations import format_wait_message, WAIT_TIPS
        msg = format_wait_message("Running", 6.0, include_tip=True, width=100)
        import re
        visible = re.sub(r"\[/?[^\]]+\]", "", msg.splitlines()[-1]).replace("└ Tip: ", "")
        self.assertIn(visible, WAIT_TIPS)


class PromptResizeRegressionTests(unittest.TestCase):
    """The interactive prompt frame must re-wrap to the current width on resize.

    Regression: prompt_async received the *result* of _prompt_fragments() (a
    static list), freezing the '>' border at the launch width while the callable
    toolbar kept resizing — mismatched separators on any resize."""

    def test_get_input_passes_callable_message(self):
        import asyncio
        from unittest import mock
        import secops_agent.ui.input_handler as ih
        h = ih.InputHandler()
        captured = {}

        async def fake(message=None, **kw):
            captured["message"] = message
            return "hi"

        with mock.patch.object(h.session, "prompt_async", side_effect=fake):
            asyncio.run(h.get_input())
        self.assertTrue(
            callable(captured["message"]),
            "prompt message must be a callable so the border re-wraps on resize")

    def test_prompt_border_tracks_current_width(self):
        import secops_agent.ui.input_handler as ih
        h = ih.InputHandler()
        orig = ih._terminal_width
        try:
            ih._terminal_width = lambda default=80: 50
            sep_small = next(t for _s, t in h._prompt_fragments() if "─" in t).rstrip("\n")
            ih._terminal_width = lambda default=80: 160
            sep_big = next(t for _s, t in h._prompt_fragments() if "─" in t).rstrip("\n")
        finally:
            ih._terminal_width = orig
        self.assertEqual(len(sep_small), 49)
        self.assertEqual(len(sep_big), 119)   # capped at FRAME_MAX_WIDTH (120) - 1

    def test_prompt_and_toolbar_share_width_source(self):
        # Both derive from _frame_width(_terminal_width()) so they never disagree.
        import secops_agent.ui.input_handler as ih
        h = ih.InputHandler()
        orig = ih._terminal_width
        try:
            ih._terminal_width = lambda default=80: 90
            sep = next(t for _s, t in h._prompt_fragments() if "─" in t).rstrip("\n")
        finally:
            ih._terminal_width = orig
        self.assertEqual(len(sep), 89)


if __name__ == "__main__":
    unittest.main()
