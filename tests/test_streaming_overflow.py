"""Regression tests for Example F (streaming text duplication).

A synthesized answer taller than the terminal viewport was re-rendered in full on
every stream chunk, so Rich's Live restacked it into scrollback that cursor-up
cannot reach — the 5-6x cascade the user sees. The fix caps the streaming Live to
the last N lines (`_streaming_tail`) plus `vertical_overflow="crop"`; the complete
answer is written once by `_flush_live_text` on the done event.

The end-to-end no-cascade reproduction through a real PTY lives in
`scratch/tui_smoke.py` (run_streaming_overflow_smoke); these lock the pure logic.
"""
from __future__ import annotations

import unittest

import asyncio
import io

from rich.console import Console

from secops_agent.core.agent import TextEvent, ThinkingEvent
from secops_agent.ui.renderer import Renderer, _StripTrailingWhitespace, _streaming_tail


class StreamingTailTests(unittest.TestCase):
    def test_short_text_is_unchanged(self) -> None:
        text = "line1\nline2\nline3"
        self.assertEqual(_streaming_tail(text, 28), text)

    def test_tall_text_is_capped_to_the_tail(self) -> None:
        lines = [f"l{i}" for i in range(100)]
        out = _streaming_tail("\n".join(lines), 28).split("\n")
        # viewport-6 = 22 lines, and it keeps the TAIL (newest content)
        self.assertEqual(len(out), 22)
        self.assertEqual(out[-1], "l99")
        self.assertEqual(out[0], "l78")

    def test_never_below_a_small_floor(self) -> None:
        body = "\n".join(f"l{i}" for i in range(50))
        # unknown viewport (0) falls back to a sane default, tiny viewport floors at 4
        self.assertGreaterEqual(len(_streaming_tail(body, 0).split("\n")), 4)
        self.assertGreaterEqual(len(_streaming_tail(body, 3).split("\n")), 4)

    def test_tail_preserves_retained_line_content(self) -> None:
        body = "\n".join(f"unique-{i}" for i in range(40))
        out = _streaming_tail(body, 28)
        self.assertIn("unique-39", out)
        self.assertNotIn("unique-0", out)



class ResizeShapeReflowTests(unittest.TestCase):
    """After a terminal resize the terminal reflows the on-screen live frame, but
    Rich's LiveRender._shape keeps the pre-resize height, so its next
    position_cursor() rewinds by the wrong row count — the shrink cascade / grow
    void. _reflow_live_shape re-measures the frame at the CURRENT width and corrects
    the shape height. These lock the correction mechanism (a true PTY reflow is not
    reproducible in a StringIO console)."""

    def _live_at(self, content, width, height=40):
        from rich.live import Live
        from secops_agent.ui.renderer import _agent_markdown
        console = Console(file=io.StringIO(), force_terminal=True, width=width, height=height)
        frame = _agent_markdown(content, width=width)
        live = Live(frame, console=console, auto_refresh=False)
        list(console.render(live._live_render))  # sets _shape to the width-`width` height
        return live, console

    def test_shrink_reflow_rewrites_height_to_narrower_width(self):
        from secops_agent.ui.renderer import _reflow_live_shape, _agent_markdown
        para = "mot " * 90  # wraps to more rows the narrower it gets
        live, _ = self._live_at(para, width=100)
        h_wide = live._live_render._shape[1]
        narrow = Console(file=io.StringIO(), force_terminal=True, width=40, height=40)
        corrected = _reflow_live_shape(live, _agent_markdown(para, width=40), narrow)
        # Height is re-measured at width 40 (taller) and written back — not stuck wide.
        self.assertEqual(live._live_render._shape[1], corrected)
        self.assertGreater(corrected, h_wide)

    def test_grow_reflow_rewrites_height_to_wider_width(self):
        from secops_agent.ui.renderer import _reflow_live_shape, _agent_markdown
        para = "mot " * 90
        live, _ = self._live_at(para, width=40)
        h_narrow = live._live_render._shape[1]
        wide = Console(file=io.StringIO(), force_terminal=True, width=100, height=40)
        corrected = _reflow_live_shape(live, _agent_markdown(para, width=100), wide)
        self.assertEqual(live._live_render._shape[1], corrected)
        self.assertLess(corrected, h_narrow)

    def test_reflow_caps_height_at_console_height(self):
        from secops_agent.ui.renderer import _reflow_live_shape, _agent_markdown
        para = "mot " * 200
        live, _ = self._live_at(para, width=80)
        tiny = Console(file=io.StringIO(), force_terminal=True, width=40, height=6)
        corrected = _reflow_live_shape(live, _agent_markdown(para, width=40), tiny)
        self.assertLessEqual(corrected, 6)  # never rewinds past the viewport

    def test_reflow_is_safe_without_a_live_render(self):
        from secops_agent.ui.renderer import _reflow_live_shape
        console = Console(file=io.StringIO(), force_terminal=True, width=40, height=20)
        self.assertEqual(_reflow_live_shape(object(), "anything", console), 0)


class TrailingWhitespaceTests(unittest.TestCase):
    """#6: the flushed streamed answer must not carry right-side padding spaces
    into scrollback (they survive copy-paste). The Segment-level stripper runs
    through console.print, so recording and ctrl+o line accounting are intact."""

    def _content_lines_with_trailing_ws(self, output: str) -> list[str]:
        return [ln for ln in output.split("\n") if ln.strip() and ln != ln.rstrip()]

    def test_streamed_answer_has_no_trailing_whitespace(self) -> None:
        renderer = Renderer()
        renderer.console = Console(width=72, record=True, force_terminal=False, file=io.StringIO())

        async def events():
            yield ThinkingEvent("Analyzing")
            yield TextEvent("## Resume\n\nLe port 22 est ouvert.\n\n- point un\n- point deux")
            yield TextEvent("", done=True)

        asyncio.run(renderer.render_agent_stream(events()))
        output = renderer.console.export_text()
        self.assertEqual(self._content_lines_with_trailing_ws(output), [])
        # content is preserved, not truncated
        self.assertIn("Le port 22 est ouvert.", output)
        self.assertIn("point deux", output)

    def test_stripper_preserves_line_count(self) -> None:
        from rich.markdown import Markdown
        from rich.padding import Padding

        text = "alpha\n\nbeta\n\n- one\n- two"
        base = Padding(Markdown(text), (0, 0, 0, 2))

        def lines(renderable):
            con = Console(width=50, record=True, force_terminal=False, file=io.StringIO())
            con.print(renderable)
            return [ln.rstrip() for ln in con.export_text().split("\n")]

        self.assertEqual(lines(base), lines(_StripTrailingWhitespace(base)))


if __name__ == "__main__":
    unittest.main()
