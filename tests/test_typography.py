"""P3 — typographic normalization module (secops_agent/ui/typography.py).

Covers the three P3 concerns the module centralizes: vertical-rhythm tokens
(DESIGN_SPEC §2), the indent columns (§1.1), and plain-text normalization
(collapse blank runs, strip trailing, no leading/trailing blank). The acceptance
test is determinism: same structure → identical output.
"""

import io
import unittest

from rich.console import Console

from secops_agent.ui import layout, typography as T
from secops_agent.ui.typography import Boundary


class IndentTests(unittest.TestCase):
    def test_indent_constants_come_from_layout(self):
        self.assertEqual(T.INDENT, layout.INDENT)
        self.assertEqual(T.RESULT_INDENT, layout.RESULT_INDENT)
        self.assertEqual(T.INDENT, 2)
        self.assertEqual(T.RESULT_INDENT, 5)
        self.assertEqual(T.INDENT_STR, "  ")
        self.assertEqual(T.RESULT_INDENT_STR, "     ")

    def test_indent_levels(self):
        self.assertEqual(T.indent("x", 0), "x")
        self.assertEqual(T.indent("x", 1), "  x")
        self.assertEqual(T.indent("x", 2), "    x")
        self.assertEqual(T.indent("x", 3), "      x")

    def test_indent_default_is_one_level(self):
        self.assertEqual(T.indent("hi"), "  hi")

    def test_indent_negative_level_is_clamped(self):
        self.assertEqual(T.indent("x", -3), "x")


class RhythmTokenTests(unittest.TestCase):
    def test_seven_tokens_have_spec_values(self):
        self.assertEqual(T.blanks_for(Boundary.BEFORE_TOOL_GROUP), 1)
        self.assertEqual(T.blanks_for(Boundary.WITHIN_TOOL_GROUP), 0)
        self.assertEqual(T.blanks_for(Boundary.AFTER_USER_TURN), 1)
        self.assertEqual(T.blanks_for(Boundary.BETWEEN_MD_BLOCKS), 1)
        self.assertEqual(T.blanks_for(Boundary.WITHIN_MD_BLOCK), 0)
        self.assertEqual(T.blanks_for(Boundary.RESULT_TO_META), 0)
        self.assertEqual(T.blanks_for(Boundary.TRAILING_PROSE), 0)

    def test_spec_tokens_are_exactly_the_seven(self):
        # SPEC_TOKENS is exactly the 7 DESIGN_SPEC §2 tokens.
        self.assertEqual(len(T.SPEC_TOKENS), 7)
        self.assertEqual(set(T.SPEC_TOKENS), {
            Boundary.BEFORE_TOOL_GROUP, Boundary.WITHIN_TOOL_GROUP,
            Boundary.AFTER_USER_TURN, Boundary.BETWEEN_MD_BLOCKS,
            Boundary.WITHIN_MD_BLOCK, Boundary.RESULT_TO_META, Boundary.TRAILING_PROSE,
        })

    def test_section_break_is_the_only_non_spec_boundary(self):
        # The only Boundary beyond the 7 spec tokens is the generic section break.
        extra = set(Boundary) - set(T.SPEC_TOKENS)
        self.assertEqual(extra, {Boundary.SECTION_BREAK})
        self.assertEqual(T.blanks_for(Boundary.SECTION_BREAK), 1)

    def _emit(self, boundary):
        console = Console(file=io.StringIO(), force_terminal=False, width=80)
        printed = T.emit(console, boundary)
        return printed, console.file.getvalue()

    def test_emit_prints_and_returns_the_blank_count(self):
        for boundary in Boundary:
            printed, out = self._emit(boundary)
            self.assertEqual(printed, T.blanks_for(boundary))
            # A blank line is exactly one newline; a 0-blank boundary prints nothing.
            self.assertEqual(out.count("\n"), T.blanks_for(boundary))

    def test_zero_blank_boundary_prints_nothing(self):
        printed, out = self._emit(Boundary.WITHIN_TOOL_GROUP)
        self.assertEqual(printed, 0)
        self.assertEqual(out, "")


class NormalizeTextTests(unittest.TestCase):
    def test_collapses_multiple_blank_lines_to_one(self):
        self.assertEqual(T.normalize_text("a\n\n\n\nb"), "a\n\nb")

    def test_strips_trailing_whitespace_per_line(self):
        self.assertEqual(T.normalize_text("a   \nb\t\n"), "a\nb")

    def test_drops_leading_and_trailing_blank_lines(self):
        self.assertEqual(T.normalize_text("\n\n  \na\nb\n\n  \n"), "a\nb")

    def test_never_two_consecutive_blanks(self):
        out = T.normalize_text("a\n\n\nb\n\n\n\nc")
        self.assertNotIn("\n\n\n", out)

    def test_no_trailing_blank_line(self):
        out = T.normalize_text("a\nb\n\n\n")
        self.assertFalse(out.endswith("\n"))

    def test_normalizes_crlf_and_cr(self):
        self.assertEqual(T.normalize_text("a\r\nb\rc"), "a\nb\nc")

    def test_is_idempotent(self):
        messy = "\n\n a  \n\n\n b \n\n"
        once = T.normalize_text(messy)
        self.assertEqual(once, T.normalize_text(once))

    def test_empty_and_blank_only_input(self):
        self.assertEqual(T.normalize_text(""), "")
        self.assertEqual(T.normalize_text("\n\n  \n\t\n"), "")


class CollapseBlankLinesTests(unittest.TestCase):
    def test_preserves_markdown_hard_break_trailer(self):
        # An ordered-list line may end with two spaces as a hard-break marker;
        # collapse_blank_lines only touches BLANK lines, so it must survive.
        lines = ["1\\. body  ", "", "", "next"]
        self.assertEqual(
            T.collapse_blank_lines(lines),
            ["1\\. body  ", "", "next"],
        )

    def test_drops_leading_and_trailing_blanks(self):
        self.assertEqual(T.collapse_blank_lines(["", "", "a", "", ""]), ["a"])


class DeterminismAcceptanceTests(unittest.TestCase):
    """P3 acceptance: two inputs of the same structure produce identical spacing."""

    def test_same_structure_yields_identical_normalized_text(self):
        a = "Intro line one.\n\n\n- item A\n- item B\n\n\nOutro."
        b = "Different words here.\n\n- first one\n- second one\n\nClosing."
        # Same block structure (para, 2-item list, para) → identical blank rhythm.
        na, nb = T.normalize_text(a), T.normalize_text(b)
        self.assertEqual(
            [(" " if ln.strip() else "") for ln in na.split("\n")],
            [(" " if ln.strip() else "") for ln in nb.split("\n")],
        )

    def test_emit_sequence_is_deterministic(self):
        seq = [Boundary.AFTER_USER_TURN, Boundary.BEFORE_TOOL_GROUP,
               Boundary.WITHIN_TOOL_GROUP, Boundary.RESULT_TO_META]
        counts_1 = [T.blanks_for(b) for b in seq]
        counts_2 = [T.blanks_for(b) for b in seq]
        self.assertEqual(counts_1, counts_2)
        self.assertEqual(counts_1, [1, 1, 0, 0])


def _spacing_skeleton(text: str) -> list[bool]:
    """Reduce rendered text to its spacing skeleton: one bool per line, True if the
    line carries visible content, False if it is blank. Two responses of the same
    structure must have the same skeleton regardless of the words."""
    return [bool(line.strip()) for line in text.rstrip("\n").split("\n")]


class RenderDeterminismTests(unittest.TestCase):
    """P3 acceptance on REAL responses: two responses of the same block structure
    render to exactly the same spacing (blank-line skeleton)."""

    def _render(self, markdown: str) -> str:
        from secops_agent.ui import renderer as R
        console = Console(width=72, record=True, force_terminal=False, file=io.StringIO())
        console.print(R._StripTrailingWhitespace(R._agent_markdown(markdown, width=72, bullet=True)))
        return console.export_text()

    def test_same_structure_two_responses_identical_spacing(self):
        # Same structure: heading, paragraph, 2-item bullet list, closing paragraph.
        a = ("## Résultat\n\nDeux ports ouverts sur la cible analysée ici.\n\n"
             "- port 22 ssh\n- port 80 http\n\nProchaine étape: énumération web.")
        b = ("## Verdict\n\nUn service critique repéré pendant cette phase active.\n\n"
             "- service alpha\n- service bravo\n\nConclusion: passage à l'exploitation.")
        self.assertEqual(_spacing_skeleton(self._render(a)),
                         _spacing_skeleton(self._render(b)))

    def test_rendered_response_has_no_trailing_or_double_blank(self):
        rendered = self._render("Para un.\n\n\n\nPara deux après plusieurs blancs.")
        self.assertFalse(rendered.endswith("\n\n"))          # no trailing blank block
        self.assertNotIn("\n\n\n", rendered.rstrip("\n"))    # never two consecutive blanks

    def test_render_is_repeatable(self):
        md = "Intro.\n\n- a\n- b\n\nFin."
        self.assertEqual(self._render(md), self._render(md))


if __name__ == "__main__":
    unittest.main()
