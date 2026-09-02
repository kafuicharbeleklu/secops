"""
Typographic normalization for the agent-response transcript (P3).

Single source of truth for the three things that make two responses of the same
structure render with *exactly* the same spacing:

* **Vertical rhythm** — the DESIGN_SPEC §2 ``rhythm.*`` tokens, named as
  :class:`Boundary` with their blank-line counts. The response render path emits
  block boundaries through :func:`emit` (which returns the number of blank lines
  printed, so ctrl+o line-accounting stays correct) instead of ad-hoc
  ``console.print()`` / ``prefix="\\n"`` literals scattered and duplicated across
  the streaming, replay and meta-line paths.
* **Indentation** — the DESIGN_SPEC §1.1 ``indent.*`` columns, re-exported from
  :mod:`secops_agent.ui.layout` (``INDENT`` = 2, ``RESULT_INDENT`` = 5) with an
  :func:`indent` helper, so no response-path code carries a bare ``"  "`` literal.
* **Plain-text normalization** — :func:`normalize_text` / :func:`collapse_blank_lines`
  collapse blank-line runs to one, strip per-line trailing whitespace, and drop
  leading/trailing blank lines. :func:`collapse_blank_lines` is the shared rule
  that ``renderer.normalize_agent_markdown`` reuses, so the "no double blank / no
  trailing blank" rule is written **once**.

Keeping every spacing/indent/blank rule here is what the P3 acceptance criteria
require: two responses of the same structure produce identical spacing, and no
spacing rule is duplicated in the render/tool code.
"""

from __future__ import annotations

import enum
from typing import TYPE_CHECKING

from secops_agent.ui.layout import INDENT, RESULT_INDENT, INDENT_STR, RESULT_INDENT_STR

if TYPE_CHECKING:  # pragma: no cover - typing only
    from rich.console import Console

__all__ = [
    "INDENT", "RESULT_INDENT", "INDENT_STR", "RESULT_INDENT_STR", "indent",
    "Boundary", "blanks_for", "emit",
    "normalize_text", "collapse_blank_lines",
]

# ── Indentation (DESIGN_SPEC §1.1 indent.*) ──────────────────────────────
# INDENT / RESULT_INDENT and their string forms live in layout.py (the geometry
# layer); re-exported here so response-path code has one import for all
# typographic constants.


def indent(text: str = "", level: int = 1) -> str:
    """Left-pad *text* by *level* indent columns (DESIGN_SPEC ``indent.list_step``:
    each nesting level adds ``INDENT`` columns). ``level=0`` returns *text* as-is."""
    return " " * (INDENT * max(0, int(level))) + text


# ── Vertical rhythm (DESIGN_SPEC §2 rhythm.*) ────────────────────────────
class Boundary(enum.Enum):
    """A block boundary in the agent-response transcript. Its value is the DESIGN_SPEC
    §2 token name; :data:`_BLANKS` maps it to the number of blank lines it emits."""

    BEFORE_TOOL_GROUP = "before_tool_group"   # 1 blank before the first call of a tool group
    WITHIN_TOOL_GROUP = "within_tool_group"   # 0 between consecutive calls / call↔result
    AFTER_USER_TURN = "after_user_turn"       # 1 between the user input and the response
    BETWEEN_MD_BLOCKS = "between_md_blocks"   # 1 between md blocks of a different kind
    WITHIN_MD_BLOCK = "within_md_block"       # 0 between items of one list / paragraph
    RESULT_TO_META = "result_to_meta"         # 0 — the ⎿ meta line immediately follows the result
    TRAILING_PROSE = "trailing_prose"         # 0 — no trailing blank at the end of a response


# The one place the §2 blank-line counts are defined.
_BLANKS: dict[Boundary, int] = {
    Boundary.BEFORE_TOOL_GROUP: 1,
    Boundary.WITHIN_TOOL_GROUP: 0,
    Boundary.AFTER_USER_TURN: 1,
    Boundary.BETWEEN_MD_BLOCKS: 1,
    Boundary.WITHIN_MD_BLOCK: 0,
    Boundary.RESULT_TO_META: 0,
    Boundary.TRAILING_PROSE: 0,
}


def blanks_for(boundary: Boundary) -> int:
    """Number of blank lines the §2 rhythm rules place at *boundary*."""
    return _BLANKS[boundary]


def emit(console: "Console", boundary: Boundary) -> int:
    """Print the blank line(s) for *boundary* and return the count printed.

    The return value lets the caller keep ctrl+o line-accounting correct (each
    printed blank is one transcript row). A 0-blank boundary prints nothing and
    returns 0, so callers can route *every* block transition through ``emit`` and
    let the token decide whether a gap appears."""
    count = _BLANKS[boundary]
    for _ in range(count):
        console.print()
    return count


# ── Plain-text normalization ─────────────────────────────────────────────
def collapse_blank_lines(lines: list[str]) -> list[str]:
    """Collapse runs of blank lines to a single blank and drop leading/trailing
    blank lines. Operates on a line list and touches only blank lines — non-blank
    content (including Markdown hard-break trailers) is preserved verbatim.

    This is the shared implementation of the "no ≥2 consecutive blanks / no
    leading or trailing blank" rule (DESIGN_SPEC ``rhythm.within_md_block`` /
    ``rhythm.trailing_prose``); ``renderer.normalize_agent_markdown`` reuses it so
    the rule is written once."""
    out: list[str] = []
    for line in lines:
        if not line.strip():
            if not out or not out[-1].strip():
                continue  # drop a leading blank or collapse a run to one
            out.append("")
        else:
            out.append(line)
    while out and not out[-1].strip():
        out.pop()
    return out


def normalize_text(text: str) -> str:
    """Normalize plain model text before rendering: normalize line endings, strip
    per-line trailing whitespace, collapse blank-line runs to one, and drop
    leading/trailing blank lines. Deterministic and idempotent — the same input
    structure always yields the same output.

    Use this for non-Markdown model-text sinks (``--print`` / JSON output, error
    warnings). The TUI Markdown path routes through
    ``renderer.normalize_agent_markdown``, which reuses :func:`collapse_blank_lines`
    for the same blank-line rule."""
    raw = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    stripped = [line.rstrip() for line in raw]
    return "\n".join(collapse_blank_lines(stripped))
