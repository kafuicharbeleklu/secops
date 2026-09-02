"""
Centralized terminal-layout layer (P2 — resize responsiveness).

Single source of truth for terminal geometry across the TUI:

* **Cell-accurate measurement.** Widths are counted in *terminal cells* via
  ``rich.cells`` — so CJK/fullwidth glyphs, emoji, ZWJ sequences and combining
  marks are measured correctly, never by byte or codepoint count. This is the
  fix for parasitic wrapping and cut lines on wide/complex text.
* **Size resolution with safe fallbacks.** :func:`terminal_size` reads the size
  *fresh* every call (no caching → no stale-width resize bug), clamps to ``>= 1``,
  and falls back to a safe 80x24 for pipes / redirected output / unknown size.
* **Responsive breakpoints.** :class:`Layout` classifies the current width into
  ``narrow`` / ``medium`` / ``wide`` and exposes the per-breakpoint knobs
  (metadata hidden, hints abbreviated, text width capped on ultra-wide).
* **Debounced resize.** :class:`ResizeDebouncer` coalesces a SIGWINCH burst (an
  interactive drag-resize) into a single settled redraw to avoid flicker.

Every layout decision in the TUI should derive from the *current* width via this
module rather than a hardcoded constant.
"""

from __future__ import annotations

import re
import sys
import shutil
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable

from rich.cells import cell_len as _rich_cell_len, set_cell_size as _rich_set_cell_size

__all__ = [
    "SAFE_WIDTH", "SAFE_HEIGHT", "NARROW_MAX", "WIDE_MIN",
    "TEXT_MAX_WIDTH", "FRAME_MAX_WIDTH", "RESIZE_DEBOUNCE",
    "Breakpoint", "Layout", "ResizeDebouncer",
    "strip_ansi", "cell_len", "fit_cell", "pad_cell",
    "terminal_size", "is_tty", "color_enabled", "classify", "resolve",
]

# ── Safe fallbacks: unknown width / non-TTY / get_terminal_size failure ──
SAFE_WIDTH = 80
SAFE_HEIGHT = 24

# ── Width breakpoints, in terminal cells ──
#   narrow : width <= NARROW_MAX   → single column, abbreviated hints, metadata hidden
#   medium : NARROW_MAX < w < WIDE_MIN → default layout
#   wide   : width >= WIDE_MIN     → cap the text column, align the rest left
NARROW_MAX = 59
WIDE_MIN = 120

# ── Readable-width caps for very wide terminals ──
# Full-width prose on a 200-column terminal is unreadable; cap the text column
# while the frame (prompt/toolbar/tool output) may run a little wider.
TEXT_MAX_WIDTH = 100
FRAME_MAX_WIDTH = 120

# Coalescing window for a drag-resize burst (seconds). Sits alongside the
# streaming render throttle; long enough to swallow a drag, short enough to feel
# immediate on release.
RESIZE_DEBOUNCE = 0.08

_ELLIPSIS = "…"  # …

# CSI escapes (colours, cursor) and OSC sequences (e.g. OSC 8 hyperlinks).
_ANSI_RE = re.compile(r"\x1b\[[0-9;:?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")


class Breakpoint(str, Enum):
    NARROW = "narrow"
    MEDIUM = "medium"
    WIDE = "wide"


# ── Cell-accurate string measurement ──────────────────────────────────

def strip_ansi(text: str) -> str:
    """Drop CSI/OSC escape sequences so they do not count toward display width."""
    return _ANSI_RE.sub("", str(text))


def cell_len(text: str) -> int:
    """Display width of *text* in terminal cells, ignoring ANSI escapes.

    Correct for CJK/fullwidth (2 cells), emoji (2), ZWJ sequences (collapsed),
    and combining marks (0) — unlike ``len()``, which counts codepoints."""
    clean = strip_ansi(text)
    if not clean:
        return 0
    width = _rich_cell_len(clean)
    # rich returns a negative sentinel for strings with control chars; fall back
    # to a defensive codepoint count so callers never get a bogus negative width.
    return width if width >= 0 else len(clean)


def fit_cell(text: str, width: int, *, ellipsis: str = _ELLIPSIS) -> str:
    """Truncate *text* to at most *width* display cells, appending *ellipsis*
    when it does not fit. ANSI is stripped (plain text out); a wide glyph is
    never split across the boundary (rich pads with a space instead)."""
    if width <= 0:
        return ""
    clean = strip_ansi(str(text)).replace("\n", " ")
    if cell_len(clean) <= width:
        return clean
    ell_w = cell_len(ellipsis)
    if width <= ell_w:
        return _rich_set_cell_size(ellipsis, width)
    return _rich_set_cell_size(clean, width - ell_w) + ellipsis


def pad_cell(text: str, width: int, *, align: str = "left", fill: str = " ") -> str:
    """Pad (or truncate) *text* to exactly *width* display cells.

    Measures in cells so a padded column of mixed CJK/ASCII stays aligned.
    ANSI styling in *text* is preserved when it fits (only measurement strips
    it); an over-long value is cell-truncated via :func:`fit_cell`."""
    if width <= 0:
        return ""
    clean = str(text)
    w = cell_len(clean)
    if w > width:
        return fit_cell(clean, width)
    gap = fill * (width - w)
    if align == "right":
        return gap + clean
    if align == "center":
        left = (width - w) // 2
        return fill * left + clean + fill * (width - w - left)
    return clean + gap


# ── Terminal geometry ─────────────────────────────────────────────────

def _stdout_isatty() -> bool:
    try:
        return bool(sys.stdout.isatty())
    except Exception:
        return False


def is_tty(console: Any = None) -> bool:
    """True when writing to an interactive terminal (not a pipe/redirect)."""
    if console is not None:
        flag = getattr(console, "is_terminal", None)
        if flag is not None:
            return bool(flag)
    return _stdout_isatty()


def color_enabled() -> bool:
    """Whether colour should be emitted (honours NO_COLOR / CLICOLOR).

    Delegates to :func:`secops_agent.ui.theme.color_enabled` so the convention
    lives in one place."""
    try:
        from secops_agent.ui.theme import color_enabled as _ce
        return bool(_ce())
    except Exception:
        return _stdout_isatty()


def terminal_size(
    console: Any = None,
    *,
    default_width: int = SAFE_WIDTH,
    default_height: int = SAFE_HEIGHT,
) -> tuple[int, int]:
    """Current terminal ``(width, height)`` in cells/rows, read fresh.

    Prefers the rich ``Console`` size when supplied; on a real TTY it also
    consults the OS terminal size and takes the smaller (guards against a
    console reporting a stale/oversized width). For a pipe/redirect it honours
    the console's declared size and never lets the OS size leak in. Always
    clamps to ``>= 1`` and falls back to the safe defaults."""
    widths: list[int] = []
    heights: list[int] = []
    if console is not None:
        try:
            widths.append(int(console.size.width))
            heights.append(int(console.size.height))
        except Exception:
            pass
    if _stdout_isatty():
        try:
            size = shutil.get_terminal_size((default_width, default_height))
            widths.append(int(size.columns))
            heights.append(int(size.lines))
        except Exception:
            pass
    w = min([x for x in widths if x > 0], default=default_width)
    h = min([x for x in heights if x > 0], default=default_height)
    return max(1, w), max(1, h)


# ── Breakpoints & the resolved Layout ─────────────────────────────────

def classify(width: int) -> Breakpoint:
    """Map a width in cells to its responsive breakpoint."""
    if width <= NARROW_MAX:
        return Breakpoint.NARROW
    if width >= WIDE_MIN:
        return Breakpoint.WIDE
    return Breakpoint.MEDIUM


@dataclass(frozen=True)
class Layout:
    """An immutable snapshot of the terminal geometry for one render pass.

    Resolve it once at the top of a render (:func:`resolve`) and thread it down,
    or call ``resolve()`` fresh each render — both read the *current* size."""

    width: int
    height: int
    is_tty: bool
    color: bool
    breakpoint: Breakpoint

    @property
    def narrow(self) -> bool:
        return self.breakpoint is Breakpoint.NARROW

    @property
    def medium(self) -> bool:
        return self.breakpoint is Breakpoint.MEDIUM

    @property
    def wide(self) -> bool:
        return self.breakpoint is Breakpoint.WIDE

    @property
    def text_width(self) -> int:
        """Readable content column: full width until it exceeds the cap, then
        capped so prose never sprawls edge-to-edge on an ultra-wide terminal."""
        return max(1, min(self.width, TEXT_MAX_WIDTH))

    @property
    def frame_width(self) -> int:
        """Decorative frame column (prompt/toolbar/tool output), capped wider
        than prose so structural rules still read as full-width on mid displays."""
        return max(1, min(self.width, FRAME_MAX_WIDTH))

    @property
    def hide_metadata(self) -> bool:
        """Narrow terminals drop secondary metadata (model/scope/cwd columns)."""
        return self.narrow

    @property
    def abbreviated_hints(self) -> bool:
        """Narrow terminals show abbreviated keyboard hints."""
        return self.narrow

    def rule(self, char: str = "─", *, full: bool = False) -> str:
        """A horizontal separator sized to the current width. Defaults to
        ``width - 1`` so it never triggers terminal edge-wrap; pass
        ``full=True`` for an exact-width rule."""
        count = self.width if full else self.width - 1
        return char * max(1, count)


def resolve(console: Any = None) -> Layout:
    """Snapshot the current terminal geometry into a :class:`Layout`."""
    width, height = terminal_size(console)
    return Layout(
        width=width,
        height=height,
        is_tty=is_tty(console),
        color=color_enabled(),
        breakpoint=classify(width),
    )


# ── Debounced resize ──────────────────────────────────────────────────

class ResizeDebouncer:
    """Coalesce a SIGWINCH burst into a single settled redraw.

    An interactive drag-resize fires SIGWINCH many times per second; redrawing
    on each one tears/flickers. Install this on the running asyncio loop during
    a live-render phase: each signal (re)arms a short timer and *callback* runs
    once, only after the burst settles for ``delay`` seconds.

    POSIX-only (SIGWINCH); :meth:`install` returns ``False`` where the signal or
    the loop's ``add_signal_handler`` is unavailable (e.g. Windows, non-main
    thread), so callers degrade cleanly to per-token resize pickup."""

    def __init__(self, callback: Callable[[], None], *, delay: float = RESIZE_DEBOUNCE):
        self._callback = callback
        self._delay = delay
        self._loop: Any = None
        self._handle: Any = None
        self._installed = False

    def install(self, loop: Any) -> bool:
        import signal
        if not hasattr(signal, "SIGWINCH"):
            return False
        try:
            loop.add_signal_handler(signal.SIGWINCH, self._on_signal)
        except (NotImplementedError, RuntimeError, ValueError, OSError):
            return False
        self._loop = loop
        self._installed = True
        return True

    def _on_signal(self) -> None:
        if not self._installed or self._loop is None:
            return
        if self._handle is not None:
            self._handle.cancel()
        self._handle = self._loop.call_later(self._delay, self._fire)

    def _fire(self) -> None:
        self._handle = None
        try:
            self._callback()
        except Exception:
            pass

    def uninstall(self) -> None:
        import signal
        if self._handle is not None:
            self._handle.cancel()
            self._handle = None
        if self._installed and self._loop is not None:
            try:
                self._loop.remove_signal_handler(signal.SIGWINCH)
            except Exception:
                pass
        self._installed = False
