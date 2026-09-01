"""
Animations for the SecOps Agent TUI.
Minimal, clean spinners matching Antigravity CLI style.
Includes live elapsed timer during tool execution.
"""

from __future__ import annotations

import asyncio
import shutil
import sys
import time
from typing import Any
from rich.console import Console
from rich.status import Status

from secops_agent.ui.theme import COLORS, reduced_motion

__all__ = [
    "ThinkingSpinner",
    "ToolExecutionSpinner",
    "StartupAnimation",
    "StreamingDots",
    "WAIT_TIPS",
    "STARTUP_CLEAR_SEQUENCE",
    "format_wait_message",
    "wait_tip_for_elapsed",
]


from rich.spinner import SPINNERS


WAIT_TIPS = (
    "@path adds evidence context",
    "esc interrupts long generation",
    "ctrl+o toggles latest transcript",
    "ctrl+r reviews latest artifact",
    "/permissions reviews approvals",
    "/statusline shows runtime context",
)
_TIP_INTERVAL_SECONDS = 4.0
_TIP_DELAY_SECONDS = 2.0
_RUNNING_LABELS = ("Running", "Running.", "Running..", "Running...")
STARTUP_CLEAR_SEQUENCE = ""


def wait_tip_for_elapsed(elapsed: float, *, offset: int = 0) -> str:
    index = int(max(0.0, elapsed) // _TIP_INTERVAL_SECONDS)
    return WAIT_TIPS[(index + offset) % len(WAIT_TIPS)]


_WAIT_WARM_SECONDS = 10.0
_WAIT_URGENT_SECONDS = 30.0


def wait_urgency_color(elapsed: float) -> str:
    """ANIM-03: the wait indicator warms with elapsed time so a long turn reads
    as 'still working' - muted under ~10s, amber past it, gold past ~30s."""
    if elapsed >= _WAIT_URGENT_SECONDS:
        return COLORS["accent"]
    if elapsed >= _WAIT_WARM_SECONDS:
        return COLORS["warning"]
    return COLORS["text_muted"]


def format_wait_message(
    message: str,
    elapsed: float,
    *,
    include_tip: bool = True,
    offset: int = 0,
) -> str:
    color = wait_urgency_color(elapsed)
    if not include_tip or elapsed < _TIP_DELAY_SECONDS:
        return f"[{color}]{message}[/{color}]"
    tip = wait_tip_for_elapsed(elapsed, offset=offset)
    return (
        f"[{color}]{message}[/{color}]\n"
        f"[{COLORS['text_dim']}]└ Tip: {tip}[/{COLORS['text_dim']}]"
    )


def _running_label_for_elapsed(elapsed: float) -> str:
    index = int(max(0.0, elapsed)) % len(_RUNNING_LABELS)
    return _RUNNING_LABELS[index]

# Register custom antigravity spinner frames matching Antigravity CLI 1.0.10
SPINNERS["agy_dots"] = {
    "interval": 80,
    "frames": ["⣾", "⣷", "⣯", "⣟", "⡿", "⢿", "⣻", "⣽"]
}
# Register custom antigravity spinner frames matching Antigravity CLI 1.0.3
SPINNERS["antigravity"] = {
    "interval": 100,
    "frames": ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
}
# Invisible spinner — no rotating icon, just live-updating text.
SPINNERS["none"] = {
    "interval": 1000,
    "frames": [" "]
}


def _fit_cell(text: str, width: int) -> str:
    if width <= 0:
        return ""
    if len(text) <= width:
        return text
    if width == 1:
        return "…"
    return text[: width - 1] + "…"


import re

def extract_thought_summary(thought_text: str) -> str:
    text = thought_text.strip()
    if not text:
        return "planning next step"
    # Remove markdown formatting if any
    text = re.sub(r"[*_`#]", "", text)
    # Split into sentences or lines
    sentences = re.split(r"(?<=[.!?])\s+", text)
    sentences = [s.strip() for s in sentences if s.strip()]
    if not sentences:
        return "planning next step"
    # Try to find a sentence starting with action indicators
    action_keywords = ["run", "exec", "scan", "lookup", "request", "write", "check", "verify", "call", "test", "find", "use"]
    for s in reversed(sentences):
        s_lower = s.lower()
        if any(w in s_lower for w in ["i will", "i should", "let's", "lets", "i need to", "next step", "plan is"]):
            return s
        if any(w in s_lower for w in action_keywords):
            return s
    # Fallback to the last sentence, truncated
    last_s = sentences[-1]
    if len(last_s) > 60:
        return last_s[:57] + "..."
    return last_s


def _spinner_name() -> str:
    """Static (no rotating glyph) under reduced motion, else the agy spinner."""
    return "none" if reduced_motion() else "agy_dots"


def _spinner_refresh() -> int:
    return 2 if reduced_motion() else 12


_PHASE_LABELS = {
    "scoping": "Scoping the mission",
    "recon": "Running reconnaissance",
    "enumeration": "Enumerating the target",
    "vulnerability": "Assessing vulnerabilities",
    "exploitation": "Working the exploit path",
    "post_exploitation": "Post-exploitation",
    "reporting": "Compiling the report",
}


def thinking_label_for_phase(phase: str) -> str:
    """ANIM-04: a semantic 'what the agent is doing' label from the mission
    phase, falling back to a generic label when no mission is active.  Derived
    from the controlled phase enum only - never raw model reasoning (ASI01)."""
    return _PHASE_LABELS.get(str(phase or "").strip().lower(), "Generating")


class ThinkingSpinner:
    """Simple 'Thinking...' spinner matching Antigravity CLI exactly."""

    def __init__(self, message: str = "Thinking", console: Console | None = None, status_right: str = ""):
        self.message = message
        self._console = console
        self._status_right = status_right
        self._status: Status | None = None
        self._running = False
        self._start_time: float = 0.0
        self._timer_task: asyncio.Task | None = None

    def start(self):
        if self._running:
            return
        self._running = True
        self._start_time = time.monotonic()
        self._status = Status(
            self._status_message(0.0),
            spinner=_spinner_name(),
            spinner_style=COLORS["accent"],
            refresh_per_second=_spinner_refresh(),
            console=self._console,
        )
        self._status.start()
        try:
            loop = asyncio.get_running_loop()
            self._timer_task = loop.create_task(self._update_timer())
        except RuntimeError:
            pass

    async def _update_timer(self):
        try:
            while self._running and self._status:
                elapsed = time.monotonic() - self._start_time
                self._status.update(self._status_message(elapsed))
                await asyncio.sleep(1.0)
        except asyncio.CancelledError:
            pass
        except Exception:
            pass

    def _status_message(self, elapsed: float) -> str:
        message = format_wait_message(self.message, elapsed, include_tip=True)
        if not self._status_right:
            return message

        width = self._console.size.width if self._console else shutil.get_terminal_size((80, 24)).columns
        if sys.stdout.isatty():
            width = min(width, shutil.get_terminal_size((width or 80, 24)).columns)
        width = max(1, width)
        separator = "─" * max(1, width - 1)
        left = "esc to cancel"
        right = _fit_cell(self._status_right, max(10, width - len(left) - 2))
        spacing = " " * max(1, width - len(left) - len(right) - 1)
        footer = f"{left}{spacing}{right}"
        return (
            f"{message}\n"
            f"[{COLORS['text_dim']}]{separator}[/]\n"
            f"[{COLORS['accent']}]>[/]\n"
            f"[{COLORS['text_dim']}]{separator}[/]\n"
            f"[{COLORS['text_muted']}]{footer}[/]"
        )

    def stop(self):
        if self._timer_task and not self._timer_task.done():
            self._timer_task.cancel()
            self._timer_task = None
        if self._status and self._running:
            try:
                self._status.stop()
            except Exception:
                pass
        self._running = False

    def update(self, message: str):
        """Accept thought content updates (used by renderer) but don't change the display."""
        self.message = message

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def elapsed(self) -> float:
        if self._start_time:
            return time.monotonic() - self._start_time
        return 0.0


def _tool_display_name(tool_name: str) -> str:
    names = {
        "run_shell": "Bash",
        "ping_host": "Ping",
        "nmap_scan": "Nmap",
        "dns_lookup": "DNS",
    }
    return names.get(tool_name, tool_name.replace("_", " ").title())


def _render_progress_bar(percent: float, width: int = 12) -> str:
    """Render a compact determinate progress bar as Rich markup (ANIM-01).

    Shown on the tool spinner when a ``ToolProgressEvent`` carries a percentage
    (nmap ports, gobuster/ffuf requests, VPN handshake).  Tools that report no
    percentage keep the indeterminate spinner unchanged — the caller only calls
    this when ``percent is not None``.  Filled cells use the accent colour while
    running and the success colour at completion; the remainder stays dim.
    """
    pct = max(0.0, min(100.0, float(percent)))
    width = max(1, int(width))
    filled = max(0, min(width, int(round((pct / 100.0) * width))))
    fill_color = COLORS["success"] if pct >= 100.0 else COLORS["accent"]
    return (
        f"[{fill_color}]{'━' * filled}[/]"
        f"[{COLORS['text_dim']}]{'━' * (width - filled)}[/] "
        f"{pct:.0f}%"
    )


class ToolExecutionSpinner:
    """Spinner shown during tool execution with live elapsed timer."""

    def __init__(self, tool_name: str, arguments: dict[str, Any] | None = None, console: Console | None = None, status_right: str = ""):
        self.tool_name = tool_name
        self.arguments = arguments or {}
        self.display_name = _tool_display_name(tool_name)
        self._console = console
        self._status_right = status_right
        self._status: Status | None = None
        self._running = False
        self._start_time: float = 0.0
        self._timer_task: asyncio.Task | None = None
        self._phase: str = ""
        self._detail: str = ""
        self._percent: float | None = None

    def start(self):
        if self._running:
            return
        self._running = True
        self._start_time = time.monotonic()
        self._status = Status(
            self._format_message(0.0),
            spinner=_spinner_name(),
            spinner_style=COLORS["accent"],
            refresh_per_second=_spinner_refresh(),
            console=self._console,
        )
        self._status.start()

        # Launch the timer updater task
        try:
            loop = asyncio.get_running_loop()
            self._timer_task = loop.create_task(self._update_timer())
        except RuntimeError:
            # No running event loop — skip timer
            pass

    def _format_message(self, elapsed: float) -> str:
        """Format spinner message with elapsed time."""
        label = _running_label_for_elapsed(elapsed)
        if elapsed >= 1.0:
            time_str = f" ({int(elapsed)}s)"
        else:
            time_str = ""

        if self._phase:
            phase_str = f" · {self._phase}"
            if self._detail:
                phase_str += f" · {self._detail}"
            if self._percent is not None:
                phase_str += f" · {_render_progress_bar(self._percent)}"
        else:
            phase_str = ""

        # Lead with the tool name so the spinner is a self-sufficient running
        # indicator (the static ● row is suppressed in a TTY to avoid a
        # redundant double indicator).
        status_base = f"{self.display_name} · {label}{time_str}{phase_str}"
        status = format_wait_message(status_base, elapsed, include_tip=True)

        if not self._status_right:
            return status

        width = self._console.size.width if self._console else shutil.get_terminal_size((80, 24)).columns
        if sys.stdout.isatty():
            width = min(width, shutil.get_terminal_size((width or 80, 24)).columns)
        width = max(1, width)
        separator = "─" * max(1, width - 1)
        left = "esc to cancel"
        right = _fit_cell(self._status_right, max(10, width - len(left) - 2))
        spacing = " " * max(1, width - len(left) - len(right) - 1)
        footer = f"{left}{spacing}{right}"
        return (
            f"{status}\n"
            f"[{COLORS['text_dim']}]{separator}[/]\n"
            f"[{COLORS['accent']}]>[/]\n"
            f"[{COLORS['text_dim']}]{separator}[/]\n"
            f"[{COLORS['text_muted']}]{footer}[/]"
        )

    async def _update_timer(self):
        """Periodically update the spinner with elapsed time."""
        try:
            while self._running and self._status:
                elapsed = time.monotonic() - self._start_time
                self._status.update(self._format_message(elapsed))
                await asyncio.sleep(1.0)
        except asyncio.CancelledError:
            pass
        except Exception:
            pass

    def stop(self):
        if self._timer_task and not self._timer_task.done():
            self._timer_task.cancel()
            self._timer_task = None
        if self._status and self._running:
            try:
                self._status.stop()
            except Exception:
                pass
        self._running = False

    def update_phase(self, phase: str, detail: str = "", percent: float | None = None):
        """Update the visible tool phase without printing new terminal lines."""
        self._phase = phase.strip()
        self._detail = detail.strip()
        self._percent = percent
        if self._status and self._running:
            elapsed = time.monotonic() - self._start_time
            self._status.update(self._format_message(elapsed))

    @property
    def elapsed(self) -> float:
        """Return elapsed time since spinner started."""
        if self._start_time:
            return time.monotonic() - self._start_time
        return 0.0


class StartupAnimation:
    """Startup screen preparation without login animation."""

    def __init__(self, console: Console | None = None, tool_count: int = 28):
        self.console = console or Console()
        self.tool_count = tool_count

    async def play(self, skip: bool = False):
        import sys

        if STARTUP_CLEAR_SEQUENCE:
            sys.stdout.write(STARTUP_CLEAR_SEQUENCE)
            sys.stdout.flush()


class StreamingDots:
    _FRAMES = ["   ", "  ·", " ··", "···", "·· ", "·  "]

    def __init__(self):
        self._index = 0

    def next_frame(self) -> str:
        frame = self._FRAMES[self._index % len(self._FRAMES)]
        self._index += 1
        return frame

    def reset(self):
        self._index = 0
