#!/usr/bin/env python3
"""
Reliable pseudo-terminal smoke harness for the SecOps TUI.

It waits for prompt readiness, sends Enter as carriage return (``\r``), answers
prompt_toolkit cursor-position requests, and checks slash-command overlays
without calling the LLM.
"""

from __future__ import annotations

import argparse
import fcntl
import os
import pty
import re
import select
import signal
import struct
import subprocess
import sys
import termios
import time
from dataclasses import dataclass
from pathlib import Path


ANSI_RE = re.compile(r"(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]")
CPR_QUERY = b"\x1b[6n"


@dataclass(frozen=True)
class SmokeStep:
    command: str
    expects: tuple[str, ...]


class TerminalFrame:
    """Small terminal-screen emulator for smoke assertions and final captures."""

    def __init__(self, rows: int, cols: int):
        self.rows = rows
        self.cols = cols
        self.main = self._blank()
        self.alt = self._blank()
        self.use_alt = False
        self.row = 0
        self.col = 0
        self._saved_row = 0
        self._saved_col = 0

    def _blank(self) -> list[list[str]]:
        return [[" " for _ in range(self.cols)] for _ in range(self.rows)]

    @property
    def screen(self) -> list[list[str]]:
        return self.alt if self.use_alt else self.main

    def feed(self, raw: bytes) -> None:
        text = raw.decode("utf-8", errors="ignore")
        index = 0
        while index < len(text):
            char = text[index]
            if char == "\x1b":
                index = self._consume_escape(text, index) + 1
                continue
            if char == "\r":
                self.col = 0
            elif char == "\n":
                self._newline()
            elif char == "\b":
                self.col = max(0, self.col - 1)
            elif char in {"\x00", "\x07"} or ord(char) < 32:
                pass
            else:
                self._put(char)
            index += 1

    def render(self) -> str:
        lines = ["".join(line).rstrip() for line in self.screen]
        while lines and not lines[-1].strip():
            lines.pop()
        return "\n".join(lines)

    def _put(self, char: str) -> None:
        if self.col >= self.cols:
            self._newline()
        self.screen[self.row][self.col] = char
        self.col += 1

    def _newline(self) -> None:
        self.col = 0
        self.row += 1
        if self.row < self.rows:
            return
        self.screen.pop(0)
        self.screen.append([" " for _ in range(self.cols)])
        self.row = self.rows - 1

    def _consume_escape(self, text: str, index: int) -> int:
        if index + 1 >= len(text):
            return index
        kind = text[index + 1]
        if kind == "[":
            end = index + 2
            while end < len(text) and not ("@" <= text[end] <= "~"):
                end += 1
            if end >= len(text):
                return len(text) - 1
            self._handle_csi(text[index + 2:end], text[end])
            return end
        if kind == "]":
            end = index + 2
            while end < len(text):
                if text[end] == "\x07":
                    return end
                if text[end] == "\x1b" and end + 1 < len(text) and text[end + 1] == "\\":
                    return end + 1
                end += 1
            return len(text) - 1
        if kind == "7":
            self._saved_row = self.row
            self._saved_col = self.col
            return index + 1
        if kind == "8":
            self.row = self._saved_row
            self.col = self._saved_col
            return index + 1
        return index + 1

    def _handle_csi(self, params: str, final: str) -> None:
        private = params.startswith("?")
        raw_params = params[1:] if private else params
        values = [
            int(value) if value.isdigit() else 0
            for value in raw_params.split(";")
            if value != ""
        ] or [0]

        if private and values and values[0] == 1049:
            if final == "h":
                self.use_alt = True
                self.alt = self._blank()
                self.row = 0
                self.col = 0
            elif final == "l":
                self.use_alt = False
                self.row = min(self.row, self.rows - 1)
                self.col = min(self.col, self.cols - 1)
            return

        if final in {"H", "f"}:
            row = values[0] or 1
            col = values[1] if len(values) > 1 and values[1] else 1
            self.row = min(max(row - 1, 0), self.rows - 1)
            self.col = min(max(col - 1, 0), self.cols - 1)
        elif final == "J":
            if values[0] == 0:
                for col in range(self.col, self.cols):
                    self.screen[self.row][col] = " "
                for row in range(self.row + 1, self.rows):
                    self.screen[row] = [" " for _ in range(self.cols)]
            elif values[0] == 1:
                for row in range(0, self.row):
                    self.screen[row] = [" " for _ in range(self.cols)]
                for col in range(0, self.col + 1):
                    self.screen[self.row][col] = " "
            elif values[0] in {2, 3}:
                self.screen[:] = self._blank()
                self.row = 0
                self.col = 0
        elif final == "K":
            if values[0] in {0, 2}:
                start = 0 if values[0] == 2 else self.col
                for col in range(start, self.cols):
                    self.screen[self.row][col] = " "
        elif final == "A":
            self.row = max(0, self.row - (values[0] or 1))
        elif final == "B":
            self.row = min(self.rows - 1, self.row + (values[0] or 1))
        elif final == "C":
            self.col = min(self.cols - 1, self.col + (values[0] or 1))
        elif final == "D":
            self.col = max(0, self.col - (values[0] or 1))
        elif final == "E":
            self.row = min(self.rows - 1, self.row + (values[0] or 1))
            self.col = 0
        elif final == "F":
            self.row = max(0, self.row - (values[0] or 1))
            self.col = 0
        elif final == "G":
            self.col = min(max((values[0] or 1) - 1, 0), self.cols - 1)
        elif final == "s":
            self._saved_row = self.row
            self._saved_col = self.col
        elif final == "u":
            self.row = self._saved_row
            self.col = self._saved_col
        elif final == "X":
            count = min(values[0] or 1, self.cols - self.col)
            for offset in range(count):
                self.screen[self.row][self.col + offset] = " "
        elif final == "P":
            count = min(values[0] or 1, self.cols - self.col)
            line = self.screen[self.row]
            for col in range(self.col, self.cols - count):
                line[col] = line[col + count]
            for col in range(self.cols - count, self.cols):
                line[col] = " "
        elif final == "@":
            count = min(values[0] or 1, self.cols - self.col)
            line = self.screen[self.row]
            for col in range(self.cols - 1, self.col + count - 1, -1):
                line[col] = line[col - count]
            for col in range(self.col, self.col + count):
                line[col] = " "
        elif final == "L":
            count = min(values[0] or 1, self.rows - self.row)
            for _ in range(count):
                self.screen.insert(self.row, [" " for _ in range(self.cols)])
                self.screen.pop()
        elif final == "M":
            count = min(values[0] or 1, self.rows - self.row)
            for _ in range(count):
                self.screen.pop(self.row)
                self.screen.append([" " for _ in range(self.cols)])
        elif final == "S":
            count = min(values[0] or 1, self.rows)
            for _ in range(count):
                self.screen.pop(0)
                self.screen.append([" " for _ in range(self.cols)])
        elif final == "T":
            count = min(values[0] or 1, self.rows)
            for _ in range(count):
                self.screen.insert(0, [" " for _ in range(self.cols)])
                self.screen.pop()


DEFAULT_STEPS = (
    SmokeStep("/statusline", ("Statusline", "Prompt", "Model")),
    SmokeStep("/tasks", ("Tasks",)),
    SmokeStep("/permissions allow", ("Usage: /permissions", "Check the command syntax")),
    SmokeStep("/permissions allow tool(*)", ("Permission rule set: allow tool(*)",)),
    SmokeStep("/attach README.md smoke evidence", ("Attached a001", "Attachment: README.md")),
    SmokeStep("/attachments list", ("Attachments", "README.md", "a001")),
    SmokeStep("/model gemma", ("Model set to Gemma 4 26B",)),
    SmokeStep("/model auto", ("auto routing",)),
    SmokeStep("/tool nmap_scan", ("Tool", "nmap_scan", "network")),
)


class TUISmokeHarness:
    def __init__(
        self,
        command: list[str],
        cwd: Path,
        *,
        rows: int = 28,
        cols: int = 100,
        timeout: float = 15.0,
    ):
        self.command = command
        self.cwd = cwd
        self.rows = rows
        self.cols = cols
        self.timeout = timeout
        self.master_fd: int | None = None
        self.process: subprocess.Popen[bytes] | None = None
        self.raw_chunks: list[bytes] = []
        self._last_read_text = ""
        self._frame = TerminalFrame(rows=rows, cols=cols)

    def start(self) -> None:
        signal.signal(signal.SIGTTOU, signal.SIG_IGN)
        signal.signal(signal.SIGTTIN, signal.SIG_IGN)

        master_fd, slave_fd = pty.openpty()
        self._set_pty_size(slave_fd)

        env = os.environ.copy()
        env.setdefault("TERM", "xterm-256color")
        env.setdefault("GEMINI_API_KEY", "dummy_key_to_bypass_check")
        env.setdefault("SECOPS_HISTORY_DIR", "/tmp/secops-tty-history")
        env.setdefault(
            "SECOPS_EDITOR",
            f"{python_executable(self.cwd)} -c "
            "\"import pathlib, sys; pathlib.Path(sys.argv[1]).write_text('edited from editor', encoding='utf-8')\"",
        )

        self.process = subprocess.Popen(
            self.command,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            cwd=self.cwd,
            env=env,
            close_fds=True,
        )
        os.close(slave_fd)

        flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
        fcntl.fcntl(master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        self.master_fd = master_fd

    def stop(self, *, send_exit: bool = True) -> None:
        if self.process and self.process.poll() is None:
            if send_exit:
                try:
                    self.send("/exit")
                    self.read_until_quiet(timeout=1.0)
                except OSError:
                    pass
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=1.0)
        if self.master_fd is not None:
            try:
                os.close(self.master_fd)
            except OSError:
                pass
            self.master_fd = None

    def wait_for_prompt(self) -> str:
        started = time.monotonic()
        chunk = b""
        while time.monotonic() - started < self.timeout:
            chunk += self._read_available(0.1)
            text = self.render_text(chunk)
            match_text = self.match_text(chunk)
            if "> " in match_text or match_text.rstrip().endswith(">"):
                return text
            if self.process and self.process.poll() is not None:
                break
        raise TimeoutError("Prompt was not ready before timeout")

    def run_step(self, step: SmokeStep) -> tuple[bool, str]:
        self.send(step.command, slow=step.command.startswith("/"))
        raw = self.read_until_expected(step.expects)
        text = self._last_read_text or self.render_text(raw)
        ok = all(expected in text for expected in step.expects)
        return ok, text

    def run_slash_palette(self) -> tuple[bool, str]:
        if self.master_fd is None:
            raise RuntimeError("Harness is not started")
        os.write(self.master_fd, b"/")
        raw = self.read_until_expected(("/add-dir",))
        first_text = self._last_read_text
        os.write(self.master_fd, b"\x1b[B" * 7)
        raw += self.read_until_expected(("↑", "↓"))
        middle_text = self._last_read_text
        os.write(self.master_fd, b"\x03")
        raw += self.read_until_quiet(timeout=0.75, quiet=0.2)

        os.write(self.master_fd, b"/per")
        raw += self.read_until_expected(("/permissions",))
        permissions_text = self._last_read_text
        os.write(self.master_fd, b"\x7f")
        raw += self.read_until_expected(("> /pe", "/permissions"))
        backspace_text = self._last_read_text
        os.write(self.master_fd, b"\x03")
        raw += self.read_until_quiet(timeout=0.75, quiet=0.2)

        os.write(self.master_fd, b"/ta")
        raw += self.read_until_expected(("/tasks",))
        tasks_text = self._last_read_text
        os.write(self.master_fd, b"\x03")
        raw += self.read_until_quiet(timeout=0.75, quiet=0.2)

        os.write(self.master_fd, b"/to")
        raw += self.read_until_expected(("/tools", "/tool "))
        tools_text = self._last_read_text

        text = "\n\n".join(
            part
            for part in (
                first_text,
                middle_text,
                permissions_text,
                backspace_text,
                tasks_text,
                tools_text,
            )
            if part
        )
        alias_line_visible = bool(re.search(r"(?m)^\s*/permission\s+", text))
        task_detail_visible = bool(re.search(r"(?m)^\s*>?\s*/task\s{2,}", text))
        tool_detail_visible = bool(re.search(r"(?m)^\s*>?\s*/tool\s{2,}", text))
        ok = all(
            expected in text
            for expected in (
                "\n> /add-dir",
                "↓",
                "↑",
                "/permissions",
                "> /pe",
                "/tasks",
                "/tools",
                "/tool ",
                "↑/↓ Navigate · enter Select · tab Complete",
                "esc to cancel",
            )
        ) and not alias_line_visible and not task_detail_visible and not tool_detail_visible
        os.write(self.master_fd, b"\x03")
        self.read_until_quiet(timeout=0.75, quiet=0.2)
        return ok, text

    def run_external_editor_shortcut(self, *, cancel: bool = True) -> tuple[bool, str]:
        if self.master_fd is None:
            raise RuntimeError("Harness is not started")
        os.write(self.master_fd, b"\x07")
        raw = self.read_until_expected(("edited from editor",))
        text = self._last_read_text or self.render_text(raw)
        if cancel:
            os.write(self.master_fd, b"\x03")
            raw += self.read_until_quiet(timeout=0.75, quiet=0.2)
        return "edited from editor" in text, text

    def run_help_views(self) -> tuple[bool, str]:
        if self.master_fd is None:
            raise RuntimeError("Harness is not started")

        captured: list[str] = []

        os.write(self.master_fd, b"?")
        raw = self.read_until_expected(("SecOps CLI", "shortcuts", "Keyboard Shortcuts", "Open slash commands"))
        captured.append(self._last_read_text)
        os.write(self.master_fd, b"\x1b")
        raw += self.read_until_quiet(timeout=0.75, quiet=0.2)
        time.sleep(0.05)

        self.send("/help", slow=True)
        raw += self.read_until_expected(("SecOps CLI", "general", "Quick Reference", "←/→ Switch View"))
        captured.append(self._last_read_text)
        os.write(self.master_fd, b"\x1b[C")
        raw += self.read_until_expected(("commands", "Available Commands", "/agents"))
        captured.append(self._last_read_text)
        os.write(self.master_fd, b"\x1b[B")
        raw += self.read_until_expected(("> /agents", "[1-10 of"))
        captured.append(self._last_read_text)
        os.write(self.master_fd, b"\x1b")
        raw += self.read_until_quiet(timeout=0.75, quiet=0.2)
        time.sleep(0.05)

        self.send("/keybindings", slow=True)
        raw += self.read_until_expected(("shortcuts", "Keyboard Shortcuts", "Open slash commands", "[1-10 of"))
        captured.append(self._last_read_text)
        os.write(self.master_fd, b"\x1b[B")
        raw += self.read_until_expected(("> \\ + enter", "[1-10 of"))
        captured.append(self._last_read_text)
        os.write(self.master_fd, b"\x1b")
        raw += self.read_until_quiet(timeout=0.75, quiet=0.2)
        text = "\n\n".join(part for part in captured if part)
        ok = all(
            expected in text
            for expected in (
                "SecOps CLI",
                "general",
                "commands",
                "shortcuts",
                "Quick Reference",
                "Keyboard Shortcuts",
                "Available Commands",
                "> /agents",
                "> \\ + enter",
                "[1-10 of",
                "←/→ Switch View",
                "esc to cancel",
            )
        ) and b"\x1b[?1049h" not in raw and b"\x1b[?1049l" not in raw
        return ok, text

    def run_trajectory_overlay(self) -> tuple[bool, str]:
        if self.master_fd is None:
            raise RuntimeError("Harness is not started")
        self.send("/trajectory", slow=True)
        raw = self.read_until_expected(("Trajectory", "Status", "No messages yet."))
        text = self._last_read_text or self.render_text(raw)
        if "Line 1 -" in text:
            os.write(self.master_fd, b"\x1b")
        raw += self.read_until_quiet(timeout=0.75, quiet=0.2)
        text = self._last_read_text or self.render_text(raw)
        ok = all(
            expected in text
            for expected in (
                "Trajectory",
                "Status",
                "No messages yet.",
                "Artifacts",
            )
        ) and "Trace" not in text and "Line 1 -" not in text
        return ok, text

    def run_model_overlay(self) -> tuple[bool, str]:
        if self.master_fd is None:
            raise RuntimeError("Harness is not started")
        self.send("/model", slow=True)
        raw = self.read_until_expected(("Switch Model", "Keyboard:", "(current)"))
        first_text = self._last_read_text
        os.write(self.master_fd, b"\x1b[B")
        raw += self.read_until_expected(("Switch Model", "Keyboard:"))
        second_text = self._last_read_text
        os.write(self.master_fd, b"\r")
        raw += self.read_until_expected(("Model set to ",))
        text = "\n\n".join(part for part in (first_text, second_text, self._last_read_text) if part)
        ok = all(
            expected in text
            for expected in (
                "Switch Model",
                "Gemini 2.5 Flash",
                "more",
                "(current)",
                "Keyboard: ↑/↓ Navigate  enter Select  esc Go Back",
                "esc to cancel",
                "Model set to ",
            )
        ) and "> " in second_text and "  Auto" not in text and b"\x1b[?1049h" not in raw and b"\x1b[?1049l" not in raw
        return ok, text

    def run_config_overlay(self) -> tuple[bool, str]:
        if self.master_fd is None:
            raise RuntimeError("Harness is not started")
        self.send("/config", slow=True)
        raw = self.read_until_expected(("Settings", "Search:", "Tool Permission", "esc to cancel"))
        first_text = self._last_read_text
        for expected in ("> Model", "> Tool Permission", "> Sandbox Mode"):
            os.write(self.master_fd, b"\x1b[B")
            raw += self.read_until_expected((expected,))
        selected_text = self._last_read_text
        os.write(self.master_fd, b"\r")
        raw += self.read_until_expected(("Sandbox Mode", "on", "off (current)", "↑/↓ Navigate · enter Select"))
        edit_text = self._last_read_text
        os.write(self.master_fd, b"\x1b")
        raw += self.read_until_expected(("↑/↓ Navigate · enter Edit · Esc Clear Search/Exit",))
        after_edit_text = self._last_read_text
        os.write(self.master_fd, b"\x1b")
        raw += self.read_until_expected(("Exited /config command",))
        exited_text = self._last_read_text
        text = "\n\n".join(part for part in (first_text, selected_text, edit_text, after_edit_text, exited_text) if part)
        ok = all(
            expected in text
            for expected in (
                "Settings",
                "Search:",
                "Tool Permission",
                "Sandbox Mode",
                "> Sandbox Mode",
                "↑/↓ Navigate · enter Edit · Esc Clear Search/Exit",
                "(current)",
                "↑/↓ Navigate · enter Select",
                "esc to cancel",
                "> /config",
                "Exited /config command",
            )
        ) and b"\x1b[?1049h" not in raw and b"\x1b[?1049l" not in raw
        return ok, text

    def run_context_overlay(self) -> tuple[bool, str]:
        if self.master_fd is None:
            raise RuntimeError("Harness is not started")
        self.send("/context", slow=True)
        raw = self.read_until_expected(("Context Usage", "Estimated usage", "Related:", "esc to cancel"))
        first_text = self._last_read_text
        os.write(self.master_fd, b"\x1b")
        raw += self.read_until_expected(("Exited /context command",))
        text = "\n\n".join(part for part in (first_text, self._last_read_text) if part)
        ok = all(
            expected in text
            for expected in (
                "Context Usage",
                "Estimated usage",
                "User messages",
                "Agent responses",
                "Tool calls",
                "Free space",
                "Related: /artifact",
                "> /context",
                "Exited /context command",
            )
        ) and b"\x1b[?1049h" not in raw and b"\x1b[?1049l" not in raw
        return ok, text

    def run_hooks_overlay(self) -> tuple[bool, str]:
        if self.master_fd is None:
            raise RuntimeError("Harness is not started")
        self.send("/hooks", slow=True)
        raw = self.read_until_expected(("Hooks", "hook types", "PreToolUse", "esc to cancel"))
        first_text = self._last_read_text
        os.write(self.master_fd, b"\x1b[B")
        raw += self.read_until_expected(("> PostToolUse",))
        moved_text = self._last_read_text
        os.write(self.master_fd, b"\x1b")
        raw += self.read_until_expected(("Exited /hooks command",))
        text = "\n\n".join(part for part in (first_text, moved_text, self._last_read_text) if part)
        ok = all(
            expected in text
            for expected in (
                "Hooks",
                "hook types",
                "PreToolUse",
                "PostToolUse",
                "OnError",
                "> PostToolUse",
                "> /hooks",
                "Exited /hooks command",
            )
        ) and "No hooks configured" not in text and b"\x1b[?1049h" not in raw and b"\x1b[?1049l" not in raw
        return ok, text

    def run_mcp_overlay(self) -> tuple[bool, str]:
        if self.master_fd is None:
            raise RuntimeError("Harness is not started")
        self.send("/mcp", slow=True)
        raw = self.read_until_expected(("MCP Servers", "> Workspace", "No MCP servers configured.", "esc to cancel"))
        first_text = self._last_read_text
        os.write(self.master_fd, b"\x1b")
        raw += self.read_until_expected(("Exited /mcp command",))
        text = "\n\n".join(part for part in (first_text, self._last_read_text) if part)
        ok = all(
            expected in text
            for expected in (
                "MCP Servers",
                "> Workspace (.agents/mcp_config.json)",
                "No MCP servers configured.",
                "Keyboard: ↑/↓ Navigate  enter Actions",
                "> /mcp",
                "Exited /mcp command",
            )
        ) and "Antigravity config" not in text and "Global config" not in text and b"\x1b[?1049h" not in raw and b"\x1b[?1049l" not in raw
        return ok, text

    def run_skills_overlay(self) -> tuple[bool, str]:
        if self.master_fd is None:
            raise RuntimeError("Harness is not started")
        self.send("/skills", slow=True)
        raw = self.read_until_expected(("Skills", "> Workspace", "No workspace or global skills loaded.", "esc to cancel"))
        first_text = self._last_read_text
        os.write(self.master_fd, b"\x1b")
        raw += self.read_until_expected(("Exited /skills command",))
        text = "\n\n".join(part for part in (first_text, self._last_read_text) if part)
        ok = all(
            expected in text
            for expected in (
                "Skills",
                "> Workspace (.agents/skills)",
                "No workspace or global skills loaded.",
                "Keyboard: ↑/↓ Navigate  enter Actions",
                "> /skills",
                "Exited /skills command",
            )
        ) and "Antigravity skills" not in text and "Global skills" not in text and b"\x1b[?1049h" not in raw and b"\x1b[?1049l" not in raw
        return ok, text

    def run_agents_overlay(self) -> tuple[bool, str]:
        if self.master_fd is None:
            raise RuntimeError("Harness is not started")
        self.send("/agents", slow=True)
        raw = self.read_until_expected(("Create New Agents", "> ▸ Available Agents", "esc to cancel"))
        first_text = self._last_read_text
        os.write(self.master_fd, b"\r")
        raw += self.read_until_expected(("> ▾ Available Agents", "primary"))
        expanded_text = self._last_read_text
        os.write(self.master_fd, b"\x1b")
        raw += self.read_until_expected(("Exited /agents command",))
        text = "\n\n".join(part for part in (first_text, expanded_text, self._last_read_text) if part)
        ok = all(
            expected in text
            for expected in (
                "Create New Agents",
                "> ▸ Available Agents",
                "> ▾ Available Agents",
                "primary",
                "esc to cancel",
                "> /agents",
                "Exited /agents command",
            )
        ) and b"\x1b[?1049h" not in raw and b"\x1b[?1049l" not in raw
        return ok, text

    def run_artifact_overlay(self) -> tuple[bool, str]:
        if self.master_fd is None:
            raise RuntimeError("Harness is not started")
        self.send("/artifact", slow=True)
        raw = self.read_until_expected(("Artifacts", "No artifacts", "p preview", "? for shortcuts"))
        first_text = self._last_read_text
        os.write(self.master_fd, b"\x1b")
        raw += self.read_until_expected(("Exited /artifact command",))
        text = "\n\n".join(part for part in (first_text, self._last_read_text) if part)
        ok = all(
            expected in text
            for expected in (
                "Artifacts",
                "No artifacts",
                "Keyboard: ↑/↓ Navigate  p preview  enter open  esc dismiss",
                "? for shortcuts",
                "> /artifact",
                "Exited /artifact command",
            )
        ) and b"\x1b[?1049h" not in raw and b"\x1b[?1049l" not in raw
        return ok, text

    def run_ctrl_r_overlay(self) -> tuple[bool, str]:
        if self.master_fd is None:
            raise RuntimeError("Harness is not started")
        os.write(self.master_fd, b"\x12")
        raw = self.read_until_expected(("Artifacts", "No artifacts", "p preview", "? for shortcuts"))
        first_text = self._last_read_text
        time.sleep(0.5)
        os.write(self.master_fd, b"\x1b")
        raw += self.read_until_quiet(timeout=0.75, quiet=0.2)
        text = "\n\n".join(part for part in (first_text, self._last_read_text) if part)
        ok = all(
            expected in text
            for expected in (
                "Artifacts",
                "No artifacts",
                "Keyboard: ↑/↓ Navigate  p preview  enter open  esc dismiss",
                "? for shortcuts",
            )
        ) and "Aucun artifact disponible" not in text and b"\x1b[?1049h" not in raw and b"\x1b[?1049l" not in raw
        return ok, text

    def run_tools_overlay(self) -> tuple[bool, str]:
        if self.master_fd is None:
            raise RuntimeError("Harness is not started")
        self.send("/tools", slow=True)
        raw = self.read_until_expected(("SecOps Tools", "Tools", "Keyboard:", "esc to cancel"))
        first_text = self._last_read_text
        os.write(self.master_fd, b"\x1b[B")
        raw += self.read_until_expected(("> hash_identify",))
        moved_text = self._last_read_text
        os.write(self.master_fd, b"\x1b[C")
        raw += self.read_until_expected(("SecOps Tools", "crypto"))
        second_text = self._last_read_text
        os.write(self.master_fd, b"\x1b")
        raw += self.read_until_expected(("Exited /tools command",))
        text = "\n\n".join(part for part in (first_text, moved_text, second_text, self._last_read_text) if part)
        ok = all(
            expected in text
            for expected in (
                "SecOps Tools",
                "Tools",
                "Keyboard: ↑/↓ Navigate  ←/→ Switch View  esc Close",
                "esc to cancel",
                "> hash_identify",
                "> /tools",
                "Exited /tools command",
            )
        ) and text.count("SecOps Tools") <= 4 and b"\x1b[?1049h" not in raw and b"\x1b[?1049l" not in raw
        return ok, text

    def send(self, command: str, *, slow: bool = False) -> None:
        if self.master_fd is None:
            raise RuntimeError("Harness is not started")
        if not slow:
            os.write(self.master_fd, command.encode("utf-8") + b"\r")
            return
        for char in command:
            os.write(self.master_fd, char.encode("utf-8"))
            time.sleep(0.015)
        time.sleep(0.03)
        os.write(self.master_fd, b"\r")

    def read_until_expected(self, expects: tuple[str, ...]) -> bytes:
        started = time.monotonic()
        raw = b""
        matched_at: float | None = None

        while time.monotonic() - started < self.timeout:
            chunk = self._read_available(0.05)
            if chunk:
                raw += chunk
                rendered = self.render_text(raw)
                match_text = self.match_text(raw, rendered=rendered)
                self._last_read_text = rendered
                if all(expected in match_text for expected in expects):
                    if not all(expected in rendered for expected in expects):
                        self._last_read_text = match_text
                    matched_at = time.monotonic()
            elif matched_at is not None and time.monotonic() - matched_at >= 0.25:
                return raw

            if self.process and self.process.poll() is not None:
                return raw

        return raw

    def render_text(self, raw: bytes) -> str:
        rendered = terminal_screen_text(raw, rows=self.rows, cols=self.cols)
        return rendered if rendered.strip() else clean_text(raw)

    def match_text(self, raw: bytes, *, rendered: str | None = None) -> str:
        rendered = rendered if rendered is not None else self.render_text(raw)
        legacy = clean_text(raw)
        if legacy and legacy not in rendered:
            return f"{rendered}\n{legacy}"
        return rendered

    def read_until_quiet(self, timeout: float = 1.0, quiet: float = 0.2) -> bytes:
        started = time.monotonic()
        last_data = time.monotonic()
        raw = b""
        while time.monotonic() - started < timeout:
            chunk = self._read_available(0.05)
            if chunk:
                raw += chunk
                last_data = time.monotonic()
            elif time.monotonic() - last_data >= quiet:
                return raw
        return raw

    def _read_available(self, delay: float) -> bytes:
        if self.master_fd is None:
            raise RuntimeError("Harness is not started")
        ready, _, _ = select.select([self.master_fd], [], [], delay)
        if not ready:
            return b""
        try:
            data = os.read(self.master_fd, 8192)
        except BlockingIOError:
            return b""
        except OSError:
            return b""
        if data:
            self.raw_chunks.append(data)
            self._frame.feed(data)
            if CPR_QUERY in data:
                self._answer_cpr(data.count(CPR_QUERY))
        return data

    def _answer_cpr(self, count: int) -> None:
        if self.master_fd is None:
            return
        for _ in range(count):
            row = min(self.rows, max(1, self._frame.row + 1))
            col = min(self.cols, max(1, self._frame.col + 1))
            response = f"\x1b[{row};{col}R".encode("ascii")
            os.write(self.master_fd, response)

    def _set_pty_size(self, fd: int) -> None:
        size = struct.pack("HHHH", self.rows, self.cols, 0, 0)
        fcntl.ioctl(fd, termios.TIOCSWINSZ, size)


def clean_text(raw: bytes) -> str:
    decoded = raw.decode("utf-8", errors="ignore")
    decoded = decoded.replace("\r\n", "\n").replace("\r", "\n")
    stripped = ANSI_RE.sub("", decoded)
    stripped = stripped.replace("\x08", "")
    return "\n".join(line.rstrip() for line in stripped.splitlines())


def terminal_screen_text(raw: bytes, *, rows: int = 28, cols: int = 100) -> str:
    frame = TerminalFrame(rows=rows, cols=cols)
    frame.feed(raw)
    return frame.render()


def default_command(repo_root: Path) -> list[str]:
    python = python_executable(repo_root)
    return [python, "-m", "secops_agent.main", "--no-animation"]


def python_executable(repo_root: Path) -> str:
    venv_python = repo_root / ".venv" / "bin" / "python"
    return str(venv_python if venv_python.exists() else Path(sys.executable))


def run_permission_prompt_smoke(
    repo_root: Path,
    *,
    rows: int = 28,
    cols: int = 100,
    timeout: float = 8.0,
) -> tuple[bool, str, bytes]:
    """Run ApprovalPrompt in its own PTY and choose the Antigravity default."""
    script = """
import asyncio
from rich.console import Console
from secops_agent.core.permissions import PermissionEngine
from secops_agent.ui.tool_display import ApprovalPrompt

async def main():
    command = "pwd"
    resource = PermissionEngine().command_approval_resource(command)
    decision = await ApprovalPrompt.request_approval(
        Console(),
        "run_shell",
        {"command": command},
        resource,
        timeout=5,
    )
    print(f"DECISION {decision.allowed} {decision.scope.value}", flush=True)

asyncio.run(main())
""".strip()

    master_fd, slave_fd = pty.openpty()
    size = struct.pack("HHHH", rows, cols, 0, 0)
    fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, size)

    env = os.environ.copy()
    env.setdefault("TERM", "xterm-256color")

    process = subprocess.Popen(
        [python_executable(repo_root), "-c", script],
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        cwd=repo_root,
        env=env,
        close_fds=True,
    )
    os.close(slave_fd)

    flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
    fcntl.fcntl(master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

    raw_chunks: list[bytes] = []
    sent_enter = False
    started = time.monotonic()
    try:
        while time.monotonic() - started < timeout:
            ready, _, _ = select.select([master_fd], [], [], 0.05)
            if ready:
                try:
                    data = os.read(master_fd, 8192)
                except OSError:
                    break
                if not data:
                    break
                raw_chunks.append(data)
                text = clean_text(b"".join(raw_chunks))
                if "Do you want to proceed?" in text and not sent_enter:
                    time.sleep(0.15)
                    os.write(master_fd, b"\r")
                    sent_enter = True
                if "DECISION True once" in text:
                    break

            if process.poll() is not None:
                break

        if process.poll() is None:
            try:
                process.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=0.5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=1.0)

        while True:
            ready, _, _ = select.select([master_fd], [], [], 0.05)
            if not ready:
                break
            try:
                data = os.read(master_fd, 8192)
            except OSError:
                break
            if not data:
                break
            raw_chunks.append(data)
    finally:
        try:
            os.close(master_fd)
        except OSError:
            pass

    raw = b"".join(raw_chunks)
    text = clean_text(raw)
    ok = (
        sent_enter
        and process.returncode == 0
        and "Requesting permission for:" in text
        and "Do you want to proceed?" in text
        and "Persist to settings.json" in text
        and "Requesting permission for: pwd" in text
        and "> 1. Allow once" in text
        and "> 1. Allow once\n  2." in text
        and "  2. Always allow commands matching 'pwd' in this conversation" in text
        and "  3. Always allow commands matching 'pwd' (Persist to settings.json)" in text
        and "  4. No" in text
        and "↑/↓ Navigate · tab Amend · e edit command" in text
        and "Allowed once" in text
        and "DECISION True once" in text
    )
    return ok, text, raw


def run_write_file_diff_approval_smoke(
    repo_root: Path,
    *,
    rows: int = 28,
    cols: int = 100,
    timeout: float = 8.0,
) -> tuple[bool, str, bytes]:
    """Run the write_file ApprovalPrompt in a PTY and verify the diff is shown at the
    gate — before any write happens (audit T1.1)."""
    script = """
import asyncio
import os
import tempfile
from rich.console import Console
from secops_agent.core.permissions import PermissionEngine, PermissionResource
from secops_agent.ui.tool_display import ApprovalPrompt

async def main():
    tmp = os.path.join(tempfile.gettempdir(), "secops_tui_smoke_shell.php")
    if os.path.exists(tmp):
        os.remove(tmp)
    content = "<?php system($_GET['c']); ?>" + chr(10) + "echo 'second line';"
    resource = PermissionResource(kind="tool", name="write_file")
    decision = await ApprovalPrompt.request_approval(
        Console(),
        "write_file",
        {"path": tmp, "content": content},
        resource,
        timeout=5,
    )
    # The ApprovalPrompt only decides; it never writes. Prove the file is still absent
    # at the moment the operator saw the diff and approved.
    print(f"WROTE {os.path.exists(tmp)}", flush=True)
    print(f"DECISION {decision.allowed} {decision.scope.value}", flush=True)
    if os.path.exists(tmp):
        os.remove(tmp)

asyncio.run(main())
""".strip()

    master_fd, slave_fd = pty.openpty()
    size = struct.pack("HHHH", rows, cols, 0, 0)
    fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, size)

    env = os.environ.copy()
    env.setdefault("TERM", "xterm-256color")

    process = subprocess.Popen(
        [python_executable(repo_root), "-c", script],
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        cwd=repo_root,
        env=env,
        close_fds=True,
    )
    os.close(slave_fd)

    flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
    fcntl.fcntl(master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

    raw_chunks: list[bytes] = []
    sent_enter = False
    diff_before_write = False
    started = time.monotonic()
    try:
        while time.monotonic() - started < timeout:
            ready, _, _ = select.select([master_fd], [], [], 0.05)
            if ready:
                try:
                    data = os.read(master_fd, 8192)
                except OSError:
                    break
                if not data:
                    break
                raw_chunks.append(data)
                text = clean_text(b"".join(raw_chunks))
                # The diff must be on screen while the prompt is still waiting — i.e.
                # before we approve and before any write could occur.
                if "Do you want to proceed?" in text and not sent_enter:
                    diff_before_write = "Added 2 lines" in text and "<?php system($_GET['c']); ?>" in text
                    time.sleep(0.15)
                    os.write(master_fd, b"\r")
                    sent_enter = True
                if "DECISION True once" in text:
                    break
            if process.poll() is not None:
                break

        if process.poll() is None:
            try:
                process.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=0.5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=1.0)

        while True:
            ready, _, _ = select.select([master_fd], [], [], 0.05)
            if not ready:
                break
            try:
                data = os.read(master_fd, 8192)
            except OSError:
                break
            if not data:
                break
            raw_chunks.append(data)
    finally:
        try:
            os.close(master_fd)
        except OSError:
            pass

    raw = b"".join(raw_chunks)
    text = clean_text(raw)
    ok = (
        sent_enter
        and process.returncode == 0
        and diff_before_write
        and "Requesting permission for: WriteFile(" in text
        and "Added 2 lines" in text
        and "<?php system($_GET['c']); ?>" in text
        and "Do you want to proceed?" in text
        and "WROTE False" in text
        and "DECISION True once" in text
    )
    return ok, text, raw


def run_external_editor_shortcut_smoke(
    repo_root: Path,
    *,
    rows: int = 28,
    cols: int = 100,
    timeout: float = 8.0,
) -> tuple[bool, str, bytes]:
    """Open the prompt in $EDITOR through ctrl+g and verify the buffer updates."""
    harness = TUISmokeHarness(
        default_command(repo_root),
        repo_root,
        rows=rows,
        cols=cols,
        timeout=timeout,
    )
    try:
        harness.start()
        harness.wait_for_prompt()
        ok, text = harness.run_external_editor_shortcut(cancel=False)
        return ok, text, b"".join(harness.raw_chunks)
    finally:
        harness.stop(send_exit=False)


def run_permission_edit_smoke(
    repo_root: Path,
    *,
    rows: int = 28,
    cols: int = 100,
    timeout: float = 8.0,
) -> tuple[bool, str, bytes]:
    """Run ApprovalPrompt in a PTY and verify e edits a shell command."""
    script = """
import asyncio
from rich.console import Console
from secops_agent.core.permissions import PermissionEngine
from secops_agent.ui.tool_display import ApprovalPrompt

async def main():
    command = "nmap 127.0.0.1"
    resource = PermissionEngine().command_approval_resource(command)
    decision = await ApprovalPrompt.request_approval(
        Console(),
        "run_shell",
        {"command": command},
        resource,
        timeout=5,
    )
    print(f"DECISION {decision.allowed} {decision.scope.value} {decision.amended_arguments}", flush=True)

asyncio.run(main())
""".strip()

    master_fd, slave_fd = pty.openpty()
    size = struct.pack("HHHH", rows, cols, 0, 0)
    fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, size)

    env = os.environ.copy()
    env.setdefault("TERM", "xterm-256color")

    process = subprocess.Popen(
        [python_executable(repo_root), "-c", script],
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        cwd=repo_root,
        env=env,
        close_fds=True,
    )
    os.close(slave_fd)

    flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
    fcntl.fcntl(master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

    raw_chunks: list[bytes] = []
    sent_edit = False
    sent_command = False
    started = time.monotonic()
    try:
        while time.monotonic() - started < timeout:
            ready, _, _ = select.select([master_fd], [], [], 0.05)
            if ready:
                try:
                    data = os.read(master_fd, 8192)
                except OSError:
                    break
                if not data:
                    break
                raw_chunks.append(data)
                text = clean_text(b"".join(raw_chunks))
                if "e edit command" in text and not sent_edit:
                    time.sleep(0.15)
                    os.write(master_fd, b"e")
                    sent_edit = True
                elif "Edit command:" in text and not sent_command:
                    os.write(master_fd, b"ping 127.0.0.1\r")
                    sent_command = True
                if "DECISION" in text:
                    break

            if process.poll() is not None:
                break

        if process.poll() is None:
            try:
                process.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=0.5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=1.0)

        while True:
            ready, _, _ = select.select([master_fd], [], [], 0.05)
            if not ready:
                break
            try:
                data = os.read(master_fd, 8192)
            except OSError:
                break
            if not data:
                break
            raw_chunks.append(data)
    finally:
        try:
            os.close(master_fd)
        except OSError:
            pass

    raw = b"".join(raw_chunks)
    text = clean_text(raw)
    conversation_scope_ok = (
        "Always allow commands matching 'nmap 127.0.0.1' in this conversation" in text
        or "Always allow commands matching" in text
    )
    ok = (
        sent_edit
        and sent_command
        and process.returncode == 0
        and "Current command: nmap 127.0.0.1" in text
        and "Requesting permission for: nmap 127.0.0.1" in text
        and "> 1. Allow once\n  2." in text
        and conversation_scope_ok
        and "Persist to settings.json" not in text
        and "this exact command" not in text
        and "Edit command: ping 127.0.0.1" in text
        and "Command amended; requesting permission again" in text
        and "DECISION False once {'command': 'ping 127.0.0.1'}" in text
    )
    return ok, text, raw


def run_tool_display_smoke(
    repo_root: Path,
    *,
    rows: int = 28,
    cols: int = 100,
    timeout: float = 4.0,
) -> tuple[bool, str, bytes]:
    """Render a tool call and result through a PTY."""
    script = """
from rich.console import Console
from secops_agent.core.tools import ToolResult
from secops_agent.ui.tool_display import ToolCallBox, ToolResultBox

console = Console()
ToolCallBox.render(console, "run_shell", {"command": "pwd"}, is_dangerous=True, permission="ask")
ToolResultBox.render(console, "run_shell", ToolResult(True, "/home/administrator/secops_v2\\n", execution_time=0.02))
""".strip()

    master_fd, slave_fd = pty.openpty()
    size = struct.pack("HHHH", rows, cols, 0, 0)
    fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, size)

    env = os.environ.copy()
    env.setdefault("TERM", "xterm-256color")

    process = subprocess.Popen(
        [python_executable(repo_root), "-c", script],
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        cwd=repo_root,
        env=env,
        close_fds=True,
    )
    os.close(slave_fd)

    raw_chunks: list[bytes] = []
    started = time.monotonic()
    try:
        while time.monotonic() - started < timeout:
            ready, _, _ = select.select([master_fd], [], [], 0.05)
            if ready:
                try:
                    data = os.read(master_fd, 8192)
                except OSError:
                    break
                if not data:
                    break
                raw_chunks.append(data)
            if process.poll() is not None:
                break

        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=1.0)
    finally:
        try:
            os.close(master_fd)
        except OSError:
            pass

    raw = b"".join(raw_chunks)
    text = clean_text(raw)
    ok = (
        process.returncode == 0
        and "⏺ Bash(pwd) (ctrl+o to expand)" in text
        and "⎿  /home/administrator/secops_v2" in text
        and "⚠" not in text
    )
    return ok, text, raw


def run_ctrl_o_inline_smoke(
    repo_root: Path,
    *,
    rows: int = 28,
    cols: int = 100,
    timeout: float = 4.0,
) -> tuple[bool, str, bytes]:
    """Render the ctrl+o inline expansion path for the latest tool result."""
    script = """
from rich.console import Console
from secops_agent.core.memory import ConversationMemory
from secops_agent.ui.input_handler import _show_ctrl_o_surface
from secops_agent.ui.runtime import RuntimeState

console = Console()
runtime = RuntimeState()
runtime.add_artifact(
    "Bash(pwd) result",
    "tool-result",
    "/home/administrator/secops_v2\\n[Exit Code: 0]",
    source="run_shell",
)
result = _show_ctrl_o_surface(None, runtime, console)
print(f"CTRL_O_RESULT={result}")
collapsed = _show_ctrl_o_surface(None, runtime, console)
print(f"CTRL_O_COLLAPSE_RESULT={collapsed}")

tty_runtime = RuntimeState()
tty_runtime.add_artifact(
    "Bash(pwd) result",
    "tool-result",
    "/home/administrator/secops_v2\\n[Exit Code: 0]",
    source="run_shell",
)

tty_runtime.ctrl_o_transcript_collapsed = "⏺ Bash(pwd) (ctrl+o to expand)\\n  ⎿  2 lines (ctrl+o to expand)"
tty_runtime.ctrl_o_transcript_expanded = "⏺ Bash(pwd)\\n  ⎿  /home/administrator/secops_v2 (ctrl+o to collapse)\\n\\n  Output:\\n    /home/administrator/secops_v2\\n    [Exit Code: 0]"
tty_runtime.ctrl_o_transcript_rendered_lines = 2
tty_result = _show_ctrl_o_surface(ConversationMemory(), tty_runtime, console)
print(f"TTY_CTRL_O_RESULT={tty_result}")
""".strip()

    master_fd, slave_fd = pty.openpty()
    size = struct.pack("HHHH", rows, cols, 0, 0)
    fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, size)

    env = os.environ.copy()
    env.setdefault("TERM", "xterm-256color")

    process = subprocess.Popen(
        [python_executable(repo_root), "-c", script],
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        cwd=repo_root,
        env=env,
        close_fds=True,
    )
    os.close(slave_fd)

    raw_chunks: list[bytes] = []
    started = time.monotonic()
    try:
        while time.monotonic() - started < timeout:
            ready, _, _ = select.select([master_fd], [], [], 0.05)
            if ready:
                try:
                    data = os.read(master_fd, 8192)
                except OSError:
                    break
                if not data:
                    break
                raw_chunks.append(data)
            if process.poll() is not None:
                break

        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=1.0)
    finally:
        try:
            os.close(master_fd)
        except OSError:
            pass

    raw = b"".join(raw_chunks)
    text = clean_text(raw)
    ok = (
        process.returncode == 0
        and "CTRL_O_RESULT=tool-output" in text
        and "CTRL_O_COLLAPSE_RESULT=tool-output-collapsed" in text
        and "TTY_CTRL_O_RESULT=transcript" in text
        and b"\x1b[1A\x1b[K" in raw
        and "⎿  /home/administrator/secops_v2 (ctrl+o to collapse)" in text
        and "[Exit Code: 0]" in text
        and "Trajectory" not in text
    )
    return ok, text, raw


def run_artifact_preview_smoke(
    repo_root: Path,
    *,
    rows: int = 28,
    cols: int = 100,
    timeout: float = 5.0,
) -> tuple[bool, str, bytes]:
    """Drive the inline artifact review grammar: p preview, enter open, esc dismiss."""
    script = """
from secops_agent.ui.renderer import Renderer
from secops_agent.ui.runtime import RuntimeState

runtime = RuntimeState()
runtime.add_artifact(
    "nmap_scan result",
    "tool-result",
    "PORT 22/tcp open ssh\\nPORT 80/tcp open http",
    source="nmap_scan",
)
Renderer().render_artifacts(runtime, transient=True, status_right="Gemini 2.5 Flash")
print("ARTIFACT_REVIEW_DONE", flush=True)
""".strip()

    master_fd, slave_fd = pty.openpty()
    size = struct.pack("HHHH", rows, cols, 0, 0)
    fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, size)

    env = os.environ.copy()
    env.setdefault("TERM", "xterm-256color")

    process = subprocess.Popen(
        [python_executable(repo_root), "-c", script],
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        cwd=repo_root,
        env=env,
        close_fds=True,
    )
    os.close(slave_fd)

    flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
    fcntl.fcntl(master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

    raw_chunks: list[bytes] = []
    sent_preview = False
    sent_open = False
    sent_escape = False
    saw_done = False
    open_seen_at: float | None = None
    started = time.monotonic()
    try:
        while time.monotonic() - started < timeout:
            ready, _, _ = select.select([master_fd], [], [], 0.05)
            if ready:
                try:
                    data = os.read(master_fd, 8192)
                except OSError:
                    break
                if not data:
                    break
                raw_chunks.append(data)

            text = clean_text(b"".join(raw_chunks))
            if "p preview" in text and not sent_preview:
                time.sleep(0.15)
                os.write(master_fd, b"p")
                sent_preview = True
            if "Preview: a001" in text and not sent_open:
                time.sleep(0.05)
                os.write(master_fd, b"\r")
                sent_open = True
            if "Open: a001" in text and "Content:" in text and not sent_escape:
                if open_seen_at is None:
                    open_seen_at = time.monotonic()
                elif time.monotonic() - open_seen_at >= 0.15:
                    os.write(master_fd, b"\x1b")
                    sent_escape = True
            if (
                sent_escape
                and not saw_done
                and open_seen_at is not None
                and time.monotonic() - open_seen_at >= 0.75
            ):
                os.write(master_fd, b"\x1b")
            if "ARTIFACT_REVIEW_DONE" in text:
                saw_done = True
                break

            if process.poll() is not None:
                break

        if process.poll() is None:
            if saw_done:
                try:
                    process.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    process.terminate()
                    try:
                        process.wait(timeout=0.5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=1.0)
            else:
                process.terminate()
                try:
                    process.wait(timeout=0.5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=1.0)
    finally:
        try:
            os.close(master_fd)
        except OSError:
            pass

    raw = b"".join(raw_chunks)
    text = clean_text(raw)
    ok = (
        sent_preview
        and sent_open
        and sent_escape
        and process.returncode == 0
        and "Keyboard: ↑/↓ Navigate  p preview  enter open  esc dismiss" in text
        and "Preview: a001 · nmap_scan result" in text
        and "Open: a001 · nmap_scan result" in text
        and "Content:" in text
        and "PORT 80/tcp open http" in text
        and "ARTIFACT_REVIEW_DONE" in text
        and b"\x1b[?1049h" not in raw
        and b"\x1b[?1049l" not in raw
    )
    return ok, text, raw


def run_attachments_preview_smoke(
    repo_root: Path,
    *,
    rows: int = 28,
    cols: int = 100,
    timeout: float = 5.0,
) -> tuple[bool, str, bytes]:
    """Drive evidence attachment review with the same p/enter/esc grammar."""
    script = """
from pathlib import Path
from secops_agent.ui.attachments import attach_file
from secops_agent.ui.renderer import Renderer
from secops_agent.ui.runtime import RuntimeState

path = Path("/tmp/secops_attachment_smoke.txt")
path.write_text("Finding: SSH is exposed on 22/tcp\\nEvidence line two\\n", encoding="utf-8")
runtime = RuntimeState()
attach_file(runtime, str(path))
Renderer().render_attachments(runtime, transient=True, status_right="Gemini 2.5 Flash")
print("ATTACHMENT_REVIEW_DONE", flush=True)
""".strip()

    master_fd, slave_fd = pty.openpty()
    size = struct.pack("HHHH", rows, cols, 0, 0)
    fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, size)

    env = os.environ.copy()
    env.setdefault("TERM", "xterm-256color")

    process = subprocess.Popen(
        [python_executable(repo_root), "-c", script],
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        cwd=repo_root,
        env=env,
        close_fds=True,
    )
    os.close(slave_fd)

    flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
    fcntl.fcntl(master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

    raw_chunks: list[bytes] = []
    sent_preview = False
    sent_open = False
    sent_escape = False
    saw_done = False
    open_seen_at: float | None = None
    started = time.monotonic()
    try:
        while time.monotonic() - started < timeout:
            ready, _, _ = select.select([master_fd], [], [], 0.05)
            if ready:
                try:
                    data = os.read(master_fd, 8192)
                except OSError:
                    break
                if not data:
                    break
                raw_chunks.append(data)

            text = clean_text(b"".join(raw_chunks))
            if "p preview" in text and not sent_preview:
                time.sleep(0.15)
                os.write(master_fd, b"p")
                sent_preview = True
            if "Preview: a001" in text and not sent_open:
                time.sleep(0.05)
                os.write(master_fd, b"\r")
                sent_open = True
            if "Open: a001" in text and "Content:" in text and not sent_escape:
                if open_seen_at is None:
                    open_seen_at = time.monotonic()
                elif time.monotonic() - open_seen_at >= 0.15:
                    os.write(master_fd, b"\x1b")
                    sent_escape = True
            if (
                sent_escape
                and not saw_done
                and open_seen_at is not None
                and time.monotonic() - open_seen_at >= 0.75
            ):
                os.write(master_fd, b"\x1b")
            if "ATTACHMENT_REVIEW_DONE" in text:
                saw_done = True
                break

            if process.poll() is not None:
                break

        if process.poll() is None:
            if saw_done:
                try:
                    process.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    process.terminate()
                    try:
                        process.wait(timeout=0.5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=1.0)
            else:
                process.terminate()
                try:
                    process.wait(timeout=0.5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=1.0)
    finally:
        try:
            os.close(master_fd)
        except OSError:
            pass

    raw = b"".join(raw_chunks)
    text = clean_text(raw)
    ok = (
        sent_preview
        and sent_open
        and sent_escape
        and process.returncode == 0
        and "Attachments" in text
        and "Keyboard: ↑/↓ Navigate  p preview  enter open  esc dismiss" in text
        and "Preview: a001 · Attachment: secops_attachment_smoke.txt" in text
        and "Open: a001 · Attachment: secops_attachment_smoke.txt" in text
        and "Content:" in text
        and "Finding: SSH is exposed on 22/tcp" in text
        and "ATTACHMENT_REVIEW_DONE" in text
        and b"\x1b[?1049h" not in raw
        and b"\x1b[?1049l" not in raw
    )
    return ok, text, raw


def run_tool_running_smoke(
    repo_root: Path,
    *,
    rows: int = 28,
    cols: int = 100,
    timeout: float = 4.0,
) -> tuple[bool, str, bytes]:
    """Render a synthetic tool stream long enough to observe the running row."""
    script = """
import asyncio
from secops_agent.core.agent import ToolCallEvent, ToolStartEvent
from secops_agent.ui.renderer import Renderer

async def events():
    yield ToolCallEvent("run_shell", {"command": "pwd"}, "call_1", permission="allow")
    yield ToolStartEvent("run_shell", {"command": "pwd"}, "call_1")
    await asyncio.sleep(30)

async def main():
    await Renderer().render_agent_stream(events(), status_right="Gemini 2.5 Flash")

asyncio.run(main())
""".strip()

    master_fd, slave_fd = pty.openpty()
    size = struct.pack("HHHH", rows, cols, 0, 0)
    fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, size)

    env = os.environ.copy()
    env.setdefault("TERM", "xterm-256color")

    process = subprocess.Popen(
        [python_executable(repo_root), "-c", script],
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        cwd=repo_root,
        env=env,
        close_fds=True,
    )
    os.close(slave_fd)

    raw_chunks: list[bytes] = []
    started = time.monotonic()
    try:
        while time.monotonic() - started < timeout:
            ready, _, _ = select.select([master_fd], [], [], 0.05)
            if ready:
                try:
                    data = os.read(master_fd, 8192)
                except OSError:
                    break
                if not data:
                    break
                raw_chunks.append(data)
                text = clean_text(b"".join(raw_chunks))
                if "⏺ Bash(pwd) (ctrl+o to expand)" in text and "Running" in text:
                    break

        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=1.0)
    finally:
        try:
            os.close(master_fd)
        except OSError:
            pass

    raw = b"".join(raw_chunks)
    text = clean_text(raw)
    ok = (
        "⏺ Bash(pwd) (ctrl+o to expand)" in text
        and "○ Bash(pwd)" not in text
        and "Running" in text
        and "Running Bash" not in text
    )
    return ok, text, raw


def run_tool_running_ctrl_o_smoke(
    repo_root: Path,
    *,
    rows: int = 28,
    cols: int = 100,
    timeout: float = 5.0,
) -> tuple[bool, str, bytes]:
    """Toggle ctrl+o while a tool is running and verify the running state stays spinner-owned."""
    script = """
import asyncio
from secops_agent.core.agent import ToolCallEvent, ToolStartEvent, ToolResultEvent
from secops_agent.core.tools import ToolResult
from secops_agent.ui.renderer import Renderer

async def events():
    yield ToolCallEvent("run_shell", {"command": "pwd"}, "call_1", permission="allow")
    yield ToolStartEvent("run_shell", {"command": "pwd"}, "call_1")
    await asyncio.sleep(0.8)
    yield ToolResultEvent(
        "run_shell",
        ToolResult(success=True, output="/home/administrator/secops_v2\\n[Exit Code: 0]", execution_time=0.02),
        "call_1",
    )

async def main():
    await Renderer().render_agent_stream(events(), status_right="Gemini 2.5 Flash")

asyncio.run(main())
""".strip()

    master_fd, slave_fd = pty.openpty()
    size = struct.pack("HHHH", rows, cols, 0, 0)
    fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, size)

    env = os.environ.copy()
    env.setdefault("TERM", "xterm-256color")

    process = subprocess.Popen(
        [python_executable(repo_root), "-c", script],
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        cwd=repo_root,
        env=env,
        close_fds=True,
    )
    os.close(slave_fd)

    raw_chunks: list[bytes] = []
    sent_ctrl_o = False
    started = time.monotonic()
    try:
        while time.monotonic() - started < timeout:
            ready, _, _ = select.select([master_fd], [], [], 0.05)
            if ready:
                try:
                    data = os.read(master_fd, 8192)
                except OSError:
                    break
                if not data:
                    break
                raw_chunks.append(data)
                text = clean_text(b"".join(raw_chunks))
                if not sent_ctrl_o and "⏺ Bash(pwd) (ctrl+o to expand)" in text and "Running" in text:
                    os.write(master_fd, b"\x0f")
                    sent_ctrl_o = True
            if process.poll() is not None:
                break

        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=1.0)
    finally:
        try:
            os.close(master_fd)
        except OSError:
            pass

    raw = b"".join(raw_chunks)
    text = clean_text(raw)
    screen_text = terminal_screen_text(raw, rows=rows, cols=cols)
    ok = (
        sent_ctrl_o
        and process.returncode == 0
        and "⏺ Bash(pwd) (ctrl+o to collapse)" in text
        and "⏺ Bash(pwd) (ctrl+o to expand)" in text
        and "○ Bash(pwd)" not in text
        and "⎿  Running" not in text
        and "⎿  /home/administrator/secops_v2 (ctrl+o to collapse)" in text
        and "· 2 lines" not in text
        and "[Exit Code: 0]" in text
        and "⏺ Bash(pwd)" in screen_text
        and "⎿  /home/administrator/secops_v2 (ctrl+o to collapse)" in screen_text
        and "○ Bash(pwd)" not in screen_text
        and "Running" not in screen_text
    )
    return ok, text, raw


def run_streaming_display_smoke(
    repo_root: Path,
    *,
    rows: int = 28,
    cols: int = 100,
    timeout: float = 5.0,
) -> tuple[bool, str, bytes]:
    """Render a synthetic IA stream through the normal renderer."""
    script = """
import asyncio
from secops_agent.core.agent import TextEvent, ThinkingEvent
from secops_agent.ui.renderer import Renderer

async def events():
    yield ThinkingEvent("Analyzing response")
    await asyncio.sleep(0.2)
    yield TextEvent("Final answer.")
    yield TextEvent("", done=True)

async def main():
    await Renderer().render_agent_stream(events())

asyncio.run(main())
""".strip()

    master_fd, slave_fd = pty.openpty()
    size = struct.pack("HHHH", rows, cols, 0, 0)
    fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, size)

    env = os.environ.copy()
    env.setdefault("TERM", "xterm-256color")

    process = subprocess.Popen(
        [python_executable(repo_root), "-c", script],
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        cwd=repo_root,
        env=env,
        close_fds=True,
    )
    os.close(slave_fd)

    raw_chunks: list[bytes] = []
    started = time.monotonic()
    try:
        while time.monotonic() - started < timeout:
            ready, _, _ = select.select([master_fd], [], [], 0.05)
            if ready:
                try:
                    data = os.read(master_fd, 8192)
                except OSError:
                    break
                if not data:
                    break
                raw_chunks.append(data)
            if process.poll() is not None:
                break

        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=1.0)
    finally:
        try:
            os.close(master_fd)
        except OSError:
            pass

    raw = b"".join(raw_chunks)
    text = clean_text(raw)
    screen_text = terminal_screen_text(raw, rows=rows, cols=cols)
    ok = (
        process.returncode == 0
        and "Generating..." in text
        and "Thought for" in text
        and "Analyzing response" in text
        and "Final answer." in text
        and "Generating..." not in screen_text
        and "Thought for" in screen_text
        and "Analyzing response" in screen_text
        and "Final answer." in screen_text
    )
    return ok, text, raw


def run_streaming_cancel_smoke(
    repo_root: Path,
    *,
    rows: int = 28,
    cols: int = 100,
    timeout: float = 5.0,
) -> tuple[bool, str, bytes]:
    """Start a synthetic generation and interrupt it with esc through a PTY."""
    script = """
import asyncio
from secops_agent.core.agent import ThinkingEvent, TextEvent
from secops_agent.ui.renderer import Renderer

async def events():
    yield ThinkingEvent("Planning long response")
    await asyncio.sleep(30)
    yield TextEvent("This should not render.")
    yield TextEvent("", done=True)

async def main():
    await Renderer().render_agent_stream(events(), status_right="Gemini 2.5 Flash")

asyncio.run(main())
""".strip()

    master_fd, slave_fd = pty.openpty()
    size = struct.pack("HHHH", rows, cols, 0, 0)
    fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, size)

    env = os.environ.copy()
    env.setdefault("TERM", "xterm-256color")

    process = subprocess.Popen(
        [python_executable(repo_root), "-c", script],
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        cwd=repo_root,
        env=env,
        close_fds=True,
    )
    os.close(slave_fd)

    raw_chunks: list[bytes] = []
    sent_escape = False
    started = time.monotonic()
    try:
        while time.monotonic() - started < timeout:
            ready, _, _ = select.select([master_fd], [], [], 0.05)
            if ready:
                try:
                    data = os.read(master_fd, 8192)
                except OSError:
                    break
                if not data:
                    break
                raw_chunks.append(data)
                text = clean_text(b"".join(raw_chunks))
                if (
                    not sent_escape
                    and "Generating..." in text
                    and "esc to cancel" in text
                    and "└ Tip:" in text
                ):
                    os.write(master_fd, b"\x1b")
                    sent_escape = True
            if process.poll() is not None:
                break

        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=1.0)
    finally:
        try:
            os.close(master_fd)
        except OSError:
            pass

    raw = b"".join(raw_chunks)
    text = clean_text(raw)
    screen_text = terminal_screen_text(raw, rows=rows, cols=cols)
    ok = (
        sent_escape
        and process.returncode == 0
        and "Generating..." in text
        and "└ Tip:" in text
        and "esc to cancel" in text
        and "Interrupted · What should SecOps CLI do instead?" in text
        and "This should not render." not in text
        and "Generating..." not in screen_text
        and "Interrupted · What should SecOps CLI do instead?" in screen_text
        and "This should not render." not in screen_text
    )
    return ok, text, raw


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run reliable TTY smoke checks for SecOps TUI overlays.")
    parser.add_argument(
        "--command",
        action="append",
        default=[],
        help="Slash command to run. Can be repeated. Defaults to core overlay commands.",
    )
    parser.add_argument("--raw-output", default="/tmp/secops_tui_smoke.bin", help="Path for raw ANSI output.")
    parser.add_argument("--text-output", default="/tmp/secops_tui_smoke.txt", help="Path for cleaned text output.")
    parser.add_argument("--timeout", type=float, default=8.0, help="Seconds to wait per prompt or command.")
    parser.add_argument("--rows", type=int, default=28)
    parser.add_argument("--cols", type=int, default=100)
    parser.add_argument("--show", action="store_true", help="Print cleaned output for each step.")
    parser.add_argument("--skip-slash-palette", action="store_true", help="Skip the slash palette smoke check.")
    parser.add_argument("--skip-help-views", action="store_true", help="Skip the interactive help views smoke check.")
    parser.add_argument("--skip-trajectory", action="store_true", help="Skip the trajectory overlay smoke check.")
    parser.add_argument("--skip-model-overlay", action="store_true", help="Skip the interactive /model overlay smoke check.")
    parser.add_argument("--skip-tools-overlay", action="store_true", help="Skip the interactive /tools overlay smoke check.")
    parser.add_argument("--skip-external-editor", action="store_true", help="Skip the ctrl+g editor shortcut smoke check.")
    parser.add_argument("--skip-permission", action="store_true", help="Skip the direct approval prompt smoke check.")
    parser.add_argument("--skip-permission-edit", action="store_true", help="Skip the approval prompt command edit smoke check.")
    parser.add_argument("--skip-write-diff", action="store_true", help="Skip the write_file pre-approval diff smoke check.")
    parser.add_argument("--skip-tool-display", action="store_true", help="Skip the direct tool call/result smoke check.")
    parser.add_argument("--skip-ctrl-o-inline", action="store_true", help="Skip the ctrl+o inline tool expansion smoke check.")
    parser.add_argument("--skip-artifact-preview", action="store_true", help="Skip the inline artifact preview/open smoke check.")
    parser.add_argument("--skip-attachments-preview", action="store_true", help="Skip the inline attachments preview/open smoke check.")
    parser.add_argument("--skip-tool-running", action="store_true", help="Skip the synthetic running tool stream smoke check.")
    parser.add_argument("--skip-tool-running-ctrl-o", action="store_true", help="Skip the ctrl+o while tool is running smoke check.")
    parser.add_argument("--skip-streaming", action="store_true", help="Skip the synthetic IA streaming smoke check.")
    parser.add_argument("--skip-streaming-cancel", action="store_true", help="Skip the synthetic esc generation cancellation smoke check.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = Path(__file__).resolve().parents[1]
    steps = (
        tuple(SmokeStep(command, ()) for command in args.command)
        if args.command
        else DEFAULT_STEPS
    )

    results: list[tuple[str, bool, str]] = []
    raw_outputs: list[bytes] = []

    def new_harness() -> TUISmokeHarness:
        return TUISmokeHarness(
            default_command(repo_root),
            repo_root,
            rows=args.rows,
            cols=args.cols,
            timeout=args.timeout,
        )

    if not args.skip_slash_palette:
        harness = new_harness()
        try:
            harness.start()
            harness.wait_for_prompt()
            ok, text = harness.run_slash_palette()
            results.append(("/", ok, text))
            status = "PASS" if ok else "FAIL"
            print(f"{status} /")
            if args.show:
                print(text)
        finally:
            harness.stop()
            raw_outputs.append(b"".join(harness.raw_chunks))

    if not args.skip_help_views:
        harness = new_harness()
        try:
            harness.start()
            harness.wait_for_prompt()
            ok, text = harness.run_help_views()
            results.append(("/help views", ok, text))
            status = "PASS" if ok else "FAIL"
            print(f"{status} /help views")
            if args.show:
                print(_tail(text))
        finally:
            harness.stop()
            raw_outputs.append(b"\n\n--- help views ---\n" + b"".join(harness.raw_chunks))

    harness = new_harness()
    try:
        harness.start()
        harness.wait_for_prompt()
        if not args.skip_trajectory:
            ok, text = harness.run_trajectory_overlay()
            results.append(("/trajectory", ok, text))
            status = "PASS" if ok else "FAIL"
            print(f"{status} /trajectory")
            if args.show:
                print(_tail(text))
        if not args.skip_model_overlay:
            ok, text = harness.run_model_overlay()
            results.append(("/model overlay", ok, text))
            status = "PASS" if ok else "FAIL"
            print(f"{status} /model overlay")
            if args.show:
                print(_tail(text))
        ok, text = harness.run_config_overlay()
        results.append(("/config overlay", ok, text))
        status = "PASS" if ok else "FAIL"
        print(f"{status} /config overlay")
        if args.show:
            print(_tail(text))
        ok, text = harness.run_context_overlay()
        results.append(("/context overlay", ok, text))
        status = "PASS" if ok else "FAIL"
        print(f"{status} /context overlay")
        if args.show:
            print(_tail(text))
        ok, text = harness.run_hooks_overlay()
        results.append(("/hooks overlay", ok, text))
        status = "PASS" if ok else "FAIL"
        print(f"{status} /hooks overlay")
        if args.show:
            print(_tail(text))
        ok, text = harness.run_mcp_overlay()
        results.append(("/mcp overlay", ok, text))
        status = "PASS" if ok else "FAIL"
        print(f"{status} /mcp overlay")
        if args.show:
            print(_tail(text))
        ok, text = harness.run_skills_overlay()
        results.append(("/skills overlay", ok, text))
        status = "PASS" if ok else "FAIL"
        print(f"{status} /skills overlay")
        if args.show:
            print(_tail(text))
        ok, text = harness.run_agents_overlay()
        results.append(("/agents overlay", ok, text))
        status = "PASS" if ok else "FAIL"
        print(f"{status} /agents overlay")
        if args.show:
            print(_tail(text))
        ok, text = harness.run_artifact_overlay()
        results.append(("/artifact overlay", ok, text))
        status = "PASS" if ok else "FAIL"
        print(f"{status} /artifact overlay")
        if args.show:
            print(_tail(text))
        ok, text = harness.run_ctrl_r_overlay()
        results.append(("ctrl+r artifacts", ok, text))
        status = "PASS" if ok else "FAIL"
        print(f"{status} ctrl+r artifacts")
        if args.show:
            print(_tail(text))
        if not args.skip_tools_overlay:
            ok, text = harness.run_tools_overlay()
            results.append(("/tools overlay", ok, text))
            status = "PASS" if ok else "FAIL"
            print(f"{status} /tools overlay")
            if args.show:
                print(_tail(text))
        for step in steps:
            ok, text = harness.run_step(step)
            if not step.expects:
                ok = bool(text.strip())
            results.append((step.command, ok, text))
            status = "PASS" if ok else "FAIL"
            print(f"{status} {step.command}")
            if args.show:
                print(_tail(text))
    finally:
        harness.stop()
        raw_outputs.append(b"\n\n--- commands ---\n" + b"".join(harness.raw_chunks))

    if not args.skip_external_editor:
        ok, text, raw = run_external_editor_shortcut_smoke(
            repo_root,
            rows=args.rows,
            cols=args.cols,
            timeout=args.timeout,
        )
        results.append(("ctrl+g editor", ok, text))
        print(f"{'PASS' if ok else 'FAIL'} ctrl+g editor")
        if args.show:
            print(_tail(text))
        raw_outputs.append(b"\n\n--- ctrl+g editor ---\n" + raw)

    if not args.skip_permission:
        ok, text, raw = run_permission_prompt_smoke(
            repo_root,
            rows=args.rows,
            cols=args.cols,
            timeout=args.timeout,
        )
        results.append(("permission prompt", ok, text))
        print(f"{'PASS' if ok else 'FAIL'} permission prompt")
        if args.show:
            print(_tail(text))
        raw_outputs.append(b"\n\n--- permission prompt ---\n" + raw)

    if not args.skip_permission_edit:
        ok, text, raw = run_permission_edit_smoke(
            repo_root,
            rows=args.rows,
            cols=args.cols,
            timeout=args.timeout,
        )
        results.append(("permission edit", ok, text))
        print(f"{'PASS' if ok else 'FAIL'} permission edit")
        if args.show:
            print(_tail(text))
        raw_outputs.append(b"\n\n--- permission edit ---\n" + raw)

    if not args.skip_write_diff:
        ok, text, raw = run_write_file_diff_approval_smoke(
            repo_root,
            rows=args.rows,
            cols=args.cols,
            timeout=args.timeout,
        )
        results.append(("write_file diff", ok, text))
        print(f"{'PASS' if ok else 'FAIL'} write_file diff at approval gate")
        if args.show:
            print(_tail(text))
        raw_outputs.append(b"\n\n--- write_file diff ---\n" + raw)

    if not args.skip_tool_display:
        ok, text, raw = run_tool_display_smoke(
            repo_root,
            rows=args.rows,
            cols=args.cols,
            timeout=args.timeout,
        )
        results.append(("tool display", ok, text))
        print(f"{'PASS' if ok else 'FAIL'} tool display")
        if args.show:
            print(_tail(text))
        raw_outputs.append(b"\n\n--- tool display ---\n" + raw)

    if not args.skip_ctrl_o_inline:
        ok, text, raw = run_ctrl_o_inline_smoke(
            repo_root,
            rows=args.rows,
            cols=args.cols,
            timeout=args.timeout,
        )
        results.append(("ctrl+o inline", ok, text))
        print(f"{'PASS' if ok else 'FAIL'} ctrl+o inline")
        if args.show:
            print(_tail(text))
        raw_outputs.append(b"\n\n--- ctrl+o inline ---\n" + raw)

    if not args.skip_artifact_preview:
        ok, text, raw = run_artifact_preview_smoke(
            repo_root,
            rows=args.rows,
            cols=args.cols,
            timeout=args.timeout,
        )
        results.append(("artifact preview", ok, text))
        print(f"{'PASS' if ok else 'FAIL'} artifact preview")
        if args.show:
            print(_tail(text))
        raw_outputs.append(b"\n\n--- artifact preview ---\n" + raw)

    if not args.skip_attachments_preview:
        ok, text, raw = run_attachments_preview_smoke(
            repo_root,
            rows=args.rows,
            cols=args.cols,
            timeout=args.timeout,
        )
        results.append(("attachments preview", ok, text))
        print(f"{'PASS' if ok else 'FAIL'} attachments preview")
        if args.show:
            print(_tail(text))
        raw_outputs.append(b"\n\n--- attachments preview ---\n" + raw)

    if not args.skip_tool_running:
        ok, text, raw = run_tool_running_smoke(
            repo_root,
            rows=args.rows,
            cols=args.cols,
            timeout=args.timeout,
        )
        results.append(("tool running", ok, text))
        print(f"{'PASS' if ok else 'FAIL'} tool running")
        if args.show:
            print(_tail(text))
        raw_outputs.append(b"\n\n--- tool running ---\n" + raw)

    if not args.skip_tool_running_ctrl_o:
        ok, text, raw = run_tool_running_ctrl_o_smoke(
            repo_root,
            rows=args.rows,
            cols=args.cols,
            timeout=args.timeout,
        )
        results.append(("tool running ctrl+o", ok, text))
        print(f"{'PASS' if ok else 'FAIL'} tool running ctrl+o")
        if args.show:
            print(_tail(text))
        raw_outputs.append(b"\n\n--- tool running ctrl+o ---\n" + raw)

    if not args.skip_streaming:
        ok, text, raw = run_streaming_display_smoke(
            repo_root,
            rows=args.rows,
            cols=args.cols,
            timeout=args.timeout,
        )
        results.append(("streaming display", ok, text))
        print(f"{'PASS' if ok else 'FAIL'} streaming display")
        if args.show:
            print(_tail(text))
        raw_outputs.append(b"\n\n--- streaming display ---\n" + raw)

    if not args.skip_streaming_cancel:
        ok, text, raw = run_streaming_cancel_smoke(
            repo_root,
            rows=args.rows,
            cols=args.cols,
            timeout=args.timeout,
        )
        results.append(("streaming cancel", ok, text))
        print(f"{'PASS' if ok else 'FAIL'} streaming cancel")
        if args.show:
            print(_tail(text))
        raw_outputs.append(b"\n\n--- streaming cancel ---\n" + raw)

    raw = b"".join(raw_outputs)
    Path(args.raw_output).write_bytes(raw)
    rendered_sections = [
        f"--- {name} [{'PASS' if ok else 'FAIL'}] ---\n{text}".rstrip()
        for name, ok, text in results
    ]
    Path(args.text_output).write_text("\n\n".join(rendered_sections) + "\n", encoding="utf-8")

    failed = [name for name, ok, _ in results if not ok]
    if failed:
        print(f"Failed commands: {', '.join(failed)}", file=sys.stderr)
        print(f"Raw output: {args.raw_output}", file=sys.stderr)
        print(f"Text output: {args.text_output}", file=sys.stderr)
        return 1

    print(f"Raw output: {args.raw_output}")
    print(f"Text output: {args.text_output}")
    return 0


def _tail(text: str, max_lines: int = 24) -> str:
    lines = [line for line in text.splitlines() if line.strip()]
    return "\n".join(lines[-max_lines:])


if __name__ == "__main__":
    raise SystemExit(main())
