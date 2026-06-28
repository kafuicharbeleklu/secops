#!/usr/bin/env python3
"""Capture selected Antigravity CLI TUI surfaces through a PTY."""

from __future__ import annotations

import argparse
import fcntl
import os
import pty
import select
import signal
import struct
import subprocess
import sys
import termios
import time
from dataclasses import dataclass
from pathlib import Path
import re

from scratch.tui_smoke import CPR_QUERY, clean_text, terminal_screen_text


DEFAULT_AGY = "/home/administrator/.local/bin/agy"
ESC = b"\x1b"
CTRL_O = b"\x0f"
CTRL_R = b"\x12"
UP = ESC + b"[A"
DOWN = ESC + b"[B"
RIGHT = ESC + b"[C"
LEFT = ESC + b"[D"
PAGEDOWN = ESC + b"[6~"


@dataclass(frozen=True)
class Scenario:
    description: str
    keys: list[tuple[float, bytes]]


EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
LOCAL_USER_RE = re.compile(r"\b[\w.-]+@[\w.-]+\b")


def redact_capture_text(text: str) -> str:
    """Redact account-like identifiers while preserving layout evidence."""
    text = EMAIL_RE.sub("<account>", text)
    return LOCAL_USER_RE.sub("<account>", text)


def set_pty_size(fd: int, rows: int, cols: int) -> None:
    size = struct.pack("HHHH", rows, cols, 0, 0)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, size)


def read_for(master_fd: int, seconds: float, *, row: int, col: int) -> bytes:
    deadline = time.monotonic() + seconds
    raw = bytearray()
    while time.monotonic() < deadline:
        ready, _, _ = select.select([master_fd], [], [], 0.05)
        if not ready:
            continue
        try:
            data = os.read(master_fd, 8192)
        except OSError:
            break
        if not data:
            break
        raw.extend(data)
        if CPR_QUERY in data:
            os.write(master_fd, f"\x1b[{row};{col}R".encode("ascii"))
    return bytes(raw)


def read_until_prompt(master_fd: int, seconds: float, *, row: int, col: int) -> bytes:
    deadline = time.monotonic() + seconds
    raw = bytearray()
    while time.monotonic() < deadline:
        raw.extend(read_for(master_fd, min(0.5, max(0.0, deadline - time.monotonic())), row=row, col=col))
        text = clean_text(bytes(raw))
        if "? for shortcuts" in text or "\n> " in text or text.rstrip().endswith(">"):
            break
    return bytes(raw)


def run_capture(
    name: str,
    scenario: Scenario,
    *,
    agy: str,
    out_dir: Path,
    rows: int,
    cols: int,
    cwd: Path,
    max_seconds: float,
) -> str:
    master_fd, slave_fd = pty.openpty()
    set_pty_size(slave_fd, rows, cols)

    env = os.environ.copy()
    env.setdefault("TERM", "xterm-256color")
    env.setdefault("COLORTERM", "truecolor")

    process = subprocess.Popen(
        [agy],
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        cwd=cwd,
        env=env,
        close_fds=True,
        start_new_session=True,
    )
    os.close(slave_fd)

    flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
    fcntl.fcntl(master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

    deadline = time.monotonic() + max_seconds
    raw = bytearray()
    raw.extend(read_until_prompt(master_fd, min(12.0, max(0.0, deadline - time.monotonic())), row=rows, col=1))
    for pause, payload in scenario.keys:
        if time.monotonic() >= deadline:
            break
        if pause:
            raw.extend(
                read_for(
                    master_fd,
                    min(pause, max(0.0, deadline - time.monotonic())),
                    row=rows,
                    col=1,
                )
            )
        if payload:
            try:
                os.write(master_fd, payload)
            except BlockingIOError:
                pass
            except OSError:
                break
        raw.extend(read_for(master_fd, min(1.2, max(0.0, deadline - time.monotonic())), row=rows, col=1))
    raw.extend(read_for(master_fd, min(1.0, max(0.0, deadline - time.monotonic())), row=rows, col=1))

    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=1)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
    try:
        os.close(master_fd)
    except OSError:
        pass

    out_dir.mkdir(parents=True, exist_ok=True)
    raw_path = out_dir / f"agy_{name}.bin"
    text_path = out_dir / f"agy_{name}.txt"
    frame_path = out_dir / f"agy_{name}_frame.txt"
    payload = bytes(raw)
    raw_path.write_bytes(payload)
    text_path.write_text(clean_text(payload), encoding="utf-8")
    frame = terminal_screen_text(payload, rows=rows, cols=cols)
    frame_path.write_text(frame, encoding="utf-8")
    return frame


def repeat(payload: bytes, count: int, pause: float = 0.05) -> list[tuple[float, bytes]]:
    return [(pause, payload) for _ in range(count)]


def basic_scenarios() -> dict[str, Scenario]:
    return {
        "idle": Scenario("fresh startup idle frame", [(5.0, b"")]),
        "shortcuts": Scenario("press ? to open shortcut help", [(0.2, b"?")]),
        "slash_palette": Scenario("type / to open slash palette", [(1.5, b"/")]),
        "slash_palette_tab": Scenario("type / then tab", [(1.5, b"/"), (0.2, b"\t")]),
        "help_command": Scenario("run /help", [(0.2, b"/help\r")]),
        "model_command": Scenario("run /model", [(0.2, b"/model\r")]),
    }


def deep_scenarios() -> dict[str, Scenario]:
    scenarios = basic_scenarios()
    scenarios.update(
        {
            "help_commands_tab": Scenario(
                "open /help then switch to commands tab",
                [(0.2, b"/help\r"), (0.5, RIGHT)],
            ),
            "help_shortcuts_tab": Scenario(
                "open /help then switch to shortcuts tab",
                [(0.2, b"/help\r"), (0.5, RIGHT), (0.2, RIGHT)],
            ),
            "help_shortcuts_scroll": Scenario(
                "open /help shortcuts tab and scroll down",
                [(0.2, b"/help\r"), (0.5, RIGHT), (0.2, RIGHT)]
                + repeat(DOWN, 12),
            ),
            "shortcut_help_general_tab": Scenario(
                "press ? then move left twice to general tab",
                [(0.2, b"?"), (0.4, LEFT), (0.2, LEFT)],
            ),
            "slash_palette_down_5": Scenario(
                "open slash palette and move selection down five rows",
                [(1.5, b"/")] + repeat(DOWN, 5),
            ),
            "slash_palette_down_20": Scenario(
                "open slash palette and move deeper into the command list",
                [(1.5, b"/")] + repeat(DOWN, 20),
            ),
            "slash_palette_page_down": Scenario(
                "open slash palette and page down",
                [(1.5, b"/"), (0.2, PAGEDOWN)],
            ),
            "slash_palette_filter_key": Scenario(
                "filter slash palette with /key",
                [(1.5, b"/"), (0.2, b"key")],
            ),
            "slash_palette_filter_plugin": Scenario(
                "filter slash palette with /plugin",
                [(1.5, b"/"), (0.2, b"plugin")],
            ),
            "model_down_3": Scenario(
                "open model picker and move down three rows",
                [(0.2, b"/model\r")] + repeat(DOWN, 3),
            ),
            "model_page_down": Scenario(
                "open model picker and page down",
                [(0.2, b"/model\r"), (0.2, PAGEDOWN)],
            ),
            "agents_command": Scenario("run /agents", [(0.2, b"/agents\r")]),
            "artifact_command": Scenario("run /artifact", [(0.2, b"/artifact\r")]),
            "changelog_command": Scenario("run /changelog", [(0.2, b"/changelog\r")]),
            "keybindings_command": Scenario("run /keybindings", [(0.2, b"/keybindings\r")]),
            "plugins_filter_only": Scenario(
                "discover plugin-related slash commands without executing them",
                [(1.5, b"/"), (0.2, b"plugins")],
            ),
            "generation_short_prompt": Scenario(
                "send a harmless short prompt and wait for generation UI",
                [(1.5, b"Respond with only OK.\r"), (8.0, b"")],
            ),
            "permission_probe_pwd": Scenario(
                "ask AGY to run only pwd and wait for any permission prompt",
                [(1.5, b"Run only the pwd command and do nothing else.\r"), (12.0, b"")],
            ),
        }
    )
    return scenarios


def full_scenarios() -> dict[str, Scenario]:
    scenarios = deep_scenarios()
    scenarios.update(
        {
            "help_commands_scroll_deep": Scenario(
                "open /help commands tab and scroll through many command rows",
                [(0.2, b"/help\r"), (0.5, RIGHT)] + repeat(DOWN, 80, 0.08),
            ),
            "help_shortcuts_scroll_deep": Scenario(
                "open /help shortcuts tab and scroll through many shortcut rows",
                [(0.2, b"/help\r"), (0.5, RIGHT), (0.2, RIGHT)] + repeat(DOWN, 40, 0.08),
            ),
            "slash_palette_scroll_all_slow": Scenario(
                "open slash palette and slowly walk through the command list",
                [(1.5, b"/")] + repeat(DOWN, 115, 0.10),
            ),
            "ctrl_o_idle": Scenario("press ctrl+o on an idle session", [(1.0, CTRL_O)]),
            "ctrl_r_idle": Scenario("press ctrl+r on an idle session", [(1.0, CTRL_R)]),
            "context_command": Scenario("run /context", [(0.2, b"/context\r")]),
            "config_command": Scenario("run /config", [(0.2, b"/config\r")]),
            "settings_command": Scenario("run /settings", [(0.2, b"/settings\r")]),
            "hooks_command": Scenario("run /hooks", [(0.2, b"/hooks\r")]),
            "mcp_command": Scenario("run /mcp", [(0.2, b"/mcp\r")]),
            "credits_command": Scenario("run /credits", [(0.2, b"/credits\r")]),
            "diff_command": Scenario("run /diff", [(0.2, b"/diff\r")]),
            "memory_command": Scenario("run /memory", [(0.2, b"/memory\r")]),
            "permissions_command": Scenario("run /permissions", [(0.2, b"/permissions\r")]),
            "long_generation": Scenario(
                "send a long harmless writing request and wait for long generation UI",
                [
                    (
                        1.5,
                        b"Write a detailed numbered list of 40 concise terminal UX observations. Do not use tools.\r",
                    ),
                    (22.0, b""),
                ],
            ),
            "long_generation_cancel_esc": Scenario(
                "start a long generation and press esc to observe cancellation UX",
                [
                    (
                        1.5,
                        b"Write a very long numbered list of 120 concise terminal UX observations. Do not use tools.\r",
                    ),
                    (2.0, ESC),
                    (5.0, b""),
                ],
            ),
            "tool_pwd_ctrl_o_after": Scenario(
                "ask AGY to run pwd, wait, then press ctrl+o",
                [(1.5, b"Run only the pwd command and do nothing else.\r"), (14.0, CTRL_O), (4.0, b"")],
            ),
            "tool_sleep_long": Scenario(
                "ask AGY to run a benign slow local command",
                [
                    (
                        1.5,
                        b"Run only this command and do nothing else: python3 -c \"import time; time.sleep(6); print('done')\"\r",
                    ),
                    (22.0, b""),
                ],
            ),
            "tool_sleep_ctrl_o_during": Scenario(
                "ask AGY to run a slow command and press ctrl+o while it is likely active",
                [
                    (
                        1.5,
                        b"Run only this command and do nothing else: python3 -c \"import time; time.sleep(8); print('done')\"\r",
                    ),
                    (8.0, CTRL_O),
                    (12.0, b""),
                ],
            ),
        }
    )
    for letter in "abcdefghijklmnopqrstuvwxyz":
        scenarios[f"slash_filter_{letter}"] = Scenario(
            f"filter slash palette with /{letter}",
            [(1.5, b"/"), (0.2, letter.encode("ascii"))],
        )
    return scenarios


def static_commands() -> dict[str, list[str]]:
    return {
        "version": ["--version"],
        "help": ["--help"],
        "help_subcommand": ["help"],
        "plugin_help": ["plugin", "--help"],
        "plugins_help": ["plugins", "--help"],
        "install_help": ["install", "--help"],
        "update_help": ["update", "--help"],
        "changelog_help": ["changelog", "--help"],
    }


def select_scenarios(mode: str, names: list[str]) -> dict[str, Scenario]:
    if mode == "full":
        scenarios = full_scenarios()
    elif mode == "deep":
        scenarios = deep_scenarios()
    else:
        scenarios = basic_scenarios()
    if not names:
        return scenarios
    missing = [name for name in names if name not in scenarios]
    if missing:
        available = ", ".join(sorted(scenarios))
        raise SystemExit(f"Unknown scenario(s): {', '.join(missing)}\nAvailable: {available}")
    return {name: scenarios[name] for name in names}


def capture_static_cli(agy: str, out_dir: Path) -> list[str]:
    static_dir = out_dir / "static_cli"
    static_dir.mkdir(parents=True, exist_ok=True)
    captured: list[str] = []
    for name, args in static_commands().items():
        path = static_dir / f"{name}.txt"
        command = [agy, *args]
        try:
            result = subprocess.run(
                command,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=30,
                check=False,
            )
            content = f"$ {' '.join(command)}\n\n{result.stdout}"
        except subprocess.TimeoutExpired as exc:
            content = f"$ {' '.join(command)}\n\nTIMEOUT after {exc.timeout}s\n"
        path.write_text(content, encoding="utf-8")
        captured.append(str(path))
    return captured


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--agy", default=DEFAULT_AGY)
    parser.add_argument("--out-dir", default="/tmp/secops_agi_fresh")
    parser.add_argument("--rows", type=int, default=28)
    parser.add_argument("--cols", type=int, default=100)
    parser.add_argument("--mode", choices=("basic", "deep", "full"), default="basic")
    parser.add_argument("--scenario", action="append", default=[], help="Capture only this scenario; repeatable.")
    parser.add_argument("--no-print-frames", action="store_true")
    parser.add_argument("--max-scenario-seconds", type=float, default=24.0)
    parser.add_argument("--skip-static", action="store_true")
    parser.add_argument("--redacted-summary", action="store_true", help="Write summary_redacted.md with account-like text redacted.")
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    cwd = Path.cwd()
    scenarios = select_scenarios(args.mode, args.scenario)
    out_dir.mkdir(parents=True, exist_ok=True)
    static_paths = [] if args.skip_static or args.scenario else capture_static_cli(args.agy, out_dir)
    manifest_lines = [
        f"mode: {args.mode}",
        f"cwd: {cwd}",
        f"rows: {args.rows}",
        f"cols: {args.cols}",
        "",
        "static_cli:",
        *[f"- {path}" for path in static_paths],
        "",
    ]

    for name, scenario in scenarios.items():
        print(f"capturing {name}: {scenario.description}", file=sys.stderr, flush=True)
        frame = run_capture(
            name,
            scenario,
            agy=args.agy,
            out_dir=out_dir,
            rows=args.rows,
            cols=args.cols,
            cwd=cwd,
            max_seconds=args.max_scenario_seconds,
        )
        manifest_lines.append(f"{name}: {scenario.description}")
        if not args.no_print_frames:
            print(f"\n=== {name} ===")
            print(frame)
    (out_dir / "manifest.txt").write_text("\n".join(manifest_lines) + "\n", encoding="utf-8")
    if args.redacted_summary:
        summary_lines = [
            "# AGY Capture Summary",
            "",
            f"mode: {args.mode}",
            f"rows: {args.rows}",
            f"cols: {args.cols}",
            "",
        ]
        for name in scenarios:
            frame_path = out_dir / f"agy_{name}_frame.txt"
            if not frame_path.exists():
                continue
            summary_lines.extend(
                [
                    f"## {name}",
                    "",
                    "```text",
                    redact_capture_text(frame_path.read_text(encoding="utf-8")),
                    "```",
                    "",
                ]
            )
        (out_dir / "summary_redacted.md").write_text("\n".join(summary_lines), encoding="utf-8")
    print(f"\nWrote captures to {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
