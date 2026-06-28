#!/usr/bin/env python3
"""Capture AGY's permission prompt with a temporary request-review setting."""

from __future__ import annotations

import argparse
import json
import os
import pty
import select
import signal
import struct
import subprocess
import sys
import termios
import time
import fcntl
from pathlib import Path

from scratch.tui_smoke import CPR_QUERY, clean_text, terminal_screen_text


DEFAULT_AGY = Path("/home/administrator/.local/bin/agy")
DEFAULT_SETTINGS = Path.home() / ".gemini" / "antigravity-cli" / "settings.json"
DEFAULT_PROMPT = "Run only the pwd command and wait for my approval if required."
DEFAULT_MODE = "request-review"
SUPPORTED_MODES = ("request-review", "proceed-in-sandbox", "always-proceed", "strict")


def set_pty_size(fd: int, rows: int, cols: int) -> None:
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))


def read_for(master_fd: int, seconds: float, *, row: int) -> bytes:
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
            os.write(master_fd, f"\x1b[{row};1R".encode("ascii"))
    return bytes(raw)


def read_until_text(master_fd: int, marker: str, seconds: float, *, row: int) -> bytes:
    deadline = time.monotonic() + seconds
    raw = bytearray()
    while time.monotonic() < deadline:
        raw.extend(read_for(master_fd, min(0.5, max(0.0, deadline - time.monotonic())), row=row))
        if marker in clean_text(bytes(raw)):
            break
    return bytes(raw)


def set_tool_permission(settings_path: Path, mode: str) -> bytes:
    original = settings_path.read_bytes()
    data = json.loads(original.decode("utf-8"))
    data["toolPermission"] = mode
    settings_path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return original


def output_stem(mode: str) -> str:
    return f"agy_permission_prompt_{mode.replace('-', '_')}"


def capture_prompt(
    *,
    agy: Path,
    settings_path: Path,
    out_dir: Path,
    rows: int,
    cols: int,
    prompt: str,
    mode: str,
    max_seconds: float,
) -> int:
    original_settings = set_tool_permission(settings_path, mode)
    master_fd: int | None = None
    process: subprocess.Popen[bytes] | None = None
    raw = bytearray()
    try:
        master_fd, slave_fd = pty.openpty()
        set_pty_size(slave_fd, rows, cols)
        env = os.environ.copy()
        env.setdefault("TERM", "xterm-256color")
        env.setdefault("COLORTERM", "truecolor")
        process = subprocess.Popen(
            [str(agy)],
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            cwd=Path.cwd(),
            env=env,
            close_fds=True,
            start_new_session=True,
        )
        os.close(slave_fd)
        flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
        fcntl.fcntl(master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

        raw.extend(read_until_text(master_fd, "? for shortcuts", 20.0, row=rows))
        time.sleep(0.2)
        os.write(master_fd, prompt.encode("utf-8") + b"\r")
        raw.extend(read_for(master_fd, max_seconds, row=rows))

        try:
            os.write(master_fd, b"\x1b")
            raw.extend(read_for(master_fd, 1.0, row=rows))
        except OSError:
            pass
    finally:
        if process and process.poll() is None:
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
        if master_fd is not None:
            try:
                os.close(master_fd)
            except OSError:
                pass
        settings_path.write_bytes(original_settings)

    out_dir.mkdir(parents=True, exist_ok=True)
    raw_payload = bytes(raw)
    stem = output_stem(mode)
    (out_dir / f"{stem}.bin").write_bytes(raw_payload)
    (out_dir / f"{stem}.txt").write_text(
        clean_text(raw_payload),
        encoding="utf-8",
    )
    (out_dir / f"{stem}_frame.txt").write_text(
        terminal_screen_text(raw_payload, rows=rows, cols=cols),
        encoding="utf-8",
    )
    restored_payload = settings_path.read_bytes()
    restored = json.loads(restored_payload.decode("utf-8")).get("toolPermission")
    print(f"mode={mode}")
    print(f"restored_toolPermission={restored}")
    print(f"wrote={out_dir}")
    text = clean_text(raw_payload)
    prompt_seen = any(
        marker in text.lower()
        for marker in (
            "permission",
            "approve",
            "allow",
            "deny",
            "requested",
        )
    )
    print(f"permission_text_seen={str(prompt_seen).lower()}")
    return 0 if restored_payload == original_settings else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--agy", type=Path, default=DEFAULT_AGY)
    parser.add_argument("--settings", type=Path, default=DEFAULT_SETTINGS)
    parser.add_argument("--out-dir", type=Path, default=Path("/tmp/secops_agy_permission_prompt"))
    parser.add_argument("--rows", type=int, default=34)
    parser.add_argument("--cols", type=int, default=120)
    parser.add_argument("--prompt", default=DEFAULT_PROMPT)
    parser.add_argument("--mode", choices=SUPPORTED_MODES, default=DEFAULT_MODE)
    parser.add_argument("--max-seconds", type=float, default=45.0)
    args = parser.parse_args()
    return capture_prompt(
        agy=args.agy,
        settings_path=args.settings,
        out_dir=args.out_dir,
        rows=args.rows,
        cols=args.cols,
        prompt=args.prompt,
        mode=args.mode,
        max_seconds=args.max_seconds,
    )


if __name__ == "__main__":
    raise SystemExit(main())
