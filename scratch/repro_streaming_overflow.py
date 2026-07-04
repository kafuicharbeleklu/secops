"""End-to-end regression harness for Example F (streaming text duplication).

Streams a markdown answer TALLER than the viewport through the real renderer over
a 28-row PTY, then replays the raw output through a bounded screen + scrollback
emulator (the key real-terminal constraint: cursor-up clamps at the top visible
row and cannot re-enter scrollback). It counts how many times an early marker
line is visible when scrolling up.

  Before the fix (vertical_overflow="visible"): ~6 copies (the cascade).
  After  the fix (_streaming_tail + "crop"):      1 copy.

Run:  .venv/bin/python scratch/repro_streaming_overflow.py
Exit: 0 if exactly one copy (clean), 1 if the cascade regressed.

The pure tail-cropping logic is unit-tested in tests/test_streaming_overflow.py;
this proves the end-to-end rendering has no scrollback duplication.
"""
from __future__ import annotations

import fcntl
import os
import pty
import re
import select
import struct
import sys
import termios
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ROWS, COLS = 28, 100

SCRIPT = r'''
import asyncio
from secops_agent.core.agent import TextEvent, ThinkingEvent
from secops_agent.ui.renderer import Renderer

LINES = ["# MARKER_ALPHA Informations systeme", ""]
for i in range(1, 38):
    LINES.append(f"- ligne numero {i:02d} du rapport systeme detaille")
BODY = "\n".join(LINES)

async def events():
    yield ThinkingEvent("Analyzing")
    await asyncio.sleep(0.1)
    step = max(1, len(BODY) // 30)
    for i in range(0, len(BODY), step):
        yield TextEvent(BODY[i:i+step])
        await asyncio.sleep(0.02)
    yield TextEvent("", done=True)

async def main():
    await Renderer().render_agent_stream(events())

asyncio.run(main())
'''.strip()

_CSI = re.compile(rb"\x1b\[([0-9;?]*)([A-Za-z])")


def emulate(raw: bytes) -> list[str]:
    """Minimal xterm emulator with a bounded screen and permanent scrollback."""
    screen = [""] * ROWS
    scrollback: list[str] = []
    row = col = 0
    i, n = 0, len(raw)
    while i < n:
        b = raw[i]
        if b == 0x1B and i + 1 < n and raw[i + 1] == ord("["):
            m = _CSI.match(raw, i)
            if not m:
                i += 1
                continue
            nums = [int(x) for x in m.group(1).decode().split(";") if x.isdigit()]
            final = m.group(2).decode()
            a = nums[0] if nums else None
            if final == "A":
                row = max(0, row - (a or 1))            # clamp at top visible row
            elif final == "B":
                row = min(ROWS - 1, row + (a or 1))
            elif final == "G":
                col = max(0, (a or 1) - 1)
            elif final == "H":
                row = min(ROWS - 1, max(0, (nums[0] - 1) if nums else 0))
                col = max(0, (nums[1] - 1) if len(nums) > 1 else 0)
            elif final == "K":
                if (a or 0) == 0:
                    screen[row] = screen[row][:col]
                elif a == 2:
                    screen[row] = ""
            elif final == "J":
                mode = a or 0
                if mode == 0:
                    screen[row] = screen[row][:col]
                    for r in range(row + 1, ROWS):
                        screen[r] = ""
                elif mode == 2:
                    screen = [""] * ROWS
            i = m.end()
            continue
        if b == 0x1B and i + 1 < n and raw[i + 1] == ord("]"):
            j = raw.find(b"\x07", i)
            i = (j + 1) if j != -1 else n
            continue
        ch = chr(b)
        if ch == "\r":
            col = 0
        elif ch == "\n":
            if row < ROWS - 1:
                row += 1
            else:
                scrollback.append(screen.pop(0))
                screen.append("")
        elif ch == "\x08":
            col = max(0, col - 1)
        elif b >= 0x20:
            frag = bytearray([b])
            while i + 1 < n and raw[i + 1] >= 0x20 and raw[i + 1] != 0x1B:
                i += 1
                frag.append(raw[i])
            text = frag.decode("utf-8", "ignore")
            ln = screen[row]
            if len(ln) < col:
                ln = ln + " " * (col - len(ln))
            screen[row] = ln[:col] + text + ln[col + len(text):]
            col += len(text)
        i += 1
    return scrollback + screen


def main() -> int:
    master_fd, slave_fd = pty.openpty()
    fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLS, 0, 0))
    env = os.environ.copy()
    env.setdefault("TERM", "xterm-256color")
    import subprocess
    proc = subprocess.Popen(
        [str(REPO / ".venv/bin/python"), "-c", SCRIPT],
        stdin=slave_fd, stdout=slave_fd, stderr=slave_fd, cwd=str(REPO), env=env, close_fds=True,
    )
    os.close(slave_fd)
    chunks: list[bytes] = []
    started = time.monotonic()
    while time.monotonic() - started < 8:
        ready, _, _ = select.select([master_fd], [], [], 0.05)
        if ready:
            try:
                data = os.read(master_fd, 8192)
            except OSError:
                break
            if not data:
                break
            chunks.append(data)
        if proc.poll() is not None:
            break
    if proc.poll() is None:
        proc.terminate()
    try:
        os.close(master_fd)
    except OSError:
        pass
    buf = emulate(b"".join(chunks))
    marker = sum(1 for ln in buf if "MARKER_ALPHA" in ln)
    body = sum(1 for ln in buf if "ligne numero" in ln)
    ok = marker == 1 and body == 37
    print(f"MARKER_ALPHA copies (scrollback+screen): {marker}   body lines: {body}/37")
    print("PASS: no streaming duplication" if ok else "FAIL: Example F cascade present")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
