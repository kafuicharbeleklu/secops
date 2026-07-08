#!/usr/bin/env python3
"""Live TUI audit: drive a full realistic turn (thinking -> tool card -> tall
streaming answer -> done) through the real renderer over a PTY, then replay the
raw bytes through a bounded screen+scrollback emulator and count EVERY class of
duplication at once:

  * MARKER_ALPHA copies         -> Example F (streaming cascade)   expect 1
  * '● vpn_status' rows         -> tool-card echo (audit §7.8)     expect 1
  * '⎿' collapsed result rows   -> result-line echo                expect 1
  * 'Thought for'/'Analyzing'   -> thinking accumulation (Ex. C)   expect 1 per turn

Usage:  repro_turn_duplication.py [--repeat N]
Exit 0 iff every count matches expectation.
"""
from __future__ import annotations
import fcntl, os, pty, re, select, struct, sys, termios, time, subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ROWS, COLS = 28, 100
REPEAT = int(sys.argv[sys.argv.index("--repeat") + 1]) if "--repeat" in sys.argv else 1

SCRIPT = f'''
import asyncio
from secops_agent.core.agent import (TextEvent, ThinkingEvent, ToolCallEvent, ToolResultEvent)
from secops_agent.core.tools import ToolResult
from secops_agent.ui.renderer import Renderer

LINES = ["# MARKER_ALPHA Informations systeme", ""]
for i in range(1, 38):
    LINES.append(f"- ligne numero {{i:02d}} du rapport systeme detaille")
BODY = "\\n".join(LINES)
VPN_OUT = "tun0: flags=4305<UP,POINTOPOINT,RUNNING> inet 10.8.0.3 netmask 255.255.255.255\\n[Exit Code: 0]"

async def one_turn():
    yield ThinkingEvent("Analyzing the request")
    await asyncio.sleep(0.1)
    yield ToolCallEvent("vpn_status", {{}}, "t1")
    await asyncio.sleep(0.05)
    yield ToolResultEvent("vpn_status", ToolResult(success=True, output=VPN_OUT, execution_time=0.03), "t1")
    await asyncio.sleep(0.05)
    step = max(1, len(BODY) // 30)
    for i in range(0, len(BODY), step):
        yield TextEvent(BODY[i:i+step])
        await asyncio.sleep(0.02)
    yield TextEvent("", done=True)

async def main():
    r = Renderer()
    for _ in range({REPEAT}):
        await r.render_agent_stream(one_turn())

asyncio.run(main())
'''.strip()

_CSI = re.compile(rb"\x1b\[([0-9;?]*)([A-Za-z])")

def emulate(raw: bytes) -> list[str]:
    screen = [""] * ROWS
    scrollback: list[str] = []
    row = col = 0
    i, n = 0, len(raw)
    while i < n:
        b = raw[i]
        if b == 0x1B and i + 1 < n and raw[i + 1] == ord("["):
            m = _CSI.match(raw, i)
            if not m:
                i += 1; continue
            nums = [int(x) for x in m.group(1).decode().split(";") if x.isdigit()]
            final = m.group(2).decode(); a = nums[0] if nums else None
            if final == "A": row = max(0, row - (a or 1))
            elif final == "B": row = min(ROWS - 1, row + (a or 1))
            elif final == "G": col = max(0, (a or 1) - 1)
            elif final == "H":
                row = min(ROWS - 1, max(0, (nums[0] - 1) if nums else 0))
                col = max(0, (nums[1] - 1) if len(nums) > 1 else 0)
            elif final == "K":
                if (a or 0) == 0: screen[row] = screen[row][:col]
                elif a == 2: screen[row] = ""
            elif final == "J":
                mode = a or 0
                if mode == 0:
                    screen[row] = screen[row][:col]
                    for r in range(row + 1, ROWS): screen[r] = ""
                elif mode == 2: screen = [""] * ROWS
            i = m.end(); continue
        if b == 0x1B and i + 1 < n and raw[i + 1] == ord("]"):
            j = raw.find(b"\x07", i); i = (j + 1) if j != -1 else n; continue
        ch = chr(b)
        if ch == "\r": col = 0
        elif ch == "\n":
            if row < ROWS - 1: row += 1
            else:
                scrollback.append(screen.pop(0)); screen.append("")
        elif ch == "\x08": col = max(0, col - 1)
        elif b >= 0x20:
            frag = bytearray([b])
            while i + 1 < n and raw[i + 1] >= 0x20 and raw[i + 1] != 0x1B:
                i += 1; frag.append(raw[i])
            text = frag.decode("utf-8", "ignore")
            ln = screen[row]
            if len(ln) < col: ln = ln + " " * (col - len(ln))
            screen[row] = ln[:col] + text + ln[col + len(text):]
            col += len(text)
        i += 1
    return scrollback + screen

def main() -> int:
    master_fd, slave_fd = pty.openpty()
    fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLS, 0, 0))
    env = os.environ.copy(); env.setdefault("TERM", "xterm-256color")
    proc = subprocess.Popen([str(REPO / ".venv/bin/python"), "-c", SCRIPT],
        stdin=slave_fd, stdout=slave_fd, stderr=slave_fd, cwd=str(REPO), env=env, close_fds=True)
    os.close(slave_fd)
    chunks: list[bytes] = []; started = time.monotonic()
    while time.monotonic() - started < 15:
        ready, _, _ = select.select([master_fd], [], [], 0.05)
        if ready:
            try: data = os.read(master_fd, 8192)
            except OSError: break
            if not data: break
            chunks.append(data)
        if proc.poll() is not None: break
    if proc.poll() is None: proc.terminate()
    try: os.close(master_fd)
    except OSError: pass
    buf = emulate(b"".join(chunks))
    marker = sum(1 for ln in buf if "MARKER_ALPHA" in ln)
    tool = sum(1 for ln in buf if "vpn_status" in ln and "●" in ln)
    result_rows = sum(1 for ln in buf if "⎿" in ln)
    thought = sum(1 for ln in buf if "Thought for" in ln or "Analyzing" in ln)
    body = sum(1 for ln in buf if "ligne numero" in ln)
    exp_marker, exp_tool, exp_thought, exp_body = REPEAT, REPEAT, REPEAT, 37 * REPEAT
    print(f"repeat={REPEAT}")
    print(f"  MARKER_ALPHA copies : {marker:3}  (expect {exp_marker})  {'OK' if marker==exp_marker else 'DUP!'}")
    print(f"  ● vpn_status rows   : {tool:3}  (expect {exp_tool})  {'OK' if tool==exp_tool else 'DUP!'}")
    print(f"  ⎿ result rows       : {result_rows:3}  (expect ~{exp_tool})")
    print(f"  Thought/Analyzing   : {thought:3}  (expect {exp_thought})  {'OK' if thought==exp_thought else 'DUP!'}")
    print(f"  body lines          : {body:3}  (expect {exp_body})  {'OK' if body==exp_body else 'MISS'}")
    ok = marker == exp_marker and tool == exp_tool and thought == exp_thought and body == exp_body
    if "--dump" in sys.argv:
        print("\n----- final frame (screen+scrollback) -----")
        for ln in buf:
            if ln.strip(): print("|", ln)
    print("PASS" if ok else "FAIL: duplication present")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
