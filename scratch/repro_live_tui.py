#!/usr/bin/env python3
"""Drive the REAL secops TUI live over a PTY, capture ALL raw bytes, replay
through a scrollback-keeping emulator, and count duplication of distinctive
lines (Example F: streaming cascade; tool-card echo). Uses the real API key
from .env. Live model is flaky (500s) -> retries the prompt a couple of times.

Usage: repro_live_tui.py "prompt one" ["prompt two" ...]
"""
from __future__ import annotations
import fcntl, os, pty, re, select, struct, sys, termios, time, subprocess
from pathlib import Path
from collections import Counter

REPO = Path(__file__).resolve().parent.parent
ROWS, COLS = 30, 100

def load_key() -> str:
    for line in (REPO / ".env").read_text().splitlines():
        m = re.match(r"GEMINI_API_KEY=(.*)", line.strip())
        if m:
            return m.group(1).strip().strip('"').strip("'")
    return ""

_CSI = re.compile(rb"\x1b\[([0-9;?]*)([A-Za-z])")

def emulate(raw: bytes):
    screen = [""] * ROWS; scrollback: list[str] = []; row = col = 0
    i, n = 0, len(raw)
    while i < n:
        b = raw[i]
        if b == 0x1B and i + 1 < n and raw[i + 1] == ord("["):
            m = _CSI.match(raw, i)
            if not m: i += 1; continue
            nums = [int(x) for x in m.group(1).decode(errors="ignore").split(";") if x.isdigit()]
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
        ch = chr(b) if b < 128 else ""
        if ch == "\r": col = 0
        elif ch == "\n":
            if row < ROWS - 1: row += 1
            else: scrollback.append(screen.pop(0)); screen.append("")
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

def read_available(fd, timeout):
    out = b""; end = time.monotonic() + timeout
    while time.monotonic() < end:
        r, _, _ = select.select([fd], [], [], 0.1)
        if r:
            try: d = os.read(fd, 65536)
            except OSError: break
            if not d: break
            out += d
        else:
            if out: break
    return out

def main() -> int:
    prompts = sys.argv[1:] or ["donne moi mes informations systeme"]
    key = load_key()
    master_fd, slave_fd = pty.openpty()
    fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLS, 0, 0))
    env = os.environ.copy()
    env["TERM"] = "xterm-256color"; env["GEMINI_API_KEY"] = key
    env["SECOPS_HISTORY_DIR"] = "/tmp/secops-live-history"
    proc = subprocess.Popen([str(REPO / "secops")], stdin=slave_fd, stdout=slave_fd,
        stderr=slave_fd, cwd=str(REPO), env=env, close_fds=True)
    os.close(slave_fd)
    fcntl.fcntl(master_fd, fcntl.F_SETFL, fcntl.fcntl(master_fd, fcntl.F_GETFL) | os.O_NONBLOCK)
    all_raw = bytearray()
    boot = read_available(master_fd, 12); all_raw += boot   # wait for banner + prompt
    for prompt in prompts:
        got_answer = False
        for attempt in range(2):
            os.write(master_fd, prompt.encode() + b"\r")
            # read until quiet for a while, up to 75s (accommodate backoff)
            end = time.monotonic() + 75; quiet_since = None
            while time.monotonic() < end:
                d = read_available(master_fd, 1.0)
                if d:
                    all_raw += d; quiet_since = None
                    low = d.decode("utf-8", "ignore").lower()
                    if "informations" in low or "il reste" in low or "phase" in low or "pentest" in low:
                        got_answer = True
                else:
                    if quiet_since is None: quiet_since = time.monotonic()
                    elif time.monotonic() - quiet_since > 3.5:
                        break
                if proc.poll() is not None: break
            if got_answer: break
            time.sleep(1)
        time.sleep(0.5)
    try: os.write(master_fd, b"/exit\r"); time.sleep(0.5); all_raw += read_available(master_fd, 2)
    except OSError: pass
    if proc.poll() is None: proc.terminate()
    try: os.close(master_fd)
    except OSError: pass

    buf = emulate(bytes(all_raw))
    print(f"=== FINAL EMULATED SCREEN+SCROLLBACK ({len(buf)} lines) ===")
    for ln in buf:
        if ln.strip(): print("|", ln.rstrip())
    # duplication signals: repeated non-trivial content lines
    norm = [re.sub(r"\s+", " ", ln.strip()) for ln in buf if len(ln.strip()) > 25]
    dup = {k: v for k, v in Counter(norm).items() if v > 1}
    print("\n=== REPEATED CONTENT LINES (>1 occurrence, len>25) ===")
    if not dup: print("  none — no visible duplication")
    for k, v in sorted(dup.items(), key=lambda x: -x[1])[:20]:
        print(f"  x{v}: {k[:90]}")
    tool_cards = Counter(re.sub(r"\(.*", "", ln.strip()) for ln in buf if "●" in ln)
    print("\n=== TOOL CARD (●) ROWS ===")
    for k, v in tool_cards.items(): print(f"  x{v}: {k.strip()}")
    print(f"\nraw bytes captured: {len(all_raw)}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
