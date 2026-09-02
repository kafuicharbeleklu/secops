#!/usr/bin/env python3
"""Live check of the ctrl+o cascade fix against the REAL secops TUI.

Launches the TUI over a pty with the real key, asks for system info (drives the
sysinfo tool -> a ~46-line output), waits for the turn to settle, then presses
ctrl+o several times and replays every byte through a pyte terminal to count how
many '● Sysinfo' cards actually remain. Clean == at most one card visible.
"""
from __future__ import annotations
import fcntl, os, pty, re, select, struct, sys, termios, time
from pathlib import Path
import pyte

REPO = Path(__file__).resolve().parent.parent
ROWS, COLS = int(os.environ.get("ROWS", "40")), 100

def load_key() -> str:
    for line in (REPO / ".env").read_text().splitlines():
        m = re.match(r"GEMINI_API_KEY=(.*)", line.strip())
        if m:
            return m.group(1).strip().strip('"').strip("'")
    return ""

def run(prompt: str, toggles: int = 6, budget: float = 150.0):
    key = load_key()
    if not key:
        print("NO API KEY"); return 2
    pid, fd = pty.fork()
    if pid == 0:
        os.environ.update({
            "GEMINI_API_KEY": key, "PYTHONDONTWRITEBYTECODE": "1",
            "TERM": "xterm-256color", "COLUMNS": str(COLS), "LINES": str(ROWS),
        })
        os.chdir(REPO)
        os.execv(str(REPO / ".venv/bin/python"), [
            str(REPO / ".venv/bin/python"), "-m", "secops_agent.main",
            "--permission-mode", "always-proceed",
        ])
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLS, 0, 0))

    screen = pyte.HistoryScreen(COLS, ROWS, history=5000, ratio=0.5)
    stream = pyte.ByteStream(screen)
    raw = bytearray()

    def pump(seconds: float):
        end = time.time() + seconds
        while time.time() < end:
            r, _, _ = select.select([fd], [], [], 0.2)
            if fd in r:
                try:
                    data = os.read(fd, 65536)
                except OSError:
                    return False
                if not data:
                    return False
                raw.extend(data); stream.feed(data)
        return True

    def visible() -> str:
        return "\n".join(screen.display)

    pump(6)                                  # banner / prompt
    os.write(fd, prompt.encode() + b"\r")
    # wait for the turn to finish: idle statusline and a rendered Sysinfo card
    deadline = time.time() + budget
    settled = False
    while time.time() < deadline:
        pump(3)
        v = visible()
        if "Sysinfo" in v or "ctrl+o" in v:
            settled = True
            pump(6)                          # let the turn finish + anchor install
            break
    if not settled:
        print("!! no tool card appeared (model flaky?) — inspect below")

    print("--- screen BEFORE toggles ---")
    for line in screen.display:
        if line.strip():
            print("   " + line.rstrip()[:96])
    before_cards = sum(1 for r in screen.display if "Sysinfo(" in r)
    for _ in range(toggles):
        os.write(fd, b"\x0f")                # ctrl+o
        pump(1.2)
    after_cards = sum(1 for r in screen.display if "Sysinfo(" in r)

    hist = ["".join(c.data for c in ln.values()) for ln in screen.history.top]
    orphans = sum(1 for r in hist + list(screen.display) if "Sysinfo(" in r)

    v = visible()
    print("--- screen AFTER toggles ---")
    for line in screen.display:
        if line.strip():
            print("   " + line.rstrip()[:96])

    os.write(fd, b"/exit\r"); pump(2)
    try: os.close(fd)
    except OSError: pass

    print(f"settled={settled} toggles={toggles} rows={ROWS}")
    print(f"  cards visible BEFORE toggles : {before_cards}")
    print(f"  cards visible AFTER  toggles : {after_cards}   (clean: <= 1)")
    print(f"  cards in scrollback+screen   : {orphans}   (clean: small, not ~toggles)")
    print(f"  too-tall hint shown          : {'Output too tall' in ''.join(hist) + v}")
    print("--- summary ---")
    return 0 if after_cards <= 1 else 1

if __name__ == "__main__":
    sys.exit(run(sys.argv[1] if len(sys.argv) > 1 else "give me my system information"))
