import os
import pty
import sys
import time
import select
import subprocess
import signal
import fcntl
import termios
import struct

def set_pty_size(fd, rows, cols):
    size = struct.pack("HHHH", rows, cols, 0, 0)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, size)

def main():
    signal.signal(signal.SIGTTOU, signal.SIG_IGN)
    signal.signal(signal.SIGTTIN, signal.SIG_IGN)

    master_fd, slave_fd = pty.openpty()
    set_pty_size(slave_fd, 24, 80)
    
    env = os.environ.copy()
    env["TERM"] = "xterm-256color"
    env["GEMINI_API_KEY"] = "dummy_key_to_bypass_check"
    
    p = subprocess.Popen(
        ["./.venv/bin/secops"],
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        env=env,
        close_fds=True
    )
    
    os.close(slave_fd)
    
    fl = fcntl.fcntl(master_fd, fcntl.F_GETFL)
    fcntl.fcntl(master_fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
    
    output = []
    
    # Wait for prompt ">"
    start_time = time.time()
    prompt_detected = False
    while time.time() - start_time < 8:
        r, w, x = select.select([master_fd], [], [], 0.1)
        if r:
            try:
                data = os.read(master_fd, 4096)
                if not data:
                    break
                output.append(data)
                decoded = data.decode("utf-8", errors="ignore")
                if ">" in decoded:
                    prompt_detected = True
                    break
            except OSError:
                break
                
    if prompt_detected:
        print("[Script] Prompt detected! Sending / to trigger completions...")
        os.write(master_fd, b"/")
        time.sleep(0.5)
        
        # Trigger autocomplete
        os.write(master_fd, b"\t")
        time.sleep(1)
        
        # Read the resulting scrollback to see our dropdown menu and footer
        start_time = time.time()
        while time.time() - start_time < 3:
            r, w, x = select.select([master_fd], [], [], 0.1)
            if r:
                try:
                    data = os.read(master_fd, 4096)
                    if not data:
                        break
                    output.append(data)
                except OSError:
                    break
                    
    p.terminate()
    try:
        p.wait(timeout=1)
    except subprocess.TimeoutExpired:
        p.kill()
        
    raw_output = b"".join(output)
    # Write to a raw log
    with open("/home/administrator/secops_v2/completions_scrollback.bin", "wb") as f:
        f.write(raw_output)
    print("\nCaptured scrollback length:", len(raw_output))

if __name__ == "__main__":
    main()
