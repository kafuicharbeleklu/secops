"""
Sudo capability checks and secure local authentication helpers.

The password path is deliberately local-only: callers receive success/failure
metadata, never the password or raw sudo output.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import os
import pty
import select
import shutil
import subprocess
import sys
import time
from typing import Callable

from secops_agent.core.shell_analysis import analyze_shell_command


@dataclass
class SudoAuthenticationDecision:
    success: bool
    reason: str = ""


def command_uses_sudo(command: str) -> bool:
    return analyze_shell_command(command).uses_sudo


def format_sudo_interactive_reason(stderr: str) -> str:
    detail = " ".join(str(stderr or "").strip().split())
    if not detail:
        return "sudo requires interactive authentication"

    normalized = detail.casefold()
    interactive_markers = (
        "a terminal is required",
        "a password is required",
        "password is required",
        "no tty",
        "must have a tty",
        "read the password",
    )
    if any(marker in normalized for marker in interactive_markers):
        return "sudo requires interactive authentication"

    return f"sudo requires interactive authentication: {detail[:180]}"


async def sudo_noninteractive_status() -> tuple[bool, str]:
    if not shutil.which("sudo"):
        return False, "sudo is not installed"
    process = await asyncio.create_subprocess_exec(
        "sudo",
        "-n",
        "true",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        _, stderr = await asyncio.wait_for(process.communicate(), timeout=5)
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        return False, "sudo non-interactive check timed out"
    if process.returncode == 0:
        return True, "sudo non-interactive authentication is available"
    return False, format_sudo_interactive_reason(stderr.decode("utf-8", errors="replace"))


def can_prompt_for_sudo() -> bool:
    return bool(shutil.which("sudo") and sys.stdin.isatty() and sys.stdout.isatty())


async def authenticate_sudo_with_password(
    password_reader: Callable[[str], str],
    *,
    timeout: int = 30,
) -> SudoAuthenticationDecision:
    """Read a password locally and cache credentials for non-interactive tools."""
    if not shutil.which("sudo"):
        return SudoAuthenticationDecision(False, "sudo is not installed")
    try:
        password = await asyncio.to_thread(password_reader, "sudo password: ")
    except (EOFError, KeyboardInterrupt):
        return SudoAuthenticationDecision(False, "sudo authentication cancelled")
    except Exception as exc:
        return SudoAuthenticationDecision(False, f"sudo password prompt failed: {exc}")

    if not password:
        return SudoAuthenticationDecision(False, "sudo password was empty")

    try:
        return await asyncio.to_thread(_validate_sudo_password, password, timeout)
    finally:
        password = ""


def _validate_sudo_password(password: str, timeout: int) -> SudoAuthenticationDecision:
    stdin_decision = _validate_sudo_password_with_stdin(password, timeout)
    if stdin_decision.success or "password was accepted" in stdin_decision.reason:
        return stdin_decision

    pty_decision = _validate_sudo_password_with_pty(password, timeout)
    if not pty_decision.success:
        return pty_decision

    verified, reason = _verify_sudo_noninteractive_ticket()
    if verified:
        return pty_decision
    return SudoAuthenticationDecision(
        False,
        "sudo authentication was accepted only for the password prompt terminal; "
        f"non-interactive tools still cannot use sudo. {reason}",
    )


def _validate_sudo_password_with_stdin(password: str, timeout: int) -> SudoAuthenticationDecision:
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            ["sudo", "-S", "-p", "", "-v"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
        )
        _, stderr = process.communicate(
            input=(password + "\n").encode("utf-8", errors="ignore"),
            timeout=max(1, int(timeout)),
        )
    except subprocess.TimeoutExpired:
        if process is not None:
            process.kill()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
        return SudoAuthenticationDecision(False, "sudo authentication timed out")
    except OSError as exc:
        return SudoAuthenticationDecision(False, f"sudo stdin authentication failed: {exc}")

    if process.returncode != 0:
        return SudoAuthenticationDecision(False, "sudo authentication failed")

    verified, reason = _verify_sudo_noninteractive_ticket()
    if verified:
        return SudoAuthenticationDecision(True, "sudo authentication cached")
    return SudoAuthenticationDecision(
        False,
        f"sudo password was accepted, but non-interactive sudo is still unavailable. {reason}",
    )


def _verify_sudo_noninteractive_ticket() -> tuple[bool, str]:
    try:
        result = subprocess.run(
            ["sudo", "-n", "true"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return False, "sudo non-interactive verification timed out"
    except OSError as exc:
        return False, f"sudo non-interactive verification failed: {exc}"

    if result.returncode == 0:
        return True, "sudo non-interactive authentication is available"
    stderr = result.stderr.decode("utf-8", errors="replace") if isinstance(result.stderr, bytes) else str(result.stderr or "")
    return False, format_sudo_interactive_reason(stderr)


def _validate_sudo_password_with_pty(password: str, timeout: int) -> SudoAuthenticationDecision:
    master_fd, slave_fd = pty.openpty()
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            ["sudo", "-S", "-p", "", "-v"],
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            close_fds=True,
            start_new_session=True,
        )
        os.close(slave_fd)
        slave_fd = -1
        os.write(master_fd, (password + "\n").encode("utf-8", errors="ignore"))

        deadline = time.monotonic() + max(1, int(timeout))
        while process.poll() is None and time.monotonic() < deadline:
            ready, _, _ = select.select([master_fd], [], [], 0.05)
            if ready:
                try:
                    os.read(master_fd, 4096)
                except OSError:
                    break

        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=1)
            return SudoAuthenticationDecision(False, "sudo authentication timed out")

        if process.returncode == 0:
            return SudoAuthenticationDecision(True, "sudo authentication cached")
        return SudoAuthenticationDecision(False, "sudo authentication failed")
    except OSError as exc:
        return SudoAuthenticationDecision(False, f"sudo PTY authentication failed: {exc}")
    finally:
        if slave_fd >= 0:
            try:
                os.close(slave_fd)
            except OSError:
                pass
        try:
            os.close(master_fd)
        except OSError:
            pass
