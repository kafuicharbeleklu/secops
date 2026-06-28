"""
Shared utility functions for the SecOps Agent.
Provides common helpers used across tool modules, UI components, and core logic.
"""

from __future__ import annotations

import asyncio
import inspect
import shlex
import shutil
from typing import Awaitable, Callable, Mapping, Tuple

from secops_agent.core.execution import ExecutionProgress, ExecutionSupervisor
from secops_agent.core.sandbox import validate_exec_command
from secops_agent.core.tools import report_tool_metadata

ProgressCallback = Callable[[str, float | None], Awaitable[None] | None]


async def run_cmd(
    cmd: list[str],
    timeout: int = 120,
    env: Mapping[str, str] | None = None,
    cwd: str | None = None,
) -> Tuple[str, str, int]:
    """
    Execute a shell command asynchronously.

    Args:
        cmd: Command and arguments as a list of strings.
        timeout: Maximum execution time in seconds.

    Returns:
        Tuple of (stdout, stderr, returncode).
    """
    check = validate_exec_command(cmd)
    if not check.allowed:
        return "", f"Sandbox blocked command: {check.reason}", 126

    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
            cwd=cwd,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return (
            stdout.decode("utf-8", errors="replace"),
            stderr.decode("utf-8", errors="replace"),
            proc.returncode or 0,
        )
    except asyncio.CancelledError:
        if proc:
            try:
                proc.kill()
            except Exception:
                pass
        raise
    except asyncio.TimeoutError:
        if proc:
            try:
                proc.kill()
            except Exception:
                pass
        return "", f"Command timed out after {timeout}s", 1
    except Exception as e:
        return "", str(e), 1


async def run_cmd_streaming(
    cmd: list[str],
    timeout: int = 120,
    env: Mapping[str, str] | None = None,
    cwd: str | None = None,
    progress: ProgressCallback | None = None,
    report_interval: float = 2.0,
    idle_interval: float = 3.0,
    progress_percent: float | None = 50,
    inactivity_timeout: int | float | None = None,
) -> Tuple[str, str, int]:
    """Execute a command while periodically reporting output and elapsed time."""
    check = validate_exec_command(cmd)
    if not check.allowed:
        return "", f"Sandbox blocked command: {check.reason}", 126

    async def emit(detail: str, percent: float | None = progress_percent) -> None:
        if not progress:
            return
        result = progress(detail, percent)
        if inspect.isawaitable(result):
            await result

    command = " ".join(shlex.quote(str(part)) for part in cmd)
    last_relay = 0.0

    async def relay(event: ExecutionProgress) -> None:
        nonlocal last_relay
        now = asyncio.get_running_loop().time()
        if event.phase == "receiving output":
            if report_interval > 0 and last_relay and now - last_relay < report_interval:
                return
            last_relay = now
        elif event.phase == "running":
            if idle_interval > 0 and last_relay and now - last_relay < idle_interval:
                return
            last_relay = now
        await emit(event.detail, 20 if event.phase == "process started" else progress_percent)

    result = await ExecutionSupervisor().run_shell(
        command,
        max_runtime=timeout,
        inactivity_timeout=inactivity_timeout,
        idle_interval=idle_interval,
        progress=relay,
        env=env,
        cwd=cwd,
    )
    report_tool_metadata("spool_path", str(result.spool_path))
    report_tool_metadata("stdout_path", str(result.stdout_path))
    report_tool_metadata("stderr_path", str(result.stderr_path))
    report_tool_metadata("execution_status", result.status)
    if result.timeout_reason:
        report_tool_metadata("timeout_reason", result.timeout_reason)
    if result.timed_out:
        if result.timeout_reason == "inactivity":
            timeout_msg = f"Command stopped after {inactivity_timeout}s without output"
        else:
            timeout_msg = f"Command timed out after {timeout}s"
        stderr = f"{result.stderr}\n{timeout_msg}\nSpool: {result.spool_path}".strip()
        return result.stdout, stderr, 1
    if result.status != "completed":
        return result.stdout, result.stderr or "Command failed before completion", 1
    return result.stdout, result.stderr, result.exit_code or 0


def is_tool_installed(name: str) -> bool:
    """Check if a shell command/tool exists in PATH."""
    return shutil.which(name) is not None


def truncate_text(text: str, max_len: int = 100) -> str:
    """Truncate text safely with ellipsis."""
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def sanitize_output(text: str) -> str:
    """Strip excessive whitespace from output."""
    return text.strip()
