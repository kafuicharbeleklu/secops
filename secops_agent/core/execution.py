"""
Supervised local process execution for long-running tools.

This module owns process lifecycle, output spooling, idle tracking, and clean
termination. It deliberately does not make permission decisions.
"""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass
from datetime import datetime, timezone
import inspect
import os
from pathlib import Path
import signal
import uuid
from typing import Awaitable, Callable, Mapping

from secops_agent.config import settings


@dataclass
class ExecutionProgress:
    phase: str
    detail: str = ""
    percent: float | None = None


@dataclass
class SupervisedProcessResult:
    command: str
    status: str
    stdout: str
    stderr: str
    exit_code: int | None
    execution_time: float
    output_lines: int
    output_chars: int
    spool_path: Path
    stdout_path: Path
    stderr_path: Path
    timeout_reason: str = ""

    @property
    def timed_out(self) -> bool:
        return self.status == "timed_out"

    @property
    def failed(self) -> bool:
        return self.status not in {"completed"} or (self.exit_code not in {0, None})


ProgressCallback = Callable[[ExecutionProgress], Awaitable[None] | None]


class ExecutionSupervisor:
    """Run shell commands as supervised tasks with spool files and progress."""

    def __init__(
        self,
        *,
        run_dir: str | Path | None = None,
        max_capture_chars: int | None = None,
    ) -> None:
        self.run_dir = Path(run_dir).expanduser() if run_dir else _default_run_dir()
        self.max_capture_chars = max(1, int(max_capture_chars or 50_000))

    async def run_shell(
        self,
        command: str,
        *,
        max_runtime: int | float | None,
        inactivity_timeout: int | float | None = 120,
        idle_interval: int | float = 1.0,
        progress: ProgressCallback | None = None,
        env: Mapping[str, str] | None = None,
        cwd: str | None = None,
    ) -> SupervisedProcessResult:
        """Execute a shell command and supervise process lifecycle."""
        paths = self._new_spool_paths("shell")
        loop = asyncio.get_running_loop()
        started_at = loop.time()
        last_output_at = started_at
        proc: asyncio.subprocess.Process | None = None
        stdout_chunks: list[bytes] = []
        stderr_chunks: list[bytes] = []
        captured_stdout = 0
        captured_stderr = 0
        output_lines = 0
        output_chars = 0
        last_output_report = 0.0
        last_stream_label = ""

        async def emit(phase: str, detail: str = "", percent: float | None = None) -> None:
            if not progress:
                return
            maybe = progress(ExecutionProgress(phase=phase, detail=detail, percent=percent))
            if inspect.isawaitable(maybe):
                await maybe

        def elapsed_label() -> str:
            return _format_elapsed(loop.time() - started_at)

        async def read_stream(
            reader: asyncio.StreamReader | None,
            memory_sink: list[bytes],
            spool_handle,
            label: str,
        ) -> None:
            nonlocal captured_stdout, captured_stderr, last_output_at
            nonlocal output_lines, output_chars, last_output_report
            nonlocal last_stream_label
            if reader is None:
                return
            while True:
                chunk = await reader.read(4096)
                if not chunk:
                    return
                last_output_at = loop.time()
                last_stream_label = label
                spool_handle.write(chunk)
                spool_handle.flush()
                with paths.spool_path.open("ab") as combined:
                    combined.write(f"[{label.upper()}] ".encode("utf-8"))
                    combined.write(chunk)
                    if not chunk.endswith(b"\n"):
                        combined.write(b"\n")

                text = chunk.decode("utf-8", errors="replace")
                output_lines += max(1, text.count("\n"))
                output_chars += len(text)
                if label == "stdout" and captured_stdout < self.max_capture_chars:
                    allowed = self.max_capture_chars - captured_stdout
                    memory_sink.append(chunk[:allowed])
                    captured_stdout += min(len(chunk), allowed)
                elif label == "stderr" and captured_stderr < self.max_capture_chars:
                    allowed = self.max_capture_chars - captured_stderr
                    memory_sink.append(chunk[:allowed])
                    captured_stderr += min(len(chunk), allowed)

                now = loop.time()
                if last_output_report == 0.0 or now - last_output_report >= 1.0:
                    last_output_report = now
                    last_line = next(
                        (line.strip() for line in reversed(text.splitlines()) if line.strip()),
                        "",
                    )
                    detail = f"{elapsed_label()} · {output_lines:,} lines · {output_chars:,} chars"
                    if last_line:
                        detail += f" · {label}: {' '.join(last_line.split())[:72]}"
                    await emit("receiving output", detail, 50)

        async def idle_reporter() -> None:
            sleep_for = max(0.1, float(idle_interval or 1.0))
            if inactivity_timeout:
                sleep_for = min(sleep_for, max(0.1, float(inactivity_timeout) / 2))
            while proc is not None and proc.returncode is None:
                await asyncio.sleep(sleep_for)
                if proc is None or proc.returncode is not None:
                    return
                idle_for = loop.time() - last_output_at
                detail = (
                    f"{elapsed_label()} elapsed · idle {_format_elapsed(idle_for)} · "
                    f"{output_lines:,} lines · {output_chars:,} chars"
                )
                if last_stream_label:
                    detail += f" · last {last_stream_label}"
                if inactivity_timeout:
                    remaining = max(0.0, float(inactivity_timeout) - idle_for)
                    detail += f" · inactivity stop in {_format_elapsed(remaining)}"
                if output_chars == 0:
                    detail += " · waiting for output"
                await emit("running", detail, 45)

        async def wait_with_limits() -> str:
            while proc is not None and proc.returncode is None:
                await asyncio.sleep(0.1)
                now = loop.time()
                if max_runtime and now - started_at >= float(max_runtime):
                    return "max_runtime"
                if inactivity_timeout and now - last_output_at >= float(inactivity_timeout):
                    return "inactivity"
            return ""

        try:
            await emit("starting process", "launching shell command", 15)
            proc = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
                cwd=cwd,
                start_new_session=True,
            )
            await emit("process started", f"pid {proc.pid} · spool {paths.spool_path}", 20)

            with paths.stdout_path.open("wb") as stdout_file, paths.stderr_path.open("wb") as stderr_file:
                stdout_task = asyncio.create_task(
                    read_stream(proc.stdout, stdout_chunks, stdout_file, "stdout")
                )
                stderr_task = asyncio.create_task(
                    read_stream(proc.stderr, stderr_chunks, stderr_file, "stderr")
                )
                idle_task = asyncio.create_task(idle_reporter())
                limit_task = asyncio.create_task(wait_with_limits())
                try:
                    timeout_reason = await limit_task
                    if timeout_reason:
                        await emit("timeout", f"{timeout_reason} reached · stopping process group", 100)
                        await self._stop_process_group(proc)
                    await proc.wait()
                    await asyncio.gather(stdout_task, stderr_task)
                finally:
                    idle_task.cancel()
                    if not limit_task.done():
                        limit_task.cancel()
                    for task in (stdout_task, stderr_task, idle_task, limit_task):
                        if not task.done():
                            task.cancel()
                    await asyncio.gather(stdout_task, stderr_task, idle_task, limit_task, return_exceptions=True)

            status = "timed_out" if timeout_reason else "completed"
            await emit("collecting output", f"{output_lines:,} lines · rc {proc.returncode}", 95)
            stdout = b"".join(stdout_chunks).decode("utf-8", errors="replace")
            stderr = b"".join(stderr_chunks).decode("utf-8", errors="replace")
            if captured_stdout >= self.max_capture_chars or captured_stderr >= self.max_capture_chars:
                note = f"\n[Output truncated in memory; full spool: {paths.spool_path}]\n"
                if captured_stdout >= self.max_capture_chars:
                    stdout += note
                else:
                    stderr += note

            return SupervisedProcessResult(
                command=command,
                status=status,
                stdout=stdout,
                stderr=stderr,
                exit_code=proc.returncode,
                execution_time=loop.time() - started_at,
                output_lines=output_lines,
                output_chars=output_chars,
                spool_path=paths.spool_path,
                stdout_path=paths.stdout_path,
                stderr_path=paths.stderr_path,
                timeout_reason=timeout_reason,
            )
        except asyncio.CancelledError:
            await emit("cancelling", "interrupt received · stopping process group", 100)
            await self._stop_process_group(proc)
            await emit("cancelled", "process group stopped", 100)
            raise
        except Exception as exc:
            return SupervisedProcessResult(
                command=command,
                status="failed",
                stdout="",
                stderr=str(exc),
                exit_code=None,
                execution_time=loop.time() - started_at,
                output_lines=output_lines,
                output_chars=output_chars,
                spool_path=paths.spool_path,
                stdout_path=paths.stdout_path,
                stderr_path=paths.stderr_path,
            )

    def _new_spool_paths(self, prefix: str) -> "_SpoolPaths":
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        run_id = f"{prefix}-{stamp}-{uuid.uuid4().hex[:8]}"
        run_dir = self.run_dir / run_id
        try:
            run_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            fallback = Path("./.secops_runs") / run_id
            fallback.mkdir(parents=True, exist_ok=True)
            run_dir = fallback
        return _SpoolPaths(
            spool_path=run_dir / "combined.log",
            stdout_path=run_dir / "stdout.log",
            stderr_path=run_dir / "stderr.log",
        )

    async def _stop_process_group(self, process: asyncio.subprocess.Process | None) -> None:
        if process is None or process.returncode is not None:
            return
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        except Exception:
            with contextlib.suppress(Exception):
                process.kill()
        try:
            await asyncio.wait_for(process.wait(), timeout=2.0)
            return
        except asyncio.TimeoutError:
            pass
        except Exception:
            return
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except Exception:
            with contextlib.suppress(Exception):
                process.kill()
        with contextlib.suppress(Exception):
            await process.wait()


@dataclass
class _SpoolPaths:
    spool_path: Path
    stdout_path: Path
    stderr_path: Path


def _default_run_dir() -> Path:
    try:
        path = settings.sessions_dir.parent / "runs"
        path.mkdir(parents=True, exist_ok=True)
        return path
    except OSError:
        path = Path("./.secops_runs")
        path.mkdir(parents=True, exist_ok=True)
        return path


def _format_elapsed(seconds: float) -> str:
    seconds = max(0.0, seconds)
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = int(seconds // 60)
    rest = int(seconds % 60)
    return f"{minutes}m {rest}s"
