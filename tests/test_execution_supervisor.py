from __future__ import annotations

import asyncio
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

from secops_agent.core.execution import ExecutionProgress, ExecutionSupervisor
from secops_agent.core.tools import ToolCategory, ToolRegistry, report_tool_metadata


class ExecutionSupervisorTests(unittest.IsolatedAsyncioTestCase):
    async def test_supervisor_spools_stdout_and_returns_completion_metadata(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            supervisor = ExecutionSupervisor(run_dir=tmpdir)

            result = await supervisor.run_shell(
                "printf 'hello\\nworld\\n'",
                max_runtime=5,
                inactivity_timeout=5,
            )
            stdout_text = result.stdout_path.read_text(encoding="utf-8")
            spool_text = result.spool_path.read_text(encoding="utf-8")

        self.assertEqual(result.status, "completed")
        self.assertEqual(result.exit_code, 0)
        self.assertIn("hello", result.stdout)
        self.assertIn("world", stdout_text)
        self.assertIn("[STDOUT] hello", spool_text)
        self.assertEqual(result.output_lines, 2)

    async def test_supervisor_reports_idle_and_stops_on_inactivity_timeout(self):
        events: list[ExecutionProgress] = []
        with tempfile.TemporaryDirectory() as tmpdir:
            supervisor = ExecutionSupervisor(run_dir=tmpdir)

            result = await supervisor.run_shell(
                "sh -c 'sleep 2'",
                max_runtime=5,
                inactivity_timeout=0.3,
                progress=lambda event: events.append(event),
            )

        self.assertEqual(result.status, "timed_out")
        self.assertEqual(result.timeout_reason, "inactivity")
        self.assertTrue(any(event.phase == "running" and "idle" in event.detail for event in events))
        self.assertTrue(any("inactivity stop in" in event.detail for event in events))
        self.assertTrue(any("chars" in event.detail for event in events))
        self.assertTrue(any(event.phase == "timeout" for event in events))

    async def test_supervisor_uses_max_runtime_as_global_guardrail(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            supervisor = ExecutionSupervisor(run_dir=tmpdir)

            result = await supervisor.run_shell(
                "sh -c 'while true; do printf x; sleep 0.05; done'",
                max_runtime=0.3,
                inactivity_timeout=5,
            )

        self.assertEqual(result.status, "timed_out")
        self.assertEqual(result.timeout_reason, "max_runtime")
        self.assertGreater(result.output_chars, 0)

    async def test_supervisor_truncates_memory_capture_but_keeps_full_spool(self):
        command = (
            f"{sys.executable} -c "
            "\"import sys; sys.stdout.write('A' * 2000)\""
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            supervisor = ExecutionSupervisor(run_dir=tmpdir, max_capture_chars=100)

            result = await supervisor.run_shell(
                command,
                max_runtime=5,
                inactivity_timeout=5,
            )
            stdout_size = result.stdout_path.stat().st_size

        self.assertLess(len(result.stdout), 300)
        self.assertIn("Output truncated in memory", result.stdout)
        self.assertGreater(stdout_size, 1000)

    async def test_supervisor_cancellation_stops_process_group_and_reports_progress(self):
        events: list[ExecutionProgress] = []
        with tempfile.TemporaryDirectory() as tmpdir:
            supervisor = ExecutionSupervisor(run_dir=tmpdir)
            task = asyncio.create_task(
                supervisor.run_shell(
                    "sh -c 'sleep 30'",
                    max_runtime=60,
                    inactivity_timeout=60,
                    progress=lambda event: events.append(event),
                )
            )

            process_group_id: int | None = None
            for _ in range(50):
                for event in events:
                    match = re.search(r"pid (\d+)", event.detail)
                    if event.phase == "process started" and match:
                        process_group_id = int(match.group(1))
                        break
                if process_group_id is not None:
                    break
                await asyncio.sleep(0.02)

            self.assertIsNotNone(process_group_id)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

            for _ in range(30):
                try:
                    os.killpg(process_group_id, 0)  # type: ignore[arg-type]
                except ProcessLookupError:
                    break
                await asyncio.sleep(0.05)
            else:
                self.fail("cancelled supervised process group is still alive")

        self.assertTrue(any(event.phase == "cancelling" for event in events))
        self.assertTrue(any(event.phase == "cancelled" for event in events))

    async def test_tool_registry_carries_trusted_execution_metadata(self):
        registry = ToolRegistry()

        async def metadata_tool() -> str:
            report_tool_metadata("spool_path", "/tmp/secops-spool/combined.log")
            report_tool_metadata("execution_status", "completed")
            return "compact output"

        registry.register(
            "metadata_tool",
            "metadata test",
            ToolCategory.SYSTEM,
            {},
            metadata_tool,
        )

        result = await registry.execute("metadata_tool", {})

        self.assertTrue(result.success)
        self.assertEqual(result.output, "compact output")
        self.assertEqual(result.metadata["spool_path"], "/tmp/secops-spool/combined.log")
        self.assertEqual(result.metadata["execution_status"], "completed")


if __name__ == "__main__":
    unittest.main()
