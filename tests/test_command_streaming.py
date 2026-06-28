from __future__ import annotations

import sys
import unittest

from secops_agent.utils.helpers import run_cmd_streaming


class CommandStreamingTests(unittest.IsolatedAsyncioTestCase):
    async def test_run_cmd_streaming_reports_output_progress(self):
        progress_events: list[tuple[str, float | None]] = []

        async def record_progress(detail: str, percent: float | None = None):
            progress_events.append((detail, percent))

        script = (
            "import sys, time\n"
            "for index in range(3):\n"
            "    print(f'line {index}', flush=True)\n"
            "    time.sleep(0.03)\n"
        )

        stdout, stderr, rc = await run_cmd_streaming(
            [sys.executable, "-c", script],
            timeout=2,
            progress=record_progress,
            report_interval=0,
            idle_interval=0.5,
            progress_percent=55,
        )

        self.assertEqual(rc, 0)
        self.assertEqual(stderr, "")
        self.assertIn("line 0", stdout)
        self.assertTrue(any("line" in detail for detail, _ in progress_events))
        self.assertTrue(any(percent == 55 for _, percent in progress_events))

    async def test_run_cmd_streaming_reports_idle_elapsed_progress(self):
        progress_events: list[str] = []

        async def record_progress(detail: str, percent: float | None = None):
            progress_events.append(detail)

        script = "import time\n" "time.sleep(0.15)\n"

        stdout, stderr, rc = await run_cmd_streaming(
            [sys.executable, "-c", script],
            timeout=2,
            progress=record_progress,
            report_interval=10,
            idle_interval=0.05,
        )

        self.assertEqual(rc, 0)
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")
        self.assertTrue(any("waiting for output" in detail for detail in progress_events))


if __name__ == "__main__":
    unittest.main()
