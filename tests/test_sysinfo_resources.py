"""Regression test for A4: `sysinfo` must report CPU, memory and disk so the
agent can answer "how much RAM / CPU / disk" instead of declining."""
from __future__ import annotations

import unittest

from secops_agent.tools.forensics import sysinfo


class SysinfoResourcesTests(unittest.IsolatedAsyncioTestCase):
    async def test_resources_category_reports_cpu_memory_disk(self) -> None:
        out = await sysinfo(category="resources")
        self.assertIn("CPU", out)
        self.assertIn("Memory", out)
        self.assertIn("Disk", out)

    async def test_all_category_includes_resources_section(self) -> None:
        out = await sysinfo(category="all")
        self.assertIn("Resources", out)
        self.assertIn("Memory", out)


if __name__ == "__main__":
    unittest.main()
