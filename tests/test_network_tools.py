from __future__ import annotations

import unittest
from unittest.mock import patch

import secops_agent.tools.network as net


class NmapScanTypeTests(unittest.IsolatedAsyncioTestCase):
    async def test_auto_scan_detects_service_versions(self):
        captured: dict[str, list[str]] = {}

        async def fake_stream(cmd, **kwargs):
            captured["cmd"] = cmd
            return ("80/tcp open http Apache httpd 2.4.41 ((Ubuntu))\n", "", 0)

        async def noop_progress(*args, **kwargs):
            return None

        with patch.object(net, "_check_tool", return_value=True), \
             patch.object(net, "report_progress", new=noop_progress), \
             patch.object(net, "_run_cmd_streaming", new=fake_stream):
            out = await net.nmap_scan("10.0.0.1", scan_type="auto")

        # 'auto' must run service/version detection so version questions are answerable.
        self.assertIn("-sV", captured["cmd"])
        self.assertIn("Apache httpd 2.4.41", out)


if __name__ == "__main__":
    unittest.main()
