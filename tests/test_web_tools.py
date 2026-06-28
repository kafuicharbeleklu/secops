from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

from secops_agent.core.tools import registry
from secops_agent.tools import web


class WebToolTests(unittest.IsolatedAsyncioTestCase):
    def test_waf_detect_requires_approval(self):
        tool_def = registry.get_tool("waf_detect")

        self.assertIsNotNone(tool_def)
        self.assertTrue(tool_def.dangerous)

    async def test_dir_brute_uses_builtin_fallback_when_system_wordlists_are_missing(self):
        commands: list[list[str]] = []

        async def fake_run_cmd(cmd, timeout=0, progress=None, **_):
            commands.append(list(cmd))
            wordlist = Path(cmd[cmd.index("-w") + 1])
            self.assertTrue(wordlist.exists())
            self.assertIn("uploads", wordlist.read_text(encoding="utf-8"))
            if progress:
                await progress("0.1s · 1 lines · 36 chars", 50)
            return "/uploads (Status: 301) [Size: 123]\n", "", 0

        with patch("secops_agent.tools.web.shutil.which", lambda name: "/usr/bin/gobuster" if name == "gobuster" else None), patch(
            "secops_agent.tools.web._run_cmd_streaming",
            fake_run_cmd,
        ), patch("secops_agent.tools.web._WORDLIST_CANDIDATES", ()):
            output = await web.dir_brute("http://10.10.10.5", wordlist="/missing/common.txt")

        self.assertIn("Using built-in fallback wordlist", output)
        self.assertIn("/uploads", output)
        self.assertEqual(commands[0][0:4], ["gobuster", "dir", "-u", "http://10.10.10.5"])
        self.assertFalse(Path(commands[0][commands[0].index("-w") + 1]).exists())


if __name__ == "__main__":
    unittest.main()
