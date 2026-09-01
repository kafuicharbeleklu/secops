"""#4: write_file drops relative payloads in a dedicated workspace, not the
operator's current directory — a generated webshell must never land in their
project/repo (RootMe run wrote shell.php into the agent's own repo).
"""
from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from secops_agent.config import settings
from secops_agent.tools.exploitation import write_file


class PayloadWorkspaceTests(unittest.TestCase):
    def test_workspace_dir_is_not_the_cwd(self):
        self.assertTrue(hasattr(settings, "workspace_dir"))
        self.assertNotEqual(Path(settings.workspace_dir).resolve(), Path.cwd().resolve())

    def test_relative_write_lands_in_workspace_not_cwd(self):
        name = "secops_wf_probe.txt"  # unique so a stray leftover can't mask the check
        cwd_target = Path.cwd() / name
        self.addCleanup(lambda: cwd_target.exists() and cwd_target.unlink())
        self.assertFalse(cwd_target.exists())
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict("os.environ", {"SECOPS_WORKSPACE_DIR": tmp}):
                out = asyncio.run(write_file(name, "data"))
            self.assertTrue((Path(tmp) / name).is_file())
            self.assertIn(tmp, out)
            self.assertFalse(cwd_target.exists(), "write leaked into the operator's cwd")

    def test_absolute_path_is_respected(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "abs.txt"
            asyncio.run(write_file(str(target), "data"))
            self.assertTrue(target.is_file())


if __name__ == "__main__":
    unittest.main()
