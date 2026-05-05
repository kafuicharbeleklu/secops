"""Tests for high-level tools (enumerate_web, test_credentials, enumerate_dns, capture_evidence)."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

from app.knowledge_store import KnowledgeStore
from app.methodology import EngagementState, PentestPhase
from app.tool_executor import (
    MissingTargetError,
    ToolExecutionError,
    ToolExecutor,
    ToolMissingError,
)
from app.tool_policy import ToolPolicyError
from app.tool_registry import ToolRegistry


def _make_executor(tmpdir, **kwargs):
    workspace = Path(tmpdir) / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    knowledge_root = Path(tmpdir) / "knowledge"
    knowledge_root.mkdir(parents=True, exist_ok=True)
    store = KnowledgeStore(knowledge_root, [])
    command_permission_mode = kwargs.pop("command_permission_mode", "session")
    return ToolExecutor(
        workspace=workspace,
        knowledge_root=knowledge_root,
        knowledge_store=store,
        command_permission_mode=command_permission_mode,
        tool_registry=ToolRegistry(),
        **kwargs,
    )


class TestEnumerateWeb(unittest.TestCase):
    def setUp(self):
        self.tmpdir = TemporaryDirectory()
        self.executor = _make_executor(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_missing_target_raises(self):
        with self.assertRaises(MissingTargetError):
            self.executor._enumerate_web("", "80")

    def test_scope_validation(self):
        self.executor.set_scope(["10.10.10.0/24"])
        with self.assertRaises(Exception):
            self.executor._enumerate_web("192.168.1.1", "80")

    @patch("shutil.which")
    @patch.object(ToolExecutor, "execute_command")
    def test_chains_gobuster_and_nikto(self, mock_exec, mock_which):
        mock_which.side_effect = lambda cmd: f"/usr/bin/{cmd}"
        mock_exec.return_value = {"stdout": "results", "returncode": 0}

        result = self.executor._enumerate_web("10.10.10.10", "80")
        self.assertEqual(result["target"], "10.10.10.10")
        self.assertEqual(result["port"], "80")
        self.assertEqual(len(result["scans"]), 2)
        self.assertEqual(mock_exec.call_count, 2)

    @patch("shutil.which", return_value=None)
    def test_tools_not_installed(self, mock_which):
        result = self.executor._enumerate_web("10.10.10.10", "80")
        self.assertEqual(len(result["scans"]), 2)
        self.assertIn("skipped", result["scans"][0])
        self.assertIn("skipped", result["scans"][1])

    @patch("shutil.which")
    @patch.object(ToolExecutor, "execute_command", side_effect=ToolExecutionError("fail"))
    def test_graceful_failure(self, mock_exec, mock_which):
        mock_which.side_effect = lambda cmd: f"/usr/bin/{cmd}"
        result = self.executor._enumerate_web("10.10.10.10", "80")
        self.assertEqual(len(result["scans"]), 2)
        self.assertIn("error", result["scans"][0])

    def test_default_port(self):
        result = self.executor.dispatch("enumerate_web", {"target": "10.10.10.10"})
        self.assertEqual(result["port"], "80")

    @patch("shutil.which", return_value=None)
    def test_dispatch_accepts_integer_port(self, mock_which):
        result = self.executor.dispatch("enumerate_web", {"target": "10.10.10.10", "port": 80})
        self.assertEqual(result["port"], "80")


class TestTestCredentials(unittest.TestCase):
    def setUp(self):
        self.tmpdir = TemporaryDirectory()
        self.executor = _make_executor(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_missing_target_raises(self):
        with self.assertRaises(MissingTargetError):
            self.executor._test_credentials("", "ssh", "user", "pass")

    def test_missing_service_raises(self):
        with self.assertRaises(ToolExecutionError):
            self.executor._test_credentials("10.10.10.10", "", "user", "pass")

    def test_missing_username_raises(self):
        with self.assertRaises(ToolExecutionError):
            self.executor._test_credentials("10.10.10.10", "ssh", "", "pass")

    def test_unsupported_service_raises(self):
        with self.assertRaises(ToolExecutionError) as ctx:
            self.executor._test_credentials("10.10.10.10", "rdp", "user", "pass")
        self.assertIn("non supporte", str(ctx.exception))

    @patch("shutil.which")
    @patch.object(ToolExecutor, "execute_command")
    def test_ssh_with_sshpass(self, mock_exec, mock_which):
        mock_which.side_effect = lambda cmd: f"/usr/bin/{cmd}" if cmd in ("sshpass", "ssh") else None
        mock_exec.return_value = {"stdout": "uid=1000", "returncode": 0}
        result = self.executor._test_credentials("10.10.10.10", "ssh", "admin", "password123")
        self.assertEqual(result["returncode"], 0)
        call_args = mock_exec.call_args[0][0]
        self.assertIn("sshpass", call_args)

    @patch("shutil.which")
    @patch.object(ToolExecutor, "execute_command")
    def test_ssh_fallback_hydra(self, mock_exec, mock_which):
        def which_side_effect(cmd):
            if cmd == "sshpass":
                return None
            if cmd == "hydra":
                return "/usr/bin/hydra"
            return None
        mock_which.side_effect = which_side_effect
        mock_exec.return_value = {"stdout": "login: admin", "returncode": 0}
        result = self.executor._test_credentials("10.10.10.10", "ssh", "admin", "pass")
        call_args = mock_exec.call_args[0][0]
        self.assertIn("hydra", call_args)

    @patch("shutil.which")
    @patch.object(ToolExecutor, "execute_command")
    def test_ftp_with_curl(self, mock_exec, mock_which):
        mock_which.side_effect = lambda cmd: f"/usr/bin/{cmd}" if cmd == "curl" else None
        mock_exec.return_value = {"stdout": "drwxr-xr-x", "returncode": 0}
        result = self.executor._test_credentials("10.10.10.10", "ftp", "anonymous", "guest")
        call_args = mock_exec.call_args[0][0]
        self.assertIn("ftp://", call_args)

    @patch("shutil.which")
    @patch.object(ToolExecutor, "execute_command")
    def test_smb_with_smbclient(self, mock_exec, mock_which):
        mock_which.side_effect = lambda cmd: f"/usr/bin/{cmd}" if cmd == "smbclient" else None
        mock_exec.return_value = {"stdout": "Sharename", "returncode": 0}
        result = self.executor._test_credentials("10.10.10.10", "smb", "admin", "pass")
        call_args = mock_exec.call_args[0][0]
        self.assertIn("smbclient", call_args)

    def test_scope_validation(self):
        self.executor.set_scope(["10.10.10.0/24"])
        with self.assertRaises(Exception):
            self.executor._test_credentials("192.168.1.1", "ssh", "user", "pass")


class TestEnumerateDns(unittest.TestCase):
    def setUp(self):
        self.tmpdir = TemporaryDirectory()
        self.executor = _make_executor(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_empty_domain_raises(self):
        with self.assertRaises(ToolExecutionError):
            self.executor._enumerate_dns("")

    @patch("shutil.which")
    @patch.object(ToolExecutor, "execute_command")
    def test_uses_dig(self, mock_exec, mock_which):
        def which_side_effect(cmd):
            if cmd == "dig":
                return "/usr/bin/dig"
            return None
        mock_which.side_effect = which_side_effect
        mock_exec.return_value = {"stdout": "A 10.10.10.10", "returncode": 0}
        result = self.executor._enumerate_dns("example.com")
        self.assertEqual(result["domain"], "example.com")
        self.assertTrue(len(result["results"]) >= 1)

    @patch("shutil.which", return_value=None)
    def test_no_dns_tools(self, mock_which):
        result = self.executor._enumerate_dns("example.com")
        self.assertIn("skipped", result["results"][0])


class TestCaptureEvidence(unittest.TestCase):
    def setUp(self):
        self.tmpdir = TemporaryDirectory()
        self.executor = _make_executor(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_empty_title_raises(self):
        with self.assertRaises(ToolExecutionError):
            self.executor._capture_evidence("", "content")

    def test_empty_content_raises(self):
        with self.assertRaises(ToolExecutionError):
            self.executor._capture_evidence("title", "")

    def test_creates_evidence_file(self):
        result = self.executor._capture_evidence("SSH Access", "uid=1000(admin)", "ssh")
        self.assertIn("evidence", result["path"])
        self.assertTrue(Path(result["path"]).exists())
        content = Path(result["path"]).read_text(encoding="utf-8")
        self.assertIn("SSH Access", content)
        self.assertIn("uid=1000(admin)", content)
        self.assertIn("ssh", content)

    def test_filename_sanitization(self):
        result = self.executor._capture_evidence("Preuve avec/caracteres spéciaux!", "data")
        self.assertNotIn("/", result["filename"].split("_", 2)[-1])
        self.assertNotIn("!", result["filename"])

    def test_evidence_dir_created(self):
        self.executor._capture_evidence("test", "data")
        evidence_dir = self.executor.workspace / "evidence"
        self.assertTrue(evidence_dir.is_dir())


class TestHighLevelToolsInAvailableTools(unittest.TestCase):
    def setUp(self):
        self.tmpdir = TemporaryDirectory()
        self.executor = _make_executor(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_new_tools_in_available_tools(self):
        tools = self.executor.available_tools()
        tool_names = {t.name for t in tools}
        self.assertIn("enumerate_web", tool_names)
        self.assertIn("test_credentials", tool_names)
        self.assertIn("enumerate_dns", tool_names)
        self.assertIn("capture_evidence", tool_names)

    def test_dispatch_unknown_tool(self):
        with self.assertRaises(ToolExecutionError):
            self.executor.dispatch("nonexistent_tool", {})

    def test_command_tools_can_be_disabled_by_plugin_rule(self):
        executor = _make_executor(self.tmpdir.name, command_permission_mode="deny")

        tool_names = {tool.name for tool in executor.available_tools()}

        self.assertNotIn("execute_command", tool_names)
        self.assertNotIn("execute_admin_command", tool_names)
        with self.assertRaises(ToolExecutionError):
            executor.dispatch("execute_command", {"command": "id"})

    def test_tool_plugins_expose_metadata(self):
        plugin = self.executor._tool_plugins["scan_target"]

        self.assertEqual(plugin.spec.name, "scan_target")
        self.assertEqual(plugin.phases, ("recon",))
        self.assertEqual(plugin.risk, "medium")

    def test_policy_blocks_target_placeholder_before_dispatch(self):
        with self.assertRaises(ToolPolicyError) as ctx:
            self.executor.dispatch("scan_target", {"target": "TARGET_IP", "mode": "quick"})

        self.assertIn("placeholder", str(ctx.exception))
        self.assertIn("/target", ctx.exception.remediation)

    def test_policy_blocks_out_of_scope_target_before_handler(self):
        self.executor.set_scope(["10.10.10.0/24"])

        with self.assertRaises(ToolPolicyError) as ctx:
            self.executor.dispatch("scan_target", {"target": "192.168.1.1", "mode": "quick"})

        self.assertEqual(ctx.exception.code, "scope_violation")

    def test_policy_blocks_high_risk_tool_outside_allowed_phase(self):
        self.executor._engagement = EngagementState(phase=PentestPhase.RECON)

        with self.assertRaises(ToolPolicyError) as ctx:
            self.executor.dispatch(
                "exploit_workflow",
                {"query": "CVE-2021-41773", "target": "10.10.10.10"},
            )

        self.assertIn("politique de phase", str(ctx.exception))
        self.assertEqual(ctx.exception.code, "phase_violation")


if __name__ == "__main__":
    unittest.main()
