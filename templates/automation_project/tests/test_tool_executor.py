import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from app.knowledge_store import KnowledgeStore
from app.tool_executor import (
    InteractiveAdminRequired,
    MissingTargetError,
    PermissionDenied,
    ToolExecutionError,
    ToolExecutor,
    ToolsMissingError,
)


class ToolExecutorTests(unittest.TestCase):
    def setUp(self):
        repo_root = Path(__file__).resolve().parents[3]
        self.knowledge_root = repo_root / "knowledge"
        self.workspace = repo_root / "templates" / "automation_project" / "workspace"
        self.knowledge_store = KnowledgeStore.load(self.knowledge_root)

    def test_execute_command_requires_permission_by_default(self):
        executor = ToolExecutor(
            workspace=self.workspace,
            knowledge_root=self.knowledge_root,
            knowledge_store=self.knowledge_store,
            permission_callback=lambda **_kwargs: False,
            command_permission_mode="ask",
        )

        with patch("app.tool_executor.shutil.which", return_value="/usr/bin/echo"):
            with self.assertRaises(PermissionDenied):
                executor.execute_command("echo hello", "test")

    def test_available_tools_for_context_filters_by_prompt_and_phase(self):
        executor = ToolExecutor(
            workspace=self.workspace,
            knowledge_root=self.knowledge_root,
            knowledge_store=self.knowledge_store,
        )

        tools = executor.available_tools_for_context(
            phase="enumeration",
            prompt="Find directories on the web server using gobuster",
        )
        names = {tool.name for tool in tools}

        self.assertIn("enumerate_web", names)
        self.assertIn("analyze_service", names)
        self.assertIn("list_findings", names)
        self.assertNotIn("exploit_workflow", names)

    def test_execute_command_can_be_allowed_for_session(self):
        decisions = iter(["session"])
        executor = ToolExecutor(
            workspace=self.workspace,
            knowledge_root=self.knowledge_root,
            knowledge_store=self.knowledge_store,
            permission_callback=lambda **_kwargs: next(decisions),
            command_permission_mode="ask",
        )

        with patch("app.tool_executor.shutil.which", return_value="/usr/bin/echo"):
            with patch("app.tool_executor.subprocess.run") as run_mock:
                run_mock.return_value.stdout = "hello\n"
                run_mock.return_value.stderr = ""
                run_mock.return_value.returncode = 0
                first = executor.execute_command("echo hello", "test")
                second = executor.execute_command("echo again", "test")

        self.assertEqual(first["stdout"], "hello\n")
        self.assertEqual(second["stdout"], "hello\n")
        self.assertEqual(run_mock.call_count, 2)
        self.assertEqual(executor.command_permission_mode, "session")

    def test_execute_command_allows_unrestricted_binary_when_no_allowlist_is_set(self):
        executor = ToolExecutor(
            workspace=self.workspace,
            knowledge_root=self.knowledge_root,
            knowledge_store=self.knowledge_store,
            permission_callback=lambda **_kwargs: True,
            command_permission_mode="ask",
        )

        class Completed:
            def __init__(self, stdout="", stderr="", returncode=0):
                self.stdout = stdout
                self.stderr = stderr
                self.returncode = returncode

        with patch("app.tool_executor.shutil.which", return_value="/usr/bin/df"):
            with patch(
                "app.tool_executor.subprocess.run",
                return_value=Completed(stdout="Filesystem      Size  Used Avail Use%\n", returncode=0),
            ):
                result = executor.execute_command("df -h", "verifier le stockage")

        self.assertEqual(result["command"], "df -h")
        self.assertIn("Filesystem", result["stdout"])

    def test_execute_command_emits_live_progress_when_callback_is_set(self):
        progress_events = []
        executor = ToolExecutor(
            workspace=self.workspace,
            knowledge_root=self.knowledge_root,
            knowledge_store=self.knowledge_store,
            permission_callback=lambda **_kwargs: True,
            command_permission_mode="ask",
            progress_callback=progress_events.append,
        )

        class FakePopen:
            def __init__(self):
                self.stdout = StringIO("alpha\nbeta\n")
                self.stderr = StringIO("warn\n")
                self.returncode = 0

            def poll(self):
                return 0

            def wait(self, timeout=None):
                return self.returncode

            def kill(self):
                self.returncode = 124

        with patch("app.tool_executor.shutil.which", return_value="/usr/bin/echo"):
            with patch("app.tool_executor.subprocess.Popen", return_value=FakePopen()):
                result = executor.execute_command("echo hello", "test")

        self.assertEqual(result["stdout"], "alpha\nbeta\n")
        self.assertEqual(result["stderr"], "warn\n")
        self.assertTrue(Path(result["log_path"]).exists())
        log_content = Path(result["log_path"]).read_text(encoding="utf-8")
        self.assertIn("alpha", log_content)
        self.assertIn("beta", log_content)
        self.assertIn("warn", log_content)
        self.assertFalse(any(e.get("content") == "alpha" for e in progress_events))
        self.assertTrue(any(e.get("content") == "echo | stderr: warn" for e in progress_events))

    def test_execute_command_compacts_nmap_progress(self):
        progress_events = []
        executor = ToolExecutor(
            workspace=self.workspace,
            knowledge_root=self.knowledge_root,
            knowledge_store=self.knowledge_store,
            permission_callback=lambda **_kwargs: True,
            command_permission_mode="ask",
            progress_callback=progress_events.append,
        )

        class FakePopen:
            def __init__(self):
                self.stdout = StringIO(
                    "Starting Nmap 7.98\n"
                    "Stats: 0:00:05 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan\n"
                    "Connect Scan Timing: About 43.00% done; ETC: 15:29 (0:00:07 remaining)\n"
                    "22/tcp open ssh OpenSSH\n"
                )
                self.stderr = StringIO("")
                self.returncode = 0

            def poll(self):
                return 0

            def wait(self, timeout=None):
                return self.returncode

            def kill(self):
                self.returncode = 124

        command = "nmap -sC -sV --stats-every 5s --top-ports 1000 10.10.10.10"
        with patch("app.tool_executor.shutil.which", return_value="/usr/bin/nmap"):
            with patch("app.tool_executor.subprocess.Popen", return_value=FakePopen()):
                result = executor.execute_command(command, "scan")

        contents = [e.get("content", "") for e in progress_events]
        self.assertTrue(any("nmap | demarrage" in content for content in contents))
        self.assertTrue(any("nmap | Connect Scan | ecoule 0:00:05" in content for content in contents))
        self.assertTrue(any("nmap | Connect Scan | 43.0%" in content for content in contents))
        self.assertTrue(any("port ouvert detecte: 22/tcp open ssh OpenSSH" in content for content in contents))
        self.assertTrue(all("Starting Nmap" not in content for content in contents))
        self.assertIn("Starting Nmap 7.98", result["stdout"])
        self.assertTrue(Path(result["log_path"]).exists())

    def test_execute_command_emits_structured_gobuster_progress(self):
        progress_events = []
        executor = ToolExecutor(
            workspace=self.workspace,
            knowledge_root=self.knowledge_root,
            knowledge_store=self.knowledge_store,
            permission_callback=lambda **_kwargs: True,
            command_permission_mode="ask",
            progress_callback=progress_events.append,
        )

        class FakePopen:
            def __init__(self):
                self.stdout = StringIO(
                    "Progress: 50 / 100 (50.00%)\n"
                    "/hidden (Status: 301) [Size: 0]\n"
                    "Found: /admin (Status: 200)\n"
                )
                self.stderr = StringIO("")
                self.returncode = 0

            def poll(self):
                return 0

            def wait(self, timeout=None):
                return self.returncode

            def kill(self):
                self.returncode = 124

        command = "gobuster dir -u http://10.10.10.10 -w common.txt"
        with patch("app.tool_executor.shutil.which", return_value="/usr/bin/gobuster"):
            with patch("app.tool_executor.subprocess.Popen", return_value=FakePopen()):
                result = executor.execute_command(command, "enum web")

        activity_events = [event for event in progress_events if event.get("progress_kind") == "activity"]
        finding_events = [event for event in progress_events if event.get("progress_kind") == "finding"]
        self.assertTrue(any(event.get("tool") == "gobuster" and event.get("percent") == "50.0%" for event in activity_events))
        self.assertTrue(any(event.get("detail") == "/hidden (301)" for event in finding_events))
        self.assertTrue(any(event.get("detail") == "/admin (200)" for event in finding_events))
        self.assertIn("/hidden", result["stdout"])

    def test_execute_command_reports_missing_binary(self):
        executor = ToolExecutor(
            workspace=self.workspace,
            knowledge_root=self.knowledge_root,
            knowledge_store=self.knowledge_store,
            permission_callback=lambda **_kwargs: True,
            command_permission_mode="ask",
        )

        with patch("app.tool_executor.shutil.which", return_value=None):
            with self.assertRaises(ToolExecutionError) as ctx:
                executor.execute_command("nmap 10.10.10.10", "scan")

        self.assertIn("nmap", str(ctx.exception))

    def test_trigger_install_many_reports_batch_missing_tools(self):
        executor = ToolExecutor(
            workspace=self.workspace,
            knowledge_root=self.knowledge_root,
            knowledge_store=self.knowledge_store,
        )

        with patch.object(executor.tool_registry, "refresh"):
            with patch.object(executor.tool_registry, "is_known", return_value=True):
                with patch.object(
                    executor.tool_registry,
                    "is_installed",
                    side_effect=lambda name: name == "nikto",
                ):
                    with self.assertRaises(ToolsMissingError) as ctx:
                        executor._trigger_install_many(["nikto", "hydra", "tracerout"])

        self.assertEqual(ctx.exception.installed, ["nikto"])
        self.assertEqual(ctx.exception.executables, ["hydra", "traceroute"])

    def test_execute_command_rejects_target_placeholder(self):
        executor = ToolExecutor(
            workspace=self.workspace,
            knowledge_root=self.knowledge_root,
            knowledge_store=self.knowledge_store,
            permission_callback=lambda **_kwargs: True,
            command_permission_mode="ask",
        )

        with self.assertRaises(MissingTargetError):
            executor.execute_command("nmap -p 80 TARGET_IP", "scan")

    def test_install_tool_uses_apt_get_with_noninteractive_sudo(self):
        executor = ToolExecutor(
            workspace=self.workspace,
            knowledge_root=self.knowledge_root,
            knowledge_store=self.knowledge_store,
        )

        which_values = {
            "apt-get": "/usr/bin/apt-get",
            "sudo": "/usr/bin/sudo",
            "nmap": "/usr/bin/nmap",
        }

        class Completed:
            def __init__(self, stdout="", stderr="", returncode=0):
                self.stdout = stdout
                self.stderr = stderr
                self.returncode = returncode

        with patch("app.tool_executor.os.geteuid", return_value=1000):
            with patch("app.tool_executor.shutil.which", side_effect=lambda name: which_values.get(name)):
                with patch(
                    "app.tool_executor.subprocess.run",
                    side_effect=[
                        Completed(stdout="updated", returncode=0),
                        Completed(stdout="installed", returncode=0),
                    ],
                ) as run_mock:
                    result = executor.install_tool("nmap")

        self.assertEqual(result["status"], "installed")
        self.assertEqual(
            run_mock.call_args_list[0].args[0],
            ["/usr/bin/sudo", "-n", "/usr/bin/apt-get", "-qq", "-o", "Dpkg::Use-Pty=0", "update"],
        )
        self.assertEqual(
            run_mock.call_args_list[1].args[0],
            ["/usr/bin/sudo", "-n", "/usr/bin/apt-get", "-qq", "-o", "Dpkg::Use-Pty=0", "install", "-y", "nmap"],
        )

    def test_install_tool_reports_manual_steps_when_sudo_needs_password(self):
        executor = ToolExecutor(
            workspace=self.workspace,
            knowledge_root=self.knowledge_root,
            knowledge_store=self.knowledge_store,
        )

        which_values = {
            "apt-get": "/usr/bin/apt-get",
            "sudo": "/usr/bin/sudo",
            "nmap": None,
        }

        class Completed:
            def __init__(self, stdout="", stderr="", returncode=0):
                self.stdout = stdout
                self.stderr = stderr
                self.returncode = returncode

        with patch("app.tool_executor.os.geteuid", return_value=1000):
            with patch("app.tool_executor.shutil.which", side_effect=lambda name: which_values.get(name)):
                with patch(
                    "app.tool_executor.subprocess.run",
                    return_value=Completed(stderr="sudo: a password is required", returncode=1),
                ):
                    result = executor.install_tool("nmap")

        self.assertEqual(result["status"], "manual_required")
        self.assertIn("sudo apt-get -qq", result["manual_command"])

    def test_install_tool_interactive_validates_sudo_then_runs_quiet_apt(self):
        executor = ToolExecutor(
            workspace=self.workspace,
            knowledge_root=self.knowledge_root,
            knowledge_store=self.knowledge_store,
        )

        which_values = {
            "apt-get": "/usr/bin/apt-get",
            "sudo": "/usr/bin/sudo",
            "nmap": "/usr/bin/nmap",
        }

        class Completed:
            def __init__(self, returncode=0):
                self.returncode = returncode
                self.stdout = None
                self.stderr = None

        with patch("app.tool_executor.os.geteuid", return_value=1000):
            with patch("app.tool_executor.shutil.which", side_effect=lambda name: which_values.get(name)):
                with patch(
                    "app.tool_executor.subprocess.run",
                    side_effect=[Completed(returncode=0), Completed(returncode=0), Completed(returncode=0)],
                ) as run_mock:
                    result = executor.install_tool("nmap", interactive=True)

        self.assertEqual(result["status"], "installed")
        self.assertEqual(run_mock.call_args_list[0].args[0], ["/usr/bin/sudo", "-v"])
        self.assertEqual(
            run_mock.call_args_list[1].args[0],
            ["/usr/bin/sudo", "-n", "/usr/bin/apt-get", "-qq", "-o", "Dpkg::Use-Pty=0", "update"],
        )
        self.assertEqual(
            run_mock.call_args_list[2].args[0],
            ["/usr/bin/sudo", "-n", "/usr/bin/apt-get", "-qq", "-o", "Dpkg::Use-Pty=0", "install", "-y", "nmap"],
        )

    def test_install_tools_runs_single_quiet_batch_install(self):
        executor = ToolExecutor(
            workspace=self.workspace,
            knowledge_root=self.knowledge_root,
            knowledge_store=self.knowledge_store,
        )

        which_values = {
            "apt-get": "/usr/bin/apt-get",
            "sudo": "/usr/bin/sudo",
            "hydra": "/usr/bin/hydra",
            "dirb": "/usr/bin/dirb",
        }

        class Completed:
            def __init__(self, stdout="", stderr="", returncode=0):
                self.stdout = stdout
                self.stderr = stderr
                self.returncode = returncode

        with patch("app.tool_executor.os.geteuid", return_value=1000):
            with patch("app.tool_executor.shutil.which", side_effect=lambda name: which_values.get(name)):
                with patch(
                    "app.tool_executor.subprocess.run",
                    side_effect=[
                        Completed(stdout="updated", returncode=0),
                        Completed(stdout="installed", returncode=0),
                    ],
                ) as run_mock:
                    result = executor.install_tools(["hydra", "dirb"])

        self.assertEqual(result["status"], "installed")
        self.assertEqual(result["installed"], ["hydra", "dirb"])
        self.assertEqual(
            run_mock.call_args_list[1].args[0],
            [
                "/usr/bin/sudo",
                "-n",
                "/usr/bin/apt-get",
                "-qq",
                "-o",
                "Dpkg::Use-Pty=0",
                "install",
                "-y",
                "hydra",
                "dirb",
            ],
        )

    def test_execute_admin_command_uses_noninteractive_sudo(self):
        executor = ToolExecutor(
            workspace=self.workspace,
            knowledge_root=self.knowledge_root,
            knowledge_store=self.knowledge_store,
            permission_callback=lambda **_kwargs: True,
            command_permission_mode="ask",
        )

        class Completed:
            def __init__(self, stdout="", stderr="", returncode=0):
                self.stdout = stdout
                self.stderr = stderr
                self.returncode = returncode

        which_values = {
            "apt-get": "/usr/bin/apt-get",
            "sudo": "/usr/bin/sudo",
        }

        with patch("app.tool_executor.os.geteuid", return_value=1000):
            with patch("app.tool_executor.shutil.which", side_effect=lambda name: which_values.get(name)):
                with patch(
                    "app.tool_executor.subprocess.run",
                    return_value=Completed(stdout="Hit:1 repo\n", returncode=0),
                ) as run_mock:
                    result = executor.execute_admin_command("apt update", "mise a jour locale")

        self.assertEqual(result["command"], "apt-get update")
        self.assertEqual(
            run_mock.call_args.args[0],
            ["/usr/bin/sudo", "-n", "/usr/bin/apt-get", "update"],
        )

    def test_execute_admin_command_requests_interactive_sudo_when_password_is_required(self):
        executor = ToolExecutor(
            workspace=self.workspace,
            knowledge_root=self.knowledge_root,
            knowledge_store=self.knowledge_store,
            permission_callback=lambda **_kwargs: True,
            command_permission_mode="ask",
        )

        class Completed:
            def __init__(self, stdout="", stderr="", returncode=0):
                self.stdout = stdout
                self.stderr = stderr
                self.returncode = returncode

        which_values = {
            "apt-get": "/usr/bin/apt-get",
            "sudo": "/usr/bin/sudo",
        }

        with patch("app.tool_executor.os.geteuid", return_value=1000):
            with patch("app.tool_executor.shutil.which", side_effect=lambda name: which_values.get(name)):
                with patch(
                    "app.tool_executor.subprocess.run",
                    return_value=Completed(stderr="sudo: a password is required", returncode=1),
                ):
                    with self.assertRaises(InteractiveAdminRequired) as ctx:
                        executor.execute_admin_command("apt update", "mise a jour locale")

        self.assertIn("apt-get update", str(ctx.exception))

    def test_execute_admin_command_supports_generic_command_via_sudo(self):
        executor = ToolExecutor(
            workspace=self.workspace,
            knowledge_root=self.knowledge_root,
            knowledge_store=self.knowledge_store,
            permission_callback=lambda **_kwargs: True,
            command_permission_mode="ask",
        )

        class Completed:
            def __init__(self, stdout="", stderr="", returncode=0):
                self.stdout = stdout
                self.stderr = stderr
                self.returncode = returncode

        which_values = {
            "systemctl": "/usr/bin/systemctl",
            "sudo": "/usr/bin/sudo",
        }

        with patch("app.tool_executor.os.geteuid", return_value=1000):
            with patch("app.tool_executor.shutil.which", side_effect=lambda name: which_values.get(name)):
                with patch(
                    "app.tool_executor.subprocess.run",
                    return_value=Completed(stdout="active\n", returncode=0),
                ) as run_mock:
                    result = executor.execute_admin_command(
                        "systemctl status ssh",
                        "verifier le service ssh",
                    )

        self.assertEqual(result["command"], "systemctl status ssh")
        self.assertEqual(
            run_mock.call_args.args[0],
            ["/usr/bin/sudo", "-n", "/usr/bin/systemctl", "status", "ssh"],
        )
