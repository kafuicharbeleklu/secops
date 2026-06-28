from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from secops_agent.core.agent import (
    ApprovalRequestEvent,
    SecOpsAgent,
    SudoAuthenticationRequestEvent,
    TextEvent,
    ToolProgressEvent,
    ToolResultEvent,
    ToolStartEvent,
)
from secops_agent.core.llm import Message, StreamChunk, ToolCallChunk
from secops_agent.core.memory import ConversationMemory
from secops_agent.core.permissions import (
    ApprovalDecision,
    ApprovalScope,
    PermissionDecision,
    PermissionEngine,
    PermissionResource,
)
from secops_agent.core.sandbox import set_sandbox_enabled, validate_shell_command
from secops_agent.core.sudo import SudoAuthenticationDecision, command_uses_sudo
from secops_agent.core.tools import ToolCategory, ToolRegistry, _current_progress
from secops_agent.tools.forensics import (
    _effective_shell_inactivity_timeout,
    _effective_shell_timeout,
    _force_noninteractive_sudo,
    run_shell,
)


class FakeLLM:
    model_name = "fake-model"

    def __init__(self, command: str):
        self.command = command
        self.calls = 0

    def prepare_for_prompt(self, prompt: str, **kwargs):
        return None

    async def stream_chat(self, messages: list[Message], tools_schema=None):
        self.calls += 1
        if self.calls == 1:
            yield StreamChunk(
                tool_call=ToolCallChunk(
                    name="run_shell",
                    arguments={"command": self.command},
                    id="call_1",
                )
            )
        else:
            yield StreamChunk(content="done")


class OneToolLLM:
    model_name = "fake-model"

    def __init__(self, name: str, arguments: dict | None = None):
        self.name = name
        self.arguments = arguments or {}
        self.calls = 0

    def prepare_for_prompt(self, prompt: str, **kwargs):
        return None

    async def stream_chat(self, messages: list[Message], tools_schema=None):
        self.calls += 1
        if self.calls == 1:
            yield StreamChunk(
                tool_call=ToolCallChunk(
                    name=self.name,
                    arguments=self.arguments,
                    id="call_1",
                )
            )
            return
        yield StreamChunk(content="done")


class MissionStateEchoLLM:
    model_name = "fake-model"

    def __init__(self):
        self.calls = 0

    def prepare_for_prompt(self, prompt: str, **kwargs):
        return None

    async def stream_chat(self, messages: list[Message], tools_schema=None):
        self.calls += 1
        if self.calls == 1:
            yield StreamChunk(
                tool_call=ToolCallChunk(
                    name="run_shell",
                    arguments={"command": "date"},
                    id="call_1",
                )
            )
            return
        yield StreamChunk(
            content=(
                "The current system time is Thu Jun 4 11:40:55 PM GMT 2026.\n\n"
                "Mission State\n\n"
                " • Name: SecOps CLI session\n"
                " • Phase: SCOPING\n"
            )
        )


async def _run_agent(agent: SecOpsAgent, approval: ApprovalDecision | None = None):
    events = []
    async for event in agent.stream_response("run shell"):
        events.append(event)
        if isinstance(event, ApprovalRequestEvent):
            event.approval_future.set_result(approval or ApprovalDecision(allowed=False))
    return events


def _agent_for_command(command: str, tool_func=None) -> SecOpsAgent:
    registry = ToolRegistry()

    async def default_tool(**_):
        raise AssertionError("run_shell should not execute")

    registry.register(
        name="run_shell",
        description="Execute a shell command",
        category=ToolCategory.SYSTEM,
        parameters={"command": {"type": "string", "required": True}},
        func=tool_func or default_tool,
        dangerous=True,
    )
    permissions = PermissionEngine()
    permissions.remember(
        PermissionResource(kind="tool", name="run_shell"),
        PermissionDecision.ALLOW,
    )
    return SecOpsAgent(
        llm=FakeLLM(command),
        registry=registry,
        memory=ConversationMemory(),
        permissions=permissions,
        max_iterations=2,
    )


class AgentPermissionTests(unittest.IsolatedAsyncioTestCase):
    async def test_run_shell_requests_command_approval_for_sudo(self):
        agent = _agent_for_command("sudo id")

        events = await _run_agent(agent, ApprovalDecision(allowed=False))

        approvals = [event for event in events if isinstance(event, ApprovalRequestEvent)]
        self.assertEqual([event.resource.value for event in approvals], ["command_exact(sudo id)"])
        self.assertFalse(any(isinstance(event, ToolStartEvent) for event in events))
        result_events = [event for event in events if isinstance(event, ToolResultEvent)]
        self.assertIn("Permission denied by user: command(sudo id)", result_events[0].result.error)

    async def test_focused_local_answer_strips_mission_state_pollution(self):
        registry = ToolRegistry()

        async def run_shell(command: str):
            return "Thu Jun  4 11:40:55 PM GMT 2026\n[Exit Code: 0]"

        registry.register(
            name="run_shell",
            description="Execute a shell command",
            category=ToolCategory.SYSTEM,
            parameters={"command": {"type": "string", "required": True}},
            func=run_shell,
            dangerous=False,
        )
        agent = SecOpsAgent(
            llm=MissionStateEchoLLM(),
            registry=registry,
            memory=ConversationMemory(),
            permissions=PermissionEngine(),
            max_iterations=2,
        )

        events = []
        async for event in agent.stream_response("what time is it on my system?"):
            events.append(event)

        rendered_text = "".join(event.content for event in events if isinstance(event, TextEvent))
        self.assertIn("The current system time is", rendered_text)
        self.assertNotIn("Mission State", rendered_text)
        self.assertNotIn("SCOPING", rendered_text)

    async def test_interrupted_command_approval_uses_agy_followup_copy(self):
        agent = _agent_for_command("sudo id")

        events = await _run_agent(agent, ApprovalDecision(allowed=False, interrupted=True))

        result_events = [event for event in events if isinstance(event, ToolResultEvent)]
        self.assertIn(
            "Interrupted · What should SecOps CLI do instead?",
            result_events[0].result.error,
        )
        self.assertNotIn("Permission denied by user", result_events[0].result.error)

    async def test_run_shell_sudo_authentication_event_allows_real_forensics_tool(self):
        executed_commands = []

        async def safe_tool(command: str):
            executed_commands.append(command)
            return "executed"

        safe_tool.__module__ = "secops_agent.tools.forensics"
        agent = _agent_for_command("sudo id", tool_func=safe_tool)
        events = []

        async def sudo_status():
            return False, "sudo requires interactive authentication"

        with patch("secops_agent.core.agent.sudo_noninteractive_status", sudo_status), patch(
            "secops_agent.core.agent.can_prompt_for_sudo",
            return_value=True,
        ):
            async for event in agent.stream_response("run shell"):
                events.append(event)
                if isinstance(event, ApprovalRequestEvent):
                    event.approval_future.set_result(ApprovalDecision(allowed=True))
                elif isinstance(event, SudoAuthenticationRequestEvent):
                    event.authentication_future.set_result(
                        SudoAuthenticationDecision(True, "sudo authentication cached")
                    )

        self.assertEqual(executed_commands, ["sudo id"])
        self.assertEqual(len([event for event in events if isinstance(event, SudoAuthenticationRequestEvent)]), 1)
        self.assertTrue(any(isinstance(event, ToolStartEvent) for event in events))

    async def test_run_shell_sudo_authentication_failure_prevents_execution(self):
        executed_commands = []

        async def safe_tool(command: str):
            executed_commands.append(command)
            return "executed"

        safe_tool.__module__ = "secops_agent.tools.forensics"
        agent = _agent_for_command("sudo id", tool_func=safe_tool)
        events = []

        async def sudo_status():
            return False, "sudo requires interactive authentication"

        with patch("secops_agent.core.agent.sudo_noninteractive_status", sudo_status), patch(
            "secops_agent.core.agent.can_prompt_for_sudo",
            return_value=True,
        ):
            async for event in agent.stream_response("run shell"):
                events.append(event)
                if isinstance(event, ApprovalRequestEvent):
                    event.approval_future.set_result(ApprovalDecision(allowed=True))
                elif isinstance(event, SudoAuthenticationRequestEvent):
                    event.authentication_future.set_result(
                        SudoAuthenticationDecision(False, "sudo authentication failed")
                    )

        self.assertEqual(executed_commands, [])
        self.assertFalse(any(isinstance(event, ToolStartEvent) for event in events))
        result_events = [event for event in events if isinstance(event, ToolResultEvent)]
        self.assertIn("Sudo authentication was not completed", result_events[0].result.error)
        self.assertIn("sudo authentication failed", result_events[0].result.error)

    async def test_connect_vpn_config_sudo_authentication_event_allows_tool(self):
        executed_arguments = []

        async def connect_vpn_config(**kwargs):
            executed_arguments.append(kwargs)
            return "vpn started"

        registry = ToolRegistry()
        registry.register(
            name="connect_vpn_config",
            description="Connect VPN",
            category=ToolCategory.SYSTEM,
            parameters={"config_path": {"type": "string", "required": False}},
            func=connect_vpn_config,
            dangerous=True,
        )
        permissions = PermissionEngine()
        permissions.remember(
            PermissionResource(kind="tool", name="connect_vpn_config"),
            PermissionDecision.ALLOW,
        )
        agent = SecOpsAgent(
            llm=OneToolLLM("connect_vpn_config", {"config_path": "/tmp/lab.ovpn"}),
            registry=registry,
            memory=ConversationMemory(),
            permissions=permissions,
            max_iterations=1,
        )
        events = []
        approvals = []

        async def sudo_status():
            return False, "sudo requires interactive authentication"

        with patch("secops_agent.core.agent.sudo_noninteractive_status", sudo_status), patch(
            "secops_agent.core.agent.can_prompt_for_sudo",
            return_value=True,
        ):
            async for event in agent.stream_response("connect vpn"):
                events.append(event)
                if isinstance(event, ApprovalRequestEvent):
                    approvals.append(event)
                    event.approval_future.set_result(ApprovalDecision(allowed=True))
                elif isinstance(event, SudoAuthenticationRequestEvent):
                    event.authentication_future.set_result(
                        SudoAuthenticationDecision(True, "sudo authentication cached")
                    )

        self.assertEqual(
            [event.resource.value for event in approvals],
            ["command_exact(sudo openvpn --config /tmp/lab.ovpn)"],
        )
        sudo_events = [event for event in events if isinstance(event, SudoAuthenticationRequestEvent)]
        self.assertEqual(len(sudo_events), 1)
        self.assertEqual(sudo_events[0].command, "sudo openvpn --config /tmp/lab.ovpn")
        self.assertTrue(any(isinstance(event, ToolStartEvent) for event in events))
        self.assertEqual(executed_arguments, [{"config_path": "/tmp/lab.ovpn"}])

    async def test_connect_vpn_sandbox_block_does_not_prompt_for_password(self):
        from secops_agent.tools.forensics import connect_vpn_config

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "lab.ovpn"
            config_path.write_text("client\n", encoding="utf-8")
            registry = ToolRegistry()
            registry.register(
                name="connect_vpn_config",
                description="Connect VPN",
                category=ToolCategory.SYSTEM,
                parameters={"config_path": {"type": "string", "required": False}},
                func=connect_vpn_config,
                dangerous=True,
            )
            permissions = PermissionEngine()
            permissions.remember(
                PermissionResource(kind="tool", name="connect_vpn_config"),
                PermissionDecision.ALLOW,
            )
            agent = SecOpsAgent(
                llm=OneToolLLM("connect_vpn_config", {"config_path": str(config_path)}),
                registry=registry,
                memory=ConversationMemory(),
                permissions=permissions,
                max_iterations=1,
            )

            async def sudo_status():
                return False, "sudo requires interactive authentication"

            set_sandbox_enabled(True)
            try:
                with patch("secops_agent.core.agent.sudo_noninteractive_status", sudo_status), patch(
                    "secops_agent.core.agent.can_prompt_for_sudo",
                    return_value=True,
                ), patch(
                    "secops_agent.tools.forensics.shutil.which",
                    lambda name: "/usr/sbin/openvpn" if name == "openvpn" else None,
                ):
                    events = []
                    async for event in agent.stream_response("connect vpn"):
                        events.append(event)
            finally:
                set_sandbox_enabled(False)

        self.assertFalse(any(isinstance(event, SudoAuthenticationRequestEvent) for event in events))
        result = next(event.result for event in events if isinstance(event, ToolResultEvent))
        self.assertIn("Sandbox blocked command", (result.output or "") + (result.error or ""))

    async def test_sandbox_blocked_sudo_command_does_not_prompt_for_password(self):
        agent = _agent_for_command("sudo apt update", tool_func=run_shell)
        events = []

        async def sudo_status():
            return False, "sudo requires interactive authentication"

        set_sandbox_enabled(True)
        try:
            with patch("secops_agent.core.agent.sudo_noninteractive_status", sudo_status), patch(
                "secops_agent.core.agent.can_prompt_for_sudo",
                return_value=True,
            ):
                async for event in agent.stream_response("run shell"):
                    events.append(event)
                    if isinstance(event, ApprovalRequestEvent):
                        event.approval_future.set_result(ApprovalDecision(allowed=True))
        finally:
            set_sandbox_enabled(False)

        self.assertFalse(any(isinstance(event, SudoAuthenticationRequestEvent) for event in events))
        result = next(event.result for event in events if isinstance(event, ToolResultEvent))
        self.assertIn("Sandbox blocked command", (result.output or "") + (result.error or ""))

    async def test_run_shell_denies_blocked_executable_after_tool_allow(self):
        agent = _agent_for_command("rm -rf /tmp/example")

        events = await _run_agent(agent)

        self.assertFalse(any(isinstance(event, ToolStartEvent) for event in events))
        result_events = [event for event in events if isinstance(event, ToolResultEvent)]
        self.assertTrue(result_events)
        self.assertIn("command(rm)", result_events[0].result.error)

    async def test_run_shell_requests_command_approval_for_ask_executable(self):
        agent = _agent_for_command("nmap 127.0.0.1")

        events = await _run_agent(agent, ApprovalDecision(allowed=False))

        approvals = [event for event in events if isinstance(event, ApprovalRequestEvent)]
        self.assertEqual([event.resource.value for event in approvals], ["command_prefix(nmap 127.0.0.1)"])
        result_events = [event for event in events if isinstance(event, ToolResultEvent)]
        self.assertIn("Permission denied by user: command(nmap 127.0.0.1)", result_events[0].result.error)
        self.assertFalse(any(isinstance(event, ToolStartEvent) for event in events))

    async def test_run_shell_allows_safe_command_after_tool_allow(self):
        async def safe_tool(**_):
            return "executed"

        agent = _agent_for_command("ping 127.0.0.1", tool_func=safe_tool)

        events = await _run_agent(agent)

        self.assertTrue(any(isinstance(event, ToolStartEvent) for event in events))
        result_events = [event for event in events if isinstance(event, ToolResultEvent)]
        self.assertEqual(result_events[0].result.output, "executed")

    async def test_file_analyze_shadow_is_denied_before_execution(self):
        executed = []

        async def file_analyze(filepath: str):
            executed.append(filepath)
            return "executed"

        registry = ToolRegistry()
        registry.register(
            name="file_analyze",
            description="Analyze file",
            category=ToolCategory.FORENSICS,
            parameters={"filepath": {"type": "string", "required": True}},
            func=file_analyze,
            dangerous=False,
        )
        agent = SecOpsAgent(
            llm=OneToolLLM("file_analyze", {"filepath": "/etc/shadow"}),
            registry=registry,
            memory=ConversationMemory(),
            permissions=PermissionEngine(),
            max_iterations=1,
        )

        events = await _run_agent(agent)

        self.assertEqual(executed, [])
        self.assertFalse(any(isinstance(event, ToolStartEvent) for event in events))
        result = next(event.result for event in events if isinstance(event, ToolResultEvent))
        self.assertIn("Permission denied by policy: read_file(/etc/shadow)", result.error or "")

    async def test_log_analyze_shadow_is_denied_before_execution(self):
        executed = []

        async def log_analyze(logfile: str):
            executed.append(logfile)
            return "executed"

        registry = ToolRegistry()
        registry.register(
            name="log_analyze",
            description="Analyze log",
            category=ToolCategory.FORENSICS,
            parameters={"logfile": {"type": "string", "required": True}},
            func=log_analyze,
            dangerous=False,
        )
        agent = SecOpsAgent(
            llm=OneToolLLM("log_analyze", {"logfile": "/etc/shadow"}),
            registry=registry,
            memory=ConversationMemory(),
            permissions=PermissionEngine(),
            max_iterations=1,
        )

        events = await _run_agent(agent)

        self.assertEqual(executed, [])
        result = next(event.result for event in events if isinstance(event, ToolResultEvent))
        self.assertIn("Permission denied by policy: read_file(/etc/shadow)", result.error or "")

    async def test_find_files_root_search_requires_approval_before_execution(self):
        executed = []

        async def find_files(search_type: str, path: str = "/"):
            executed.append((search_type, path))
            return "executed"

        registry = ToolRegistry()
        registry.register(
            name="find_files",
            description="Find files",
            category=ToolCategory.FORENSICS,
            parameters={
                "search_type": {"type": "string", "required": True},
                "path": {"type": "string", "required": False, "default": "/"},
            },
            func=find_files,
            dangerous=False,
        )
        agent = SecOpsAgent(
            llm=OneToolLLM("find_files", {"search_type": "suid", "path": "/"}),
            registry=registry,
            memory=ConversationMemory(),
            permissions=PermissionEngine(),
            max_iterations=1,
        )

        events = await _run_agent(agent, ApprovalDecision(allowed=False))

        approvals = [event for event in events if isinstance(event, ApprovalRequestEvent)]
        self.assertEqual([event.resource.value for event in approvals], ["read_file(/)"])
        self.assertEqual(executed, [])
        result = next(event.result for event in events if isinstance(event, ToolResultEvent))
        self.assertIn("Permission denied by user: read_file(/)", result.error or "")

    async def test_workspace_safe_file_read_remains_allowed(self):
        executed = []

        async def file_analyze(filepath: str):
            executed.append(filepath)
            return "executed"

        with tempfile.TemporaryDirectory() as tmpdir:
            safe_path = str(Path(tmpdir) / "note.txt")
            Path(safe_path).write_text("ok", encoding="utf-8")
            registry = ToolRegistry()
            registry.register(
                name="file_analyze",
                description="Analyze file",
                category=ToolCategory.FORENSICS,
                parameters={"filepath": {"type": "string", "required": True}},
                func=file_analyze,
                dangerous=False,
            )
            agent = SecOpsAgent(
                llm=OneToolLLM("file_analyze", {"filepath": safe_path}),
                registry=registry,
                memory=ConversationMemory(),
                permissions=PermissionEngine(),
                max_iterations=1,
            )

            events = await _run_agent(agent)

        self.assertEqual(executed, [safe_path])
        result = next(event.result for event in events if isinstance(event, ToolResultEvent))
        self.assertEqual(result.output, "executed")

    async def test_persistent_command_approval_is_saved_to_settings(self):
        async def safe_tool(**_):
            return "executed"

        with tempfile.TemporaryDirectory() as tmpdir:
            settings_path = Path(tmpdir) / "settings.json"
            registry = ToolRegistry()
            registry.register(
                name="run_shell",
                description="Execute a shell command",
                category=ToolCategory.SYSTEM,
                parameters={"command": {"type": "string", "required": True}},
                func=safe_tool,
                dangerous=True,
            )
            permissions = PermissionEngine(settings_path=settings_path)
            permissions.remember(
                PermissionResource(kind="tool", name="run_shell"),
                PermissionDecision.ALLOW,
            )
            agent = SecOpsAgent(
                llm=FakeLLM("nmap 127.0.0.1"),
                registry=registry,
                memory=ConversationMemory(),
                permissions=permissions,
                max_iterations=2,
            )

            await _run_agent(
                agent,
                ApprovalDecision(allowed=True, scope=ApprovalScope.PERSISTENT),
            )

            reloaded = PermissionEngine(settings_path=settings_path)
            self.assertEqual(
                reloaded.check_command_permission(["nmap"], command_text="nmap 127.0.0.1"),
                PermissionDecision.ALLOW,
            )
            self.assertEqual(
                reloaded.check_command_permission(["nmap"], command_text="nmap 127.0.0.1 -sV"),
                PermissionDecision.ALLOW,
            )
            self.assertEqual(
                reloaded.check_command_permission(["nmap"], command_text="nmap 192.0.2.10"),
                PermissionDecision.ASK,
            )
            self.assertEqual(
                reloaded.check_command_permission(["sudo"], command_text="nmap 127.0.0.1 && sudo id"),
                PermissionDecision.ASK,
            )
            self.assertIn('"command_prefix(nmap 127.0.0.1)": "allow"', settings_path.read_text(encoding="utf-8"))

    def test_command_approval_resource_uses_exact_when_prefix_is_not_useful(self):
        engine = PermissionEngine()

        self.assertEqual(
            engine.command_approval_resource("pwd").value,
            "command_prefix(pwd)",
        )
        self.assertEqual(
            engine.command_approval_resource("nmap 127.0.0.1").value,
            "command_prefix(nmap 127.0.0.1)",
        )
        self.assertEqual(
            engine.command_approval_resource("nmap 127.0.0.1 -sV").value,
            "command_prefix(nmap 127.0.0.1)",
        )
        self.assertEqual(
            engine.command_approval_resource("uname -a").value,
            "command_exact(uname -a)",
        )
        self.assertEqual(
            engine.command_approval_resource("sudo apt update && sudo apt upgrade -y").value,
            "command_exact(sudo apt update && sudo apt upgrade -y)",
        )

    def test_exact_command_approval_does_not_cover_argument_extensions(self):
        engine = PermissionEngine()
        engine.remember(
            PermissionResource(kind="command_exact", name="uname -a"),
            PermissionDecision.ALLOW,
        )

        self.assertEqual(
            engine.check_command_permission(["uname"], command_text="uname -a"),
            PermissionDecision.ALLOW,
        )
        self.assertEqual(
            engine.check_command_permission(["uname"], command_text="uname -a --extra"),
            PermissionDecision.ASK,
        )

    async def test_command_prefix_approval_does_not_cover_shell_control_extensions(self):
        engine = PermissionEngine()
        engine.remember(
            PermissionResource(kind="command_prefix", name="nmap 127.0.0.1"),
            PermissionDecision.ALLOW,
        )

        self.assertEqual(
            engine.check_command_permission(["nmap"], command_text="nmap 127.0.0.1"),
            PermissionDecision.ALLOW,
        )
        self.assertEqual(
            engine.check_command_permission(["nmap"], command_text="nmap 127.0.0.1 -sV"),
            PermissionDecision.ALLOW,
        )

        unsafe_commands = (
            "nmap 127.0.0.1 && sudo id",
            "nmap 127.0.0.1 || sudo id",
            "nmap 127.0.0.1; sudo id",
            "nmap 127.0.0.1 | tee /tmp/out",
            "nmap 127.0.0.1 > /tmp/out",
            "nmap 127.0.0.1 < /tmp/in",
            "nmap 127.0.0.1 $(id)",
            "nmap 127.0.0.1 `id`",
            "nmap 127.0.0.1\nsudo id",
        )
        for command in unsafe_commands:
            with self.subTest(command=command):
                self.assertEqual(
                    engine.check_command_permission(["nmap"], command_text=command),
                    PermissionDecision.ASK,
                )

    async def test_once_exact_approval_covers_current_compound_shell_call(self):
        executed_commands = []

        async def safe_tool(command: str):
            executed_commands.append(command)
            return "executed"

        agent = _agent_for_command("nmap 127.0.0.1 && sudo id", tool_func=safe_tool)

        events = await _run_agent(agent, ApprovalDecision(allowed=True))

        approvals = [event for event in events if isinstance(event, ApprovalRequestEvent)]
        self.assertEqual(
            [event.resource.value for event in approvals],
            ["command_exact(nmap 127.0.0.1 && sudo id)"],
        )
        self.assertEqual(executed_commands, ["nmap 127.0.0.1 && sudo id"])

    async def test_amended_shell_command_is_rechecked_before_execution(self):
        executed_commands = []

        async def safe_tool(command: str):
            executed_commands.append(command)
            return "executed"

        agent = _agent_for_command("nmap 127.0.0.1", tool_func=safe_tool)

        events = await _run_agent(
            agent,
            ApprovalDecision(
                allowed=False,
                amended_arguments={"command": "ping 127.0.0.1"},
            ),
        )

        self.assertTrue(any(isinstance(event, ToolStartEvent) for event in events))
        self.assertEqual(executed_commands, ["ping 127.0.0.1"])
        tool_call_messages = [
            message for message in agent.memory.messages
            if message.role == "model" and message.tool_calls
        ]
        self.assertEqual(tool_call_messages[-1].tool_calls[0]["arguments"]["command"], "ping 127.0.0.1")

    def test_shell_command_resources_inspect_nested_shell_scripts(self):
        permissions = PermissionEngine()

        resources = permissions.shell_command_resources("bash -lc 'rm -rf /tmp/example'")

        self.assertEqual([resource.value for resource in resources], ["command(rm)"])

    def test_run_shell_sudo_detection_handles_newline_separator(self):
        self.assertTrue(command_uses_sudo("echo ok\nsudo id"))
        self.assertTrue(command_uses_sudo("echo $(sudo id)"))
        self.assertTrue(command_uses_sudo("echo `sudo id`"))
        self.assertTrue(command_uses_sudo("bash -lc 'sudo id'"))
        self.assertFalse(command_uses_sudo("echo 'sudo id'"))

    def test_run_shell_force_noninteractive_sudo_rewrites_newline_sudo(self):
        self.assertEqual(
            _force_noninteractive_sudo("echo ok\nsudo id"),
            "echo ok\nsudo -n id",
        )
        self.assertEqual(
            _force_noninteractive_sudo("echo $(sudo id)"),
            "echo $(sudo -n id)",
        )
        self.assertEqual(
            _force_noninteractive_sudo("echo `sudo id`"),
            "echo `sudo -n id`",
        )

    def test_shell_analysis_ignores_quoted_non_command_sudo_text(self):
        permissions = PermissionEngine()

        resources = permissions.shell_command_resources("echo 'sudo id'")

        self.assertEqual([resource.value for resource in resources], ["command(echo)"])
        self.assertFalse(command_uses_sudo("echo 'sudo id'"))

    def test_sandbox_uses_command_position_not_every_token(self):
        set_sandbox_enabled(True)
        try:
            self.assertTrue(validate_shell_command("echo sudo").allowed)
            self.assertFalse(validate_shell_command("echo $(sudo id)").allowed)
            self.assertFalse(validate_shell_command("bash -lc 'sudo id'").allowed)
        finally:
            set_sandbox_enabled(False)

    async def test_run_shell_timeout_stops_command_group(self):
        output = await run_shell("sh -c 'sleep 5 & wait'", timeout=1)

        self.assertIn("Command timed out after 1s and was stopped", output)
        self.assertIn("[Spool:", output)

    async def test_run_shell_inactivity_timeout_stops_silent_command(self):
        output = await run_shell("sh -c 'sleep 2'", timeout=5, inactivity_timeout=1)

        self.assertIn("Command stopped after 1s without output", output)
        self.assertIn("[Spool:", output)

    async def test_run_shell_reports_live_output_progress(self):
        progress_events = []
        token = _current_progress.set(lambda progress: progress_events.append(progress))
        try:
            output = await run_shell("sh -c 'echo first; sleep 0.1; echo second'", timeout=3)
        finally:
            _current_progress.reset(token)

        self.assertIn("first", output)
        self.assertIn("second", output)
        self.assertTrue(any(event.phase == "receiving output" for event in progress_events))

    async def test_run_shell_sudo_precheck_reports_progress_and_sanitizes_tty_error(self):
        calls = []

        async def fake_run_cmd(args, timeout=0):
            calls.append(args)
            if args == ["sudo", "-n", "true"]:
                return "", "sudo: a terminal is required to read the password", 1
            raise AssertionError(f"unexpected command: {args}")

        progress_events = []
        token = _current_progress.set(lambda progress: progress_events.append(progress))
        try:
            with patch("secops_agent.tools.forensics._run_cmd", fake_run_cmd), patch(
                "secops_agent.tools.forensics.shutil.which",
                lambda name: "/usr/bin/sudo" if name == "sudo" else None,
            ):
                output = await run_shell("sudo apt update", timeout=10)
        finally:
            _current_progress.reset(token)

        self.assertEqual(calls, [["sudo", "-n", "true"]])
        self.assertIn("Sudo requires interactive authentication", output)
        self.assertNotIn("terminal is required", output)
        self.assertTrue(any(event.phase == "checking sudo authentication" for event in progress_events))
        self.assertTrue(any(event.phase == "sudo authentication required" for event in progress_events))

    async def test_run_shell_uses_noninteractive_sudo_after_successful_precheck(self):
        captured = {}

        class FakeExecutionResult:
            stdout = "ok\n"
            stderr = ""
            timed_out = False
            timeout_reason = None
            exit_code = 0
            spool_path = Path("/tmp/secops-spool/combined.log")
            stdout_path = Path("/tmp/secops-spool/stdout.log")
            stderr_path = Path("/tmp/secops-spool/stderr.log")
            status = "completed"

        class FakeSupervisor:
            async def run_shell(self, command, **kwargs):
                captured["command"] = command
                return FakeExecutionResult()

        async def fake_sudo_status():
            return True, "sudo non-interactive authentication is available"

        with patch("secops_agent.tools.forensics._sudo_noninteractive_status", fake_sudo_status), patch(
            "secops_agent.tools.forensics.ExecutionSupervisor",
            FakeSupervisor,
        ):
            output = await run_shell("sudo killall openvpn && ps aux | grep openvpn", timeout=10)

        self.assertIn("ok", output)
        self.assertEqual(captured["command"], "sudo -n killall openvpn && ps aux | grep openvpn")

    async def test_agent_reports_idle_progress_for_silent_tool(self):
        registry = ToolRegistry()

        async def silent_tool():
            await asyncio.sleep(0.05)
            return "done"

        registry.register(
            name="silent_tool",
            description="Silent long-running test tool",
            category=ToolCategory.SYSTEM,
            parameters={},
            func=silent_tool,
            dangerous=False,
        )
        agent = SecOpsAgent(
            llm=OneToolLLM("silent_tool"),
            registry=registry,
            memory=ConversationMemory(),
            max_iterations=2,
            tool_idle_progress_interval=0.01,
        )

        events = await _run_agent(agent)

        self.assertTrue(
            any(
                isinstance(event, ToolProgressEvent)
                and event.phase == "still running"
                and "waiting for tool output" in event.detail
                for event in events
            )
        )
        result_events = [event for event in events if isinstance(event, ToolResultEvent)]
        self.assertEqual(result_events[0].result.output, "done")

    def test_system_update_commands_get_longer_default_timeout(self):
        self.assertEqual(_effective_shell_timeout("sudo apt upgrade -y", 30), 1800)
        self.assertEqual(_effective_shell_timeout("sudo apt install -y nmap", 30), 1800)
        self.assertEqual(_effective_shell_timeout("echo ok", 30), 30)
        self.assertEqual(_effective_shell_inactivity_timeout("sudo apt upgrade -y", 120), 600)
        self.assertEqual(_effective_shell_inactivity_timeout("echo ok", 120), 120)
        self.assertIsNone(_effective_shell_inactivity_timeout("sudo apt upgrade -y", 0))

    def test_registry_timeout_respects_tool_timeout_argument_default(self):
        async def slow_tool(timeout: int = 300):
            return "done"

        registry = ToolRegistry()
        registry.register(
            name="slow",
            description="Slow command",
            category=ToolCategory.SYSTEM,
            parameters={"timeout": {"type": "integer", "default": 300}},
            func=slow_tool,
            dangerous=False,
        )
        tool_def = registry.get_tool("slow")

        self.assertIsNotNone(tool_def)
        self.assertGreaterEqual(registry._execution_timeout(tool_def, {}), 305)

    def test_registry_outer_timeout_respects_long_running_shell_commands(self):
        registry = ToolRegistry()
        registry.register(
            name="run_shell",
            description="Shell command",
            category=ToolCategory.SYSTEM,
            parameters={
                "command": {"type": "string", "required": True},
                "timeout": {"type": "integer", "default": 300},
            },
            func=run_shell,
            dangerous=True,
        )
        tool_def = registry.get_tool("run_shell")

        self.assertIsNotNone(tool_def)
        self.assertGreaterEqual(
            registry._execution_timeout(
                tool_def,
                {"command": "sudo apt update && sudo apt upgrade -y", "timeout": 300},
            ),
            1805,
        )


if __name__ == "__main__":
    unittest.main()
