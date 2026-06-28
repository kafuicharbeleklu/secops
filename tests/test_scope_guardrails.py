from __future__ import annotations

import unittest

from secops_agent.core.agent import (
    ApprovalRequestEvent,
    SecOpsAgent,
    ToolCallEvent,
    ToolResultEvent,
    ToolStartEvent,
)
from secops_agent.core.llm import Message, StreamChunk, ToolCallChunk
from secops_agent.core.memory import ConversationMemory
from secops_agent.core.mission import MissionContext, Scope
from secops_agent.core.permissions import PermissionDecision, PermissionEngine, PermissionResource
from secops_agent.core.scope_guard import ScopeGuard, shell_command_targets, tool_target_values
from secops_agent.core.structured_memory import StructuredMemory
from secops_agent.core.tools import ToolCategory, ToolRegistry


class SingleToolLLM:
    model_name = "fake-model"

    def __init__(self, tool_name: str, arguments: dict):
        self.tool_name = tool_name
        self.arguments = arguments
        self.calls = 0

    def prepare_for_prompt(self, prompt: str, **kwargs):
        return None

    def set_mission_context(self, context: str) -> None:
        self.context = context

    async def stream_chat(self, messages: list[Message], tools_schema=None):
        self.calls += 1
        if self.calls == 1:
            yield StreamChunk(
                tool_call=ToolCallChunk(
                    name=self.tool_name,
                    arguments=dict(self.arguments),
                    id="call_1",
                )
            )
            return
        yield StreamChunk(content="done")


async def _collect_events(agent: SecOpsAgent):
    events = []
    async for event in agent.stream_response("run scoped tool"):
        events.append(event)
        if isinstance(event, ApprovalRequestEvent):
            event.approval_future.set_result(False)
    return events


class ScopeGuardrailTests(unittest.IsolatedAsyncioTestCase):
    def test_scope_matches_ip_cidr_domain_subdomain_and_url_path(self):
        scope = Scope(
            in_scope=["10.10.10.0/24", "example.com", "https://portal.example.net/app"],
            out_of_scope=["10.10.10.8", "admin.example.com"],
        )

        self.assertTrue(scope.is_in_scope("10.10.10.7"))
        self.assertTrue(scope.is_in_scope("10.10.10.0/29"))
        self.assertTrue(scope.is_in_scope("https://www.example.com/login"))
        self.assertTrue(scope.is_in_scope("https://portal.example.net/app/login"))
        self.assertFalse(scope.is_in_scope("10.10.11.7"))
        self.assertFalse(scope.is_in_scope("10.10.10.0/16"))
        self.assertFalse(scope.is_in_scope("10.10.10.8"))
        self.assertFalse(scope.is_in_scope("https://admin.example.com"))
        self.assertFalse(scope.is_in_scope("https://portal.example.net/admin"))

    def test_scope_guard_extracts_tool_and_shell_targets(self):
        self.assertEqual(
            tool_target_values("http_headers", {"url": "https://www.example.com/a"}),
            ["https://www.example.com/a"],
        )
        self.assertEqual(
            shell_command_targets("nmap -sV -p 80 10.10.10.5 && curl https://www.example.com"),
            ["10.10.10.5", "https://www.example.com"],
        )
        self.assertEqual(shell_command_targets("cat report.example.com.txt"), [])

    def test_scope_targets_match_nested_shell_analysis(self):
        self.assertEqual(
            shell_command_targets("bash -lc 'curl http://10.10.10.7/'"),
            ["http://10.10.10.7/"],
        )
        self.assertEqual(
            shell_command_targets("echo $(curl https://www.example.com/status)"),
            ["https://www.example.com/status"],
        )

    async def test_agent_blocks_out_of_scope_tool_before_execution(self):
        executed: list[str] = []
        registry = ToolRegistry()

        async def ping_host(**_):
            executed.append("ping_host")
            return "pong"

        registry.register(
            name="ping_host",
            description="Ping host",
            category=ToolCategory.NETWORK,
            parameters={"target": {"type": "string", "required": True}},
            func=ping_host,
            dangerous=False,
        )

        memory = ConversationMemory()
        mission = MissionContext(name="scope test")
        mission.scope.in_scope.append("10.10.10.0/24")
        structured_memory = StructuredMemory(conversation=memory, mission=mission)
        agent = SecOpsAgent(
            llm=SingleToolLLM("ping_host", {"target": "203.0.113.10"}),
            registry=registry,
            memory=memory,
            structured_memory=structured_memory,
            max_iterations=2,
        )

        events = await _collect_events(agent)

        self.assertEqual([event.name for event in events if isinstance(event, ToolCallEvent)], ["ping_host"])
        self.assertEqual([event.name for event in events if isinstance(event, ToolStartEvent)], [])
        self.assertEqual(executed, [])
        results = [event for event in events if isinstance(event, ToolResultEvent)]
        self.assertEqual(results[0].name, "ping_host")
        self.assertIn("outside authorized scope", results[0].result.error or "")
        self.assertIn("203.0.113.10", mission.blocked_reasons[-1])

    async def test_agent_blocks_out_of_scope_shell_network_command_before_prompt(self):
        executed: list[str] = []
        registry = ToolRegistry()

        async def run_shell(**_):
            executed.append("run_shell")
            return "shell output"

        registry.register(
            name="run_shell",
            description="Run shell",
            category=ToolCategory.SYSTEM,
            parameters={"command": {"type": "string", "required": True}},
            func=run_shell,
            dangerous=True,
        )

        memory = ConversationMemory()
        mission = MissionContext(name="shell scope test")
        mission.scope.in_scope.append("10.10.10.0/24")
        structured_memory = StructuredMemory(conversation=memory, mission=mission)
        permissions = PermissionEngine()
        permissions.remember(
            PermissionResource(kind="tool", name="run_shell"),
            PermissionDecision.ALLOW,
        )
        agent = SecOpsAgent(
            llm=SingleToolLLM("run_shell", {"command": "nmap -sV 203.0.113.10"}),
            registry=registry,
            memory=memory,
            permissions=permissions,
            structured_memory=structured_memory,
            max_iterations=2,
        )

        events = await _collect_events(agent)

        self.assertEqual([event.tool_name for event in events if isinstance(event, ApprovalRequestEvent)], [])
        self.assertEqual([event.name for event in events if isinstance(event, ToolStartEvent)], [])
        self.assertEqual(executed, [])
        results = [event for event in events if isinstance(event, ToolResultEvent)]
        self.assertEqual(results[0].name, "run_shell")
        self.assertIn("outside authorized scope", results[0].result.error or "")

    async def test_agent_allows_in_scope_url_tool(self):
        executed: list[str] = []
        registry = ToolRegistry()

        async def http_headers(**_):
            executed.append("http_headers")
            return "HTTP/1.1 200 OK"

        registry.register(
            name="http_headers",
            description="Fetch headers",
            category=ToolCategory.RECON,
            parameters={"url": {"type": "string", "required": True}},
            func=http_headers,
            dangerous=False,
        )

        memory = ConversationMemory()
        mission = MissionContext(name="scope allow test")
        mission.scope.in_scope.append("example.com")
        structured_memory = StructuredMemory(conversation=memory, mission=mission)
        agent = SecOpsAgent(
            llm=SingleToolLLM("http_headers", {"url": "https://www.example.com/login"}),
            registry=registry,
            memory=memory,
            structured_memory=structured_memory,
            max_iterations=2,
        )

        events = await _collect_events(agent)

        self.assertEqual([event.name for event in events if isinstance(event, ToolStartEvent)], ["http_headers"])
        self.assertEqual(executed, ["http_headers"])
        self.assertFalse(any("scope" in reason.lower() for reason in mission.blocked_reasons))

    def test_scope_guard_blocks_explicit_out_of_scope_without_in_scope_list(self):
        mission = MissionContext(name="explicit deny test")
        mission.scope.out_of_scope.append("blocked.example.com")

        result = ScopeGuard(mission).check_tool_call(
            "http_headers",
            {"url": "https://blocked.example.com/admin"},
        )

        self.assertFalse(result.allowed)
        self.assertIn("Out-of-scope target blocked", result.reason)


if __name__ == "__main__":
    unittest.main()
