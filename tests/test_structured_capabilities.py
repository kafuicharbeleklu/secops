from __future__ import annotations

import unittest

from secops_agent.core.agent import PlanPreviewEvent, SecOpsAgent
from secops_agent.core.llm import Message, StreamChunk, ToolCallChunk
from secops_agent.core.memory import ConversationMemory
from secops_agent.core.mission import MissionContext
from secops_agent.core.permissions import (
    PermissionDecision,
    PermissionEngine,
    PermissionResource,
)
from secops_agent.core.result_parser import ToolResultParser, parse_nmap_output
from secops_agent.core.structured_memory import StructuredMemory
from secops_agent.core.tools import ToolCategory, ToolRegistry


NMAP_OUTPUT = """Nmap scan report for scanme.example
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.4
80/tcp   open  http    Apache httpd 2.4.49
443/tcp  open  https
3306/tcp open  mysql   MySQL 5.7
"""


class StructuredFakeLLM:
    model_name = "fake-model"

    def __init__(self) -> None:
        self.calls = 0
        self.mission_contexts: list[str] = []
        self.prepared_contexts: list[dict | None] = []

    def set_mission_context(self, context: str) -> None:
        self.mission_contexts.append(context)

    def prepare_for_prompt(self, prompt: str, context: dict | None = None):
        self.prepared_contexts.append(context)
        return None

    async def stream_chat(self, messages: list[Message], tools_schema=None):
        self.calls += 1
        if self.calls == 1:
            yield StreamChunk(
                tool_call=ToolCallChunk(
                    name="nmap_scan",
                    arguments={"target": "10.10.10.5"},
                    id="call_1",
                )
            )
            return
        yield StreamChunk(content="done")


class StructuredCapabilityTests(unittest.IsolatedAsyncioTestCase):
    def test_nmap_parser_keeps_line_boundaries_when_version_is_missing(self):
        parsed = parse_nmap_output(NMAP_OUTPUT, {"target": "10.10.10.5"})

        services = {(svc.port, svc.service, svc.version) for svc in parsed.services_discovered}

        self.assertEqual(len(parsed.services_discovered), 4)
        self.assertIn((443, "https", ""), services)
        self.assertIn((3306, "mysql", "MySQL 5.7"), services)
        self.assertEqual(parsed.severity, "critical")
        self.assertTrue(any("CVE-2021-41773" in f.title for f in parsed.findings))

    async def test_agent_integrates_tool_results_into_structured_context(self):
        async def nmap_scan(**_):
            return NMAP_OUTPUT

        async def http_headers(**_):
            return "HTTP/1.1 200 OK\n"

        registry = ToolRegistry()
        registry.register(
            name="nmap_scan",
            description="Run an Nmap scan",
            category=ToolCategory.NETWORK,
            parameters={"target": {"type": "string", "required": True}},
            func=nmap_scan,
            dangerous=False,
        )
        registry.register(
            name="http_headers",
            description="Fetch HTTP headers",
            category=ToolCategory.RECON,
            parameters={"url": {"type": "string", "required": True}},
            func=http_headers,
            dangerous=False,
        )

        mission = MissionContext(name="unit-test mission")
        memory = ConversationMemory()
        structured_memory = StructuredMemory(conversation=memory, mission=mission)
        llm = StructuredFakeLLM()
        permissions = PermissionEngine()
        permissions.remember(
            PermissionResource(kind="tool", name="nmap_scan"),
            PermissionDecision.ALLOW,
        )
        agent = SecOpsAgent(
            llm=llm,
            registry=registry,
            memory=memory,
            permissions=permissions,
            structured_memory=structured_memory,
            result_parser=ToolResultParser(mission=mission),
            max_iterations=2,
        )

        async for _event in agent.stream_response("scan 10.10.10.5"):
            if isinstance(_event, PlanPreviewEvent) and _event.acknowledgment_future is not None:
                _event.acknowledgment_future.set_result(True)

        self.assertEqual(llm.calls, 2)
        self.assertEqual(len(mission.hosts), 1)
        self.assertEqual(len(mission.services), 4)
        self.assertTrue(mission.findings)
        self.assertIn("10.10.10.5:80/tcp", structured_memory.knowledge.services)
        self.assertTrue(llm.mission_contexts)
        self.assertIn("Known Attack Surface", llm.mission_contexts[-1])
        self.assertIn("80/tcp http Apache httpd 2.4.49", llm.mission_contexts[-1])
        self.assertNotIn("Recent Conversation", llm.mission_contexts[-1])
        self.assertEqual(len(mission.action_trace), 1)
        trace = mission.action_trace[0]
        self.assertEqual(trace.tool_name, "nmap_scan")
        self.assertEqual(trace.status, "succeeded")
        self.assertEqual(trace.permission, "allow")
        self.assertIn("service(s)", trace.result_summary)
        self.assertTrue(any("New service" in change for change in trace.state_changes))
        self.assertTrue(any(action["tool_name"] == "http_headers" for action in trace.suggested_actions))

    def test_repeated_parser_results_do_not_duplicate_findings(self):
        mission = MissionContext(name="dedupe mission")
        parser = ToolResultParser(mission=mission)
        structured_memory = StructuredMemory(mission=mission)

        first = parser.parse("nmap_scan", NMAP_OUTPUT, {"target": "10.10.10.5"})
        second = parser.parse("nmap_scan", NMAP_OUTPUT, {"target": "10.10.10.5"})

        first_changes = structured_memory.knowledge.integrate(first)
        second_changes = structured_memory.knowledge.integrate(second)
        structured_memory.sync_to_mission()

        self.assertEqual(len(mission.hosts), 1)
        self.assertEqual(len(mission.services), 4)
        self.assertEqual(len(mission.findings), 1)
        self.assertEqual(len(structured_memory.knowledge.findings), 1)
        self.assertTrue(any("New finding" in change for change in first_changes))
        self.assertFalse(any("New finding" in change for change in second_changes))


if __name__ == "__main__":
    unittest.main()
