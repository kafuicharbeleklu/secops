from __future__ import annotations

import unittest

from secops_agent.core.agent import (
    ErrorEvent,
    PlanPreviewEvent,
    SecOpsAgent,
    TextEvent,
    ToolResultEvent,
    ToolStartEvent,
)
from secops_agent.core.llm import Message, StreamChunk, ToolCallChunk
from secops_agent.core.memory import ConversationMemory
from secops_agent.core.mission import MissionContext, PentestPhase
from secops_agent.core.permissions import PermissionDecision, PermissionEngine, PermissionResource
from secops_agent.core.planner import MissionPlanner
from secops_agent.core.reporting import generate_pentest_report
from secops_agent.core.result_parser import ToolResultParser
from secops_agent.core.structured_memory import StructuredMemory
from secops_agent.core.tools import ToolCategory, ToolRegistry


DNS_OUTPUT = """example.com. 300 IN A 93.184.216.34
example.com. 300 IN MX 10 mail.example.com.
"""

NMAP_WEB_OUTPUT = """Nmap scan report for 10.10.10.5
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.49
"""

DIR_BRUTE_OUTPUT = """/admin (Status: 200) [Size: 1234]
.git [Status: 200, Size: 321, Words: 10, Lines: 5]
"""

NIKTO_OUTPUT = """+ Server: Apache/2.4.49
+ /admin/: Directory indexing found.
+ The X-Content-Type-Options header is not defined.
"""


class ScenarioLLM:
    model_name = "scenario-model"

    def __init__(self, tool_name: str, arguments: dict, final_text: str = "done") -> None:
        self.tool_name = tool_name
        self.arguments = arguments
        self.final_text = final_text
        self.calls = 0
        self.contexts: list[str] = []

    def prepare_for_prompt(self, prompt: str, **kwargs):
        return None

    def set_mission_context(self, context: str) -> None:
        self.contexts.append(context)

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
        yield StreamChunk(content=self.final_text)


class FailingParser:
    def parse(self, tool_name: str, raw_output: str, arguments: dict | None = None):
        raise RuntimeError("parser boom")


def _integrate(
    structured_memory: StructuredMemory,
    parser: ToolResultParser,
    tool_name: str,
    output: str,
    arguments: dict,
):
    parsed = parser.parse(tool_name, output, arguments)
    structured_memory.knowledge.integrate(parsed)
    structured_memory.sync_to_mission()
    return parsed


async def _collect_events(agent: SecOpsAgent, prompt: str = "run scenario"):
    events = []
    async for event in agent.stream_response(prompt):
        events.append(event)
        if isinstance(event, PlanPreviewEvent) and event.acknowledgment_future is not None:
            event.acknowledgment_future.set_result(True)
    return events


class AgentEvaluationHarnessTests(unittest.IsolatedAsyncioTestCase):
    def test_recon_scenario_keeps_passive_actions_and_scope_context(self):
        mission = MissionContext(name="P10 recon scenario")
        mission.add_target("https://example.com", "url")
        memory = StructuredMemory(mission=mission)
        parser = ToolResultParser(mission=mission)

        parsed = _integrate(
            memory,
            parser,
            "dns_lookup",
            DNS_OUTPUT,
            {"domain": "example.com"},
        )
        actions = MissionPlanner(max_actions=12).plan(mission)
        context = memory.build_context_for_llm(include_conversation=False)

        self.assertEqual(parsed.summary.splitlines()[0], "DNS lookup for example.com: 2 record(s)")
        self.assertEqual(mission.phase, PentestPhase.RECON)
        self.assertIn("example.com", context)
        self.assertIn("Suggested Next Actions", context)
        self.assertIn("dns_lookup", {action.tool_name for action in actions})
        self.assertIn("whois_lookup", {action.tool_name for action in actions})
        self.assertFalse(
            any(
                action.requires_approval
                for action in actions
                if action.tool_name in {"dns_lookup", "whois_lookup", "http_headers"}
            )
        )

    def test_web_vulnerability_scenario_builds_findings_evidence_plan_and_report(self):
        mission = MissionContext(name="P10 web vuln scenario")
        mission.add_target("10.10.10.5", "ip")
        memory = StructuredMemory(mission=mission)
        parser = ToolResultParser(mission=mission)

        _integrate(memory, parser, "nmap_scan", NMAP_WEB_OUTPUT, {"target": "10.10.10.5"})
        _integrate(memory, parser, "dir_brute", DIR_BRUTE_OUTPUT, {"url": "http://10.10.10.5"})
        _integrate(memory, parser, "nikto_scan", NIKTO_OUTPUT, {"url": "http://10.10.10.5"})

        actions = MissionPlanner(max_actions=16).plan(mission)
        report = generate_pentest_report(mission, title="P10 Scenario Report")
        categories = {finding.category for finding in mission.findings}

        self.assertEqual(mission.phase, PentestPhase.VULNERABILITY)
        self.assertIn("known_vuln", categories)
        self.assertIn("dir_enum", categories)
        self.assertIn("web_vuln", categories)
        self.assertTrue(all(finding.evidence_items for finding in mission.findings))
        self.assertIn("cve_lookup", {action.tool_name for action in actions})
        self.assertIn("Validate finding evidence", " ".join(action.title for action in actions))
        self.assertIn("# P10 Scenario Report", report)
        self.assertIn("Apache Path Traversal", report)
        self.assertIn("Interesting path: /.git", report)
        self.assertIn("Structured evidence snippets:", report)

    async def test_permission_denial_scenario_blocks_tool_before_execution(self):
        executed: list[str] = []
        registry = ToolRegistry()

        async def dir_brute(**_):
            executed.append("dir_brute")
            return DIR_BRUTE_OUTPUT

        registry.register(
            name="dir_brute",
            description="Discover web paths",
            category=ToolCategory.WEB,
            parameters={"url": {"type": "string", "required": True}},
            func=dir_brute,
            dangerous=True,
        )

        mission = MissionContext(name="P10 permission scenario")
        mission.add_target("http://10.10.10.5", "url")
        memory = ConversationMemory()
        structured_memory = StructuredMemory(conversation=memory, mission=mission)
        permissions = PermissionEngine()
        permissions.remember(
            PermissionResource(kind="tool", name="dir_brute"),
            PermissionDecision.DENY,
        )
        agent = SecOpsAgent(
            llm=ScenarioLLM("dir_brute", {"url": "http://10.10.10.5"}),
            registry=registry,
            memory=memory,
            permissions=permissions,
            structured_memory=structured_memory,
            result_parser=ToolResultParser(mission=mission),
            max_iterations=2,
        )

        events = await _collect_events(agent)
        results = [event for event in events if isinstance(event, ToolResultEvent)]

        self.assertEqual(executed, [])
        self.assertEqual([event.name for event in events if isinstance(event, ToolStartEvent)], [])
        self.assertEqual(results[0].name, "dir_brute")
        self.assertIn("Permission denied by policy", results[0].result.error or "")
        self.assertEqual(len(mission.action_trace), 1)
        self.assertEqual(mission.action_trace[0].tool_name, "dir_brute")
        self.assertEqual(mission.action_trace[0].status, "denied")
        self.assertEqual(mission.action_trace[0].permission, "deny")
        self.assertIn("Permission denied by policy", mission.action_trace[0].error)

    async def test_parser_failure_scenario_keeps_agent_loop_alive(self):
        registry = ToolRegistry()

        async def custom_scan(**_):
            return "raw parser input"

        registry.register(
            name="custom_scan",
            description="Custom parser failure fixture",
            category=ToolCategory.RECON,
            parameters={"target": {"type": "string", "required": True}},
            func=custom_scan,
            dangerous=False,
        )

        mission = MissionContext(name="P10 parser failure scenario")
        memory = ConversationMemory()
        structured_memory = StructuredMemory(conversation=memory, mission=mission)
        llm = ScenarioLLM("custom_scan", {"target": "10.10.10.5"}, final_text="still alive")
        agent = SecOpsAgent(
            llm=llm,
            registry=registry,
            memory=memory,
            structured_memory=structured_memory,
            result_parser=FailingParser(),
            max_iterations=2,
        )

        events = await _collect_events(agent)
        text = "".join(event.content for event in events if isinstance(event, TextEvent))

        self.assertFalse(any(isinstance(event, ErrorEvent) for event in events))
        self.assertEqual([event.name for event in events if isinstance(event, ToolStartEvent)], ["custom_scan"])
        self.assertEqual([event.name for event in events if isinstance(event, ToolResultEvent)], ["custom_scan"])
        self.assertIn("still alive", text)
        self.assertEqual(llm.calls, 2)
        self.assertFalse(mission.findings)


if __name__ == "__main__":
    unittest.main()
