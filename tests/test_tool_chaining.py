from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from secops_agent.core.agent import (
    ApprovalRequestEvent,
    PlanPreviewEvent,
    SecOpsAgent,
    SuggestedActionsEvent,
    TextEvent,
    ToolCallEvent,
    ToolResultEvent,
    ToolStartEvent,
)
from secops_agent.core.experience import ExperienceStore
from secops_agent.core.llm import Message, StreamChunk, ToolCallChunk
from secops_agent.core.memory import ConversationMemory
from secops_agent.core.mission import MissionContext, Service
from secops_agent.core.request_context import EnvironmentHint, set_operator_environment
from secops_agent.core.permissions import (
    ApprovalDecision,
    PermissionDecision,
    PermissionEngine,
    PermissionResource,
)
from secops_agent.core.planner import NextAction
from secops_agent.core.result_parser import ToolResultParser
from secops_agent.core.structured_memory import StructuredMemory
from secops_agent.core.tools import ToolCategory, ToolRegistry


NMAP_HTTP_OUTPUT = """Nmap scan report for scanme.example
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.51
"""


class ChainFakeLLM:
    model_name = "fake-model"

    def __init__(self) -> None:
        self.calls = 0
        self.last_prompt = ""
        self.last_context = None

    def prepare_for_prompt(self, prompt: str, **kwargs):
        self.last_prompt = prompt
        self.last_context = kwargs.get("context")
        return None

    def set_mission_context(self, context: str) -> None:
        self.context = context

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


class FollowupToolLLM(ChainFakeLLM):
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
        if self.calls == 2:
            yield StreamChunk(
                tool_call=ToolCallChunk(
                    name="http_headers",
                    arguments={"url": "http://10.10.10.5"},
                    id="call_2",
                )
            )
            return
        yield StreamChunk(content="done")


async def _collect_events(
    agent: SecOpsAgent,
    prompt: str = "enumerate 10.10.10.5",
    approval: ApprovalDecision | None = None,
):
    events = []
    async for event in agent.stream_response(prompt):
        events.append(event)
        if isinstance(event, ApprovalRequestEvent):
            event.approval_future.set_result(approval or ApprovalDecision(allowed=False))
        elif isinstance(event, PlanPreviewEvent) and event.acknowledgment_future is not None:
            event.acknowledgment_future.set_result(True)
    return events


class ToolChainingTests(unittest.IsolatedAsyncioTestCase):
    async def test_alternating_calls_stop_after_three_empty_observations(self):
        """Convergence must track blackboard progress, not only call identity."""
        registry = ToolRegistry()
        executed: list[str] = []

        for name, output in (
            ("hash_generate", "🔑 Hash Generation for: 'x'\n\n  SHA256: abcdef0123456789"),
            ("hash_identify", "🔐 Hash Analysis\n  Length: 64 chars\n  Possible types:\n    • SHA-256"),
            ("sysinfo", "🖥️ System Information\n\n  Hostname: test-host"),
        ):
            async def tool(*, _name=name, _output=output, **_kwargs):
                executed.append(_name)
                return _output

            registry.register(
                name=name,
                description=name,
                category=ToolCategory.CRYPTO,
                parameters={},
                func=tool,
                dangerous=False,
            )

        class AlternatingLLM(ChainFakeLLM):
            def __init__(self):
                super().__init__()
                self.names = ["hash_generate", "hash_identify", "sysinfo", "hash_generate"]

            async def stream_chat(self, messages, tools_schema=None):
                self.calls += 1
                if self.calls <= len(self.names):
                    yield StreamChunk(
                        tool_call=ToolCallChunk(
                            name=self.names[self.calls - 1], arguments={}, id=f"call_{self.calls}"
                        )
                    )
                    return
                yield StreamChunk(content="done")

        memory = ConversationMemory()
        mission = MissionContext(name="no progress")
        agent = SecOpsAgent(
            llm=AlternatingLLM(), registry=registry, memory=memory,
            permissions=PermissionEngine(),
            structured_memory=StructuredMemory(conversation=memory, mission=mission),
            result_parser=ToolResultParser(mission=mission), max_iterations=8,
        )

        events = await _collect_events(agent, "enumerate the authorized lab")
        self.assertEqual(executed, ["hash_generate", "hash_identify", "sysinfo"])
        self.assertTrue(any(
            isinstance(event, TextEvent) and "three successful actions" in event.content
            for event in events
        ))

    def _proposal_agent(self, *, allow_dir_brute: bool = False, experience_store=None):
        executed: list[str] = []
        registry = ToolRegistry()

        async def nmap_scan(**_):
            executed.append("nmap_scan")
            return NMAP_HTTP_OUTPUT

        async def http_headers(**_):
            executed.append("http_headers")
            return "HTTP/1.1 200 OK\nServer: Apache/2.4.51\n"

        async def tech_detect(**_):
            executed.append("tech_detect")
            return "Technology Detection for http://10.10.10.5:\n  Server: Apache"

        async def dir_brute(**_):
            executed.append("dir_brute")
            return "/admin (Status: 200) [Size: 1234]"

        registry.register(
            name="nmap_scan",
            description="Run nmap",
            category=ToolCategory.NETWORK,
            parameters={
                "target": {"type": "string", "required": True},
                "extra_args": {"type": "string", "required": False},
            },
            func=nmap_scan,
            dangerous=False,
        )
        registry.register(
            name="http_headers",
            description="Fetch headers",
            category=ToolCategory.RECON,
            parameters={"url": {"type": "string", "required": True}},
            func=http_headers,
            dangerous=False,
        )
        registry.register(
            name="tech_detect",
            description="Detect technologies",
            category=ToolCategory.RECON,
            parameters={"url": {"type": "string", "required": True}},
            func=tech_detect,
            dangerous=False,
        )
        registry.register(
            name="dir_brute",
            description="Discover paths",
            category=ToolCategory.WEB,
            parameters={"url": {"type": "string", "required": True}},
            func=dir_brute,
            dangerous=True,
        )

        memory = ConversationMemory()
        mission = MissionContext(name="proposal selection mission")
        structured_memory = StructuredMemory(conversation=memory, mission=mission)
        permissions = PermissionEngine()
        for tool_name in ("nmap_scan", "http_headers", "tech_detect"):
            permissions.remember(
                PermissionResource(kind="tool", name=tool_name),
                PermissionDecision.ALLOW,
            )
        if allow_dir_brute:
            permissions.remember(
                PermissionResource(kind="tool", name="dir_brute"),
                PermissionDecision.ALLOW,
            )

        llm = ChainFakeLLM()
        agent = SecOpsAgent(
            llm=llm,
            registry=registry,
            memory=memory,
            permissions=permissions,
            structured_memory=structured_memory,
            result_parser=ToolResultParser(mission=mission),
            experience_store=experience_store,
            max_iterations=2,
        )
        return agent, executed, llm

    async def test_duplicate_in_iteration_tool_call_runs_once(self):
        """E5 (live re-audit 2026-07-04, audit §7.8 'VPN card rendered twice'):
        some model tiers emit the *same* tool call twice in one response. The loop
        must execute it once and surface one result/card, not two."""
        agent, executed, _ = self._proposal_agent()

        class DoubleNmapLLM(ChainFakeLLM):
            async def stream_chat(self, messages, tools_schema=None):
                self.calls += 1
                if self.calls == 1:
                    call = ToolCallChunk(
                        name="nmap_scan",
                        arguments={"target": "10.10.10.5"},
                        id="dup",
                    )
                    yield StreamChunk(tool_call=call)
                    yield StreamChunk(tool_call=call)  # identical, same response
                    return
                yield StreamChunk(content="done")

        agent.llm = DoubleNmapLLM()
        events = await _collect_events(agent, "enumerate 10.10.10.5")
        results = [
            event for event in events
            if isinstance(event, ToolResultEvent) and event.name == "nmap_scan"
        ]
        self.assertEqual(
            executed.count("nmap_scan"), 1,
            f"nmap_scan executed {executed.count('nmap_scan')}x (expected 1)",
        )
        self.assertEqual(len(results), 1, "duplicate tool result event / card")

    async def test_planner_candidates_are_not_executed_by_default(self):
        executed: list[str] = []
        registry = ToolRegistry()

        async def nmap_scan(**_):
            executed.append("nmap_scan")
            return NMAP_HTTP_OUTPUT

        async def http_headers(**_):
            executed.append("http_headers")
            return "HTTP/1.1 200 OK\nServer: Apache/2.4.51\n"

        registry.register(
            name="nmap_scan",
            description="Run nmap",
            category=ToolCategory.NETWORK,
            parameters={
                "target": {"type": "string", "required": True},
                "extra_args": {"type": "string", "required": False},
            },
            func=nmap_scan,
            dangerous=False,
        )
        registry.register(
            name="http_headers",
            description="Fetch headers",
            category=ToolCategory.RECON,
            parameters={"url": {"type": "string", "required": True}},
            func=http_headers,
            dangerous=False,
        )

        memory = ConversationMemory()
        mission = MissionContext(name="proposal-first mission")
        structured_memory = StructuredMemory(conversation=memory, mission=mission)
        permissions = PermissionEngine()
        for tool_name in ("nmap_scan", "http_headers"):
            permissions.remember(
                PermissionResource(kind="tool", name=tool_name),
                PermissionDecision.ALLOW,
            )

        agent = SecOpsAgent(
            llm=ChainFakeLLM(),
            registry=registry,
            memory=memory,
            permissions=permissions,
            structured_memory=structured_memory,
            result_parser=ToolResultParser(mission=mission),
            max_iterations=2,
        )

        # A specific single-tool request stays in single-step proposal mode:
        # the planner suggests http_headers but never auto-executes it.
        events = await _collect_events(agent, "fais un scan des ports sur 10.10.10.5")

        suggestions = [event for event in events if isinstance(event, SuggestedActionsEvent)]
        self.assertEqual([event.name for event in events if isinstance(event, ToolCallEvent)], ["nmap_scan"])
        self.assertEqual([event.name for event in events if isinstance(event, ToolStartEvent)], ["nmap_scan"])
        self.assertEqual(executed, ["nmap_scan"])
        self.assertEqual(len(mission.services), 1)
        self.assertEqual(len(suggestions), 1)
        self.assertEqual([action.tool_name for action in suggestions[0].actions], ["http_headers"])

    async def test_open_ended_request_chains_llm_tool_calls_multi_step(self):
        # RC2: a broad request ("enumerate 10.10.10.5") lets the model chain
        # tool calls across iterations within one turn.
        agent, executed, _ = self._proposal_agent()
        agent.max_iterations = 4
        llm = FollowupToolLLM()
        agent.llm = llm

        events = await _collect_events(agent)

        # nmap (iter 1) -> http_headers (iter 2) -> final text (iter 3).
        self.assertEqual(llm.calls, 3)
        self.assertEqual(
            [event.name for event in events if isinstance(event, ToolCallEvent)],
            ["nmap_scan", "http_headers"],
        )
        self.assertEqual(
            [event.name for event in events if isinstance(event, ToolStartEvent)],
            ["nmap_scan", "http_headers"],
        )
        self.assertEqual(executed, ["nmap_scan", "http_headers"])
        # Suggestions are suppressed while the model is chaining.
        self.assertEqual(
            [event for event in events if isinstance(event, SuggestedActionsEvent)],
            [],
        )

    async def test_continue_runs_only_top_suggested_action_without_llm(self):
        agent, executed, llm = self._proposal_agent()
        await _collect_events(agent)
        calls_before = llm.calls

        events = await _collect_events(agent, "continue")

        self.assertEqual(llm.calls, calls_before)
        self.assertEqual([event.name for event in events if isinstance(event, ToolCallEvent)], ["http_headers"])
        self.assertEqual([event.name for event in events if isinstance(event, ToolStartEvent)], ["http_headers"])
        self.assertEqual(executed, ["nmap_scan", "http_headers"])

    async def test_continue_skips_high_risk_missing_tool_install_suggestion(self):
        executed: list[str] = []
        registry = ToolRegistry()

        async def run_shell(**_):
            executed.append("run_shell")
            return "installed"

        async def http_headers(**_):
            executed.append("http_headers")
            return "Server: Apache/2.4.41 (Ubuntu)"

        registry.register(
            name="run_shell",
            description="Run shell",
            category=ToolCategory.SYSTEM,
            parameters={"command": {"type": "string", "required": True}},
            func=run_shell,
            dangerous=True,
        )
        registry.register(
            name="http_headers",
            description="Fetch HTTP headers",
            category=ToolCategory.WEB,
            parameters={"url": {"type": "string", "required": True}},
            func=http_headers,
            dangerous=False,
        )

        llm = ChainFakeLLM()
        agent = SecOpsAgent(
            llm=llm,
            registry=registry,
            memory=ConversationMemory(),
            permissions=PermissionEngine(),
            max_iterations=1,
        )
        agent._last_suggested_actions = [
            NextAction(
                title="Install missing local tool: ffuf",
                rationale="ffuf is missing locally.",
                tool_name="run_shell",
                arguments={"command": "sudo apt install -y ffuf"},
                risk="high",
                requires_approval=True,
                method="missing_tool_install",
            ),
            NextAction(
                title="Analyze HTTP headers",
                rationale="HTTP is open.",
                tool_name="http_headers",
                arguments={"url": "http://10.10.10.5"},
                risk="low",
                method="http_headers",
            ),
        ]
        calls_before = llm.calls

        events = await _collect_events(agent, "continue")

        self.assertEqual(llm.calls, calls_before)
        self.assertEqual([event.name for event in events if isinstance(event, ToolCallEvent)], ["http_headers"])
        self.assertEqual([event.name for event in events if isinstance(event, ToolStartEvent)], ["http_headers"])
        self.assertEqual(executed, ["http_headers"])

    async def test_numbered_choice_runs_selected_suggestion_without_llm(self):
        agent, executed, llm = self._proposal_agent()
        await _collect_events(agent)
        calls_before = llm.calls

        events = await _collect_events(agent, "2")

        self.assertEqual(llm.calls, calls_before)
        self.assertEqual([event.name for event in events if isinstance(event, ToolCallEvent)], ["tech_detect"])
        self.assertEqual([event.name for event in events if isinstance(event, ToolStartEvent)], ["tech_detect"])
        self.assertEqual(executed, ["nmap_scan", "tech_detect"])

    async def test_suggestion_selection_records_learning_signals(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = ExperienceStore(Path(tmpdir) / "case_lessons.jsonl")
            agent, executed, llm = self._proposal_agent(experience_store=store)

            await _collect_events(agent)
            selected_events = await _collect_events(agent, "2")
            signals = store.load_signals(limit=None)
            summary = store.signal_summary()

        outcomes_by_tool = [
            (signal.outcome, signal.tool_name)
            for signal in signals
            if signal.tool_name in {"http_headers", "tech_detect", "dir_brute"}
        ]

        self.assertEqual([event.name for event in selected_events if isinstance(event, ToolStartEvent)], ["tech_detect"])
        self.assertEqual(executed, ["nmap_scan", "tech_detect"])
        self.assertEqual(llm.calls, 2)
        self.assertIn(("suggested", "http_headers"), outcomes_by_tool)
        self.assertIn(("suggested", "tech_detect"), outcomes_by_tool)
        self.assertIn(("suggested", "dir_brute"), outcomes_by_tool)
        self.assertIn(("selected", "tech_detect"), outcomes_by_tool)
        self.assertIn(("ignored", "http_headers"), outcomes_by_tool)
        self.assertIn(("ignored", "dir_brute"), outcomes_by_tool)
        self.assertIn(("succeeded", "tech_detect"), outcomes_by_tool)
        self.assertEqual(summary["selected"], 1)
        self.assertEqual(summary["succeeded"], 1)
        self.assertEqual(summary["failed"], 0)

    async def test_multi_number_choice_runs_selected_suggestions_without_extra_wording(self):
        agent, executed, llm = self._proposal_agent()
        await _collect_events(agent)
        calls_before_selection = llm.calls

        selected_events = await _collect_events(agent, "1 2")

        self.assertEqual(llm.calls, calls_before_selection)
        self.assertEqual([event.name for event in selected_events if isinstance(event, ToolStartEvent)], ["http_headers", "tech_detect"])
        self.assertEqual(executed, ["nmap_scan", "http_headers", "tech_detect"])

    async def test_all_choice_runs_all_available_suggestions(self):
        agent, executed, llm = self._proposal_agent(allow_dir_brute=True)
        await _collect_events(agent)
        calls_before_selection = llm.calls

        selected_events = await _collect_events(agent, "tous")

        self.assertEqual(llm.calls, calls_before_selection)
        self.assertEqual([event.name for event in selected_events if isinstance(event, ToolStartEvent)], ["http_headers", "tech_detect", "dir_brute"])
        self.assertEqual(executed, ["nmap_scan", "http_headers", "tech_detect", "dir_brute"])

    async def test_all_except_choice_excludes_numbered_suggestions(self):
        agent, executed, llm = self._proposal_agent(allow_dir_brute=True)
        await _collect_events(agent)
        calls_before_selection = llm.calls

        selected_events = await _collect_events(agent, "tout sauf 3")

        self.assertEqual(llm.calls, calls_before_selection)
        self.assertEqual([event.name for event in selected_events if isinstance(event, ToolStartEvent)], ["http_headers", "tech_detect"])
        self.assertEqual(executed, ["nmap_scan", "http_headers", "tech_detect"])

    async def test_selected_dangerous_suggestion_still_requests_approval(self):
        agent, executed, llm = self._proposal_agent()
        await _collect_events(agent)
        calls_before = llm.calls

        events = await _collect_events(agent, "3")

        self.assertEqual(llm.calls, calls_before)
        self.assertEqual([event.name for event in events if isinstance(event, ToolCallEvent)], ["dir_brute"])
        self.assertEqual([event.tool_name for event in events if isinstance(event, ApprovalRequestEvent)], ["dir_brute"])
        self.assertEqual([event.name for event in events if isinstance(event, ToolStartEvent)], [])
        self.assertEqual(executed, ["nmap_scan"])

    async def test_session_allow_and_chain_budget_do_not_imply_orchestration_intent(self):
        agent, executed, _ = self._proposal_agent(allow_dir_brute=True)
        agent.max_chained_actions_per_turn = 3

        events = await _collect_events(agent)

        self.assertEqual([event.name for event in events if isinstance(event, ToolCallEvent)], ["nmap_scan"])
        self.assertEqual([event.name for event in events if isinstance(event, ToolStartEvent)], ["nmap_scan"])
        self.assertEqual(executed, ["nmap_scan"])

    async def test_agent_chains_registered_candidates_through_permission_flow(self):
        executed: list[str] = []
        registry = ToolRegistry()

        async def nmap_scan(**_):
            executed.append("nmap_scan")
            return NMAP_HTTP_OUTPUT

        async def http_headers(**_):
            executed.append("http_headers")
            return "HTTP/1.1 200 OK\nServer: Apache/2.4.51\nX-Frame-Options: DENY\n"

        async def tech_detect(**_):
            executed.append("tech_detect")
            return "Technology Detection for http://10.10.10.5:\n  Server: Apache"

        async def dir_brute(**_):
            executed.append("dir_brute")
            return "/admin (Status: 200) [Size: 1234]"

        registry.register(
            name="nmap_scan",
            description="Run nmap",
            category=ToolCategory.NETWORK,
            parameters={"target": {"type": "string", "required": True}},
            func=nmap_scan,
            dangerous=False,
        )
        registry.register(
            name="http_headers",
            description="Fetch headers",
            category=ToolCategory.RECON,
            parameters={"url": {"type": "string", "required": True}},
            func=http_headers,
            dangerous=False,
        )
        registry.register(
            name="tech_detect",
            description="Detect technologies",
            category=ToolCategory.RECON,
            parameters={"url": {"type": "string", "required": True}},
            func=tech_detect,
            dangerous=False,
        )
        registry.register(
            name="dir_brute",
            description="Discover paths",
            category=ToolCategory.WEB,
            parameters={"url": {"type": "string", "required": True}},
            func=dir_brute,
            dangerous=True,
        )

        memory = ConversationMemory()
        mission = MissionContext(name="chain mission")
        structured_memory = StructuredMemory(conversation=memory, mission=mission)
        permissions = PermissionEngine()
        for tool_name in ("nmap_scan", "http_headers", "tech_detect"):
            permissions.remember(
                PermissionResource(kind="tool", name=tool_name),
                PermissionDecision.ALLOW,
            )

        agent = SecOpsAgent(
            llm=ChainFakeLLM(),
            registry=registry,
            memory=memory,
            permissions=permissions,
            structured_memory=structured_memory,
            result_parser=ToolResultParser(mission=mission),
            max_iterations=2,
            max_chained_actions_per_turn=3,
            allow_automatic_planner_execution=True,
        )

        events = await _collect_events(agent)

        tool_calls = [event.name for event in events if isinstance(event, ToolCallEvent)]
        starts = [event.name for event in events if isinstance(event, ToolStartEvent)]
        approvals = [event for event in events if isinstance(event, ApprovalRequestEvent)]
        results = [event.name for event in events if isinstance(event, ToolResultEvent)]

        self.assertEqual(tool_calls[:4], ["nmap_scan", "http_headers", "tech_detect", "dir_brute"])
        self.assertEqual(starts, ["nmap_scan", "http_headers", "tech_detect"])
        self.assertEqual(executed, ["nmap_scan", "http_headers", "tech_detect"])
        self.assertEqual([event.tool_name for event in approvals], ["dir_brute"])
        self.assertIn("dir_brute", results)
        self.assertEqual(len(mission.services), 1)
        self.assertTrue(any(message.tool_calls for message in memory.messages if message.role == "model"))

    async def test_guided_lab_question_does_not_auto_chain_after_scan(self):
        executed: list[str] = []
        registry = ToolRegistry()

        async def nmap_scan(**_):
            executed.append("nmap_scan")
            return NMAP_HTTP_OUTPUT

        async def http_headers(**_):
            executed.append("http_headers")
            return "HTTP/1.1 200 OK\nServer: Apache/2.4.51\n"

        registry.register(
            name="nmap_scan",
            description="Run nmap",
            category=ToolCategory.NETWORK,
            parameters={"target": {"type": "string", "required": True}},
            func=nmap_scan,
            dangerous=False,
        )
        registry.register(
            name="http_headers",
            description="Fetch headers",
            category=ToolCategory.RECON,
            parameters={"url": {"type": "string", "required": True}},
            func=http_headers,
            dangerous=False,
        )

        memory = ConversationMemory()
        mission = MissionContext(name="guided lab mission")
        structured_memory = StructuredMemory(conversation=memory, mission=mission)
        permissions = PermissionEngine()
        permissions.remember(
            PermissionResource(kind="tool", name="nmap_scan"),
            PermissionDecision.ALLOW,
        )
        permissions.remember(
            PermissionResource(kind="tool", name="http_headers"),
            PermissionDecision.ALLOW,
        )
        agent = SecOpsAgent(
            llm=ChainFakeLLM(),
            registry=registry,
            memory=memory,
            permissions=permissions,
            structured_memory=structured_memory,
            result_parser=ToolResultParser(mission=mission),
            max_iterations=2,
            max_chained_actions_per_turn=3,
        )

        events = await _collect_events(
            agent,
            "First, let's get information about the target. Scan the machine, how many ports are open?",
        )

        self.assertEqual([event.name for event in events if isinstance(event, ToolCallEvent)], ["nmap_scan"])
        self.assertEqual([event.name for event in events if isinstance(event, ToolStartEvent)], ["nmap_scan"])
        self.assertEqual(executed, ["nmap_scan"])
        self.assertFalse(any(isinstance(event, SuggestedActionsEvent) for event in events))

    async def test_guided_lab_suite_runs_requested_directory_discovery(self):
        executed: list[tuple[str, dict]] = []
        registry = ToolRegistry()

        async def nmap_scan(**kwargs):
            executed.append(("nmap_scan", kwargs))
            return NMAP_HTTP_OUTPUT

        async def dir_brute(**kwargs):
            executed.append(("dir_brute", kwargs))
            return "/panel (Status: 301) [Size: 314]\n/uploads (Status: 301) [Size: 316]"

        registry.register(
            name="nmap_scan",
            description="Run nmap",
            category=ToolCategory.NETWORK,
            parameters={
                "target": {"type": "string", "required": True},
                "scan_type": {"type": "string", "required": False},
            },
            func=nmap_scan,
            dangerous=False,
        )
        registry.register(
            name="dir_brute",
            description="Discover paths",
            category=ToolCategory.WEB,
            parameters={"url": {"type": "string", "required": True}},
            func=dir_brute,
            dangerous=True,
        )

        memory = ConversationMemory()
        mission = MissionContext(name="guided checklist")
        structured_memory = StructuredMemory(conversation=memory, mission=mission)
        llm = ChainFakeLLM()
        agent = SecOpsAgent(
            llm=llm,
            registry=registry,
            memory=memory,
            permissions=PermissionEngine(),
            structured_memory=structured_memory,
            result_parser=ToolResultParser(mission=mission),
            max_iterations=2,
        )
        prompt = """Target IP Address
10.10.10.5

First, let's get information about the target.
Answer the questions below
Scan the machine, how many ports are open?

What version of Apache is running?

What service is running on port 22?
Find directories on the web server using the GoBuster tool.

What is the hidden directory?
"""

        # nmap_scan is r3 active enumeration: it now routes through approval before it
        # hits the real target (audit T2.7), consistent with dir_brute below.
        first_events = await _collect_events(agent, prompt, approval=ApprovalDecision(allowed=True))
        calls_before = llm.calls
        next_events = await _collect_events(
            agent,
            "et la suite ?",
            approval=ApprovalDecision(allowed=True),
        )
        first_text = "\n".join(event.content for event in first_events if isinstance(event, TextEvent))
        next_text = "\n".join(event.content for event in next_events if isinstance(event, TextEvent))

        self.assertEqual(llm.calls, calls_before)
        self.assertEqual(
            [(event.name, event.arguments) for event in first_events if isinstance(event, ToolCallEvent)],
            [("nmap_scan", {"target": "10.10.10.5", "scan_type": "version"})],
        )
        self.assertEqual(
            [event.tool_name for event in first_events if isinstance(event, ApprovalRequestEvent)],
            ["nmap_scan"],
        )
        self.assertEqual(
            [(event.name, event.arguments) for event in next_events if isinstance(event, ToolCallEvent)],
            [("dir_brute", {"url": "http://10.10.10.5"})],
        )
        self.assertEqual([event.tool_name for event in next_events if isinstance(event, ApprovalRequestEvent)], ["dir_brute"])
        self.assertEqual(
            [(event.name, event.arguments) for event in next_events if isinstance(event, ToolStartEvent)],
            [("dir_brute", {"url": "http://10.10.10.5"})],
        )
        self.assertEqual(
            executed,
            [
                ("nmap_scan", {"target": "10.10.10.5", "scan_type": "version"}),
                ("dir_brute", {"url": "http://10.10.10.5"}),
            ],
        )
        self.assertIn("Résultat Nmap", first_text)
        self.assertIn("Port ouvert: 1", first_text)
        self.assertIn("Question restante: trouver le hidden directory", first_text)
        self.assertIn("Résultat GoBuster", next_text)
        self.assertIn("/panel", next_text)

    async def test_private_virtual_lab_question_is_focused_without_ctf_classification(self):
        # The operator declared a private lab (--env lab / SECOPS_ENV=lab). Autonomy
        # escalation is earned on that explicit signal, not on "VM VirtualBox" text
        # in the prompt (audit R3.8 / ASI01).
        set_operator_environment(EnvironmentHint.PRIVATE_LAB)
        self.addCleanup(set_operator_environment, None)
        executed: list[str] = []
        registry = ToolRegistry()

        async def nmap_scan(**_):
            executed.append("nmap_scan")
            return NMAP_HTTP_OUTPUT

        async def http_headers(**_):
            executed.append("http_headers")
            return "HTTP/1.1 200 OK\nServer: Apache/2.4.51\n"

        registry.register(
            name="nmap_scan",
            description="Run nmap",
            category=ToolCategory.NETWORK,
            parameters={"target": {"type": "string", "required": True}},
            func=nmap_scan,
            dangerous=False,
        )
        registry.register(
            name="http_headers",
            description="Fetch headers",
            category=ToolCategory.RECON,
            parameters={"url": {"type": "string", "required": True}},
            func=http_headers,
            dangerous=False,
        )

        memory = ConversationMemory()
        mission = MissionContext(name="private virtual lab")
        structured_memory = StructuredMemory(conversation=memory, mission=mission)
        permissions = PermissionEngine()
        for tool_name in ("nmap_scan", "http_headers"):
            permissions.remember(
                PermissionResource(kind="tool", name=tool_name),
                PermissionDecision.ALLOW,
            )
        llm = ChainFakeLLM()
        agent = SecOpsAgent(
            llm=llm,
            registry=registry,
            memory=memory,
            permissions=permissions,
            structured_memory=structured_memory,
            result_parser=ToolResultParser(mission=mission),
            max_iterations=2,
            max_chained_actions_per_turn=3,
            allow_automatic_planner_execution=True,
        )

        events = await _collect_events(
            agent,
            "Dans ma VM VirtualBox 10.10.10.5, combien de ports sont ouverts ?",
        )

        self.assertEqual([event.name for event in events if isinstance(event, ToolCallEvent)], ["nmap_scan"])
        self.assertEqual([event.name for event in events if isinstance(event, ToolStartEvent)], ["nmap_scan"])
        self.assertEqual(executed, ["nmap_scan"])
        self.assertFalse(any(isinstance(event, SuggestedActionsEvent) for event in events))
        self.assertEqual(llm.last_context["environment_hint"], "private_lab")
        self.assertEqual(llm.last_context["technical_goal"], "port_scan")
        self.assertTrue(llm.last_context["focused_answer_turn"])

    async def test_private_virtual_lab_single_scan_keeps_next_action_proposals(self):
        # Private lab declared by the operator (--env lab), not inferred from prompt
        # text — autonomy is earned on the explicit signal (audit R3.8 / ASI01).
        set_operator_environment(EnvironmentHint.PRIVATE_LAB)
        self.addCleanup(set_operator_environment, None)
        agent, executed, llm = self._proposal_agent()

        events = await _collect_events(
            agent,
            "Sur ma VM VMware 10.10.10.5, fais un scan des ports ouverts.",
        )

        suggestions = [event for event in events if isinstance(event, SuggestedActionsEvent)]
        self.assertEqual([event.name for event in events if isinstance(event, ToolCallEvent)], ["nmap_scan"])
        self.assertEqual([event.name for event in events if isinstance(event, ToolStartEvent)], ["nmap_scan"])
        self.assertEqual(executed, ["nmap_scan"])
        self.assertEqual([action.tool_name for action in suggestions[0].actions], ["http_headers", "tech_detect", "dir_brute"])
        self.assertEqual(llm.last_context["environment_hint"], "private_lab")
        self.assertEqual(llm.last_context["user_intent"], "run_single_tool")
        self.assertFalse(llm.last_context["focused_answer_turn"])

    async def test_nmap_target_embedded_in_extra_args_is_normalized_for_display_and_execution(self):
        class ExtraArgsLLM(ChainFakeLLM):
            async def stream_chat(self, messages: list[Message], tools_schema=None):
                self.calls += 1
                if self.calls == 1:
                    yield StreamChunk(
                        tool_call=ToolCallChunk(
                            name="nmap_scan",
                            arguments={"target": "", "extra_args": "-Pn 10.10.10.5"},
                            id="call_1",
                        )
                    )
                    return
                yield StreamChunk(content="done")

        executed_args: list[dict] = []
        registry = ToolRegistry()

        async def nmap_scan(**kwargs):
            executed_args.append(kwargs)
            return NMAP_HTTP_OUTPUT

        registry.register(
            name="nmap_scan",
            description="Run nmap",
            category=ToolCategory.NETWORK,
            parameters={
                "target": {"type": "string", "required": True},
                "extra_args": {"type": "string", "required": False},
            },
            func=nmap_scan,
            dangerous=False,
        )
        permissions = PermissionEngine()
        permissions.remember(
            PermissionResource(kind="tool", name="nmap_scan"),
            PermissionDecision.ALLOW,
        )
        agent = SecOpsAgent(
            llm=ExtraArgsLLM(),
            registry=registry,
            memory=ConversationMemory(),
            permissions=permissions,
            max_iterations=2,
        )

        events = await _collect_events(agent)
        call = next(event for event in events if isinstance(event, ToolCallEvent))

        self.assertEqual(call.arguments["target"], "10.10.10.5")
        self.assertEqual(call.arguments["extra_args"], "-Pn")
        self.assertEqual(executed_args, [{"target": "10.10.10.5", "extra_args": "-Pn"}])

    async def test_nmap_target_embedded_with_flag_in_target_is_normalized(self):
        class FlaggedTargetLLM(ChainFakeLLM):
            async def stream_chat(self, messages: list[Message], tools_schema=None):
                self.calls += 1
                if self.calls == 1:
                    yield StreamChunk(
                        tool_call=ToolCallChunk(
                            name="nmap_scan",
                            arguments={"target": "-sn 10.10.10.5"},
                            id="call_1",
                        )
                    )
                    return
                yield StreamChunk(content="done")

        executed_args: list[dict] = []
        registry = ToolRegistry()

        async def nmap_scan(**kwargs):
            executed_args.append(kwargs)
            return NMAP_HTTP_OUTPUT

        registry.register(
            name="nmap_scan",
            description="Run nmap",
            category=ToolCategory.NETWORK,
            parameters={
                "target": {"type": "string", "required": True},
                "extra_args": {"type": "string", "required": False},
            },
            func=nmap_scan,
            dangerous=False,
        )
        permissions = PermissionEngine()
        permissions.remember(
            PermissionResource(kind="tool", name="nmap_scan"),
            PermissionDecision.ALLOW,
        )
        agent = SecOpsAgent(
            llm=FlaggedTargetLLM(),
            registry=registry,
            memory=ConversationMemory(),
            permissions=permissions,
            max_iterations=2,
        )

        events = await _collect_events(agent)
        call = next(event for event in events if isinstance(event, ToolCallEvent))

        self.assertEqual(call.arguments["target"], "10.10.10.5")
        self.assertEqual(call.arguments["extra_args"], "-sn")
        self.assertEqual(executed_args, [{"target": "10.10.10.5", "extra_args": "-sn"}])

    async def test_execute_bash_alias_routes_to_run_shell(self):
        class ExecuteBashLLM(ChainFakeLLM):
            async def stream_chat(self, messages: list[Message], tools_schema=None):
                self.calls += 1
                if self.calls == 1:
                    yield StreamChunk(
                        tool_call=ToolCallChunk(
                            name="execute_bash",
                            arguments={"command": "curl -s http://10.10.10.5/panel/"},
                            id="call_1",
                        )
                    )
                    return
                yield StreamChunk(content="done")

        executed_args: list[dict] = []
        registry = ToolRegistry()

        async def run_shell(**kwargs):
            executed_args.append(kwargs)
            return "<form method='post' enctype='multipart/form-data'></form>"

        registry.register(
            name="run_shell",
            description="Run shell command",
            category=ToolCategory.SYSTEM,
            parameters={"command": {"type": "string", "required": True}},
            func=run_shell,
            dangerous=True,
        )
        permissions = PermissionEngine()
        permissions.remember(
            PermissionResource(kind="tool", name="run_shell"),
            PermissionDecision.ALLOW,
        )
        permissions.remember(
            PermissionResource(kind="command", name="curl"),
            PermissionDecision.ALLOW,
        )
        agent = SecOpsAgent(
            llm=ExecuteBashLLM(),
            registry=registry,
            memory=ConversationMemory(),
            permissions=permissions,
            max_iterations=2,
        )

        events = await _collect_events(agent)

        self.assertEqual([event.name for event in events if isinstance(event, ToolCallEvent)], ["run_shell"])
        self.assertEqual([event.name for event in events if isinstance(event, ToolStartEvent)], ["run_shell"])
        self.assertEqual(executed_args, [{"command": "curl -s http://10.10.10.5/panel/"}])

    async def test_http_get_alias_routes_to_run_shell_curl(self):
        class HttpGetLLM(ChainFakeLLM):
            async def stream_chat(self, messages: list[Message], tools_schema=None):
                self.calls += 1
                if self.calls == 1:
                    yield StreamChunk(
                        tool_call=ToolCallChunk(
                            name="http_get",
                            arguments={"url": "http://10.10.10.5/panel/"},
                            id="call_1",
                        )
                    )
                    return
                yield StreamChunk(content="done")

        executed_args: list[dict] = []
        registry = ToolRegistry()

        async def run_shell(**kwargs):
            executed_args.append(kwargs)
            return "<form method='post' enctype='multipart/form-data'></form>"

        registry.register(
            name="run_shell",
            description="Run shell command",
            category=ToolCategory.SYSTEM,
            parameters={"command": {"type": "string", "required": True}},
            func=run_shell,
            dangerous=True,
        )
        permissions = PermissionEngine()
        permissions.remember(
            PermissionResource(kind="tool", name="run_shell"),
            PermissionDecision.ALLOW,
        )
        permissions.remember(
            PermissionResource(kind="command", name="curl"),
            PermissionDecision.ALLOW,
        )
        agent = SecOpsAgent(
            llm=HttpGetLLM(),
            registry=registry,
            memory=ConversationMemory(),
            permissions=permissions,
            max_iterations=2,
        )

        events = await _collect_events(agent)

        self.assertEqual([event.name for event in events if isinstance(event, ToolCallEvent)], ["run_shell"])
        self.assertEqual([event.name for event in events if isinstance(event, ToolStartEvent)], ["run_shell"])
        self.assertEqual(executed_args, [{"command": "curl -sL --max-time 20 http://10.10.10.5/panel/"}])

    async def test_explicit_gobuster_request_uses_known_web_target_without_llm(self):
        class BrokenLLM:
            model_name = "broken"

            def __init__(self) -> None:
                self.called = False

            def prepare_for_prompt(self, prompt: str, **kwargs):
                return None

            async def stream_chat(self, messages: list[Message], tools_schema=None):
                self.called = True
                raise AssertionError("LLM should not be called for explicit GoBuster preflight")

        executed_args: list[dict] = []
        registry = ToolRegistry()

        async def dir_brute(**kwargs):
            executed_args.append(kwargs)
            return "/uploads (Status: 301) [Size: 313]"

        registry.register(
            name="dir_brute",
            description="Discover paths",
            category=ToolCategory.WEB,
            parameters={"url": {"type": "string", "required": True}},
            func=dir_brute,
            dangerous=True,
        )

        memory = ConversationMemory()
        mission = MissionContext(name="guided lab mission")
        mission.add_service(Service(host="10.129.153.73", port=80, service="http", state="open"))
        structured_memory = StructuredMemory(conversation=memory, mission=mission)
        llm = BrokenLLM()
        agent = SecOpsAgent(
            llm=llm,
            registry=registry,
            memory=memory,
            permissions=PermissionEngine(),
            structured_memory=structured_memory,
            result_parser=ToolResultParser(mission=mission),
            max_iterations=1,
        )

        events = await _collect_events(
            agent,
            "Find directories on the web server using the GoBuster tool.",
            approval=ApprovalDecision(allowed=True),
        )

        self.assertFalse(llm.called)
        tool_calls = [event for event in events if isinstance(event, ToolCallEvent)]
        approvals = [event for event in events if isinstance(event, ApprovalRequestEvent)]
        starts = [event for event in events if isinstance(event, ToolStartEvent)]

        self.assertEqual([(event.name, event.arguments) for event in tool_calls], [("dir_brute", {"url": "http://10.129.153.73"})])
        self.assertEqual([event.resource.value for event in approvals], ["tool(dir_brute)"])
        self.assertEqual([(event.name, event.arguments) for event in starts], [("dir_brute", {"url": "http://10.129.153.73"})])
        self.assertEqual(executed_args, [{"url": "http://10.129.153.73"}])

    async def test_upload_surface_suggestion_does_not_auto_generate_payload(self):
        class UploadSurfaceLLM:
            model_name = "fake-model"

            def __init__(self) -> None:
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
                            name="dir_brute",
                            arguments={"url": "http://10.10.10.5"},
                            id="call_1",
                        )
                    )
                    return
                yield StreamChunk(content="done")

        executed: list[str] = []
        registry = ToolRegistry()

        async def dir_brute(**_):
            executed.append("dir_brute")
            return "/panel (Status: 301) [Size: 313]\n"

        async def generate_payload(**_):
            executed.append("generate_payload")
            return "payload"

        registry.register(
            name="dir_brute",
            description="Discover paths",
            category=ToolCategory.WEB,
            parameters={"url": {"type": "string", "required": True}},
            func=dir_brute,
            dangerous=True,
        )
        registry.register(
            name="generate_payload",
            description="Generate payload",
            category=ToolCategory.EXPLOIT,
            parameters={"payload_type": {"type": "string", "required": True}},
            func=generate_payload,
            dangerous=True,
        )

        memory = ConversationMemory()
        mission = MissionContext(name="upload replay")
        structured_memory = StructuredMemory(conversation=memory, mission=mission)
        permissions = PermissionEngine()
        for tool_name in ("dir_brute", "generate_payload"):
            permissions.remember(
                PermissionResource(kind="tool", name=tool_name),
                PermissionDecision.ALLOW,
            )
        agent = SecOpsAgent(
            llm=UploadSurfaceLLM(),
            registry=registry,
            memory=memory,
            permissions=permissions,
            structured_memory=structured_memory,
            result_parser=ToolResultParser(mission=mission),
            max_iterations=2,
            max_chained_actions_per_turn=3,
            allow_automatic_planner_execution=True,
        )

        events = await _collect_events(agent, "Find directories on the web server using GoBuster.")

        tool_calls = [event.name for event in events if isinstance(event, ToolCallEvent)]
        suggestions = [event for event in events if isinstance(event, SuggestedActionsEvent)]

        self.assertEqual(tool_calls, ["dir_brute"])
        self.assertEqual(executed, ["dir_brute"])
        self.assertTrue(any(
            action.method == "upload_surface_validation"
            for event in suggestions
            for action in event.actions
        ))
        self.assertFalse(any(event.name == "generate_payload" for event in events if isinstance(event, ToolCallEvent)))


if __name__ == "__main__":
    unittest.main()
