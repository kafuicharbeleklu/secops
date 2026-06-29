from __future__ import annotations

import unittest
from unittest.mock import patch

from secops_agent.core.agent import SecOpsAgent, TextEvent, ToolCallEvent, ToolStartEvent
from secops_agent.core.llm import Message, StreamChunk
from secops_agent.core.memory import ConversationMemory
from secops_agent.core.permissions import PermissionEngine
from secops_agent.core.tools import ToolCategory, ToolRegistry


class CapturingLLM:
    model_name = "capture"

    def __init__(self):
        self.called = False
        self.tools_schema = None
        self.context = None

    def prepare_for_prompt(self, prompt: str, **kwargs):
        self.context = kwargs.get("context")

    async def stream_chat(self, messages: list[Message], tools_schema=None):
        self.called = True
        self.tools_schema = tools_schema or []
        yield StreamChunk(content="ready")


class BrokenLLM:
    model_name = "broken"

    def __init__(self):
        self.called = False

    def prepare_for_prompt(self, prompt: str, **kwargs):
        pass

    async def stream_chat(self, *args, **kwargs):
        self.called = True
        raise AssertionError("LLM should not be called for deterministic local answers")


class ArchivedToolMarkerLLM:
    model_name = "archived-marker"

    def prepare_for_prompt(self, prompt: str, **kwargs):
        pass

    async def stream_chat(self, messages: list[Message], tools_schema=None):
        yield StreamChunk(content='[Archived tool call: http_get {"url": "http://10.10.10.5/panel/"}]')


async def _collect(agent: SecOpsAgent, prompt: str):
    events = []
    async for event in agent.stream_response(prompt):
        events.append(event)
    return events


def _registry_with_tools(*names: str) -> ToolRegistry:
    registry = ToolRegistry()

    async def noop(**_kwargs):
        return "ok"

    for name in names:
        registry.register(
            name=name,
            description=f"{name} tool",
            category=ToolCategory.MCP if name.startswith("mcp_") else ToolCategory.SYSTEM,
            parameters={"target": {"type": "string", "required": False}},
            func=noop,
            dangerous=name.startswith("mcp_"),
        )
    return registry


class RequestRoutingTests(unittest.IsolatedAsyncioTestCase):
    async def test_time_question_is_answered_without_llm_or_tool_call(self):
        llm = BrokenLLM()
        agent = SecOpsAgent(
            llm,
            _registry_with_tools("run_shell", "sysinfo", "nmap_scan"),
            ConversationMemory(),
            permissions=PermissionEngine(),
        )

        events = await _collect(agent, "what time is it on my system?")
        text = "".join(event.content for event in events if isinstance(event, TextEvent))

        self.assertFalse(llm.called)
        self.assertIn("The current system time is", text)
        self.assertFalse(any(isinstance(event, ToolCallEvent) for event in events))

    async def test_ip_question_is_answered_without_llm(self):
        llm = BrokenLLM()
        agent = SecOpsAgent(
            llm,
            _registry_with_tools("sysinfo", "run_shell"),
            ConversationMemory(),
            permissions=PermissionEngine(),
        )

        class Completed:
            stdout = "192.168.6.149 192.168.136.184\n"

        with patch("secops_agent.core.agent.subprocess.run", return_value=Completed()):
            events = await _collect(agent, "what is my ip address?")
        text = "".join(event.content for event in events if isinstance(event, TextEvent))

        self.assertFalse(llm.called)
        self.assertIn("192.168.6.149", text)
        self.assertIn("192.168.136.184", text)

    async def test_target_ip_lab_questions_start_nmap_without_local_ip_answer(self):
        llm = BrokenLLM()
        executed = []
        registry = ToolRegistry()

        async def nmap_scan(**kwargs):
            executed.append(kwargs)
            return "22/tcp open ssh\n80/tcp open http Apache/2.4.41"

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
        agent = SecOpsAgent(llm, registry, ConversationMemory(), permissions=PermissionEngine())
        prompt = """Target IP Address
10.129.134.39

First, let's get information about the target.
Answer the questions below
Scan the machine, how many ports are open?

What version of Apache is running?

What service is running on port 22?
Find directories on the web server using the GoBuster tool.

What is the hidden directory?
"""

        events = await _collect(agent, prompt)
        text = "".join(event.content for event in events if isinstance(event, TextEvent))

        self.assertFalse(llm.called)
        self.assertNotIn("Local IP addresses", text)
        self.assertEqual(
            [(event.name, event.arguments) for event in events if isinstance(event, ToolCallEvent)],
            [("nmap_scan", {"target": "10.129.134.39", "scan_type": "version"})],
        )
        self.assertEqual(
            [(event.name, event.arguments) for event in events if isinstance(event, ToolStartEvent)],
            [("nmap_scan", {"target": "10.129.134.39", "scan_type": "version"})],
        )
        self.assertEqual(executed, [{"target": "10.129.134.39", "scan_type": "version"}])

    async def test_port_scan_prompt_ranks_scan_tools_first_over_safe_baseline(self):
        llm = CapturingLLM()
        registry = _registry_with_tools(
            "nmap_scan",
            "ping_host",
            "port_check",
            "dir_brute",
            "tech_detect",
            "mcp_external",
        )
        agent = SecOpsAgent(llm, registry, ConversationMemory(), permissions=PermissionEngine())

        await _collect(agent, "scan open ports on the current target")

        names = [schema["name"] for schema in llm.tools_schema]
        # PORT_SCAN priority tools lead; safe baseline tools follow.
        self.assertEqual(names[:3], ["ping_host", "port_check", "nmap_scan"])
        self.assertIn("dir_brute", names)
        self.assertIn("tech_detect", names)
        # External (MCP supply-chain) tools stay out of the safe baseline.
        self.assertNotIn("mcp_external", names)
        self.assertEqual("port_scan", llm.context["technical_goal"])

    async def test_web_directory_prompt_leads_with_dir_brute_plus_safe_baseline(self):
        llm = CapturingLLM()
        registry = _registry_with_tools(
            "dir_brute",
            "http_headers",
            "tech_detect",
            "nmap_scan",
            "mcp_external",
        )
        agent = SecOpsAgent(llm, registry, ConversationMemory(), permissions=PermissionEngine())

        await _collect(agent, "Find directories on the web server using GoBuster")

        names = [schema["name"] for schema in llm.tools_schema]
        self.assertEqual(names[0], "dir_brute")
        # Safe baseline fills in the rest; external tools excluded.
        self.assertIn("http_headers", names)
        self.assertIn("nmap_scan", names)
        self.assertNotIn("mcp_external", names)
        self.assertEqual("web_dir_enum", llm.context["technical_goal"])

    async def test_pasted_walkthrough_context_does_not_trigger_gobuster_preflight(self):
        llm = CapturingLLM()
        registry = _registry_with_tools("dir_brute", "nmap_scan")
        agent = SecOpsAgent(llm, registry, ConversationMemory(), permissions=PermissionEngine())
        pasted = (
            "this can help you?: 00:00:00\n"
            "hello in this video we do the root me box\n"
            "00:02:46\n"
            "now it wants us to run go buster against the web browser\n"
            "gobuster dir -u http://10.10.10.5 -w common.txt\n"
            + "\n".join(f"00:{minute:02d}:00 more walkthrough text" for minute in range(10))
        )

        events = await _collect(agent, pasted)

        self.assertTrue(llm.called)
        self.assertFalse(any(isinstance(event, ToolCallEvent) for event in events))

    async def test_exploit_request_exposes_safe_baseline_not_offensive_primitives(self):
        llm = CapturingLLM()
        registry = _registry_with_tools("generate_payload", "run_shell", "nmap_scan", "dir_brute")
        agent = SecOpsAgent(llm, registry, ConversationMemory(), permissions=PermissionEngine())

        await _collect(agent, "upload a webshell and get a reverse shell")

        names = {s["name"] for s in llm.tools_schema}
        # The model is never blinded: the safe recon/enum floor is always exposed
        # so it cannot fall back to an empty toolset (and let grounding hijack).
        self.assertIn("nmap_scan", names)
        self.assertIn("dir_brute", names)
        # Offensive primitives stay behind the autonomy gate until sandbox/approved.
        self.assertNotIn("generate_payload", names)
        self.assertNotIn("run_shell", names)
        self.assertEqual("exploit_step", llm.context["technical_goal"])

    async def test_archived_tool_markers_are_not_rendered_as_current_actions(self):
        agent = SecOpsAgent(
            ArchivedToolMarkerLLM(),
            _registry_with_tools("run_shell"),
            ConversationMemory(),
            permissions=PermissionEngine(),
        )

        events = await _collect(agent, "continue")
        text = "".join(event.content for event in events if isinstance(event, TextEvent))

        self.assertNotIn("Archived tool call", text)
        self.assertNotIn("http_get", text)
        self.assertIn("did not run a tool", text)


def _full_registry():
    import importlib
    import pkgutil

    import secops_agent.tools as tools_pkg
    from secops_agent.core.tools import registry

    for module in pkgutil.iter_modules(tools_pkg.__path__):
        importlib.import_module(f"secops_agent.tools.{module.name}")
    return registry


class AnnounceFirstLLM:
    """Announces an action on call 1 without a tool call, answers on call 2."""

    model_name = "announce"

    def __init__(self):
        self.calls = 0

    def prepare_for_prompt(self, prompt: str, **kwargs):
        pass

    async def stream_chat(self, messages: list[Message], tools_schema=None):
        self.calls += 1
        if self.calls == 1:
            yield StreamChunk(content="Je vais scanner le port 80 du serveur.")
            return
        yield StreamChunk(content="Le port 80 est ouvert.")


class SilentLLM:
    model_name = "silent"

    def __init__(self):
        self.calls = 0

    def prepare_for_prompt(self, prompt: str, **kwargs):
        pass

    async def stream_chat(self, messages: list[Message], tools_schema=None):
        self.calls += 1
        yield StreamChunk(content="")


class LoopGuardrailTests(unittest.IsolatedAsyncioTestCase):
    async def test_announced_action_without_tool_call_triggers_one_retry(self):
        llm = AnnounceFirstLLM()
        agent = SecOpsAgent(
            llm,
            _registry_with_tools("nmap_scan", "ping_host"),
            ConversationMemory(),
            permissions=PermissionEngine(),
        )

        await _collect(agent, "scan the box")

        # The announcement-without-action grants exactly one corrective pass.
        self.assertEqual(llm.calls, 2)
        reminders = [
            m
            for m in agent.memory.messages
            if m.role == "user" and "System reminder" in m.content
        ]
        self.assertEqual(len(reminders), 1)

    async def test_blank_turn_falls_back_to_a_clarifying_message(self):
        llm = SilentLLM()
        agent = SecOpsAgent(
            llm,
            _registry_with_tools("nmap_scan"),
            ConversationMemory(),
            permissions=PermissionEngine(),
        )

        events = await _collect(agent, "scan the box")
        text = "".join(e.content for e in events if isinstance(e, TextEvent))

        # Empty output is not an action announcement -> no retry, but never blank.
        self.assertEqual(llm.calls, 1)
        self.assertIn("clarify", text.lower())
        last_assistant = [m for m in agent.memory.messages if m.role == "model"][-1]
        self.assertTrue(last_assistant.content.strip())


class SafeBaselineToolExposureTests(unittest.TestCase):
    """RC1: a vague request exposes a usable safe baseline, not an empty schema."""

    def _agent(self):
        return SecOpsAgent(
            CapturingLLM(),
            _full_registry(),
            ConversationMemory(),
            permissions=PermissionEngine(),
        )

    def test_vague_request_exposes_safe_baseline_instead_of_nothing(self):
        from secops_agent.core.request_context import classify_request

        agent = self._agent()
        decision = classify_request("scan the box")
        names = {s["name"] for s in agent._tools_schema_for_decision(decision)}

        # Previously empty; now a broad safe toolset is offered.
        self.assertIn("nmap_scan", names)
        self.assertIn("dns_lookup", names)
        # Tools formerly unreachable by any goal are now exposed.
        self.assertIn("nuclei_scan", names)
        self.assertIn("hash_identify", names)
        # Privileged + offensive primitives stay behind the gate.
        self.assertNotIn("run_shell", names)
        self.assertNotIn("connect_vpn_config", names)
        self.assertNotIn("webshell_exec", names)
        self.assertNotIn("generate_payload", names)
        self.assertNotIn("start_listener", names)

    def test_goal_specific_tools_rank_before_baseline(self):
        from secops_agent.core.request_context import classify_request

        agent = self._agent()
        decision = classify_request("how many ports are open on 10.10.10.5?")
        names = [s["name"] for s in agent._tools_schema_for_decision(decision)]

        # PORT_SCAN priority tools lead the schema, baseline follows.
        self.assertEqual(names[0], "ping_host")
        self.assertLess(names.index("nmap_scan"), names.index("hash_identify"))

    def test_unapproved_exploit_exposes_safe_baseline_not_offensive_primitives(self):
        from secops_agent.core.request_context import classify_request

        agent = self._agent()
        decision = classify_request("upload a php webshell and get a reverse shell")
        names = {s["name"] for s in agent._tools_schema_for_decision(decision)}

        # EXPLOIT risk without approval → high-risk schemas are withheld, but the
        # safe baseline floor is still exposed so the model is never blinded.
        self.assertIn("nmap_scan", names)
        self.assertIn("hash_identify", names)
        self.assertNotIn("webshell_exec", names)
        self.assertNotIn("generate_payload", names)
        self.assertNotIn("start_listener", names)
        self.assertNotIn("run_shell", names)

    def test_sandbox_autonomy_exposes_offensive_primitives(self):
        from secops_agent.core.request_context import classify_request

        agent = self._agent()
        decision = classify_request("upload a php webshell and get a reverse shell")
        withheld = {s["name"] for s in agent._tools_schema_for_decision(decision)}

        # Free-execution modes imply an authorised target → SANDBOX autonomy,
        # which exposes the offensive primitives the gated path withholds.
        agent.set_autonomy_for_permission_mode("always-proceed")
        exposed = {s["name"] for s in agent._tools_schema_for_decision(decision)}

        self.assertTrue(withheld <= exposed)
        self.assertTrue(exposed - withheld, "sandbox should expose additional high-risk tools")
        self.assertIn("webshell_exec", exposed)


class DirCandidatePrioritisationTests(unittest.TestCase):
    """P3-A: gobuster answers prioritise an attack surface instead of flat-listing."""

    def test_attack_surface_scores_above_static_noise(self):
        from secops_agent.core.agent import SecOpsAgent

        for high in ("/panel", "/uploads", "/admin", "/dev/backup"):
            self.assertEqual(SecOpsAgent._dir_candidate_score(high), 2, high)
        for noise in ("/css", "/js", "/assets", "/static"):
            self.assertEqual(SecOpsAgent._dir_candidate_score(noise), 0, noise)
        self.assertEqual(SecOpsAgent._dir_candidate_score("/server-status"), 1)

    def test_best_candidate_is_the_attack_surface(self):
        from secops_agent.core.agent import SecOpsAgent

        paths = ["/css", "/server-status", "/panel", "/uploads", "/js"]
        best = sorted(paths, key=SecOpsAgent._dir_candidate_score, reverse=True)[0]
        self.assertEqual(best, "/panel")


class _FakeLessonStore:
    def __init__(self, scored):
        self._scored = scored

    def retrieve(self, mission, limit=3):
        return self._scored[:limit]


class _RecordingContextLLM:
    model_name = "recorder"

    def __init__(self):
        self.mission_context = ""

    def prepare_for_prompt(self, prompt: str, **kwargs):
        pass

    def set_mission_context(self, context: str):
        self.mission_context = context

    async def stream_chat(self, messages, tools_schema=None):
        yield StreamChunk(content="ok")


class MemoryBriefingTests(unittest.TestCase):
    """Memory briefing (§5): prime the model with relevant prior lessons."""

    def _lesson(self):
        from secops_agent.core.experience import CaseLesson

        return CaseLesson(
            title="Apache upload panel needed an extension filtering check",
            outcome="success",
            action_tool_name="http_request",
            review_status="reviewed",
            confidence=0.8,
        )

    def _agent(self, store):
        return SecOpsAgent(
            CapturingLLM(),
            _registry_with_tools("nmap_scan"),
            ConversationMemory(),
            permissions=PermissionEngine(),
            experience_store=store,
        )

    def test_briefing_lists_matching_lessons(self):
        from secops_agent.core.mission import MissionContext

        agent = self._agent(_FakeLessonStore([(self._lesson(), 0.5)]))
        text = agent._relevant_lessons_briefing(MissionContext(name="m"))

        self.assertIn("Relevant Prior Lessons", text)
        self.assertIn("extension filtering", text)
        self.assertIn("[http_request]", text)

    def test_briefing_is_silent_without_matches(self):
        from secops_agent.core.mission import MissionContext

        agent = self._agent(_FakeLessonStore([]))
        self.assertEqual(agent._relevant_lessons_briefing(MissionContext(name="m")), "")

    def test_briefing_empty_without_store(self):
        from secops_agent.core.mission import MissionContext

        agent = SecOpsAgent(
            CapturingLLM(),
            _registry_with_tools("nmap_scan"),
            ConversationMemory(),
            permissions=PermissionEngine(),
        )
        self.assertEqual(agent._relevant_lessons_briefing(MissionContext(name="m")), "")

    def test_briefing_reaches_mission_context_during_a_turn(self):
        import asyncio

        from secops_agent.core.mission import MissionContext
        from secops_agent.core.structured_memory import StructuredMemory

        memory = ConversationMemory()
        mission = MissionContext(name="briefing mission")
        structured = StructuredMemory(conversation=memory, mission=mission)
        llm = _RecordingContextLLM()
        agent = SecOpsAgent(
            llm,
            _registry_with_tools("nmap_scan"),
            memory,
            permissions=PermissionEngine(),
            structured_memory=structured,
            experience_store=_FakeLessonStore([(self._lesson(), 0.5)]),
        )

        async def run():
            async for _ in agent.stream_response("scan the box"):
                pass

        asyncio.run(run())
        self.assertIn("Relevant Prior Lessons", llm.mission_context)
        self.assertIn("extension filtering", llm.mission_context)


class EnvironmentAwareAutonomyTests(unittest.TestCase):
    """Chantier 2: autonomy adapts per turn to the detected environment."""

    def _agent(self, autonomy=None):
        return SecOpsAgent(
            CapturingLLM(),
            _full_registry(),
            ConversationMemory(),
            permissions=PermissionEngine(),
            autonomy=autonomy,
        )

    def test_ctf_escalates_to_supervised_and_unblocks_approved_exploit(self):
        from secops_agent.core.autonomy import AutonomyLevel
        from secops_agent.core.request_context import classify_request

        agent = self._agent()
        decision = classify_request(
            "lance la phase d'exploitation complète sur la box HackTheBox"
        )
        policy = agent._autonomy_for_turn(decision)

        self.assertEqual(policy.level, AutonomyLevel.SUPERVISED)
        # Supervised does not pause for exploitation → multi-step chaining allowed.
        self.assertFalse(policy.pauses_for(decision.risk))
        # An approved exploit batch exposes the offensive primitives.
        names = {s["name"] for s in agent._tools_schema_for_decision(decision)}
        self.assertIn("webshell_exec", names)

    def test_authorized_org_stays_risk_based_and_pauses_exploit(self):
        from secops_agent.core.autonomy import AutonomyLevel
        from secops_agent.core.request_context import classify_request

        agent = self._agent()
        decision = classify_request(
            "lance la phase d'exploitation complète sur le serveur de production"
        )
        policy = agent._autonomy_for_turn(decision)

        self.assertEqual(policy.level, AutonomyLevel.RISK_BASED)
        self.assertTrue(policy.pauses_for(decision.risk))

    def test_unapproved_exploit_in_lab_exposes_safe_baseline_not_offensive(self):
        from secops_agent.core.request_context import classify_request

        agent = self._agent()
        decision = classify_request("upload a php webshell on the HackTheBox machine")
        names = {s["name"] for s in agent._tools_schema_for_decision(decision)}

        # CTF escalates to supervised: the safe baseline is exposed, but an
        # unapproved exploit's offensive primitives are still withheld.
        self.assertIn("nmap_scan", names)
        self.assertNotIn("webshell_exec", names)
        self.assertNotIn("run_shell", names)

    def test_explicit_policy_overrides_environment_adaptation(self):
        from secops_agent.core.autonomy import AutonomyLevel, AutonomyPolicy
        from secops_agent.core.request_context import classify_request

        agent = self._agent(autonomy=AutonomyPolicy(level=AutonomyLevel.COPILOT))
        decision = classify_request("scan the HackTheBox machine")

        self.assertEqual(agent._autonomy_for_turn(decision).level, AutonomyLevel.COPILOT)


if __name__ == "__main__":
    unittest.main()
