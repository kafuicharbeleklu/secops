"""Plan-preview gate + divergence surfacing (audit item #7 / T2.1, Part A steps 2-3).

Before a mission's first *active* (>= r2) step, the agent shows the candidate
trajectory and takes a single acknowledgment — an added *review* gate that never
replaces the PermissionEngine (the per-tool approval still fires afterward). A
decline aborts the step exactly like a denied approval. Once acknowledged, an
active tool that was not in the plan surfaces a PlanDivergenceEvent (once per
tool) rather than running silently. In SANDBOX the plan is built and emitted but
auto-acknowledged (non-blocking). Passive (r0/r1) tools never trip the gate, and
a scope-denied tool is blocked before any plan is shown.
"""
from __future__ import annotations

import asyncio
import unittest

from secops_agent.core.agent import (
    ApprovalRequestEvent,
    PlanDivergenceEvent,
    PlanPreviewEvent,
    SecOpsAgent,
    ToolResultEvent,
)
from secops_agent.core.autonomy import AutonomyLevel, AutonomyPolicy
from secops_agent.core.llm import Message, StreamChunk, ToolCallChunk
from secops_agent.core.memory import ConversationMemory
from secops_agent.core.mission import MissionContext, MissionPlan, PlanStep
from secops_agent.core.permissions import (
    ApprovalDecision,
    PermissionDecision,
    PermissionEngine,
    PermissionResource,
)
from secops_agent.core.result_parser import ToolResultParser
from secops_agent.core.structured_memory import StructuredMemory
from secops_agent.core.tools import ToolCategory, ToolRegistry


class _ToolSeqLLM:
    """Yields a fixed sequence of tool calls (one per turn), then a plain answer."""

    model_name = "fake-model"

    def __init__(self, calls: list[tuple[str, dict]]):
        self._calls = list(calls)
        self.i = 0

    def prepare_for_prompt(self, prompt: str, **kwargs):
        return None

    def set_mission_context(self, context: str) -> None:
        pass

    async def stream_chat(self, messages: list[Message], tools_schema=None):
        if self.i < len(self._calls):
            name, args = self._calls[self.i]
            self.i += 1
            yield StreamChunk(
                tool_call=ToolCallChunk(name=name, arguments=args, id=f"call_{self.i}")
            )
            return
        yield StreamChunk(content="done")


def _build_agent(calls, *, sandbox=False, mission=None):
    executed: list[str] = []
    registry = ToolRegistry()

    async def _nmap(**_kwargs):
        executed.append("nmap_scan")
        return "PORT STATE SERVICE\n80/tcp open http"

    async def _dirb(**_kwargs):
        executed.append("dir_brute")
        return "/admin (Status: 200)"

    async def _passive(**_kwargs):
        executed.append("whoami_local")
        return "user"

    # nmap_scan / dir_brute infer to r3 (ACTIVE_ENUMERATION) from the builtin map;
    # a dangerous=False unknown tool infers to r0 (passive).
    registry.register(
        name="nmap_scan", description="scan", category=ToolCategory.NETWORK,
        parameters={"target": {"type": "string", "required": True}},
        func=_nmap, dangerous=True,
    )
    registry.register(
        name="dir_brute", description="brute", category=ToolCategory.NETWORK,
        parameters={"url": {"type": "string", "required": True}},
        func=_dirb, dangerous=True,
    )
    registry.register(
        name="whoami_local", description="who", category=ToolCategory.SYSTEM,
        parameters={}, func=_passive, dangerous=False,
    )

    memory = ConversationMemory()
    mission = mission or MissionContext(name="plan-preview mission")
    structured = StructuredMemory(conversation=memory, mission=mission)
    agent = SecOpsAgent(
        llm=_ToolSeqLLM(calls),
        registry=registry,
        memory=memory,
        permissions=PermissionEngine(),
        structured_memory=structured,
        result_parser=ToolResultParser(mission=mission),
        max_iterations=4,
    )
    if sandbox:
        agent.autonomy = AutonomyPolicy(level=AutonomyLevel.SANDBOX)
    return agent, executed, mission


async def _collect(agent, prompt, *, plan_ack=True, approval=True):
    events = []
    async for event in agent.stream_response(prompt):
        events.append(event)
        if isinstance(event, PlanPreviewEvent) and event.acknowledgment_future is not None:
            event.acknowledgment_future.set_result(ApprovalDecision(allowed=plan_ack))
        elif isinstance(event, ApprovalRequestEvent):
            event.approval_future.set_result(ApprovalDecision(allowed=approval))
    return events


def _indices(events, kind):
    return [i for i, e in enumerate(events) if isinstance(e, kind)]


class PlanPreviewGateTest(unittest.TestCase):
    def test_plan_ack_precedes_first_active_tool_and_approval_still_fires(self):
        agent, executed, _m = _build_agent([("nmap_scan", {"target": "10.10.10.5"})])
        events = asyncio.run(_collect(agent, "run the network tool", plan_ack=True, approval=True))

        previews = _indices(events, PlanPreviewEvent)
        approvals = _indices(events, ApprovalRequestEvent)
        self.assertEqual(len(previews), 1, "exactly one plan preview before the first active step")
        self.assertTrue(approvals, "the per-tool approval must still fire (plan-ack does not replace it)")
        self.assertLess(previews[0], approvals[0], "plan acknowledgment precedes the per-tool approval")
        self.assertEqual(executed.count("nmap_scan"), 1, "tool runs once both gates pass")

        preview = events[previews[0]]
        self.assertEqual(preview.plan.steps[0].tool_name, "nmap_scan")
        self.assertTrue(preview.plan.steps[0].active)

    def test_plan_decline_aborts_the_tool_like_a_denied_approval(self):
        agent, executed, _m = _build_agent([("nmap_scan", {"target": "10.10.10.5"})])
        events = asyncio.run(_collect(agent, "run the network tool", plan_ack=False))

        self.assertEqual(len(_indices(events, PlanPreviewEvent)), 1)
        self.assertEqual(_indices(events, ApprovalRequestEvent), [], "declined plan never reaches per-tool approval")
        self.assertEqual(executed.count("nmap_scan"), 0, "declined plan aborts the tool before execution")
        results = [e for e in events if isinstance(e, ToolResultEvent)]
        self.assertTrue(results and not results[0].result.success)

    def test_plan_gate_fires_once_across_multiple_active_steps(self):
        agent, executed, mission = _build_agent(
            [("nmap_scan", {"target": "10.10.10.5"}), ("dir_brute", {"url": "http://10.10.10.5"})]
        )
        events = asyncio.run(_collect(agent, "run the network tool", plan_ack=True, approval=True))
        self.assertEqual(
            len(_indices(events, PlanPreviewEvent)), 1,
            "the plan is acknowledged once, not per active step",
        )
        self.assertTrue(mission.plan.acknowledged)

    def test_passive_tool_does_not_trip_the_gate(self):
        agent, executed, _m = _build_agent([("whoami_local", {})])
        events = asyncio.run(_collect(agent, "run the local tool"))
        self.assertEqual(_indices(events, PlanPreviewEvent), [], "r0/r1 recon never triggers a plan preview")
        self.assertEqual(executed.count("whoami_local"), 1)

    def test_active_tool_outside_acknowledged_plan_emits_divergence(self):
        mission = MissionContext(name="diverge")
        # Pre-acknowledge a plan whose only step is nmap_scan.
        mission.plan = MissionPlan(
            steps=[PlanStep(title="scan", tool_name="nmap_scan", active=True)],
            acknowledged=True,
        )
        agent, executed, mission = _build_agent(
            [("dir_brute", {"url": "http://10.10.10.5"})], mission=mission
        )
        events = asyncio.run(_collect(agent, "run the network tool", approval=True))

        divergences = [e for e in events if isinstance(e, PlanDivergenceEvent)]
        self.assertEqual(len(divergences), 1, "an unplanned active tool surfaces a divergence notice")
        self.assertEqual(divergences[0].tool_name, "dir_brute")
        self.assertEqual(mission.plan.divergences, ["dir_brute"])
        # No *new* plan preview: the plan was already acknowledged.
        self.assertEqual(_indices(events, PlanPreviewEvent), [])

    def test_sandbox_auto_acknowledges_non_blocking(self):
        agent, executed, mission = _build_agent(
            [("nmap_scan", {"target": "10.10.10.5"})], sandbox=True
        )
        events = asyncio.run(_collect(agent, "run the network tool", approval=True))

        previews = [e for e in events if isinstance(e, PlanPreviewEvent)]
        self.assertEqual(len(previews), 1, "the plan is still emitted for the record in SANDBOX")
        self.assertIsNone(previews[0].acknowledgment_future, "SANDBOX auto-acknowledges (non-blocking)")
        self.assertTrue(mission.plan.acknowledged)
        self.assertEqual(executed.count("nmap_scan"), 1)

    def test_plan_mode_previews_active_step_but_never_executes_it(self):
        agent, executed, _mission = _build_agent([("nmap_scan", {"target": "10.10.10.5"})])
        agent.set_autonomy_for_permission_mode("plan")
        agent.permissions.remember(
            PermissionResource("tool", "*"), PermissionDecision.DENY
        )
        agent.permissions.remember(
            PermissionResource("command", "*"), PermissionDecision.DENY
        )

        events = asyncio.run(_collect(agent, "plan the network assessment", plan_ack=True))

        self.assertEqual(len(_indices(events, PlanPreviewEvent)), 1)
        self.assertEqual(executed, [])
        results = [event for event in events if isinstance(event, ToolResultEvent)]
        self.assertTrue(results and "Permission denied by policy" in (results[0].result.error or ""))

    def test_plan_mode_execution_lock_beats_a_later_exact_allow(self):
        permissions = PermissionEngine()
        permissions.remember(PermissionResource("tool", "*"), PermissionDecision.DENY)
        permissions.remember(PermissionResource("tool", "nmap_scan"), PermissionDecision.ALLOW)

        self.assertEqual(
            PermissionDecision.DENY,
            permissions.evaluate_tool("nmap_scan"),
        )

    def test_scope_denied_tool_is_blocked_before_any_plan_preview(self):
        mission = MissionContext(name="scope")
        mission.narrow_scope("10.10.10.5")
        agent, executed, mission = _build_agent(
            [("nmap_scan", {"target": "10.10.10.6"})], mission=mission
        )
        events = asyncio.run(_collect(agent, "run the network tool", approval=True))

        self.assertEqual(_indices(events, PlanPreviewEvent), [], "scope block short-circuits before the plan gate")
        self.assertEqual(executed.count("nmap_scan"), 0, "out-of-scope tool never executes")
        results = [e for e in events if isinstance(e, ToolResultEvent)]
        self.assertTrue(results and not results[0].result.success)


class PlanPrintModeTest(unittest.TestCase):
    def test_json_print_records_plan_and_auto_acknowledges(self):
        """--print is headless: the plan is auto-acknowledged (no hang) and recorded
        in the JSON envelope; the per-tool gate still denies the dangerous tool."""
        import contextlib
        import io
        import json as _json

        from secops_agent.main import _run_print_prompt
        from secops_agent.ui.runtime import RuntimeState

        agent, executed, _m = _build_agent([("nmap_scan", {"target": "10.10.10.5"})])
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            asyncio.run(
                _run_print_prompt(agent, RuntimeState(), "run the network tool", 30.0, "json")
            )
        payload = _json.loads(out.getvalue())
        self.assertIsNotNone(payload["plan"], "the plan is recorded in the JSON print record")
        self.assertEqual(payload["plan"]["steps"][0]["tool_name"], "nmap_scan")
        self.assertEqual(
            executed.count("nmap_scan"), 0,
            "the per-tool approval still denies the dangerous tool in --print",
        )


if __name__ == "__main__":
    unittest.main()
