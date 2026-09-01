"""#2b: a run_shell command gets a single, specific approval.

On the RootMe run every shell command prompted twice — once for tool(run_shell),
once for command_exact(<cmd>) — driving approval fatigue. The generic tool prompt
is now skipped: the command-gate is the single prompt, still DENYs destructive
commands, and a mode-level DENY (plan mode) is still respected.
"""
from __future__ import annotations

import unittest

from secops_agent.core.agent import (
    ApprovalRequestEvent,
    PlanPreviewEvent,
    SecOpsAgent,
    ToolResultEvent,
)
from secops_agent.core.memory import ConversationMemory
from secops_agent.core.permissions import (
    ApprovalDecision,
    PermissionDecision,
    PermissionEngine,
    PermissionResource,
)
from secops_agent.core.tools import ToolCategory, ToolRegistry
from tests.test_agent_permissions import FakeLLM


def _agent(command: str, tool_func, *, plan_mode: bool = False) -> SecOpsAgent:
    registry = ToolRegistry()
    registry.register(
        name="run_shell", description="Execute a shell command", category=ToolCategory.SYSTEM,
        parameters={"command": {"type": "string", "required": True}}, func=tool_func, dangerous=True,
    )
    permissions = PermissionEngine()  # NOTE: no tool(run_shell) pre-allow -> tool default ASK
    if plan_mode:
        permissions.remember(PermissionResource("command", "*"), PermissionDecision.DENY)
        permissions.remember(PermissionResource("tool", "*"), PermissionDecision.DENY)
    return SecOpsAgent(
        llm=FakeLLM(command), registry=registry, memory=ConversationMemory(),
        permissions=permissions, max_iterations=2,
    )


async def _run(agent: SecOpsAgent, approval: ApprovalDecision):
    events = []
    async for event in agent.stream_response("run shell"):
        events.append(event)
        if isinstance(event, ApprovalRequestEvent):
            event.approval_future.set_result(approval)
        elif isinstance(event, PlanPreviewEvent) and event.acknowledgment_future is not None:
            event.acknowledgment_future.set_result(ApprovalDecision(allowed=True))
    return events


class RunShellSingleApprovalTests(unittest.IsolatedAsyncioTestCase):
    async def test_curl_asks_once_at_the_command_level_only(self):
        executed = []

        async def run_shell(command: str):
            executed.append(command)
            return "ok"

        agent = _agent("curl -sL http://10.0.0.1/panel/", run_shell)
        events = await _run(agent, ApprovalDecision(allowed=True))
        approvals = [e for e in events if isinstance(e, ApprovalRequestEvent)]

        self.assertEqual(len(approvals), 1, "run_shell should prompt exactly once (the command)")
        self.assertNotIn("tool(run_shell)", approvals[0].resource.value)
        self.assertTrue(approvals[0].resource.value.startswith("command"))
        self.assertEqual(executed, ["curl -sL http://10.0.0.1/panel/"])

    async def test_destructive_command_is_denied_without_a_prompt(self):
        executed = []

        async def run_shell(command: str):
            executed.append(command)
            return "ok"

        agent = _agent("rm -rf /tmp/x", run_shell)
        events = await _run(agent, ApprovalDecision(allowed=True))

        self.assertFalse([e for e in events if isinstance(e, ApprovalRequestEvent)], "rm must not prompt")
        self.assertFalse(executed, "rm must never execute")
        results = [e for e in events if isinstance(e, ToolResultEvent)]
        self.assertTrue(results and not results[0].result.success)

    async def test_plan_mode_still_denies_run_shell(self):
        executed = []

        async def run_shell(command: str):
            executed.append(command)
            return "ok"

        agent = _agent("curl http://x/", run_shell, plan_mode=True)
        events = await _run(agent, ApprovalDecision(allowed=True))

        self.assertFalse([e for e in events if isinstance(e, ApprovalRequestEvent)])
        self.assertFalse(executed, "plan mode must block run_shell")


if __name__ == "__main__":
    unittest.main()
