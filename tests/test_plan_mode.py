"""PROC-01 — first-class read-only *plan* permission mode, from
docs/UX_RESEARCH_PROPOSAL_2026-09-01.md (audit P2-01, "Élevée").

Plan mode must guarantee a genuinely execution-free planning session: the model
may still propose a trajectory, but a session-wide DENY is evaluated before
*every* tool/command — including passive r0/r1 tools — and a later narrow ALLOW
must not be able to bypass it.  These tests lock that guarantee in place.
"""
from __future__ import annotations

import unittest

import secops_agent.main as main_module
from secops_agent.cli.permissions import PERMISSION_MODES, normalize_permission_mode
from secops_agent.core.agent import SecOpsAgent
from secops_agent.core.autonomy import AutonomyLevel
from secops_agent.core.memory import ConversationMemory
from secops_agent.core.permissions import (
    PermissionDecision,
    PermissionEngine,
    PermissionResource,
)
from secops_agent.core.tools import ToolRegistry
from secops_agent.ui.runtime import RuntimeState


class _FakeLLM:
    model_name = "fake-model"

    def prepare_for_prompt(self, prompt: str, **kwargs):
        return None

    async def stream_chat(self, messages, tools_schema=None):
        if False:  # pragma: no cover - never streams in these tests
            yield None


def _make_agent() -> SecOpsAgent:
    return SecOpsAgent(
        llm=_FakeLLM(),
        registry=ToolRegistry(),
        memory=ConversationMemory(),
        permissions=PermissionEngine(),
        max_iterations=2,
    )


class PlanModeEngineLockTests(unittest.TestCase):
    """The categorical DENY lock the plan mode installs on the engine."""

    def _locked_engine(self) -> PermissionEngine:
        engine = PermissionEngine()
        engine.remember(PermissionResource("tool", "*"), PermissionDecision.DENY)
        engine.remember(PermissionResource("command", "*"), PermissionDecision.DENY)
        return engine

    def test_passive_tool_is_blocked(self):
        # dns_lookup is ALLOW (passive) by default; the lock must override that.
        engine = PermissionEngine()
        self.assertEqual(engine.evaluate_tool("dns_lookup"), PermissionDecision.ALLOW)
        self.assertEqual(self._locked_engine().evaluate_tool("dns_lookup"), PermissionDecision.DENY)

    def test_dangerous_tool_is_blocked(self):
        self.assertEqual(
            self._locked_engine().evaluate_tool("generate_payload", dangerous=True),
            PermissionDecision.DENY,
        )

    def test_shell_command_is_blocked(self):
        self.assertEqual(
            self._locked_engine().check_tool_permission("run_shell", {"command": "ls"}),
            PermissionDecision.DENY,
        )

    def test_narrow_allow_cannot_bypass_the_lock(self):
        engine = self._locked_engine()
        engine.remember(PermissionResource("tool", "dns_lookup"), PermissionDecision.ALLOW)
        self.assertEqual(engine.evaluate_tool("dns_lookup"), PermissionDecision.DENY)


class PlanModeApplyTests(unittest.TestCase):
    """_apply_permission_mode('plan', ...) wires the lock, autonomy and sandbox."""

    def test_apply_plan_installs_lock_and_copilot_autonomy(self):
        agent = _make_agent()
        runtime = RuntimeState()
        main_module._apply_permission_mode("plan", agent, runtime)

        self.assertEqual(runtime.permission_mode, "plan")
        self.assertFalse(runtime.sandbox_enabled)
        self.assertEqual(agent.permissions.evaluate_tool("dns_lookup"), PermissionDecision.DENY)
        self.assertEqual(
            agent.permissions.evaluate_tool("generate_payload", dangerous=True),
            PermissionDecision.DENY,
        )
        self.assertEqual(agent.autonomy.level, AutonomyLevel.COPILOT)

    def test_switching_away_from_plan_lifts_the_lock(self):
        agent = _make_agent()
        runtime = RuntimeState()
        main_module._apply_permission_mode("plan", agent, runtime)
        main_module._apply_permission_mode("request-review", agent, runtime)

        self.assertEqual(runtime.permission_mode, "request-review")
        # passive recon is executable again once the read-only session ends
        self.assertEqual(agent.permissions.evaluate_tool("dns_lookup"), PermissionDecision.ALLOW)
        self.assertNotEqual(agent.autonomy.level, AutonomyLevel.COPILOT)


class PlanModeSurfaceTests(unittest.TestCase):
    """Plan mode is a selectable, validated permission mode."""

    def test_plan_is_a_valid_cli_mode(self):
        self.assertIn("plan", PERMISSION_MODES)
        self.assertEqual(normalize_permission_mode("plan"), "plan")


if __name__ == "__main__":
    unittest.main()
