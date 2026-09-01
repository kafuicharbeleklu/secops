"""PROC-02 — Shift+Tab permission-mode cycling with the mode kept visible, from
docs/UX_RESEARCH_PROPOSAL_2026-09-01.md.

The Shift+Tab key binding lives in the prompt_toolkit input layer (hard to drive
headless); these tests cover the pure cycle order and the apply-and-refresh
helper it calls, which carry the behaviour.  The mode itself is surfaced by the
statusline (FMT-06).
"""
from __future__ import annotations

import unittest

import secops_agent.main as main_module
from secops_agent.cli.permissions import PERMISSION_MODES, next_permission_mode
from secops_agent.core.agent import SecOpsAgent
from secops_agent.core.memory import ConversationMemory
from secops_agent.core.permissions import PermissionEngine
from secops_agent.core.tools import ToolRegistry
from secops_agent.ui.runtime import RuntimeState


class _FakeLLM:
    model_name = "fake-model"

    def prepare_for_prompt(self, prompt, **kwargs):
        return None

    async def stream_chat(self, messages, tools_schema=None):
        if False:  # pragma: no cover - never streams here
            yield None


def _make_agent() -> SecOpsAgent:
    return SecOpsAgent(
        llm=_FakeLLM(),
        registry=ToolRegistry(),
        memory=ConversationMemory(),
        permissions=PermissionEngine(),
        max_iterations=2,
    )


class NextPermissionModeTests(unittest.TestCase):
    def test_cycle_wraps_through_all_modes(self):
        seq = ["plan"]
        for _ in range(len(PERMISSION_MODES)):
            seq.append(next_permission_mode(seq[-1]))
        self.assertEqual(seq[-1], "plan")  # a full lap returns to the start
        self.assertEqual(next_permission_mode("request-review"), "proceed-in-sandbox")
        self.assertEqual(next_permission_mode("strict"), "plan")

    def test_unknown_mode_resets_to_first(self):
        self.assertEqual(next_permission_mode("bogus"), PERMISSION_MODES[0])


class CyclePermissionModeTests(unittest.TestCase):
    def test_cycle_applies_next_mode_and_refreshes_statusline(self):
        agent = _make_agent()
        runtime = RuntimeState()  # defaults to request-review
        payload = main_module._cycle_permission_mode(agent, runtime)

        self.assertEqual(runtime.permission_mode, "proceed-in-sandbox")
        self.assertIsInstance(payload, dict)
        self.assertEqual(payload["permissions"], main_module._permission_label(agent, runtime))

    def test_full_cycle_returns_to_start(self):
        agent = _make_agent()
        runtime = RuntimeState()
        start = runtime.permission_mode
        for _ in range(len(PERMISSION_MODES)):
            main_module._cycle_permission_mode(agent, runtime)
        self.assertEqual(runtime.permission_mode, start)


if __name__ == "__main__":
    unittest.main()
