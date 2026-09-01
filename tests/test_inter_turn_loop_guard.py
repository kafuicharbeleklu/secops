"""#1b: inter-turn no-progress guard.

The intra-turn convergence guard only sees repetition within a single turn; a
weak model can re-issue the identical tool call across separate turns
("continue"/"ok") — as on the RootMe run. After a few identical turns the agent
should nudge itself (soft, not a hard stop) to switch tool/approach.
"""
from __future__ import annotations

import unittest

from secops_agent.core.agent import SecOpsAgent, StatusEvent
from secops_agent.core.llm import StreamChunk, ToolCallChunk
from secops_agent.core.memory import ConversationMemory
from secops_agent.core.permissions import PermissionDecision, PermissionEngine, PermissionResource
from secops_agent.core.tools import ToolCategory, ToolRegistry


class _RepeatLLM:
    model_name = "fake-model"

    def __init__(self):
        self.calls = 0

    def prepare_for_prompt(self, prompt, **kwargs):
        return None

    async def stream_chat(self, messages, tools_schema=None):
        self.calls += 1
        # odd call = re-issue the same tool call; even call = synthesise "done"
        if self.calls % 2 == 1:
            yield StreamChunk(
                tool_call=ToolCallChunk(name="probe_net", arguments={"target": "10.0.0.1"}, id=f"c{self.calls}")
            )
        else:
            yield StreamChunk(content="done")


def _agent() -> SecOpsAgent:
    registry = ToolRegistry()

    async def probe_net(target: str):
        return f"probed {target}"

    registry.register(
        name="probe_net", description="passive probe", category=ToolCategory.NETWORK,
        parameters={"target": {"type": "string", "required": True}}, func=probe_net, dangerous=False,
    )
    permissions = PermissionEngine()
    permissions.remember(PermissionResource(kind="tool", name="probe_net"), PermissionDecision.ALLOW)
    return SecOpsAgent(
        llm=_RepeatLLM(), registry=registry, memory=ConversationMemory(),
        permissions=permissions, max_iterations=4,
    )


class InterTurnLoopGuardTests(unittest.IsolatedAsyncioTestCase):
    async def _run_turn(self, agent) -> list[str]:
        statuses = []
        async for event in agent.stream_response("continue"):
            if isinstance(event, StatusEvent):
                statuses.append(str(getattr(event, "message", "") or ""))
        return statuses

    async def test_nudge_fires_only_after_repeated_turns(self):
        agent = _agent()

        def has_nudge(statuses):
            return any("identical tool call across the last few turns" in s for s in statuses)

        turn1 = await self._run_turn(agent)
        turn2 = await self._run_turn(agent)
        turn3 = await self._run_turn(agent)

        self.assertFalse(has_nudge(turn1), "should not nudge on the first turn")
        self.assertFalse(has_nudge(turn2), "should not nudge on the second turn")
        self.assertTrue(has_nudge(turn3), "should nudge once the same call repeats across turns")

    async def test_streak_resets_and_does_not_spam(self):
        agent = _agent()
        await self._run_turn(agent)
        await self._run_turn(agent)
        await self._run_turn(agent)          # nudge here, streak reset to 0
        turn4 = await self._run_turn(agent)  # streak rebuilding, no nudge again immediately
        self.assertFalse(
            any("identical tool call across the last few turns" in s for s in turn4),
            "nudge must be one-shot, not repeated every subsequent turn",
        )


if __name__ == "__main__":
    unittest.main()
