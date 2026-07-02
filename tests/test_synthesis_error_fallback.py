"""Regression test for A5: a transient failure of the *synthesis* LLM call must
not discard a tool result already obtained in the same turn.

Before the fix, an ErrorEvent from the post-tool synthesis call ended the turn
immediately (`yield error; return`), so a successful tool result was silently
lost and the user got an empty answer. The loop must instead present the
extracted summary so the correct data still reaches the user.
"""
from __future__ import annotations

import unittest

from secops_agent.core.agent import (
    ErrorEvent,
    SecOpsAgent,
    TextEvent,
    ToolResultEvent,
)
from secops_agent.core.llm import Message, StreamChunk, ToolCallChunk
from secops_agent.core.memory import ConversationMemory
from secops_agent.core.permissions import (
    PermissionDecision,
    PermissionEngine,
    PermissionResource,
)
from secops_agent.core.result_parser import ToolResultParser
from secops_agent.core.tools import ToolCategory, ToolRegistry

FAKE_NMAP = "PORT   STATE SERVICE VERSION\n631/tcp open ipp CUPS 2.4\n"


class ToolThenSynthesisErrorLLM:
    """Call 1 requests a tool; call 2 (synthesis) fails with a transient 500."""

    model_name = "fake-model"

    def __init__(self) -> None:
        self.calls = 0

    def prepare_for_prompt(self, prompt: str, **kwargs) -> None:
        return None

    async def stream_chat(self, messages: list[Message], tools_schema=None):
        self.calls += 1
        if self.calls == 1:
            yield StreamChunk(
                tool_call=ToolCallChunk(
                    name="nmap_scan",
                    arguments={"target": "127.0.0.1"},
                    id="call_1",
                )
            )
            return
        yield StreamChunk(error="Gemini API Error: 500 INTERNAL")


class SynthesisErrorFallbackTests(unittest.IsolatedAsyncioTestCase):
    async def test_tool_result_presented_when_synthesis_fails(self) -> None:
        registry = ToolRegistry()

        async def fake_nmap(**_):
            return FAKE_NMAP

        registry.register(
            name="nmap_scan",
            description="Nmap scan",
            category=ToolCategory.SYSTEM,
            parameters={"target": {"type": "string", "required": True}},
            func=fake_nmap,
            dangerous=False,
        )
        permissions = PermissionEngine()
        permissions.remember(
            PermissionResource(kind="tool", name="nmap_scan"),
            PermissionDecision.ALLOW,
        )
        agent = SecOpsAgent(
            llm=ToolThenSynthesisErrorLLM(),
            registry=registry,
            memory=ConversationMemory(),
            permissions=permissions,
            result_parser=ToolResultParser(),
            max_iterations=3,
        )

        events = []
        async for event in agent.stream_response("scan 127.0.0.1"):
            events.append(event)

        full_text = "".join(e.content for e in events if isinstance(e, TextEvent))
        tool_results = [e for e in events if isinstance(e, ToolResultEvent)]

        # the tool actually ran and succeeded
        self.assertTrue(any(r.result.success for r in tool_results))
        # the transient synthesis error is still surfaced (not hidden)
        self.assertTrue(any(isinstance(e, ErrorEvent) for e in events))
        # A5: the correct tool result is presented instead of an empty turn
        self.assertIn("Ports ouverts", full_text)
        self.assertIn("631/tcp", full_text)


if __name__ == "__main__":
    unittest.main()
