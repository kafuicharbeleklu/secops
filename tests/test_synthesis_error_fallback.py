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

    def __init__(self, tool_name: str = "nmap_scan", arguments=None) -> None:
        self.calls = 0
        self._tool_name = tool_name
        self._arguments = arguments if arguments is not None else {"target": "127.0.0.1"}

    def prepare_for_prompt(self, prompt: str, **kwargs) -> None:
        return None

    async def stream_chat(self, messages: list[Message], tools_schema=None):
        self.calls += 1
        if self.calls == 1:
            yield StreamChunk(
                tool_call=ToolCallChunk(
                    name=self._tool_name,
                    arguments=self._arguments,
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
        # (single open port → singular French agreement, R4).
        self.assertIn("Port ouvert", full_text)
        self.assertIn("631/tcp", full_text)

    async def test_generic_tool_fallback_has_no_collapse_trailer(self) -> None:
        """RC-α / D5-leak: when synthesis fails, the A5 fallback for a tool
        without a bespoke formatter must present a clean fact, never the
        parser's internal '(+N more line(s))' collapse trailer."""
        registry = ToolRegistry()

        long_output = "\n".join(
            [
                "Hostname: audit-box",
                "OS: Ubuntu 24.04",
                "Kernel: 6.8.0",
                "CPU: 8 cores",
                "Memory: 32 GiB",
                "Disk: 512 GiB",
                "Uptime: 3h 20m",
            ]
        )

        async def fake_sysinfo(**_):
            return long_output

        registry.register(
            name="sysinfo",
            description="System info",
            category=ToolCategory.SYSTEM,
            parameters={},
            func=fake_sysinfo,
            dangerous=False,
        )
        permissions = PermissionEngine()
        permissions.remember(
            PermissionResource(kind="tool", name="sysinfo"),
            PermissionDecision.ALLOW,
        )
        agent = SecOpsAgent(
            llm=ToolThenSynthesisErrorLLM(tool_name="sysinfo", arguments={}),
            registry=registry,
            memory=ConversationMemory(),
            permissions=permissions,
            result_parser=ToolResultParser(),
            max_iterations=3,
        )

        events = []
        async for event in agent.stream_response("donne-moi les infos système"):
            events.append(event)

        full_text = "".join(e.content for e in events if isinstance(e, TextEvent))
        self.assertTrue(full_text.strip(), "A5 fallback must not end empty")
        self.assertNotIn("(+", full_text)
        self.assertNotIn("more line(s)", full_text)


class FirstCallTransientErrorLLM:
    """The first (tool-selection) call fails with a transient 500 — no tool runs,
    so there is no result to fall back on."""

    model_name = "fake-model"

    def prepare_for_prompt(self, prompt: str, **kwargs) -> None:
        return None

    async def stream_chat(self, messages: list[Message], tools_schema=None):
        yield StreamChunk(error="Gemini API Error: 500 INTERNAL")


class FirstCallTransientErrorTests(unittest.IsolatedAsyncioTestCase):
    async def test_transient_first_call_error_never_ends_empty(self) -> None:
        """RC-γ / D5: a transient error on the first LLM call must surface a
        clean notice, never leave the turn empty."""
        agent = SecOpsAgent(
            llm=FirstCallTransientErrorLLM(),
            registry=ToolRegistry(),
            memory=ConversationMemory(),
            permissions=PermissionEngine(),
            result_parser=ToolResultParser(),
            max_iterations=2,
            llm_max_attempts=1,  # no backoff — go straight to the ErrorEvent
        )

        events = []
        async for event in agent.stream_response(
            "explique ta méthodologie de test d'intrusion"
        ):
            events.append(event)

        full_text = "".join(e.content for e in events if isinstance(e, TextEvent))
        # the turn is not left empty
        self.assertTrue(full_text.strip(), "transient first-call error left the turn empty")
        # a clean French "service unavailable, retry" notice
        self.assertIn("indisponible", full_text.lower())
        # the transient error is still surfaced (not silently swallowed)
        self.assertTrue(any(isinstance(e, ErrorEvent) for e in events))


if __name__ == "__main__":
    unittest.main()
