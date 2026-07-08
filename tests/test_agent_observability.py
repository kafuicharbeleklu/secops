from __future__ import annotations

import unittest

from secops_agent.core.agent import ErrorEvent, SecOpsAgent, StatusEvent, TextEvent
from secops_agent.core.llm import StreamChunk, ToolCallChunk
from secops_agent.core.memory import ConversationMemory
from secops_agent.core.observability import InMemoryTraceSink, StructuredTracer
from secops_agent.core.tools import ToolCategory, ToolRegistry


class ErrorThenTextLLM:
    def __init__(self, error: str, final_text: str = "ok") -> None:
        self.error = error
        self.final_text = final_text
        self.calls = 0

    async def stream_chat(self, messages, tools_schema=None):
        self.calls += 1
        if self.calls == 1:
            yield StreamChunk(error=self.error, done=True)
            return
        yield StreamChunk(content=self.final_text)
        yield StreamChunk(done=True)


class AlwaysErrorLLM:
    def __init__(self, error: str) -> None:
        self.error = error
        self.calls = 0

    async def stream_chat(self, messages, tools_schema=None):
        self.calls += 1
        yield StreamChunk(error=self.error, done=True)


class AgentObservabilityTests(unittest.IsolatedAsyncioTestCase):
    async def test_llm_temporary_error_retries_with_exponential_backoff(self):
        sink = InMemoryTraceSink()
        llm = ErrorThenTextLLM("The model service is temporarily unavailable.")
        agent = SecOpsAgent(
            llm=llm,
            registry=ToolRegistry(),
            memory=ConversationMemory(),
            trace_sink=sink,
            llm_retry_base_seconds=0,
        )

        events = [event async for event in agent.stream_response("hello")]
        text = "".join(event.content for event in events if isinstance(event, TextEvent))
        statuses = [event for event in events if isinstance(event, StatusEvent)]

        self.assertEqual(llm.calls, 2)
        self.assertIn("ok", text)
        self.assertTrue(any("retrying" in event.message for event in statuses))
        trace_events = [event["event"] for event in sink.events]
        self.assertIn("turn_started", trace_events)
        self.assertIn("llm_request_error", trace_events)
        self.assertIn("llm_retry_scheduled", trace_events)
        self.assertIn("llm_request_completed", trace_events)

    async def test_llm_500_internal_error_is_retried(self):
        sink = InMemoryTraceSink()
        llm = ErrorThenTextLLM(
            "Gemini API Error: 500 INTERNAL. {'error': {'code': 500, "
            "'message': 'Internal error encountered.', 'status': 'INTERNAL'}}"
        )
        agent = SecOpsAgent(
            llm=llm,
            registry=ToolRegistry(),
            memory=ConversationMemory(),
            trace_sink=sink,
            llm_retry_base_seconds=0,
        )

        events = [event async for event in agent.stream_response("scan the host")]
        text = "".join(event.content for event in events if isinstance(event, TextEvent))

        self.assertEqual(llm.calls, 2)
        self.assertIn("ok", text)
        self.assertIn("llm_retry_scheduled", [event["event"] for event in sink.events])

    async def test_llm_invalid_argument_error_is_not_retried(self):
        sink = InMemoryTraceSink()
        llm = AlwaysErrorLLM("Gemini API Error: 400 INVALID_ARGUMENT.")
        agent = SecOpsAgent(
            llm=llm,
            registry=ToolRegistry(),
            memory=ConversationMemory(),
            trace_sink=sink,
            llm_retry_base_seconds=0,
        )

        events = [event async for event in agent.stream_response("scan")]
        errors = [event for event in events if isinstance(event, ErrorEvent)]

        self.assertEqual(llm.calls, 1)
        self.assertEqual(errors[0].error, "Gemini API Error: 400 INVALID_ARGUMENT.")
        self.assertFalse(any(event["event"] == "llm_retry_scheduled" for event in sink.events))

    async def test_tool_trace_records_metadata_without_raw_output(self):
        sink = InMemoryTraceSink()
        registry = ToolRegistry()

        async def secret_tool(**_):
            return "secret output should not be traced"

        registry.register(
            name="secret_tool",
            description="Test tool",
            category=ToolCategory.SYSTEM,
            parameters={"password": {"type": "string", "required": False}},
            func=secret_tool,
            dangerous=False,
        )
        llm = ErrorThenTextLLM("", final_text="")

        async def stream_chat(messages, tools_schema=None):
            yield StreamChunk(
                tool_call=ToolCallChunk(
                    name="secret_tool",
                    arguments={"password": "super-secret"},
                    id="secret_tool",
                )
            )
            yield StreamChunk(done=True)

        llm.stream_chat = stream_chat
        agent = SecOpsAgent(
            llm=llm,
            registry=registry,
            memory=ConversationMemory(),
            trace_sink=sink,
            llm_retry_base_seconds=0,
            max_iterations=1,
        )

        async for _event in agent.stream_response("run tool"):
            pass

        started = next(event for event in sink.events if event["event"] == "tool_started")
        completed = next(event for event in sink.events if event["event"] == "tool_completed")
        self.assertEqual(started["arguments"]["password"], "[REDACTED]")
        self.assertEqual(completed["output_chars"], len("secret output should not be traced"))
        self.assertNotIn("secret output", str(sink.events))


class StructuredTracerTests(unittest.TestCase):
    def test_tracer_redacts_sensitive_keys(self):
        sink = InMemoryTraceSink()
        tracer = StructuredTracer(sink=sink, run_id="test-run")

        tracer.emit("sample", api_key="abc", nested={"token": "def", "target": "10.10.10.5"})

        event = sink.events[0]
        self.assertEqual(event["api_key"], "[REDACTED]")
        self.assertEqual(event["nested"]["token"], "[REDACTED]")
        self.assertEqual(event["nested"]["target"], "10.10.10.5")


class PrintModeRetryHeartbeatTests(unittest.IsolatedAsyncioTestCase):
    """E2 (live re-audit 2026-07-04): a transient-5xx storm made `--print` hang
    silently because the consumer dropped every StatusEvent — the retry/backoff
    produced no output until success or final error. The retry itself is correct
    (covered above); this proves the *headless* surface now shows progress."""

    def _agent(self) -> SecOpsAgent:
        return SecOpsAgent(
            llm=ErrorThenTextLLM("Gemini API Error: 500 INTERNAL", final_text="ok"),
            registry=ToolRegistry(),
            memory=ConversationMemory(),
            llm_retry_base_seconds=0,
        )

    async def test_text_mode_writes_retry_heartbeat_to_stderr(self) -> None:
        import contextlib
        import io

        from secops_agent.main import _run_print_prompt
        from secops_agent.ui.runtime import RuntimeState

        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            await _run_print_prompt(self._agent(), RuntimeState(), "hello", 30.0, "text")
        self.assertIn("retrying", err.getvalue(), "retry heartbeat missing from stderr")
        self.assertIn("ok", out.getvalue())          # stdout is still the clean answer
        self.assertNotIn("retrying", out.getvalue())  # progress never pollutes stdout

    async def test_json_mode_records_status_stream(self) -> None:
        import contextlib
        import io
        import json as _json

        from secops_agent.main import _run_print_prompt
        from secops_agent.ui.runtime import RuntimeState

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            await _run_print_prompt(self._agent(), RuntimeState(), "hello", 30.0, "json")
        payload = _json.loads(out.getvalue())
        self.assertIn("status", payload)
        self.assertTrue(
            any("retrying" in message for message in payload["status"]),
            f"no retry status recorded: {payload['status']!r}",
        )
        self.assertIn("ok", payload["response"])


if __name__ == "__main__":
    unittest.main()
