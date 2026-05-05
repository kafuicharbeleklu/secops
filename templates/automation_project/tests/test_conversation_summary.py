"""Tests for conversation summary and audit integration in AgentLoop."""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock

from app.agent_loop import AgentLoop
from app.audit_logger import AuditLogger
from app.findings import FindingsStore
from app.methodology import EngagementState
from app.llm_client import AgentDecision


class TestConversationSummary(unittest.TestCase):
    """Tests for _trim_history with summary preservation."""

    def _make_loop(self):
        llm_client = MagicMock()
        tool_executor = MagicMock()
        loop = AgentLoop(llm_client, tool_executor)
        return loop

    def test_no_trim_under_limit(self):
        loop = self._make_loop()
        for i in range(10):
            loop.messages.append({"role": "user", "content": f"message {i}"})
        loop._trim_history()
        self.assertEqual(len(loop.messages), 10)

    def test_trim_generates_summary(self):
        loop = self._make_loop()
        # Fill with 40 messages (exceeds MAX_HISTORY=30)
        for i in range(40):
            role = "user" if i % 2 == 0 else "assistant"
            loop.messages.append({"role": role, "content": f"message {i}"})

        loop._trim_history()
        # Should have: first message + summary + last 30
        self.assertLessEqual(len(loop.messages), 32)
        # Second message should be the summary
        self.assertEqual(loop.messages[1]["role"], "system")
        self.assertIn("RESUME DES ECHANGES PRECEDENTS", loop.messages[1]["content"])

    def test_trim_preserves_first_message(self):
        loop = self._make_loop()
        loop.messages.append({"role": "user", "content": "initial request"})
        for i in range(35):
            loop.messages.append({"role": "assistant", "content": f"response {i}"})

        loop._trim_history()
        self.assertEqual(loop.messages[0]["role"], "user")
        self.assertEqual(loop.messages[0]["content"], "initial request")

    def test_trim_preserves_recent_messages(self):
        loop = self._make_loop()
        for i in range(40):
            loop.messages.append({"role": "user", "content": f"message {i}"})

        loop._trim_history()
        # The last message should be the most recent
        self.assertEqual(loop.messages[-1]["content"], "message 39")

    def test_summary_includes_user_messages(self):
        loop = self._make_loop()
        messages = [
            {"role": "user", "content": "scan target 10.10.10.10"},
            {"role": "assistant", "content": "scanning..."},
            {"role": "user", "content": "check port 80"},
        ]
        summary = loop._build_conversation_summary(messages)
        self.assertIn("User: scan target", summary)
        self.assertIn("User: check port", summary)

    def test_summary_includes_assistant_messages(self):
        loop = self._make_loop()
        messages = [
            {"role": "assistant", "content": "Found 3 open ports on the target."},
        ]
        summary = loop._build_conversation_summary(messages)
        self.assertIn("Agent: Found 3 open ports", summary)

    def test_summary_includes_tool_messages(self):
        loop = self._make_loop()
        messages = [
            {"role": "tool", "content": json.dumps({"name": "nmap", "result": "ok"})},
        ]
        summary = loop._build_conversation_summary(messages)
        self.assertIn("Tool nmap: execute", summary)

    def test_summary_handles_invalid_tool_json(self):
        loop = self._make_loop()
        messages = [
            {"role": "tool", "content": "not valid json"},
        ]
        summary = loop._build_conversation_summary(messages)
        # Should not crash, just skip
        self.assertIsInstance(summary, str)

    def test_summary_skips_system_messages(self):
        loop = self._make_loop()
        messages = [
            {"role": "system", "content": "old summary"},
            {"role": "user", "content": "hello"},
        ]
        summary = loop._build_conversation_summary(messages)
        self.assertNotIn("old summary", summary)
        self.assertIn("User: hello", summary)

    def test_summary_limits_to_15_entries(self):
        loop = self._make_loop()
        messages = [
            {"role": "user", "content": f"msg {i}"} for i in range(25)
        ]
        summary = loop._build_conversation_summary(messages)
        lines = [l for l in summary.split("\n") if l.strip()]
        self.assertLessEqual(len(lines), 15)

    def test_summary_truncates_long_content(self):
        loop = self._make_loop()
        long_content = "x" * 500
        messages = [{"role": "user", "content": long_content}]
        summary = loop._build_conversation_summary(messages)
        # User content truncated to 100 chars
        user_line = [l for l in summary.split("\n") if "User:" in l][0]
        self.assertLessEqual(len(user_line), 110)  # "- User: " + 100 chars

    def test_empty_messages_returns_empty_summary(self):
        loop = self._make_loop()
        summary = loop._build_conversation_summary([])
        self.assertEqual(summary, "")


class TestAgentLoopAuditIntegration(unittest.TestCase):
    """Tests for audit logger integration in AgentLoop."""

    def setUp(self):
        self.tmpdir = TemporaryDirectory()
        self.workspace = Path(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_audit_logger_accepted_in_init(self):
        llm_client = MagicMock()
        tool_executor = MagicMock()
        audit_logger = AuditLogger(self.workspace)
        loop = AgentLoop(llm_client, tool_executor, audit_logger=audit_logger)
        self.assertIs(loop.audit_logger, audit_logger)

    def test_audit_logger_none_by_default(self):
        llm_client = MagicMock()
        tool_executor = MagicMock()
        loop = AgentLoop(llm_client, tool_executor)
        self.assertIsNone(loop.audit_logger)

    def test_audit_logs_tool_success(self):
        audit_logger = AuditLogger(self.workspace)
        llm_client = MagicMock()
        tool_executor = MagicMock()
        tool_executor.available_tools.return_value = ()
        tool_executor.dispatch.return_value = {"stdout": "ok", "returncode": 0}

        loop = AgentLoop(llm_client, tool_executor, audit_logger=audit_logger)
        loop.findings_store = FindingsStore()
        loop.engagement = EngagementState()

        # Simulate LLM deciding to call a tool then giving final answer
        llm_client.decide_next_step.side_effect = [
            AgentDecision(
                thought="test",
                tool_name="read_file",
                arguments={"path": "test.txt"},
                final_answer=None,
                raw_text="",
            ),
            AgentDecision(
                thought="done",
                tool_name=None,
                arguments={},
                final_answer="Terminé",
                raw_text="Terminé",
            ),
        ]

        events = list(loop.run("test", ""))
        self.assertEqual(audit_logger.count, 1)
        self.assertEqual(audit_logger.entries[0].event_type, "tool_call")
        self.assertEqual(audit_logger.entries[0].tool_name, "read_file")

    def test_audit_logs_tool_error(self):
        from app.tool_executor import ToolExecutionError

        audit_logger = AuditLogger(self.workspace)
        llm_client = MagicMock()
        tool_executor = MagicMock()
        tool_executor.available_tools.return_value = ()
        tool_executor.dispatch.side_effect = ToolExecutionError("boom")

        loop = AgentLoop(llm_client, tool_executor, audit_logger=audit_logger)
        loop.findings_store = FindingsStore()
        loop.engagement = EngagementState()

        llm_client.decide_next_step.side_effect = [
            AgentDecision(
                thought="test",
                tool_name="bad_tool",
                arguments={},
                final_answer=None,
                raw_text="",
            ),
            AgentDecision(
                thought="done",
                tool_name=None,
                arguments={},
                final_answer="Erreur",
                raw_text="Erreur",
            ),
        ]

        events = list(loop.run("test", ""))
        self.assertEqual(audit_logger.count, 1)
        self.assertEqual(audit_logger.entries[0].event_type, "tool_error")

    def test_no_crash_without_audit_logger(self):
        """Verify that the loop works fine when audit_logger is None."""
        llm_client = MagicMock()
        tool_executor = MagicMock()
        tool_executor.available_tools.return_value = ()

        loop = AgentLoop(llm_client, tool_executor)  # No audit_logger
        loop.findings_store = FindingsStore()
        loop.engagement = EngagementState()

        llm_client.decide_next_step.return_value = AgentDecision(
            thought="ok",
            tool_name=None,
            arguments={},
            final_answer="Bonjour",
            raw_text="Bonjour",
        )

        events = list(loop.run("hello", ""))
        final = [e for e in events if e["type"] == "final_answer"]
        self.assertEqual(len(final), 1)


class TestReportWithAuditTimeline(unittest.TestCase):
    """Tests for audit timeline inclusion in reports."""

    def setUp(self):
        self.tmpdir = TemporaryDirectory()
        self.workspace = Path(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_report_includes_audit_timeline(self):
        from app.report_generator import generate_pentest_report

        audit_logger = AuditLogger(self.workspace)
        audit_logger.log_tool_call("nmap", {"command": "nmap -sV target"}, {"stdout": "22/tcp open ssh"})
        audit_logger.log_finding("nmap", 1, "22/tcp open ssh")

        findings_store = FindingsStore()
        engagement = EngagementState()

        # Add a finding so report isn't empty
        from app.findings import Finding, FindingType
        findings_store.add(Finding(FindingType.PORT, "22", "nmap", "high"))

        output_path = self.workspace / "test_report.md"
        generate_pentest_report(
            target_summary="10.10.10.10",
            findings_store=findings_store,
            engagement_state=engagement,
            session_duration_minutes=5,
            output_path=output_path,
            audit_logger=audit_logger,
        )

        content = output_path.read_text(encoding="utf-8")
        self.assertIn("Timeline des Actions", content)
        self.assertIn("nmap", content)

    def test_report_without_audit_logger(self):
        from app.report_generator import generate_pentest_report

        findings_store = FindingsStore()
        engagement = EngagementState()
        from app.findings import Finding, FindingType
        findings_store.add(Finding(FindingType.PORT, "22", "nmap", "high"))

        output_path = self.workspace / "test_report_no_audit.md"
        generate_pentest_report(
            target_summary="10.10.10.10",
            findings_store=findings_store,
            engagement_state=engagement,
            session_duration_minutes=5,
            output_path=output_path,
        )
        content = output_path.read_text(encoding="utf-8")
        self.assertNotIn("Timeline des Actions", content)


if __name__ == "__main__":
    unittest.main()
