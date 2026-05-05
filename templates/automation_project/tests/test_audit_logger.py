"""Tests for app.audit_logger — Audit trail persistence and formatting."""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from app.audit_logger import AuditEntry, AuditLogger


class TestAuditEntry(unittest.TestCase):
    def test_default_timestamp(self):
        entry = AuditEntry(event_type="test")
        self.assertTrue(entry.timestamp)
        self.assertIn("T", entry.timestamp)

    def test_fields(self):
        entry = AuditEntry(
            event_type="tool_call",
            tool_name="nmap",
            arguments={"command": "nmap -sV 10.10.10.10"},
            result_summary="Scan completed",
            target="10.10.10.10",
            phase="recon",
        )
        self.assertEqual(entry.event_type, "tool_call")
        self.assertEqual(entry.tool_name, "nmap")
        self.assertEqual(entry.target, "10.10.10.10")


class TestAuditLogger(unittest.TestCase):
    def setUp(self):
        self.tmpdir = TemporaryDirectory()
        self.workspace = Path(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_init_creates_audit_dir(self):
        logger = AuditLogger(self.workspace)
        self.assertTrue((self.workspace / "audit").is_dir())

    def test_log_writes_to_file(self):
        logger = AuditLogger(self.workspace)
        entry = AuditEntry(event_type="test", tool_name="echo")
        logger.log(entry)

        self.assertTrue(logger.audit_file.exists())
        content = logger.audit_file.read_text(encoding="utf-8").strip()
        data = json.loads(content)
        self.assertEqual(data["event_type"], "test")
        self.assertEqual(data["tool_name"], "echo")

    def test_log_tool_call(self):
        logger = AuditLogger(self.workspace)
        logger.log_tool_call(
            "nmap",
            {"command": "nmap -sV target"},
            {"stdout": "PORT STATE SERVICE\n22/tcp open ssh", "returncode": 0},
            target="10.10.10.10",
            phase="recon",
        )
        self.assertEqual(logger.count, 1)
        entry = logger.entries[0]
        self.assertEqual(entry.event_type, "tool_call")
        self.assertEqual(entry.tool_name, "nmap")
        self.assertIn("PORT STATE SERVICE", entry.result_summary)

    def test_log_tool_call_error(self):
        logger = AuditLogger(self.workspace)
        logger.log_tool_call(
            "nmap",
            {"command": "nmap bad"},
            {"error": "command failed"},
            success=False,
        )
        self.assertEqual(logger.entries[0].event_type, "tool_error")

    def test_log_finding(self):
        logger = AuditLogger(self.workspace)
        logger.log_finding("nmap", 3, "22, 80, 443", target="target", phase="recon")
        self.assertEqual(logger.count, 1)
        self.assertEqual(logger.entries[0].event_type, "finding")
        self.assertIn("3 decouverte(s)", logger.entries[0].result_summary)

    def test_log_phase_change(self):
        logger = AuditLogger(self.workspace)
        logger.log_phase_change("recon", "enumeration", "Ports identifies")
        self.assertEqual(logger.entries[0].event_type, "phase_change")
        self.assertIn("recon -> enumeration", logger.entries[0].result_summary)

    def test_log_scope_change(self):
        logger = AuditLogger(self.workspace)
        logger.log_scope_change(["10.10.10.0/24", "192.168.1.0/24"])
        self.assertEqual(logger.entries[0].event_type, "scope_change")
        self.assertIn("10.10.10.0/24", logger.entries[0].result_summary)

    def test_log_scope_change_empty(self):
        logger = AuditLogger(self.workspace)
        logger.log_scope_change([])
        self.assertIn("aucun", logger.entries[0].result_summary)

    def test_timeline(self):
        logger = AuditLogger(self.workspace)
        logger.log_tool_call("nmap", {}, {"stdout": "ok"})
        logger.log_finding("nmap", 2, "22, 80")
        timeline = logger.timeline()
        self.assertEqual(len(timeline), 2)
        self.assertIsInstance(timeline[0], dict)

    def test_timeline_markdown(self):
        logger = AuditLogger(self.workspace)
        logger.log_tool_call("nmap", {"command": "nmap -sV target"}, {"stdout": "ok"}, target="target")
        logger.log_finding("nmap", 2, "22, 80")
        logger.log_phase_change("recon", "enumeration", "ports trouves")
        logger.log_scope_change(["10.0.0.0/8"])

        md = logger.timeline_markdown()
        self.assertIn("**nmap**", md)
        self.assertIn("Decouvertes", md)
        self.assertIn("Phase:", md)
        self.assertIn("Scope", md)

    def test_timeline_markdown_empty(self):
        logger = AuditLogger(self.workspace)
        self.assertEqual(logger.timeline_markdown(), "")

    def test_multiple_entries_jsonl(self):
        logger = AuditLogger(self.workspace)
        logger.log(AuditEntry(event_type="a"))
        logger.log(AuditEntry(event_type="b"))
        logger.log(AuditEntry(event_type="c"))

        lines = logger.audit_file.read_text(encoding="utf-8").strip().split("\n")
        self.assertEqual(len(lines), 3)
        for line in lines:
            data = json.loads(line)
            self.assertIn("event_type", data)

    def test_count_property(self):
        logger = AuditLogger(self.workspace)
        self.assertEqual(logger.count, 0)
        logger.log(AuditEntry(event_type="test"))
        self.assertEqual(logger.count, 1)

    def test_entries_returns_copy(self):
        logger = AuditLogger(self.workspace)
        logger.log(AuditEntry(event_type="test"))
        entries = logger.entries
        entries.clear()
        self.assertEqual(logger.count, 1)

    def test_result_summary_truncation(self):
        logger = AuditLogger(self.workspace)
        long_output = "x" * 1000
        logger.log_tool_call("nmap", {}, {"stdout": long_output})
        self.assertLessEqual(len(logger.entries[0].result_summary), 500)

    def test_load_from_file(self):
        logger = AuditLogger(self.workspace)
        logger.log(AuditEntry(event_type="tool_call", tool_name="nmap"))
        logger.log(AuditEntry(event_type="finding", tool_name="gobuster"))

        loaded = AuditLogger.load_from_file(logger.audit_file)
        self.assertEqual(loaded.count, 2)
        self.assertEqual(loaded.entries[0].tool_name, "nmap")
        self.assertEqual(loaded.entries[1].tool_name, "gobuster")

    def test_load_from_nonexistent_file(self):
        loaded = AuditLogger.load_from_file(self.workspace / "nonexistent.jsonl")
        self.assertEqual(loaded.count, 0)


if __name__ == "__main__":
    unittest.main()
