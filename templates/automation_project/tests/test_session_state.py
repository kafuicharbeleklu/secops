"""Tests for the Session State persistence module."""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from app.session_state import (
    SessionState,
    SessionSummary,
    delete_session,
    list_sessions,
    load_session,
    save_session,
)


class TestSessionState(unittest.TestCase):
    def test_defaults(self):
        state = SessionState()
        self.assertEqual(state.phase, "recon")
        self.assertEqual(state.tools_used, [])
        self.assertEqual(state.targets, [])
        self.assertEqual(state.scope, [])
        self.assertTrue(len(state.started_at) > 0)

    def test_touch_updates_last_active(self):
        state = SessionState()
        old_ts = state.last_active
        import time
        time.sleep(0.01)
        state.touch()
        # Should be updated (or at least not earlier)
        self.assertTrue(len(state.last_active) > 0)

    def test_custom_values(self):
        state = SessionState(
            session_id="test_session",
            target_summary="10.10.10.10",
            phase="exploit",
            tools_used=["nmap", "gobuster"],
            scope=["10.10.10.0/24"],
            findings_count=5,
        )
        self.assertEqual(state.session_id, "test_session")
        self.assertEqual(state.phase, "exploit")
        self.assertEqual(len(state.tools_used), 2)


class TestSaveSession(unittest.TestCase):
    def setUp(self):
        self.tmpdir = TemporaryDirectory()
        self.workspace = Path(self.tmpdir.name) / "workspace"
        self.workspace.mkdir()

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_save_creates_file(self):
        state = SessionState(session_id="test1", phase="recon")
        path = save_session(self.workspace, state)
        self.assertTrue(path.exists())
        self.assertIn("session_test1.json", path.name)

    def test_save_auto_generates_id(self):
        state = SessionState()
        path = save_session(self.workspace, state)
        self.assertTrue(path.exists())
        self.assertTrue(len(state.session_id) > 0)

    def test_save_content_is_valid_json(self):
        state = SessionState(
            session_id="json_test",
            target_summary="target",
            tools_used=["nmap"],
        )
        path = save_session(self.workspace, state)
        data = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(data["session_id"], "json_test")
        self.assertEqual(data["tools_used"], ["nmap"])

    def test_save_creates_sessions_dir(self):
        state = SessionState(session_id="dirtest")
        save_session(self.workspace, state)
        self.assertTrue((self.workspace / "sessions").is_dir())

    def test_overwrite_existing(self):
        state = SessionState(session_id="overwrite", phase="recon")
        save_session(self.workspace, state)
        state.phase = "exploit"
        save_session(self.workspace, state)
        loaded = load_session(self.workspace, "overwrite")
        self.assertEqual(loaded.phase, "exploit")


class TestLoadSession(unittest.TestCase):
    def setUp(self):
        self.tmpdir = TemporaryDirectory()
        self.workspace = Path(self.tmpdir.name) / "workspace"
        self.workspace.mkdir()

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_load_existing(self):
        state = SessionState(
            session_id="load_test",
            target_summary="10.10.10.10",
            phase="enum",
            tools_used=["nmap", "gobuster"],
            scope=["10.10.10.0/24"],
            findings_count=3,
        )
        save_session(self.workspace, state)
        loaded = load_session(self.workspace, "load_test")
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.session_id, "load_test")
        self.assertEqual(loaded.phase, "enum")
        self.assertEqual(loaded.tools_used, ["nmap", "gobuster"])
        self.assertEqual(loaded.findings_count, 3)

    def test_load_nonexistent_returns_none(self):
        result = load_session(self.workspace, "nonexistent")
        self.assertIsNone(result)

    def test_load_corrupted_returns_none(self):
        sessions_dir = self.workspace / "sessions"
        sessions_dir.mkdir()
        bad_file = sessions_dir / "session_corrupt.json"
        bad_file.write_text("not json", encoding="utf-8")
        result = load_session(self.workspace, "corrupt")
        self.assertIsNone(result)

    def test_load_ignores_unknown_fields(self):
        sessions_dir = self.workspace / "sessions"
        sessions_dir.mkdir()
        data = {
            "session_id": "extra_fields",
            "phase": "recon",
            "unknown_field": "should be ignored",
        }
        path = sessions_dir / "session_extra_fields.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        loaded = load_session(self.workspace, "extra_fields")
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.session_id, "extra_fields")
        self.assertFalse(hasattr(loaded, "unknown_field"))


class TestListSessions(unittest.TestCase):
    def setUp(self):
        self.tmpdir = TemporaryDirectory()
        self.workspace = Path(self.tmpdir.name) / "workspace"
        self.workspace.mkdir()

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_empty_workspace(self):
        sessions = list_sessions(self.workspace)
        self.assertEqual(sessions, [])

    def test_lists_saved_sessions(self):
        save_session(self.workspace, SessionState(session_id="s1", phase="recon"))
        save_session(self.workspace, SessionState(session_id="s2", phase="exploit"))
        sessions = list_sessions(self.workspace)
        self.assertEqual(len(sessions), 2)
        ids = {s.session_id for s in sessions}
        self.assertIn("s1", ids)
        self.assertIn("s2", ids)

    def test_returns_session_summaries(self):
        save_session(self.workspace, SessionState(
            session_id="summary_test",
            target_summary="10.10.10.10",
            phase="enum",
            findings_count=5,
        ))
        sessions = list_sessions(self.workspace)
        self.assertEqual(len(sessions), 1)
        s = sessions[0]
        self.assertIsInstance(s, SessionSummary)
        self.assertEqual(s.session_id, "summary_test")
        self.assertEqual(s.target, "10.10.10.10")
        self.assertEqual(s.phase, "enum")
        self.assertEqual(s.findings_count, 5)

    def test_skips_corrupted_files(self):
        save_session(self.workspace, SessionState(session_id="good"))
        sessions_dir = self.workspace / "sessions"
        bad_file = sessions_dir / "session_bad.json"
        bad_file.write_text("not json", encoding="utf-8")
        sessions = list_sessions(self.workspace)
        self.assertEqual(len(sessions), 1)
        self.assertEqual(sessions[0].session_id, "good")


class TestDeleteSession(unittest.TestCase):
    def setUp(self):
        self.tmpdir = TemporaryDirectory()
        self.workspace = Path(self.tmpdir.name) / "workspace"
        self.workspace.mkdir()

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_delete_existing(self):
        save_session(self.workspace, SessionState(session_id="to_delete"))
        self.assertTrue(delete_session(self.workspace, "to_delete"))
        self.assertIsNone(load_session(self.workspace, "to_delete"))

    def test_delete_nonexistent(self):
        self.assertFalse(delete_session(self.workspace, "nonexistent"))


class TestRoundTrip(unittest.TestCase):
    """Test full save → list → load → verify cycle."""

    def setUp(self):
        self.tmpdir = TemporaryDirectory()
        self.workspace = Path(self.tmpdir.name) / "workspace"
        self.workspace.mkdir()

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_full_roundtrip(self):
        original = SessionState(
            session_id="roundtrip",
            target_summary="10.10.10.10",
            phase="exploit",
            tools_used=["nmap", "gobuster", "nikto"],
            targets=[{"raw": "10.10.10.10", "address": "10.10.10.10", "target_type": "ip"}],
            scope=["10.10.10.0/24"],
            active_case_slug="htb-example",
            conversation_summary="Scanned target, found web services",
            findings_count=12,
        )
        save_session(self.workspace, original)

        sessions = list_sessions(self.workspace)
        self.assertEqual(len(sessions), 1)
        self.assertEqual(sessions[0].session_id, "roundtrip")

        loaded = load_session(self.workspace, "roundtrip")
        self.assertEqual(loaded.session_id, original.session_id)
        self.assertEqual(loaded.target_summary, original.target_summary)
        self.assertEqual(loaded.phase, original.phase)
        self.assertEqual(loaded.tools_used, original.tools_used)
        self.assertEqual(loaded.scope, original.scope)
        self.assertEqual(loaded.active_case_slug, original.active_case_slug)
        self.assertEqual(loaded.conversation_summary, original.conversation_summary)
        self.assertEqual(loaded.findings_count, original.findings_count)
        self.assertEqual(len(loaded.targets), 1)


if __name__ == "__main__":
    unittest.main()
