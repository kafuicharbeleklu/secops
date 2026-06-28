from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from secops_agent.core.memory import ConversationMemory
from secops_agent.core.llm import Message
from secops_agent.core.mission import Finding, Host, MissionContext, Service
from secops_agent.core.result_parser import ToolResultParser
from secops_agent.core.structured_memory import StructuredMemory
from secops_agent.main import (
    _load_agent_session,
    _reset_agent_structured_state,
    _save_agent_session,
)


class SessionPersistenceTests(unittest.TestCase):
    def _session_settings(self, tmpdir: str):
        return SimpleNamespace(sessions_dir=Path(tmpdir))

    def _structured_memory(self, memory: ConversationMemory) -> StructuredMemory:
        mission = MissionContext(name="Persisted assessment")
        mission.add_target("example.com", "domain")
        service = Service(
            host="93.184.216.34",
            port=443,
            protocol="tcp",
            service="https",
            version="Apache httpd 2.4.49",
        )
        finding = Finding(
            title="Missing security headers",
            severity="low",
            category="headers",
            target="https://example.com",
            evidence="Missing: Strict-Transport-Security",
            tool_used="http_headers",
        )
        mission.add_host(Host(ip="93.184.216.34", hostname="example.com"))
        mission.add_service(service)
        mission.upsert_finding(finding)
        mission.refresh_phase_from_state()

        structured_memory = StructuredMemory(conversation=memory, mission=mission)
        structured_memory.knowledge.add_service(service)
        structured_memory.knowledge.add_finding(finding)
        structured_memory.knowledge.add_note("Evidence reviewed for reporting.")
        return structured_memory

    def test_save_and_load_session_restores_structured_state(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("secops_agent.core.memory.settings", self._session_settings(tmpdir)):
                memory = ConversationMemory()
                memory.add_user_message("scan example.com")
                memory.add_assistant_message("Recorded findings.")
                structured_memory = self._structured_memory(memory)

                path = memory.save_session("assessment", structured_memory=structured_memory)
                payload = json.loads(path.read_text(encoding="utf-8"))

                self.assertEqual(payload["version"], 2)
                self.assertIn("messages", payload)
                self.assertIn("structured_memory", payload)

                loaded_memory = ConversationMemory()
                loaded_structured = StructuredMemory(
                    conversation=loaded_memory,
                    mission=MissionContext(name="empty"),
                )

                self.assertTrue(
                    loaded_memory.load_session(
                        "assessment",
                        structured_memory=loaded_structured,
                    )
                )

        self.assertEqual(loaded_memory.messages[0].content, "scan example.com")
        self.assertEqual(loaded_structured.mission.name, "Persisted assessment")
        self.assertEqual(loaded_structured.mission.phase.value, "vulnerability")
        self.assertEqual(len(loaded_structured.mission.findings), 1)
        self.assertEqual(len(loaded_structured.mission.findings[0].evidence_items), 1)
        self.assertIn("93.184.216.34:443/tcp", loaded_structured.knowledge.services)
        self.assertEqual(loaded_structured.knowledge.notes, ["Evidence reviewed for reporting."])

    def test_legacy_list_session_format_still_loads_messages(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            session_path = Path(tmpdir) / "legacy.json"
            session_path.write_text(
                json.dumps([Message(role="user", content="legacy prompt").to_dict()]),
                encoding="utf-8",
            )
            with patch("secops_agent.core.memory.settings", self._session_settings(tmpdir)):
                memory = ConversationMemory()
                structured_memory = StructuredMemory(
                    conversation=memory,
                    mission=MissionContext(name="legacy mission"),
                )

                self.assertTrue(memory.load_session("legacy", structured_memory=structured_memory))

        self.assertEqual(memory.messages[0].content, "legacy prompt")
        self.assertEqual(structured_memory.mission.name, "legacy mission")
        self.assertFalse(structured_memory.knowledge.findings)

    def test_agent_session_helpers_resync_result_parser_mission(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("secops_agent.core.memory.settings", self._session_settings(tmpdir)):
                source_memory = ConversationMemory()
                source_structured = self._structured_memory(source_memory)
                source_agent = SimpleNamespace(
                    memory=source_memory,
                    structured_memory=source_structured,
                    result_parser=ToolResultParser(mission=source_structured.mission),
                )
                _save_agent_session(source_agent, "agent-session")

                target_memory = ConversationMemory()
                target_structured = StructuredMemory(
                    conversation=target_memory,
                    mission=MissionContext(name="blank"),
                )
                target_agent = SimpleNamespace(
                    memory=target_memory,
                    structured_memory=target_structured,
                    result_parser=ToolResultParser(mission=target_structured.mission),
                )

                self.assertTrue(_load_agent_session(target_agent, "agent-session"))

        self.assertEqual(target_agent.structured_memory.mission.name, "Persisted assessment")
        self.assertIs(target_agent.result_parser.mission, target_agent.structured_memory.mission)

    def test_reset_agent_structured_state_clears_mission_and_knowledge(self):
        memory = ConversationMemory()
        structured_memory = self._structured_memory(memory)
        agent = SimpleNamespace(
            memory=memory,
            structured_memory=structured_memory,
            result_parser=ToolResultParser(mission=structured_memory.mission),
        )

        _reset_agent_structured_state(agent, name="Fresh session")

        self.assertEqual(agent.structured_memory.mission.name, "Fresh session")
        self.assertFalse(agent.structured_memory.knowledge.findings)
        self.assertFalse(agent.structured_memory.knowledge.services)
        self.assertIs(agent.result_parser.mission, agent.structured_memory.mission)


if __name__ == "__main__":
    unittest.main()
