from __future__ import annotations

import asyncio
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from secops_agent.core.llm import GeminiProvider
from secops_agent.core.memory import ConversationMemory
from secops_agent.core.mission import MissionContext
from secops_agent.core.preferences import load_model_preference, save_model_preference
from secops_agent.core.result_parser import ToolResultParser
from secops_agent.core.structured_memory import StructuredMemory
from secops_agent.core.tools import ToolRegistry
from secops_agent.core.agent import SecOpsAgent
from secops_agent.main import (
    _autosave_agent_session,
    _format_session_description,
    _load_agent_session,
    _session_summary,
    _set_model_selection,
    _startup_model_selection,
    run_chat_loop,
)
from secops_agent.ui.runtime import RuntimeState
from rich.console import Console


class _FakeRenderer:
    def __init__(self) -> None:
        self.console = Console(width=100, record=True, force_terminal=False, file=io.StringIO())
        self.messages: list[str] = []

    def render_user_input(self, *args, **kwargs) -> None:
        self.messages.append(str(args[0]) if args else "")

    def render_success(self, message: str) -> None:
        self.messages.append(message)

    def render_status(self, message: str) -> None:
        self.messages.append(message)

    def render_error(self, message: str) -> None:
        self.messages.append(message)

    def render_welcome(self) -> None:
        self.messages.append("welcome")


class _FakeInputHandler:
    def __init__(self, inputs: list[str]) -> None:
        self._inputs = list(inputs)

    def update_context(self, **kwargs) -> None:
        return None

    async def get_input(self, **kwargs):
        if self._inputs:
            return self._inputs.pop(0)
        return "/exit"


class RuntimePersistenceTests(unittest.TestCase):
    def test_model_preference_preserves_existing_permission_settings(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            settings_path = Path(tmpdir) / "settings.json"
            settings_path.write_text(
                json.dumps({"permissions": {"tool(*)": "allow"}}),
                encoding="utf-8",
            )

            save_model_preference(
                "gemma-high",
                resolved_model="gemma-4-26b-a4b-it",
                thinking_level="high",
                path=settings_path,
            )

            data = json.loads(settings_path.read_text(encoding="utf-8"))
            self.assertEqual(data["permissions"], {"tool(*)": "allow"})
            self.assertEqual(data["preferences"]["model"]["raw_model"], "gemma-high")
            self.assertEqual(
                load_model_preference(settings_path)["thinking_level"],
                "high",
            )

    def test_model_selection_command_persists_selected_model(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            settings_path = Path(tmpdir) / "settings.json"
            agent = SimpleNamespace(llm=GeminiProvider(api_key="", model_name="gemini"))

            with patch.dict(os.environ, {"SECOPS_SETTINGS_FILE": str(settings_path)}):
                message = _set_model_selection(agent, "gemma-high", persist=True)

            data = json.loads(settings_path.read_text(encoding="utf-8"))
            self.assertIn("Gemma 4 26B", message)
            self.assertEqual(data["preferences"]["model"]["raw_model"], "gemma-high")
            self.assertEqual(data["preferences"]["model"]["thinking_level"], "high")

    def test_startup_model_selection_uses_cli_override_before_preference(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            settings_path = Path(tmpdir) / "settings.json"
            save_model_preference(
                "gemma-high",
                resolved_model="gemma-4-26b-a4b-it",
                thinking_level="high",
                path=settings_path,
            )

            with patch.dict(os.environ, {"SECOPS_SETTINGS_FILE": str(settings_path)}):
                self.assertEqual(_startup_model_selection("gemini"), ("gemini", None))
                self.assertEqual(_startup_model_selection(None), ("gemma-high", "high"))

    def test_autosave_writes_active_session_with_metadata(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            session_settings = SimpleNamespace(
                sessions_dir=Path(tmpdir),
                MODEL_TEMPERATURE=0.2,
                MODEL_MAX_TOKENS=4096,
                TOOL_TIMEOUT=60,
                LOG_FILE="secops.log",
            )
            memory = ConversationMemory()
            memory.add_user_message("hello")
            structured_memory = StructuredMemory(
                conversation=memory,
                mission=MissionContext(name="autosave test"),
            )
            agent = SimpleNamespace(
                memory=memory,
                structured_memory=structured_memory,
                llm=SimpleNamespace(
                    model_name="gemini-2.5-flash",
                    current_thinking_level="",
                    model_auto_routing=False,
                ),
            )
            runtime = RuntimeState()
            runtime.add_artifact(
                "nmap_scan result",
                "tool-result",
                "PORT 80/tcp open http",
                source="nmap_scan",
            )

            with (
                patch("secops_agent.main.settings", session_settings),
                patch("secops_agent.core.memory.settings", session_settings),
            ):
                path = _autosave_agent_session(agent, runtime, "secops-auto")

            self.assertIsNotNone(path)
            payload = json.loads(Path(path).read_text(encoding="utf-8"))
            self.assertEqual(payload["version"], 2)
            self.assertTrue(payload["metadata"]["auto_saved"])
            self.assertEqual(payload["metadata"]["name"], "secops-auto")
            self.assertEqual(payload["metadata"]["reason"], "exit")
            self.assertEqual(payload["messages"][0]["content"], "hello")
            self.assertEqual(payload["runtime"]["artifacts"][0]["title"], "nmap_scan result")

    def test_session_load_restores_runtime_artifacts_and_model(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            session_settings = SimpleNamespace(sessions_dir=Path(tmpdir))
            source_memory = ConversationMemory()
            source_memory.add_user_message("scan")
            source_runtime = RuntimeState()
            source_runtime.add_artifact(
                "HTTP report",
                "response",
                "report body",
                source="assistant",
            )
            source_agent = SimpleNamespace(
                memory=source_memory,
                structured_memory=StructuredMemory(
                    conversation=source_memory,
                    mission=MissionContext(name="source"),
                ),
                llm=GeminiProvider(api_key="", model_name="gemma-high"),
            )
            target_memory = ConversationMemory()
            target_runtime = RuntimeState()
            target_agent = SimpleNamespace(
                memory=target_memory,
                structured_memory=StructuredMemory(
                    conversation=target_memory,
                    mission=MissionContext(name="target"),
                ),
                result_parser=SimpleNamespace(mission=None),
                llm=GeminiProvider(api_key="", model_name="gemini"),
            )

            with (
                patch("secops_agent.main.settings", session_settings),
                patch("secops_agent.core.memory.settings", session_settings),
            ):
                _autosave_agent_session(source_agent, source_runtime, "restorable")
                loaded = _load_agent_session(target_agent, "restorable", runtime=target_runtime)

            self.assertTrue(loaded)
            self.assertEqual(target_memory.messages[0].content, "scan")
            self.assertEqual(target_runtime.artifacts[0].title, "HTTP report")
            self.assertEqual(target_runtime.artifacts[0].content, "report body")
            self.assertEqual(target_agent.llm.model_name, "gemma-4-26b-a4b-it")
            self.assertEqual(target_agent.llm.current_thinking_level, "high")

    def test_resume_without_arg_tracks_loaded_session_for_exit_autosave(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            session_settings = SimpleNamespace(
                sessions_dir=Path(tmpdir),
                MODEL_TEMPERATURE=0.2,
                MODEL_MAX_TOKENS=4096,
                TOOL_TIMEOUT=60,
                LOG_FILE="secops.log",
            )
            source_memory = ConversationMemory()
            source_memory.add_user_message("previous prompt")
            source_runtime = RuntimeState()
            source_runtime.add_artifact("evidence", "response", "body", source="assistant")
            source_agent = SimpleNamespace(
                memory=source_memory,
                structured_memory=StructuredMemory(
                    conversation=source_memory,
                    mission=MissionContext(name="source"),
                ),
                llm=SimpleNamespace(
                    model_name="gemini-2.5-flash",
                    current_thinking_level="",
                    model_auto_routing=False,
                ),
            )
            target_memory = ConversationMemory()
            target_mission = MissionContext(name="target")
            target_agent = SecOpsAgent(
                llm=GeminiProvider(api_key="", model_name="gemini"),
                registry=ToolRegistry(),
                memory=target_memory,
                structured_memory=StructuredMemory(
                    conversation=target_memory,
                    mission=target_mission,
                ),
                result_parser=ToolResultParser(mission=target_mission),
                max_iterations=1,
            )
            renderer = _FakeRenderer()
            input_handler = _FakeInputHandler(["/resume", "/exit"])

            with (
                patch("secops_agent.main.settings", session_settings),
                patch("secops_agent.core.memory.settings", session_settings),
                patch("sys.stdin.isatty", return_value=False),
                patch("sys.stdout.isatty", return_value=False),
            ):
                _autosave_agent_session(source_agent, source_runtime, "restorable")
                asyncio.run(
                    run_chat_loop(
                        target_agent,
                        renderer,
                        input_handler,
                        skip_animation=True,
                    )
                )

            files = sorted(path.name for path in Path(tmpdir).glob("*.json"))
            payload = json.loads((Path(tmpdir) / "restorable.json").read_text(encoding="utf-8"))

        self.assertEqual(files, ["restorable.json"])
        self.assertEqual(payload["messages"][0]["content"], "previous prompt")
        self.assertEqual(payload["runtime"]["artifacts"][0]["title"], "evidence")
        self.assertTrue(any("restorable" in message for message in renderer.messages))

    def test_session_summary_includes_resume_metadata(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            session_settings = SimpleNamespace(sessions_dir=Path(tmpdir))
            memory = ConversationMemory()
            memory.add_user_message("hello")
            runtime = RuntimeState()
            runtime.add_artifact("artifact", "response", "content")
            agent = SimpleNamespace(
                memory=memory,
                structured_memory=StructuredMemory(
                    conversation=memory,
                    mission=MissionContext(name="summary"),
                ),
                llm=SimpleNamespace(
                    model_name="gemini-2.5-flash",
                    current_thinking_level="",
                    model_auto_routing=False,
                ),
            )

            with (
                patch("secops_agent.main.settings", session_settings),
                patch("secops_agent.core.memory.settings", session_settings),
            ):
                _autosave_agent_session(agent, runtime, "summary-session")
                summary = _session_summary("summary-session")

            self.assertEqual(summary["messages"], 1)
            self.assertEqual(summary["artifacts"], 1)
            self.assertEqual(summary["model"], "gemini-2.5-flash")
            self.assertIn("gemini-2.5-flash", _format_session_description(summary))

    def test_autosave_skips_empty_session(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            session_settings = SimpleNamespace(sessions_dir=Path(tmpdir))
            memory = ConversationMemory()
            structured_memory = StructuredMemory(
                conversation=memory,
                mission=MissionContext(name="empty autosave test"),
            )
            agent = SimpleNamespace(
                memory=memory,
                structured_memory=structured_memory,
                llm=SimpleNamespace(
                    model_name="gemini-2.5-flash",
                    current_thinking_level="",
                    model_auto_routing=False,
                ),
            )

            with (
                patch("secops_agent.main.settings", session_settings),
                patch("secops_agent.core.memory.settings", session_settings),
            ):
                path = _autosave_agent_session(agent, RuntimeState(), "secops-empty")

            self.assertIsNone(path)
            self.assertFalse(list(Path(tmpdir).glob("*.json")))

    def test_clear_removes_archive_before_autosave_activity_check(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            session_settings = SimpleNamespace(sessions_dir=Path(tmpdir))
            memory = ConversationMemory(max_messages=1)
            memory.add_user_message("old")
            memory.add_user_message("new")
            self.assertTrue(memory.get_all_messages())
            memory.clear()
            structured_memory = StructuredMemory(
                conversation=memory,
                mission=MissionContext(name="cleared"),
            )
            agent = SimpleNamespace(
                memory=memory,
                structured_memory=structured_memory,
                llm=SimpleNamespace(
                    model_name="gemini-2.5-flash",
                    current_thinking_level="",
                    model_auto_routing=False,
                ),
            )

            with (
                patch("secops_agent.main.settings", session_settings),
                patch("secops_agent.core.memory.settings", session_settings),
            ):
                path = _autosave_agent_session(agent, RuntimeState(), "cleared")

            self.assertIsNone(path)
            self.assertEqual(memory.get_all_messages(), [])


if __name__ == "__main__":
    unittest.main()
