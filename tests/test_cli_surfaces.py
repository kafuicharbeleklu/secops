from __future__ import annotations

import tempfile
import unittest
from unittest.mock import patch
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from secops_agent.cli.attachments import parse_attach_argument
from secops_agent.cli.cancel import CANCEL_USAGE, parse_cancel_argument
from secops_agent.cli.permissions import (
    PERMISSIONS_USAGE,
    normalize_permission_mode,
    parse_permission_argument,
    plan_permission_command,
)
from secops_agent.cli.sandbox import SANDBOX_USAGE, parse_sandbox_argument
from secops_agent.cli.sessions import (
    LOAD_USAGE,
    SAVE_USAGE,
    build_session_metadata,
    build_session_summary,
    format_session_description,
    parse_export_argument,
    parse_load_argument,
    parse_save_argument,
    resolve_resume_target,
    resolve_session_model,
    should_autosave_session,
)
from secops_agent.cli.slash import parse_slash_command
from secops_agent.cli.surfaces import should_use_interactive_surface
from secops_agent.cli.tasks import TASK_USAGE, parse_task_argument
from secops_agent.cli.tools import parse_tool_argument
from secops_agent.cli.workspace import ADD_DIR_USAGE, parse_add_dir_argument
from secops_agent.main import _export_pentest_report, _unknown_command_message, run_chat_loop
from secops_agent.core.mission import MissionContext
from secops_agent.ui.commands import get_command, suggest_command


class CliSurfaceTests(unittest.TestCase):
    def test_session_summary_helpers_preserve_resume_picker_metadata(self):
        legacy = build_session_summary(
            "legacy.json",
            [{"role": "user", "content": "hello"}],
            modified_at="2026-06-03T10:00:00+00:00",
        )
        versioned = build_session_summary(
            "restorable.json",
            {
                "metadata": {
                    "saved_at": "2026-06-03T09:08:07+00:00",
                    "model": "gemini-2.5-flash",
                    "cwd": "/home/administrator/secops_v2",
                    "auto_saved": True,
                },
                "messages": [{"role": "user", "content": "scan"}],
                "runtime": {"artifacts": [{"title": "report"}]},
            },
        )
        malformed = build_session_summary(
            "bad.json",
            {"metadata": [], "messages": "nope", "runtime": {"artifacts": "nope"}},
        )

        self.assertEqual(legacy["label"], "legacy")
        self.assertEqual(legacy["messages"], 1)
        self.assertEqual(legacy["saved_at"], "2026-06-03T10:00:00+00:00")
        self.assertEqual(versioned["messages"], 1)
        self.assertEqual(versioned["artifacts"], 1)
        self.assertEqual(versioned["model"], "gemini-2.5-flash")
        self.assertTrue(versioned["auto_saved"])
        self.assertEqual(malformed["messages"], 0)
        self.assertEqual(malformed["artifacts"], 0)

        description = format_session_description(versioned)

        self.assertIn("2026-06-03 09:08", description)
        self.assertIn("gemini-2.5-flash", description)
        self.assertIn("1 msg", description)
        self.assertIn("1 artifact", description)
        self.assertIn("secops_v2", description)

    def test_resolve_session_model_preserves_current_restore_semantics(self):
        normal = resolve_session_model(
            {
                "model": "gemma-high",
                "thinking_level": " high ",
                "model_auto_routing": False,
            }
        )
        auto = resolve_session_model(
            {
                "model": "gemini-2.5-flash",
                "thinking_level": "",
                "model_auto_routing": True,
            }
        )
        empty = resolve_session_model({"model": "   "})
        invalid = resolve_session_model(["not", "metadata"])

        self.assertEqual(normal.raw_model, "gemma-high")
        self.assertEqual(normal.thinking_level, "high")
        self.assertEqual(auto.raw_model, "auto")
        self.assertIsNone(auto.thinking_level)
        self.assertEqual(empty.raw_model, "")
        self.assertEqual(invalid.raw_model, "")

    def test_session_autosave_helpers_preserve_current_main_semantics(self):
        empty_mission = SimpleNamespace(
            targets=[],
            hosts={},
            services={},
            findings=[],
            credentials=[],
            blocked_reasons=[],
            completed_objectives=[],
        )
        active_mission = SimpleNamespace(
            targets=[],
            hosts={},
            services={"10.0.0.5:80/tcp": object()},
            findings=[],
            credentials=[],
            blocked_reasons=[],
            completed_objectives=[],
        )

        self.assertFalse(
            should_autosave_session(message_count=0, artifact_count=0, mission=empty_mission)
        )
        self.assertTrue(
            should_autosave_session(message_count=1, artifact_count=0, mission=empty_mission)
        )
        self.assertTrue(
            should_autosave_session(message_count=0, artifact_count=1, mission=empty_mission)
        )
        self.assertTrue(
            should_autosave_session(message_count=0, artifact_count=0, mission=active_mission)
        )

        metadata = build_session_metadata(
            "restorable",
            auto_saved=True,
            reason="exit",
            model_name="gemma-4-26b-a4b-it",
            thinking_level="high",
            model_auto_routing=True,
            cwd="/workspace",
            now=datetime(2026, 6, 3, 9, 8, 7, tzinfo=timezone.utc),
        )

        self.assertEqual(metadata["name"], "restorable")
        self.assertTrue(metadata["auto_saved"])
        self.assertEqual(metadata["reason"], "exit")
        self.assertEqual(metadata["saved_at"], "2026-06-03T09:08:07+00:00")
        self.assertEqual(metadata["model"], "gemma-4-26b-a4b-it")
        self.assertEqual(metadata["thinking_level"], "high")
        self.assertTrue(metadata["model_auto_routing"])
        self.assertEqual(metadata["cwd"], "/workspace")

    def test_parse_attach_argument_preserves_current_main_semantics(self):
        empty = parse_attach_argument("")
        list_alias = parse_attach_argument(" LS ")
        attach = parse_attach_argument(" evidence.txt investigation note ")

        self.assertEqual(empty.action, "list")
        self.assertEqual(empty.argument, "")
        self.assertEqual(list_alias.action, "list")
        self.assertEqual(attach.action, "attach")
        self.assertEqual(attach.argument, "evidence.txt investigation note")

    def test_parse_tool_argument_preserves_current_main_semantics(self):
        listing = parse_tool_argument("")
        detail = parse_tool_argument(" nmap_scan ")

        self.assertEqual(listing.action, "list")
        self.assertEqual(listing.tool_name, "")
        self.assertEqual(detail.action, "detail")
        self.assertEqual(detail.tool_name, "nmap_scan")

    def test_resolve_resume_target_preserves_current_main_semantics(self):
        explicit = resolve_resume_target(
            " chosen ",
            interactive_surface=True,
            selected_session="ignored",
            latest_session="latest",
        )
        selected = resolve_resume_target(
            "",
            interactive_surface=True,
            selected_session="picked.json",
            latest_session="latest.json",
        )
        exited = resolve_resume_target("", interactive_surface=True)
        latest = resolve_resume_target(
            "",
            interactive_surface=False,
            latest_session="latest.json",
        )
        empty = resolve_resume_target("", interactive_surface=False)

        self.assertEqual((explicit.action, explicit.target), ("load", "chosen"))
        self.assertEqual((selected.action, selected.target), ("load", "picked.json"))
        self.assertEqual(exited.action, "exit")
        self.assertEqual((latest.action, latest.target), ("load", "latest.json"))
        self.assertEqual(empty.action, "empty")

    def test_parse_export_argument_preserves_default_timestamp_name(self):
        explicit = parse_export_argument(" report-name ")
        generated = parse_export_argument("", now=datetime(2026, 6, 3, 9, 8, 7))

        self.assertEqual(explicit.name, "report-name")
        self.assertEqual(generated.name, "secops_20260603_090807")

    def test_parse_session_name_arguments_preserve_current_main_semantics(self):
        empty_save = parse_save_argument("")
        empty_load = parse_load_argument(" ")
        self.assertEqual(empty_save.error, SAVE_USAGE)
        self.assertEqual(empty_load.error, LOAD_USAGE)

        save = parse_save_argument(" my session ")
        load = parse_load_argument("restorable")
        self.assertEqual(save.name, "my session")
        self.assertEqual(save.error, "")
        self.assertEqual(load.name, "restorable")

    def test_parse_add_dir_argument_preserves_current_main_semantics(self):
        empty = parse_add_dir_argument("")
        self.assertEqual(empty.error, ADD_DIR_USAGE)

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            child = root / "workspace"
            child.mkdir()

            relative = parse_add_dir_argument("workspace", cwd=root)
            self.assertEqual(relative.path, child)
            self.assertEqual(relative.error, "")

            missing = parse_add_dir_argument("missing", cwd=root)
            self.assertEqual(missing.error, f"Directory not found: {root / 'missing'}")

    def test_parse_cancel_argument_preserves_current_main_semantics(self):
        empty = parse_cancel_argument("")
        self.assertEqual(empty.error, CANCEL_USAGE)

        task = parse_cancel_argument(" task-1 ")
        self.assertEqual(task.task_id, "task-1")
        self.assertEqual(task.error, "")

        spaced = parse_cancel_argument("task-1 logs")
        self.assertEqual(spaced.task_id, "task-1 logs")

    def test_parse_sandbox_argument_preserves_current_main_semantics(self):
        self.assertEqual(parse_sandbox_argument("").action, "status")
        self.assertIsNone(parse_sandbox_argument("status").enabled)

        on = parse_sandbox_argument("ENABLED")
        self.assertEqual(on.action, "on")
        self.assertTrue(on.enabled)

        off = parse_sandbox_argument("disable")
        self.assertEqual(off.action, "off")
        self.assertFalse(off.enabled)

        invalid = parse_sandbox_argument("maybe")
        self.assertEqual(invalid.action, "maybe")
        self.assertEqual(invalid.error, SANDBOX_USAGE)

    def test_parse_task_argument_preserves_current_main_semantics(self):
        empty = parse_task_argument("")
        self.assertEqual(empty.error, TASK_USAGE)

        detail = parse_task_argument("task-1")
        self.assertEqual(detail.task_id, "task-1")
        self.assertEqual(detail.action, "detail")

        logs = parse_task_argument("task-1 OUTPUT")
        self.assertEqual(logs.task_id, "task-1")
        self.assertEqual(logs.action, "logs")

        unknown_action = parse_task_argument("task-1 preview")
        self.assertEqual(unknown_action.task_id, "task-1")
        self.assertEqual(unknown_action.action, "detail")

    def test_parse_permission_argument_preserves_current_main_semantics(self):
        self.assertEqual(parse_permission_argument("").kind, "show")

        clear = parse_permission_argument("clear now")
        self.assertEqual(clear.kind, "clear")
        self.assertEqual(clear.action, "clear")

        rule = parse_permission_argument("ALLOW tool(nmap_scan)")
        self.assertEqual(rule.kind, "rule")
        self.assertEqual(rule.action, "allow")
        self.assertEqual(rule.resource_text, "tool(nmap_scan)")

        invalid = parse_permission_argument("allow")
        self.assertEqual(invalid.kind, "invalid")
        self.assertEqual(invalid.error, PERMISSIONS_USAGE)

    def test_permission_rule_confirm_token_is_parsed(self):
        # Audit T2.8: a high-risk allow needs an explicit `confirm` second confirmation.
        plain = parse_permission_argument("allow tool(run_shell)")
        self.assertEqual(plain.kind, "rule")
        self.assertEqual(plain.resource_text, "tool(run_shell)")
        self.assertFalse(plain.confirmed)

        confirmed = parse_permission_argument("allow tool(run_shell) confirm")
        self.assertEqual(confirmed.kind, "rule")
        self.assertEqual(confirmed.resource_text, "tool(run_shell)")
        self.assertTrue(confirmed.confirmed)

        # The token must not corrupt a resource that legitimately ends in ')'.
        compound = parse_permission_argument("allow command_exact(whoami && id) confirm")
        self.assertEqual(compound.resource_text, "command_exact(whoami && id)")
        self.assertTrue(compound.confirmed)

    def test_plan_permission_command_preserves_current_main_branching(self):
        menu = plan_permission_command("", interactive_surface=True)
        show = plan_permission_command("", interactive_surface=False)
        clear = plan_permission_command("clear", interactive_surface=True)
        rule = plan_permission_command("deny tool(run_shell)", interactive_surface=False)
        invalid = plan_permission_command("allow", interactive_surface=True)

        self.assertEqual(menu.action, "menu")
        self.assertFalse(menu.render_policy)
        self.assertEqual(show.action, "show")
        self.assertTrue(show.render_policy)
        self.assertEqual(clear.action, "clear")
        self.assertFalse(clear.render_policy)
        self.assertEqual(rule.action, "rule")
        self.assertEqual(rule.argument.resource_text, "tool(run_shell)")
        self.assertFalse(rule.render_policy)
        self.assertEqual(invalid.action, "invalid")
        self.assertEqual(invalid.argument.error, PERMISSIONS_USAGE)
        self.assertFalse(invalid.render_policy)

    def test_normalize_permission_mode_preserves_current_cli_semantics(self):
        self.assertEqual(normalize_permission_mode(None), "request-review")
        self.assertEqual(normalize_permission_mode("plan"), "plan")
        self.assertEqual(normalize_permission_mode(" STRICT "), "strict")
        self.assertEqual(
            normalize_permission_mode("request-review", dangerously_skip_permissions=True),
            "always-proceed",
        )

        with self.assertRaisesRegex(ValueError, "Unknown permission mode 'maybe'"):
            normalize_permission_mode("maybe")

    def test_parse_slash_command_preserves_current_main_semantics(self):
        parsed = parse_slash_command("/MODEL   gemma-high  ", get_command)

        self.assertEqual(parsed.raw, "/MODEL   gemma-high")
        self.assertEqual(parsed.command, "/model")
        self.assertEqual(parsed.argument, "gemma-high")
        self.assertEqual(parsed.canonical_command, "/model")

    def test_parse_slash_command_resolves_aliases_and_keeps_unknowns(self):
        alias = parse_slash_command("/permission", get_command)
        unknown = parse_slash_command("/does-not-exist arg", get_command)

        self.assertEqual(alias.command, "/permission")
        self.assertEqual(alias.canonical_command, "/permissions")
        self.assertEqual(unknown.command, "/does-not-exist")
        self.assertEqual(unknown.argument, "arg")
        self.assertEqual(unknown.canonical_command, "/does-not-exist")

    def test_parse_slash_command_rejects_non_slash_input(self):
        with self.assertRaises(ValueError):
            parse_slash_command("hello", get_command)

    def test_unknown_command_suggests_close_canonical_command_and_usage(self):
        suggestion = suggest_command("/permissons")

        self.assertIsNotNone(suggestion)
        self.assertEqual(suggestion.name, "/permissions")
        self.assertEqual(
            _unknown_command_message("/permissons"),
            "Unknown command: /permissons\n"
            "Did you mean /permissions?\n"
            "Usage: /permissions [allow|ask|deny|clear] <resource>",
        )

    def test_unknown_command_falls_back_to_help_when_not_close(self):
        self.assertIsNone(suggest_command("/unrelated-command"))
        self.assertEqual(
            _unknown_command_message("/unrelated-command"),
            "Unknown command: /unrelated-command\nUse /help to list available commands.",
        )

    def test_interactive_surface_requires_known_command_tty_and_no_argument(self):
        self.assertTrue(
            should_use_interactive_surface(
                "/model",
                "",
                stdin_isatty=True,
                stdout_isatty=True,
            )
        )
        self.assertFalse(
            should_use_interactive_surface(
                "/model",
                "gemma",
                stdin_isatty=True,
                stdout_isatty=True,
            )
        )
        self.assertFalse(
            should_use_interactive_surface(
                "/unknown",
                "",
                stdin_isatty=True,
                stdout_isatty=True,
            )
        )
        self.assertFalse(
            should_use_interactive_surface(
                "/help",
                "",
                stdin_isatty=False,
                stdout_isatty=True,
            )
        )

    def test_main_keeps_run_chat_loop_compatibility_export(self):
        self.assertTrue(callable(run_chat_loop))

    def test_structured_report_export_writes_markdown(self):
        mission = MissionContext(name="CLI report test")
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("secops_agent.main.Path.home", return_value=Path(tmpdir)):
                path = _export_pentest_report(mission, "assessment")

            self.assertEqual(path, Path(tmpdir) / ".secops_agent" / "reports" / "assessment.md")
            self.assertIn("# CLI report test Pentest Report", path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
