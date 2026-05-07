import unittest
import io
import json
import re
import sys
import time
from contextlib import redirect_stdout
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from prompt_toolkit.input.defaults import create_pipe_input
from prompt_toolkit.keys import Keys
from prompt_toolkit.layout import Window
from prompt_toolkit.output import DummyOutput

from app.branding import THEME_PALETTES
from app.findings import Finding, FindingsStore, FindingType
from app.jobs import JobTracker
from app.learning_journal import LearningJournal
from app.methodology import parse_phase
from app.project_shell import (
    AutomationProjectShell,
    ClaudeStyleRadioList,
    COMMAND_MENU_ENTRIES,
    COMMAND_SPECS,
    CommandAwareAutoSuggest,
    PromptSession,
    STATUSLINE_FIELDS,
)
from app.session_state import SessionState, save_session
from app.tool_executor import ToolExecutionError


ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


class ProjectShellChatTests(unittest.TestCase):
    def setUp(self):
        patcher_load = patch("app.shell_template.BaseTerminalShell.load_state", return_value=None)
        patcher_save = patch("app.shell_template.BaseTerminalShell.save_state", return_value=None)
        self.addCleanup(patcher_load.stop)
        self.addCleanup(patcher_save.stop)
        patcher_load.start()
        patcher_save.start()
        patcher_jobs = patch("app.project_shell.JobTracker.load_state", side_effect=lambda _path: JobTracker())
        self.addCleanup(patcher_jobs.stop)
        patcher_jobs.start()

    def test_free_text_falls_back_to_memory_when_gemini_fails(self):
        shell = AutomationProjectShell()

        def fake_call(_prompt):
            shell.last_gemini_error = "Acces refuse par l'API Gemini (403)."
            return None

        shell._call_gemini = fake_call
        shell.handle_unresolved_text("je vois http smb ssh sur cette machine")

        self.assertEqual(shell.panel.title, "Agent local")
        self.assertTrue(
            any("• Cas analogue: basic_penetration" in line for line in shell.panel.lines)
        )
        self.assertTrue(any("• Hypothèse:" in line or "• Prochaine piste:" in line for line in shell.panel.lines))

    def test_generic_fallback_does_not_force_lab_memory_when_gemini_fails(self):
        shell = AutomationProjectShell()
        shell.active_case = shell.knowledge_store.get_case("basic_penetration")

        def fake_call(_prompt):
            shell.last_gemini_error = "Acces refuse par l'API Gemini (403)."
            return None

        shell._call_gemini = fake_call
        shell.handle_unresolved_text("aide moi a ecrire un script python")

        self.assertFalse(any("cas analogue:" in line for line in shell.panel.lines))
        self.assertTrue(any("Si tu veux exploiter la memoire de lab" in line for line in shell.panel.lines))
        self.assertFalse(any("cible active:" in line for line in shell.panel.lines))

    def test_free_text_captures_target_for_context(self):
        shell = AutomationProjectShell()
        with patch.object(shell, "_call_gemini", return_value=None):
            shell.last_gemini_error = "network error"
            shell.handle_unresolved_text("la cible est 10.129.134.165, que regarder ensuite ?")

        self.assertEqual(shell.current_target, "10.129.134.165")
        self.assertIsNotNone(shell.active_target)
        self.assertEqual(shell.active_target.address, "10.129.134.165")
        self.assertEqual(shell.agent_loop.active_target.address, "10.129.134.165")
        self.assertTrue(any("10.129.134.165" in line for line in shell.panel.lines))

    def test_target_declaration_only_sets_target_without_agent_action(self):
        shell = AutomationProjectShell()
        with patch.object(shell.agent_loop, "run") as run_mock:
            shell.handle_unresolved_text("Target IP Address 10.130.169.228")

        run_mock.assert_not_called()
        self.assertEqual(shell.current_target, "10.130.169.228")
        self.assertIsNotNone(shell.active_target)
        self.assertTrue(any("Aucune commande lancee" in line for line in shell.panel.lines))

    def test_bare_scan_word_is_not_a_command_alias(self):
        shell = AutomationProjectShell()
        with patch.object(shell, "_ask_agent", return_value=None) as ask_mock:
            shell.process_input("scan")

        ask_mock.assert_called_once_with("scan")

    def test_case_command_activates_case(self):
        shell = AutomationProjectShell()
        shell.dispatch_command("/case", ["basic_penetration"])

        self.assertEqual(shell.panel.title, "Cas actif")
        self.assertEqual(shell.active_case.slug, "basic_penetration")

    def test_shell_does_not_activate_first_case_by_default(self):
        shell = AutomationProjectShell()

        self.assertIsNone(shell.active_case)

    def test_shell_starts_without_printed_welcome_panel(self):
        shell = AutomationProjectShell()

        self.assertEqual(shell.panel.title, "")
        self.assertEqual(shell.panel.lines, [])
        self.assertEqual(shell.panel.variant, "plain")

    def test_panel_rendering_uses_codex_title_and_list_style(self):
        shell = AutomationProjectShell()
        shell.set_panel(
            "Point model corrigé.",
            [
                "J'ai aligne le picker /model.",
                "",
                "› 1. Default ✔ avec le check colle au modele actif.",
                "Ligne separee: Enter to confirm · Esc to exit.",
                "",
                "Verification:",
                "suite complete: 628 tests OK",
            ],
            tone="success",
        )
        output = io.StringIO()

        with redirect_stdout(output):
            shell.render_panel_state()

        rendered = ANSI_RE.sub("", output.getvalue())
        self.assertIn("• Point model corrigé.", rendered)
        self.assertIn("  J'ai aligne le picker /model.", rendered)
        self.assertIn("  - › 1. Default ✔ avec le check colle au modele actif.", rendered)
        self.assertIn("  - Ligne separee: Enter to confirm · Esc to exit.", rendered)
        self.assertIn("  Verification:", rendered)
        self.assertIn("  - suite complete: 628 tests OK", rendered)
        self.assertNotIn("✓ Point model corrigé.", rendered)
        self.assertNotIn("  •", rendered)

    def test_status_panel_rows_render_as_codex_dash_items(self):
        shell = AutomationProjectShell()
        shell.dispatch_command("/status", [])
        output = io.StringIO()

        with redirect_stdout(output):
            shell.render_panel_state()

        rendered = ANSI_RE.sub("", output.getvalue())
        self.assertIn("• Status", rendered)
        self.assertIn("  - Modele:", rendered)
        self.assertIn("  - Memoire:", rendered)
        self.assertNotIn("  Modele:", rendered)
        self.assertNotIn("  • Modele:", rendered)

    def test_status_command_reports_session_context(self):
        shell = AutomationProjectShell()

        shell.dispatch_command("/status", [])

        self.assertEqual(shell.panel.title, "Status")
        self.assertTrue(any("Modele:" in line for line in shell.panel.lines))
        self.assertTrue(any("Memoire:" in line for line in shell.panel.lines))
        self.assertTrue(any("Findings:" in line for line in shell.panel.lines))

    def test_doctor_command_reports_local_diagnostics(self):
        shell = AutomationProjectShell()

        shell.dispatch_command("/doctor", [])

        self.assertEqual(shell.panel.title, "Diagnostic")
        self.assertEqual(shell.panel.variant, "plain")
        self.assertTrue(any(line.startswith("─") for line in shell.panel.lines))
        self.assertTrue(any("Diagnostics" in line for line in shell.panel.lines))
        self.assertTrue(any("Updates" in line for line in shell.panel.lines))
        self.assertTrue(any("Version locks" in line for line in shell.panel.lines))
        self.assertTrue(any("Python:" in line for line in shell.panel.lines))
        self.assertTrue(any("Gemini:" in line for line in shell.panel.lines))
        self.assertTrue(any("Outils pentest:" in line for line in shell.panel.lines))

    def test_doctor_separator_renders_without_color(self):
        shell = AutomationProjectShell()
        shell.dispatch_command("/doctor", [])
        separator = next(line for line in shell.panel.lines if line.startswith("─"))
        output = io.StringIO()

        with redirect_stdout(output):
            shell.render_panel_state()

        self.assertIn(separator, output.getvalue().splitlines())

    def test_doctor_rendering_matches_claude_tree_style(self):
        shell = AutomationProjectShell()
        shell.dispatch_command("/doctor", [])
        output = io.StringIO()

        with redirect_stdout(output):
            shell.render_panel_state()

        rendered = ANSI_RE.sub("", output.getvalue())
        self.assertIn("Diagnostics", rendered)
        self.assertIn("  ├ Currently running:", rendered)
        self.assertIn("  └ Search: OK", rendered)
        self.assertIn("Updates", rendered)
        self.assertIn("Version locks", rendered)
        self.assertNotIn("• Diagnostic", rendered)
        self.assertNotIn("  - Python:", rendered)

    def test_doctor_tty_runs_tabbed_overlay_without_panel_trace(self):
        shell = AutomationProjectShell()
        previous_panel = shell.panel

        with patch.object(shell, "_can_use_transient_page", return_value=True):
            with patch.object(shell, "render_panel_state") as render_mock:
                with patch.object(shell, "_run_doctor_view", return_value="continue") as doctor_mock:
                    shell.dispatch_command("/doctor", [])

        self.assertIs(shell.panel, previous_panel)
        self.assertTrue(shell._stream_rendered_panel)
        doctor_mock.assert_called_once_with()
        render_mock.assert_not_called()

    def test_doctor_view_uses_same_page_eraseable_application(self):
        shell = AutomationProjectShell()
        captured = []

        class FakeApplication:
            def __init__(self, **kwargs):
                captured.append(kwargs)

            def run(self):
                return "continue"

        with patch("app.project_shell.Application", FakeApplication):
            result = shell._run_doctor_view()

        self.assertEqual(result, "continue")
        self.assertTrue(captured)
        self.assertFalse(captured[0]["full_screen"])
        self.assertTrue(captured[0]["erase_when_done"])

    def test_doctor_active_tab_uses_same_colored_container_as_help(self):
        shell = AutomationProjectShell()

        fragments = shell._doctor_header_fragments("updates")

        self.assertIn((shell._help_active_tab_style(), " updates "), fragments)
        self.assertIn(("", "diagnostics"), fragments)
        self.assertIn(("", "locks"), fragments)
        self.assertNotIn(("", "overview"), fragments)

    def test_doctor_body_fragments_split_diagnostic_tabs(self):
        shell = AutomationProjectShell()

        diagnostics = "".join(text for _style, text in shell._doctor_body_fragments("diagnostics"))
        updates = "".join(text for _style, text in shell._doctor_body_fragments("updates"))

        self.assertTrue(diagnostics.startswith("SECOPS doctor   "))
        self.assertIn((shell._help_active_tab_style(), " diagnostics "), shell._doctor_body_fragments("diagnostics"))
        self.assertIn("Diagnostics", diagnostics)
        self.assertNotIn("Updates", diagnostics)
        self.assertNotIn("Version locks", diagnostics)
        self.assertIn("Updates", updates)
        self.assertNotIn("Diagnostics", updates)
        self.assertNotIn("Version locks", updates)
        self.assertIn("Press Enter to continue", updates)

    def test_stats_command_reports_session_counters(self):
        shell = AutomationProjectShell()
        shell.conversation_history = [{"user": "scan", "agent": "ok"}]
        shell.agent_loop.messages = [{"role": "user", "content": "scan"}]
        shell.llm_client.last_prompt_chars = 1200
        shell.llm_client.last_tool_count = 4

        shell.dispatch_command("/stats", [])

        self.assertEqual(shell.panel.title, "Statistiques")
        self.assertTrue(any("Echanges retenus: 1" in line for line in shell.panel.lines))
        self.assertTrue(any("Outils proposes au modele: 4" in line for line in shell.panel.lines))

    def test_profile_command_switches_profile_and_persists(self):
        shell = AutomationProjectShell()

        shell.dispatch_command("/profile", ["debug"])

        self.assertEqual(shell.ux_profile, "debug")
        self.assertEqual(shell.panel.title, "Profil UX")
        self.assertTrue(any("Profil actif: debug" in line for line in shell.panel.lines))
        self.assertEqual(shell.build_state_payload()["profile"], "debug")

    def test_profile_menu_uses_inline_dropdown_without_page(self):
        shell = AutomationProjectShell()
        previous_panel = shell.panel

        with patch.object(shell, "_can_use_transient_page", return_value=True):
            with patch.object(shell, "clear_screen") as clear_mock:
                with patch.object(shell, "render_shell_header") as header_mock:
                    with patch.object(shell, "render_panel_state") as panel_mock:
                        with patch.object(shell, "_run_inline_choice", return_value="debug") as inline_mock:
                            shell.dispatch_command("/profile", [])

        self.assertIs(shell.panel, previous_panel)
        self.assertEqual(shell.ux_profile, "debug")
        inline_mock.assert_called_once()
        args, kwargs = inline_mock.call_args
        self.assertEqual(args[0], "Select UX profile")
        self.assertEqual([value for value, _label in args[2]], ["quiet", "ops", "debug"])
        self.assertEqual(kwargs["default"], "ops")
        clear_mock.assert_not_called()
        header_mock.assert_not_called()
        panel_mock.assert_not_called()

    def test_profile_state_payload_restores_profile(self):
        shell = AutomationProjectShell()

        shell.apply_state_payload({"profile": "quiet"})

        self.assertEqual(shell.ux_profile, "quiet")

    def test_statusline_command_sets_fields_and_persists(self):
        shell = AutomationProjectShell()

        shell.dispatch_command("/statusline", ["model,target,phase,scope,findings,jobs,context"])

        self.assertEqual(
            shell.statusline_fields,
            ["model", "target", "phase", "scope", "findings", "jobs", "context"],
        )
        self.assertEqual(shell.panel.title, "Statusline")
        self.assertTrue(any("Configuration enregistree" in line for line in shell.panel.lines))
        self.assertEqual(shell.build_state_payload()["statusline"], shell.statusline_fields)

    def test_statusline_menu_uses_inline_dropdown_without_page(self):
        shell = AutomationProjectShell()
        previous_panel = shell.panel

        with patch.object(shell, "_can_use_transient_page", return_value=True):
            with patch.object(shell, "clear_screen") as clear_mock:
                with patch.object(shell, "render_shell_header") as header_mock:
                    with patch.object(shell, "render_panel_state") as panel_mock:
                        with patch.object(shell, "_run_inline_choice", return_value="full") as inline_mock:
                            shell.dispatch_command("/statusline", [])

        self.assertIs(shell.panel, previous_panel)
        self.assertEqual(shell.statusline_fields, list(STATUSLINE_FIELDS))
        inline_mock.assert_called_once()
        args, kwargs = inline_mock.call_args
        self.assertEqual(args[0], "Select statusline")
        self.assertEqual([value for value, _label in args[2]], ["profile", "compact", "full"])
        self.assertEqual(kwargs["default"], "profile")
        clear_mock.assert_not_called()
        header_mock.assert_not_called()
        panel_mock.assert_not_called()

    def test_statusline_picker_keeps_current_label_separated_from_description(self):
        shell = AutomationProjectShell()

        labels = dict(shell._statusline_picker_options())

        self.assertIn("Profile default (current)   Use", labels["profile"])
        self.assertNotIn("(current)Use", labels["profile"])

    def test_statusline_rejects_unknown_fields(self):
        shell = AutomationProjectShell()

        shell.dispatch_command("/statusline", ["model", "banana"])

        self.assertEqual(shell.statusline_fields, [])
        self.assertEqual(shell.panel.tone, "warn")
        self.assertTrue(any("banana" in line for line in shell.panel.lines))

    def test_statusline_default_clears_custom_fields(self):
        shell = AutomationProjectShell()
        shell.statusline_fields = ["model", "target"]

        shell.dispatch_command("/statusline", ["default"])

        self.assertEqual(shell.statusline_fields, [])
        self.assertTrue(any("profil" in line for line in shell.panel.lines))

    def test_statusline_state_payload_restores_custom_fields(self):
        shell = AutomationProjectShell()

        shell.apply_state_payload({"statusline": ["model", "target", "bad", "jobs"]})

        self.assertEqual(shell.statusline_fields, ["model", "target", "jobs"])

    def test_notify_command_switches_mode_and_persists(self):
        shell = AutomationProjectShell()

        shell.dispatch_command("/notify", ["all"])

        self.assertEqual(shell.notification_mode, "all")
        self.assertEqual(shell.panel.title, "Notifications")
        self.assertTrue(any("Mode actif: all" in line for line in shell.panel.lines))
        self.assertEqual(shell.build_state_payload()["notifications"], "all")

    def test_notify_menu_uses_inline_dropdown_without_page(self):
        shell = AutomationProjectShell()
        previous_panel = shell.panel

        with patch.object(shell, "_can_use_transient_page", return_value=True):
            with patch.object(shell, "clear_screen") as clear_mock:
                with patch.object(shell, "render_shell_header") as header_mock:
                    with patch.object(shell, "render_panel_state") as panel_mock:
                        with patch.object(shell, "_run_inline_choice", return_value="all") as inline_mock:
                            shell.dispatch_command("/notify", [])

        self.assertIs(shell.panel, previous_panel)
        self.assertEqual(shell.notification_mode, "all")
        inline_mock.assert_called_once()
        args, kwargs = inline_mock.call_args
        self.assertEqual(args[0], "Select notifications")
        self.assertEqual([value for value, _label in args[2]], ["off", "bell", "title", "all"])
        self.assertEqual(kwargs["default"], "off")
        clear_mock.assert_not_called()
        header_mock.assert_not_called()
        panel_mock.assert_not_called()

    def test_notification_state_payload_restores_mode(self):
        shell = AutomationProjectShell()

        shell.apply_state_payload({"notifications": "title"})

        self.assertEqual(shell.notification_mode, "title")

    def test_job_completion_notification_marks_event_and_emits_terminal_signals(self):
        shell = AutomationProjectShell()
        shell.notification_mode = "all"
        command = "nmap 10.10.10.10"
        job = shell.jobs.create(
            "tool",
            command,
            details=[f"commande: {command}"],
            status="running",
        )
        shell._active_tool_jobs[f"execute_command:{command}"] = job.job_id
        event = {
            "type": "tool_success",
            "name": "execute_command",
            "result": {"command": command, "returncode": 0},
        }

        with patch.object(shell, "_terminal_is_tty", return_value=True):
            with patch.object(shell, "_terminal_write") as write_mock:
                shell._finish_tool_job(event)

        self.assertIn(f"Job #{job.job_id} termine", event["notification"])
        writes = "".join(call.args[0] for call in write_mock.call_args_list)
        self.assertIn("\a", writes)
        self.assertIn("\033]0;SECOPS - Job", writes)

    def test_copy_command_saves_current_panel_to_workspace(self):
        shell = AutomationProjectShell()
        with TemporaryDirectory() as tmpdir:
            shell.workspace = Path(tmpdir)
            shell.set_panel("Agent", ["ligne utile"], tone="info")
            with patch.object(shell, "_copy_to_clipboard", return_value=False):
                shell.dispatch_command("/copy", [])

            output_path = shell.workspace / "last_output.txt"
            self.assertTrue(output_path.exists())
            self.assertIn("ligne utile", output_path.read_text(encoding="utf-8"))

        self.assertEqual(shell.panel.title, "Copie")
        self.assertTrue(any("Presse-papiers: indisponible" in line for line in shell.panel.lines))

    def test_copy_last_full_saves_recorded_full_output(self):
        shell = AutomationProjectShell()
        with TemporaryDirectory() as tmpdir:
            shell.workspace = Path(tmpdir)
            shell._set_transcript_panel(
                "Agent",
                ["sortie resumee"],
                full_text="sortie resumee\n\nsortie complete brute",
                log_path="/tmp/secops-full.log",
            )
            with patch.object(shell, "_copy_to_clipboard", return_value=False) as copy_mock:
                shell.dispatch_command("/copy", ["last", "--full"])

            output_path = shell.workspace / "last_output_full.txt"
            self.assertTrue(output_path.exists())
            self.assertIn("sortie complete brute", output_path.read_text(encoding="utf-8"))
            copy_mock.assert_called_once()

        self.assertEqual(shell.panel.title, "Copie")
        self.assertTrue(any("Log complet: /tmp/secops-full.log" in line for line in shell.panel.lines))

    def test_view_last_uses_pager_for_full_output(self):
        shell = AutomationProjectShell()
        shell._set_transcript_panel(
            "Agent",
            ["sortie resumee"],
            full_text="sortie complete a inspecter",
            log_path="/tmp/secops-full.log",
        )

        with patch("app.project_shell.pydoc.pager") as pager_mock:
            shell.dispatch_command("/view", ["last", "--pager"])

        pager_mock.assert_called_once_with("sortie complete a inspecter")
        self.assertEqual(shell.panel.title, "Vue")
        self.assertTrue(any("Dernier output ouvert" in line for line in shell.panel.lines))

    def test_view_job_reads_partial_log(self):
        shell = AutomationProjectShell()
        with TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "job.log"
            log_path.write_text("partial nmap output\n22/tcp open ssh\n", encoding="utf-8")
            job = shell.jobs.create(
                "tool",
                "nmap 10.10.10.10",
                status="cancelled",
                result=f"log partiel: {log_path}",
            )

            shell.dispatch_command("/view", [str(job.job_id)])

        self.assertEqual(shell.panel.title, "Vue job")
        self.assertTrue(any("partial nmap output" in line for line in shell.panel.lines))
        self.assertTrue(any(str(log_path) in line for line in shell.panel.lines))

    def test_model_command_switches_to_gemma_alias_for_session(self):
        shell = AutomationProjectShell()

        shell.dispatch_command("/model", ["gemma"])

        self.assertEqual(shell.panel.title, "Modele LLM")
        self.assertEqual(shell.gemini_runtime.model, "gemma-4-26b-a4b-it")
        self.assertTrue(shell.llm_client.use_native_tools)
        self.assertTrue(any("gemma-4-26b-a4b-it" in line for line in shell.panel.lines))

    def test_model_command_enables_auto_routing(self):
        shell = AutomationProjectShell()

        shell.dispatch_command("/model", ["auto"])

        self.assertTrue(shell.model_auto_routing)
        self.assertEqual(shell.gemini_runtime.model, "gemma-4-26b-a4b-it")
        self.assertTrue(shell.llm_client.use_native_tools)

    def test_model_bench_reports_routing_without_api_call(self):
        shell = AutomationProjectShell()

        shell.dispatch_command("/model", ["bench"])

        self.assertEqual(shell.panel.title, "Benchmark modele")
        self.assertTrue(any("sans appel API" in line for line in shell.panel.lines))
        self.assertTrue(any("gemma-4-26b-a4b-it" in line for line in shell.panel.lines))

    def test_model_command_is_transient_in_interactive_history(self):
        shell = AutomationProjectShell()

        self.assertTrue(shell._is_transient_command("/model"))
        self.assertTrue(shell._is_transient_command("/model gemma"))
        self.assertTrue(shell._is_transient_command("/phase"))
        self.assertTrue(shell._is_transient_command("/scope 10.10.10.10"))
        self.assertTrue(shell._is_transient_command("/permissions deny"))
        self.assertTrue(shell._is_transient_command("/compact"))
        self.assertTrue(shell._is_transient_command("/"))
        self.assertFalse(shell._is_transient_command("/menu"))
        self.assertTrue(shell._is_transient_command("/theme"))
        self.assertTrue(shell._is_transient_command("/reasoning"))
        self.assertTrue(shell._is_transient_command("/profile debug"))
        self.assertTrue(shell._is_transient_command("/help"))
        self.assertTrue(shell._is_transient_command("/doctor"))
        self.assertTrue(shell._is_transient_command("/clear"))
        self.assertTrue(shell._is_transient_command("/status"))
        self.assertTrue(shell._is_transient_command("/stats"))
        self.assertTrue(shell._is_transient_command("/case"))
        self.assertTrue(shell._is_transient_command("/case list"))
        self.assertTrue(shell._is_transient_command("/target"))
        self.assertTrue(shell._is_transient_command("/target list"))
        self.assertTrue(shell._is_transient_command("/learn"))
        self.assertTrue(shell._is_transient_command("/plan"))
        self.assertTrue(shell._is_transient_command("/session"))
        self.assertTrue(shell._is_transient_command("/session list"))
        self.assertTrue(shell._is_transient_command("/rewind"))
        self.assertTrue(shell._is_transient_command("/workflow"))
        self.assertTrue(shell._is_transient_command("/workflow list"))
        self.assertTrue(shell._is_transient_command("/session resume"))
        self.assertFalse(shell._is_transient_command("/session resume resume-me"))
        self.assertTrue(shell._is_transient_command("/resume"))
        self.assertFalse(shell._is_transient_command("/resume resume-me"))
        self.assertTrue(shell._is_transient_command("/tools"))
        self.assertFalse(shell._is_transient_command("/tools install nmap"))
        self.assertFalse(shell._is_transient_command("/case basic_penetration"))
        self.assertFalse(shell._is_transient_command("/target 10.10.10.10"))
        self.assertFalse(shell._is_transient_command("/session save lab"))
        self.assertFalse(shell._is_transient_command("/workflow recon-web"))
        self.assertFalse(shell._is_transient_command("/side question rapide"))

    def test_submitted_user_message_background_skips_commands(self):
        shell = AutomationProjectShell()

        self.assertTrue(shell._should_render_submitted_user_message("analyse smb"))
        self.assertTrue(shell._should_render_submitted_user_message("oui"))
        self.assertFalse(shell._should_render_submitted_user_message("/target 10.10.10.10"))
        self.assertFalse(shell._should_render_submitted_user_message("!pwd"))
        self.assertFalse(shell._should_render_submitted_user_message("?"))

    def test_submitted_user_message_lines_match_prompt_shape(self):
        shell = AutomationProjectShell()

        lines = shell._submitted_user_message_lines("scan web\npuis smb")

        self.assertEqual(lines, ["› scan web", "  puis smb"])

    def test_transient_command_result_messages_match_cli_transcript_style(self):
        shell = AutomationProjectShell()

        self.assertEqual(shell._transient_command_result_message("/help"), "Help dialog dismissed")
        self.assertEqual(shell._transient_command_result_message("/doctor"), "SECOPS diagnostics dismissed")
        self.assertEqual(shell._transient_command_result_message("/status"), "Status dialog dismissed")
        self.assertEqual(shell._transient_command_result_message("/stats"), "Stats dialog dismissed")
        self.assertEqual(shell._transient_command_result_message("/case"), "Case dialog dismissed")
        self.assertEqual(shell._transient_command_result_message("/target"), "Target dialog dismissed")
        self.assertEqual(shell._transient_command_result_message("/workflow list"), "Workflow dialog dismissed")
        self.assertEqual(shell._transient_command_result_message("/session resume"), "Resume dialog dismissed")
        self.assertEqual(shell._transient_command_result_message("/clear"), "")
        self.assertEqual(shell._transient_command_result_message("/"), "Command palette dismissed")

    def test_clear_transient_command_prints_no_result_line(self):
        shell = AutomationProjectShell()

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            shell._print_transient_command_result("/clear")

        self.assertEqual(buffer.getvalue(), "")

    def test_suppressed_transient_result_prints_once_only(self):
        shell = AutomationProjectShell()
        shell._suppress_transient_result_once = True

        first = io.StringIO()
        with redirect_stdout(first):
            shell._print_transient_command_result("/theme")

        second = io.StringIO()
        with redirect_stdout(second):
            shell._print_transient_command_result("/theme")

        self.assertEqual(first.getvalue(), "")
        self.assertIn("Theme dialog dismissed", second.getvalue())

    def test_panel_transient_command_uses_dialog_and_restores_previous_panel(self):
        shell = AutomationProjectShell()
        previous_panel = shell.panel
        shell.set_panel("Status", ["Modele: gemma", "Memoire: 1 cas"], tone="info")

        with patch.object(shell, "_can_use_transient_page", return_value=True):
            with patch.object(shell, "_run_panel_dialog", return_value="continue") as dialog_mock:
                result = shell._show_panel_command_transient("/status", previous_panel)

        self.assertTrue(result)
        self.assertIs(shell.panel, previous_panel)
        self.assertTrue(shell._stream_rendered_panel)
        self.assertEqual(dialog_mock.call_args.args[0].title, "Status")

    def test_panel_dialog_uses_same_page_eraseable_application(self):
        shell = AutomationProjectShell()
        shell.set_panel("Status", ["Modele: gemma"], tone="info")
        captured = []

        class FakeApplication:
            def __init__(self, **kwargs):
                captured.append(kwargs)

            def run(self):
                return "continue"

        with patch("app.project_shell.Application", FakeApplication):
            result = shell._run_panel_dialog(shell.panel)

        self.assertEqual(result, "continue")
        self.assertFalse(captured[0]["full_screen"])
        self.assertTrue(captured[0]["erase_when_done"])

    def test_panel_dialog_separator_uses_plain_style(self):
        shell = AutomationProjectShell()
        shell.set_panel("Status", ["Modele: gemma"], tone="info")

        fragments = shell._panel_dialog_fragments(shell._panel_dialog_lines(shell.panel), 0, 5)

        self.assertTrue(any(style == "" and text.strip().startswith("─") for style, text in fragments))
        self.assertFalse(any(style == shell._menu_detail_style() and text.strip().startswith("─") for style, text in fragments))

    def test_interaction_separator_is_plain_without_time(self):
        shell = AutomationProjectShell()
        output = io.StringIO()

        with patch("app.project_shell.shutil.get_terminal_size", return_value=SimpleNamespace(columns=50, lines=24)):
            with redirect_stdout(output):
                shell._render_interaction_separator()

        raw = output.getvalue()
        self.assertIn("─" * 48, raw)
        self.assertNotRegex(raw, r"\d{2}:\d{2}")
        self.assertNotIn("\x1b", raw)

    def test_transient_command_result_prints_tree_connector(self):
        shell = AutomationProjectShell()
        output = io.StringIO()

        with redirect_stdout(output):
            shell._print_transient_command_result("/help")

        rendered = ANSI_RE.sub("", output.getvalue())
        self.assertIn("  ⎿  Help dialog dismissed", rendered)

    def test_model_menu_restores_previous_panel_without_model_trace(self):
        shell = AutomationProjectShell()
        previous_panel = shell.panel

        with patch.object(shell, "_can_use_transient_page", return_value=True):
            with patch.object(shell, "clear_screen") as clear_mock:
                with patch.object(shell, "render_shell_header") as header_mock:
                    with patch.object(shell, "render_panel_state") as panel_mock:
                        with patch.object(shell, "_run_model_picker_choice", return_value=("gemma", "low")):
                            shell.dispatch_command("/model", [])

        self.assertIs(shell.panel, previous_panel)
        self.assertEqual(shell.gemini_runtime.model, "gemma-4-26b-a4b-it")
        self.assertEqual(shell.model_thinking_overrides["gemma-4-26b-a4b-it"], "low")
        clear_mock.assert_not_called()
        header_mock.assert_not_called()
        panel_mock.assert_not_called()

    def test_model_picker_erases_dropdown_after_selection(self):
        shell = AutomationProjectShell()
        captured = []

        class FakeApplication:
            def __init__(self, **kwargs):
                captured.append(kwargs)

            def run(self):
                return "cancel"

        with patch("app.project_shell.Application", FakeApplication):
            shell._run_model_picker_choice(
                "Select model",
                [],
                shell._model_picker_options(),
                default="default",
            )

        self.assertTrue(captured)
        self.assertTrue(captured[0]["erase_when_done"])

    def test_model_menu_matches_claude_style_model_list_with_effort_footer(self):
        shell = AutomationProjectShell()

        options = shell._model_picker_options()
        values = [value for value, _label in options]
        labels = [label for _value, label in options]

        self.assertEqual(values, ["default", "gemini", "gemma", "gemma-31b"])
        self.assertTrue(labels[0].startswith("Default ✔"))
        self.assertTrue(any("Use the default model" in label for label in labels))
        self.assertFalse(any("thinking high" in label for label in labels))
        self.assertIn("○ Low effort ← → to adjust", str(shell._model_picker_toolbar(shell._model_picker_effort_label("low"))))
        self.assertIn("◐ Medium effort ← → to adjust", str(shell._model_picker_toolbar(shell._model_picker_effort_label("medium"))))
        self.assertIn("● High effort (default) ← → to adjust", str(shell._model_picker_toolbar(shell._model_picker_effort_label("high"))))
        self.assertIn("◈ Max effort ← → to adjust", str(shell._model_picker_toolbar(shell._model_picker_effort_label("max"))))
        self.assertIn("Press enter to confirm or esc to go back", str(shell._model_picker_instruction_toolbar()))

    def test_model_picker_left_right_adjusts_effort_footer(self):
        shell = AutomationProjectShell()
        state = {"effort": "low"}

        shell._move_model_picker_effort(state, 1)
        self.assertEqual(state["effort"], "medium")
        shell._move_model_picker_effort(state, 1)
        self.assertEqual(state["effort"], "high")
        shell._move_model_picker_effort(state, 1)
        self.assertEqual(state["effort"], "max")
        shell._move_model_picker_effort(state, 1)
        self.assertEqual(state["effort"], "max")
        shell._move_model_picker_effort(state, -1)
        self.assertEqual(state["effort"], "high")
        shell._move_model_picker_effort(state, -1)
        self.assertEqual(state["effort"], "medium")
        shell._move_model_picker_effort(state, -1)
        self.assertEqual(state["effort"], "low")

    def test_model_picker_number_spacing_matches_shared_marker(self):
        radio_list = ClaudeStyleRadioList(
            values=[("default", "Default ✔"), ("gemini", "gemini-2.5-flash")],
            default="default",
            show_numbers=True,
            open_character="",
            select_character="›",
            close_character="",
            show_cursor=False,
            show_scrollbar=False,
        )

        text = "".join(fragment[1] for fragment in radio_list._get_text_fragments())

        self.assertIn("› 1. Default ✔", text)
        self.assertNotIn("›  1.", text)

    def test_selected_inline_option_highlights_label_and_description(self):
        shell = AutomationProjectShell()
        radio_list = ClaudeStyleRadioList(
            values=shell._model_picker_options(),
            default="default",
            show_numbers=True,
            open_character="",
            select_character="›",
            close_character="",
            show_cursor=False,
            show_scrollbar=False,
            default_style="class:option",
            selected_style=shell._inline_selected_style(),
            checked_style="",
            number_style="class:number",
        )

        fragments = radio_list._get_text_fragments()

        self.assertTrue(
            any(style == "class:selected-option" and "Default ✔" in text for style, text in fragments)
        )
        self.assertTrue(
            any(style == "class:selected-option" and "Use the default model" in text for style, text in fragments)
        )
        self.assertTrue(
            any(style == shell._menu_detail_style() and "Custom Gemma" in text for style, text in fragments)
        )

    def test_choice_list_caps_visible_options_at_six(self):
        radio_list = ClaudeStyleRadioList(
            values=[(str(index), f"Option {index}") for index in range(8)],
            default="0",
        )

        self.assertEqual(radio_list.window.height.preferred, 6)
        self.assertEqual(radio_list.window.height.max, 6)

    def test_model_command_accepts_thinking_level_inline(self):
        shell = AutomationProjectShell()

        shell.dispatch_command("/model", ["gemma", "high"])

        self.assertEqual(shell.gemini_runtime.model, "gemma-4-26b-a4b-it")
        self.assertEqual(shell.model_thinking_overrides["gemma-4-26b-a4b-it"], "high")
        self.assertTrue(shell.llm_client.use_native_tools)

    def test_model_command_default_clears_thinking_override(self):
        shell = AutomationProjectShell()
        shell.model_thinking_overrides["gemma-4-26b-a4b-it"] = "high"

        shell.dispatch_command("/model", ["gemma", "default"])

        self.assertEqual(shell.gemini_runtime.model, "gemma-4-26b-a4b-it")
        self.assertNotIn("gemma-4-26b-a4b-it", shell.model_thinking_overrides)

    def test_model_command_default_selects_default_model(self):
        shell = AutomationProjectShell()
        shell.dispatch_command("/model", ["gemma"])

        shell.dispatch_command("/model", ["default"])

        self.assertEqual(shell.gemini_runtime.model, "gemini-2.5-flash")
        self.assertFalse(shell.model_auto_routing)

    def test_scope_menu_can_use_active_target_without_trace(self):
        shell = AutomationProjectShell()
        previous_panel = shell.panel
        shell.current_target = "10.10.10.10"

        with patch.object(shell, "_can_use_transient_page", return_value=True):
            with patch.object(shell, "clear_screen"):
                with patch.object(shell, "render_shell_header"):
                    with patch.object(shell, "render_panel_state"):
                        with patch.object(shell, "_run_inline_choice", return_value="target"):
                            shell.dispatch_command("/scope", [])

        self.assertIs(shell.panel, previous_panel)
        self.assertEqual(shell.tool_executor.authorized_scope, {"10.10.10.10"})

    def test_command_menu_fuzzy_matches_descriptions_and_shortcuts(self):
        shell = AutomationProjectShell()

        debug_entry = shell._menu_matches("debug", limit=1)[0]
        shortcut_entry = shell._menu_entry_from_query("v")
        log_entry = shell._menu_entry_from_query("logs")

        self.assertEqual(debug_entry["command"], "/profile")
        self.assertEqual(shortcut_entry["command"], "/view")
        self.assertEqual(log_entry["command"], "/view")

    def test_command_palette_fallback_shows_shortcuts_and_descriptions(self):
        shell = AutomationProjectShell()

        with patch.object(shell, "_can_use_transient_page", return_value=False):
            shell.process_input("/")

        self.assertEqual(shell.panel.title, "Palette")
        self.assertTrue(any("Recherche fuzzy" in line for line in shell.panel.lines))
        self.assertTrue(any("s  /status" in line for line in shell.panel.lines))
        self.assertTrue(any("v  /view" in line and "Logs" in line for line in shell.panel.lines))

    def test_menu_tty_uses_overlay_without_palette_panel_trace(self):
        shell = AutomationProjectShell()
        previous_panel = shell.panel

        with patch.object(shell, "_can_use_transient_page", return_value=True):
            with patch.object(shell, "clear_screen") as clear_mock:
                with patch.object(shell, "render_shell_header") as header_mock:
                    with patch.object(shell, "render_panel_state") as panel_mock:
                        with patch.object(shell, "_run_menu_overlay", return_value=None) as overlay_mock:
                            shell.process_input("/")

        self.assertIs(shell.panel, previous_panel)
        overlay_mock.assert_called_once_with()
        clear_mock.assert_not_called()
        header_mock.assert_not_called()
        panel_mock.assert_not_called()

    def test_menu_overlay_uses_same_page_eraseable_application(self):
        shell = AutomationProjectShell()
        captured = []

        class FakeApplication:
            def __init__(self, **kwargs):
                captured.append(kwargs)

            def run(self):
                return None

        with patch("app.project_shell.Application", FakeApplication):
            result = shell._run_menu_overlay()

        self.assertIsNone(result)
        self.assertTrue(captured)
        self.assertFalse(captured[0]["full_screen"])
        self.assertTrue(captured[0]["erase_when_done"])

    def test_menu_overlay_options_align_command_slash_with_prompt_input(self):
        shell = AutomationProjectShell()
        options = shell._menu_overlay_options()
        radio_list = ClaudeStyleRadioList(
            values=options,
            default="/model",
            show_numbers=False,
            open_character="",
            select_character="›",
            close_character="",
            show_cursor=False,
            show_scrollbar=False,
            default_style="class:option",
            selected_style=shell._inline_selected_style(),
            checked_style="",
            number_style="class:number",
            detail_style=None,
        )

        fragments = radio_list._get_text_fragments()
        rendered = "".join(text for _style, text in fragments)

        self.assertIn("› /model", rendered)
        self.assertNotIn("› 1. /model", rendered)
        self.assertEqual(rendered.splitlines()[0].index("/"), len("› "))
        self.assertIn("Choix du modele LLM", rendered)
        self.assertFalse(any(style == shell._menu_detail_style() for style, _text in fragments))

    def test_bare_question_mark_shows_keyboard_help(self):
        shell = AutomationProjectShell()

        result = shell.process_input("?")

        self.assertTrue(result)
        self.assertEqual(shell.panel.title, "Raccourcis clavier")
        self.assertTrue(any("Ctrl+O" in line for line in shell.panel.lines))

    def test_help_fallback_uses_claude_like_sections(self):
        shell = AutomationProjectShell()

        with patch.object(shell, "_can_use_transient_page", return_value=False):
            shell.dispatch_command("/help", [])

        self.assertEqual(shell.panel.title, "Help")
        self.assertTrue(any("SECOPS TUI" in line for line in shell.panel.lines))
        self.assertTrue(any("Shortcuts" in line for line in shell.panel.lines))
        self.assertTrue(any("Browse default commands" in line for line in shell.panel.lines))
        self.assertTrue(any("/model" in line for line in shell.panel.lines))
        self.assertTrue(any("Esc to cancel" in line for line in shell.panel.lines))

    def test_help_tty_runs_transient_overlay_without_panel_trace(self):
        shell = AutomationProjectShell()
        previous_panel = shell.panel

        with patch.object(shell, "_can_use_transient_page", return_value=True):
            with patch.object(shell, "_run_help_view", return_value="cancel") as help_mock:
                shell.dispatch_command("/help", [])

        self.assertIs(shell.panel, previous_panel)
        help_mock.assert_called_once_with()

    def test_help_view_uses_same_page_eraseable_application(self):
        shell = AutomationProjectShell()
        captured = []

        class FakeApplication:
            def __init__(self, **kwargs):
                captured.append(kwargs)

            def run(self):
                return "cancel"

        with patch("app.project_shell.Application", FakeApplication):
            result = shell._run_help_view()

        self.assertEqual(result, "cancel")
        self.assertTrue(captured)
        self.assertFalse(captured[0]["full_screen"])
        self.assertTrue(captured[0]["erase_when_done"])

    def test_help_active_tab_uses_colored_container(self):
        shell = AutomationProjectShell()

        fragments = shell._help_header_fragments("general")

        self.assertIn((shell._help_active_tab_style(), " general "), fragments)
        self.assertIn(("", "commands"), fragments)
        self.assertIn(("", "custom-commands"), fragments)

    def test_help_body_fragments_replace_plain_header_in_overlay(self):
        shell = AutomationProjectShell()
        state = {"command_index": 0, "custom_index": 0}

        fragments = shell._help_body_fragments("commands", state)
        rendered = "".join(text for _style, text in fragments)

        self.assertTrue(rendered.startswith("SECOPS TUI   general"))
        self.assertIn((shell._help_active_tab_style(), " commands "), fragments)
        self.assertIn("Browse default commands", rendered)

    def test_help_body_uses_muted_detail_lines(self):
        shell = AutomationProjectShell()
        state = {"command_index": 0, "custom_index": 0}

        fragments = shell._help_body_fragments("commands", state)

        self.assertTrue(
            any(style == shell._menu_detail_style() and text.startswith("    ") for style, text in fragments)
        )
        self.assertTrue(any(style == "" and text.startswith("› /model") for style, text in fragments))

    def test_help_custom_commands_list_local_workflows(self):
        shell = AutomationProjectShell()

        lines = shell._help_custom_command_lines()

        self.assertTrue(any("Browse custom commands" in line for line in lines))
        self.assertTrue(any("/workflow recon-web" in line for line in lines))
        self.assertTrue(any("/workflow smb-enum" in line for line in lines))

    def test_tools_fallback_uses_tabbed_sections(self):
        shell = AutomationProjectShell()

        with patch.object(shell, "_can_use_transient_page", return_value=False):
            shell.dispatch_command("/tools", [])

        self.assertEqual(shell.panel.title, "Outils pentest")
        self.assertTrue(any("Onglets TTY:" in line for line in shell.panel.lines))
        self.assertTrue(any(line == "recon" for line in shell.panel.lines))
        self.assertTrue(any("nmap" in line for line in shell.panel.lines))

    def test_tools_tty_runs_transient_overlay_without_panel_trace(self):
        shell = AutomationProjectShell()
        previous_panel = shell.panel

        with patch.object(shell, "_can_use_transient_page", return_value=True):
            with patch.object(shell, "render_panel_state") as panel_mock:
                with patch.object(shell, "_run_tools_view", return_value="cancel") as tools_mock:
                    shell.dispatch_command("/tools", [])

        self.assertIs(shell.panel, previous_panel)
        tools_mock.assert_called_once_with()
        panel_mock.assert_not_called()

    def test_tools_view_uses_same_page_eraseable_application(self):
        shell = AutomationProjectShell()
        captured = []

        class FakeApplication:
            def __init__(self, **kwargs):
                captured.append(kwargs)

            def run(self):
                return "cancel"

        with patch("app.project_shell.Application", FakeApplication):
            result = shell._run_tools_view()

        self.assertEqual(result, "cancel")
        self.assertTrue(captured)
        self.assertFalse(captured[0]["full_screen"])
        self.assertTrue(captured[0]["erase_when_done"])

    def test_tools_lines_use_tabs_and_shared_selection_marker(self):
        shell = AutomationProjectShell()
        state = {"indices": {"recon": 0}}

        overview = shell._tools_lines_for_tab("overview", state)
        recon = shell._tools_lines_for_tab("recon", state)

        self.assertTrue(any("SECOPS tools" in line and "OVERVIEW" in line for line in overview))
        self.assertTrue(any("Browse recon tools" in line for line in recon))
        self.assertTrue(any(line.startswith("› ") for line in recon))

    def test_tools_active_tab_uses_same_colored_container_as_help(self):
        shell = AutomationProjectShell()

        fragments = shell._tools_header_fragments("installed")

        self.assertIn((shell._help_active_tab_style(), " installed "), fragments)
        self.assertIn(("", "overview"), fragments)
        self.assertIn(("", "missing"), fragments)

    def test_tools_body_fragments_replace_plain_header_in_overlay(self):
        shell = AutomationProjectShell()
        state = {"indices": {"recon": 0}}

        fragments = shell._tools_body_fragments("recon", state)
        rendered = "".join(text for _style, text in fragments)

        self.assertTrue(rendered.startswith("SECOPS tools   overview"))
        self.assertIn((shell._help_active_tab_style(), " recon "), fragments)
        self.assertIn("Browse recon tools", rendered)

    def test_tools_body_uses_muted_detail_lines(self):
        shell = AutomationProjectShell()
        state = {"indices": {"recon": 0}}

        fragments = shell._tools_body_fragments("recon", state)

        self.assertTrue(any(style == "" and text.lstrip().startswith("› ") for style, text in fragments))
        self.assertTrue(
            any(style == shell._menu_detail_style() and "phases:" in text for style, text in fragments)
        )
        self.assertTrue(
            any(style == shell._menu_detail_style() and "targets:" in text for style, text in fragments)
        )

    def test_menu_detail_style_changes_font_only(self):
        shell = AutomationProjectShell()

        detail_style = replace(THEME_PALETTES["dark"], no_color=False).prompt_style_dict()["menu.detail"]
        active_detail_style = shell.palette.prompt_style_dict()["menu.detail"]

        self.assertIn("fg:", detail_style)
        self.assertIn("noinherit", detail_style)
        self.assertIn("noreverse", detail_style)
        self.assertNotIn("bg:", detail_style)
        self.assertIn("noinherit", active_detail_style)
        self.assertNotIn("bg:", active_detail_style)

    def test_bare_slash_opens_command_palette(self):
        shell = AutomationProjectShell()

        with patch.object(shell, "_run_command_palette") as palette_mock:
            result = shell.process_input("/")

        self.assertTrue(result)
        palette_mock.assert_called_once_with()

    def test_command_palette_search_includes_all_slash_commands(self):
        shell = AutomationProjectShell()

        self.assertEqual(shell._menu_matches("quit", limit=1)[0]["command"], "/quit")
        self.assertEqual(shell._menu_matches("clear", limit=1)[0]["command"], "/clear")

    def test_command_palette_returns_false_when_quit_is_selected(self):
        shell = AutomationProjectShell()

        with (
            patch.object(shell, "_can_use_transient_page", return_value=True),
            patch.object(shell, "_clear_transient_screen") as clear_mock,
            patch.object(shell, "_run_menu_overlay", return_value="/quit"),
            patch.object(shell, "_print_session_summary") as summary_mock,
        ):
            result = shell._run_command_palette()

        self.assertFalse(result)
        clear_mock.assert_not_called()
        summary_mock.assert_called_once_with()

    def test_command_palette_opens_inline_like_model_picker(self):
        shell = AutomationProjectShell()
        previous_panel = shell.panel

        with (
            patch.object(shell, "_can_use_transient_page", return_value=True),
            patch.object(shell, "_clear_transient_screen") as clear_mock,
            patch.object(shell, "_run_menu_overlay", return_value=None),
        ):
            result = shell._run_command_palette()

        self.assertTrue(result)
        self.assertIs(shell.panel, previous_panel)
        clear_mock.assert_not_called()

    def test_command_palette_descriptions_share_option_style(self):
        shell = AutomationProjectShell()

        radio_list = ClaudeStyleRadioList(
            values=shell._menu_overlay_options(),
            default="/model",
            show_numbers=False,
            open_character="",
            select_character="›",
            close_character="",
            show_cursor=False,
            show_scrollbar=False,
            default_style="class:option",
            selected_style=shell._inline_selected_style(),
            checked_style="",
            number_style="class:number",
            detail_style=None,
        )
        fragments = radio_list._get_text_fragments()
        rendered = "".join(text for _style, text in fragments)

        selected_rows = [text for style, text in fragments if style == "class:selected-option"]
        self.assertTrue(any("/model" in text for text in selected_rows))
        self.assertTrue(
            any("Choix du modele LLM" in text for text in selected_rows)
        )
        self.assertIn("/permissions      Autorisations commandes", rendered)
        self.assertFalse(any(style == shell._menu_detail_style() for style, _text in fragments))
        self.assertFalse(any("Command palette" in text for _style, text in fragments))
        self.assertFalse(any("Tab completions" in text for _style, text in fragments))

    def test_prompt_slash_completion_keeps_all_commands_scrollable(self):
        shell = AutomationProjectShell()

        completions = list(
            shell.completer.get_completions(
                SimpleNamespace(text_before_cursor="/"),
                SimpleNamespace(),
            )
        )

        self.assertGreater(len(completions), 6)
        self.assertEqual(
            [completion.text for completion in completions[:6]],
            [entry["command"] for entry in COMMAND_MENU_ENTRIES[:6]],
        )
        self.assertIn("Choix du modele LLM", completions[0].display_text)
        self.assertEqual(completions[0].display_meta_text, "")
        self.assertIn("/quit", [completion.text for completion in completions])
        self.assertNotIn("/menu", [completion.text for completion in completions])
        self.assertNotIn("/menu", COMMAND_SPECS)
        self.assertEqual(shell.chrome.reserve_space_for_menu, 7)

    def test_prompt_session_caps_visible_completion_menu_to_six(self):
        captured_heights = []

        def fake_completions_menu(*args, **kwargs):
            captured_heights.append(kwargs.get("max_height"))
            return Window()

        with patch("app.project_shell._PROMPT_MODULE.CompletionsMenu", fake_completions_menu):
            with create_pipe_input() as pipe_input:
                PromptSession(input=pipe_input, output=DummyOutput())

        self.assertIn(6, captured_heights)

    def test_prompt_slash_starts_inline_completion_from_empty_prompt(self):
        shell = AutomationProjectShell()
        bindings = shell._prompt_key_bindings()

        class FakeBuffer:
            text = ""
            inserted = ""
            started = None

            def insert_text(self, value):
                self.inserted += value

            def start_completion(self, **kwargs):
                self.started = kwargs

        class FakeApp:
            result = None

            def exit(self, result=None, **kwargs):
                self.result = result

        binding = next(binding for binding in bindings.bindings if binding.keys == ("/",))
        event = SimpleNamespace(current_buffer=FakeBuffer(), app=FakeApp())

        binding.handler(event)

        self.assertIsNone(event.app.result)
        self.assertEqual(event.current_buffer.inserted, "/")
        self.assertEqual(event.current_buffer.started, {"select_first": False})

    def test_prompt_slash_inserts_literal_inside_existing_text(self):
        shell = AutomationProjectShell()
        bindings = shell._prompt_key_bindings()

        class FakeBuffer:
            text = "scan "
            inserted = ""

            def insert_text(self, value):
                self.inserted += value

        class FakeApp:
            result = None

            def exit(self, result=None, **kwargs):
                self.result = result

        binding = next(binding for binding in bindings.bindings if binding.keys == ("/",))
        event = SimpleNamespace(current_buffer=FakeBuffer(), app=FakeApp())

        binding.handler(event)

        self.assertIsNone(event.app.result)
        self.assertEqual(event.current_buffer.inserted, "/")

    def test_prompt_uses_claude_style_navigation_bindings(self):
        shell = AutomationProjectShell()
        captured_init = {}
        captured_prompt = {}

        class FakePromptSession:
            def __init__(self, **kwargs):
                captured_init.update(kwargs)

            def prompt(self, *args, **kwargs):
                captured_prompt.update(kwargs)
                return "status"

        with patch("app.project_shell.PromptSession", FakePromptSession):
            result = shell.prompt()

        self.assertEqual(result, "status")
        self.assertIn("history", captured_init)
        self.assertTrue(captured_prompt["multiline"])
        self.assertTrue(captured_prompt["enable_open_in_editor"])
        self.assertIsNotNone(captured_prompt["key_bindings"])
        self.assertIsInstance(captured_prompt["auto_suggest"], CommandAwareAutoSuggest)
        self.assertEqual(captured_prompt["default"], "")

    def test_prompt_auto_suggest_is_disabled_for_slash_commands(self):
        suggestion = CommandAwareAutoSuggest()

        self.assertIsNone(
            suggestion.get_suggestion(
                SimpleNamespace(),
                SimpleNamespace(text_before_cursor="/"),
            )
        )

    def test_empty_prompt_enter_does_not_submit_new_prompt(self):
        shell = AutomationProjectShell()

        self.assertFalse(shell._prompt_enter_should_submit(""))
        self.assertFalse(shell._prompt_enter_should_submit("   "))
        self.assertTrue(shell._prompt_enter_should_submit("/status"))

    def test_prompt_command_shortcuts_preserve_draft(self):
        shell = AutomationProjectShell()

        class FakeBuffer:
            text = "analyse 10.10.10.10"

        class FakeApp:
            result = None

            def exit(self, result=None, **kwargs):
                self.result = result

        event = SimpleNamespace(current_buffer=FakeBuffer(), app=FakeApp())

        shell._exit_prompt_with_command(event, "/model")

        self.assertEqual(event.app.result, "/model")
        self.assertEqual(shell._prompt_draft, "analyse 10.10.10.10")

    def test_prompt_tab_submits_complete_command(self):
        shell = AutomationProjectShell()
        bindings = shell._prompt_key_bindings()

        class FakeBuffer:
            text = "/status"
            submitted = False
            reset_called = False

            def validate_and_handle(self):
                self.submitted = True

            def reset(self):
                self.reset_called = True

        class FakeApp:
            result = None

            def exit(self, result=None, **kwargs):
                self.result = result

        binding = next(binding for binding in bindings.bindings if binding.keys == (Keys.Tab,))
        event = SimpleNamespace(current_buffer=FakeBuffer(), app=FakeApp())

        binding.handler(event)

        self.assertTrue(event.current_buffer.submitted)
        self.assertFalse(event.current_buffer.reset_called)
        self.assertIsNone(event.app.result)

    def test_prompt_tab_starts_completion_for_incomplete_command(self):
        shell = AutomationProjectShell()
        bindings = shell._prompt_key_bindings()

        class FakeBuffer:
            text = "/sta"
            complete_state = None
            started = False

            def start_completion(self, **kwargs):
                self.started = kwargs

            def validate_and_handle(self):
                raise AssertionError("Tab must complete incomplete commands before submitting")

        binding = next(binding for binding in bindings.bindings if binding.keys == (Keys.Tab,))
        event = SimpleNamespace(current_buffer=FakeBuffer(), app=SimpleNamespace())

        binding.handler(event)

        self.assertEqual(event.current_buffer.started, {"select_first": True})

    def test_prompt_escape_cancels_input(self):
        shell = AutomationProjectShell()
        bindings = shell._prompt_key_bindings()

        class FakeBuffer:
            text = "/status"
            complete_state = None
            reset_called = False

            def reset(self):
                self.reset_called = True

            def validate_and_handle(self):
                raise AssertionError("Esc must cancel instead of submitting")

        class FakeApp:
            result = None
            invalidated = False

            def exit(self, result=None, **kwargs):
                self.result = result

            def invalidate(self):
                self.invalidated = True

        binding = next(binding for binding in bindings.bindings if binding.keys == (Keys.Escape,))
        event = SimpleNamespace(current_buffer=FakeBuffer(), app=FakeApp())

        binding.handler(event)

        self.assertTrue(event.current_buffer.reset_called)
        self.assertTrue(event.app.invalidated)
        self.assertIsNone(event.app.result)

    def test_empty_prompt_escape_does_not_submit_new_prompt(self):
        shell = AutomationProjectShell()
        bindings = shell._prompt_key_bindings()

        class FakeBuffer:
            text = ""
            complete_state = None
            reset_called = False

            def reset(self):
                self.reset_called = True

            def validate_and_handle(self):
                raise AssertionError("Esc on empty prompt must stay in the current prompt")

        class FakeApp:
            result = None
            invalidated = False

            def exit(self, result=None, **kwargs):
                self.result = result

            def invalidate(self):
                self.invalidated = True

        binding = next(binding for binding in bindings.bindings if binding.keys == (Keys.Escape,))
        event = SimpleNamespace(current_buffer=FakeBuffer(), app=FakeApp())

        binding.handler(event)

        self.assertFalse(event.current_buffer.reset_called)
        self.assertTrue(event.app.invalidated)
        self.assertIsNone(event.app.result)

    def test_prompt_ctrl_c_quits_session(self):
        shell = AutomationProjectShell()
        bindings = shell._prompt_key_bindings()

        class FakeBuffer:
            text = "/status"

            def reset(self):
                raise AssertionError("Ctrl+C must quit instead of clearing the buffer")

        class FakeApp:
            result = None

            def exit(self, result=None, **kwargs):
                self.result = result

        binding = next(binding for binding in bindings.bindings if binding.keys == (Keys.ControlC,))
        event = SimpleNamespace(current_buffer=FakeBuffer(), app=FakeApp())

        binding.handler(event)

        self.assertEqual(event.app.result, "/quit")

    def test_prompt_reuses_preserved_draft_once(self):
        shell = AutomationProjectShell()
        shell._prompt_draft = "draft conserve"
        captured_prompt = {}

        class FakePromptSession:
            def __init__(self, **kwargs):
                pass

            def prompt(self, *args, **kwargs):
                captured_prompt.update(kwargs)
                return kwargs["default"]

        with patch("app.project_shell.PromptSession", FakePromptSession):
            result = shell.prompt()

        self.assertEqual(result, "draft conserve")
        self.assertEqual(captured_prompt["default"], "draft conserve")
        self.assertEqual(shell._prompt_draft, "")

    def test_transcript_text_uses_visible_or_full_entries(self):
        shell = AutomationProjectShell()
        shell._set_transcript_panel(
            "Agent",
            ["sortie resumee"],
            full_text="sortie complete",
            source="agent",
        )

        self.assertIn("sortie resumee", shell._transcript_text(show_all=False))
        self.assertIn("sortie complete", shell._transcript_text(show_all=True))

    def test_transcript_viewer_falls_back_to_panel_when_not_tty(self):
        shell = AutomationProjectShell()
        shell._set_transcript_panel("Agent", ["ligne transcript"], full_text="ligne complete")

        with patch("app.project_shell.sys.stdin.isatty", return_value=False):
            shell._run_transcript_viewer()

        self.assertEqual(shell.panel.title, "Transcript")
        self.assertTrue(any("ligne transcript" in line for line in shell.panel.lines))

    def test_transient_choice_uses_navigation_keybindings(self):
        shell = AutomationProjectShell()

        with patch.object(shell, "clear_screen") as clear_mock:
            with patch.object(shell, "render_shell_header") as header_mock:
                with patch.object(shell, "_run_inline_choice", return_value="cancel") as inline_mock:
                    selected = shell._run_transient_choice_page(
                        "Menu",
                        [],
                        [("cancel", "Retour")],
                    )

        self.assertEqual(selected, "cancel")
        inline_mock.assert_called_once_with("Menu", [], [("cancel", "Retour")], default=None)
        clear_mock.assert_not_called()
        header_mock.assert_not_called()

    def test_inline_choice_erases_dropdown_after_selection(self):
        shell = AutomationProjectShell()
        captured = []

        class FakeApplication:
            def __init__(self, **kwargs):
                captured.append(kwargs)

            def run(self):
                return "cancel"

        with patch("app.project_shell.Application", FakeApplication):
            shell._run_inline_choice("Menu", [], [("cancel", "Retour")], default="cancel")

        self.assertTrue(captured)
        self.assertTrue(captured[0]["erase_when_done"])

    def test_phase_menu_uses_shared_current_label_style(self):
        shell = AutomationProjectShell()
        captured = {}

        with patch.object(shell, "_run_inline_choice", return_value="cancel") as inline_mock:
            shell._run_phase_menu_page()

        args, _kwargs = inline_mock.call_args
        captured["options"] = args[2]
        labels = [label for _value, label in captured["options"]]

        self.assertTrue(any("Reconnaissance (current)" in label for label in labels))
        self.assertFalse(any(label.startswith("* ") for label in labels))

    def test_shift_tab_permission_cycle_updates_executor_mode(self):
        shell = AutomationProjectShell()

        self.assertEqual(shell._cycle_prompt_permission_mode(), "auto-low-risk")
        self.assertEqual(shell.command_permission_mode, "auto-low-risk")
        self.assertEqual(shell.tool_executor.command_permission_mode, "auto-low-risk")
        self.assertEqual(shell._cycle_prompt_permission_mode(), "read-only")
        self.assertEqual(shell._cycle_prompt_permission_mode(), "session")
        self.assertEqual(shell._cycle_prompt_permission_mode(), "ask")

    def test_permissions_command_accepts_claude_mode_aliases(self):
        shell = AutomationProjectShell()

        shell.dispatch_command("/permissions", ["default"])
        self.assertEqual(shell.command_permission_mode, "ask")

        shell.dispatch_command("/permissions", ["acceptEdits"])
        self.assertEqual(shell.command_permission_mode, "auto-low-risk")

        shell.dispatch_command("/permissions", ["auto-review"])
        self.assertEqual(shell.command_permission_mode, "auto-low-risk")

        shell.dispatch_command("/permissions", ["plan"])
        self.assertEqual(shell.command_permission_mode, "read-only")

        shell.dispatch_command("/permissions", ["bypassPermissions"])
        self.assertEqual(shell.command_permission_mode, "session")

        shell.dispatch_command("/permissions", ["full-access"])
        self.assertEqual(shell.command_permission_mode, "session")

    def test_meta_t_toggles_current_model_thinking(self):
        shell = AutomationProjectShell()
        shell.dispatch_command("/model", ["gemma"])

        self.assertTrue(shell._toggle_current_model_thinking())
        self.assertEqual(shell.model_thinking_overrides["gemma-4-26b-a4b-it"], "off")
        self.assertTrue(shell._toggle_current_model_thinking())
        self.assertNotIn("gemma-4-26b-a4b-it", shell.model_thinking_overrides)

    def test_agent_keyboard_interrupt_returns_to_shell(self):
        shell = AutomationProjectShell()

        with patch.object(shell.agent_loop, "run", side_effect=KeyboardInterrupt):
            shell.handle_unresolved_text("analyse la cible")

        self.assertEqual(shell.panel.title, "Agent")
        self.assertEqual(shell.panel.tone, "warn")
        self.assertIn("Operation annulee.", shell.panel.lines)

    def test_phase_menu_allows_guarded_phase_when_scope_exists(self):
        shell = AutomationProjectShell()
        previous_panel = shell.panel
        shell.tool_executor.set_scope(["10.10.10.0/24"])

        with patch.object(shell, "_can_use_transient_page", return_value=True):
            with patch.object(shell, "clear_screen") as clear_mock:
                with patch.object(shell, "render_shell_header") as header_mock:
                    with patch.object(shell, "render_panel_state"):
                        with patch.object(shell, "_run_inline_choice", return_value="exploitation"):
                            shell.dispatch_command("/phase", [])

        self.assertIs(shell.panel, previous_panel)
        self.assertEqual(shell.engagement.phase.value, "exploitation")
        clear_mock.assert_not_called()
        header_mock.assert_not_called()

    def test_permissions_command_updates_executor_mode(self):
        shell = AutomationProjectShell()

        shell.dispatch_command("/permissions", ["deny"])

        self.assertEqual(shell.command_permission_mode, "deny")
        self.assertEqual(shell.tool_executor.command_permission_mode, "deny")
        self.assertEqual(shell.panel.title, "Permissions")
        self.assertTrue(any("desactive" in line for line in shell.panel.lines))

    def test_permissions_command_accepts_read_only_and_auto_low_risk(self):
        shell = AutomationProjectShell()

        shell.dispatch_command("/permissions", ["read-only"])
        self.assertEqual(shell.command_permission_mode, "read-only")
        self.assertEqual(shell.tool_executor.command_permission_mode, "read-only")

        shell.dispatch_command("/permissions", ["auto-low-risk"])
        self.assertEqual(shell.command_permission_mode, "auto-low-risk")
        self.assertEqual(shell.tool_executor.command_permission_mode, "auto-low-risk")
        self.assertTrue(any("auto faible risque" in line for line in shell.panel.lines))

    def test_permissions_menu_restores_previous_panel_without_trace(self):
        shell = AutomationProjectShell()
        previous_panel = shell.panel

        with patch.object(shell, "_can_use_transient_page", return_value=True):
            with patch.object(shell, "clear_screen") as clear_mock:
                with patch.object(shell, "render_shell_header") as header_mock:
                    with patch.object(shell, "render_panel_state") as panel_mock:
                        with patch.object(shell, "_run_permissions_inline_choice", return_value="session") as picker_mock:
                            shell.dispatch_command("/permissions", [])

        self.assertIs(shell.panel, previous_panel)
        self.assertEqual(shell.command_permission_mode, "session")
        self.assertEqual(shell.tool_executor.command_permission_mode, "session")
        picker_mock.assert_called_once_with()
        clear_mock.assert_not_called()
        header_mock.assert_not_called()
        panel_mock.assert_not_called()

    def test_permissions_inline_picker_matches_codex_dropdown(self):
        shell = AutomationProjectShell()

        options = shell._permissions_picker_options()
        values = [value for value, _label in options]
        labels = [label for _value, label in options]
        radio_list = ClaudeStyleRadioList(
            values=options,
            default=shell._permissions_picker_default(),
            show_numbers=True,
            open_character="",
            select_character="›",
            close_character="",
            show_cursor=False,
            show_scrollbar=False,
            default_style="class:option",
            selected_style=shell._inline_selected_style(),
            checked_style="",
            number_style="class:number",
        )
        fragments = radio_list._get_text_fragments()
        text = "".join(fragment[1] for fragment in fragments)

        self.assertEqual(values, ["ask", "auto-low-risk", "session"])
        self.assertTrue(labels[0].startswith("Default (current)"))
        self.assertIn("Auto-review", labels[1])
        self.assertIn("Full Access", labels[2])
        self.assertIn("› 1. Default (current)", text)
        self.assertNotIn("›  1.", text)
        self.assertTrue(
            any(style == "class:selected-option" and "Codex can read" in text for style, text in fragments)
        )

        radio_list._selected_index = 1
        fragments = radio_list._get_text_fragments()
        self.assertTrue(
            any(style == shell._menu_detail_style() and "Codex can read" in text for style, text in fragments)
        )
        self.assertTrue(
            any(style == "class:selected-option" and "Same workspace-write" in text for style, text in fragments)
        )

    def test_compact_command_summarizes_agent_context(self):
        shell = AutomationProjectShell()
        shell.agent_loop.messages = [
            {"role": "user", "content": "question 1"},
            {"role": "assistant", "content": "reponse 1"},
            {"role": "user", "content": "question 2"},
            {"role": "assistant", "content": "reponse 2"},
            {"role": "user", "content": "question 3"},
        ]
        shell.conversation_history = [
            {"user": f"u{index}", "agent": f"a{index}"}
            for index in range(5)
        ]

        shell.dispatch_command("/compact", ["2"])

        self.assertEqual(shell.panel.title, "Compactage")
        self.assertEqual(shell.agent_loop.messages[0]["role"], "system")
        self.assertEqual(len(shell.agent_loop.messages), 3)
        self.assertEqual(len(shell.conversation_history), 3)
        self.assertTrue(any("Messages agent: 5 -> 3" in line for line in shell.panel.lines))

    def test_side_command_does_not_mutate_agent_memory(self):
        shell = AutomationProjectShell()
        shell.agent_loop.messages = [{"role": "user", "content": "contexte existant"}]
        shell.conversation_history = [{"user": "avant", "agent": "avant"}]

        with patch.object(shell, "_call_gemini_text", return_value="Reponse laterale.") as call_mock:
            shell.dispatch_command("/side", ["que", "sais-tu", "du", "port", "80", "?"])

        self.assertEqual(shell.panel.title, "Question laterale")
        self.assertEqual(shell.panel.lines, ["Reponse laterale."])
        self.assertEqual(shell.agent_loop.messages, [{"role": "user", "content": "contexte existant"}])
        self.assertEqual(shell.conversation_history, [{"user": "avant", "agent": "avant"}])
        self.assertIn("mode question laterale", call_mock.call_args.args[0])

    def test_btw_command_uses_side_context_without_mutating_agent_memory(self):
        shell = AutomationProjectShell()
        shell.agent_loop.messages = [{"role": "user", "content": "contexte existant"}]
        shell.conversation_history = [{"user": "avant", "agent": "avant"}]

        with patch.object(shell, "_call_gemini_text", return_value="Reponse laterale."):
            with patch.object(shell, "_run_dismissible_overlay") as overlay_mock:
                shell.dispatch_command("/btw", ["question", "rapide"])

        overlay_mock.assert_called_once()
        self.assertEqual(shell.agent_loop.messages, [{"role": "user", "content": "contexte existant"}])
        self.assertEqual(shell.conversation_history, [{"user": "avant", "agent": "avant"}])

    def test_bang_shell_command_routes_through_tool_executor(self):
        shell = AutomationProjectShell()

        with patch.object(shell, "_ask_agent", side_effect=AssertionError("agent should not run")):
            with patch.object(
                shell.tool_executor,
                "execute_command",
                return_value={
                    "command": "pwd",
                    "reason": "Commande shell explicite via !",
                    "stdout": "/tmp/workspace\n",
                    "stderr": "",
                    "returncode": 0,
                },
            ) as execute_mock:
                result = shell.process_input("!pwd")

        self.assertTrue(result)
        execute_mock.assert_called_once_with("pwd", "Commande shell explicite via !")
        self.assertEqual(shell.panel.title, "Shell")
        self.assertTrue(any("/tmp/workspace" in line for line in shell.panel.lines))
        self.assertEqual(shell.audit_logger.count, 1)

    def test_bang_shell_command_reports_executor_error(self):
        shell = AutomationProjectShell()

        with patch.object(
            shell.tool_executor,
            "execute_command",
            side_effect=ToolExecutionError("Commande bloquee en mode read-only: nmap"),
        ):
            result = shell.process_input("!nmap 10.10.10.10")

        self.assertTrue(result)
        self.assertEqual(shell.panel.title, "Shell")
        self.assertTrue(any("read-only" in line for line in shell.panel.lines))
        self.assertEqual(shell.audit_logger.count, 1)

    def test_empty_bang_shell_command_shows_usage(self):
        shell = AutomationProjectShell()

        result = shell.process_input("!")

        self.assertTrue(result)
        self.assertEqual(shell.panel.title, "Shell")
        self.assertTrue(any("Usage: !<commande>" in line for line in shell.panel.lines))

    def test_keyword_catalog_includes_recent_shell_history(self):
        shell = AutomationProjectShell()

        with patch.object(shell, "_latest_history_entries", return_value=["!pwd", "scan target"]):
            catalog = shell.get_keyword_catalog()

        self.assertEqual(catalog["!pwd"], "commande shell recente")
        self.assertNotIn("scan target", catalog)

    def test_history_search_entries_deduplicate_session_prompts(self):
        shell = AutomationProjectShell()
        shell.conversation_history = [
            {"user": "scan", "agent": "ok"},
            {"user": "enum", "agent": "ok"},
            {"user": "scan", "agent": "ok"},
        ]

        self.assertEqual(shell._history_search_entries("session"), ["scan", "enum"])

    def test_prompt_references_are_expanded_before_agent_call(self):
        shell = AutomationProjectShell()
        shell.findings_store.add(Finding(FindingType.PORT, "22", "nmap", "high"))
        event_stream = iter(
            [
                {"type": "thinking_start"},
                {"type": "thinking_end"},
                {"type": "final_answer", "content": "Le port 22 est en contexte."},
            ]
        )

        with patch.object(shell.agent_loop, "run", return_value=event_stream) as run_mock:
            shell.handle_unresolved_text("resume @findings")

        self.assertIn("REFERENCES UTILISATEUR", run_mock.call_args.args[0])
        self.assertIn("22", run_mock.call_args.args[0])
        self.assertEqual(shell.conversation_history[-1]["user"], "resume @findings")

    def test_file_prompt_reference_reads_workspace_file(self):
        shell = AutomationProjectShell()
        with TemporaryDirectory() as tmpdir:
            shell.workspace = Path(tmpdir)
            shell.tool_executor.workspace = shell.workspace
            (shell.workspace / "note.txt").write_text("indice smb", encoding="utf-8")
            event_stream = iter(
                [
                    {"type": "thinking_start"},
                    {"type": "thinking_end"},
                    {"type": "final_answer", "content": "Note prise en compte."},
                ]
            )

            with patch.object(shell.agent_loop, "run", return_value=event_stream) as run_mock:
                shell.handle_unresolved_text("analyse @note.txt")

        self.assertIn("[@note.txt]", run_mock.call_args.args[0])
        self.assertIn("indice smb", run_mock.call_args.args[0])

    def test_model_command_rejects_unknown_model_name(self):
        shell = AutomationProjectShell()
        original_model = shell.gemini_runtime.model

        shell.dispatch_command("/model", ["not-a-model"])

        self.assertEqual(shell.gemini_runtime.model, original_model)
        self.assertEqual(shell.panel.title, "Modele LLM")
        self.assertTrue(any("Modele inconnu" in line for line in shell.panel.lines))

    def test_case_off_deactivates_active_case(self):
        shell = AutomationProjectShell()
        shell.active_case = shell.knowledge_store.get_case("basic_penetration")

        shell.dispatch_command("/case", ["off"])

        self.assertIsNone(shell.active_case)
        self.assertEqual(shell.panel.title, "Cas")
        self.assertTrue(any("Aucun cas actif" in line for line in shell.panel.lines))

    def test_phase_exploit_requires_scope(self):
        shell = AutomationProjectShell()

        shell.dispatch_command("/phase", ["exploit"])

        self.assertEqual(shell.panel.title, "Phase")
        self.assertEqual(shell.panel.tone, "warn")
        self.assertTrue(any("/scope" in line for line in shell.panel.lines))

    def test_phase_exploit_requires_confirmation(self):
        shell = AutomationProjectShell()
        shell.tool_executor.set_scope(["10.10.10.0/24"])

        shell.dispatch_command("/phase", ["exploit"])

        self.assertEqual(shell.panel.title, "Phase")
        self.assertEqual(shell.panel.tone, "warn")
        self.assertTrue(any("confirm" in line for line in shell.panel.lines))

    def test_phase_exploit_confirm_allows_transition(self):
        shell = AutomationProjectShell()
        shell.tool_executor.set_scope(["10.10.10.0/24"])

        shell.dispatch_command("/phase", ["exploit", "confirm"])

        self.assertEqual(shell.engagement.phase.value, "exploitation")
        self.assertEqual(shell.panel.tone, "success")

    def test_phase_exploit_creates_checkpoint_before_transition(self):
        shell = AutomationProjectShell()
        with TemporaryDirectory() as tmpdir:
            shell.workspace = Path(tmpdir)
            shell.tool_executor.workspace = shell.workspace
            shell._findings_state_path = shell.workspace / "findings_state.json"
            shell.tool_executor.set_scope(["10.10.10.0/24"])
            shell.findings_store.add(Finding(FindingType.PORT, "22", "nmap"))

            shell.dispatch_command("/phase", ["exploit", "confirm"])
            checkpoint = shell._load_last_checkpoint_payload()
            findings_snapshot_exists = Path(checkpoint["findings_path"]).exists()

        self.assertEqual(shell.engagement.phase.value, "exploitation")
        self.assertIsNotNone(checkpoint)
        self.assertEqual(checkpoint["trigger"], "phase:exploitation")
        self.assertEqual(checkpoint["session"]["phase"], "recon")
        self.assertTrue(findings_snapshot_exists)
        self.assertTrue(any("Checkpoint:" in line for line in shell.panel.lines))

    def test_risky_command_start_creates_checkpoint_and_job_detail(self):
        shell = AutomationProjectShell()
        with TemporaryDirectory() as tmpdir:
            shell.workspace = Path(tmpdir)
            shell.tool_executor.workspace = shell.workspace
            shell._findings_state_path = shell.workspace / "findings_state.json"

            job_id = shell._start_tool_job(
                {
                    "type": "tool_start",
                    "name": "execute_command",
                    "args": {"command": "hydra -l admin -P words.txt 10.10.10.10 ssh"},
                }
            )
            checkpoint = shell._load_last_checkpoint_payload()

        job = shell.jobs.get(job_id)
        self.assertIsNotNone(checkpoint)
        self.assertEqual(checkpoint["trigger"], "tool:execute_command")
        self.assertTrue(any("checkpoint:" in detail for detail in job.details))

    def test_rewind_restores_last_checkpoint_context_and_findings(self):
        shell = AutomationProjectShell()
        with TemporaryDirectory() as tmpdir:
            shell.workspace = Path(tmpdir)
            shell.tool_executor.workspace = shell.workspace
            shell._findings_state_path = shell.workspace / "findings_state.json"
            shell.tool_executor.set_scope(["10.10.10.0/24"])
            shell.findings_store.add(Finding(FindingType.PORT, "22", "nmap"))
            shell._save_checkpoint("avant mutation test", trigger="test")

            shell.engagement.set_phase(parse_phase("exploit"), "mutation test")
            shell.tool_executor.set_scope(["192.0.2.0/24"])
            shell.findings_store.clear()

            shell.dispatch_command("/rewind", [])

        self.assertEqual(shell.panel.title, "Rewind")
        self.assertEqual(shell.panel.tone, "success")
        self.assertEqual(shell.engagement.phase.value, "recon")
        self.assertEqual(shell.tool_executor.authorized_scope, {"10.10.10.0/24"})
        self.assertEqual(shell.findings_store.count, 1)

    def test_workflow_command_lists_local_toml_definitions(self):
        shell = AutomationProjectShell()

        shell.dispatch_command("/workflow", ["list"])

        self.assertEqual(shell.panel.title, "Workflows")
        self.assertTrue(any("recon-web" in line for line in shell.panel.lines))
        self.assertTrue(any("smb-enum" in line for line in shell.panel.lines))

    def test_workflow_requires_scope_before_execution(self):
        shell = AutomationProjectShell()

        with patch.object(shell.tool_executor, "execute_command") as execute_mock:
            shell.dispatch_command("/workflow", ["recon-web"])

        execute_mock.assert_not_called()
        self.assertEqual(shell.panel.title, "Workflow")
        self.assertEqual(shell.panel.tone, "warn")
        self.assertTrue(any("/scope" in line for line in shell.panel.lines))

    def test_workflow_executes_toml_steps_through_tool_executor(self):
        shell = AutomationProjectShell()
        shell.current_target = "10.10.10.10"
        shell.tool_executor.set_scope(["10.10.10.0/24"])

        def fake_execute(command, reason):
            return {
                "command": command,
                "stdout": "ok\n",
                "stderr": "",
                "returncode": 0,
            }

        with patch.object(shell.tool_executor, "execute_command", side_effect=fake_execute) as execute_mock:
            shell.dispatch_command("/workflow", ["smb-enum"])

        self.assertEqual(execute_mock.call_count, 3)
        first_command = execute_mock.call_args_list[0].args[0]
        self.assertIn("nmap", first_command)
        self.assertIn("10.10.10.10", first_command)
        self.assertEqual(shell.panel.title, "Workflow")
        self.assertTrue(any("Enumeration SMB" in line for line in shell.panel.lines))
        self.assertTrue(any("Etat: termine" in line for line in shell.panel.lines))

    def test_successful_reply_is_kept_in_history_and_can_show_more_than_twelve_lines(self):
        shell = AutomationProjectShell()
        response_text = "\n".join(f"ligne {index}" for index in range(1, 16))

        with patch.object(
            shell,
            "_call_gemini",
            return_value=SimpleNamespace(model="gemini-2.5-flash", text=response_text),
        ):
            shell.handle_unresolved_text("donne moi un resultat detaille")

        self.assertEqual(shell.panel.title, "Agent")
        self.assertEqual(len(shell.panel.lines), 15)
        self.assertEqual(shell.conversation_history[-1]["user"], "donne moi un resultat detaille")
        self.assertIn("ligne 15", shell.conversation_history[-1]["agent"])

    def test_shell_exposes_command_tools_in_ask_mode_by_default(self):
        shell = AutomationProjectShell()
        statuses = {entry.label: entry.value for entry in shell.get_status_entries()}

        self.assertIn("pentest", statuses["outils"])

    def test_jobs_command_reports_empty_queue(self):
        shell = AutomationProjectShell()

        shell.dispatch_command("/jobs", [])

        self.assertEqual(shell.panel.title, "Jobs")
        self.assertTrue(any("Aucune tache" in line for line in shell.panel.lines))

    def test_learn_command_reports_recent_attempts(self):
        shell = AutomationProjectShell()
        with TemporaryDirectory() as tmpdir:
            shell.learning_journal = LearningJournal(Path(tmpdir) / "attempt_journal.jsonl")
            shell.learning_journal.append_attempt(
                tool_name="scan_target",
                arguments={"target": "10.10.10.10"},
                status="success",
                target="10.10.10.10",
                phase="recon",
                result_summary="22/tcp open ssh",
                findings=["22", "22/ssh"],
            )

            shell.dispatch_command("/learn", [])

        self.assertEqual(shell.panel.title, "Apprentissage")
        self.assertTrue(any("scan_target" in line for line in shell.panel.lines))
        self.assertTrue(any("22" in line for line in shell.panel.lines))

    def test_tool_permission_selector_maps_session_choice(self):
        shell = AutomationProjectShell()

        with patch.object(shell, "_choose_permission_option", return_value="session"):
            with patch.object(shell, "save_state") as save_mock:
                decision = shell._request_tool_permission(
                    tool_name="execute_command",
                    details="df -h",
                    reason="Afficher le stockage",
                )

        self.assertEqual(decision, "session")
        self.assertEqual(shell.command_permission_mode, "session")
        self.assertEqual(shell.tool_executor.command_permission_mode, "session")
        save_mock.assert_called_once()

    def test_tool_permission_selector_uses_harmonized_inline_choice(self):
        shell = AutomationProjectShell()
        options = [
            ("once", "Autoriser une fois"),
            ("session", "Autoriser pour la session"),
            ("deny", "Refuser"),
        ]

        with patch.object(sys.stdin, "isatty", return_value=True):
            with patch.object(sys.stdout, "isatty", return_value=True):
                with patch.object(shell, "_run_inline_choice", return_value="once") as inline_mock:
                    selection = shell._choose_permission_option(
                        "Autorisation requise",
                        [("outil", "execute_command"), ("raison", "scan")],
                        options,
                        default="once",
                    )

        self.assertEqual(selection, "once")
        inline_mock.assert_called_once()
        args, kwargs = inline_mock.call_args
        self.assertEqual(args[0], "Autorisation requise")
        self.assertEqual(args[1], ["outil   : execute_command", "raison  : scan"])
        self.assertEqual(args[2], options)
        self.assertEqual(kwargs["default"], "once")
        self.assertEqual(kwargs["select_character"], "›")
        self.assertIs(kwargs["footer_control"].__self__, shell)
        self.assertIs(kwargs["footer_control"].__func__, shell._permission_toolbar.__func__)
        self.assertTrue(callable(kwargs["extra_key_bindings"]))

    def test_install_permission_selector_accepts_yes(self):
        shell = AutomationProjectShell()

        with patch.object(sys.stdin, "isatty", return_value=True):
            with patch.object(sys.stdout, "isatty", return_value=True):
                with patch.object(shell, "_inline_confirm", return_value=True):
                    self.assertTrue(shell._request_install_permission("nmap", "sudo apt-get install -y nmap"))

    def test_state_payload_does_not_persist_active_case(self):
        shell = AutomationProjectShell()
        shell.active_case = shell.knowledge_store.get_case("basic_penetration")

        payload = shell.build_state_payload()

        self.assertNotIn("active_case_slug", payload)

    def test_session_resume_restores_case_and_findings(self):
        shell = AutomationProjectShell()
        with TemporaryDirectory() as tmpdir:
            shell.workspace = Path(tmpdir)
            shell.workspace.mkdir(parents=True, exist_ok=True)

            findings_store = FindingsStore()
            findings_store.add(Finding(
                finding_type=FindingType.CREDENTIAL,
                value="ssh://root:toor (port 22)",
                source_tool="hydra",
                confidence="high",
                severity="critical",
                target_ref="10.10.10.10",
                attributes={"service": "ssh", "username": "root", "password": "toor", "port": "22"},
            ))
            findings_store.save_state(shell.workspace / "findings_state.json")

            save_session(
                shell.workspace,
                SessionState(
                    session_id="resume-me",
                    target_summary="10.10.10.10",
                    phase="enumeration",
                    tools_used=["nmap"],
                    targets=[{
                        "raw": "10.10.10.10",
                        "address": "10.10.10.10",
                        "target_type": "ip",
                    }],
                    scope=["10.10.10.0/24"],
                    active_case_slug="basic_penetration",
                    findings_count=1,
                ),
            )

            shell.dispatch_command("/session", ["resume", "resume-me"])

        self.assertEqual(shell.panel.title, "Session restauree")
        self.assertEqual(shell.engagement.phase.value, "enumeration")
        self.assertEqual(shell.active_case.slug, "basic_penetration")
        self.assertEqual(shell._active_case_slug, "basic_penetration")
        self.assertEqual(shell.findings_store.count, 1)
        self.assertEqual(shell.tool_executor.findings_store.count, 1)
        self.assertEqual(shell.agent_loop.findings_store.count, 1)
        self.assertEqual(shell.current_target, "10.10.10.10")
        self.assertTrue(any("Cas actif: basic_penetration" in line for line in shell.panel.lines))

    def test_session_resume_without_id_uses_overlay_and_restores(self):
        shell = AutomationProjectShell()
        with TemporaryDirectory() as tmpdir:
            shell.workspace = Path(tmpdir)
            shell.workspace.mkdir(parents=True, exist_ok=True)
            save_session(
                shell.workspace,
                SessionState(
                    session_id="resume-me",
                    target_summary="10.10.10.10",
                    phase="enumeration",
                    tools_used=["nmap"],
                    scope=["10.10.10.0/24"],
                ),
            )

            with patch.object(shell, "_can_use_transient_page", return_value=True):
                with patch.object(shell, "_run_session_resume_overlay", return_value="resume-me") as overlay_mock:
                    with patch.object(shell, "render_panel_state") as render_mock:
                        shell.dispatch_command("/session", ["resume"])

        overlay_mock.assert_called_once_with()
        render_mock.assert_called_once_with()
        self.assertEqual(shell.panel.title, "Session restauree")
        self.assertEqual(shell.engagement.phase.value, "enumeration")
        self.assertTrue(any("ID: resume-me" in line for line in shell.panel.lines))

    def test_resume_command_without_id_uses_overlay_and_restores(self):
        shell = AutomationProjectShell()
        with TemporaryDirectory() as tmpdir:
            shell.workspace = Path(tmpdir)
            shell.workspace.mkdir(parents=True, exist_ok=True)
            save_session(
                shell.workspace,
                SessionState(
                    session_id="resume-me",
                    target_summary="10.10.10.10",
                    phase="enumeration",
                    tools_used=["nmap"],
                    scope=["10.10.10.0/24"],
                ),
            )

            with patch.object(shell, "_can_use_transient_page", return_value=True):
                with patch.object(shell, "_run_session_resume_overlay", return_value="resume-me") as overlay_mock:
                    with patch.object(shell, "render_panel_state") as render_mock:
                        keep_running = shell.dispatch_command("/resume", [])

        self.assertTrue(keep_running)
        overlay_mock.assert_called_once_with()
        render_mock.assert_called_once_with()
        self.assertEqual(shell.panel.title, "Session restauree")
        self.assertEqual(shell.engagement.phase.value, "enumeration")
        self.assertTrue(any("ID: resume-me" in line for line in shell.panel.lines))

    def test_resume_command_ctrl_c_result_quits_cleanly(self):
        shell = AutomationProjectShell()

        with patch.object(shell, "_can_use_transient_page", return_value=True):
            with patch.object(shell, "_run_session_resume_overlay", return_value="__quit__"):
                with patch.object(shell, "_print_session_summary") as summary_mock:
                    keep_running = shell.dispatch_command("/resume", [])

        self.assertFalse(keep_running)
        summary_mock.assert_called_once_with()

    def test_resume_last_restores_most_recent_updated_session(self):
        shell = AutomationProjectShell()
        with TemporaryDirectory() as tmpdir:
            shell.workspace = Path(tmpdir)
            sessions_dir = shell.workspace / "sessions"
            sessions_dir.mkdir(parents=True, exist_ok=True)

            def write_session(session_id, last_active, phase):
                payload = {
                    "session_id": session_id,
                    "target_summary": "",
                    "phase": phase,
                    "tools_used": [],
                    "targets": [],
                    "scope": [],
                    "active_case_slug": "",
                    "conversation_summary": session_id,
                    "findings_count": 0,
                    "started_at": "2026-05-07T08:00:00",
                    "last_active": last_active,
                }
                path = sessions_dir / f"session_{session_id}.json"
                path.write_text(json.dumps(payload), encoding="utf-8")

            write_session("older", "2026-05-07T09:00:00", "recon")
            write_session("newer", "2026-05-07T10:00:00", "enumeration")

            shell.dispatch_command("/resume", ["--last"])

        self.assertEqual(shell.panel.title, "Session restauree")
        self.assertTrue(any("ID: newer" in line for line in shell.panel.lines))
        self.assertEqual(shell.engagement.phase.value, "enumeration")

    def test_session_resume_without_id_non_tty_keeps_usage(self):
        shell = AutomationProjectShell()

        with patch.object(shell, "_can_use_transient_page", return_value=False):
            shell.dispatch_command("/resume", [])

        self.assertEqual(shell.panel.title, "Resume")
        self.assertTrue(any("Usage: /resume [id|--last]" in line for line in shell.panel.lines))

    def test_session_resume_rows_sort_and_filter(self):
        shell = AutomationProjectShell()
        with TemporaryDirectory() as tmpdir:
            shell.workspace = Path(tmpdir)
            sessions_dir = shell.workspace / "sessions"
            sessions_dir.mkdir(parents=True, exist_ok=True)

            def write_session(session_id, started_at, last_active, summary):
                payload = {
                    "session_id": session_id,
                    "target_summary": "",
                    "phase": "recon",
                    "tools_used": [],
                    "targets": [],
                    "scope": [],
                    "active_case_slug": "",
                    "conversation_summary": summary,
                    "findings_count": 0,
                    "started_at": started_at,
                    "last_active": last_active,
                }
                path = sessions_dir / f"session_{session_id}.json"
                path.write_text(json.dumps(payload), encoding="utf-8")

            write_session("created-newer", "2026-05-07T08:00:00", "2026-05-07T09:00:00", "web enum")
            write_session("updated-newer", "2026-05-06T08:00:00", "2026-05-07T10:00:00", "ssh follow-up")

            updated_rows = shell._session_resume_rows("", "updated")
            created_rows = shell._session_resume_rows("", "created")
            filtered_rows = shell._session_resume_rows("web", "updated")

        self.assertEqual(updated_rows[0]["summary"].session_id, "updated-newer")
        self.assertEqual(created_rows[0]["summary"].session_id, "created-newer")
        self.assertEqual(len(filtered_rows), 1)
        self.assertEqual(filtered_rows[0]["summary"].session_id, "created-newer")
        self.assertEqual(filtered_rows[0]["conversation"], "web enum")
        self.assertIn("state", filtered_rows[0])

    def test_session_resume_overlay_uses_same_page_eraseable_application(self):
        shell = AutomationProjectShell()
        captured = []

        class FakeApplication:
            def __init__(self, **kwargs):
                captured.append(kwargs)

            def run(self):
                return None

        with patch("app.project_shell.Application", FakeApplication):
            result = shell._run_session_resume_overlay()

        self.assertIsNone(result)
        self.assertTrue(captured)
        self.assertFalse(captured[0]["full_screen"])
        self.assertTrue(captured[0]["erase_when_done"])

    def test_resume_toolbar_matches_codex_picker_controls(self):
        shell = AutomationProjectShell()

        toolbar = str(shell._session_resume_toolbar())

        self.assertIn("←/→ sort", toolbar)
        self.assertIn("Ctrl+E details", toolbar)
        self.assertIn("Esc", toolbar)

    def test_initialize_interactive_enables_live_stream(self):
        shell = AutomationProjectShell()

        shell.initialize_interactive()

        self.assertTrue(shell.live_agent_stream)

    def test_footer_context_uses_model_and_current_directory(self):
        shell = AutomationProjectShell()

        footer = shell.get_footer_context()

        self.assertIn("gemini-2.5-flash", footer)
        self.assertIn("automation_project", footer)

    def test_footer_toolbar_uses_plain_context_without_badge_background(self):
        shell = AutomationProjectShell()

        toolbar = str(shell._toolbar())

        self.assertIn("gemini-2.5-flash", toolbar)
        self.assertIn("phase", toolbar)
        self.assertIn("Reconnaissance", toolbar)
        self.assertIn("toolbar.value.success", toolbar)
        self.assertNotIn("<style", toolbar)
        self.assertNotIn("bg=", toolbar)
        styles = shell.palette.prompt_style_dict()
        self.assertNotIn("bg:", styles["bottom-toolbar"])
        self.assertIn("noreverse", styles["bottom-toolbar"])
        self.assertIn("noinherit", styles["bottom-toolbar"])
        self.assertNotIn("bg:", styles["toolbar.label"])
        self.assertNotIn("bg:", styles["toolbar.meta"])
        self.assertNotIn("bg:", styles["toolbar.sep"])
        self.assertIn("noinherit", styles["toolbar.label"])
        self.assertIn("noinherit", styles["toolbar.meta"])
        self.assertIn("noinherit", styles["toolbar.sep"])
        if shell.palette.no_color:
            self.assertNotIn("", styles)
            self.assertEqual(styles["input-selection"], "noinherit noreverse")
        else:
            self.assertNotIn("bg:", styles[""])
            self.assertNotIn("bg:", styles["input-selection"])
            self.assertIn("noinherit", styles["input-selection"])
            self.assertIn("noreverse", styles["input-selection"])
            self.assertNotIn("bg:", styles["completion-menu"])
            self.assertNotIn("bg:", styles["completion-menu.completion.current"])
            self.assertNotIn("bg:", styles["completion-menu.meta.completion.current"])
            self.assertIn(shell.palette.prompt_brand_hex, styles["completion-menu.completion.current"])
            self.assertIn(shell.palette.prompt_brand_hex, styles["completion-menu.meta.completion.current"])
            self.assertIn("noreverse", styles["completion-menu.completion.current"])
            self.assertIn("noreverse", styles["completion-menu.meta.completion.current"])
        if shell.palette.no_color:
            self.assertNotIn("fg:", styles["toolbar.value.success"])
        else:
            self.assertIn(shell.palette.success_badge_bg_hex, styles["toolbar.value.success"])
        self.assertNotIn("bg:", styles["toolbar.value.success"])
        if shell.palette.no_color:
            self.assertEqual(styles["selected-option"], "bold")
        else:
            self.assertNotIn("bg:", styles["selected-option"])
            self.assertIn(shell.palette.prompt_brand_hex, styles["selected-option"])
            self.assertIn("bold", styles["selected-option"])

    def test_theme_command_switches_palette_for_session(self):
        shell = AutomationProjectShell()

        shell.dispatch_command("/theme", ["graphite"])

        self.assertEqual(shell.theme_name, "graphite")
        self.assertEqual(shell.palette.theme_name, "graphite")
        self.assertEqual(shell.panel.title, "Theme")
        self.assertTrue(any("Theme actif: graphite" in line for line in shell.panel.lines))

    def test_theme_command_redraws_current_screen_when_interactive(self):
        shell = AutomationProjectShell()

        with (
            patch.object(shell, "_can_use_transient_page", return_value=True),
            patch.object(shell, "_clear_transient_screen") as clear_mock,
            patch.object(shell, "render_shell_header") as header_mock,
            patch.object(shell, "render_panel_state") as panel_mock,
        ):
            shell.dispatch_command("/theme", ["graphite"])

        clear_mock.assert_called_once_with()
        header_mock.assert_called_once_with()
        panel_mock.assert_called_once_with()
        self.assertTrue(shell._stream_rendered_panel)
        self.assertTrue(shell._suppress_transient_result_once)

    def test_theme_menu_uses_inline_dropdown_without_page(self):
        shell = AutomationProjectShell()
        previous_panel = shell.panel
        initial_theme = shell.theme_name

        with patch.object(shell, "_can_use_transient_page", return_value=True):
            with patch.object(shell, "clear_screen") as clear_mock:
                with patch.object(shell, "render_shell_header") as header_mock:
                    with patch.object(shell, "render_panel_state") as panel_mock:
                        with patch.object(shell, "_run_inline_choice", return_value="accessible") as inline_mock:
                            shell.dispatch_command("/theme", [])

        self.assertIs(shell.panel, previous_panel)
        self.assertEqual(shell.theme_name, "accessible")
        inline_mock.assert_called_once()
        args, kwargs = inline_mock.call_args
        self.assertEqual(args[0], "Choisir le theme")
        self.assertEqual([value for value, _label in args[2]], ["dark", "graphite", "accessible", "ansi"])
        self.assertEqual(kwargs["default"], initial_theme)
        clear_mock.assert_called_once_with()
        header_mock.assert_called_once_with()
        panel_mock.assert_called_once_with()
        self.assertTrue(shell._stream_rendered_panel)

    def test_project_palettes_expose_dark_graphite_accessible_ansi_only(self):
        forbidden_values = {"#fdc910", "#38bdf8", "#1d4ed8", "#2563eb"}

        self.assertEqual(set(THEME_PALETTES), {"dark", "graphite", "accessible", "ansi"})
        for theme_name, palette in THEME_PALETTES.items():
            self.assertEqual(palette.theme_name, theme_name)
            self.assertNotEqual(palette.background_hex, "#ffffff")
            self.assertNotEqual(palette.user_message_bg_hex, palette.input_bg_hex)
            palette_values = {value for value in vars(palette).values() if isinstance(value, str)}
            self.assertTrue(forbidden_values.isdisjoint(palette_values))

    def test_retired_light_and_mono_themes_are_rejected(self):
        shell = AutomationProjectShell()

        for retired_theme in ("light", "mono", "claude", "codex"):
            shell.dispatch_command("/theme", [retired_theme])

            self.assertEqual(shell.theme_name, "dark")
            self.assertTrue(any(f"Theme inconnu: {retired_theme}" in line for line in shell.panel.lines))
            self.assertTrue(any("dark, graphite, accessible, ansi" in line for line in shell.panel.lines))

    def test_no_color_keeps_selected_theme_but_strips_color(self):
        with patch.dict("os.environ", {"NO_COLOR": "1"}):
            shell = AutomationProjectShell()

        self.assertEqual(shell.theme_name, "dark")
        self.assertEqual(shell.palette.theme_name, "dark")
        self.assertTrue(shell.palette.no_color)
        self.assertEqual(shell.palette.accent_ansi, "")
        self.assertNotIn("fg:", shell.palette.prompt_style_dict()["toolbar.value.success"])

    def test_toolbar_truncates_to_terminal_width(self):
        shell = AutomationProjectShell()
        shell.current_target = "very-long-target-name.internal.example"
        shell.findings_store.add(Finding(FindingType.PORT, "10.10.10.10:443", "nmap"))

        with patch("shutil.get_terminal_size", return_value=SimpleNamespace(columns=40, lines=24)):
            toolbar = str(shell._toolbar())

        self.assertIn("toolbar.label", toolbar)
        self.assertIn("...", toolbar)
        self.assertNotIn("very-long-target-name.internal.example", toolbar)

    def test_ops_profile_toolbar_keeps_target_phase_and_findings_visible(self):
        shell = AutomationProjectShell()
        shell.ux_profile = "ops"

        toolbar = str(shell._toolbar())

        self.assertIn("phase", toolbar)
        self.assertIn("cible", toolbar)
        self.assertIn("findings", toolbar)
        self.assertIn("aucune", toolbar)

    def test_debug_profile_toolbar_shows_model_tokens_and_logs(self):
        shell = AutomationProjectShell()
        shell.ux_profile = "debug"
        shell.llm_client.last_prompt_chars = 1200
        shell._last_output_log_path = "/tmp/debug.log"

        toolbar = str(shell._toolbar())

        self.assertIn("model", toolbar)
        self.assertIn("tokens", toolbar)
        self.assertIn("~300", toolbar)
        self.assertIn("logs", toolbar)
        self.assertIn("debug.log", toolbar)

    def test_custom_statusline_overrides_profile_toolbar_fields(self):
        shell = AutomationProjectShell()
        shell.ux_profile = "quiet"
        shell.statusline_fields = ["model", "target", "scope", "jobs", "context"]
        shell.current_target = "10.10.10.10"
        shell.tool_executor.set_scope(["10.10.10.0/24"])

        with patch("shutil.get_terminal_size", return_value=SimpleNamespace(columns=160, lines=24)):
            toolbar = str(shell._toolbar())

        self.assertIn("model", toolbar)
        self.assertIn("cible", toolbar)
        self.assertIn("scope", toolbar)
        self.assertIn("jobs", toolbar)
        self.assertIn("context", toolbar)
        self.assertNotIn(">quiet<", toolbar)

    def test_reasoning_command_switches_display_mode(self):
        shell = AutomationProjectShell()

        shell.dispatch_command("/reasoning", ["full"])

        self.assertEqual(shell.reasoning_mode, "full")
        self.assertEqual(shell.panel.title, "Raisonnement")
        self.assertTrue(any("Mode actif: full" in line for line in shell.panel.lines))

    def test_reasoning_menu_uses_inline_dropdown_without_page(self):
        shell = AutomationProjectShell()
        previous_panel = shell.panel

        with patch.object(shell, "_can_use_transient_page", return_value=True):
            with patch.object(shell, "clear_screen") as clear_mock:
                with patch.object(shell, "render_shell_header") as header_mock:
                    with patch.object(shell, "render_panel_state") as panel_mock:
                        with patch.object(shell, "_run_inline_choice", return_value="full") as inline_mock:
                            shell.dispatch_command("/reasoning", [])

        self.assertIs(shell.panel, previous_panel)
        self.assertEqual(shell.reasoning_mode, "full")
        inline_mock.assert_called_once()
        args, kwargs = inline_mock.call_args
        self.assertEqual(args[0], "Select reasoning display")
        self.assertEqual([value for value, _label in args[2]], ["hidden", "summary", "full"])
        self.assertEqual(kwargs["default"], "summary")
        clear_mock.assert_not_called()
        header_mock.assert_not_called()
        panel_mock.assert_not_called()

    def test_reasoning_command_rejects_unknown_mode(self):
        shell = AutomationProjectShell()

        shell.dispatch_command("/reasoning", ["verbose"])

        self.assertEqual(shell.reasoning_mode, "summary")
        self.assertEqual(shell.panel.title, "Raisonnement")
        self.assertTrue(any("Modes valides" in line for line in shell.panel.lines))

    def test_local_system_request_uses_local_agent_context(self):
        shell = AutomationProjectShell()
        event_stream = iter(
            [
                {"type": "thinking_start"},
                {"type": "thinking_end"},
                {"type": "final_answer", "content": "Je peux lancer apt-get update."},
            ]
        )

        with patch.object(shell.agent_loop, "run", return_value=event_stream) as run_mock:
            shell.handle_unresolved_text("fais une mise a jour de notre systeme actuel")

        self.assertEqual(run_mock.call_args.args[0], "fais une mise a jour de notre systeme actuel")
        self.assertIn("Contexte local", run_mock.call_args.args[1])
        self.assertIn("N'exige pas d'IP cible", run_mock.call_args.args[1])

    def test_generic_request_does_not_force_active_case_context(self):
        shell = AutomationProjectShell()
        shell.active_case = shell.knowledge_store.get_case("basic_penetration")
        event_stream = iter(
            [
                {"type": "thinking_start"},
                {"type": "thinking_end"},
                {"type": "final_answer", "content": "Je peux aider sur Python."},
            ]
        )

        with patch.object(shell.agent_loop, "run", return_value=event_stream) as run_mock:
            shell.handle_unresolved_text("aide moi a ecrire un script python")

        self.assertIn("Contexte general", run_mock.call_args.args[1])
        self.assertIn("ne doit pas cadrer cette demande", run_mock.call_args.args[1])
        self.assertNotIn("Cas actif:", run_mock.call_args.args[1])

    def test_case_relevant_request_uses_active_case_context(self):
        shell = AutomationProjectShell()
        shell.active_case = shell.knowledge_store.get_case("basic_penetration")
        event_stream = iter(
            [
                {"type": "thinking_start"},
                {"type": "thinking_end"},
                {"type": "final_answer", "content": "Commence par un scan."},
            ]
        )

        with patch.object(shell.agent_loop, "run", return_value=event_stream) as run_mock:
            shell.handle_unresolved_text("sur la room basic_penetration, que scanner ?")

        self.assertIn("Contexte cible", run_mock.call_args.args[1])
        self.assertIn("Cas actif:", run_mock.call_args.args[1])

    def test_case_relevant_request_without_active_case_injects_memory_candidates(self):
        shell = AutomationProjectShell()
        event_stream = iter(
            [
                {"type": "thinking_start"},
                {"type": "thinking_end"},
                {"type": "final_answer", "content": "Commence par un scan quick."},
            ]
        )

        with patch.object(shell.agent_loop, "run", return_value=event_stream) as run_mock:
            shell.handle_unresolved_text(
                "Target IP Address 10.129.134.165 Scan the machine, how many ports are open?"
            )

        context = run_mock.call_args.args[1]
        self.assertIn("MEMOIRE CANDIDATE", context)
        self.assertIn("basic_penetration", context)
        self.assertIn("pas des faits valides", context)

    def test_generic_request_does_not_force_case_context_from_current_target_alone(self):
        shell = AutomationProjectShell()
        shell.active_case = shell.knowledge_store.get_case("basic_penetration")
        shell.current_target = "10.10.10.10"
        event_stream = iter(
            [
                {"type": "thinking_start"},
                {"type": "thinking_end"},
                {"type": "final_answer", "content": "Je peux aider sur Python."},
            ]
        )

        with patch.object(shell.agent_loop, "run", return_value=event_stream) as run_mock:
            shell.handle_unresolved_text("explique moi une comprehension de liste en python")

        self.assertIn("Contexte general", run_mock.call_args.args[1])
        self.assertNotIn("Cas actif:", run_mock.call_args.args[1])

    def test_memory_fallback_summarizes_gemini_error(self):
        shell = AutomationProjectShell()

        def fake_call(_prompt):
            shell.last_gemini_error = (
                "429 RESOURCE_EXHAUSTED. {'error': {'code': 429, 'message': 'Quota exceeded'}}"
            )
            return None

        shell._call_gemini = fake_call
        shell.handle_unresolved_text("explique moi un dictionnaire python")

        self.assertTrue(any("quota atteint" in line for line in shell.panel.lines))
        self.assertFalse(any("RESOURCE_EXHAUSTED" in line for line in shell.panel.lines))

    def test_interactive_shell_streams_agent_events_progressively(self):
        shell = AutomationProjectShell()
        shell.live_agent_stream = True
        snapshots = []

        def capture_dashboard():
            snapshots.append(
                {
                    "title": shell.panel.title,
                    "lines": list(shell.panel.lines),
                    "tone": shell.panel.tone,
                }
            )

        event_stream = iter(
            [
                {"type": "thinking_start"},
                {"type": "thinking_end"},
                {"type": "tool_start", "name": "query_knowledge", "args": {"query": "http smb ssh"}},
                {
                    "type": "tool_success",
                    "name": "query_knowledge",
                    "result": {"matches": []},
                },
                {"type": "final_answer", "content": "Passe ensuite a l'enumeration SMB."},
            ]
        )

        with patch.object(shell.agent_loop, "run", return_value=event_stream):
            with patch.object(sys.stdout, "isatty", return_value=True):
                with patch("app.project_shell.ActivitySpinner.start", return_value=None):
                    with patch("app.project_shell.ActivitySpinner.stop", return_value=None):
                        with patch.object(shell, "_render_live_panel_update", side_effect=capture_dashboard):
                            shell.handle_unresolved_text("que faire ensuite ?")

        self.assertEqual(snapshots[0]["lines"], ["→ Consultation de la memoire pertinente..."])
        self.assertIn("• Memoire: http smb ssh", snapshots[1]["lines"])
        self.assertIn("  └ aucun cas analogue trouve", snapshots[2]["lines"])
        self.assertIn("Passe ensuite a l'enumeration SMB.", snapshots[-1]["lines"])
        self.assertEqual(shell.panel.title, "Agent")
        self.assertIn("Passe ensuite a l'enumeration SMB.", shell.conversation_history[-1]["agent"])

    def test_interactive_shell_does_not_render_empty_panel_for_thought_event(self):
        shell = AutomationProjectShell()
        shell.live_agent_stream = True
        snapshots = []

        def capture_dashboard():
            snapshots.append(
                {
                    "title": shell.panel.title,
                    "lines": list(shell.panel.lines),
                    "tone": shell.panel.tone,
                }
            )

        event_stream = iter(
            [
                {"type": "thinking_start"},
                {"type": "thinking_end"},
                {"type": "thought", "content": "je vais commencer par un ping"},
                {"type": "tool_start", "name": "execute_command", "args": {"command": "ping -c 4 8.8.8.8"}},
            ]
        )

        with patch.object(shell.agent_loop, "run", return_value=event_stream):
            with patch.object(sys.stdout, "isatty", return_value=True):
                with patch("app.project_shell.ActivitySpinner.start", return_value=None):
                    with patch("app.project_shell.ActivitySpinner.stop", return_value=None):
                        with patch.object(shell, "_render_live_panel_update", side_effect=capture_dashboard):
                            shell.handle_unresolved_text("verifie la connectivite avec 8.8.8.8")

        self.assertEqual(snapshots[0]["lines"], ["→ Preparation d'une commande locale..."])
        self.assertEqual(snapshots[1]["lines"], ["• Commande: ping -c 4 8.8.8.8"])

    def test_interactive_shell_hides_reasoning_when_mode_hidden(self):
        shell = AutomationProjectShell()
        shell.live_agent_stream = True
        shell.reasoning_mode = "hidden"
        snapshots = []

        def capture_dashboard():
            snapshots.append(
                {
                    "title": shell.panel.title,
                    "lines": list(shell.panel.lines),
                    "tone": shell.panel.tone,
                }
            )

        event_stream = iter(
            [
                {"type": "thinking_start"},
                {"type": "thinking_end"},
                {"type": "thought", "content": "raisonnement brut a ne pas afficher"},
                {"type": "tool_start", "name": "execute_command", "args": {"command": "nmap 10.10.10.10"}},
            ]
        )

        with patch.object(shell.agent_loop, "run", return_value=event_stream):
            with patch.object(sys.stdout, "isatty", return_value=True):
                with patch("app.project_shell.ActivitySpinner.start", return_value=None):
                    with patch("app.project_shell.ActivitySpinner.stop", return_value=None):
                        with patch.object(shell, "_render_live_panel_update", side_effect=capture_dashboard):
                            shell.handle_unresolved_text("scanne la cible")

        self.assertEqual(snapshots[0]["lines"], ["• Commande: nmap 10.10.10.10"])
        self.assertFalse(any("raisonnement brut" in line for snapshot in snapshots for line in snapshot["lines"]))

    def test_interactive_shell_streams_full_reasoning_when_mode_full(self):
        shell = AutomationProjectShell()
        shell.live_agent_stream = True
        shell.reasoning_mode = "full"
        snapshots = []

        def capture_dashboard():
            snapshots.append(
                {
                    "title": shell.panel.title,
                    "lines": list(shell.panel.lines),
                    "tone": shell.panel.tone,
                }
            )

        event_stream = iter(
            [
                {"type": "thinking_start"},
                {"type": "thinking_end"},
                {"type": "thought", "content": "je vais commencer par un scan"},
                {"type": "tool_start", "name": "execute_command", "args": {"command": "nmap 10.10.10.10"}},
            ]
        )

        with patch.object(shell.agent_loop, "run", return_value=event_stream):
            with patch.object(sys.stdout, "isatty", return_value=True):
                with patch("app.project_shell.ActivitySpinner.start", return_value=None):
                    with patch("app.project_shell.ActivitySpinner.stop", return_value=None):
                        with patch.object(shell, "_render_live_panel_update", side_effect=capture_dashboard):
                            shell.handle_unresolved_text("scanne la cible")

        self.assertEqual(snapshots[0]["lines"], ["• je vais commencer par un scan"])
        self.assertEqual(snapshots[1]["lines"], ["• Commande: nmap 10.10.10.10"])

    def test_interactive_shell_streams_command_progress_events(self):
        shell = AutomationProjectShell()
        shell.live_agent_stream = True
        snapshots = []

        def capture_dashboard():
            snapshots.append(
                {
                    "title": shell.panel.title,
                    "lines": list(shell.panel.lines),
                    "tone": shell.panel.tone,
                }
            )

        def event_stream():
            yield {"type": "thinking_start"}
            yield {"type": "thinking_end"}
            yield {"type": "tool_start", "name": "execute_command", "args": {"command": "nmap 10.10.10.10"}}
            shell._handle_tool_progress(
                {
                    "type": "tool_progress",
                    "command": "nmap 10.10.10.10",
                    "stream": "status",
                    "content": "commande toujours en cours... 5s",
                    "ephemeral": True,
                }
            )
            yield {
                "type": "tool_success",
                "name": "execute_command",
                "result": {
                    "command": "nmap 10.10.10.10",
                    "stdout": "22/tcp open ssh",
                    "stderr": "",
                    "returncode": 0,
                },
            }
            yield {"type": "final_answer", "content": "Le scan est termine."}

        with patch.object(shell.agent_loop, "run", return_value=event_stream()):
            with patch.object(sys.stdout, "isatty", return_value=True):
                with patch("app.project_shell.ActivitySpinner.start", return_value=None):
                    with patch("app.project_shell.ActivitySpinner.stop", return_value=None):
                        with patch.object(shell, "_render_live_panel_update", side_effect=capture_dashboard):
                            shell.handle_unresolved_text("scanne cette cible")

        self.assertTrue(
            any("  ├ commande toujours en cours... 5s" in line for snap in snapshots for line in snap["lines"])
        )
        self.assertTrue(any("Le scan est termine." in line for line in shell.panel.lines))
        self.assertEqual(shell.jobs.active_count, 0)
        self.assertEqual(shell.jobs.recent()[0].status, "success")
        self.assertTrue(any("nmap 10.10.10.10" in job.title for job in shell.jobs.recent()))

    def test_shell_preserves_structured_progress_metadata(self):
        shell = AutomationProjectShell()
        snapshots = []
        shell._live_stream_state = {
            "events": [
                {"type": "tool_start", "name": "execute_command", "args": {"command": "nmap 10.10.10.10"}},
            ],
            "stream_progress": True,
            "last_snapshot": None,
        }

        def capture_dashboard():
            snapshots.append(list(shell.panel.lines))

        with patch.object(shell, "_render_live_panel_update", side_effect=capture_dashboard):
            shell._handle_tool_progress(
                {
                    "type": "tool_progress",
                    "command": "nmap 10.10.10.10",
                    "stream": "status",
                    "content": "nmap | Connect Scan | 43.0% | ecoule 12s",
                    "tool": "nmap",
                    "progress_kind": "activity",
                    "phase": "Connect Scan",
                    "percent": "43.0%",
                    "elapsed_label": "12s",
                    "ephemeral": True,
                }
            )

        self.assertTrue(any("nmap | Connect Scan | 43.0% | ecoule 12s" in line for line in snapshots[-1]))
        self.assertEqual(shell._live_stream_state["events"][-1]["progress_kind"], "activity")

    def test_quiet_profile_suppresses_activity_progress_but_keeps_findings(self):
        shell = AutomationProjectShell()
        shell.ux_profile = "quiet"
        snapshots = []
        shell._live_stream_state = {
            "events": [
                {"type": "tool_start", "name": "execute_command", "args": {"command": "nmap 10.10.10.10"}},
            ],
            "stream_progress": True,
            "last_snapshot": None,
        }

        def capture_dashboard():
            snapshots.append(list(shell.panel.lines))

        with patch.object(shell, "_render_live_panel_update", side_effect=capture_dashboard):
            shell._handle_tool_progress(
                {
                    "type": "tool_progress",
                    "command": "nmap 10.10.10.10",
                    "stream": "status",
                    "content": "nmap | Connect Scan | 43.0% | ecoule 12s",
                    "tool": "nmap",
                    "progress_kind": "activity",
                    "phase": "Connect Scan",
                    "percent": "43.0%",
                    "elapsed_label": "12s",
                    "ephemeral": True,
                }
            )
            shell._handle_tool_progress(
                {
                    "type": "tool_progress",
                    "command": "nmap 10.10.10.10",
                    "stream": "status",
                    "content": "nmap | port ouvert detecte: 22/tcp open ssh",
                    "tool": "nmap",
                    "progress_kind": "finding",
                    "detail": "22/tcp open ssh",
                }
            )

        flat_lines = [line for snapshot in snapshots for line in snapshot]
        self.assertFalse(any("43.0%" in line for line in flat_lines))
        self.assertTrue(any("22/tcp open ssh" in line for line in flat_lines))
        self.assertEqual(shell._live_stream_state["events"][-1]["progress_kind"], "finding")

    def test_high_level_scan_tool_creates_visible_job(self):
        shell = AutomationProjectShell()
        shell.live_agent_stream = True

        def event_stream():
            yield {"type": "thinking_start"}
            yield {"type": "thinking_end"}
            yield {
                "type": "tool_start",
                "name": "scan_target",
                "args": {"target": "10.10.10.10", "mode": "quick"},
            }
            shell._handle_tool_progress(
                {
                    "type": "tool_progress",
                    "command": "nmap --top-ports 1000 10.10.10.10",
                    "stream": "status",
                    "content": "nmap | Connect Scan | 50.0% | ecoule 10s",
                    "ephemeral": True,
                }
            )
            yield {
                "type": "tool_success",
                "name": "scan_target",
                "result": {
                    "command": "nmap --top-ports 1000 10.10.10.10",
                    "stdout": "22/tcp open ssh",
                    "stderr": "",
                    "returncode": 0,
                    "log_path": "/tmp/nmap.log",
                },
            }
            yield {"type": "final_answer", "content": "Scan termine."}

        with patch.object(shell.agent_loop, "run", return_value=event_stream()):
            with patch.object(sys.stdout, "isatty", return_value=True):
                with patch("app.project_shell.ActivitySpinner.start", return_value=None):
                    with patch("app.project_shell.ActivitySpinner.stop", return_value=None):
                        with patch.object(shell, "_render_live_panel_update", return_value=None):
                            shell.handle_unresolved_text("scanne 10.10.10.10")

        self.assertEqual(shell.jobs.active_count, 0)
        job = shell.jobs.recent()[0]
        self.assertEqual(job.status, "success")
        self.assertIn("scan 10.10.10.10", job.title)
        self.assertIn("log:", job.result)

    def test_missing_tool_creates_pending_install_request(self):
        shell = AutomationProjectShell()
        event_stream = iter(
            [
                {"type": "thinking_start"},
                {"type": "thinking_end"},
                {
                    "type": "tool_missing",
                    "name": "execute_command",
                    "executable": "nmap",
                    "arguments": {"command": "nmap -sC -sV 8.8.8.8"},
                    "message": "L'outil nmap est requis mais non installe sur cette machine. Autorisez-vous son installation ?",
                },
                {
                    "type": "final_answer",
                    "content": "L'outil nmap est requis mais non installe sur cette machine. Autorisez-vous son installation ?",
                },
            ]
        )

        with patch.object(shell.agent_loop, "run", return_value=event_stream):
            shell.handle_unresolved_text("scan 8.8.8.8")

        self.assertEqual(shell.pending_tool_install["executable"], "nmap")
        self.assertEqual(
            shell.pending_tool_install["arguments"]["command"],
            "nmap -sC -sV 8.8.8.8",
        )
        self.assertEqual(shell.jobs.active_count, 1)
        self.assertTrue(shell.pending_tool_install.get("job_id"))

    def test_pending_install_confirmation_uses_shell_managed_flow(self):
        shell = AutomationProjectShell()
        shell.pending_tool_install = {
            "executable": "nmap",
            "arguments": {"command": "nmap -sC -sV 8.8.8.8"},
        }

        with patch.object(shell.agent_loop, "run", side_effect=AssertionError("agent loop should not run")):
            with patch.object(
                shell.tool_executor,
                "build_install_plan",
                return_value={
                    "manual_command": "sudo apt-get update && sudo apt-get install -y nmap",
                },
            ):
                with patch.object(shell, "_request_install_permission", return_value=True):
                    with patch.object(shell, "_request_interactive_sudo_permission", return_value=False):
                        with patch.object(
                            shell.tool_executor,
                            "install_tool",
                            return_value={
                                "executable": "nmap",
                                "manual_command": "sudo apt-get update && sudo apt-get install -y nmap",
                                "status": "manual_required",
                                "steps": [
                                    {
                                        "command": "/usr/bin/sudo -n /usr/bin/apt-get update",
                                        "stdout": "",
                                        "stderr": "sudo: a password is required",
                                        "returncode": 1,
                                    }
                                ],
                            },
                        ):
                            shell.handle_unresolved_text("oui install le nmap")

        self.assertIsNone(shell.pending_tool_install)
        self.assertEqual(shell.panel.title, "Installation outil")
        self.assertTrue(any("commande manuelle:" in line for line in shell.panel.lines))
        self.assertTrue(any("puis relance: nmap -sC -sV 8.8.8.8" in line for line in shell.panel.lines))

    def test_pending_install_confirmation_stays_sticky_on_unrelated_input(self):
        shell = AutomationProjectShell()
        shell.pending_tool_install = {
            "executable": "nmap",
            "arguments": {"command": "nmap -sC -sV 8.8.8.8"},
        }

        with patch.object(shell, "_ask_agent", side_effect=AssertionError("agent should not run")):
            shell.handle_unresolved_text("sudo apt-get update && sudo apt-get install -y nmap")

        self.assertEqual(shell.pending_tool_install["executable"], "nmap")
        self.assertEqual(shell.panel.title, "Installation outil")
        self.assertTrue(any("Reponds oui" in line for line in shell.panel.lines))

    def test_interactive_sudo_install_retries_original_command_after_success(self):
        shell = AutomationProjectShell()
        shell.pending_tool_install = {
            "name": "execute_command",
            "executable": "nmap",
            "thought": "Je dois scanner la cible.",
            "arguments": {"command": "nmap -sC -sV 8.8.8.8"},
        }

        install_results = [
            {
                "executable": "nmap",
                "manual_command": "sudo apt-get update && sudo apt-get install -y nmap",
                "status": "manual_required",
                "steps": [
                    {
                        "command": "/usr/bin/sudo -n /usr/bin/apt-get update",
                        "stdout": "",
                        "stderr": "sudo: a password is required",
                        "returncode": 1,
                    }
                ],
            },
            {
                "executable": "nmap",
                "manual_command": "sudo apt-get update && sudo apt-get install -y nmap",
                "status": "installed",
                "steps": [
                    {
                        "command": "/usr/bin/sudo /usr/bin/apt-get update",
                        "stdout": "",
                        "stderr": "",
                        "returncode": 0,
                    },
                    {
                        "command": "/usr/bin/sudo /usr/bin/apt-get install -y nmap",
                        "stdout": "",
                        "stderr": "",
                        "returncode": 0,
                    },
                ],
            },
        ]

        with patch.object(shell.agent_loop, "run", side_effect=AssertionError("agent loop should not run")):
            with patch.object(
                shell.tool_executor,
                "build_install_plan",
                return_value={
                    "manual_command": "sudo apt-get update && sudo apt-get install -y nmap",
                },
            ):
                with patch.object(shell, "_request_install_permission", return_value=True):
                    with patch.object(shell, "_request_interactive_sudo_permission", return_value=True):
                        with patch("builtins.print"):
                            with patch.object(shell.tool_executor, "install_tool", side_effect=install_results) as install_mock:
                                with patch.object(
                                    shell.tool_executor,
                                    "execute_command",
                                    return_value={
                                        "command": "nmap -sC -sV 8.8.8.8",
                                        "stdout": "22/tcp open ssh",
                                        "stderr": "",
                                        "returncode": 0,
                                    },
                                ) as retry_mock:
                                    with patch.object(
                                        shell.agent_loop,
                                        "resume_after_external_tool",
                                        return_value=iter(
                                            [
                                                {"type": "thinking_start"},
                                                {"type": "thinking_end"},
                                                {
                                                    "type": "final_answer",
                                                    "content": "22/tcp est ouvert. Passe ensuite a l'enumeration SMB.",
                                                },
                                            ]
                                        ),
                                    ) as resume_mock:
                                        shell.handle_unresolved_text("oui install le nmap")

        self.assertIsNone(shell.pending_tool_install)
        self.assertEqual(install_mock.call_args_list[0].kwargs, {})
        self.assertEqual(install_mock.call_args_list[1].kwargs, {"interactive": True})
        retry_mock.assert_called_once_with(
            "nmap -sC -sV 8.8.8.8",
            "Relance automatique apres installation de l'outil requis.",
        )
        resume_mock.assert_called_once_with(
            shell._build_case_context(),
            result={
                "command": "nmap -sC -sV 8.8.8.8",
                "stdout": "22/tcp open ssh",
                "stderr": "",
                "returncode": 0,
            },
            tool_name="execute_command",
            arguments={"command": "nmap -sC -sV 8.8.8.8"},
            thought="Je dois scanner la cible.",
        )
        self.assertEqual(shell.panel.title, "Agent")
        self.assertTrue(any("enumeration SMB" in line for line in shell.panel.lines))
        self.assertIn("enumeration SMB", shell.conversation_history[-1]["agent"])

    def test_tools_install_command_prepares_single_batch_confirmation(self):
        shell = AutomationProjectShell()

        with patch.object(shell.tool_registry, "refresh"):
            with patch.object(shell.tool_registry, "is_known", return_value=True):
                with patch.object(
                    shell.tool_registry,
                    "is_installed",
                    side_effect=lambda name: name == "nikto",
                ):
                    shell.dispatch_command("/tools", ["install", "nikto", "hydra", "tracerout"])

        self.assertEqual(shell.pending_tool_install["name"], "install_pentest_tools")
        self.assertEqual(shell.pending_tool_install["executables"], ["hydra", "traceroute"])
        self.assertEqual(shell.jobs.active_count, 1)
        self.assertTrue(any("deja installe(s): nikto" in line for line in shell.panel.lines))
        self.assertTrue(any("a installer: hydra, traceroute" in line for line in shell.panel.lines))
        self.assertTrue(any("job: #" in line for line in shell.panel.lines))

        shell.dispatch_command("/jobs", [])

        self.assertTrue(any("pending" in line and "hydra, traceroute" in line for line in shell.panel.lines))

    def test_jobs_cancel_marks_job_cancelled_and_reports_view_hint(self):
        shell = AutomationProjectShell()
        command = "nmap -sV 10.10.10.10"
        with TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "partial.log"
            log_path.write_text("scan partiel\n", encoding="utf-8")
            job = shell.jobs.create(
                "tool",
                command,
                details=[f"commande: {command}"],
                status="running",
                result="execution en cours",
            )
            shell._active_tool_jobs[f"execute_command:{command}"] = job.job_id
            shell._last_active_tool_job_id = job.job_id

            with patch.object(
                shell.tool_executor,
                "cancel_command",
                return_value={"cancelled": True, "log_path": str(log_path)},
            ) as cancel_mock:
                shell.dispatch_command("/jobs", ["cancel", str(job.job_id)])

        cancel_mock.assert_called_once_with(command)
        self.assertEqual(job.status, "cancelled")
        self.assertEqual(shell.jobs.active_count, 0)
        self.assertTrue(any(f"Job {job.job_id} annulé" in line for line in shell.panel.lines))
        self.assertTrue(any(f"/view {job.job_id}" in line for line in shell.panel.lines))
        self.assertTrue(any(str(log_path) in line for line in shell.panel.lines))

    def test_pending_batch_install_decline_marks_job_cancelled(self):
        shell = AutomationProjectShell()
        shell.pending_tool_install = {
            "name": "install_pentest_tools",
            "executable": "hydra",
            "executables": ["hydra", "dirb"],
            "arguments": {"tool_names": ["hydra", "dirb"]},
        }
        shell._attach_install_job(shell.pending_tool_install)

        shell.handle_unresolved_text("non")

        self.assertEqual(shell.jobs.active_count, 0)
        self.assertEqual(shell.jobs.recent()[0].status, "cancelled")

    def test_batch_install_confirmation_uses_batch_executor(self):
        shell = AutomationProjectShell()
        shell.pending_tool_install = {
            "name": "install_pentest_tools",
            "executable": "hydra",
            "executables": ["hydra", "dirb"],
            "arguments": {"tool_names": ["hydra", "dirb"]},
        }

        with patch.object(
            shell.tool_executor,
            "build_install_batch_plan",
            return_value={
                "manual_command": "sudo apt-get -qq -o Dpkg::Use-Pty=0 update && sudo apt-get -qq -o Dpkg::Use-Pty=0 install -y hydra dirb",
            },
        ) as plan_mock:
            with patch.object(shell, "_request_install_permission", return_value=True):
                with patch.object(
                    shell.tool_executor,
                    "install_tools",
                    return_value={
                        "executables": ["hydra", "dirb"],
                        "packages": ["hydra", "dirb"],
                        "manual_command": "sudo apt-get -qq -o Dpkg::Use-Pty=0 update && sudo apt-get -qq -o Dpkg::Use-Pty=0 install -y hydra dirb",
                        "status": "installed",
                        "steps": [
                            {"command": "sudo -n apt-get update", "stdout": "", "stderr": "", "returncode": 0},
                            {"command": "sudo -n apt-get install hydra dirb", "stdout": "", "stderr": "", "returncode": 0},
                        ],
                        "installed": ["hydra", "dirb"],
                        "missing": [],
                    },
                ) as install_mock:
                    shell.handle_unresolved_text("oui")

        plan_mock.assert_called_once_with(["hydra", "dirb"])
        install_mock.assert_called_once_with(["hydra", "dirb"])
        self.assertIsNone(shell.pending_tool_install)
        self.assertEqual(shell.jobs.active_count, 0)
        self.assertEqual(shell.jobs.recent()[0].status, "success")
        self.assertTrue(any("disponible(s): hydra, dirb" in line for line in shell.panel.lines))

    def test_permission_denied_event_creates_retry_request(self):
        shell = AutomationProjectShell()
        event_stream = iter(
            [
                {"type": "thinking_start"},
                {"type": "thinking_end"},
                {
                    "type": "tool_denied",
                    "name": "execute_command",
                    "arguments": {"command": "ping -c 4 8.8.8.8"},
                    "thought": "Je veux verifier la connectivite.",
                    "result": {"error": "Permission refusee: ping -c 4 8.8.8.8"},
                    "message": "Permission refusee pour execute_command. Autorisez-vous une nouvelle tentative ?",
                },
                {
                    "type": "final_answer",
                    "content": "Permission refusee pour execute_command. Autorisez-vous une nouvelle tentative ?",
                },
            ]
        )

        with patch.object(shell.agent_loop, "run", return_value=event_stream):
            shell.handle_unresolved_text("ping 8.8.8.8")

        self.assertEqual(shell.pending_tool_retry["name"], "execute_command")
        self.assertEqual(
            shell.pending_tool_retry["arguments"]["command"],
            "ping -c 4 8.8.8.8",
        )

    def test_admin_required_event_creates_pending_admin_request(self):
        shell = AutomationProjectShell()
        event_stream = iter(
            [
                {"type": "thinking_start"},
                {"type": "thinking_end"},
                {
                    "type": "tool_admin_required",
                    "name": "execute_admin_command",
                    "arguments": {"command": "apt update", "reason": "mettre a jour le systeme local"},
                    "thought": "Je mets a jour le systeme local.",
                    "command": "apt-get update",
                    "manual_command": "sudo apt-get update",
                    "message": "La commande admin apt-get update requiert sudo interactif. Autorisez-vous une nouvelle tentative avec saisie du mot de passe admin ?",
                },
                {
                    "type": "final_answer",
                    "content": "La commande admin apt-get update requiert sudo interactif. Autorisez-vous une nouvelle tentative avec saisie du mot de passe admin ?",
                },
            ]
        )

        with patch.object(shell.agent_loop, "run", return_value=event_stream):
            shell.handle_unresolved_text("fais une mise a jour de notre systeme actuel")

        self.assertEqual(shell.pending_admin_command["name"], "execute_admin_command")
        self.assertEqual(shell.pending_admin_command["arguments"]["command"], "apt update")

    def test_pending_admin_command_runs_interactively_and_resumes_agent(self):
        shell = AutomationProjectShell()
        pending_context = shell._build_agent_context("fais une mise a jour de notre systeme actuel")
        shell.pending_admin_command = {
            "name": "execute_admin_command",
            "thought": "Je mets a jour le systeme local.",
            "arguments": {
                "command": "apt update",
                "reason": "mettre a jour le systeme local",
            },
            "case_context": pending_context,
        }

        with patch.object(shell, "_request_interactive_sudo_permission", return_value=True):
            with patch("builtins.print"):
                with patch.object(
                    shell.tool_executor,
                    "execute_admin_command",
                    return_value={
                        "command": "apt-get update",
                        "stdout": "",
                        "stderr": "",
                        "returncode": 0,
                    },
                ) as admin_mock:
                    with patch.object(
                        shell.agent_loop,
                        "resume_after_external_tool",
                        return_value=iter(
                            [
                                {"type": "thinking_start"},
                                {"type": "thinking_end"},
                                {"type": "final_answer", "content": "La mise a jour APT est terminee."},
                            ]
                        ),
                    ) as resume_mock:
                        shell.handle_unresolved_text("oui")

        self.assertIsNone(shell.pending_admin_command)
        admin_mock.assert_called_once_with(
            "apt update",
            "mettre a jour le systeme local",
            interactive=True,
            skip_permission=True,
        )
        resume_mock.assert_called_once_with(
            pending_context,
            result={
                "command": "apt-get update",
                "stdout": "",
                "stderr": "",
                "returncode": 0,
            },
            tool_name="execute_admin_command",
            arguments={"command": "apt update", "reason": "mettre a jour le systeme local"},
            thought="Je mets a jour le systeme local.",
        )
        self.assertTrue(any("mise a jour APT" in line for line in shell.panel.lines))

    def test_pending_tool_retry_retries_and_resumes_agent(self):
        shell = AutomationProjectShell()
        shell.pending_tool_retry = {
            "name": "execute_command",
            "thought": "Je veux verifier la connectivite.",
            "arguments": {"command": "ping -c 4 8.8.8.8"},
        }

        with patch.object(
            shell.tool_executor,
            "execute_command",
            return_value={
                "command": "ping -c 4 8.8.8.8",
                "stdout": "64 bytes from 8.8.8.8",
                "stderr": "",
                "returncode": 0,
            },
        ) as retry_mock:
            with patch.object(
                shell.agent_loop,
                "resume_after_external_tool",
                return_value=iter(
                    [
                        {"type": "thinking_start"},
                        {"type": "thinking_end"},
                        {"type": "final_answer", "content": "La connectivite est validee. Passe au scan de ports."},
                    ]
                ),
            ) as resume_mock:
                shell.handle_unresolved_text("oui")

        self.assertIsNone(shell.pending_tool_retry)
        retry_mock.assert_called_once_with(
            "ping -c 4 8.8.8.8",
            "Relance automatique apres installation de l'outil requis.",
        )
        resume_mock.assert_called_once_with(
            shell._build_case_context(),
            result={
                "command": "ping -c 4 8.8.8.8",
                "stdout": "64 bytes from 8.8.8.8",
                "stderr": "",
                "returncode": 0,
            },
            tool_name="execute_command",
            arguments={"command": "ping -c 4 8.8.8.8"},
            thought="Je veux verifier la connectivite.",
        )
        self.assertEqual(shell.panel.title, "Agent")
        self.assertTrue(any("scan de ports" in line for line in shell.panel.lines))


    def test_clear_command_resets_display(self):
        shell = AutomationProjectShell()
        shell._header_rendered = True

        with patch.object(shell, "clear_screen") as clear_mock:
            with patch.object(shell, "render_shell_header"):
                result = shell.dispatch_command("/clear", [])

        self.assertTrue(result)
        clear_mock.assert_called_once()
        self.assertEqual(shell.panel.title, "")
        self.assertEqual(shell.panel.lines, [])
        self.assertEqual(shell.panel.variant, "plain")
        self.assertTrue(shell._header_rendered)

    def test_export_command_with_no_findings(self):
        shell = AutomationProjectShell()

        result = shell.dispatch_command("/export", [])

        self.assertTrue(result)
        self.assertEqual(shell.panel.title, "Export")
        self.assertTrue(any("Aucune decouverte" in line for line in shell.panel.lines))
        self.assertEqual(shell.panel.tone, "warn")

    def test_export_command_creates_files(self):
        shell = AutomationProjectShell()
        from app.findings import Finding, FindingType
        shell.findings_store.add(Finding(FindingType.PORT, "22", "nmap", "high"))

        with patch.object(shell.findings_store, "export_json") as json_mock:
            with patch.object(shell.findings_store, "export_markdown") as md_mock:
                result = shell.dispatch_command("/export", [])

        self.assertTrue(result)
        self.assertEqual(shell.panel.title, "Export")
        self.assertEqual(shell.panel.tone, "success")
        json_mock.assert_called_once()
        md_mock.assert_called_once()

    def test_export_command_json_only(self):
        shell = AutomationProjectShell()
        from app.findings import Finding, FindingType
        shell.findings_store.add(Finding(FindingType.PORT, "80", "nmap", "high"))

        with patch.object(shell.findings_store, "export_json") as json_mock:
            with patch.object(shell.findings_store, "export_markdown") as md_mock:
                shell.dispatch_command("/export", ["json"])

        json_mock.assert_called_once()
        md_mock.assert_not_called()

    def test_export_command_md_only(self):
        shell = AutomationProjectShell()
        from app.findings import Finding, FindingType
        shell.findings_store.add(Finding(FindingType.PORT, "443", "nmap", "high"))

        with patch.object(shell.findings_store, "export_json") as json_mock:
            with patch.object(shell.findings_store, "export_markdown") as md_mock:
                shell.dispatch_command("/export", ["md"])

        json_mock.assert_not_called()
        md_mock.assert_called_once()

    def test_export_transcript_json_creates_file(self):
        shell = AutomationProjectShell()
        with TemporaryDirectory() as tmpdir:
            shell.workspace = Path(tmpdir)
            shell._set_transcript_panel(
                "Agent",
                ["sortie resumee"],
                full_text="sortie complete",
                log_path="/tmp/secops.log",
            )

            shell.dispatch_command("/export", ["transcript", "--format", "json"])

            exported = list(shell.workspace.glob("transcript_*.json"))
            self.assertEqual(len(exported), 1)
            data = json.loads(exported[0].read_text(encoding="utf-8"))

        self.assertEqual(shell.panel.title, "Export")
        self.assertEqual(data[0]["full"], "sortie complete")
        self.assertEqual(data[0]["log_path"], "/tmp/secops.log")

    def test_export_transcript_txt_default_creates_file(self):
        shell = AutomationProjectShell()
        with TemporaryDirectory() as tmpdir:
            shell.workspace = Path(tmpdir)
            shell._set_transcript_panel("Agent", ["sortie resumee"], full_text="sortie complete")

            shell.dispatch_command("/export", ["transcript"])

            exported = list(shell.workspace.glob("transcript_*.txt"))
            self.assertEqual(len(exported), 1)
            content = exported[0].read_text(encoding="utf-8")

        self.assertIn("sortie complete", content)
        self.assertEqual(shell.panel.tone, "success")

    def test_report_passes_current_attack_plan(self):
        shell = AutomationProjectShell()
        from app.findings import Finding, FindingType
        shell.findings_store.add(Finding(FindingType.PORT, "80", "nmap", "high"))
        report_path = shell.workspace / "test_report.md"

        with patch("app.project_shell.generate_pentest_report", return_value=report_path) as report_mock:
            shell.dispatch_command("/report", [])

        self.assertEqual(shell.panel.title, "Rapport pentest")
        self.assertTrue(any("Etapes plan:" in line for line in shell.panel.lines))
        attack_plan = report_mock.call_args.kwargs["attack_plan"]
        self.assertGreaterEqual(len(attack_plan.steps), 1)

    def test_keyword_catalog_includes_installed_tools(self):
        shell = AutomationProjectShell()
        catalog = shell.get_keyword_catalog()

        for tool in shell.tool_registry.installed_tools:
            self.assertIn(tool.name, catalog)
            self.assertEqual(catalog[tool.name], tool.description)

    def test_keyword_catalog_includes_detected_targets(self):
        shell = AutomationProjectShell()
        from app.target_context import Target, TargetType
        t = Target(raw="10.10.10.10", target_type=TargetType.IP, address="10.10.10.10")
        shell.targets.append(t)

        catalog = shell.get_keyword_catalog()

        self.assertIn("10.10.10.10", catalog)
        self.assertEqual(catalog["10.10.10.10"], "ip")

    def test_quit_shows_session_summary(self):
        shell = AutomationProjectShell()
        shell._session_start = time.time() - 120  # 2 minutes ago
        shell.engagement.record_tool_use("nmap")

        with patch("builtins.print"):
            result = shell.dispatch_command("/quit", [])

        self.assertFalse(result)
        self.assertEqual(shell.panel.title, "Session terminee")
        self.assertTrue(any("Phase:" in line for line in shell.panel.lines))
        self.assertTrue(any("Duree:" in line for line in shell.panel.lines))
        self.assertTrue(any("nmap" in line for line in shell.panel.lines))

    def test_target_shows_enriched_findings(self):
        shell = AutomationProjectShell()
        from app.target_context import Target, TargetType
        from app.findings import Finding, FindingType
        t = Target(raw="10.10.10.10", target_type=TargetType.IP, address="10.10.10.10")
        shell.active_target = t
        shell.findings_store.add(Finding(FindingType.VULNERABILITY, "XSS dans /login", "nikto", "medium"))
        shell.findings_store.add(Finding(FindingType.PATH, "/admin (200)", "gobuster", "high"))

        shell.dispatch_command("/target", [])

        self.assertEqual(shell.panel.title, "Cible active")
        self.assertTrue(any("vulns:" in line for line in shell.panel.lines))
        self.assertTrue(any("chemins:" in line for line in shell.panel.lines))

    def test_inline_confirm_accepts_oui(self):
        shell = AutomationProjectShell()

        with patch("builtins.input", return_value="oui"):
            result = shell._inline_confirm("Installer nmap ?")

        self.assertTrue(result)

    def test_inline_confirm_rejects_non(self):
        shell = AutomationProjectShell()

        with patch("builtins.input", return_value="non"):
            result = shell._inline_confirm("Installer nmap ?")

        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
