import unittest
import sys
import time
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from app.findings import Finding, FindingsStore, FindingType
from app.jobs import JobTracker
from app.learning_journal import LearningJournal
from app.project_shell import AutomationProjectShell
from app.session_state import SessionState, save_session


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

    def test_status_command_reports_session_context(self):
        shell = AutomationProjectShell()

        shell.dispatch_command("/status", [])

        self.assertEqual(shell.panel.title, "Status")
        self.assertTrue(any("Modele:" in line for line in shell.panel.lines))
        self.assertTrue(any("Memoire:" in line for line in shell.panel.lines))
        self.assertTrue(any("Findings:" in line for line in shell.panel.lines))

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
        self.assertTrue(shell._is_transient_command("/menu"))
        self.assertFalse(shell._is_transient_command("/side question rapide"))
        self.assertFalse(shell._is_transient_command("/status"))

    def test_model_menu_restores_previous_panel_without_model_trace(self):
        shell = AutomationProjectShell()
        previous_panel = shell.panel

        with patch.object(shell, "_can_use_transient_page", return_value=True):
            with patch.object(shell, "clear_screen"):
                with patch.object(shell, "render_shell_header"):
                    with patch.object(shell, "render_panel_state"):
                        with patch(
                            "app.project_shell.choice",
                            side_effect=["gemma", "low"],
                        ):
                            shell.dispatch_command("/model", [])

        self.assertIs(shell.panel, previous_panel)
        self.assertEqual(shell.gemini_runtime.model, "gemma-4-26b-a4b-it")
        self.assertEqual(shell.model_thinking_overrides["gemma-4-26b-a4b-it"], "low")

    def test_scope_menu_can_use_active_target_without_trace(self):
        shell = AutomationProjectShell()
        previous_panel = shell.panel
        shell.current_target = "10.10.10.10"

        with patch.object(shell, "_can_use_transient_page", return_value=True):
            with patch.object(shell, "clear_screen"):
                with patch.object(shell, "render_shell_header"):
                    with patch.object(shell, "render_panel_state"):
                        with patch("app.project_shell.choice", return_value="target"):
                            shell.dispatch_command("/scope", [])

        self.assertIs(shell.panel, previous_panel)
        self.assertEqual(shell.tool_executor.authorized_scope, {"10.10.10.10"})

    def test_phase_menu_allows_guarded_phase_when_scope_exists(self):
        shell = AutomationProjectShell()
        previous_panel = shell.panel
        shell.tool_executor.set_scope(["10.10.10.0/24"])

        with patch.object(shell, "_can_use_transient_page", return_value=True):
            with patch.object(shell, "clear_screen"):
                with patch.object(shell, "render_shell_header"):
                    with patch.object(shell, "render_panel_state"):
                        with patch("app.project_shell.choice", return_value="exploitation"):
                            shell.dispatch_command("/phase", [])

        self.assertIs(shell.panel, previous_panel)
        self.assertEqual(shell.engagement.phase.value, "exploitation")

    def test_permissions_command_updates_executor_mode(self):
        shell = AutomationProjectShell()

        shell.dispatch_command("/permissions", ["deny"])

        self.assertEqual(shell.command_permission_mode, "deny")
        self.assertEqual(shell.tool_executor.command_permission_mode, "deny")
        self.assertEqual(shell.panel.title, "Permissions")
        self.assertTrue(any("desactive" in line for line in shell.panel.lines))

    def test_permissions_menu_restores_previous_panel_without_trace(self):
        shell = AutomationProjectShell()
        previous_panel = shell.panel

        with patch.object(shell, "_can_use_transient_page", return_value=True):
            with patch.object(shell, "clear_screen"):
                with patch.object(shell, "render_shell_header"):
                    with patch.object(shell, "render_panel_state"):
                        with patch("app.project_shell.choice", return_value="deny"):
                            shell.dispatch_command("/permissions", [])

        self.assertIs(shell.panel, previous_panel)
        self.assertEqual(shell.command_permission_mode, "deny")
        self.assertEqual(shell.tool_executor.command_permission_mode, "deny")

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
        self.assertIn(shell.palette.success_badge_bg_hex, styles["toolbar.value.success"])
        self.assertNotIn("bg:", styles["toolbar.value.success"])

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

        self.assertIn("• Memoire: http smb ssh", snapshots[0]["lines"])
        self.assertIn("  └ aucun cas analogue trouve", snapshots[1]["lines"])
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

        self.assertEqual(snapshots[0]["lines"], ["◦ je vais commencer par un ping", "• Commande: ping -c 4 8.8.8.8"])

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
