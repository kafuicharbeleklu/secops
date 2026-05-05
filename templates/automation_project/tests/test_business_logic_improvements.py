"""Tests for business logic improvements (S1–S12)."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.agent_loop import AgentLoop
from app.findings import (
    Finding,
    FindingType,
    FindingsStore,
    parse_enum4linux_output,
    parse_ffuf_output,
    parse_smbclient_output,
    parse_sqlmap_output,
    parse_tool_output,
    parse_whatweb_output,
    parse_wpscan_output,
)
from app.knowledge_store import KnowledgeStore
from app.llm_client import AgentDecision
from app.methodology import EngagementState, PentestPhase
from app.target_context import Target, TargetType, merge_findings, build_target_context
from app.terminal_renderer import TerminalRenderer
from app.tool_executor import (
    TOOL_TIMEOUTS,
    SAFE_PIPE_TARGETS,
    ToolExecutionError,
    ToolExecutor,
    ToolMissingError,
)


# =========================================================================
# S4 — Findings deduplication
# =========================================================================


class TestFindingsDedup(unittest.TestCase):
    def test_duplicate_findings_are_ignored(self):
        store = FindingsStore()
        store.add(Finding(FindingType.PORT, "22", "nmap"))
        store.add(Finding(FindingType.PORT, "22", "nmap"))
        self.assertEqual(store.count, 1)

    def test_same_value_different_source_is_kept(self):
        store = FindingsStore()
        store.add(Finding(FindingType.PORT, "22", "nmap"))
        store.add(Finding(FindingType.PORT, "22", "masscan"))
        self.assertEqual(store.count, 2)

    def test_same_value_different_type_is_kept(self):
        store = FindingsStore()
        store.add(Finding(FindingType.PORT, "22", "nmap"))
        store.add(Finding(FindingType.SERVICE, "22", "nmap"))
        self.assertEqual(store.count, 2)

    def test_add_many_deduplicates(self):
        store = FindingsStore()
        findings = [
            Finding(FindingType.PORT, "22", "nmap"),
            Finding(FindingType.PORT, "80", "nmap"),
            Finding(FindingType.PORT, "22", "nmap"),
        ]
        store.add_many(findings)
        self.assertEqual(store.count, 2)

    def test_ingest_returns_only_new_findings(self):
        store = FindingsStore()
        nmap_output = "22/tcp   open  ssh\n80/tcp   open  http\n"
        first = store.ingest_tool_output("nmap", nmap_output)
        self.assertTrue(len(first) > 0)
        count_after_first = store.count

        # Same output again — should return empty since all already ingested
        second = store.ingest_tool_output("nmap", nmap_output)
        self.assertEqual(len(second), 0)
        self.assertEqual(store.count, count_after_first)

    def test_clear_resets_seen_set(self):
        store = FindingsStore()
        store.add(Finding(FindingType.PORT, "22", "nmap"))
        store.clear()
        self.assertEqual(store.count, 0)
        # After clear, same finding should be accepted again
        store.add(Finding(FindingType.PORT, "22", "nmap"))
        self.assertEqual(store.count, 1)


# =========================================================================
# S7 — New tool parsers
# =========================================================================


class TestParseFFuf(unittest.TestCase):
    def test_extracts_paths(self):
        output = "/admin [Status: 200, Size: 1234]\n/secret [Status: 301, Size: 567]\n"
        findings = parse_ffuf_output(output)
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(f.finding_type == FindingType.PATH for f in findings))

    def test_empty_output(self):
        self.assertEqual(parse_ffuf_output(""), [])


class TestParseSqlmap(unittest.TestCase):
    def test_extracts_vulnerabilities(self):
        output = "Parameter 'id' is vulnerable. Type: boolean-based blind\n"
        findings = parse_sqlmap_output(output)
        self.assertTrue(len(findings) > 0)
        self.assertTrue(all(f.finding_type == FindingType.VULNERABILITY for f in findings))


class TestParseEnum4linux(unittest.TestCase):
    def test_extracts_users(self):
        output = "user:[administrator] rid:[0x1f4]\nuser:[guest] rid:[0x1f5]\n"
        findings = parse_enum4linux_output(output)
        users = [f for f in findings if f.finding_type == FindingType.USER]
        self.assertEqual(len(users), 2)
        self.assertIn("administrator", users[0].value)

    def test_extracts_shares(self):
        output = "\\\\10.10.10.5\\ADMIN$\n\\\\10.10.10.5\\IPC$\n"
        findings = parse_enum4linux_output(output)
        paths = [f for f in findings if f.finding_type == FindingType.PATH]
        self.assertTrue(len(paths) >= 1)


class TestParseWpscan(unittest.TestCase):
    def test_extracts_vulnerabilities(self):
        output = "[!] WordPress version 5.2.1 is vulnerable\n[!] XML-RPC seems to be enabled\n"
        findings = parse_wpscan_output(output)
        vulns = [f for f in findings if f.finding_type == FindingType.VULNERABILITY]
        self.assertTrue(len(vulns) >= 1)


class TestParseWhatweb(unittest.TestCase):
    def test_extracts_technologies(self):
        output = "Apache [2.4.29] PHP [7.2.10] WordPress [5.2.1]\n"
        findings = parse_whatweb_output(output)
        self.assertTrue(len(findings) > 0)
        self.assertTrue(all(f.finding_type == FindingType.SERVICE for f in findings))


class TestParseSmbclient(unittest.TestCase):
    def test_extracts_shares(self):
        output = "    Sharename       Type      Comment\n    ---------       ----      -------\n    public          Disk      Public share\n    admin$          Disk      Admin\n"
        findings = parse_smbclient_output(output)
        paths = [f for f in findings if f.finding_type == FindingType.PATH]
        self.assertTrue(len(paths) >= 1)


class TestToolParserRouting(unittest.TestCase):
    def test_routes_to_new_parsers(self):
        for tool in ("ffuf", "sqlmap", "enum4linux", "wpscan", "whatweb", "smbclient"):
            # Just verify routing doesn't crash
            result = parse_tool_output(tool, "")
            self.assertIsInstance(result, list)


# =========================================================================
# S11 — Findings export
# =========================================================================


class TestFindingsExport(unittest.TestCase):
    def test_export_json(self):
        store = FindingsStore()
        store.add(Finding(FindingType.PORT, "22", "nmap"))
        store.add(Finding(FindingType.SERVICE, "22/ssh", "nmap"))
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "findings.json"
            store.export_json(path)
            data = json.loads(path.read_text())
            self.assertEqual(len(data), 2)
            self.assertEqual(data[0]["type"], "port")
            self.assertEqual(data[0]["value"], "22")

    def test_export_markdown(self):
        store = FindingsStore()
        store.add(Finding(FindingType.PORT, "22", "nmap"))
        store.add(Finding(FindingType.VULNERABILITY, "CVE-2021-1234", "nikto"))
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "report.md"
            store.export_markdown(path)
            content = path.read_text()
            self.assertIn("# Rapport", content)
            self.assertIn("Port", content)
            self.assertIn("CVE-2021-1234", content)


# =========================================================================
# S1 — Auto phase advance
# =========================================================================


class TestAutoPhaseAdvance(unittest.TestCase):
    def test_should_suggest_advance_from_recon(self):
        engagement = EngagementState()
        findings = [Finding(FindingType.PORT, "22", "nmap")]
        self.assertTrue(engagement.should_suggest_advance(findings))

    def test_should_suggest_advance_from_enum(self):
        engagement = EngagementState(phase=PentestPhase.ENUMERATION)
        findings = [Finding(FindingType.VULNERABILITY, "vuln", "nikto")]
        self.assertTrue(engagement.should_suggest_advance(findings))

    def test_should_not_advance_from_reporting(self):
        engagement = EngagementState(phase=PentestPhase.REPORTING)
        findings = [Finding(FindingType.PORT, "22", "nmap")]
        self.assertFalse(engagement.should_suggest_advance(findings))

    def test_agent_loop_emits_phase_advance_event(self):
        class FakeToolExecutor:
            def available_tools(self):
                return ()

            def dispatch(self, tool_name, arguments):
                return {
                    "command": "nmap 10.10.10.10",
                    "stdout": "22/tcp   open  ssh\n80/tcp   open  http\n",
                    "stderr": "",
                    "returncode": 0,
                }

        class FakeLLMClient:
            def __init__(self):
                self.decisions = [
                    AgentDecision(
                        thought="Scan de la cible.",
                        tool_name="execute_command",
                        arguments={"command": "nmap 10.10.10.10"},
                        final_answer=None,
                        raw_text="",
                    ),
                    AgentDecision(
                        thought="Fin.",
                        tool_name=None,
                        arguments={},
                        final_answer="Ports trouves.",
                        raw_text="",
                    ),
                ]

            def decide_next_step(self, messages, system_prompt, tool_specs):
                return self.decisions.pop(0)

        loop = AgentLoop(FakeLLMClient(), FakeToolExecutor(), max_iterations=4)
        events = list(loop.run("scan la cible", "Contexte"))

        phase_events = [e for e in events if e["type"] == "phase_advance"]
        self.assertTrue(len(phase_events) > 0, "Expected phase_advance event")
        self.assertEqual(phase_events[0]["from"], "recon")
        self.assertEqual(phase_events[0]["to"], "enumeration")


# =========================================================================
# S2 — Target enrichment via merge_findings
# =========================================================================


class TestTargetEnrichment(unittest.TestCase):
    def test_merge_findings_adds_ports(self):
        target = Target(raw="10.10.10.5", target_type=TargetType.IP, address="10.10.10.5")
        findings = [
            Finding(FindingType.PORT, "22", "nmap"),
            Finding(FindingType.PORT, "80", "nmap"),
        ]
        merge_findings(target, findings)
        self.assertEqual(sorted(target.ports), [22, 80])

    def test_merge_findings_adds_services(self):
        target = Target(raw="10.10.10.5", target_type=TargetType.IP, address="10.10.10.5")
        findings = [Finding(FindingType.SERVICE, "22/ssh", "nmap")]
        merge_findings(target, findings)
        self.assertEqual(target.services[22], "ssh")

    def test_merge_findings_sets_os(self):
        target = Target(raw="10.10.10.5", target_type=TargetType.IP, address="10.10.10.5")
        findings = [Finding(FindingType.OS, "Ubuntu 18.04", "nmap")]
        merge_findings(target, findings)
        self.assertEqual(target.os_hint, "Ubuntu 18.04")

    def test_agent_loop_enriches_active_target(self):
        target = Target(raw="10.10.10.5", target_type=TargetType.IP, address="10.10.10.5")

        class FakeToolExecutor:
            def available_tools(self):
                return ()

            def dispatch(self, tool_name, arguments):
                return {
                    "command": "nmap 10.10.10.5",
                    "stdout": "22/tcp   open  ssh\n",
                    "stderr": "",
                    "returncode": 0,
                }

        class FakeLLMClient:
            def __init__(self):
                self.decisions = [
                    AgentDecision(
                        thought="Scan.",
                        tool_name="execute_command",
                        arguments={"command": "nmap 10.10.10.5"},
                        final_answer=None,
                        raw_text="",
                    ),
                    AgentDecision(
                        thought="Fin.",
                        tool_name=None,
                        arguments={},
                        final_answer="Port 22 ouvert.",
                        raw_text="",
                    ),
                ]

            def decide_next_step(self, messages, system_prompt, tool_specs):
                return self.decisions.pop(0)

        loop = AgentLoop(FakeLLMClient(), FakeToolExecutor(), max_iterations=4)
        loop.active_target = target
        loop.targets = [target]
        list(loop.run("scan", "Contexte"))

        self.assertIn(22, target.ports)


# =========================================================================
# S3 — Target context in system prompt
# =========================================================================


class TestTargetContextInjection(unittest.TestCase):
    def test_build_target_context_with_active(self):
        target = Target(raw="10.10.10.5", target_type=TargetType.IP, address="10.10.10.5")
        target.ports = [22, 80]
        ctx = build_target_context([target], target)
        self.assertIn("10.10.10.5", ctx)
        self.assertIn("22", ctx)

    def test_build_target_context_no_targets(self):
        ctx = build_target_context([], None)
        self.assertIn("Aucune cible", ctx)

    def test_agent_loop_includes_target_in_system_prompt(self):
        target = Target(raw="10.10.10.5", target_type=TargetType.IP, address="10.10.10.5")
        target.ports = [22]

        captured_prompts = []

        class FakeLLMClient:
            def decide_next_step(self, messages, system_prompt, tool_specs):
                captured_prompts.append(system_prompt)
                return AgentDecision(
                    thought="",
                    tool_name=None,
                    arguments={},
                    final_answer="ok",
                    raw_text="ok",
                )

        class FakeToolExecutor:
            def available_tools(self):
                return ()

        loop = AgentLoop(FakeLLMClient(), FakeToolExecutor(), max_iterations=2)
        loop.active_target = target
        loop.targets = [target]
        list(loop.run("test", "Contexte"))

        self.assertTrue(len(captured_prompts) > 0)
        self.assertIn("10.10.10.5", captured_prompts[0])


# =========================================================================
# S5 — History trimming
# =========================================================================


class TestHistoryTrimming(unittest.TestCase):
    def test_trim_history_respects_max(self):
        class FakeLLMClient:
            def decide_next_step(self, messages, system_prompt, tool_specs):
                return AgentDecision(
                    thought="",
                    tool_name=None,
                    arguments={},
                    final_answer="ok",
                    raw_text="ok",
                )

        class FakeToolExecutor:
            def available_tools(self):
                return ()

        loop = AgentLoop(FakeLLMClient(), FakeToolExecutor(), max_iterations=2)
        # Overfill the history
        for i in range(50):
            loop.messages.append({"role": "user", "content": f"message {i}"})
        list(loop.run("new message", "Contexte"))
        self.assertLessEqual(len(loop.messages), AgentLoop.MAX_HISTORY + 5)


# =========================================================================
# S6 — Adaptive timeout
# =========================================================================


class TestAdaptiveTimeout(unittest.TestCase):
    def test_nmap_has_longer_timeout(self):
        self.assertGreater(TOOL_TIMEOUTS["nmap"], 30)

    def test_hydra_has_long_timeout(self):
        self.assertGreaterEqual(TOOL_TIMEOUTS["hydra"], 300)

    def test_default_timeout_is_30(self):
        self.assertNotIn("echo", TOOL_TIMEOUTS)
        # default 30 is implicit — checked in execute_command


# =========================================================================
# S8 — Pipeline validation
# =========================================================================


class TestPipelineValidation(unittest.TestCase):
    def setUp(self):
        repo_root = Path(__file__).resolve().parents[3]
        self.knowledge_root = repo_root / "knowledge"
        self.workspace = repo_root / "templates" / "automation_project" / "workspace"
        self.knowledge_store = KnowledgeStore.load(self.knowledge_root)

    def test_pipe_to_grep_is_allowed(self):
        executor = ToolExecutor(
            workspace=self.workspace,
            knowledge_root=self.knowledge_root,
            knowledge_store=self.knowledge_store,
            permission_callback=lambda **_kwargs: True,
            command_permission_mode="ask",
        )
        # Should not raise
        executor._validate_pipeline("nmap 10.10.10.10 | grep open")

    def test_pipe_to_head_is_allowed(self):
        executor = ToolExecutor(
            workspace=self.workspace,
            knowledge_root=self.knowledge_root,
            knowledge_store=self.knowledge_store,
        )
        executor._validate_pipeline("cat /etc/passwd | head -5")

    def test_pipe_to_unsafe_command_is_blocked(self):
        executor = ToolExecutor(
            workspace=self.workspace,
            knowledge_root=self.knowledge_root,
            knowledge_store=self.knowledge_store,
        )
        with self.assertRaises(ToolExecutionError):
            executor._validate_pipeline("ls | rm -rf")

    def test_pipe_to_python_is_blocked(self):
        executor = ToolExecutor(
            workspace=self.workspace,
            knowledge_root=self.knowledge_root,
            knowledge_store=self.knowledge_store,
        )
        with self.assertRaises(ToolExecutionError):
            executor._validate_pipeline("echo test | python3")

    def test_safe_pipe_targets_list(self):
        expected = {"grep", "head", "tail", "sort", "uniq", "wc", "awk", "sed", "cut", "tr"}
        self.assertEqual(SAFE_PIPE_TARGETS, expected)


# =========================================================================
# S12 — Improved _trigger_install
# =========================================================================


class TestTriggerInstall(unittest.TestCase):
    def setUp(self):
        repo_root = Path(__file__).resolve().parents[3]
        self.knowledge_root = repo_root / "knowledge"
        self.workspace = repo_root / "templates" / "automation_project" / "workspace"
        self.knowledge_store = KnowledgeStore.load(self.knowledge_root)

    def test_trigger_install_rejects_unknown_tool(self):
        executor = ToolExecutor(
            workspace=self.workspace,
            knowledge_root=self.knowledge_root,
            knowledge_store=self.knowledge_store,
        )
        with self.assertRaises(ToolExecutionError) as ctx:
            executor._trigger_install("completely_unknown_tool_xyz")
        self.assertIn("inconnu", str(ctx.exception))

    def test_trigger_install_reports_already_installed(self):
        executor = ToolExecutor(
            workspace=self.workspace,
            knowledge_root=self.knowledge_root,
            knowledge_store=self.knowledge_store,
        )
        with patch.object(executor.tool_registry, "is_installed", return_value=True):
            result = executor._trigger_install("nmap")
        self.assertEqual(result["status"], "already_installed")

    def test_trigger_install_raises_for_missing_known_tool(self):
        executor = ToolExecutor(
            workspace=self.workspace,
            knowledge_root=self.knowledge_root,
            knowledge_store=self.knowledge_store,
        )
        with patch.object(executor.tool_registry, "is_installed", return_value=False):
            with self.assertRaises(ToolMissingError):
                executor._trigger_install("nmap")


# =========================================================================
# S10 — Renderer handles new events
# =========================================================================


class TestRendererNewEvents(unittest.TestCase):
    def test_renders_findings_event(self):
        renderer = TerminalRenderer()
        rendered = renderer.render(
            [
                {"type": "findings", "count": 3, "tool": "nmap"},
                {"type": "final_answer", "content": "Done."},
            ],
            model_label="gemini-2.5-flash",
        )
        self.assertTrue(any("3 decouverte(s)" in line for line in rendered["lines"]))

    def test_renders_phase_advance_event(self):
        renderer = TerminalRenderer()
        rendered = renderer.render(
            [
                {"type": "phase_advance", "from": "recon", "to": "enumeration"},
                {"type": "final_answer", "content": "Phase avancee."},
            ],
            model_label="gemini-2.5-flash",
        )
        self.assertTrue(any("recon" in line and "enumeration" in line for line in rendered["lines"]))


# =========================================================================
# Suggestion #2 — Structured findings summary
# =========================================================================


class TestStructuredSummary(unittest.TestCase):
    def test_structured_summary_empty(self):
        store = FindingsStore()
        self.assertEqual(store.structured_summary(), "")

    def test_structured_summary_with_ports_and_services(self):
        store = FindingsStore()
        store.add(Finding(FindingType.PORT, "22", "nmap"))
        store.add(Finding(FindingType.PORT, "80", "nmap"))
        store.add(Finding(FindingType.SERVICE, "22/ssh", "nmap"))
        summary = store.structured_summary()
        self.assertIn("Ports ouverts", summary)
        self.assertIn("22", summary)
        self.assertIn("80", summary)
        self.assertIn("Services", summary)

    def test_structured_summary_with_credentials(self):
        store = FindingsStore()
        store.add(Finding(FindingType.CREDENTIAL, "admin:pass123", "hydra"))
        summary = store.structured_summary()
        self.assertIn("Credentials", summary)
        self.assertIn("admin:pass123", summary)


# =========================================================================
# Suggestion #3 — Anti-loop (failed commands)
# =========================================================================


class TestAntiLoop(unittest.TestCase):
    def test_failed_command_is_blocked_on_retry(self):
        call_count = 0

        class FakeToolExecutor:
            def available_tools(self):
                return ()

            def dispatch(self, tool_name, arguments):
                nonlocal call_count
                call_count += 1
                return {"stdout": "", "stderr": "error", "returncode": 1, "command": "bad_cmd"}

        class FakeLLMClient:
            def __init__(self):
                self.decisions = [
                    AgentDecision(
                        thought="Essai 1.",
                        tool_name="execute_command",
                        arguments={"command": "bad_cmd"},
                        final_answer=None,
                        raw_text="",
                    ),
                    AgentDecision(
                        thought="Essai 2 meme commande.",
                        tool_name="execute_command",
                        arguments={"command": "bad_cmd"},
                        final_answer=None,
                        raw_text="",
                    ),
                    AgentDecision(
                        thought="Fin.",
                        tool_name=None,
                        arguments={},
                        final_answer="J'arrete.",
                        raw_text="",
                    ),
                ]

            def decide_next_step(self, messages, system_prompt, tool_specs):
                return self.decisions.pop(0)

        loop = AgentLoop(FakeLLMClient(), FakeToolExecutor(), max_iterations=5)
        events = list(loop.run("test", "Contexte"))

        # The second attempt should be blocked (tool_error, not dispatched)
        self.assertEqual(call_count, 1, "Failed command should only be dispatched once")
        error_events = [e for e in events if e["type"] == "tool_error"]
        self.assertTrue(len(error_events) >= 1)
        self.assertIn("deja echoue", error_events[-1]["error"])


# =========================================================================
# Suggestion #1 — Multi-step continuation hint
# =========================================================================


class TestMultiStepContinuation(unittest.TestCase):
    def test_continuation_hint_injected_after_tool(self):
        captured_messages = []

        class FakeToolExecutor:
            def available_tools(self):
                return ()

            def dispatch(self, tool_name, arguments):
                return {"stdout": "22/tcp open ssh\n", "stderr": "", "returncode": 0, "command": "nmap"}

        class FakeLLMClient:
            def __init__(self):
                self.call_count = 0

            def decide_next_step(self, messages, system_prompt, tool_specs):
                self.call_count += 1
                captured_messages.append(list(messages))
                if self.call_count == 1:
                    return AgentDecision(
                        thought="Scan.",
                        tool_name="execute_command",
                        arguments={"command": "nmap 10.10.10.10"},
                        final_answer=None,
                        raw_text="",
                    )
                return AgentDecision(
                    thought="Fin.",
                    tool_name=None,
                    arguments={},
                    final_answer="Port 22 ouvert.",
                    raw_text="",
                )

        loop = AgentLoop(FakeLLMClient(), FakeToolExecutor(), max_iterations=5)
        list(loop.run("scan", "Contexte"))

        # After a bounded tool call, the agent should be instructed to answer,
        # not to continue the playbook automatically.
        self.assertTrue(len(captured_messages) >= 2)
        second_call_msgs = captured_messages[1]
        continuation_msgs = [m for m in second_call_msgs if "Ne lance aucun nouvel outil" in m.get("content", "")]
        self.assertTrue(len(continuation_msgs) > 0, "Continuation hint should be injected")


# =========================================================================
# Suggestion #2 — Findings injected in system prompt
# =========================================================================


class TestFindingsInPrompt(unittest.TestCase):
    def test_findings_appear_in_system_prompt(self):
        captured_prompts = []

        class FakeLLMClient:
            def decide_next_step(self, messages, system_prompt, tool_specs):
                captured_prompts.append(system_prompt)
                return AgentDecision(
                    thought="",
                    tool_name=None,
                    arguments={},
                    final_answer="ok",
                    raw_text="ok",
                )

        class FakeToolExecutor:
            def available_tools(self):
                return ()

        loop = AgentLoop(FakeLLMClient(), FakeToolExecutor(), max_iterations=2)
        loop.findings_store.add(Finding(FindingType.PORT, "22", "nmap"))
        loop.findings_store.add(Finding(FindingType.PORT, "80", "nmap"))
        list(loop.run("analyse", "Contexte"))

        self.assertTrue(len(captured_prompts) > 0)
        self.assertIn("FINDINGS ACCUMULES", captured_prompts[0])
        self.assertIn("22", captured_prompts[0])
        self.assertIn("80", captured_prompts[0])


# =========================================================================
# Suggestion #4 — Phase playbooks
# =========================================================================


class TestPhasePlaybooks(unittest.TestCase):
    def test_all_phases_have_playbook(self):
        from app.methodology import PHASE_METADATA, PentestPhase
        for phase in PentestPhase:
            if phase == PentestPhase.REPORTING:
                continue  # Reporting is synthesis, no numbered playbook
            meta = PHASE_METADATA[phase]
            self.assertIn("PLAYBOOK", meta["prompt_fragment"].upper(),
                         f"Phase {phase.value} missing playbook")

    def test_recon_playbook_mentions_nmap(self):
        from app.methodology import PHASE_METADATA, PentestPhase
        recon = PHASE_METADATA[PentestPhase.RECON]["prompt_fragment"]
        self.assertIn("nmap", recon.lower())

    def test_enum_playbook_mentions_gobuster(self):
        from app.methodology import PHASE_METADATA, PentestPhase
        enum = PHASE_METADATA[PentestPhase.ENUMERATION]["prompt_fragment"]
        self.assertIn("gobuster", enum.lower())

# =========================================================================
# Suggestion #8 — Output truncation
# =========================================================================


class TestOutputTruncation(unittest.TestCase):
    def test_short_output_not_truncated(self):
        loop = AgentLoop(None, None, max_iterations=1)
        result = {"stdout": "short output", "returncode": 0}
        compact = loop._truncate_result("execute_command", result)
        self.assertEqual(compact["stdout"], "short output")

    def test_long_output_truncated(self):
        loop = AgentLoop(None, None, max_iterations=1)
        long_stdout = "line\n" * 1000  # ~5000 chars
        result = {"stdout": long_stdout, "returncode": 0}
        compact = loop._truncate_result("execute_command", result)
        self.assertLess(len(compact["stdout"]), len(long_stdout))
        self.assertIn("lignes restantes", compact["stdout"])

    def test_truncation_includes_findings(self):
        loop = AgentLoop(None, None, max_iterations=1)
        loop.findings_store.add(Finding(FindingType.PORT, "22", "nmap"))
        long_stdout = "x" * 3000
        result = {"stdout": long_stdout, "returncode": 0}
        compact = loop._truncate_result("execute_command", result)
        self.assertIn("Findings extraits", compact["stdout"])

    def test_non_dict_result_not_truncated(self):
        loop = AgentLoop(None, None, max_iterations=1)
        self.assertEqual(loop._truncate_result("tool", "plain string"), "plain string")


# =========================================================================
# Suggestion #10 — Findings correlation
# =========================================================================


class TestFindingsCorrelation(unittest.TestCase):
    def test_web_ports_suggest_gobuster(self):
        loop = AgentLoop(None, None, max_iterations=1)
        loop.findings_store.add(Finding(FindingType.PORT, "80", "nmap"))
        suggestions = loop._suggest_next_actions()
        self.assertIn("gobuster", suggestions)

    def test_smb_ports_suggest_enum4linux(self):
        loop = AgentLoop(None, None, max_iterations=1)
        loop.findings_store.add(Finding(FindingType.PORT, "445", "nmap"))
        suggestions = loop._suggest_next_actions()
        self.assertIn("enum4linux", suggestions)

    def test_no_suggestions_when_empty(self):
        loop = AgentLoop(None, None, max_iterations=1)
        suggestions = loop._suggest_next_actions()
        self.assertEqual(suggestions, "")

    def test_already_used_tool_not_suggested(self):
        loop = AgentLoop(None, None, max_iterations=1)
        loop.findings_store.add(Finding(FindingType.PORT, "80", "nmap"))
        loop.engagement.record_tool_use("gobuster")
        suggestions = loop._suggest_next_actions()
        self.assertNotIn("gobuster", suggestions)

    def test_credential_with_ssh_suggests_login(self):
        loop = AgentLoop(None, None, max_iterations=1)
        loop.findings_store.add(Finding(FindingType.PORT, "22", "nmap"))
        loop.findings_store.add(Finding(FindingType.CREDENTIAL, "admin:pass", "hydra"))
        suggestions = loop._suggest_next_actions()
        self.assertIn("SSH", suggestions)


# =========================================================================
# Suggestion #12 — Findings persistence
# =========================================================================


class TestFindingsPersistence(unittest.TestCase):
    def test_save_and_load_roundtrip(self):
        store = FindingsStore()
        store.add(Finding(FindingType.PORT, "22", "nmap"))
        store.add(Finding(FindingType.SERVICE, "22/ssh", "nmap"))
        store.add(Finding(FindingType.CREDENTIAL, "admin:pass", "hydra"))
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "state.json"
            store.save_state(path)
            self.assertTrue(path.exists())
            restored = FindingsStore.load_state(path)
            self.assertEqual(restored.count, 3)
            self.assertEqual(len(restored.ports), 1)
            self.assertEqual(len(restored.credentials), 1)

    def test_load_missing_file_returns_empty(self):
        restored = FindingsStore.load_state(Path("/nonexistent/path.json"))
        self.assertEqual(restored.count, 0)

    def test_load_corrupt_file_returns_empty(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "bad.json"
            path.write_text("not json at all", encoding="utf-8")
            restored = FindingsStore.load_state(path)
            self.assertEqual(restored.count, 0)

    def test_save_creates_parent_dirs(self):
        store = FindingsStore()
        store.add(Finding(FindingType.PORT, "80", "nmap"))
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "nested" / "deep" / "state.json"
            store.save_state(path)
            self.assertTrue(path.exists())


# =========================================================================
# Suggestion #7 — scan_target tool
# =========================================================================


class TestScanTarget(unittest.TestCase):
    def setUp(self):
        repo_root = Path(__file__).resolve().parents[3]
        self.knowledge_root = repo_root / "knowledge"
        self.workspace = repo_root / "templates" / "automation_project" / "workspace"
        self.knowledge_store = KnowledgeStore.load(self.knowledge_root)

    def test_scan_target_in_available_tools(self):
        executor = ToolExecutor(
            workspace=self.workspace,
            knowledge_root=self.knowledge_root,
            knowledge_store=self.knowledge_store,
        )
        tool_names = [t.name for t in executor.available_tools()]
        self.assertIn("scan_target", tool_names)

    def test_scan_target_requires_target(self):
        executor = ToolExecutor(
            workspace=self.workspace,
            knowledge_root=self.knowledge_root,
            knowledge_store=self.knowledge_store,
            permission_callback=lambda **_kwargs: True,
            command_permission_mode="ask",
        )
        from app.tool_executor import MissingTargetError
        with self.assertRaises(MissingTargetError):
            executor._scan_target("", "quick")

    def test_scan_target_dispatches_via_name(self):
        executor = ToolExecutor(
            workspace=self.workspace,
            knowledge_root=self.knowledge_root,
            knowledge_store=self.knowledge_store,
        )
        # Verify dispatch routing works (will raise ToolMissingError if nmap not installed)
        from app.tool_executor import MissingTargetError
        try:
            executor.dispatch("scan_target", {"target": "", "mode": "quick"})
        except MissingTargetError:
            pass  # Expected: empty target

    @patch("shutil.which", return_value="/usr/bin/nmap")
    @patch.object(ToolExecutor, "execute_command")
    def test_scan_target_adds_nmap_stats_flag(self, mock_exec, mock_which):
        executor = ToolExecutor(
            workspace=self.workspace,
            knowledge_root=self.knowledge_root,
            knowledge_store=self.knowledge_store,
            permission_callback=lambda **_kwargs: True,
            command_permission_mode="ask",
        )

        executor._scan_target("10.10.10.10", "quick")

        self.assertIn("--stats-every 5s", mock_exec.call_args.args[0])


# =========================================================================
# Suggestion #9 — Retry hints
# =========================================================================


class TestRetryHints(unittest.TestCase):
    def test_nmap_hint(self):
        loop = AgentLoop(None, None, max_iterations=1)
        hint = loop._build_retry_hint("nmap -sC -sV 10.10.10.10", {"stderr": "error"})
        self.assertIn("ports", hint.lower())

    def test_gobuster_hint(self):
        loop = AgentLoop(None, None, max_iterations=1)
        hint = loop._build_retry_hint("gobuster dir -u http://target", {"stderr": ""})
        self.assertIn("wordlist", hint.lower())

    def test_timeout_fallback(self):
        loop = AgentLoop(None, None, max_iterations=1)
        hint = loop._build_retry_hint("unknown_tool run", {"stderr": "connection timeout"})
        self.assertIn("expire", hint.lower())

    def test_permission_fallback(self):
        loop = AgentLoop(None, None, max_iterations=1)
        hint = loop._build_retry_hint("unknown_tool run", {"stderr": "permission denied"})
        self.assertIn("admin_command", hint.lower())

    def test_not_found_fallback(self):
        loop = AgentLoop(None, None, max_iterations=1)
        hint = loop._build_retry_hint("mystery_tool", {"stderr": "command not found"})
        self.assertIn("install_pentest_tool", hint.lower())

    def test_unknown_no_hint(self):
        loop = AgentLoop(None, None, max_iterations=1)
        hint = loop._build_retry_hint("unknown_tool", {"stderr": ""})
        self.assertEqual(hint, "")


if __name__ == "__main__":
    unittest.main()
