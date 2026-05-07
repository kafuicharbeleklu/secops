import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from app.attack_planner import StepStatus
from app.agent_loop import AgentLoop
from app.learning_journal import LearningJournal
from app.llm_client import AgentDecision
from app.knowledge_store import KnowledgeStore
from app.methodology import PentestPhase
from app.target_context import Target, TargetType
from app.tool_executor import (
    InteractiveAdminRequired,
    PermissionDenied,
    ToolExecutor,
    ToolMissingError,
    ToolsMissingError,
)
from app.tool_policy import ToolPolicyError


class FakeLLMClient:
    def __init__(self, decisions):
        self.decisions = list(decisions)

    def decide_next_step(self, messages, system_prompt, tool_specs):
        return self.decisions.pop(0)


class AgentLoopTests(unittest.TestCase):
    def test_core_prompt_requests_codex_response_style(self):
        self.assertIn("style Codex", AgentLoop.CORE_PROMPT)
        self.assertIn("'• '", AgentLoop.CORE_PROMPT)
        self.assertIn("'- '", AgentLoop.CORE_PROMPT)
        self.assertIn("titres Markdown", AgentLoop.CORE_PROMPT)

    def test_exported_plan_preserves_step_status(self):
        class FakeToolExecutor:
            def __init__(self):
                self.authorized_scope = set()

            def available_tools(self):
                return ()

            def dispatch(self, tool_name, arguments):
                return {"stdout": "scan ok", "stderr": "", "returncode": 0}

        llm = FakeLLMClient(
            [
                AgentDecision(
                    thought="Je lance le scan initial.",
                    tool_name="scan_target",
                    arguments={"target": "10.10.10.10", "mode": "quick"},
                    final_answer=None,
                    raw_text="",
                ),
                AgentDecision(
                    thought="Termine.",
                    tool_name=None,
                    arguments={},
                    final_answer="Scan termine.",
                    raw_text="",
                ),
            ]
        )
        loop = AgentLoop(llm, FakeToolExecutor(), max_iterations=3)
        target = Target(raw="10.10.10.10", target_type=TargetType.IP, address="10.10.10.10")
        loop.targets = [target]
        loop.active_target = target

        events = list(loop.run("scan la cible", "Contexte"))

        self.assertEqual(events[-1]["type"], "final_answer")
        self.assertEqual(loop.current_plan.steps[0].status, StepStatus.DONE)
        exported = loop.export_state()
        restored = AgentLoop(FakeLLMClient([]), FakeToolExecutor(), max_iterations=1)
        restored.import_state(exported)
        self.assertEqual(restored.current_plan.steps[0].status, StepStatus.DONE)

    def test_runs_tool_then_returns_final_answer(self):
        repo_root = Path(__file__).resolve().parents[3]
        knowledge_root = repo_root / "knowledge"
        workspace = repo_root / "templates" / "automation_project" / "workspace"
        knowledge_store = KnowledgeStore.load(knowledge_root)
        tools = ToolExecutor(
            workspace=workspace,
            knowledge_root=knowledge_root,
            knowledge_store=knowledge_store,
            command_permission_mode="deny",
        )
        llm = FakeLLMClient(
            [
                AgentDecision(
                    thought="Je consulte la memoire.",
                    tool_name="query_knowledge",
                    arguments={"query": "http smb ssh"},
                    final_answer=None,
                    raw_text="",
                ),
                AgentDecision(
                    thought="J'ai assez d'information.",
                    tool_name=None,
                    arguments={},
                    final_answer="La prochaine piste est l'enumeration SMB.",
                    raw_text="",
                ),
            ]
        )
        loop = AgentLoop(llm, tools, max_iterations=4)

        events = list(loop.run("que faire ensuite ?", "Cas actif: basic_penetration"))

        self.assertTrue(any(event["type"] == "tool_start" for event in events))
        self.assertTrue(any(event["type"] == "tool_success" for event in events))
        self.assertEqual(events[-1]["type"], "final_answer")
        self.assertIn("enumeration SMB", events[-1]["content"])

    def test_records_tool_attempts_in_learning_journal(self):
        class FakeToolExecutor:
            def __init__(self):
                self.authorized_scope = set()

            def available_tools(self):
                return ()

            def dispatch(self, tool_name, arguments):
                return {
                    "command": "nmap 10.10.10.10",
                    "stdout": "22/tcp   open  ssh\n",
                    "stderr": "",
                    "returncode": 0,
                }

        llm = FakeLLMClient(
            [
                AgentDecision(
                    thought="Je scanne.",
                    tool_name="execute_command",
                    arguments={"command": "nmap 10.10.10.10"},
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
        )

        with TemporaryDirectory() as tmpdir:
            journal = LearningJournal(Path(tmpdir) / "attempt_journal.jsonl")
            loop = AgentLoop(llm, FakeToolExecutor(), max_iterations=4, learning_journal=journal)
            loop.active_case_label = "tryhackme/basic_penetration"
            list(loop.run("scan", "Contexte"))

            attempts = journal.recent()

        self.assertEqual(len(attempts), 1)
        self.assertEqual(attempts[0].tool_name, "execute_command")
        self.assertEqual(attempts[0].status, "success")
        self.assertEqual(attempts[0].case_label, "tryhackme/basic_penetration")
        self.assertIn("22", attempts[0].findings)

    def test_injects_learning_journal_in_decision_prompt(self):
        class CapturingLLMClient:
            def __init__(self):
                self.system_prompt = ""

            def decide_next_step(self, messages, system_prompt, tool_specs):
                self.system_prompt = system_prompt
                return AgentDecision(
                    thought="",
                    tool_name=None,
                    arguments={},
                    final_answer="Termine.",
                    raw_text="",
                )

        class FakeToolExecutor:
            def __init__(self):
                self.authorized_scope = set()

            def available_tools(self):
                return ()

            def dispatch(self, tool_name, arguments):
                return {}

        with TemporaryDirectory() as tmpdir:
            journal = LearningJournal(Path(tmpdir) / "attempt_journal.jsonl")
            journal.append_attempt(
                tool_name="execute_command",
                arguments={"command": "nmap 10.10.10.10"},
                status="failed",
                target="10.10.10.10",
                phase="recon",
                result_summary="Timeout nmap",
                retry_hint="Reduire le nombre de ports ou augmenter le timeout.",
            )
            llm = CapturingLLMClient()
            loop = AgentLoop(llm, FakeToolExecutor(), max_iterations=1, learning_journal=journal)
            list(loop.run("reprends", "Contexte"))

        self.assertIn("MEMOIRE D'EXPERIENCE RECENTE", llm.system_prompt)
        self.assertIn("execute_command", llm.system_prompt)
        self.assertIn("Reduire le nombre de ports", llm.system_prompt)

    def test_stops_and_requests_install_when_required_tool_is_missing(self):
        repo_root = Path(__file__).resolve().parents[3]
        knowledge_root = repo_root / "knowledge"
        workspace = repo_root / "templates" / "automation_project" / "workspace"
        knowledge_store = KnowledgeStore.load(knowledge_root)

        class MissingToolExecutor:
            def available_tools(self):
                return ()

            def dispatch(self, tool_name, arguments):
                raise ToolMissingError("nmap")

        llm = FakeLLMClient(
            [
                AgentDecision(
                    thought="Je dois scanner la cible.",
                    tool_name="execute_command",
                    arguments={"command": "nmap 10.10.10.10"},
                    final_answer=None,
                    raw_text="",
                )
            ]
        )
        loop = AgentLoop(llm, MissingToolExecutor(), max_iterations=2)

        events = list(loop.run("scan la cible", "Cas actif: basic_penetration"))

        self.assertTrue(any(event["type"] == "tool_missing" for event in events))
        self.assertEqual(events[-1]["type"], "final_answer")
        self.assertIn("installation", events[-1]["content"])

    def test_stops_and_requests_single_batch_install_for_multiple_tools(self):
        class MissingToolsExecutor:
            def available_tools(self):
                return ()

            def dispatch(self, tool_name, arguments):
                raise ToolsMissingError(["hydra", "dirb"], installed=["nikto"])

        llm = FakeLLMClient(
            [
                AgentDecision(
                    thought="Je dois installer le lot demande.",
                    tool_name="install_pentest_tools",
                    arguments={"tool_names": ["nikto", "hydra", "dirb"]},
                    final_answer=None,
                    raw_text="",
                )
            ]
        )
        loop = AgentLoop(llm, MissingToolsExecutor(), max_iterations=2)

        events = list(loop.run("install nikto hydra dirb", ""))
        missing_event = next(event for event in events if event["type"] == "tool_missing")

        self.assertEqual(missing_event["name"], "install_pentest_tools")
        self.assertEqual(missing_event["executables"], ["hydra", "dirb"])
        self.assertEqual(missing_event["installed"], ["nikto"])
        self.assertIn("hydra, dirb", events[-1]["content"])

    def test_can_resume_after_external_tool_result(self):
        class MissingToolExecutor:
            def available_tools(self):
                return ()

            def dispatch(self, tool_name, arguments):
                raise ToolMissingError("nmap")

        llm = FakeLLMClient(
            [
                AgentDecision(
                    thought="Je dois scanner la cible.",
                    tool_name="execute_command",
                    arguments={"command": "nmap 10.10.10.10"},
                    final_answer=None,
                    raw_text="",
                ),
                AgentDecision(
                    thought="J'ai assez d'information.",
                    tool_name=None,
                    arguments={},
                    final_answer="22/tcp est ouvert, passe ensuite a l'enumeration SMB.",
                    raw_text="",
                ),
            ]
        )
        loop = AgentLoop(llm, MissingToolExecutor(), max_iterations=2)

        initial_events = list(loop.run("scan la cible", "Cas actif: basic_penetration"))
        self.assertTrue(any(event["type"] == "tool_missing" for event in initial_events))

        resumed_events = list(
            loop.resume_after_external_tool(
                "Cas actif: basic_penetration",
                result={
                    "command": "nmap 10.10.10.10",
                    "stdout": "22/tcp open ssh",
                    "stderr": "",
                    "returncode": 0,
                },
            )
        )

        self.assertIsNone(loop.pending_external_tool)
        self.assertEqual(resumed_events[-1]["type"], "final_answer")
        self.assertIn("enumeration SMB", resumed_events[-1]["content"])
        self.assertGreaterEqual(loop.findings_store.count, 1)
        self.assertTrue(any(f.value == "22" for f in loop.findings_store.ports))
        self.assertFalse(
            any(
                message.get("role") == "assistant"
                and "Autorisez-vous son installation" in message.get("content", "")
                for message in loop.messages
            )
        )

    def test_permission_denied_stops_and_can_resume_after_retry(self):
        class DeniedToolExecutor:
            def __init__(self):
                self.calls = 0

            def available_tools(self):
                return ()

            def dispatch(self, tool_name, arguments):
                self.calls += 1
                raise PermissionDenied(arguments["command"])

        executor = DeniedToolExecutor()
        llm = FakeLLMClient(
            [
                AgentDecision(
                    thought="Je veux verifier la connectivite.",
                    tool_name="execute_command",
                    arguments={"command": "ping -c 4 8.8.8.8"},
                    final_answer=None,
                    raw_text="",
                ),
                AgentDecision(
                    thought="C'est bon.",
                    tool_name=None,
                    arguments={},
                    final_answer="La connectivite est validee, passe au scan de ports.",
                    raw_text="",
                ),
            ]
        )
        loop = AgentLoop(llm, executor, max_iterations=2)

        initial_events = list(loop.run("ping 8.8.8.8", "Cas actif: basic_penetration"))
        self.assertTrue(any(event["type"] == "tool_denied" for event in initial_events))
        self.assertEqual(initial_events[-1]["type"], "final_answer")

        resumed_events = list(
            loop.resume_after_external_tool(
                "Cas actif: basic_penetration",
                result={
                    "command": "ping -c 4 8.8.8.8",
                    "stdout": "64 bytes from 8.8.8.8",
                    "stderr": "",
                    "returncode": 0,
                },
            )
        )

        self.assertIsNone(loop.pending_external_tool)
        self.assertEqual(resumed_events[-1]["type"], "final_answer")
        self.assertIn("scan de ports", resumed_events[-1]["content"])

    def test_admin_command_can_request_interactive_sudo(self):
        class AdminToolExecutor:
            def available_tools(self):
                return ()

            def dispatch(self, tool_name, arguments):
                raise InteractiveAdminRequired("apt-get update", "sudo apt-get update")

        llm = FakeLLMClient(
            [
                AgentDecision(
                    thought="Je mets a jour le systeme local.",
                    tool_name="execute_admin_command",
                    arguments={"command": "apt update"},
                    final_answer=None,
                    raw_text="",
                )
            ]
        )
        loop = AgentLoop(llm, AdminToolExecutor(), max_iterations=2)

        events = list(loop.run("fais une mise a jour du systeme actuel", "Contexte local"))

        self.assertTrue(any(event["type"] == "tool_admin_required" for event in events))
        self.assertEqual(events[-1]["type"], "final_answer")
        self.assertIn("sudo interactif", events[-1]["content"])

    def test_does_not_auto_advance_to_exploitation_without_scope(self):
        class GuardedToolExecutor:
            def __init__(self):
                self.authorized_scope = set()

            def available_tools(self):
                return ()

            def dispatch(self, tool_name, arguments):
                return {
                    "command": "nikto -h 10.10.10.10",
                    "stdout": "+ /admin/: Directory indexing found.\n",
                    "stderr": "",
                    "returncode": 0,
                }

        llm = FakeLLMClient(
            [
                AgentDecision(
                    thought="Je cherche des vulns web.",
                    tool_name="execute_command",
                    arguments={"command": "nikto -h 10.10.10.10"},
                    final_answer=None,
                    raw_text="",
                ),
                AgentDecision(
                    thought="Stop.",
                    tool_name=None,
                    arguments={},
                    final_answer="Enumeration terminee.",
                    raw_text="",
                ),
            ]
        )
        loop = AgentLoop(llm, GuardedToolExecutor(), max_iterations=3)
        loop.engagement.phase = PentestPhase.ENUMERATION

        events = list(loop.run("cherche des vulns", "Contexte"))

        self.assertEqual(loop.engagement.phase.value, "enumeration")
        self.assertFalse(any(event["type"] == "phase_advance" for event in events))
        guard_thoughts = [event["content"] for event in events if event["type"] == "thought"]
        self.assertTrue(any("/scope" in thought for thought in guard_thoughts))

    def test_policy_block_event_exposes_remediation(self):
        class FakeToolExecutor:
            def __init__(self):
                self.authorized_scope = set()

            def available_tools(self):
                return ()

            def dispatch(self, tool_name, arguments):
                raise ToolPolicyError(
                    "placeholder cible detecte",
                    remediation="Definis la cible active avec /target <ip|url>.",
                    code="placeholder_target",
                )

        llm = FakeLLMClient(
            [
                AgentDecision(
                    thought="Je scanne.",
                    tool_name="scan_target",
                    arguments={"target": "TARGET_IP", "mode": "quick"},
                    final_answer=None,
                    raw_text="",
                ),
                AgentDecision(
                    thought="Je corrige.",
                    tool_name=None,
                    arguments={},
                    final_answer="Il faut definir une cible reelle.",
                    raw_text="",
                ),
            ]
        )
        loop = AgentLoop(llm, FakeToolExecutor(), max_iterations=2)

        events = list(loop.run("scan", "Contexte"))

        policy_events = [event for event in events if event["type"] == "tool_policy_blocked"]
        self.assertEqual(len(policy_events), 1)
        self.assertEqual(policy_events[0]["policy_code"], "placeholder_target")
        self.assertIn("/target", policy_events[0]["remediation"])

    def test_bounded_scan_does_not_chain_enumeration_tool(self):
        class FakeToolExecutor:
            def __init__(self):
                self.authorized_scope = set()
                self.calls = []

            def available_tools(self):
                return ()

            def dispatch(self, tool_name, arguments):
                self.calls.append(tool_name)
                return {
                    "command": "nmap 10.10.10.10",
                    "stdout": "22/tcp   open  ssh\n80/tcp   open  http\n",
                    "stderr": "",
                    "returncode": 0,
                }

        llm = FakeLLMClient(
            [
                AgentDecision(
                    thought="Je scanne.",
                    tool_name="scan_target",
                    arguments={"target": "10.10.10.10", "mode": "quick"},
                    final_answer=None,
                    raw_text="",
                ),
                AgentDecision(
                    thought="Je continue.",
                    tool_name="enumerate_web",
                    arguments={"target": "10.10.10.10", "port": "80"},
                    final_answer=None,
                    raw_text="",
                ),
            ]
        )
        tools = FakeToolExecutor()
        loop = AgentLoop(llm, tools, max_iterations=4)

        events = list(loop.run("Scan the machine, how many ports are open?", "Contexte"))

        self.assertEqual(tools.calls, ["scan_target"])
        self.assertFalse(any(event.get("name") == "enumerate_web" for event in events))
        self.assertEqual(events[-1]["type"], "final_answer")
        self.assertIn("Nombre de ports ouverts: 2", events[-1]["content"])
