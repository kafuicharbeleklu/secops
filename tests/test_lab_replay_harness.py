from __future__ import annotations

import unittest
from dataclasses import dataclass

from secops_agent.core.agent import SuggestedActionsEvent, ToolCallEvent, ToolResultEvent
from secops_agent.core.experience import CaseLesson, SuggestionSignal
from secops_agent.core.mission import MissionContext, PentestPhase
from secops_agent.core.planner import MissionPlanner, NextAction
from secops_agent.core.reporting import generate_pentest_report
from secops_agent.core.replay_evaluation import (
    ReplayExpectation,
    evaluate_learning_gate,
    score_replay_events,
    score_replay_plan,
)
from secops_agent.core.result_parser import ToolResultParser
from secops_agent.core.structured_memory import StructuredMemory
from secops_agent.core.tools import ToolResult


@dataclass(frozen=True)
class ReplayStep:
    tool_name: str
    arguments: dict
    output: str


@dataclass(frozen=True)
class ReplayFixture:
    platform: str
    name: str
    target: str
    target_type: str
    steps: tuple[ReplayStep, ...]


@dataclass
class ReplayResult:
    fixture: ReplayFixture
    mission: MissionContext
    actions: list[NextAction]
    report: str


ROOTME_REPLAY = ReplayFixture(
    platform="RootMe",
    name="RootMe-like upload and SUID path",
    target="10.129.153.73",
    target_type="ip",
    steps=(
        ReplayStep(
            "nmap_scan",
            {"target": "10.129.153.73"},
            """Nmap scan report for 10.129.153.73
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13
80/tcp open  http    Apache httpd 2.4.41
""",
        ),
        ReplayStep(
            "dir_brute",
            {"url": "http://10.129.153.73"},
            """/uploads (Status: 301) [Size: 313]
/panel (Status: 301) [Size: 311]
""",
        ),
        ReplayStep(
            "run_shell",
            {"command": "find / -perm -4000 -type f 2>/dev/null"},
            """/usr/bin/passwd
/usr/bin/sudo
/usr/bin/python
[Exit Code: 0]
""",
        ),
    ),
)


ROOTME_HOST_DISCOVERY_REPLAY = ReplayFixture(
    platform="RootMe",
    name="RootMe-like host discovery retry",
    target="10.129.153.73",
    target_type="ip",
    steps=(
        ReplayStep(
            "nmap_scan",
            {"target": "10.129.153.73"},
            """Starting Nmap 7.98 ( https://nmap.org ) at 2026-06-02 21:24 +0000
Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
Nmap done: 1 IP address (0 hosts up) scanned in 2.26 seconds
""",
        ),
    ),
)


ROOTME_EMPTY_CONTENT_REPLAY = ReplayFixture(
    platform="RootMe",
    name="RootMe-like empty content discovery",
    target="10.129.153.73",
    target_type="ip",
    steps=(
        ReplayStep(
            "nmap_scan",
            {"target": "10.129.153.73"},
            """Nmap scan report for 10.129.153.73
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41
""",
        ),
        ReplayStep(
            "dir_brute",
            {"url": "http://10.129.153.73"},
            "No results.",
        ),
    ),
)


HTB_REPLAY = ReplayFixture(
    platform="HackTheBox",
    name="HTB-like service and source disclosure path",
    target="10.10.10.5",
    target_type="ip",
    steps=(
        ReplayStep(
            "nmap_scan",
            {"target": "10.10.10.5"},
            """Nmap scan report for 10.10.10.5
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 8.9p1
80/tcp  open  http    nginx 1.18.0
445/tcp open  microsoft-ds Samba smbd 4.15
""",
        ),
        ReplayStep(
            "dir_brute",
            {"url": "http://10.10.10.5"},
            """/admin (Status: 200) [Size: 1234]
.git [Status: 200, Size: 321, Words: 10, Lines: 5]
""",
        ),
    ),
)


HTB_TIMEOUT_REPLAY = ReplayFixture(
    platform="HackTheBox",
    name="HTB-like content discovery timeout",
    target="10.10.10.5",
    target_type="ip",
    steps=(
        ReplayStep(
            "nmap_scan",
            {"target": "10.10.10.5"},
            """Nmap scan report for 10.10.10.5
PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.18.0
""",
        ),
        ReplayStep(
            "dir_brute",
            {"url": "http://10.10.10.5"},
            "Tool execution timed out after 305s.",
        ),
    ),
)


TRYHACKME_REPLAY = ReplayFixture(
    platform="TryHackMe",
    name="TryHackMe-like vulnerable Apache path",
    target="10.10.10.20",
    target_type="ip",
    steps=(
        ReplayStep(
            "nmap_scan",
            {"target": "10.10.10.20"},
            """Nmap scan report for 10.10.10.20
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.49
""",
        ),
        ReplayStep(
            "nikto_scan",
            {"url": "http://10.10.10.20"},
            """+ Server: Apache/2.4.49
+ /cgi-bin/: Directory indexing found.
+ The X-Content-Type-Options header is not defined.
""",
        ),
    ),
)


TRYHACKME_READINESS_REPLAY = ReplayFixture(
    platform="TryHackMe",
    name="TryHackMe-like missing local readiness tools",
    target="10.10.10.20",
    target_type="ip",
    steps=(
        ReplayStep(
            "lab_setup_check",
            {"provider": "tryhackme", "target": "10.10.10.20"},
            """Local Lab Setup: TryHackMe

Tools:
  nmap: not installed
  curl: /usr/bin/curl
  gobuster: not installed
  dirb: not installed
  openvpn: not installed
  python3: /usr/bin/python3
""",
        ),
    ),
)


PORTSWIGGER_REPLAY = ReplayFixture(
    platform="PortSwigger",
    name="PortSwigger-like SQL injection lab",
    target="https://academy.example/lab",
    target_type="url",
    steps=(
        ReplayStep(
            "http_headers",
            {"url": "https://academy.example/lab"},
            """HTTP/1.1 200 OK
Server: lab-server
Content-Type: text/html
""",
        ),
        ReplayStep(
            "sql_injection_test",
            {"url": "https://academy.example/lab/filter?category=Pets"},
            """Parameter: category (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: category=Pets' AND 1=1--
back-end DBMS: PostgreSQL
""",
        ),
    ),
)


GENERIC_CTF_REPLAY = ReplayFixture(
    platform="Generic CTF",
    name="Timed CTF hidden config path",
    target="http://challenge.local",
    target_type="url",
    steps=(
        ReplayStep(
            "dir_brute",
            {"url": "http://challenge.local"},
            """/backup (Status: 200) [Size: 2048]
/.env (Status: 200) [Size: 128]
/api (Status: 200) [Size: 512]
""",
        ),
    ),
)


PRIVATE_VM_REPLAY = ReplayFixture(
    platform="Private VM",
    name="Private lab VM service discovery",
    target="192.168.56.20",
    target_type="ip",
    steps=(
        ReplayStep(
            "nmap_scan",
            {"target": "192.168.56.20"},
            """Nmap scan report for 192.168.56.20
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.3p1 Ubuntu
80/tcp open  http    Apache httpd 2.4.57
""",
        ),
    ),
)


AUTHORIZED_CLIENT_REPLAY = ReplayFixture(
    platform="Authorized Client",
    name="Authorized client web enumeration",
    target="https://portal.client.test",
    target_type="url",
    steps=(
        ReplayStep(
            "http_headers",
            {"url": "https://portal.client.test"},
            """HTTP/1.1 200 OK
Server: nginx
X-Frame-Options: DENY
Content-Type: text/html
""",
        ),
        ReplayStep(
            "dir_brute",
            {"url": "https://portal.client.test"},
            """/login (Status: 200) [Size: 1420]
/assets (Status: 301) [Size: 178]
""",
        ),
    ),
)


def _replay(fixture: ReplayFixture) -> ReplayResult:
    mission = MissionContext(name=f"{fixture.platform} replay")
    mission.add_target(fixture.target, fixture.target_type)
    memory = StructuredMemory(mission=mission)
    parser = ToolResultParser(mission=mission)

    for step in fixture.steps:
        parsed = parser.parse(step.tool_name, step.output, step.arguments)
        memory.knowledge.integrate(parsed)
        memory.sync_to_mission()

    actions = MissionPlanner(max_actions=30).plan(mission)
    report = generate_pentest_report(mission, title=f"{fixture.platform} Replay Report")
    return ReplayResult(fixture=fixture, mission=mission, actions=actions, report=report)


def _score(result: ReplayResult, expectation: ReplayExpectation):
    return score_replay_plan(
        expectation=expectation,
        mission=result.mission,
        actions=result.actions,
        tool_calls=result.fixture.steps,
        evidence_text=result.report,
    )


class MultiPlatformLabReplayHarnessTests(unittest.TestCase):
    def test_rootme_replay_covers_scan_hidden_upload_suid_and_report(self):
        result = _replay(ROOTME_REPLAY)
        categories = {finding.category for finding in result.mission.findings}
        methods = {action.method for action in result.actions}
        titles = " ".join(action.title for action in result.actions)

        self.assertEqual(result.mission.phase, PentestPhase.VULNERABILITY)
        self.assertIn("dir_enum", categories)
        self.assertIn("suid_binary", categories)
        self.assertIn("upload_surface_validation", methods)
        self.assertIn("suid_privilege_escalation_review", methods)
        self.assertIn("/uploads", result.report)
        self.assertIn("/panel", result.report)
        self.assertIn("Unusual SUID binary: /usr/bin/python", result.report)
        self.assertIn("Remove unintended SUID bits", result.report)
        self.assertNotIn("reverse shell", titles.casefold())

    def test_rootme_host_discovery_failure_proposes_pn_without_web_chain(self):
        result = _replay(ROOTME_HOST_DISCOVERY_REPLAY)
        categories = {finding.category for finding in result.mission.findings}
        tools = {action.tool_name for action in result.actions}
        pn_retry = next(action for action in result.actions if action.method == "host_discovery_retry")

        self.assertEqual(result.mission.phase, PentestPhase.RECON)
        self.assertIn("scan_host_discovery_failed", categories)
        self.assertEqual(pn_retry.arguments["extra_args"], "-Pn")
        self.assertIn("nmap_scan", tools)
        self.assertNotIn("http_headers", tools)
        self.assertNotIn("dir_brute", tools)

    def test_rootme_empty_content_discovery_proposes_bounded_retry(self):
        result = _replay(ROOTME_EMPTY_CONTENT_REPLAY)
        categories = {finding.category for finding in result.mission.findings}
        brute = next(action for action in result.actions if action.method == "content_discovery_retry")

        self.assertIn("content_discovery_empty", categories)
        self.assertEqual(brute.tool_name, "dir_brute")
        self.assertEqual(brute.arguments["extensions"], "php,txt,bak,html")
        self.assertTrue(brute.requires_approval)
        self.assertFalse(any(action.tool_name == "generate_payload" for action in result.actions))

    def test_hackthebox_replay_covers_services_source_disclosure_and_controlled_actions(self):
        result = _replay(HTB_REPLAY)
        tools = {action.tool_name for action in result.actions}
        categories = {finding.category for finding in result.mission.findings}
        methods = {action.method for action in result.actions}

        self.assertGreaterEqual(len(result.mission.services), 3)
        self.assertIn("dir_enum", categories)
        self.assertIn("source_disclosure_review", methods)
        self.assertIn("http_headers", tools)
        self.assertIn("tech_detect", tools)
        self.assertIn("dir_brute", tools)
        self.assertIn("Review SSH exposure", " ".join(action.title for action in result.actions))
        self.assertIn("Interesting path: /.git", result.report)

    def test_hackthebox_timeout_replay_proposes_bounded_recovery(self):
        result = _replay(HTB_TIMEOUT_REPLAY)
        categories = {finding.category for finding in result.mission.findings}
        retry = next(action for action in result.actions if action.method == "timeout_retry")

        self.assertIn("tool_timeout", categories)
        self.assertEqual(retry.tool_name, "dir_brute")
        self.assertEqual(retry.arguments["threads"], 5)
        self.assertTrue(retry.requires_approval)
        self.assertIn("timed out", result.report)

    def test_tryhackme_replay_covers_known_vuln_without_treating_reference_as_access(self):
        result = _replay(TRYHACKME_REPLAY)
        categories = {finding.category for finding in result.mission.findings}
        methods = {action.method for action in result.actions}
        tools = {action.tool_name for action in result.actions}

        self.assertEqual(result.mission.phase, PentestPhase.VULNERABILITY)
        self.assertIn("known_vuln", categories)
        self.assertIn("web_vuln", categories)
        self.assertIn("cve_lookup", tools)
        self.assertIn("directory_listing_review", methods)
        self.assertIn("exploit_feasibility_review", methods)
        self.assertNotEqual(result.mission.phase, PentestPhase.EXPLOITATION)
        self.assertIn("Apache Path Traversal", result.report)

    def test_tryhackme_readiness_replay_proposes_install_steps_without_scan_chain(self):
        result = _replay(TRYHACKME_READINESS_REPLAY)
        missing_tools = {
            finding.evidence_items[0].metadata.get("missing_tool")
            for finding in result.mission.findings
            if finding.category == "tool_prerequisite_missing"
        }
        install_commands = {
            action.arguments.get("command")
            for action in result.actions
            if action.method == "missing_tool_install"
        }

        self.assertEqual(missing_tools, {"gobuster", "nmap", "openvpn"})
        self.assertIn("sudo apt install -y nmap", install_commands)
        self.assertIn("sudo apt install -y gobuster", install_commands)
        self.assertIn("sudo apt install -y openvpn", install_commands)
        self.assertFalse(any(action.tool_name == "nmap_scan" for action in result.actions))

    def test_portswigger_replay_covers_web_lab_sqli_and_payload_proposal(self):
        result = _replay(PORTSWIGGER_REPLAY)
        sqli_actions = [
            action
            for action in result.actions
            if action.tool_name == "generate_payload"
            and action.arguments.get("payload_type") == "sqli"
        ]

        self.assertEqual(result.mission.phase, PentestPhase.VULNERABILITY)
        self.assertTrue(any(finding.category == "sqli" for finding in result.mission.findings))
        self.assertEqual(len(sqli_actions), 1)
        self.assertEqual(sqli_actions[0].method, "payload_generation")
        self.assertTrue(sqli_actions[0].requires_approval)
        self.assertEqual(sqli_actions[0].risk, "high")
        self.assertIn("SQL Injection in 'category'", result.report)

    def test_generic_ctf_replay_covers_hidden_config_paths_without_exploitation_chain(self):
        result = _replay(GENERIC_CTF_REPLAY)
        paths = {
            evidence.metadata.get("path")
            for finding in result.mission.findings
            for evidence in finding.evidence_items
        }

        self.assertEqual(result.mission.phase, PentestPhase.VULNERABILITY)
        self.assertEqual(paths, {"/backup", "/.env", "/api"})
        self.assertTrue(any(action.method == "sensitive_file_exposure_review" for action in result.actions))
        self.assertFalse(any(action.tool_name == "generate_payload" for action in result.actions))
        self.assertIn("Interesting path: /.env", result.report)

    def test_fixture_matrix_keeps_replay_local_and_reportable(self):
        fixtures = [
            ROOTME_REPLAY,
            ROOTME_EMPTY_CONTENT_REPLAY,
            HTB_REPLAY,
            HTB_TIMEOUT_REPLAY,
            TRYHACKME_REPLAY,
            TRYHACKME_READINESS_REPLAY,
            PORTSWIGGER_REPLAY,
            GENERIC_CTF_REPLAY,
            PRIVATE_VM_REPLAY,
            AUTHORIZED_CLIENT_REPLAY,
        ]

        for fixture in fixtures:
            with self.subTest(platform=fixture.platform):
                result = _replay(fixture)
                self.assertTrue(
                    result.mission.findings or result.mission.services or result.mission.hosts
                )
                self.assertTrue(all(finding.evidence_items for finding in result.mission.findings))
                self.assertIn(f"# {fixture.platform} Replay Report", result.report)
                self.assertIn("## Executive Summary", result.report)
                self.assertIn("## Findings", result.report)
                if result.mission.findings:
                    self.assertIn("Structured evidence snippets:", result.report)

    def test_p56_replay_scores_ctf_vm_and_authorized_client_paths(self):
        cases = [
            (
                ROOTME_REPLAY,
                ReplayExpectation(
                    scenario="rootme-scored",
                    max_tool_calls=3,
                    required_tools=("nmap_scan", "dir_brute", "run_shell"),
                    forbidden_action_tools=("generate_payload",),
                    required_action_methods=(
                        "upload_surface_validation",
                        "suid_privilege_escalation_review",
                    ),
                    forbidden_action_methods=("payload_generation",),
                    required_evidence_terms=("/uploads", "/panel", "/usr/bin/python"),
                ),
            ),
            (
                PRIVATE_VM_REPLAY,
                ReplayExpectation(
                    scenario="private-vm-scored",
                    max_tool_calls=1,
                    required_tools=("nmap_scan",),
                    required_action_tools=("http_headers", "tech_detect", "dir_brute"),
                    forbidden_action_tools=("generate_payload",),
                    forbidden_action_methods=("payload_generation",),
                    required_evidence_terms=("OpenSSH 9.3p1", "Apache httpd 2.4.57"),
                ),
            ),
            (
                AUTHORIZED_CLIENT_REPLAY,
                ReplayExpectation(
                    scenario="authorized-client-scored",
                    max_tool_calls=2,
                    required_tools=("http_headers", "dir_brute"),
                    forbidden_action_tools=("generate_payload",),
                    forbidden_action_methods=("payload_generation",),
                    required_evidence_terms=("X-Frame-Options", "/login"),
                ),
            ),
        ]

        for fixture, expectation in cases:
            with self.subTest(scenario=expectation.scenario):
                result = _replay(fixture)
                score = _score(result, expectation)

                self.assertTrue(score.passed, score.violations)
                self.assertTrue(score.stop_point_ok)
                self.assertTrue(score.evidence_bound)
                self.assertTrue(score.tool_count_ok)
                self.assertTrue(score.no_ctf_contamination)
                self.assertTrue(score.scope_bound)

    def test_p56_replay_score_flags_ctf_answer_contamination(self):
        action = NextAction(
            title="Reuse known lab answer /panel",
            rationale="Prior CTF answer said root.txt is there.",
            tool_name="dir_brute",
            arguments={"url": "http://192.168.56.20"},
            experience=["similar prior success: hidden directory was /panel and user.txt was present"],
        )
        mission = MissionContext(name="private VM negative replay")
        mission.add_target("192.168.56.20", "ip")

        score = score_replay_plan(
            expectation=ReplayExpectation(
                scenario="ctf-contamination-negative",
                max_tool_calls=1,
                forbidden_text_terms=("/panel",),
                required_evidence_terms=("Apache",),
            ),
            mission=mission,
            actions=[action],
            tool_calls=["nmap_scan"],
            evidence_text="Apache httpd 2.4.57 observed on port 80",
        )

        self.assertFalse(score.passed)
        self.assertFalse(score.no_ctf_contamination)
        self.assertIn("ctf contamination terms", " ".join(score.violations))

    def test_p56_replay_score_flags_tool_call_after_suggestion_point(self):
        events = [
            ToolCallEvent("nmap_scan", {"target": "10.10.10.5"}, "call_1"),
            ToolResultEvent(
                "nmap_scan",
                ToolResult(True, "PORT   STATE SERVICE VERSION\n80/tcp open http Apache"),
                "call_1",
            ),
            SuggestedActionsEvent(actions=[
                NextAction(
                    title="Analyze HTTP headers",
                    rationale="Confirm metadata.",
                    tool_name="http_headers",
                    arguments={"url": "http://10.10.10.5"},
                )
            ]),
            ToolCallEvent("dir_brute", {"url": "http://10.10.10.5"}, "call_2"),
        ]

        score = score_replay_events(
            events,
            expectation=ReplayExpectation(
                scenario="post-suggestion-tool-negative",
                max_tool_calls=1,
                required_evidence_terms=("Apache",),
            ),
        )

        self.assertFalse(score.passed)
        self.assertFalse(score.stop_point_ok)
        self.assertIn("tool calls after suggestion point", " ".join(score.violations))

    def test_p56_replay_score_flags_out_of_scope_suggestions(self):
        mission = MissionContext(name="client scope negative replay")
        mission.scope.in_scope.append("10.10.10.5")
        action = NextAction(
            title="Scan external host",
            rationale="This should stay outside the authorized scope.",
            tool_name="nmap_scan",
            arguments={"target": "10.10.10.8"},
        )

        score = score_replay_plan(
            expectation=ReplayExpectation(
                scenario="scope-negative",
                required_evidence_terms=("authorized scope",),
            ),
            mission=mission,
            actions=[action],
            evidence_text="authorized scope is 10.10.10.5",
        )

        self.assertFalse(score.passed)
        self.assertFalse(score.scope_bound)
        self.assertIn("out-of-scope action values", " ".join(score.violations))

    def test_p56_learning_gate_requires_reviewed_lesson_replays_and_success_signal(self):
        result = _replay(PRIVATE_VM_REPLAY)
        score = _score(
            result,
            ReplayExpectation(
                scenario="private-vm-promotion",
                max_tool_calls=1,
                required_tools=("nmap_scan",),
                required_action_tools=("http_headers", "tech_detect", "dir_brute"),
                forbidden_action_tools=("generate_payload",),
                required_evidence_terms=("Apache httpd 2.4.57",),
            ),
        )
        lesson = CaseLesson(
            title="HTTP service discovery should lead to bounded web enumeration",
            outcome="success",
            action_tool_name="dir_brute",
            service_fingerprints=["Apache httpd"],
            review_status="reviewed",
        )
        signals = [
            SuggestionSignal(
                outcome="selected",
                action_key="dir_brute|http://192.168.56.20",
                tool_name="dir_brute",
            ),
            SuggestionSignal(
                outcome="succeeded",
                action_key="dir_brute|http://192.168.56.20",
                tool_name="dir_brute",
            ),
        ]

        decision = evaluate_learning_gate(lesson, [score], signals=signals)

        self.assertTrue(decision.eligible, decision.reasons)
        self.assertEqual(decision.replay_count, 1)
        self.assertEqual(decision.matched_successes, 1)

    def test_p56_learning_gate_blocks_failed_replays_or_unreviewed_lessons(self):
        lesson = CaseLesson(
            title="Unreviewed CTF path answer",
            outcome="success",
            action_tool_name="dir_brute",
            endpoint_hints=["/panel"],
        )
        contaminated = score_replay_plan(
            expectation=ReplayExpectation(
                scenario="contaminated-replay",
                forbidden_text_terms=("/panel",),
                required_evidence_terms=("Apache",),
            ),
            actions=[
                NextAction(
                    title="Reuse /panel",
                    rationale="Known CTF answer.",
                    tool_name="dir_brute",
                    arguments={"url": "http://192.168.56.20"},
                    experience=["/panel"],
                )
            ],
            tool_calls=["nmap_scan"],
            evidence_text="Apache service observed",
        )

        decision = evaluate_learning_gate(
            lesson,
            [contaminated],
            signals=[
                SuggestionSignal(
                    outcome="succeeded",
                    action_key="dir_brute|http://192.168.56.20",
                    tool_name="dir_brute",
                )
            ],
        )

        self.assertFalse(decision.eligible)
        self.assertIn("lesson is not reviewed", decision.reasons)
        self.assertTrue(any("failed replay gates" in reason for reason in decision.reasons))


if __name__ == "__main__":
    unittest.main()
