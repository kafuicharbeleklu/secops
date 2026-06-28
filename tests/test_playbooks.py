from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from secops_agent.core.agent import SecOpsAgent
from secops_agent.core.experience import CaseLesson, ExperienceStore, SuggestionSignal
from secops_agent.core.memory import ConversationMemory
from secops_agent.core.mission import Host, MissionContext, Service
from secops_agent.core.permissions import PermissionDecision, PermissionEngine, PermissionResource
from secops_agent.core.planner import MissionPlanner, NextAction
from secops_agent.core.playbooks import (
    PLAYBOOK_SAFETY_CONSTRAINTS,
    TechnicalPlaybook,
    build_technical_playbook,
)
from secops_agent.core.replay_evaluation import (
    ReplayExpectation,
    ReplayScore,
    score_replay_plan,
)
from secops_agent.core.structured_memory import StructuredMemory
from secops_agent.core.tools import ToolCategory, ToolRegistry


def _passing_score(scenario: str = "private-vm-playbook") -> ReplayScore:
    return ReplayScore(
        scenario=scenario,
        stop_point_ok=True,
        evidence_bound=True,
        tool_count_ok=True,
        no_ctf_contamination=True,
        scope_bound=True,
        tool_calls=("nmap_scan",),
        action_tools=("dir_brute",),
        action_methods=(),
        evidence_refs=("Apache httpd 2.4.57",),
        violations=(),
    )


def _reviewed_dir_lesson(**overrides):
    data = {
        "title": "Bounded web content discovery after Apache service discovery",
        "outcome": "success",
        "action_tool_name": "dir_brute",
        "action_arguments": {"url": "http://192.168.56.20"},
        "service_fingerprints": ["Apache httpd"],
        "evidence_refs": ["replay:private-vm:apache-http"],
        "evidence": ["Apache httpd 2.4.57 observed on port 80"],
        "confidence": 0.8,
        "review_status": "reviewed",
    }
    data.update(overrides)
    return CaseLesson(**data)


def _successful_signals(count: int = 2):
    return [
        SuggestionSignal(
            outcome="succeeded",
            action_key=f"dir_brute|success-{index}",
            tool_name="dir_brute",
        )
        for index in range(count)
    ]


def _built_dir_playbook(**lesson_overrides) -> TechnicalPlaybook:
    result = build_technical_playbook(
        _reviewed_dir_lesson(**lesson_overrides),
        [_passing_score()],
        signals=_successful_signals(2),
    )
    if result.playbook is None:
        raise AssertionError(f"expected playbook, got reasons={result.reasons}")
    return result.playbook


def _http_mission(target: str = "192.168.56.20") -> MissionContext:
    mission = MissionContext(name="playbook planner mission")
    mission.add_target(target)
    mission.add_service(Service(
        host=target,
        port=80,
        service="http",
        version="Apache httpd 2.4.57",
        state="open",
    ))
    return mission


class _UnusedLLM:
    model_name = "unused"


class PlaybookTests(unittest.TestCase):
    def test_builds_controlled_playbook_from_reviewed_lesson_replays_and_signals(self):
        lesson = _reviewed_dir_lesson()

        result = build_technical_playbook(
            lesson,
            [_passing_score()],
            signals=_successful_signals(2),
        )

        self.assertTrue(result.eligible, result.reasons)
        assert result.playbook is not None
        playbook = result.playbook
        self.assertEqual(playbook.tool_name, "dir_brute")
        self.assertEqual(playbook.arguments, {"url": "http://192.168.56.20"})
        self.assertEqual(playbook.matched_successes, 2)
        self.assertEqual(playbook.replay_scenarios, ("private-vm-playbook",))
        self.assertEqual(playbook.safety_constraints, PLAYBOOK_SAFETY_CONSTRAINTS)
        self.assertEqual(playbook.risk_class, "r3_active_enumeration")
        self.assertEqual(playbook.required_access, "")
        self.assertGreater(playbook.confidence, lesson.confidence)

    def test_playbook_preserves_risk_and_required_access_from_lesson(self):
        lesson = _reviewed_dir_lesson(
            title="Privilege escalation follow-up after upload shell",
            risk_class="r6_offensive_payload_or_exploit_assistance",
            required_access="user",
        )

        result = build_technical_playbook(
            lesson,
            [_passing_score()],
            signals=_successful_signals(2),
        )

        self.assertTrue(result.eligible, result.reasons)
        assert result.playbook is not None
        self.assertEqual(
            result.playbook.risk_class,
            "r6_offensive_payload_or_exploit_assistance",
        )
        self.assertEqual(result.playbook.required_access, "user")
        self.assertEqual(result.playbook.to_dict()["required_access"], "user")
        self.assertEqual(result.playbook.to_next_action(priority=70).risk, "high")

    def test_playbook_next_action_is_proposal_only_and_keeps_permission_gate(self):
        result = build_technical_playbook(
            _reviewed_dir_lesson(),
            [_passing_score()],
            signals=_successful_signals(2),
        )
        assert result.playbook is not None

        action = result.playbook.to_next_action(priority=72)

        self.assertIsInstance(action, NextAction)
        self.assertEqual(action.tool_name, "dir_brute")
        self.assertTrue(action.requires_approval)
        self.assertEqual(action.priority, 72)
        self.assertIn("normal permission checks", action.rationale)
        self.assertIn("user approval still required", action.experience_details[0]["missing_evidence"])
        self.assertIn("scope and permission checks still apply", action.experience_details[0]["missing_evidence"])

    def test_blocks_playbook_when_lesson_is_not_reviewed(self):
        lesson = _reviewed_dir_lesson(review_status="unreviewed")

        result = build_technical_playbook(
            lesson,
            [_passing_score()],
            signals=_successful_signals(2),
        )

        self.assertFalse(result.eligible)
        self.assertIsNone(result.playbook)
        self.assertIn("lesson is not reviewed", result.reasons)

    def test_blocks_playbook_when_success_signals_are_insufficient(self):
        lesson = _reviewed_dir_lesson()

        result = build_technical_playbook(
            lesson,
            [_passing_score()],
            signals=_successful_signals(1),
        )

        self.assertFalse(result.eligible)
        self.assertIsNone(result.playbook)
        self.assertIn("not enough successful selected actions: 1", result.reasons)

    def test_blocks_playbook_when_replay_fails_scope_or_stop_point(self):
        mission = MissionContext(name="scope negative")
        mission.scope.in_scope.append("10.10.10.5")
        failed_score = score_replay_plan(
            expectation=ReplayExpectation(
                scenario="out-of-scope-playbook",
                forbidden_action_tools=("generate_payload",),
                required_evidence_terms=("authorized",),
            ),
            mission=mission,
            actions=[
                NextAction(
                    title="Generate payload outside scope",
                    rationale="Should be blocked.",
                    tool_name="generate_payload",
                    arguments={"target": "10.10.10.8"},
                )
            ],
            tool_calls=("nmap_scan",),
            evidence_text="authorized scope is 10.10.10.5",
        )

        result = build_technical_playbook(
            _reviewed_dir_lesson(),
            [failed_score],
            signals=_successful_signals(2),
        )

        self.assertFalse(result.eligible)
        self.assertIsNone(result.playbook)
        self.assertTrue(any("failed replay gates" in reason for reason in result.reasons))

    def test_blocks_playbook_without_evidence_references(self):
        lesson = _reviewed_dir_lesson(evidence_refs=[], evidence=[])

        result = build_technical_playbook(
            lesson,
            [_passing_score()],
            signals=_successful_signals(2),
        )

        self.assertFalse(result.eligible)
        self.assertIn("lesson has no evidence references", result.reasons)

    def test_playbook_serialization_does_not_expose_ctf_answers(self):
        lesson = _reviewed_dir_lesson(
            title="root.txt: THM{secretflag}",
            evidence=["user.txt: abc123", "Apache service evidence"],
            evidence_refs=["root.txt: THM{secretflag}"],
        )

        result = build_technical_playbook(
            lesson,
            [_passing_score()],
            signals=_successful_signals(2),
        )
        assert result.playbook is not None
        serialized = str(result.playbook.to_dict())

        self.assertNotIn("THM{secretflag}", serialized)
        self.assertNotIn("abc123", serialized)
        self.assertIn("Apache service evidence", serialized)

    def test_planner_suggests_playbook_only_when_scope_and_service_match(self):
        playbook = _built_dir_playbook()
        mission = _http_mission()
        planner = MissionPlanner(playbooks=[playbook], max_actions=10)

        actions = planner.plan(mission)
        playbook_actions = [action for action in actions if action.phase == "proposal"]
        audit = planner.learning_audit()

        self.assertEqual(len(playbook_actions), 1)
        action = playbook_actions[0]
        self.assertEqual(action.tool_name, "dir_brute")
        self.assertEqual(action.arguments, {"url": "http://192.168.56.20"})
        self.assertTrue(action.requires_approval)
        self.assertEqual(action.experience_details[0]["effect"], "playbook-proposal")
        self.assertEqual(audit[0]["source_type"], "playbook")
        self.assertEqual(audit[0]["status"], "applied")
        self.assertTrue(audit[0]["proposal_only"])
        self.assertTrue(audit[0]["service_match"])

    def test_planner_filters_playbook_when_action_target_is_out_of_scope(self):
        playbook = _built_dir_playbook()
        mission = _http_mission("10.10.10.5")
        planner = MissionPlanner(playbooks=[playbook], max_actions=10)

        actions = planner.plan(mission)
        audit = planner.learning_audit()

        self.assertFalse(any(action.phase == "proposal" for action in actions))
        self.assertEqual(audit[0]["source_type"], "playbook")
        self.assertEqual(audit[0]["status"], "rejected")
        self.assertFalse(audit[0]["scope_allowed"])
        self.assertIn("playbook action target is out of scope", audit[0]["reasons"])

    def test_planner_filters_playbook_without_matching_current_service_evidence(self):
        playbook = _built_dir_playbook()
        mission = MissionContext(name="ssh only mission")
        mission.add_target("192.168.56.20")
        mission.add_service(Service(
            host="192.168.56.20",
            port=22,
            service="ssh",
            version="OpenSSH 9.6",
            state="open",
        ))
        planner = MissionPlanner(playbooks=[playbook], max_actions=10)

        actions = planner.plan(mission)
        audit = planner.learning_audit()

        self.assertFalse(any(action.phase == "proposal" for action in actions))
        self.assertEqual(audit[0]["source_type"], "playbook")
        self.assertEqual(audit[0]["status"], "rejected")
        self.assertFalse(audit[0]["service_match"])
        self.assertIn("service family mismatch", audit[0]["reasons"])

    def test_planner_filters_playbook_when_required_access_is_missing(self):
        playbook = _built_dir_playbook(required_access="user")
        mission = _http_mission()
        planner = MissionPlanner(playbooks=[playbook], max_actions=10)

        actions = planner.plan(mission)
        audit = planner.learning_audit()

        self.assertFalse(any(action.phase == "proposal" for action in actions))
        self.assertEqual(audit[0]["source_type"], "playbook")
        self.assertEqual(audit[0]["status"], "rejected")
        self.assertFalse(audit[0]["access_match"])
        self.assertEqual(audit[0]["required_access"], "user")
        self.assertEqual(audit[0]["current_access"], "none")
        self.assertIn("required access state missing", audit[0]["reasons"])
        self.assertIn("requires user access", audit[0]["missing_evidence"])

    def test_planner_allows_access_gated_playbook_when_shell_exists(self):
        playbook = _built_dir_playbook(required_access="user")
        mission = _http_mission()
        mission.hosts.append(Host(ip="192.168.56.20", access_level="user"))
        planner = MissionPlanner(playbooks=[playbook], max_actions=10)

        actions = planner.plan(mission)
        playbook_actions = [action for action in actions if action.phase == "proposal"]
        audit = planner.learning_audit()

        self.assertEqual(len(playbook_actions), 1)
        self.assertEqual(audit[0]["status"], "applied")
        self.assertTrue(audit[0]["access_match"])
        self.assertEqual(audit[0]["required_access"], "user")
        self.assertEqual(audit[0]["current_access"], "user")

    def test_agent_suggestions_filter_playbook_when_tool_is_not_registered(self):
        playbook = _built_dir_playbook()
        memory = ConversationMemory()
        mission = _http_mission()
        structured_memory = StructuredMemory(conversation=memory, mission=mission)
        agent = SecOpsAgent(
            llm=_UnusedLLM(),
            registry=ToolRegistry(),
            memory=memory,
            structured_memory=structured_memory,
            planner=MissionPlanner(playbooks=[playbook], max_actions=10),
        )

        suggestions = agent._suggested_next_actions(max_actions=10)
        audit = agent.planner.learning_audit()
        playbook_audit = next(entry for entry in audit if entry["source_type"] == "playbook")

        self.assertFalse(any(action.phase == "proposal" for action in suggestions))
        self.assertEqual(playbook_audit["status"], "rejected")
        self.assertFalse(playbook_audit["registry_available"])
        self.assertIn("tool is not registered locally", playbook_audit["reasons"])

    def test_agent_suggestion_signal_records_playbook_audit_context(self):
        playbook = _built_dir_playbook()
        registry = ToolRegistry()

        async def dir_brute(**_):
            return "/admin (Status: 200)"

        registry.register(
            name="dir_brute",
            description="Discover paths",
            category=ToolCategory.WEB,
            parameters={"url": {"type": "string", "required": True}},
            func=dir_brute,
            dangerous=False,
        )
        memory = ConversationMemory()
        mission = _http_mission()
        structured_memory = StructuredMemory(conversation=memory, mission=mission)
        with TemporaryDirectory() as tmpdir:
            store = ExperienceStore(Path(tmpdir) / "case_lessons.jsonl")
            agent = SecOpsAgent(
                llm=_UnusedLLM(),
                registry=registry,
                memory=memory,
                structured_memory=structured_memory,
                planner=MissionPlanner(playbooks=[playbook], max_actions=10),
                experience_store=store,
            )

            suggestions = agent._suggested_next_actions(max_actions=10)
            agent._record_suggestion_batch(suggestions)
            signals = store.load_signals(limit=None)

        playbook_signal = next(signal for signal in signals if signal.tool_name == "dir_brute")
        self.assertEqual(playbook_signal.audit_status, "applied")
        self.assertIn("playbook passed evidence and scope gates", playbook_signal.audit_reasons)

    def test_playbook_proposal_is_never_chained_automatically(self):
        playbook = _built_dir_playbook()
        registry = ToolRegistry()

        async def dir_brute(**_):
            return "/admin (Status: 200)"

        registry.register(
            name="dir_brute",
            description="Discover paths",
            category=ToolCategory.WEB,
            parameters={"url": {"type": "string", "required": True}},
            func=dir_brute,
            dangerous=False,
        )
        permissions = PermissionEngine()
        permissions.remember(
            PermissionResource(kind="tool", name="dir_brute"),
            PermissionDecision.ALLOW,
        )
        memory = ConversationMemory()
        mission = _http_mission()
        structured_memory = StructuredMemory(conversation=memory, mission=mission)
        agent = SecOpsAgent(
            llm=_UnusedLLM(),
            registry=registry,
            memory=memory,
            permissions=permissions,
            structured_memory=structured_memory,
            planner=MissionPlanner(playbooks=[playbook], max_actions=10),
            max_chained_actions_per_turn=3,
            allow_automatic_planner_execution=True,
        )

        suggestions = agent._suggested_next_actions(max_actions=10)
        suggestion_audit = agent.planner.learning_audit()
        playbook_audit = next(entry for entry in suggestion_audit if entry["source_type"] == "playbook")
        chained = agent._build_chained_tool_calls(remaining_budget=3)

        self.assertTrue(any(action.phase == "proposal" for action in suggestions))
        self.assertEqual(playbook_audit["status"], "applied")
        self.assertTrue(playbook_audit["registry_available"])
        self.assertTrue(playbook_audit["proposal_only"])
        self.assertEqual(chained, [])


if __name__ == "__main__":
    unittest.main()
