"""
Unit tests for secops_agent core modules.

Covers:
  - MissionContext phase inference and automatic transitions
  - PermissionEngine tier classification
  - ToolRegistry registration and schema generation
  - ConversationMemory sliding window and budget trimming
  - KnowledgeBase integration
  - ScopeGuard validation
  - MissionPlanner basic action generation
"""

from __future__ import annotations

import json
import pytest
from pathlib import Path

# ── Mission & Phase tests ────────────────────────────────────────────

from secops_agent.core.mission import (
    ActionTraceEntry,
    Credential,
    Finding,
    Host,
    MissionContext,
    PentestPhase,
    PhaseTransition,
    Scope,
    Service,
    Target,
)


# Real phases excluding the internal _phase_order sentinel
_REAL_PHASES = [p for p in PentestPhase if isinstance(p.value, str) and p.value != "None"]


class TestPentestPhase:
    def test_phase_order(self):
        assert _REAL_PHASES[0] == PentestPhase.SCOPING
        assert _REAL_PHASES[-1] == PentestPhase.REPORTING

    def test_rank_ascending(self):
        prev = -1
        for phase in _REAL_PHASES:
            assert phase.rank > prev, f"{phase} rank {phase.rank} <= {prev}"
            prev = phase.rank

    def test_next_phase(self):
        nxt = PentestPhase.SCOPING.next_phase()
        assert nxt == PentestPhase.RECON, f"Expected RECON, got {nxt}"
        nxt2 = PentestPhase.RECON.next_phase()
        assert nxt2 == PentestPhase.ENUMERATION, f"Expected ENUMERATION, got {nxt2}"
        assert PentestPhase.REPORTING.next_phase() is None


class TestMissionContext:
    def _make_mission(self, **kwargs) -> MissionContext:
        return MissionContext(name="test", **kwargs)

    def test_initial_phase_is_scoping(self):
        m = self._make_mission()
        assert m.phase == PentestPhase.SCOPING

    def test_add_target_adds_to_scope(self):
        m = self._make_mission()
        m.add_target("10.10.10.1", "ip")
        assert "10.10.10.1" in m.scope.in_scope
        assert len(m.targets) == 1

    def test_infer_phase_scoping_when_empty(self):
        m = self._make_mission()
        phase, _ = m.infer_phase_from_state()
        assert phase == PentestPhase.SCOPING

    def test_infer_phase_recon_with_targets(self):
        m = self._make_mission()
        m.add_target("10.10.10.1", "ip")
        phase, _ = m.infer_phase_from_state()
        assert phase == PentestPhase.RECON

    def test_infer_phase_enumeration_with_services(self):
        m = self._make_mission()
        m.add_target("10.10.10.1", "ip")
        m.services.append(Service(host="10.10.10.1", port=80, state="open"))
        phase, _ = m.infer_phase_from_state()
        assert phase == PentestPhase.ENUMERATION

    def test_infer_phase_vulnerability_with_findings(self):
        m = self._make_mission()
        m.add_target("10.10.10.1", "ip")
        m.findings.append(Finding(
            title="SQL Injection",
            severity="high",
            target="10.10.10.1",
        ))
        phase, _ = m.infer_phase_from_state()
        assert phase == PentestPhase.VULNERABILITY

    def test_infer_phase_post_exploitation_with_credentials(self):
        m = self._make_mission()
        m.credentials.append(Credential(
            username="admin", secret="pass", host="10.10.10.1", service="ssh",
        ))
        phase, _ = m.infer_phase_from_state()
        assert phase == PentestPhase.POST_EXPLOITATION

    def test_refresh_phase_advances_forward(self):
        m = self._make_mission()
        assert m.phase == PentestPhase.SCOPING
        m.add_target("10.10.10.1", "ip")
        changed = m.refresh_phase_from_state()
        assert changed is True
        assert m.phase == PentestPhase.RECON

    def test_refresh_phase_does_not_regress(self):
        m = self._make_mission()
        m.add_target("10.10.10.1", "ip")
        m.refresh_phase_from_state()
        assert m.phase == PentestPhase.RECON
        # Remove targets but phase should not regress
        m.targets.clear()
        m.scope.in_scope.clear()
        changed = m.refresh_phase_from_state(allow_regression=False)
        assert m.phase == PentestPhase.RECON

    def test_transition_phase_records_history(self):
        m = self._make_mission()
        m.transition_phase(PentestPhase.RECON, "targets defined")
        assert len(m.phase_history) == 1
        assert m.phase_history[0].from_phase == "scoping"
        assert m.phase_history[0].to_phase == "recon"

    def test_serialization_roundtrip(self):
        m = self._make_mission()
        m.add_target("10.10.10.1", "ip")
        m.findings.append(Finding(title="Test", severity="low", target="10.10.10.1"))
        m.add_action_trace(ActionTraceEntry(
            tool_name="nmap_scan",
            arguments={"target": "10.10.10.1", "api_key": "secret"},
            status="succeeded",
            result_summary="Nmap scan found one host.",
            state_changes=["New host: 10.10.10.1"],
        ))
        d = m.to_dict()
        m2 = MissionContext.from_dict(d)
        assert m2.name == m.name
        assert len(m2.targets) == len(m.targets)
        assert len(m2.findings) == len(m.findings)
        assert m2.phase == m.phase
        assert len(m2.action_trace) == 1
        assert m2.action_trace[0].tool_name == "nmap_scan"
        assert m2.action_trace[0].arguments["api_key"] == "***REDACTED***"
        assert m2.action_trace[0].state_changes == ["New host: 10.10.10.1"]

    def test_finding_info_category_does_not_trigger_vulnerability_phase(self):
        """CVE/exploit references should not move phase to VULNERABILITY."""
        m = self._make_mission()
        m.add_target("10.10.10.1", "ip")
        m.findings.append(Finding(
            title="CVE-2021-1234 reference",
            severity="high",
            target="10.10.10.1",
            category="cve_reference",
        ))
        phase, _ = m.infer_phase_from_state()
        # Should stay at RECON, not jump to VULNERABILITY
        assert phase != PentestPhase.VULNERABILITY


# ── Permission tests ─────────────────────────────────────────────────

from secops_agent.core.permissions import (
    ActionTier,
    PermissionDecision,
    TOOL_TIERS,
)


class TestPermissions:
    def test_passive_tools_are_allow(self):
        passive_tools = ["ping_host", "dns_lookup", "nmap_scan", "ssl_check", "cve_lookup"]
        for tool in passive_tools:
            assert TOOL_TIERS.get(tool) == ActionTier.PASSIVE, f"{tool} should be PASSIVE"

    def test_active_tools_require_confirmation(self):
        active_tools = ["dir_brute", "nikto_scan", "sql_injection_test", "run_shell", "generate_payload"]
        for tool in active_tools:
            assert TOOL_TIERS.get(tool) == ActionTier.ACTIVE, f"{tool} should be ACTIVE"

    def test_ffuf_and_nuclei_are_active(self):
        assert TOOL_TIERS.get("ffuf_scan") == ActionTier.ACTIVE
        assert TOOL_TIERS.get("nuclei_scan") == ActionTier.ACTIVE


# ── Tool registry tests ─────────────────────────────────────────────

from secops_agent.core.tools import ToolCategory, ToolRegistry, ToolRiskClass


class TestToolRegistry:
    def test_register_and_retrieve(self):
        registry = ToolRegistry()

        async def test_tool(target: str) -> str:
            return f"scanned {target}"

        registry.register(
            name="test_tool",
            description="A test tool",
            category=ToolCategory.RECON,
            parameters={"target": {"type": "string", "description": "target", "required": True}},
            func=test_tool,
        )

        tool_def = registry.get_tool("test_tool")
        assert tool_def is not None
        assert tool_def.name == "test_tool"
        assert tool_def.category == ToolCategory.RECON

    def test_schema_generation(self):
        registry = ToolRegistry()

        async def schema_test(target: str, ports: str = "") -> str:
            return "ok"

        registry.register(
            name="schema_test",
            description="schema test",
            category=ToolCategory.NETWORK,
            parameters={
                "target": {"type": "string", "description": "Target IP", "required": True},
                "ports": {"type": "string", "description": "Port range", "required": False},
            },
            func=schema_test,
        )

        schemas = registry.get_tools_schema()
        assert len(schemas) >= 1
        found = [s for s in schemas if s["name"] == "schema_test"]
        assert len(found) == 1

    def test_tool_categories_cover_pentest_domains(self):
        expected = {"recon", "network", "web", "exploit", "crypto", "forensics", "osint", "system"}
        actual = {c.value for c in ToolCategory}
        assert expected.issubset(actual)

    def test_risk_class_ordering(self):
        classes = list(ToolRiskClass)
        # R0 should come before R8
        assert classes.index(ToolRiskClass.PURE_LOCAL_COMPUTATION) < classes.index(
            ToolRiskClass.CREDENTIALED_REMOTE_OR_IDENTITY_ACTION
        )


# ── Memory tests ─────────────────────────────────────────────────────

from secops_agent.core.memory import ConversationMemory


class TestConversationMemory:
    def test_sliding_window_enforced(self):
        mem = ConversationMemory(max_messages=5)
        for i in range(10):
            mem.add_user_message(f"msg {i}")
        assert len(mem.messages) == 5
        assert len(mem._archive) == 5

    def test_get_all_messages_includes_archive(self):
        mem = ConversationMemory(max_messages=3)
        for i in range(6):
            mem.add_user_message(f"msg {i}")
        all_msgs = mem.get_all_messages()
        assert len(all_msgs) == 6

    def test_token_estimation(self):
        mem = ConversationMemory()
        mem.add_user_message("a" * 400)  # ~100 tokens
        tokens = mem.estimate_tokens()
        assert tokens == 100

    def test_trim_to_budget(self):
        mem = ConversationMemory()
        for i in range(10):
            mem.add_user_message("x" * 40)  # 10 tokens each
        trimmed = mem.trim_to_budget(30)  # 30 tokens = ~3 messages
        assert len(trimmed) <= 4

    def test_clear(self):
        mem = ConversationMemory(max_messages=3)
        for i in range(5):
            mem.add_user_message(f"msg {i}")
        mem.clear()
        assert len(mem.messages) == 0
        assert len(mem._archive) == 0

    def test_stats(self):
        mem = ConversationMemory()
        mem.add_user_message("hello")
        mem.add_assistant_message("hi")
        mem.add_tool_result("test_tool", "result")
        stats = mem.get_stats()
        assert stats["user_messages"] == 1
        assert stats["assistant_messages"] == 1
        assert stats["tool_messages"] == 1
        assert stats["total_messages"] == 3


# ── KnowledgeBase tests ──────────────────────────────────────────────

from secops_agent.core.structured_memory import KnowledgeBase


class TestKnowledgeBase:
    def test_add_host(self):
        kb = KnowledgeBase()
        changes = kb.add_host(Host(ip="10.10.10.1", os="Linux"))
        assert len(changes) == 1
        assert "New host" in changes[0]

    def test_merge_host(self):
        kb = KnowledgeBase()
        kb.add_host(Host(ip="10.10.10.1"))
        changes = kb.add_host(Host(ip="10.10.10.1", os="Linux"))
        assert any("OS detected" in c for c in changes)

    def test_add_service(self):
        kb = KnowledgeBase()
        svc = Service(host="10.10.10.1", port=80, service="http", version="Apache/2.4")
        changes = kb.add_service(svc)
        assert len(changes) == 1
        assert "New service" in changes[0]

    def test_add_finding(self):
        kb = KnowledgeBase()
        f = Finding(title="XSS in /search", severity="medium", target="10.10.10.1")
        changes = kb.add_finding(f)
        assert len(changes) == 1
        assert "MEDIUM" in changes[0]

    def test_add_credential(self):
        kb = KnowledgeBase()
        cred = Credential(username="admin", secret="admin123", host="10.10.10.1", service="ssh")
        changes = kb.add_credential(cred)
        assert len(changes) == 1
        assert "admin" in changes[0]

    def test_serialization_roundtrip(self):
        kb = KnowledgeBase()
        kb.add_host(Host(ip="10.10.10.1", os="Linux"))
        kb.add_service(Service(host="10.10.10.1", port=22, service="ssh"))
        kb.add_finding(Finding(title="Weak SSH", severity="low", target="10.10.10.1"))
        d = kb.to_dict()
        assert "hosts" in d
        assert "services" in d
        assert "findings" in d


# ── ScopeGuard tests ─────────────────────────────────────────────────

from secops_agent.core.scope_guard import ScopeGuard


class TestScopeGuard:
    def test_in_scope_target_allowed(self):
        mission = MissionContext()
        mission.add_target("10.10.10.1", "ip")
        guard = ScopeGuard(mission)
        result = guard.check_tool_call("nmap_scan", {"target": "10.10.10.1"})
        assert result.allowed is True

    def test_out_of_scope_target_denied(self):
        mission = MissionContext()
        mission.add_target("10.10.10.1", "ip")
        mission.scope.out_of_scope.append("192.168.1.0/24")
        guard = ScopeGuard(mission)
        result = guard.check_tool_call("nmap_scan", {"target": "192.168.1.100"})
        assert result.allowed is False

    def test_reference_tools_always_allowed(self):
        mission = MissionContext()
        mission.add_target("10.10.10.1", "ip")
        guard = ScopeGuard(mission)
        # cve_lookup is reference-only, should always be allowed
        result = guard.check_tool_call("cve_lookup", {"query": "CVE-2021-44228"})
        assert result.allowed is True


# ── Planner tests ────────────────────────────────────────────────────

from secops_agent.core.planner import MissionPlanner, NextAction


class TestMissionPlanner:
    def test_empty_mission_suggests_scoping(self):
        planner = MissionPlanner()
        mission = MissionContext()
        actions = planner.plan(mission)
        assert len(actions) >= 1
        assert any("scope" in a.title.lower() for a in actions)

    def test_target_generates_recon_actions(self):
        planner = MissionPlanner()
        mission = MissionContext()
        mission.add_target("example.com", "domain")
        actions = planner.plan(mission)
        tool_names = {a.tool_name for a in actions}
        assert "dns_lookup" in tool_names
        assert "whois_lookup" in tool_names

    def test_web_service_generates_web_actions(self):
        planner = MissionPlanner()
        mission = MissionContext()
        mission.add_target("10.10.10.1", "ip")
        mission.services.append(Service(
            host="10.10.10.1", port=80, service="http", state="open",
        ))
        actions = planner.plan(mission)
        tool_names = {a.tool_name for a in actions}
        assert "http_headers" in tool_names or "dir_brute" in tool_names

    def test_actions_have_priority_and_risk(self):
        planner = MissionPlanner()
        mission = MissionContext()
        mission.add_target("10.10.10.1", "ip")
        actions = planner.plan(mission)
        for action in actions:
            assert isinstance(action.priority, int)
            assert action.risk in ("low", "medium", "high")

    def test_next_action_key_is_stable(self):
        a1 = NextAction(title="scan", rationale="test", tool_name="nmap_scan",
                        arguments={"target": "10.10.10.1"})
        a2 = NextAction(title="scan", rationale="test", tool_name="nmap_scan",
                        arguments={"target": "10.10.10.1"})
        assert a1.key == a2.key

    def test_prompt_summary_is_nonempty(self):
        planner = MissionPlanner()
        mission = MissionContext()
        mission.add_target("10.10.10.1", "ip")
        summary = planner.build_prompt_summary(mission)
        assert "Suggested" in summary


# ── Reporting tests ──────────────────────────────────────────────────

from secops_agent.core.reporting import PentestReportGenerator


class TestReporting:
    def test_empty_mission_report(self):
        gen = PentestReportGenerator()
        mission = MissionContext(name="Empty Test")
        report = gen.generate_markdown(mission)
        assert "Empty Test" in report
        assert "# " in report

    def test_report_includes_findings(self):
        gen = PentestReportGenerator()
        mission = MissionContext(name="Finding Test")
        mission.findings.append(Finding(
            title="SQL Injection in /login",
            severity="critical",
            target="10.10.10.1",
            evidence="Unauthenticated SQL injection.",
        ))
        report = gen.generate_markdown(mission)
        assert "SQL Injection" in report
        assert "Critical" in report or "critical" in report.lower()

    def test_report_includes_remediation(self):
        gen = PentestReportGenerator()
        mission = MissionContext(name="Remediation Test")
        mission.findings.append(Finding(
            title="Missing Security Headers",
            severity="medium",
            target="10.10.10.1",
            category="headers",
        ))
        report = gen.generate_markdown(mission)
        assert len(report) > 100
