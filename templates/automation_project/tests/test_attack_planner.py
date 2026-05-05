"""Tests for the Attack Graph Planner module."""

import unittest
from unittest.mock import MagicMock

from app.attack_planner import (
    AttackPlan,
    AttackPriority,
    AttackStep,
    StepStatus,
    build_attack_plan,
    format_plan_display,
    format_plan_prompt,
    reconcile_attack_plan,
)
from app.findings import Finding, FindingsStore, FindingType
from app.methodology import EngagementState, PentestPhase


def _make_findings(*specs):
    """Helper to build a FindingsStore from (type, value, source) tuples."""
    store = FindingsStore()
    for ftype, value, source in specs:
        store.add(Finding(finding_type=ftype, value=value, source_tool=source))
    return store


class TestAttackStepDataclass(unittest.TestCase):
    def test_defaults(self):
        step = AttackStep(index=0, name="scan", tool="scan_target")
        self.assertEqual(step.priority, AttackPriority.MEDIUM)
        self.assertEqual(step.status, StepStatus.PENDING)
        self.assertEqual(step.depends_on, [])
        self.assertEqual(step.arguments, {})

    def test_custom_values(self):
        step = AttackStep(
            index=1,
            name="enum web",
            tool="enumerate_web",
            arguments={"target": "10.10.10.10", "port": "80"},
            priority=AttackPriority.HIGH,
            depends_on=[0],
            rationale="Web port open",
        )
        self.assertEqual(step.index, 1)
        self.assertEqual(step.depends_on, [0])


class TestAttackPlan(unittest.TestCase):
    def test_empty_plan(self):
        plan = AttackPlan(target="10.10.10.10")
        self.assertEqual(plan.pending_steps, [])
        self.assertIsNone(plan.next_step)
        self.assertTrue(plan.is_complete)

    def test_next_step_no_deps(self):
        plan = AttackPlan(target="test", steps=[
            AttackStep(index=0, name="scan", tool="scan_target"),
            AttackStep(index=1, name="enum", tool="enumerate_web"),
        ])
        self.assertEqual(plan.next_step.index, 0)

    def test_next_step_with_deps(self):
        plan = AttackPlan(target="test", steps=[
            AttackStep(index=0, name="scan", tool="scan_target"),
            AttackStep(index=1, name="enum", tool="enumerate_web", depends_on=[0]),
        ])
        # Step 1 depends on step 0, so next should be step 0
        self.assertEqual(plan.next_step.index, 0)

        # After marking step 0 done, next should be step 1
        plan.mark_done(0)
        self.assertEqual(plan.next_step.index, 1)

    def test_mark_done(self):
        plan = AttackPlan(target="test", steps=[
            AttackStep(index=0, name="scan", tool="scan_target"),
        ])
        plan.mark_done(0)
        self.assertEqual(plan.steps[0].status, StepStatus.DONE)
        self.assertTrue(plan.is_complete)

    def test_mark_skipped(self):
        plan = AttackPlan(target="test", steps=[
            AttackStep(index=0, name="scan", tool="scan_target"),
        ])
        plan.mark_skipped(0)
        self.assertEqual(plan.steps[0].status, StepStatus.SKIPPED)
        self.assertTrue(plan.is_complete)

    def test_mark_failed(self):
        plan = AttackPlan(target="test", steps=[
            AttackStep(index=0, name="scan", tool="scan_target"),
        ])
        plan.mark_failed(0)
        self.assertEqual(plan.steps[0].status, StepStatus.FAILED)
        self.assertTrue(plan.is_complete)

    def test_progress_summary(self):
        plan = AttackPlan(target="test", steps=[
            AttackStep(index=0, name="a", tool="t"),
            AttackStep(index=1, name="b", tool="t"),
            AttackStep(index=2, name="c", tool="t"),
        ])
        self.assertIn("0/3", plan.progress_summary)
        plan.mark_done(0)
        plan.mark_skipped(1)
        self.assertIn("1/3", plan.progress_summary)
        self.assertIn("1 ignore", plan.progress_summary)

    def test_roundtrip_serialization(self):
        plan = AttackPlan(target="10.10.10.10", phase="enumeration", steps=[
            AttackStep(
                index=0,
                name="Enum web",
                tool="enumerate_web",
                arguments={"target": "10.10.10.10", "port": "80"},
                status=StepStatus.DONE,
            ),
            AttackStep(
                index=1,
                name="Test SSH",
                tool="test_credentials",
                arguments={"target": "10.10.10.10", "service": "ssh"},
                status=StepStatus.FAILED,
            ),
        ])
        restored = AttackPlan.from_dict(plan.to_dict())
        self.assertEqual(restored.target, "10.10.10.10")
        self.assertEqual(restored.steps[0].status, StepStatus.DONE)
        self.assertEqual(restored.steps[1].status, StepStatus.FAILED)

    def test_reconcile_preserves_matching_status(self):
        previous = AttackPlan(target="target", steps=[
            AttackStep(
                index=0,
                name="Enum web",
                tool="enumerate_web",
                arguments={"target": "10.10.10.10", "port": "80"},
                status=StepStatus.DONE,
            ),
        ])
        new_plan = AttackPlan(target="target", steps=[
            AttackStep(
                index=0,
                name="Enum web",
                tool="enumerate_web",
                arguments={"target": "10.10.10.10", "port": "80"},
            ),
            AttackStep(index=1, name="Nikto", tool="execute_command", arguments={"command": "nikto -h 10.10.10.10"}),
        ])
        merged = reconcile_attack_plan(previous, new_plan)
        self.assertEqual(merged.steps[0].status, StepStatus.DONE)
        self.assertEqual(merged.steps[1].status, StepStatus.PENDING)

    def test_is_complete_false(self):
        plan = AttackPlan(target="test", steps=[
            AttackStep(index=0, name="a", tool="t"),
        ])
        self.assertFalse(plan.is_complete)

    def test_next_step_prefers_highest_score_when_available(self):
        plan = AttackPlan(target="test", steps=[
            AttackStep(index=0, name="low value", tool="t", score=20),
            AttackStep(index=1, name="high value", tool="t", score=85),
        ])
        self.assertEqual(plan.next_step.index, 1)


class TestBuildAttackPlan(unittest.TestCase):
    def test_empty_findings_generates_scan(self):
        """With no findings, should suggest initial scan."""
        store = FindingsStore()
        engagement = EngagementState()
        target = MagicMock()
        target.label = "10.10.10.10"
        plan = build_attack_plan(store, target, engagement)
        self.assertEqual(len(plan.steps), 1)
        self.assertEqual(plan.steps[0].tool, "scan_target")
        self.assertEqual(plan.steps[0].priority, AttackPriority.CRITICAL)
        self.assertGreater(plan.steps[0].score, 0)
        self.assertEqual(plan.steps[0].risk, "medium")

    def test_web_port_generates_enumerate_web(self):
        """Open web port should trigger web enumeration."""
        store = _make_findings(
            (FindingType.PORT, "80", "nmap"),
            (FindingType.SERVICE, "80/http Apache httpd 2.4.49", "nmap"),
        )
        engagement = EngagementState()
        target = MagicMock()
        target.label = "10.10.10.10"
        plan = build_attack_plan(store, target, engagement)
        tool_names = [s.tool for s in plan.steps]
        self.assertIn("enumerate_web", tool_names)

    def test_smb_port_generates_enum4linux(self):
        """Open SMB port should trigger SMB enumeration."""
        store = _make_findings(
            (FindingType.PORT, "445", "nmap"),
        )
        engagement = EngagementState()
        target = MagicMock()
        target.label = "10.10.10.10"
        plan = build_attack_plan(store, target, engagement)
        commands = [s.arguments.get("command", "") for s in plan.steps]
        self.assertTrue(any("enum4linux" in cmd for cmd in commands))

    def test_ftp_port_generates_anonymous_test(self):
        """Open FTP port should trigger anonymous access test."""
        store = _make_findings(
            (FindingType.PORT, "21", "nmap"),
        )
        engagement = EngagementState()
        target = MagicMock()
        target.label = "10.10.10.10"
        plan = build_attack_plan(store, target, engagement)
        tool_names = [s.tool for s in plan.steps]
        self.assertIn("test_credentials", tool_names)

    def test_service_with_version_generates_analyze(self):
        """Detected service with version should trigger analyze_service."""
        store = _make_findings(
            (FindingType.PORT, "80", "nmap"),
            (FindingType.SERVICE, "80/Apache 2.4.49", "nmap"),
        )
        engagement = EngagementState()
        target = MagicMock()
        target.label = "10.10.10.10"
        plan = build_attack_plan(store, target, engagement)
        tool_names = [s.tool for s in plan.steps]
        self.assertIn("analyze_service", tool_names)

    def test_wordpress_detection(self):
        """WordPress paths should trigger wpscan."""
        store = _make_findings(
            (FindingType.PORT, "80", "nmap"),
            (FindingType.PATH, "/wp-login.php (200)", "gobuster"),
        )
        engagement = EngagementState()
        target = MagicMock()
        target.label = "10.10.10.10"
        plan = build_attack_plan(store, target, engagement)
        commands = [s.arguments.get("command", "") for s in plan.steps]
        self.assertTrue(any("wpscan" in cmd for cmd in commands))

    def test_no_duplicate_tools(self):
        """Already-used tools should not be repeated in plan."""
        store = _make_findings(
            (FindingType.PORT, "80", "nmap"),
        )
        engagement = EngagementState()
        engagement.record_tool_use("gobuster")
        engagement.record_tool_use("nikto")
        target = MagicMock()
        target.label = "10.10.10.10"
        plan = build_attack_plan(store, target, engagement)
        # enumerate_web uses gobuster+nikto, but those are already used
        # so enumerate_web should NOT appear
        tool_names = [s.tool for s in plan.steps]
        self.assertNotIn("enumerate_web", tool_names)

    def test_no_target_uses_placeholder(self):
        """When no active target, plan uses 'cible' placeholder."""
        store = _make_findings(
            (FindingType.PORT, "22", "nmap"),
        )
        engagement = EngagementState()
        plan = build_attack_plan(store, None, engagement)
        self.assertEqual(plan.target, "cible")

    def test_vulnerability_triggers_searchsploit(self):
        """Existing vulnerabilities should trigger searchsploit."""
        store = _make_findings(
            (FindingType.PORT, "80", "nmap"),
            (FindingType.VULNERABILITY, "XSS detected in /form", "nikto"),
        )
        engagement = EngagementState()
        target = MagicMock()
        target.label = "10.10.10.10"
        plan = build_attack_plan(store, target, engagement)
        tool_names = [s.tool for s in plan.steps]
        self.assertIn("search_exploit", tool_names)

    def test_skip_tcpwrapped_services(self):
        """tcpwrapped services should not trigger analyze_service."""
        store = _make_findings(
            (FindingType.PORT, "80", "nmap"),
            (FindingType.SERVICE, "80/tcpwrapped", "nmap"),
        )
        engagement = EngagementState()
        target = MagicMock()
        target.label = "10.10.10.10"
        plan = build_attack_plan(store, target, engagement)
        tool_names = [s.tool for s in plan.steps]
        self.assertNotIn("analyze_service", tool_names)

    def test_ssh_credentials_use_discovered_values(self):
        """Planner should reuse the real SSH credentials already discovered."""
        store = FindingsStore()
        store.add(Finding(FindingType.PORT, "22", "nmap"))
        store.add(Finding(
            finding_type=FindingType.CREDENTIAL,
            value="ssh://root:toor (port 22)",
            source_tool="hydra",
            confidence="high",
            severity="critical",
            target_ref="10.10.10.10",
            attributes={"service": "ssh", "username": "root", "password": "toor", "port": "22"},
        ))
        engagement = EngagementState()
        target = MagicMock()
        target.label = "10.10.10.10"

        plan = build_attack_plan(store, target, engagement)

        ssh_steps = [s for s in plan.steps if s.tool == "test_credentials" and s.arguments.get("service") == "ssh"]
        self.assertEqual(len(ssh_steps), 1)
        self.assertEqual(ssh_steps[0].arguments["username"], "root")
        self.assertEqual(ssh_steps[0].arguments["password"], "toor")

    def test_smb_credentials_use_discovered_values(self):
        """Planner should reuse the real SMB credentials already discovered."""
        store = FindingsStore()
        store.add(Finding(FindingType.PORT, "445", "nmap"))
        store.add(Finding(
            finding_type=FindingType.CREDENTIAL,
            value="smb://administrator:passw0rd (port 445)",
            source_tool="hydra",
            confidence="high",
            severity="critical",
            target_ref="10.10.10.10",
            attributes={
                "service": "smb",
                "username": "administrator",
                "password": "passw0rd",
                "port": "445",
            },
        ))
        engagement = EngagementState()
        target = MagicMock()
        target.label = "10.10.10.10"

        plan = build_attack_plan(store, target, engagement)

        smb_steps = [s for s in plan.steps if s.tool == "test_credentials" and s.arguments.get("service") == "smb"]
        self.assertEqual(len(smb_steps), 1)
        self.assertEqual(smb_steps[0].arguments["username"], "administrator")
        self.assertEqual(smb_steps[0].arguments["password"], "passw0rd")


class TestFormatPlanPrompt(unittest.TestCase):
    def test_empty_plan(self):
        plan = AttackPlan(target="test")
        self.assertEqual(format_plan_prompt(plan), "")

    def test_format_with_steps(self):
        plan = AttackPlan(target="test", steps=[
            AttackStep(index=0, name="Scan", tool="scan_target", priority=AttackPriority.CRITICAL),
            AttackStep(index=1, name="Enum", tool="enumerate_web", depends_on=[0]),
        ])
        prompt = format_plan_prompt(plan)
        self.assertIn("PLAN D'ATTAQUE", prompt)
        self.assertIn("scan_target", prompt)
        self.assertIn("PROCHAINE ETAPE", prompt)

    def test_format_includes_score_when_available(self):
        plan = AttackPlan(target="test", steps=[
            AttackStep(index=0, name="Scan", tool="scan_target", score=91),
        ])
        prompt = format_plan_prompt(plan)
        self.assertIn("score 91", prompt)

    def test_shows_next_step(self):
        plan = AttackPlan(target="test", steps=[
            AttackStep(index=0, name="Done Step", tool="t", status=StepStatus.DONE),
            AttackStep(index=1, name="Next Step", tool="enumerate_web"),
        ])
        prompt = format_plan_prompt(plan)
        self.assertIn("Next Step", prompt)


class TestFormatPlanDisplay(unittest.TestCase):
    def test_empty_plan(self):
        plan = AttackPlan(target="test")
        lines = format_plan_display(plan)
        self.assertTrue(any("Aucun plan" in line for line in lines))

    def test_display_with_steps(self):
        plan = AttackPlan(target="10.10.10.10", phase="recon", steps=[
            AttackStep(index=0, name="Scan", tool="scan_target"),
        ])
        lines = format_plan_display(plan)
        self.assertTrue(any("10.10.10.10" in line for line in lines))
        self.assertTrue(any("Scan" in line for line in lines))


if __name__ == "__main__":
    unittest.main()
