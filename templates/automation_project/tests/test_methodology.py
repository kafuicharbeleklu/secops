"""Tests for methodology module."""

import unittest

from app.methodology import EngagementState, PentestPhase, parse_phase


class FakeFinding:
    def __init__(self, ftype):
        self.finding_type = type("FT", (), {"value": ftype})()


class TestParsephase(unittest.TestCase):
    def test_recon(self):
        self.assertEqual(parse_phase("recon"), PentestPhase.RECON)

    def test_reconnaissance(self):
        self.assertEqual(parse_phase("reconnaissance"), PentestPhase.RECON)

    def test_enum(self):
        self.assertEqual(parse_phase("enum"), PentestPhase.ENUMERATION)

    def test_exploit(self):
        self.assertEqual(parse_phase("exploit"), PentestPhase.EXPLOITATION)

    def test_post(self):
        self.assertEqual(parse_phase("post"), PentestPhase.POST_EXPLOITATION)

    def test_report(self):
        self.assertEqual(parse_phase("rapport"), PentestPhase.REPORTING)

    def test_unknown(self):
        self.assertIsNone(parse_phase("unknown"))

    def test_case_insensitive(self):
        self.assertEqual(parse_phase("RECON"), PentestPhase.RECON)


class TestEngagementState(unittest.TestCase):
    def test_initial_phase(self):
        state = EngagementState()
        self.assertEqual(state.phase, PentestPhase.RECON)

    def test_advance_phase(self):
        state = EngagementState()
        new = state.advance_phase("ports found")
        self.assertEqual(new, PentestPhase.ENUMERATION)
        self.assertEqual(state.phase, PentestPhase.ENUMERATION)
        self.assertEqual(len(state.phase_history), 1)

    def test_advance_from_reporting_returns_none(self):
        state = EngagementState(phase=PentestPhase.REPORTING)
        self.assertIsNone(state.advance_phase())

    def test_set_phase(self):
        state = EngagementState()
        state.set_phase(PentestPhase.EXPLOITATION, "skip")
        self.assertEqual(state.phase, PentestPhase.EXPLOITATION)
        self.assertEqual(len(state.phase_history), 1)

    def test_set_same_phase_noop(self):
        state = EngagementState()
        state.set_phase(PentestPhase.RECON)
        self.assertEqual(len(state.phase_history), 0)

    def test_record_tool_use(self):
        state = EngagementState()
        state.record_tool_use("nmap")
        state.record_tool_use("nmap")
        self.assertEqual(state.tools_used, ["nmap"])

    def test_should_suggest_advance_recon_with_ports(self):
        state = EngagementState(phase=PentestPhase.RECON)
        findings = [FakeFinding("port")]
        self.assertTrue(state.should_suggest_advance(findings))

    def test_should_suggest_advance_recon_no_findings(self):
        state = EngagementState(phase=PentestPhase.RECON)
        self.assertFalse(state.should_suggest_advance([]))

    def test_should_suggest_advance_enum_with_vuln(self):
        state = EngagementState(phase=PentestPhase.ENUMERATION)
        findings = [FakeFinding("vulnerability")]
        self.assertTrue(state.should_suggest_advance(findings))

    def test_should_not_advance_reporting(self):
        state = EngagementState(phase=PentestPhase.REPORTING)
        self.assertFalse(state.should_suggest_advance([FakeFinding("port")]))

    def test_phase_context_prompt(self):
        state = EngagementState()
        prompt = state.phase_context_prompt()
        self.assertIn("RECONNAISSANCE", prompt)

    def test_phase_context_with_findings(self):
        state = EngagementState()
        prompt = state.phase_context_prompt("port: 22, 80")
        self.assertIn("22", prompt)

    def test_phase_label(self):
        state = EngagementState()
        self.assertEqual(state.phase_label, "Reconnaissance")

    def test_phase_guard_requires_scope_for_exploitation(self):
        message = EngagementState.phase_guard_message(
            PentestPhase.EXPLOITATION,
            has_scope=False,
            confirmed=False,
        )
        self.assertIn("/scope", message)

    def test_phase_guard_requires_confirmation_for_exploitation(self):
        message = EngagementState.phase_guard_message(
            PentestPhase.EXPLOITATION,
            has_scope=True,
            confirmed=False,
        )
        self.assertIn("confirm", message)

    def test_phase_guard_not_required_for_enumeration(self):
        message = EngagementState.phase_guard_message(
            PentestPhase.ENUMERATION,
            has_scope=False,
            confirmed=False,
        )
        self.assertEqual(message, "")


if __name__ == "__main__":
    unittest.main()
