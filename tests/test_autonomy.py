from __future__ import annotations

import unittest

from secops_agent.core.autonomy import AutonomyLevel, AutonomyPolicy
from secops_agent.core.request_context import (
    EnvironmentHint,
    RequestDecision,
    RequestRisk,
    UserIntent,
)


def _decision(risk: RequestRisk, intent: UserIntent = UserIntent.UNKNOWN) -> RequestDecision:
    return RequestDecision(risk=risk, user_intent=intent)


class AutonomyPolicySchemaExposureTests(unittest.TestCase):
    def test_low_risk_schemas_always_exposed(self):
        policy = AutonomyPolicy()  # default RISK_BASED
        for risk in (RequestRisk.PASSIVE, RequestRisk.ACTIVE_LOW, RequestRisk.ACTIVE_HIGH):
            self.assertTrue(policy.exposes_tool_schemas(_decision(risk)))

    def test_exploit_schemas_withheld_without_approval(self):
        policy = AutonomyPolicy()
        self.assertFalse(policy.exposes_tool_schemas(_decision(RequestRisk.EXPLOIT)))
        self.assertFalse(policy.exposes_tool_schemas(_decision(RequestRisk.DESTRUCTIVE)))

    def test_exploit_schemas_exposed_after_approval(self):
        policy = AutonomyPolicy()
        for intent in (UserIntent.APPROVED_BATCH, UserIntent.EXECUTE_SELECTED):
            self.assertTrue(policy.exposes_tool_schemas(_decision(RequestRisk.EXPLOIT, intent)))

    def test_sandbox_exposes_high_risk_unconditionally(self):
        policy = AutonomyPolicy(level=AutonomyLevel.SANDBOX)
        self.assertTrue(policy.exposes_tool_schemas(_decision(RequestRisk.EXPLOIT)))
        self.assertTrue(policy.exposes_tool_schemas(_decision(RequestRisk.DESTRUCTIVE)))


class AutonomyPolicyPauseTests(unittest.TestCase):
    def test_risk_based_pauses_on_high_risk_only(self):
        policy = AutonomyPolicy()  # RISK_BASED
        self.assertFalse(policy.pauses_for(RequestRisk.ACTIVE_LOW))
        self.assertTrue(policy.pauses_for(RequestRisk.EXPLOIT))
        self.assertTrue(policy.pauses_for(RequestRisk.DESTRUCTIVE))

    def test_copilot_pauses_on_everything(self):
        policy = AutonomyPolicy(level=AutonomyLevel.COPILOT)
        self.assertTrue(policy.pauses_for(RequestRisk.PASSIVE))
        self.assertTrue(policy.pauses_for(RequestRisk.EXPLOIT))

    def test_supervised_pauses_on_destructive_only(self):
        policy = AutonomyPolicy(level=AutonomyLevel.SUPERVISED)
        self.assertFalse(policy.pauses_for(RequestRisk.EXPLOIT))
        self.assertTrue(policy.pauses_for(RequestRisk.DESTRUCTIVE))

    def test_sandbox_never_pauses(self):
        policy = AutonomyPolicy(level=AutonomyLevel.SANDBOX)
        self.assertFalse(policy.pauses_for(RequestRisk.DESTRUCTIVE))


class AutonomyPolicyEnvironmentTests(unittest.TestCase):
    def test_lab_and_ctf_escalate_to_supervised(self):
        for hint in (EnvironmentHint.CTF_ONLINE, EnvironmentHint.PRIVATE_LAB):
            self.assertEqual(AutonomyPolicy.for_environment(hint).level, AutonomyLevel.SUPERVISED)

    def test_unknown_and_org_stay_risk_based(self):
        for hint in (EnvironmentHint.UNKNOWN, EnvironmentHint.AUTHORIZED_ORG):
            self.assertEqual(AutonomyPolicy.for_environment(hint).level, AutonomyLevel.RISK_BASED)


class AutonomyPostureLabelTests(unittest.TestCase):
    """G4 / P1-4: the active posture must be surfaceable as a short human label.
    This is display-only and must not alter the gating behaviour."""

    def test_each_level_has_a_human_label(self):
        labels = {
            AutonomyLevel.COPILOT: "copilote",
            AutonomyLevel.RISK_BASED: "semi-auto",
            AutonomyLevel.SUPERVISED: "supervisé",
            AutonomyLevel.SANDBOX: "sandbox",
        }
        for level, expected in labels.items():
            with self.subTest(level=level):
                self.assertEqual(AutonomyPolicy(level=level).label, expected)

    def test_label_does_not_change_gating(self):
        # Reading the label must not weaken the safety gate (invariant).
        policy = AutonomyPolicy()  # RISK_BASED
        _ = policy.label
        self.assertFalse(policy.exposes_tool_schemas(_decision(RequestRisk.EXPLOIT)))
        self.assertTrue(policy.pauses_for(RequestRisk.DESTRUCTIVE))


if __name__ == "__main__":
    unittest.main()
