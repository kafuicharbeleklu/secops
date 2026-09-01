"""PROC-03 — type-to-confirm + default-deny for high-risk (R6-R8) approvals,
from docs/UX_RESEARCH_PROPOSAL_2026-09-01.md.

An offensive/irreversible action (exploit assistance, extension execution,
credentialed remote action) must not default to "Allow once" and must be
confirmed by typing the tool name — so it can't be authorised by a reflexive
Enter.  Lower-risk approvals keep Antigravity's first-action default.
"""
from __future__ import annotations

import unittest

import secops_agent.main  # noqa: F401  # populate the tool registry (risk classes)
from secops_agent.core.permissions import PermissionResource
from secops_agent.ui.tool_display import (
    _approval_default_index,
    _approval_lines,
    _approval_options,
    _approval_risk_tier,
    _is_high_risk_approval,
    _typed_confirmation_matches,
    _typed_confirmation_token,
)

HI = PermissionResource(kind="tool", name="generate_payload")  # r6 exploit assistance
LO = PermissionResource(kind="tool", name="nmap_scan")         # r3 active enumeration


class HighRiskApprovalTests(unittest.TestCase):
    def test_risk_tier_resolves(self):
        self.assertEqual(_approval_risk_tier("generate_payload", HI), 6)
        self.assertEqual(_approval_risk_tier("nmap_scan", LO), 3)
        self.assertIsNone(
            _approval_risk_tier("run_shell", PermissionResource(kind="command", name="ls"))
        )

    def test_high_risk_classification(self):
        self.assertTrue(_is_high_risk_approval("generate_payload", HI))
        self.assertFalse(_is_high_risk_approval("nmap_scan", LO))

    def test_high_risk_defaults_to_deny(self):
        options = _approval_options(HI)
        index = _approval_default_index("generate_payload", HI, options)
        self.assertEqual(options[index][0], "DENY_ONCE")

    def test_low_risk_defaults_to_first_action(self):
        options = _approval_options(LO)
        self.assertEqual(_approval_default_index("nmap_scan", LO, options), 0)

    def test_high_risk_card_requires_typed_confirmation(self):
        options = _approval_options(HI)
        lines = _approval_lines(
            "generate_payload",
            {"target": "x"},
            HI,
            _approval_default_index("generate_payload", HI, options),
            options,
            80,
        )
        rendered = "\n".join(lines)
        self.assertIn("High-risk", rendered)
        self.assertIn("Type 'generate_payload' to confirm", rendered)
        # the deny option carries the cursor; "Allow once" does not
        self.assertRegex(rendered, r">\s*\d+\.\s*No")
        self.assertNotIn("> 1. Allow once", rendered)

    def test_low_risk_card_is_unchanged(self):
        options = _approval_options(LO)
        lines = _approval_lines("nmap_scan", {"target": "127.0.0.1"}, LO, 0, options, 80)
        rendered = "\n".join(lines)
        self.assertNotIn("High-risk", rendered)
        self.assertIn("> 1. Allow once", rendered)

    def test_confirmation_token_and_matching(self):
        self.assertEqual(_typed_confirmation_token("generate_payload", HI), "generate_payload")
        self.assertTrue(_typed_confirmation_matches("generate_payload", " Generate_Payload "))
        self.assertFalse(_typed_confirmation_matches("generate_payload", "yes"))


if __name__ == "__main__":
    unittest.main()
