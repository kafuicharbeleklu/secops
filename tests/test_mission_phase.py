from __future__ import annotations

import unittest

from secops_agent.core.mission import (
    Credential,
    Finding,
    Host,
    MissionContext,
    PentestPhase,
    Service,
)
from secops_agent.core.result_parser import ToolResultParser


NMAP_WITH_FINDING = """Nmap scan report for scanme.example
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.49
"""


class MissionPhaseTests(unittest.TestCase):
    def test_refresh_phase_progresses_from_scope_to_recon(self):
        mission = MissionContext(name="phase test")

        changed = mission.refresh_phase_from_state()
        self.assertFalse(changed)
        self.assertEqual(mission.phase, PentestPhase.SCOPING)

        mission.add_target("example.com", "domain")
        changed = mission.refresh_phase_from_state()

        self.assertTrue(changed)
        self.assertEqual(mission.phase, PentestPhase.RECON)
        self.assertIn("reconnaissance", mission.phase_reason.lower())
        self.assertEqual(mission.phase_history[-1].from_phase, "scoping")
        self.assertEqual(mission.phase_history[-1].to_phase, "recon")

    def test_services_move_phase_to_enumeration(self):
        mission = MissionContext(name="phase test")
        mission.add_target("10.10.10.5")
        mission.add_host(Host(ip="10.10.10.5"))
        mission.add_service(Service(host="10.10.10.5", port=22, service="ssh"))

        mission.refresh_phase_from_state()

        self.assertEqual(mission.phase, PentestPhase.ENUMERATION)
        self.assertIn("open services", mission.phase_reason.lower())

    def test_actionable_finding_moves_phase_to_vulnerability(self):
        mission = MissionContext(name="phase test")
        mission.add_service(Service(host="10.10.10.5", port=80, service="http"))
        mission.add_finding(
            title="Missing security headers",
            severity="low",
            category="headers",
            target="http://example.com",
            tool_used="http_headers",
        )

        mission.refresh_phase_from_state()

        self.assertEqual(mission.phase, PentestPhase.VULNERABILITY)
        self.assertIn("actionable findings", mission.phase_reason.lower())

    def test_reference_findings_do_not_trigger_vulnerability_phase(self):
        mission = MissionContext(name="phase test")
        mission.add_target("example.com", "domain")
        mission.add_finding(
            title="CVE-2021-41773 reference",
            severity="critical",
            category="cve_reference",
            target="CVE-2021-41773",
            tool_used="cve_lookup",
        )

        mission.refresh_phase_from_state()

        self.assertEqual(mission.phase, PentestPhase.RECON)
        self.assertNotIn("vulnerability", mission.phase.value)

    def test_credentials_move_phase_to_post_exploitation(self):
        mission = MissionContext(name="phase test")
        mission.credentials.append(
            Credential(username="alice", secret="redacted", host="10.10.10.5", service="ssh")
        )

        mission.refresh_phase_from_state()

        self.assertEqual(mission.phase, PentestPhase.POST_EXPLOITATION)
        self.assertIn("credentials", mission.phase_reason.lower())

    def test_refresh_does_not_regress_phase_by_default(self):
        mission = MissionContext(name="phase test")
        mission.transition_phase(PentestPhase.VULNERABILITY, "manual validation in progress")

        changed = mission.refresh_phase_from_state()

        self.assertFalse(changed)
        self.assertEqual(mission.phase, PentestPhase.VULNERABILITY)
        self.assertEqual(mission.phase_reason, "manual validation in progress")

    def test_parser_updates_phase_after_structured_result(self):
        mission = MissionContext(name="phase test")
        parser = ToolResultParser(mission=mission)

        parser.parse("nmap_scan", NMAP_WITH_FINDING, {"target": "10.10.10.5"})

        self.assertEqual(mission.phase, PentestPhase.VULNERABILITY)
        self.assertEqual(len(mission.services), 1)
        self.assertEqual(len(mission.findings), 1)
        self.assertIn("actionable findings", mission.phase_reason.lower())

    def test_prompt_summary_includes_phase_reason(self):
        mission = MissionContext(name="phase test")
        mission.add_target("example.com", "domain")
        mission.refresh_phase_from_state()

        summary = mission.build_prompt_summary()

        self.assertIn("Phase reason", summary)
        self.assertIn("reconnaissance", summary.lower())


if __name__ == "__main__":
    unittest.main()
