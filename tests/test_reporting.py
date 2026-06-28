from __future__ import annotations

import unittest
from datetime import datetime, timezone

from secops_agent.core.mission import Evidence, Finding, Host, MissionContext, Service
from secops_agent.core.reporting import PentestReportGenerator, generate_pentest_report


class ReportingTests(unittest.TestCase):
    def _mission(self) -> MissionContext:
        mission = MissionContext(name="Acme External Assessment")
        mission.started_at = "2026-06-01T12:00:00"
        mission.add_target("example.com", "domain")
        mission.scope.out_of_scope.append("admin.example.com")
        mission.scope.rules.append("Passive recon before active validation.")
        mission.completed_objectives.append("Mapped HTTP service exposure.")
        mission.blocked_reasons.append("Target is outside authorized scope: admin.example.com")
        mission.add_host(Host(ip="93.184.216.34", hostname="example.com"))
        mission.add_service(Service(
            host="93.184.216.34",
            port=443,
            protocol="tcp",
            service="https",
            version="Apache httpd 2.4.49",
        ))
        mission.add_finding(
            title="SQL Injection in 'id'",
            severity="critical",
            category="sqli",
            target="https://example.com/item?id=1",
            evidence="Parameter: id, Type: boolean-based blind",
            tool_used="sql_injection_test",
            remediation="Use parameterized queries for the affected endpoint.",
            confirmed=True,
            evidence_items=[
                Evidence(
                    title="SQL Injection in 'id'",
                    source_tool="sql_injection_test",
                    target="https://example.com/item?id=1",
                    snippet="Parameter: id, Type: boolean-based blind",
                    metadata={"parameter": "id", "place": "GET"},
                )
            ],
        )
        mission.add_finding(
            title="Missing security headers",
            severity="low",
            category="headers",
            target="https://example.com",
            evidence="Missing: Strict-Transport-Security",
            tool_used="http_headers",
        )
        return mission

    def test_report_contains_required_sections(self):
        report = PentestReportGenerator().generate_markdown(
            self._mission(),
            generated_at=datetime(2026, 6, 2, 10, 0, tzinfo=timezone.utc),
        )

        self.assertIn("# Acme External Assessment Pentest Report", report)
        self.assertIn("## Executive Summary", report)
        self.assertIn("## Scope", report)
        self.assertIn("## Methodology", report)
        self.assertIn("## Attack Surface", report)
        self.assertIn("## Findings", report)
        self.assertIn("## Remediation Summary", report)
        self.assertIn("## Appendix", report)

    def test_report_renders_findings_evidence_and_remediation(self):
        report = generate_pentest_report(
            self._mission(),
            generated_at=datetime(2026, 6, 2, 10, 0, tzinfo=timezone.utc),
        )

        self.assertIn("### 1. SQL Injection in 'id'", report)
        self.assertIn("- **Severity:** Critical", report)
        self.assertIn("- **Status:** confirmed", report)
        self.assertIn("Metadata: parameter=id, place=GET", report)
        self.assertIn("```text\nParameter: id, Type: boolean-based blind\n```", report)
        self.assertIn("Use parameterized queries for the affected endpoint.", report)
        self.assertIn("### 2. Missing security headers", report)
        self.assertIn("Implement the missing security headers", report)

    def test_report_sorts_findings_by_severity_and_counts(self):
        report = generate_pentest_report(
            self._mission(),
            generated_at=datetime(2026, 6, 2, 10, 0, tzinfo=timezone.utc),
        )

        critical_index = report.index("### 1. SQL Injection")
        low_index = report.index("### 2. Missing security headers")
        self.assertLess(critical_index, low_index)
        self.assertIn("| Critical | 1 |", report)
        self.assertIn("| Low | 1 |", report)
        self.assertIn("Highest recorded severity: Critical.", report)

    def test_report_handles_empty_mission_without_inventing_findings(self):
        mission = MissionContext(name="Empty Assessment")

        report = generate_pentest_report(
            mission,
            generated_at=datetime(2026, 6, 2, 10, 0, tzinfo=timezone.utc),
        )

        self.assertIn("No findings were recorded.", report)
        self.assertIn("No services were recorded.", report)
        self.assertIn("- Not recorded.", report)
        self.assertIn("Highest recorded severity: Informational.", report)

    def test_generate_returns_report_artifact(self):
        generated = PentestReportGenerator().generate(
            self._mission(),
            generated_at=datetime(2026, 6, 2, 10, 0, tzinfo=timezone.utc),
        )

        self.assertEqual(generated.format, "markdown")
        self.assertEqual(generated.title, "Acme External Assessment Pentest Report")
        self.assertIn("## Executive Summary", generated.content)


if __name__ == "__main__":
    unittest.main()
