"""Tests for pdf_report — PDF pentest report generation."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from app.attack_planner import AttackPlan, AttackStep, StepStatus
from app.findings import Finding, FindingType, FindingsStore
from app.methodology import EngagementState, PentestPhase


class TestPdfReportAvailability(unittest.TestCase):
    """Test fpdf2 availability check."""

    def test_fpdf2_available(self):
        from app.pdf_report import _fpdf2_available
        # Should return True if fpdf2 is installed in the venv
        result = _fpdf2_available()
        self.assertIsInstance(result, bool)


class TestPdfReportGeneration(unittest.TestCase):
    """Test PDF report generation."""

    def setUp(self):
        self.tmpdir = TemporaryDirectory()
        self.workspace = Path(self.tmpdir.name)

        # Build a FindingsStore with sample data
        self.store = FindingsStore()
        self.store.add(Finding(FindingType.PORT, "22", "nmap", "high"))
        self.store.add(Finding(FindingType.PORT, "80", "nmap", "high"))
        self.store.add(Finding(FindingType.SERVICE, "22/OpenSSH 8.9p1", "nmap", "high"))
        self.store.add(Finding(FindingType.SERVICE, "80/Apache httpd 2.4.49", "nmap", "high"))
        self.store.add(Finding(FindingType.VULNERABILITY, "Path traversal CVE-2021-41773", "nikto", "high"))
        self.store.add(Finding(FindingType.CREDENTIAL, "ssh://admin:password123 (port 22)", "hydra", "high"))
        self.store.add(Finding(FindingType.PATH, "/admin (200)", "gobuster", "high"))
        self.store.add(Finding(FindingType.OS, "Ubuntu 20.04", "nmap", "medium"))

        self.engagement = EngagementState()
        self.engagement.record_tool_use("nmap")
        self.engagement.record_tool_use("gobuster")
        self.engagement.record_tool_use("nikto")
        self.engagement.advance_phase("Ports decouverts")
        self.engagement.advance_phase("Vulns detectees")

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_generate_pdf_creates_file(self):
        try:
            from app.pdf_report import generate_pdf_report
        except ImportError:
            self.skipTest("fpdf2 not installed")

        output_path = self.workspace / "test_report.pdf"
        result = generate_pdf_report(
            target_summary="10.10.10.10 (lab test)",
            findings_store=self.store,
            engagement_state=self.engagement,
            session_duration_minutes=15,
            output_path=output_path,
        )
        self.assertTrue(output_path.exists())
        self.assertEqual(result, output_path)
        # PDF should be non-empty
        self.assertGreater(output_path.stat().st_size, 100)

    def test_pdf_starts_with_header(self):
        try:
            from app.pdf_report import generate_pdf_report
        except ImportError:
            self.skipTest("fpdf2 not installed")

        output_path = self.workspace / "test_header.pdf"
        generate_pdf_report(
            target_summary="target.htb",
            findings_store=self.store,
            engagement_state=self.engagement,
            session_duration_minutes=5,
            output_path=output_path,
        )
        # PDF magic bytes
        content = output_path.read_bytes()
        self.assertTrue(content.startswith(b"%PDF"))

    def test_generate_pdf_empty_findings(self):
        try:
            from app.pdf_report import generate_pdf_report
        except ImportError:
            self.skipTest("fpdf2 not installed")

        empty_store = FindingsStore()
        output_path = self.workspace / "test_empty.pdf"
        generate_pdf_report(
            target_summary="empty target",
            findings_store=empty_store,
            engagement_state=EngagementState(),
            session_duration_minutes=0,
            output_path=output_path,
        )
        self.assertTrue(output_path.exists())

    def test_generate_pdf_with_audit_logger(self):
        try:
            from app.pdf_report import generate_pdf_report
        except ImportError:
            self.skipTest("fpdf2 not installed")

        from app.audit_logger import AuditLogger

        audit = AuditLogger(self.workspace)
        audit.log_tool_call("nmap", {"command": "nmap -sC 10.10.10.10"}, {"stdout": "ok"})
        audit.log_finding("nmap", 3, "22, 80, 443")

        output_path = self.workspace / "test_audit.pdf"
        generate_pdf_report(
            target_summary="10.10.10.10",
            findings_store=self.store,
            engagement_state=self.engagement,
            session_duration_minutes=10,
            output_path=output_path,
            audit_logger=audit,
        )
        self.assertTrue(output_path.exists())

    def test_generate_pdf_creates_parent_dirs(self):
        try:
            from app.pdf_report import generate_pdf_report
        except ImportError:
            self.skipTest("fpdf2 not installed")

        output_path = self.workspace / "deep" / "nested" / "report.pdf"
        generate_pdf_report(
            target_summary="test",
            findings_store=self.store,
            engagement_state=self.engagement,
            output_path=output_path,
        )
        self.assertTrue(output_path.exists())

    def test_generate_pdf_with_attack_plan(self):
        try:
            from app.pdf_report import generate_pdf_report
        except ImportError:
            self.skipTest("fpdf2 not installed")

        attack_plan = AttackPlan(target="10.10.10.10", phase="enumeration", steps=[
            AttackStep(
                index=0,
                name="Enumeration web",
                tool="enumerate_web",
                status=StepStatus.DONE,
            ),
        ])
        output_path = self.workspace / "test_plan.pdf"
        generate_pdf_report(
            target_summary="test",
            findings_store=self.store,
            engagement_state=self.engagement,
            output_path=output_path,
            attack_plan=attack_plan,
        )
        self.assertTrue(output_path.exists())
        self.assertGreater(output_path.stat().st_size, 100)

    def test_generate_pdf_with_evidence(self):
        try:
            from app.pdf_report import generate_pdf_report
        except ImportError:
            self.skipTest("fpdf2 not installed")

        self.store.add(Finding(
            finding_type=FindingType.VULNERABILITY,
            value="Configuration leak",
            source_tool="nikto",
            confidence="high",
            raw_output="db_password=secret123",
            severity="high",
            target_ref="10.10.10.10",
            attributes={"password": "secret123"},
        ))
        output_path = self.workspace / "test_evidence.pdf"
        generate_pdf_report(
            target_summary="test",
            findings_store=self.store,
            engagement_state=self.engagement,
            output_path=output_path,
        )
        self.assertTrue(output_path.exists())
        self.assertGreater(output_path.stat().st_size, 100)


class TestPdfHelpers(unittest.TestCase):
    """Test PDF helper functions in isolation."""

    def test_severity_order(self):
        from app.pdf_report import SEVERITY_ORDER
        self.assertLess(SEVERITY_ORDER["critical"], SEVERITY_ORDER["high"])
        self.assertLess(SEVERITY_ORDER["high"], SEVERITY_ORDER["medium"])
        self.assertLess(SEVERITY_ORDER["medium"], SEVERITY_ORDER["low"])


if __name__ == "__main__":
    unittest.main()
