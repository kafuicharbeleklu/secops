"""Tests for the analyze_service exploit matching pipeline."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

from app.cve_lookup import CVEEntry
from app.findings import FindingsStore, FindingType
from app.knowledge_store import KnowledgeStore
from app.tool_executor import ToolExecutionError, ToolExecutor
from app.tool_registry import ToolRegistry


def _make_executor(tmpdir, **kwargs):
    workspace = Path(tmpdir) / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    knowledge_root = Path(tmpdir) / "knowledge"
    knowledge_root.mkdir(parents=True, exist_ok=True)
    store = KnowledgeStore(knowledge_root, [])
    return ToolExecutor(
        workspace=workspace,
        knowledge_root=knowledge_root,
        knowledge_store=store,
        command_permission_mode="session",
        tool_registry=ToolRegistry(),
        **kwargs,
    )


class TestAnalyzeServiceValidation(unittest.TestCase):
    def setUp(self):
        self.tmpdir = TemporaryDirectory()
        self.executor = _make_executor(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_empty_service_raises(self):
        with self.assertRaises(ToolExecutionError):
            self.executor._analyze_service("")

    def test_empty_service_whitespace_raises(self):
        with self.assertRaises(ToolExecutionError):
            self.executor._analyze_service("   ")

    def test_in_available_tools(self):
        tools = self.executor.available_tools()
        tool_names = {t.name for t in tools}
        self.assertIn("analyze_service", tool_names)

    def test_dispatch_routes_correctly(self):
        with patch.object(self.executor, "_analyze_service", return_value={"ok": True}) as mock:
            result = self.executor.dispatch("analyze_service", {
                "service": "apache",
                "version": "2.4.49",
                "port": "80",
            })
            mock.assert_called_once_with("apache", "2.4.49", "80")


class TestAnalyzeServicePipeline(unittest.TestCase):
    def setUp(self):
        self.tmpdir = TemporaryDirectory()
        self.findings_store = FindingsStore()
        self.executor = _make_executor(
            self.tmpdir.name,
            findings_store=self.findings_store,
        )

    def tearDown(self):
        self.tmpdir.cleanup()

    @patch("app.tool_executor.search_cve")
    @patch("shutil.which", return_value=None)
    def test_cve_only_no_searchsploit(self, mock_which, mock_cve):
        """When searchsploit is not installed, CVE lookup still works."""
        mock_cve.return_value = [
            CVEEntry(cve_id="CVE-2021-41773", score=7.5, severity="high",
                     description="Path traversal in Apache 2.4.49"),
        ]
        result = self.executor._analyze_service("apache", "2.4.49", "80")
        self.assertEqual(result["service"], "apache")
        self.assertEqual(result["version"], "2.4.49")
        self.assertEqual(len(result["cves"]), 1)
        self.assertEqual(result["cves"][0]["id"], "CVE-2021-41773")
        self.assertIn("skipped", result["exploits"])
        self.assertGreater(result["risk_score"], 0)

    @patch("app.tool_executor.search_cve")
    @patch("shutil.which", return_value=None)
    def test_no_cves_found(self, mock_which, mock_cve):
        """When no CVEs are found, risk is info level."""
        mock_cve.return_value = []
        result = self.executor._analyze_service("customapp", "1.0")
        self.assertEqual(result["cves"], [])
        self.assertEqual(result["risk_score"], 0.0)
        self.assertEqual(result["risk_level"], "info")
        self.assertIn("Aucune CVE", result["recommendation"])

    @patch("app.tool_executor.search_cve")
    @patch("shutil.which")
    @patch.object(ToolExecutor, "execute_command")
    def test_full_pipeline_with_exploits(self, mock_exec, mock_which, mock_cve):
        """Full pipeline with CVEs + searchsploit results."""
        mock_cve.return_value = [
            CVEEntry(cve_id="CVE-2021-41773", score=9.8, severity="critical",
                     description="RCE in Apache 2.4.49"),
            CVEEntry(cve_id="CVE-2021-42013", score=9.1, severity="critical",
                     description="Path traversal in Apache 2.4.50"),
        ]
        mock_which.side_effect = lambda cmd: f"/usr/bin/{cmd}"
        mock_exec.return_value = {
            "stdout": (
                "Apache 2.4.49 - Path Traversal  | exploits/multiple/webapps/50383.sh\n"
                "Apache 2.4.50 - RCE             | exploits/multiple/webapps/50512.py\n"
            ),
            "returncode": 0,
        }

        result = self.executor._analyze_service("apache", "2.4.49")
        self.assertEqual(len(result["cves"]), 2)
        self.assertEqual(result["exploit_count"], 2)
        self.assertGreaterEqual(result["risk_score"], 9.0)
        self.assertEqual(result["risk_level"], "critical")
        self.assertIn("RISQUE ELEVE", result["recommendation"])
        self.assertIn("Exploits publics", result["recommendation"])

    @patch("app.tool_executor.search_cve")
    @patch("shutil.which", return_value=None)
    def test_creates_cve_findings(self, mock_which, mock_cve):
        """Pipeline should create CVE-typed findings in the store."""
        self.executor._active_target = MagicMock(label="10.10.10.10")
        mock_cve.return_value = [
            CVEEntry(cve_id="CVE-2024-1234", score=8.0, severity="high",
                     description="Test vuln"),
            CVEEntry(cve_id="CVE-2024-5678", score=5.0, severity="medium",
                     description="Another vuln"),
        ]
        self.executor._analyze_service("testservice", "3.0")
        cve_findings = self.findings_store.by_type(FindingType.CVE)
        self.assertEqual(len(cve_findings), 2)
        values = [f.value for f in cve_findings]
        self.assertTrue(any("CVE-2024-1234" in v for v in values))
        self.assertTrue(any("CVE-2024-5678" in v for v in values))
        self.assertEqual(cve_findings[0].target_ref, "10.10.10.10")
        self.assertEqual(cve_findings[0].normalized_severity, "high")
        self.assertEqual(cve_findings[0].attributes["service"], "testservice")
        self.assertEqual(cve_findings[0].attributes["version"], "3.0")
        self.assertEqual(cve_findings[0].raw_output, "Test vuln")

    @patch("app.tool_executor.search_cve")
    @patch("shutil.which", return_value=None)
    def test_risk_level_classification(self, mock_which, mock_cve):
        """Test the risk level thresholds."""
        # Low risk
        mock_cve.return_value = [
            CVEEntry(cve_id="CVE-LOW", score=2.0, severity="low", description="Low"),
        ]
        result = self.executor._analyze_service("svc", "1.0")
        self.assertEqual(result["risk_level"], "low")

        # Medium risk
        mock_cve.return_value = [
            CVEEntry(cve_id="CVE-MED", score=5.0, severity="medium", description="Med"),
        ]
        result = self.executor._analyze_service("svc2", "2.0")
        self.assertEqual(result["risk_level"], "medium")

        # High risk
        mock_cve.return_value = [
            CVEEntry(cve_id="CVE-HIGH", score=8.5, severity="high", description="High"),
        ]
        result = self.executor._analyze_service("svc3", "3.0")
        self.assertEqual(result["risk_level"], "high")

    @patch("app.tool_executor.search_cve")
    @patch("shutil.which")
    @patch.object(ToolExecutor, "execute_command")
    def test_risk_multiplier_with_exploits(self, mock_exec, mock_which, mock_cve):
        """Exploit availability should multiply the risk score."""
        mock_cve.return_value = [
            CVEEntry(cve_id="CVE-TEST", score=6.0, severity="medium", description="Test"),
        ]
        mock_which.side_effect = lambda cmd: f"/usr/bin/{cmd}"
        mock_exec.return_value = {
            "stdout": "Test Exploit | exploits/linux/local/12345.py\n",
            "returncode": 0,
        }
        result = self.executor._analyze_service("testsvc", "1.0")
        # 6.0 * 1.5 = 9.0
        self.assertEqual(result["risk_score"], 9.0)
        self.assertEqual(result["exploit_count"], 1)

    @patch("app.tool_executor.search_cve")
    @patch("shutil.which")
    @patch.object(ToolExecutor, "execute_command", side_effect=ToolExecutionError("fail"))
    def test_searchsploit_failure_graceful(self, mock_exec, mock_which, mock_cve):
        """searchsploit failure should not break the pipeline."""
        mock_cve.return_value = [
            CVEEntry(cve_id="CVE-TEST", score=7.0, severity="high", description="Test"),
        ]
        mock_which.side_effect = lambda cmd: f"/usr/bin/{cmd}"
        result = self.executor._analyze_service("testsvc", "2.0")
        self.assertIn("error", result["exploits"])
        # Risk score should still reflect CVE score
        self.assertEqual(result["risk_score"], 7.0)

    @patch("app.tool_executor.search_cve")
    @patch("shutil.which", return_value=None)
    def test_no_findings_store(self, mock_which, mock_cve):
        """Pipeline works even without a findings_store set."""
        mock_cve.return_value = [
            CVEEntry(cve_id="CVE-NOFS", score=5.0, severity="medium", description="NoFS"),
        ]
        self.executor.findings_store = None
        result = self.executor._analyze_service("svc", "1.0")
        self.assertEqual(len(result["cves"]), 1)

    @patch("app.tool_executor.search_cve")
    @patch("shutil.which", return_value=None)
    def test_timestamp_present(self, mock_which, mock_cve):
        mock_cve.return_value = []
        result = self.executor._analyze_service("svc", "1.0")
        self.assertIn("timestamp", result)
        self.assertTrue(len(result["timestamp"]) > 0)

    @patch("app.tool_executor.search_cve")
    @patch("shutil.which", return_value=None)
    def test_high_cvss_no_exploit_recommendation(self, mock_which, mock_cve):
        """High CVSS but no exploits should give specific recommendation."""
        mock_cve.return_value = [
            CVEEntry(cve_id="CVE-NOEXP", score=8.0, severity="high",
                     description="No exploit available"),
        ]
        result = self.executor._analyze_service("svc", "1.0")
        self.assertIn("pas d'exploit public", result["recommendation"])


class TestCVEFindingType(unittest.TestCase):
    """Test the new CVE finding type in FindingsStore."""

    def test_cve_finding_type_exists(self):
        self.assertEqual(FindingType.CVE.value, "cve")

    def test_structured_summary_includes_cves(self):
        from app.findings import Finding
        store = FindingsStore()
        store.add(Finding(
            finding_type=FindingType.CVE,
            value="CVE-2021-41773 (CVSS 9.8, critical)",
            source_tool="analyze_service",
        ))
        summary = store.structured_summary()
        self.assertIn("CVEs:", summary)
        self.assertIn("CVE-2021-41773", summary)


if __name__ == "__main__":
    unittest.main()
