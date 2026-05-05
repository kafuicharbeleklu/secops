"""Tests for new SECOPS features: CVE lookup, report generator, scope validation, searchsploit parser."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from app.cve_lookup import CVEEntry, format_cve_results, search_cve
from app.attack_planner import AttackPlan, AttackPriority, AttackStep, StepStatus
from app.findings import (
    Finding,
    FindingType,
    FindingsStore,
    parse_searchsploit_output,
    parse_tool_output,
)
from app.knowledge_store import KnowledgeStore
from app.methodology import EngagementState, PentestPhase
from app.report_generator import generate_pentest_report
from app.tool_executor import (
    ScopeViolationError,
    ToolExecutionError,
    ToolExecutor,
    ToolMissingError,
)


# ---------------------------------------------------------------------------
# CVE Lookup Tests
# ---------------------------------------------------------------------------


class TestCVEEntry(unittest.TestCase):
    def test_cve_entry_is_frozen(self):
        entry = CVEEntry(cve_id="CVE-2021-44228", score=10.0, severity="critical", description="Log4Shell")
        self.assertEqual(entry.cve_id, "CVE-2021-44228")
        self.assertEqual(entry.score, 10.0)
        with self.assertRaises(AttributeError):
            entry.score = 5.0


class TestFormatCveResults(unittest.TestCase):
    def test_empty_list(self):
        result = format_cve_results([])
        self.assertIn("Aucune", result)

    def test_formats_entries(self):
        entries = [
            CVEEntry("CVE-2021-44228", 10.0, "critical", "Log4Shell RCE"),
            CVEEntry("CVE-2021-45046", 9.0, "critical", "Log4j DoS"),
        ]
        result = format_cve_results(entries)
        self.assertIn("CVE-2021-44228", result)
        self.assertIn("10.0", result)
        self.assertIn("CVE-2021-45046", result)


class TestSearchCve(unittest.TestCase):
    def test_empty_service_returns_empty(self):
        self.assertEqual(search_cve(""), [])
        self.assertEqual(search_cve("", ""), [])

    @patch("app.cve_lookup.urllib.request.urlopen")
    def test_parses_nvd_response(self, mock_urlopen):
        fake_response = json.dumps({
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2021-41773",
                        "metrics": {
                            "cvssMetricV31": [{
                                "cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}
                            }]
                        },
                        "descriptions": [
                            {"lang": "en", "value": "Path traversal in Apache 2.4.49"}
                        ],
                    }
                }
            ]
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__ = lambda s: MagicMock(read=lambda: fake_response)
        mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)

        results = search_cve("apache", "2.4.49")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].cve_id, "CVE-2021-41773")
        self.assertEqual(results[0].score, 7.5)
        self.assertEqual(results[0].severity, "high")
        self.assertIn("Path traversal", results[0].description)

    @patch("app.cve_lookup.urllib.request.urlopen", side_effect=TimeoutError("timeout"))
    def test_network_error_returns_empty(self, _mock):
        results = search_cve("apache", "2.4.49")
        self.assertEqual(results, [])

    @patch("app.cve_lookup.urllib.request.urlopen")
    def test_results_sorted_by_score(self, mock_urlopen):
        fake_response = json.dumps({
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-LOW",
                        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 3.0, "baseSeverity": "LOW"}}]},
                        "descriptions": [{"lang": "en", "value": "Low severity"}],
                    }
                },
                {
                    "cve": {
                        "id": "CVE-HIGH",
                        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
                        "descriptions": [{"lang": "en", "value": "Critical severity"}],
                    }
                },
            ]
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__ = lambda s: MagicMock(read=lambda: fake_response)
        mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)

        results = search_cve("test", limit=5)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].cve_id, "CVE-HIGH")
        self.assertGreater(results[0].score, results[1].score)


# ---------------------------------------------------------------------------
# Searchsploit Parser Tests
# ---------------------------------------------------------------------------


class TestParseSearchsploitOutput(unittest.TestCase):
    SAMPLE = (
        "------------------------------------------------- ---------------------------------\n"
        " Exploit Title                                    |  Path\n"
        "------------------------------------------------- ---------------------------------\n"
        "Apache 2.4.49 - Path Traversal & RCE             | exploits/multiple/webapps/50383.py\n"
        "Apache 2.4.50 - Remote Code Execution             | exploits/multiple/webapps/50406.py\n"
        "------------------------------------------------- ---------------------------------\n"
    )

    def test_extracts_exploits(self):
        findings = parse_searchsploit_output(self.SAMPLE)
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0].finding_type, FindingType.VULNERABILITY)
        self.assertIn("Apache 2.4.49", findings[0].value)
        self.assertIn("exploits/", findings[0].value)
        self.assertEqual(findings[0].source_tool, "searchsploit")

    def test_empty_output(self):
        self.assertEqual(parse_searchsploit_output(""), [])

    def test_skips_separator_lines(self):
        output = "------- separator line          | exploits/fake/path.py\n"
        findings = parse_searchsploit_output(output)
        self.assertEqual(len(findings), 0)

    def test_routes_via_parse_tool_output(self):
        output = "Apache mod_ssl - Buffer Overflow  | exploits/linux/remote/764.c\n"
        findings = parse_tool_output("searchsploit", output)
        self.assertTrue(len(findings) > 0)
        self.assertEqual(findings[0].source_tool, "searchsploit")


# ---------------------------------------------------------------------------
# Report Generator Tests
# ---------------------------------------------------------------------------


class TestGeneratePentestReport(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.store = FindingsStore()
        self.engagement = EngagementState()

    def test_generates_report_file(self):
        self.store.add(Finding(FindingType.PORT, "22", "nmap", "high"))
        self.store.add(Finding(FindingType.PORT, "80", "nmap", "high"))
        self.store.add(Finding(FindingType.SERVICE, "22/ssh", "nmap", "high"))
        self.store.add(Finding(FindingType.SERVICE, "80/http", "nmap", "high"))

        output_path = Path(self.tmp_dir) / "report.md"
        result = generate_pentest_report(
            target_summary="10.10.10.5",
            findings_store=self.store,
            engagement_state=self.engagement,
            session_duration_minutes=15,
            output_path=output_path,
        )
        self.assertTrue(result.exists())
        content = result.read_text(encoding="utf-8")
        self.assertIn("Rapport de Test de Penetration", content)
        self.assertIn("10.10.10.5", content)
        self.assertIn("2", content)  # 2 ports

    def test_report_includes_vulnerabilities(self):
        self.store.add(Finding(FindingType.VULNERABILITY, "SQL Injection in /login", "sqlmap", "high"))
        self.store.add(Finding(FindingType.VULNERABILITY, "XSS in /search", "nikto", "medium"))

        output_path = Path(self.tmp_dir) / "report_vulns.md"
        result = generate_pentest_report(
            target_summary="target.htb",
            findings_store=self.store,
            engagement_state=self.engagement,
            output_path=output_path,
        )
        content = result.read_text(encoding="utf-8")
        self.assertIn("Vulnerabilites Detectees", content)
        self.assertIn("SQL Injection", content)
        self.assertIn("XSS", content)

    def test_report_includes_credentials(self):
        self.store.add(Finding(FindingType.CREDENTIAL, "ssh://admin:pass123 (port 22)", "hydra", "high"))

        output_path = Path(self.tmp_dir) / "report_creds.md"
        result = generate_pentest_report(
            target_summary="10.10.10.5",
            findings_store=self.store,
            engagement_state=self.engagement,
            output_path=output_path,
        )
        content = result.read_text(encoding="utf-8")
        self.assertIn("Credentials Compromis", content)
        self.assertIn("admin", content)

    def test_report_includes_phase_timeline(self):
        self.store.add(Finding(FindingType.PORT, "80", "nmap"))
        self.engagement.advance_phase("Ports identifies.")
        self.engagement.advance_phase("Vulns trouvees.")

        output_path = Path(self.tmp_dir) / "report_timeline.md"
        result = generate_pentest_report(
            target_summary="10.10.10.5",
            findings_store=self.store,
            engagement_state=self.engagement,
            output_path=output_path,
        )
        content = result.read_text(encoding="utf-8")
        self.assertIn("Timeline des Phases", content)
        self.assertIn("recon", content)
        self.assertIn("enumeration", content)

    def test_report_includes_tools_used(self):
        self.store.add(Finding(FindingType.PORT, "22", "nmap"))
        self.engagement.record_tool_use("nmap")
        self.engagement.record_tool_use("gobuster")

        output_path = Path(self.tmp_dir) / "report_tools.md"
        result = generate_pentest_report(
            target_summary="10.10.10.5",
            findings_store=self.store,
            engagement_state=self.engagement,
            output_path=output_path,
        )
        content = result.read_text(encoding="utf-8")
        self.assertIn("Outils Utilises", content)
        self.assertIn("nmap", content)
        self.assertIn("gobuster", content)

    def test_report_includes_recommendations(self):
        self.store.add(Finding(FindingType.VULNERABILITY, "test vuln", "nikto"))

        output_path = Path(self.tmp_dir) / "report_reco.md"
        result = generate_pentest_report(
            target_summary="10.10.10.5",
            findings_store=self.store,
            engagement_state=self.engagement,
            output_path=output_path,
        )
        content = result.read_text(encoding="utf-8")
        self.assertIn("Recommandations", content)
        self.assertIn("severite", content)

    def test_report_with_empty_findings(self):
        """Even with no findings the report should still be generated."""
        output_path = Path(self.tmp_dir) / "report_empty.md"
        result = generate_pentest_report(
            target_summary="10.10.10.5",
            findings_store=self.store,
            engagement_state=self.engagement,
            output_path=output_path,
        )
        content = result.read_text(encoding="utf-8")
        self.assertIn("Rapport de Test de Penetration", content)
        self.assertIn("0", content)  # 0 ports

    def test_report_includes_surface_attack_table(self):
        self.store.add(Finding(FindingType.SERVICE, "22/ssh", "nmap", "high"))
        self.store.add(Finding(FindingType.SERVICE, "80/http", "nmap", "high"))

        output_path = Path(self.tmp_dir) / "report_surface.md"
        result = generate_pentest_report(
            target_summary="10.10.10.5",
            findings_store=self.store,
            engagement_state=self.engagement,
            output_path=output_path,
        )
        content = result.read_text(encoding="utf-8")
        self.assertIn("Surface d'Attaque", content)
        self.assertIn("| 22 |", content)
        self.assertIn("| 80 |", content)

    def test_report_includes_attack_plan(self):
        self.store.add(Finding(FindingType.PORT, "80", "nmap", "high"))
        attack_plan = AttackPlan(target="10.10.10.5", phase="enumeration", steps=[
            AttackStep(
                index=0,
                name="Enumeration web",
                tool="enumerate_web",
                arguments={"target": "10.10.10.5", "port": "80"},
                priority=AttackPriority.HIGH,
                status=StepStatus.DONE,
            ),
            AttackStep(
                index=1,
                name="Recherche exploits",
                tool="search_exploit",
                arguments={"query": "apache"},
                priority=AttackPriority.MEDIUM,
                status=StepStatus.FAILED,
            ),
        ])

        output_path = Path(self.tmp_dir) / "report_plan.md"
        result = generate_pentest_report(
            target_summary="10.10.10.5",
            findings_store=self.store,
            engagement_state=self.engagement,
            output_path=output_path,
            attack_plan=attack_plan,
        )
        content = result.read_text(encoding="utf-8")
        self.assertIn("Plan d'Attaque", content)
        self.assertIn("Enumeration web", content)
        self.assertIn("done", content)
        self.assertIn("failed", content)

    def test_report_includes_evidence_section(self):
        self.store.add(Finding(
            finding_type=FindingType.VULNERABILITY,
            value="Configuration leak in /config",
            source_tool="nikto",
            confidence="high",
            raw_output="GET /config returned 200\ndb_password=secret123\nadmin=true",
            severity="high",
            target_ref="10.10.10.5",
            attributes={"path": "/config", "password": "secret123"},
        ))

        output_path = Path(self.tmp_dir) / "report_evidence.md"
        result = generate_pentest_report(
            target_summary="10.10.10.5",
            findings_store=self.store,
            engagement_state=self.engagement,
            output_path=output_path,
        )
        content = result.read_text(encoding="utf-8")
        self.assertIn("## Preuves", content)
        self.assertIn("Configuration leak", content)
        self.assertIn("Cible :** 10.10.10.5", content)
        self.assertIn("path=/config", content)
        self.assertIn("password=<redacted>", content)
        self.assertIn("db_password=<redacted>", content)
        self.assertNotIn("secret123", content)


# ---------------------------------------------------------------------------
# Scope Validation Tests
# ---------------------------------------------------------------------------


class TestScopeValidation(unittest.TestCase):
    def setUp(self):
        repo_root = Path(__file__).resolve().parents[3]
        self.knowledge_root = repo_root / "knowledge"
        self.workspace = repo_root / "templates" / "automation_project" / "workspace"
        self.knowledge_store = KnowledgeStore.load(self.knowledge_root)

    def _make_executor(self, scope=None):
        return ToolExecutor(
            workspace=self.workspace,
            knowledge_root=self.knowledge_root,
            knowledge_store=self.knowledge_store,
            permission_callback=lambda **_kwargs: True,
            command_permission_mode="session",
            authorized_scope=scope,
        )

    def test_no_scope_allows_everything(self):
        executor = self._make_executor(scope=None)
        # Should not raise
        executor._validate_scope("192.168.1.1")
        executor._validate_scope_in_command("nmap 10.10.10.10")

    def test_scope_allows_ip_in_range(self):
        executor = self._make_executor(scope=["10.10.10.0/24"])
        executor._validate_scope("10.10.10.5")  # Should not raise

    def test_scope_blocks_ip_outside_range(self):
        executor = self._make_executor(scope=["10.10.10.0/24"])
        with self.assertRaises(ScopeViolationError):
            executor._validate_scope("192.168.1.1")

    def test_scope_with_exact_ip(self):
        executor = self._make_executor(scope=["10.10.10.5"])
        executor._validate_scope("10.10.10.5")  # Should not raise
        with self.assertRaises(ScopeViolationError):
            executor._validate_scope("10.10.10.6")

    def test_scope_validates_command_ips(self):
        executor = self._make_executor(scope=["10.10.10.0/24"])
        executor._validate_scope_in_command("nmap -sV 10.10.10.5")  # OK
        with self.assertRaises(ScopeViolationError):
            executor._validate_scope_in_command("nmap -sV 192.168.1.1")

    def test_scope_allows_domains_when_scope_is_ip_only(self):
        """Domain targets remain allowed when the scope contains only IP/CIDR entries."""
        executor = self._make_executor(scope=["10.10.10.0/24"])
        executor._validate_scope("target.htb")  # Should not raise

    def test_scope_allows_matching_domain(self):
        executor = self._make_executor(scope=["target.htb"])
        executor._validate_scope("target.htb")
        executor._validate_scope("https://target.htb/admin")
        with self.assertRaises(ScopeViolationError):
            executor._validate_scope("other.htb")

    def test_scope_allows_wildcard_subdomain(self):
        executor = self._make_executor(scope=["*.example.com"])
        executor._validate_scope("app.example.com")
        executor._validate_scope("https://api.example.com/login")
        with self.assertRaises(ScopeViolationError):
            executor._validate_scope("example.com")

    def test_scope_url_port_is_enforced(self):
        executor = self._make_executor(scope=["https://app.example.com:8443"])
        executor._validate_scope("https://app.example.com:8443/admin")
        with self.assertRaises(ScopeViolationError):
            executor._validate_scope("https://app.example.com:443/admin")

    def test_scope_validates_command_domains_when_domain_scope_exists(self):
        executor = self._make_executor(scope=["target.htb"])
        executor._validate_scope_in_command("nmap -sV target.htb")
        with self.assertRaises(ScopeViolationError):
            executor._validate_scope_in_command("nmap -sV other.htb")

    def test_scope_ignores_command_output_files(self):
        executor = self._make_executor(scope=["target.htb"])
        executor._validate_scope_in_command("nmap -oN report.txt target.htb")

    def test_set_scope(self):
        executor = self._make_executor(scope=None)
        self.assertEqual(len(executor.authorized_scope), 0)
        executor.set_scope(["10.10.10.0/24", "192.168.1.0/24"])
        self.assertEqual(len(executor.authorized_scope), 2)
        executor._validate_scope("10.10.10.5")  # OK
        executor._validate_scope("192.168.1.100")  # OK

    def test_set_scope_clear(self):
        executor = self._make_executor(scope=["10.10.10.0/24"])
        executor.set_scope([])
        executor._validate_scope("192.168.1.1")  # Should not raise anymore

    def test_scope_blocks_in_execute_command(self):
        executor = self._make_executor(scope=["10.10.10.0/24"])
        with patch("app.tool_executor.shutil.which", return_value="/usr/bin/nmap"):
            with self.assertRaises(ScopeViolationError):
                executor.execute_command("nmap 192.168.1.1", "scan hors scope")

    def test_scope_is_subclass_of_tool_execution_error(self):
        self.assertTrue(issubclass(ScopeViolationError, ToolExecutionError))

    def test_scope_multiple_cidrs(self):
        executor = self._make_executor(scope=["10.10.10.0/24", "172.16.0.0/16"])
        executor._validate_scope("10.10.10.50")  # OK
        executor._validate_scope("172.16.5.10")  # OK
        with self.assertRaises(ScopeViolationError):
            executor._validate_scope("8.8.8.8")


# ---------------------------------------------------------------------------
# Tool Executor — search_cve dispatch
# ---------------------------------------------------------------------------


class TestSearchCveDispatch(unittest.TestCase):
    def setUp(self):
        repo_root = Path(__file__).resolve().parents[3]
        self.knowledge_root = repo_root / "knowledge"
        self.workspace = repo_root / "templates" / "automation_project" / "workspace"
        self.knowledge_store = KnowledgeStore.load(self.knowledge_root)

    def test_search_cve_empty_service_raises(self):
        executor = ToolExecutor(
            workspace=self.workspace,
            knowledge_root=self.knowledge_root,
            knowledge_store=self.knowledge_store,
        )
        with self.assertRaises(ToolExecutionError):
            executor.dispatch("search_cve", {"service": "", "version": ""})

    @patch("app.tool_executor.search_cve", return_value=[])
    @patch("app.tool_executor.format_cve_results", return_value="Aucune CVE trouvee.")
    def test_search_cve_returns_result(self, _fmt, _search):
        executor = ToolExecutor(
            workspace=self.workspace,
            knowledge_root=self.knowledge_root,
            knowledge_store=self.knowledge_store,
        )
        result = executor.dispatch("search_cve", {"service": "apache", "version": "2.4.49"})
        self.assertEqual(result["service"], "apache")
        self.assertEqual(result["version"], "2.4.49")
        self.assertIn("count", result)
        self.assertIn("results", result)

    def test_search_cve_in_available_tools(self):
        executor = ToolExecutor(
            workspace=self.workspace,
            knowledge_root=self.knowledge_root,
            knowledge_store=self.knowledge_store,
        )
        tool_names = [t.name for t in executor.available_tools()]
        self.assertIn("search_cve", tool_names)


# ---------------------------------------------------------------------------
# Tool Executor — search_exploit dispatch
# ---------------------------------------------------------------------------


class TestSearchExploitDispatch(unittest.TestCase):
    def setUp(self):
        repo_root = Path(__file__).resolve().parents[3]
        self.knowledge_root = repo_root / "knowledge"
        self.workspace = repo_root / "templates" / "automation_project" / "workspace"
        self.knowledge_store = KnowledgeStore.load(self.knowledge_root)

    def test_search_exploit_empty_query_raises(self):
        executor = ToolExecutor(
            workspace=self.workspace,
            knowledge_root=self.knowledge_root,
            knowledge_store=self.knowledge_store,
        )
        with self.assertRaises(ToolExecutionError):
            executor.dispatch("search_exploit", {"query": ""})

    def test_search_exploit_missing_tool_raises(self):
        executor = ToolExecutor(
            workspace=self.workspace,
            knowledge_root=self.knowledge_root,
            knowledge_store=self.knowledge_store,
            permission_callback=lambda **_kwargs: True,
            command_permission_mode="session",
        )
        with patch("app.tool_executor.shutil.which", return_value=None):
            with self.assertRaises(ToolMissingError):
                executor.dispatch("search_exploit", {"query": "apache 2.4.49"})

    def test_search_exploit_in_available_tools(self):
        executor = ToolExecutor(
            workspace=self.workspace,
            knowledge_root=self.knowledge_root,
            knowledge_store=self.knowledge_store,
        )
        tool_names = [t.name for t in executor.available_tools()]
        self.assertIn("search_exploit", tool_names)


if __name__ == "__main__":
    unittest.main()
