from __future__ import annotations

import unittest

from secops_agent.core.mission import Evidence, Finding, MissionContext, Service
from secops_agent.core.planner import MissionPlanner
from secops_agent.core.result_parser import ToolResultParser
from secops_agent.core.structured_memory import StructuredMemory


class MissionPlannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.planner = MissionPlanner(max_actions=12)

    def test_empty_mission_asks_for_authorized_scope(self):
        mission = MissionContext(name="planner test")

        actions = self.planner.plan(mission)

        self.assertEqual(actions[0].title, "Define authorized scope")
        self.assertEqual(actions[0].tool_name, "")
        self.assertEqual(actions[0].phase, "scoping")

    def test_domain_target_generates_passive_recon_actions(self):
        mission = MissionContext(name="planner test")
        mission.add_target("https://example.com", "url")

        actions = self.planner.plan(mission)
        tools = {action.tool_name for action in actions}

        self.assertIn("dns_lookup", tools)
        self.assertIn("whois_lookup", tools)
        self.assertIn("subdomain_enum", tools)
        self.assertIn("http_headers", tools)
        self.assertFalse(any(action.requires_approval for action in actions if action.tool_name in {"dns_lookup", "whois_lookup", "http_headers"}))

    def test_out_of_scope_target_is_not_planned(self):
        mission = MissionContext(name="planner test")
        mission.add_target("example.com", "domain")
        mission.targets.append(type(mission.targets[0])("blocked.example", type="domain"))
        mission.scope.out_of_scope.append("blocked.example")

        actions = self.planner.plan(mission)
        serialized = " ".join(str(action.arguments) for action in actions)

        self.assertIn("example.com", serialized)
        self.assertNotIn("blocked.example", serialized)

    def test_web_service_generates_enumeration_and_vulnerability_candidates(self):
        mission = MissionContext(name="planner test")
        mission.add_service(Service(host="10.10.10.5", port=80, service="http", version="Apache httpd 2.4.49"))

        actions = self.planner.plan(mission)
        tools = {action.tool_name for action in actions}
        brute = next(action for action in actions if action.tool_name == "dir_brute")

        self.assertIn("http_headers", tools)
        self.assertIn("tech_detect", tools)
        self.assertIn("dir_brute", tools)
        self.assertIn("nikto_scan", tools)
        self.assertIn("searchsploit", tools)
        self.assertTrue(brute.requires_approval)
        self.assertEqual(brute.arguments["url"], "http://10.10.10.5")

    def test_nmap_host_discovery_failure_prioritizes_pn_retry(self):
        mission = MissionContext(name="planner test")
        parser = ToolResultParser(mission=mission)
        parser.parse(
            "nmap_scan",
            """Starting Nmap 7.98 ( https://nmap.org ) at 2026-06-02 21:24 +0000
Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
Nmap done: 1 IP address (0 hosts up) scanned in 2.26 seconds
""",
            {"target": "10.129.153.73"},
        )

        actions = self.planner.plan(mission)
        nmap_actions = [action for action in actions if action.tool_name == "nmap_scan"]

        self.assertEqual(len(nmap_actions), 1)
        self.assertEqual(nmap_actions[0].method, "host_discovery_retry")
        self.assertEqual(nmap_actions[0].arguments["extra_args"], "-Pn")
        self.assertTrue(nmap_actions[0].requires_approval)

    def test_missing_dir_brute_wordlist_prioritizes_retry_with_available_wordlist(self):
        mission = MissionContext(name="planner test")
        mission.add_service(Service(host="10.10.10.5", port=80, service="http"))
        parser = ToolResultParser(mission=mission)
        parser.parse(
            "dir_brute",
            'No results. wordlist file "/usr/share/wordlists/dirb/common.txt" does not exist: stat',
            {"url": "http://10.10.10.5"},
        )

        actions = self.planner.plan(mission)
        brute_actions = [action for action in actions if action.tool_name == "dir_brute"]

        self.assertEqual(len(brute_actions), 1)
        self.assertEqual(brute_actions[0].method, "tool_prerequisite_retry")
        self.assertEqual(brute_actions[0].arguments, {"url": "http://10.10.10.5"})
        self.assertIn("wordlist", brute_actions[0].rationale)

    def test_empty_dir_brute_result_prioritizes_extension_retry(self):
        mission = MissionContext(name="planner test")
        mission.add_service(Service(host="10.10.10.5", port=80, service="http"))
        parser = ToolResultParser(mission=mission)
        parser.parse("dir_brute", "No results.", {"url": "http://10.10.10.5"})

        actions = self.planner.plan(mission)
        brute_actions = [action for action in actions if action.tool_name == "dir_brute"]

        self.assertEqual(len(brute_actions), 1)
        self.assertEqual(brute_actions[0].method, "content_discovery_retry")
        self.assertEqual(brute_actions[0].arguments["extensions"], "php,txt,bak,html")
        self.assertTrue(brute_actions[0].requires_approval)

    def test_tool_timeout_prioritizes_bounded_retry(self):
        mission = MissionContext(name="planner test")
        mission.add_service(Service(host="10.10.10.5", port=80, service="http"))
        parser = ToolResultParser(mission=mission)
        parser.parse(
            "dir_brute",
            "Tool execution timed out after 305s.",
            {"url": "http://10.10.10.5"},
        )

        actions = self.planner.plan(mission)
        retry = next(action for action in actions if action.method == "timeout_retry")

        self.assertEqual(retry.tool_name, "dir_brute")
        self.assertEqual(retry.arguments["threads"], 5)
        self.assertTrue(retry.requires_approval)

    def test_missing_nmap_tool_proposes_install_and_blocks_retry_until_installed(self):
        mission = MissionContext(name="planner test")
        parser = ToolResultParser(mission=mission)
        parser.parse(
            "nmap_scan",
            "❌ Error: nmap is not installed. Install with: sudo apt install nmap",
            {"target": "10.10.10.5"},
        )

        actions = self.planner.plan(mission)
        install = next(action for action in actions if action.method == "missing_tool_install")

        self.assertEqual(install.tool_name, "run_shell")
        self.assertEqual(install.arguments["command"], "sudo apt install -y nmap")
        self.assertEqual(install.risk, "high")
        self.assertTrue(install.requires_approval)
        self.assertFalse(any(action.tool_name == "nmap_scan" for action in actions))

    def test_missing_dir_brute_engine_proposes_install_and_blocks_dir_brute(self):
        mission = MissionContext(name="planner test")
        mission.add_service(Service(host="10.10.10.5", port=80, service="http"))
        parser = ToolResultParser(mission=mission)
        parser.parse(
            "dir_brute",
            "❌ Neither gobuster nor dirb is installed.",
            {"url": "http://10.10.10.5"},
        )

        actions = self.planner.plan(mission)
        install = next(action for action in actions if action.method == "missing_tool_install")

        self.assertEqual(install.arguments["command"], "sudo apt install -y gobuster")
        self.assertFalse(any(action.tool_name == "dir_brute" for action in actions))

    def test_confirmed_cve_finding_generates_cve_lookup_candidate(self):
        mission = MissionContext(name="planner test")
        mission.add_finding(
            title="CVE-2021-41773 - Apache Path Traversal",
            severity="critical",
            category="known_vuln",
            target="10.10.10.5",
            tool_used="nmap_scan",
        )

        actions = self.planner.plan(mission)
        cve_actions = [action for action in actions if action.tool_name == "cve_lookup"]

        self.assertEqual(cve_actions[0].arguments["cve_id"], "CVE-2021-41773")
        self.assertGreaterEqual(cve_actions[0].priority, 80)

    def test_passive_reference_finding_only_requests_correlation(self):
        mission = MissionContext(name="planner test")
        mission.add_finding(
            title="CVE-2021-41773 reference",
            severity="critical",
            category="cve_reference",
            target="CVE-2021-41773",
            tool_used="cve_lookup",
        )

        actions = self.planner.plan(mission)

        self.assertFalse(any(action.tool_name == "cve_lookup" for action in actions))
        self.assertTrue(any(action.title.startswith("Correlate reference") for action in actions))

    def test_structured_memory_context_includes_suggested_next_actions(self):
        mission = MissionContext(name="planner test")
        mission.add_service(Service(host="10.10.10.5", port=443, service="https"))
        memory = StructuredMemory(mission=mission)

        context = memory.build_context_for_llm(include_conversation=False)

        self.assertIn("Suggested Next Actions", context)
        self.assertIn("Candidate actions only", context)
        self.assertIn("http_headers", context)
        self.assertIn("ssl_check", context)

    def test_upload_surface_finding_generates_bounded_exploitation_candidate(self):
        mission = MissionContext(name="planner test")
        mission.add_finding(
            title="Interesting path: /panel (301)",
            severity="medium",
            category="dir_enum",
            target="http://10.10.10.5",
            evidence="Status 301, Size 313",
            tool_used="dir_brute",
            evidence_items=[
                Evidence(
                    title="Interesting path: /panel (301)",
                    source_tool="dir_brute",
                    target="http://10.10.10.5",
                    snippet="Status 301, Size 313",
                    metadata={"path": "/panel"},
                )
            ],
        )

        actions = self.planner.plan(mission)
        upload = next(action for action in actions if action.method == "upload_surface_validation")

        self.assertEqual(upload.phase, "exploitation")
        self.assertEqual(upload.risk, "high")
        self.assertTrue(upload.requires_approval)
        self.assertEqual(upload.tool_name, "")
        self.assertIn("http://10.10.10.5/panel", upload.title)
        self.assertIn("Status 301", upload.evidence[0])
        self.assertTrue(upload.prerequisites)

    def test_source_disclosure_finding_generates_bounded_review_candidate(self):
        mission = MissionContext(name="planner test")
        mission.add_finding(
            title="Interesting path: /.git (200)",
            severity="medium",
            category="dir_enum",
            target="http://10.10.10.5",
            evidence="Status 200, Size 321",
            tool_used="dir_brute",
            evidence_items=[
                Evidence(
                    title="Interesting path: /.git (200)",
                    source_tool="dir_brute",
                    target="http://10.10.10.5",
                    snippet="Status 200, Size 321",
                    metadata={"path": "/.git"},
                )
            ],
        )

        actions = self.planner.plan(mission)
        review = next(action for action in actions if action.method == "source_disclosure_review")

        self.assertEqual(review.phase, "vulnerability")
        self.assertEqual(review.risk, "high")
        self.assertTrue(review.requires_approval)
        self.assertEqual(review.tool_name, "")
        self.assertFalse(any(action.tool_name == "generate_payload" for action in actions))

    def test_sensitive_file_finding_generates_bounded_review_candidate(self):
        mission = MissionContext(name="planner test")
        mission.add_finding(
            title="Interesting path: /.env (200)",
            severity="medium",
            category="dir_enum",
            target="http://challenge.local",
            evidence="Status 200, Size 128",
            tool_used="dir_brute",
            evidence_items=[
                Evidence(
                    title="Interesting path: /.env (200)",
                    source_tool="dir_brute",
                    target="http://challenge.local",
                    snippet="Status 200, Size 128",
                    metadata={"path": "/.env"},
                )
            ],
        )

        actions = self.planner.plan(mission)
        review = next(action for action in actions if action.method == "sensitive_file_exposure_review")

        self.assertEqual(review.phase, "vulnerability")
        self.assertEqual(review.risk, "high")
        self.assertTrue(review.requires_approval)
        self.assertIn("secrets", " ".join(review.prerequisites).casefold())
        self.assertFalse(any(action.tool_name == "generate_payload" for action in actions))

    def test_directory_listing_finding_generates_bounded_review_candidate(self):
        mission = MissionContext(name="planner test")
        mission.add_finding(
            title="/backup/: Directory indexing found.",
            severity="medium",
            category="web_vuln",
            target="http://10.10.10.20/backup/",
            evidence="Directory indexing found.",
            tool_used="nikto_scan",
        )

        actions = self.planner.plan(mission)
        review = next(action for action in actions if action.method == "directory_listing_review")

        self.assertEqual(review.phase, "vulnerability")
        self.assertEqual(review.risk, "medium")
        self.assertTrue(review.requires_approval)
        self.assertFalse(any(action.tool_name == "generate_payload" for action in actions))

    def test_sqli_finding_generates_payload_generation_candidate(self):
        mission = MissionContext(name="planner test")
        mission.add_finding(
            title="SQL Injection in 'id' (GET)",
            severity="critical",
            category="sqli",
            target="http://10.10.10.5/item?id=1",
            evidence="Parameter: id, Types: boolean-based blind",
            tool_used="sql_injection_test",
        )

        actions = self.planner.plan(mission)
        payload = next(action for action in actions if action.method == "payload_generation")

        self.assertEqual(payload.tool_name, "generate_payload")
        self.assertEqual(payload.arguments, {"payload_type": "sqli"})
        self.assertEqual(payload.risk, "high")
        self.assertTrue(payload.requires_approval)

    def test_suid_finding_generates_privilege_escalation_review_candidate(self):
        mission = MissionContext(name="planner test")
        mission.add_finding(
            title="Unusual SUID binary: /usr/bin/bash",
            severity="high",
            category="suid_binary",
            target="/usr/bin/bash",
            evidence="SUID enumeration output included /usr/bin/bash",
            tool_used="run_shell",
        )

        actions = self.planner.plan(mission)
        suid = next(action for action in actions if action.method == "suid_privilege_escalation_review")

        self.assertEqual(suid.phase, "exploitation")
        self.assertEqual(suid.risk, "high")
        self.assertTrue(suid.requires_approval)
        self.assertEqual(suid.tool_name, "")
        self.assertIn("/usr/bin/bash", suid.title)


if __name__ == "__main__":
    unittest.main()
