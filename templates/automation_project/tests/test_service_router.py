"""Tests for service_router — playbook matching and service plan generation."""

import unittest

from app.service_router import (
    PLAYBOOKS,
    ServicePlaybook,
    ServiceAnalysisPlan,
    build_service_plan,
    extract_services_from_findings,
    route_service,
)


class TestRouteService(unittest.TestCase):
    """Test route_service matching against known service patterns."""

    def test_match_apache(self):
        pb = route_service("apache", "2.4.49")
        self.assertIsNotNone(pb)
        self.assertEqual(pb.label, "Serveur Web")

    def test_match_httpd(self):
        pb = route_service("httpd")
        self.assertIsNotNone(pb)
        self.assertEqual(pb.label, "Serveur Web")

    def test_match_nginx(self):
        pb = route_service("nginx", "1.18.0")
        self.assertIsNotNone(pb)
        self.assertEqual(pb.label, "Serveur Web")

    def test_match_iis(self):
        pb = route_service("Microsoft IIS", "10.0")
        self.assertIsNotNone(pb)
        self.assertEqual(pb.label, "Serveur Web")

    def test_match_openssh(self):
        pb = route_service("OpenSSH", "8.9p1")
        self.assertIsNotNone(pb)
        self.assertEqual(pb.label, "SSH")

    def test_match_ssh_generic(self):
        pb = route_service("ssh")
        self.assertIsNotNone(pb)
        self.assertEqual(pb.label, "SSH")

    def test_match_smb(self):
        pb = route_service("microsoft-ds")
        self.assertIsNotNone(pb)
        self.assertEqual(pb.label, "SMB/Samba")

    def test_match_samba(self):
        pb = route_service("Samba smbd", "4.13.17")
        self.assertIsNotNone(pb)
        self.assertEqual(pb.label, "SMB/Samba")

    def test_match_mysql(self):
        pb = route_service("MySQL", "5.7.38")
        self.assertIsNotNone(pb)
        self.assertEqual(pb.label, "Base de donnees")

    def test_match_postgresql(self):
        pb = route_service("PostgreSQL", "14.5")
        self.assertIsNotNone(pb)
        self.assertEqual(pb.label, "Base de donnees")

    def test_match_ftp(self):
        pb = route_service("vsftpd", "3.0.3")
        self.assertIsNotNone(pb)
        self.assertEqual(pb.label, "FTP")

    def test_match_ftp_generic(self):
        pb = route_service("ftp")
        self.assertIsNotNone(pb)
        self.assertEqual(pb.label, "FTP")

    def test_match_wordpress(self):
        pb = route_service("WordPress", "5.8")
        self.assertIsNotNone(pb)
        self.assertEqual(pb.label, "WordPress")

    def test_match_smtp(self):
        pb = route_service("Postfix", "3.5.6")
        self.assertIsNotNone(pb)
        self.assertEqual(pb.label, "SMTP")

    def test_match_dns(self):
        pb = route_service("ISC BIND", "9.16")
        self.assertIsNotNone(pb)
        self.assertEqual(pb.label, "DNS")

    def test_match_redis(self):
        pb = route_service("Redis", "6.2.7")
        self.assertIsNotNone(pb)
        self.assertEqual(pb.label, "Redis")

    def test_match_rdp(self):
        pb = route_service("ms-wbt-server")
        self.assertIsNotNone(pb)
        self.assertEqual(pb.label, "RDP")

    def test_match_mongodb(self):
        pb = route_service("MongoDB", "5.0")
        self.assertIsNotNone(pb)
        self.assertEqual(pb.label, "MongoDB")

    def test_match_ldap(self):
        pb = route_service("ldap")
        self.assertIsNotNone(pb)
        self.assertEqual(pb.label, "LDAP/AD")

    def test_match_snmp(self):
        pb = route_service("snmp")
        self.assertIsNotNone(pb)
        self.assertEqual(pb.label, "SNMP")

    def test_no_match_unknown(self):
        pb = route_service("tcpwrapped")
        self.assertIsNone(pb)

    def test_no_match_empty(self):
        pb = route_service("")
        self.assertIsNone(pb)

    def test_case_insensitive(self):
        pb = route_service("APACHE")
        self.assertIsNotNone(pb)
        self.assertEqual(pb.label, "Serveur Web")


class TestBuildServicePlan(unittest.TestCase):
    """Test build_service_plan with various service combinations."""

    def test_empty_services(self):
        plan = build_service_plan({}, "10.10.10.10")
        self.assertEqual(len(plan.entries), 0)
        self.assertEqual(plan.target, "10.10.10.10")

    def test_single_web_service(self):
        services = {80: "Apache httpd 2.4.49"}
        plan = build_service_plan(services, "10.10.10.10")
        self.assertEqual(len(plan.entries), 1)
        self.assertEqual(plan.entries[0]["playbook"].label, "Serveur Web")

    def test_multiple_services(self):
        services = {
            22: "OpenSSH 8.9p1",
            80: "Apache httpd 2.4.49",
            445: "microsoft-ds",
        }
        plan = build_service_plan(services, "target")
        self.assertGreaterEqual(len(plan.entries), 2)

    def test_priority_ordering(self):
        services = {
            22: "OpenSSH 8.9p1",   # medium
            80: "nginx 1.18.0",    # high
        }
        plan = build_service_plan(services, "target")
        # High priority should come first
        priorities = [e["playbook"].priority for e in plan.entries]
        self.assertEqual(priorities[0], "high")

    def test_dedup_same_service_type(self):
        services = {
            80: "Apache httpd 2.4.49",
            8080: "nginx 1.18.0",
        }
        plan = build_service_plan(services, "target")
        # Both are "Serveur Web" — only one should be in the plan
        labels = [e["playbook"].label for e in plan.entries]
        self.assertEqual(labels.count("Serveur Web"), 1)

    def test_prompt_fragment_generated(self):
        services = {80: "Apache httpd 2.4.49"}
        plan = build_service_plan(services, "10.10.10.10")
        fragment = plan.prompt_fragment
        self.assertIn("PLAYBOOKS PAR SERVICE", fragment)
        self.assertIn("Serveur Web", fragment)

    def test_prompt_fragment_empty_when_no_match(self):
        services = {9999: "tcpwrapped"}
        plan = build_service_plan(services, "target")
        self.assertEqual(plan.prompt_fragment, "")

    def test_unknown_service_not_matched(self):
        services = {9999: "some_unknown_service"}
        plan = build_service_plan(services, "target")
        self.assertEqual(len(plan.entries), 0)


class TestExtractServicesFromFindings(unittest.TestCase):
    """Test extracting services from a FindingsStore."""

    def test_extract_from_nmap_findings(self):
        from app.findings import Finding, FindingType, FindingsStore

        store = FindingsStore()
        store.add(Finding(FindingType.SERVICE, "80/Apache httpd 2.4.49", "nmap", "high"))
        store.add(Finding(FindingType.SERVICE, "22/OpenSSH 8.9p1", "nmap", "high"))
        store.add(Finding(FindingType.PORT, "80", "nmap", "high"))

        services = extract_services_from_findings(store)
        self.assertEqual(len(services), 2)
        self.assertIn(80, services)
        self.assertIn(22, services)
        self.assertEqual(services[80], "Apache httpd 2.4.49")

    def test_extract_empty_store(self):
        from app.findings import FindingsStore

        store = FindingsStore()
        services = extract_services_from_findings(store)
        self.assertEqual(len(services), 0)

    def test_malformed_service_value(self):
        from app.findings import Finding, FindingType, FindingsStore

        store = FindingsStore()
        store.add(Finding(FindingType.SERVICE, "no_slash_here", "nmap", "high"))
        store.add(Finding(FindingType.SERVICE, "abc/ssh", "nmap", "high"))

        services = extract_services_from_findings(store)
        # "no_slash_here" has no "/" so no port extracted
        # "abc/ssh" has non-numeric port so it should be skipped
        self.assertEqual(len(services), 0)


class TestServicePlaybookDataclass(unittest.TestCase):
    """Test ServicePlaybook data integrity."""

    def test_all_playbooks_have_tools(self):
        for pb in PLAYBOOKS:
            self.assertTrue(len(pb.tools) > 0, f"{pb.label} has no tools")

    def test_all_playbooks_have_checks(self):
        for pb in PLAYBOOKS:
            self.assertTrue(len(pb.checks) > 0, f"{pb.label} has no checks")

    def test_all_playbooks_have_valid_priority(self):
        valid = {"critical", "high", "medium", "low"}
        for pb in PLAYBOOKS:
            self.assertIn(pb.priority, valid, f"{pb.label} has invalid priority")

    def test_playbook_count(self):
        self.assertGreaterEqual(len(PLAYBOOKS), 10)


if __name__ == "__main__":
    unittest.main()
