"""Tests for findings module."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from app.findings import (
    Finding,
    FindingType,
    FindingsStore,
    parse_credential_value,
    parse_gobuster_output,
    parse_hydra_output,
    parse_nmap_output,
    parse_nikto_output,
    parse_tool_output,
)


class TestParseNmap(unittest.TestCase):
    SAMPLE = (
        "Starting Nmap 7.94 ( https://nmap.org )\n"
        "Nmap scan report for 10.10.10.5\n"
        "PORT     STATE SERVICE     VERSION\n"
        "22/tcp   open  ssh         OpenSSH 7.6p1\n"
        "80/tcp   open  http        Apache httpd 2.4.29\n"
        "445/tcp  open  netbios-ssn Samba smbd 4.7.6\n"
        "OS details: Ubuntu Linux 18.04\n"
    )

    def test_extracts_ports(self):
        findings = parse_nmap_output(self.SAMPLE)
        ports = [f for f in findings if f.finding_type == FindingType.PORT]
        self.assertEqual(len(ports), 3)
        values = {f.value for f in ports}
        self.assertEqual(values, {"22", "80", "445"})

    def test_extracts_services(self):
        findings = parse_nmap_output(self.SAMPLE)
        svcs = [f for f in findings if f.finding_type == FindingType.SERVICE]
        self.assertTrue(len(svcs) >= 3)
        svc_values = [f.value for f in svcs]
        self.assertTrue(any("ssh" in v for v in svc_values))
        self.assertTrue(any("http" in v for v in svc_values))

    def test_extracts_os(self):
        findings = parse_nmap_output(self.SAMPLE)
        os_findings = [f for f in findings if f.finding_type == FindingType.OS]
        self.assertEqual(len(os_findings), 1)
        self.assertIn("Ubuntu", os_findings[0].value)

    def test_sets_target_reference_and_severity(self):
        findings = parse_nmap_output(self.SAMPLE)
        self.assertTrue(findings)
        self.assertTrue(all(f.target_ref == "10.10.10.5" for f in findings))
        port_finding = next(f for f in findings if f.finding_type == FindingType.PORT)
        os_finding = next(f for f in findings if f.finding_type == FindingType.OS)
        self.assertEqual(port_finding.normalized_severity, "info")
        self.assertEqual(os_finding.normalized_severity, "low")

    def test_empty_output(self):
        self.assertEqual(parse_nmap_output(""), [])


class TestParseGobuster(unittest.TestCase):
    def test_status_format(self):
        output = "/admin (Status: 200)\n/login (Status: 302)\n"
        findings = parse_gobuster_output(output)
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0].finding_type, FindingType.PATH)

    def test_bracket_format(self):
        output = "/secret [Status: 200, Size: 1234]\n"
        findings = parse_gobuster_output(output)
        self.assertEqual(len(findings), 1)
        self.assertIn("/secret", findings[0].value)


class TestParseNikto(unittest.TestCase):
    def test_extracts_vulns(self):
        output = (
            "+ Target IP: 10.10.10.5\n"
            "+ Server: Apache/2.4.29\n"
            "+ /admin/: Directory indexing found.\n"
            "+ OSVDB-3092: /admin/: This might be interesting.\n"
        )
        findings = parse_nikto_output(output)
        vulns = [f for f in findings if f.finding_type == FindingType.VULNERABILITY]
        self.assertTrue(len(vulns) >= 1)


class TestParseHydra(unittest.TestCase):
    def test_extracts_credentials(self):
        output = "[22][ssh] host: 10.10.10.5   login: admin   password: secret123\n"
        findings = parse_hydra_output(output)
        self.assertEqual(len(findings), 1)
        credential = findings[0]
        self.assertEqual(credential.finding_type, FindingType.CREDENTIAL)
        self.assertIn("admin", credential.value)
        self.assertIn("secret123", credential.value)
        self.assertEqual(credential.target_ref, "10.10.10.5")
        self.assertEqual(credential.normalized_severity, "critical")
        self.assertEqual(credential.attributes["service"], "ssh")
        self.assertEqual(credential.attributes["username"], "admin")
        self.assertEqual(credential.attributes["password"], "secret123")
        self.assertEqual(credential.attributes["port"], "22")


class TestCredentialParsing(unittest.TestCase):
    def test_parse_credential_value(self):
        details = parse_credential_value("ssh://root:toor (port 22)")
        self.assertEqual(details["service"], "ssh")
        self.assertEqual(details["username"], "root")
        self.assertEqual(details["password"], "toor")
        self.assertEqual(details["port"], "22")


class TestParseToolOutput(unittest.TestCase):
    def test_routes_to_nmap(self):
        output = "22/tcp   open  ssh\n"
        findings = parse_tool_output("nmap", output)
        self.assertTrue(len(findings) > 0)

    def test_unknown_tool_returns_empty(self):
        self.assertEqual(parse_tool_output("unknown_tool", "data"), [])


class TestFindingsStore(unittest.TestCase):
    def test_add_and_count(self):
        store = FindingsStore()
        store.add(Finding(FindingType.PORT, "22", "nmap"))
        self.assertEqual(store.count, 1)

    def test_by_type(self):
        store = FindingsStore()
        store.add(Finding(FindingType.PORT, "22", "nmap"))
        store.add(Finding(FindingType.SERVICE, "22/ssh", "nmap"))
        self.assertEqual(len(store.ports), 1)
        self.assertEqual(len(store.services), 1)

    def test_ingest_tool_output(self):
        store = FindingsStore()
        new = store.ingest_tool_output("nmap", "80/tcp   open  http\n")
        self.assertTrue(len(new) > 0)
        self.assertEqual(store.count, len(new))

    def test_summary(self):
        store = FindingsStore()
        store.add(Finding(FindingType.PORT, "22", "nmap"))
        store.add(Finding(FindingType.PORT, "80", "nmap"))
        s = store.summary()
        self.assertIn("port", s)
        self.assertIn("22", s)

    def test_summary_empty(self):
        store = FindingsStore()
        self.assertIn("Aucune", store.summary())

    def test_clear(self):
        store = FindingsStore()
        store.add(Finding(FindingType.PORT, "22", "nmap"))
        store.clear()
        self.assertEqual(store.count, 0)

    def test_save_and_load_preserves_metadata(self):
        store = FindingsStore()
        store.add(Finding(
            finding_type=FindingType.CREDENTIAL,
            value="ssh://admin:secret123 (port 22)",
            source_tool="hydra",
            confidence="high",
            raw_output="raw line",
            severity="critical",
            target_ref="10.10.10.5",
            attributes={"service": "ssh", "username": "admin", "password": "secret123", "port": "22"},
        ))
        with TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "findings.json"
            store.save_state(path)
            restored = FindingsStore.load_state(path)

        self.assertEqual(restored.count, 1)
        restored_finding = restored.credentials[0]
        self.assertEqual(restored_finding.target_ref, "10.10.10.5")
        self.assertEqual(restored_finding.normalized_severity, "critical")
        self.assertEqual(restored_finding.raw_output, "raw line")
        self.assertEqual(restored_finding.attributes["username"], "admin")
        self.assertEqual(restored_finding.attributes["port"], "22")


if __name__ == "__main__":
    unittest.main()
