from __future__ import annotations

import unittest

from secops_agent.core.result_parser import ToolResultParser


class ResultParserTests(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = ToolResultParser()

    def test_dns_parser_extracts_records_hosts_and_next_steps(self):
        raw = """example.com. 300 IN A 93.184.216.34
example.com. 300 IN AAAA 2606:2800:220:1:248:1893:25c8:1946
example.com. 300 IN MX 10 mail.example.com.
example.com. 300 IN NS ns1.example.com.
"""

        parsed = self.parser.parse("dns_lookup", raw, {"domain": "example.com"})

        self.assertEqual(len(parsed.data["records"]), 4)
        self.assertEqual(len(parsed.hosts_discovered), 2)
        self.assertIn("93.184.216.34", {host.ip for host in parsed.hosts_discovered})
        self.assertIn("Run nmap_scan", parsed.next_steps[0])

    def test_whois_parser_extracts_registration_metadata(self):
        raw = """Domain Name: EXAMPLE.COM
Registrar: Example Registrar LLC
Registrant Organization: Example Org
Domain Status: clientTransferProhibited
Name Server: NS1.EXAMPLE.COM
Name Server: NS2.EXAMPLE.COM
Registrant Email: admin@example.com
"""

        parsed = self.parser.parse("whois_lookup", raw, {"target": "example.com"})

        self.assertEqual(parsed.data["domain"], "EXAMPLE.COM")
        self.assertEqual(parsed.data["registrar"], "Example Registrar LLC")
        self.assertEqual(parsed.data["nameservers"], ["NS1.EXAMPLE.COM", "NS2.EXAMPLE.COM"])
        self.assertIn("Run DNS lookups", parsed.next_steps[0])
        self.assertFalse(parsed.findings)

    def test_http_headers_parser_uses_actual_headers_not_analysis_labels(self):
        raw = """HTTP/1.1 200 OK
Server: Apache/2.4.49
X-Frame-Options: DENY

Missing Security Headers:
  X-Frame-Options (Clickjacking Protection) - MISSING
  Strict-Transport-Security (HSTS) - MISSING
"""

        parsed = self.parser.parse("http_headers", raw, {"url": "https://example.com"})

        finding = parsed.findings[0]
        self.assertIn("Strict-Transport-Security", finding.evidence)
        self.assertNotIn("X-Frame-Options", finding.evidence)
        self.assertEqual(parsed.data["headers"]["server"], "Apache/2.4.49")

    def test_ssl_parser_detects_expired_and_self_signed_certificate(self):
        raw = """subject=CN=example.com
issuer=CN=example.com
notBefore=May  1 00:00:00 2026 GMT
notAfter=May 30 00:00:00 2026 GMT
serial=01
Verify return code: 10 (certificate has expired)
"""

        parsed = self.parser.parse("ssl_check", raw, {"domain": "example.com"})

        titles = {finding.title for finding in parsed.findings}
        self.assertIn("SSL certificate expired on example.com", titles)
        self.assertIn("Self-signed certificate on example.com", titles)
        self.assertEqual(parsed.severity, "high")
        self.assertEqual(parsed.data["subject"], "CN=example.com")

    def test_dir_brute_parser_handles_gobuster_dirb_and_ffuf_formats(self):
        raw = """/admin (Status: 200) [Size: 1234]
panel (Status: 301) [Size: 316] [--> http://example.com/panel/]
uploads (Status: 301) [Size: 318] [--> http://example.com/uploads/]
==> DIRECTORY: http://example.com/backup/
.git [Status: 200, Size: 321, Words: 10, Lines: 5]
"""

        parsed = self.parser.parse("dir_brute", raw, {"url": "http://example.com"})

        paths = {entry["path"] for entry in parsed.data["paths"]}
        self.assertEqual(paths, {"/admin", "/panel", "/uploads", "/backup/", "/.git"})
        self.assertEqual(len(parsed.findings), 5)
        self.assertTrue(any(step.startswith("Dump .git repository") for step in parsed.next_steps))

    def test_dir_brute_parser_records_missing_wordlist_as_operational_blocker(self):
        raw = 'No results. 2026/06/02 wordlist file "/usr/share/wordlists/dirb/common.txt" does not exist: stat'

        parsed = self.parser.parse("dir_brute", raw, {"url": "http://example.com"})

        self.assertEqual(parsed.data["missing_wordlist"], "/usr/share/wordlists/dirb/common.txt")
        self.assertEqual(parsed.findings[0].category, "tool_prerequisite_missing")
        self.assertEqual(parsed.findings[0].severity, "info")
        self.assertIn("Retry dir_brute", parsed.next_steps[0])

    def test_dir_brute_parser_records_empty_result_as_operational_signal(self):
        parsed = self.parser.parse("dir_brute", "No results.", {"url": "http://example.com"})

        finding = parsed.findings[0]
        self.assertEqual(finding.category, "content_discovery_empty")
        self.assertEqual(finding.severity, "info")
        self.assertTrue(parsed.data["empty_result"])
        self.assertIn("extensions", parsed.next_steps[0])
        self.assertNotIn("Investigate interesting paths manually", parsed.next_steps)

    def test_parser_records_supervised_timeout_as_operational_signal(self):
        parsed = self.parser.parse(
            "nikto_scan",
            "Tool execution timed out after 605s.",
            {"url": "http://example.com"},
        )

        finding = parsed.findings[0]
        self.assertEqual(finding.category, "tool_timeout")
        self.assertEqual(finding.severity, "info")
        self.assertEqual(finding.tool_used, "nikto_scan")
        self.assertTrue(parsed.data["timeout_detected"])
        self.assertIn("Retry nikto_scan", parsed.next_steps[0])

    def test_lab_setup_parser_records_installable_missing_tools_from_readiness(self):
        raw = """Local Lab Setup: HackTheBox

Tools:
  nmap: not installed
  curl: /usr/bin/curl
  gobuster: not installed
  dirb: /usr/bin/dirb
  openvpn: not installed
  python3: /usr/bin/python3
"""

        parsed = self.parser.parse("lab_setup_check", raw, {"provider": "hackthebox"})

        missing_tools = set(parsed.data["missing_tools"])
        self.assertEqual(missing_tools, {"nmap", "openvpn"})
        self.assertNotIn("gobuster", missing_tools)

    def test_missing_ffuf_install_command_is_shell_safe(self):
        parsed = self.parser.parse(
            "ffuf_scan",
            "❌ ffuf is not installed. Install with: go install github.com/ffuf/ffuf/v2@latest",
            {"url": "http://example.com/FUZZ"},
        )

        finding = next(item for item in parsed.findings if item.title == "Missing local tool: ffuf")
        metadata = finding.evidence_items[0].metadata
        self.assertEqual(metadata["install_package"], "ffuf")
        self.assertEqual(metadata["install_command"], "sudo apt install -y ffuf")
        self.assertNotIn("(", metadata["install_command"])

    def test_nmap_parser_records_host_discovery_failure_retry_hint(self):
        raw = """Starting Nmap 7.98 ( https://nmap.org ) at 2026-06-02 21:24 +0000
Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
Nmap done: 1 IP address (0 hosts up) scanned in 2.26 seconds
"""

        parsed = self.parser.parse("nmap_scan", raw, {"target": "10.129.153.73"})

        self.assertTrue(parsed.data["host_discovery_failed"])
        self.assertEqual(parsed.findings[0].category, "scan_host_discovery_failed")
        self.assertEqual(parsed.findings[0].severity, "info")
        self.assertIn("-Pn", parsed.next_steps[0])

    def test_parser_records_missing_tool_install_hint(self):
        raw = "❌ Error: nmap is not installed. Install with: sudo apt install nmap"

        parsed = self.parser.parse("nmap_scan", raw, {"target": "10.10.10.5"})

        missing = next(finding for finding in parsed.findings if finding.category == "tool_prerequisite_missing")
        metadata = missing.evidence_items[0].metadata
        self.assertEqual(missing.severity, "info")
        self.assertEqual(metadata["missing_tool"], "nmap")
        self.assertEqual(metadata["install_package"], "nmap")
        self.assertEqual(metadata["install_command"], "sudo apt install -y nmap")
        self.assertIn("nmap", parsed.data["missing_tools"])
        self.assertIn("Install missing local tool: nmap", parsed.next_steps[0])

    def test_nikto_parser_handles_pathless_header_findings(self):
        raw = """+ Server: Apache/2.4.49
+ /admin/: Directory indexing found.
+ The X-Content-Type-Options header is not defined.
+ OSVDB-3092: /backup/: This might be interesting.
"""

        parsed = self.parser.parse("nikto_scan", raw, {"url": "http://example.com"})

        self.assertEqual(parsed.data["server"], "Apache/2.4.49")
        self.assertEqual(len(parsed.findings), 3)
        self.assertTrue(any("X-Content-Type-Options" in finding.title for finding in parsed.findings))
        self.assertEqual(parsed.severity, "medium")

    def test_sqlmap_parser_collects_injection_types_and_dbms(self):
        raw = """Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 123=123
    Type: time-based blind
    Title: MySQL >= 5.0.12 time-based blind
back-end DBMS: MySQL >= 5.0
"""

        parsed = self.parser.parse("sql_injection_test", raw, {"url": "http://example.com/item?id=1"})

        self.assertEqual(len(parsed.findings), 1)
        self.assertIn("boolean-based blind", parsed.findings[0].evidence)
        self.assertIn("time-based blind", parsed.findings[0].evidence)
        self.assertEqual(parsed.data["dbms"], "MySQL >= 5.0")
        self.assertEqual(parsed.severity, "critical")

    def test_searchsploit_parser_extracts_text_table_references(self):
        raw = """Exploit Title                                      | Path
--------------------------------------------------- | -------------------------
Apache HTTP Server 2.4.49 - Path Traversal          | linux/remote/50383.py
Apache HTTP Server 2.4.50 - Remote Code Execution   | multiple/remote/50406.py
"""

        parsed = self.parser.parse("searchsploit", raw, {"query": "Apache 2.4.49"})

        self.assertEqual(len(parsed.data["results"]), 2)
        self.assertEqual(len(parsed.findings), 2)
        self.assertEqual(parsed.findings[0].severity, "info")
        self.assertIn("Review exploit applicability", parsed.next_steps[0])

    def test_cve_parser_reads_cvss_from_json_detail(self):
        raw = """🔍 CVE Lookup: CVE-2021-41773

📋 CVE Details:
{"id": "CVE-2021-41773", "summary": "Path traversal and file disclosure in Apache HTTP Server.", "cvss": 9.8}
"""

        parsed = self.parser.parse("cve_lookup", raw, {"cve_id": "CVE-2021-41773"})

        self.assertEqual(len(parsed.findings), 1)
        self.assertEqual(parsed.findings[0].severity, "critical")
        self.assertEqual(parsed.data["cvss"], 9.8)
        self.assertIn("Correlate CVE", parsed.next_steps[0])

    def test_run_shell_parser_extracts_unusual_suid_candidates(self):
        raw = """/usr/bin/passwd
/usr/bin/sudo
/usr/bin/bash
/usr/local/bin/nmap
[Exit Code: 0]
"""

        parsed = self.parser.parse(
            "run_shell",
            raw,
            {"command": "find / -perm -4000 -type f 2>/dev/null"},
        )

        targets = {finding.target for finding in parsed.findings}
        self.assertEqual(targets, {"/usr/bin/bash", "/usr/local/bin/nmap"})
        self.assertEqual(parsed.severity, "high")
        self.assertTrue(all(finding.category == "suid_binary" for finding in parsed.findings))
        self.assertIn("privilege-escalation review", parsed.next_steps[0])

    def test_generic_parser_surfaces_short_output_as_the_summary(self):
        # vpn_status has no dedicated parser -> generic fallback. The summary
        # must be the actual fact, not a "N line(s) of output" meta count.
        parsed = self.parser.parse(
            "vpn_status", "VPN active: connected via tun0 (10.10.14.7)", {}
        )

        self.assertEqual(parsed.summary, "VPN active: connected via tun0 (10.10.14.7)")
        self.assertNotIn("line(s) of output", parsed.summary)

    def test_generic_parser_leads_long_output_with_first_line_and_count(self):
        raw = "\n".join(f"line {i}" for i in range(1, 21))

        parsed = self.parser.parse("some_tool", raw, {})

        self.assertTrue(parsed.summary.startswith("line 1"))
        self.assertIn("+19 more line(s)", parsed.summary)

    def test_generic_parser_lead_skips_banner_and_section_rule(self):
        raw = (
            "🖥️  System Information\n"
            "── OS ──\n"
            "  Hostname: ubuntu-desktop\n"
            "  OS: Ubuntu 26.04 LTS\n"
        ) + "\n".join(f"  detail{i}: value" for i in range(10))

        parsed = self.parser.parse("sysinfo", raw, {})

        # Leads with the first key:value fact, not the emoji banner or "── OS ──".
        self.assertTrue(parsed.summary.startswith("Hostname: ubuntu-desktop"))
        self.assertNotIn("System Information", parsed.summary)
        self.assertNotIn("── OS ──", parsed.summary)

    def test_generic_parser_handles_empty_output(self):
        parsed = self.parser.parse("vpn_status", "   \n  ", {})

        self.assertEqual(parsed.summary, "vpn_status: (no output)")


if __name__ == "__main__":
    unittest.main()
