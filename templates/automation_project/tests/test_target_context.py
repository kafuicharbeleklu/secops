"""Tests for target_context module."""

import unittest

from app.target_context import (
    Target,
    TargetType,
    build_target_context,
    detect_targets,
    merge_findings,
)


class TestDetectTargets(unittest.TestCase):
    def test_single_ip(self):
        targets = detect_targets("scanne la cible 10.10.10.5")
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].target_type, TargetType.IP)
        self.assertEqual(targets[0].address, "10.10.10.5")

    def test_multiple_ips(self):
        targets = detect_targets("cibles: 10.10.10.5, 192.168.1.100")
        self.assertEqual(len(targets), 2)
        self.assertEqual(targets[0].address, "10.10.10.5")
        self.assertEqual(targets[1].address, "192.168.1.100")

    def test_excludes_loopback(self):
        targets = detect_targets("ping 127.0.0.1")
        self.assertEqual(len(targets), 0)

    def test_excludes_broadcast(self):
        targets = detect_targets("adresse 255.255.255.255")
        self.assertEqual(len(targets), 0)

    def test_cidr_detection(self):
        targets = detect_targets("scan le reseau 192.168.1.0/24")
        cidr = [t for t in targets if t.target_type == TargetType.CIDR]
        self.assertEqual(len(cidr), 1)
        self.assertEqual(cidr[0].address, "192.168.1.0/24")

    def test_url_detection(self):
        targets = detect_targets("teste http://example.com/login")
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].target_type, TargetType.URL)
        self.assertEqual(targets[0].address, "example.com")

    def test_https_url(self):
        targets = detect_targets("cible: https://secure.target.io:8443/api")
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].target_type, TargetType.URL)
        self.assertEqual(targets[0].address, "secure.target.io")

    def test_domain_detection(self):
        targets = detect_targets("enumere target.htb")
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].target_type, TargetType.DOMAIN)
        self.assertEqual(targets[0].address, "target.htb")

    def test_deduplication(self):
        targets = detect_targets("ping 10.10.10.5 puis nmap 10.10.10.5")
        self.assertEqual(len(targets), 1)

    def test_mixed_targets(self):
        text = "scan 10.10.10.5, enumere http://web.target.com et 192.168.0.0/16"
        targets = detect_targets(text)
        types = {t.target_type for t in targets}
        self.assertIn(TargetType.IP, types)
        self.assertIn(TargetType.URL, types)
        self.assertIn(TargetType.CIDR, types)

    def test_empty_string(self):
        self.assertEqual(detect_targets(""), [])

    def test_no_targets(self):
        self.assertEqual(detect_targets("bonjour comment ca va"), [])


class TestTarget(unittest.TestCase):
    def test_label_ip(self):
        t = Target(raw="10.10.10.5", target_type=TargetType.IP, address="10.10.10.5")
        self.assertEqual(t.label, "10.10.10.5")

    def test_label_url(self):
        t = Target(raw="http://x.com/a", target_type=TargetType.URL, address="x.com")
        self.assertEqual(t.label, "http://x.com/a")

    def test_summary_basic(self):
        t = Target(raw="10.10.10.5", target_type=TargetType.IP, address="10.10.10.5")
        s = t.summary
        self.assertIn("ip", s)
        self.assertIn("10.10.10.5", s)

    def test_summary_with_ports(self):
        t = Target(raw="10.10.10.5", target_type=TargetType.IP, address="10.10.10.5", ports=[22, 80])
        self.assertIn("22", t.summary)
        self.assertIn("80", t.summary)


class TestMergeFindings(unittest.TestCase):
    def test_merge_port(self):
        t = Target(raw="10.10.10.5", target_type=TargetType.IP, address="10.10.10.5")

        class FakeFinding:
            def __init__(self, ft, val):
                self.finding_type = ft
                self.value = val

        class FakeType:
            def __init__(self, v):
                self.value = v

        merge_findings(t, [FakeFinding(FakeType("port"), "22")])
        self.assertIn(22, t.ports)

    def test_merge_service(self):
        t = Target(raw="10.10.10.5", target_type=TargetType.IP, address="10.10.10.5")

        class FakeFinding:
            def __init__(self, ft, val):
                self.finding_type = ft
                self.value = val

        class FakeType:
            def __init__(self, v):
                self.value = v

        merge_findings(t, [FakeFinding(FakeType("service"), "80/http")])
        self.assertEqual(t.services.get(80), "http")
        self.assertIn("web", t.tags)


class TestBuildTargetContext(unittest.TestCase):
    def test_no_targets(self):
        ctx = build_target_context([], None)
        self.assertIn("Aucune cible", ctx)

    def test_active_target(self):
        t = Target(raw="10.10.10.5", target_type=TargetType.IP, address="10.10.10.5")
        ctx = build_target_context([t], t)
        self.assertIn("Cible active", ctx)
        self.assertIn("10.10.10.5", ctx)


if __name__ == "__main__":
    unittest.main()
