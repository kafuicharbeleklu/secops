from __future__ import annotations

import unittest

from secops_agent.core.mission import Evidence, Finding, MissionContext
from secops_agent.core.result_parser import ToolResultParser
from secops_agent.core.structured_memory import KnowledgeBase


class EvidenceModelTests(unittest.TestCase):
    def test_finding_builds_structured_evidence_from_legacy_text(self):
        finding = Finding(
            title="Missing security headers",
            severity="low",
            category="headers",
            target="https://example.com",
            evidence="Missing: Strict-Transport-Security",
            tool_used="http_headers",
        )

        self.assertEqual(len(finding.evidence_items), 1)
        evidence = finding.evidence_items[0]
        self.assertEqual(evidence.source_tool, "http_headers")
        self.assertEqual(evidence.target, "https://example.com")
        self.assertIn("Strict-Transport-Security", evidence.snippet)

    def test_finding_evidence_roundtrip_preserves_source_metadata(self):
        finding = Finding(
            title="SQL Injection in 'id'",
            severity="critical",
            category="sqli",
            target="http://example.com/item?id=1",
            evidence="Parameter: id",
            tool_used="sql_injection_test",
            evidence_items=[
                Evidence(
                    title="SQL Injection in 'id'",
                    source_tool="sql_injection_test",
                    target="http://example.com/item?id=1",
                    snippet="Parameter: id",
                    metadata={"parameter": "id", "place": "GET"},
                )
            ],
        )

        restored = Finding.from_dict(finding.to_dict())

        self.assertEqual(restored.evidence, "Parameter: id")
        self.assertEqual(len(restored.evidence_items), 1)
        self.assertEqual(restored.evidence_items[0].metadata["parameter"], "id")
        self.assertEqual(restored.evidence_items[0].source_tool, "sql_injection_test")

    def test_finding_merge_deduplicates_evidence_items(self):
        first = Finding(
            title="Interesting path: /admin (200)",
            severity="medium",
            category="dir_enum",
            target="http://example.com",
            evidence="Status 200, Size 1234",
            tool_used="dir_brute",
        )
        duplicate = Finding(
            title="Interesting path: /admin (200)",
            severity="medium",
            category="dir_enum",
            target="http://example.com",
            evidence="Status 200, Size 1234",
            tool_used="dir_brute",
        )
        new_evidence = Finding(
            title="Interesting path: /admin (200)",
            severity="medium",
            category="dir_enum",
            target="http://example.com",
            evidence="Status 301, Size 1234",
            tool_used="dir_brute",
        )

        first.merge_from(duplicate)
        first.merge_from(new_evidence)

        self.assertEqual(len(first.evidence_items), 2)
        self.assertIn("Status 301", first.evidence)

    def test_parser_attaches_http_header_evidence_metadata(self):
        parser = ToolResultParser()
        raw = """HTTP/1.1 200 OK
Server: Apache/2.4.49
X-Frame-Options: DENY
"""

        parsed = parser.parse("http_headers", raw, {"url": "https://example.com"})

        evidence = parsed.findings[0].evidence_items[0]
        self.assertEqual(evidence.source_tool, "http_headers")
        self.assertEqual(evidence.metadata["missing_headers"], [
            "X-Content-Type-Options",
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-XSS-Protection",
        ])
        self.assertIn("server", evidence.metadata["observed_headers"])

    def test_parser_attaches_sqlmap_evidence_metadata_to_mission(self):
        mission = MissionContext(name="evidence mission")
        parser = ToolResultParser(mission=mission)
        raw = """Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
back-end DBMS: MySQL >= 5.0
"""

        parsed = parser.parse("sql_injection_test", raw, {"url": "http://example.com/item?id=1"})

        self.assertEqual(len(parsed.findings), 1)
        self.assertEqual(len(mission.findings), 1)
        evidence = mission.findings[0].evidence_items[0]
        self.assertEqual(evidence.source_tool, "sql_injection_test")
        self.assertEqual(evidence.metadata["parameter"], "id")
        self.assertEqual(evidence.metadata["place"], "GET")
        self.assertEqual(evidence.metadata["types"], ["boolean-based blind"])

    def test_mission_and_knowledge_summaries_include_evidence_counts(self):
        finding = Finding(
            title="Missing security headers",
            severity="low",
            category="headers",
            target="https://example.com",
            evidence="Missing: Strict-Transport-Security",
            tool_used="http_headers",
        )
        mission = MissionContext(name="summary evidence mission")
        mission.upsert_finding(finding)
        knowledge = KnowledgeBase()
        knowledge.add_finding(finding)

        self.assertIn("evidence:1", mission.build_prompt_summary())
        self.assertIn("evidence:1", knowledge.build_summary())


if __name__ == "__main__":
    unittest.main()
