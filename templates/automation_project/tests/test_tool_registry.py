"""Tests for tool_registry module."""

import unittest
from unittest.mock import patch

from app.tool_registry import PentestTool, ToolCategory, ToolRegistry


class TestToolRegistry(unittest.TestCase):
    def _make_catalog(self):
        return [
            {
                "name": "nmap",
                "category": ToolCategory.RECON,
                "description": "Port scanner.",
                "package": "nmap",
                "phases": ("recon", "enumeration"),
                "target_types": ("ip", "domain"),
            },
            {
                "name": "gobuster",
                "category": ToolCategory.ENUM,
                "description": "Dir brute-force.",
                "package": "gobuster",
                "phases": ("enumeration",),
                "target_types": ("ip", "url"),
            },
            {
                "name": "sqlmap",
                "category": ToolCategory.EXPLOIT,
                "description": "SQL injection.",
                "package": "sqlmap",
                "phases": ("exploitation",),
                "target_types": ("url",),
            },
        ]

    @patch("shutil.which")
    def test_scan_detects_installed(self, mock_which):
        mock_which.side_effect = lambda name: f"/usr/bin/{name}" if name == "nmap" else None
        registry = ToolRegistry(catalog=self._make_catalog())
        self.assertTrue(registry.is_installed("nmap"))
        self.assertFalse(registry.is_installed("gobuster"))
        self.assertFalse(registry.is_installed("sqlmap"))

    @patch("shutil.which", return_value=None)
    def test_all_tools_returns_all(self, _):
        registry = ToolRegistry(catalog=self._make_catalog())
        self.assertEqual(len(registry.all_tools), 3)

    @patch("shutil.which", return_value=None)
    def test_installed_tools_empty(self, _):
        registry = ToolRegistry(catalog=self._make_catalog())
        self.assertEqual(len(registry.installed_tools), 0)

    @patch("shutil.which")
    def test_suggest_by_phase(self, mock_which):
        mock_which.return_value = "/usr/bin/tool"
        registry = ToolRegistry(catalog=self._make_catalog())
        recon_tools = registry.suggest_tools(phase="recon")
        names = [t.name for t in recon_tools]
        self.assertIn("nmap", names)
        self.assertNotIn("sqlmap", names)

    @patch("shutil.which")
    def test_suggest_by_target_type(self, mock_which):
        mock_which.return_value = "/usr/bin/tool"
        registry = ToolRegistry(catalog=self._make_catalog())
        url_tools = registry.suggest_tools(target_type="url")
        names = [t.name for t in url_tools]
        self.assertIn("gobuster", names)
        self.assertIn("sqlmap", names)
        self.assertNotIn("nmap", names)

    @patch("shutil.which", return_value=None)
    def test_get_package(self, _):
        registry = ToolRegistry(catalog=self._make_catalog())
        self.assertEqual(registry.get_package("nmap"), "nmap")
        self.assertIsNone(registry.get_package("unknown"))

    @patch("shutil.which", return_value=None)
    def test_is_known(self, _):
        registry = ToolRegistry(catalog=self._make_catalog())
        self.assertTrue(registry.is_known("nmap"))
        self.assertFalse(registry.is_known("unknown"))

    @patch("shutil.which", return_value=None)
    def test_normalizes_common_tool_typos(self, _):
        catalog = self._make_catalog() + [
            {
                "name": "traceroute",
                "category": ToolCategory.RECON,
                "description": "Route tracing.",
                "package": "traceroute",
                "phases": ("recon",),
                "target_types": ("ip",),
            }
        ]
        registry = ToolRegistry(catalog=catalog)
        self.assertEqual(registry.normalize_name("tracerout"), "traceroute")
        self.assertTrue(registry.is_known("tracerout"))
        self.assertEqual(registry.get_package("tracerout"), "traceroute")

    @patch("shutil.which", return_value=None)
    def test_known_executables(self, _):
        registry = ToolRegistry(catalog=self._make_catalog())
        execs = registry.known_executables()
        self.assertEqual(execs, {"nmap", "gobuster", "sqlmap"})

    @patch("shutil.which", return_value=None)
    def test_format_inventory_empty(self, _):
        registry = ToolRegistry(catalog=self._make_catalog())
        inv = registry.format_inventory(installed_only=True)
        self.assertIn("Aucun outil", inv)

    @patch("shutil.which", return_value="/usr/bin/x")
    def test_format_inventory_all(self, _):
        registry = ToolRegistry(catalog=self._make_catalog())
        inv = registry.format_inventory()
        self.assertIn("nmap", inv)
        self.assertIn("gobuster", inv)

    @patch("shutil.which")
    def test_refresh(self, mock_which):
        mock_which.return_value = None
        registry = ToolRegistry(catalog=self._make_catalog())
        self.assertFalse(registry.is_installed("nmap"))
        mock_which.return_value = "/usr/bin/nmap"
        registry.refresh()
        self.assertTrue(registry.is_installed("nmap"))


if __name__ == "__main__":
    unittest.main()
