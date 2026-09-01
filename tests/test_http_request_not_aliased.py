"""#1 root cause: a registered tool (notably http_request, with multipart
upload) must never be aliased to run_shell/curl.

The RootMe run looped forever because every http_request call was hijacked into
`curl <url>` GET, dropping the upload params. _canonical_tool_name now leaves a
real registered tool alone and only falls back to the shell alias when the tool
is unavailable.
"""
from __future__ import annotations

import unittest
from types import SimpleNamespace

from secops_agent.core.agent import SecOpsAgent
from secops_agent.core.tools import ToolCategory, ToolRegistry


class CanonicalToolNameTests(unittest.TestCase):
    def _agent(self, *names: str) -> SimpleNamespace:
        registry = ToolRegistry()

        async def func(**_kwargs):
            return ""

        for name in names:
            registry.register(
                name=name, description=name, category=ToolCategory.WEB,
                parameters={}, func=func, dangerous=True,
            )
        return SimpleNamespace(registry=registry)

    def test_registered_http_request_reaches_the_real_tool(self):
        agent = self._agent("http_request", "run_shell")
        self.assertEqual(SecOpsAgent._canonical_tool_name(agent, "http_request"), "http_request")

    def test_registered_fetch_url_reaches_the_real_tool(self):
        agent = self._agent("fetch_url", "run_shell")
        self.assertEqual(SecOpsAgent._canonical_tool_name(agent, "fetch_url"), "fetch_url")

    def test_hallucinated_http_name_still_falls_back_to_shell(self):
        agent = self._agent("run_shell")  # http_request NOT available here
        self.assertEqual(SecOpsAgent._canonical_tool_name(agent, "http_request"), "run_shell")
        self.assertEqual(SecOpsAgent._canonical_tool_name(agent, "http_post"), "run_shell")

    def test_short_aliases_still_map(self):
        agent = self._agent("nmap_scan", "run_shell")
        self.assertEqual(SecOpsAgent._canonical_tool_name(agent, "nmap"), "nmap_scan")
        self.assertEqual(SecOpsAgent._canonical_tool_name(agent, "bash"), "run_shell")


if __name__ == "__main__":
    unittest.main()
