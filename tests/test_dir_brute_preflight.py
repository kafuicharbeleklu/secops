"""Regression test for A3 (dir_brute): plural "find hidden directories on <url>"
must route to dir_brute, not fall through because the marker was singular."""
from __future__ import annotations

import unittest

# Register the real tools so dir_brute is available to the router.
from secops_agent.tools import (  # noqa: F401
    crypto,
    exploit,
    exploitation,
    forensics,
    network,
    recon,
    web,
)
from secops_agent.core.preflight import PreflightRouter
from secops_agent.core.request_context import classify_request
from secops_agent.core.tools import registry


class DirBrutePreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        self.router = PreflightRouter(registry=registry)

    def _route(self, prompt: str):
        return self.router.route(prompt, classify_request(prompt))

    def test_plural_hidden_directories_routes_dir_brute(self) -> None:
        calls = self._route("find hidden directories on http://10.10.10.5")
        self.assertTrue(any(c.name == "dir_brute" for c in calls))

    def test_singular_hidden_directory_still_routes(self) -> None:
        calls = self._route("find the hidden directory on http://10.10.10.5")
        self.assertTrue(any(c.name == "dir_brute" for c in calls))


if __name__ == "__main__":
    unittest.main()
