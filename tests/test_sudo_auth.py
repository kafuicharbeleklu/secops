from __future__ import annotations

import subprocess
import unittest
from unittest.mock import patch

from secops_agent.core.sudo import _validate_sudo_password


class FakeSudoProcess:
    def __init__(self, returncode: int = 0):
        self.returncode = returncode
        self.input: bytes | None = None
        self.killed = False

    def communicate(self, input: bytes | None = None, timeout: int | None = None):
        self.input = input
        return b"", b""

    def kill(self):
        self.killed = True

    def wait(self, timeout: int | None = None):
        return self.returncode


class SudoAuthenticationTests(unittest.TestCase):
    def test_password_authentication_creates_noninteractive_sudo_ticket(self):
        process = FakeSudoProcess(returncode=0)

        with patch("secops_agent.core.sudo.shutil.which", return_value="/usr/bin/sudo"), patch(
            "secops_agent.core.sudo.subprocess.Popen",
            return_value=process,
        ), patch(
            "secops_agent.core.sudo.subprocess.run",
            return_value=subprocess.CompletedProcess(["sudo", "-n", "true"], 0, b"", b""),
        ):
            decision = _validate_sudo_password("secret", 30)

        self.assertTrue(decision.success)
        self.assertEqual(process.input, b"secret\n")

    def test_password_authentication_fails_if_noninteractive_ticket_is_unusable(self):
        process = FakeSudoProcess(returncode=0)

        with patch("secops_agent.core.sudo.shutil.which", return_value="/usr/bin/sudo"), patch(
            "secops_agent.core.sudo.subprocess.Popen",
            return_value=process,
        ), patch(
            "secops_agent.core.sudo.subprocess.run",
            return_value=subprocess.CompletedProcess(
                ["sudo", "-n", "true"],
                1,
                b"",
                b"sudo: interactive authentication is required",
            ),
        ):
            decision = _validate_sudo_password("secret", 30)

        self.assertFalse(decision.success)
        self.assertIn("non-interactive sudo is still unavailable", decision.reason)


if __name__ == "__main__":
    unittest.main()
