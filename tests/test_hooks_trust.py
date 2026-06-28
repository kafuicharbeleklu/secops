import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from secops_agent.core.hooks import HookManager, _command_hash, load_hooks


class HookTrustTests(unittest.TestCase):
    def test_string_hook_defaults_to_untrusted_disabled(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            hook_path = Path(tmpdir) / "hooks.json"
            hook_path.write_text(json.dumps({"after_tool": ["echo done"]}), encoding="utf-8")

            manager = load_hooks([("workspace", hook_path)])

        self.assertEqual(1, len(manager.hooks))
        hook = manager.hooks[0]
        self.assertFalse(hook.enabled)
        self.assertEqual("pending_review", hook.trust_status)
        self.assertEqual([], manager.enabled_hooks)

    def test_hash_changed_hook_is_disabled(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            hook_path = Path(tmpdir) / "hooks.json"
            hook_path.write_text(
                json.dumps(
                    {
                        "after_tool": [
                            {
                                "name": "changed",
                                "command": "echo done",
                                "enabled": True,
                                "trusted_hash": "not-the-current-hash",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            manager = load_hooks([("workspace", hook_path)])

        self.assertEqual(1, len(manager.hooks))
        hook = manager.hooks[0]
        self.assertFalse(hook.enabled)
        self.assertEqual("hash_changed", hook.trust_status)

    def test_untrusted_hook_does_not_execute_run_cmd(self):
        manager = HookManager(
            hooks=[
                load_hooks_from_raw(
                    {
                        "after_tool": [
                            {
                                "name": "pending",
                                "command": "echo should-not-run",
                                "enabled": True,
                            }
                        ]
                    }
                ).hooks[0]
            ]
        )

        async def fake_run_cmd(*args, **kwargs):
            raise AssertionError("untrusted hook should not execute")

        with patch("secops_agent.core.hooks.run_cmd", fake_run_cmd):
            runs = asyncio.run(manager.run("after_tool", "nmap_scan", {"target": "127.0.0.1"}))

        self.assertEqual([], runs)

    def test_trusted_hook_executes_with_redacted_allowlisted_environment(self):
        command = ["python", "hook.py"]
        manager = load_hooks_from_raw(
            {
                "after_tool": [
                    {
                        "name": "trusted",
                        "command": command,
                        "enabled": True,
                        "trusted_hash": _command_hash(command),
                    }
                ]
            }
        )
        captured = {}

        async def fake_run_cmd(cmd, timeout, env, cwd):
            captured["cmd"] = cmd
            captured["timeout"] = timeout
            captured["env"] = env
            captured["cwd"] = cwd
            return "ok", "", 0

        with patch.dict(
            os.environ,
            {
                "PATH": "/usr/bin",
                "HOME": "/home/tester",
                "AWS_SECRET_ACCESS_KEY": "should-not-leak",
                "GEMINI_API_KEY": "should-not-leak",
            },
            clear=True,
        ):
            with patch("secops_agent.core.hooks.run_cmd", fake_run_cmd):
                runs = asyncio.run(
                    manager.run(
                        "after_tool",
                        "web_probe",
                        {
                            "target": "http://example.test",
                            "api_key": "live-key",
                            "nested": {"private_token": "nested-secret"},
                        },
                    )
                )

        self.assertEqual(1, len(runs))
        self.assertEqual(command, captured["cmd"])
        self.assertEqual("/usr/bin", captured["env"]["PATH"])
        self.assertEqual("/home/tester", captured["env"]["HOME"])
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", captured["env"])
        self.assertNotIn("GEMINI_API_KEY", captured["env"])
        args = json.loads(captured["env"]["SECOPS_TOOL_ARGS_JSON"])
        self.assertEqual("[REDACTED]", args["api_key"])
        self.assertEqual("[REDACTED]", args["nested"]["private_token"])


def load_hooks_from_raw(raw: dict) -> HookManager:
    with tempfile.TemporaryDirectory() as tmpdir:
        hook_path = Path(tmpdir) / "hooks.json"
        hook_path.write_text(json.dumps(raw), encoding="utf-8")
        return load_hooks([("workspace", hook_path)])


if __name__ == "__main__":
    unittest.main()
