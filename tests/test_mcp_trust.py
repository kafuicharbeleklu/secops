import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from secops_agent.core.mcp import (
    MCPRuntime,
    MCPServerSession,
    _mcp_schema_to_parameters,
    _mcp_server_hash,
    _mcp_start_environment,
    load_mcp_config,
)
from secops_agent.core.tools import ToolRegistry


class MCPTrustTests(unittest.TestCase):
    def test_mcp_config_without_trusted_hash_is_not_enabled(self):
        state = load_mcp_from_raw(
            {
                "mcpServers": {
                    "evidence": {
                        "command": "python",
                        "args": ["server.py"],
                    }
                }
            }
        )

        self.assertEqual(1, len(state.servers))
        self.assertEqual("pending_review", state.servers[0].trust_status)
        self.assertEqual([], state.enabled_servers)

    def test_mcp_config_with_matching_trusted_hash_is_enabled(self):
        env = {"TOKEN": "configured-token"}
        trusted_hash = _mcp_server_hash("python", ["server.py"], env)
        state = load_mcp_from_raw(
            {
                "mcpServers": {
                    "evidence": {
                        "command": "python",
                        "args": ["server.py"],
                        "env": env,
                        "trusted_hash": trusted_hash,
                    }
                }
            }
        )

        self.assertEqual(1, len(state.enabled_servers))
        self.assertEqual("trusted", state.servers[0].trust_status)

    def test_untrusted_mcp_server_is_not_started(self):
        state = load_mcp_from_raw({"mcpServers": {"evidence": {"command": "python", "args": ["server.py"]}}})
        runtime = MCPRuntime()

        async def fail_start(*args, **kwargs):
            raise AssertionError("untrusted MCP server should not start")

        with patch.object(MCPServerSession, "start", fail_start):
            count = asyncio.run(runtime.start(state, ToolRegistry()))

        self.assertEqual(0, count)
        self.assertIn("requires review", "\n".join(runtime.errors))

    def test_mcp_start_environment_does_not_inherit_ambient_secrets(self):
        with patch.dict(
            os.environ,
            {
                "PATH": "/usr/bin",
                "HOME": "/home/tester",
                "GEMINI_API_KEY": "ambient-secret",
                "AWS_SECRET_ACCESS_KEY": "ambient-secret",
            },
            clear=True,
        ):
            env = _mcp_start_environment({"MCP_TOKEN": "configured-token"})

        self.assertEqual("/usr/bin", env["PATH"])
        self.assertEqual("/home/tester", env["HOME"])
        self.assertEqual("configured-token", env["MCP_TOKEN"])
        self.assertNotIn("GEMINI_API_KEY", env)
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", env)

    def test_mcp_schema_preserves_enum_array_items_and_nested_objects(self):
        params = _mcp_schema_to_parameters(
            {
                "type": "object",
                "required": ["mode", "options"],
                "properties": {
                    "mode": {
                        "type": "string",
                        "enum": ["fast", "deep"],
                        "description": "Scan mode",
                    },
                    "ports": {
                        "type": "array",
                        "items": {"type": "integer", "description": "TCP port"},
                    },
                    "options": {
                        "type": "object",
                        "required": ["path"],
                        "properties": {
                            "path": {"type": "string"},
                            "aggressive": {"type": "boolean"},
                        },
                    },
                },
            }
        )

        self.assertEqual(["fast", "deep"], params["mode"]["enum"])
        self.assertTrue(params["mode"]["required"])
        self.assertEqual("integer", params["ports"]["items"]["type"])
        self.assertEqual("object", params["options"]["type"])
        self.assertTrue(params["options"]["required"])
        self.assertTrue(params["options"]["properties"]["path"]["required"])
        self.assertFalse(params["options"]["properties"]["aggressive"]["required"])


def load_mcp_from_raw(raw: dict):
    with tempfile.TemporaryDirectory() as tmpdir:
        config_path = Path(tmpdir) / "mcp_config.json"
        config_path.write_text(json.dumps(raw), encoding="utf-8")
        return load_mcp_config([("workspace", config_path)])


if __name__ == "__main__":
    unittest.main()
