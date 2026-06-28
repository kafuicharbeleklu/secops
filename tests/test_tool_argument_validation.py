from __future__ import annotations

import unittest
from unittest.mock import patch

from secops_agent.core.tools import ToolCategory, ToolRegistry, ToolRiskClass, registry


class ToolArgumentValidationTests(unittest.IsolatedAsyncioTestCase):
    async def test_execute_coerces_simple_types_defaults_and_ignores_unknowns(self):
        seen = {}

        async def probe(target: str, ports: str = "", count: int = 0, follow: bool = False, modes=None):
            seen.update({
                "target": target,
                "ports": ports,
                "count": count,
                "follow": follow,
                "modes": modes,
            })
            return "ok"

        registry = ToolRegistry()
        registry.register(
            name="probe",
            description="Probe target",
            category=ToolCategory.RECON,
            parameters={
                "target": {"type": "string", "required": True},
                "ports": {"type": "string", "required": False},
                "count": {"type": "integer", "required": False, "default": 4},
                "follow": {"type": "boolean", "required": False, "default": False},
                "modes": {
                    "type": "array",
                    "items": {"type": "string", "enum": ["quick", "deep"]},
                    "required": False,
                },
            },
            func=probe,
        )

        with self.assertLogs("secops_agent.core.tools", level="WARNING") as captured:
            result = await registry.execute(
                "probe",
                {
                    "target": 123,
                    "ports": [80, 443],
                    "count": "5",
                    "follow": "yes",
                    "modes": "quick,deep",
                    "unexpected": "ignored",
                },
            )

        self.assertTrue(result.success, result.error)
        self.assertEqual(result.output, "ok")
        self.assertIn("Ignoring unexpected argument", captured.output[0])
        self.assertEqual(seen, {
            "target": "123",
            "ports": "80,443",
            "count": 5,
            "follow": True,
            "modes": ["quick", "deep"],
        })

    async def test_execute_returns_error_for_missing_required_argument(self):
        executed = False

        async def probe(target: str):
            nonlocal executed
            executed = True
            return target

        registry = ToolRegistry()
        registry.register(
            name="probe",
            description="Probe target",
            category=ToolCategory.RECON,
            parameters={"target": {"type": "string", "required": True}},
            func=probe,
        )

        result = await registry.execute("probe", {})

        self.assertFalse(result.success)
        self.assertFalse(executed)
        self.assertIn("Invalid arguments for tool 'probe'", result.error or "")
        self.assertIn("missing required argument 'target'", result.error or "")
        self.assertEqual(result.metadata["risk_class"], ToolRiskClass.NETWORK_OBSERVATION.value)
        self.assertEqual(result.metadata["tool_category"], ToolCategory.RECON.value)

    async def test_execute_attaches_internal_risk_metadata_to_result(self):
        async def probe(target: str):
            return f"checked {target}"

        registry = ToolRegistry()
        registry.register(
            name="probe",
            description="Probe target",
            category=ToolCategory.WEB,
            parameters={"target": {"type": "string", "required": True}},
            func=probe,
            dangerous=True,
        )

        result = await registry.execute("probe", {"target": "10.0.0.1"})

        self.assertTrue(result.success, result.error)
        self.assertEqual(result.metadata["risk_class"], ToolRiskClass.ACTIVE_ENUMERATION.value)
        self.assertEqual(result.metadata["tool_category"], ToolCategory.WEB.value)

    async def test_execute_returns_error_for_uncoercible_argument(self):
        executed = False

        async def probe(count: int):
            nonlocal executed
            executed = True
            return str(count)

        registry = ToolRegistry()
        registry.register(
            name="probe",
            description="Probe target",
            category=ToolCategory.RECON,
            parameters={"count": {"type": "integer", "required": True}},
            func=probe,
        )

        result = await registry.execute("probe", {"count": "many"})

        self.assertFalse(result.success)
        self.assertFalse(executed)
        self.assertIn("argument 'count' must be an integer", result.error or "")

    async def test_execute_returns_error_for_enum_mismatch(self):
        async def probe(mode: str):
            return mode

        registry = ToolRegistry()
        registry.register(
            name="probe",
            description="Probe target",
            category=ToolCategory.RECON,
            parameters={"mode": {"type": "string", "required": True, "enum": ["quick", "deep"]}},
            func=probe,
        )

        result = await registry.execute("probe", {"mode": "full"})

        self.assertFalse(result.success)
        self.assertIn("argument 'mode' must be one of", result.error or "")

    def test_get_tools_schema_outputs_standard_object_schema(self):
        registry = ToolRegistry()
        registry.register(
            name="probe",
            description="Probe target",
            category=ToolCategory.RECON,
            parameters={
                "target": {"type": "string", "required": True, "default": "127.0.0.1"},
                "count": {"type": "integer", "required": False, "default": 4},
            },
            func=lambda **_: "ok",
        )

        schema = registry.get_tools_schema()[0]

        self.assertEqual(schema["parameters"]["type"], "object")
        self.assertEqual(schema["parameters"]["required"], ["target"])
        self.assertNotIn("required", schema["parameters"]["properties"]["target"])
        self.assertNotIn("default", schema["parameters"]["properties"]["target"])
        self.assertNotIn("default", schema["parameters"]["properties"]["count"])
        self.assertNotIn("risk_class", schema)

    def test_registry_infers_internal_risk_class_without_changing_dangerous_flag(self):
        registry = ToolRegistry()
        registry.register(
            name="probe",
            description="Probe target",
            category=ToolCategory.WEB,
            parameters={},
            func=lambda **_: "ok",
            dangerous=True,
        )
        registry.register(
            name="local_hash",
            description="Local hash helper",
            category=ToolCategory.CRYPTO,
            parameters={},
            func=lambda **_: "ok",
            dangerous=False,
        )
        registry.register(
            name="mcp:external_tool",
            description="External MCP tool",
            category=ToolCategory.MCP,
            parameters={},
            func=lambda **_: "ok",
            dangerous=True,
        )

        self.assertTrue(registry.get_tool("probe").dangerous)
        self.assertEqual(registry.get_tool("probe").risk_class, ToolRiskClass.ACTIVE_ENUMERATION)
        self.assertFalse(registry.get_tool("local_hash").dangerous)
        self.assertEqual(
            registry.get_tool("local_hash").risk_class,
            ToolRiskClass.PURE_LOCAL_COMPUTATION,
        )
        self.assertEqual(
            registry.get_tool("mcp:external_tool").risk_class,
            ToolRiskClass.EXTENSION_SUPPLY_CHAIN_EXECUTION,
        )

    def test_register_accepts_explicit_risk_class(self):
        registry = ToolRegistry()
        registry.register(
            name="credentialed_smb_enum",
            description="Credentialed SMB enumeration",
            category=ToolCategory.NETWORK,
            parameters={},
            func=lambda **_: "ok",
            dangerous=True,
            risk_class="r8_credentialed_remote_or_identity_action",
        )

        self.assertEqual(
            registry.get_tool("credentialed_smb_enum").risk_class,
            ToolRiskClass.CREDENTIALED_REMOTE_OR_IDENTITY_ACTION,
        )

    def test_builtin_representative_tools_have_internal_risk_classes(self):
        from secops_agent.tools import crypto, exploit, forensics, network, recon, web  # noqa: F401

        expected = {
            "hash_identify": ToolRiskClass.PURE_LOCAL_COMPUTATION,
            "sysinfo": ToolRiskClass.LOCAL_OBSERVATION,
            "vpn_status": ToolRiskClass.LOCAL_OBSERVATION,
            "ping_host": ToolRiskClass.NETWORK_OBSERVATION,
            "http_headers": ToolRiskClass.NETWORK_OBSERVATION,
            "nmap_scan": ToolRiskClass.ACTIVE_ENUMERATION,
            "dir_brute": ToolRiskClass.ACTIVE_ENUMERATION,
            "file_analyze": ToolRiskClass.LOCAL_FILE_ACCESS,
            "run_shell": ToolRiskClass.PRIVILEGED_LOCAL_ACTION,
            "connect_vpn_config": ToolRiskClass.PRIVILEGED_LOCAL_ACTION,
            "generate_payload": ToolRiskClass.OFFENSIVE_PAYLOAD_OR_EXPLOIT_ASSISTANCE,
        }

        for tool_name, risk_class in expected.items():
            with self.subTest(tool=tool_name):
                tool_def = registry.get_tool(tool_name)
                self.assertIsNotNone(tool_def)
                self.assertEqual(tool_def.risk_class, risk_class)

    async def test_object_schema_registration_is_validated_too(self):
        seen = {}

        async def probe(target: str, count: int = 0):
            seen.update({"target": target, "count": count})
            return "ok"

        registry = ToolRegistry()
        registry.register(
            name="probe",
            description="Probe target",
            category=ToolCategory.RECON,
            parameters={
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "count": {"type": "integer", "default": 2},
                },
                "required": ["target"],
            },
            func=probe,
        )

        result = await registry.execute("probe", {"target": "10.0.0.1", "count": "3"})

        self.assertTrue(result.success, result.error)
        self.assertEqual(seen, {"target": "10.0.0.1", "count": 3})

    async def test_ssl_audit_rejects_injection_targets_before_execution(self):
        from secops_agent.tools.crypto import ssl_audit

        hostile_targets = (
            "example.com:443; id",
            "example.com:443 && id",
            "example.com:443 | id",
            "example.com:443 `id`",
            "example.com:443 $(id)",
            "example.com:443\nid",
            "example.com:443 > /tmp/out",
        )

        with patch("secops_agent.tools.crypto._run_cmd") as run_cmd:
            for target in hostile_targets:
                with self.subTest(target=target):
                    result = await ssl_audit(target)
                    self.assertIn("Invalid TLS target", result)
            run_cmd.assert_not_called()

    async def test_ssl_audit_openssl_fallback_uses_argv_without_shell(self):
        from secops_agent.tools.crypto import ssl_audit

        calls = []

        async def fake_run_cmd(cmd, timeout=0):
            calls.append(cmd)
            return "CONNECTED\nProtocol  : TLSv1.2\nextra\nmore\nlines\nhidden", "", 0

        def fake_which(name):
            return "/usr/bin/openssl" if name == "openssl" else None

        with patch("secops_agent.tools.crypto.shutil.which", fake_which), patch(
            "secops_agent.tools.crypto._run_cmd",
            fake_run_cmd,
        ):
            result = await ssl_audit("example.com:443")

        self.assertTrue(calls)
        self.assertIn("Basic SSL/TLS Audit for example.com:443", result)
        for cmd in calls:
            with self.subTest(cmd=cmd):
                self.assertEqual(cmd[0], "openssl")
                self.assertNotIn("bash", cmd)
                self.assertNotIn("-c", cmd)
                self.assertNotIn("|", cmd)
                self.assertIn("-connect", cmd)
                self.assertIn("example.com:443", cmd)


if __name__ == "__main__":
    unittest.main()
