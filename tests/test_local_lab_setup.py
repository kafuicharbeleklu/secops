from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from secops_agent.core.agent import (
    ApprovalRequestEvent,
    SecOpsAgent,
    TextEvent,
    ToolCallEvent,
    ToolResultEvent,
    ToolStartEvent,
)
from secops_agent.core.memory import ConversationMemory
from secops_agent.core.permissions import ApprovalDecision, PermissionEngine
from secops_agent.core.result_parser import ToolResultParser
from secops_agent.core.sandbox import set_sandbox_enabled
from secops_agent.core.tools import ToolCategory, ToolRegistry
from secops_agent.tools import forensics


class BrokenLLM:
    model_name = "broken"

    def __init__(self):
        self.called = False

    def prepare_for_prompt(self, prompt: str, **kwargs):
        return None

    async def stream_chat(self, *args, **kwargs):
        self.called = True
        raise AssertionError("LLM should not be called for local lab preflight")


async def _collect(agent: SecOpsAgent, prompt: str, approval: ApprovalDecision | None = None):
    events = []
    async for event in agent.stream_response(prompt):
        events.append(event)
        if isinstance(event, ApprovalRequestEvent):
            event.approval_future.set_result(approval or ApprovalDecision(allowed=False))
    return events


class LocalLabSetupTests(unittest.IsolatedAsyncioTestCase):
    async def test_vpn_download_activation_prompt_connects_without_llm(self):
        registry = ToolRegistry()
        executed = []

        async def connect_vpn_config(**kwargs):
            executed.append(kwargs)
            return "vpn handled"

        registry.register(
            name="connect_vpn_config",
            description="Connect lab VPN",
            category=ToolCategory.SYSTEM,
            parameters={},
            func=connect_vpn_config,
            dangerous=True,
        )
        llm = BrokenLLM()
        agent = SecOpsAgent(
            llm=llm,
            registry=registry,
            memory=ConversationMemory(),
            permissions=PermissionEngine(),
            max_iterations=1,
        )

        with patch.object(SecOpsAgent, "_single_download_vpn_config", return_value=""):
            events = await _collect(
                agent,
                "j'ai un fichier de configuration vpn dans Download execute le",
                ApprovalDecision(allowed=True),
            )

        self.assertFalse(llm.called)
        approvals = [event for event in events if isinstance(event, ApprovalRequestEvent)]
        self.assertEqual([event.resource.value for event in approvals], ["tool(connect_vpn_config)"])
        calls = [event for event in events if isinstance(event, ToolCallEvent)]
        self.assertEqual([event.name for event in calls], ["connect_vpn_config"])
        self.assertTrue(any(isinstance(event, ToolStartEvent) for event in events))
        result = next(event for event in events if isinstance(event, ToolResultEvent))
        self.assertIn("vpn handled", result.result.output)
        self.assertEqual(executed, [{"directory": "~/Downloads"}])

    async def test_tryhackme_vpn_connect_prompt_uses_permission_flow(self):
        registry = ToolRegistry()
        executed = []

        async def connect_vpn_config(**kwargs):
            executed.append(kwargs)
            return "vpn handled"

        registry.register(
            name="connect_vpn_config",
            description="Connect lab VPN",
            category=ToolCategory.SYSTEM,
            parameters={},
            func=connect_vpn_config,
            dangerous=True,
        )
        llm = BrokenLLM()
        agent = SecOpsAgent(
            llm=llm,
            registry=registry,
            memory=ConversationMemory(),
            permissions=PermissionEngine(),
            max_iterations=1,
        )

        with patch.object(SecOpsAgent, "_single_download_vpn_config", return_value=""):
            events = await _collect(
                agent,
                "connecte le vpn tryhackme avec le fichier de configuration dans Downloads",
                ApprovalDecision(allowed=True),
            )

        self.assertFalse(llm.called)
        approvals = [event for event in events if isinstance(event, ApprovalRequestEvent)]
        self.assertEqual([event.resource.value for event in approvals], ["tool(connect_vpn_config)"])
        self.assertEqual(executed, [{"directory": "~/Downloads"}])

    async def test_vpn_connect_prompt_uses_detected_single_download_config(self):
        registry = ToolRegistry()
        executed = []

        async def connect_vpn_config(**kwargs):
            executed.append(kwargs)
            return "vpn handled"

        registry.register(
            name="connect_vpn_config",
            description="Connect lab VPN",
            category=ToolCategory.SYSTEM,
            parameters={},
            func=connect_vpn_config,
            dangerous=True,
        )
        agent = SecOpsAgent(
            llm=BrokenLLM(),
            registry=registry,
            memory=ConversationMemory(),
            permissions=PermissionEngine(),
            max_iterations=1,
        )

        with patch.object(
            SecOpsAgent,
            "_single_download_vpn_config",
            return_value="/home/administrator/Downloads/lab.ovpn",
        ):
            await _collect(
                agent,
                "active le vpn dans download s'il te plaît",
                ApprovalDecision(allowed=True),
            )

        self.assertEqual(
            executed,
            [{"directory": "~/Downloads", "config_path": "/home/administrator/Downloads/lab.ovpn"}],
        )

    async def test_vpn_status_prompt_uses_status_tool_without_llm(self):
        registry = ToolRegistry()
        executed = []

        async def vpn_status(**kwargs):
            executed.append(kwargs)
            return "VPN status: down/stale"

        registry.register(
            name="vpn_status",
            description="Check VPN status",
            category=ToolCategory.SYSTEM,
            parameters={},
            func=vpn_status,
            dangerous=False,
        )
        agent = SecOpsAgent(
            BrokenLLM(),
            registry,
            ConversationMemory(),
            permissions=PermissionEngine(),
            result_parser=ToolResultParser(),
        )

        events = await _collect(agent, "is the vpn still activate?")

        self.assertFalse(agent.llm.called)
        self.assertEqual([event.name for event in events if isinstance(event, ToolCallEvent)], ["vpn_status"])
        self.assertEqual(executed, [{}])
        rendered_text = "".join(event.content for event in events if isinstance(event, TextEvent))
        self.assertNotIn("Je vais traiter cette demande", rendered_text)
        # The answer leads with the actual status, not a "N line(s)" meta count.
        self.assertIn("VPN status: down/stale", rendered_text)
        self.assertNotIn("line(s) of output", rendered_text)

    async def test_vpn_disconnect_prompt_uses_disconnect_tool_without_llm(self):
        registry = ToolRegistry()
        executed = []

        async def disconnect_vpn(**kwargs):
            executed.append(kwargs)
            return "VPN disconnected"

        registry.register(
            name="disconnect_vpn",
            description="Disconnect VPN",
            category=ToolCategory.SYSTEM,
            parameters={},
            func=disconnect_vpn,
            dangerous=True,
        )
        agent = SecOpsAgent(BrokenLLM(), registry, ConversationMemory(), permissions=PermissionEngine())

        events = await _collect(
            agent,
            "can you desactivate vpn?",
            ApprovalDecision(allowed=True),
        )

        self.assertFalse(agent.llm.called)
        approvals = [event for event in events if isinstance(event, ApprovalRequestEvent)]
        self.assertEqual([event.resource.value for event in approvals], ["tool(disconnect_vpn)"])
        self.assertEqual([event.name for event in events if isinstance(event, ToolCallEvent)], ["disconnect_vpn"])
        self.assertEqual(executed, [{}])

    async def test_hackthebox_readiness_prompt_uses_local_check_with_target_without_llm(self):
        registry = ToolRegistry()
        executed = []

        async def lab_setup_check(**kwargs):
            executed.append(kwargs)
            return "htb readiness"

        registry.register(
            name="lab_setup_check",
            description="Check lab setup",
            category=ToolCategory.SYSTEM,
            parameters={},
            func=lab_setup_check,
            dangerous=False,
        )
        llm = BrokenLLM()
        agent = SecOpsAgent(
            llm=llm,
            registry=registry,
            memory=ConversationMemory(),
            permissions=PermissionEngine(),
            max_iterations=1,
        )

        events = await _collect(agent, "prepare mon environnement HackTheBox pour 10.10.10.5")

        self.assertFalse(llm.called)
        calls = [event for event in events if isinstance(event, ToolCallEvent)]
        self.assertEqual([event.name for event in calls], ["lab_setup_check"])
        self.assertEqual(executed, [{"provider": "hackthebox", "directory": "~/Downloads", "target": "10.10.10.5"}])

    async def test_public_web_lab_readiness_prompt_uses_local_check_without_vpn_assumption(self):
        registry = ToolRegistry()
        executed = []

        async def lab_setup_check(**kwargs):
            executed.append(kwargs)
            return "public lab readiness"

        registry.register(
            name="lab_setup_check",
            description="Check lab setup",
            category=ToolCategory.SYSTEM,
            parameters={},
            func=lab_setup_check,
            dangerous=False,
        )
        llm = BrokenLLM()
        agent = SecOpsAgent(
            llm=llm,
            registry=registry,
            memory=ConversationMemory(),
            permissions=PermissionEngine(),
            max_iterations=1,
        )

        events = await _collect(agent, "vérifie mon setup RootMe pour http://challenge.local/")

        self.assertFalse(llm.called)
        calls = [event for event in events if isinstance(event, ToolCallEvent)]
        self.assertEqual([event.name for event in calls], ["lab_setup_check"])
        self.assertEqual(executed, [{"provider": "rootme", "directory": "~/Downloads", "target": "http://challenge.local/"}])

    async def test_lab_setup_check_reports_vpn_configs_and_sudo_state(self):
        async def fake_run_cmd(args, timeout=0):
            command = " ".join(args)
            if args == ["sudo", "-n", "true"]:
                return "", "sudo: a password is required", 1
            if "cat /etc/os-release" in command:
                return 'PRETTY_NAME="Ubuntu 26.04 LTS"\nID=ubuntu\n', "", 0
            if "ip -brief addr show type tun" in command:
                return "", "", 0
            return "", "", 0

        with tempfile.TemporaryDirectory() as tmpdir:
            config = Path(tmpdir) / "tryhackme.ovpn"
            config.write_text("client\n", encoding="utf-8")
            with patch("secops_agent.tools.forensics._run_cmd", fake_run_cmd), patch(
                "secops_agent.tools.forensics.shutil.which",
                lambda name: f"/usr/bin/{name}" if name in {"sudo", "openvpn"} else None,
            ):
                output = await forensics.lab_setup_check("tryhackme", tmpdir)

        self.assertIn("Local Lab Setup: TryHackMe", output)
        self.assertIn(str(config), output)
        self.assertIn("openvpn: /usr/bin/openvpn", output)
        self.assertIn("sudo requires interactive authentication", output)
        self.assertIn("connect_vpn_config", output)

    async def test_lab_setup_check_reports_multiplatform_readiness(self):
        async def fake_run_cmd(args, timeout=0):
            command = " ".join(args)
            if args == ["sudo", "-n", "true"]:
                return "", "", 0
            if "cat /etc/os-release" in command:
                return 'PRETTY_NAME="Ubuntu 26.04 LTS"\nID=ubuntu\n', "", 0
            if "ip -brief addr show type tun" in command:
                return "tun0 UNKNOWN 10.8.0.2/24\n", "", 0
            if "ip route get" in command:
                return "10.10.10.5 dev tun0 src 10.8.0.2\n", "", 0
            if "ping -c 1" in command:
                return "1 packets transmitted, 1 received, 0% packet loss\n", "", 0
            return "", "", 0

        with tempfile.TemporaryDirectory() as tmpdir:
            config = Path(tmpdir) / "htb.ovpn"
            config.write_text("client\n", encoding="utf-8")
            wordlist = Path(tmpdir) / "common.txt"
            wordlist.write_text("admin\nuploads\n", encoding="utf-8")
            with patch("secops_agent.tools.forensics._run_cmd", fake_run_cmd), patch(
                "secops_agent.tools.forensics.shutil.which",
                lambda name: f"/usr/bin/{name}" if name in {"sudo", "openvpn", "nmap", "curl", "gobuster"} else None,
            ), patch("secops_agent.tools.forensics._LAB_WORDLIST_CANDIDATES", (str(wordlist),)):
                output = await forensics.lab_setup_check("hackthebox", tmpdir, "10.10.10.5")

        self.assertIn("Local Lab Setup: HackTheBox", output)
        self.assertIn("VPN or a provider network path is commonly required", output)
        self.assertIn("nmap: /usr/bin/nmap", output)
        self.assertIn("gobuster: /usr/bin/gobuster", output)
        self.assertIn("Wordlists:", output)
        self.assertIn(str(wordlist), output)
        self.assertIn("Target readiness:", output)
        self.assertIn("10.10.10.5 dev tun0", output)
        self.assertIn("1 packets transmitted, 1 received", output)

    async def test_lab_setup_check_public_platform_hint_does_not_require_vpn(self):
        async def fake_run_cmd(args, timeout=0):
            command = " ".join(args)
            if args == ["sudo", "-n", "true"]:
                return "", "", 0
            if "cat /etc/os-release" in command:
                return 'PRETTY_NAME="Ubuntu 26.04 LTS"\n', "", 0
            if "ip -brief addr show type tun" in command:
                return "", "", 0
            if "ip route get" in command:
                return "default via 192.168.1.1\n", "", 0
            if "ping -c 1" in command:
                return "", "", 1
            if "curl -k -I" in command:
                return "HTTP/1.1 200 OK\nServer: nginx\n", "", 0
            return "", "", 0

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("secops_agent.tools.forensics._run_cmd", fake_run_cmd), patch(
                "secops_agent.tools.forensics.shutil.which",
                lambda name: f"/usr/bin/{name}" if name in {"sudo", "curl"} else None,
            ), patch("secops_agent.tools.forensics._LAB_WORDLIST_CANDIDATES", ()):
                output = await forensics.lab_setup_check("portswigger", tmpdir, "https://example.test/lab")

        self.assertIn("Local Lab Setup: PortSwigger Web Security Academy", output)
        self.assertIn("VPN is usually not required", output)
        self.assertIn("Fallback: dir_brute can use a compact built-in list", output)
        self.assertIn("HTTP/1.1 200 OK", output)
        self.assertIn("Start with the provided public challenge URL/host", output)

    async def test_vpn_status_reports_down_tun_with_openvpn_as_not_usable(self):
        async def fake_run_cmd(args, timeout=0):
            command = " ".join(args)
            if "ip -brief addr show type tun" in command:
                return "tun0             DOWN           192.168.136.184/18\n", "", 0
            if "ps -eo" in command:
                return "13481 root openvpn /usr/sbin/openvpn --config lab.ovpn\n", "", 0
            raise AssertionError(f"unexpected command: {args}")

        with patch("secops_agent.tools.forensics._run_cmd", fake_run_cmd):
            output = await forensics.vpn_status()

        self.assertIn("VPN status: down/stale", output)
        self.assertIn("not usable", output)
        self.assertIn("tun0: DOWN · down", output)

    async def test_vpn_status_reports_named_tun_interfaces_as_connected(self):
        async def fake_run_cmd(args, timeout=0):
            command = " ".join(args)
            if "ip -brief addr show type tun" in command:
                return (
                    "tun0             UNKNOWN        192.168.136.184/18\n"
                    "tun1             UNKNOWN        192.168.136.184/18\n"
                ), "", 0
            if "ps -eo" in command:
                return "72717 root openvpn /usr/sbin/openvpn --config lab.ovpn\n", "", 0
            raise AssertionError(f"unexpected command: {args}")

        with patch("secops_agent.tools.forensics._run_cmd", fake_run_cmd):
            output = await forensics.vpn_status()

        self.assertIn("VPN status: connected", output)
        self.assertIn("tun0: UNKNOWN · active · 192.168.136.184/18", output)
        self.assertIn("tun1: UNKNOWN · active · 192.168.136.184/18", output)

    async def test_disconnect_vpn_returns_manual_sudo_when_process_remains(self):
        calls = []

        async def fake_run_cmd(args, timeout=0):
            calls.append(args)
            command = " ".join(args)
            if "ps -eo" in command:
                return "13481 root openvpn /usr/sbin/openvpn --config lab.ovpn\n", "", 0
            if command.startswith("bash -lc kill"):
                return "", "", 0
            if args == ["sudo", "-n", "true"]:
                return "", "sudo: a password is required", 1
            if "ip -brief addr show type tun" in command:
                return "tun0             DOWN           192.168.136.184/18\n", "", 0
            raise AssertionError(f"unexpected command: {args}")

        with patch("secops_agent.tools.forensics._run_cmd", fake_run_cmd):
            output = await forensics.disconnect_vpn()

        self.assertIn("VPN disconnect incomplete", output)
        self.assertIn("sudo kill 13481", output)
        self.assertIn("VPN status: down/stale", output)
        self.assertTrue(any("kill 13481" in " ".join(call) for call in calls))

    async def test_connect_vpn_config_returns_manual_command_when_sudo_is_interactive(self):
        async def fake_run_cmd(args, timeout=0):
            if args == ["sudo", "-n", "true"]:
                return "", "sudo: a password is required", 1
            raise AssertionError(f"unexpected command: {args}")

        with tempfile.TemporaryDirectory() as tmpdir:
            config = Path(tmpdir) / "tryhackme.ovpn"
            config.write_text("client\n", encoding="utf-8")
            with patch("secops_agent.tools.forensics._run_cmd", fake_run_cmd), patch(
                "secops_agent.tools.forensics.shutil.which",
                lambda name: "/usr/bin/openvpn" if name == "openvpn" else "/usr/bin/sudo",
            ):
                output = await forensics.connect_vpn_config(str(config))

        self.assertIn("Sudo requires interactive authentication", output)
        self.assertIn("sudo openvpn --config", output)
        self.assertIn(str(config), output)
        self.assertNotIn("A terminal is required", output)

    async def test_connect_vpn_config_reports_sandbox_block_before_sudo_prompt(self):
        async def fake_sudo_status():
            raise AssertionError("sudo status should not be checked when sandbox blocks sudo")

        with tempfile.TemporaryDirectory() as tmpdir:
            config = Path(tmpdir) / "tryhackme.ovpn"
            config.write_text("client\n", encoding="utf-8")
            set_sandbox_enabled(True)
            try:
                with patch("secops_agent.tools.forensics._sudo_noninteractive_status", fake_sudo_status), patch(
                    "secops_agent.tools.forensics.shutil.which",
                    lambda name: "/usr/bin/openvpn" if name == "openvpn" else "/usr/bin/sudo",
                ):
                    output = await forensics.connect_vpn_config(str(config))
            finally:
                set_sandbox_enabled(False)

        self.assertIn("Sandbox blocked command", output)
        self.assertIn("'sudo' is blocked in sandbox mode", output)

    async def test_connect_vpn_config_waits_for_connected_state_and_reports_vpn_ip(self):
        async def fake_run_cmd(args, timeout=0):
            command = " ".join(args)
            if args == ["sudo", "-n", "true"]:
                return "", "", 0
            if "nohup sudo -n" in command:
                return "12345\n", "", 0
            if "ps -p 12345" in command:
                return "12345\n", "", 0
            raise AssertionError(f"unexpected command: {args}")

        async def fake_tun_addresses():
            return ["192.168.136.184/24"]

        with tempfile.TemporaryDirectory() as tmpdir:
            config = Path(tmpdir) / "tryhackme.ovpn"
            config.write_text("client\n", encoding="utf-8")
            with patch("secops_agent.tools.forensics._run_cmd", fake_run_cmd), patch(
                "secops_agent.tools.forensics.shutil.which",
                lambda name: "/usr/bin/openvpn" if name == "openvpn" else "/usr/bin/sudo",
            ), patch(
                "secops_agent.tools.forensics._vpn_log_tail",
                return_value="Initialization Sequence Completed\n",
            ), patch("secops_agent.tools.forensics._vpn_tun_addresses", fake_tun_addresses):
                output = await forensics.connect_vpn_config(str(config))

        self.assertIn("VPN connected", output)
        self.assertIn("VPN IP: 192.168.136.184/24", output)
        self.assertIn("OpenVPN reported the tunnel as ready", output)

    async def test_connect_vpn_config_classifies_tls_timeout_as_network_block(self):
        calls = []

        async def fake_run_cmd(args, timeout=0):
            calls.append(args)
            command = " ".join(args)
            if args == ["sudo", "-n", "true"]:
                return "", "", 0
            if "nohup sudo -n" in command:
                return "12345\n", "", 0
            if "kill 12345" in command:
                return "", "", 0
            raise AssertionError(f"unexpected command: {args}")

        async def fake_tun_addresses():
            return []

        log_tail = (
            "TLS Error: TLS key negotiation failed to occur within 60 seconds "
            "(check your network connectivity)\n"
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            config = Path(tmpdir) / "tryhackme.ovpn"
            config.write_text("client\n", encoding="utf-8")
            with patch("secops_agent.tools.forensics._run_cmd", fake_run_cmd), patch(
                "secops_agent.tools.forensics.shutil.which",
                lambda name: "/usr/bin/openvpn" if name == "openvpn" else "/usr/bin/sudo",
            ), patch("secops_agent.tools.forensics._vpn_log_tail", return_value=log_tail), patch(
                "secops_agent.tools.forensics._vpn_tun_addresses",
                fake_tun_addresses,
            ):
                output = await forensics.connect_vpn_config(str(config))

        self.assertIn("VPN failed", output)
        self.assertIn("UDP/1194", output)
        self.assertIn("Try another network or mobile hotspot", output)
        self.assertTrue(any("kill 12345" in " ".join(call) for call in calls))

    async def test_run_shell_sudo_precheck_returns_manual_command(self):
        async def fake_sudo_status():
            return False, "sudo requires interactive authentication"

        with patch("secops_agent.tools.forensics._sudo_noninteractive_status", fake_sudo_status):
            output = await forensics.run_shell("sudo apt update && sudo apt upgrade -y", timeout=10)

        self.assertIn("Sudo requires interactive authentication", output)
        self.assertIn("sudo apt update && sudo apt upgrade -y", output)
        self.assertNotIn("A terminal is required", output)

    def test_system_prompt_allows_authorized_lab_vpn_setup(self):
        from secops_agent.core.llm import GeminiProvider

        prompt = GeminiProvider(api_key="")._system_instruction()

        self.assertIn("Lab setup", prompt)
        self.assertIn("THM", prompt)
        self.assertIn("RootMe", prompt)
        self.assertIn("PortSwigger", prompt)
        self.assertIn("lab_setup_check", prompt)
        self.assertIn("sudo", prompt)


if __name__ == "__main__":
    unittest.main()
