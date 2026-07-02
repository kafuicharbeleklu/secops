"""
System and forensics tools.
File analysis, log analysis, process inspection, and system information.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import os
from pathlib import Path
import re
import shlex
import shutil
from typing import Optional
from urllib.parse import urlparse

from secops_agent.config import settings
from secops_agent.core.execution import ExecutionProgress, ExecutionSupervisor
from secops_agent.core.sudo import (
    command_uses_sudo as _core_command_uses_sudo,
    format_sudo_interactive_reason as _core_format_sudo_interactive_reason,
)
from secops_agent.core.tools import report_progress, report_tool_metadata, tool, ToolCategory
from secops_agent.core.sandbox import validate_shell_command
from secops_agent.utils.helpers import run_cmd as _run_cmd

_LONG_RUNNING_COMMAND_MARKERS = (
    " apt update",
    " apt upgrade",
    " apt install",
    " apt-get update",
    " apt-get upgrade",
    " apt-get install",
    " apt full-upgrade",
    " apt-get dist-upgrade",
    " do-release-upgrade",
    " dnf upgrade",
    " dnf install",
    " yum update",
    " yum install",
    " pacman -syu",
)
_LONG_COMMAND_TIMEOUT = 1800
_LONG_COMMAND_INACTIVITY_TIMEOUT = 600
_VPN_CONFIG_SUFFIXES = {".ovpn", ".conf"}
_VPN_CONNECT_WAIT_SECONDS = 75
_VPN_CONNECT_POLL_SECONDS = 2
_LAB_CONFIG_SEARCH_LIMIT = 25
_LAB_WORDLIST_CANDIDATES = (
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/dirb/wordlists/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
    "/usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
)
_LAB_TOOL_NAMES = (
    "nmap",
    "curl",
    "gobuster",
    "dirb",
    "ffuf",
    "feroxbuster",
    "nikto",
    "sqlmap",
    "searchsploit",
    "nc",
    "python3",
    "openvpn",
    "nmcli",
)
_VPN_FIRST_PROVIDERS = {"tryhackme", "hackthebox", "htb", "thm", "vulnhub"}
_PUBLIC_WEB_LAB_PROVIDERS = {"rootme", "root-me", "portswigger", "web-security-academy", "picoctf", "overthewire"}
_SUDO_INTERACTIVE_RE = re.compile(r"(^|(?<=[;&|(`\n\r])\s*)sudo(?!\s+-(?:n|S|A)\b)(?=\s|$)")


@dataclass(frozen=True)
class _VpnInterface:
    name: str
    state: str
    addresses: tuple[str, ...]
    raw: str

    @property
    def active(self) -> bool:
        state = self.state.upper()
        raw = self.raw.upper()
        return state not in {"DOWN"} and "NO-CARRIER" not in raw


def _effective_shell_timeout(command: str, timeout: int | str | None) -> int:
    try:
        effective = int(timeout or settings.TOOL_TIMEOUT)
    except (TypeError, ValueError):
        effective = settings.TOOL_TIMEOUT
    effective = max(1, effective)

    if _is_long_running_shell_command(command):
        effective = max(effective, _LONG_COMMAND_TIMEOUT)
    return effective


def _is_long_running_shell_command(command: str) -> bool:
    normalized = f" {' '.join(str(command).lower().split())}"
    return any(marker in normalized for marker in _LONG_RUNNING_COMMAND_MARKERS)


def _format_timeout_label(seconds: int | None) -> str:
    if seconds is None:
        return "disabled"
    if seconds < 60:
        return f"{seconds}s"
    minutes = seconds // 60
    remainder = seconds % 60
    return f"{minutes}m {remainder}s" if remainder else f"{minutes}m"


def _effective_shell_inactivity_timeout(command: str, value: int | str | None = None) -> int | None:
    if value in {None, ""}:
        return _LONG_COMMAND_INACTIVITY_TIMEOUT if _is_long_running_shell_command(command) else 120
    try:
        timeout = int(value)
    except (TypeError, ValueError):
        return _LONG_COMMAND_INACTIVITY_TIMEOUT if _is_long_running_shell_command(command) else 120
    if timeout <= 0:
        return None
    if _is_long_running_shell_command(command):
        return max(timeout, _LONG_COMMAND_INACTIVITY_TIMEOUT)
    return timeout


def _command_uses_sudo(command: str) -> bool:
    return _core_command_uses_sudo(command)


def _force_noninteractive_sudo(command: str) -> str:
    """Use sudo in non-interactive mode after the sudo precheck has passed."""
    return _SUDO_INTERACTIVE_RE.sub(lambda match: f"{match.group(1)}sudo -n", str(command or ""))


def _format_sudo_interactive_reason(stderr: str) -> str:
    return _core_format_sudo_interactive_reason(stderr)


async def _sudo_noninteractive_status() -> tuple[bool, str]:
    if not shutil.which("sudo"):
        return False, "sudo is not installed"
    _, stderr, rc = await _run_cmd(["sudo", "-n", "true"], timeout=5)
    if rc == 0:
        return True, "sudo non-interactive authentication is available"
    return False, _format_sudo_interactive_reason(stderr)


def _resolve_user_path(path: str | None) -> Path:
    raw = str(path or "").strip() or "~/Downloads"
    return Path(raw).expanduser()


def _is_vpn_config(path: Path) -> bool:
    return path.is_file() and path.suffix.lower() in _VPN_CONFIG_SUFFIXES


def _find_vpn_config_paths(directory: str | None = None) -> list[Path]:
    root = _resolve_user_path(directory)
    if not root.exists() or not root.is_dir():
        return []

    candidates: list[Path] = []
    for entry in sorted(root.iterdir()):
        if _is_vpn_config(entry):
            candidates.append(entry)
        elif entry.is_dir():
            for child in sorted(entry.glob("*.ovpn")) + sorted(entry.glob("*.conf")):
                if _is_vpn_config(child):
                    candidates.append(child)
        if len(candidates) >= _LAB_CONFIG_SEARCH_LIMIT:
            break
    return candidates[:_LAB_CONFIG_SEARCH_LIMIT]


def _format_shell_command(parts: list[str]) -> str:
    return " ".join(shlex.quote(part) for part in parts)


def _manual_openvpn_command(config_path: Path) -> str:
    return _format_shell_command(["sudo", "openvpn", "--config", str(config_path)])


def _vpn_log_tail(log_path: Path, *, chars: int = 4000) -> str:
    try:
        return log_path.read_text(encoding="utf-8", errors="replace")[-chars:]
    except OSError:
        return ""


def _vpn_log_status(log_tail: str) -> tuple[str, str]:
    normalized = " ".join(str(log_tail or "").split()).casefold()
    if "initialization sequence completed" in normalized:
        return "connected", "OpenVPN reported initialization complete."
    if "tls key negotiation failed" in normalized or ("tls error" in normalized and "60 seconds" in normalized):
        return (
            "failed",
            "TLS handshake timed out. The current network may be blocking UDP/1194, NAT traversal, or the VPN server may be unreachable.",
        )
    if "auth_failed" in normalized or "authentication failed" in normalized:
        return "failed", "VPN authentication failed. The configuration or credentials were rejected."
    if "cannot open tun" in normalized or "cannot ioctl tunsetiff" in normalized:
        return "failed", "OpenVPN could not create the TUN interface. Check local permissions and TUN/TAP support."
    if "exiting due to fatal error" in normalized or "fatal error" in normalized:
        return "failed", "OpenVPN exited with a fatal error. Review the recent log output below."
    return "pending", ""


def _parse_vpn_tun_interfaces(output: str) -> list[_VpnInterface]:
    interfaces: list[_VpnInterface] = []
    for raw_line in str(output or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        addresses = tuple(
            part
            for part in parts[2:]
            if "/" in part and re.match(r"^\d{1,3}(?:\.\d{1,3}){3}/\d+$", part)
        )
        interfaces.append(_VpnInterface(parts[0], parts[1], addresses, line))
    return interfaces


async def _vpn_tun_interfaces() -> list[_VpnInterface]:
    stdout, _, _ = await _run_cmd(
        [
            "bash",
            "-lc",
            (
                "{ ip -brief addr show type tun 2>/dev/null || true; "
                "ip -brief addr show 2>/dev/null | awk '$1 ~ /^tun[0-9]+/ {print}'; } "
                "| awk '!seen[$1]++'"
            ),
        ],
        timeout=5,
    )
    return _parse_vpn_tun_interfaces(stdout)


async def _vpn_tun_addresses(*, active_only: bool = True) -> list[str]:
    interfaces = await _vpn_tun_interfaces()
    addresses: list[str] = []
    for interface in interfaces:
        if active_only and not interface.active:
            continue
        addresses.extend(interface.addresses)
    return addresses


async def _openvpn_processes() -> list[str]:
    stdout, _, _ = await _run_cmd(
        [
            "bash",
            "-lc",
            (
                "ps -eo pid=,user=,comm=,args= | "
                "awk '$3 !~ /^(awk|bash|grep|sh)$/ && "
                "($3 == \"openvpn\" || $0 ~ /(^|[[:space:]\\/])openvpn([[:space:]]|$)/) {print}'"
            ),
        ],
        timeout=5,
    )
    return [line.strip() for line in stdout.splitlines() if line.strip()]


def _process_pids(process_lines: list[str]) -> list[str]:
    pids: list[str] = []
    for line in process_lines:
        first = line.split(maxsplit=1)[0] if line.split() else ""
        if first.isdigit() and first not in pids:
            pids.append(first)
    return pids


async def _vpn_status_report() -> str:
    interfaces = await _vpn_tun_interfaces()
    processes = await _openvpn_processes()
    active_interfaces = [interface for interface in interfaces if interface.active and interface.addresses]
    down_interfaces = [interface for interface in interfaces if not interface.active]

    if active_interfaces:
        status = "connected"
        conclusion = "VPN tunnel is active and usable."
    elif down_interfaces and processes:
        status = "down/stale"
        conclusion = "VPN tunnel is not usable: TUN exists but is DOWN/NO-CARRIER while OpenVPN processes remain."
    elif down_interfaces:
        status = "disconnected"
        conclusion = "VPN tunnel is not usable: TUN exists but is DOWN/NO-CARRIER."
    elif processes:
        status = "starting/stale"
        conclusion = "OpenVPN is running, but no active TUN interface is available yet."
    else:
        status = "disconnected"
        conclusion = "No active VPN tunnel or OpenVPN process was detected."

    lines = [f"VPN status: {status}", f"Conclusion: {conclusion}", ""]
    lines.append("TUN interfaces:")
    if interfaces:
        for interface in interfaces:
            active_label = "active" if interface.active else "down"
            addresses = ", ".join(interface.addresses) if interface.addresses else "no IPv4 address"
            lines.append(f"  - {interface.name}: {interface.state} · {active_label} · {addresses}")
    else:
        lines.append("  none")

    lines.append("")
    lines.append("OpenVPN processes:")
    if processes:
        for process in processes[:8]:
            lines.append(f"  - {process}")
        if len(processes) > 8:
            lines.append(f"  ... {len(processes) - 8} more")
    else:
        lines.append("  none")
    return "\n".join(lines)


def _provider_key(provider: str | None) -> str:
    key = str(provider or "lab").strip().casefold().replace(" ", "-").replace("_", "-")
    aliases = {
        "try-hack-me": "tryhackme",
        "thm": "tryhackme",
        "hack-the-box": "hackthebox",
        "htb": "hackthebox",
        "root-me": "rootme",
        "port-swigger": "portswigger",
        "web-security-academy": "portswigger",
        "pico-ctf": "picoctf",
    }
    return aliases.get(key, key or "lab")


def _provider_label(provider: str | None) -> str:
    labels = {
        "tryhackme": "TryHackMe",
        "hackthebox": "HackTheBox",
        "rootme": "RootMe",
        "portswigger": "PortSwigger Web Security Academy",
        "picoctf": "PicoCTF",
        "overthewire": "OverTheWire",
        "vulnhub": "VulnHub",
        "ctf": "Generic CTF",
        "lab": "Authorized lab",
    }
    key = _provider_key(provider)
    return labels.get(key, str(provider or "Authorized lab").strip() or "Authorized lab")


def _provider_hint(provider: str | None) -> str:
    key = _provider_key(provider)
    if key in _VPN_FIRST_PROVIDERS:
        return "VPN or a provider network path is commonly required before scanning private targets."
    if key in _PUBLIC_WEB_LAB_PROVIDERS:
        return "VPN is usually not required unless the challenge explicitly provides a config."
    return "Use only authorized targets; confirm VPN or network requirements from the challenge page."


def _wordlist_status() -> tuple[list[Path], str]:
    found = [Path(candidate) for candidate in _LAB_WORDLIST_CANDIDATES if Path(candidate).is_file()]
    if found:
        return found, "system wordlist available"
    return [], "no common system wordlist found; dir_brute can use its built-in fallback"


def _target_host(target: str | None) -> str:
    value = str(target or "").strip()
    if not value:
        return ""
    parsed = urlparse(value if "://" in value else f"//{value}")
    return parsed.hostname or value.split("/")[0].split(":")[0]


@tool(
    name="file_analyze",
    description="Analyze a file to determine its type, metadata, and extract useful information.",
    category=ToolCategory.FORENSICS,
    parameters={
        "filepath": {"type": "string", "description": "Path to the file to analyze", "required": True},
    },
    dangerous=False,
)
async def file_analyze(filepath: str) -> str:
    """Analyze a file."""
    if not os.path.exists(filepath):
        return f"❌ File not found: {filepath}"

    result = f"📄 File Analysis: {filepath}\n\n"

    # File type
    if shutil.which("file"):
        stdout, _, _ = await _run_cmd(["file", "-b", filepath])
        result += f"  Type: {stdout.strip()}\n"

    # File size
    size = os.path.getsize(filepath)
    if size < 1024:
        size_str = f"{size} B"
    elif size < 1024 * 1024:
        size_str = f"{size / 1024:.1f} KB"
    else:
        size_str = f"{size / (1024 * 1024):.1f} MB"
    result += f"  Size: {size_str}\n"

    # Hashes
    import hashlib
    with open(filepath, "rb") as f:
        data = f.read()
        result += f"  MD5:    {hashlib.md5(data).hexdigest()}\n"
        result += f"  SHA1:   {hashlib.sha1(data).hexdigest()}\n"
        result += f"  SHA256: {hashlib.sha256(data).hexdigest()}\n"

    # Strings extraction (first 20)
    if shutil.which("strings"):
        stdout, _, _ = await _run_cmd(["strings", "-n", "8", filepath])
        strings_list = stdout.strip().split("\n")[:20]
        if strings_list and strings_list[0]:
            result += f"\n  Interesting strings ({len(strings_list)} shown):\n"
            for s in strings_list:
                result += f"    {s}\n"

    # File permissions
    import stat
    st = os.stat(filepath)
    result += f"\n  Permissions: {oct(st.st_mode)[-3:]}\n"
    result += f"  Owner UID: {st.st_uid}\n"

    return result


@tool(
    name="run_shell",
    description="Execute a shell command and return the output. Use for system enumeration, file operations, and general purpose tasks.",
    category=ToolCategory.SYSTEM,
    parameters={
        "command": {"type": "string", "description": "Shell command to execute", "required": True},
        "timeout": {"type": "integer", "description": "Command timeout in seconds (default: 300)", "required": False, "default": 300},
        "inactivity_timeout": {"type": "integer", "description": "Seconds without output before stopping the command (default: 120, 0 disables)", "required": False, "default": 120},
    },
    dangerous=True,
)
async def run_shell(command: str, timeout: int = 300, inactivity_timeout: int = 120) -> str:
    """Execute a shell command."""
    check = validate_shell_command(command)
    if not check.allowed:
        return f"❌ Sandbox blocked command: {check.reason}"

    # NOTE: Destructive-command blocking is handled by validate_shell_command()
    # above (sandbox.py). The previous naive substring check was removed because
    # it was weaker and trivially bypassable compared to the sandbox regex rules.

    timeout = _effective_shell_timeout(command, timeout)
    inactivity_timeout = _effective_shell_inactivity_timeout(command, inactivity_timeout)
    try:
        if _command_uses_sudo(command):
            await report_progress("checking sudo authentication", "sudo -n true", percent=5)
            sudo_ok, sudo_reason = await _sudo_noninteractive_status()
            if not sudo_ok:
                await report_progress("sudo authentication required", "manual terminal command needed", percent=100)
                safe_command = " ".join(str(command).split())
                return (
                    "❌ Sudo requires interactive authentication, so SecOps CLI "
                    "cannot run this command unattended.\n\n"
                    f"Reason: {sudo_reason}\n\n"
                    "Run this in your terminal instead:\n\n"
                    f"```bash\n{safe_command}\n```"
                )
            command = _force_noninteractive_sudo(command)

        display_command = " ".join(command.split())
        if len(display_command) > 100:
            display_command = display_command[:99] + "…"
        idle_label = (
            f"inactivity {_format_timeout_label(inactivity_timeout)}"
            if inactivity_timeout is not None
            else "inactivity disabled"
        )
        await report_progress(
            "running shell command",
            f"{display_command} · max {_format_timeout_label(timeout)} · {idle_label}",
            percent=10,
        )

        async def relay_progress(progress: ExecutionProgress) -> None:
            await report_progress(progress.phase, progress.detail, progress.percent)

        result = await ExecutionSupervisor().run_shell(
            command,
            max_runtime=timeout,
            inactivity_timeout=inactivity_timeout,
            progress=relay_progress,
        )
        report_tool_metadata("spool_path", str(result.spool_path))
        report_tool_metadata("stdout_path", str(result.stdout_path))
        report_tool_metadata("stderr_path", str(result.stderr_path))
        report_tool_metadata("execution_status", result.status)
        if result.timeout_reason:
            report_tool_metadata("timeout_reason", result.timeout_reason)
        output = result.stdout
        errors = result.stderr

        formatted = ""
        if output:
            formatted += output
        if errors:
            formatted += f"\n[STDERR]\n{errors}"
        if not formatted:
            formatted = "(no output)"

        if result.timed_out:
            if result.timeout_reason == "inactivity":
                message = (
                    f"❌ Command stopped after {_format_timeout_label(inactivity_timeout)} without output "
                    f"(max runtime {_format_timeout_label(timeout)})"
                )
            else:
                message = f"❌ Command timed out after {_format_timeout_label(timeout)} and was stopped"
            return f"{message}\n\n[Partial output]\n{formatted.strip()}\n\n[Spool: {result.spool_path}]"

        formatted += f"\n\n[Exit Code: {result.exit_code}]"
        if "[Output truncated in memory;" in formatted:
            formatted += f"\n[Spool: {result.spool_path}]"
        return formatted

    except asyncio.CancelledError:
        raise
    except Exception as e:
        return f"❌ Error: {str(e)}"


@tool(
    name="sysinfo",
    description="Gather system information including OS, kernel, network interfaces, running services, and user accounts.",
    category=ToolCategory.SYSTEM,
    parameters={
        "category": {"type": "string", "description": "Info category: 'all', 'os', 'resources', 'network', 'users', 'processes', 'services'", "required": False, "default": "all"},
    },
    dangerous=False,
)
async def sysinfo(category: str = "all") -> str:
    """Gather system information."""
    result = "🖥️  System Information\n\n"

    async def get_cmd(cmd: str) -> str:
        stdout, _, _ = await _run_cmd(["bash", "-c", cmd], timeout=10)
        return stdout.strip()

    if category in ("all", "os"):
        result += "── OS ──\n"
        result += f"  Hostname: {await get_cmd('hostname')}\n"
        result += f"  OS: {await get_cmd('cat /etc/os-release 2>/dev/null | head -2 || uname -o')}\n"
        result += f"  Kernel: {await get_cmd('uname -r')}\n"
        result += f"  Arch: {await get_cmd('uname -m')}\n"
        result += f"  Uptime: {await get_cmd('uptime -p 2>/dev/null || uptime')}\n\n"

    if category in ("all", "resources"):
        result += "── Resources ──\n"
        result += f"  CPU cores: {await get_cmd('nproc 2>/dev/null')}\n"
        result += f"  CPU model: {await get_cmd('grep -m1 \"model name\" /proc/cpuinfo | cut -d: -f2- | sed \"s/^ //\" || lscpu 2>/dev/null | grep \"Model name\"')}\n"
        result += f"  Memory: {await get_cmd('free -h 2>/dev/null | grep -i \"^Mem:\" || free -h 2>/dev/null')}\n"
        result += f"  Disk (/): {await get_cmd('df -h / 2>/dev/null | tail -1')}\n\n"

    if category in ("all", "network"):
        result += "── Network ──\n"
        result += f"  Interfaces:\n{await get_cmd('ip -brief addr 2>/dev/null || ifconfig 2>/dev/null | head -30')}\n"
        result += f"  Default Gateway: {await get_cmd('ip route | grep default | head -1')}\n"
        result += f"  DNS: {await get_cmd('cat /etc/resolv.conf | grep nameserver')}\n\n"

    if category in ("all", "users"):
        result += "── Users ──\n"
        result += f"  Current: {await get_cmd('whoami')} (UID: {await get_cmd('id')})\n"
        result += f"  Logged in:\n{await get_cmd('who 2>/dev/null || w')}\n"
        result += f"  Sudo: {await get_cmd('sudo -l 2>/dev/null | tail -5 || echo N/A')}\n\n"

    if category in ("all", "processes"):
        result += "── Top Processes ──\n"
        result += f"{await get_cmd('ps aux --sort=-%mem | head -10')}\n\n"

    if category in ("all", "services"):
        result += "── Listening Services ──\n"
        result += f"{await get_cmd('ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null | head -20')}\n"

    return result


@tool(
    name="lab_setup_check",
    description=(
        "Check local pentest lab setup prerequisites across authorized CTF/lab "
        "platforms: OS, VPN configs, tunnel state, target reachability, wordlists, "
        "and common tool availability."
    ),
    category=ToolCategory.SYSTEM,
    parameters={
        "provider": {"type": "string", "description": "Lab provider label, e.g. tryhackme, hackthebox, rootme, portswigger, ctf", "required": False, "default": "lab"},
        "directory": {"type": "string", "description": "Directory to search for VPN configs", "required": False, "default": "~/Downloads"},
        "target": {"type": "string", "description": "Optional authorized lab target IP, host, or URL to check reachability", "required": False},
    },
    dangerous=False,
)
async def lab_setup_check(provider: str = "lab", directory: str = "~/Downloads", target: str = "") -> str:
    """Inspect local lab setup without changing system state."""
    provider_key = _provider_key(provider)
    provider_label = _provider_label(provider)
    root = _resolve_user_path(directory)
    configs = _find_vpn_config_paths(str(root))
    sudo_ok, sudo_reason = await _sudo_noninteractive_status()
    wordlists, wordlist_state = _wordlist_status()
    target_value = str(target or "").strip()
    target_host = _target_host(target_value)

    async def get_cmd(cmd: str, timeout: int = 8, empty: str = "not available") -> str:
        stdout, stderr, rc = await _run_cmd(["bash", "-lc", cmd], timeout=timeout)
        text = stdout.strip() or stderr.strip()
        return text.strip() if text else ("ok" if rc == 0 and empty == "ok" else empty)

    result = f"Local Lab Setup: {provider_label}\n\n"
    result += "Platform:\n"
    result += f"  Key: {provider_key}\n"
    result += f"  Hint: {_provider_hint(provider_key)}\n\n"
    result += "OS:\n"
    result += f"  {await get_cmd('cat /etc/os-release 2>/dev/null | grep -E \"^(PRETTY_NAME|ID|VERSION_ID)=\" | head -3 || uname -a')}\n\n"
    result += "VPN configs:\n"
    result += f"  Search directory: {root}\n"
    if configs:
        for config in configs:
            result += f"  - {config}\n"
    else:
        result += "  No .ovpn/.conf files found in the search directory.\n"
    result += "\nTools:\n"
    for tool_name in _LAB_TOOL_NAMES:
        result += f"  {tool_name}: {shutil.which(tool_name) or 'not installed'}\n"
    result += f"  sudo: {'ready for non-interactive use' if sudo_ok else sudo_reason}\n\n"
    result += "Wordlists:\n"
    result += f"  Status: {wordlist_state}\n"
    for path in wordlists[:5]:
        result += f"  - {path}\n"
    if not wordlists:
        result += "  Fallback: dir_brute can use a compact built-in list for first-pass discovery.\n"
    result += "\n"
    result += "Network:\n"
    result += f"  TUN/TAP: {await get_cmd('ip -brief addr show type tun 2>/dev/null || true', empty='no tun interface detected')}\n\n"

    if target_host:
        quoted_host = shlex.quote(target_host)
        result += "Target readiness:\n"
        result += f"  Target: {target_value}\n"
        result += f"  Route: {await get_cmd(f'ip route get {quoted_host} 2>/dev/null | head -1', timeout=5, empty='route not available')}\n"
        result += f"  Ping: {await get_cmd(f'ping -c 1 -W 2 {quoted_host} 2>/dev/null | tail -2', timeout=5, empty='no ping response or ping unavailable')}\n"
        if target_value.startswith(("http://", "https://")):
            quoted_target = shlex.quote(target_value)
            result += f"  HTTP: {await get_cmd(f'curl -k -I --max-time 5 {quoted_target} 2>/dev/null | head -5', timeout=7, empty='no HTTP response or curl unavailable')}\n"
        result += "\n"

    if configs and shutil.which("openvpn"):
        selected = configs[0]
        result += "Next step:\n"
        result += f"  To connect with approval, use connect_vpn_config on: {selected}\n"
    elif configs:
        result += "Next step:\n"
        result += "  Install OpenVPN first, then connect using the discovered config.\n"
    else:
        result += "Next step:\n"
        if provider_key in _PUBLIC_WEB_LAB_PROVIDERS:
            result += "  Start with the provided public challenge URL/host; add a VPN config only if the platform requires one.\n"
        else:
            result += "  Put the provider .ovpn file in Downloads, pass its path explicitly, or confirm the challenge does not require VPN.\n"
    return result


@tool(
    name="vpn_status",
    description="Check whether a local lab VPN tunnel is connected, down/stale, starting, or disconnected.",
    category=ToolCategory.SYSTEM,
    parameters={},
    dangerous=False,
)
async def vpn_status() -> str:
    """Report local VPN state without changing the system."""
    return await _vpn_status_report()


@tool(
    name="disconnect_vpn",
    description="Stop local OpenVPN processes for an authorized lab VPN and report the resulting tunnel state.",
    category=ToolCategory.SYSTEM,
    parameters={},
    dangerous=True,
)
async def disconnect_vpn() -> str:
    """Stop local OpenVPN processes where possible."""
    processes = await _openvpn_processes()
    pids = _process_pids(processes)
    if not pids:
        return "No OpenVPN process is running.\n\n" + await _vpn_status_report()

    await report_progress("stopping OpenVPN", f"{len(pids)} process(es)", percent=20)
    pid_args = " ".join(shlex.quote(pid) for pid in pids)
    await _run_cmd(["bash", "-lc", f"kill {pid_args} >/dev/null 2>&1 || true"], timeout=5)
    await asyncio.sleep(0.5)

    remaining = _process_pids(await _openvpn_processes())
    if remaining:
        sudo_ok, sudo_reason = await _sudo_noninteractive_status()
        if not sudo_ok:
            manual = f"sudo kill {' '.join(remaining)}"
            return (
                "VPN disconnect incomplete: OpenVPN process(es) are still running and require sudo.\n\n"
                f"Reason: {sudo_reason}\n\n"
                "Run this in your terminal:\n\n"
                f"```bash\n{manual}\n```\n\n"
                + await _vpn_status_report()
            )
        await report_progress("stopping OpenVPN with sudo", f"{len(remaining)} process(es)", percent=65)
        sudo_pid_args = " ".join(shlex.quote(pid) for pid in remaining)
        await _run_cmd(["bash", "-lc", f"sudo -n kill {sudo_pid_args} >/dev/null 2>&1 || true"], timeout=5)
        await asyncio.sleep(0.5)

    remaining_after = _process_pids(await _openvpn_processes())
    await report_progress("vpn status", "verifying tunnel state", percent=100)
    report = await _vpn_status_report()
    if remaining_after:
        return (
            "VPN disconnect attempted, but OpenVPN process(es) are still running.\n\n"
            + report
        )
    return "VPN disconnected: OpenVPN process(es) stopped.\n\n" + report


@tool(
    name="connect_vpn_config",
    description=(
        "Connect to an authorized lab VPN configuration such as a TryHackMe .ovpn "
        "file. This may change local networking and requires approval."
    ),
    category=ToolCategory.SYSTEM,
    parameters={
        "config_path": {"type": "string", "description": "Path to the .ovpn/.conf file. If omitted, Downloads is searched.", "required": False},
        "directory": {"type": "string", "description": "Directory to search when config_path is omitted or relative", "required": False, "default": "~/Downloads"},
        "background": {"type": "boolean", "description": "Start OpenVPN in the background and return its PID/log path", "required": False, "default": True},
    },
    dangerous=True,
)
async def connect_vpn_config(
    config_path: str = "",
    directory: str = "~/Downloads",
    background: bool = True,
) -> str:
    """Start an authorized lab VPN if local prerequisites allow it."""
    root = _resolve_user_path(directory)
    selected: Path | None = None
    raw_config = str(config_path or "").strip()
    if raw_config:
        candidate = Path(raw_config).expanduser()
        if not candidate.is_absolute():
            candidate = root / candidate
        selected = candidate
    else:
        configs = _find_vpn_config_paths(str(root))
        if not configs:
            return (
                "❌ No VPN configuration file found.\n\n"
                f"Searched: {root}\n"
                "Expected a .ovpn or .conf file. Pass config_path explicitly if it is elsewhere."
            )
        if len(configs) > 1:
            lines = "\n".join(f"  - {path}" for path in configs)
            return (
                "Multiple VPN configuration files were found. Choose one explicitly:\n\n"
                f"{lines}"
            )
        selected = configs[0]

    selected = selected.expanduser()
    if not selected.exists() or not _is_vpn_config(selected):
        return f"❌ VPN config not found or unsupported: {selected}"

    openvpn = shutil.which("openvpn")
    if not openvpn:
        return (
            "❌ OpenVPN is not installed.\n\n"
            "Install it first, then retry:\n\n"
            "```bash\nsudo apt install openvpn\n```"
        )

    manual_command = _manual_openvpn_command(selected)
    sandbox_check = validate_shell_command(manual_command)
    if not sandbox_check.allowed:
        return f"❌ Sandbox blocked command: {sandbox_check.reason}"

    sudo_ok, sudo_reason = await _sudo_noninteractive_status()
    if not sudo_ok:
        return (
            "❌ Sudo requires interactive authentication, so SecOps CLI cannot "
            "start the VPN unattended.\n\n"
            f"Reason: {sudo_reason}\n\n"
            "Run this in your terminal instead:\n\n"
            f"```bash\n{manual_command}\n```"
        )

    if not background:
        return (
            "OpenVPN foreground sessions need an attached terminal. Run this manually:\n\n"
            f"```bash\n{manual_command}\n```"
        )

    log_dir = Path.home() / ".secops_agent" / "vpn"
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return f"❌ Could not create VPN log directory {log_dir}: {exc}"
    log_path = log_dir / f"openvpn-{selected.stem}.log"
    command = (
        "nohup "
        + _format_shell_command(["sudo", "-n", openvpn, "--config", str(selected)])
        + f" > {shlex.quote(str(log_path))} 2>&1 & echo $!"
    )
    stdout, stderr, rc = await _run_cmd(["bash", "-lc", command], timeout=10)
    if rc != 0 or not stdout.strip():
        return (
            "❌ Failed to start OpenVPN.\n\n"
            f"{stderr.strip() or stdout.strip() or 'No process id returned.'}"
        )

    pid = stdout.strip().splitlines()[-1].strip()
    status = "started"
    status_detail = ""
    log_tail = ""
    vpn_addresses: list[str] = []
    deadline = asyncio.get_running_loop().time() + _VPN_CONNECT_WAIT_SECONDS
    await report_progress("waiting for VPN handshake", f"pid {pid}", percent=30)
    while True:
        log_tail = _vpn_log_tail(log_path)
        status, status_detail = _vpn_log_status(log_tail)
        vpn_addresses = await _vpn_tun_addresses()
        if vpn_addresses and status != "failed":
            status = "connected"
            if not status_detail:
                status_detail = "TUN interface is active."
            break
        if status in {"connected", "failed"}:
            break

        running_text, _, _ = await _run_cmd(
            ["bash", "-lc", f"ps -p {shlex.quote(pid)} -o pid= 2>/dev/null"],
            timeout=5,
        )
        if not running_text.strip():
            status = "exited"
            status_detail = "OpenVPN process exited before the tunnel was ready."
            break

        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            status = "started"
            status_detail = "OpenVPN is still running, but the VPN handshake did not finish before the wait limit."
            break
        await report_progress(
            "waiting for VPN handshake",
            f"{max(0, int(remaining))}s remaining",
            percent=60,
        )
        await asyncio.sleep(min(_VPN_CONNECT_POLL_SECONDS, max(0.2, remaining)))

    if status == "failed":
        await _run_cmd(
            ["bash", "-lc", f"sudo -n kill {shlex.quote(pid)} >/dev/null 2>&1 || kill {shlex.quote(pid)} >/dev/null 2>&1 || true"],
            timeout=5,
        )

    await report_progress(f"vpn {status}", status_detail or str(selected), percent=100)

    result = f"VPN {status}: {selected}\n"
    result += f"PID: {pid}\n"
    result += f"Log: {log_path}\n"
    if vpn_addresses:
        result += f"VPN IP: {', '.join(vpn_addresses)}\n"
    if status_detail:
        result += f"Status: {status_detail}\n"
    if status == "connected":
        result += "OpenVPN reported the tunnel as ready.\n"
    elif status == "failed":
        result += "\nRecommended next checks:\n"
        result += "  - Try another network or mobile hotspot if UDP/1194 is blocked.\n"
        result += "  - If the provider offers TCP configs, download and use one.\n"
        result += "  - Confirm the lab VPN server is currently available.\n"
        if log_tail:
            result += "\nRecent log output:\n"
            result += log_tail.strip()[-1200:]
    elif log_tail:
        result += "\nRecent log output:\n"
        result += log_tail.strip()[-1200:]
    else:
        result += "No log output captured yet.\n"
    return result


@tool(
    name="log_analyze",
    description="Analyze log files for suspicious patterns, failed logins, errors, and security events.",
    category=ToolCategory.FORENSICS,
    parameters={
        "logfile": {"type": "string", "description": "Path to log file (e.g., /var/log/auth.log, /var/log/syslog)", "required": True},
        "pattern": {"type": "string", "description": "Specific pattern to search for (optional)", "required": False},
        "tail_lines": {"type": "integer", "description": "Number of recent lines to analyze (default: 100)", "required": False, "default": 100},
    },
    dangerous=False,
)
async def log_analyze(logfile: str, pattern: Optional[str] = None, tail_lines: int = 100) -> str:
    """Analyze log files for security events."""
    if not os.path.exists(logfile):
        return f"❌ Log file not found: {logfile}"

    result = f"📋 Log Analysis: {logfile}\n\n"

    tail_lines = max(1, min(tail_lines, 10000))  # Clamp to sane range
    safe_logfile = shlex.quote(logfile)

    if pattern:
        safe_pattern = shlex.quote(pattern)
        cmd = f"grep -i {safe_pattern} {safe_logfile} | tail -{tail_lines}"
    else:
        cmd = f"tail -{tail_lines} {safe_logfile}"

    stdout, stderr, rc = await _run_cmd(["bash", "-c", cmd], timeout=30)

    if not stdout:
        return result + "No matching entries found."

    # Count security-relevant patterns
    lines = stdout.split("\n")
    security_patterns = {
        "Failed login": len([l for l in lines if "failed" in l.lower() and ("login" in l.lower() or "auth" in l.lower())]),
        "Invalid user": len([l for l in lines if "invalid user" in l.lower()]),
        "Connection refused": len([l for l in lines if "refused" in l.lower()]),
        "Permission denied": len([l for l in lines if "permission denied" in l.lower()]),
        "Error": len([l for l in lines if "error" in l.lower()]),
        "Warning": len([l for l in lines if "warning" in l.lower()]),
        "Root activity": len([l for l in lines if "root" in l.lower()]),
    }

    result += "📊 Pattern Summary:\n"
    for pattern_name, count in security_patterns.items():
        if count > 0:
            result += f"  {'⚠️ ' if count > 5 else '  '}{pattern_name}: {count}\n"

    result += f"\n📝 Log Entries ({len(lines)} lines):\n"
    result += stdout[:5000]  # Limit output

    return result


@tool(
    name="find_files",
    description="Search for files matching specific criteria (SUID, writable, recent, by extension, etc.).",
    category=ToolCategory.FORENSICS,
    parameters={
        "search_type": {"type": "string", "description": "Search type: 'suid' (SUID binaries), 'writable' (world-writable), 'recent' (recently modified), 'extension' (by extension), 'large' (large files), 'hidden' (hidden files)", "required": True},
        "path": {"type": "string", "description": "Starting path for search (default: /)", "required": False, "default": "/"},
        "extension": {"type": "string", "description": "File extension for 'extension' search type", "required": False},
        "days": {"type": "integer", "description": "Number of days for 'recent' search (default: 7)", "required": False, "default": 7},
    },
    dangerous=False,
)
async def find_files(search_type: str, path: str = "/", extension: Optional[str] = None, days: int = 7) -> str:
    """Search for interesting files."""
    safe_path = shlex.quote(path)
    safe_days = str(max(1, min(days, 365)))  # Clamp to sane range
    safe_ext = shlex.quote(extension) if extension else None

    commands = {
        "suid": f"find {safe_path} -perm -4000 -type f 2>/dev/null | head -50",
        "writable": f"find {safe_path} -writable -type f 2>/dev/null | head -50",
        "recent": f"find {safe_path} -mtime -{safe_days} -type f 2>/dev/null | head -50",
        "extension": f"find {safe_path} -name {safe_ext} -type f 2>/dev/null | head -50" if safe_ext else "echo 'Extension required'",
        "large": f"find {safe_path} -size +100M -type f 2>/dev/null | head -30",
        "hidden": f"find {safe_path} -name '.*' -type f 2>/dev/null | head -50",
    }

    if search_type not in commands:
        return f"❌ Unknown search type. Available: {', '.join(commands.keys())}"

    cmd = commands[search_type]
    stdout, stderr, rc = await _run_cmd(["bash", "-c", cmd], timeout=60)

    result = f"🔍 File Search ({search_type}) in {path}\n\n"
    if stdout:
        files = [f for f in stdout.strip().split("\n") if f]
        result += f"Found {len(files)} files:\n"
        for f in files:
            result += f"  📄 {f}\n"
    else:
        result += "No files found matching criteria."

    return result
