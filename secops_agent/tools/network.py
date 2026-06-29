"""
Network reconnaissance and scanning tools.
Wraps common network security tools: nmap, ping, traceroute, netcat.
"""

from __future__ import annotations

import asyncio
import shutil
from typing import Optional

from secops_agent.core.tools import report_progress, tool, ToolCategory
from secops_agent.core.sudo import sudo_noninteractive_status
from secops_agent.utils.helpers import (
    run_cmd as _run_cmd,
    run_cmd_streaming as _run_cmd_streaming,
    is_tool_installed as _check_tool,
)

# Sentinel returned by nmap when root is required
_ROOT_REQUIRED_MARKERS = (
    "requires root privileges",
    "you requested a scan type which requires root",
    "quitting!",
)


async def _sudo_available() -> bool:
    """Return True if non-interactive sudo is currently usable."""
    ok, _ = await sudo_noninteractive_status()
    return ok


@tool(
    name="nmap_scan",
    description=(
        "Run an Nmap scan against a target host or network. "
        "Automatically uses TCP connect scan (-sT) when root/sudo is unavailable, "
        "or SYN scan (-sS) when sudo is cached. "
        "Supports version detection, OS detection, and aggressive scanning."
    ),
    category=ToolCategory.NETWORK,
    parameters={
        "target": {"type": "string", "description": "Target IP address, hostname, or CIDR range to scan", "required": True},
        "scan_type": {
            "type": "string",
            "description": (
                "Scan type: 'auto' (smart default — SYN if root available, else TCP connect), "
                "'syn' (SYN/stealth, needs root), 'tcp' (TCP connect, no root needed), "
                "'udp' (UDP), 'ping' (ping sweep), 'version' (service version detection), "
                "'os' (OS detection, needs root), 'aggressive' (all-in-one)"
            ),
            "required": False,
            "default": "auto",
        },
        "ports": {"type": "string", "description": "Port specification (e.g., '80,443', '1-1000', 'top100'). Default scans top 1000 ports.", "required": False},
        "extra_args": {"type": "string", "description": "Additional nmap arguments as a string", "required": False},
    },
    dangerous=True,
)
async def nmap_scan(target: str, scan_type: str = "auto", ports: Optional[str] = None, extra_args: Optional[str] = None) -> str:
    """Execute an Nmap scan against the specified target."""
    await report_progress("checking prerequisites", "nmap", percent=5)
    if not _check_tool("nmap"):
        return "❌ Error: nmap is not installed. Install with: sudo apt install nmap"

    # Resolve 'auto' → SYN if root available, TCP connect otherwise
    resolved_type = scan_type
    if scan_type in ("auto", "syn"):
        has_sudo = await _sudo_available()
        if not has_sudo:
            if scan_type == "syn":
                await report_progress(
                    "sudo not available",
                    "falling back to TCP connect scan (-sT) — SYN scan requires root",
                    percent=8,
                )
            resolved_type = "tcp" if not has_sudo else "syn"
        else:
            resolved_type = "syn"

    await report_progress("building scan plan", f"{resolved_type} scan for {target}", percent=10)
    cmd = _build_nmap_cmd(resolved_type, target, ports, extra_args)

    port_scope = ports or "default top 1000"
    await report_progress("running port scan", f"{target} · {port_scope} · timeout 300s", percent=20)
    stdout, stderr, rc = await _run_cmd_streaming(
        cmd,
        timeout=300,
        inactivity_timeout=120,
        progress=lambda detail, percent=None: report_progress(
            "receiving scan output",
            detail,
            percent=percent,
        ),
        progress_percent=50,
    )
    combined = (stdout + stderr).lower()

    # Auto-retry with TCP connect if nmap reports root required
    needs_root_retry = any(marker in combined for marker in _ROOT_REQUIRED_MARKERS)
    if needs_root_retry and resolved_type != "tcp":
        await report_progress(
            "retrying without root",
            "nmap requires root for this scan type → retrying with TCP connect (-sT)",
            percent=55,
        )
        cmd_retry = _build_nmap_cmd("tcp", target, ports, extra_args)
        stdout, stderr, rc = await _run_cmd_streaming(
            cmd_retry,
            timeout=300,
            inactivity_timeout=120,
            progress=lambda detail, percent=None: report_progress(
                "receiving scan output (retry)",
                detail,
                percent=percent,
            ),
            progress_percent=75,
        )

    await report_progress("summarizing scan output", f"{len(stdout):,} stdout chars", percent=95)

    if rc != 0 and not stdout and stderr:
        # Still failing — give actionable guidance instead of confusing the LLM
        await report_progress("scan failed", f"rc {rc}", percent=100)
        return (
            f"❌ Nmap scan failed (rc={rc}).\n"
            f"stderr: {stderr.strip()}\n\n"
            "ℹ️  If root is required: use scan_type='tcp' (no root needed) or run "
            "'sudo -v' in a terminal to cache your sudo credentials first."
        )

    await report_progress("scan completed", f"{len(stdout.splitlines()):,} output lines", percent=100)
    if rc != 0 and stderr:
        return f"⚠️ Nmap completed with warnings:\n{stdout}\n{stderr}"
    return stdout if stdout else f"No output from nmap. stderr: {stderr}"


def _build_nmap_cmd(
    scan_type: str,
    target: str,
    ports: Optional[str],
    extra_args: Optional[str],
) -> list[str]:
    """Build validated nmap command list."""
    scan_flags: dict[str, list[str]] = {
        "syn": ["-sS"],
        "tcp": ["-sT"],
        "udp": ["-sU"],
        "ping": ["-sn"],
        "version": ["-sT", "-sV"],   # -sT so it works without root too
        "os": ["-O"],
        "aggressive": ["-A"],
    }
    cmd = ["nmap"] + scan_flags.get(scan_type, ["-sT"])

    if ports:
        if ports == "top100":
            cmd.extend(["--top-ports", "100"])
        else:
            cmd.extend(["-p", ports])

    # Extra arguments — validated against safety whitelist
    _NMAP_BLOCKED_PREFIXES = (
        "-oN", "-oX", "-oG", "-oA", "-oS",
        "--script",
        "--datadir",
        "--resume",
    )
    _NMAP_SHELL_META = set(";&|`$(){}[]<>'\"\\n\r")
    if extra_args:
        for arg in extra_args.split():
            has_meta = any(ch in _NMAP_SHELL_META for ch in arg)
            is_blocked = any(arg.startswith(p) or arg == p for p in _NMAP_BLOCKED_PREFIXES)
            if not has_meta and not is_blocked:
                cmd.append(arg)

    # No --reason: nmap's reason column ("syn-ack") would otherwise be parsed
    # into the service version and leak into answers ("http syn-ack Apache ...").
    cmd.extend(["-T4", target])
    return cmd


@tool(
    name="ping_host",
    description="Ping a host to check if it's alive and measure latency.",
    category=ToolCategory.NETWORK,
    parameters={
        "target": {"type": "string", "description": "Target IP or hostname to ping", "required": True},
        "count": {"type": "integer", "description": "Number of ping packets to send (default: 4)", "required": False, "default": 4},
    },
    dangerous=False,
)
async def ping_host(target: str, count: int = 4) -> str:
    """Ping a host to check availability."""
    cmd = ["ping", "-c", str(count), "-W", "3", target]
    stdout, stderr, rc = await _run_cmd(cmd, timeout=30)

    if rc != 0:
        return f"❌ Host {target} appears to be down or unreachable.\n{stderr}"
    return stdout


@tool(
    name="traceroute",
    description="Trace the network route to a target host, showing all intermediate hops.",
    category=ToolCategory.NETWORK,
    parameters={
        "target": {"type": "string", "description": "Target IP or hostname", "required": True},
        "max_hops": {"type": "integer", "description": "Maximum number of hops (default: 30)", "required": False, "default": 30},
    },
    dangerous=False,
)
async def traceroute(target: str, max_hops: int = 30) -> str:
    """Trace route to a target."""
    tool_name = "traceroute" if _check_tool("traceroute") else "tracepath"
    if not _check_tool(tool_name):
        return "❌ Error: traceroute/tracepath not installed."

    if tool_name == "traceroute":
        cmd = ["traceroute", "-m", str(max_hops), target]
    else:
        cmd = ["tracepath", target]

    stdout, stderr, rc = await _run_cmd(cmd, timeout=60)
    return stdout if stdout else f"No output. {stderr}"


@tool(
    name="port_check",
    description="Check if a specific port is open on a target using netcat.",
    category=ToolCategory.NETWORK,
    parameters={
        "target": {"type": "string", "description": "Target IP or hostname", "required": True},
        "port": {"type": "integer", "description": "Port number to check", "required": True},
        "protocol": {"type": "string", "description": "Protocol: 'tcp' or 'udp'", "required": False, "default": "tcp"},
    },
    dangerous=False,
)
async def port_check(target: str, port: int, protocol: str = "tcp") -> str:
    """Check if a specific port is open."""
    nc_cmd = "nc"
    if not _check_tool(nc_cmd):
        nc_cmd = "ncat"
        if not _check_tool(nc_cmd):
            return "❌ Error: netcat (nc/ncat) not installed."

    cmd = [nc_cmd, "-z", "-v", "-w", "5"]
    if protocol == "udp":
        cmd.append("-u")
    cmd.extend([target, str(port)])

    stdout, stderr, rc = await _run_cmd(cmd, timeout=10)
    output = stdout + stderr
    if rc == 0:
        return f"✅ Port {port}/{protocol} is OPEN on {target}\n{output}"
    else:
        return f"❌ Port {port}/{protocol} is CLOSED/FILTERED on {target}\n{output}"


@tool(
    name="dns_lookup",
    description="Perform DNS lookups using dig. Supports various record types (A, AAAA, MX, NS, TXT, CNAME, SOA, ANY).",
    category=ToolCategory.NETWORK,
    parameters={
        "domain": {"type": "string", "description": "Domain name to look up", "required": True},
        "record_type": {"type": "string", "description": "DNS record type: A, AAAA, MX, NS, TXT, CNAME, SOA, ANY", "required": False, "default": "A"},
        "dns_server": {"type": "string", "description": "Custom DNS server to query (e.g., 8.8.8.8)", "required": False},
    },
    dangerous=False,
)
async def dns_lookup(domain: str, record_type: str = "A", dns_server: Optional[str] = None) -> str:
    """Perform DNS lookup."""
    if _check_tool("dig"):
        cmd = ["dig", "+noall", "+answer", "+authority", domain, record_type.upper()]
        if dns_server:
            cmd.insert(1, f"@{dns_server}")
    elif _check_tool("nslookup"):
        cmd = ["nslookup", f"-type={record_type.upper()}", domain]
        if dns_server:
            cmd.append(dns_server)
    else:
        return "❌ Error: dig and nslookup not installed."

    stdout, stderr, rc = await _run_cmd(cmd, timeout=15)
    return stdout if stdout else f"No records found. {stderr}"
