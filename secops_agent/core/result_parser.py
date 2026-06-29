"""
Structured parsers for security tool outputs.

Each parser converts raw stdout from a tool into a ParsedResult with:
  - summary (2-3 lines for the LLM)
  - findings (vulnerabilities / info notes)
  - hosts_discovered / services_discovered (for the KnowledgeBase)
  - next_steps (suggested follow-up actions)

The ToolResultParser class dispatches to the right parser by tool name
and can optionally integrate results into a MissionContext.
"""

from __future__ import annotations

import re
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from secops_agent.core.mission import (
    Evidence,
    Finding,
    Host,
    MissionContext,
    Service,
)


# ---------------------------------------------------------------------------
# ParsedResult — the structured output of every parser
# ---------------------------------------------------------------------------

@dataclass
class ParsedResult:
    """Structured representation of a tool's output."""

    tool_name: str = ""
    raw_output: str = ""
    summary: str = ""
    findings: List[Finding] = field(default_factory=list)
    hosts_discovered: List[Host] = field(default_factory=list)
    services_discovered: List[Service] = field(default_factory=list)
    next_steps: List[str] = field(default_factory=list)
    severity: str = "info"  # overall severity: info/low/medium/high/critical
    data: Dict[str, Any] = field(default_factory=dict)  # parser-specific extras


# ---------------------------------------------------------------------------
# Known vulnerable versions (quick lookup for auto-flagging)
# ---------------------------------------------------------------------------

_ANSI_RE = re.compile(r"(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]")


def _clean_text(value: str) -> str:
    return _ANSI_RE.sub("", value or "").strip()


def _first_matching_line(raw: str, patterns: tuple[str, ...]) -> str:
    """Return the first line containing one of the case-insensitive patterns."""
    lowered_patterns = tuple(pattern.casefold() for pattern in patterns)
    for line in (raw or "").splitlines():
        clean = _clean_text(line)
        lowered = clean.casefold()
        if clean and any(pattern in lowered for pattern in lowered_patterns):
            return clean
    return ""


def _evidence(
    title: str,
    snippet: str,
    *,
    source_tool: str,
    target: str,
    metadata: Dict[str, Any] | None = None,
) -> Evidence:
    return Evidence(
        title=title,
        source_tool=source_tool,
        target=target,
        snippet=_clean_text(snippet)[:2000],
        metadata=dict(metadata or {}),
    )


_MISSING_TOOL_INSTALL_HINTS: Dict[str, Dict[str, Any]] = {
    "nmap": {
        "patterns": ("nmap is not installed",),
        "package": "nmap",
    },
    "nikto": {
        "patterns": ("nikto is not installed",),
        "package": "nikto",
    },
    "sqlmap": {
        "patterns": ("sqlmap is not installed",),
        "package": "sqlmap",
    },
    "openvpn": {
        "patterns": ("openvpn is not installed",),
        "package": "openvpn",
    },
    "whois": {
        "patterns": ("whois is not installed",),
        "package": "whois",
    },
    "curl": {
        "patterns": ("curl is not installed", "curl not installed"),
        "package": "curl",
    },
    "openssl": {
        "patterns": ("openssl not installed", "neither testssl.sh nor openssl is installed"),
        "package": "openssl",
    },
    "searchsploit": {
        "patterns": ("searchsploit not installed",),
        "package": "exploitdb",
    },
    "gobuster": {
        "patterns": ("neither gobuster nor dirb is installed",),
        "package": "gobuster",
        "alternatives": ("dirb",),
    },
    "nc": {
        "patterns": ("nc: not installed",),
        "package": "netcat-openbsd",
        "alternatives": ("ncat", "netcat"),
    },
    "traceroute": {
        "patterns": ("traceroute/tracepath not installed",),
        "package": "traceroute",
        "alternatives": ("tracepath",),
    },
    "netcat": {
        "patterns": ("netcat (nc/ncat) not installed",),
        "package": "netcat-openbsd",
        "alternatives": ("ncat",),
    },
    "dig": {
        "patterns": (
            "dig and nslookup not installed",
            "neither subfinder nor dig is available",
        ),
        "package": "dnsutils",
        "alternatives": ("nslookup", "subfinder"),
    },
    "ffuf": {
        "patterns": ("ffuf is not installed",),
        "package": "ffuf",
        "install_command": "sudo apt install -y ffuf",
    },
    "nuclei": {
        "patterns": ("nuclei is not installed",),
        "package": "nuclei",
        "install_command": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    },
}
_LAB_SETUP_INSTALLABLE_TOOLS = {
    "nmap",
    "curl",
    "nikto",
    "sqlmap",
    "searchsploit",
    "openvpn",
    "nc",
    "ffuf",
    "nuclei",
}


def _contains_timeout(raw: str) -> bool:
    lowered = _clean_text(raw).casefold()
    return any(
        marker in lowered
        for marker in (
            "tool execution timed out",
            "command timed out",
            "timed out after",
            "stopped after",
        )
    )


def _primary_target_from_args(args: Dict[str, Any]) -> str:
    for key in ("target", "url", "domain", "query", "config_path", "command"):
        value = str(args.get(key) or "").strip()
        if value:
            return value[:200]
    return "local system"


def _missing_tool_findings(raw: str, args: Dict[str, Any], source_tool: str) -> List[Finding]:
    """Extract local missing-tool blockers from known tool error formats."""
    clean = _clean_text(raw)
    lowered = clean.casefold()
    target = _primary_target_from_args(args)
    findings: List[Finding] = []

    def append_missing_tool(missing_tool: str, hint: Dict[str, Any], evidence: str) -> None:
        if any(
            (
                item.evidence_items[0].metadata.get("missing_tool")
                if item.evidence_items else ""
            ) == missing_tool
            for item in findings
        ):
            return
        package = str(hint["package"])
        install_command = str(hint.get("install_command") or f"sudo apt install -y {package}")
        title = f"Missing local tool: {missing_tool}"
        metadata = {
            "missing_tool": missing_tool,
            "install_package": package,
            "install_command": install_command,
            "alternatives": list(hint.get("alternatives", ())),
        }
        findings.append(Finding(
            title=title,
            severity="info",
            category="tool_prerequisite_missing",
            target=target,
            evidence=evidence,
            tool_used=source_tool,
            evidence_items=[
                _evidence(
                    title,
                    evidence,
                    source_tool=source_tool,
                    target=target,
                    metadata=metadata,
                )
            ],
        ))

    for missing_tool, hint in _MISSING_TOOL_INSTALL_HINTS.items():
        patterns = tuple(str(pattern).casefold() for pattern in hint.get("patterns", ()))
        if not patterns or not any(pattern in lowered for pattern in patterns):
            continue
        evidence = _first_matching_line(clean, patterns) or clean[:500]
        append_missing_tool(missing_tool, hint, evidence)

    if source_tool == "lab_setup_check":
        setup_missing = {
            match.group(1).strip().casefold()
            for match in re.finditer(r"^\s*([a-zA-Z0-9_.+-]+):\s+not installed\s*$", clean, re.MULTILINE)
        }
        installable = set(_LAB_SETUP_INSTALLABLE_TOOLS)
        if "gobuster" in setup_missing and "dirb" in setup_missing:
            installable.add("gobuster")
        for missing_tool in sorted(setup_missing & installable):
            hint = _MISSING_TOOL_INSTALL_HINTS.get(missing_tool)
            if not hint:
                continue
            evidence = _first_matching_line(clean, (f"{missing_tool}: not installed",)) or f"{missing_tool}: not installed"
            append_missing_tool(missing_tool, hint, evidence)

    return findings


def _timeout_findings(raw: str, args: Dict[str, Any], source_tool: str) -> List[Finding]:
    """Extract supervised execution timeouts as operational blockers."""
    clean = _clean_text(raw)
    if not _contains_timeout(clean):
        return []
    target = _primary_target_from_args(args)
    evidence = _first_matching_line(
        clean,
        (
            "Tool execution timed out",
            "Command timed out",
            "timed out after",
            "stopped after",
        ),
    ) or clean[:500]
    title = f"{source_tool} timed out for {target}"
    metadata = {
        "source_tool": source_tool,
        "retry_method": "timeout_retry",
    }
    return [
        Finding(
            title=title,
            severity="info",
            category="tool_timeout",
            target=target,
            evidence=evidence,
            tool_used=source_tool,
            evidence_items=[
                _evidence(
                    title,
                    evidence,
                    source_tool=source_tool,
                    target=target,
                    metadata=metadata,
                )
            ],
        )
    ]


_KNOWN_VULNS: List[tuple[str, str, str, str]] = [
    # (service_pattern, version_pattern, CVE, severity)
    ("apache", r"2\.4\.49",  "CVE-2021-41773 — Apache Path Traversal / RCE", "critical"),
    ("apache", r"2\.4\.50",  "CVE-2021-42013 — Apache Path Traversal bypass", "critical"),
    ("openssh", r"[78]\.\d",  "", ""),  # no auto-flag, but track version
    ("vsftpd", r"2\.3\.4",   "CVE-2011-2523 — vsftpd 2.3.4 Backdoor", "critical"),
    ("proftpd", r"1\.3\.5",  "CVE-2015-3306 — ProFTPD mod_copy RCE", "high"),
    ("exim", r"4\.8[0-9]",   "CVE-2019-10149 — Exim RCE", "critical"),
    ("webmin", r"1\.9[0-2]", "CVE-2019-15107 — Webmin RCE", "critical"),
    ("smbd", r"[34]\.\d",    "", ""),
    ("mysql", r"5\.[567]",   "", ""),
    ("tomcat", r"[89]\.\d",  "", ""),
]


def _check_known_vulns(service: str, version: str, target: str) -> List[Finding]:
    """Return findings for known vulnerable service versions."""
    findings: List[Finding] = []
    combined = f"{service} {version}".lower()
    for svc_pat, ver_pat, cve, severity in _KNOWN_VULNS:
        if svc_pat not in combined:
            continue
        if not cve:
            continue
        if re.search(ver_pat, version):
            evidence = f"{service} {version}".strip()
            findings.append(Finding(
                title=cve,
                severity=severity,
                category="known_vuln",
                target=target,
                evidence=evidence,
                tool_used="nmap_scan",
                evidence_items=[
                    _evidence(
                        cve,
                        evidence,
                        source_tool="nmap_scan",
                        target=target,
                        metadata={"service": service, "version": version},
                    )
                ],
            ))
    return findings


# ---------------------------------------------------------------------------
# Individual parsers
# ---------------------------------------------------------------------------

def _overall_severity(findings: List[Finding]) -> str:
    order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    current = "info"
    for finding in findings:
        if order.get(finding.severity, 0) > order.get(current, 0):
            current = finding.severity
    return current


def _severity_from_cvss(score: float | None) -> str:
    if score is None:
        return "info"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def parse_nmap_output(raw: str, args: Dict[str, Any]) -> ParsedResult:
    """Parse nmap stdout into structured data."""
    target = args.get("target", "unknown")
    services: List[Service] = []
    findings: List[Finding] = []
    os_guess = ""

    # Extract ports: "80/tcp  open  http  Apache httpd 2.4.49"
    port_re = re.compile(
        r"^\s*(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)[ \t]*(.*)",
        re.MULTILINE,
    )
    for m in port_re.finditer(raw):
        port, proto, state, svc_name, version = m.groups()
        version = version.strip()
        svc = Service(
            host=target, port=int(port), protocol=proto,
            service=svc_name, version=version, state=state,
        )
        services.append(svc)

        # Auto-detect known vulns
        vulns = _check_known_vulns(svc_name, version, target)
        if vulns:
            svc.vulns = [f.title for f in vulns]
            findings.extend(vulns)

    # OS detection
    os_match = re.search(r"OS details?:\s*(.+)", raw)
    if os_match:
        os_guess = os_match.group(1).strip()

    # Aggressive scan info
    os_match2 = re.search(r"Running:\s*(.+)", raw)
    if os_match2 and not os_guess:
        os_guess = os_match2.group(1).strip()

    lowered_raw = raw.casefold()
    host_discovery_failed = not services and (
        "host seems down" in lowered_raw
        or "try -pn" in lowered_raw
        or ("0 hosts up" in lowered_raw and "nmap done" in lowered_raw)
    )
    if host_discovery_failed:
        evidence = _first_matching_line(
            raw,
            ("Host seems down", "try -Pn", "0 hosts up"),
        ) or "Nmap did not identify the target as up."
        title = f"Nmap host discovery failed for {target}"
        findings.append(Finding(
            title=title,
            severity="info",
            category="scan_host_discovery_failed",
            target=target,
            evidence=evidence,
            tool_used="nmap_scan",
            evidence_items=[
                _evidence(
                    title,
                    evidence,
                    source_tool="nmap_scan",
                    target=target,
                    metadata={"retry_extra_args": "-Pn"},
                )
            ],
        ))

    host = Host(ip=target, os=os_guess, services=list(services))

    # Hostname
    hostname_match = re.search(r"Nmap scan report for (\S+)", raw)
    if hostname_match:
        name = hostname_match.group(1)
        if name != target:
            host.hostname = name

    # Next steps
    next_steps = _suggest_nmap_next_steps(services, findings)
    if host_discovery_failed:
        next_steps.insert(0, "Retry nmap_scan with -Pn to skip host discovery")

    # Summary
    svc_list = ", ".join(f"{s.port}/{s.service}" for s in services[:8])
    if len(services) > 8:
        svc_list += f" +{len(services) - 8} more"
    if host_discovery_failed:
        summary = (
            f"Nmap host discovery failed for {target}"
            "\nSuggested retry: use -Pn because Nmap reported the host as down."
        )
    else:
        summary = (
            f"{len(services)} service(s) on {target}"
            + (f" ({os_guess})" if os_guess else "")
            + (f"\nServices: {svc_list}" if svc_list else "")
            + (f"\n⚠ {len(findings)} known vuln(s) detected" if findings else "")
        )

    overall = "info"
    if any(f.severity == "critical" for f in findings):
        overall = "critical"
    elif any(f.severity == "high" for f in findings):
        overall = "high"

    return ParsedResult(
        tool_name="nmap_scan",
        raw_output=raw,
        summary=summary,
        findings=findings,
        hosts_discovered=[host],
        services_discovered=services,
        next_steps=next_steps,
        severity=overall,
        data={"host_discovery_failed": host_discovery_failed},
    )


def _suggest_nmap_next_steps(services: List[Service], findings: List[Finding]) -> List[str]:
    steps: List[str] = []
    svc_names = {s.service.lower() for s in services}
    ports = {s.port for s in services}
    operational_categories = {"scan_host_discovery_failed", "tool_prerequisite_missing"}

    if findings:
        for f in findings:
            if f.category in operational_categories:
                continue
            steps.append(f"Verify {f.title} on {f.target}")

    if "http" in svc_names or 80 in ports or 8080 in ports or 443 in ports:
        steps.append("Run dir_brute on web services")
        steps.append("Run nikto_scan for web vulnerabilities")
    if "ssh" in svc_names:
        steps.append("Check SSH auth methods and version")
    if "mysql" in svc_names or "postgresql" in svc_names:
        steps.append("Test database authentication")
    if "ftp" in svc_names:
        steps.append("Check FTP anonymous login")
    if "smb" in svc_names or "microsoft-ds" in svc_names or 445 in ports:
        steps.append("Enumerate SMB shares")

    return steps[:6]


def parse_dir_brute_output(raw: str, args: Dict[str, Any]) -> ParsedResult:
    """Parse gobuster/dirb directory brute-force output."""
    url = args.get("url", args.get("target", "unknown"))
    found: List[Dict[str, str]] = []
    findings: List[Finding] = []
    missing_wordlist_match = re.search(
        r'wordlist file\s+"?([^"\r\n]+)"?\s+does not exist',
        raw,
        re.IGNORECASE,
    )
    if missing_wordlist_match:
        missing_path = missing_wordlist_match.group(1).strip()
        title = f"Directory brute-force wordlist missing for {url}"
        evidence = _first_matching_line(raw, ("wordlist file", "does not exist")) or raw[:500]
        findings.append(Finding(
            title=title,
            severity="info",
            category="tool_prerequisite_missing",
            target=url,
            evidence=evidence,
            tool_used="dir_brute",
            evidence_items=[
                _evidence(
                    title,
                    evidence,
                    source_tool="dir_brute",
                    target=url,
                    metadata={"missing_wordlist": missing_path},
                )
            ],
        ))

    # Gobuster format: "/admin (Status: 200) [Size: 1234]" or
    # quiet output without a leading slash: "admin (Status: 200) [Size: 1234]".
    gobuster_re = re.compile(r"^(/?[^\s\[]+)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)])?", re.MULTILINE)
    for m in gobuster_re.finditer(raw):
        path, status, size = m.groups()
        if not path.startswith("/"):
            path = f"/{path}"
        found.append({"path": path, "status": status, "size": size or "?"})

    # Dirb format: "==> DIRECTORY: http://target/admin/"  or "+ http://target/robots.txt (CODE:200|SIZE:29)"
    dirb_re = re.compile(r"\+\s+(https?://\S+)\s+\(CODE:(\d+)\|SIZE:(\d+)\)", re.MULTILINE)
    for m in dirb_re.finditer(raw):
        full_url, status, size = m.groups()
        path = re.sub(r"https?://[^/]+", "", full_url)
        found.append({"path": path, "status": status, "size": size})

    # Dirb directory-only format: "==> DIRECTORY: http://target/admin/"
    dirb_dir_re = re.compile(r"^==>\s+DIRECTORY:\s+https?://[^/]+(/[^ \t\r\n]*)", re.MULTILINE)
    for m in dirb_dir_re.finditer(raw):
        found.append({"path": m.group(1), "status": "directory", "size": "?"})

    # ffuf format: "admin [Status: 200, Size: 1234, Words: ...]"
    ffuf_re = re.compile(r"^([^\s\[]+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)", re.MULTILINE)
    for m in ffuf_re.finditer(raw):
        path, status, size = m.groups()
        if not path.startswith("/"):
            path = f"/{path}"
        found.append({"path": path, "status": status, "size": size})

    empty_discovery = (
        not found
        and not missing_wordlist_match
        and not _contains_timeout(raw)
        and (
            not _clean_text(raw)
            or _clean_text(raw).casefold() in {"no results.", "no results", "(no output)", "no output."}
            or _clean_text(raw).casefold().startswith(("no results.", "no output."))
        )
    )
    if empty_discovery:
        evidence = _first_matching_line(raw, ("No results", "no output")) or "No paths were discovered."
        title = f"No web content paths found on {url}"
        findings.append(Finding(
            title=title,
            severity="info",
            category="content_discovery_empty",
            target=url,
            evidence=evidence,
            tool_used="dir_brute",
            evidence_items=[
                _evidence(
                    title,
                    evidence,
                    source_tool="dir_brute",
                    target=url,
                    metadata={
                        "retry_extensions": "php,txt,bak,html",
                        "retry_threads": 10,
                    },
                )
            ],
        ))

    # Flag interesting directories
    interesting = {"admin", "login", "dashboard", "config", "backup", "upload",
                   "api", "debug", "test", "staging", "phpmyadmin", ".git",
                   ".env", "wp-admin", "server-status", "manager", "panel"}
    for entry in found:
        path_lower = entry["path"].lower()
        if any(i in path_lower for i in interesting):
            title = f"Interesting path: {entry['path']} ({entry['status']})"
            evidence = f"Status {entry['status']}, Size {entry['size']}"
            findings.append(Finding(
                title=title,
                severity="medium" if entry["status"] in ("200", "301", "302", "directory") else "low",
                category="dir_enum",
                target=url,
                evidence=evidence,
                tool_used="dir_brute",
                evidence_items=[
                    _evidence(
                        title,
                        evidence,
                        source_tool="dir_brute",
                        target=url,
                        metadata={
                            "path": entry["path"],
                            "status": entry["status"],
                            "size": entry["size"],
                        },
                    )
                ],
            ))

    interesting_count = sum(1 for finding in findings if finding.category == "dir_enum")
    summary = f"{len(found)} path(s) found on {url}"
    if missing_wordlist_match:
        summary += "\nDirectory brute force did not run because the configured wordlist is missing."
    if empty_discovery:
        summary += "\nDirectory brute force completed but did not find paths."
    if interesting_count:
        summary += f"\n⚠ {interesting_count} interesting path(s)"

    next_steps = []
    if missing_wordlist_match:
        next_steps.append("Retry dir_brute with an available or built-in fallback wordlist")
    if empty_discovery:
        next_steps.append("Retry dir_brute with file extensions or a broader confirmed wordlist")
    if any(finding.category == "dir_enum" for finding in findings):
        next_steps.append("Investigate interesting paths manually")
    if any(".git" in e["path"] for e in found):
        next_steps.append("Dump .git repository for source code disclosure")

    return ParsedResult(
        tool_name="dir_brute",
        raw_output=raw,
        summary=summary,
        findings=findings,
        next_steps=next_steps,
        severity=_overall_severity(findings),
        data={
            "paths": found,
            "missing_wordlist": missing_wordlist_match.group(1).strip()
            if missing_wordlist_match else "",
            "empty_result": empty_discovery,
        },
    )


def parse_nikto_output(raw: str, args: Dict[str, Any]) -> ParsedResult:
    """Parse nikto scan output."""
    target = args.get("url", args.get("target", "unknown"))
    findings: List[Finding] = []

    server_info = ""

    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped.startswith("+"):
            continue
        body = stripped[1:].strip()
        body = body.lstrip("+").strip()
        if not body:
            continue
        if body.lower().startswith(("target ip", "target hostname", "start time", "end time")):
            continue
        if body.lower().startswith("server:"):
            server_info = body.split(":", 1)[1].strip()
            continue

        osvdb = ""
        path = ""
        desc = body
        osvdb_match = re.match(r"(OSVDB-\d+):\s*(?:(/\S*):\s*)?(.+)", body)
        path_match = re.match(r"(/\S*):\s*(.+)", body)
        if osvdb_match:
            osvdb, path, desc = osvdb_match.groups()
            osvdb = f"{osvdb}: "
            path = path or ""
        elif path_match:
            path, desc = path_match.groups()
        desc = desc.strip()

        # Classify severity
        sev = "info"
        desc_lower = desc.lower()
        if any(w in desc_lower for w in ("xss", "injection", "rce", "rfi", "lfi", "remote")):
            sev = "high"
        elif any(w in desc_lower for w in ("directory listing", "directory indexing", "backup", "config", "default", "not defined", "not present")):
            sev = "medium"
        elif any(w in desc_lower for w in ("outdated", "headers", "cookie")):
            sev = "low"

        title = desc[:120]
        evidence = f"{osvdb or ''} {desc}"[:500]
        finding_target = f"{target}{path or ''}"
        findings.append(Finding(
            title=title,
            severity=sev,
            category="web_vuln",
            target=finding_target,
            evidence=evidence,
            tool_used="nikto_scan",
            evidence_items=[
                _evidence(
                    title,
                    evidence,
                    source_tool="nikto_scan",
                    target=finding_target,
                    metadata={"path": path, "osvdb": osvdb.rstrip(": ")},
                )
            ],
        ))

    summary = f"Nikto scan on {target}: {len(findings)} finding(s)"
    if server_info:
        summary += f"\nServer: {server_info}"

    next_steps = []
    if any(f.severity in ("high", "critical") for f in findings):
        next_steps.append("Manually verify high-severity findings")
    if any("sql" in f.title.lower() for f in findings):
        next_steps.append("Run sql_injection_test on flagged endpoints")
    if any("xss" in f.title.lower() for f in findings):
        next_steps.append("Run xss_test on flagged endpoints")

    overall = "info"
    if any(f.severity == "critical" for f in findings):
        overall = "critical"
    elif any(f.severity == "high" for f in findings):
        overall = "high"
    elif any(f.severity == "medium" for f in findings):
        overall = "medium"

    return ParsedResult(
        tool_name="nikto_scan",
        raw_output=raw,
        summary=summary,
        findings=findings,
        next_steps=next_steps,
        severity=overall,
        data={"server": server_info} if server_info else {},
    )


def parse_sqlmap_output(raw: str, args: Dict[str, Any]) -> ParsedResult:
    """Parse sqlmap output."""
    target = args.get("url", args.get("target", "unknown"))
    findings: List[Finding] = []

    # SQLMap injectable parameter blocks.
    injectable_re = re.compile(
        r"^\s*Parameter:\s*(\S+)\s*\(([^)]+)\)(.*?)(?=^\s*Parameter:|\Z)",
        re.MULTILINE | re.DOTALL,
    )
    for m in injectable_re.finditer(raw):
        param, place, block = m.groups()
        types = [t.strip() for t in re.findall(r"^\s*Type:\s*(.+)$", block, re.MULTILINE)]
        titles = [t.strip() for t in re.findall(r"^\s*Title:\s*(.+)$", block, re.MULTILINE)]
        inject_type = ", ".join(types) if types else place
        evidence = f"Parameter: {param}, Place: {place}"
        if types:
            evidence += f", Types: {', '.join(types)}"
        if titles:
            evidence += f", Titles: {'; '.join(titles[:3])}"
        title = f"SQL Injection in '{param}' ({inject_type})"
        findings.append(Finding(
            title=title,
            severity="critical",
            category="sqli",
            target=target,
            evidence=evidence[:500],
            tool_used="sql_injection_test",
            evidence_items=[
                _evidence(
                    title,
                    evidence[:500],
                    source_tool="sql_injection_test",
                    target=target,
                    metadata={
                        "parameter": param,
                        "place": place,
                        "types": types,
                        "titles": titles[:5],
                    },
                )
            ],
        ))

    # Database type
    dbms_match = re.search(r"back-end DBMS:\s*(.+)", raw)
    dbms = dbms_match.group(1).strip() if dbms_match else ""

    # Check for "not injectable"
    not_injectable = "all tested parameters do not appear to be injectable" in raw.lower()

    if not_injectable and not findings:
        summary = f"SQLMap: No injection found on {target}"
    else:
        summary = f"SQLMap: {len(findings)} injectable parameter(s) on {target}"
        if dbms:
            summary += f"\nDatabase: {dbms}"

    next_steps = []
    if findings:
        next_steps.append("Extract database schema (--tables)")
        next_steps.append("Dump credentials if authorized")
        next_steps.append("Check for OS command execution (--os-shell)")

    return ParsedResult(
        tool_name="sql_injection_test",
        raw_output=raw,
        summary=summary,
        findings=findings,
        next_steps=next_steps,
        severity="critical" if findings else "info",
        data={"dbms": dbms},
    )


def parse_dns_output(raw: str, args: Dict[str, Any]) -> ParsedResult:
    """Parse DNS lookup output (dig/nslookup)."""
    target = args.get("target", args.get("domain", "unknown"))
    records: List[Dict[str, str]] = []
    hosts: List[Host] = []

    # dig format: "example.com.  300  IN  A  93.184.216.34"
    dig_re = re.compile(r"^(\S+)\s+(?:\d+\s+)?(?:IN\s+)?([A-Z0-9]+)\s+(.+)$", re.MULTILINE)
    for m in dig_re.finditer(raw):
        name, rtype, value = m.groups()
        rtype = rtype.upper()
        value = value.strip().strip('"')
        records.append({"name": name, "type": rtype, "value": value})

    # nslookup fallback: "Name: example.com" followed by "Address: 93.184.216.34"
    ns_name = ""
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("name:"):
            ns_name = stripped.split(":", 1)[1].strip()
        elif stripped.lower().startswith("address:") and ns_name:
            value = stripped.split(":", 1)[1].strip()
            if re.match(r"^[0-9a-fA-F:.]+$", value):
                records.append({"name": ns_name, "type": "AAAA" if ":" in value else "A", "value": value})

    for record in records:
        if record["type"] in {"A", "AAAA"}:
            hostname = record["name"].rstrip(".")
            hosts.append(Host(ip=record["value"], hostname=hostname))

    summary = f"DNS lookup for {target}: {len(records)} record(s)"
    ips = [r["value"] for r in records if r["type"] == "A"]
    if ips:
        summary += f"\nIPs: {', '.join(ips[:5])}"

    next_steps = []
    if ips:
        next_steps.append("Run nmap_scan against resolved in-scope IPs")
    if any(r["type"] == "MX" for r in records):
        next_steps.append("Review MX hosts for exposed mail services")

    return ParsedResult(
        tool_name="dns_lookup",
        raw_output=raw,
        summary=summary,
        hosts_discovered=hosts,
        next_steps=next_steps,
        data={"records": records},
    )


def parse_whois_output(raw: str, args: Dict[str, Any]) -> ParsedResult:
    """Parse WHOIS output into registrar, nameserver, and contact metadata."""
    target = args.get("target", "unknown")
    clean = _clean_text(raw)

    no_match = re.search(r"(?i)\b(no match|not found|no entries found)\b", clean)
    domain_match = re.search(r"(?im)^(?:Domain Name|domain):\s*(.+)$", clean)
    registrar_match = re.search(r"(?im)^Registrar:\s*(.+)$", clean)
    org_match = re.search(r"(?im)^(?:Registrant Organization|OrgName|Organization):\s*(.+)$", clean)
    status = sorted(set(re.findall(r"(?im)^Domain Status:\s*([^\r\n]+)", clean)))
    nameservers = sorted(set(ns.strip().rstrip(".") for ns in re.findall(r"(?im)^Name Server:\s*(\S+)", clean)))
    emails = sorted(set(re.findall(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", clean)))

    if no_match:
        summary = f"WHOIS lookup for {target}: no registration match"
    else:
        domain = domain_match.group(1).strip() if domain_match else target
        registrar = registrar_match.group(1).strip() if registrar_match else ""
        summary = f"WHOIS lookup for {domain}"
        if registrar:
            summary += f"\nRegistrar: {registrar}"
        if nameservers:
            summary += f"\nName servers: {', '.join(nameservers[:4])}"

    next_steps = []
    if nameservers:
        next_steps.append("Run DNS lookups against discovered name servers")
    if emails:
        next_steps.append("Treat WHOIS emails as OSINT only; do not target without scope")

    return ParsedResult(
        tool_name="whois_lookup",
        raw_output=raw,
        summary=summary,
        next_steps=next_steps,
        data={
            "domain": domain_match.group(1).strip() if domain_match else target,
            "registrar": registrar_match.group(1).strip() if registrar_match else "",
            "organization": org_match.group(1).strip() if org_match else "",
            "status": status,
            "nameservers": nameservers,
            "emails": emails[:10],
            "no_match": bool(no_match),
        },
    )


def parse_ssl_output(raw: str, args: Dict[str, Any]) -> ParsedResult:
    """Parse SSL/TLS check output."""
    domain = args.get("domain", args.get("target", "unknown"))
    findings: List[Finding] = []
    data: Dict[str, Any] = {}

    for key in ("subject", "issuer", "notBefore", "notAfter", "serial", "SHA1 Fingerprint"):
        match = re.search(rf"^{re.escape(key)}=(.+)$", raw, re.MULTILINE)
        if match:
            data[key] = match.group(1).strip()

    # Check for expired cert
    expired = "certificate has expired" in raw.lower() or "verify return code: 10" in raw.lower()
    not_after = data.get("notAfter")
    if not_after:
        try:
            expires_at = datetime.strptime(not_after, "%b %d %H:%M:%S %Y GMT").replace(tzinfo=timezone.utc)
            data["expires_at"] = expires_at.isoformat()
            expired = expired or expires_at < datetime.now(timezone.utc)
        except ValueError:
            pass

    if expired:
        title = f"SSL certificate expired on {domain}"
        evidence = "Certificate has expired"
        findings.append(Finding(
            title=title,
            severity="high",
            category="ssl",
            target=domain,
            evidence=evidence,
            tool_used="ssl_check",
            evidence_items=[
                _evidence(
                    title,
                    evidence,
                    source_tool="ssl_check",
                    target=domain,
                    metadata={"not_after": not_after, "expires_at": data.get("expires_at", "")},
                )
            ],
        ))

    # Check for self-signed
    subject = data.get("subject", "")
    issuer = data.get("issuer", "")
    self_signed = (
        "self signed" in raw.lower()
        or "self-signed" in raw.lower()
        or bool(subject and issuer and subject == issuer)
    )
    if self_signed:
        title = f"Self-signed certificate on {domain}"
        evidence = "Self-signed certificate detected"
        findings.append(Finding(
            title=title,
            severity="medium",
            category="ssl",
            target=domain,
            evidence=evidence,
            tool_used="ssl_check",
            evidence_items=[
                _evidence(
                    title,
                    evidence,
                    source_tool="ssl_check",
                    target=domain,
                    metadata={"subject": subject, "issuer": issuer},
                )
            ],
        ))

    summary = f"SSL check for {domain}: {len(findings)} issue(s)"
    return ParsedResult(
        tool_name="ssl_check",
        raw_output=raw,
        summary=summary,
        findings=findings,
        severity=_overall_severity(findings),
        data=data,
    )


def parse_http_headers_output(raw: str, args: Dict[str, Any]) -> ParsedResult:
    """Parse HTTP headers analysis output."""
    url = args.get("url", "unknown")
    findings: List[Finding] = []
    headers: Dict[str, str] = {}
    header_re = re.compile(r"^([A-Za-z][A-Za-z0-9_.-]*):\s*(.*)$")
    for line in raw.splitlines():
        match = header_re.match(line.strip())
        if match:
            headers[match.group(1).lower()] = match.group(2).strip()

    missing_headers = []
    security_headers = {
        "x-frame-options": "X-Frame-Options",
        "x-content-type-options": "X-Content-Type-Options",
        "strict-transport-security": "Strict-Transport-Security",
        "content-security-policy": "Content-Security-Policy",
        "x-xss-protection": "X-XSS-Protection",
    }
    for header_key, header_name in security_headers.items():
        if header_key not in headers:
            missing_headers.append(header_name)

    if missing_headers:
        title = f"Missing security headers on {url}"
        evidence = f"Missing: {', '.join(missing_headers)}"
        findings.append(Finding(
            title=title,
            severity="low",
            category="headers",
            target=url,
            evidence=evidence,
            tool_used="http_headers",
            evidence_items=[
                _evidence(
                    title,
                    evidence,
                    source_tool="http_headers",
                    target=url,
                    metadata={
                        "missing_headers": missing_headers,
                        "observed_headers": sorted(headers),
                    },
                )
            ],
        ))

    summary = f"HTTP headers for {url}"
    if missing_headers:
        summary += f"\n⚠ Missing {len(missing_headers)} security header(s)"

    return ParsedResult(
        tool_name="http_headers",
        raw_output=raw,
        summary=summary,
        findings=findings,
        severity="low" if findings else "info",
        data={"headers": headers, "missing_headers": missing_headers},
    )


def parse_searchsploit_output(raw: str, args: Dict[str, Any]) -> ParsedResult:
    """Parse searchsploit table or JSON output into exploit references."""
    query = args.get("query", "unknown")
    clean = _clean_text(raw)
    results: List[Dict[str, str]] = []

    try:
        payload = json.loads(clean)
    except json.JSONDecodeError:
        payload = None

    if isinstance(payload, dict):
        for item in payload.get("RESULTS_EXPLOIT", []) or []:
            title = str(item.get("Title") or item.get("title") or "").strip()
            path = str(item.get("Path") or item.get("path") or "").strip()
            codes = item.get("Codes") or item.get("codes") or ""
            if title:
                results.append({"title": title, "path": path, "codes": str(codes)})
    else:
        for line in clean.splitlines():
            if "|" not in line:
                continue
            if re.search(r"(?i)exploit title\s*\|\s*path", line):
                continue
            if set(line.replace("|", "").replace(" ", "").strip()) <= {"-"}:
                continue
            title, path = [part.strip() for part in line.rsplit("|", 1)]
            if title and path:
                results.append({"title": title, "path": path, "codes": ""})

    findings: List[Finding] = []
    for entry in results[:10]:
        title = f"Exploit reference available: {entry['title'][:100]}"
        evidence = f"Path: {entry['path']}" + (f"; Codes: {entry['codes']}" if entry.get("codes") else "")
        findings.append(Finding(
            title=title,
            severity="info",
            category="exploit_reference",
            target=str(query),
            evidence=evidence,
            tool_used="searchsploit",
            evidence_items=[
                _evidence(
                    title,
                    evidence,
                    source_tool="searchsploit",
                    target=str(query),
                    metadata={
                        "exploit_title": entry["title"],
                        "path": entry["path"],
                        "codes": entry.get("codes", ""),
                    },
                )
            ],
        ))

    summary = f"searchsploit for {query}: {len(results)} result(s)"
    next_steps = ["Review exploit applicability against confirmed service versions"] if results else []
    return ParsedResult(
        tool_name="searchsploit",
        raw_output=raw,
        summary=summary,
        findings=findings,
        next_steps=next_steps,
        severity="info",
        data={"results": results},
    )


def parse_cve_output(raw: str, args: Dict[str, Any]) -> ParsedResult:
    """Parse CVE lookup output into a CVE reference finding."""
    requested = str(args.get("cve_id", "")).upper()
    clean = _clean_text(raw)
    cve_match = re.search(r"CVE-\d{4}-\d{4,7}", clean, re.IGNORECASE)
    cve_id = requested or (cve_match.group(0).upper() if cve_match else "unknown")

    details: Dict[str, Any] = {}
    json_match = re.search(r"(\{.*\})", clean, re.DOTALL)
    if json_match:
        try:
            loaded = json.loads(json_match.group(1))
            if isinstance(loaded, dict):
                details = loaded
        except json.JSONDecodeError:
            details = {}

    summary_text = str(
        details.get("summary")
        or details.get("description")
        or details.get("Summary")
        or ""
    ).strip()
    score: float | None = None
    raw_score = details.get("cvss") or details.get("cvss3") or details.get("cvss_score")
    if raw_score is None:
        score_match = re.search(r"(?i)\bCVSS(?:v3)?[:\s]+([0-9]+(?:\.[0-9])?)", clean)
        raw_score = score_match.group(1) if score_match else None
    try:
        score = float(raw_score) if raw_score is not None else None
    except (TypeError, ValueError):
        score = None

    findings: List[Finding] = []
    if cve_id != "unknown" and (summary_text or score is not None):
        severity = _severity_from_cvss(score)
        title = cve_id if not summary_text else f"{cve_id}: {summary_text[:100]}"
        evidence = f"CVSS: {score}" if score is not None else "CVE detail available"
        findings.append(Finding(
            title=title,
            severity=severity,
            category="cve_reference",
            target=cve_id,
            evidence=evidence,
            tool_used="cve_lookup",
            evidence_items=[
                _evidence(
                    title,
                    evidence,
                    source_tool="cve_lookup",
                    target=cve_id,
                    metadata={"cve_id": cve_id, "cvss": score, "summary": summary_text},
                )
            ],
        ))

    summary = f"CVE lookup for {cve_id}: {len(findings)} reference(s)"
    if score is not None:
        summary += f"\nCVSS: {score}"
    next_steps = ["Correlate CVE against confirmed product and version before reporting"] if findings else []
    return ParsedResult(
        tool_name="cve_lookup",
        raw_output=raw,
        summary=summary,
        findings=findings,
        next_steps=next_steps,
        severity=_overall_severity(findings),
        data={"cve_id": cve_id, "cvss": score, "summary": summary_text, "details": details},
    )


_COMMON_SUID_BASENAMES = {
    "at",
    "chfn",
    "chsh",
    "crontab",
    "dbus-daemon-launch-helper",
    "expiry",
    "fusermount",
    "gpasswd",
    "mount",
    "newgrp",
    "passwd",
    "pkexec",
    "ssh-keysign",
    "su",
    "sudo",
    "umount",
}


def parse_run_shell_output(raw: str, args: Dict[str, Any]) -> ParsedResult:
    """Parse shell output and extract high-signal local privilege evidence."""
    parsed = parse_generic_output(raw, {**args, "_tool_name": "run_shell"})
    command = str(args.get("command") or "").casefold()
    clean = _clean_text(raw)
    suid_context = (
        "suid" in command
        or "-perm -4000" in command
        or "-perm /4000" in command
        or "u=s" in command
        or "setuid" in command
    )
    if not suid_context:
        return parsed

    paths = []
    for line in clean.splitlines():
        stripped = line.strip()
        if not stripped.startswith("/") or " " in stripped:
            continue
        if stripped.endswith(":") or stripped.startswith("/proc/"):
            continue
        paths.append(stripped)

    findings: List[Finding] = []
    for path in paths[:50]:
        basename = path.rsplit("/", 1)[-1].casefold()
        if basename in _COMMON_SUID_BASENAMES:
            continue
        title = f"Unusual SUID binary: {path}"
        evidence = f"SUID enumeration output included {path}"
        findings.append(Finding(
            title=title,
            severity="high",
            category="suid_binary",
            target=path,
            evidence=evidence,
            tool_used="run_shell",
            evidence_items=[
                _evidence(
                    title,
                    evidence,
                    source_tool="run_shell",
                    target=path,
                    metadata={"path": path, "command": str(args.get("command") or "")[:300]},
                )
            ],
        ))

    if findings:
        parsed.findings = findings
        parsed.severity = "high"
        parsed.summary = f"run_shell: {len(findings)} unusual SUID candidate(s)"
        parsed.next_steps = [
            "Assess unusual SUID binaries with a bounded, authorized privilege-escalation review"
        ]
    return parsed


def parse_generic_output(raw: str, args: Dict[str, Any]) -> ParsedResult:
    """Fallback parser — lead the summary with the actual content.

    Tools without a dedicated parser (vpn_status, sysinfo, lab_setup_check, ...)
    previously summarised as a meta count ("N line(s) of output / First line:")
    which buried the key fact and read as noise in the answer. Now a short
    output is surfaced verbatim; a long one leads with its first substantive
    line plus a remainder count.
    """
    tool = args.get("_tool_name", "unknown")
    clean = _clean_text(raw)
    lines = [line for line in clean.split("\n") if line.strip()]

    if not lines:
        summary = f"{tool}: (no output)"
    elif len(lines) <= 4 and len(clean) <= 400:
        summary = clean
    else:
        lead = _first_informative_line(lines)
        summary = lead[:200]
        if len(lines) > 1:
            summary += f"  (+{len(lines) - 1} more line(s))"

    return ParsedResult(
        tool_name=tool,
        raw_output=raw,
        summary=summary,
    )


def _first_informative_line(lines: list[str]) -> str:
    """Pick the most useful line to lead a collapsed preview.

    Prefer the first ``key: value`` fact (e.g. ``Hostname: ubuntu-desktop``),
    skipping decorative banners (``🖥️ System Information``) and section rules
    (``── OS ──``) that read as noise rather than information.
    """
    def is_banner_or_rule(text: str) -> bool:
        stripped = text.strip()
        # Section rule like "── OS ──": mostly box-drawing around a short label.
        core = stripped.strip("─-=_~ ").strip()
        if core != stripped and len(core) <= 16:
            return True
        # Emoji/symbol banner with no value (no colon), e.g. "🖥️ System Information".
        if ":" not in stripped and not stripped[:1].isascii():
            return True
        return False

    for line in lines:
        stripped = line.strip()
        before, sep, after = stripped.partition(":")
        if sep and after.strip() and any(ch.isalnum() for ch in before):
            return stripped
    for line in lines:
        if not is_banner_or_rule(line):
            return line.strip()
    return lines[0].strip()


# ---------------------------------------------------------------------------
# ffuf / nuclei parsers
# ---------------------------------------------------------------------------


def parse_ffuf_output(raw: str, args: Dict[str, Any]) -> ParsedResult:
    """Parse ffuf stdout into structured findings.

    ffuf verbose output contains lines like:
        [Status: 200, Size: 1234, Words: 56, Lines: 78, Duration: 12ms]
        | URL | http://target/admin
    """
    target_url = args.get("url", "unknown")
    findings: List[Finding] = []
    found_paths: List[str] = []

    # Pattern for ffuf result lines (verbose mode with -v)
    url_re = re.compile(r"\|\s*URL\s*\|\s*(\S+)")
    status_re = re.compile(r"\[Status:\s*(\d+),\s*Size:\s*(\d+)")

    current_status = ""
    current_size = ""
    for line in raw.splitlines():
        status_match = status_re.search(line)
        if status_match:
            current_status = status_match.group(1)
            current_size = status_match.group(2)
            continue

        url_match = url_re.search(line)
        if url_match:
            found_url = url_match.group(1)
            found_paths.append(found_url)

            # Determine severity based on path and status
            path_lower = found_url.lower()
            sensitive_paths = (
                "/admin", "/login", "/dashboard", "/phpmyadmin",
                "/wp-admin", "/manager", "/console", "/shell",
                "/backup", "/.env", "/.git", "/config",
                "/actuator", "/debug", "/api", "/swagger",
            )
            is_sensitive = any(kw in path_lower for kw in sensitive_paths)
            severity = "medium" if is_sensitive else "info"

            findings.append(Finding(
                title=f"Discovered: {found_url} [{current_status}]",
                severity=severity,
                category="content_discovery",
                target=found_url,
                evidence=f"Status {current_status}, Size {current_size}",
                tool_used="ffuf_scan",
            ))
            current_status = ""
            current_size = ""

    # Also parse non-verbose compact output: "path [Status: 200, ...]"
    compact_re = re.compile(
        r"^(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)",
        re.MULTILINE,
    )
    seen_urls = {f.target for f in findings}
    for m in compact_re.finditer(raw):
        path, status, size = m.group(1), m.group(2), m.group(3)
        if path not in seen_urls:
            found_paths.append(path)
            path_lower = path.lower()
            sensitive_paths = (
                "/admin", "/login", "/dashboard", "/.env", "/.git",
            )
            is_sensitive = any(kw in path_lower for kw in sensitive_paths)
            findings.append(Finding(
                title=f"Discovered: {path} [{status}]",
                severity="medium" if is_sensitive else "info",
                category="content_discovery",
                target=path,
                evidence=f"Status {status}, Size {size}",
                tool_used="ffuf_scan",
            ))

    # Next steps
    next_steps: List[str] = []
    if any("admin" in p.lower() or "login" in p.lower() for p in found_paths):
        next_steps.append("Test discovered admin/login pages for default credentials")
    if any(".env" in p.lower() or ".git" in p.lower() for p in found_paths):
        next_steps.append("Check exposed .env/.git files for secrets and configuration")
    if found_paths:
        next_steps.append("Run nikto_scan on interesting discovered paths")
    else:
        next_steps.append("Retry ffuf with a larger wordlist or different extensions")

    n_found = len(findings)
    summary = f"ffuf: {n_found} path(s) discovered on {target_url}"
    if n_found:
        top = ", ".join(found_paths[:5])
        summary += f"\nTop results: {top}"

    return ParsedResult(
        tool_name="ffuf_scan",
        raw_output=raw,
        summary=summary,
        findings=findings,
        next_steps=next_steps,
        severity=_overall_severity(findings) if findings else "info",
    )


def parse_nuclei_output(raw: str, args: Dict[str, Any]) -> ParsedResult:
    """Parse nuclei stdout into structured findings.

    Nuclei outputs lines like:
        [2024-01-15 10:30:45] [cve-2021-44228] [http] [critical] http://target/path
    or:
        [apache-detect] [http] [info] http://target
    """
    target = args.get("target", "unknown")
    findings: List[Finding] = []

    # Match nuclei finding lines — flexible for different output formats:
    # [template-id] [protocol] [severity] matched-url
    # Optional timestamp prefix: [2024-01-15 10:30:45]
    finding_re = re.compile(
        r"(?:\[\d{4}-[^\]]+\]\s*)?"
        r"\[([^\]]+)\]\s*"     # template-id
        r"\[([^\]]+)\]\s*"     # protocol
        r"\[([^\]]+)\]\s*"     # severity
        r"(\S+)"               # matched URL/host
    )

    severity_map = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "info",
    }

    for line in raw.splitlines():
        m = finding_re.search(line)
        if not m:
            continue
        template_id, protocol, sev_raw, matched_at = m.groups()
        sev = severity_map.get(sev_raw.strip().lower(), "info")

        # Determine category from template ID
        template_lower = template_id.lower()
        if template_lower.startswith("cve-"):
            category = "cve"
        elif "misconfig" in template_lower:
            category = "misconfiguration"
        elif "default" in template_lower or "login" in template_lower:
            category = "default_credentials"
        elif "exposure" in template_lower or "disclosure" in template_lower:
            category = "information_disclosure"
        elif "xss" in template_lower:
            category = "xss"
        elif "sqli" in template_lower or "injection" in template_lower:
            category = "injection"
        else:
            category = "vuln_scan"

        findings.append(Finding(
            title=f"{template_id} ({protocol})",
            severity=sev,
            category=category,
            target=matched_at,
            evidence=line.strip(),
            tool_used="nuclei_scan",
        ))

    # Count by severity
    sev_counts: Dict[str, int] = {}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    # Next steps based on findings
    next_steps: List[str] = []
    if sev_counts.get("critical") or sev_counts.get("high"):
        next_steps.append("Investigate critical/high findings for exploitability")
        cve_findings = [f for f in findings if f.category == "cve" and f.severity in ("critical", "high")]
        if cve_findings:
            cve_ids = [f.title.split()[0] for f in cve_findings[:3]]
            next_steps.append(f"Search for exploits: {', '.join(cve_ids)}")
    if sev_counts.get("medium"):
        next_steps.append("Review medium findings for business logic impact")
    if not findings:
        next_steps.append("Try nuclei with broader templates (e.g., -tags 'cve,misconfig,exposure')")
        next_steps.append("Run targeted scans: nikto_scan or sql_injection_test")

    # Summary
    n_total = len(findings)
    sev_parts = [f"{count} {sev}" for sev, count in sorted(sev_counts.items(), key=lambda x: ["critical", "high", "medium", "low", "info"].index(x[0]) if x[0] in ["critical", "high", "medium", "low", "info"] else 99)]
    summary = f"nuclei: {n_total} finding(s) on {target}"
    if sev_parts:
        summary += f" ({', '.join(sev_parts)})"

    return ParsedResult(
        tool_name="nuclei_scan",
        raw_output=raw,
        summary=summary,
        findings=findings,
        next_steps=next_steps,
        severity=_overall_severity(findings) if findings else "info",
    )


# ---------------------------------------------------------------------------
# ToolResultParser — dispatcher
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Exploitation tool parsers
# ---------------------------------------------------------------------------


def parse_http_request_output(raw: str, args: Dict[str, Any]) -> ParsedResult:
    """Parse http_request output (curl -i response)."""
    url = args.get("url", "unknown")
    method = args.get("method", "GET")
    clean = _clean_text(raw)

    # Extract HTTP status code
    status_code = ""
    status_match = re.search(r"HTTP/[\d.]+ (\d{3})", clean)
    if status_match:
        status_code = status_match.group(1)

    # Check for upload success indicators
    upload_file = args.get("upload_file", "")
    findings: List[Finding] = []

    if upload_file and status_code and int(status_code) < 400:
        success_markers = ("succes", "upload", "fichier téléversé", "moved", "ok")
        if any(marker in clean.casefold() for marker in success_markers) or status_code in ("200", "301", "302"):
            findings.append(Finding(
                title=f"File upload accepted at {url}",
                severity="high",
                category="web_vuln",
                target=url,
                evidence=f"HTTP {status_code} response to {method} with file {upload_file}",
                tool_used="http_request",
            ))

    summary = f"{method} {url} → HTTP {status_code}" if status_code else f"{method} {url}"
    if upload_file:
        summary += f" (uploaded: {upload_file})"

    return ParsedResult(
        tool_name="http_request",
        raw_output=raw,
        summary=summary,
        findings=findings,
        data={"status_code": status_code, "method": method, "url": url},
    )


def parse_write_file_output(raw: str, args: Dict[str, Any]) -> ParsedResult:
    """Parse write_file output."""
    path = args.get("path", "unknown")
    clean = _clean_text(raw)
    success = "✅" in clean or "file created" in clean.casefold()

    return ParsedResult(
        tool_name="write_file",
        raw_output=raw,
        summary=f"File {'created' if success else 'creation failed'}: {path}",
        data={"path": path, "success": success},
    )


def parse_fetch_url_output(raw: str, args: Dict[str, Any]) -> ParsedResult:
    """Parse fetch_url output."""
    url = args.get("url", "unknown")
    clean = _clean_text(raw)

    status_code = ""
    status_match = re.search(r"HTTP (\d{3})", clean)
    if status_match:
        status_code = status_match.group(1)

    summary = f"Fetched {url}"
    if status_code:
        summary += f" → HTTP {status_code}"

    return ParsedResult(
        tool_name="fetch_url",
        raw_output=raw,
        summary=summary,
        data={"url": url, "status_code": status_code},
    )


def parse_webshell_exec_output(raw: str, args: Dict[str, Any]) -> ParsedResult:
    """Parse webshell_exec output."""
    shell_url = args.get("shell_url", "unknown")
    command = args.get("command", "")
    clean = _clean_text(raw)

    findings: List[Finding] = []
    success = bool(clean) and "❌" not in clean and "⚠ Empty response" not in clean

    if success and command in ("id", "whoami"):
        findings.append(Finding(
            title=f"Remote code execution confirmed via webshell at {shell_url}",
            severity="critical",
            category="rce",
            target=shell_url,
            evidence=f"Command '{command}' returned: {clean[:200]}",
            tool_used="webshell_exec",
        ))

    summary = f"Webshell exec '{command}' at {shell_url}"
    if success:
        first_line = clean.split("\n")[0][:120] if clean else ""
        summary += f" → {first_line}"
    else:
        summary += " → no response"

    return ParsedResult(
        tool_name="webshell_exec",
        raw_output=raw,
        summary=summary,
        findings=findings,
        severity="critical" if findings else "info",
        data={"shell_url": shell_url, "command": command, "success": success},
    )


def parse_start_listener_output(raw: str, args: Dict[str, Any]) -> ParsedResult:
    """Parse start_listener output."""
    port = args.get("port", "?")
    clean = _clean_text(raw)
    got_connection = "connection" in clean.casefold() or "connect" in clean.casefold()

    findings: List[Finding] = []
    if got_connection:
        findings.append(Finding(
            title=f"Reverse shell connection received on port {port}",
            severity="critical",
            category="rce",
            target=f"listener:{port}",
            evidence=clean[:500],
            tool_used="start_listener",
        ))

    summary = f"Listener on port {port}"
    if got_connection:
        summary += " → connection received"
    elif "timed out" in clean.casefold() or "no connection" in clean.casefold():
        summary += " → no connection"
    else:
        summary += " → session ended"

    return ParsedResult(
        tool_name="start_listener",
        raw_output=raw,
        summary=summary,
        findings=findings,
        severity="critical" if findings else "info",
        data={"port": port, "connection_received": got_connection},
    )


# Parser registry: tool_name → parser function
_PARSERS: Dict[str, Callable[[str, Dict[str, Any]], ParsedResult]] = {
    "nmap_scan": parse_nmap_output,
    "dns_lookup": parse_dns_output,
    "whois_lookup": parse_whois_output,
    "http_headers": parse_http_headers_output,
    "dir_brute": parse_dir_brute_output,
    "sql_injection_test": parse_sqlmap_output,
    "nikto_scan": parse_nikto_output,
    "ssl_check": parse_ssl_output,
    "ssl_audit": parse_ssl_output,
    "run_shell": parse_run_shell_output,
    "xss_test": parse_generic_output,
    "searchsploit": parse_searchsploit_output,
    "cve_lookup": parse_cve_output,
    "ffuf_scan": parse_ffuf_output,
    "nuclei_scan": parse_nuclei_output,
    # Exploitation tools
    "http_request": parse_http_request_output,
    "write_file": parse_write_file_output,
    "fetch_url": parse_fetch_url_output,
    "webshell_exec": parse_webshell_exec_output,
    "start_listener": parse_start_listener_output,
}


class ToolResultParser:
    """Dispatches tool outputs to specialised parsers.

    Usage::

        parser = ToolResultParser()
        parsed = parser.parse("nmap_scan", raw_output, {"target": "10.10.10.5"})
    """

    def __init__(self, mission: MissionContext | None = None) -> None:
        self.mission = mission

    def parse(
        self,
        tool_name: str,
        raw_output: str,
        arguments: Dict[str, Any] | None = None,
    ) -> ParsedResult:
        """Parse a tool's raw output into a ParsedResult."""
        args = dict(arguments or {})
        args["_tool_name"] = tool_name

        parser_fn = _PARSERS.get(tool_name, parse_generic_output)
        result = parser_fn(raw_output, args)
        result.tool_name = tool_name
        missing_tool_findings = _missing_tool_findings(raw_output, args, tool_name)
        if missing_tool_findings:
            existing_keys = {finding.key for finding in result.findings}
            added_missing_tools: List[str] = []
            for finding in missing_tool_findings:
                if finding.key in existing_keys:
                    continue
                result.findings.append(finding)
                existing_keys.add(finding.key)
                metadata = finding.evidence_items[0].metadata if finding.evidence_items else {}
                added_missing_tools.append(str(metadata.get("missing_tool") or finding.target))
            if added_missing_tools:
                result.severity = _overall_severity(result.findings)
                result.data.setdefault("missing_tools", [])
                result.data["missing_tools"].extend(added_missing_tools)
                for missing_tool in added_missing_tools:
                    result.next_steps.insert(0, f"Install missing local tool: {missing_tool}")
                if result.summary:
                    result.summary += f"\nMissing local tool(s): {', '.join(added_missing_tools)}"
                else:
                    result.summary = f"Missing local tool(s): {', '.join(added_missing_tools)}"

        timeout_findings = _timeout_findings(raw_output, args, tool_name)
        if timeout_findings:
            existing_keys = {finding.key for finding in result.findings}
            for finding in timeout_findings:
                if finding.key in existing_keys:
                    continue
                result.findings.append(finding)
                existing_keys.add(finding.key)
            result.severity = _overall_severity(result.findings)
            result.data["timeout_detected"] = True
            if not any("timeout" in step.casefold() for step in result.next_steps):
                result.next_steps.insert(0, f"Retry {tool_name} with a bounded recovery profile")
            if result.summary:
                result.summary += "\nTool execution timed out before producing a complete result."
            else:
                result.summary = "Tool execution timed out before producing a complete result."

        # Integrate into mission if available
        if self.mission:
            for host in result.hosts_discovered:
                self.mission.add_host(host)
            for svc in result.services_discovered:
                self.mission.add_service(svc)
            for finding in result.findings:
                finding.phase = self.mission.phase.value
                self.mission.upsert_finding(finding)
            self.mission.refresh_phase_from_state()

        return result

    @staticmethod
    def has_parser(tool_name: str) -> bool:
        return tool_name in _PARSERS

    @staticmethod
    def supported_tools() -> List[str]:
        return list(_PARSERS.keys())
