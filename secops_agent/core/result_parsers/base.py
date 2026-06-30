"""Shared base for the result parsers: ParsedResult + cross-family helpers.

Split out of the former result_parser.py monolith (Phase 4.1). The public façade
secops_agent.core.result_parser re-exports everything needed by call sites.
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
