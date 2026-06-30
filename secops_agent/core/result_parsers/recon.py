"""Recon/network output parsers: nmap, dns, whois, ssl.

Part of the Phase 4.1 result_parser split; shared helpers come from .base.
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
from secops_agent.core.result_parsers.base import (
    ParsedResult,
    _ANSI_RE,
    _clean_text,
    _first_matching_line,
    _evidence,
    _MISSING_TOOL_INSTALL_HINTS,
    _LAB_SETUP_INSTALLABLE_TOOLS,
    _contains_timeout,
    _primary_target_from_args,
    _missing_tool_findings,
    _timeout_findings,
    _KNOWN_VULNS,
    _check_known_vulns,
    _overall_severity,
    _severity_from_cvss,
)


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
    # Anchor the local part to a left boundary ((?<![\w.+-])) so re.findall does
    # not retry a full match at every interior position of a long run — that
    # retry is what makes the unanchored pattern O(n^2) (ReDoS) on hostile input.
    emails = sorted(set(re.findall(r"(?<![\w.+-])[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", clean)))

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
