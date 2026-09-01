"""OBSERVE parsers for network/recon observation tools.

These six tools (`subdomain_enum`, `tech_detect`, `waf_detect`, `port_check`,
`ping_host`, `traceroute`) discover hosts/services/findings but previously fell to
``parse_generic_output`` — a text summary that never populated the blackboard, i.e.
an OBSERVE blind spot. Each parser here maps the tool's real output shape onto
``hosts_discovered`` / ``services_discovered`` / ``findings`` so discoveries reach
``MissionContext`` and enrich multi-turn reasoning (audit R3.3; CLAUDE.md §6).
"""
from __future__ import annotations

import re
from typing import Any, Dict, List
from urllib.parse import urlparse

from secops_agent.core.mission import Finding, Host, Service
from secops_agent.core.result_parsers.base import (
    ParsedResult,
    _clean_text,
    _evidence,
    _overall_severity,
)


def _host_port_from_url(url: str) -> tuple[str, int]:
    """Best-effort (host, port) from a URL, defaulting to the scheme's port.

    ``urlparse(...).port`` raises ValueError on a malformed/out-of-range port, and
    tool output is attacker-influenced, so both the parse and the port access are
    guarded (found by result-parser fuzzing).
    """
    fallback = str(url or "").strip() or "unknown"
    text = str(url or "").strip()
    if "://" not in text:
        text = f"http://{text}"
    try:
        parsed = urlparse(text)
        host = parsed.hostname or fallback
        port = parsed.port
        scheme = parsed.scheme
    except ValueError:
        return fallback, 80
    if port:
        return host, port
    return host, 443 if scheme == "https" else 80


def parse_subdomain_enum_output(raw: str, args: Dict[str, Any]) -> ParsedResult:
    """subdomain_enum: each discovered subdomain becomes a host on the blackboard."""
    domain = str(args.get("domain") or args.get("target") or "").strip() or "unknown"
    clean = _clean_text(raw)

    subs: List[str] = []
    for line in clean.splitlines():
        stripped = line.strip()
        if stripped.startswith("•"):
            candidate = stripped.lstrip("•").strip()
            if candidate and candidate not in subs:
                subs.append(candidate)

    hosts = [Host(ip=sub, hostname=sub) for sub in subs]
    if subs:
        preview = ", ".join(subs[:8]) + (f" +{len(subs) - 8} more" if len(subs) > 8 else "")
        summary = f"{len(subs)} subdomain(s) for {domain}\n{preview}"
        next_steps = ["Run nmap_scan / http_headers against in-scope subdomains"]
    else:
        summary = f"No subdomains discovered for {domain}"
        next_steps = []

    return ParsedResult(
        tool_name="subdomain_enum",
        raw_output=raw,
        summary=summary,
        hosts_discovered=hosts,
        next_steps=next_steps,
        data={"subdomains": subs},
    )


def parse_tech_detect_output(raw: str, args: Dict[str, Any]) -> ParsedResult:
    """tech_detect: the web server + detected tech become a service on the blackboard."""
    url = str(args.get("url") or args.get("target") or "").strip() or "unknown"
    clean = _clean_text(raw)

    server = ""
    technologies: List[str] = []
    for line in clean.splitlines():
        stripped = line.strip()
        server_match = re.search(r"Server:\s*(.+)$", stripped)
        if server_match:
            server = server_match.group(1).strip()
            continue
        tagged = re.search(r"(?:CMS|Framework|Powered By):\s*(.+)$", stripped)
        if tagged:
            tech = tagged.group(1).strip()
            if tech and tech not in technologies:
                technologies.append(tech)
            continue
        detected = re.search(r"([\w.\-]+(?: [\w.\-]+)?)\s+detected", stripped)
        if detected:
            tech = detected.group(1).strip()
            if tech and tech not in technologies:
                technologies.append(tech)

    host, port = _host_port_from_url(url)
    services: List[Service] = []
    if server or technologies:
        svc = Service(
            host=host,
            port=port,
            protocol="tcp",
            service="http",
            version=server,
            banner=", ".join(technologies),
        )
        services.append(svc)
        hosts = [Host(ip=host, services=[svc])]
    else:
        hosts = []

    detail = ", ".join(filter(None, [server, *technologies]))
    summary = f"Technologies on {url}: {detail}" if detail else f"No technologies detected for {url}"
    next_steps = []
    if server or technologies:
        next_steps.append("Run searchsploit / cve_lookup against the detected stack")

    return ParsedResult(
        tool_name="tech_detect",
        raw_output=raw,
        summary=summary,
        hosts_discovered=hosts,
        services_discovered=services,
        next_steps=next_steps,
        data={"server": server, "technologies": technologies},
    )


def parse_waf_detect_output(raw: str, args: Dict[str, Any]) -> ParsedResult:
    """waf_detect: a detected WAF/CDN is a finding on the blackboard."""
    url = str(args.get("url") or args.get("target") or "").strip() or "unknown"
    clean = _clean_text(raw)

    detected: List[str] = []
    in_detected = False
    for line in clean.splitlines():
        stripped = line.strip()
        if "WAF/CDN Detected" in stripped:
            in_detected = True
            continue
        if in_detected:
            if stripped.startswith("•"):
                waf = stripped.lstrip("•").strip()
                if waf and waf not in detected:
                    detected.append(waf)
            elif "response headers" in stripped.lower():
                in_detected = False

    findings: List[Finding] = []
    if detected:
        title = f"WAF/CDN present on {url}"
        evidence = "Detected: " + ", ".join(detected)
        findings.append(
            Finding(
                title=title,
                severity="info",
                category="waf",
                target=url,
                evidence=evidence,
                tool_used="waf_detect",
                evidence_items=[
                    _evidence(
                        title,
                        evidence,
                        source_tool="waf_detect",
                        target=url,
                        metadata={"waf": detected},
                    )
                ],
            )
        )
        summary = f"WAF/CDN on {url}: {', '.join(detected)}"
        next_steps = ["Account for the WAF when crafting payloads; stay within authorized scope"]
    else:
        summary = f"No WAF explicitly detected on {url} (custom rules may still apply)"
        next_steps = []

    return ParsedResult(
        tool_name="waf_detect",
        raw_output=raw,
        summary=summary,
        findings=findings,
        severity=_overall_severity(findings),
        next_steps=next_steps,
        data={"waf": detected},
    )


def parse_port_check_output(raw: str, args: Dict[str, Any]) -> ParsedResult:
    """port_check: an open port becomes a service on the blackboard."""
    target = str(args.get("target") or "").strip() or "unknown"
    clean = _clean_text(raw)

    port = args.get("port")
    protocol = str(args.get("protocol") or "tcp").strip() or "tcp"
    state = ""
    match = re.search(r"Port\s+(\d+)/(\w+)\s+is\s+(OPEN|CLOSED/FILTERED|CLOSED|FILTERED)", clean, re.I)
    if match:
        port = int(match.group(1))
        protocol = match.group(2).lower()
        state = match.group(3).upper()
    is_open = state.startswith("OPEN") if state else ("is OPEN" in clean)

    services: List[Service] = []
    hosts: List[Host] = []
    if is_open and port is not None:
        svc = Service(host=target, port=int(port), protocol=protocol, service="", state="open")
        services.append(svc)
        hosts.append(Host(ip=target, services=[svc]))
        summary = f"Port {port}/{protocol} is open on {target}"
        next_steps = ["Run nmap_scan -sV on the open port to fingerprint the service"]
    else:
        summary = f"Port {port}/{protocol} is closed or filtered on {target}"
        next_steps = []

    return ParsedResult(
        tool_name="port_check",
        raw_output=raw,
        summary=summary,
        hosts_discovered=hosts,
        services_discovered=services,
        next_steps=next_steps,
        data={"port": port, "protocol": protocol, "open": bool(is_open)},
    )


def parse_ping_output(raw: str, args: Dict[str, Any]) -> ParsedResult:
    """ping_host: a live host becomes a host on the blackboard."""
    target = str(args.get("target") or "").strip() or "unknown"
    clean = _clean_text(raw)

    data: Dict[str, Any] = {}
    received = 0
    stats = re.search(r"(\d+)\s+packets transmitted,\s+(\d+)\s+(?:packets\s+)?received", clean)
    if stats:
        data["packets_transmitted"] = int(stats.group(1))
        received = int(stats.group(2))
        data["packets_received"] = received
    rtt = re.search(r"(?:rtt|round-trip)[^=]*=\s*[\d.]+/([\d.]+)/", clean)
    if rtt:
        data["rtt_avg_ms"] = float(rtt.group(1))

    down = "appears to be down" in clean.lower() or "100% packet loss" in clean.lower()
    alive = received > 0 and not down
    data["alive"] = alive

    hosts: List[Host] = []
    if alive:
        resolved = re.search(r"PING\s+\S+\s+\(([\d.]+)\)", clean)
        ip = resolved.group(1) if resolved else target
        hostname = target if resolved and target != ip else ""
        hosts.append(Host(ip=ip, hostname=hostname))
        rtt_note = f" (avg {data['rtt_avg_ms']} ms)" if "rtt_avg_ms" in data else ""
        summary = f"{target} is alive{rtt_note}"
        next_steps = ["Run nmap_scan against the live host"]
    else:
        summary = f"{target} did not respond to ping (may be filtered)"
        next_steps = ["Retry nmap_scan with -Pn to skip host discovery"]

    return ParsedResult(
        tool_name="ping_host",
        raw_output=raw,
        summary=summary,
        hosts_discovered=hosts,
        next_steps=next_steps,
        data=data,
    )


def parse_traceroute_output(raw: str, args: Dict[str, Any]) -> ParsedResult:
    """traceroute: a reached destination becomes a host on the blackboard."""
    target = str(args.get("target") or "").strip() or "unknown"
    clean = _clean_text(raw)

    hops: List[str] = []
    for line in clean.splitlines():
        hop = re.match(r"\s*(\d+)\s+(.+)$", line)
        if hop:
            hops.append(hop.group(2).strip())

    # The destination is reached when the final hop resolved (not all "* * *").
    reached = bool(hops) and set(hops[-1].split()) != {"*"}
    hosts: List[Host] = []
    if reached:
        hosts.append(Host(ip=target))
        summary = f"Route to {target} traced in {len(hops)} hop(s)"
        next_steps = ["Run nmap_scan against the reachable host"]
    else:
        summary = f"Route to {target} did not complete ({len(hops)} hop(s), destination unreachable)"
        next_steps = []

    return ParsedResult(
        tool_name="traceroute",
        raw_output=raw,
        summary=summary,
        hosts_discovered=hosts,
        next_steps=next_steps,
        data={"hop_count": len(hops), "reached": reached},
    )
