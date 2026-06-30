"""Web-enumeration output parsers: dir_brute, nikto, http_headers, ffuf, nuclei, http_request, fetch_url.

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
