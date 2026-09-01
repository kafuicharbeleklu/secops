"""Structured parsers for local evidence, crypto helpers, and lab operations.

These tools are not network scanners, but their outputs still drive planning and
must not collapse into an opaque transcript.  Parsers deliberately avoid copying
secrets (passwords, payload bodies, or full logs) into mission state.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from secops_agent.core.mission import Finding
from secops_agent.core.result_parsers.base import ParsedResult, _clean_text, _evidence


def _result(tool: str, raw: str, summary: str, *, data: Dict[str, Any] | None = None,
            findings: List[Finding] | None = None, next_steps: List[str] | None = None) -> ParsedResult:
    findings = findings or []
    return ParsedResult(
        tool_name=tool,
        raw_output=raw,
        summary=summary,
        data=data or {},
        findings=findings,
        next_steps=next_steps or [],
        severity=max((finding.severity for finding in findings), default="info", key=_severity_rank),
    )


def _severity_rank(value: str) -> int:
    return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(value, 0)


def parse_exploit_info_output(raw: str, args: Dict[str, Any]) -> ParsedResult:
    clean = _clean_text(raw)
    edb_id = str(args.get("edb_id") or "")
    match = re.search(r"EDB-ID:\s*([^\s)]+)", clean, re.I)
    edb_id = match.group(1) if match else edb_id
    path_match = re.search(r"^\s*Path:\s*(.+)$", clean, re.M | re.I)
    path = path_match.group(1).strip() if path_match else ""
    findings: List[Finding] = []
    if edb_id and (path or "Exploit Details" in clean):
        title = f"Exploit reference available: EDB-{edb_id}"
        evidence = f"ExploitDB entry {edb_id}" + (f"; path: {path}" if path else "")
        findings.append(Finding(
            title=title, severity="info", category="exploit_reference", target=edb_id,
            evidence=evidence, tool_used="exploit_info",
            evidence_items=[_evidence(title, evidence, source_tool="exploit_info", target=edb_id,
                                      metadata={"edb_id": edb_id, "path": path})],
        ))
    return _result(
        "exploit_info", raw,
        f"ExploitDB {edb_id}: {'reference details available' if findings else 'no reference found'}",
        data={"edb_id": edb_id, "path": path}, findings=findings,
        next_steps=["Validate applicability against confirmed in-scope version evidence"] if findings else [],
    )


def parse_generate_payload_output(raw: str, args: Dict[str, Any]) -> ParsedResult:
    clean = _clean_text(raw)
    payload_type = str(args.get("payload_type") or "unknown")
    labels = re.findall(r"^\s*\[([^\]]+)]\s*$", clean, re.M)
    return _result(
        "generate_payload", raw,
        f"Generated {len(labels)} {payload_type} payload template(s); none executed",
        data={"payload_type": payload_type, "target_os": str(args.get("target_os") or ""),
              "template_labels": labels},
        next_steps=["Use a payload only after explicit authorization and target-specific review"] if labels else [],
    )


def parse_hash_identify_output(raw: str, args: Dict[str, Any]) -> ParsedResult:
    clean = _clean_text(raw)
    length_match = re.search(r"Length:\s*(\d+)\s+chars", clean, re.I)
    possible = re.findall(r"^\s*[•*-]\s*(.+?)\s*$", clean, re.M)
    types = [item for item in possible if item and "possible types" not in item.casefold()]
    length = int(length_match.group(1)) if length_match else None
    summary = f"Hash identification: {', '.join(types[:3])}" if types else "Hash type could not be identified"
    return _result("hash_identify", raw, summary, data={"length": length, "possible_types": types})


def parse_hash_generate_output(raw: str, args: Dict[str, Any]) -> ParsedResult:
    clean = _clean_text(raw)
    algorithms = re.findall(r"^\s*([A-Z0-9-]+):\s*[0-9a-f]{16,}\s*$", clean, re.M | re.I)
    return _result(
        "hash_generate", raw,
        f"Generated {len(algorithms)} hash value(s): {', '.join(item.upper() for item in algorithms)}",
        data={"algorithms": [item.lower() for item in algorithms]},
    )


def parse_password_strength_output(raw: str, args: Dict[str, Any]) -> ParsedResult:
    clean = _clean_text(raw)
    rating_match = re.search(r"Rating:\s*(.+)$", clean, re.M | re.I)
    score_match = re.search(r"Score:\s*(-?\d+)\s*/\s*(\d+)", clean, re.I)
    entropy_match = re.search(r"Entropy:\s*~?([0-9.]+)\s*bits", clean, re.I)
    rating = rating_match.group(1).strip() if rating_match else "unknown"
    score = int(score_match.group(1)) if score_match else None
    entropy = float(entropy_match.group(1)) if entropy_match else None
    findings: List[Finding] = []
    if score is not None and score < 5:
        title = "Weak password supplied for local strength analysis"
        evidence = f"Password-strength score: {score}/8; rating: {rating}"
        findings.append(Finding(
            title=title, severity="medium" if score < 3 else "low", category="weak_secret",
            target="operator-supplied secret", evidence=evidence, tool_used="password_strength",
            evidence_items=[_evidence(title, evidence, source_tool="password_strength",
                                      target="operator-supplied secret", metadata={"score": score, "rating": rating})],
        ))
    return _result(
        "password_strength", raw, f"Password strength: {rating}",
        data={"rating": rating, "score": score, "entropy_bits": entropy}, findings=findings,
        next_steps=["Use a unique password-manager generated secret"] if findings else [],
    )


def parse_file_analyze_output(raw: str, args: Dict[str, Any]) -> ParsedResult:
    clean = _clean_text(raw)
    path = str(args.get("filepath") or args.get("path") or "unknown")
    fields = {key.casefold(): value.strip() for key, value in re.findall(r"^\s*([A-Za-z0-9 -]+):\s*(.+)$", clean, re.M)}
    permissions = fields.get("permissions", "")
    findings: List[Finding] = []
    if permissions and permissions[-1:] in {"2", "3", "6", "7"}:
        title = f"World-writable file: {path}"
        evidence = f"file_analyze reported permissions {permissions}"
        findings.append(Finding(
            title=title, severity="medium", category="world_writable_file", target=path,
            evidence=evidence, tool_used="file_analyze",
            evidence_items=[_evidence(title, evidence, source_tool="file_analyze", target=path,
                                      metadata={"permissions": permissions})],
        ))
    return _result(
        "file_analyze", raw, f"File analysis: {path} ({fields.get('type', 'type unavailable')})",
        data={"path": path, "type": fields.get("type", ""), "size": fields.get("size", ""),
              "permissions": permissions, "sha256": fields.get("sha256", "")},
        findings=findings, next_steps=["Review file ownership and write permissions"] if findings else [],
    )


def parse_sysinfo_output(raw: str, args: Dict[str, Any]) -> ParsedResult:
    clean = _clean_text(raw)
    pairs = re.findall(r"^\s*([A-Za-z][A-Za-z /()-]+):\s*(.+)$", clean, re.M)
    fields = {key.casefold(): value.strip() for key, value in pairs}
    hostname = fields.get("hostname", "")
    # Lead with a concise, meaningful fact rather than falsely claiming no facts
    # were found: prefer stable keys (hostname, gateway, OS...) over a noisy dump.
    _preferred = ("hostname", "default gateway", "os", "kernel", "dns")
    _lead = next(((k, fields[k]) for k in _preferred if fields.get(k)), None)
    if _lead:
        _label = {"os": "OS", "dns": "DNS"}.get(_lead[0], _lead[0].title())
        summary = f"{_label}: {_lead[1]}"
    elif pairs:
        key, value = pairs[0]
        summary = f"{key.strip()}: {value.strip()}"
    else:
        content = [line.strip() for line in clean.splitlines() if line.strip()]
        summary = f"System info: {len(content)} line(s)" if content else "sysinfo: no output"
    return _result(
        "sysinfo", raw, summary,
        data={"hostname": hostname, "os": fields.get("os", ""), "kernel": fields.get("kernel", ""),
              "default_gateway": fields.get("default gateway", "")},
    )


def parse_lab_setup_check_output(raw: str, args: Dict[str, Any]) -> ParsedResult:
    clean = _clean_text(raw)
    missing = re.findall(r"^\s*([\w.-]+):\s*not installed\s*$", clean, re.M | re.I)
    # dir_brute has a supported dirb fallback; do not make a missing gobuster
    # look like a blocking prerequisite when the readiness output shows dirb.
    if "dirb:" in clean.casefold():
        missing = [tool for tool in missing if tool.casefold() != "gobuster"]
    configs = re.findall(r"^\s*-\s*(.+\.(?:ovpn|conf))\s*$", clean, re.M | re.I)
    target = str(args.get("target") or "")
    summary = f"Lab setup: {len(missing)} missing tool(s), {len(configs)} VPN config(s)"
    return _result(
        "lab_setup_check", raw, summary,
        data={"provider": str(args.get("provider") or "lab"), "missing_tools": missing,
              "vpn_configs": configs, "target": target},
        next_steps=["Install missing local prerequisites before an authorized assessment"] if missing else [],
    )


def _vpn_result(tool: str, raw: str, args: Dict[str, Any]) -> ParsedResult:
    clean = _clean_text(raw)
    match = re.search(r"\bVPN\s+(connected|disconnected|started|failed|exited)\b", clean, re.I)
    status = match.group(1).lower() if match else ("running" if "OpenVPN process" in clean else "unknown")
    ip_match = re.search(r"VPN IP:\s*(.+)$", clean, re.M | re.I)
    config_match = re.search(r"VPN\s+\w+:\s*(.+)$", clean, re.M | re.I)
    lines = [line.strip() for line in clean.splitlines() if line.strip()]
    if not lines:
        summary = f"{tool}: (no output)"
    elif len(lines) <= 4 and len(clean) <= 400:
        summary = clean
    else:
        summary = lines[0]
    return _result(
        tool, raw, summary,
        data={"status": status, "vpn_ip": ip_match.group(1).strip() if ip_match else "",
              "config": config_match.group(1).strip() if config_match else ""},
        next_steps=["Review VPN logs before retrying"] if status in {"failed", "exited", "unknown"} else [],
    )


def parse_vpn_status_output(raw: str, args: Dict[str, Any]) -> ParsedResult:
    return _vpn_result("vpn_status", raw, args)


def parse_connect_vpn_config_output(raw: str, args: Dict[str, Any]) -> ParsedResult:
    return _vpn_result("connect_vpn_config", raw, args)


def parse_disconnect_vpn_output(raw: str, args: Dict[str, Any]) -> ParsedResult:
    return _vpn_result("disconnect_vpn", raw, args)


def parse_log_analyze_output(raw: str, args: Dict[str, Any]) -> ParsedResult:
    clean = _clean_text(raw)
    logfile = str(args.get("logfile") or "local log")
    counts = {
        name.casefold().replace(" ", "_"): int(value)
        for name, value in re.findall(r"^\s*(?:⚠️\s*)?([A-Za-z ]+):\s*(\d+)\s*$", clean, re.M)
    }
    failed_logins = counts.get("failed_login", 0)
    findings: List[Finding] = []
    if failed_logins:
        title = f"Failed authentication attempts in {logfile}"
        evidence = f"log_analyze counted {failed_logins} failed login event(s)"
        findings.append(Finding(
            title=title, severity="medium" if failed_logins > 5 else "low",
            category="failed_authentication", target=logfile, evidence=evidence, tool_used="log_analyze",
            evidence_items=[_evidence(title, evidence, source_tool="log_analyze", target=logfile,
                                      metadata={"failed_logins": failed_logins})],
        ))
    return _result(
        "log_analyze", raw, f"Log analysis: {sum(counts.values())} security-relevant event(s)",
        data={"logfile": logfile, "pattern_counts": counts}, findings=findings,
        next_steps=["Correlate failed authentication sources and timestamps"] if failed_logins else [],
    )


def parse_find_files_output(raw: str, args: Dict[str, Any]) -> ParsedResult:
    clean = _clean_text(raw)
    search_type = str(args.get("search_type") or "unknown")
    paths = re.findall(r"^\s*(?:📄\s*)?(/\S+)\s*$", clean, re.M)
    return _result(
        "find_files", raw, f"File search ({search_type}): {len(paths)} candidate(s)",
        data={"search_type": search_type, "path": str(args.get("path") or "/"), "matches": paths},
        next_steps=["Review each candidate within the authorized scope"] if paths else [],
    )
