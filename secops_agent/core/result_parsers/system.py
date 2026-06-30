"""System/generic output parsers: run_shell, generic fallback.

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
