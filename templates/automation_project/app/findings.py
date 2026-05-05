"""Findings accumulator — structured extraction and storage of pentest discoveries."""

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path


class FindingType(Enum):
    PORT = "port"
    SERVICE = "service"
    VULNERABILITY = "vulnerability"
    CREDENTIAL = "credential"
    PATH = "path"
    HOSTNAME = "hostname"
    OS = "os"
    USER = "user"
    FILE = "file"
    CVE = "cve"


@dataclass
class Finding:
    finding_type: FindingType
    value: str
    source_tool: str
    confidence: str = "medium"
    raw_output: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    severity: str = ""
    target_ref: str = ""
    attributes: dict[str, str] = field(default_factory=dict)

    @property
    def normalized_severity(self) -> str:
        """Return the effective severity, falling back to legacy confidence."""
        return (self.severity or self.confidence or "unknown").strip().lower() or "unknown"

    @property
    def effective_confidence(self) -> str:
        """Return a display-safe confidence value."""
        return (self.confidence or "unknown").strip().lower() or "unknown"


# ---------------------------------------------------------------------------
# Output parsers
# ---------------------------------------------------------------------------

_NMAP_PORT_RE = re.compile(r"^(\d+)/(\w+)\s+open\s+(.*)$", re.MULTILINE)
_NMAP_OS_RE = re.compile(r"OS details?:\s*(.+)", re.IGNORECASE)
_NMAP_SERVICE_RE = re.compile(r"^(\d+)/\w+\s+open\s+(\S+)", re.MULTILINE)

_GOBUSTER_PATH_RE = re.compile(r"^(/\S+)\s+\(Status:\s*(\d+)\)", re.MULTILINE)
_GOBUSTER_ALT_RE = re.compile(r"^(/\S+)\s+\[Status:\s*(\d+)", re.MULTILINE)

_NIKTO_VULN_RE = re.compile(r"^\+\s+(.+)$", re.MULTILINE)

_HYDRA_CRED_RE = re.compile(
    r"\[(\d+)\]\[(\w+)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(\S+)",
    re.IGNORECASE,
)

_NMAP_TARGET_RE = re.compile(r"^Nmap scan report for (.+)$", re.MULTILINE)
_CREDENTIAL_VALUE_RE = re.compile(
    r"(?:(?P<service>[a-z0-9+._-]+)://)?"
    r"(?P<username>[^:\s]+):(?P<password>.+?)"
    r"(?:\s+\(port\s+(?P<port>\d+)\))?$",
    re.IGNORECASE,
)


def _extract_nmap_target(stdout: str) -> str:
    match = _NMAP_TARGET_RE.search(stdout)
    if not match:
        return ""
    raw = match.group(1).strip()
    if "(" in raw and ")" in raw:
        inside = raw.rsplit("(", 1)[-1].rstrip(")")
        return inside.strip()
    return raw.split()[0]


def parse_credential_value(value: str) -> dict[str, str]:
    """Parse a credential string into structured fields when possible."""
    text = (value or "").strip()
    if not text:
        return {}
    match = _CREDENTIAL_VALUE_RE.match(text)
    if not match:
        return {}
    details = {
        key: val.strip()
        for key, val in match.groupdict(default="").items()
        if val and val.strip()
    }
    if "service" in details:
        details["service"] = details["service"].lower()
    return details


def parse_nmap_output(stdout: str) -> list[Finding]:
    """Extract ports, services, and OS hints from nmap output."""
    findings = []
    target_ref = _extract_nmap_target(stdout)
    for match in _NMAP_PORT_RE.finditer(stdout):
        port = match.group(1)
        service = match.group(3).strip()
        findings.append(Finding(
            FindingType.PORT,
            port,
            "nmap",
            "high",
            match.group(0),
            severity="info",
            target_ref=target_ref,
        ))
        if service:
            findings.append(Finding(
                FindingType.SERVICE,
                f"{port}/{service}",
                "nmap",
                "high",
                "",
                severity="info",
                target_ref=target_ref,
            ))

    os_match = _NMAP_OS_RE.search(stdout)
    if os_match:
        findings.append(Finding(
            FindingType.OS,
            os_match.group(1).strip(),
            "nmap",
            "medium",
            "",
            severity="low",
            target_ref=target_ref,
        ))

    return findings


def parse_gobuster_output(stdout: str) -> list[Finding]:
    """Extract discovered paths from gobuster output."""
    findings = []
    for pattern in (_GOBUSTER_PATH_RE, _GOBUSTER_ALT_RE):
        for match in pattern.finditer(stdout):
            path = match.group(1)
            status = match.group(2)
            findings.append(Finding(FindingType.PATH, f"{path} ({status})", "gobuster", "high", match.group(0)))
    return findings


def parse_nikto_output(stdout: str) -> list[Finding]:
    """Extract vulnerability findings from nikto output."""
    findings = []
    skip_prefixes = ("target ip:", "target hostname:", "target port:", "start time:", "end time:", "server:", "-")
    for match in _NIKTO_VULN_RE.finditer(stdout):
        line = match.group(1).strip()
        if any(line.lower().startswith(p) for p in skip_prefixes):
            continue
        if len(line) > 10:
            findings.append(Finding(FindingType.VULNERABILITY, line, "nikto", "medium", match.group(0)))
    return findings


def parse_hydra_output(stdout: str) -> list[Finding]:
    """Extract credentials from hydra output."""
    findings = []
    for match in _HYDRA_CRED_RE.finditer(stdout):
        port, protocol, host, login, password = match.groups()
        value = f"{protocol}://{login}:{password} (port {port})"
        findings.append(
            Finding(
                finding_type=FindingType.CREDENTIAL,
                value=value,
                source_tool="hydra",
                confidence="high",
                raw_output=match.group(0),
                severity="critical",
                target_ref=host,
                attributes={
                    "service": protocol.lower(),
                    "username": login,
                    "password": password,
                    "port": port,
                },
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Additional parsers
# ---------------------------------------------------------------------------

_FFUF_PATH_RE = re.compile(
    r"^(\S+)\s+\[Status:\s*(\d+)", re.MULTILINE
)


def parse_ffuf_output(stdout: str) -> list[Finding]:
    """Extract discovered paths from ffuf output."""
    findings = []
    for match in _FFUF_PATH_RE.finditer(stdout):
        path = match.group(1)
        status = match.group(2)
        findings.append(Finding(FindingType.PATH, f"{path} ({status})", "ffuf", "high", match.group(0)))
    return findings


_SQLMAP_VULN_RE = re.compile(
    r"(?:Parameter|is vulnerable|injection|Type:)\s*(.+)", re.IGNORECASE
)


def parse_sqlmap_output(stdout: str) -> list[Finding]:
    """Extract SQL injection findings from sqlmap output."""
    findings = []
    for match in _SQLMAP_VULN_RE.finditer(stdout):
        line = match.group(0).strip()
        if len(line) > 10:
            findings.append(Finding(FindingType.VULNERABILITY, line, "sqlmap", "high", match.group(0)))
    return findings


_ENUM4LINUX_USER_RE = re.compile(r"user:\[([^\]]+)\]", re.IGNORECASE)
_ENUM4LINUX_SHARE_RE = re.compile(r"\\\\[^\s]+\\(\S+)", re.IGNORECASE)


def parse_enum4linux_output(stdout: str) -> list[Finding]:
    """Extract users and shares from enum4linux output."""
    findings = []
    for match in _ENUM4LINUX_USER_RE.finditer(stdout):
        findings.append(Finding(FindingType.USER, match.group(1), "enum4linux", "high", match.group(0)))
    for match in _ENUM4LINUX_SHARE_RE.finditer(stdout):
        findings.append(Finding(FindingType.PATH, match.group(1), "enum4linux", "medium", match.group(0)))
    return findings


_WPSCAN_VULN_RE = re.compile(r"^\s*\[!\]\s+(.+)$", re.MULTILINE)


def parse_wpscan_output(stdout: str) -> list[Finding]:
    """Extract vulnerability findings from wpscan output."""
    findings = []
    skip_prefixes = ("title:", "url:", "reference", "no wpscan")
    for match in _WPSCAN_VULN_RE.finditer(stdout):
        line = match.group(1).strip()
        if any(line.lower().startswith(p) for p in skip_prefixes):
            continue
        if len(line) > 10:
            findings.append(Finding(FindingType.VULNERABILITY, line, "wpscan", "medium", match.group(0)))
    return findings


_WHATWEB_TECH_RE = re.compile(
    r"(\S+)\s+\[([^\]]+)\]",
)


def parse_whatweb_output(stdout: str) -> list[Finding]:
    """Extract technology detections from whatweb output."""
    findings = []
    for match in _WHATWEB_TECH_RE.finditer(stdout):
        tech = match.group(2).strip()
        if tech and len(tech) > 2:
            findings.append(Finding(FindingType.SERVICE, tech, "whatweb", "medium", match.group(0)))
    return findings


_SMBCLIENT_SHARE_RE = re.compile(
    r"^\s+(\S+)\s+(?:Disk|IPC|Printer)", re.MULTILINE
)


def parse_smbclient_output(stdout: str) -> list[Finding]:
    """Extract share names from smbclient output."""
    findings = []
    for match in _SMBCLIENT_SHARE_RE.finditer(stdout):
        share = match.group(1).strip()
        if share and share not in ("Sharename", "---"):
            findings.append(Finding(FindingType.PATH, f"smb://{share}", "smbclient", "high", match.group(0)))
    return findings


_SEARCHSPLOIT_RE = re.compile(
    r"^(.+?)\s+\|\s+(exploits/\S+|shellcodes/\S+)",
    re.MULTILINE,
)


def parse_searchsploit_output(stdout: str) -> list[Finding]:
    """Extract exploit references from searchsploit output."""
    findings = []
    for match in _SEARCHSPLOIT_RE.finditer(stdout):
        title = match.group(1).strip()
        path = match.group(2).strip()
        if title and not title.startswith("---"):
            findings.append(
                Finding(
                    FindingType.VULNERABILITY,
                    f"{title} [{path}]",
                    "searchsploit",
                    "medium",
                    match.group(0),
                )
            )
    return findings


# Map tool names to their parsers
_TOOL_PARSERS = {
    "nmap": parse_nmap_output,
    "gobuster": parse_gobuster_output,
    "nikto": parse_nikto_output,
    "hydra": parse_hydra_output,
    "ffuf": parse_ffuf_output,
    "sqlmap": parse_sqlmap_output,
    "enum4linux": parse_enum4linux_output,
    "wpscan": parse_wpscan_output,
    "whatweb": parse_whatweb_output,
    "smbclient": parse_smbclient_output,
    "searchsploit": parse_searchsploit_output,
}


def parse_tool_output(tool_name: str, stdout: str) -> list[Finding]:
    """Route to the appropriate parser for a given tool."""
    parser = _TOOL_PARSERS.get(tool_name)
    if parser:
        return parser(stdout)
    return []


class FindingsStore:
    """Accumulates findings during a pentest session."""

    def __init__(self):
        self._findings: list[Finding] = []
        self._seen: set[tuple[str, str, str]] = set()

    def _dedup_key(self, finding: Finding) -> tuple[str, str, str]:
        ftype = finding.finding_type.value if hasattr(finding.finding_type, "value") else str(finding.finding_type)
        return (ftype, finding.value, finding.source_tool)

    def add(self, finding: Finding) -> None:
        key = self._dedup_key(finding)
        if key not in self._seen:
            self._seen.add(key)
            self._findings.append(finding)

    def add_many(self, findings: list[Finding]) -> None:
        for finding in findings:
            self.add(finding)

    def ingest_tool_output(self, tool_name: str, stdout: str) -> list[Finding]:
        """Parse tool output and store the findings. Returns new findings."""
        new_findings = parse_tool_output(tool_name, stdout)
        before = len(self._findings)
        self.add_many(new_findings)
        # Return only the actually-added findings (after dedup)
        return self._findings[before:]

    @property
    def all(self) -> list[Finding]:
        return list(self._findings)

    @property
    def count(self) -> int:
        return len(self._findings)

    def by_type(self, finding_type: FindingType) -> list[Finding]:
        return [f for f in self._findings if f.finding_type == finding_type]

    @property
    def ports(self) -> list[Finding]:
        return self.by_type(FindingType.PORT)

    @property
    def services(self) -> list[Finding]:
        return self.by_type(FindingType.SERVICE)

    @property
    def vulnerabilities(self) -> list[Finding]:
        return self.by_type(FindingType.VULNERABILITY)

    @property
    def credentials(self) -> list[Finding]:
        return self.by_type(FindingType.CREDENTIAL)

    def summary(self, limit: int = 20) -> str:
        """Produce a prompt-friendly summary of accumulated findings."""
        if not self._findings:
            return "Aucune decouverte enregistree."
        by_type: dict[str, list[str]] = {}
        for f in self._findings:
            key = f.finding_type.value
            by_type.setdefault(key, []).append(f.value)
        lines = []
        for ftype, values in by_type.items():
            unique = list(dict.fromkeys(values))[:limit]
            lines.append(f"{ftype} ({len(values)}): {', '.join(unique)}")
        return "\n".join(lines)

    def structured_summary(self) -> str:
        """Compact structured summary for LLM prompt injection."""
        if not self._findings:
            return ""
        parts = []
        ports = self.ports
        if ports:
            parts.append(f"Ports ouverts: {', '.join(f.value for f in ports[:15])}")
        services = self.services
        if services:
            parts.append(f"Services: {', '.join(f.value for f in services[:10])}")
        vulns = self.vulnerabilities
        if vulns:
            parts.append(f"Vulnerabilites: {', '.join(f.value[:50] for f in vulns[:5])}")
        cves = self.by_type(FindingType.CVE)
        if cves:
            parts.append(f"CVEs: {', '.join(f.value[:60] for f in cves[:5])}")
        creds = self.credentials
        if creds:
            parts.append(f"Credentials: {', '.join(f.value for f in creds[:5])}")
        paths = self.by_type(FindingType.PATH)
        if paths:
            parts.append(f"Chemins decouverts: {', '.join(f.value for f in paths[:10])}")
        os_findings = self.by_type(FindingType.OS)
        if os_findings:
            parts.append(f"OS: {os_findings[0].value}")
        return " | ".join(parts) if parts else ""

    def clear(self) -> None:
        self._findings.clear()
        self._seen.clear()

    def export_json(self, path: Path) -> None:
        """Export all findings as a JSON file."""
        data = [
            {
                "type": f.finding_type.value,
                "value": f.value,
                "source": f.source_tool,
                "confidence": f.confidence,
                "raw_output": f.raw_output,
                "severity": f.severity,
                "target_ref": f.target_ref,
                "attributes": f.attributes,
                "timestamp": f.timestamp,
            }
            for f in self._findings
        ]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    def export_markdown(self, path: Path) -> None:
        """Export all findings as a Markdown report."""
        by_type: dict[str, list[Finding]] = {}
        for f in self._findings:
            key = f.finding_type.value
            by_type.setdefault(key, []).append(f)

        lines = ["# Rapport de decouvertes SECOPS", ""]
        lines.append(f"Total: {len(self._findings)} decouverte(s)")
        lines.append("")
        for ftype, findings in by_type.items():
            lines.append(f"## {ftype.capitalize()} ({len(findings)})")
            lines.append("")
            for f in findings:
                details = [f"source: {f.source_tool}", f"confiance: {f.effective_confidence}"]
                if f.severity:
                    details.append(f"severite: {f.normalized_severity}")
                if f.target_ref:
                    details.append(f"cible: {f.target_ref}")
                lines.append(f"- **{f.value}** ({', '.join(details)})")
            lines.append("")

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(lines), encoding="utf-8")

    def save_state(self, path: Path) -> None:
        """Persist findings to a JSON file for session recovery."""
        data = [
            {
                "type": f.finding_type.value,
                "value": f.value,
                "source": f.source_tool,
                "confidence": f.confidence,
                "raw_output": f.raw_output,
                "severity": f.severity,
                "target_ref": f.target_ref,
                "attributes": f.attributes,
                "timestamp": f.timestamp,
            }
            for f in self._findings
        ]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    @classmethod
    def load_state(cls, path: Path) -> "FindingsStore":
        """Restore findings from a previously saved state file."""
        store = cls()
        if not path.exists():
            return store
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return store
        for entry in data:
            try:
                finding_type = FindingType(entry["type"])
            except (KeyError, ValueError):
                continue
            store.add(Finding(
                finding_type=finding_type,
                value=entry.get("value", ""),
                source_tool=entry.get("source", "unknown"),
                confidence=entry.get("confidence", "medium"),
                raw_output=entry.get("raw_output", ""),
                timestamp=entry.get("timestamp", ""),
                severity=entry.get("severity", ""),
                target_ref=entry.get("target_ref", ""),
                attributes=entry.get("attributes", {}) or {},
            ))
        return store
