"""Target intelligence — detect, classify, and enrich pentest targets."""

import re
from dataclasses import dataclass, field
from enum import Enum


class TargetType(Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    CIDR = "cidr"
    HOSTNAME = "hostname"


# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

_IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_CIDR_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)/\d{1,2}\b"
)
_URL_RE = re.compile(
    r"\bhttps?://[^\s,;\"'<>]+", re.IGNORECASE
)
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|io|co|info|dev|xyz|me|app|cloud|local|lan|htb|thm|internal)\b",
    re.IGNORECASE,
)

# Addresses that are never valid pentest targets
_EXCLUDED_IPS = {"0.0.0.0", "255.255.255.255", "127.0.0.1"}


@dataclass
class Target:
    """Represents a pentest target with progressive enrichment."""

    raw: str
    target_type: TargetType
    address: str
    ports: list[int] = field(default_factory=list)
    services: dict[int, str] = field(default_factory=dict)
    os_hint: str = ""
    tags: set[str] = field(default_factory=set)

    @property
    def label(self):
        if self.target_type == TargetType.URL:
            return self.raw
        return self.address

    @property
    def summary(self):
        parts = [f"{self.target_type.value}: {self.address}"]
        if self.ports:
            parts.append(f"ports: {', '.join(str(p) for p in sorted(self.ports)[:10])}")
        if self.services:
            svc_list = [f"{p}/{s}" for p, s in sorted(self.services.items())[:6]]
            parts.append(f"services: {', '.join(svc_list)}")
        if self.os_hint:
            parts.append(f"os: {self.os_hint}")
        if self.tags:
            parts.append(f"tags: {', '.join(sorted(self.tags))}")
        return " | ".join(parts)


def _classify(raw: str) -> TargetType:
    """Classify a raw string into a target type."""
    if _CIDR_RE.fullmatch(raw):
        return TargetType.CIDR
    if _URL_RE.fullmatch(raw):
        return TargetType.URL
    if _IP_RE.fullmatch(raw):
        return TargetType.IP
    if _DOMAIN_RE.fullmatch(raw):
        return TargetType.DOMAIN
    return TargetType.HOSTNAME


def _normalize_address(raw: str, target_type: TargetType) -> str:
    """Extract the core address from a raw target string."""
    if target_type == TargetType.URL:
        # Strip scheme and path to get host
        stripped = re.sub(r"^https?://", "", raw, flags=re.IGNORECASE)
        return stripped.split("/")[0].split(":")[0].lower()
    return raw.strip().lower()


def detect_targets(text: str) -> list[Target]:
    """Extract all pentest targets from a block of text.

    Returns de-duplicated targets ordered by first appearance.
    """
    seen_addresses = set()
    targets = []

    # Order matters: CIDR before IP, URL before domain
    for match in _CIDR_RE.finditer(text):
        raw = match.group(0)
        addr = _normalize_address(raw, TargetType.CIDR)
        if addr not in seen_addresses:
            seen_addresses.add(addr)
            targets.append(Target(raw=raw, target_type=TargetType.CIDR, address=addr))

    for match in _URL_RE.finditer(text):
        raw = match.group(0)
        addr = _normalize_address(raw, TargetType.URL)
        if addr not in seen_addresses:
            seen_addresses.add(addr)
            targets.append(Target(raw=raw, target_type=TargetType.URL, address=addr))

    for match in _IP_RE.finditer(text):
        raw = match.group(0)
        if raw in _EXCLUDED_IPS:
            continue
        # Skip if this IP was already captured as part of a CIDR
        if raw in seen_addresses:
            continue
        # Skip if it's part of a CIDR match
        start = match.start()
        end = match.end()
        if end < len(text) and text[end] == "/":
            continue
        seen_addresses.add(raw)
        targets.append(Target(raw=raw, target_type=TargetType.IP, address=raw))

    for match in _DOMAIN_RE.finditer(text):
        raw = match.group(0)
        addr = raw.lower()
        if addr not in seen_addresses:
            seen_addresses.add(addr)
            targets.append(Target(raw=raw, target_type=TargetType.DOMAIN, address=addr))

    return targets


def merge_findings(target: Target, findings) -> None:
    """Enrich a target with structured findings from a scan.

    ``findings`` is an iterable of Finding dataclass instances
    (from the findings module).
    """
    for finding in findings:
        ftype = finding.finding_type.value if hasattr(finding.finding_type, "value") else str(finding.finding_type)

        if ftype == "port":
            try:
                port = int(finding.value)
                if port not in target.ports:
                    target.ports.append(port)
            except (ValueError, TypeError):
                pass

        elif ftype == "service":
            # value expected as "port/service_name"
            parts = str(finding.value).split("/", 1)
            if len(parts) == 2:
                try:
                    port = int(parts[0])
                    target.services[port] = parts[1]
                except (ValueError, TypeError):
                    pass

        elif ftype == "os":
            if finding.value:
                target.os_hint = str(finding.value)

        elif ftype == "hostname":
            target.tags.add(f"hostname:{finding.value}")

    # Auto-tag based on services
    service_tags = {
        "http": "web",
        "https": "web",
        "ssh": "linux",
        "smb": "windows",
        "rdp": "windows",
        "ftp": "ftp",
        "mysql": "database",
        "mssql": "database",
        "postgresql": "database",
        "dns": "dns",
        "ldap": "ad",
        "kerberos": "ad",
    }
    for service in target.services.values():
        tag = service_tags.get(service.lower().split()[0])
        if tag:
            target.tags.add(tag)


def build_target_context(targets: list[Target], active: "Target | None" = None) -> str:
    """Build a prompt-friendly context string from known targets."""
    if not targets and not active:
        return "Aucune cible connue."

    parts = []
    if active:
        parts.append(f"Cible active: {active.summary}")
    else:
        parts.append("Aucune cible active.")

    others = [t for t in targets if t is not active]
    if others:
        parts.append(f"{len(others)} autre(s) cible(s) detectee(s):")
        for t in others[:5]:
            parts.append(f"  - {t.label} ({t.target_type.value})")

    return "\n".join(parts)
