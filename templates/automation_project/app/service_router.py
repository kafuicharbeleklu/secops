"""Service router — automatic analysis playbooks based on detected services.

Given services discovered by nmap (or other recon tools), this module
selects the optimal enumeration and exploitation pipeline for each
service, producing actionable guidance the agent can follow.
"""

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class ServicePlaybook:
    """Analysis playbook for a specific service type."""

    service_pattern: str         # regex pattern matching service names
    label: str                   # human-readable label
    tools: tuple[str, ...]       # ordered list of tool names to run
    checks: tuple[str, ...]      # specific manual/automated checks
    priority: str = "medium"     # critical / high / medium / low


# ---- Built-in Playbooks ----

PLAYBOOKS: tuple[ServicePlaybook, ...] = (
    ServicePlaybook(
        service_pattern=r"apache|httpd|nginx|iis|lighttpd",
        label="Serveur Web",
        tools=("enumerate_web", "analyze_service"),
        checks=(
            "Chercher .htaccess, .git, /server-status, /server-info",
            "Tester les methodes HTTP (PUT, DELETE, TRACE)",
            "Verifier les headers de securite (X-Frame-Options, CSP, HSTS)",
            "Chercher /robots.txt et /sitemap.xml",
        ),
        priority="high",
    ),
    ServicePlaybook(
        service_pattern=r"openssh|ssh",
        label="SSH",
        tools=("analyze_service",),
        checks=(
            "Tester credentials par defaut (admin, root, guest)",
            "Verifier la version pour CVE connues",
            "Verifier les algorithmes faibles (ssh-audit si disponible)",
        ),
        priority="medium",
    ),
    ServicePlaybook(
        service_pattern=r"smb|samba|microsoft-ds|netbios",
        label="SMB/Samba",
        tools=("analyze_service",),
        checks=(
            "Tester null session (enum4linux -a)",
            "Lister les shares accessibles (smbclient -L)",
            "Verifier EternalBlue (MS17-010) si Windows",
            "Chercher des fichiers sensibles dans les shares",
        ),
        priority="high",
    ),
    ServicePlaybook(
        service_pattern=r"mysql|mariadb|postgresql|postgres|mssql|oracle",
        label="Base de donnees",
        tools=("analyze_service", "test_credentials"),
        checks=(
            "Tester credentials par defaut (root:root, sa:sa, postgres:postgres)",
            "Verifier l'acces distant sans mot de passe",
            "Chercher des bases de donnees accessibles",
        ),
        priority="high",
    ),
    ServicePlaybook(
        service_pattern=r"ftp|vsftpd|proftpd|pure-ftpd",
        label="FTP",
        tools=("analyze_service",),
        checks=(
            "Tester l'acces anonyme (anonymous:guest)",
            "Verifier la version pour CVE connues (vsftpd 2.3.4 backdoor)",
            "Chercher des fichiers sensibles dans le repertoire FTP",
        ),
        priority="medium",
    ),
    ServicePlaybook(
        service_pattern=r"wordpress|wp-",
        label="WordPress",
        tools=("analyze_service",),
        checks=(
            "wpscan --enumerate u,p,t pour users, plugins, themes",
            "Chercher wp-config.php.bak ou wp-config.php~",
            "Verifier xmlrpc.php (brute-force, SSRF)",
        ),
        priority="high",
    ),
    ServicePlaybook(
        service_pattern=r"smtp|postfix|exim|sendmail",
        label="SMTP",
        tools=("analyze_service",),
        checks=(
            "Tester VRFY et EXPN pour l'enumeration d'utilisateurs",
            "Verifier open relay",
            "Verifier la version pour CVE connues",
        ),
        priority="medium",
    ),
    ServicePlaybook(
        service_pattern=r"dns|bind|named|dnsmasq",
        label="DNS",
        tools=("enumerate_dns", "analyze_service"),
        checks=(
            "Tester le transfert de zone (dig AXFR)",
            "Enumerer les sous-domaines",
            "Verifier la version pour CVE connues",
        ),
        priority="medium",
    ),
    ServicePlaybook(
        service_pattern=r"ldap|active.directory",
        label="LDAP/AD",
        tools=("analyze_service",),
        checks=(
            "Tester l'acces anonyme (ldapsearch)",
            "Enumerer users, groupes, OUs",
            "Chercher des attributs sensibles (description, info)",
        ),
        priority="high",
    ),
    ServicePlaybook(
        service_pattern=r"snmp",
        label="SNMP",
        tools=("analyze_service",),
        checks=(
            "Tester community strings (public, private)",
            "Enumerer les informations systeme (snmpwalk)",
            "Chercher des credentials dans les MIBs",
        ),
        priority="medium",
    ),
    ServicePlaybook(
        service_pattern=r"rdp|ms-wbt-server|remote.desktop",
        label="RDP",
        tools=("analyze_service",),
        checks=(
            "Verifier BlueKeep (CVE-2019-0708) si Windows ancien",
            "Tester credentials par defaut",
            "Verifier le NLA (Network Level Authentication)",
        ),
        priority="high",
    ),
    ServicePlaybook(
        service_pattern=r"redis",
        label="Redis",
        tools=("analyze_service",),
        checks=(
            "Tester l'acces sans authentification (redis-cli)",
            "Verifier CONFIG GET pour exfiltrer des infos",
            "Ecriture de fichier via SLAVEOF ou CONFIG SET",
        ),
        priority="high",
    ),
    ServicePlaybook(
        service_pattern=r"mongodb|mongo",
        label="MongoDB",
        tools=("analyze_service",),
        checks=(
            "Tester l'acces sans authentification",
            "Lister les bases et collections",
            "Chercher des credentials stockees en clair",
        ),
        priority="high",
    ),
)

# Pre-compile patterns for performance
_COMPILED_PLAYBOOKS: list[tuple[re.Pattern, ServicePlaybook]] = [
    (re.compile(pb.service_pattern, re.IGNORECASE), pb)
    for pb in PLAYBOOKS
]


def route_service(service_name: str, version: str = "") -> ServicePlaybook | None:
    """Match a detected service to its optimal analysis playbook.

    Parameters
    ----------
    service_name : str
        The service name as reported by nmap or similar.
    version : str
        Optional version string for more precise matching.

    Returns
    -------
    ServicePlaybook or None
        The matching playbook, or None if no match.
    """
    combined = f"{service_name} {version}".strip().lower()
    if not combined:
        return None

    for pattern, playbook in _COMPILED_PLAYBOOKS:
        if pattern.search(combined):
            return playbook

    return None


@dataclass
class ServiceAnalysisPlan:
    """An ordered analysis plan for all detected services on a target."""

    target: str
    entries: list[dict] = field(default_factory=list)

    @property
    def prompt_fragment(self) -> str:
        """Generate a prompt fragment for the agent with service-specific guidance."""
        if not self.entries:
            return ""
        lines = [f"PLAYBOOKS PAR SERVICE ({len(self.entries)} service(s) detecte(s)):"]
        for entry in self.entries:
            pb = entry["playbook"]
            lines.append(
                f"  [{pb.priority.upper()}] {pb.label} (port {entry['port']}, "
                f"{entry['service_name']} {entry.get('version', '')}):"
            )
            lines.append(f"    Outils: {', '.join(pb.tools)}")
            for check in pb.checks[:3]:
                lines.append(f"    - {check}")
        return "\n".join(lines)


def build_service_plan(
    services: dict[int, str],
    target: str,
) -> ServiceAnalysisPlan:
    """Generate an ordered analysis plan for all detected services.

    Parameters
    ----------
    services : dict[int, str]
        Map of port number to service description (e.g., {80: "Apache httpd 2.4.49"}).
    target : str
        The target IP or hostname.

    Returns
    -------
    ServiceAnalysisPlan
        An ordered plan with playbooks matched to each service.
    """
    plan = ServiceAnalysisPlan(target=target)

    # Priority ordering
    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

    entries = []
    seen_labels = set()

    for port, svc_desc in services.items():
        # Split service name and version
        parts = svc_desc.strip().split(None, 1)
        service_name = parts[0] if parts else svc_desc
        version = parts[1] if len(parts) > 1 else ""

        playbook = route_service(service_name, version)
        if playbook and playbook.label not in seen_labels:
            seen_labels.add(playbook.label)
            entries.append({
                "port": port,
                "service_name": service_name,
                "version": version,
                "playbook": playbook,
            })

    # Sort by priority
    entries.sort(key=lambda e: priority_order.get(e["playbook"].priority, 3))
    plan.entries = entries

    return plan


def extract_services_from_findings(findings_store) -> dict[int, str]:
    """Extract a port→service map from the FindingsStore for routing.

    Parameters
    ----------
    findings_store : FindingsStore
        The findings store to extract services from.

    Returns
    -------
    dict[int, str]
        Map of port number to service description.
    """
    from app.findings import FindingType

    services = {}
    for finding in findings_store.by_type(FindingType.SERVICE):
        parts = finding.value.split("/", 1)
        if len(parts) == 2:
            try:
                port = int(parts[0])
                services[port] = parts[1]
            except ValueError:
                continue
    return services
