"""Dynamic pentest tool registry — discover, categorize, and recommend tools."""

import shutil
from dataclasses import dataclass
from enum import Enum


class ToolCategory(Enum):
    RECON = "recon"
    ENUM = "enumeration"
    EXPLOIT = "exploitation"
    POST_EXPLOIT = "post_exploitation"
    UTIL = "utility"


@dataclass(frozen=True)
class PentestTool:
    """Describes a pentest tool known to the registry."""

    name: str
    category: ToolCategory
    description: str
    package: str
    phases: tuple[str, ...]
    target_types: tuple[str, ...]
    installed: bool = False


# ---------------------------------------------------------------------------
# Built-in tool catalog — extend freely
# ---------------------------------------------------------------------------

_CATALOG: list[dict] = [
    # --- Reconnaissance ---
    {
        "name": "nmap",
        "category": ToolCategory.RECON,
        "description": "Scanner de ports et detection de services/OS.",
        "package": "nmap",
        "phases": ("recon", "enumeration"),
        "target_types": ("ip", "domain", "cidr", "hostname"),
    },
    {
        "name": "masscan",
        "category": ToolCategory.RECON,
        "description": "Scanner de ports ultra-rapide pour larges plages.",
        "package": "masscan",
        "phases": ("recon",),
        "target_types": ("ip", "cidr"),
    },
    {
        "name": "whois",
        "category": ToolCategory.RECON,
        "description": "Recherche WHOIS sur domaines et IPs.",
        "package": "whois",
        "phases": ("recon",),
        "target_types": ("domain", "ip"),
    },
    {
        "name": "dig",
        "category": ToolCategory.RECON,
        "description": "Requetes DNS avancees.",
        "package": "dnsutils",
        "phases": ("recon",),
        "target_types": ("domain", "hostname"),
    },
    {
        "name": "host",
        "category": ToolCategory.RECON,
        "description": "Resolution DNS simple.",
        "package": "dnsutils",
        "phases": ("recon",),
        "target_types": ("domain", "hostname"),
    },
    {
        "name": "traceroute",
        "category": ToolCategory.RECON,
        "description": "Tracer le chemin reseau vers la cible.",
        "package": "traceroute",
        "phases": ("recon",),
        "target_types": ("ip", "domain", "hostname"),
    },
    # --- Enumeration ---
    {
        "name": "gobuster",
        "category": ToolCategory.ENUM,
        "description": "Brute-force de repertoires et sous-domaines web.",
        "package": "gobuster",
        "phases": ("enumeration",),
        "target_types": ("ip", "domain", "url"),
    },
    {
        "name": "dirb",
        "category": ToolCategory.ENUM,
        "description": "Scanner de repertoires web par dictionnaire.",
        "package": "dirb",
        "phases": ("enumeration",),
        "target_types": ("ip", "domain", "url"),
    },
    {
        "name": "nikto",
        "category": ToolCategory.ENUM,
        "description": "Scanner de vulnerabilites serveurs web.",
        "package": "nikto",
        "phases": ("enumeration",),
        "target_types": ("ip", "domain", "url"),
    },
    {
        "name": "ffuf",
        "category": ToolCategory.ENUM,
        "description": "Fuzzer web rapide pour repertoires et parametres.",
        "package": "ffuf",
        "phases": ("enumeration",),
        "target_types": ("ip", "domain", "url"),
    },
    {
        "name": "smbclient",
        "category": ToolCategory.ENUM,
        "description": "Client SMB pour enumeration de partages.",
        "package": "smbclient",
        "phases": ("enumeration",),
        "target_types": ("ip", "hostname"),
    },
    {
        "name": "enum4linux",
        "category": ToolCategory.ENUM,
        "description": "Enumeration de cibles Windows/Samba.",
        "package": "enum4linux",
        "phases": ("enumeration",),
        "target_types": ("ip", "hostname"),
    },
    {
        "name": "wpscan",
        "category": ToolCategory.ENUM,
        "description": "Scanner de vulnerabilites WordPress.",
        "package": "wpscan",
        "phases": ("enumeration",),
        "target_types": ("ip", "domain", "url"),
    },
    {
        "name": "whatweb",
        "category": ToolCategory.ENUM,
        "description": "Detection de technologies web.",
        "package": "whatweb",
        "phases": ("enumeration",),
        "target_types": ("ip", "domain", "url"),
    },
    # --- Exploitation ---
    {
        "name": "sqlmap",
        "category": ToolCategory.EXPLOIT,
        "description": "Detection et exploitation automatisee d'injections SQL.",
        "package": "sqlmap",
        "phases": ("exploitation",),
        "target_types": ("url",),
    },
    {
        "name": "hydra",
        "category": ToolCategory.EXPLOIT,
        "description": "Brute-force de credentials sur services reseau.",
        "package": "hydra",
        "phases": ("exploitation",),
        "target_types": ("ip", "domain", "hostname"),
    },
    {
        "name": "searchsploit",
        "category": ToolCategory.EXPLOIT,
        "description": "Recherche locale dans la base ExploitDB.",
        "package": "exploitdb",
        "phases": ("exploitation",),
        "target_types": ("ip", "domain", "hostname", "url"),
    },
    {
        "name": "john",
        "category": ToolCategory.EXPLOIT,
        "description": "Cassage de mots de passe hors-ligne.",
        "package": "john",
        "phases": ("exploitation", "post_exploitation"),
        "target_types": ("ip", "domain", "hostname"),
    },
    {
        "name": "hashcat",
        "category": ToolCategory.EXPLOIT,
        "description": "Cassage de mots de passe GPU-accelere.",
        "package": "hashcat",
        "phases": ("exploitation", "post_exploitation"),
        "target_types": ("ip", "domain", "hostname"),
    },
    # --- Post-exploitation ---
    {
        "name": "netcat",
        "category": ToolCategory.UTIL,
        "description": "Couteau suisse TCP/UDP pour reverse shells et transferts.",
        "package": "netcat-openbsd",
        "phases": ("exploitation", "post_exploitation"),
        "target_types": ("ip", "domain", "hostname"),
    },
    # --- Utilities ---
    {
        "name": "curl",
        "category": ToolCategory.UTIL,
        "description": "Requetes HTTP/S en ligne de commande.",
        "package": "curl",
        "phases": ("recon", "enumeration", "exploitation", "post_exploitation"),
        "target_types": ("ip", "domain", "url", "hostname"),
    },
    {
        "name": "wget",
        "category": ToolCategory.UTIL,
        "description": "Telechargement de fichiers depuis le web.",
        "package": "wget",
        "phases": ("recon", "enumeration", "exploitation", "post_exploitation"),
        "target_types": ("ip", "domain", "url", "hostname"),
    },
    {
        "name": "ping",
        "category": ToolCategory.UTIL,
        "description": "Test de connectivite ICMP.",
        "package": "iputils-ping",
        "phases": ("recon",),
        "target_types": ("ip", "domain", "hostname"),
    },
]

_ALIASES = {
    "tracerout": "traceroute",
}


class ToolRegistry:
    """Registry of known pentest tools with runtime availability detection."""

    def __init__(self, catalog=None):
        self._catalog = catalog if catalog is not None else list(_CATALOG)
        self._tools: dict[str, PentestTool] = {}
        self._scan()

    def _scan(self):
        """Detect which tools are installed on the system."""
        self._tools.clear()
        for entry in self._catalog:
            installed = bool(shutil.which(entry["name"]))
            tool = PentestTool(
                name=entry["name"],
                category=entry["category"],
                description=entry["description"],
                package=entry["package"],
                phases=tuple(entry["phases"]),
                target_types=tuple(entry["target_types"]),
                installed=installed,
            )
            self._tools[tool.name] = tool

    def refresh(self):
        """Re-scan installed tools (call after an installation)."""
        self._scan()

    def normalize_name(self, name: str) -> str:
        """Normalize user-provided tool names and common typos."""
        normalized = (name or "").strip().lower()
        return _ALIASES.get(normalized, normalized)

    @property
    def all_tools(self) -> tuple[PentestTool, ...]:
        return tuple(self._tools.values())

    @property
    def installed_tools(self) -> tuple[PentestTool, ...]:
        return tuple(t for t in self._tools.values() if t.installed)

    @property
    def missing_tools(self) -> tuple[PentestTool, ...]:
        return tuple(t for t in self._tools.values() if not t.installed)

    def get(self, name: str) -> PentestTool | None:
        return self._tools.get(self.normalize_name(name))

    def is_known(self, name: str) -> bool:
        return self.normalize_name(name) in self._tools

    def is_installed(self, name: str) -> bool:
        tool = self._tools.get(self.normalize_name(name))
        return bool(tool and tool.installed)

    def get_package(self, name: str) -> str | None:
        """Return the apt package name for a known tool."""
        tool = self._tools.get(self.normalize_name(name))
        return tool.package if tool else None

    def suggest_tools(
        self,
        phase: str | None = None,
        target_type: str | None = None,
        installed_only: bool = True,
    ) -> list[PentestTool]:
        """Recommend tools for a given phase and/or target type."""
        candidates = list(self._tools.values())
        if installed_only:
            candidates = [t for t in candidates if t.installed]
        if phase:
            candidates = [t for t in candidates if phase in t.phases]
        if target_type:
            candidates = [t for t in candidates if target_type in t.target_types]
        return candidates

    def format_inventory(self, installed_only: bool = False) -> str:
        """Produce a human/LLM-readable inventory string."""
        tools = self.installed_tools if installed_only else self.all_tools
        if not tools:
            return "Aucun outil pentest detecte."
        lines = []
        for tool in sorted(tools, key=lambda t: (t.category.value, t.name)):
            status = "installe" if tool.installed else "absent"
            lines.append(
                f"  {tool.name:<16} [{tool.category.value}] {tool.description} ({status})"
            )
        return "\n".join(lines)

    def known_executables(self) -> set[str]:
        """Return the set of all known tool executable names."""
        return set(self._tools.keys())

    def installable_packages(self) -> dict[str, str]:
        """Return {executable: package} for tools that have an apt package."""
        return {
            t.name: t.package
            for t in self._tools.values()
            if t.package and not t.installed
        }
