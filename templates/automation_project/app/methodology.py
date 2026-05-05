"""Pentest methodology engine — phase-aware reasoning and engagement state."""

from dataclasses import dataclass, field
from enum import Enum


class PentestPhase(Enum):
    RECON = "recon"
    ENUMERATION = "enumeration"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"


_PHASE_ORDER = list(PentestPhase)
_GUARDED_PHASES = {
    PentestPhase.EXPLOITATION,
    PentestPhase.POST_EXPLOITATION,
}

PHASE_METADATA = {
    PentestPhase.RECON: {
        "label": "Reconnaissance",
        "objective": "Identifier la surface d'attaque.",
        "typical_tools": ("nmap", "masscan", "whois", "dig", "ping"),
        "advance_when": "Ports ou services identifies.",
        "prompt_fragment": (
            "Phase: RECONNAISSANCE. Objectif: identifier ports, services, OS.\n"
            "PLAYBOOK:\n"
            "1. Lance nmap -sC -sV sur la cible pour decouvrir ports et services.\n"
            "2. Si des ports web (80, 443, 8080) sont ouverts, note-les pour la phase enum.\n"
            "3. Si des ports SMB (139, 445) sont ouverts, note-les pour enum4linux.\n"
            "4. Si des ports SSH (22) sont ouverts, note-les pour tester les credentials plus tard.\n"
            "5. Passe a ENUMERATION quand tu as identifie au moins les ports et services principaux.\n"
            "NE T'ARRETE PAS apres un seul scan si la cible n'est pas encore bien cartographiee."
        ),
    },
    PentestPhase.ENUMERATION: {
        "label": "Enumeration",
        "objective": "Approfondir chaque service.",
        "typical_tools": ("gobuster", "nikto", "ffuf", "smbclient", "enum4linux"),
        "advance_when": "Vulnerabilites ou vecteurs identifies.",
        "prompt_fragment": (
            "Phase: ENUMERATION. Objectif: approfondir chaque service decouvert.\n"
            "PLAYBOOK:\n"
            "1. HTTP/HTTPS (80/443/8080) → lance gobuster pour trouver les chemins caches, "
            "puis nikto pour les vulns web.\n"
            "2. SMB (445) → lance enum4linux pour lister shares, users, policies.\n"
            "3. FTP (21) → teste l'acces anonyme avec 'ftp <target>'.\n"
            "4. Si /wp-admin ou /wp-login trouve → lance wpscan.\n"
            "5. Passe a EXPLOITATION quand tu as des vulns, des chemins sensibles, ou des credentials.\n"
            "ENCHAINE les outils automatiquement sans attendre que l'utilisateur relance."
        ),
    },
    PentestPhase.EXPLOITATION: {
        "label": "Exploitation",
        "objective": "Exploiter les vulns pour obtenir un acces.",
        "typical_tools": ("sqlmap", "hydra", "searchsploit", "john", "netcat"),
        "advance_when": "Acces obtenu.",
        "prompt_fragment": (
            "Phase: EXPLOITATION. Objectif: exploiter les vulns identifiees.\n"
            "PLAYBOOK:\n"
            "1. Si credential trouvee → teste l'acces (ssh, ftp, web login).\n"
            "2. Si formulaire web vuln → lance sqlmap.\n"
            "3. Si page login sans credential → hydra avec wordlist commune.\n"
            "4. Si version de service connue → searchsploit pour chercher des exploits.\n"
            "5. Passe a POST-EXPLOITATION quand tu as un shell ou un acces utilisateur.\n"
            "CORRELE les findings precedents pour choisir le vecteur d'attaque."
        ),
    },
    PentestPhase.POST_EXPLOITATION: {
        "label": "Post-exploitation",
        "objective": "Escalader privileges, pivoter, extraire preuves.",
        "typical_tools": ("netcat", "curl", "wget"),
        "advance_when": "Objectif atteint.",
        "prompt_fragment": (
            "Phase: POST-EXPLOITATION. Objectif: escalade de privileges, pivot, preuves.\n"
            "PLAYBOOK:\n"
            "1. Cherche /etc/shadow, /etc/passwd, fichiers de config avec credentials.\n"
            "2. Cherche les binaires SUID, les cron jobs, les capabilities.\n"
            "3. Si hash trouve → john ou hashcat pour cracker.\n"
            "4. Consolide toutes les preuves dans workspace/.\n"
            "5. Passe a RAPPORT quand l'objectif du lab est atteint."
        ),
    },
    PentestPhase.REPORTING: {
        "label": "Rapport",
        "objective": "Synthetiser decouvertes et recommandations.",
        "typical_tools": (),
        "advance_when": "",
        "prompt_fragment": (
            "Phase: RAPPORT. Objectif: synthetiser les decouvertes.\n"
            "Genere un rapport structuré avec: resume executif, vulnerabilites trouvees, "
            "chemins d'attaque, preuves, et recommandations de remediation."
        ),
    },
}


@dataclass
class PhaseTransition:
    from_phase: PentestPhase
    to_phase: PentestPhase
    reason: str


@dataclass
class EngagementState:
    phase: PentestPhase = PentestPhase.RECON
    tools_used: list[str] = field(default_factory=list)
    phase_history: list[PhaseTransition] = field(default_factory=list)

    def record_tool_use(self, tool_name: str) -> None:
        if tool_name not in self.tools_used:
            self.tools_used.append(tool_name)

    def advance_phase(self, reason: str = "") -> PentestPhase | None:
        idx = _PHASE_ORDER.index(self.phase)
        if idx >= len(_PHASE_ORDER) - 1:
            return None
        new_phase = _PHASE_ORDER[idx + 1]
        self.phase_history.append(PhaseTransition(self.phase, new_phase, reason or "Progression automatique."))
        self.phase = new_phase
        return new_phase

    def set_phase(self, phase: PentestPhase, reason: str = "") -> None:
        if phase == self.phase:
            return
        self.phase_history.append(PhaseTransition(self.phase, phase, reason or "Changement manuel."))
        self.phase = phase

    def next_phase_candidate(self) -> PentestPhase | None:
        idx = _PHASE_ORDER.index(self.phase)
        if idx >= len(_PHASE_ORDER) - 1:
            return None
        return _PHASE_ORDER[idx + 1]

    def should_suggest_advance(self, findings) -> bool:
        if self.phase == PentestPhase.REPORTING or not findings:
            return False
        ftypes = set()
        for f in findings:
            v = f.finding_type.value if hasattr(f.finding_type, "value") else str(f.finding_type)
            ftypes.add(v)
        if self.phase == PentestPhase.RECON:
            return bool(ftypes & {"port", "service"})
        if self.phase == PentestPhase.ENUMERATION:
            return bool(ftypes & {"vulnerability", "credential", "path"})
        if self.phase == PentestPhase.EXPLOITATION:
            return bool(ftypes & {"credential", "user", "file"})
        return False

    def phase_context_prompt(self, findings_summary: str = "") -> str:
        meta = PHASE_METADATA.get(self.phase, {})
        parts = [meta.get("prompt_fragment", f"Phase: {self.phase.value}")]
        if findings_summary:
            parts.append(f"\nDecouvertes:\n{findings_summary}")
        if self.tools_used:
            parts.append(f"\nOutils utilises: {', '.join(self.tools_used[-10:])}")
        return "\n".join(parts)

    @property
    def phase_label(self) -> str:
        return PHASE_METADATA.get(self.phase, {}).get("label", self.phase.value)

    @staticmethod
    def is_guarded_phase(phase: PentestPhase | None) -> bool:
        return bool(phase in _GUARDED_PHASES)

    @classmethod
    def phase_guard_message(
        cls,
        phase: PentestPhase | None,
        *,
        has_scope: bool,
        confirmed: bool,
    ) -> str:
        if not cls.is_guarded_phase(phase):
            return ""
        if not has_scope:
            return (
                f"Transition vers {PHASE_METADATA[phase]['label']} bloquee: "
                "definis d'abord un scope autorise avec /scope."
            )
        if not confirmed:
            return (
                f"Transition vers {PHASE_METADATA[phase]['label']} bloquee: "
                f"confirmation humaine requise via /phase {phase.value} confirm."
            )
        return ""


def parse_phase(raw: str) -> PentestPhase | None:
    normalized = raw.strip().lower().replace("-", "_").replace(" ", "_")
    aliases = {
        "recon": PentestPhase.RECON, "reconnaissance": PentestPhase.RECON,
        "enum": PentestPhase.ENUMERATION, "enumeration": PentestPhase.ENUMERATION,
        "exploit": PentestPhase.EXPLOITATION, "exploitation": PentestPhase.EXPLOITATION,
        "post": PentestPhase.POST_EXPLOITATION, "post_exploit": PentestPhase.POST_EXPLOITATION,
        "post_exploitation": PentestPhase.POST_EXPLOITATION,
        "report": PentestPhase.REPORTING, "reporting": PentestPhase.REPORTING,
        "rapport": PentestPhase.REPORTING,
    }
    return aliases.get(normalized)
