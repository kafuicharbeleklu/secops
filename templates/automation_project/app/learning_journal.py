"""Learning journal — append-only record of agent attempts and outcomes."""

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path


@dataclass
class LearningAttempt:
    """A compact, reusable trace of one agent action."""

    timestamp: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    tool_name: str = ""
    arguments: dict = field(default_factory=dict)
    status: str = ""
    target: str = ""
    phase: str = ""
    case_label: str = ""
    result_summary: str = ""
    findings: list[str] = field(default_factory=list)
    retry_hint: str = ""


class LearningJournal:
    """Persist action outcomes for later review and knowledge curation."""

    def __init__(self, path: Path):
        self.path = Path(path)

    def append_attempt(
        self,
        *,
        tool_name: str,
        arguments: dict | None = None,
        status: str,
        target: str = "",
        phase: str = "",
        case_label: str = "",
        result_summary: str = "",
        findings: list[str] | None = None,
        retry_hint: str = "",
    ) -> None:
        attempt = LearningAttempt(
            tool_name=tool_name,
            arguments=dict(arguments or {}),
            status=status,
            target=target,
            phase=phase,
            case_label=case_label,
            result_summary=(result_summary or "")[:500],
            findings=list(findings or [])[:10],
            retry_hint=(retry_hint or "")[:300],
        )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(asdict(attempt), ensure_ascii=False) + "\n")

    def recent(self, limit: int = 10) -> list[LearningAttempt]:
        if not self.path.exists():
            return []
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []

        attempts: list[LearningAttempt] = []
        for line in lines[-limit:]:
            if not line.strip():
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            fields = {
                key: value
                for key, value in data.items()
                if key in LearningAttempt.__dataclass_fields__
            }
            attempts.append(LearningAttempt(**fields))
        return attempts

    def decision_context(self, limit: int = 8) -> str:
        """Return a compact prompt fragment from recent attempts."""
        attempts = self.recent(limit=limit)
        if not attempts:
            return ""

        lines = [
            "MEMOIRE D'EXPERIENCE RECENTE:",
            "Utilise ces traces pour eviter les repetitions et choisir un pivot, sans les traiter comme des faits non verifies sur la cible courante.",
        ]
        for attempt in attempts:
            target = attempt.target or "cible non precisee"
            phase = attempt.phase or "phase inconnue"
            summary = " ".join((attempt.result_summary or "").split())[:140]
            findings = ", ".join(attempt.findings[:3])
            details = f"- {attempt.status} | {phase} | {attempt.tool_name} | {target}"
            if summary:
                details += f" | resultat: {summary}"
            if findings:
                details += f" | decouvertes: {findings}"
            if attempt.retry_hint:
                details += f" | pivot: {attempt.retry_hint[:120]}"
            lines.append(details)
        return "\n".join(lines)
