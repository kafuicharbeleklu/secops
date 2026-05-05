"""Audit trail logger — persistent JSONL logging of all agent actions.

Records every tool call, finding, phase transition, and scope change
with timestamps for legal compliance and reproducibility.
"""

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path


@dataclass
class AuditEntry:
    """A single audit log entry."""

    timestamp: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    event_type: str = ""  # command_exec, tool_call, finding, phase_change, scope_change
    tool_name: str = ""
    arguments: dict = field(default_factory=dict)
    result_summary: str = ""
    target: str = ""
    phase: str = ""
    user_approved: bool = True


class AuditLogger:
    """Append-only JSONL audit logger for pentest sessions."""

    def __init__(self, workspace: Path):
        self.audit_dir = workspace / "audit"
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        session_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.audit_file = self.audit_dir / f"session_{session_ts}.jsonl"
        self._entries: list[AuditEntry] = []

    def log(self, entry: AuditEntry) -> None:
        """Append an entry to the in-memory list and write to disk."""
        self._entries.append(entry)
        try:
            with open(self.audit_file, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(asdict(entry), ensure_ascii=False) + "\n")
        except OSError:
            pass  # Non-blocking: audit is best-effort

    def log_tool_call(
        self,
        tool_name: str,
        arguments: dict,
        result,
        *,
        target: str = "",
        phase: str = "",
        success: bool = True,
    ) -> None:
        """Convenience method to log a tool execution."""
        # Truncate result summary to keep entries manageable
        if isinstance(result, dict):
            summary = result.get("stdout", "") or result.get("error", "")
        else:
            summary = str(result)
        summary = summary[:500] if summary else ""

        self.log(AuditEntry(
            event_type="tool_call" if success else "tool_error",
            tool_name=tool_name,
            arguments=dict(arguments) if arguments else {},
            result_summary=summary,
            target=target,
            phase=phase,
        ))

    def log_finding(
        self,
        tool_name: str,
        count: int,
        preview: str = "",
        *,
        target: str = "",
        phase: str = "",
    ) -> None:
        """Log a findings discovery event."""
        self.log(AuditEntry(
            event_type="finding",
            tool_name=tool_name,
            result_summary=f"{count} decouverte(s): {preview[:200]}",
            target=target,
            phase=phase,
        ))

    def log_phase_change(
        self,
        from_phase: str,
        to_phase: str,
        reason: str = "",
        *,
        target: str = "",
    ) -> None:
        """Log a phase transition."""
        self.log(AuditEntry(
            event_type="phase_change",
            result_summary=f"{from_phase} -> {to_phase}: {reason}",
            target=target,
            phase=to_phase,
        ))

    def log_scope_change(self, scope_entries: list[str]) -> None:
        """Log a scope definition change."""
        self.log(AuditEntry(
            event_type="scope_change",
            result_summary=f"Scope defini: {', '.join(scope_entries) or 'aucun'}",
        ))

    @property
    def entries(self) -> list[AuditEntry]:
        """Return all in-memory entries."""
        return list(self._entries)

    @property
    def count(self) -> int:
        return len(self._entries)

    def timeline(self) -> list[dict]:
        """Return a serializable timeline for report generation."""
        return [asdict(e) for e in self._entries]

    def timeline_markdown(self) -> str:
        """Format the audit trail as Markdown for report inclusion."""
        if not self._entries:
            return ""
        lines = []
        for entry in self._entries:
            ts = entry.timestamp
            etype = entry.event_type
            tool = entry.tool_name
            summary = entry.result_summary[:120]
            if etype == "tool_call":
                cmd = entry.arguments.get("command", "")
                if cmd:
                    lines.append(f"- `{ts}` **{tool}** `{cmd[:80]}` — {summary}")
                else:
                    lines.append(f"- `{ts}` **{tool}** — {summary}")
            elif etype == "tool_error":
                lines.append(f"- `{ts}` **{tool}** (erreur) — {summary}")
            elif etype == "finding":
                lines.append(f"- `{ts}` Decouvertes ({tool}) — {summary}")
            elif etype == "phase_change":
                lines.append(f"- `{ts}` Phase: {summary}")
            elif etype == "scope_change":
                lines.append(f"- `{ts}` {summary}")
            else:
                lines.append(f"- `{ts}` [{etype}] {summary}")
        return "\n".join(lines)

    @classmethod
    def load_from_file(cls, path: Path) -> "AuditLogger":
        """Load an existing audit log file into memory."""
        logger = cls.__new__(cls)
        logger.audit_dir = path.parent
        logger.audit_file = path
        logger._entries = []
        if path.exists():
            try:
                for line in path.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        logger._entries.append(AuditEntry(**{
                            k: v for k, v in data.items()
                            if k in AuditEntry.__dataclass_fields__
                        }))
                    except (json.JSONDecodeError, TypeError):
                        continue
            except OSError:
                pass
        return logger
