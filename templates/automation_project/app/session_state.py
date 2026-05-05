"""Session state — persist and restore full pentest session state.

Saves findings, engagement phase, targets, tool history, scope, and
conversation summary to enable resuming interrupted pentests.
"""

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path


@dataclass
class SessionSummary:
    """Compact summary of a saved session for listing."""

    session_id: str
    target: str
    phase: str
    findings_count: int
    started_at: str
    last_active: str


@dataclass
class SessionState:
    """Complete pentest session state for persistence."""

    session_id: str = ""
    target_summary: str = ""
    phase: str = "recon"
    tools_used: list[str] = field(default_factory=list)
    targets: list[dict] = field(default_factory=list)
    scope: list[str] = field(default_factory=list)
    active_case_slug: str = ""
    conversation_summary: str = ""
    findings_count: int = 0
    started_at: str = field(
        default_factory=lambda: datetime.now().isoformat(timespec="seconds")
    )
    last_active: str = field(
        default_factory=lambda: datetime.now().isoformat(timespec="seconds")
    )

    def touch(self) -> None:
        """Update the last_active timestamp."""
        self.last_active = datetime.now().isoformat(timespec="seconds")


def _sessions_dir(workspace: Path) -> Path:
    """Return the sessions directory, creating it if needed."""
    d = workspace / "sessions"
    d.mkdir(parents=True, exist_ok=True)
    return d


def save_session(workspace: Path, state: SessionState) -> Path:
    """Save a session state to a JSON file in workspace/sessions/.

    Parameters
    ----------
    workspace : Path
        The workspace directory.
    state : SessionState
        The session state to persist.

    Returns
    -------
    Path
        Path to the written session file.
    """
    state.touch()
    if not state.session_id:
        state.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    sessions_dir = _sessions_dir(workspace)
    path = sessions_dir / f"session_{state.session_id}.json"
    data = asdict(state)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def load_session(workspace: Path, session_id: str) -> SessionState | None:
    """Load a session state from a JSON file.

    Parameters
    ----------
    workspace : Path
        The workspace directory.
    session_id : str
        The session ID to load.

    Returns
    -------
    SessionState or None
        The restored session state, or None if not found.
    """
    sessions_dir = _sessions_dir(workspace)
    path = sessions_dir / f"session_{session_id}.json"
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    # Filter only known fields
    known_fields = set(SessionState.__dataclass_fields__.keys())
    filtered = {k: v for k, v in data.items() if k in known_fields}
    return SessionState(**filtered)


def list_sessions(workspace: Path) -> list[SessionSummary]:
    """List all saved sessions, sorted by most recent first.

    Parameters
    ----------
    workspace : Path
        The workspace directory.

    Returns
    -------
    list[SessionSummary]
        Summary of each saved session.
    """
    sessions_dir = _sessions_dir(workspace)
    summaries = []
    for path in sorted(sessions_dir.glob("session_*.json"), reverse=True):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            summaries.append(SessionSummary(
                session_id=data.get("session_id", path.stem.replace("session_", "")),
                target=data.get("target_summary", ""),
                phase=data.get("phase", ""),
                findings_count=data.get("findings_count", 0),
                started_at=data.get("started_at", ""),
                last_active=data.get("last_active", ""),
            ))
        except (json.JSONDecodeError, OSError):
            continue
    return summaries


def delete_session(workspace: Path, session_id: str) -> bool:
    """Delete a saved session file.

    Returns True if deleted, False if not found.
    """
    sessions_dir = _sessions_dir(workspace)
    path = sessions_dir / f"session_{session_id}.json"
    if path.exists():
        path.unlink()
        return True
    return False
