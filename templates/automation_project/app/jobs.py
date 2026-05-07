"""Job tracking for shell-visible tasks."""

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


ACTIVE_STATUSES = {"pending", "running", "waiting"}


@dataclass
class Job:
    """A shell-visible task created from a user intent."""

    job_id: int
    kind: str
    title: str
    status: str = "pending"
    details: list[str] = field(default_factory=list)
    result: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)

    @property
    def is_active(self):
        return self.status in ACTIVE_STATUSES

    def display_line(self):
        age = int((datetime.now() - self.created_at).total_seconds())
        return f"#{self.job_id} {self.status:<9} {self.kind:<10} {self.title} ({age}s)"

    def to_dict(self):
        return {
            "job_id": self.job_id,
            "kind": self.kind,
            "title": self.title,
            "status": self.status,
            "details": list(self.details),
            "result": self.result,
            "created_at": self.created_at.isoformat(timespec="seconds"),
            "updated_at": self.updated_at.isoformat(timespec="seconds"),
        }

    @classmethod
    def from_dict(cls, data):
        def parse_dt(value):
            try:
                return datetime.fromisoformat(value)
            except Exception:
                return datetime.now()

        return cls(
            job_id=int(data.get("job_id", 0)),
            kind=str(data.get("kind", "job")),
            title=str(data.get("title", "")),
            status=str(data.get("status", "pending")),
            details=list(data.get("details") or []),
            result=str(data.get("result", "")),
            created_at=parse_dt(data.get("created_at", "")),
            updated_at=parse_dt(data.get("updated_at", "")),
        )


class JobTracker:
    """Small in-memory queue for pending/running/completed shell jobs."""

    def __init__(self, state_path=None):
        self._jobs: list[Job] = []
        self._next_id = 1
        self.state_path = Path(state_path) if state_path else None

    @classmethod
    def load_state(cls, state_path):
        tracker = cls(state_path=state_path)
        path = Path(state_path)
        if not path.exists():
            return tracker
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return tracker

        jobs = payload.get("jobs", []) if isinstance(payload, dict) else []
        for item in jobs:
            if not isinstance(item, dict):
                continue
            job = Job.from_dict(item)
            if job.job_id <= 0:
                continue
            if job.status == "running":
                job.status = "waiting"
                job.result = job.result or "session interrompue; verification requise"
            tracker._jobs.append(job)
        tracker._next_id = max((job.job_id for job in tracker._jobs), default=0) + 1
        return tracker

    def save_state(self):
        if not self.state_path:
            return
        payload = {
            "version": 1,
            "next_id": self._next_id,
            "jobs": [job.to_dict() for job in self._jobs[-100:]],
        }
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            self.state_path.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except Exception:
            return

    def create(self, kind, title, *, details=None, status="pending", result=""):
        job = Job(
            job_id=self._next_id,
            kind=kind,
            title=title,
            status=status,
            details=list(details or []),
            result=result,
        )
        self._next_id += 1
        self._jobs.append(job)
        self.save_state()
        return job

    def get(self, job_id):
        for job in self._jobs:
            if job.job_id == job_id:
                return job
        return None

    def update(self, job_id, *, status=None, details=None, result=None, append_detail=None):
        job = self.get(job_id)
        if not job:
            return None
        if status:
            job.status = status
        if details is not None:
            job.details = list(details)
        if append_detail:
            job.details.append(append_detail)
        if result is not None:
            job.result = result
        job.updated_at = datetime.now()
        self.save_state()
        return job

    def cancel(self, job_id, *, result="", append_detail=None):
        return self.update(
            job_id,
            status="cancelled",
            result=result,
            append_detail=append_detail,
        )

    def recent(self, limit=10):
        return list(reversed(self._jobs[-limit:]))

    @property
    def active_count(self):
        return sum(1 for job in self._jobs if job.is_active)

    @property
    def total_count(self):
        return len(self._jobs)
