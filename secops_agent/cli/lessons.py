"""Pure parsing/formatting helpers for the ``/lessons`` slash command (Phase 3.2).

Human validation of cross-mission lessons. The store-side mutation lives in
``ExperienceStore.review_lesson`` (already tested); this module only parses the
operator's command and formats the lesson list, so it stays unit-testable without
a live store or TUI. See ``docs/ARCHITECTURE.md`` §5.2.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

# Human review decisions an operator can apply to a lesson. "unreviewed" is the
# initial state, never a promotion target.
VALID_REVIEW_STATUSES: tuple[str, ...] = ("reviewed", "blocked", "deprecated")

LESSONS_USAGE = "Usage: /lessons [list | review <id> <reviewed|blocked|deprecated> [note]]"


@dataclass(frozen=True)
class LessonsCommand:
    action: str  # "list" | "review" | "error"
    lesson_id: str = ""
    status: str = ""
    note: str = ""
    error: str = ""


def parse_lessons_command(argument: str) -> LessonsCommand:
    """Parse the text following ``/lessons`` into a structured command."""
    text = str(argument or "").strip()
    if not text or text.lower() == "list":
        return LessonsCommand(action="list")

    parts = text.split(None, 3)
    if parts[0].lower() != "review":
        return LessonsCommand(action="error", error=LESSONS_USAGE)
    if len(parts) < 3:
        return LessonsCommand(action="error", error=LESSONS_USAGE)

    lesson_id = parts[1]
    status = parts[2].lower()
    note = parts[3].strip() if len(parts) > 3 else ""
    if status not in VALID_REVIEW_STATUSES:
        allowed = ", ".join(VALID_REVIEW_STATUSES)
        return LessonsCommand(
            action="error",
            error=f"Unknown review status '{parts[2]}'. Allowed: {allowed}.\n{LESSONS_USAGE}",
        )
    return LessonsCommand(action="review", lesson_id=lesson_id, status=status, note=note)


def _lesson_label(lesson: Any) -> str:
    reason = ""
    if hasattr(lesson, "reason"):
        try:
            reason = str(lesson.reason()).strip()
        except Exception:
            reason = ""
    return reason or str(getattr(lesson, "title", "") or "(untitled lesson)").strip()


def format_lessons_for_review(lessons: Iterable[Any], *, limit: int = 30) -> str:
    """Render lessons for the operator, surfacing unreviewed ones first."""
    items = list(lessons)
    if not items:
        return "No stored lessons yet."

    # Unreviewed lessons await a human decision — list them first.
    order = {"unreviewed": 0, "reviewed": 1, "deprecated": 2, "blocked": 3}
    items.sort(key=lambda lesson: order.get(str(getattr(lesson, "review_status", "")), 4))

    unreviewed = sum(1 for lesson in items if getattr(lesson, "review_status", "") == "unreviewed")
    lines = [f"Lessons: {len(items)} total, {unreviewed} unreviewed."]
    for lesson in items[:limit]:
        status = str(getattr(lesson, "review_status", "") or "unreviewed")
        lesson_id = str(getattr(lesson, "id", "") or "")
        label = _lesson_label(lesson)
        if len(label) > 90:
            label = label[:87] + "…"
        lines.append(f"  [{lesson_id}] ({status}) {label}")
    if len(items) > limit:
        lines.append(f"  … and {len(items) - limit} more.")
    lines.append("Promote with: /lessons review <id> <reviewed|blocked|deprecated> [note]")
    return "\n".join(lines)
