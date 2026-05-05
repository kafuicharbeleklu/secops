import re
from dataclasses import dataclass
from pathlib import Path


HEADING_RE = re.compile(r"^(#{1,6})\s+(.*)$")
LIST_ITEM_RE = re.compile(r"^(?:[-*]|\d+\.)\s+(.*)$")


@dataclass(frozen=True)
class KnowledgeCase:
    platform: str
    slug: str
    title: str
    summary: str
    case_dir: Path
    source_files: tuple[Path, ...]
    signals: tuple[str, ...]
    hypotheses: tuple[str, ...]
    actions: tuple[str, ...]
    pivots: tuple[str, ...]
    lessons: tuple[str, ...]
    artifacts: tuple[str, ...]
    techniques: tuple[str, ...]
    services: tuple[str, ...]
    search_blob: str

    @property
    def label(self):
        return f"{self.platform}/{self.slug}"


@dataclass(frozen=True)
class KnowledgeSuggestion:
    case: KnowledgeCase
    score: int
    matched_signals: tuple[str, ...]
    matched_hypotheses: tuple[str, ...]
    matched_actions: tuple[str, ...]
    matched_pivots: tuple[str, ...]


def _slugify(value):
    normalized = re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")
    return normalized or value.lower()


def _parse_markdown(path):
    if not path.exists():
        return path.stem.replace("_", " ").title(), {}

    title = path.stem.replace("_", " ").title()
    sections = {}
    current = None

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        stripped = raw_line.strip()
        if not stripped:
            continue

        heading = HEADING_RE.match(stripped)
        if heading:
            level = len(heading.group(1))
            label = heading.group(2).strip()
            if level == 1:
                title = label
            elif level == 2:
                current = label
                sections.setdefault(label, [])
            continue

        if current:
            sections[current].append(stripped)

    return title, sections


def _extract_items(lines):
    items = []
    current = None

    for line in lines:
        match = LIST_ITEM_RE.match(line)
        if match:
            if current:
                items.append(current)
            current = match.group(1).strip()
            continue

        if current:
            current = f"{current} {line.strip()}"
        elif line.strip():
            items.append(line.strip())

    if current:
        items.append(current)
    return tuple(item for item in items if item)


def _find_section_items(sections, *needles):
    for title, lines in sections.items():
        lowered = title.lower()
        if any(needle in lowered for needle in needles):
            return _extract_items(lines)
    return ()


def _find_section_text(sections, *needles):
    items = _find_section_items(sections, *needles)
    if items:
        return items[0]

    for title, lines in sections.items():
        lowered = title.lower()
        if any(needle in lowered for needle in needles):
            for line in lines:
                stripped = line.strip()
                if stripped:
                    return stripped
    return ""


def _matching_items(items, tokens, limit):
    if not items:
        return ()

    if not tokens:
        return tuple(items[:limit])

    matches = []
    for item in items:
        lowered = item.lower()
        if any(token in lowered for token in tokens):
            matches.append(item)
    if matches:
        return tuple(matches[:limit])
    return tuple(items[:limit])


class KnowledgeStore:
    def __init__(self, root_dir, cases):
        self.root_dir = Path(root_dir).resolve()
        self.cases = tuple(cases)

    @classmethod
    def load(cls, root_dir):
        root_dir = Path(root_dir).resolve()
        if not root_dir.exists():
            return cls(root_dir, [])

        case_dirs = set()
        for filename in ("lab_profile.md", "case_memory.md"):
            for path in root_dir.rglob(filename):
                case_dirs.add(path.parent)

        cases = []
        for case_dir in sorted(case_dirs):
            try:
                relative = case_dir.relative_to(root_dir)
            except ValueError:
                continue

            if len(relative.parts) < 2:
                continue

            platform = relative.parts[0]
            slug = relative.parts[-1]

            profile_title, profile_sections = _parse_markdown(case_dir / "lab_profile.md")
            memory_title, memory_sections = _parse_markdown(case_dir / "case_memory.md")
            title = profile_title or memory_title or slug.replace("_", " ").title()

            signals = _find_section_items(memory_sections, "signaux") or _find_section_items(
                profile_sections, "signaux"
            )
            hypotheses = _find_section_items(memory_sections, "hypoth")
            actions = _find_section_items(memory_sections, "actions")
            pivots = _find_section_items(memory_sections, "pivot")
            lessons = _find_section_items(memory_sections, "lecons") or _find_section_items(
                profile_sections, "ce que ce cas doit apprendre"
            )
            artifacts = _find_section_items(profile_sections, "artefacts")
            techniques = (
                _find_section_items(memory_sections, "technique")
                or _find_section_items(profile_sections, "technique")
            )
            services = (
                _find_section_items(memory_sections, "service")
                or _find_section_items(profile_sections, "service")
            )

            summary = (
                _find_section_text(memory_sections, "situation abstraite")
                or _find_section_text(profile_sections, "signaux")
                or _find_section_text(profile_sections, "profil")
            )

            source_files = tuple(
                path
                for path in (
                    case_dir / "lab_profile.md",
                    case_dir / "case_memory.md",
                    case_dir / "agent_runbook.md",
                )
                if path.exists()
            )
            search_blob = " ".join(
                filter(
                    None,
                    [
                        platform,
                        slug,
                        title,
                        summary,
                        *signals,
                        *hypotheses,
                        *actions,
                        *pivots,
                        *lessons,
                        *artifacts,
                        *techniques,
                        *services,
                    ],
                )
            ).lower()

            cases.append(
                KnowledgeCase(
                    platform=platform,
                    slug=slug,
                    title=title,
                    summary=summary,
                    case_dir=case_dir,
                    source_files=source_files,
                    signals=signals,
                    hypotheses=hypotheses,
                    actions=actions,
                    pivots=pivots,
                    lessons=lessons,
                    artifacts=artifacts,
                    techniques=techniques,
                    services=services,
                    search_blob=search_blob,
                )
            )

        return cls(root_dir, cases)

    @property
    def case_count(self):
        return len(self.cases)

    def get_case(self, slug):
        normalized = _slugify(slug)
        for case in self.cases:
            if case.slug == normalized:
                return case
        return None

    def resolve_case(self, raw_query):
        query = raw_query.strip().lower()
        if not query:
            return None, []

        normalized = _slugify(query)
        exact = [
            case
            for case in self.cases
            if case.slug == normalized or case.label.lower() == query or case.title.lower() == query
        ]
        if exact:
            return exact[0], exact

        matches = [
            case
            for case in self.cases
            if query in case.slug.lower()
            or query in case.label.lower()
            or query in case.title.lower()
        ]
        if len(matches) == 1:
            return matches[0], matches
        return None, matches

    def catalog(self):
        return {
            case.slug: f"cas memoire {case.platform} - {case.title}"
            for case in self.cases
        }

    def suggest(self, raw_query, limit=3):
        query = raw_query.strip().lower()
        tokens = [token for token in re.findall(r"[a-z0-9_./-]+", query) if len(token) > 1]
        suggestions = []

        # Weighted scoring per field for more relevant matches
        field_weights = {
            "signals": 4,
            "techniques": 4,
            "services": 3,
            "hypotheses": 2,
            "actions": 2,
            "pivots": 2,
            "lessons": 1,
        }

        for case in self.cases:
            score = 0
            if query and query in case.search_blob:
                score += 8
            for token in tokens:
                if token in case.slug.lower():
                    score += 6
                if token in case.title.lower():
                    score += 6
                # Score individual fields by weight
                for field_name, weight in field_weights.items():
                    field_values = getattr(case, field_name, ())
                    if any(token in v.lower() for v in field_values):
                        score += weight

            if not tokens and not query:
                score = 1

            if score <= 0:
                continue

            suggestions.append(
                KnowledgeSuggestion(
                    case=case,
                    score=score,
                    matched_signals=_matching_items(case.signals, tokens, 2),
                    matched_hypotheses=_matching_items(case.hypotheses, tokens, 2),
                    matched_actions=_matching_items(case.actions, tokens, 2),
                    matched_pivots=_matching_items(case.pivots, tokens, 1),
                )
            )

        suggestions.sort(
            key=lambda item: (
                -item.score,
                item.case.platform.lower(),
                item.case.slug.lower(),
            )
        )
        return tuple(suggestions[:limit])
