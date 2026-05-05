"""PDF report generator — produces professional PDF pentest reports.

Converts a Markdown pentest report to a formatted PDF document
using fpdf2. Falls back gracefully if fpdf2 is not installed.
"""

from datetime import datetime
from pathlib import Path

from app.findings import FindingType
from app.report_generator import (
    _evidence_excerpt,
    _evidence_findings,
    _format_evidence_attributes,
)


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}


def _fpdf2_available() -> bool:
    """Check if fpdf2 is installed."""
    try:
        import fpdf  # noqa: F401
        return True
    except ImportError:
        return False


def generate_pdf_report(
    *,
    target_summary: str,
    findings_store,
    engagement_state,
    session_duration_minutes: int = 0,
    output_path: Path,
    audit_logger=None,
    attack_plan=None,
) -> Path:
    """Generate a professional PDF pentest report.

    Parameters
    ----------
    target_summary : str
        Human-readable description of the target(s).
    findings_store : FindingsStore
        Accumulated findings from the session.
    engagement_state : EngagementState
        Phase transitions and tool usage history.
    session_duration_minutes : int
        Elapsed session time in minutes.
    output_path : Path
        Where to write the PDF file.
    audit_logger : AuditLogger, optional
        Audit trail logger for action timeline.
    attack_plan : AttackPlan, optional
        Current attack plan with step statuses.

    Returns
    -------
    Path
        The path to the written PDF file.

    Raises
    ------
    ImportError
        If fpdf2 is not installed.
    """
    if not _fpdf2_available():
        raise ImportError(
            "fpdf2 est requis pour la generation PDF. "
            "Installe-le avec: pip install fpdf2"
        )

    from fpdf import FPDF

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    # ---- Title Page ----
    pdf.set_font("Helvetica", "B", 24)
    pdf.cell(0, 20, _safe_text("Rapport de Test de Penetration"), new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.ln(5)

    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, "SECOPS Agent", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.ln(10)

    # Metadata table
    pdf.set_font("Helvetica", "", 11)
    _add_field(pdf, "Date", now)
    _add_field(pdf, "Cible", target_summary)
    _add_field(pdf, "Duree session", f"{session_duration_minutes} min")
    _add_field(pdf, "Phase finale", _safe_text(engagement_state.phase_label))
    pdf.ln(10)

    # ---- Resume Executif ----
    _section_title(pdf, "Resume Executif")

    vuln_count = len(findings_store.vulnerabilities)
    cred_count = len(findings_store.credentials)
    port_count = len(findings_store.ports)
    service_count = len(findings_store.services)
    path_count = len(findings_store.by_type(FindingType.PATH))

    stats = [
        f"{port_count} port(s) ouvert(s) identifies",
        f"{service_count} service(s) detecte(s)",
        f"{vuln_count} vulnerabilite(s) detectee(s)",
        f"{cred_count} credential(s) compromise(s)",
        f"{path_count} chemin(s) decouverts",
        f"{len(engagement_state.tools_used)} outil(s) utilise(s)",
    ]
    for stat in stats:
        _bullet_item(pdf, stat)
    pdf.ln(5)

    # ---- Risk Summary Bar ----
    if vuln_count or cred_count:
        _section_title(pdf, "Evaluation du Risque")
        if cred_count > 0:
            _risk_badge(pdf, "CRITIQUE", "Credentials compromis detectes")
        elif vuln_count >= 5:
            _risk_badge(pdf, "ELEVE", f"{vuln_count} vulnerabilites detectees")
        elif vuln_count >= 1:
            _risk_badge(pdf, "MOYEN", f"{vuln_count} vulnerabilite(s) detectee(s)")
        else:
            _risk_badge(pdf, "FAIBLE", "Aucune vulnerabilite critique")
        pdf.ln(5)

    # ---- Vulnerabilites ----
    if findings_store.vulnerabilities:
        _section_title(pdf, "Vulnerabilites Detectees")
        sorted_vulns = sorted(
            findings_store.vulnerabilities,
            key=lambda f: SEVERITY_ORDER.get(f.normalized_severity, 5),
        )
        for f in sorted_vulns:
            pdf.set_font("Helvetica", "B", 10)
            severity = f.normalized_severity.upper()
            pdf.cell(0, 7, _safe_text(f"[{severity}] {f.value[:90]}"), new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 9)
            detail = f"  Source: {f.source_tool} | Confiance: {f.effective_confidence} | Severite: {f.normalized_severity}"
            if f.target_ref:
                detail += f" | Cible: {f.target_ref}"
            detail += f" | {f.timestamp}"
            pdf.cell(0, 5, _safe_text(detail), new_x="LMARGIN", new_y="NEXT")
            pdf.ln(2)

    # ---- Credentials ----
    if findings_store.credentials:
        _section_title(pdf, "Credentials Compromis")
        for f in findings_store.credentials:
            _bullet_item(pdf, _safe_text(f"{f.value} (source: {f.source_tool})"))
        pdf.ln(3)

    # ---- Surface d'attaque ----
    if findings_store.services:
        _section_title(pdf, "Surface d'Attaque")
        # Table header
        pdf.set_font("Helvetica", "B", 10)
        col_widths = [30, 80, 60]
        headers = ["Port", "Service", "Source"]
        for i, header in enumerate(headers):
            pdf.cell(col_widths[i], 7, header, border=1)
        pdf.ln()

        # Table rows
        pdf.set_font("Helvetica", "", 9)
        for f in findings_store.services:
            parts = f.value.split("/", 1)
            port = parts[0] if len(parts) == 2 else "-"
            svc = parts[1] if len(parts) == 2 else f.value
            pdf.cell(col_widths[0], 6, _safe_text(str(port)[:30]), border=1)
            pdf.cell(col_widths[1], 6, _safe_text(svc[:80]), border=1)
            pdf.cell(col_widths[2], 6, _safe_text(f.source_tool[:60]), border=1)
            pdf.ln()
        pdf.ln(5)

    # ---- Chemins decouverts ----
    paths = findings_store.by_type(FindingType.PATH)
    if paths:
        _section_title(pdf, "Chemins Decouverts")
        for f in paths:
            _bullet_item(pdf, _safe_text(f"{f.value} (source: {f.source_tool})"))
        pdf.ln(3)

    # ---- OS ----
    os_findings = findings_store.by_type(FindingType.OS)
    if os_findings:
        _section_title(pdf, "Systeme d'Exploitation")
        for f in os_findings:
            _bullet_item(pdf, _safe_text(f"{f.value} (source: {f.source_tool})"))
        pdf.ln(3)

    # ---- Timeline des phases ----
    if engagement_state.phase_history:
        _section_title(pdf, "Timeline des Phases")
        for transition in engagement_state.phase_history:
            _bullet_item(
                pdf,
                _safe_text(f"{transition.from_phase.value} -> {transition.to_phase.value}: {transition.reason}"),
            )
        pdf.ln(3)

    # ---- Plan d'attaque ----
    if attack_plan and getattr(attack_plan, "steps", None):
        _section_title(pdf, "Plan d'Attaque")
        pdf.set_font("Helvetica", "", 9)
        pdf.multi_cell(
            0,
            5,
            _safe_text(f"Cible planifiee: {attack_plan.target} | Progression: {attack_plan.progress_summary}"),
        )
        pdf.ln(1)
        for step in attack_plan.steps[:25]:
            line = (
                f"#{step.index} [{step.status.value}] [{step.priority.value}] "
                f"{step.tool}: {step.name}"
            )
            pdf.set_font("Helvetica", "", 8)
            pdf.multi_cell(0, 4, _safe_text(line))
        pdf.ln(3)

    # ---- Preuves ----
    evidence_findings = _evidence_findings(findings_store, limit=12)
    if evidence_findings:
        _section_title(pdf, "Preuves")
        for index, f in enumerate(evidence_findings, start=1):
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(
                0,
                5,
                _safe_text(f"Preuve {index} - {f.finding_type.value}: {f.value[:90]}"),
            )
            pdf.set_font("Helvetica", "", 8)
            detail = (
                f"Source: {f.source_tool} | Confiance: {f.effective_confidence} | "
                f"Severite: {f.normalized_severity}"
            )
            if f.target_ref:
                detail += f" | Cible: {f.target_ref}"
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(0, 4, _safe_text(detail))
            attributes = _format_evidence_attributes(f)
            if attributes:
                pdf.set_x(pdf.l_margin)
                pdf.multi_cell(0, 4, _safe_text(f"Attributs: {attributes}"))
            excerpt = _evidence_excerpt(f, max_lines=4, max_chars=300)
            if excerpt:
                pdf.set_font("Courier", "", 7)
                pdf.set_x(pdf.l_margin)
                pdf.multi_cell(0, 4, _safe_text(excerpt))
            pdf.ln(2)

    # ---- Outils utilises ----
    if engagement_state.tools_used:
        _section_title(pdf, "Outils Utilises")
        tools_text = ", ".join(engagement_state.tools_used)
        pdf.set_font("Helvetica", "", 10)
        pdf.multi_cell(0, 6, tools_text)
        pdf.ln(3)

    # ---- Audit timeline ----
    if audit_logger and audit_logger.count:
        _section_title(pdf, "Timeline des Actions")
        for entry in audit_logger.entries[:50]:
            ts = entry.timestamp
            etype = entry.event_type
            tool = entry.tool_name
            summary = entry.result_summary[:100]
            if etype == "tool_call":
                cmd = entry.arguments.get("command", "")
                line = f"{ts} [{tool}] {cmd[:60]} - {summary}" if cmd else f"{ts} [{tool}] {summary}"
            elif etype == "finding":
                line = f"{ts} Decouverte ({tool}): {summary}"
            elif etype == "phase_change":
                line = f"{ts} Phase: {summary}"
            else:
                line = f"{ts} [{etype}] {summary}"
            pdf.set_font("Helvetica", "", 8)
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(0, 4, _safe_text(line))
        pdf.ln(3)

    # ---- Recommandations ----
    _section_title(pdf, "Recommandations")
    if vuln_count:
        _bullet_item(pdf, "Corriger les vulnerabilites identifiees par ordre de severite.")
    if cred_count:
        _bullet_item(pdf, "Changer immediatement les credentials compromis.")
    if not vuln_count and not cred_count:
        _bullet_item(pdf, "Aucune vulnerabilite critique detectee a ce stade.")
    _bullet_item(pdf, "Effectuer un re-test apres remediation.")

    # ---- Write PDF ----
    output_path.parent.mkdir(parents=True, exist_ok=True)
    pdf.output(str(output_path))
    return output_path


def _safe_text(text: str) -> str:
    """Sanitize text for Helvetica (latin-1 only) by replacing unsupported chars."""
    replacements = {
        "\u2192": "->",   # →
        "\u2022": "-",    # •
        "\u2014": "--",   # —
        "\u2013": "-",    # –
        "\u2018": "'",    # '
        "\u2019": "'",    # '
        "\u201c": '"',    # "
        "\u201d": '"',    # "
        "\u2026": "...",  # …
    }
    for char, replacement in replacements.items():
        text = text.replace(char, replacement)
    # Final fallback: replace any remaining non-latin-1 chars
    try:
        text.encode("latin-1")
    except UnicodeEncodeError:
        text = text.encode("latin-1", errors="replace").decode("latin-1")
    return text


# ---- PDF Helper Functions ----

def _section_title(pdf, title: str) -> None:
    """Add a section title to the PDF."""
    pdf.set_font("Helvetica", "B", 13)
    pdf.ln(3)
    pdf.set_x(pdf.l_margin)
    pdf.cell(0, 10, _safe_text(title), new_x="LMARGIN", new_y="NEXT")
    # Underline
    pdf.set_draw_color(70, 130, 180)
    pdf.set_line_width(0.5)
    pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
    pdf.set_x(pdf.l_margin)
    pdf.ln(3)


def _add_field(pdf, label: str, value: str) -> None:
    """Add a label: value field."""
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(40, 7, f"{label}:")
    pdf.set_font("Helvetica", "", 11)
    pdf.cell(0, 7, value, new_x="LMARGIN", new_y="NEXT")


def _bullet_item(pdf, text: str) -> None:
    """Add a bullet point item."""
    pdf.set_font("Helvetica", "", 10)
    pdf.set_x(pdf.l_margin)
    pdf.multi_cell(0, 6, f"  - {_safe_text(text)}")


def _risk_badge(pdf, level: str, description: str) -> None:
    """Add a risk level badge."""
    colors = {
        "CRITIQUE": (220, 50, 50),
        "ELEVE": (255, 140, 0),
        "MOYEN": (255, 200, 0),
        "FAIBLE": (50, 180, 50),
    }
    r, g, b = colors.get(level, (128, 128, 128))

    pdf.set_fill_color(r, g, b)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(30, 8, f" {level} ", fill=True)
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Helvetica", "", 11)
    pdf.cell(0, 8, f"  {description}", new_x="LMARGIN", new_y="NEXT")
    pdf.set_fill_color(255, 255, 255)
