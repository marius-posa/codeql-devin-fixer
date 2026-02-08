"""PDF report generation for the telemetry dashboard.

Produces a compliance-grade summary PDF containing overall statistics,
severity/category breakdowns, and a full issues table.
"""

import io
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)


_SEVERITY_ORDER = ["critical", "high", "medium", "low"]
_SEV_COLORS = {
    "critical": colors.HexColor("#cf222e"),
    "high": colors.HexColor("#9a6700"),
    "medium": colors.HexColor("#8250df"),
    "low": colors.HexColor("#0969da"),
}


def _header_style() -> ParagraphStyle:
    base = getSampleStyleSheet()
    return ParagraphStyle(
        "ReportHeader",
        parent=base["Heading1"],
        fontSize=18,
        spaceAfter=6,
    )


def _section_style() -> ParagraphStyle:
    base = getSampleStyleSheet()
    return ParagraphStyle(
        "SectionHeader",
        parent=base["Heading2"],
        fontSize=13,
        spaceBefore=14,
        spaceAfter=6,
    )


def _body_style() -> ParagraphStyle:
    base = getSampleStyleSheet()
    return ParagraphStyle(
        "BodyText",
        parent=base["BodyText"],
        fontSize=9,
        leading=12,
    )


def _make_breakdown_table(data: dict, title: str) -> list:
    if not data:
        return []
    elements: list = []
    elements.append(Paragraph(title, _section_style()))
    rows = [["Category", "Count"]]
    order = _SEVERITY_ORDER if title.lower().startswith("sev") else []
    if order:
        sorted_keys = sorted(data.keys(), key=lambda k: order.index(k) if k in order else 99)
    else:
        sorted_keys = sorted(data.keys(), key=lambda k: -data[k])
    for key in sorted_keys:
        rows.append([key.capitalize(), str(data[key])])
    t = Table(rows, colWidths=[2.5 * inch, 1.2 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2328")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ALIGN", (1, 0), (1, -1), "RIGHT"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f6f8fa")]),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    elements.append(t)
    return elements


def _make_issues_table(issues: list[dict]) -> list:
    if not issues:
        return [Paragraph("No issues tracked.", _body_style())]
    elements: list = []
    elements.append(Paragraph("Issues", _section_style()))
    headers = ["Rule", "Severity", "Status", "Category", "File", "Line", "Seen"]
    rows = [headers]
    for iss in issues:
        filename = iss.get("file", "")
        if filename and len(filename) > 40:
            filename = "..." + filename[-37:]
        rows.append([
            iss.get("rule_id", "-")[:30],
            (iss.get("severity_tier") or "-").capitalize(),
            iss.get("status", "-"),
            iss.get("cwe_family", "-"),
            filename or "-",
            str(iss.get("start_line", "-")),
            str(iss.get("appearances", 1)) + "x",
        ])
    col_widths = [1.3 * inch, 0.7 * inch, 0.7 * inch, 0.9 * inch, 1.8 * inch, 0.5 * inch, 0.5 * inch]
    t = Table(rows, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2328")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f6f8fa")]),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    elements.append(t)
    return elements


def generate_pdf(
    stats: dict,
    issues: list[dict],
    repo_filter: str = "",
) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
    )

    elements: list = []

    title = "CodeQL Devin Fixer — Security Report"
    if repo_filter:
        short = repo_filter.replace("https://github.com/", "")
        title += f" ({short})"
    elements.append(Paragraph(title, _header_style()))
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    elements.append(Paragraph(f"Generated: {generated}", _body_style()))
    elements.append(Spacer(1, 12))

    elements.append(Paragraph("Summary", _section_style()))
    summary_rows = [
        ["Metric", "Value"],
        ["Repositories Scanned", str(stats.get("repos_scanned", 0))],
        ["Total Runs", str(stats.get("total_runs", 0))],
        ["Total Issues Found", str(stats.get("total_issues", 0))],
        ["Current Issues", str(stats.get("latest_issues", stats.get("total_issues", 0)))],
        ["Devin Sessions Created", str(stats.get("sessions_created", 0))],
        ["Sessions Finished", str(stats.get("sessions_finished", 0))],
        ["PRs Created", str(stats.get("prs_total", 0))],
        ["PRs Merged", str(stats.get("prs_merged", 0))],
        ["Fix Rate", f"{stats.get('fix_rate', 0)}%"],
    ]
    t = Table(summary_rows, colWidths=[3 * inch, 2 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2328")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ALIGN", (1, 0), (1, -1), "RIGHT"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f6f8fa")]),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 8))

    sev = stats.get("severity_breakdown", {})
    elements.extend(_make_breakdown_table(sev, "Severity Breakdown"))

    cat = stats.get("category_breakdown", {})
    elements.extend(_make_breakdown_table(cat, "Category Breakdown"))

    if issues:
        elements.append(PageBreak())
    elements.extend(_make_issues_table(issues))

    doc.build(elements)
    return buf.getvalue()
