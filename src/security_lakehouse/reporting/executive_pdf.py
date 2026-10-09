"""Executive compliance PDF export from point-in-time assessment snapshots."""

from __future__ import annotations

import io
from typing import Any
from xml.sax.saxutils import escape

_PDF_UNAVAILABLE = "Executive PDF export requires reportlab. Install with: pip install 'grc-lake[server]'"


def render_executive_pdf(assessment: dict[str, Any], *, org_name: str = "GRC Lake") -> bytes:
    """Render an audit-ready executive summary PDF from a snapshot payload."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import inch
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer
    except ImportError as exc:  # pragma: no cover - exercised when server extra missing
        raise RuntimeError(_PDF_UNAVAILABLE) from exc

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
        title="GRC Lake Executive Compliance Report",
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "ExecTitle",
        parent=styles["Title"],
        fontSize=20,
        spaceAfter=6,
    )
    subtitle_style = ParagraphStyle(
        "ExecSubtitle",
        parent=styles["Normal"],
        fontSize=10,
        textColor=colors.HexColor("#475569"),
        spaceAfter=14,
    )
    heading_style = ParagraphStyle(
        "ExecHeading",
        parent=styles["Heading2"],
        fontSize=12,
        spaceBefore=12,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "ExecBody",
        parent=styles["Normal"],
        fontSize=9,
        leading=12,
    )

    posture = assessment.get("posture") or {}
    evaluated_at = escape(str(assessment.get("evaluated_at") or "—"))
    reason = escape(str(assessment.get("snapshot_reason") or "manual"))
    assessment_hash = escape(str(assessment.get("assessment_hash") or "—"))
    catalog = assessment.get("catalog_bundle") or {}
    bundle_id = escape(str(catalog.get("bundle_id") or catalog.get("id") or "—"))

    story: list[Any] = [
        Paragraph(f"{escape(org_name)} — Executive Compliance Report", title_style),
        Paragraph(
            f"Point-in-time snapshot · {evaluated_at} · reason: {reason.replace('_', ' ')}",
            subtitle_style,
        ),
    ]

    summary_rows = [
        ["Posture score", f"{posture.get('score', '—')}%"],
        ["Posture state", str(posture.get("state", "—")).replace("_", " ")],
        ["Frameworks", str(posture.get("framework_count", 0))],
        ["Controls", str(posture.get("control_count", 0))],
        ["Assets", str(posture.get("asset_count", 0))],
        ["Open violations", str(posture.get("open_violation_count", 0))],
        ["Critical violations", str(posture.get("critical_violation_count", 0))],
        ["Stale controls", str(posture.get("stale_control_count", 0))],
    ]
    story.extend(
        [
            Paragraph("Executive summary", heading_style),
            _styled_table(summary_rows, header=("Metric", "Value")),
            Spacer(1, 8),
        ]
    )

    frameworks = assessment.get("frameworks") or []
    if frameworks:
        fw_rows = [
            [
                row.get("framework", "—"),
                f"{row.get('score', '—')}%",
                str(row.get("control_count", 0)),
                str(row.get("failing_control_count", 0)),
                str(row.get("violation_count", 0)),
            ]
            for row in frameworks
        ]
        story.extend(
            [
                Paragraph("Framework readiness", heading_style),
                _styled_table(
                    fw_rows,
                    header=("Framework", "Score", "Controls", "Failing", "Violations"),
                ),
                Spacer(1, 8),
            ]
        )

    violations = assessment.get("violations") or []
    if violations:
        top = violations[:15]
        viol_rows = [
            [
                row.get("control_id", "—"),
                row.get("severity", "—"),
                row.get("asset_id", "—"),
                row.get("environment", "—"),
            ]
            for row in top
        ]
        story.extend(
            [
                Paragraph("Open violations (top 15)", heading_style),
                _styled_table(
                    viol_rows,
                    header=("Control", "Severity", "Asset", "Environment"),
                ),
                Spacer(1, 8),
            ]
        )

    freshness = assessment.get("evidence_freshness") or {}
    stale_count = freshness.get("stale_count", posture.get("stale_evidence_count", 0))
    story.extend(
        [
            Paragraph("Evidence freshness", heading_style),
            Paragraph(
                f"Tracked sources: {escape(str(freshness.get('count', 0)))} · stale/expired: {escape(str(stale_count))}",
                body_style,
            ),
            Spacer(1, 8),
        ]
    )

    story.extend(
        [
            Paragraph("Integrity & catalog", heading_style),
            Paragraph(f"Assessment hash: <font name='Courier' size='8'>{assessment_hash}</font>", body_style),
            Paragraph(f"Catalog bundle: {bundle_id}", body_style),
            Spacer(1, 12),
            Paragraph(
                "Generated by GRC Lake from an immutable point-in-time snapshot. "
                "Verify the hash chain at GET /api/v1/snapshots/integrity.",
                ParagraphStyle(
                    "Footer",
                    parent=body_style,
                    fontSize=8,
                    textColor=colors.HexColor("#64748b"),
                ),
            ),
        ]
    )

    doc.build(story)
    return buffer.getvalue()


def _styled_table(rows: list[list[str]], *, header: tuple[str, ...]):
    from reportlab.lib import colors
    from reportlab.platypus import Table, TableStyle

    data = [list(header), *rows]
    table = Table(data, hAlign="LEFT", repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e2e8f0")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return table
