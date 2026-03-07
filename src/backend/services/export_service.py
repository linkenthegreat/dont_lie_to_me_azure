"""Export service for generating PDF and CSV reports."""

import csv
import io
import logging
from datetime import datetime, timezone
from typing import List

logger = logging.getLogger(__name__)


def generate_csv_report(analyses: List[dict]) -> str:
    """Generate CSV report from analysis results."""
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "Timestamp", "Endpoint", "Input Text (truncated)",
        "Classification", "Confidence", "Reasoning/Summary",
    ])

    for a in analyses:
        result = a.get("result", {})
        writer.writerow([
            a.get("timestamp", ""),
            a.get("endpoint", ""),
            a.get("inputText", "")[:200],
            result.get("classification", result.get("overall_verdict", "")),
            result.get("confidence", ""),
            result.get("reasoning", result.get("summary", ""))[:200],
        ])

    return output.getvalue()


def generate_pdf_report(analyses: List[dict]) -> bytes:
    """Generate PDF report from analysis results using reportlab."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer,
    )
    from reportlab.lib.styles import getSampleStyleSheet

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    styles = getSampleStyleSheet()
    elements = []

    # Title
    elements.append(Paragraph(
        "Don't Lie To Me &ndash; Scam Analysis Report", styles["Title"]
    ))
    elements.append(Paragraph(
        f"Generated: {datetime.now(timezone.utc).isoformat()}Z", styles["Normal"]
    ))
    elements.append(Spacer(1, 20))

    # Summary stats
    total = len(analyses)
    scam_count = sum(
        1 for a in analyses
        if a.get("result", {}).get("classification") in ("SCAM", "LIKELY_SCAM")
    )
    elements.append(Paragraph(f"Total analyses: {total}", styles["Normal"]))
    elements.append(Paragraph(
        f"Scam / Likely Scam detected: {scam_count}", styles["Normal"]
    ))
    elements.append(Spacer(1, 20))

    # Table
    data = [["Timestamp", "Type", "Classification", "Confidence"]]
    for a in analyses[:50]:
        r = a.get("result", {})
        data.append([
            a.get("timestamp", "")[:19],
            a.get("endpoint", ""),
            r.get("classification", "N/A"),
            str(r.get("confidence", "")),
        ])

    table = Table(data, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0078d4")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f0f4f8")]),
    ]))
    elements.append(table)

    doc.build(elements)
    return buffer.getvalue()
