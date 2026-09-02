from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from datetime import datetime
from models import Scan, Vulnerability


def generate_pdf_report(scan: Scan, output_path: str):
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
    )

    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="CustomTitle",
            parent=styles["Heading1"],
            fontSize=18,
            spaceAfter=12,
            textColor=colors.darkblue,
        )
    )
    styles.add(
        ParagraphStyle(
            name="SubTitle",
            parent=styles["Heading2"],
            fontSize=12,
            spaceAfter=6,
            textColor=colors.gray,
        )
    )

    elements = []

    # Title
    elements.append(Paragraph("SecureCode Scanner X – Security Report", styles["CustomTitle"]))
    elements.append(Paragraph(f"Scan: {scan.scan_name}", styles["SubTitle"]))
    elements.append(Paragraph(f"File: {scan.file_name}", styles["SubTitle"]))
    elements.append(Paragraph(f"Language: {scan.language}", styles["SubTitle"]))
    elements.append(Paragraph(f"Date: {scan.created_at.strftime('%Y-%m-%d %H:%M')}", styles["SubTitle"]))
    elements.append(Spacer(1, 0.2 * inch))

    # Security Score
    score_data = [
        ["Security Score", str(scan.security_score)],
        ["Risk Level", scan.risk_level],
        ["Total Vulnerabilities", str(scan.total_vulnerabilities)],
        ["Critical", str(scan.critical_count)],
        ["High", str(scan.high_count)],
        ["Medium", str(scan.medium_count)],
        ["Low", str(scan.low_count)],
    ]
    score_table = Table(score_data, colWidths=[2.5 * inch, 2 * inch])
    score_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ]
        )
    )
    elements.append(score_table)
    elements.append(Spacer(1, 0.3 * inch))

    # Vulnerabilities
    elements.append(Paragraph("Vulnerabilities", styles["Heading2"]))

    vuln_data = [["Severity", "Vulnerability", "File", "Line", "CWE"]]
    for v in scan.vulnerabilities.order_by(Vulnerability.severity, Vulnerability.line_number):
        vuln_data.append(
            [v.severity, v.vuln_name, v.file_name, str(v.line_number), v.cwe_id or ""]
        )

    vuln_table = Table(
        vuln_data,
        colWidths=[0.8 * inch, 2.2 * inch, 2.2 * inch, 0.6 * inch, 1.2 * inch],
    )
    vuln_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ]
        )
    )
    elements.append(vuln_table)
    elements.append(Spacer(1, 0.3 * inch))

    # Recommendations
    elements.append(Paragraph("Key Recommendations", styles["Heading2"]))
    recs = set()
    for v in scan.vulnerabilities:
        recs.add(v.remediation)
    for i, r in enumerate(list(recs)[:10], start=1):
        elements.append(Paragraph(f"{i}. {r}", styles["Normal"]))
        elements.append(Spacer(1, 0.1 * inch))

    doc.build(elements)