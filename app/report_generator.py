"""
Forensic Report Generator — produces a structured PDF report from a
completed analysis result, suitable for institutional action, legal
review, or handoff to law enforcement (as called for in the PS).

Uses reportlab (pure Python — no external binary like wkhtmltopdf needed,
which matters since this has to run reliably wherever we deploy it).
"""

import io
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
)

VERDICT_COLORS = {
    "Malicious": colors.HexColor("#C62828"),
    "Suspicious": colors.HexColor("#F57F17"),
    "Safe": colors.HexColor("#2E7D32"),
}


def _build_styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="ReportTitle", fontSize=18, spaceAfter=4, fontName="Helvetica-Bold"))
    styles.add(ParagraphStyle(name="SectionHeading", fontSize=13, spaceBefore=14, spaceAfter=6, fontName="Helvetica-Bold"))
    styles.add(ParagraphStyle(name="MetaText", fontSize=9, textColor=colors.grey))
    styles.add(ParagraphStyle(name="BodyTextSmall", fontSize=10, leading=14))
    return styles


def generate_pdf_report(case):
    """
    case: a dict from case_db.get_case() — must include summary fields
    (id, analyzed_at, filename, verdict, fraud_score) and 'full_result'
    (the complete analyze_email() output dict).

    Returns raw PDF bytes, ready to send as an HTTP response or save to disk.
    """
    styles = _build_styles()
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.75 * inch, bottomMargin=0.75 * inch)
    elements = []

    full = case.get("full_result") or {}
    verdict = case.get("verdict", "Unknown")
    score = case.get("fraud_score", 0)
    verdict_color = VERDICT_COLORS.get(verdict, colors.black)

    elements.append(Paragraph("Email Threat Forensics — Case Report", styles["ReportTitle"]))
    elements.append(Paragraph(
        f"Case #{case.get('id', 'N/A')} &nbsp;|&nbsp; Analyzed: {case.get('analyzed_at', 'N/A')} "
        f"&nbsp;|&nbsp; File: {case.get('filename', 'N/A')}",
        styles["MetaText"]
    ))
    elements.append(Spacer(1, 12))

    verdict_style = ParagraphStyle(
        name="Verdict", fontSize=20, fontName="Helvetica-Bold",
        textColor=verdict_color, spaceAfter=4,
    )
    elements.append(Paragraph(f"VERDICT: {verdict.upper()}", verdict_style))
    elements.append(Paragraph(f"Fraud Score: {score} / 100", styles["BodyTextSmall"]))
    elements.append(Spacer(1, 10))

    identity = full.get("identity", {})
    elements.append(Paragraph("Sender Identity", styles["SectionHeading"]))
    identity_table_data = [
        ["From", identity.get("from", "N/A")],
        ["Reply-To", identity.get("reply_to", "N/A") or "(none)"],
        ["Return-Path", identity.get("return_path", "N/A") or "(none)"],
        ["Subject", full.get("subject", "N/A")],
    ]
    identity_table = Table(identity_table_data, colWidths=[1.3 * inch, 5 * inch])
    identity_table.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor("#DDDDDD")),
    ]))
    elements.append(identity_table)

    elements.append(Paragraph("Evidence", styles["SectionHeading"]))
    reasons = full.get("threat_assessment", {}).get("reasons", [])
    if reasons:
        for reason in reasons:
            elements.append(Paragraph(f"• {reason}", styles["BodyTextSmall"]))
    else:
        elements.append(Paragraph("No specific risk indicators recorded.", styles["BodyTextSmall"]))

    elements.append(Paragraph("Sender Trace Path", styles["SectionHeading"]))
    chain = full.get("received_chain", [])
    if chain:
        chain_data = [["Hop", "IP(s)", "Timestamp"]]
        for hop in chain:
            chain_data.append([
                str(hop.get("hop_number", "?")),
                ", ".join(hop.get("ips_found", [])) or "(none found)",
                hop.get("timestamp", "N/A") or "N/A",
            ])
        chain_table = Table(chain_data, colWidths=[0.6 * inch, 2.2 * inch, 3.5 * inch])
        chain_table.setStyle(TableStyle([
            ("FONTSIZE", (0, 0), (-1, -1), 8.5),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F0F0F0")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#DDDDDD")),
        ]))
        elements.append(chain_table)
    else:
        elements.append(Paragraph("No relay chain data available.", styles["BodyTextSmall"]))

    elements.append(Paragraph("Estimated Origin", styles["SectionHeading"]))
    geo = full.get("geolocation") or {}
    if geo and not geo.get("error"):
        origin_text = (
            f"{geo.get('city', 'Unknown')}, {geo.get('region', '')}, {geo.get('country', 'Unknown')} "
            f"(IP: {geo.get('ip', 'N/A')}, ISP: {geo.get('isp', 'N/A')})<br/>"
            f"VPN/Proxy: {geo.get('is_proxy_or_vpn', False)} &nbsp;|&nbsp; "
            f"Hosting Provider: {geo.get('is_hosting_provider', False)}"
        )
    else:
        origin_text = "Origin could not be determined."
    elements.append(Paragraph(origin_text, styles["BodyTextSmall"]))

    elements.append(Paragraph("Domain Intelligence", styles["SectionHeading"]))
    domain_info = full.get("domain_intelligence") or {}
    whois_info = domain_info.get("whois", {})
    dns_info = domain_info.get("dns", {})
    if whois_info.get("error"):
        domain_text = f"WHOIS: unavailable ({whois_info['error'][:80]}...)<br/>"
    else:
        domain_text = (
            f"Registrar: {whois_info.get('registrar', 'Unknown')} &nbsp;|&nbsp; "
            f"Domain age: {whois_info.get('domain_age_days', 'Unknown')} days<br/>"
        )
    domain_text += f"MX records present: {dns_info.get('has_mx_records', False)}"
    elements.append(Paragraph(domain_text, styles["BodyTextSmall"]))

    elements.append(Paragraph("Identity Correlation", styles["SectionHeading"]))
    correlation = full.get("correlation") or {}
    correlation_text = (
        f"Same domain seen in {correlation.get('same_domain_count', 0)} prior case(s) &nbsp;|&nbsp; "
        f"Same IP seen in {correlation.get('same_ip_count', 0)} prior case(s)<br/>"
        f"Linked entities: {', '.join(correlation.get('linked_entities', [])) or '(none)'}"
    )
    elements.append(Paragraph(correlation_text, styles["BodyTextSmall"]))

    elements.append(Paragraph("Chain of Custody", styles["SectionHeading"]))
    evidence_hash = case.get("evidence_hash") or full.get("evidence_hash") or "Not recorded"
    custody_text = (
        f"Evidence Integrity Hash (SHA-256): <font face='Courier'>{evidence_hash}</font><br/>"
        f"This hash was computed from the original uploaded file at the moment of analysis. "
        f"If this file is re-hashed later and the value differs, the evidence has been altered."
    )
    elements.append(Paragraph(custody_text, styles["BodyTextSmall"]))

    elements.append(Spacer(1, 20))
    elements.append(Paragraph(
        "This report was generated automatically by the Email Threat Forensics platform. "
        "It is intended to support investigation and is not a substitute for professional legal or forensic review. "
        "Personally identifiable information in this report should be handled in accordance with your "
        "organization's data retention and privacy policies.",
        styles["MetaText"]
    ))

    doc.build(elements)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes


if __name__ == "__main__":
    fake_case = {
        "id": 1,
        "analyzed_at": datetime.now().isoformat(),
        "filename": "sample_phishing.eml",
        "verdict": "Malicious",
        "fraud_score": 100,
        "evidence_hash": "9fbd53726ad480b63fa69da6c630532b8445b27f4be02ea71df234a5bd358c26",
        "full_result": {
            "subject": "Urgent: Your account has been limited - Action required",
            "identity": {
                "from": "PayPal Security <accounts@paypa1-secure.com>",
                "reply_to": "recovery-support@paypa1-secure.com",
                "return_path": "<accounts@paypa1-secure.com>",
            },
            "threat_assessment": {
                "reasons": [
                    "SPF check failed (+30)",
                    "DKIM missing or invalid (+20)",
                    "ML classifier flagged body text as phishing with 95% confidence (+24)",
                ]
            },
            "received_chain": [
                {"hop_number": 1, "ips_found": ["103.216.92.10"], "timestamp": "2026-09-11T10:14:15+00:00"},
                {"hop_number": 2, "ips_found": ["185.220.101.47"], "timestamp": "2026-09-11T03:14:20-07:00"},
            ],
            "geolocation": {
                "city": "New Delhi", "region": "Delhi", "country": "India",
                "ip": "103.216.92.10", "isp": "Bharat Communication Systems",
                "is_proxy_or_vpn": False, "is_hosting_provider": False,
            },
            "domain_intelligence": {
                "whois": {"error": "WHOIS lookup failed: No match"},
                "dns": {"has_mx_records": False},
            },
            "correlation": {"same_domain_count": 1, "same_ip_count": 1, "linked_entities": []},
        },
    }

    pdf_bytes = generate_pdf_report(fake_case)
    with open("test_report.pdf", "wb") as f:
        f.write(pdf_bytes)
    print(f"Generated PDF: {len(pdf_bytes)} bytes, saved to test_report.pdf")