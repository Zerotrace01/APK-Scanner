"""
DroidScan — report_generator.py
=================================
Generates a court-ready PDF forensic report from analysis results.

Dependencies:
    pip install reportlab
"""

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer,
    Table, TableStyle, HRFlowable,
)
from datetime import datetime

BRAND   = colors.HexColor("#BA7517")
DARK    = colors.HexColor("#1A1A1A")
RED     = colors.HexColor("#A32D2D")
GREEN   = colors.HexColor("#1D9E75")
AMBER   = colors.HexColor("#BA7517")
LIGHT   = colors.HexColor("#F5F5F5")
BORDER  = colors.HexColor("#DDDDDD")


def _verdict_color(verdict: str):
    return {
        "MALICIOUS":  RED,
        "SUSPICIOUS": AMBER,
        "BENIGN":     GREEN,
    }.get(verdict, colors.grey)


def generate_pdf_report(results: dict, output_path: str):
    doc    = SimpleDocTemplate(
        output_path, pagesize=A4,
        leftMargin=20*mm, rightMargin=20*mm,
        topMargin=20*mm, bottomMargin=20*mm,
    )
    styles = getSampleStyleSheet()
    story  = []

    title_s  = ParagraphStyle("title", parent=styles["Heading1"],
                               fontSize=20, textColor=DARK)
    h2_s     = ParagraphStyle("h2", parent=styles["Heading2"],
                               fontSize=13, textColor=BRAND, spaceAfter=6)
    body_s   = styles["BodyText"]
    footer_s = ParagraphStyle("footer", parent=styles["Normal"],
                               fontSize=8, textColor=colors.grey)

    # ── Header ───────────────────────────────────────────────────────────────
    story.append(Paragraph("DroidScan — Forensic APK Analysis Report", title_s))
    story.append(Paragraph(
        f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        body_s,
    ))
    story.append(Spacer(1, 6*mm))
    story.append(HRFlowable(width="100%", color=BRAND))
    story.append(Spacer(1, 4*mm))

    # ── Verdict banner ───────────────────────────────────────────────────────
    verdict = results.get("verdict", "UNKNOWN")
    score   = results.get("final_score", 0)
    vc      = _verdict_color(verdict)
    story.append(Table(
        [[f"VERDICT: {verdict}   |   Risk Score: {score}/100"]],
        colWidths=["100%"],
        style=TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), vc),
            ("TEXTCOLOR",     (0, 0), (-1, -1), colors.white),
            ("FONTSIZE",      (0, 0), (-1, -1), 14),
            ("FONTNAME",      (0, 0), (-1, -1), "Helvetica-Bold"),
            ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
            ("TOPPADDING",    (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ]),
    ))
    story.append(Spacer(1, 6*mm))

    # ── App metadata ─────────────────────────────────────────────────────────
    story.append(Paragraph("Application Metadata", h2_s))
    meta = results.get("static", {}).get("meta", {})
    if meta:
        meta_rows = [[k.replace("_", " ").title(), str(v)] for k, v in meta.items()]
        story.append(Table(meta_rows, colWidths=[60*mm, 110*mm],
            style=TableStyle([
                ("FONTSIZE",       (0, 0), (-1, -1), 9),
                ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, LIGHT]),
                ("GRID",           (0, 0), (-1, -1), 0.5, BORDER),
                ("FONTNAME",       (0, 0), (0, -1),  "Helvetica-Bold"),
            ]),
        ))
    story.append(Spacer(1, 5*mm))

    # ── Obfuscation ───────────────────────────────────────────────────────────
    story.append(Paragraph("Obfuscation Analysis", h2_s))
    obf = results.get("static", {}).get("obfuscation", {})
    obf_level = obf.get("obfuscation_level", "UNKNOWN")
    obf_score = obf.get("obfuscation_score", 0)
    obf_color = RED if obf_level == "HEAVY" else AMBER if obf_level == "MODERATE" else GREEN
    story.append(Table(
        [[f"Level: {obf_level}   |   Score: {obf_score}/100   |   {obf.get('summary', '')}"]],
        colWidths=["100%"],
        style=TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), obf_color),
            ("TEXTCOLOR",     (0, 0), (-1, -1), colors.white),
            ("FONTSIZE",      (0, 0), (-1, -1), 10),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]),
    ))
    story.append(Spacer(1, 5*mm))

    # ── Dangerous permissions ─────────────────────────────────────────────────
    story.append(Paragraph("Dangerous Permissions", h2_s))
    flagged = results.get("static", {}).get("permissions", {}).get("flagged", [])
    if flagged:
        rows = [["Permission", "Risk"]] + [
            [p["permission"].split(".")[-1], p["risk"]] for p in flagged
        ]
        story.append(Table(rows, colWidths=[80*mm, 90*mm],
            style=TableStyle([
                ("FONTSIZE",       (0, 0), (-1, -1), 9),
                ("BACKGROUND",     (0, 0), (-1,  0), BRAND),
                ("TEXTCOLOR",      (0, 0), (-1,  0), colors.white),
                ("FONTNAME",       (0, 0), (-1,  0), "Helvetica-Bold"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#FFF8EE")]),
                ("GRID",           (0, 0), (-1, -1), 0.5, BORDER),
            ]),
        ))
    else:
        story.append(Paragraph("No dangerous permissions detected.", body_s))
    story.append(Spacer(1, 5*mm))

    # ── Correlation patterns ──────────────────────────────────────────────────
    story.append(Paragraph("Attack Pattern Correlation", h2_s))
    confirmed = results.get("correlation", {}).get("confirmed", [])
    if confirmed:
        rows = [["ID", "Pattern", "Severity", "Confidence"]] + [
            [p["id"], p["name"], p["severity"], f"{p['confidence']}%"]
            for p in confirmed
        ]
        story.append(Table(rows, colWidths=[18*mm, 100*mm, 28*mm, 24*mm],
            style=TableStyle([
                ("FONTSIZE",       (0, 0), (-1, -1), 9),
                ("BACKGROUND",     (0, 0), (-1,  0), RED),
                ("TEXTCOLOR",      (0, 0), (-1,  0), colors.white),
                ("FONTNAME",       (0, 0), (-1,  0), "Helvetica-Bold"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#FFF0F0")]),
                ("GRID",           (0, 0), (-1, -1), 0.5, BORDER),
            ]),
        ))
    else:
        story.append(Paragraph("No attack patterns confirmed.", body_s))
    story.append(Spacer(1, 5*mm))

    # ── C2 indicators ─────────────────────────────────────────────────────────
    story.append(Paragraph("C2 Indicators", h2_s))
    c2_hits = results.get("c2", {}).get("c2_indicators", [])
    if c2_hits:
        rows = [["ID", "Name", "Severity"]] + [
            [h["id"], h["name"], h["severity"]] for h in c2_hits
        ]
        story.append(Table(rows, colWidths=[20*mm, 120*mm, 30*mm],
            style=TableStyle([
                ("FONTSIZE",       (0, 0), (-1, -1), 9),
                ("BACKGROUND",     (0, 0), (-1,  0), RED),
                ("TEXTCOLOR",      (0, 0), (-1,  0), colors.white),
                ("FONTNAME",       (0, 0), (-1,  0), "Helvetica-Bold"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#FFF0F0")]),
                ("GRID",           (0, 0), (-1, -1), 0.5, BORDER),
            ]),
        ))
    else:
        story.append(Paragraph("No C2 indicators detected.", body_s))
    story.append(Spacer(1, 5*mm))

    # ── MITRE ATT&CK ──────────────────────────────────────────────────────────
    story.append(Paragraph("MITRE ATT&CK for Mobile — Technique Mapping", h2_s))
    mitre = results.get("c2", {}).get("mitre_tags", [])
    if mitre:
        rows = [["Technique ID", "Name", "Tactic"]] + [
            [t["technique_id"], t["name"], t["tactic"]] for t in mitre
        ]
        story.append(Table(rows, colWidths=[30*mm, 100*mm, 40*mm],
            style=TableStyle([
                ("FONTSIZE",       (0, 0), (-1, -1), 9),
                ("BACKGROUND",     (0, 0), (-1,  0), DARK),
                ("TEXTCOLOR",      (0, 0), (-1,  0), colors.white),
                ("FONTNAME",       (0, 0), (-1,  0), "Helvetica-Bold"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT]),
                ("GRID",           (0, 0), (-1, -1), 0.5, BORDER),
            ]),
        ))
    story.append(Spacer(1, 5*mm))

    # ── Footer ────────────────────────────────────────────────────────────────
    story.append(HRFlowable(width="100%", color=BRAND))
    story.append(Spacer(1, 3*mm))
    story.append(Paragraph(
        "This report was generated by DroidScan v1.0 — CideCode 2K26 Submission. "
        "Chain-of-custody maintained via SHA-256 hash verification. "
        "All data collected is based on submitted APK file and sandbox analysis.",
        footer_s,
    ))

    doc.build(story)
    print(f"[+] PDF report saved: {output_path}")
