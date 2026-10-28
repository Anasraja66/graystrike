"""
PDF Report Generator Service
Generates professional executive & developer cybersecurity assessment reports using ReportLab.
"""
from io import BytesIO
from datetime import datetime, timezone
from typing import List, Dict, Any
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)


class ReportGenerator:
    @staticmethod
    def generate_pdf(
        target_url: str,
        org_name: str,
        scan_date: str,
        findings: List[Dict[str, Any]],
        pages_crawled: int = 1
    ) -> bytes:
        """Generate a complete professional PDF security audit report."""
        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=40,
            leftMargin=40,
            topMargin=40,
            bottomMargin=40
        )

        styles = getSampleStyleSheet()

        # Custom typography styles
        title_style = ParagraphStyle(
            "ReportTitle",
            parent=styles["Heading1"],
            fontSize=24,
            leading=28,
            textColor=colors.HexColor("#0f172a"),
            fontName="Helvetica-Bold",
            spaceAfter=6
        )

        subtitle_style = ParagraphStyle(
            "ReportSubtitle",
            parent=styles["Normal"],
            fontSize=11,
            leading=15,
            textColor=colors.HexColor("#64748b"),
            spaceAfter=15
        )

        h2_style = ParagraphStyle(
            "SectionHeader",
            parent=styles["Heading2"],
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#1e293b"),
            fontName="Helvetica-Bold",
            spaceBefore=12,
            spaceAfter=6
        )

        body_style = ParagraphStyle(
            "ReportBody",
            parent=styles["Normal"],
            fontSize=9.5,
            leading=13,
            textColor=colors.HexColor("#334155")
        )

        elements = []

        # Header Title
        elements.append(Paragraph("APT Agents — Security Assessment Report", title_style))
        elements.append(Paragraph(f"Autonomous Web Application Penetration Test | Confidential", subtitle_style))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#2563eb"), spaceAfter=15))

        # Metadata Table
        meta_data = [
            [Paragraph("<b>Target Application:</b>", body_style), Paragraph(target_url, body_style)],
            [Paragraph("<b>Organization:</b>", body_style), Paragraph(org_name, body_style)],
            [Paragraph("<b>Assessment Date:</b>", body_style), Paragraph(scan_date, body_style)],
            [Paragraph("<b>Pages Analyzed:</b>", body_style), Paragraph(str(pages_crawled), body_style)],
        ]
        meta_table = Table(meta_data, colWidths=[130, 390])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ('PADDING', (0, 0), (-1, -1), 6),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#f1f5f9")),
        ]))
        elements.append(meta_table)
        elements.append(Spacer(1, 15))

        # Severity Summary
        critical = sum(1 for f in findings if f.get("severity", "").lower() == "critical")
        high = sum(1 for f in findings if f.get("severity", "").lower() == "high")
        medium = sum(1 for f in findings if f.get("severity", "").lower() == "medium")
        low = sum(1 for f in findings if f.get("severity", "").lower() == "low")
        info = sum(1 for f in findings if f.get("severity", "").lower() == "info")

        elements.append(Paragraph("Executive Summary & Risk Distribution", h2_style))
        summary_data = [
            ["Critical", "High", "Medium", "Low", "Info", "Total"],
            [str(critical), str(high), str(medium), str(low), str(info), str(len(findings))]
        ]
        summary_table = Table(summary_data, colWidths=[85, 85, 85, 85, 85, 95])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor("#f8fafc")),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 15))

        # Detailed Findings Section
        elements.append(Paragraph("Detailed Vulnerability Findings & Remediation", h2_style))
        elements.append(Spacer(1, 6))

        if not findings:
            elements.append(Paragraph("No security vulnerabilities were identified in the authorized testing scope.", body_style))
        else:
            for idx, f in enumerate(findings, 1):
                sev = f.get("severity", "MEDIUM").upper()
                sev_color = "#dc2626" if sev == "CRITICAL" else "#ea580c" if sev == "HIGH" else "#d97706" if sev == "MEDIUM" else "#2563eb"

                finding_rows = [
                    [Paragraph(f"<b>#{idx}. {f.get('title')}</b>", body_style), Paragraph(f"<font color='{sev_color}'><b>{sev}</b></font>", body_style)],
                    [Paragraph("<b>Category:</b>", body_style), Paragraph(f"{f.get('category')} | {f.get('cwe_id', '')} | {f.get('owasp_ref', '')}", body_style)],
                    [Paragraph("<b>Affected Asset:</b>", body_style), Paragraph(f.get("affected_asset", ""), body_style)],
                    [Paragraph("<b>Evidence:</b>", body_style), Paragraph(f.get("evidence_summary", ""), body_style)],
                ]

                if f.get("business_impact"):
                    finding_rows.append([
                        Paragraph("<b>Business Risk:</b>", body_style),
                        Paragraph(f"<font color='#b91c1c'><b>{f.get('business_impact')}</b></font>", body_style)
                    ])

                finding_rows.append([
                    Paragraph("<b>Remediation:</b>", body_style),
                    Paragraph(f.get("remediation_steps", ""), body_style)
                ])

                if f.get("ai_fix_prompt"):
                    finding_rows.append([
                        Paragraph("<b>⚡ AI Fix Prompt:</b><br/><font size='7' color='#64748b'>(Claude/Lovable)</font>", body_style),
                        Paragraph(f"<i>{f.get('ai_fix_prompt')}</i>", body_style)
                    ])

                f_table = Table(finding_rows, colWidths=[120, 400])
                f_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#ffffff")),
                    ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f8fafc")),
                    ('PADDING', (0, 0), (-1, -1), 5),
                    ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#f1f5f9")),
                ]))
                elements.append(f_table)
                elements.append(Spacer(1, 10))

        # Footer Notice
        elements.append(Spacer(1, 15))
        elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cbd5e1"), spaceAfter=10))
        elements.append(Paragraph(
            "<b>Disclaimer:</b> This report reflects passive and non-destructive automated security analysis performed by APT Agents under authorized scope. Continuous testing and manual verification of critical business logic remain recommended.",
            ParagraphStyle("Disclaimer", parent=styles["Normal"], fontSize=8, leading=10, textColor=colors.HexColor("#94a3b8"))
        ))

        doc.build(elements)
        buffer.seek(0)
        return buffer.getvalue()

    @staticmethod
    def generate_compliance_packet_pdf(
        target_url: str,
        org_name: str,
        scan_date: str,
        compliance_data: Dict[str, Any],
        findings: List[Dict[str, Any]]
    ) -> bytes:
        """Generate a formal Auditor Evidence Packet PDF for SOC 2, ISO 27001, PCI-DSS, and HIPAA."""
        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            "CompTitle",
            parent=styles["Heading1"],
            fontSize=20,
            leading=24,
            textColor=colors.HexColor("#0f172a"),
            fontName="Helvetica-Bold",
            spaceAfter=4
        )

        subtitle_style = ParagraphStyle(
            "CompSubtitle",
            parent=styles["Normal"],
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#475569"),
            spaceAfter=12
        )

        h2_style = ParagraphStyle(
            "CompH2",
            parent=styles["Heading2"],
            fontSize=12,
            leading=16,
            textColor=colors.HexColor("#1e293b"),
            fontName="Helvetica-Bold",
            spaceBefore=10,
            spaceAfter=5
        )

        body_style = ParagraphStyle(
            "CompBody",
            parent=styles["Normal"],
            fontSize=8.5,
            leading=11.5,
            textColor=colors.HexColor("#334155")
        )

        elements = []

        # Cover & Attestation Header
        elements.append(Paragraph("REGULATORY COMPLIANCE EVIDENCE PACKET & ATTESTATION", title_style))
        elements.append(Paragraph("Automated Continuous Penetration Testing Audit Report | SOC 2 · ISO 27001 · PCI-DSS · HIPAA", subtitle_style))
        elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#4f46e5"), spaceAfter=12))

        # Scope & Metadata
        meta_data = [
            [Paragraph("<b>Target System:</b>", body_style), Paragraph(target_url, body_style)],
            [Paragraph("<b>Audited Organization:</b>", body_style), Paragraph(org_name, body_style)],
            [Paragraph("<b>Audit Timestamp:</b>", body_style), Paragraph(f"{scan_date} (UTC)", body_style)],
            [Paragraph("<b>Testing Standard:</b>", body_style), Paragraph("AICPA SOC 2 (CC7.1/CC7.2), PCI-DSS v4.0 (Req 11.3), ISO 27001:2022 (A.8.20)", body_style)]
        ]
        meta_table = Table(meta_data, colWidths=[130, 410])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ('PADDING', (0, 0), (-1, -1), 5),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#f1f5f9")),
        ]))
        elements.append(meta_table)
        elements.append(Spacer(1, 10))

        # Executive Attestation Box
        attest_text = (
            "<b>Auditor Attestation:</b> This evidence packet certifies that continuous automated security vulnerability testing "
            "was conducted against the authorized web application assets using autonomous multi-agent penetration testing engines. "
            "Testing encompassed external surface discovery, application logic boundary testing, cryptographic controls, and access control verifications."
        )
        attest_table = Table([[Paragraph(attest_text, body_style)]], colWidths=[540])
        attest_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#eff6ff")),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#93c5fd")),
            ('PADDING', (0, 0), (-1, -1), 8),
        ]))
        elements.append(attest_table)
        elements.append(Spacer(1, 12))

        # Framework Scores Table
        elements.append(Paragraph("1. Compliance Framework Summary & Control Pass Rates", h2_style))
        fw_rows = [["Framework", "Regulation Standard", "Score", "Status", "Controls"]]
        for fw_key, fw in compliance_data.items():
            st_color = "#16a34a" if fw["status"] == "PASSED" else "#d97706" if fw["status"] == "NEEDS_REMEDIATION" else "#dc2626"
            fw_rows.append([
                Paragraph(f"<b>{fw['framework_name']}</b>", body_style),
                Paragraph(fw["full_name"], body_style),
                Paragraph(f"<b>{fw['compliance_score']}%</b>", body_style),
                Paragraph(f"<font color='{st_color}'><b>{fw['status']}</b></font>", body_style),
                Paragraph(f"{fw['passing_controls']}/{fw['total_controls']} Pass", body_style),
            ])
        fw_table = Table(fw_rows, colWidths=[80, 240, 50, 95, 75])
        fw_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1e1b4b")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (2, 0), (-1, -1), 'CENTER'),
            ('PADDING', (0, 0), (-1, -1), 5),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ]))
        elements.append(fw_table)
        elements.append(Spacer(1, 12))

        # Detailed Controls Breakdown
        elements.append(Paragraph("2. Control Evidence & Audit Checkpoints", h2_style))
        ctrl_rows = [["Control ID", "Regulatory Requirement", "Status", "Violations"]]
        for fw_key, fw in compliance_data.items():
            for ctrl in fw.get("controls", []):
                st_str = "PASS" if ctrl["status"] == "COMPLIANT" else "NON-COMPLIANT"
                st_col = "#16a34a" if ctrl["status"] == "COMPLIANT" else "#dc2626"
                ctrl_rows.append([
                    Paragraph(f"<b>{ctrl['control_id']}</b>", body_style),
                    Paragraph(ctrl["title"], body_style),
                    Paragraph(f"<font color='{st_col}'><b>{st_str}</b></font>", body_style),
                    Paragraph(str(ctrl["violations_count"]), body_style),
                ])
        ctrl_table = Table(ctrl_rows, colWidths=[100, 310, 80, 50])
        ctrl_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (2, 0), (-1, -1), 'CENTER'),
            ('PADDING', (0, 0), (-1, -1), 4),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ]))
        elements.append(ctrl_table)
        elements.append(Spacer(1, 15))

        # Sign-off Block
        elements.append(Paragraph("3. Executive Sign-Off & Verification Attestation", h2_style))
        sign_rows = [
            [Paragraph("<b>Chief Information Security Officer (CISO):</b>", body_style), Paragraph("<b>Independent Compliance Lead Auditor:</b>", body_style)],
            [Spacer(1, 18), Spacer(1, 18)],
            [Paragraph("Signature: ___________________________", body_style), Paragraph("Signature: ___________________________", body_style)],
            [Paragraph(f"Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}", body_style), Paragraph(f"Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}", body_style)],
        ]
        sign_table = Table(sign_rows, colWidths=[270, 270])
        sign_table.setStyle(TableStyle([
            ('PADDING', (0, 0), (-1, -1), 4),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ]))
        elements.append(sign_table)

        doc.build(elements)
        buffer.seek(0)
        return buffer.getvalue()
