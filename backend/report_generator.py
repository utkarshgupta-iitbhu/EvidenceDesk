import io
import uuid
import html
from datetime import datetime, timezone
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

class ForensicPDFReporter:
    """Generates defensible, detailed triage PDF summaries strictly from verified server records."""

    @staticmethod
    def _esc(val) -> str:
        return html.escape(str(val if val is not None else ""))

    @classmethod
    def generate(cls, scan_record: dict) -> bytes:
        scan_id = scan_record.get("scan_id", "N/A")
        scan_type = scan_record.get("module", "triage")
        data = scan_record.get("result", {})
        intake_time = scan_record.get("created_at", "Recorded at intake")
        export_time_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=36, leftMargin=36,
            topMargin=36, bottomMargin=36
        )

        styles = getSampleStyleSheet()
        report_id = str(uuid.uuid4())[:8].upper()

        title_style = ParagraphStyle(
            'ReportTitle',
            parent=styles['Heading1'],
            fontSize=15,
            leading=18,
            textColor=colors.HexColor('#0f172a'),
            fontName='Helvetica-Bold'
        )
        subtitle_style = ParagraphStyle(
            'ReportSubtitle',
            parent=styles['Normal'],
            fontSize=8.5,
            leading=11.5,
            textColor=colors.HexColor('#475569'),
            fontName='Helvetica'
        )
        section_style = ParagraphStyle(
            'SectionHeader',
            parent=styles['Heading2'],
            fontSize=10,
            leading=13,
            textColor=colors.HexColor('#1e293b'),
            fontName='Helvetica-Bold'
        )
        body_style = ParagraphStyle(
            'BodyText',
            parent=styles['Normal'],
            fontSize=8,
            leading=11,
            textColor=colors.HexColor('#334155'),
            fontName='Helvetica'
        )
        disclaimer_style = ParagraphStyle(
            'DisclaimerText',
            parent=styles['Normal'],
            fontSize=7,
            leading=9.5,
            textColor=colors.HexColor('#64748b'),
            fontName='Helvetica-Oblique'
        )

        elements = []

        # 1. Header Banner
        elements.append(Paragraph("EvidenceDesk — Digital Evidence Triage Report", title_style))
        elements.append(Paragraph(
            f"Server Scan ID: {cls._esc(scan_id)} | Report ID: ED-{cls._esc(report_id)} | Module: {cls._esc(scan_type).upper()}", 
            subtitle_style
        ))
        elements.append(Spacer(1, 10))

        # 2. Intake Record Table
        target_name = cls._esc(data.get("fileName", data.get("sourceName", "Unknown Target")))
        status = cls._esc(data.get("status", "Review Required"))
        score = data.get("triageScore", data.get("heuristicScore", 0))
        score_label = cls._esc(data.get("scoreLabel", "Triage Indicator Score"))
        
        file_sha256 = cls._esc(data.get("fileSha256", data.get("sha256", "Not recorded")))
        text_sha256 = cls._esc(data.get("textSha256", ""))
        md5 = cls._esc(data.get("fileMd5", data.get("md5", "Not recorded")))

        record_data = [
            [Paragraph("<b>Target Reference:</b>", body_style), Paragraph(target_name, body_style)],
            [Paragraph("<b>Triage Assessment:</b>", body_style), Paragraph(f"<b>{status}</b>", body_style)],
            [Paragraph(f"<b>{score_label}:</b>", body_style), Paragraph(f"<b>{score} / 100</b> (Uncalibrated heuristic index)", body_style)],
            [Paragraph("<b>File SHA-256 Hash:</b>", body_style), Paragraph(file_sha256, body_style)],
        ]
        if text_sha256:
            record_data.append([Paragraph("<b>Text Stream SHA-256:</b>", body_style), Paragraph(text_sha256, body_style)])

        record_data.extend([
            [Paragraph("<b>Legacy MD5 Hash:</b>", body_style), Paragraph(md5, body_style)],
            [Paragraph("<b>Intake Timestamp:</b>", body_style), Paragraph(cls._esc(intake_time), body_style)],
            [Paragraph("<b>Export Timestamp:</b>", body_style), Paragraph(cls._esc(export_time_utc), body_style)],
            [Paragraph("<b>Analysis Engine:</b>", body_style), Paragraph("EvidenceDesk v1.2.0 (Server-Verified Intake)", body_style)]
        ])

        overview_table = Table(record_data, colWidths=[130, 410])
        overview_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('PADDING', (0, 0), (-1, -1), 3.5),
        ]))
        elements.append(overview_table)
        elements.append(Spacer(1, 10))

        # 3. Module-Specific Technical Details (Attachments, EXIF, or Text Metrics)
        if scan_type == "email":
            headers = data.get("headers", {})
            attachments = data.get("attachments", [])
            
            elements.append(Paragraph("Header Transport & Attachment Inventory", section_style))
            elements.append(Spacer(1, 3))
            
            hdr_data = [
                [Paragraph("<b>From:</b>", body_style), Paragraph(cls._esc(headers.get("from", "N/A")), body_style)],
                [Paragraph("<b>Reply-To:</b>", body_style), Paragraph(cls._esc(headers.get("replyTo", "N/A")), body_style)],
                [Paragraph("<b>Return-Path:</b>", body_style), Paragraph(cls._esc(headers.get("returnPath", "N/A")), body_style)],
                [Paragraph("<b>Reported Auth:</b>", body_style), Paragraph(cls._esc(headers.get("authReported", "N/A")), body_style)],
            ]
            hdr_table = Table(hdr_data, colWidths=[100, 440])
            hdr_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f1f5f9')),
                ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
                ('PADDING', (0, 0), (-1, -1), 3),
            ]))
            elements.append(hdr_table)
            elements.append(Spacer(1, 6))

            if attachments:
                att_rows = [[Paragraph("<b>ATTACHMENT</b>", body_style), Paragraph("<b>SIZE</b>", body_style), Paragraph("<b>SHA-256 HASH</b>", body_style), Paragraph("<b>FLAG</b>", body_style)]]
                for a in attachments:
                    att_rows.append([
                        Paragraph(cls._esc(a.get("filename", "")), body_style),
                        Paragraph(f"{a.get('sizeKb', 0)} KB", body_style),
                        Paragraph(cls._esc(a.get("sha256", "")), body_style),
                        Paragraph("RISKY EXT" if a.get("flagged") else "Standard", body_style)
                    ])
                att_table = Table(att_rows, colWidths=[130, 50, 300, 60])
                att_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e2e8f0')),
                    ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
                    ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
                    ('PADDING', (0, 0), (-1, -1), 3),
                ]))
                elements.append(att_table)
                elements.append(Spacer(1, 8))

        elif scan_type == "image":
            meta = data.get("metadata", {})
            stego = data.get("steganography", {})
            elements.append(Paragraph("Image Structure & Metadata Telemetry", section_style))
            elements.append(Spacer(1, 3))
            img_data = [
                [Paragraph("<b>Format & Dimensions:</b>", body_style), Paragraph(f"{cls._esc(data.get('format'))} ({cls._esc(data.get('dimensions'))})", body_style)],
                [Paragraph("<b>Camera Make/Model:</b>", body_style), Paragraph(f"{cls._esc(meta.get('Make', ''))} {cls._esc(meta.get('Model', ''))}".strip() or "None recorded", body_style)],
                [Paragraph("<b>Software Identifier:</b>", body_style), Paragraph(cls._esc(meta.get('Software', 'None recorded')), body_style)],
                [Paragraph("<b>ELA Variance Score:</b>", body_style), Paragraph(f"{data.get('ela', {}).get('varianceScore', 0)} / 100", body_style)],
                [Paragraph("<b>Trailing Bytes / Stego:</b>", body_style), Paragraph(cls._esc(stego.get('details', 'No anomalies detected past EOF')), body_style)]
            ]
            img_table = Table(img_data, colWidths=[140, 400])
            img_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f1f5f9')),
                ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
                ('PADDING', (0, 0), (-1, -1), 3),
            ]))
            elements.append(img_table)
            elements.append(Spacer(1, 8))

        elif scan_type == "text":
            metrics = data.get("metrics", {})
            elements.append(Paragraph("Stylistic Uniformity Indicators", section_style))
            elements.append(Spacer(1, 3))
            txt_data = [
                [Paragraph("<b>Discourse Volume:</b>", body_style), Paragraph(f"{data.get('totalWords', 0)} words across {data.get('totalSentences', 0)} sentences", body_style)],
                [Paragraph("<b>Sentence Burstiness:</b>", body_style), Paragraph(f"{metrics.get('burstiness', 'N/A')} (Coefficient of variation of sentence lengths)", body_style)],
                [Paragraph("<b>Transition Marker Density:</b>", body_style), Paragraph(str(metrics.get('aiBuzzwordDensity', '0%')), body_style)],
                [Paragraph("<b>Passive Voice Clauses:</b>", body_style), Paragraph(str(metrics.get('passiveClausesCount', 0)), body_style)]
            ]
            txt_table = Table(txt_data, colWidths=[140, 400])
            txt_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f1f5f9')),
                ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
                ('PADDING', (0, 0), (-1, -1), 3),
            ]))
            elements.append(txt_table)
            elements.append(Spacer(1, 8))

        # 4. Flagged Findings
        elements.append(Paragraph("Recorded Indicators & Technical Observations", section_style))
        elements.append(Spacer(1, 3))

        findings = data.get("findings", [])
        if findings:
            finding_rows = [
                [Paragraph("<b>SEVERITY</b>", body_style), Paragraph("<b>OBSERVATION & DETAIL</b>", body_style), Paragraph("<b>TECHNICAL CAVEAT / CONTEXT</b>", body_style)]
            ]
            for f in findings:
                if isinstance(f, dict):
                    sev = cls._esc(f.get("severity", "INFO")).upper()
                    title = cls._esc(f.get("title", ""))
                    detail = cls._esc(f.get("detail", ""))
                    caveat = cls._esc(f.get("caveat", ""))
                    obs_cell = Paragraph(f"<b>{title}</b><br/>{detail}", body_style)
                    caveat_cell = Paragraph(caveat, disclaimer_style)
                else:
                    sev = "INFO"
                    obs_cell = Paragraph(cls._esc(str(f)), body_style)
                    caveat_cell = Paragraph("Routine finding.", disclaimer_style)

                finding_rows.append([Paragraph(f"<b>{sev}</b>", body_style), obs_cell, caveat_cell])

            findings_table = Table(finding_rows, colWidths=[65, 275, 200])
            findings_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e2e8f0')),
                ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
                ('PADDING', (0, 0), (-1, -1), 3.5),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            elements.append(findings_table)
        else:
            elements.append(Paragraph("No anomalous indicators flagged by the automated rules in this sample.", body_style))

        elements.append(Spacer(1, 10))

        # 5. Methodology & Disclaimer
        elements.append(Paragraph("Methodology Limitations & Non-Attribution Notice", section_style))
        elements.append(Spacer(1, 2))
        
        limitations_text = (
            "<b>NOTICE:</b> This document is an automated preliminary triage summary generated by EvidenceDesk v1.2.0 "
            "from an authenticated server-side analysis record. It records algorithmic heuristic observations and does not "
            "constitute legal proof of file tampering, synthetic generation, or sender legitimacy. Email authentication headers "
            "were inspected as unverified message text without live DNS/DKIM cryptographic validation. Image ELA differences "
            "can arise from standard JPEG recompression rather than deliberate tampering. Text burstiness and transition frequency "
            "are uncalibrated stylistic metrics and do not prove or disprove AI authorship. All findings must be corroborated "
            "through independent investigation by qualified forensic personnel."
        )
        elements.append(Paragraph(limitations_text, disclaimer_style))
        elements.append(Spacer(1, 8))

        doc.build(elements)
        buffer.seek(0)
        return buffer.getvalue()
