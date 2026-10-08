import time
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.platypus.flowables import HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT

def draw_dark_bg(canvas, doc):
    """Draws a solid dark slate background across the entire PDF page canvas."""
    canvas.saveState()
    canvas.setFillColor(colors.HexColor('#05080f'))
    canvas.rect(0, 0, doc.pagesize[0], doc.pagesize[1], fill=1, stroke=0)
    canvas.restoreState()

def generate_forensic_pdf(data, output_path):
    """Generates a 10-Module Forensic PDF report with the CYBERCOP dark theme."""
    
    doc = SimpleDocTemplate(
        output_path, pagesize=letter,
        rightMargin=30, leftMargin=30,
        topMargin=40, bottomMargin=40
    )
    
    elements = []
    
    # --- CYBERCOP DARK THEME PALETTE ---
    color_card = colors.HexColor('#0f141e')
    color_border = colors.HexColor('#1e293b')
    color_accent = colors.HexColor('#0ea5e9')
    color_muted = colors.HexColor('#94a3b8')
    
    # --- TYPOGRAPHY ---
    title_style = ParagraphStyle(
        'TitleStyle', fontName='Helvetica-Bold', fontSize=20, leading=24,
        textColor=colors.white, alignment=TA_CENTER, spaceAfter=8
    )
    heading_style = ParagraphStyle(
        'HeadingStyle', fontName='Helvetica-Bold', fontSize=10, leading=14,
        textColor=colors.white, backColor=color_card, 
        alignment=TA_LEFT, spaceBefore=14, spaceAfter=6, borderPadding=6
    )
    normal_mono = ParagraphStyle('Mono', fontName='Courier', fontSize=8, leading=12, textColor=colors.HexColor('#cbd5e1'), spaceAfter=2)
    bold_mono = ParagraphStyle('MonoBold', fontName='Courier-Bold', fontSize=8, leading=12, textColor=colors.white)

    meta = data.get('forensic_metadata', {})
    risk = data.get('risk_data', {})
    ai = data.get('ai_data', {})
    urls = data.get('urls', [])
    sandbox = data.get('sandbox_data', [])

    # =========================================================================
    # HEADER & BRANDING
    # =========================================================================
    elements.append(Paragraph("CYBERCOP // 10-STAGE FORENSIC REPORT", title_style))
    elements.append(HRFlowable(width="100%", color=color_accent, thickness=1.5, spaceBefore=0, spaceAfter=12))

    # =========================================================================
    # MODULE 1 & 2: EMAIL ACQUISITION & PARSING
    # =========================================================================
    elements.append(Paragraph("/// MODULE 1 & 2: EMAIL ACQUISITION & PARSING", heading_style))
    m1_data = [
        [Paragraph("OPERATOR ID:", normal_mono), Paragraph("ATIK KHAN, ABHISHEK KARMAKAR, KHALIQ UR REHMAN KHAN", bold_mono), 
         Paragraph("ACQUISITION NODE:", normal_mono), Paragraph(meta.get('processing_node', 'CYBERCOP_NODE_01'), bold_mono)],
        [Paragraph("UTC TIMESTAMP:", normal_mono), Paragraph(meta.get('analysis_timestamp_utc', 'N/A')[:19].replace('T', ' '), bold_mono),
         Paragraph("PARSING STATUS:", normal_mono), Paragraph("<font color='#10b981'>SUCCESS (RFC822)</font>", bold_mono)]
    ]
    t_m1 = Table(m1_data, colWidths=[110, 160, 110, 160])
    t_m1.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), color_card),
        ('GRID', (0, 0), (-1, -1), 0.5, color_border),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('PADDING', (0, 0), (-1, -1), 6),
    ]))
    elements.append(t_m1)

    # =========================================================================
    # MODULE 3: HEADER & AUTHENTICATION ANALYSIS
    # =========================================================================
    elements.append(Paragraph("/// MODULE 3: HEADER & AUTHENTICATION ANALYSIS", heading_style))
    m3_data = [
        [Paragraph("SPF VERIFICATION", bold_mono), Paragraph("DKIM SIGNATURE", bold_mono), Paragraph("DMARC POLICY", bold_mono)],
        [Paragraph(meta.get('spf_status', 'FAIL / NOT FOUND'), normal_mono), 
         Paragraph(meta.get('dkim_status', 'UNVERIFIED'), normal_mono), 
         Paragraph(meta.get('dmarc_status', 'QUARANTINE / REJECT'), normal_mono)]
    ]
    t_m3 = Table(m3_data, colWidths=[180, 180, 180])
    t_m3.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), color_card),
        ('GRID', (0, 0), (-1, -1), 0.5, color_border),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('PADDING', (0, 0), (-1, -1), 6),
        ('TEXTCOLOR', (0, 1), (-1, 1), colors.HexColor('#ef4444'))
    ]))
    elements.append(t_m3)

    # =========================================================================
    # MODULE 4 & 5: IOC EXTRACTION & IP GEOLOCATION
    # =========================================================================
    elements.append(Paragraph("/// MODULE 4 & 5: IOC EXTRACTION & GEOLOCATION", heading_style))
    if urls:
        m4_data = [[Paragraph("DOMAIN (IOC)", bold_mono), Paragraph("FULL URL", bold_mono), Paragraph("GEO / REPUTATION", bold_mono)]]
        for u in urls:
            domain = Paragraph(u.get('domain', 'N/A'), normal_mono)
            url_str = Paragraph(u.get('original_url', 'N/A'), normal_mono)
            status_val = u.get('reputation', {}).get('status', 'UNKNOWN')
            geo_status = Paragraph(f"GEO: IP Routed<br/>REP: {status_val}", normal_mono)
            m4_data.append([domain, url_str, geo_status])
            
        t_m4 = Table(m4_data, colWidths=[140, 260, 140])
        t_m4.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), color_border),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [color_card, colors.HexColor('#0b0f17')]),
            ('GRID', (0, 0), (-1, -1), 0.5, color_border),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(t_m4)
    else:
        elements.append(Paragraph("No network IOCs or Geolocation data detected in payload.", normal_mono))

    # =========================================================================
    # MODULE 6: THREAT INTELLIGENCE
    # =========================================================================
    elements.append(Paragraph("/// MODULE 6: THREAT INTELLIGENCE (SANDBOXING)", heading_style))
    if sandbox:
        m6_data = [[Paragraph("FILENAME", bold_mono), Paragraph("VERDICT", bold_mono), Paragraph("THREAT INTEL STATUS", bold_mono)]]
        for s in sandbox:
            rep = s.get('sandbox_report', {})
            m6_data.append([
                Paragraph(s.get('filename', 'Unknown'), normal_mono),
                Paragraph(rep.get('verdict', 'N/A'), normal_mono),
                Paragraph(rep.get('status', 'N/A'), normal_mono)
            ])
        t_m6 = Table(m6_data, colWidths=[180, 100, 260])
        t_m6.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), color_border),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('GRID', (0, 0), (-1, -1), 0.5, color_border),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(t_m6)
    else:
        elements.append(Paragraph("No executable attachments found for Threat Intel Sandbox detonation.", normal_mono))

    # =========================================================================
    # MODULE 7 & 8: AI/ML DETECTION & RISK SCORING (FIXED SIZING)
    # =========================================================================
    elements.append(Paragraph("/// MODULE 7 & 8: AI/ML DETECTION & RISK SCORING", heading_style))
    severity = risk.get('severity', 'UNKNOWN').upper()
    sev_color = colors.HexColor('#ef4444') if severity in ['HIGH', 'CRITICAL'] else (colors.HexColor('#f59e0b') if severity == 'MEDIUM' else colors.HexColor('#10b981'))
    sev_styled = Paragraph(f"<font color='{sev_color.hexval()}'><b>{severity}</b></font>", bold_mono)

    # Fixed font sizes and padding to prevent oversized text overflow
    ai_val_style = ParagraphStyle('AIVal', fontName='Helvetica-Bold', fontSize=14, leading=16, textColor=colors.white, alignment=TA_CENTER)
    score_val_style = ParagraphStyle('ScoreVal', fontName='Helvetica-Bold', fontSize=14, leading=16, textColor=colors.white, alignment=TA_CENTER)

    m7_data = [
        [Paragraph("MODULE 7: AI PHISHING CONFIDENCE", normal_mono), Paragraph("MODULE 8: FINAL HEURISTIC SCORE", normal_mono)],
        [Paragraph(str(ai.get('percentage', 'N/A')), ai_val_style), 
         Paragraph(str(risk.get('score', 0)), score_val_style)],
        [Paragraph("Deep Neural Net (64x32 MLP)", normal_mono), sev_styled]
    ]
    t_m7 = Table(m7_data, colWidths=[270, 270])
    t_m7.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), color_card),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('GRID', (0, 0), (-1, -1), 0.5, color_border),
        ('PADDING', (0, 0), (-1, -1), 6),
    ]))
    elements.append(t_m7)

    # =========================================================================
    # MODULE 9 & 10: FORENSIC INVESTIGATION & REPORT GENERATION
    # =========================================================================
    elements.append(Paragraph("/// MODULE 9 & 10: FORENSIC INVESTIGATION & REPORT GENERATION", heading_style))
    hash_val = meta.get('blockchain_sha256_hash', 'PENDING')
    
    m9_data = [
        [Paragraph("CHAIN OF CUSTODY (M9):", normal_mono), Paragraph(hash_val, bold_mono)],
        [Paragraph("REPORT COMPILER (M10):", normal_mono), Paragraph("CYBERCOP Automated PDF Engine v2.0", bold_mono)]
    ]
    t_m9 = Table(m9_data, colWidths=[140, 400])
    t_m9.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), color_card),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('GRID', (0, 0), (-1, -1), 0.5, color_accent),
        ('PADDING', (0, 0), (-1, -1), 6),
    ]))
    elements.append(t_m9)
    
    # FOOTER (Line by Line Team Stack)
    elements.append(Spacer(1, 15))
    elements.append(HRFlowable(width="100%", color=color_border, thickness=1, spaceBefore=0, spaceAfter=5))
    elements.append(Paragraph("DEVELOPED & ENGINEERED BY:", ParagraphStyle('FTitle', fontName='Courier-Bold', fontSize=7, leading=9, textColor=colors.HexColor('#94a3b8'), alignment=TA_CENTER)))
    elements.append(Paragraph("ATIK KHAN", ParagraphStyle('F1', fontName='Courier-Bold', fontSize=7, leading=9, textColor=colors.white, alignment=TA_CENTER)))
    elements.append(Paragraph("ABHISHEK KARMAKAR", ParagraphStyle('F2', fontName='Courier-Bold', fontSize=7, leading=9, textColor=colors.white, alignment=TA_CENTER)))
    elements.append(Paragraph("KHALIQ UR REHMAN KHAN", ParagraphStyle('F3', fontName='Courier-Bold', fontSize=7, leading=9, textColor=colors.white, alignment=TA_CENTER)))
    elements.append(Paragraph("☣ POWERED BY UMBRELLA CORPORATION ☣", ParagraphStyle('Footer2', fontName='Courier-Bold', fontSize=7, leading=9, textColor=colors.HexColor('#ef4444'), alignment=TA_CENTER, spaceBefore=4)))

    # Build PDF with the dark background canvas callback applied to all pages
    doc.build(elements, onFirstPage=draw_dark_bg, onLaterPages=draw_dark_bg)