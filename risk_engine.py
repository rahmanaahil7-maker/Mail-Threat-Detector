def calculate_risk(parsed_data, urls=None, sandbox_data=None, ai_data=None):
    """
    Evaluates multi-vector telemetry (headers, URLs, sandboxing, and AI confidence)
    to compute a dynamic risk score, severity rating, and matched heuristic rules.
    """
    score = 0
    matched_rules = []

    # Ensure parameters are valid lists/dicts
    urls = urls or []
    sandbox_data = sandbox_data or []
    ai_data = ai_data or {}
    parsed_data = parsed_data or {}

    # 1. Header & Authentication Analysis (SPF, DKIM, DMARC)
    spf = parsed_data.get('spf_status', '').upper()
    dkim = parsed_data.get('dkim_status', '').upper()
    dmarc = parsed_data.get('dmarc_status', '').upper()

    if 'PASS' not in spf:
        score += 5
        matched_rules.append("SPF record missing or failed (+5)")
    if 'PASS' not in dkim:
        score += 5
        matched_rules.append("DKIM signature unverified or missing (+5)")
    if 'PASS' not in dmarc:
        score += 5
        matched_rules.append("DMARC policy missing or failed (+5)")

    # 2. URL Threat Intelligence Check
    for u in urls:
        rep = u.get('reputation', {})
        status = rep.get('status', '').upper()
        if 'MALICIOUS' in status or 'PHISHING' in status or 'SUSPICIOUS' in status:
            score += 25
            matched_rules.append(f"Malicious IOC Domain detected: {u.get('domain', 'Unknown')} (+25)")

    # 3. Sandbox Detonation Check
    for item in sandbox_data:
        report = item.get('sandbox_report', {})
        verdict = report.get('verdict', '').upper()
        if 'MALICIOUS' in verdict or 'THREAT' in verdict or 'SUSPICIOUS' in verdict:
            score += 40
            matched_rules.append(f"Sandbox isolated threat in attachment: {item.get('filename', 'payload')} (+40)")

    # 4. Deep Neural Network (DNN) AI Confidence Integration
    print("--- DEBUG AI DATA ---", ai_data)
    if ai_data and not ai_data.get('error'):
        try:
            # Clean percentage string (e.g. "78.5%" -> 78.5)
            pct_str = str(ai_data.get('percentage', '0')).replace('%', '').strip()
            ai_confidence = float(pct_str)
            
            if ai_confidence > 10.0:
                ai_weight = int(ai_confidence * 0.35) # Scaled contribution
                score += ai_weight
                matched_rules.append(f"DNN Phishing Confidence flagged at {ai_confidence}% (+{ai_weight})")
        except (ValueError, TypeError):
            pass

    # Cap maximum score at 100
    score = min(score, 100)

    # 5. Dynamic Severity Assignment
    if score >= 50:
        severity = "HIGH"
    elif score >= 25:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    # Fallback if no signatures triggered
    if not matched_rules:
        matched_rules.append("No malicious heuristic signatures triggered.")

    return {
        "score": score,
        "severity": severity,
        "matched_rules": matched_rules
    }