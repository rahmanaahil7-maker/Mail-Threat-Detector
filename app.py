import os
import re
import json
import time
import base64
import threading
import hashlib
from datetime import datetime, timezone
import tldextract
import ipaddress
import dns.resolver
import quopri
from flask import Flask, render_template, request, redirect, send_file, session, url_for
from werkzeug.utils import secure_filename
from flask_session import Session

# Google API Imports
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

# Custom modular scripts
from parser import parse_eml_content as parse_email
from analyzer import analyze_headers
from ip_analyzer import analyze_and_store_ips
from threat_intel import check_ip_reputation, check_url_reputation
from ai_analyzer import analyze_email_content
from risk_engine import calculate_risk
from report_generator import generate_forensic_pdf
from sandbox_analyzer import detonate_attachment
from siem_integration import forward_to_siem
from blockchain_evidence import store_blockchain_evidence

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.secret_key = "cyber_soc_secret_key_atik007" 
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# --- GOOGLE OAUTH SETTINGS ---
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
CLIENT_SECRETS_FILE = "credentials.json"

MONITORING_ACTIVE = False
PROCESSED_MSG_IDS = set()

# --- CUSTOM DNS INFRASTRUCTURE ---
# Enforce secure DNS resolution for threat intel lookups
custom_resolver = dns.resolver.Resolver(configure=False)
custom_resolver.nameservers = ['9.9.9.9', '149.112.112.112'] # Quad9 Malware Blocking


# --- ADVANCED REPORTING: MITRE ATT&CK MAPPING ---
def map_to_mitre(matched_rules):
    """Maps heuristic threat triggers to standard MITRE ATT&CK framework tactics."""
    mitre_data = []
    rule_mapping = {
        "Hidden URL detected": {"id": "T1566.002", "tactic": "Initial Access", "technique": "Phishing: Spearphishing Link"},
        "Suspicious attachment": {"id": "T1566.001", "tactic": "Initial Access", "technique": "Phishing: Spearphishing Attachment"},
        "Domain spoofing": {"id": "T1548", "tactic": "Privilege Escalation", "technique": "Abuse Elevation Control Mechanism"},
        "Macro execution": {"id": "T1059.005", "tactic": "Execution", "technique": "Command and Scripting Interpreter: Visual Basic"}
    }
    
    for rule in matched_rules:
        for key, mapping in rule_mapping.items():
            if key.lower() in rule.lower():
                mitre_data.append(mapping)
    
    if not mitre_data:
        mitre_data.append({"id": "T1566", "tactic": "Initial Access", "technique": "Phishing"})
        
    return [dict(t) for t in {tuple(d.items()) for d in mitre_data}] 


# --- HELPER FUNCTION: CORE PIPELINE ---
def process_email_file(filepath, filename):
    """Executes the full distributed threat analysis pipeline."""
    parsed_data = parse_email(filepath)
    analysis_data = analyze_headers(filepath)
    ai_prediction = analyze_email_content(parsed_data.get("subject", ""), parsed_data.get("body", ""))
    
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        raw_text = f.read()
        
    # Decode Quoted-Printable text to fix '=' signs breaking URLs
    try:
        raw_text = quopri.decodestring(raw_text.encode('utf-8')).decode('utf-8', errors='ignore')
    except Exception:
        pass

    # Stricter URL Regex to ignore trailing punctuation
    url_pattern = re.compile(r'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s<>"\',()]*[^\s<>"\',().])?', re.IGNORECASE)
    found_urls = list(set(re.findall(url_pattern, raw_text)))
    url_data = []
    
    for u in found_urls:
        ext = tldextract.extract(u)
        reputation = check_url_reputation(u)
        time.sleep(0.3)
        url_data.append({
            "original_url": u, "subdomain": ext.subdomain,
            "domain": ext.domain, "suffix": ext.suffix,
            "is_secure": u.lower().startswith('https'), "reputation": reputation
        })
        
    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    raw_ips = list(set(re.findall(ip_pattern, raw_text)))
    public_ips = []
    for ip_str in raw_ips:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if not ip_obj.is_private and not ip_obj.is_loopback: public_ips.append(ip_str)
        except ValueError: pass
    
    geo_results = analyze_and_store_ips(public_ips)
    ip_intel = {}
    for ip in public_ips:
        ip_intel[ip] = check_ip_reputation(ip)
        time.sleep(0.3)
    
    risk_data = calculate_risk(parsed_data=parsed_data, ai_data=ai_prediction, urls=url_data)
    sandbox_data = [detonate_attachment(filepath, "payload.bin")]
    
    # Enhanced Report Features
    mitre_mapping = map_to_mitre(risk_data.get('matched_rules', []))
    
    forensic_metadata = {
        "analysis_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "processing_node": os.uname().nodename if hasattr(os, 'uname') else "CYBERCOP_NODE_01",
        "dns_resolver": custom_resolver.nameservers[0],
        "operator_id": "ATIK KHAN, ABHISHEK KARMAKAR, KHALIQ UR REHMAN KHAN",
        "mitre_attack_matrix": mitre_mapping
    }
    
    full_dataset = {
        "parsed": parsed_data, "analysis": analysis_data, "urls": url_data,
        "ips": public_ips, "geo": geo_results, "ip_intel": ip_intel,
        "ai_data": ai_prediction, "risk_data": risk_data, 
        "sandbox_data": sandbox_data, "forensic_metadata": forensic_metadata
    }
    
    # Immutable Storage & SIEM Forwarding
    evidence_hash = store_blockchain_evidence(full_dataset)
    full_dataset['forensic_metadata']['blockchain_sha256_hash'] = evidence_hash
    forward_to_siem(risk_data, filename, risk_data.get('severity', 'UNKNOWN'))
    
    return render_template('index.html', filename=filename, parsed=parsed_data, 
                           analysis=analysis_data, urls=url_data, ips=public_ips, 
                           geo=geo_results, ip_intel=ip_intel, ai_data=ai_prediction, 
                           risk_data=risk_data, sandbox_data=sandbox_data, 
                           evidence_hash=evidence_hash, raw_json=json.dumps(full_dataset), 
                           monitoring=MONITORING_ACTIVE)


# --- MAIN WEB ROUTES ---
@app.route('/', methods=['GET', 'POST'])
def index():
    global MONITORING_ACTIVE
    if request.method == 'POST':
        file = request.files.get('email_file')
        if file and file.filename != '':
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            return process_email_file(filepath, filename)
    return render_template('index.html', filename=None, monitoring=MONITORING_ACTIVE)

@app.route('/download_report', methods=['POST'])
def download_report():
    report_data_json = request.form.get('report_data')
    if not report_data_json: return redirect('/')
    data = json.loads(report_data_json)
    
    pdf_filename = f"CYBERCOP_Forensic_Report_{int(time.time())}.pdf"
    pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], pdf_filename)
    generate_forensic_pdf(data, pdf_path) 
    return send_file(pdf_path, as_attachment=True)


# --- MOBILE APPLICATION API ENDPOINT ---
@app.route('/api/v1/analyze', methods=['POST'])
def mobile_api_analyze():
    """REST API for mobile application ingestion."""
    if 'file' not in request.files:
        return json.jsonify({"error": "No file uploaded", "status": "failed"}), 400
        
    file = request.files['file']
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    
    parsed_data = parse_email(filepath)
    ai_prediction = analyze_email_content(parsed_data.get("subject", ""), parsed_data.get("body", ""))
    
    return json.jsonify({
        "status": "success",
        "filename": filename,
        "ai_confidence": ai_prediction,
        "operator": "ATIK_007",
        "timestamp": datetime.now(timezone.utc).isoformat()
    })


# --- GMAIL OAUTH INTEGRATION ---
@app.route('/authorize')
def authorize():
    flow = Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES)
    flow.redirect_uri = url_for('oauth2callback', _external=True)
    authorization_url, state = flow.authorization_url(access_type='offline', include_granted_scopes='true')
    session['state'] = state
    session['code_verifier'] = flow.code_verifier 
    return redirect(authorization_url)

@app.route('/oauth2callback')
def oauth2callback():
    state = session['state']
    flow = Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
    flow.redirect_uri = url_for('oauth2callback', _external=True)
    if 'code_verifier' in session: flow.code_verifier = session['code_verifier']
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials
    session['credentials'] = {
        'token': credentials.token, 'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri, 'client_id': credentials.client_id,
        'client_secret': credentials.client_secret, 'scopes': credentials.scopes
    }
    return redirect(url_for('fetch_latest_email'))

@app.route('/fetch_latest_email')
def fetch_latest_email():
    if 'credentials' not in session: return redirect(url_for('authorize'))
    creds = Credentials(**session['credentials'])
    try:
        service = build('gmail', 'v1', credentials=creds)
        results = service.users().messages().list(userId='me', maxResults=1).execute()
        if not results.get('messages', []): return "No emails found in inbox.", 400
        msg_id = results['messages'][0]['id']
        message = service.users().messages().get(userId='me', id=msg_id, format='raw').execute()
        msg_raw = base64.urlsafe_b64decode(message['raw'].encode('ASCII'))
        filename = f"gmail_cyber_{msg_id}.eml"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        with open(filepath, 'wb') as f: f.write(msg_raw)
        return process_email_file(filepath, filename)
    except Exception as e: return f"Error: {e}", 500


# --- REAL-TIME MONITORING BACKGROUND WORKER ---
def background_mail_monitor(creds_data):
    global MONITORING_ACTIVE
    creds = Credentials(**creds_data)
    service = build('gmail', 'v1', credentials=creds)
    while MONITORING_ACTIVE:
        try:
            results = service.users().messages().list(userId='me', q='is:unread', maxResults=3).execute()
            for msg_item in results.get('messages', []):
                msg_id = msg_item['id']
                if msg_id not in PROCESSED_MSG_IDS:
                    PROCESSED_MSG_IDS.add(msg_id)
                    message = service.users().messages().get(userId='me', id=msg_id, format='raw').execute()
                    msg_raw = base64.urlsafe_b64decode(message['raw'].encode('ASCII'))
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], f"live_alert_{msg_id}.eml")
                    with open(filepath, 'wb') as f: f.write(msg_raw)
        except Exception: pass
        time.sleep(30)

@app.route('/toggle_monitoring', methods=['POST'])
def toggle_monitoring():
    global MONITORING_ACTIVE
    if 'credentials' not in session: return redirect(url_for('authorize'))
    MONITORING_ACTIVE = not MONITORING_ACTIVE
    if MONITORING_ACTIVE:
        t = threading.Thread(target=background_mail_monitor, args=(session['credentials'],), daemon=True)
        t.start()
    return redirect('/')


if __name__ == '__main__':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    # NOTE: If Port 5000 is blocked by Windows on your machine, change port=5000 to port=5001 here.
    app.run(host="0.0.0.0", debug=True, port=5000)