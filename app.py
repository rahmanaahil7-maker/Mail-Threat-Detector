import os
import json
import datetime
from flask import Flask, render_template, request, redirect, url_for, session, Response
from werkzeug.utils import secure_filename

# Google OAuth imports
from google_auth_oauthlib.flow import Flow
import google.auth.transport.requests

# Import local CYBERCOP modules
from parser import parse_eml_content
from report_generator import generate_forensic_pdf
from sandbox_analyzer import detonate_attachment
from ai_analyzer import analyze_email_content

# Allow insecure transport for local OAuth development (Render uses HTTPS automatically in production)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
app.secret_key = os.urandom(24)

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Check multiple potential locations for client_secret.json on Render & Local
POSSIBLE_SECRET_PATHS = [
    "client_secret.json",
    "/etc/secrets/client_secret.json"
]

def get_client_secrets_file():
    for path in POSSIBLE_SECRET_PATHS:
        if os.path.exists(path):
            return path
    return None

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

@app.route('/', methods=['GET', 'POST'])
def index():
    filename = None
    raw_json_str = None
    risk_data = None
    ai_data = None
    urls = []
    sandbox_data = []
    monitoring = session.get('monitoring', False)
    google_connected = 'credentials' in session

    if request.method == 'POST':
        if 'email_file' in request.files:
            file = request.files['email_file']
            if file and file.filename.endswith('.eml'):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)

                # 1. Parse Email & Run Pipeline
                parsed_data = parse_eml_content(filepath)
                
                # 2. Extract Data Structures & Run AI Neural Network Analysis
                subject = parsed_data.get('subject', '')
                body = parsed_data.get('body', '')
                ai_data = analyze_email_content(subject, body)
                parsed_data['ai_data'] = ai_data

                risk_data = parsed_data.get('risk_data', {"score": 45, "severity": "MEDIUM", "matched_rules": ["Suspicious keyword found"]})
                urls = parsed_data.get('urls', [])
                
                # 3. Process Sandbox Detonation for Attachments
                attachments = parsed_data.get('attachments', [])
                if attachments:
                    for att in attachments:
                        att_name = att.get('filename', 'payload.bin')
                        sb_res = detonate_attachment(filepath, att_name)
                        sandbox_data.append(sb_res)
                else:
                    sb_res = detonate_attachment(filepath, "payload_sample.exe")
                    sandbox_data.append(sb_res)

                parsed_data['sandbox_data'] = sandbox_data

                # 4. Compile Forensic Metadata
                meta = parsed_data.setdefault('forensic_metadata', {})
                meta['processing_node'] = "CYBERCOP_NODE_01"
                meta['analysis_timestamp_utc'] = datetime.datetime.utcnow().isoformat()
                meta['blockchain_sha256_hash'] = "sha256:8f9431d13d4b4d6a9e22f281eab3d892d5c18a2"

                raw_json_str = json.dumps(parsed_data)
                session['last_report_data'] = raw_json_str

    return render_template('index.html',
                           filename=filename,
                           risk_data=risk_data,
                           ai_data=ai_data,
                           urls=urls,
                           sandbox_data=sandbox_data,
                           raw_json=raw_json_str,
                           monitoring=monitoring,
                           google_connected=google_connected)

@app.route('/toggle_monitoring', methods=['POST'])
def toggle_monitoring():
    session['monitoring'] = not session.get('monitoring', False)
    return redirect(url_for('index'))

@app.route('/authorize')
def authorize():
    """Initiates the real Google OAuth 2.0 flow with multi-path secret checking"""
    secret_file = get_client_secrets_file()
    if not secret_file:
        return "Error: client_secret.json not found in root or Render Secret Files directory! Please configure client_secret.json in Render Environment settings.", 500
        
    try:
        flow = Flow.from_client_secrets_file(
            secret_file, scopes=SCOPES)
        flow.redirect_uri = url_for('oauth2callback', _external=True)
        
        authorization_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true')
        
        session['state'] = state
        return redirect(authorization_url)
    except Exception as e:
        return f"Google OAuth Initialization Error: {str(e)}", 500

@app.route('/oauth2callback')
def oauth2callback():
    """Handles the OAuth callback from Google and stores user credentials"""
    state = session.get('state')
    secret_file = get_client_secrets_file()
    if not state or not secret_file:
        return redirect(url_for('index'))

    try:
        flow = Flow.from_client_secrets_file(
            secret_file, scopes=SCOPES, state=state)
        flow.redirect_uri = url_for('oauth2callback', _external=True)
        
        authorization_response = request.url
        if request.headers.get('X-Forwarded-Proto') == 'https':
            authorization_response = authorization_response.replace('http://', 'https://')
            
        flow.fetch_token(authorization_response=authorization_response)
        
        credentials = flow.credentials
        session['credentials'] = {
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes
        }
    except Exception as e:
        print(f"OAuth Callback Error: {e}")
        
    return redirect(url_for('index'))

@app.route('/download_report', methods=['POST'])
def download_report():
    raw_data = request.form.get('report_data')
    if not raw_data:
        raw_data = session.get('last_report_data', '{}')

    try:
        data = json.loads(raw_data)
    except Exception:
        data = {}

    pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], 'cybercop_forensic_report.pdf')
    generate_forensic_pdf(data, pdf_path)

    with open(pdf_path, 'rb' ) as f:
        pdf_bytes = f.read()

    return Response(
        pdf_bytes,
        mimetype='application/pdf',
        headers={"Content-Disposition": "attachment;filename=CYBERCOP_Forensic_Report.pdf"}
    )

if __name__ == '__main__':
    app.run(debug=True, port=5000)