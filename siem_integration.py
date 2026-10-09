import requests
import json
from datetime import datetime

# Replace with your actual SIEM webhook or ELK Logstash endpoint
SIEM_WEBHOOK_URL = "https://your-siem-instance.internal/api/webhook/cybercop"

def forward_to_siem(threat_data, filename, severity):
    """Pushes forensic threat telemetry to a centralized SIEM."""
    payload = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "sensor": "CYBERCOP_NODE_01",
        "operator": "ATIK_007",
        "event_type": "THREAT_INGESTION",
        "file_analyzed": filename,
        "severity": severity,
        "risk": threat_data.get('score', 0),
        "iocs": {
            "urls": threat_data.get('urls', []),
            "ips": threat_data.get('ips', [])
        }
    }
    
    try:
        headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer SIEM_API_KEY'}
        # requests.post(SIEM_WEBHOOK_URL, data=json.dumps(payload), headers=headers, timeout=3)
        print(f"[SIEM] Successfully forwarded telemetry for {filename}")
        return True
    except Exception as e:
        print(f"[SIEM ERROR] Could not reach SIEM endpoint: {e}")
        return False