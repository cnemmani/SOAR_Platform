"""
Account Takeover & Collaboration Platform Protection Service (Port 8056)
Detects: Login anomalies, impossible travel, brute force, session hijack,
         Teams/Slack phishing, SharePoint/OneDrive malware, Google Workspace threats
"""
from flask import Flask, jsonify, request
from flask_cors import CORS
from datetime import datetime, timedelta
from collections import defaultdict, deque
import math
import re

app = Flask(__name__)
CORS(app)

# In-memory tracking
login_history = defaultdict(list)
failed_logins = defaultdict(list)
collab_alerts = deque(maxlen=500)
platform_events = defaultdict(list)

# Collaboration Platform Threat Patterns
COLLAB_PATTERNS = {
    'teams_phishing': {
        'patterns': [
            r'teams.*external.*user', r'teams.*guest.*access',
            r'teams.*file.*share.*external', r'teams.*meeting.*anonymous',
            r'teams.*phish', r'teams.*malware.*link'
        ],
        'risk': 70,
        'description': 'Suspicious Microsoft Teams activity'
    },
    'slack_threat': {
        'patterns': [
            r'slack.*external.*collaborator', r'slack.*guest.*invite',
            r'slack.*file.*share.*external', r'slack.*bot.*added',
            r'slack.*webhook.*created', r'slack.*token.*leak'
        ],
        'risk': 65,
        'description': 'Suspicious Slack activity detected'
    },
    'sharepoint_malware': {
        'patterns': [
            r'sharepoint.*malware.*detected', r'sharepoint.*ransomware',
            r'sharepoint.*suspicious.*download', r'sharepoint.*mass.*delete',
            r'sharepoint.*external.*share', r'onedrive.*sync.*anomaly'
        ],
        'risk': 80,
        'description': 'SharePoint/OneDrive threat detected'
    },
    'google_workspace_threat': {
        'patterns': [
            r'google.*drive.*external.*share', r'google.*docs.*phishing',
            r'gmail.*suspicious.*forwarding', r'google.*workspace.*anomaly',
            r'google.*admin.*suspicious', r'google.*oauth.*abuse'
        ],
        'risk': 75,
        'description': 'Google Workspace security threat'
    },
    'file_exfiltration': {
        'patterns': [
            r'mass.*download.*files', r'bulk.*export.*data',
            r'download.*all.*files', r'external.*share.*sensitive',
            r'file.*sync.*external', r'data.*exfiltration'
        ],
        'risk': 85,
        'description': 'Potential data exfiltration via collaboration tools'
    },
    'account_compromise': {
        'patterns': [
            r'mfa.*bypassed', r'password.*changed.*unusual',
            r'login.*impossible.*travel', r'multiple.*failed.*mfa',
            r'session.*hijack', r'token.*stolen'
        ],
        'risk': 90,
        'description': 'Account compromise indicators detected'
    }
}

def haversine(lat1, lon1, lat2, lon2):
    R = 6371
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat/2)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon/2)**2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))

def scan_collaboration_event(event_type, event_data):
    """Scan collaboration platform events for threats"""
    findings = []
    risk = 0
    
    event_text = f"{event_type} {str(event_data)}".lower()
    
    for category, config in COLLAB_PATTERNS.items():
        for pattern in config['patterns']:
            if re.search(pattern, event_text, re.IGNORECASE):
                findings.append({
                    'type': category,
                    'risk': config['risk'],
                    'description': config['description'],
                    'matched_pattern': pattern[:50]
                })
                risk = max(risk, config['risk'])
                break
    
    return {'risk_score': risk, 'findings': findings}

@app.route('/health')
def health():
    return jsonify({
        "status": "healthy",
        "service": "ato-collab-protection",
        "users_tracked": len(login_history),
        "collab_alerts": len(collab_alerts),
        "features": [
            "login_anomaly_detection",
            "impossible_travel",
            "brute_force_detection",
            "session_hijack",
            "teams_protection",
            "slack_protection",
            "sharepoint_protection",
            "google_workspace_protection",
            "file_exfiltration",
            "account_compromise"
        ]
    })

# ========== LOGIN PROTECTION ==========

@app.route('/analyze/login', methods=['POST'])
def analyze_login():
    data = request.get_json()
    username = data.get('username', '')
    ip = data.get('ip', '')
    tenant = data.get('tenant', 'global')
    success = data.get('success', True)
    lat = data.get('lat', 0)
    lon = data.get('lon', 0)
    
    findings = []
    risk = 0
    
    history = login_history[username]
    
    # Brute force
    recent_fails = [l for l in failed_logins[username] if l['time'] > datetime.now() - timedelta(minutes=15)]
    if len(recent_fails) >= 5:
        findings.append({'type': 'brute_force', 'attempts': len(recent_fails), 'risk': 80})
        risk = max(risk, 80)
    
    # Impossible travel
    if len(history) >= 1:
        prev = history[-1]
        if prev.get('lat') and prev.get('lon') and lat and lon:
            dist = haversine(prev['lat'], prev['lon'], lat, lon)
            time_diff = max(0.01, (datetime.now() - prev['time']).total_seconds() / 3600)
            if dist / time_diff > 800:
                findings.append({'type': 'impossible_travel', 'distance_km': round(dist), 'time_hours': round(time_diff, 1), 'risk': 90})
                risk = max(risk, 90)
    
    # Session hijack
    if ip and len(history) >= 1:
        prev = history[-1]
        if prev.get('ip') and prev['ip'] != ip and success:
            findings.append({'type': 'session_hijack', 'prev_ip': prev['ip'], 'curr_ip': ip, 'risk': 75})
            risk = max(risk, 75)
    
    # Store login
    login_history[username].append({
        'time': datetime.now(), 'ip': ip, 'tenant': tenant,
        'success': success, 'lat': lat, 'lon': lon
    })
    if len(login_history[username]) > 100:
        login_history[username] = login_history[username][-100:]
    
    if not success:
        failed_logins[username].append({'time': datetime.now(), 'ip': ip})
    
    action = 'lock_account' if risk >= 80 else 'require_mfa' if risk >= 60 else 'alert' if risk >= 30 else 'allow'
    
    return jsonify({
        'username': username, 'tenant': tenant, 'risk_score': risk,
        'findings': findings, 'action': action, 'timestamp': datetime.now().isoformat()
    })

# ========== COLLABORATION PROTECTION ==========

@app.route('/analyze/collaboration', methods=['POST'])
def analyze_collaboration():
    """Analyze collaboration platform events (Teams, Slack, SharePoint, Google Workspace)"""
    data = request.get_json()
    platform = data.get('platform', 'unknown')  # teams, slack, sharepoint, google_workspace
    event_type = data.get('event_type', 'unknown')
    event_data = data.get('event_data', {})
    user = data.get('user', '')
    tenant = data.get('tenant', 'global')
    
    result = scan_collaboration_event(event_type, event_data)
    
    if result['risk_score'] >= 30:
        alert = {
            'timestamp': datetime.now().isoformat(),
            'platform': platform,
            'event_type': event_type,
            'user': user,
            'tenant': tenant,
            'risk_score': result['risk_score'],
            'findings': result['findings']
        }
        collab_alerts.append(alert)
        platform_events[platform].append(alert)
    
    action = 'block' if result['risk_score'] >= 80 else 'review' if result['risk_score'] >= 50 else 'monitor'
    
    return jsonify({
        'platform': platform,
        'risk_score': result['risk_score'],
        'findings': result['findings'],
        'action': action,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/collaboration/alerts')
def get_collab_alerts():
    """Get all collaboration platform alerts"""
    platform = request.args.get('platform', 'all')
    limit = request.args.get('limit', 50, type=int)
    
    alerts = list(collab_alerts)
    if platform != 'all':
        alerts = [a for a in alerts if a['platform'] == platform]
    
    return jsonify({
        'alerts': alerts[-limit:],
        'total': len(alerts),
        'by_platform': {
            'teams': len([a for a in collab_alerts if a['platform'] == 'teams']),
            'slack': len([a for a in collab_alerts if a['platform'] == 'slack']),
            'sharepoint': len([a for a in collab_alerts if a['platform'] == 'sharepoint']),
            'google_workspace': len([a for a in collab_alerts if a['platform'] == 'google_workspace'])
        }
    })

# ========== USERS ==========

@app.route('/users')
def get_users():
    tenant = request.args.get('tenant', 'global')
    users = []
    for username, history in login_history.items():
        fails = len([l for l in failed_logins[username] if l['time'] > datetime.now() - timedelta(hours=24)])
        risk = min(100, fails * 15)
        users.append({
            'username': username,
            'risk_score': risk,
            'failed_logins': fails,
            'total_logins': len(history),
            'locked': risk >= 80,
            'last_login': history[-1]['time'].isoformat() if history else None
        })
    users.sort(key=lambda u: u['risk_score'], reverse=True)
    return jsonify({'tenant': tenant, 'users': users[:50], 'total': len(users)})

# ========== STATS ==========

@app.route('/stats')
def get_stats():
    return jsonify({
        'login_protection': {
            'users_tracked': len(login_history),
            'brute_force_attempts': sum(len(v) for v in failed_logins.values()),
            'locked_accounts': sum(1 for u in login_history if any(l['success'] == False for l in login_history[u][-10:]) and len([l for l in failed_logins.get(u, []) if l['time'] > datetime.now() - timedelta(hours=24)]) >= 5)
        },
        'collaboration_protection': {
            'total_alerts': len(collab_alerts),
            'teams': len([a for a in collab_alerts if a['platform'] == 'teams']),
            'slack': len([a for a in collab_alerts if a['platform'] == 'slack']),
            'sharepoint': len([a for a in collab_alerts if a['platform'] == 'sharepoint']),
            'google_workspace': len([a for a in collab_alerts if a['platform'] == 'google_workspace'])
        }
    })

if __name__ == '__main__':
    print("🛡️ ATO + Collaboration Protection (Port 8056)")
    print("   Features: Login Anomaly, Teams, Slack, SharePoint, Google Workspace")
    app.run(host='0.0.0.0', port=8056, debug=False)
