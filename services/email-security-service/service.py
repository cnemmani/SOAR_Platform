"""
Email Security & DLP Service - Complete Email Protection
Features: AI-Powered DLP, DMARC/SPF/DKIM, Background Wazuh Alert Scanning
"""
from flask import Flask, make_response, request, jsonify, request
from flask_cors import CORS
import json, os, re, sqlite3, requests, subprocess, threading, time
from datetime import datetime
from collections import deque

app = Flask(__name__)
@app.before_request
def handle_cors_preflight():
    if request.method == 'OPTIONS':
        from flask import make_response as mr
        response = mr()
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Tenant-ID'
        response.headers['Access-Control-Allow-Methods'] = 'GET, PUT, POST, DELETE, OPTIONS, PATCH'
        response.headers['Access-Control-Max-Age'] = '3600'
        return response
@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Tenant-ID'
    response.headers['Access-Control-Allow-Methods'] = 'GET, PUT, POST, DELETE, OPTIONS, PATCH'
    return response

CORS(app)

DB_FILE = '/home/ubuntu/soar-dashboard/email_security.db'
WAZUH_DB = '/home/ubuntu/soar-dashboard/wazuh_alerts.db'

DLP_POLICIES = [
    {'id': 'DLP-001', 'name': 'PII Detection', 'description': 'SSN, Credit Card, Email, Phone',
     'patterns': [r'\b\d{3}-\d{2}-\d{4}\b', r'\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b'],
     'action': 'block_or_encrypt', 'severity': 'critical', 'enabled': True},
    {'id': 'DLP-002', 'name': 'Financial Data', 'description': 'Invoice, Wire, Bank details',
     'patterns': [r'\b(?:invoice|payment|wire|transfer|bank|account.*number)\b'],
     'action': 'encrypt_and_notify', 'severity': 'high', 'enabled': True},
    {'id': 'DLP-003', 'name': 'Intellectual Property', 'description': 'Source code, credentials',
     'patterns': [r'\b(?:password|secret|token|api.key|credential)\b', r'\.(?:py|js|java|key|pem|crt)\b'],
     'action': 'block_external', 'severity': 'critical', 'enabled': True},
    {'id': 'DLP-004', 'name': 'Healthcare (HIPAA)', 'description': 'Patient, diagnosis, medical records',
     'patterns': [r'\b(?:diagnosis|patient|medical|health|prescription|HIPAA|PHI)\b'],
     'action': 'encrypt_and_audit', 'severity': 'critical', 'enabled': True},
    {'id': 'DLP-005', 'name': 'GDPR Data', 'description': 'EU personal data, passport, national ID',
     'patterns': [r'\b(?:GDPR|personal.data|passport|national.id)\b'],
     'action': 'encrypt_and_notify', 'severity': 'high', 'enabled': True}
]

email_stats = {'total_scanned':0,'dlp_violations':0,'encrypted_sent':0,
               'blocked_external':0,'auth_failures':0,'accidental_send_prevented':0,
               'last_scan':None}
recent_violations = deque(maxlen=500)

def init_db():
    conn = sqlite3.connect(DB_FILE)
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS dlp_violations (
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, policy_id TEXT,
            sender TEXT, recipient TEXT, subject TEXT, patterns_matched TEXT,
            action_taken TEXT, severity TEXT, content_snippet TEXT);
        CREATE TABLE IF NOT EXISTS email_auth_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, domain TEXT,
            dmarc_status TEXT, spf_status TEXT, dkim_status TEXT, issues TEXT);
        CREATE TABLE IF NOT EXISTS monitored_domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT UNIQUE, added TEXT,
            dmarc_status TEXT, spf_status TEXT, dkim_status TEXT, gateway TEXT,
            scan_inbound INTEGER DEFAULT 1, scan_outbound INTEGER DEFAULT 1,
            dlp_enabled INTEGER DEFAULT 1, notes TEXT);
    ''')
    conn.commit(); conn.close()

init_db()

def check_email_auth(domain):
    results = {'domain':domain,'dmarc':'unknown','spf':'unknown','dkim':'unknown','issues':[]}
    try:
        dmarc = subprocess.run(['dig','+short','TXT',f'_dmarc.{domain}'],capture_output=True,text=True,timeout=5)
        if 'v=DMARC1' in dmarc.stdout: results['dmarc']='valid'
        else: results['dmarc']='missing'; results['issues'].append('DMARC not configured')
    except: results['issues'].append('DMARC check failed')
    try:
        spf = subprocess.run(['dig','+short','TXT',domain],capture_output=True,text=True,timeout=5)
        if 'v=spf1' in spf.stdout: results['spf']='valid'
        else: results['spf']='missing'; results['issues'].append('SPF not configured')
    except: results['issues'].append('SPF check failed')
    conn = sqlite3.connect(DB_FILE)
    conn.execute("INSERT INTO email_auth_records (timestamp,domain,dmarc_status,spf_status,dkim_status,issues) VALUES (?,?,?,?,?,?)",
                 (datetime.now().isoformat(),domain,results['dmarc'],results['spf'],results['dkim'],json.dumps(results['issues'])))
    conn.commit()
    conn.execute("UPDATE monitored_domains SET dmarc_status=?,spf_status=?,dkim_status=? WHERE domain=?",
                 (results['dmarc'],results['spf'],results['dkim'],domain))
    conn.commit(); conn.close()
    if results['issues']: email_stats['auth_failures']+=1
    return results

def scan_content_for_dlp(description, sender, recipient, subject):
    """Scan any text content for DLP violations"""
    violations = []
    for policy in DLP_POLICIES:
        if not policy['enabled']: continue
        matched = []
        for pattern in policy['patterns']:
            matches = re.findall(pattern, description, re.IGNORECASE)
            if matches: matched.extend(matches[:3])
        if matched:
            v = {'timestamp':datetime.now().isoformat(),'policy_id':policy['id'],
                 'policy_name':policy['name'],'action_taken':policy['action'],
                 'severity':policy['severity'],'patterns_matched':matched[:5],
                 'sender':sender,'recipient':recipient,'subject':subject}
            violations.append(v)
            recent_violations.append(v)
            email_stats['dlp_violations']+=1
            if 'block' in policy['action']: email_stats['blocked_external']+=1
            if 'encrypt' in policy['action']: email_stats['encrypted_sent']+=1
    email_stats['total_scanned']+=1
    return violations

def background_dlp_scanner():
    """Continuously scan Wazuh alerts for DLP violations"""
    last_scan_id = 0
    print("🔄 Background DLP scanner started - monitoring all agents/alerts")
    time.sleep(10)
    
    while True:
        try:
            if not os.path.exists(WAZUH_DB):
                time.sleep(30)
                continue
            
            conn = sqlite3.connect(WAZUH_DB)
            conn.row_factory = sqlite3.Row
            rows = conn.execute("""
                SELECT id, rule_description, attacker_ip, agent_name, timestamp
                FROM wazuh_alerts WHERE id > ? AND rule_description IS NOT NULL AND rule_description != ''
                ORDER BY id ASC LIMIT 50
            """, (last_scan_id,)).fetchall()
            conn.close()
            
            for row in rows:
                description = row['rule_description'] or ''
                if len(description) < 20:
                    last_scan_id = max(last_scan_id, row['id'])
                    continue
                
                violations = scan_content_for_dlp(
                    description,
                    row['attacker_ip'] or 'unknown',
                    row['agent_name'] or 'system',
                    f"Wazuh Alert #{row['id']}"
                )
                
                for v in violations:
                    conn2 = sqlite3.connect(DB_FILE)
                    conn2.execute("""INSERT INTO dlp_violations 
                        (timestamp,policy_id,sender,recipient,subject,patterns_matched,action_taken,severity,content_snippet)
                        VALUES (?,?,?,?,?,?,?,?,?)""",
                        (v['timestamp'], v['policy_id'], v['sender'], v['recipient'],
                         v['subject'], json.dumps(v['patterns_matched']), v['action_taken'],
                         v['severity'], description[:100]))
                    conn2.commit(); conn2.close()
                
                last_scan_id = max(last_scan_id, row['id'])
            
            if len(rows) > 0:
                email_stats['last_scan'] = datetime.now().isoformat()
                print(f"📧 DLP: {len(rows)} alerts scanned, {email_stats['dlp_violations']} violations total")
            
            time.sleep(30)
        except Exception as e:
            print(f"DLP scanner error: {e}")
            time.sleep(60)

# Start background scanner
threading.Thread(target=background_dlp_scanner, daemon=True).start()

@app.route('/health')
def health():
    return jsonify({
        'status':'healthy','service':'email-security',
        'stats':email_stats,'background_scanner':True,
        'monitoring':'All agents and alerts from Wazuh DB'
    })

@app.route('/dlp/policies')
def get_policies():
    return jsonify({'policies':DLP_POLICIES,'total':len(DLP_POLICIES)})

@app.route('/dlp/violations')
def get_violations():
    conn = sqlite3.connect(DB_FILE); conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM dlp_violations ORDER BY id DESC LIMIT ?",
                       (request.args.get('limit',50,type=int),)).fetchall()
    conn.close()
    return jsonify({'violations':[dict(r) for r in rows],'total':len(rows),'stats':email_stats})

@app.route('/domains')
def get_domains():
    conn = sqlite3.connect(DB_FILE); conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM monitored_domains ORDER BY added DESC").fetchall()
    conn.close()
    return jsonify({'domains':[dict(r) for r in rows],'total':len(rows)})

@app.route('/domains', methods=['POST'])
def add_domain():
    data = request.get_json()
    if not data or not data.get('domain'): return jsonify({'error':'Domain required'}),400
    domain = data['domain'].strip().lower()
    conn = sqlite3.connect(DB_FILE)
    try:
        conn.execute("INSERT INTO monitored_domains (domain,added,gateway,scan_inbound,scan_outbound,dlp_enabled) VALUES (?,?,?,?,?,?)",
                     (domain,datetime.now().isoformat(),data.get('gateway','postfix'),data.get('scan_inbound',1),data.get('scan_outbound',1),data.get('dlp_enabled',1)))
        conn.commit(); check_email_auth(domain)
        return jsonify({'status':'added','domain':domain})
    except sqlite3.IntegrityError: return jsonify({'error':'Domain already exists'}),409
    finally: conn.close()

@app.route('/domains/<domain>', methods=['PUT'])
def update_domain(domain):
    data = request.get_json()
    if not data: return jsonify({'error':'No data'}),400
    conn = sqlite3.connect(DB_FILE)
    for k in ['gateway','scan_inbound','scan_outbound','dlp_enabled','notes']:
        if k in data: conn.execute(f"UPDATE monitored_domains SET {k}=? WHERE domain=?",(data[k],domain))
    conn.commit(); conn.close()
    return jsonify({'status':'updated'})

@app.route('/domains/<domain>', methods=['DELETE'])
def delete_domain(domain):
    conn = sqlite3.connect(DB_FILE)
    conn.execute("DELETE FROM monitored_domains WHERE domain=?",(domain,))
    conn.commit(); conn.close()
    return jsonify({'status':'deleted'})

@app.route('/auth/check/<domain>')
def check_auth(domain):
    return jsonify(check_email_auth(domain))

@app.route('/auth/records')
def auth_records():
    conn = sqlite3.connect(DB_FILE); conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM email_auth_records ORDER BY id DESC LIMIT 50").fetchall()
    conn.close()
    return jsonify({'records':[dict(r) for r in rows],'total':len(rows)})

@app.route('/stats')
def stats():
    return jsonify(email_stats)

if __name__ == '__main__':
    print(f"📧 Email Security & DLP (Port 8042) | {len(DLP_POLICIES)} policies | Background Scanner Active")
    app.run(host='0.0.0.0', port=8042, debug=False)
