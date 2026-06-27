"""
Unified AI-Powered DLP + Email Security + Social Engineering Service
- DLP: Credit cards, SSN, API keys, passwords, PII
- Email Fraud: Phishing, BEC, Credential Harvesting
- Social Engineering: Impersonation, Pretexting, Baiting
- AI Analysis: Ollama LLM for threat classification & confidence scoring
"""
from flask import Flask, make_response, request, jsonify, request
from flask_cors import CORS
import re, json, os, subprocess, threading, time, requests
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

OLLAMA_URL = 'http://localhost:11434'
AI_MODEL = 'qwen2:0.5b'

# ==================== DLP PATTERNS ====================
DLP_PATTERNS = {
    'credit_card': {'pattern': r'\b(?:\d{4}[-\s]?){3}\d{4}\b', 'severity': 'critical', 'desc': 'Credit card number'},
    'ssn': {'pattern': r'\b\d{3}-\d{2}-\d{4}\b', 'severity': 'critical', 'desc': 'Social Security Number'},
    'api_key': {'pattern': r'\b(?:AIza|sk-|ghp_|xox[baprs]-)[A-Za-z0-9_\-]{20,}\b', 'severity': 'critical', 'desc': 'API key/token exposed'},
    'password_clear': {'pattern': r'(?:password|passwd|pwd)[\s:=]+[\S]{6,}', 'severity': 'high', 'desc': 'Password in plain text'},
    'aws_key': {'pattern': r'\bAKIA[0-9A-Z]{16}\b', 'severity': 'critical', 'desc': 'AWS Access Key'},
    'private_key': {'pattern': r'-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----', 'severity': 'critical', 'desc': 'Private key exposed'},
    'db_connection': {'pattern': r'(?:jdbc|mongodb|mysql|postgresql|redis)://[^/\s]+:[^/\s]+@', 'severity': 'critical', 'desc': 'Database connection string'},
    'pii_phone': {'pattern': r'\b(?:\+\d{1,3}[-.]?)?\(?\d{3}\)?[-.]?\d{3}[-.]?\d{4}\b', 'severity': 'medium', 'desc': 'Phone number (PII)'},
    'confidential': {'pattern': r'\b(?:confidential|proprietary|internal.only|do.not.forward|trade.secret)\b', 'severity': 'medium', 'desc': 'Confidential content'},
    'data_exfil': {'pattern': r'\b(?:upload|send|transfer|share).*(?:all|entire|complete|full).*(?:data|file|customer|client)', 'severity': 'high', 'desc': 'Potential data exfiltration'},
    'file_sensitive': {'pattern': r'\.(?:xlsx?|docx?|pptx?|pdf|csv|sql|bak|dump)\b', 'severity': 'low', 'desc': 'Sensitive file attachment'},
    'iban': {'pattern': r'\b[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b', 'severity': 'high', 'desc': 'IBAN bank account'},
}

# ==================== SOCIAL ENGINEERING PATTERNS ====================
SOCIAL_ENG_PATTERNS = {
    'phishing': [
        r'verify.your.account', r'click.here.to.login', r'update.your.password',
        r'account.suspended', r'security.alert', r'unusual.login',
        r'confirm.your.identity', r'limited.your.account', r'reactivate.your.account'
    ],
    'bec_fraud': [
        r'wire.transfer', r'invoice.attached', r'urgent.payment',
        r'change.bank.details', r'ceo.request', r'urgent.wire',
        r'payment.to.vendor', r'new.account.details'
    ],
    'credential_harvesting': [
        r'login.to.view', r'sign.in.to.access', r'verify.credentials',
        r're-enter.password', r'password.expired', r'unlock.account'
    ],
    'impersonation': [
        r'ceo', r'cfo', r'president', r'director', r'executive',
        r'sent.from.my.phone', r'quick.question', r'are.you.available'
    ],
    'urgency_pressure': [
        r'urgent', r'immediate', r'asap', r'deadline', r'critical',
        r'action.required', r'final.notice', r'last.warning'
    ]
}

# Storage
incidents = deque(maxlen=5000)
stats = {
    'total_scanned': 0, 'dlp_violations': 0, 'critical_dlp': 0,
    'phishing_detected': 0, 'bec_detected': 0, 'credential_harvesting': 0,
    'impersonation': 0, 'ai_analyzed': 0, 'last_scan': None
}

def get_ai_analysis(content, context='email'):
    """Use Ollama AI to analyze content for threats"""
    try:
        prompt = f"Analyze this {context} for security threats. Classify as: PHISHING, BEC_FRAUD, CREDENTIAL_HARVEST, IMPERSONATION, DLP_VIOLATION, or SAFE. Reply with classification and confidence 0-100. Content: {content[:300]}"
        
        resp = requests.post(f"{OLLAMA_URL}/api/generate",
            json={"model": AI_MODEL, "prompt": prompt, "stream": False,
                  "options": {"max_tokens": 30, "temperature": 0.1}}, timeout=8)
        
        if resp.status_code == 200:
            text = resp.json().get('response', '').strip().upper()
            # Parse AI response
            classification = 'SAFE'
            confidence = 50
            
            if 'PHISHING' in text: classification = 'PHISHING'; confidence = 85
            elif 'BEC' in text: classification = 'BEC_FRAUD'; confidence = 85
            elif 'CREDENTIAL' in text: classification = 'CREDENTIAL_HARVESTING'; confidence = 80
            elif 'IMPERSONATION' in text: classification = 'IMPERSONATION'; confidence = 75
            elif 'DLP' in text: classification = 'DLP_VIOLATION'; confidence = 90
            elif 'SAFE' in text: classification = 'SAFE'; confidence = 70
            
            # Extract numeric confidence if present
            import re
            conf_match = re.search(r'(\d{2,3})', text)
            if conf_match:
                confidence = min(100, int(conf_match.group(1)))
            
            return {'classification': classification, 'confidence': confidence, 'raw': text[:100]}
    except: pass
    return {'classification': 'SAFE', 'confidence': 50, 'raw': 'AI unavailable'}

def scan_content(content, source='email'):
    """Comprehensive scan: DLP + Social Engineering + AI"""
    results = {
        'dlp_violations': [],
        'social_threats': [],
        'ai_analysis': None,
        'overall_risk': 0
    }
    
    content_lower = content.lower()
    
    # 1. DLP Scan
    for rule_name, rule_info in DLP_PATTERNS.items():
        matches = re.findall(rule_info['pattern'], content, re.IGNORECASE)
        if matches:
            redacted = [m[:4] + '****' + m[-4:] if len(m) > 8 else '****' for m in matches[:3]]
            results['dlp_violations'].append({
                'rule': rule_name, 'severity': rule_info['severity'],
                'description': rule_info['desc'], 'match_count': len(matches),
                'redacted_samples': redacted
            })
    
    # 2. Social Engineering Scan
    for threat_type, patterns in SOCIAL_ENG_PATTERNS.items():
        for pattern in patterns:
            pattern_regex = pattern.replace('.', r'\s*')
            if re.search(pattern_regex, content_lower):
                results['social_threats'].append({
                    'type': threat_type,
                    'confidence': 75,
                    'indicator': pattern.replace('.', ' ')
                })
                break
    
    # 3. AI Analysis (for high-risk content)
    if results['dlp_violations'] or results['social_threats']:
        results['ai_analysis'] = get_ai_analysis(content, source)
        stats['ai_analyzed'] += 1
    
    # 4. Calculate overall risk
    risk = 0
    for v in results['dlp_violations']:
        if v['severity'] == 'critical': risk += 30
        elif v['severity'] == 'high': risk += 20
        else: risk += 10
    for t in results['social_threats']:
        risk += 15
    if results['ai_analysis'] and results['ai_analysis']['classification'] != 'SAFE':
        risk += results['ai_analysis']['confidence'] // 5
    
    results['overall_risk'] = min(100, risk)
    
    return results

def background_scanner():
    """Continuous background scanning"""
    print("🛡️ AI-Powered DLP & Email Security Scanner starting...")
    time.sleep(10)
    
    while True:
        try:
            count = 0
            # Scan email fraud alerts
            try:
                resp = requests.get('http://localhost:8025/api/email-fraud/alerts?limit=30', timeout=10)
                if resp.status_code == 200:
                    for alert in resp.json().get('alerts', []):
                        content = f"{alert.get('subject','')} {alert.get('body','')} {alert.get('email_from','')}"
                        results = scan_content(content[:2000], 'email_fraud')
                        
                        for v in results['dlp_violations']:
                            incidents.append({'type': 'dlp', 'source': 'email_fraud', **v, 'timestamp': datetime.now().isoformat()})
                            stats['dlp_violations'] += 1
                            if v['severity'] == 'critical': stats['critical_dlp'] += 1
                            count += 1
                        
                        for t in results['social_threats']:
                            incidents.append({'type': 'social', 'source': 'email_fraud', **t, 'timestamp': datetime.now().isoformat()})
                            if t['type'] == 'phishing': stats['phishing_detected'] += 1
                            elif t['type'] == 'bec_fraud': stats['bec_detected'] += 1
                            elif t['type'] == 'credential_harvesting': stats['credential_harvesting'] += 1
                            elif t['type'] == 'impersonation': stats['impersonation'] += 1
                            count += 1
            except: pass
            
            # Scan mail logs
            for log_path in ['/var/log/mail.log']:
                if os.path.exists(log_path):
                    try:
                        result = subprocess.run(['sudo', 'tail', '-100', log_path],
                                              capture_output=True, text=True, timeout=10)
                        results = scan_content(result.stdout[:5000], 'mail_log')
                        for v in results['dlp_violations']:
                            incidents.append({'type': 'dlp', 'source': 'mail_log', **v, 'timestamp': datetime.now().isoformat()})
                            stats['dlp_violations'] += 1
                            count += 1
                    except: pass
            
            stats['total_scanned'] += 1
            stats['last_scan'] = datetime.now().isoformat()
            if count > 0: print(f"🛡️ Scan: {count} incidents found")
            
        except Exception as e:
            print(f"Scanner error: {e}")
        
        time.sleep(45)

threading.Thread(target=background_scanner, daemon=True).start()

# ==================== API ENDPOINTS ====================
@app.route('/health')
def health():
    return jsonify({
        'status': 'healthy', 'service': 'dlp-ai-security',
        'ai_model': AI_MODEL, 'stats': stats, 'incidents': len(incidents)
    })

@app.route('/incidents')
def get_incidents():
    tenant = request.args.get('tenant', 'all')
    limit = request.args.get('limit', 100, type=int)
    incident_type = request.args.get('type', 'all')
    severity = request.args.get('severity', 'all')
    
    items = list(incidents)
    if incident_type != 'all':
        items = [i for i in items if i.get('type') == incident_type]
    if severity != 'all':
        items = [i for i in items if i.get('severity') == severity]
    
    return jsonify({
        'incidents': items[-limit:],
        'total': len(items),
        'stats': stats
    })

@app.route('/scan', methods=['POST'])
def scan_now():
    """Scan submitted content with AI"""
    data = request.get_json()
    if not data or not data.get('content'):
        return jsonify({'error': 'Content required'}), 400
    
    results = scan_content(data['content'], data.get('source', 'api'))
    
    # Store findings
    for v in results['dlp_violations']:
        incidents.append({'type': 'dlp', 'source': 'api', **v, 'timestamp': datetime.now().isoformat()})
        stats['dlp_violations'] += 1
    for t in results['social_threats']:
        incidents.append({'type': 'social', 'source': 'api', **t, 'timestamp': datetime.now().isoformat()})
    
    return jsonify(results)

@app.route('/patterns')
def get_patterns():
    tenant = request.args.get('tenant', 'all')
    return jsonify({
        'dlp_patterns': {k: {'severity': v['severity'], 'desc': v['desc']} for k, v in DLP_PATTERNS.items()},
        'social_patterns': {k: len(v) for k, v in SOCIAL_ENG_PATTERNS.items()},
        'ai_model': AI_MODEL
    })

@app.route('/stats')
def get_stats():
    return jsonify(stats)

if __name__ == '__main__':
    print("=" * 60)
    print(f"🛡️ AI-POWERED DLP & EMAIL SECURITY (Port 8031)")
    print(f"   🤖 Model: {AI_MODEL}")
    print(f"   📋 DLP Patterns: {len(DLP_PATTERNS)}")
    print(f"   🎣 Social Eng Patterns: {sum(len(v) for v in SOCIAL_ENG_PATTERNS.values())}")
    print("=" * 60)
    app.run(host='0.0.0.0', port=8061, debug=False)
