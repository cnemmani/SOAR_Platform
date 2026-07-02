"""
SUPER POWERED AI Email Security Scanner
Catches: URL shorteners, obfuscated links, fake moderation, spoofing, and more
"""
from flask import Flask, make_response, request, jsonify, request
from flask_cors import CORS
import re, os, subprocess, threading, time, requests
from datetime import datetime
from collections import deque

app = Flask(__name__)
@app.before_request
def handle_cors_preflight():
    if request.method == 'OPTIONS':
        resp = make_response()
        resp.headers['Access-Control-Allow-Origin'] = '*'
        resp.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Tenant-ID'
        resp.headers['Access-Control-Allow-Methods'] = 'GET, PUT, POST, DELETE, OPTIONS, PATCH'
        return resp
@app.after_request
def add_cors(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Tenant-ID'
    response.headers['Access-Control-Allow-Methods'] = 'GET, PUT, POST, DELETE, OPTIONS, PATCH'
    return response

CORS(app)

OLLAMA_URL = "http://localhost:11434"
PIPELINE_URL = "http://localhost:8015/process"

detected_incidents = deque(maxlen=2000)
stats = {
    'total_scanned': 0, 'phishing': 0, 'bec': 0, 'spoofing': 0,
    'spam': 0, 'fraud_detected': 0, 'auto_blocked': 0, 'last_scan': None
}

# POWERFUL detection patterns
DETECTION_RULES = {
    # URL Manipulation
    "safelinks_obfuscation": {
        "patterns": ["safelinks.protection.outlook.com"],
        "risk": 25, "category": "URL_MANIPULATION", "severity": "high",
        "description": "Microsoft ATP Safelinks - real URL destination hidden"
    },
    "url_shortener": {
        "patterns": ["shorturl.fm", "bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly", "rb.gy"],
        "risk": 30, "category": "URL_MANIPULATION", "severity": "high",
        "description": "URL shortener detected - cannot verify destination"
    },
    "open_redirect": {
        "patterns": ["redirect=", "url=", "return_url=", "redirect_uri=", "callback="],
        "risk": 20, "category": "URL_MANIPULATION", "severity": "medium",
        "description": "Open redirect parameter - possible phishing chain"
    },
    # Social Engineering
    "spoofed_moderation": {
        "patterns": ["please moderate", "comment.*waiting", "approve.*comment", "wp-admin/comment", "moderation panel", "pending comment"],
        "risk": 25, "category": "SOCIAL_ENGINEERING", "severity": "high",
        "description": "Fake comment moderation email - common phishing template"
    },
    "ceo_impersonation": {
        "patterns": ["i am the ceo", "from the ceo", "ceo request", "executive request", "urgent wire transfer", "from the desk of"],
        "risk": 30, "category": "BEC_FRAUD", "severity": "critical",
        "description": "CEO/Executive impersonation - BEC attack"
    },
    "fake_invoice": {
        "patterns": ["invoice attached", "payment overdue", "outstanding invoice", "wire transfer", "bank details changed", "update payment"],
        "risk": 25, "category": "FINANCIAL_FRAUD", "severity": "high",
        "description": "Fake invoice or payment request"
    },
    "urgency_tactics": {
        "patterns": ["urgent", "immediately", "asap", "action required", "limited time", "expires", "deadline", "last chance"],
        "risk": 15, "category": "SOCIAL_ENGINEERING", "severity": "medium",
        "description": "Urgency pressure - psychological manipulation"
    },
    "fear_tactics": {
        "patterns": ["account.*locked", "account.*suspended", "security.*breach", "unauthorized.*access"],
        "risk": 20, "category": "SOCIAL_ENGINEERING", "severity": "high",
        "description": "Fear tactics - emotional manipulation"
    },
    # Indicators
    "external_ip": {
        "patterns": ["ip address:.*[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"],
        "risk": 10, "category": "INDICATOR", "severity": "low",
        "description": "External IP address embedded in email"
    },
    "multiple_action_links": {
        "patterns": ["approve it:.*trash it:.*spam it:"],
        "risk": 15, "category": "SOCIAL_ENGINEERING", "severity": "medium",
        "description": "Multiple action links - legitimate emails use single link"
    },
    "excessive_urls": {
        "patterns": ["(https?://[^ ]+){6,}"],
        "risk": 15, "category": "INDICATOR", "severity": "medium",
        "description": "Excessive URLs in email body"
    },
    "free_email_author": {
        "patterns": ["@gmail.com.*comment", "@yahoo.com.*comment", "@outlook.com.*comment"],
        "risk": 10, "category": "INDICATOR", "severity": "low",
        "description": "Random free email provider - likely spam bot"
    },
    "credential_phishing": {
        "patterns": ["verify your account", "update your password", "login.*required", "credential.*expired"],
        "risk": 25, "category": "PHISHING", "severity": "high",
        "description": "Credential harvesting attempt"
    },
    "gift_card_scam": {
        "patterns": ["gift card", "apple card", "google play card", "amazon card", "buy.*gift"],
        "risk": 25, "category": "FINANCIAL_FRAUD", "severity": "high",
        "description": "Gift card scam detected"
    },
    # Original patterns kept below

    # URL Shorteners (masked malicious links)
    'url_shortener': {
        'patterns': [r'shorturl\.\w+', r'bit\.ly', r'tinyurl\.com', r't\.co', r'ow\.ly', 
                    r'rb\.gy', r'cutt\.ly', r'tiny\.cc', r'is\.gd', r'short\.link'],
        'risk': 30,
        'description': 'Masked URL via shortener service'
    },
    # Obfuscated/Oversized URLs
    'obfuscated_url': {
        'patterns': [r'safelinks\.protection\.outlook\.com', r'data=05%', r'%[0-9A-F]{2}.*%[0-9A-F]{2}.*%[0-9A-F]{2}',
                    r'urldefense\.com', r'click\.pstmrk\.it', r'email\.mg\..*\.com'],
        'risk': 25,
        'description': 'Obfuscated/tracking URL detected'
    },
    # Fake moderation/approval
    'fake_moderation': {
        'patterns': [r'please moderate', r'waiting for your approval', r'comment.*waiting',
                    r'pending.*approval', r'moderation.*panel', r'comments.*waiting'],
        'risk': 20,
        'description': 'Fake moderation/approval request'
    },
    # Comment spam
    'comment_spam': {
        'patterns': [r'<a href=.*comment', r'comment:.*http', r'author:.*ip address',
                    r'currently.*comments.*waiting'],
        'risk': 20,
        'description': 'Comment spam with embedded links'
    },
    # Excessive URLs
    'excessive_urls': {
        'patterns': [r'(https?://.*){5,}'],  # 5+ URLs
        'risk': 20,
        'description': 'Excessive number of URLs'
    },
    # Phishing keywords
    'phishing_keywords': {
        'patterns': [r'urgent.*action', r'verify.*account', r'click.*here', r'suspend.*account',
                    r'password.*reset', r'login.*required', r'security.*update'],
        'risk': 15,
        'description': 'Phishing language detected'
    },
    # Spoofed sender
    'spoofed_sender': {
        'patterns': [r'from:.*<.*@.*>.*sent:.*to:.*<.*@.*>'],
        'risk': 15,
        'description': 'Email header manipulation'
    },
    # Fake approval links
    'fake_approval': {
        'patterns': [r'approve.*it:.*http', r'trash.*it:.*http', r'spam.*it:.*http',
                    r'wp-admin/comment\.php'],
        'risk': 25,
        'description': 'Fake approve/trash/spam links'
    },
    # Suspicious IPs (known bad)
    'known_bad_ip': {
        'patterns': [r'185\.237\.106\.\d+', r'81\.12\.124\.\d+'],
        'risk': 25,
        'description': 'Known malicious IP address'
    },

    "masked_url": {
        "patterns": ["shorturl\.fm", "bit\.ly", "tinyurl\.com", "short\.gy"],
        "risk": 25, "category": "OBFUSCATION",
        "description": "Masked URL via shortener service"
    },
    "tracking_url": {
        "patterns": ["safelinks\.protection\.outlook\.com", "urldefense\.com"],
        "risk": 20, "category": "OBFUSCATION",
        "description": "Obfuscated/tracking URL detected"
    },
    "fake_approval": {
        "patterns": ["approve.*it:.*http", "trash.*it:.*http", "spam.*it:.*http"],
        "risk": 20, "category": "SOCIAL_ENGINEERING",
        "description": "Fake approve/trash/spam links"
    },
    "known_malicious_ip": {
        "patterns": ["81\.12\.124\.150"],
        "risk": 15, "category": "THREAT_INTEL",
        "description": "Known malicious IP address"
    }
}

def analyze_email(email_data):
    results = {'threats': [], 'risk_score': 0, 'categories': [], 'actions': [], 'red_flags': []}
    
    subject = (email_data.get('subject', '') or '').lower()
    body = (email_data.get('body', '') or '').lower()
    sender = (email_data.get('sender', '') or '').lower()
    sender_ip = email_data.get('sender_ip', '')
    full_text = f"{subject} {body} {sender}"
    
    for category, config in DETECTION_RULES.items():
        for pattern in config['patterns']:
            if re.search(pattern, full_text, re.IGNORECASE):
                results['categories'].append(category)
                results['risk_score'] += config['risk']
                results['red_flags'].append(config['description'])
                break
    
    results['risk_score'] = min(100, results['risk_score'])
    
    # Determine threats
    if results['risk_score'] >= 60:
        results['threats'].append('phishing')
        results['threats'].append('spam')
        results['actions'] = ['block_sender', 'quarantine_email', 'notify_admin']
    elif results['risk_score'] >= 30:
        results['threats'].append('suspicious')
        results['actions'] = ['flag_for_review', 'warn_recipient']
    else:
        results['actions'] = ['monitor']
    
    # Auto-block known bad IPs
    if sender_ip and any(re.search(p, sender_ip) for p in ['185\.237\.106\.\d+', '81\.12\.124\.\d+']):
        results['actions'].append('block_ip')
    
    # Update stats
    stats['total_scanned'] += 1
    for t in results['threats']:
        if t in stats: stats[t] = stats.get(t, 0) + 1
    if 'block_sender' in results['actions']: stats['auto_blocked'] += 1
    if 'phishing' in results['threats']: stats['phishing'] += 1
    
    return results

def scan_mail_logs():
    count = 0
    log_file = '/var/log/mail.log'
    if not os.path.exists(log_file): return 0
    try:
        result = subprocess.run(['sudo', 'tail', '-50', log_file], capture_output=True, text=True, timeout=10)
        for line in result.stdout.strip().split('\n'):
            if not line.strip(): continue
            email_data = {'subject': '', 'body': line, 'sender': '', 'source': 'postfix_mta', 'timestamp': datetime.now().isoformat()}
            ip_match = re.search(r'\b([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\b', line)
            if ip_match: email_data['sender_ip'] = ip_match.group(1)
            result = analyze_email(email_data)
            if result['risk_score'] >= 20:
                detected_incidents.append({'timestamp': datetime.now().isoformat(), **email_data, 'analysis': result, 'source': 'email_gateway'})
                count += 1
    except: pass
    return count

def background_scanner():
    time.sleep(10)
    while True:
        count = scan_mail_logs()
        if count > 0: print(f'📧 {count} suspicious emails found')
        stats['last_scan'] = datetime.now().isoformat()
        time.sleep(30)

threading.Thread(target=background_scanner, daemon=True).start()

@app.route('/health')
def health():
    return jsonify({'status': 'healthy', 'service': 'super-email-scanner', 'stats': stats, 'patterns': len(DETECTION_RULES)})

@app.route('/incidents')
def get_incidents():
    return jsonify({'incidents': list(detected_incidents)[-100:], 'total': len(detected_incidents), 'stats': stats})

@app.route('/scan/email', methods=['POST'])
def scan_email():
    data = request.get_json()
    if not data: return jsonify({'error': 'No data'}), 400
    result = analyze_email(data)
    detected_incidents.append({'timestamp': datetime.now().isoformat(), **data, 'analysis': result, 'source': 'api'})
    return jsonify({
        'risk_score': result['risk_score'],
        'threats': result['threats'],
        'actions': result['actions'],
        'red_flags': result.get('red_flags', []),
        'severity': 'CRITICAL' if result['risk_score'] >= 80 else 'HIGH' if result['risk_score'] >= 60 else 'MEDIUM' if result['risk_score'] >= 30 else 'LOW'
    })

@app.route('/patterns')
def get_patterns():
    return jsonify({'detection_rules': {k: {'risk': v['risk'], 'desc': v['description']} for k, v in DETECTION_RULES.items()}})

if __name__ == '__main__':
    print("🛡️ SUPER POWERED Email Scanner (8022)")
    print(f"   Detection rules: {len(DETECTION_RULES)} categories")
    app.run(host='0.0.0.0', port=8022, debug=False)
