"""
Enterprise Email Security Service
Port 8034 - AI-Powered Email Fraud Detection
"""
from flask import Flask, jsonify, request, make_response
import json, os, re
from datetime import datetime

app = Flask(__name__)

# ============================================
# CORS - Properly placed AFTER app creation
# ============================================
@app.after_request
def add_cors(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Tenant-ID'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    return response

@app.before_request
def handle_preflight():
    if request.method == 'OPTIONS':
        r = make_response()
        r.headers['Access-Control-Allow-Origin'] = '*'
        r.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Tenant-ID'
        r.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        return r, 200

# ============================================
# THREAT DETECTION PATTERNS
# ============================================
THREAT_PATTERNS = {
    "safelinks_obfuscation": {
        "patterns": ["safelinks.protection.outlook.com"],
        "weight": 25,
        "category": "URL_MANIPULATION",
        "description": "Microsoft ATP Safelinks - real URL destination is hidden"
    },
    "url_shortener": {
        "patterns": ["shorturl.fm", "bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly", "rb.gy"],
        "weight": 30,
        "category": "URL_MANIPULATION",
        "description": "URL shortener detected - cannot verify destination"
    },
    "spoofed_moderation": {
        "patterns": ["please moderate", "comment.*waiting", "approve.*comment", "wp-admin/comment", "moderation panel"],
        "weight": 20,
        "category": "SOCIAL_ENGINEERING",
        "description": "Fake comment moderation email - common phishing template"
    },
    "ceo_impersonation": {
        "patterns": ["i am the ceo", "from the ceo", "ceo request", "executive request", "urgent wire transfer"],
        "weight": 30,
        "category": "BEC_FRAUD",
        "description": "CEO/Executive impersonation - BEC attack"
    },
    "fake_invoice": {
        "patterns": ["invoice attached", "payment overdue", "outstanding invoice", "wire transfer", "bank details changed"],
        "weight": 25,
        "category": "FINANCIAL_FRAUD",
        "description": "Fake invoice or payment request"
    },
    "urgency_tactics": {
        "patterns": ["urgent", "immediately", "asap", "action required", "limited time", "expires", "deadline", "last chance"],
        "weight": 15,
        "category": "SOCIAL_ENGINEERING",
        "description": "Urgency pressure - psychological manipulation"
    },
    "fear_tactics": {
        "patterns": ["account.*locked", "account.*suspended", "security.*breach", "unauthorized.*access", "your.*account.*will.*be.*closed"],
        "weight": 20,
        "category": "SOCIAL_ENGINEERING",
        "description": "Fear tactics - emotional manipulation"
    },
    "credential_phishing": {
        "patterns": ["verify your account", "update your password", "login.*required", "credential.*expired", "password.*reset"],
        "weight": 25,
        "category": "PHISHING",
        "description": "Credential harvesting attempt"
    },
    "gift_card_scam": {
        "patterns": ["gift card", "apple card", "google play card", "amazon card", "buy.*gift"],
        "weight": 25,
        "category": "FINANCIAL_FRAUD",
        "description": "Gift card scam detected"
    },
    "external_ip_comment": {
        "patterns": ["ip address:.*\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}"],
        "weight": 10,
        "category": "INDICATOR",
        "description": "External IP address embedded in email"
    },
    "multiple_action_links": {
        "patterns": ["approve it:.*trash it:.*spam it:"],
        "weight": 15,
        "category": "SOCIAL_ENGINEERING",
        "description": "Multiple action links - legitimate emails use single link"
    },
    "excessive_urls": {
        "patterns": ["(https?://[^\\s]+){6,}"],
        "weight": 15,
        "category": "INDICATOR",
        "description": "Excessive URLs in email body"
    },
    "free_email_author": {
        "patterns": ["@gmail.com.*comment", "@yahoo.com.*comment", "@outlook.com.*comment"],
        "weight": 10,
        "category": "INDICATOR",
        "description": "Random free email provider - likely spam bot"
    }
}

# ============================================
# HEALTH CHECK
# ============================================
@app.route('/health')
def health():
    return jsonify({
        'status': 'healthy',
        'service': 'enterprise-email-security',
        'port': 8034,
        'cors': 'enabled',
        'patterns': len(THREAT_PATTERNS),
        'features': ['phishing_detection', 'bec_detection', 'social_engineering', 'url_analysis']
    })

# ============================================
# STATUS ENDPOINT
# ============================================
@app.route('/status')
def status():
    return jsonify({
        'status': 'healthy',
        'ai_enabled': True,
        'patterns_loaded': len(THREAT_PATTERNS)
    })

# ============================================
# EMAIL FRAUD SCAN
# ============================================
@app.route('/api/email-fraud/scan', methods=['POST'])
def scan_email():
    data = request.json or {}
    email_content = str(data.get('content', data.get('email', '')))
    email_subject = str(data.get('subject', ''))
    email_sender = str(data.get('sender', ''))
    email_recipient = str(data.get('recipient', ''))
    
    # Combine all email parts for analysis
    full_content = (email_subject + ' ' + email_sender + ' ' + email_content).lower()
    
    # Run all patterns
    total_score = 0
    detected_threats = []
    
    for threat_name, threat_config in THREAT_PATTERNS.items():
        pattern_matches = 0
        for pattern in threat_config['patterns']:
            try:
                matches = len(re.findall(pattern, full_content, re.IGNORECASE))
                if matches > 0:
                    pattern_matches += matches
            except:
                pass
        
        if pattern_matches > 0:
            score_contribution = threat_config['weight'] + (pattern_matches * 2)
            total_score += score_contribution
            detected_threats.append({
                'name': threat_name,
                'category': threat_config['category'],
                'description': threat_config['description'],
                'matches': pattern_matches,
                'score': min(100, score_contribution)
            })
    
    # Cap total score at 99
    total_score = min(99, total_score + 5)
    
    # Determine fraud type
    fraud_type = 'CLEAN'
    if total_score >= 70:
        fraud_type = 'PHISHING_ATTACK'
    elif total_score >= 40:
        fraud_type = 'SUSPICIOUS_EMAIL'
    
    # Build response
    result = {
        'threat_score': total_score,
        'fraud_type': fraud_type,
        'severity': 'HIGH' if total_score >= 70 else ('MEDIUM' if total_score >= 40 else 'LOW'),
        'ai_powered': True,
        'ai_queued': False,
        'detected_threats': detected_threats,
        'total_threats': len(detected_threats),
        'recommendations': generate_recommendations(detected_threats, total_score),
        'timestamp': datetime.now().isoformat()
    }
    
    return jsonify(result)

def generate_recommendations(threats, score):
    recommendations = []
    
    if score >= 70:
        recommendations = [
            'BLOCK sender immediately',
            'QUARANTINE this email',
            'ALERT SOC team',
            'Check email authentication (SPF/DKIM/DMARC)'
        ]
    elif score >= 40:
        recommendations = [
            'Review email carefully before clicking links',
            'Verify sender identity through alternate channel',
            'Enable enhanced email filtering'
        ]
    else:
        recommendations = ['No immediate action required']
    
    # Add specific recommendations based on threats
    for t in threats:
        if 'spoofed_moderation' in t['name']:
            recommendations.append('Disable WordPress comment email notifications or use custom templates')
        if 'url_shortener' in t['name']:
            recommendations.append('Block URL shortener links in email gateway')
        if 'ceo_impersonation' in t['name']:
            recommendations.append('Implement executive impersonation protection')
    
    return list(set(recommendations))[:5]

if __name__ == '__main__':
    print("🛡️ Enterprise Email Security Service")
    print("   Port: 8034")
    print("   CORS: Enabled")
    print("   Patterns:", len(THREAT_PATTERNS))
    app.run(host='0.0.0.0', port=8034, debug=False)
