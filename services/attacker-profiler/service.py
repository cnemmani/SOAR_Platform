import sys; sys.path.insert(0, "..")
"""Attacker Profiler with Bot Detection Integration"""
from flask import Flask, request, jsonify
from flask_cors import CORS
import requests, re
from datetime import datetime
from collections import defaultdict

app = Flask(__name__)
CORS(app)

profiles = defaultdict(lambda: {
    'first_seen': None, 'last_seen': None, 'total_attempts': 0,
    'usernames': set(), 'ports': set(), 'classification': 'unknown',
    'risk_score': 0, 'vpn_detected': False, 'tor_detected': False,
    'is_bot': False, 'bot_type': 'unknown', 'bot_score': 0
})

BOT_SERVICE = 'http://localhost:8020'
VPN_SERVICE = 'http://localhost:8004'
GEO_SERVICE = 'http://localhost:8003'

@app.route('/health')
def health():
    return jsonify({
        'status': 'healthy', 'service': 'attacker-profiler',
        'profiles': len(profiles),
        'bot_integration': True
    })

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json() or {}
    ip = data.get('src_ip', data.get('ip', ''))
    if not ip: return jsonify({'error': 'IP required'}), 400
    
    profile = profiles[ip]
    now = datetime.now()
    if not profile['first_seen']: profile['first_seen'] = now.isoformat()
    profile['last_seen'] = now.isoformat()
    profile['total_attempts'] += 1
    if data.get('username'): profile['usernames'].add(data['username'])
    if data.get('port'): profile['ports'].add(str(data['port']))
    
    # Check VPN/TOR
    try:
        vpn_r = requests.get(f'{VPN_SERVICE}/check/{ip}', timeout=5)
        if vpn_r.status_code == 200:
            vpn_data = vpn_r.json()
            profile['vpn_detected'] = vpn_data.get('is_anonymized', False)
            profile['tor_detected'] = 'tor' in str(vpn_data).lower()
    except: pass
    
    # 🤖 Bot Detection
    try:
        bot_r = requests.post(f'{BOT_SERVICE}/analyze', json={
            'src_ip': ip, 'username': data.get('username', ''),
            'port': str(data.get('port', '')), 'command': str(data.get('data', {}))[:200],
            'user_agent': data.get('user_agent', '')
        }, timeout=10)
        if bot_r.status_code == 200:
            bot_data = bot_r.json()
            profile['is_bot'] = bot_data.get('is_bot', False)
            profile['bot_score'] = bot_data.get('bot_score', 0)
            profile['bot_type'] = bot_data.get('specific_type', 'unknown')
    except: pass
    
    # Calculate risk score
    risk = 0
    if profile['vpn_detected']: risk += 25
    if profile['tor_detected']: risk += 30
    if profile['is_bot']: risk += 35
    if profile['bot_score'] >= 80: risk += 20
    if profile['total_attempts'] > 10: risk += 15
    profile['risk_score'] = min(100, risk)
    
    # Classify
    if profile['is_bot'] and profile['bot_score'] >= 80:
        profile['classification'] = f"CONFIRMED_BOT_{profile['bot_type']}"
    elif profile['is_bot']:
        profile['classification'] = 'LIKELY_BOT'
    elif profile['vpn_detected'] or profile['tor_detected']:
        profile['classification'] = 'ADVERSARY_ANONYMIZED'
    else:
        profile['classification'] = 'PERSISTENT_SCANNER' if profile['total_attempts'] > 5 else 'CASUAL_ATTEMPT'
    
    return jsonify({
        'ip': ip,
        'classification': profile['classification'],
        'risk_score': profile['risk_score'],
        'is_bot': profile['is_bot'],
        'bot_type': profile['bot_type'],
        'bot_score': profile['bot_score'],
        'vpn_detected': profile['vpn_detected'],
        'tor_detected': profile['tor_detected'],
        'total_attempts': profile['total_attempts'],
        'first_seen': profile['first_seen'],
        'last_seen': profile['last_seen']
    })

@app.route('/profile/<ip>')
def get_profile(ip):
    if ip not in profiles: return jsonify({'error': 'Not found'}), 404
    p = dict(profiles[ip])
    p['usernames'] = list(p['usernames'])
    p['ports'] = list(p['ports'])
    return jsonify(p)

@app.route('/profiles')
def all_profiles():
    plist = []
    for ip, p in profiles.items():
        if p['total_attempts'] > 0:
            plist.append({'ip': ip, 'classification': p['classification'], 
                         'risk_score': p['risk_score'], 'is_bot': p['is_bot'],
                         'bot_type': p['bot_type'], 'attempts': p['total_attempts'],
                         'vpn': p['vpn_detected'], 'tor': p['tor_detected']})
    plist.sort(key=lambda x: x['risk_score'], reverse=True)
    return jsonify({'total': len(plist), 'profiles': plist[:100]})

if __name__ == '__main__':
    print("👤 Attacker Profiler + Bot Detection (Port 8016)")
    app.run(host='0.0.0.0', port=8016, debug=False)
