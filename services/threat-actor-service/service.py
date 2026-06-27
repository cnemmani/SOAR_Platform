from flask import Flask, make_response, request, jsonify, request
from flask_cors import CORS
import sqlite3
from collections import defaultdict
from datetime import datetime

app = Flask(__name__)
@app.before_request
def handle_cors_preflight():
    if request.method == 'OPTIONS':
        resp = make_response()
        resp.headers['Access-Control-Allow-Origin'] = '*'
        resp.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Tenant-ID'
        resp.headers['Access-Control-Allow-Methods'] = 'GET, PUT, POST, DELETE, OPTIONS, PATCH'
        resp.headers['Access-Control-Max-Age'] = '3600'
        return resp

@app.after_request
def add_cors(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Tenant-ID'
    response.headers['Access-Control-Allow-Methods'] = 'GET, PUT, POST, DELETE, OPTIONS, PATCH'
    return response

CORS(app)

DB_PATH = "/home/ubuntu/soar-dashboard/wazuh_alerts.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def classify_by_rules(ip, stats):
    total = stats.get('total_attacks', 0)
    targets = stats.get('unique_targets', 0)
    velocity = stats.get('attacks_per_hour', 0)
    severity = stats.get('max_severity', 0)
    
    if velocity >= 5 and targets <= 2:
        return {'type': 'Automated Threat', 'risk_score': min(100, 30 + velocity * 10)}
    elif targets >= 3 and severity >= 7:
        return {'type': 'APT Group', 'risk_score': min(100, 40 + targets * 10)}
    elif targets <= 2 and severity >= 5:
        return {'type': 'Targeted Attacker', 'risk_score': min(100, 20 + severity * 5)}
    else:
        return {'type': 'Opportunistic Attacker', 'risk_score': min(100, total * 2)}

@app.route('/health')
def health():
    return jsonify({'status': 'healthy', 'service': 'threat-actors'})

@app.route('/threat-actors')
def get_threat_actors():
    conn = get_db()
    rows = conn.execute("""
        SELECT attacker_ip, agent_name, severity, rule_description, timestamp
        FROM wazuh_alerts WHERE attacker_ip IS NOT NULL AND attacker_ip != '' AND severity >= 3
        ORDER BY timestamp DESC LIMIT 100000
    """).fetchall()
    conn.close()
    
    if not rows:
        return jsonify({'threat_actors': [], 'total': 0, 'summary': {}})
    
    ip_stats = defaultdict(lambda: {'total_attacks': 0, 'unique_targets': set(), 'max_severity': 0,
                                     'first_seen': None, 'last_seen': None, 'timestamps': []})
    
    for row in rows:
        ip = row['attacker_ip']
        if not ip: continue
        p = ip_stats[ip]
        p['total_attacks'] += 1
        p['max_severity'] = max(p['max_severity'], row['severity'] or 0)
        if row['agent_name']: p['unique_targets'].add(row['agent_name'])
        ts = row['timestamp']
        if ts:
            p['timestamps'].append(ts)
            if not p['first_seen'] or ts < p['first_seen']: p['first_seen'] = ts
            if not p['last_seen'] or ts > p['last_seen']: p['last_seen'] = ts
    
    for ip, p in ip_stats.items():
        if p['first_seen'] and p['last_seen'] and p['first_seen'] != p['last_seen']:
            try:
                first = datetime.fromisoformat(str(p['first_seen']).replace('Z','+00:00'))
                last = datetime.fromisoformat(str(p['last_seen']).replace('Z','+00:00'))
                hours = max(1, (last-first).total_seconds()/3600)
                p['attacks_per_hour'] = round(p['total_attacks']/hours, 1)
            except: p['attacks_per_hour'] = p['total_attacks']
        else: p['attacks_per_hour'] = p['total_attacks']
        p['unique_targets'] = len(p['unique_targets'])
    
    threat_actors = []
    for ip, p in ip_stats.items():
        c = classify_by_rules(ip, dict(p))
        threat_actors.append({
            'ip': ip, 'type': c['type'], 'risk_score': c['risk_score'],
            'total_attacks': p['total_attacks'], 'max_severity': p['max_severity'],
            'unique_targets': p['unique_targets'], 'attacks_per_hour': p['attacks_per_hour']
        })
    
    threat_actors.sort(key=lambda x: x['risk_score'], reverse=True)
    
    summary = {
        'automated': len([a for a in threat_actors if 'Automated' in a['type']]),
        'apt_groups': len([a for a in threat_actors if 'APT' in a['type']]),
        'targeted': len([a for a in threat_actors if 'Targeted' in a['type']]),
        'opportunistic': len([a for a in threat_actors if 'Opportunistic' in a['type']])
    }
    
    return jsonify({'threat_actors': threat_actors[:50], 'total': len(threat_actors), 'summary': summary})

@app.route('/analyze/<ip>')
def analyze_ip(ip):
    conn = get_db()
    rows = conn.execute("""
        SELECT agent_name, severity FROM wazuh_alerts 
        WHERE attacker_ip = ? LIMIT 5000
    """, (ip,)).fetchall()
    conn.close()
    
    stats = {
        'total_attacks': len(rows),
        'unique_targets': len(set(r['agent_name'] for r in rows if r['agent_name'])),
        'max_severity': max((r['severity'] or 0) for r in rows) if rows else 0
    }
    classification = classify_by_rules(ip, stats)
    return jsonify({
        'ip': ip, 'type': classification['type'], 'risk_score': classification['risk_score'],
        'total_attacks': stats['total_attacks'], 'unique_targets': stats['unique_targets']
    })

if __name__ == '__main__':
    print("👤 Threat Actor Service (Port 8020)")
    app.run(host='0.0.0.0', port=8020, debug=False)
