import sys; sys.path.insert(0, "..")
"""
Anomaly Detection Service - Tenant-Aware
"""
from flask import Flask, jsonify, request, make_response
from flask_cors import CORS
import sqlite3, random, os
from datetime import datetime, timedelta

app = Flask(__name__)
@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Tenant-ID'
    response.headers['Access-Control-Allow-Methods'] = 'GET, PUT, POST, DELETE, OPTIONS, PATCH'
    response.headers['Access-Control-Max-Age'] = '3600'
    return response

@app.before_request
def handle_preflight():
    if request.method == 'OPTIONS':
        response = make_response()
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
    response.headers['Access-Control-Max-Age'] = '3600'
    return response

@app.before_request
def handle_preflight():
    if request.method == 'OPTIONS':
        response = make_response()
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
    response.headers['Access-Control-Max-Age'] = '3600'
    return response

@app.before_request
def handle_preflight():
    if request.method == 'OPTIONS':
        response = make_response()
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
    response.headers['Access-Control-Max-Age'] = '3600'
    return response

@app.before_request
def handle_preflight():
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Tenant-ID'
        response.headers['Access-Control-Allow-Methods'] = 'GET, PUT, POST, DELETE, OPTIONS, PATCH'
        response.headers['Access-Control-Max-Age'] = '3600'
        return response

CORS(app)
DB_PATH = "/home/ubuntu/soar-dashboard/wazuh_alerts.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def filter_by_tenant(query_results, tenant):
    """Filter results by tenant based on agent name patterns"""
    if not tenant or tenant == 'all' or tenant == 'global':
        return query_results
    
    patterns = {
        'cokpit': lambda a: (a.get('agent_name','') or '').lower().startswith('cokpit'),
        'zelarsoft': lambda a: (a.get('agent_name','') or '').lower().startswith('zlr') or (a.get('agent_name','') or '').lower().startswith('zelar'),
        'vps': lambda a: (a.get('agent_name','') or '').lower().startswith('vps'),
        'finance': lambda a: (a.get('agent_name','') or '').lower().startswith('fin'),
    }
    filter_fn = patterns.get(tenant, lambda a: tenant.lower() in (a.get('agent_name','') or '').lower())
    return [a for a in query_results if filter_fn(a)]

@app.route('/health')
def health():
    conn = get_db()
    total = conn.execute("SELECT COUNT(*) FROM wazuh_alerts").fetchone()[0]
    conn.close()
    return jsonify({'status':'healthy','service':'anomaly-detector','total_alerts':total})

@app.route('/anomalies')
def get_anomalies():
    tenant = request.args.get('tenant', 'all')
    conn = get_db()
    
    # Get recent high-severity alerts as anomalies
    rows = conn.execute("""
        SELECT attacker_ip, agent_name, severity, rule_description, timestamp
        FROM wazuh_alerts WHERE severity >= 7
        ORDER BY timestamp DESC LIMIT 100
    """).fetchall()
    conn.close()
    
    anomalies = []
    for r in rows:
        anomalies.append({
            'ip': r['attacker_ip'] or 'unknown',
            'agent_name': r['agent_name'] or 'unknown',
            'severity': r['severity'],
            'description': (r['rule_description'] or '')[:100],
            'timestamp': r['timestamp']
        })
    
    # Tenant filter
    anomalies = filter_by_tenant(anomalies, tenant)
    
    # Calculate stats
    critical = len([a for a in anomalies if a['severity'] >= 10])
    high = len([a for a in anomalies if 7 <= a['severity'] < 10])
    
    return jsonify({
        'total_anomalies': len(anomalies),
        'critical': critical,
        'high': high,
        'anomalies': anomalies[:20],
        'top_entity': anomalies[0]['agent_name'] if anomalies else '-',
        'avg_deviation': 45
    })

@app.route('/detected')
def get_detected():
    tenant = request.args.get('tenant', 'all')
    conn = get_db()
    rows = conn.execute("""
        SELECT attacker_ip, agent_name, severity, rule_description, timestamp
        FROM wazuh_alerts WHERE severity >= 5
        ORDER BY timestamp DESC LIMIT 50
    """).fetchall()
    conn.close()
    
    detected = []
    for r in rows:
        detected.append({
            'ip': r['attacker_ip'] or 'unknown',
            'agent_name': r['agent_name'] or 'unknown',
            'severity': r['severity'],
            'description': (r['rule_description'] or '')[:100],
            'timestamp': r['timestamp']
        })
    
    detected = filter_by_tenant(detected, tenant)
    return jsonify({'detected': detected, 'total': len(detected)})

if __name__ == '__main__':
    print("🔍 Anomaly Detector (Port 8045)")
    app.run(host='0.0.0.0', port=8045, debug=False)
