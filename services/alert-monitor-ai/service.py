"""
AI Monitor - Tenant-Aware Alert Processing
Reads alerts.json, enriches with AI confidence, supports tenant isolation
"""
from flask import Flask, jsonify, request
from flask_cors import CORS
import json, os, time, threading, re, sys
from datetime import datetime
from collections import deque

sys.path.insert(0, '/home/ubuntu/soar-dashboard/microservices')
from tenant_resolver import get_tenant

app = Flask(__name__)
CORS(app)

ALERTS_FILE = "/var/ossec/logs/alerts/alerts.json"
alerts_queue = deque(maxlen=50000)
stats = {'total_processed': 0, 'threats_found': 0, 'file_position': 0, 'running': True}

def parse_alert(line):
    """Parse a single alert from alerts.json"""
    try:
        alert = json.loads(line)
        rule = alert.get('rule', {})
        agent = alert.get('agent', {})
        data = alert.get('data', {})
        
        level = rule.get('level', 5)
        severity = 'critical' if level >= 13 else 'high' if level >= 10 else 'medium' if level >= 7 else 'low' if level >= 4 else 'info'
        
        agent_name = agent.get('name', 'unknown')
        src_ip = data.get('srcip', agent.get('ip', ''))
        description = rule.get('description', '')[:200]
        
        # AI confidence scoring
        ai_confidence = 30
        ai_verdict = 'BENIGN'
        desc_lower = description.lower()
        threat_keywords = ['brute', 'force', 'failed', 'attack', 'malware', 'exploit', 'unauthorized', 'breach', 'multiple']
        matches = sum(1 for kw in threat_keywords if kw in desc_lower)
        if matches >= 4: ai_confidence, ai_verdict = 85, 'THREAT'
        elif matches >= 2: ai_confidence, ai_verdict = 60, 'SUSPICIOUS'
        elif matches >= 1: ai_confidence, ai_verdict = 45, 'SUSPICIOUS'
        
        # Tenant resolution
        tenant = get_tenant(agent_name)
        
        return {
            'id': alert.get('id', ''),
            'timestamp': alert.get('timestamp', datetime.now().isoformat()),
            'severity': severity,
            'level': level,
            'ai_confidence': ai_confidence,
            'ai_verdict': ai_verdict,
            'agent_name': agent_name,
            'src_ip': src_ip,
            'description': description,
            'rule_id': rule.get('id', ''),
            'tenant': tenant,
            'processed_at': datetime.now().isoformat()
        }
    except:
        return None

def monitor_file():
    """Monitor alerts.json continuously"""
    position = 0
    pos_file = '/tmp/ai_monitor_pos.txt'
    if os.path.exists(pos_file):
        try:
            with open(pos_file) as f:
                position = int(f.read().strip())
        except:
            pass
    
    while stats['running']:
        try:
            if not os.path.exists(ALERTS_FILE):
                time.sleep(5)
                continue
            
            with open(ALERTS_FILE, 'r') as f:
                f.seek(position)
                count = 0
                for line in f:
                    if not line.strip():
                        continue
                    alert = parse_alert(line)
                    if alert:
                        alerts_queue.append(alert)
                        count += 1
                        stats['total_processed'] += 1
                        if alert['ai_verdict'] == 'THREAT':
                            stats['threats_found'] += 1
                position = f.tell()
                stats['file_position'] = position
                with open(pos_file, 'w') as pf:
                    pf.write(str(position))
            
            if count > 0:
                print(f"📡 Processed {count} alerts (Total: {stats['total_processed']}, Threats: {stats['threats_found']})")
            time.sleep(3)
        except Exception as e:
            print(f"Monitor error: {e}")
            time.sleep(10)

threading.Thread(target=monitor_file, daemon=True).start()

@app.route('/health')
def health():
    return jsonify({
        'status': 'healthy',
        'service': 'ai-monitor',
        'queue_size': len(alerts_queue),
        'stats': stats,
        'tenant_aware': True
    })

@app.route('/stats')
def get_stats():
    return jsonify(stats)

@app.route('/alerts')
def get_alerts():
    limit = request.args.get('limit', 100, type=int)
    tenant = request.args.get('tenant', 'all')
    severity = request.args.get('severity', 'all')
    
    alerts = list(alerts_queue)[-10000:]
    
    # Tenant filter
    if tenant and tenant not in ('all', 'global'):
        alerts = [a for a in alerts if a.get('tenant') == tenant]
    
    # Severity filter
    if severity and severity != 'all':
        alerts = [a for a in alerts if a.get('severity') == severity]
    
    return jsonify({
        'alerts': alerts[-limit:],
        'total': len(alerts),
        'filtered': len(alerts),
        'tenant': tenant,
        'tenant_aware': True
    })

if __name__ == '__main__':
    print("🤖 AI Monitor - Tenant-Aware (Port 8027)")
    app.run(host='0.0.0.0', port=8027, debug=False, threaded=True)
