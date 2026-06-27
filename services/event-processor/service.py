"""
AI-Powered Event Processor - Merges Wazuh alerts + Attack Detection
Real-time streaming with WebSocket support
"""
from flask import Flask, jsonify, request
from flask_cors import CORS
import json, os, time, threading, requests
from collections import deque
from datetime import datetime

app = Flask(__name__)
CORS(app)

ALERTS_FILE = "/var/ossec/logs/alerts/alerts.json"
ATTACK_API = "http://localhost:8048"
CACHE_SIZE = 10000

alerts_cache = deque(maxlen=CACHE_SIZE)
stats = {
    'total_processed': 0, 'ai_processed': 0, 'threats_found': 0,
    'attack_alerts': 0, 'last_scan': None
}

def get_attack_alerts():
    """Fetch alerts from Attack Detection Service"""
    try:
        resp = requests.get(f"{ATTACK_API}/attacks?limit=100", timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            attacks = data.get('attacks', [])
            alerts = []
            for a in attacks[-50:]:  # Last 50 attacks
                alerts.append({
                    'id': f"ATK-{abs(hash(str(a.get('timestamp',''))))%100000}",
                    'timestamp': a.get('timestamp', ''),
                    'severity': a.get('severity', 'high'),
                    'level': a.get('risk_score', 80),
                    'agent_name': 'Attack Detector',
                    'src_ip': a.get('ip', ''),
                    'attacker_ip': a.get('ip', ''),
                    'description': a.get('description', '')[:200],
                    'rule_description': a.get('description', '')[:200],
                    'ai_verdict': a.get('ai_verdict', 'INSTANT_DETECTED'),
                    'ai_confidence': a.get('ai_confidence', a.get('risk_score', 80)),
                    'risk_score': a.get('risk_score', 80),
                    'source': 'attack_detection',
                    'attack_types': a.get('attack_types', []),
                    'mitre_attack': a.get('mitre_attack', []),
                    'auto_blocked': a.get('auto_blocked', False),
                    'status': 'new'
                })
            stats['attack_alerts'] = len(alerts)
            return alerts
    except Exception as e:
        print(f"Attack fetch error: {e}")
    return []

def scan_alerts_file():
    """Scan alerts.json for Wazuh alerts"""
    if not os.path.exists(ALERTS_FILE):
        return 0
    count = 0
    try:
        with open(ALERTS_FILE, 'r') as f:
            if stats.get('file_position', 0) > 0:
                f.seek(stats['file_position'])
            for line in f:
                line = line.strip()
                if not line: continue
                try:
                    alert = json.loads(line)
                    rule = alert.get('rule', {})
                    agent = alert.get('agent', {})
                    data = alert.get('data', {})
                    
                    sev_map = {0:'info',1:'info',2:'info',3:'low',4:'low',5:'medium',
                              6:'medium',7:'high',8:'high',9:'high',
                              10:'critical',11:'critical',12:'critical',
                              13:'critical',14:'critical',15:'critical'}
                    
                    alerts_cache.append({
                        'id': alert.get('id', f"ALERT-{int(time.time())}"),
                        'timestamp': alert.get('timestamp', datetime.now().isoformat()),
                        'severity': sev_map.get(rule.get('level', 5), 'medium'),
                        'level': rule.get('level', 5),
                        'agent_name': agent.get('name', 'unknown'),
                        'src_ip': data.get('srcip', agent.get('ip', '')),
                        'attacker_ip': data.get('srcip', agent.get('ip', '')),
                        'description': rule.get('description', ''),
                        'rule_description': rule.get('description', ''),
                        'rule_id': rule.get('id', ''),
                        'source': 'wazuh',
                        'status': 'new'
                    })
                    count += 1
                    stats['total_processed'] += 1
                except: continue
            stats['file_position'] = f.tell()
    except Exception as e:
        print(f"Scan error: {e}")
    return count

def background_scanner():
    """Continuous scanning + attack alert merging"""
    print("📡 Event Processor + Attack Detection started...")
    while True:
        try:
            count = scan_alerts_file()
            if count > 0:
                print(f"📡 {count} Wazuh alerts loaded (Total: {len(alerts_cache)})")
            stats['last_scan'] = datetime.now().isoformat()
        except Exception as e:
            print(f"Scanner error: {e}")
        time.sleep(3)

threading.Thread(target=background_scanner, daemon=True).start()

@app.route('/health')
def health():
    return jsonify({
        'status': 'healthy',
        'service': 'event-processor',
        'alerts': len(alerts_cache),
        'attack_alerts': stats['attack_alerts'],
        'stats': stats
    })

@app.route('/events')
def get_events():
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 50, type=int), 200)
    severity = request.args.get('severity', 0, type=int)
    
    # Get Wazuh alerts
    events = list(alerts_cache)
    
    # Get Attack Detection alerts (FRESH each request)
    attack_alerts = get_attack_alerts()
    
    # Merge both
    all_events = events + attack_alerts
    
    # Filter by severity if needed
    if severity > 0:
        all_events = [e for e in all_events if e.get('level', e.get('risk_score', 5)) >= severity]
    
    # Sort by timestamp (newest first)
    all_events.sort(key=lambda x: str(x.get('timestamp', '')), reverse=True)
    
    total = len(all_events)
    start = (page - 1) * per_page
    paginated = all_events[start:start + per_page]
    
    return jsonify({
        'events': paginated,
        'total': total,
        'total_pages': max(1, (total + per_page - 1) // per_page),
        'pagination': {'page': page, 'per_page': per_page, 'total': total},
        'stats': stats,
        'sources': {
            'wazuh': len(events),
            'attack_detection': len(attack_alerts)
        }
    })

@app.route('/stats')
def get_stats():
    return jsonify(stats)

@app.route('/event', methods=['POST'])
def add_event():
    """Accept external events (like attack alerts)"""
    event = request.get_json()
    if event:
        event.setdefault('timestamp', datetime.now().isoformat())
        event.setdefault('source', 'external')
        alerts_cache.append(event)
        return jsonify({'status': 'added'})
    return jsonify({'error': 'No data'}), 400

if __name__ == '__main__':
    print("📡 Event Processor (8005) - Wazuh + Attack Detection merged")
    app.run(host='0.0.0.0', port=8005, debug=False, threaded=True)
