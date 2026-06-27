"""
Auto-Pipeline - Uses Event Processor API (no direct DB access)
"""
from flask import Flask, jsonify, request
from flask_cors import CORS
import requests
import sqlite3
import threading
import sys
sys.path.insert(0, '/home/ubuntu/soar-dashboard/microservices')
from tenant_resolver import get_tenant
import time
from datetime import datetime

app = Flask(__name__)
CORS(app)

THREAT_DB = "/home/ubuntu/soar-dashboard/threats.db"
EVENTS_API = "http://localhost:8005/events"
PIPELINE_URL = "http://localhost:8015/process"

stats = {
    'total_processed': 0,
    'threats_detected': 0,
    'false_positives': 0,
    'auto_blocked': 0,
    'last_run': None,
    'running': True
}

def init_threat_db():
    conn = sqlite3.connect(THREAT_DB, timeout=5)
    conn.execute('''CREATE TABLE IF NOT EXISTS threats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT, agent TEXT, verdict TEXT,
        risk_score REAL, vpn_detected INTEGER, fp_score REAL,
        detected_at TEXT)''')
    conn.commit()
    conn.close()

init_threat_db()

def get_threat_count():
    try:
        conn = sqlite3.connect(THREAT_DB, timeout=5)
        count = conn.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
        conn.close()
        return count
    except:
        return stats['threats_detected']

def process_alerts_from_api():
    """Get alerts from Event Processor API and run through pipeline"""
    count = 0
    try:
        # Get high-severity alerts from the event processor API
        resp = requests.get(f"{EVENTS_API}?severity=7&per_page=20", timeout=15)
        if resp.status_code != 200:
            return 0
        
        data = resp.json()
        alerts = data.get('events', [])
        
        for alert in alerts:
            ip = alert.get('attacker_ip') or alert.get('src_ip', '')
            if not ip or ip == 'None':
                continue
            
            # Send to pipeline
            payload = {
                'src_ip': ip,
                'severity': 'high' if (alert.get('severity', 0) or 0) >= 10 else 'medium',
                'agent_name': alert.get('agent_name', 'unknown'),
                'data': {'rule_description': alert.get('rule_description', alert.get('description', ''))}
            }
            
            try:
                pipe_resp = requests.post(PIPELINE_URL, json=payload, timeout=20)
                if pipe_resp.status_code == 200:
                    result = pipe_resp.json()
                    verdict = result.get('final_verdict', '')
                    stats['total_processed'] += 1
                    
                    if 'THREAT' in verdict:
                        try:
                            conn = sqlite3.connect(THREAT_DB, timeout=5)
                            conn.execute('''INSERT OR IGNORE INTO threats 
                                (ip, agent, verdict, risk_score, vpn_detected, fp_score, detected_at)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                                (ip, alert.get('agent_name', ''), verdict,
                                 result.get('risk_score', 0),
                     alert.get('tenant', 'global'),
                                 1 if result.get('attacker_profile', {}).get('vpn_detected') else 0,
                                 result.get('scores', {}).get('fp', 0),
                                 datetime.now().isoformat()))
                            conn.commit()
                            conn.close()
                            stats['threats_detected'] += 1
                            count += 1
                        except:
                            stats['threats_detected'] += 1
                            count += 1
                    elif 'FALSE' in verdict:
                        stats['false_positives'] += 1
            except:
                pass
            
            time.sleep(0.3)
        
    except Exception as e:
        print(f"API processing error: {e}")
    
    return count

def background_worker():
    """Continuously process alerts"""
    print("🔄 Auto-Pipeline worker started (API mode)")
    time.sleep(5)
    
    while stats['running']:
        try:
            count = process_alerts_from_api()
            stats['last_run'] = datetime.now().isoformat()
            if count > 0:
                print(f"✅ Processed {count} new threats (Total: {stats['threats_detected']})")
        except Exception as e:
            print(f"Worker error: {e}")
        time.sleep(15)

# Start worker
worker = threading.Thread(target=background_worker, daemon=True)
worker.start()

@app.route('/health')
def health():
    return jsonify({
        'status': 'healthy',
        'service': 'auto-pipeline',
        'persistent_threats': get_threat_count(),
        'stats': stats
    })

@app.route('/threats')
def get_threats():
    tenant = request.args.get('tenant', 'all')
    limit = request.args.get('limit', 100, type=int)
    try:
        conn = sqlite3.connect(THREAT_DB, timeout=5)
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM threats ORDER BY detected_at DESC LIMIT ?", (limit,)).fetchall()
        conn.close()
        threats = [dict(r) for r in rows]
    except:
        threats = []
    return jsonify({
        'threats': threats,
        'total': len(threats),
        'stats': stats
    })

@app.route('/stats')
def get_stats():
    return jsonify({**stats, 'persistent_threats': get_threat_count()})

@app.route('/process-now', methods=['POST'])
def process_now():
    """Force immediate processing"""
    count = process_alerts_from_api()
    return jsonify({
        'processed': count,
        'total_threats': get_threat_count(),
        'stats': stats
    })

if __name__ == '__main__':
    print("🚀 Auto-Pipeline (API Mode) - Port 8021")
    app.run(host='0.0.0.0', port=8021, debug=False)
