"""
ZelarXDR Agent Ingestion Service
Receives events + packages from deployed agents
Port: 8051
"""
from flask import Flask, jsonify, request
import sqlite3, json
from datetime import datetime

app = Flask(__name__)
DB = '/home/ubuntu/soar-dashboard/ir_tracking.db'

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS agent_packages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT NOT NULL,
            agent_name TEXT,
            os TEXT,
            package_name TEXT NOT NULL,
            version TEXT,
            reported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(agent_id, package_name)
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS agent_assets (
            id TEXT PRIMARY KEY,
            name TEXT,
            type TEXT DEFAULT 'endpoint',
            os TEXT,
            ip TEXT,
            status TEXT DEFAULT 'online',
            tenant TEXT DEFAULT 'global',
            version TEXT,
            last_seen TIMESTAMP,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            events_collected INTEGER DEFAULT 0,
            threats_detected INTEGER DEFAULT 0,
            packages_reported INTEGER DEFAULT 0
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# CORS
@app.after_request
def add_cors(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization,X-Tenant-ID'
    response.headers['Access-Control-Allow-Methods'] = 'GET,POST,OPTIONS'
    return response

@app.before_request
def handle_preflight():
    if request.method == 'OPTIONS':
        from flask import make_response
        r = make_response()
        r.headers['Access-Control-Allow-Origin'] = '*'
        return r, 200

@app.route('/health')
def health():
    conn = get_db()
    assets = conn.execute("SELECT COUNT(*) FROM agent_assets").fetchone()[0]
    pkgs = conn.execute("SELECT COUNT(*) FROM agent_packages").fetchone()[0]
    conn.close()
    return jsonify({'status':'healthy','service':'agent-ingestion','port':8051,'assets':assets,'packages_reported':pkgs})

@app.route('/packages', methods=['POST'])
def receive_packages():
    """Receive package list from a deployed agent"""
    data = request.json or {}
    agent_id = data.get('agent_id', 'unknown')
    agent_name = data.get('agent_name', 'unknown')
    packages = data.get('packages', {})
    
    conn = get_db()
    
    # Update/create asset
    existing = conn.execute("SELECT * FROM agent_assets WHERE id=?", (agent_id,)).fetchone()
    if existing:
        conn.execute("UPDATE agent_assets SET last_seen=?, status='online', packages_reported=packages_reported+1 WHERE id=?",
                    (datetime.now().isoformat(), agent_id))
    else:
        conn.execute('''INSERT INTO agent_assets (id, name, type, os, status, tenant, last_seen, packages_reported)
                       VALUES (?,?,?,?,?,?,?,1)''',
                    (agent_id, agent_name, 'endpoint', data.get('os','Linux'), 'online', 
                     request.headers.get('X-Tenant-ID','global'), datetime.now().isoformat()))
    
    # Store packages
    count = 0
    for pkg_name, version in packages.items():
        try:
            conn.execute('''INSERT OR REPLACE INTO agent_packages (agent_id, agent_name, os, package_name, version, reported_at)
                           VALUES (?,?,?,?,?,?)''',
                        (agent_id, agent_name, data.get('os',''), pkg_name, str(version)[:50], datetime.now().isoformat()))
            count += 1
        except: pass
    
    conn.commit()
    conn.close()
    
    return jsonify({'status':'received','agent_id':agent_id,'packages':count})

@app.route('/agents/<agent_id>/packages')
def get_agent_packages(agent_id):
    """Get packages reported by a specific agent"""
    conn = get_db()
    pkgs = conn.execute("SELECT * FROM agent_packages WHERE agent_id=? ORDER BY package_name", (agent_id,)).fetchall()
    conn.close()
    return jsonify({'agent_id':agent_id,'packages':[dict(p) for p in pkgs],'total':len(pkgs)})

@app.route('/assets')
def get_assets():
    tenant = request.args.get('tenant','global')
    conn = get_db()
    if tenant == 'global':
        assets = conn.execute("SELECT * FROM agent_assets ORDER BY last_seen DESC").fetchall()
    else:
        assets = conn.execute("SELECT * FROM agent_assets WHERE tenant=? OR tenant='global' ORDER BY last_seen DESC",(tenant,)).fetchall()
    conn.close()
    return jsonify({'total':len(assets),'assets':[dict(a) for a in assets]})

@app.route('/ingest', methods=['POST'])
def ingest():
    data = request.json or {}
    agent_id = data.get('agent_id','')
    agent_name = data.get('agent_name','unknown')
    
    conn = get_db()
    existing = conn.execute("SELECT * FROM agent_assets WHERE id=?",(agent_id,)).fetchone()
    if existing:
        conn.execute("UPDATE agent_assets SET last_seen=?, events_collected=events_collected+1, status='online' WHERE id=?",
                    (datetime.now().isoformat(), agent_id))
    else:
        conn.execute('''INSERT INTO agent_assets (id,name,type,os,status,tenant,last_seen,events_collected)
                       VALUES (?,?,?,?,?,?,?,1)''',
                    (agent_id, agent_name, data.get('type','endpoint'), data.get('os','Linux'), 'online',
                     data.get('tenant','global'), datetime.now().isoformat()))
    conn.commit()
    conn.close()
    return jsonify({'status':'ingested'})

if __name__ == '__main__':
    print("🚀 Agent Ingestion Service - Port 8051")
    print("   POST /packages - Receive package lists from agents")
    print("   GET /agents/:id/packages - Get agent packages")
    print("   POST /ingest - Receive events")
    app.run(host='0.0.0.0', port=8051, debug=False)
