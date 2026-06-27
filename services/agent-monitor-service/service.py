"""
Agent Monitor Service - Serves REAL agent data from agents_health.db
Port: 8030 | Tenant-Aware | Tenant-Isolated
"""
from flask import Flask, jsonify, request
import sqlite3

app = Flask(__name__)
DB = '/home/ubuntu/soar-dashboard/agents_health.db'

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

# CORS
@app.after_request
def add_cors(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization,X-Tenant-ID'
    response.headers['Access-Control-Allow-Methods'] = 'GET,PUT,POST,DELETE,OPTIONS'
    return response

@app.before_request
def handle_preflight():
    if request.method == 'OPTIONS':
        from flask import make_response
        r = make_response()
        r.headers['Access-Control-Allow-Origin'] = '*'
        r.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization,X-Tenant-ID'
        r.headers['Access-Control-Allow-Methods'] = 'GET,PUT,POST,DELETE,OPTIONS'
        return r, 200

@app.route('/health')
def health():
    conn = get_db()
    total = conn.execute("SELECT COUNT(*) FROM agents").fetchone()[0]
    online = conn.execute("SELECT COUNT(*) FROM agents WHERE status='online'").fetchone()[0]
    tenants = conn.execute("SELECT DISTINCT COALESCE(tenant,'global') as t FROM agents").fetchall()
    conn.close()
    return jsonify({
        'status': 'healthy', 'service': 'agent-monitor', 'port': 8030,
        'total_agents': total, 'online_agents': online,
        'tenants': [t['t'] for t in tenants]
    })

@app.route('/agents')
def get_agents():
    tenant = request.args.get('tenant', 'global')
    conn = get_db()
    
    if tenant == 'global':
        agents = conn.execute("""
            SELECT id, name, type, os, status, version, last_seen, created, 
                   COALESCE(tenant,'global') as tenant, tags, ip, connection_method
            FROM agents ORDER BY name
        """).fetchall()
    else:
        agents = conn.execute("""
            SELECT id, name, type, os, status, version, last_seen, created,
                   COALESCE(tenant,'global') as tenant, tags, ip, connection_method
            FROM agents 
            WHERE tenant=? OR tenant='global' OR tenant IS NULL OR tenant=''
            ORDER BY name
        """, (tenant,)).fetchall()
    
    # Get tenant distribution
    tenant_counts = {}
    for a in agents:
        t = a['tenant'] or 'global'
        tenant_counts[t] = tenant_counts.get(t, 0) + 1
    
    online = sum(1 for a in agents if a['status'] == 'online')
    
    conn.close()
    
    return jsonify({
        'total': len(agents),
        'online': online,
        'offline': len(agents) - online,
        'tenant': tenant,
        'tenant_distribution': tenant_counts,
        'agents': [dict(a) for a in agents]
    })

@app.route('/agents/<agent_id>')
def get_agent(agent_id):
    conn = get_db()
    agent = conn.execute("SELECT * FROM agents WHERE id=?", (agent_id,)).fetchone()
    conn.close()
    if agent:
        return jsonify(dict(agent))
    return jsonify({'error': 'Agent not found'}), 404

if __name__ == '__main__':
    print("🖥️ Agent Monitor Service - Port 8030")
    print(f"📁 Database: {DB}")
    app.run(host='0.0.0.0', port=8030, debug=False)
