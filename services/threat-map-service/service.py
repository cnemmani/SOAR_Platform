"""
Tenant-Aware Threat Map Service
Proxies RTI (8070) with tenant isolation
Port: 8071
"""
from flask import Flask, jsonify, request
import sqlite3, requests
from collections import defaultdict

app = Flask(__name__)
RTI_URL = 'http://localhost:8070'
AGENT_DB = '/home/ubuntu/soar-dashboard/agents_health.db'
TENANT_DB = '/home/ubuntu/soar-dashboard/zelarsoar.db'

# CORS
@app.after_request
def add_cors(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization,X-Tenant-ID'
    response.headers['Access-Control-Allow-Methods'] = 'GET,OPTIONS'
    return response

def get_agent_tenant_map():
    """Build dynamic agent→tenant mapping from agents_health.db"""
    mapping = {}
    try:
        conn = sqlite3.connect(AGENT_DB)
        rows = conn.execute("SELECT DISTINCT name, COALESCE(tenant,'global') as tenant FROM agents WHERE name IS NOT NULL").fetchall()
        conn.close()
        for name, tenant in rows:
            mapping[name] = tenant
    except: pass
    return mapping

def get_known_tenants():
    """Get all tenants from zelarsoar.db - NO hardcoded names"""
    tenants = {'global': 'Global'}
    try:
        conn = sqlite3.connect(TENANT_DB)
        rows = conn.execute("SELECT id, name FROM tenants WHERE status='active'").fetchall()
        conn.close()
        for tid, tname in rows:
            tenants[tid] = tname or tid
    except: pass
    return tenants

def resolve_tenant(agent_name):
    """Resolve tenant from agent name dynamically"""
    if not agent_name: return 'global'
    agent_lower = agent_name.lower()
    
    # Check agent mapping DB first
    agent_map = get_agent_tenant_map()
    if agent_name in agent_map:
        return agent_map[agent_name]
    
    # Auto-detect from known tenant patterns (from DB)
    tenants = get_known_tenants()
    for tid in tenants:
        if tid != 'global' and tid.lower() in agent_lower:
            return tid
    
    # Prefix-based detection
    prefix = agent_name.split('_')[0].split('-')[0].lower()
    for tid in tenants:
        if tid.lower() == prefix:
            return tid
    
    return 'global'

@app.route('/health')
def health():
    tenants = get_known_tenants()
    return jsonify({
        'status': 'healthy',
        'service': 'threat-map-tenant-aware',
        'port': 8071,
        'tenants': len(tenants),
        'tenant_list': list(tenants.keys())
    })

@app.route('/tenants')
def list_tenants():
    """Return ALL tenants from DB - dynamic, no hardcoding"""
    tenants = get_known_tenants()
    return jsonify({
        'tenants': [{'id': tid, 'name': tname} for tid, tname in tenants.items()],
        'total': len(tenants)
    })

@app.route('/stats')
def stats():
    tenant = request.args.get('tenant', request.headers.get('X-Tenant-ID', 'global'))
    
    try:
        resp = requests.get(f'{RTI_URL}/stats', timeout=5)
        data = resp.json()
    except:
        data = {'total_alerts': 0, 'total_threats': 0, 'active_bots': 0, 'apt_groups': 0, 'blocked_ips': 0, 'threat_level': 'LOW'}
    
    # Add tenant-specific info
    tenants = get_known_tenants()
    data['current_tenant'] = tenant
    data['tenant_name'] = tenants.get(tenant, tenant)
    data['total_tenants'] = len(tenants)
    data['tenant_isolated'] = tenant != 'global'
    
    return jsonify(data)

@app.route('/live-attacks')
def live_attacks():
    tenant = request.args.get('tenant', request.headers.get('X-Tenant-ID', 'global'))
    
    try:
        resp = requests.get(f'{RTI_URL}/live-attacks', timeout=5)
        data = resp.json()
    except:
        data = {'attacks': [], 'total': 0}
    
    attacks = data.get('attacks', [])
    
    # Filter by tenant
    if tenant != 'global':
        agent_map = get_agent_tenant_map()
        filtered = []
        for a in attacks:
            agent = a.get('agent', '')
            # Resolve tenant for this agent
            agent_tenant = agent_map.get(agent, resolve_tenant(agent))
            if agent_tenant == tenant:
                a['tenant'] = agent_tenant
                filtered.append(a)
        attacks = filtered
    
    # Add tenant info to each attack
    for a in attacks:
        if 'tenant' not in a:
            a['tenant'] = resolve_tenant(a.get('agent', ''))
    
    return jsonify({
        'attacks': attacks,
        'total': len(attacks),
        'tenant': tenant,
        'tenant_isolated': tenant != 'global'
    })

@app.route('/timeline')
def timeline():
    tenant = request.args.get('tenant', 'global')
    try:
        resp = requests.get(f'{RTI_URL}/timeline', timeout=5)
        data = resp.json()
    except:
        data = {'timeline': []}
    data['tenant'] = tenant
    return jsonify(data)

@app.route('/ttps')
def ttps():
    try:
        resp = requests.get(f'{RTI_URL}/ttps', timeout=5)
        return resp.content, resp.status_code, resp.headers.items()
    except:
        return jsonify({'ttps': [], 'total': 0})

@app.route('/group-activity')
def group_activity():
    try:
        resp = requests.get(f'{RTI_URL}/group-activity', timeout=5)
        return resp.content, resp.status_code, resp.headers.items()
    except:
        return jsonify({'groups': [], 'total': 0})

if __name__ == '__main__':
    print("🌐 Tenant-Aware Threat Map Service - Port 8071")
    print(f"   Tenants from DB: {len(get_known_tenants())}")
    app.run(host='0.0.0.0', port=8071, debug=False)
