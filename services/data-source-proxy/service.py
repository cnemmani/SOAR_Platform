"""
Data Source API Proxy Service
Proxies requests to configured data sources per tenant
Port: 8055
"""
from flask import Flask, jsonify, request
import sqlite3
import requests
import json

app = Flask(__name__)
DB = '/home/ubuntu/soar-dashboard/zelarsoar.db'

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
    sources = conn.execute("SELECT tenant_id, type, status FROM data_sources").fetchall()
    conn.close()
    return jsonify({
        'status': 'healthy',
        'service': 'data-source-proxy',
        'port': 8055,
        'sources': len(sources),
        'connected': sum(1 for s in sources if s['status'] == 'connected')
    })

# ============================================
# GET Data Source Config for a Tenant
# ============================================
@app.route('/sources/<tenant_id>')
def get_tenant_sources(tenant_id):
    conn = get_db()
    sources = conn.execute(
        "SELECT * FROM data_sources WHERE tenant_id=?",
        (tenant_id,)
    ).fetchall()
    conn.close()
    
    return jsonify({
        'tenant': tenant_id,
        'sources': [dict(s) for s in sources],
        'total': len(sources)
    })

# ============================================
# PROXY: Query Wazuh API
# ============================================
@app.route('/wazuh/<tenant_id>/alerts')
def proxy_wazuh_alerts(tenant_id):
    """Proxy Wazuh alerts query for a tenant"""
    conn = get_db()
    ds = conn.execute(
        "SELECT * FROM data_sources WHERE tenant_id=? AND type='wazuh'",
        (tenant_id,)
    ).fetchone()
    conn.close()
    
    if not ds:
        return jsonify({'error': 'No Wazuh data source configured', 'tenant': tenant_id}), 404
    
    config = json.loads(ds['config']) if isinstance(ds['config'], str) else ds['config']
    
    try:
        # Forward to Wazuh API
        wazuh_url = f"http://{config.get('host','localhost')}:{config.get('port','55000')}/security/user/authenticate"
        
        # For demo, return the config and connect to events service instead
        limit = request.args.get('limit', 10)
        
        # Use the Events Service (8005) which already has Wazuh data
        resp = requests.get(
            f'http://localhost:8005/events?tenant={tenant_id}&limit={limit}',
            timeout=10
        )
        
        if resp.ok:
            data = resp.json()
            return jsonify({
                'tenant': tenant_id,
                'source': 'wazuh',
                'host': config.get('host'),
                'port': config.get('port'),
                'index': config.get('index'),
                'status': ds['status'],
                'total': data.get('total', 0),
                'alerts': data.get('events', [])[:10]
            })
        
        return jsonify({'error': 'Wazuh API unavailable', 'details': resp.text}), 502
        
    except Exception as e:
        return jsonify({
            'tenant': tenant_id,
            'source': 'wazuh',
            'status': ds['status'],
            'error': str(e),
            'note': 'Connect to port 55000 for direct Wazuh API access'
        })

# ============================================
# PROXY: Query ELK Stack
# ============================================
@app.route('/elk/<tenant_id>/search')
def proxy_elk_search(tenant_id):
    """Proxy ELK search for a tenant"""
    conn = get_db()
    ds = conn.execute(
        "SELECT * FROM data_sources WHERE tenant_id=? AND type='elk'",
        (tenant_id,)
    ).fetchone()
    conn.close()
    
    if not ds:
        return jsonify({'error': 'No ELK data source configured', 'tenant': tenant_id}), 404
    
    config = json.loads(ds['config']) if isinstance(ds['config'], str) else ds['config']
    
    try:
        # Forward to Elasticsearch
        es_url = f"http://{config.get('host','localhost')}:{config.get('port','9200')}/{config.get('index','*')}/_search"
        
        resp = requests.post(
            es_url,
            headers={'Content-Type': 'application/json'},
            json={"query": {"match_all": {}}, "size": 10},
            timeout=10
        )
        
        if resp.ok:
            data = resp.json()
            return jsonify({
                'tenant': tenant_id,
                'source': 'elk',
                'host': config.get('host'),
                'port': config.get('port'),
                'index': config.get('index'),
                'status': ds['status'],
                'total': data.get('hits',{}).get('total',{}).get('value', 0),
                'hits': data.get('hits',{}).get('hits', [])[:5]
            })
        
        return jsonify({
            'tenant': tenant_id,
            'source': 'elk',
            'status': ds['status'],
            'elasticsearch_url': es_url,
            'note': 'ELK Stack connection requires API key authentication'
        })
        
    except Exception as e:
        return jsonify({
            'tenant': tenant_id,
            'source': 'elk',
            'status': ds['status'],
            'error': str(e),
            'elasticsearch_url': f"http://{config.get('host')}:{config.get('port')}",
            'note': 'Start Elasticsearch or configure API key'
        })

# ============================================
# PROXY: Query Splunk
# ============================================
@app.route('/splunk/<tenant_id>/search')
def proxy_splunk_search(tenant_id):
    """Proxy Splunk search for a tenant"""
    conn = get_db()
    ds = conn.execute(
        "SELECT * FROM data_sources WHERE tenant_id=? AND type='splunk'",
        (tenant_id,)
    ).fetchone()
    conn.close()
    
    if not ds:
        return jsonify({'error': 'No Splunk data source configured', 'tenant': tenant_id}), 404
    
    config = json.loads(ds['config']) if isinstance(ds['config'], str) else ds['config']
    
    return jsonify({
        'tenant': tenant_id,
        'source': 'splunk',
        'host': config.get('host'),
        'port': config.get('port'),
        'index': config.get('index'),
        'status': ds['status'],
        'splunk_search_url': f"https://{config.get('host')}:{config.get('port')}/services/search/jobs",
        'note': 'Splunk requires authentication token. Current status: ' + ds['status']
    })

# ============================================
# TEST: Check all data sources for a tenant
# ============================================
@app.route('/test/<tenant_id>')
def test_tenant_sources(tenant_id):
    """Test connectivity to all data sources for a tenant"""
    conn = get_db()
    sources = conn.execute(
        "SELECT * FROM data_sources WHERE tenant_id=?",
        (tenant_id,)
    ).fetchall()
    conn.close()
    
    results = []
    for ds in sources:
        config = json.loads(ds['config']) if isinstance(ds['config'], str) else ds['config']
        host = config.get('host', 'localhost')
        port = config.get('port', '0')
        
        try:
            resp = requests.get(f"http://{host}:{port}/health", timeout=3)
            results.append({
                'type': ds['type'],
                'host': f"{host}:{port}",
                'status': 'reachable' if resp.ok else 'unhealthy',
                'http_status': resp.status_code
            })
        except:
            results.append({
                'type': ds['type'],
                'host': f"{host}:{port}",
                'status': 'unreachable',
                'note': 'Service may be offline or behind firewall'
            })
    
    return jsonify({
        'tenant': tenant_id,
        'tested_at': __import__('datetime').datetime.now().isoformat(),
        'results': results
    })

if __name__ == '__main__':
    print("🔌 Data Source API Proxy starting on port 8055...")
    print("📊 Endpoints:")
    print("   GET /sources/:tenant_id")
    print("   GET /wazuh/:tenant_id/alerts")
    print("   GET /elk/:tenant_id/search")
    print("   GET /splunk/:tenant_id/search")
    print("   GET /test/:tenant_id")
    app.run(host='0.0.0.0', port=8055, debug=False)
