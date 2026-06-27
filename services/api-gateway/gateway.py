from flask import Flask, request, jsonify, Response
from flask_cors import CORS
import requests

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

SERVICES = {
    # Core
    'ueba': 'http://localhost:8001',
    'fraud': 'http://localhost:8002',
    'geo': 'http://localhost:8003',
    'vpn': 'http://localhost:8004',
    'events': 'http://localhost:8005',
    # Threat Intel
    'vt': 'http://localhost:8006',
    'behavior': 'http://localhost:8007',
    'fp': 'http://localhost:8008',
    'threat': 'http://localhost:8009',
    # Pipeline
    'data-prep': 'http://localhost:8010',
    'hash': 'http://localhost:8011',
    'scanner': 'http://localhost:8012',
    'ultra-fp': 'http://localhost:8013',
    'notify': 'http://localhost:8014',
    'pipeline': 'http://localhost:8015',
    # Profiling & SOAR
    'attacker': 'http://localhost:8016',
    'soar': 'http://localhost:8017',
    'threat-actor': 'http://localhost:8020',
    'auto-pipeline': 'http://localhost:8021',
    'logo': 'http://localhost:8022',
    'firewall': 'http://localhost:8020',
    # Wazuh Integration
    'sso': 'http://localhost:8018',
    'wazuh': 'http://localhost:8019'
}

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', '*')
    response.headers.add('Access-Control-Allow-Methods', '*')
    return response

@app.route('/api/<service>/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])
def proxy(service, path):
    if request.method == 'OPTIONS':
        return Response('', status=200)
    if service not in SERVICES:
        return jsonify({'error': 'Service not found', 'available': list(SERVICES.keys())}), 404
    
    target_url = f"{SERVICES[service]}/{path}"
    try:
        if request.method == 'GET':
            resp = requests.get(target_url, params=request.args, timeout=30)
        else:
            resp = requests.post(target_url, json=request.json, timeout=30)
        return Response(resp.content, status=resp.status_code, content_type='application/json')
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/health')
def health():
    status = {}
    for name, url in SERVICES.items():
        try:
            r = requests.get(f"{url}/health", timeout=3)
            status[name] = 'healthy' if r.status_code == 200 else 'unhealthy'
        except:
            status[name] = 'down'
    status['api-gateway'] = 'healthy'
    return jsonify(status)


@app.route('/auth/login', methods=['POST'])
def auth_login():
    """Handle login requests"""
    data = request.get_json() or {}
    username = data.get('username', '')
    password = data.get('password', '')
    
    # Simple auth for demo
    if username == 'admin' and password == 'admin123':
        return jsonify({
            'token': 'zelarsoar_admin_token_2026',
            'user': {
                'username': 'admin',
                'display_name': 'Administrator',
                'role': 'admin',
                'tenant': 'global',
                'permissions': ['*']
            }
        })
    
    # Try tenant service
    try:
        resp = requests.post('http://127.0.0.1:8029/login', json=data, timeout=5)
        if resp.ok:
            return resp.json()
    except:
        pass
    
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/auth/tenants/public', methods=['GET'])
def public_tenants():
    try:
        resp = requests.get('http://127.0.0.1:8029/tenants', timeout=5)
        return resp.json()
    except:
        return jsonify({'tenants': [{'id': 'global', 'name': 'Global (All Tenants)'}]})

if __name__ == '__main__':
    print(f"API Gateway - {len(SERVICES)} services - Port 8000")
    app.run(host='0.0.0.0', port=8000, debug=False)
