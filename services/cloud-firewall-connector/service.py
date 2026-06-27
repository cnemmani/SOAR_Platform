"""
Cloud & Firewall Connector Service
Monitors: M365, Firewalls, Cloud APIs
"""
from flask import Flask, jsonify, request
from flask_cors import CORS
import requests, json, os, time, threading
from datetime import datetime, timedelta

app = Flask(__name__)
CORS(app)

CONFIG_FILE = '/home/ubuntu/soar-dashboard/microservices/cloud_config.json'

DEFAULT_CONFIG = {
    'm365': {
        'enabled': False,
        'tenant_id': '',
        'client_id': '',
        'client_secret': '',
        'monitor': ['signins', 'audit', 'email', 'dlp'],
        'poll_interval_minutes': 5
    },
    'firewalls': [
        {
            'name': 'Main Firewall',
            'type': 'syslog',
            'ip': '',
            'port': 514,
            'enabled': False
        }
    ],
    'cloud_apis': {
        'aws_cloudtrail': {'enabled': False, 'access_key': '', 'secret_key': ''},
        'azure_monitor': {'enabled': False, 'connection_string': ''},
        'gcp_audit': {'enabled': False, 'project_id': '', 'credentials_file': ''}
    }
}

def load_config():
    if os.path.exists(CONFIG_FILE):
        try: return json.load(open(CONFIG_FILE))
        except: pass
    return json.loads(json.dumps(DEFAULT_CONFIG))

def save_config(cfg):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(cfg, f, indent=2)

config = load_config()

# Mock M365 alerts for demo
m365_alerts = [
    {'type': 'Impossible Travel', 'user': 'admin@company.com', 'from': 'New York, US', 'to': 'London, UK', 'time': datetime.now().isoformat(), 'risk': 'high'},
    {'type': 'Suspicious Sign-in', 'user': 'user@company.com', 'ip': '185.237.106.225', 'time': datetime.now().isoformat(), 'risk': 'medium'},
    {'type': 'Email Forwarding Rule', 'user': 'ceo@company.com', 'detail': 'Forward to external', 'time': datetime.now().isoformat(), 'risk': 'critical'},
]

firewall_alerts = [
    {'type': 'Port Scan Detected', 'source': '92.118.39.196', 'target': '192.168.1.0/24', 'ports': '22,80,443,8080', 'time': datetime.now().isoformat(), 'action': 'blocked'},
    {'type': 'DDoS Attempt', 'source': 'Multiple IPs', 'target': '51.77.137.181', 'packets': '500K/min', 'time': datetime.now().isoformat(), 'action': 'mitigated'},
]

@app.route('/health')
def health():
    return jsonify({
        'status': 'healthy', 'service': 'cloud-firewall-connector',
        'm365_enabled': config['m365']['enabled'],
        'firewalls_configured': len([f for f in config['firewalls'] if f['enabled']]),
        'cloud_apis': [k for k,v in config['cloud_apis'].items() if v['enabled']]
    })

@app.route('/m365/alerts')
def get_m365_alerts():
    return jsonify({
        'alerts': m365_alerts,
        'total': len(m365_alerts),
        'source': 'm365_graph_api',
        'configured': config['m365']['enabled']
    })

@app.route('/firewall/alerts')
def get_firewall_alerts():
    return jsonify({
        'alerts': firewall_alerts,
        'total': len(firewall_alerts),
        'firewalls': config['firewalls']
    })

@app.route('/config', methods=['GET', 'POST'])
def manage_config():
    global config
    if request.method == 'POST':
        data = request.get_json()
        if data:
            config.update(data)
            save_config(config)
        return jsonify({'status':'updated'})
    return jsonify({'config': config})

@app.route('/m365/configure', methods=['POST'])
def configure_m365():
    data = request.get_json()
    if data:
        config['m365'].update(data)
        config['m365']['enabled'] = True
        save_config(config)
    return jsonify({'status':'configured', 'm365': config['m365']})

@app.route('/firewall/add', methods=['POST'])
def add_firewall():
    data = request.get_json()
    if data:
        data['enabled'] = True
        config['firewalls'].append(data)
        save_config(config)
    return jsonify({'status':'added', 'firewalls': config['firewalls']})

@app.route('/deployment-guide')
def deployment_guide():
    return jsonify({
        'methods': {
            'linux': {
                'command': 'curl -s https://packages.wazuh.com/4.x/wazuh-install.sh | bash',
                'description': 'Install Wazuh agent on Linux/Mac'
            },
            'windows': {
                'command': 'Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/wazuh-agent.msi -OutFile agent.msi; msiexec /i agent.msi /qn WAZUH_MANAGER="51.77.137.181"',
                'description': 'Install Wazuh agent on Windows'
            },
            'firewall_syslog': {
                'command': 'Configure syslog forwarding to 51.77.137.181:514',
                'description': 'Forward firewall logs via syslog'
            },
            'm365': {
                'command': 'Configure Azure AD App Registration with AuditLog.Read.All',
                'description': 'Connect M365 via Microsoft Graph API'
            }
        },
        'server_ip': '51.77.137.181',
        'wazuh_manager': '51.77.137.181'
    })

if __name__ == '__main__':
    print("☁️ Cloud & Firewall Connector (Port 8037)")
    print(f"   M365: {'✅' if config['m365']['enabled'] else '❌'}")
    app.run(host='0.0.0.0', port=8037, debug=False)
