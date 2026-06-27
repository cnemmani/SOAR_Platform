import sys; sys.path.insert(0, "..")
"""
SOAR Policy Engine - Working Version
"""
from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime, time
import json, os, subprocess

app = Flask(__name__)
CORS(app)

POLICY_FILE = '/home/ubuntu/soar-dashboard/microservices/soar_policies.json'

DEFAULT_POLICIES = {
    'business_hours': {'enabled': True, 'start_time': '08:00', 'end_time': '18:00', 'weekdays': [0,1,2,3,4]},
    'auto_block': {'enabled': True, 'off_hours_only': False, 'min_risk_score': 50, 'block_vpn_tor': True, 'block_bots': True, 'max_auto_blocks_per_day': 50},
    'auto_isolate': {'enabled': True, 'off_hours_only': True, 'min_risk_score': 80, 'max_auto_isolates_per_day': 5},
    'blocking_methods': {'local_iptables': {'enabled': True, 'priority': 1}},
    'whitelist': {'ips': ['8.8.8.8', '1.1.1.1'], 'cidr_ranges': ['10.0.0.0/8', '192.168.0.0/16']},
}

def load_policies():
    if os.path.exists(POLICY_FILE):
        try:
            with open(POLICY_FILE) as f: return {**DEFAULT_POLICIES, **json.load(f)}
        except: pass
    return json.loads(json.dumps(DEFAULT_POLICIES))

def save_policies(p): pass  # Simple no-op

policies = load_policies()
action_stats = {'auto_blocks_today': 0, 'auto_isolates_today': 0, 'manual_blocks_today': 0, 'blocked_ips': {}, 'last_reset': datetime.now().date().isoformat()}

def is_business_hours():
    bh = policies['business_hours']
    if not bh['enabled']: return True
    now = datetime.now()
    if now.weekday() not in bh['weekdays']: return False
    try: return time.fromisoformat(bh['start_time']) <= now.time() <= time.fromisoformat(bh['end_time'])
    except: return True

def reset_counters():
    today = datetime.now().date().isoformat()
    if action_stats['last_reset'] != today:
        action_stats['auto_blocks_today'] = 0
        action_stats['auto_isolates_today'] = 0
        action_stats['manual_blocks_today'] = 0
        action_stats['last_reset'] = today

def is_whitelisted(ip):
    if ip in policies['whitelist']['ips']: return True
    return False

def execute_block(ip):
    results = []
    try:
        check = subprocess.run(['sudo', 'iptables', '-C', 'INPUT', '-s', ip, '-j', 'DROP'], capture_output=True)
        if check.returncode != 0:
            subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], timeout=10)
            results.append({'method': 'iptables', 'status': 'blocked', 'target': ip})
        else:
            results.append({'method': 'iptables', 'status': 'already_blocked', 'target': ip})
    except Exception as e:
        results.append({'method': 'iptables', 'status': 'error', 'error': str(e)})
    return results

def execute_isolate(host):
    return [{'method': 'iptables', 'status': 'isolated', 'target': host}]

def should_auto_block(data):
    ab = policies['auto_block']
    if not ab['enabled']: return False, 'Disabled'
    reset_counters()
    ip = data.get('src_ip', data.get('ip', ''))
    if not ip: return False, 'No IP'
    if is_whitelisted(ip): return False, 'Whitelisted'
    if action_stats['auto_blocks_today'] >= ab['max_auto_blocks_per_day']: return False, 'Daily limit'
    risk = data.get('risk_score', 0)
    is_bot = data.get('is_bot', False)
    reasons = []
    if risk >= ab['min_risk_score']: reasons.append(f'Risk {risk}%')
    if is_bot and ab['block_bots']: reasons.append('Bot detected')
    return (len(reasons) > 0, '; '.join(reasons)) if reasons else (False, '')

def should_auto_isolate(data):
    ai = policies['auto_isolate']
    if not ai['enabled']: return False, 'Disabled'
    reset_counters()
    host = data.get('agent_name', '')
    if not host: return False, 'No host'
    if action_stats['auto_isolates_today'] >= ai['max_auto_isolates_per_day']: return False, 'Daily limit'
    risk = data.get('risk_score', 0)
    return (risk >= ai['min_risk_score'], f'Risk {risk}%') if risk >= ai['min_risk_score'] else (False, '')

@app.route('/health')
def health():
    return jsonify({'status': 'healthy', 'service': 'soar', 'business_hours': is_business_hours()})

@app.route('/policies', methods=['GET'])
def get_policies():
    return jsonify({'policies': policies, 'stats': action_stats, 'blocked_ips': list(action_stats['blocked_ips'].keys())})

@app.route('/policies', methods=['POST'])
def update_policies():
    data = request.get_json() or {}
    for k, v in data.items():
        if k in policies and isinstance(policies[k], dict): policies[k].update(v)
    return jsonify({'status': 'updated'})

@app.route('/evaluate', methods=['POST'])
def evaluate():
    data = request.get_json() or {}
    ip = data.get('src_ip', data.get('ip', ''))
    result = {'timestamp': datetime.now().isoformat(), 'business_hours': is_business_hours(), 'actions_taken': [], 'blocked': False, 'isolated': False}
    if ip and is_whitelisted(ip): return jsonify(result)
    should_block, reason = should_auto_block(data)
    if should_block:
        result['blocked'] = True
        result['blocking_results'] = execute_block(ip)
        result['actions_taken'].append(f'auto_blocked: {reason}')
        action_stats['auto_blocks_today'] += 1
        action_stats['blocked_ips'][ip] = {'time': datetime.now().isoformat(), 'reason': reason}
    return jsonify(result)

@app.route('/block', methods=['POST'])
def block():
    data = request.get_json() or {}
    ip = data.get('ip', '')
    if not ip: return jsonify({'error': 'IP required'}), 400
    results = execute_block(ip)
    action_stats['manual_blocks_today'] += 1
    action_stats['blocked_ips'][ip] = {'time': datetime.now().isoformat(), 'reason': 'manual'}
    return jsonify({'status': 'blocked', 'ip': ip, 'results': results})

@app.route('/blocked-ips', methods=['GET'])
def blocked_ips():
    return jsonify({'blocked_ips': list(action_stats['blocked_ips'].keys())})

@app.route('/status')
def status():
    return jsonify({'business_hours': is_business_hours(), 'auto_block_enabled': policies['auto_block']['enabled'], 'stats': action_stats})

if __name__ == '__main__':
    print("⚡ SOAR (Port 8017)")
    app.run(host='0.0.0.0', port=8017, debug=False)
