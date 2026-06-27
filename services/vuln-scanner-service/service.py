"""
Vulnerability Scanner Service
Scans agent packages against CVE database
Port: 8052
"""
from flask import Flask, jsonify, request
import sqlite3, json, re, os
from datetime import datetime

app = Flask(__name__)
scan_findings = []

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

# CVE Database
CVE_DB = [
    {'cve':'CVE-2024-6387','name':'regreSSHion RCE','service':'openssh','min_ver':'8.5','max_ver':'9.7','cvss':9.8,'risk':'critical','desc':'Remote Unauthenticated Code Execution in OpenSSH server','fix':'Upgrade to OpenSSH 9.8p1+ immediately.'},
    {'cve':'CVE-2023-48795','name':'Terrapin Attack','service':'openssh','min_ver':'0','max_ver':'9.5','cvss':5.9,'risk':'medium','desc':'SSH protocol prefix truncation attack','fix':'Upgrade to OpenSSH 9.6p1+'},
    {'cve':'CVE-2024-24989','name':'nginx HTTP/3 DoS','service':'nginx','min_ver':'1.25.0','max_ver':'1.25.3','cvss':7.4,'risk':'high','desc':'HTTP/3 QUIC stream memory corruption','fix':'Upgrade nginx to 1.25.4+'},
    {'cve':'CVE-2023-44487','name':'HTTP/2 Rapid Reset','service':'nginx','min_ver':'1.0','max_ver':'1.25.2','cvss':7.5,'risk':'high','desc':'HTTP/2 Rapid Reset Attack','fix':'Upgrade nginx'},
    {'cve':'CVE-2024-5535','name':'OpenSSL TLS DoS','service':'openssl','min_ver':'3.0','max_ver':'3.3.0','cvss':7.5,'risk':'high','desc':'TLS handshake Denial of Service','fix':'Upgrade to OpenSSL 3.3.1+'},
    {'cve':'CVE-2024-1086','name':'Kernel nf_tables UAF','service':'kernel','min_ver':'5.14','max_ver':'6.7','cvss':7.8,'risk':'high','desc':'Linux kernel nf_tables use-after-free','fix':'Upgrade kernel to 6.8+'},
    {'cve':'CVE-2023-42465','name':'Sudo Buffer Overflow','service':'sudo','min_ver':'1.8.0','max_ver':'1.9.14','cvss':7.0,'risk':'high','desc':'Heap-based buffer overflow in sudo','fix':'Upgrade sudo to 1.9.15p5+'},
    {'cve':'CVE-2024-2201','name':'Python HTTP Smuggling','service':'python','min_ver':'0','max_ver':'3.12.1','cvss':5.3,'risk':'medium','desc':'HTTP request smuggling','fix':'Use production WSGI server'},
]

def version_in_range(version, min_ver, max_ver):
    try:
        v = [int(x) for x in version.split('.')]
        mi = [int(x) for x in min_ver.split('.')]
        ma = [int(x) for x in max_ver.split('.')]
        while len(v)<3: v.append(0)
        while len(mi)<3: mi.append(0)
        while len(ma)<3: ma.append(0)
        vn = v[0]*10000+v[1]*100+v[2]
        return (mi[0]*10000+mi[1]*100+mi[2]) <= vn <= (ma[0]*10000+ma[1]*100+ma[2])
    except: return False

def scan_local_packages():
    """Scan local server packages"""
    findings = []
    for cve in CVE_DB:
        version = None
        try:
            if cve['service'] == 'openssh':
                r = __import__('subprocess').run(['ssh','-V'],capture_output=True,text=True,timeout=5)
                m = re.search(r'OpenSSH[_ ](\d+\.\d+)', r.stderr+r.stdout)
                if m: version = m.group(1)
            elif cve['service'] == 'nginx':
                r = __import__('subprocess').run(['nginx','-v'],capture_output=True,text=True,timeout=5)
                m = re.search(r'nginx/(\d+\.\d+\.\d+)', r.stderr+r.stdout)
                if m: version = m.group(1)
            elif cve['service'] == 'openssl':
                r = __import__('subprocess').run(['openssl','version'],capture_output=True,text=True,timeout=5)
                m = re.search(r'OpenSSL (\d+\.\d+\.\d+)', r.stdout)
                if m: version = m.group(1)
            elif cve['service'] == 'python':
                r = __import__('subprocess').run(['python3','--version'],capture_output=True,text=True,timeout=5)
                m = re.search(r'Python (\d+\.\d+\.\d+)', r.stdout+r.stderr)
                if m: version = m.group(1)
            elif cve['service'] == 'kernel':
                r = __import__('subprocess').run(['uname','-r'],capture_output=True,text=True,timeout=5)
                m = re.search(r'(\d+\.\d+)', r.stdout)
                if m: version = m.group(1)
        except: pass
        
        if version and version_in_range(version, cve['min_ver'], cve['max_ver']):
            findings.append({**cve, 'detected_version': version, 'found_at': datetime.now().isoformat(), 'source': 'local_scan'})
    return findings

def scan_agent_packages(agent_id):
    """Scan packages reported by a specific agent"""
    findings = []
    try:
        conn = sqlite3.connect('/home/ubuntu/soar-dashboard/ir_tracking.db')
        conn.row_factory = sqlite3.Row
        pkgs = conn.execute("SELECT * FROM agent_packages WHERE agent_id=?", (agent_id,)).fetchall()
        conn.close()
        
        for pkg in pkgs:
            for cve in CVE_DB:
                if cve['service'].lower() in pkg['package_name'].lower():
                    if version_in_range(pkg['version'], cve['min_ver'], cve['max_ver']):
                        findings.append({
                            **cve,
                            'detected_version': pkg['version'],
                            'package_name': pkg['package_name'],
                            'found_at': datetime.now().isoformat(),
                            'source': f'agent:{agent_id}'
                        })
    except Exception as e:
        print(f"Agent scan error: {e}")
    return findings

@app.route('/health')
def health():
    return jsonify({'status':'healthy','service':'vuln-scanner','cve_count':len(CVE_DB)})

@app.route('/scan', methods=['POST'])
def scan_target():
    data = request.json or {}
    agent_id = data.get('agent_id', '')
    
    # If agent_id provided, scan that agent's reported packages
    if agent_id and agent_id != 'unknown':
        findings = scan_agent_packages(agent_id)
        # Also add local scan results
        local = scan_local_packages()
        for f in local:
            if not any(x.get('cve')==f['cve'] for x in findings):
                findings.append(f)
        scan_type = f'agent_packages + local'
    else:
        findings = scan_local_packages()
        scan_type = 'local_only'
    
    return jsonify({
        'agent_id': agent_id,
        'timestamp': datetime.now().isoformat(),
        'scan_type': scan_type,
        'vulnerabilities_found': len(findings),
        'vulnerabilities': findings
    })

@app.route('/findings')
def get_findings():
    return jsonify({'total':len(scan_findings),'findings':scan_findings})

if __name__ == '__main__':
    scan_findings = scan_local_packages()
    print(f"📊 Initial scan: {len(scan_findings)} local CVEs found")
    app.run(host='0.0.0.0', port=8052, debug=False)
