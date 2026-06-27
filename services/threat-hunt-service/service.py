import sys; sys.path.insert(0, "..")
from cors_helper import enable_cors
"""
AI-Powered Threat Hunting Service v2.1
- Improved AI suggestions using real alert patterns
- Advanced Query Builder
- Threat Intel enrichment
"""
from flask import Flask, jsonify, request
from flask_cors import CORS
import sqlite3, json, os, re, requests
from datetime import datetime, timedelta
from collections import Counter

app = Flask(__name__)
enable_cors(app)
CORS(app)

DB = "/home/ubuntu/soar-dashboard/wazuh_alerts.db"
HUNTS_FILE = "/home/ubuntu/soar-dashboard/microservices/threat_hunts.json"
OLLAMA_URL = "http://localhost:11434"
VT_URL = "http://localhost:8006/ip"

def get_db():
    conn = sqlite3.connect(DB, timeout=10)
    conn.execute('PRAGMA journal_mode=WAL')
    conn.row_factory = sqlite3.Row
    return conn

def load_hunts():
    if os.path.exists(HUNTS_FILE):
        try: return json.load(open(HUNTS_FILE))
        except: pass
    return []

def save_hunts(hunts):
    with open(HUNTS_FILE, "w") as f: json.dump(hunts, f, indent=2)

# ─── AI Helper ──────────────────────────────────────
def ask_ai(prompt, max_tokens=80):
    try:
        resp = requests.post(f"{OLLAMA_URL}/api/generate",
            json={"model":"qwen2:0.5b","prompt":prompt,"stream":False,
                  "options":{"max_tokens":max_tokens,"temperature":0.3}}, timeout=10)
        if resp.status_code == 200:
            return resp.json().get("response","").strip()
    except: pass
    return ""

# ─── IMPROVED AI SUGGESTIONS ───────────────────────
def ai_suggest_queries():
    """Generate smart queries - with fallback if DB is busy"""
    try:
        return _ai_suggest_queries_internal()
    except Exception as e:
        print(f"AI suggest DB error: {e}")
        return ["ssh OR failed OR authentication", "process OR command OR executed", "sudo OR root OR privilege"]

def _ai_suggest_queries_internal():
    """Generate smart queries based on actual alert patterns"""
    conn = get_db()
    
    # Get top rule descriptions (most common threats)
    top_rules = conn.execute("""
        SELECT rule_description, COUNT(*) as cnt 
        FROM wazuh_alerts WHERE severity >= 5 
        AND timestamp >= datetime('now','-7 days')
        GROUP BY rule_description ORDER BY cnt DESC LIMIT 8
    """).fetchall()
    
    # Get top attacker IPs
    top_ips = conn.execute("""
        SELECT attacker_ip, COUNT(*) as cnt 
        FROM wazuh_alerts WHERE attacker_ip IS NOT NULL 
        AND attacker_ip != '' AND attacker_ip != 'None'
        AND severity >= 5 AND timestamp >= datetime('now','-7 days')
        GROUP BY attacker_ip ORDER BY cnt DESC LIMIT 5
    """).fetchall()
    
    # Get top agents being attacked
    top_agents = conn.execute("""
        SELECT agent_name, COUNT(*) as cnt 
        FROM wazuh_alerts WHERE agent_name IS NOT NULL
        AND severity >= 7 AND timestamp >= datetime('now','-7 days')
        GROUP BY agent_name ORDER BY cnt DESC LIMIT 5
    """).fetchall()
    
    conn.close()
    
    suggestions = []
    
    # Generate rule-based suggestions (always work, no AI needed)
    if top_rules:
        # Extract key words from top rules
        words = []
        for r in top_rules[:3]:
            desc = (r['rule_description'] or '').lower()
            # Extract meaningful words
            keywords = re.findall(r'\b(ssh|failed|authentication|login|sudo|root|scan|attack|malware|phish|ddos|brute|force|password|credential|process|command|powershell|wmic|smb|rdp|psexec|exfil|upload|download|ransom|trojan|backdoor|injection|xss|sql)\b', desc)
            words.extend(keywords[:3])
        
        if words:
            unique_words = list(set(words))[:6]
            suggestions.append(" OR ".join(unique_words))
    
    # Add IP-based suggestions
    if top_ips:
        ip_queries = [f'"{ip["attacker_ip"]}"' for ip in top_ips[:3]]
        suggestions.append(" OR ".join(ip_queries))
    
    # Add agent-based suggestions
    if top_agents:
        agent_queries = [f'"{agent["agent_name"]}"' for agent in top_agents[:2]]
        suggestions.append(" OR ".join(agent_queries))
    
    # Try AI enhancement if available
    if top_rules and OLLAMA_URL:
        context = " | ".join(r['rule_description'][:60] for r in top_rules[:4])
        prompt = f"Recent security alerts: {context[:300]}. Suggest 2 hunting keyword queries (2-3 words each, comma-separated, no explanation)."
        ai_response = ask_ai(prompt, 60)
        ai_suggestions = [s.strip() for s in ai_response.split(",") if s.strip() and len(s.strip()) > 5]
        if ai_suggestions:
            suggestions = ai_suggestions[:2] + suggestions[:3]
    
    # Fallback: always return at least one good query
    if not suggestions:
        suggestions = ["ssh OR failed OR authentication", "process OR command OR executed"]
    
    return suggestions[:6]

# ─── Templates ──────────────────────────────────────
TEMPLATES = {
    "suspicious_process": {"name":"Suspicious Process","query":"process OR cmd OR powershell OR wmic OR executed","hours":24},
    "lateral_movement": {"name":"Lateral Movement","query":"smb OR rdp OR psexec OR winrm OR lateral","hours":48},
    "data_exfil": {"name":"Data Exfiltration","query":"upload OR exfil OR mega OR pastebin OR dropbox OR transfer","hours":72},
    "credential_access": {"name":"Credential Access","query":"mimikatz OR lsass OR sam OR shadow OR vault OR credential","hours":24},
    "c2_communication": {"name":"C2 Communication","query":"beacon OR callback OR c2 OR command OR control","hours":168},
    "brute_force": {"name":"Brute Force","query":"failed OR invalid OR brute OR multiple OR attempts","hours":24},
    "privilege_escalation": {"name":"Privilege Escalation","query":"sudo OR root OR admin OR escalated OR privilege","hours":48},
    "web_attacks": {"name":"Web Attacks","query":"sql OR xss OR injection OR path OR traversal OR csrf","hours":72},
    "malware": {"name":"Malware Activity","query":"malware OR trojan OR virus OR ransomware OR backdoor","hours":72},
}

# ─── Routes ─────────────────────────────────────────
@app.route("/health")
def health():
    conn = get_db()
    total = conn.execute("SELECT COUNT(*) FROM wazuh_alerts").fetchone()[0]
    conn.close()
    return jsonify({"status":"healthy","service":"threat-hunt","total_alerts":total,"ai_enabled":bool(OLLAMA_URL)})

@app.route("/templates")
def get_templates():
    return jsonify({"templates": TEMPLATES})

@app.route("/suggest", methods=["GET"])
def suggest():
    suggestions = ai_suggest_queries()
    return jsonify({"suggestions": suggestions, "count": len(suggestions), "source": "real-alerts"})

@app.route("/builder-query", methods=["POST"])
def builder_query():
    data = request.get_json() or {}
    severity = int(data.get("severity", 0))
    hours = int(data.get("hours", 24))
    source = data.get("source", "all")
    agent = data.get("agent", "").strip()
    ip = data.get("ip", "").strip()
    description = data.get("description", "").strip()
    limit = int(data.get("limit", 200))
    
    conditions = []; params = []
    
    if severity > 0:
        conditions.append("severity >= ?"); params.append(severity)
    
    since = (datetime.utcnow() - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S")
    conditions.append("timestamp >= ?"); params.append(since)
    
    if source and source != "all":
        conditions.append("(agent_name LIKE ? OR rule_description LIKE ?)")
        params.extend([f"%{source}%", f"%{source}%"])
    if agent:
        conditions.append("agent_name LIKE ?"); params.append(f"%{agent}%")
    if ip:
        conditions.append("attacker_ip LIKE ?"); params.append(f"%{ip}%")
    if description:
        conditions.append("rule_description LIKE ?"); params.append(f"%{description}%")
    
    where = " AND ".join(conditions) if conditions else "1=1"
    
    conn = get_db()
    total = conn.execute(f"SELECT COUNT(*) FROM wazuh_alerts WHERE {where}", params).fetchone()[0]
    rows = conn.execute(f"SELECT * FROM wazuh_alerts WHERE {where} ORDER BY timestamp DESC LIMIT ?", params + [limit]).fetchall()
    conn.close()
    
    results = [dict(r) for r in rows]
    enriched_ips = enrich_results(results)
    
    return jsonify({"query":"Builder Query", "total":total, "returned":len(results), "results":results[:limit], "enriched_ips":enriched_ips})

@app.route("/hunt", methods=["POST"])
def run_hunt():
    data = request.get_json() or {}
    query = data.get("query", "").strip()
    hours = int(data.get("hours", 24))
    limit = int(data.get("limit", 200))
    
    if not query: return jsonify({"error":"Query required"}), 400
    
    or_groups = re.split(r'\s+OR\s+', query)
    all_conditions = []; all_params = []
    
    for group in or_groups:
        and_words = group.strip().split()
        if not and_words: continue
        group_conditions = []
        for word in and_words:
            word = word.strip().strip('"\'')
            if not word: continue
            like = f"%{word}%"
            group_conditions.append("(rule_description LIKE ? OR agent_name LIKE ? OR attacker_ip LIKE ?)")
            all_params.extend([like, like, like])
        if group_conditions:
            all_conditions.append("(" + " AND ".join(group_conditions) + ")")
    
    if not all_conditions: return jsonify({"error":"No valid search terms"}), 400
    
    where = "(" + " OR ".join(all_conditions) + ")"
    since = (datetime.utcnow() - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S")
    where = f"timestamp >= ? AND {where}"
    all_params.insert(0, since)
    
    conn = get_db()
    total = conn.execute(f"SELECT COUNT(*) FROM wazuh_alerts WHERE {where}", all_params).fetchone()[0]
    rows = conn.execute(f"SELECT * FROM wazuh_alerts WHERE {where} ORDER BY timestamp DESC LIMIT ?", all_params + [limit]).fetchall()
    conn.close()
    
    results = [dict(r) for r in rows]
    enriched_ips = enrich_results(results)
    
    # Save hunt
    hunts = load_hunts()
    hunts.append({"query":query,"hours":hours,"results":total,"timestamp":datetime.utcnow().isoformat()})
    if len(hunts) > 100: hunts = hunts[-100:]
    save_hunts(hunts)
    
    return jsonify({"query":query,"hours":hours,"total":total,"returned":len(results),"results":results[:limit],"enriched_ips":enriched_ips})

@app.route("/hunts")
def get_hunts():
    return jsonify({"hunts": load_hunts()})

@app.route("/hunts/save", methods=["POST"])
def save_named_hunt():
    data = request.get_json() or {}
    name = data.get("name","").strip()
    if not name: return jsonify({"error":"Name required"}), 400
    hunts = load_hunts()
    hunts.append({"name":name,"query":data.get("query",""),"hours":data.get("hours",24),"results":data.get("results_count",0),"timestamp":datetime.utcnow().isoformat(),"saved":True})
    if len(hunts) > 100: hunts = hunts[-100:]
    save_hunts(hunts)
    return jsonify({"status":"saved"})

def enrich_results(results):
    enriched = {}
    ips = set()
    for r in results:
        ip = r.get('attacker_ip','')
        if ip and ip not in ['0.0.0.0','127.0.0.1','N/A','None']: ips.add(ip)
    for ip in list(ips)[:10]:
        try:
            resp = requests.get(f"{VT_URL}/{ip}", timeout=3)
            if resp.status_code == 200:
                d = resp.json()
                enriched[ip] = {"vt":{"malicious":d.get("malicious",0),"suspicious":d.get("suspicious",0)}}
        except: pass
    return enriched


@app.route("/saved-hunts")
def get_saved_hunts():
    hunts = load_hunts()
    saved = [h for h in hunts if h.get("saved")]
    return jsonify({"hunts": saved})

if __name__ == "__main__":
    print("🦅 AI Threat Hunting v2.1 (Port 8039)")
    app.run(host="0.0.0.0", port=8039, debug=False)
