#!/usr/bin/env python3
"""
8-Stage Automated Pipeline - CLEAN FIXED VERSION
"""

import os
import hashlib
import requests
from datetime import datetime
from flask import Flask
from flask import request, jsonify
from flask_cors import CORS
from collections import defaultdict

app = Flask(__name__)
CORS(app)

# API Keys
ABUSEIPDB_API_KEY = "66acfbeaad8ba806df9531dba07ab2c0680dcb3fe3737d7c753c43e88f274b47e011eae990848585"
VT_API_KEY = "b1e61d68b3a8cb7afb8c315a28153a130ee08c68e25c409cc69b2f5d5f46c2df"
OLLAMA_URL = "http://localhost:11434"

# Statistics
pipeline_stats = {
    'total_processed': 0,
    'threats_detected': 0,
    'false_positives': 0,
    'by_verdict': defaultdict(int)
}

def check_ip_reputation(ip):
    """Check IP reputation with AbuseIPDB"""
    if not ip or ip in ['N/A', 'None', '']:
        return {'abuse_score': 0, 'total_reports': 0, 'isp': 'Unknown', 'country': 'Unknown'}
    
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'}
        params = {'ipAddress': ip, 'maxAgeInDays': 90}
        
        response = requests.get(url, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json().get('data', {})
            return {
                'abuse_score': data.get('abuseConfidenceScore', 0),
                'total_reports': data.get('totalReports', 0),
                'isp': data.get('isp', 'Unknown'),
                'country': data.get('countryCode', 'Unknown')
            }
    except Exception as e:
        print(f"AbuseIPDB error: {e}")
    
    return {'abuse_score': 0, 'total_reports': 0, 'isp': 'Unknown', 'country': 'Unknown'}

def check_virustotal(ip):
    """Check IP with VirusTotal"""
    if not ip or ip in ['N/A', 'None', '']:
        return {'malicious': 0, 'suspicious': 0}
    
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {'x-apikey': VT_API_KEY}
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            return {
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0)
            }
    except Exception as e:
        print(f"VirusTotal error: {e}")
    
    return {'malicious': 0, 'suspicious': 0}

def call_ollama(description):
    """Call Ollama for analysis"""
    if not OLLAMA_URL:
        return None
    
    try:
        prompt = f"Security alert: {description[:150]}. Classify as THREAT, SUSPICIOUS, or BENIGN. Reply with just one word."

        response = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={"model": "llama3.2:3b", "prompt": prompt, "stream": False},
            timeout=15
        )
        
        if response.status_code == 200:
            result = response.json()
            text = result.get('response', '')
            
            text = text.strip().upper()
            if 'THREAT' in text:
                return {'verdict': 'THREAT', 'confidence': 80}
            elif 'SUSPICIOUS' in text:
                return {'verdict': 'SUSPICIOUS', 'confidence': 60}
            elif 'BENIGN' in text:
                return {'verdict': 'BENIGN', 'confidence': 70}
            else:
                return {'verdict': 'UNKNOWN', 'confidence': 40}
    except Exception as e:
        print(f"Ollama error: {e}")
    
    return None

def classify_threat(ip, description, severity, abuse_score, vt_malicious):
    """Classify threat based on SEVERITY + CONFIDENCE"""
    
    # === SEVERITY SCORE (0-50 points) ===
    severity_map = {'critical': 50, 'high': 35, 'medium': 20, 'low': 5}
    severity_score = severity_map.get(severity.lower(), 10)
    
    # === INTELLIGENCE CONFIDENCE (0-50 points) ===
    intel_score = 0
    
    # AbuseIPDB confidence (0-25)
    if abuse_score >= 80: intel_score += 25
    elif abuse_score >= 50: intel_score += 18
    elif abuse_score >= 25: intel_score += 10
    elif abuse_score > 0: intel_score += 5
    
    # VirusTotal confidence (0-25)  
    if vt_malicious >= 10: intel_score += 25
    elif vt_malicious >= 5: intel_score += 18
    elif vt_malicious >= 1: intel_score += 10
    
    # === LLM CONFIDENCE (0-40 points) ===
    llm_result = call_ollama(description)
    llm_confidence = llm_result.get('confidence', 0) if llm_result else 0
    llm_verdict = llm_result.get('verdict', 'UNKNOWN') if llm_result else 'UNKNOWN'
    
    # LLM contributes based on its own confidence
    llm_score = int(llm_confidence * 0.4)  # 60% LLM confidence = 24 points
    if llm_verdict == 'THREAT': llm_score = min(40, llm_score + 10)
    
    # === KEYWORD MATCH CONFIDENCE (0-20 points) ===
    desc_lower = description.lower()
    threat_keywords = ['brute', 'force', 'failed', 'attack', 'malware', 'exploit',
                      'unauthorized', 'breach', 'ransom', 'virus', 'trojan', 'ddos',
                      'authentication', 'password', 'login', 'credential', 'sshd',
                      'injection', 'scan', 'phish', 'spam', 'bot', 'automated']
    
    keyword_count = sum(1 for kw in threat_keywords if kw in desc_lower)
    keyword_score = min(20, keyword_count * 3)
    
    # === FINAL SCORE = SEVERITY + CONFIDENCE ===
    total_score = severity_score + intel_score + llm_score + keyword_score
    total_score = min(100, total_score)
    
    # === AI CONFIDENCE LEVEL ===
    ai_confidence = 0
    if llm_confidence >= 70 and (abuse_score >= 50 or vt_malicious >= 3):
        ai_confidence = 90  # High confidence - multiple sources agree
    elif llm_confidence >= 50 or abuse_score >= 50 or vt_malicious >= 5:
        ai_confidence = 70  # Medium confidence - at least one strong signal
    elif llm_confidence >= 30 or abuse_score >= 25 or vt_malicious >= 1 or keyword_count >= 3:
        ai_confidence = 50  # Low confidence - some signals
    else:
        ai_confidence = 20  # Very low confidence
    
    # === FINAL VERDICT ===
    if total_score >= 60:
        verdict = "AI_THREAT_CONFIRMED"
        action = "block"
        classification = "MALICIOUS"
    elif total_score >= 35:
        verdict = "AI_THREAT_SUSPECTED"
        action = "investigate"
        classification = "SUSPICIOUS"
    else:
        verdict = "AI_CLEAR"
        pipeline_stats['false_positives'] += 1
        pipeline_stats['false_positives'] += 1
        action = "pass"
        classification = "BENIGN"
    
    print(f"   📊 Severity:{severity_score} + Intel:{intel_score} + LLM:{llm_score} + Keywords:{keyword_score} = {total_score}")
    print(f"   🎯 AI Confidence: {ai_confidence}%")
    
    return {
        'verdict': verdict,
        'action': action,
        'classification': classification,
        'risk_score': total_score,
        'ai_confidence': ai_confidence,
        'severity_score': severity_score,
        'intel_score': intel_score,
        'llm_score': llm_score,
        'keyword_score': keyword_score,
        'llm_confidence': llm_confidence,
        'llm_verdict': llm_verdict
    }
    """Classify threat based on all signals"""
    
    risk_score = 0
    
    # Severity contribution (0-30)
    severity_map = {'critical': 30, 'high': 25, 'medium': 15, 'low': 5}
    risk_score += severity_map.get(severity.lower(), 10)
    
    # AbuseIPDB contribution (0-35)
    if abuse_score >= 80:
        risk_score += 35
    elif abuse_score >= 50:
        risk_score += 25
    elif abuse_score >= 25:
        risk_score += 15
    elif abuse_score > 0:
        risk_score += 8
    
    # VirusTotal contribution (0-35)
    if vt_malicious >= 10:
        risk_score += 35
    elif vt_malicious >= 5:
        risk_score += 25
    elif vt_malicious >= 1:
        risk_score += 15
    
    # Threat keywords in description (0-20)
    desc_lower = description.lower()
    threat_keywords = ['brute', 'force', 'failed', 'attack', 'malware', 'exploit', 
                      'unauthorized', 'breach', 'ransom', 'virus', 'trojan', 'ddos',
                      'authentication', 'password', 'login', 'credential', 'sshd']
    
    keyword_count = sum(1 for kw in threat_keywords if kw in desc_lower)
    risk_score += min(20, keyword_count * 5)
    
    # Cap at 100
    risk_score = min(100, risk_score)
    
    # Get LLM analysis
    llm_result = call_ollama(description)
    llm_confidence = llm_result.get('confidence', 0) if llm_result else 0
    llm_verdict = llm_result.get('verdict', 'UNKNOWN') if llm_result else 'UNKNOWN'
    
    # Apply LLM boost
    if llm_verdict == 'THREAT':
        risk_score = min(100, risk_score + 15)
    
    # Final classification
    
    # === ULTRA-STRICT FALSE POSITIVE CHECK ===
    # Query the Ultra FP service before making final decision
    fp_check_result = None
    try:
        fp_resp = requests.post('http://localhost:8013/check', json={
            'src_ip': ip,
            'severity': severity,
            'description': description,
            'ai_confidence': ai_confidence if 'ai_confidence' in dir() else 0,
            'risk_score': risk_score
        }, timeout=5)
        if fp_resp.status_code == 200:
            fp_check_result = fp_resp.json()
            fp_score = fp_check_result.get('fp_score', 0)
            fp_verdict = fp_check_result.get('verdict', '')
            print(f"   🛡️ Ultra FP Check: {fp_score}% ({fp_verdict})")
            
            # Override verdict if FP score is high
            if fp_score >= 80:
                verdict = "FALSE_POSITIVE"
                action = "suppress"
                classification = "BENIGN"
                print(f"   ⚠️ ULTRA FP OVERRIDE: False Positive detected!")
            elif fp_score >= 60 and risk_score < 50:
                verdict = "LIKELY_FALSE_POSITIVE"
                action = "monitor"
                print(f"   ⚠️ FP OVERRIDE: Likely false positive, monitoring only")
    except Exception as e:
        print(f"   ⚠️ FP check unavailable: {e}")

    if risk_score >= 50:
        verdict = "AI_THREAT_CONFIRMED"
        action = "block"
        classification = "MALICIOUS"
    elif risk_score >= 30:
        verdict = "AI_THREAT_SUSPECTED"
        action = "investigate"
        classification = "SUSPICIOUS"
    else:
        verdict = "AI_CLEAR"
        pipeline_stats['false_positives'] += 1
        pipeline_stats['false_positives'] += 1
        action = "pass"
        classification = "BENIGN"
    
    return {
        'verdict': verdict,
        'action': action,
        'classification': classification,
        'risk_score': risk_score,
        'llm_confidence': llm_confidence,
        'llm_verdict': llm_verdict,
        'keyword_count': keyword_count
    }

@app.route('/process', methods=['POST'])
def process_alert():
    try:
        data = request.json
        if not data:
            return jsonify({'error': 'No data'}), 400
        
        src_ip = data.get('src_ip', '')
        severity = data.get('severity', 'medium')
        description = data.get('data', {}).get('rule_description', '') or data.get('description', '')
        
        print(f"\n{'='*60}")
        print(f"Processing: {src_ip} - {severity}")
        print(f"Description: {description[:100]}...")
        
        # Get reputation and VT data
        reputation = check_ip_reputation(src_ip) if src_ip else {}
        vt_data = check_virustotal(src_ip) if src_ip else {}
        
        # Classify threat
        result = classify_threat(
            src_ip, description, severity,
            reputation.get('abuse_score', 0),
            vt_data.get('malicious', 0)
        )
        
        # Update stats
        pipeline_stats['total_processed'] += 1
        pipeline_stats['by_verdict'][result['verdict']] += 1
        if 'THREAT' in result['verdict']:
            pipeline_stats['threats_detected'] += 1
        
        response = {
            'alert_id': hash(src_ip + description) % 10000000,
            'src_ip': src_ip,
            'timestamp': datetime.now().isoformat(),
            'final_verdict': result['verdict'],
            'recommended_action': result['action'],
            'risk_score': result['risk_score'],
            'llm_confidence': result['llm_confidence'],
            'llm_verdict': result['llm_verdict'],
            'ai_confidence': result['ai_confidence'],
            'score_breakdown': {'severity': result['severity_score'], 'intel': result['intel_score'], 'llm': result['llm_score'], 'keywords': result['keyword_score']},
            'scores': {
                'abuse': reputation.get('abuse_score', 0),
                'vt_malicious': vt_data.get('malicious', 0),
                'keyword_count': result['keyword_score']
            },
            'attacker_profile': {
                'classification': result['classification'],
                'isp': reputation.get('isp', 'Unknown'),
                'country': reputation.get('country', 'Unknown')
            }
        }
        
        print(f"✅ Verdict: {result['verdict']} | Risk: {result['risk_score']}% | Action: {result['action']}")
        print(f"   LLM: {result['llm_verdict']} ({result['llm_confidence']}% confidence)")
        print(f"{'='*60}\n")
        
        return jsonify(response)
    
    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/health', methods=['GET'])
def health():
    tenant = request.args.get('tenant', 'all')
    
    # Try to get tenant-specific stats from auto-pipeline
    tenant_stats = None
    if tenant and tenant != 'all' and tenant != 'global':
        try:
            resp = requests.get(f'http://localhost:8021/stats?tenant={tenant}', timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                tenant_stats = {
                    'total_processed': data.get('total_processed', 0),
                    'threats_detected': data.get('persistent_threats', data.get('threats_detected', 0)),
                    'by_verdict': data.get('by_verdict', {}),
                    'tenant': tenant
                }
        except: pass
    
    if not tenant_stats:
        # Fallback to local global stats
        tenant_stats = {
            'total_processed': pipeline_stats['total_processed'],
            'threats_detected': pipeline_stats['threats_detected'],
            'by_verdict': dict(pipeline_stats['by_verdict']),
            'tenant': 'global'
        }
    
    return jsonify({
        'status': 'healthy',
        'abuseipdb_configured': True,
        'virustotal_configured': True,
        'ollama_configured': bool(OLLAMA_URL),
        'stats': tenant_stats
    })


@app.route('/stats', methods=['GET', 'OPTIONS'])
def stats():
    if request.method == 'OPTIONS': return jsonify({}), 200
    return jsonify({'total_processed': pipeline_stats['total_processed'], 'threats_detected': pipeline_stats['threats_detected']})

if __name__ == '__main__':
    print("=" * 70)
    print("🚀 8-STAGE PIPELINE - CLEAN VERSION")
    print(f"   Threat threshold: 50+ = THREAT, 30+ = SUSPICIOUS")
    print("=" * 70)
    app.run(host='0.0.0.0', port=8015, debug=False)
