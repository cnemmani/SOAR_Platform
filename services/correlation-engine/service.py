#!/usr/bin/env python3
"""
Correlation Engine Service
Port: 8040
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import os
from datetime import datetime

app = Flask(__name__)
CORS(app)

# 8 Correlation Rules
CORRELATION_RULES = [
    {
        "id": "multi_stage_attack",
        "name": "Multi-Stage Attack Chain",
        "description": "Correlates reconnaissance → exploitation → C2 → exfiltration",
        "status": "active",
        "severity": "critical",
        "category": "Attack Chain",
        "created": "2026-06-01",
        "tags": ["recon", "exploit", "c2", "exfil"],
        "rules": [
            "reconnaissance_scan",
            "exploit_attempt",
            "c2_beacon",
            "data_exfiltration"
        ]
    },
    {
        "id": "bruteforce_exfil",
        "name": "Brute Force + Data Exfil",
        "description": "SSH brute force followed by large outbound transfer",
        "status": "active",
        "severity": "high",
        "category": "Brute Force",
        "created": "2026-06-01",
        "tags": ["bruteforce", "ssh", "data_exfil"],
        "rules": [
            "ssh_bruteforce",
            "large_outbound_transfer"
        ]
    },
    {
        "id": "lateral_movement",
        "name": "Lateral Movement",
        "description": "Multiple internal connections after external compromise",
        "status": "active",
        "severity": "high",
        "category": "Lateral Movement",
        "created": "2026-06-01",
        "tags": ["lateral", "internal", "compromise"],
        "rules": [
            "external_compromise",
            "internal_connections"
        ]
    },
    {
        "id": "ransomware_pattern",
        "name": "Ransomware Pattern",
        "description": "File encryption + ransom note + C2 beaconing",
        "status": "inactive",
        "severity": "critical",
        "category": "Malware",
        "created": "2026-06-01",
        "tags": ["ransomware", "encryption", "c2"],
        "rules": [
            "file_encryption",
            "ransom_note",
            "c2_beaconing"
        ]
    },
    {
        "id": "credential_phishing",
        "name": "Credential Phishing Chain",
        "description": "Phishing email → credential harvesting → account takeover",
        "status": "active",
        "severity": "high",
        "category": "Phishing",
        "created": "2026-06-02",
        "tags": ["phishing", "credential", "ato"],
        "rules": [
            "phishing_email",
            "credential_harvest",
            "account_takeover"
        ]
    },
    {
        "id": "dns_tunneling",
        "name": "DNS Tunneling Detection",
        "description": "Abnormal DNS query patterns indicative of data exfiltration",
        "status": "active",
        "severity": "medium",
        "category": "Network",
        "created": "2026-06-02",
        "tags": ["dns", "tunneling", "exfil"],
        "rules": [
            "dns_high_volume",
            "dns_long_domain",
            "dns_txt_records"
        ]
    },
    {
        "id": "supply_chain_attack",
        "name": "Supply Chain Attack Pattern",
        "description": "Third-party compromise → malicious update → lateral spread",
        "status": "inactive",
        "severity": "critical",
        "category": "Supply Chain",
        "created": "2026-06-03",
        "tags": ["supply_chain", "third_party", "malicious_update"],
        "rules": [
            "third_party_compromise",
            "malicious_update",
            "lateral_spread"
        ]
    },
    {
        "id": "insider_threat",
        "name": "Insider Threat Pattern",
        "description": "Excessive data access → unusual data transfer → data exfiltration",
        "status": "active",
        "severity": "high",
        "category": "Insider",
        "created": "2026-06-03",
        "tags": ["insider", "data_access", "exfil"],
        "rules": [
            "excessive_data_access",
            "unusual_data_transfer",
            "data_exfiltration"
        ]
    }
]

# Store correlation events
CORRELATION_EVENTS = []

def get_correlation_stats():
    """Get statistics about correlation rules"""
    total = len(CORRELATION_RULES)
    active = len([r for r in CORRELATION_RULES if r['status'] == 'active'])
    inactive = total - active
    return {
        'total_rules': total,
        'active_rules': active,
        'inactive_rules': inactive,
        'categories': list(set([r['category'] for r in CORRELATION_RULES]))
    }

@app.route('/health')
def health():
    stats = get_correlation_stats()
    return jsonify({
        'status': 'healthy',
        'service': 'correlation-engine',
        'port': 8040,
        'rules': stats['total_rules'],
        'active_rules': stats['active_rules'],
        'inactive_rules': stats['inactive_rules']
    })

@app.route('/rules', methods=['GET'])
def get_rules():
    """Get all correlation rules"""
    status_filter = request.args.get('status', 'all')
    category_filter = request.args.get('category', 'all')
    
    rules = CORRELATION_RULES.copy()
    
    if status_filter != 'all':
        rules = [r for r in rules if r['status'] == status_filter]
    
    if category_filter != 'all':
        rules = [r for r in rules if r['category'] == category_filter]
    
    return jsonify({
        'rules': rules,
        'total': len(rules),
        'stats': get_correlation_stats()
    })

@app.route('/rules/<rule_id>', methods=['GET'])
def get_rule(rule_id):
    """Get a specific rule by ID"""
    rule = next((r for r in CORRELATION_RULES if r['id'] == rule_id), None)
    if rule:
        return jsonify(rule)
    return jsonify({'error': 'Rule not found'}), 404

@app.route('/rules/<rule_id>', methods=['PUT'])
def update_rule(rule_id):
    """Update a rule's status or other fields"""
    data = request.get_json()
    rule = next((r for r in CORRELATION_RULES if r['id'] == rule_id), None)
    
    if not rule:
        return jsonify({'error': 'Rule not found'}), 404
    
    if 'status' in data:
        rule['status'] = data['status']
    if 'name' in data:
        rule['name'] = data['name']
    if 'description' in data:
        rule['description'] = data['description']
    if 'severity' in data:
        rule['severity'] = data['severity']
    
    return jsonify(rule)

@app.route('/rules/<rule_id>/enable', methods=['POST'])
def enable_rule(rule_id):
    """Enable a correlation rule"""
    rule = next((r for r in CORRELATION_RULES if r['id'] == rule_id), None)
    if not rule:
        return jsonify({'error': 'Rule not found'}), 404
    
    rule['status'] = 'active'
    return jsonify({
        'status': 'success',
        'message': f'Rule {rule_id} enabled',
        'rule': rule
    })

@app.route('/rules/<rule_id>/disable', methods=['POST'])
def disable_rule(rule_id):
    """Disable a correlation rule"""
    rule = next((r for r in CORRELATION_RULES if r['id'] == rule_id), None)
    if not rule:
        return jsonify({'error': 'Rule not found'}), 404
    
    rule['status'] = 'inactive'
    return jsonify({
        'status': 'success',
        'message': f'Rule {rule_id} disabled',
        'rule': rule
    })

@app.route('/correlate', methods=['POST'])
def correlate_events():
    """Correlate events against rules"""
    data = request.get_json()
    events = data.get('events', [])
    
    matches = []
    for rule in CORRELATION_RULES:
        if rule['status'] != 'active':
            continue
        
        # Simple correlation logic - check if events match rule patterns
        # In production, this would be more sophisticated
        match_count = 0
        for event in events:
            event_type = event.get('type', '')
            if event_type in rule.get('rules', []):
                match_count += 1
        
        if match_count >= 2:  # At least 2 matching events trigger correlation
            matches.append({
                'rule_id': rule['id'],
                'rule_name': rule['name'],
                'severity': rule['severity'],
                'match_count': match_count,
                'confidence': min(100, match_count * 25),
                'timestamp': datetime.utcnow().isoformat()
            })
    
    return jsonify({
        'matches': matches,
        'total_matches': len(matches),
        'events_processed': len(events)
    })

@app.route('/events', methods=['GET'])
def get_events():
    """Get correlation events"""
    return jsonify({
        'events': CORRELATION_EVENTS,
        'total': len(CORRELATION_EVENTS)
    })

@app.route('/stats', methods=['GET'])
def get_stats():
    """Get correlation engine statistics"""
    stats = get_correlation_stats()
    return jsonify({
        **stats,
        'rules_by_category': {
            category: len([r for r in CORRELATION_RULES if r['category'] == category])
            for category in stats['categories']
        },
        'events_processed': len(CORRELATION_EVENTS)
    })

if __name__ == '__main__':
    print("🔗 Correlation Engine Service")
    print(f"📍 Port: 8040")
    print(f"📋 Rules: {len(CORRELATION_RULES)} (Active: {get_correlation_stats()['active_rules']})")
    print("\n📊 Rules:")
    for rule in CORRELATION_RULES:
        status = "✅" if rule['status'] == 'active' else "⛔"
        print(f"  {status} [{rule['category']}] {rule['name']}")
    
    app.run(host='0.0.0.0', port=8040, debug=False)
