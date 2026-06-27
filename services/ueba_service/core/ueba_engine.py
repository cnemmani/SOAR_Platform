#!/usr/bin/env python3
"""
Core UEBA Engine - Behavioral analytics and anomaly detection
"""

import sqlite3
import numpy as np
from datetime import datetime, timedelta
from collections import defaultdict
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
import logging

logger = logging.getLogger(__name__)

@dataclass
class BehavioralProfile:
    entity_id: str
    entity_type: str
    hour_profile: Dict[int, float]
    day_profile: Dict[int, float]
    severity_profile: Dict[int, float]
    attack_type_profile: Dict[str, float]
    peer_group: str
    risk_score: float
    last_updated: str
    total_alerts: int
    first_seen: str
    last_seen: str

class UEBAEngine:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.behavioral_profiles: Dict[str, BehavioralProfile] = {}
        self.peer_groups: Dict[str, List[str]] = {}
        self.risk_weights = {'volume': 0.30, 'severity': 0.30, 'time_anomaly': 0.20, 'peer_anomaly': 0.10, 'attack_variety': 0.10}
        self._calculate_peer_groups()
        logger.info("UEBA Engine initialized")
    
    def _calculate_peer_groups(self) -> Dict[str, List[str]]:
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                SELECT attacker_ip, strftime('%H', timestamp) as hour
                FROM wazuh_alerts 
                WHERE attacker_ip NOT IN ('N/A', 'None', '')
                AND attacker_ip IS NOT NULL
                GROUP BY attacker_ip, hour
            """)
            entity_vectors = defaultdict(lambda: defaultdict(int))
            for row in cursor.fetchall():
                ip = row[0]
                hour = int(row[1]) if row[1] else 0
                entity_vectors[ip][hour] += 1
            conn.close()
            peer_groups = defaultdict(list)
            for ip, vector in entity_vectors.items():
                values = list(vector.values())
                if values:
                    threshold = np.percentile(values, 75) if len(values) > 1 else values[0]
                    peak_hours = [h for h, count in vector.items() if count > threshold]
                    signature = tuple(sorted(peak_hours)[:5]) if peak_hours else ('off_hours',)
                else:
                    signature = ('inactive',)
                peer_groups[signature].append(ip)
            self.peer_groups = dict(peer_groups)
            return self.peer_groups
        except Exception as e:
            logger.error(f"Error calculating peer groups: {e}")
            return {}
    
    def get_behavioral_profile(self, entity_id: str, entity_type: str = 'ip') -> Optional[BehavioralProfile]:
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            if entity_type == 'ip':
                cursor.execute("""
                    SELECT strftime('%H', timestamp) as hour, strftime('%w', timestamp) as day, severity, threat_classification, timestamp
                    FROM wazuh_alerts WHERE attacker_ip = ? AND timestamp >= datetime('now', '-30 days') ORDER BY timestamp
                """, (entity_id,))
            else:
                cursor.execute("""
                    SELECT strftime('%H', timestamp) as hour, strftime('%w', timestamp) as day, severity, threat_classification, timestamp
                    FROM wazuh_alerts WHERE agent_name = ? AND timestamp >= datetime('now', '-30 days') ORDER BY timestamp
                """, (entity_id,))
            rows = cursor.fetchall()
            conn.close()
            if not rows: return None
            hour_profile, day_profile, severity_profile, attack_profile = defaultdict(int), defaultdict(int), defaultdict(int), defaultdict(int)
            first_seen = rows[0][4] if rows[0][4] else datetime.now().isoformat()
            last_seen = rows[-1][4] if rows[-1][4] else datetime.now().isoformat()
            for row in rows:
                hour = int(row[0]) if row[0] else 0
                day = int(row[1]) if row[1] else 0
                severity = row[2] if row[2] else 0
                attack_type = row[3] if row[3] else 'Unknown'
                hour_profile[hour] += 1
                day_profile[day] += 1
                severity_profile[severity] += 1
                attack_profile[attack_type] += 1
            total = sum(hour_profile.values())
            if total > 0:
                hour_profile = {k: round(v/total, 3) for k, v in hour_profile.items()}
                day_profile = {k: round(v/total, 3) for k, v in day_profile.items()}
            peer_group = self._find_peer_group(hour_profile)
            risk_score = self._calculate_risk_score(entity_id, entity_type, hour_profile, severity_profile)
            profile = BehavioralProfile(entity_id=entity_id, entity_type=entity_type, hour_profile=hour_profile, day_profile=day_profile, severity_profile=severity_profile, attack_type_profile=dict(attack_profile), peer_group=peer_group, risk_score=risk_score, last_updated=datetime.now().isoformat(), total_alerts=total, first_seen=first_seen, last_seen=last_seen)
            self.behavioral_profiles[f"{entity_type}_{entity_id}"] = profile
            return profile
        except Exception as e:
            logger.error(f"Error getting behavioral profile: {e}")
            return None
    
    def _find_peer_group(self, hour_profile: Dict[int, float]) -> str:
        if not hour_profile: return "unknown"
        daytime = sum(hour_profile.get(h, 0) for h in range(9, 18))
        nighttime = sum(hour_profile.get(h, 0) for h in range(0, 6))
        if daytime > 0.6: return "daytime_worker"
        elif nighttime > 0.4: return "nighttime_attacker"
        elif daytime > 0.3 and nighttime > 0.3: return "mixed_pattern"
        else: return "irregular_pattern"
    
    def _calculate_risk_score(self, entity_id: str, entity_type: str, hour_profile: Dict[int, float], severity_profile: Dict[int, float]) -> float:
        risk_score = 0.0
        high_severity = sum(v for k, v in severity_profile.items() if k >= 7)
        total = sum(severity_profile.values())
        if total > 0: risk_score += (high_severity / total) * 30
        nighttime = sum(hour_profile.get(h, 0) for h in range(0, 6))
        risk_score += nighttime * 25
        attack_variety = len(severity_profile)
        risk_score += min(20, attack_variety * 2)
        risk_score += min(25, total / 100)
        return round(min(100, risk_score), 2)
    
    def detect_anomalies(self, time_window: str = '1 hour') -> List[Dict]:
        anomalies = []
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("""
                SELECT attacker_ip, COUNT(*) as alert_count
                FROM wazuh_alerts WHERE timestamp >= datetime('now', '-1 hour')
                AND attacker_ip NOT IN ('N/A', 'None', '') GROUP BY attacker_ip
                HAVING alert_count > 50 ORDER BY alert_count DESC LIMIT 20
            """)
            for row in cursor.fetchall():
                anomalies.append({'type': 'HIGH_VOLUME', 'entity': row['attacker_ip'], 'entity_type': 'ip', 'metric': row['alert_count'], 'threshold': 50, 'severity': 'HIGH', 'description': f"Unusual high volume of alerts ({row['alert_count']} in last hour)"})
            cursor = conn.execute("""
                SELECT DISTINCT attacker_ip FROM wazuh_alerts WHERE timestamp >= datetime('now', '-1 hour')
                AND attacker_ip NOT IN (SELECT DISTINCT attacker_ip FROM wazuh_alerts WHERE timestamp >= datetime('now', '-7 days') AND timestamp < datetime('now', '-1 hour'))
                AND attacker_ip NOT IN ('N/A', 'None', '') LIMIT 20
            """)
            for row in cursor.fetchall():
                anomalies.append({'type': 'NEW_ENTITY', 'entity': row['attacker_ip'], 'entity_type': 'ip', 'severity': 'MEDIUM', 'description': f"New attacker IP detected: {row['attacker_ip']}"})
            conn.close()
        except Exception as e:
            logger.error(f"Anomaly detection error: {e}")
        return anomalies
    
    def get_entity_risk(self, entity_id: str, entity_type: str = 'ip') -> Dict:
        profile = self.get_behavioral_profile(entity_id, entity_type)
        if not profile: return {'error': 'Entity not found'}
        risk_level = 'CRITICAL' if profile.risk_score >= 70 else 'HIGH' if profile.risk_score >= 50 else 'MEDIUM' if profile.risk_score >= 30 else 'LOW'
        return {'entity_id': entity_id, 'entity_type': entity_type, 'risk_score': profile.risk_score, 'risk_level': risk_level, 'peer_group': profile.peer_group, 'total_alerts': profile.total_alerts, 'first_seen': profile.first_seen, 'last_seen': profile.last_seen, 'active_hours': len(profile.hour_profile), 'unique_attack_types': len(profile.attack_type_profile)}
    
    def get_risk_trend(self, entity_id: str, entity_type: str = 'ip', days: int = 7) -> Dict:
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            if entity_type == 'ip':
                cursor.execute("SELECT DATE(timestamp) as day, COUNT(*) FROM wazuh_alerts WHERE attacker_ip = ? AND timestamp >= datetime('now', '-? days') GROUP BY DATE(timestamp) ORDER BY day", (entity_id, days))
            else:
                cursor.execute("SELECT DATE(timestamp) as day, COUNT(*) FROM wazuh_alerts WHERE agent_name = ? AND timestamp >= datetime('now', '-? days') GROUP BY DATE(timestamp) ORDER BY day", (entity_id, days))
            rows = cursor.fetchall()
            conn.close()
            if not rows: return {'error': 'No data found'}
            trend = [{'date': row[0], 'alert_count': row[1]} for row in rows]
            return {'entity_id': entity_id, 'trend_direction': 'STABLE', 'daily_metrics': trend, 'total_alerts': sum(t['alert_count'] for t in trend), 'avg_daily_alerts': round(sum(t['alert_count'] for t in trend) / len(trend), 2)}
        except Exception as e:
            return {'error': str(e)}
    
    def get_top_risk_entities(self, limit: int = 20) -> List[Dict]:
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                SELECT attacker_ip, COUNT(*) as total_alerts, AVG(severity) as avg_severity, MAX(severity) as max_severity, COUNT(DISTINCT threat_classification) as attack_variety, MAX(timestamp) as last_seen
                FROM wazuh_alerts WHERE attacker_ip NOT IN ('N/A', 'None', '') AND attacker_ip IS NOT NULL AND timestamp >= datetime('now', '-30 days')
                GROUP BY attacker_ip HAVING total_alerts > 5 ORDER BY total_alerts DESC LIMIT ?
            """, (limit,))
            rows = cursor.fetchall()
            conn.close()
            entities = []
            for row in rows:
                volume_score = min(40, row[1] / 25)
                severity_score = (row[2] / 15) * 30 if row[2] else 0
                variety_score = min(30, row[4] * 3)
                risk_score = round(min(100, volume_score + severity_score + variety_score), 2)
                risk_level = 'CRITICAL' if risk_score >= 70 else 'HIGH' if risk_score >= 50 else 'MEDIUM' if risk_score >= 30 else 'LOW'
                entities.append({'ip': row[0], 'total_alerts': row[1], 'avg_severity': round(row[2], 2) if row[2] else 0, 'max_severity': row[3] if row[3] else 0, 'attack_variety': row[4] if row[4] else 0, 'last_seen': row[5] if row[5] else 'Unknown', 'risk_score': risk_score, 'risk_level': risk_level})
            return entities
        except Exception as e:
            logger.error(f"Error getting top risk entities: {e}")
            return []
    
    def analyze_peer_group(self, entity_id: str, entity_type: str = 'ip') -> Dict:
        profile = self.get_behavioral_profile(entity_id, entity_type)
        if not profile: return {'error': 'Entity not found'}
        peers = self.peer_groups.get(profile.peer_group, [])
        if len(peers) < 3: return {'entity_id': entity_id, 'peer_group': profile.peer_group, 'peer_count': len(peers), 'analysis': 'Insufficient peers for meaningful comparison'}
        return {'entity_id': entity_id, 'peer_group': profile.peer_group, 'peer_count': len(peers), 'entity_risk': profile.risk_score, 'is_outlier': False, 'risk_deviation': 0}

_ueba_engine = None

def init_ueba_engine(db_path: str) -> UEBAEngine:
    global _ueba_engine
    if _ueba_engine is None:
        _ueba_engine = UEBAEngine(db_path)
    return _ueba_engine

def get_ueba_engine() -> Optional[UEBAEngine]:
    return _ueba_engine
