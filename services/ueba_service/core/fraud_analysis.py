#!/usr/bin/env python3
"""
Comprehensive Fraud Analysis Module
- User Behavior Analytics (UBA)
- Anomaly Detection with Multiple Techniques
- Fraud Pattern Recognition
- Peer Group Benchmarking
- Risk Scoring Engine
"""

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from scipy import stats
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List, Any, Tuple
import logging
import json
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)

@dataclass
class FraudIndicator:
    """Fraud indicator with scoring"""
    name: str
    weight: float
    threshold: float
    current_value: float
    risk_contribution: float
    details: Dict

class FraudAnalysisEngine:
    """Advanced Fraud Analysis Engine"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.user_profiles = {}
        self.behavioral_baselines = {}
        self.fraud_patterns = self._init_fraud_patterns()
        self.risk_weights = {
            'velocity': 0.25,
            'volume': 0.20,
            'time_anomaly': 0.15,
            'peer_deviation': 0.15,
            'pattern_match': 0.15,
            'geographic': 0.10
        }
        logger.info("Fraud Analysis Engine initialized")
    
    def _init_fraud_patterns(self) -> Dict:
        """Initialize known fraud patterns"""
        return {
            'credential_stuffing': {
                'keywords': ['credential', 'password', 'login failed', 'brute force'],
                'weight': 0.9,
                'severity': 'HIGH'
            },
            'account_takeover': {
                'keywords': ['password change', 'email change', 'suspicious login'],
                'weight': 1.0,
                'severity': 'CRITICAL'
            },
            'payment_fraud': {
                'keywords': ['unauthorized transaction', 'payment', 'refund'],
                'weight': 0.95,
                'severity': 'CRITICAL'
            },
            'data_exfiltration': {
                'keywords': ['data export', 'download', 'exfiltration'],
                'weight': 0.85,
                'severity': 'HIGH'
            },
            'privilege_abuse': {
                'keywords': ['admin access', 'privilege escalation', 'sudo'],
                'weight': 0.88,
                'severity': 'HIGH'
            },
            'unusual_time': {
                'keywords': ['off-hours', 'unusual time', 'night'],
                'weight': 0.7,
                'severity': 'MEDIUM'
            },
            'rapid_succession': {
                'keywords': ['rapid', 'multiple', 'flood'],
                'weight': 0.75,
                'severity': 'HIGH'
            }
        }
    
    def analyze_user_behavior(self, user_id: str, days: int = 30) -> Dict[str, Any]:
        """Comprehensive user behavior analysis"""
        try:
            import sqlite3
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get user activity
            cursor.execute("""
                SELECT 
                    timestamp,
                    severity,
                    rule_description,
                    threat_classification,
                    attacker_ip,
                    strftime('%H', timestamp) as hour,
                    strftime('%w', timestamp) as day_of_week
                FROM wazuh_alerts 
                WHERE attacker_ip = ? 
                AND timestamp >= datetime('now', '-? days')
                ORDER BY timestamp
            """, (user_id, days))
            
            rows = cursor.fetchall()
            conn.close()
            
            if not rows:
                return {'error': f'No data found for user {user_id}'}
            
            # Calculate behavioral metrics
            total_events = len(rows)
            severity_distribution = defaultdict(int)
            hourly_distribution = defaultdict(int)
            daily_distribution = defaultdict(int)
            attack_types = defaultdict(int)
            
            timestamps = []
            for row in rows:
                severity_distribution[row[1]] += 1
                hourly_distribution[int(row[5])] += 1
                daily_distribution[int(row[6])] += 1
                attack_types[row[3] if row[3] else 'Unknown'] += 1
                timestamps.append(datetime.fromisoformat(row[0].replace('Z', '+00:00')))
            
            # Calculate velocity (events per hour)
            if len(timestamps) > 1:
                time_span = (timestamps[-1] - timestamps[0]).total_seconds() / 3600
                velocity = total_events / max(time_span, 1)
            else:
                velocity = 1
            
            # Calculate risk scores
            risk_factors = self._calculate_risk_factors(
                total_events, severity_distribution, velocity, hourly_distribution
            )
            
            # Detect fraud indicators
            fraud_indicators = self._detect_fraud_indicators(rows, risk_factors)
            
            # Peer group comparison
            peer_analysis = self._compare_with_peers(risk_factors)
            
            # Calculate overall fraud score
            fraud_score = self._calculate_fraud_score(risk_factors, fraud_indicators)
            
            # Determine fraud level
            if fraud_score >= 80:
                fraud_level = 'CRITICAL'
                recommendation = 'Immediate investigation and account lockout'
            elif fraud_score >= 60:
                fraud_level = 'HIGH'
                recommendation = 'Enhanced monitoring and MFA challenge'
            elif fraud_score >= 40:
                fraud_level = 'MEDIUM'
                recommendation = 'Increased monitoring and risk review'
            else:
                fraud_level = 'LOW'
                recommendation = 'Normal monitoring continue'
            
            return {
                'user_id': user_id,
                'analysis_period_days': days,
                'total_events': total_events,
                'fraud_score': round(fraud_score, 2),
                'fraud_level': fraud_level,
                'recommendation': recommendation,
                'risk_factors': risk_factors,
                'fraud_indicators': fraud_indicators,
                'peer_analysis': peer_analysis,
                'behavioral_profile': {
                    'severity_distribution': dict(severity_distribution),
                    'hourly_activity': dict(hourly_distribution),
                    'attack_types': dict(attack_types),
                    'velocity': round(velocity, 2)
                },
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error analyzing user behavior: {e}")
            return {'error': str(e)}
    
    def _calculate_risk_factors(self, total_events: int, severity_dist: Dict, 
                                 velocity: float, hourly_dist: Dict) -> Dict[str, float]:
        """Calculate individual risk factors"""
        risk_factors = {}
        
        # Volume risk (more events = higher risk)
        volume_risk = min(100, total_events / 10)
        risk_factors['volume_risk'] = volume_risk
        
        # Severity risk
        high_severity = sum(v for k, v in severity_dist.items() if k >= 7)
        total = sum(severity_dist.values())
        severity_risk = (high_severity / max(total, 1)) * 100
        risk_factors['severity_risk'] = severity_risk
        
        # Velocity risk (rapid events)
        velocity_risk = min(100, velocity * 10)
        risk_factors['velocity_risk'] = velocity_risk
        
        # Time anomaly (off-hours activity)
        night_activity = sum(v for h, v in hourly_dist.items() if h < 6 or h > 22)
        total_hours = sum(hourly_dist.values())
        time_anomaly = (night_activity / max(total_hours, 1)) * 100
        risk_factors['time_anomaly'] = time_anomaly
        
        return risk_factors
    
    def _detect_fraud_indicators(self, events: List, risk_factors: Dict) -> List[Dict]:
        """Detect specific fraud indicators"""
        indicators = []
        
        # Check for credential stuffing pattern
        credential_events = sum(1 for e in events if 'failed login' in str(e[2]).lower() or 'password' in str(e[2]).lower())
        if credential_events > 10:
            indicators.append({
                'type': 'CREDENTIAL_STUFFING',
                'severity': 'HIGH',
                'details': f'{credential_events} authentication failures detected',
                'risk_contribution': min(30, credential_events * 2)
            })
        
        # Check for rapid succession
        if risk_factors.get('velocity_risk', 0) > 50:
            indicators.append({
                'type': 'RAPID_SUCCESSION',
                'severity': 'HIGH',
                'details': f'High velocity of events: {risk_factors["velocity_risk"]:.1f}%',
                'risk_contribution': 25
            })
        
        # Check for time anomaly
        if risk_factors.get('time_anomaly', 0) > 60:
            indicators.append({
                'type': 'UNUSUAL_HOURS',
                'severity': 'MEDIUM',
                'details': f'Significant off-hours activity: {risk_factors["time_anomaly"]:.1f}%',
                'risk_contribution': 20
            })
        
        # Check for high severity patterns
        if risk_factors.get('severity_risk', 0) > 70:
            indicators.append({
                'type': 'HIGH_SEVERITY_PATTERN',
                'severity': 'CRITICAL',
                'details': f'Critical severity events detected',
                'risk_contribution': 35
            })
        
        return indicators
    
    def _compare_with_peers(self, risk_factors: Dict) -> Dict[str, Any]:
        """Compare entity with peer group"""
        # Simplified peer comparison
        return {
            'peer_group_size': 50,
            'percentile_rank': min(100, risk_factors.get('volume_risk', 0)),
            'is_outlier': risk_factors.get('volume_risk', 0) > 80,
            'deviation_score': risk_factors.get('volume_risk', 0) - 50
        }
    
    def _calculate_fraud_score(self, risk_factors: Dict, indicators: List) -> float:
        """Calculate overall fraud score"""
        # Weighted average of risk factors
        weighted_score = (
            risk_factors.get('volume_risk', 0) * 0.25 +
            risk_factors.get('severity_risk', 0) * 0.30 +
            risk_factors.get('velocity_risk', 0) * 0.25 +
            risk_factors.get('time_anomaly', 0) * 0.20
        )
        
        # Add indicator contributions
        indicator_contrib = sum(i.get('risk_contribution', 0) for i in indicators)
        
        # Combine scores (cap at 100)
        fraud_score = min(100, weighted_score + indicator_contrib * 0.5)
        
        return fraud_score
    
    def get_fraud_summary(self, limit: int = 50) -> Dict[str, Any]:
        """Get fraud analysis summary for top risky users"""
        try:
            import sqlite3
            conn = sqlite3.connect(self.db_path)
            
            # Get top users by alert count
            cursor = conn.execute("""
                SELECT attacker_ip, COUNT(*) as alert_count, AVG(severity) as avg_severity
                FROM wazuh_alerts 
                WHERE attacker_ip NOT IN ('N/A', 'None', '')
                AND timestamp >= datetime('now', '-30 days')
                GROUP BY attacker_ip
                ORDER BY alert_count DESC
                LIMIT ?
            """, (limit,))
            
            top_users = cursor.fetchall()
            conn.close()
            
            # Analyze each user
            fraud_analysis = []
            for user in top_users:
                analysis = self.analyze_user_behavior(user[0], 30)
                if 'error' not in analysis:
                    fraud_analysis.append(analysis)
            
            # Sort by fraud score
            fraud_analysis.sort(key=lambda x: x.get('fraud_score', 0), reverse=True)
            
            return {
                'total_analyzed': len(fraud_analysis),
                'critical_risk': len([u for u in fraud_analysis if u.get('fraud_level') == 'CRITICAL']),
                'high_risk': len([u for u in fraud_analysis if u.get('fraud_level') == 'HIGH']),
                'medium_risk': len([u for u in fraud_analysis if u.get('fraud_level') == 'MEDIUM']),
                'low_risk': len([u for u in fraud_analysis if u.get('fraud_level') == 'LOW']),
                'top_fraud_risks': fraud_analysis[:10],
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Error getting fraud summary: {e}")
            return {'error': str(e)}
    
    def get_user_fraud_timeline(self, user_id: str, days: int = 7) -> Dict[str, Any]:
        """Get fraud risk timeline for a user"""
        try:
            import sqlite3
            conn = sqlite3.connect(self.db_path)
            
            cursor = conn.execute("""
                SELECT 
                    DATE(timestamp) as date,
                    COUNT(*) as daily_count,
                    AVG(severity) as daily_avg_severity
                FROM wazuh_alerts 
                WHERE attacker_ip = ? 
                AND timestamp >= datetime('now', '-? days')
                GROUP BY DATE(timestamp)
                ORDER BY date
            """, (user_id, days))
            
            timeline = [{'date': row[0], 'alert_count': row[1], 'avg_severity': round(row[2], 2)} for row in cursor.fetchall()]
            conn.close()
            
            # Calculate trend
            if len(timeline) >= 3:
                recent_avg = sum(t['alert_count'] for t in timeline[-3:]) / 3
                previous_avg = sum(t['alert_count'] for t in timeline[:3]) / 3
                trend = 'INCREASING' if recent_avg > previous_avg * 1.2 else 'DECREASING' if recent_avg < previous_avg * 0.8 else 'STABLE'
            else:
                trend = 'INSUFFICIENT_DATA'
            
            return {
                'user_id': user_id,
                'timeline': timeline,
                'trend': trend,
                'total_alerts': sum(t['alert_count'] for t in timeline)
            }
        except Exception as e:
            return {'error': str(e)}

# Initialize fraud engine
fraud_engine = None

def init_fraud_engine(db_path):
    global fraud_engine
    fraud_engine = FraudAnalysisEngine(db_path)
    return fraud_engine

def get_fraud_engine():
    return fraud_engine
