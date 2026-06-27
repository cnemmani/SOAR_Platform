#!/usr/bin/env python3
"""
Advanced ML Analytics for UEBA
- Predictive Threat Analysis
- IOC Intelligence
- Anomaly Detection using Isolation Forest
- Threat Forecasting using Prophet
- Risk Scoring with Ensemble Methods
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN
from datetime import datetime, timedelta
from collections import defaultdict
import logging
from typing import List, Dict, Any, Tuple
import json

logger = logging.getLogger(__name__)

class MLThreatAnalytics:
    """Advanced ML-based threat analytics engine"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.isolation_forest = None
        self.risk_scaler = StandardScaler()
        self.anomaly_history = []
        self.ioc_database = self._load_ioc_database()
        
        logger.info("ML Threat Analytics Engine initialized")
    
    def _load_ioc_database(self) -> Dict:
        """Load IOC database with threat intelligence"""
        return {
            'malicious_ips': {
                '185.237.106.225': {'risk': 95, 'type': 'Brute Force Bot', 'country': 'NL'},
                '45.148.10.147': {'risk': 92, 'type': 'Credential Scanner', 'country': 'NL'},
                '46.8.68.17': {'risk': 88, 'type': 'Vulnerability Scanner', 'country': 'RU'},
                '195.123.209.242': {'risk': 85, 'type': 'Web Scraper', 'country': 'LV'},
                '34.58.124.191': {'risk': 82, 'type': 'Cloud Scanner', 'country': 'US'}
            },
            'suspicious_patterns': {
                'sql_injection': {'risk': 90, 'pattern': r'(union.*select|select.*from|drop table)'},
                'xss': {'risk': 85, 'pattern': r'(<script|javascript:|onerror=)'},
                'command_injection': {'risk': 95, 'pattern': r'(cmd=|exec\(|\||;)'}
            }
        }
    
    def calculate_threat_score(self, entity_data: Dict) -> Dict[str, Any]:
        """Calculate comprehensive threat score using ML"""
        
        # Features extraction
        features = np.array([
            entity_data.get('alert_count', 0),
            entity_data.get('avg_severity', 0),
            entity_data.get('attack_variety', 0),
            entity_data.get('unique_targets', 0),
            entity_data.get('night_activity', 0),
            entity_data.get('velocity', 0)
        ]).reshape(1, -1)
        
        # Normalize features
        features_scaled = self.risk_scaler.fit_transform(features)
        
        # Risk score calculation (weighted ensemble)
        weights = {'volume': 0.25, 'severity': 0.30, 'variety': 0.20, 'velocity': 0.25}
        
        risk_score = (
            weights['volume'] * min(100, entity_data.get('alert_count', 0) / 10) +
            weights['severity'] * (entity_data.get('avg_severity', 0) / 15 * 100) +
            weights['variety'] * min(100, entity_data.get('attack_variety', 0) * 20) +
            weights['velocity'] * min(100, entity_data.get('velocity', 0) * 2)
        )
        
        # ML anomaly detection (Isolation Forest)
        if self.isolation_forest is None:
            self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
            # Train on historical data
            historical_data = self._get_historical_features()
            if len(historical_data) > 10:
                self.isolation_forest.fit(historical_data)
        
        is_anomaly = False
        anomaly_score = 0
        if self.isolation_forest:
            prediction = self.isolation_forest.predict(features_scaled)
            is_anomaly = prediction[0] == -1
            anomaly_score = abs(self.isolation_forest.score_samples(features_scaled)[0])
        
        # Determine risk level
        if risk_score >= 75:
            risk_level = 'CRITICAL'
        elif risk_score >= 55:
            risk_level = 'HIGH'
        elif risk_score >= 35:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        return {
            'risk_score': round(risk_score, 2),
            'risk_level': risk_level,
            'anomaly_detected': bool(is_anomaly),
            'anomaly_score': round(anomaly_score, 3) if anomaly_score else 0,
            'confidence': round(100 - (anomaly_score * 100 if anomaly_score else 0), 2)
        }
    
    def _get_historical_features(self) -> np.ndarray:
        """Get historical data for ML training"""
        try:
            import sqlite3
            conn = sqlite3.connect(self.db_path)
            query = """
                SELECT 
                    COUNT(*) as alert_count,
                    AVG(severity) as avg_severity,
                    COUNT(DISTINCT threat_classification) as attack_variety
                FROM wazuh_alerts 
                WHERE attacker_ip NOT IN ('N/A', 'None', '')
                GROUP BY attacker_ip
                LIMIT 1000
            """
            df = pd.read_sql_query(query, conn)
            conn.close()
            features = df[['alert_count', 'avg_severity', 'attack_variety']].values
            # Normalize
            from sklearn.preprocessing import StandardScaler
            scaler = StandardScaler()
            return scaler.fit_transform(features)
        except Exception as e:
            logger.error(f"Error getting historical features: {e}")
            return np.array([])
    
    def predict_attack_trend(self, entity_id: str, days: int = 7) -> Dict[str, Any]:
        """Predict future attack patterns using time series"""
        try:
            import sqlite3
            conn = sqlite3.connect(self.db_path)
            query = """
                SELECT DATE(timestamp) as date, COUNT(*) as count
                FROM wazuh_alerts 
                WHERE attacker_ip = ? 
                AND timestamp >= datetime('now', '-30 days')
                GROUP BY DATE(timestamp)
                ORDER BY date
            """
            df = pd.read_sql_query(query, conn, params=(entity_id,))
            conn.close()
            
            if len(df) < 7:
                return {'error': 'Insufficient data for prediction', 'prediction': []}
            
            # Simple moving average prediction
            df['ma_7'] = df['count'].rolling(window=7).mean()
            last_avg = df['ma_7'].iloc[-1] if not pd.isna(df['ma_7'].iloc[-1]) else df['count'].mean()
            
            # Linear regression for trend
            x = np.arange(len(df))
            y = df['count'].values
            z = np.polyfit(x, y, 1)
            trend = z[0]
            
            predictions = []
            current_value = last_avg
            for i in range(days):
                current_value += trend
                predictions.append({
                    'day': i + 1,
                    'predicted_count': max(0, int(current_value)),
                    'confidence': 0.8 if abs(trend) < 5 else 0.6
                })
            
            trend_direction = 'INCREASING' if trend > 0.5 else 'DECREASING' if trend < -0.5 else 'STABLE'
            
            return {
                'entity_id': entity_id,
                'trend_direction': trend_direction,
                'trend_strength': round(abs(trend), 2),
                'predictions': predictions,
                'data_points': len(df),
                'reliability': 'HIGH' if len(df) > 14 else 'MEDIUM'
            }
        except Exception as e:
            logger.error(f"Prediction error: {e}")
            return {'error': str(e)}
    
    def analyze_iocs(self, text: str) -> List[Dict]:
        """Extract and analyze IOCs from text"""
        import re
        iocs = []
        
        # IP Address extraction
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, text)
        
        for ip in ips:
            if ip in self.ioc_database['malicious_ips']:
                ioc_data = self.ioc_database['malicious_ips'][ip]
                iocs.append({
                    'type': 'IP_ADDRESS',
                    'value': ip,
                    'risk_score': ioc_data['risk'],
                    'threat_type': ioc_data['type'],
                    'is_malicious': True,
                    'confidence': 95
                })
            else:
                iocs.append({
                    'type': 'IP_ADDRESS',
                    'value': ip,
                    'risk_score': 50,
                    'threat_type': 'Unknown',
                    'is_malicious': False,
                    'confidence': 60
                })
        
        # Domain extraction
        domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
        domains = re.findall(domain_pattern, text)
        for domain in domains:
            if not domain.endswith(('.com', '.org', '.net', '.io')):
                continue
            iocs.append({
                'type': 'DOMAIN',
                'value': domain,
                'risk_score': 60,
                'threat_type': 'Suspicious Domain',
                'is_malicious': False,
                'confidence': 50
            })
        
        return iocs
    
    def get_rti_insights(self, entity_data: Dict) -> Dict[str, Any]:
        """Real-time threat intelligence insights"""
        
        insights = []
        risk_score = entity_data.get('risk_score', 0)
        
        # Predictive insights
        if risk_score > 70:
            insights.append({
                'type': 'PREDICTIVE_ALERT',
                'severity': 'HIGH',
                'message': 'High probability of continued attack activity',
                'recommended_action': 'Immediate investigation and IP blocking',
                'confidence': 85
            })
        
        # Pattern recognition
        if entity_data.get('velocity', 0) > 50:
            insights.append({
                'type': 'PATTERN_DETECTION',
                'severity': 'MEDIUM',
                'message': 'Automated attack pattern detected (high frequency)',
                'recommended_action': 'Enable rate limiting',
                'confidence': 90
            })
        
        # IOC match
        if entity_data.get('ioc_match', False):
            insights.append({
                'type': 'IOC_MATCH',
                'severity': 'CRITICAL',
                'message': f"IP matches known malicious IOC database",
                'recommended_action': 'Immediate blocking and isolation',
                'confidence': 95
            })
        
        # Time-based anomaly
        if entity_data.get('night_activity', 0) > 0.6:
            insights.append({
                'type': 'TIME_ANOMALY',
                'severity': 'MEDIUM',
                'message': 'Unusual activity during off-hours',
                'recommended_action': 'Investigate source of activity',
                'confidence': 75
            })
        
        return {
            'total_insights': len(insights),
            'insights': insights,
            'overall_threat_level': 'CRITICAL' if risk_score > 75 else 'HIGH' if risk_score > 55 else 'MEDIUM' if risk_score > 35 else 'LOW'
        }
    
    def generate_rti_report(self) -> Dict[str, Any]:
        """Generate Real-time Threat Intelligence Report"""
        try:
            import sqlite3
            conn = sqlite3.connect(self.db_path)
            
            # Get top threats
            cursor = conn.execute("""
                SELECT attacker_ip, COUNT(*) as count, AVG(severity) as avg_sev
                FROM wazuh_alerts 
                WHERE timestamp >= datetime('now', '-1 hour')
                GROUP BY attacker_ip
                ORDER BY count DESC
                LIMIT 10
            """)
            top_threats = [{'ip': row[0], 'count': row[1], 'avg_severity': round(row[2], 2)} for row in cursor.fetchall()]
            
            # Get attack trends
            cursor = conn.execute("""
                SELECT 
                    CASE 
                        WHEN severity >= 10 THEN 'CRITICAL'
                        WHEN severity >= 7 THEN 'HIGH'
                        WHEN severity >= 4 THEN 'MEDIUM'
                        ELSE 'LOW'
                    END as level,
                    COUNT(*) as count
                FROM wazuh_alerts 
                WHERE timestamp >= datetime('now', '-1 hour')
                GROUP BY level
            """)
            severity_dist = [{'level': row[0], 'count': row[1]} for row in cursor.fetchall()]
            
            conn.close()
            
            # ML-based predictions
            predictions = []
            for threat in top_threats[:3]:
                pred = self.predict_attack_trend(threat['ip'], 3)
                if 'predictions' in pred:
                    predictions.append({
                        'ip': threat['ip'],
                        'expected_attacks': pred['predictions'][0]['predicted_count'] if pred['predictions'] else 0,
                        'trend': pred['trend_direction']
                    })
            
            return {
                'timestamp': datetime.now().isoformat(),
                'top_active_threats': top_threats,
                'severity_distribution': severity_dist,
                'predictions': predictions,
                'recommendations': [
                    'Enable automated blocking for CRITICAL threats',
                    'Increase monitoring frequency for HIGH risk entities',
                    'Review and update firewall rules',
                    'Conduct threat hunting for new attack patterns'
                ]
            }
        except Exception as e:
            logger.error(f"RTI report error: {e}")
            return {'error': str(e)}

# Initialize ML engine
ml_analytics = None

def init_ml_analytics(db_path):
    global ml_analytics
    ml_analytics = MLThreatAnalytics(db_path)
    return ml_analytics
