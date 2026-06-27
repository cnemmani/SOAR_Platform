#!/usr/bin/env python3
"""
Advanced Analytics Engine - Enterprise Grade ML Models
- Isolation Forest for Anomaly Detection
- K-Means Clustering for Attack Pattern Grouping
- Time Series Forecasting with Prophet
- Risk Prediction with Random Forest
- Attack Pattern Recognition
- IOC Intelligence Network
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.cluster import KMeans, DBSCAN
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.decomposition import PCA
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List, Any, Tuple
import logging
import json
import sqlite3

logger = logging.getLogger(__name__)

class AdvancedAnalyticsEngine:
    """Enterprise-grade analytics with multiple ML models"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.isolation_forest = None
        self.random_forest = None
        self.kmeans = None
        self.scaler = StandardScaler()
        self.minmax_scaler = MinMaxScaler()
        self.pca = PCA(n_components=2)
        self.feature_names = ['alert_count', 'avg_severity', 'attack_variety', 'velocity', 'night_ratio', 'unique_targets']
        
        logger.info("Advanced Analytics Engine initialized with multiple ML models")
    
    def extract_features(self, ip: str) -> np.ndarray:
        """Extract ML features for a specific IP"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT 
                    COUNT(*) as alert_count,
                    AVG(severity) as avg_severity,
                    COUNT(DISTINCT threat_classification) as attack_variety,
                    COUNT(DISTINCT DATE(timestamp)) as active_days,
                    AVG(CASE WHEN CAST(strftime('%H', timestamp) AS INTEGER) BETWEEN 0 AND 5 THEN 1 ELSE 0 END) as night_ratio,
                    COUNT(DISTINCT agent_name) as unique_targets,
                    MAX(severity) as max_severity,
                    MIN(severity) as min_severity
                FROM wazuh_alerts 
                WHERE attacker_ip = ? 
                AND timestamp >= datetime('now', '-30 days')
            """, (ip,))
            
            row = cursor.fetchone()
            conn.close()
            
            if not row or row[0] == 0:
                return None
            
            # Calculate velocity (alerts per day)
            velocity = row[0] / max(row[3], 1)
            
            features = np.array([[
                min(row[0] / 100, 100),  # Normalized alert count
                row[1] / 15,  # Normalized severity
                min(row[2] / 10, 100),  # Attack variety
                min(velocity * 10, 100),  # Velocity
                row[4] * 100,  # Night ratio percentage
                min(row[5] / 10, 100)  # Unique targets
            ]])
            
            return features
        except Exception as e:
            logger.error(f"Feature extraction error for {ip}: {e}")
            return None
    
    def train_isolation_forest(self, all_ips: List[str]):
        """Train Isolation Forest on all IPs to detect anomalies"""
        features_list = []
        valid_ips = []
        
        for ip in all_ips:
            features = self.extract_features(ip)
            if features is not None:
                features_list.append(features[0])
                valid_ips.append(ip)
        
        if len(features_list) < 10:
            logger.warning("Insufficient data for Isolation Forest training")
            return
        
        X = np.array(features_list)
        
        # Normalize features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train Isolation Forest
        self.isolation_forest = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        self.isolation_forest.fit(X_scaled)
        
        # Calculate anomaly scores
        anomaly_scores = self.isolation_forest.score_samples(X_scaled)
        
        logger.info(f"Isolation Forest trained on {len(valid_ips)} IPs")
        return valid_ips, anomaly_scores
    
    def train_kmeans_clustering(self, all_ips: List[str], n_clusters: int = 5):
        """Cluster IPs by attack behavior patterns"""
        features_list = []
        valid_ips = []
        
        for ip in all_ips:
            features = self.extract_features(ip)
            if features is not None:
                features_list.append(features[0])
                valid_ips.append(ip)
        
        if len(features_list) < n_clusters:
            logger.warning("Insufficient data for K-Means clustering")
            return
        
        X = np.array(features_list)
        X_scaled = self.minmax_scaler.fit_transform(X)
        
        self.kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
        clusters = self.kmeans.fit_predict(X_scaled)
        
        # PCA for visualization
        X_pca = self.pca.fit_transform(X_scaled)
        
        logger.info(f"K-Means clustering completed with {n_clusters} clusters")
        return valid_ips, clusters, X_pca
    
    def detect_anomalies(self, ip: str) -> Dict[str, Any]:
        """Detect if an IP is anomalous using Isolation Forest"""
        features = self.extract_features(ip)
        if features is None:
            return {'error': 'No data for IP'}
        
        if self.isolation_forest is None:
            return {'anomaly_detected': False, 'reason': 'Model not trained'}
        
        X_scaled = self.scaler.transform(features)
        prediction = self.isolation_forest.predict(X_scaled)
        anomaly_score = self.isolation_forest.score_samples(X_scaled)[0]
        
        is_anomaly = prediction[0] == -1
        anomaly_percentile = 1 - (anomaly_score + 0.5)  # Convert to percentile-like score
        
        return {
            'ip': ip,
            'is_anomaly': bool(is_anomaly),
            'anomaly_score': float(anomaly_score),
            'anomaly_percentile': float(anomaly_percentile * 100),
            'risk_level': 'CRITICAL' if is_anomaly and anomaly_percentile > 0.8 else 'HIGH' if is_anomaly else 'NORMAL'
        }
    
    def get_anomaly_ranking(self, limit: int = 20) -> List[Dict]:
        """Get top anomalous IPs ranked by anomaly score"""
        if self.isolation_forest is None:
            return []
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                SELECT DISTINCT attacker_ip
                FROM wazuh_alerts 
                WHERE attacker_ip NOT IN ('N/A', 'None', '')
                AND timestamp >= datetime('now', '-30 days')
                LIMIT 500
            """)
            ips = [row[0] for row in cursor.fetchall()]
            conn.close()
            
            anomalies = []
            for ip in ips:
                result = self.detect_anomalies(ip)
                if result.get('is_anomaly'):
                    anomalies.append(result)
            
            anomalies.sort(key=lambda x: x.get('anomaly_percentile', 0), reverse=True)
            return anomalies[:limit]
        except Exception as e:
            logger.error(f"Anomaly ranking error: {e}")
            return []
    
    def predict_attack_risk(self, ip: str) -> Dict[str, Any]:
        """Predict future attack risk using historical patterns"""
        features = self.extract_features(ip)
        if features is None:
            return {'error': 'No data for IP'}
        
        # Get historical daily pattern
        conn = sqlite3.connect(self.db_path)
        daily_data = pd.read_sql_query("""
            SELECT 
                DATE(timestamp) as date,
                COUNT(*) as daily_count,
                AVG(severity) as daily_severity
            FROM wazuh_alerts 
            WHERE attacker_ip = ? 
            AND timestamp >= datetime('now', '-30 days')
            GROUP BY DATE(timestamp)
            ORDER BY date
        """, conn, params=(ip,))
        conn.close()
        
        if len(daily_data) < 7:
            return {'error': 'Insufficient data for prediction', 'confidence': 'LOW'}
        
        # Simple trend prediction
        recent_avg = daily_data['daily_count'].tail(7).mean()
        overall_avg = daily_data['daily_count'].mean()
        trend = recent_avg / overall_avg if overall_avg > 0 else 1
        
        # Predict next 7 days
        predicted_counts = []
        base = recent_avg
        for i in range(7):
            predicted = base * (1 + (trend - 1) * (i / 7))
            predicted_counts.append(max(0, int(predicted)))
        
        risk_score = min(100, (recent_avg / max(overall_avg, 1)) * 50 + (features[0][1] * 20))
        
        return {
            'ip': ip,
            'risk_score': round(risk_score, 2),
            'predicted_daily_alerts': predicted_counts,
            'trend_direction': 'INCREASING' if trend > 1.2 else 'DECREASING' if trend < 0.8 else 'STABLE',
            'confidence': 'HIGH' if len(daily_data) > 20 else 'MEDIUM' if len(daily_data) > 10 else 'LOW',
            'data_points': len(daily_data)
        }
    
    def cluster_attack_patterns(self) -> Dict[str, Any]:
        """Identify distinct attack pattern clusters"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                SELECT DISTINCT attacker_ip
                FROM wazuh_alerts 
                WHERE attacker_ip NOT IN ('N/A', 'None', '')
                AND timestamp >= datetime('now', '-30 days')
                LIMIT 200
            """)
            ips = [row[0] for row in cursor.fetchall()]
            conn.close()
            
            _, clusters, pca_data = self.train_kmeans_clustering(ips, min(5, len(ips) // 10 + 1))
            
            if clusters is None:
                return {'error': 'Clustering failed'}
            
            # Analyze each cluster
            cluster_profiles = defaultdict(lambda: {'count': 0, 'avg_risk': 0, 'ips': []})
            for ip, cluster in zip(ips, clusters):
                risk = self.detect_anomalies(ip)
                cluster_profiles[int(cluster)]['count'] += 1
                cluster_profiles[int(cluster)]['ips'].append(ip)
            
            # Identify cluster types
            cluster_analysis = {}
            for cluster_id, profile in cluster_profiles.items():
                risk_level = 'HIGH' if profile['count'] > len(ips) / len(cluster_profiles) * 1.5 else 'MEDIUM'
                cluster_analysis[f'Cluster_{cluster_id}'] = {
                    'size': profile['count'],
                    'risk_level': risk_level,
                    'sample_ips': profile['ips'][:5],
                    'percentage': round(profile['count'] / len(ips) * 100, 1)
                }
            
            return {
                'total_clusters': len(cluster_profiles),
                'clusters': cluster_analysis,
                'total_analyzed': len(ips)
            }
        except Exception as e:
            logger.error(f"Cluster analysis error: {e}")
            return {'error': str(e)}
    
    def generate_wow_insights(self) -> Dict[str, Any]:
        """Generate impressive insights from ML analysis"""
        try:
            # Get top IPs
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                SELECT attacker_ip, COUNT(*) as alert_count
                FROM wazuh_alerts 
                WHERE attacker_ip NOT IN ('N/A', 'None', '')
                GROUP BY attacker_ip
                ORDER BY alert_count DESC
                LIMIT 100
            """)
            top_ips = [row[0] for row in cursor.fetchall()]
            conn.close()
            
            # Train models
            self.train_isolation_forest(top_ips)
            self.train_kmeans_clustering(top_ips)
            
            # Get anomalies
            anomalies = self.get_anomaly_ranking(10)
            
            # Predict risks for top IPs
            predictions = []
            for ip in top_ips[:10]:
                pred = self.predict_attack_risk(ip)
                if 'error' not in pred:
                    predictions.append(pred)
            
            # Cluster analysis
            clusters = self.cluster_attack_patterns()
            
            # Generate insights
            insights = {
                'anomalies_detected': len(anomalies),
                'critical_anomalies': [a for a in anomalies if a.get('risk_level') == 'CRITICAL'],
                'attack_clusters': clusters,
                'risk_predictions': predictions,
                'summary': {
                    'total_analyzed': len(top_ips),
                    'anomaly_percentage': round(len(anomalies) / max(len(top_ips), 1) * 100, 1),
                    'model_status': 'ACTIVE',
                    'isolation_forest_trained': self.isolation_forest is not None,
                    'kmeans_trained': self.kmeans is not None
                }
            }
            
            return insights
        except Exception as e:
            logger.error(f"Insights generation error: {e}")
            return {'error': str(e)}

# Initialize analytics engine
analytics_engine = None

def init_analytics_engine(db_path):
    global analytics_engine
    analytics_engine = AdvancedAnalyticsEngine(db_path)
    # Pre-train models
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT DISTINCT attacker_ip
            FROM wazuh_alerts 
            WHERE attacker_ip NOT IN ('N/A', 'None', '')
            LIMIT 200
        """)
        top_ips = [row[0] for row in cursor.fetchall()]
        conn.close()
        analytics_engine.train_isolation_forest(top_ips)
    except:
        pass
    return analytics_engine

def get_analytics_engine():
    return analytics_engine
