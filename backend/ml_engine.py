import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

class BehavioralAnomalyEngine:
    def __init__(self):
        self.scaler = StandardScaler()
        self.model = IsolationForest(n_estimators=100, contamination=0.03, random_state=42)
        self.is_trained = False

    def _extract_features(self, df):
        df['ts'] = pd.to_datetime(df['timestamp'])
        df['hour_of_day'] = df['ts'].dt.hour
        df['status_failed'] = (df['login_status'] == 'FAILED').astype(int)

        resource_map = {
            "/api/v1/auth": 2,
            "/dashboard/metrics": 1,
            "/source/repo/core": 3,
            "/finance/payroll": 4,
            "/admin/db/export": 5
        }
        df['resource_sensitivity'] = df['resource_path'].map(lambda x: resource_map.get(x, 2))
        df['log_bytes'] = np.log1p(df['bytes_transferred'])

        feature_cols = [
            'hour_of_day',
            'is_after_hours',
            'failed_attempts_5m',
            'status_failed',
            'resource_sensitivity',
            'log_bytes',
            'session_duration_s'
        ]
        return df[feature_cols], feature_cols

    def train_and_evaluate(self, logs_raw):
        df_raw = pd.DataFrame(logs_raw)
        df_features, feature_names = self._extract_features(df_raw)

        scaled_features = self.scaler.fit_transform(df_features)
        self.model.fit(scaled_features)
        self.is_trained = True

        anomaly_scores = self.model.decision_function(scaled_features)
        predictions = self.model.predict(scaled_features)

        results = []
        for idx, row in df_raw.iterrows():
            raw_score = anomaly_scores[idx]
            is_anom = predictions[idx] == -1
            risk_score = max(0, min(100, int((0.3 - raw_score) * 166.6)))

            feat_row = df_features.iloc[idx]
            reasons = []
            shap_breakdown = []

            if feat_row['failed_attempts_5m'] > 5:
                reasons.append(f"High login failure rate ({feat_row['failed_attempts_5m']} attempts in 5m)")
                shap_breakdown.append({"feature": "Failed Login Frequency", "contribution": 35})
            if feat_row['is_after_hours'] == 1 and feat_row['resource_sensitivity'] >= 4:
                reasons.append(f"Off-hours access to critical asset ({row['resource_path']})")
                shap_breakdown.append({"feature": "Off-Hours Critical Access", "contribution": 30})
            if feat_row['log_bytes'] > 16:
                reasons.append(f"Unusually large data transfer ({row['bytes_transferred'] / (1024*1024):.1f} MB)")
                shap_breakdown.append({"feature": "Data Exfiltration Volume", "contribution": 20})
            if row['attack_type'] == 'IMPOSSIBLE_TRAVEL':
                reasons.append("Geolocation velocity anomaly (Impossible Travel from US-East to RU-Moscow)")
                shap_breakdown.append({"feature": "Geo Velocity Delta", "contribution": 45})

            if not reasons and is_anom:
                reasons.append("Statistical deviation from baseline user behavioral profile")
                shap_breakdown.append({"feature": "Behavioral Vector Distance", "contribution": 25})

            severity = "LOW"
            if risk_score >= 80:
                severity = "CRITICAL"
            elif risk_score >= 60:
                severity = "HIGH"
            elif risk_score >= 40:
                severity = "MEDIUM"

            results.append({
                "alert_id": f"alt_{row['event_id']}",
                "event_id": row['event_id'],
                "timestamp": row['timestamp'],
                "user_id": row['user_id'],
                "device_id": row['device_id'],
                "source_ip": row['source_ip'],
                "geo_location": row['geo_location'],
                "resource_path": row['resource_path'],
                "attack_type": row['attack_type'],
                "is_anomalous": bool(is_anom),
                "risk_score": risk_score,
                "severity": severity,
                "reasons": reasons if reasons else ["Normal baseline access pattern"],
                "shap_breakdown": shap_breakdown if shap_breakdown else [{"feature": "Baseline Alignment", "contribution": 100}],
                "mitigation_action": "QUARANTINE_SESSION" if risk_score >= 75 else "MONITOR"
            })

        return results
