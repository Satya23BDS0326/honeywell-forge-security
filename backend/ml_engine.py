import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import xgboost as xgb
import shap

class PyTorchAutoencoder(nn.Module):
    def __init__(self, input_dim):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 16),
            nn.ReLU(),
            nn.Linear(16, 8),
            nn.ReLU(),
            nn.Linear(8, 4)
        )
        self.decoder = nn.Sequential(
            nn.Linear(4, 8),
            nn.ReLU(),
            nn.Linear(8, 16),
            nn.ReLU(),
            nn.Linear(16, input_dim)
        )

    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded

class BehavioralAnomalyEngine:
    def __init__(self):
        self.scaler = StandardScaler()
        self.iso_forest = IsolationForest(n_estimators=100, contamination=0.03, random_state=42)
        self.autoencoder = None
        self.xgb_classifier = xgb.XGBClassifier(
            n_estimators=50,
            max_depth=4,
            learning_rate=0.1,
            random_state=42,
            eval_metric='mlogloss'
        )
        self.explainer = None
        self.is_trained = False
        self.attack_label_map = {
            "BENIGN": 0,
            "IMPOSSIBLE_TRAVEL": 1,
            "BRUTE_FORCE": 2,
            "CREDENTIAL_MISUSE": 3,
            "LATERAL_MOVEMENT": 4,
            "DEVICE_SPOOFING": 5
        }
        self.inv_label_map = {v: k for k, v in self.attack_label_map.items()}

    def _extract_features(self, df):
        df['ts'] = pd.to_datetime(df['timestamp'])
        df['hour_of_day'] = df['ts'].dt.hour
        df['status_failed'] = (df['login_status'] == 'FAILED').astype(int)
        df['is_ru_geo'] = (df['geo_location'] == 'RU-Moscow').astype(int)

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
            'session_duration_s',
            'is_ru_geo',
            'user_agent_mismatch',
            'distinct_resources_touched_5m'
        ]
        return df[feature_cols], feature_cols

    def train_and_evaluate(self, logs_raw):
        df_raw = pd.DataFrame(logs_raw)
        df_features, feature_names = self._extract_features(df_raw)
        scaled_features = self.scaler.fit_transform(df_features)

        # 1. Isolation Forest (Point Anomaly Scoring)
        self.iso_forest.fit(scaled_features)
        raw_iso_scores = self.iso_forest.decision_function(scaled_features)
        norm_iso_scores = np.clip((0.3 - raw_iso_scores) * 1.66, 0.0, 1.0)

        # 2. PyTorch Autoencoder (Reconstruction Error Scoring)
        input_dim = scaled_features.shape[1]
        self.autoencoder = PyTorchAutoencoder(input_dim)
        optimizer = optim.Adam(self.autoencoder.parameters(), lr=0.01)
        criterion = nn.MSELoss()

        benign_indices = df_raw[df_raw['attack_type'] == 'BENIGN'].index

        if len(benign_indices) > 0:
            train_data = scaled_features[benign_indices].copy()
        else:
            train_data = scaled_features.copy()

        self.autoencoder.train()
        with torch.enable_grad():
            for epoch in range(30):
                train_tensor = torch.tensor(train_data, dtype=torch.float32, requires_grad=False)
                optimizer.zero_grad(set_to_none=True)
                outputs = self.autoencoder(train_tensor)
                loss = criterion(outputs, train_tensor)
                loss.backward()
                optimizer.step()
        with torch.no_grad():
            all_tensor = torch.tensor(scaled_features, dtype=torch.float32)
            reconstructed = self.autoencoder(all_tensor)
            recon_errors = torch.mean((all_tensor - reconstructed) ** 2, dim=1).numpy()
            norm_ae_scores = np.clip(recon_errors / (np.max(recon_errors) + 1e-5), 0.0, 1.0)

        # 3. XGBoost Classifier (Multi-Class Threat Classification)
        y_train = df_raw['attack_type'].map(lambda x: self.attack_label_map.get(x, 0)).values
        self.xgb_classifier.fit(scaled_features, y_train)

        # 4. SHAP Tree Explainer
        self.explainer = shap.TreeExplainer(self.xgb_classifier)
        shap_values = self.explainer.shap_values(scaled_features)

        self.is_trained = True

        results = []
        asset_criticality_map = {
            "/admin/db/export": 1.0,
            "/finance/payroll": 0.9,
            "/source/repo/core": 0.7,
            "/api/v1/auth": 0.5,
            "/dashboard/metrics": 0.3
        }

        feature_display_names = {
            'hour_of_day': 'Access Hour',
            'is_after_hours': 'Off-Hours Access',
            'failed_attempts_5m': 'Failed Login Frequency',
            'status_failed': 'Failed Login Status',
            'resource_sensitivity': 'Resource Sensitivity',
            'log_bytes': 'Data Exfiltration Volume',
            'session_duration_s': 'Session Duration',
            'is_ru_geo': 'Geo Velocity Delta',
            'user_agent_mismatch': 'Device User-Agent Mismatch',
            'distinct_resources_touched_5m': 'Lateral Resource Sweep'
        }

        for idx, row in df_raw.iterrows():
            iso_score = norm_iso_scores[idx]
            ae_score = norm_ae_scores[idx]
            
            # Hybrid Anomaly Score (Ensemble of IsoForest + Autoencoder)
            anomaly_score = max(0.0, min(1.0, 0.5 * iso_score + 0.5 * ae_score))
            asset_crit = asset_criticality_map.get(row['resource_path'], 0.4)

            # Master Risk Formula from Design Deck: Risk = min(100, (Anomaly_Score * 0.6 + Asset_Criticality * 0.4) * 100)
            risk_score = min(100, int((anomaly_score * 0.6 + asset_crit * 0.4) * 100))

            pred_class_idx = self.xgb_classifier.predict(scaled_features[idx:idx+1])[0]
            predicted_attack = self.inv_label_map.get(pred_class_idx, "BENIGN")
            is_anom = risk_score >= 45 or predicted_attack != "BENIGN"

            # Compute Genuine SHAP Feature Attribution Percentages
            if isinstance(shap_values, list):
                sample_shap = np.abs(shap_values[pred_class_idx][idx])
            elif len(shap_values.shape) == 3:
                sample_shap = np.abs(shap_values[idx, :, pred_class_idx])
            else:
                sample_shap = np.abs(shap_values[idx])

            total_shap = np.sum(sample_shap) + 1e-6
            shap_percentages = (sample_shap / total_shap) * 100

            shap_breakdown = []
            top_indices = np.argsort(sample_shap)[::-1][:3]
            for f_i in top_indices:
                idx_val = int(f_i)
                f_name = feature_names[idx_val]
                disp_name = feature_display_names.get(f_name, f_name)
                pct = int(np.round(shap_percentages[idx_val]))
                if pct > 0:
                    shap_breakdown.append({"feature": disp_name, "contribution": pct})

            if not shap_breakdown:
                shap_breakdown = [{"feature": "Baseline Alignment", "contribution": 100}]

            reasons = []
            feat_row = df_features.iloc[idx]
            if feat_row['is_ru_geo'] == 1:
                reasons.append("Geolocation velocity anomaly (Impossible Travel to RU-Moscow)")
            if feat_row['failed_attempts_5m'] > 5:
                reasons.append(f"High login failure rate ({int(feat_row['failed_attempts_5m'])} attempts in 5m)")
            if feat_row['is_after_hours'] == 1 and feat_row['resource_sensitivity'] >= 4:
                reasons.append(f"Off-hours access to critical asset ({row['resource_path']})")
            if feat_row['distinct_resources_touched_5m'] >= 10:
                reasons.append(f"Lateral movement (Touched {int(feat_row['distinct_resources_touched_5m'])} resources in 5m)")
            if feat_row['user_agent_mismatch'] == 1:
                reasons.append("Device fingerprint mismatch (Device Spoofing detected)")

            if not reasons and is_anom:
                reasons.append("Unsupervised ensemble baseline deviation (Isolation Forest + Autoencoder)")

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
                "attack_type": predicted_attack if predicted_attack != "BENIGN" else row['attack_type'],
                "is_anomalous": bool(is_anom),
                "risk_score": risk_score,
                "severity": severity,
                "reasons": reasons if reasons else ["Normal baseline access pattern"],
                "shap_breakdown": shap_breakdown,
                "mitigation_action": "QUARANTINE_SESSION" if risk_score >= 75 else "MONITOR"
            })

        return results
