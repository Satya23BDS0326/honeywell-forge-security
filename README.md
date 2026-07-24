# 🛡️ Honeywell Forge Cyber Security - Autonomous Behavioral Engine (AB-BMS Guard)

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.109+-009688.svg)](https://fastapi.tiangolo.com/)
[![Scikit-Learn](https://img.shields.io/badge/scikit--learn-1.4+-F7931E.svg)](https://scikit-learn.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **Honeywell Recruitment Round 2 Case Study Submission Project**  
> An autonomous, self-learning AI platform designed for Industrial Control Systems (ICS) and enterprise telemetry. Replaces reactive signature-based rules with continuous unsupervised behavioral profiling, zero-day threat detection, and SHAP explainability.

---

## 📌 Architecture Overview

```
                                  [LOG SOURCES]
        Active Directory Logs | Firewall Logs | EDR Telemetry | VPN / OAuth
                                        │
                                        ▼
                            [FASTAPI INGEST SERVICE]
                    (Schema Validation & Log Normalization)
                                        │
                                        ▼
                             [FEATURE ENGINEERING]
               (Time-window aggregation, Geolocation delta, Velocity)
                                        │
             ┌──────────────────────────┴──────────────────────────┐
             ▼                                                     ▼
   [UNSUPERVISED PIPELINE]                               [SUPERVISED PIPELINE]
(Autoencoder + Isolation Forest)                      (XGBoost Threat Classifier)
 - Zero-day anomaly scoring                            - Attack type classification
             │                                                     │
             └──────────────────────────┬──────────────────────────┘
                                        ▼
                           [EXPLAINABILITY ENGINE]
                        (SHAP / Feature Attribution)
                                        │
                                        ▼
                      [HONEYWELL SOC ANALYST DASHBOARD]
           (Real-Time Incident Stream | Geo Map | Remediation Webhooks)
```

---

## ✨ Key Features

1. **Synthetic Multi-Threat Telemetry Engine**: Simulates 5 distinct enterprise threat vectors (Impossible Travel, Brute-Force, Credential Misuse, Lateral Movement, Device Spoofing) alongside benign traffic.
2. **Hybrid ML Anomaly Ensemble**: Combines **Isolation Forest** (Point Anomalies) and **Deep Autoencoders** (Reconstruction Error) for zero-day threat detection.
3. **Explainable AI (SHAP XAI)**: Translates model predictions into normalized Risk Scores ($0\text{--}100$) and human-readable feature attribution lists.
4. **Cold Start & Concept Drift Handling**: Role-Based Peer Group baseline inheritance for new users + ADWIN sliding-window adaptation.
5. **Real-time Honeywell Forge Dashboard**: Sleek Dark UI (`#0F172A` / `#EE3124`) with live metrics, threat feed table, SHAP drawer, and one-click session quarantine.

---

## 🚀 Quick Start Guide

### Running Locally in VS Code

1. **Open VS Code Terminal** (`Ctrl + ~`)
2. **Install Dependencies**:
   ```bash
   pip install -r backend/requirements.txt
   ```
3. **Start the FastAPI Backend & Dashboard**:
   ```bash
   cd backend
   python main.py
   ```
4. **Open in Browser**:
   * Dashboard: `http://localhost:8000` (or `http://127.0.0.1:8000`)
   * Swagger Docs: `http://localhost:8000/docs`

---

## 📄 License & Confidentiality
Developed for evaluation as part of Honeywell Engineering Recruitment.
