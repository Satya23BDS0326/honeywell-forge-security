from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
import os
import uvicorn

from generator import SyntheticLogGenerator
from ml_engine import BehavioralAnomalyEngine

app = FastAPI(
    title="Honeywell Forge Cyber Security - Autonomous Anomaly API",
    version="2.4.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

generator = SyntheticLogGenerator()
ml_engine = BehavioralAnomalyEngine()
evaluated_alerts = []

class RemediationRequest(BaseModel):
    alert_id: str
    action: str

@app.get("/api/v1/health")
def health_check():
    return {
        "status": "HEALTHY",
        "service": "Honeywell Forge Autonomous Cyber Defense Engine",
        "model_trained": ml_engine.is_trained,
        "active_alerts_count": len([a for a in evaluated_alerts if a['risk_score'] >= 60])
    }

@app.post("/api/v1/telemetry/generate")
def generate_and_evaluate_telemetry(count: int = 500):
    global evaluated_alerts
    logs = generator.generate_batch(count=count)
    evaluated_alerts = ml_engine.train_and_evaluate(logs)
    high_risk = [a for a in evaluated_alerts if a['risk_score'] >= 60]
    return {
        "message": f"Successfully processed {len(logs)} telemetry logs.",
        "total_evaluated": len(logs),
        "high_risk_alerts_count": len(high_risk),
        "anomaly_rate_percent": round((len(high_risk) / len(logs)) * 100, 2)
    }

@app.get("/api/v1/alerts/active")
def get_active_alerts(min_risk: int = 40):
    global evaluated_alerts
    if not evaluated_alerts:
        generate_and_evaluate_telemetry(count=500)
    alerts = [a for a in evaluated_alerts if a['risk_score'] >= min_risk]
    alerts_sorted = sorted(alerts, key=lambda x: x['risk_score'], reverse=True)
    return {
        "count": len(alerts_sorted),
        "alerts": alerts_sorted
    }

@app.get("/api/v1/alerts/{alert_id}/explain")
def explain_alert(alert_id: str):
    global evaluated_alerts
    alert = next((a for a in evaluated_alerts if a['alert_id'] == alert_id), None)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert ID not found")
    return alert

@app.post("/api/v1/remediation/action")
def trigger_remediation(req: RemediationRequest):
    return {
        "status": "SUCCESS",
        "alert_id": req.alert_id,
        "executed_action": req.action,
        "timestamp": "2026-07-24T22:25:00Z",
        "message": f"Action '{req.action}' successfully executed for alert {req.alert_id}."
    }

frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
if os.path.exists(frontend_dir):
    app.mount("/dashboard", StaticFiles(directory=frontend_dir, html=True), name="frontend")
    @app.get("/")
    def read_root():
        return FileResponse(os.path.join(frontend_dir, "index.html"))

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8080))
    print("\n==========================================================================")
    print(f" Honeywell Forge Cyber Security - Autonomous Engine Starting")
    print(f" Live Dashboard URL: http://localhost:{port}")
    print(f" API Documentation:  http://localhost:{port}/docs")
    print("==========================================================================\n")
    uvicorn.run("main:app", host="127.0.0.1", port=port, reload=True)
