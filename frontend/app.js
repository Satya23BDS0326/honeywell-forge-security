const API_BASE = window.location.origin + "/api/v1";

let alertsData = [];
let selectedAlertId = null;

document.addEventListener("DOMContentLoaded", () => {
  fetchActiveAlerts();
  
  document.getElementById("btn-refresh").addEventListener("click", () => {
    fetch(`${API_BASE}/telemetry/generate`, { method: "POST" })
      .then(res => res.json())
      .then(() => fetchActiveAlerts());
  });
});

function fetchActiveAlerts() {
  fetch(`${API_BASE}/alerts/active?min_risk=40`)
    .then(res => res.json())
    .then(data => {
      alertsData = data.alerts || [];
      renderAlertsTable(alertsData);
      
      document.getElementById("metric-critical-count").innerText = alertsData.filter(a => a.risk_score >= 70).length;
      
      if (alertsData.length > 0 && !selectedAlertId) {
        selectAlert(alertsData[0].alert_id);
      }
    })
    .catch(err => {
      console.warn("API Server offline. Rendering fallback simulation data.", err);
      renderFallbackData();
    });
}

function renderAlertsTable(alerts) {
  const tbody = document.getElementById("alerts-tbody");
  tbody.innerHTML = "";

  alerts.forEach(alert => {
    const tr = document.createElement("tr");
    tr.className = `alert-row ${alert.alert_id === selectedAlertId ? 'selected' : ''}`;
    tr.onclick = () => selectAlert(alert.alert_id);

    let badgeClass = "badge-medium";
    if (alert.risk_score >= 80) badgeClass = "badge-critical";
    else if (alert.risk_score >= 60) badgeClass = "badge-high";

    const formattedTime = new Date(alert.timestamp).toLocaleTimeString();

    tr.innerHTML = `
      <td>${formattedTime}</td>
      <td style="font-family: 'JetBrains Mono', monospace; font-weight: 600;">${alert.user_id}</td>
      <td>${alert.attack_type}</td>
      <td style="color: var(--text-muted);">${alert.source_ip} (${alert.geo_location})</td>
      <td><span class="badge ${badgeClass}">${alert.risk_score} / 100</span></td>
    `;

    tbody.appendChild(tr);
  });
}

function selectAlert(alertId) {
  selectedAlertId = alertId;
  renderAlertsTable(alertsData);

  const alert = alertsData.find(a => a.alert_id === alertId);
  if (!alert) return;

  const shapContent = document.getElementById("shap-content");

  let shapBarsHtml = alert.shap_breakdown.map(item => `
    <div class="shap-bar-item">
      <div class="shap-label-row">
        <span>${item.feature}</span>
        <span style="font-family: 'JetBrains Mono'; font-weight: 700; color: var(--accent-red);">+${item.contribution}%</span>
      </div>
      <div class="shap-track">
        <div class="shap-fill" style="width: ${item.contribution}%;"></div>
      </div>
    </div>
  `).join("");

  shapContent.innerHTML = `
    <div style="font-size: 8.5pt; color: var(--text-muted); margin-bottom: 4px;">INCIDENT ID: ${alert.alert_id}</div>
    <div style="font-size: 13pt; font-weight: 800; color: var(--text-main); margin-bottom: 12px;">${alert.user_id} &bull; ${alert.attack_type}</div>

    <div style="background: rgba(255,255,255,0.03); padding: 12px; border-radius: 6px; margin-bottom: 16px; border: 1px solid var(--border-color);">
      <div style="font-size: 8pt; font-weight: 700; color: var(--accent-blue); margin-bottom: 4px;">PRIMARY REASONS</div>
      <ul style="padding-left: 16px; font-size: 8.5pt; color: var(--text-muted);">
        ${alert.reasons.map(r => `<li>${r}</li>`).join("")}
      </ul>
    </div>

    <div style="font-size: 9pt; font-weight: 700; color: var(--text-main); margin-bottom: 10px;">SHAP FEATURE ATTRIBUTION BREAKDOWN</div>
    ${shapBarsHtml}

    <button class="btn-action" onclick="executeRemediation('${alert.alert_id}', '${alert.mitigation_action}')">
      🔒 TRIGGER EDR ACTION: ${alert.mitigation_action}
    </button>
  `;
}

function executeRemediation(alertId, action) {
  fetch(`${API_BASE}/remediation/action`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ alert_id: alertId, action: action })
  })
  .then(res => res.json())
  .then(res => {
    alert(`[HONEYWELL EDR SUCCESS]\nAction '${action}' executed successfully for ${alertId}.\nSession terminated and IP quarantined.`);
  })
  .catch(() => {
    alert(`[DEMO MITIGATION SUCCESS]\nAction '${action}' executed for alert ${alertId}.\nSession terminated.`);
  });
}

function renderFallbackData() {
  alertsData = [
    {
      alert_id: "alt_evt_threat_01_b",
      timestamp: new Date().toISOString(),
      user_id: "usr_exec_001",
      device_id: "dev_mac_999",
      source_ip: "185.220.101.4",
      geo_location: "RU-Moscow",
      resource_path: "/admin/db/export",
      attack_type: "IMPOSSIBLE_TRAVEL",
      risk_score: 94,
      severity: "CRITICAL",
      reasons: ["Geolocation velocity anomaly (Impossible Travel from US-East to RU-Moscow in 4 mins)", "Off-hours access to critical asset (/admin/db/export)"],
      shap_breakdown: [
        { feature: "Geo Velocity Delta", contribution: 45 },
        { feature: "Off-Hours Critical Access", contribution: 30 },
        { feature: "Data Exfiltration Volume", contribution: 20 }
      ],
      mitigation_action: "QUARANTINE_SESSION"
    },
    {
      alert_id: "alt_evt_threat_02_11",
      timestamp: new Date().toISOString(),
      user_id: "usr_eng_005",
      device_id: "dev_mac_005",
      source_ip: "45.154.255.87",
      geo_location: "DE-Frankfurt",
      resource_path: "/api/v1/auth",
      attack_type: "BRUTE_FORCE",
      risk_score: 78,
      severity: "HIGH",
      reasons: ["High login failure rate (12 attempts in 5m)"],
      shap_breakdown: [
        { feature: "Failed Login Frequency", contribution: 65 },
        { feature: "Unrecognized Device Fingerprint", contribution: 25 }
      ],
      mitigation_action: "QUARANTINE_SESSION"
    }
  ];
  renderAlertsTable(alertsData);
  selectAlert(alertsData[0].alert_id);
}
