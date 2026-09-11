# AI Adaptive XDR – Civic Cyber Shield

## Municipal Extended Detection & Response System

### Problem Statement

Municipal governments are increasingly targeted by sophisticated cyber threats — ransomware, phishing campaigns, credential stuffing, and insider threats — yet most lack the budget and personnel for enterprise-grade Security Operations Centers (SOC). City services like water utilities, public safety dispatch, and financial systems are critical infrastructure that demand continuous protection.

**Civic Cyber Shield** is an AI-powered Extended Detection and Response (XDR) prototype designed specifically for municipal cyber defense. It provides automated threat detection, risk correlation, and incident response simulation — giving small IT teams the situational awareness of a full SOC.

### System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  Streamlit Dashboard                     │
│  ┌──────┐ ┌──────────┐ ┌──────────┐ ┌───────────────┐  │
│  │ KPIs │ │Risk Gauge│ │Trend Line│ │ Alert Table    │  │
│  └──────┘ └──────────┘ └──────────┘ └───────────────┘  │
│  ┌───────────────────────────────────────────────────┐  │
│  │         Attack Simulation Console                  │  │
│  └───────────────────────────────────────────────────┘  │
└────────────────────────┬────────────────────────────────┘
                         │
        ┌────────────────┼────────────────┐
        ▼                ▼                ▼
┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│   Anomaly    │ │   Phishing   │ │     Risk     │
│  Detection   │ │  Detection   │ │ Correlation  │
│(Isol. Forest)│ │(TF-IDF + LR) │ │   Engine     │
└──────┬───────┘ └──────┬───────┘ └──────┬───────┘
       └────────────────┼────────────────┘
                        ▼
              ┌──────────────────┐
              │    Incident      │
              │   Response       │
              │   Simulation     │
              └──────────────────┘
                        ▲
                        │
              ┌──────────────────┐
              │   Synthetic Log  │
              │    Generator     │
              └──────────────────┘
```

### ML Models

| Model | Algorithm | Purpose |
|-------|-----------|---------|
| Anomaly Detector | Isolation Forest | Detects unusual login patterns, off-hours access, high failed attempts |
| Phishing Classifier | TF-IDF + Logistic Regression | Classifies emails as phishing or legitimate |
| Risk Engine | Weighted scoring formula | Combines anomaly, phishing, and IP risk into unified score |

**Risk Formula:**
```
risk_score = 0.5 × anomaly_score + 0.3 × phishing_probability + 0.2 × ip_risk_score
```

### How to Run

```bash
# 1. Clone / navigate to the project
cd adaptive-xdr

# 2. Install dependencies
pip install -r requirements.txt

# 3. Launch the dashboard
streamlit run app.py
```

The dashboard opens at `http://localhost:8501`. Click the simulation buttons to inject attack scenarios and watch the system respond in real time.

### Features

- **Real-time KPI Dashboard** — Active threats, average risk score, incident count
- **AI Anomaly Detection** — Isolation Forest trained on baseline municipal telemetry
- **Phishing Detection** — NLP-based email classification with probability scoring
- **Risk Correlation** — Multi-signal fusion into LOW/MEDIUM/HIGH/CRITICAL levels
- **Automated Response** — Simulated account locks, device isolation, alert generation
- **Attack Simulation** — One-click phishing, credential breach, and insider threat scenarios
- **Incident Reports** — Detailed AI-generated incident summaries

### Future Scope

- **Real SIEM Integration** — Ingest logs from Splunk, Elastic, or Microsoft Sentinel
- **SOAR Playbooks** — Automated response orchestration with real containment actions
- **Threat Intelligence Feeds** — Live IOC correlation from MISP, VirusTotal, AbuseIPDB
- **Network Traffic Analysis** — Deep packet inspection and lateral movement detection
- **User Behavior Analytics (UBA)** — Long-term behavioral profiling with LSTM models
- **Multi-tenant Support** — Dashboard per department with role-based access
- **Compliance Reporting** — Automated NIST CSF and CIS Controls mapping
- **Mobile Alerting** — Push notifications to on-call responders
