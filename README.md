# Argus — AI-Powered Phishing Detection for Organisations
### Civic Cyber Shield / Adaptive XDR

> **Built for Hack MUJ 4.0 — Problem Statement: AI Phishing Detection for Organisations.**

---

### Problem Statement

Phishing attacks have evolved far beyond basic reputation filters and naive keyword checks. Modern threat actors leverage:
- **AI-generated messaging** with zero grammatical flaws, convincing contextual urgency, and executive impersonation.
- **Visually cloned brand login pages** hosted on newly spun-up infrastructure that bypass domain reputation feeds.
- **Compromised legitimate sender accounts** that slip past traditional SPF/DKIM/DMARC checks.

Traditional security awareness training places the burden on employees after an attack reaches their inbox. **Argus** operates as an automated, **pre-interaction detection layer** that intercepts, dissects, and explains threats across multiple orthogonal vectors before an employee ever interacts with them. Built into a broader Municipal Extended Detection and Response (Civic Cyber Shield) framework, it equips resource-constrained organizations with enterprise-grade threat intelligence and containment.

---

### Solution: Four Independent, Explainable Detection Layers

Argus replaces opaque single-metric averages with four autonomous, explainable detection engines:

1. **Content Intelligence** (`phishing.py`)
   - Natural Language Processing via TF-IDF vectorization paired with Logistic Regression.
   - Evaluates linguistic markers, urgency spikes, coercive authority impersonation, and credential-harvesting requests.

2. **Infrastructure Analysis** (`infrastructure_analysis.py`)
   - **Lookalike / Homoglyph Domain Detection**: Evaluates domains against an allowlist of high-profile brand and civic domains using homoglyph substitution mapping (`1` ↔ `l`, `0` ↔ `o`, `rn` ↔ `m`, etc.) and token edit-distance scoring.
   - **WHOIS Domain Age**: Queries registration records via `python-whois`, automatically flagging domains created within the last $N$ days (configurable, default 30 days).
   - **Redirect-Chain Tracing**: Follows HTTP/HTTPS redirect hops (up to 10) and inspects terminating pages for credential-harvesting patterns and password input fields.
   - Primary interface: `analyze_infrastructure(url: str) -> dict`.

3. **Visual & Behavioral** (`page_similarity.py` & `sender_behavior.py` / `anomaly.py`)
   - **Perceptual-Hash Page Similarity**: Employs perceptual (`pHash`) and difference (`dHash`) hashing via `imagehash` and `Pillow` to compare screenshots against reference brand login templates (e.g., Microsoft 365, PayPal, Civic Portals), flagging visual clones.
   - **Per-Sender Behavioral Anomaly Detection**: Builds personalized baseline models for each sender account using `IsolationForest`. Models sending-hour distributions, unfamiliar recipient clusters, and writing-style fingerprints (sentence length, vocabulary richness, TF-IDF cosine similarity to past messages).

4. **Decision & Feedback Layer** (`risk_engine.py`)
   - **Multi-Layer Independent Decision Architecture**: Any strong detection signal can flag a message independently — flags are never diluted by non-firing layers.
   - **Explainable Per-Layer Verdicts**: The engine reports exactly which layer(s) fired, individual confidence scores, and plain-language technical explanations.
   - **Highest Confidence Severity**: Overall severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) is derived from the highest-confidence active flag.
   - **Persistent Analyst Feedback Loop**: An embedded SQLite database (`data/analyst_feedback.db`) captures SOC analyst Confirm and Override decisions, computing live precision metrics.

---

### System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                                Streamlit Security Dashboard                                 │
│  ┌──────┐ ┌──────────┐ ┌──────────┐ ┌───────────────┐ ┌──────────────────────────────────┐  │
│  │ KPIs │ │Risk Gauge│ │Trend Line│ │ Alert Table    │ │ Multi-Vector Threat Lab & Review │  │
│  └──────┘ └──────────┘ └──────────┘ └───────────────┘ └──────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────┐ ┌─────────────────────────────────┐  │
│  │         Attack Simulation Console                 │ │   3D Interactive Threat Globe   │  │
│  └───────────────────────────────────────────────────┘ └─────────────────────────────────┘  │
└──────────────────────────────────────────────┬──────────────────────────────────────────────┘
                                               │
               ┌───────────────────────────────┼───────────────────────────────┐
               ▼                               ▼                               ▼
      ┌─────────────────┐             ┌─────────────────┐             ┌─────────────────┐
      │     Content     │             │ Infrastructure  │             │     Visual      │
      │  Intelligence   │             │    Analysis     │             │ Page Similarity │
      │  (TF-IDF + LR)  │             │(Homoglyph/WHOIS)│             │ (pHash / dHash) │
      └────────┬────────┘             └────────┬────────┘             └────────┬────────┘
               │                               │                               │
               └───────────────────────┬───────┴───────────────────────┬───────┘
                                       │                               │
                                       ▼                               ▼
                              ┌─────────────────┐             ┌─────────────────┐
                              │ Sender Behavior │             │ Attachment & QR │
                              │ Baseline (UBA)  │             │   Inspection    │
                              │ (Isol. Forest)  │             │ (Extension/QR)  │
                              └────────┬────────┘             └────────┬────────┘
                                       │                               │
                                       └───────────────┬───────────────┘
                                                       │
                                                       ▼
                                      ┌─────────────────────────────────┐
                                      │   Decision & Feedback Engine    │
                                      │  (Independent Layer Flags &     │
                                      │   Persistent SQLite Feedback)   │
                                      └────────────────┬────────────────┘
                                                       ▼
                                      ┌─────────────────────────────────┐
                                      │  Automated Incident Containment │
                                      │   (Lock Account / Isolate / SOC)│
                                      └─────────────────────────────────┘
```

---

### ML Models & Detection Engines

| Component | Engine / Algorithm | Purpose |
|---|---|---|
| **Content Classifier** | TF-IDF Vectorizer + Logistic Regression | Classifies email body text for urgency, authority coercion, and credential lures |
| **Infrastructure Engine** | Homoglyph Token Scoring + WHOIS Age + Redirect Crawler | Flags typo-squatted brand domains, newly registered domains (<30 days), and credential-harvesting redirect targets |
| **Visual Similarity** | Perceptual Hashing (`pHash` + `dHash` via `imagehash`) | Compares page screenshots against reference brand login templates to detect visual impersonation |
| **Sender Baseline (UBA)** | Per-Account Isolation Forest + Stylistic NLP | Establishes personalized sending-hour, recipient domain, and linguistic baselines per user |
| **System Telemetry Anomaly** | Multi-feature Isolation Forest | Identifies anomalous login timings, off-hours spikes, failed attempts, and data transfer volumes |
| **Attachment & QR Inspector** | Extension Screening + QR Payload Analysis | Intercepts high-risk executables/droppers and extracts QR code URLs for infrastructure analysis |
| **Decision & Feedback Layer** | Highest-Confidence Multi-Signal Evaluator + SQLite | Evaluates layer flags independently with plain-language explanations; logs analyst confirm/override verdicts |

> **Decision Rule:** Any layer can flag independently; verdicts include which layer(s) fired and why. Overall risk severity is determined by the highest-confidence active flag, not a diluted weighted average.

---

### How to Run

```bash
# 1. Clone / navigate to the repository
git clone https://github.com/AnmolGarg8/Argus.git
cd Argus

# 2. Install dependencies
pip install -r requirements.txt

# 3. Launch the dashboard
streamlit run app.py
```

The application opens at `http://localhost:8501`.

---

### Features

- **Multi-Vector Phishing Detection**:
  - Independent content NLP classification with probability scores.
  - Homoglyph & lookalike brand spoof detection with WHOIS domain age verification.
  - Perceptual image hashing for visual brand login page cloning detection.
  - Per-account sender behavioral anomaly baselines (time, recipient patterns, writing style).
  - Dangerous attachment screening (.exe, .scr, .js, .bat, etc.) and embedded QR code destination extraction.
- **Explainable Decision Engine**:
  - Transparent per-layer firing status and plain-language technical explanations.
  - Highest-confidence severity rating (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
  - Persistent SQLite analyst feedback tracking (`✅ Confirm Threat`, `⚠️ Override`) with live accuracy metrics.
- **Municipal Extended Detection & Response (XDR)**:
  - 3D interactive threat globe visualizing attack vectors and geographic origins.
  - Real-time KPI cards: active threats, node status, attacks blocked, and origin countries.
  - Real-time System Risk Gauge and Neural Threat Trend timeline.
  - Departmental Vulnerability Index across municipal services (Finance, Public Works, Police, etc.).
  - One-click attack simulation console (Phishing campaigns, Credential stuffing, Insider threats).
  - Automated containment simulation (account locks, device network isolation, SOC priority dispatch).

---

### Future Scope

- **Real SIEM / API Ingestion** — Direct connectors for Microsoft 365 Graph API, Google Workspace, Splunk, and Elastic.
- **Headless Live Screenshotting** — Integration with containerized Playwright/Selenium sandboxes for dynamic URL screenshot capture.
- **SOAR Playbooks** — Active API orchestration with endpoint agents (e.g., CrowdStrike, Microsoft Defender).
- **Threat Intelligence Feeds** — Live IOC correlation from MISP, AlienVault OTX, and AbuseIPDB.
- **Multi-Tenant Municipal Portal** — Role-based departmental views with cross-agency threat telemetry sharing.
