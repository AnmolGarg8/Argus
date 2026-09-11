# Argus — AI-Powered Phishing Detection for Organisations

> **Pre-Interaction Multi-Vector Phishing Defense Platform**  
> *Built for Hack MUJ 4.0 — Problem Statement: AI Phishing Detection for Organisations.*

---

### Problem Statement

Phishing remains the primary initial access vector in modern enterprise breaches, having evolved far past naive keyword filters and static domain reputation blocklists:
- **AI-Generated Text**: Large language models produce grammatically flawless, contextually nuanced spear-phishing messages with believable corporate urgency and executive impersonation.
- **Lookalike Infrastructure**: Threat actors spin up newly registered domains utilizing homoglyph mutations (e.g., `paypa1.com`, `micros0ft.com`) and multi-hop redirect chains that terminate at credential-harvesting forms.
- **Visual Brand Impersonation**: Weaponized landing pages visually clone enterprise single sign-on (SSO) portals (Microsoft 365, Google Workspace, Okta) to harvest multi-factor tokens and passwords.
- **Compromised Internal Accounts**: Legitimate internal sender accounts compromised through session hijacking or stolen tokens slip completely past traditional SPF, DKIM, and DMARC checks.

Traditional security awareness training places the defensive burden entirely on the employee *after* an attack reaches their inbox. **Argus** operates as an automated **pre-interaction detection layer**, intercepting, dissecting, and explaining threats across multiple orthogonal vectors before an employee ever interacts with them.

---

### Solution: Four Independent, Explainable Detection Layers

Argus eliminates opaque, single-metric averages. Instead, it evaluates communications across four independent, specialized detection layers:

1. **Content Intelligence Layer** (`content_intelligence.py`)
   - **Engine**: TF-IDF Vectorizer coupled with a Logistic Regression classifier trained on high-signal intent corpora.
   - **Intent Pattern Heuristics**: Extracts explainable signatures across four primary threat categories:
     - *Urgency & Coercion* (`URGENCY`): "immediate action required", "account suspension within 24h".
     - *Authority Impersonation* (`AUTHORITY_IMPERSONATION`): "IT Security Helpdesk", "Executive Leadership", "HR Compliance".
     - *Credential Harvesting* (`CREDENTIAL_HARVESTING`): "verify password", "confirm login details", "session expired".
     - *Financial Wire Redirection* (`FINANCIAL_ACTION`): "wire payment immediately", "update direct deposit".

2. **Domain & Infrastructure Analysis Layer** (`domain_analyzer.py`)
   - **Homoglyph & Lookalike Detection**: Evaluates incoming URLs and sender domains against brand allowlists using unidirectional spoof-to-canonical character mappings (`1` -> `l`, `0` -> `o`, `vv` -> `w`) and Levenshtein edit distance.
   - **Domain Age Verification**: Queries live WHOIS registration records via `python-whois`, automatically flagging domains registered within the last 30 days (with a documented local mock fallback for sandboxed/offline environments).
   - **Redirect-Chain Tracing**: Recursively traces HTTP redirect hops and inspects terminating endpoints for credential harvesting keywords (`/login`, `/signin`, `/auth`).

3. **Visual Page Similarity Layer** (`page_similarity.py`)
   - **Perceptual Hashing (`pHash` & `dHash`)**: Computes 64-bit structural and frequency hashes of landing page screenshots using `imagehash` and `Pillow` (with a pure-Python fallback for WebAssembly/Stlite compatibility).
   - **Template Matching**: Compares perceptual hashes against canonical reference login templates (Microsoft 365, PayPal, Corporate Internal SSO) to catch visual clones that evade DOM-based signature scanners.

4. **Sender Behavioral Modeling Layer** (`sender_behavior.py`)
   - **User Behavioral Analytics (UBA)**: Maintains isolated, personalized `IsolationForest` models per sender account.
   - **Baseline Features**: Models typical transmission hours (business hours vs. anomalous off-hours spikes), external vs. internal recipient distributions, attachment frequency, and lexical writing-style fingerprints.
   - **Compromised Account Detection**: Identifies when a legitimate internal employee account begins sending messages that deviate radically from its historical baseline.

5. **Bonus Vector: Attachment & QR Payload Inspection** (`attachment_qr_inspection.py`)
   - **Extension Screening**: Blocks dangerous executable and script droppers (`.scr`, `.exe`, `.vbs`, `.js`, `.bat`, `.iso`, `.ps1`).
   - **QR Quishing Decoder**: Decodes embedded QR codes inside attached images, extracts destination URLs, and routes them through the domain analyzer.

6. **Verdict & Live Feedback Engine** (`verdict_engine.py`)
   - **Multi-Layer Independent Decision Architecture**: Any strong detection signal can flag a message independently — weaponized threats are never diluted by non-firing layers. Corroborating signals provide confidence boosts.
   - **Tiered Decisions**:
     - `BLOCK`: Composite Risk $\ge 75.0$ or $\ge 2$ firing layers (Definitive weaponized threat).
     - `FLAG_FOR_REVIEW`: $35.0 \le \text{Composite Risk} < 75.0$ (Suspicious indicators warranting analyst review).
     - `ALLOW`: Composite Risk $< 35.0$ (Benign corporate correspondence).
   - **Structured Explainability**: Every flagged message provides a clear, human-readable breakdown specifying exactly which layers fired and why.
   - **Live SOC Feedback Loop**: Captures analyst confirmations (`CONFIRMED_THREAT`) and overrides (`FALSE_POSITIVE`), calculating live False Positive Rate (FPR) and precision.

---

### System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                          Argus Streamlit Security Dashboard (app.py)                         │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌───────────────────┐  │
│  │ Messages Scanned │ Threat Rate  │ Weaponized Blocks│ Analyst Reviews│ Live FPR & Prec.  │  │
│  └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘ └───────────────────┘  │
│  ┌───────────────────────────────────────────────────────────────────────────────────────┐  │
│  │                     Interactive Multi-Layer Inspection Console                        │  │
│  └───────────────────────────────────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────┐ ┌─────────────────────────────────────────────────┐  │
│  │    Risk Distribution Gauge        │ │        Threat Vector Distribution Chart         │  │
│  └───────────────────────────────────┘ └─────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────────────────────────────────┐  │
│  │                Real-Time Threat Stream Ledger & Intelligence Briefings                │  │
│  └───────────────────────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────┬──────────────────────────────────────────────┘
                                               │
               ┌───────────────────────────────┼───────────────────────────────┐
               ▼                               ▼                               ▼
      ┌─────────────────┐             ┌─────────────────┐             ┌─────────────────┐
      │     Content     │             │     Domain      │             │     Visual      │
      │  Intelligence   │             │   Analyzer      │             │ Page Similarity │
      │(TF-IDF + LogReg)│             │(Homoglyph/WHOIS)│             │ (pHash / dHash) │
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
                                      │    Verdict & Feedback Engine    │
                                      │ (Multi-Layer Correlation, Tiered│
                                      │  Decisions, & Plain-English Expl│
                                      └────────────────┬────────────────┘
                                                       ▼
                                      ┌─────────────────────────────────┐
                                      │     Live SOC Feedback Loop      │
                                      │  (Confirm / Override Buttons &  │
                                      │   Empirical FPR Recalculation)  │
                                      └─────────────────────────────────┘
```

---

### ML Models & Detection Engines

| Component | Engine / Algorithm | Primary Function |
|---|---|---|
| **Content Classifier** | TF-IDF Vectorizer + Logistic Regression | Classifies email text for urgency, authority coercion, and credential lures |
| **Domain Analyzer** | Unidirectional Homoglyph Mapping + WHOIS Age + Crawler | Detects typo-squatted domains, newly registered infrastructure (<30 days), and redirect loops |
| **Visual Similarity** | Perceptual Hashing (`pHash` + `dHash` via Pillow/imagehash) | Compares page screenshots against reference brand login templates |
| **Sender Baseline (UBA)** | Per-Account Isolation Forest + Stylistic Metrics | Detects off-hours spikes, unfamiliar recipient clusters, and stylistic divergence |
| **Attachment & QR Inspector**| Extension Screening + QR Payload Analysis | Intercepts high-risk executables/droppers and decodes embedded QR links |
| **Verdict Engine** | Correlated Tiered Decision Evaluator + Live Feedback Loop | Evaluates independent signals, synthesizes plain-English explanations, and computes live FPR |

---

### Technical Transparency: Live vs. Offline/Demo Fallbacks

Argus is engineered to operate seamlessly both in full server environments and in zero-backend, client-side WebAssembly runtimes (e.g., Stlite on Vercel):
- **Machine Learning**: TF-IDF vectorization, Logistic Regression, and Isolation Forest models run locally in memory via `scikit-learn`.
- **Perceptual Hashing**: Employs `imagehash` when available, falling back to a pure-Python 64-bit difference hash implementation using `Pillow`.
- **WHOIS Domain Registration**: Queries live WHOIS servers using `python-whois` in standard Python environments. When running inside WebAssembly or behind restrictive network firewalls, queries fall back gracefully to a structured local domain age dataset.
- **Redirect Tracing**: Follows real HTTP redirect chains using `requests`. In browser-sandboxed environments where cross-origin network calls are blocked by CORS, terminating endpoint heuristics evaluate URL paths directly.
- **Hidden Ground Truth Separation**: Synthetic enterprise messages generated by `simulator.py` store ground truth strictly inside a separated `_ground_truth` dictionary column. Detection modules never access ground truth during scoring; ground truth is read exclusively for post-verdict empirical metric verification.

---

### Getting Started

#### Prerequisites
- Python 3.9+ installed
- Recommended: virtual environment (`venv`)

#### Installation & Local Execution

```bash
# 1. Clone the repository
git clone https://github.com/AnmolGarg8/Argus.git
cd Argus

# 2. Create and activate virtual environment (optional but recommended)
python -m venv venv
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Launch the Argus Defense Console
streamlit run app.py
```

The application will be accessible at `http://localhost:8501`.

#### Web / Cloud Deployment
Argus includes an `index.html` and `cyber-theme.css` configured for serverless execution via `@stlite/mountable`. It can be deployed directly to static hosting platforms such as Vercel or GitHub Pages with zero Python backend server requirements.

---

### Project Structure

```
Argus/
├── app.py                      # Main Streamlit defense dashboard & test console
├── content_intelligence.py     # NLP intent classifier (TF-IDF + Logistic Regression)
├── domain_analyzer.py          # Homoglyph detection, WHOIS age check, redirect tracer
├── page_similarity.py          # Perceptual hash screenshot comparison (pHash/dHash)
├── sender_behavior.py          # Per-account Isolation Forest behavioral baseline (UBA)
├── attachment_qr_inspection.py # Dangerous extension screening & QR code decoder
├── verdict_engine.py           # Multi-layer correlation, explanations, & feedback loop
├── simulator.py                # Synthetic enterprise communications stream generator
├── cyber-theme.css             # Cyberpunk telemetry styling
├── index.html                  # Stlite WebAssembly entrypoint for serverless deployment
├── requirements.txt            # Python dependencies
├── data/
│   └── analyst_feedback.json  # Persistent SOC analyst feedback storage
└── templates/
    └── reference_logins/       # Brand login templates (Microsoft 365, PayPal, Internal SSO)
        ├── microsoft365.png
        ├── paypal.png
        └── internal_sso_portal.png
```

---

### Future Scope

- **Enterprise SIEM / Ingestion Connectors**: Native webhook and API integrations for Microsoft 365 Graph API, Google Workspace, Splunk, and Microsoft Sentinel.
- **Headless Browser Sandbox**: Containerized Playwright/Puppeteer workers for automated, isolated screenshot capture of suspicious inbound links.
- **Automated SOAR Playbooks**: Integration with identity providers (Okta, Entra ID) to automatically invalidate user sessions and quarantine emails upon high-confidence `BLOCK` verdicts.
- **Real-Time Threat Feeds**: Dynamic synchronization with external threat feeds (MISP, AbuseIPDB, OpenPhish, PhishTank).

