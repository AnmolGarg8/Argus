"""
Argus — AI-Powered Phishing Detection & Civic Cyber Shield
Main Streamlit Dashboard
"""

import os
import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
import datetime

from simulator import (
    generate_normal_activity,
    simulate_phishing_attack,
    simulate_credential_breach,
    simulate_insider_threat,
)
from anomaly import AnomalyDetector
from phishing import PhishingDetector
from risk_engine import (
    compute_risk_scores,
    evaluate_multilayer_threat,
    log_analyst_feedback,
    get_live_accuracy_metrics,
    get_feedback_records,
)
from incident_response import process_incidents
from globe_map import render_3d_globe
from infrastructure_analysis import analyze_infrastructure, detect_lookalike_domain, check_domain_age, trace_redirect_chain
from page_similarity import analyze_page_similarity
from sender_behavior import analyze_sender_behavior
from attachment_qr_inspection import analyze_attachment
from PIL import Image

# ── Page Config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Argus — AI-Powered Phishing Detection & Civic Cyber Shield",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── Cyber Aesthetic Injection ───────────────────────────────────────────────
try:
    with open("cyber-theme.css", "r") as f:
        theme_css = f.read()
        st.markdown(f"<style>{theme_css}</style>", unsafe_allow_html=True)
except Exception:
    pass

# ── Hide Streamlit default header/footer & Menu ──────────────────────────────
st.markdown("""
<style>
    header, [data-testid="stHeader"], [data-testid="stToolbar"], footer, #MainMenu {
        display: none !important;
        visibility: hidden !important;
    }
    .stApp { top: -70px; }
</style>
""", unsafe_allow_html=True)

# ── Sticky Navbar (no JS needed here, purely visual) ─────────────────────────
st.markdown("""
<div class="cyber-navbar">
    <div class="nav-left">
        <div style="font-size:1.5rem; color:#00D4FF; margin-right:1rem;">☰</div>
        <div class="nav-logo">ARGUS // XDR</div>
    </div>
    <div class="nav-right">
        <div class="status-indicator">
            <div class="pulse-dot"></div>
            KERNEL_ONLINE
        </div>
        <div style="color:#94A3B8; font-size:1.1rem;">📡</div>
        <div style="width:32px; height:32px; background:#00D4FF; border-radius:3px; display:flex; align-items:center; justify-content:center; color:#000; font-weight:900; font-size:0.8rem;">AG</div>
    </div>
</div>
<div style="margin-top: 45px;"></div>
""", unsafe_allow_html=True)

# ── Hardware Guard (Autonomous Kernel Integration) ───────────────────────────
import streamlit.components.v1 as components

components.html("""
<!DOCTYPE html>
<html>
<head>
<style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Courier New', monospace; background: transparent; overflow: hidden; }

    .shield-container {
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 5px 0;
    }

    .shield-active-box {
        background: rgba(0, 212, 255, 0.1);
        border: 2px solid #00d4ff;
        color: #00d4ff;
        padding: 8px 15px;
        font-size: 13px;
        font-weight: 900;
        letter-spacing: 1px;
        text-transform: uppercase;
        animation: activePulse 2s infinite;
    }
    @keyframes activePulse {
        0%, 100% { box-shadow: 0 0 10px rgba(0,212,255,0.2); }
        50% { box-shadow: 0 0 20px rgba(0,212,255,0.5); }
    }

    #shield-status {
        color: #00d4ff;
        font-size: 11px;
        letter-spacing: 1px;
        text-transform: uppercase;
    }
    /* Removed redundant breach overlay styles to prevent overlapping */
</style>
</head>
<body>

<div class="shield-container">
    <div class="shield-active-box">🛡️ SHIELD_ACTIVE // MONITORING</div>
    <span id="shield-status">KERN_STATE: SECURE // SENSORS: ONLINE</span>
</div>

<script>
    let lastHash = "";
    let isPrimed = false;

    function getHash() {
        return navigator.mediaDevices.enumerateDevices().then(devices => {
            return devices.length + devices.map(d => d.kind).join(':');
        });
    }

    async function autoShield() {
        try {
            const h = await getHash();
            if (!isPrimed) { lastHash = h; isPrimed = true; return; }
            if (h !== lastHash) {
                triggerAlert("HARDWARE_INTREPT_PULSE");
                lastHash = h;
            }
        } catch(e) {}
    }

    function triggerAlert(name) {
        // Voice Alert
        try {
            const m = new SpeechSynthesisUtterance("CRITICAL ALERT. UNAUTHORIZED HARDWARE DETECTED.");
            window.speechSynthesis.speak(m);
        } catch(e) {}
        
        // Signal Parent (index.html) to show global alert - prevents overlapping
        try { window.parent.postMessage({type:'HARDWARE_BREACH', device: name}, '*'); } catch(e) {}
    }

    // High frequency autonomous scan (500ms) - NO PROMPTS
    setInterval(autoShield, 500);

    if (navigator.usb) {
        navigator.usb.addEventListener('connect', (e) => triggerAlert(e.device.productName || "USB_UNIT"));
    }
</script>
</body>
</html>
""", height=53)
# ── Initialize Models (cached) ──────────────────────────────────────────────
@st.cache_resource
def load_models():
    anomaly_detector = AnomalyDetector()
    phishing_detector = PhishingDetector()
    phishing_detector.train()
    baseline = generate_normal_activity(200)
    anomaly_detector.fit(baseline)
    return anomaly_detector, phishing_detector

anomaly_detector, phishing_detector = load_models()

def evaluate_events_pipeline(df_events: pd.DataFrame) -> pd.DataFrame:
    """
    Main detection pipeline running all independent detection layers:
      - Content Intelligence (TF-IDF + LR)
      - Infrastructure Analysis (Lookalikes, WHOIS, TLDs, and keywords)
      - Sender Behavior Modeling (Per-account Isolation Forest baselines)
      - Attachment Screening (Dangerous extensions)
      - System Telemetry Anomaly (Isolation Forest on login times, transfers, failed logins)
    Note: Page Similarity (visual_result) requires screenshot inputs and is available
    interactively in the Multi-Vector Threat Inspection Lab tab.

    Resolves threat severity using evaluate_multilayer_threat() ("highest confidence flag wins").
    """
    df_scored = df_events.copy()
    # Step 1: Baseline Anomaly & Phishing NLP
    df_scored = anomaly_detector.predict(df_scored)
    df_scored = phishing_detector.predict(df_scored)

    risk_scores = []
    risk_levels = []
    layers_fired_list = []

    for _, row in df_scored.iterrows():
        # 1. Content Result
        content_res = {"phishing_probability": float(row.get("phishing_probability", 0.0))}

        # 2. Infrastructure Result
        url = row.get("url", "")
        infra_res = analyze_infrastructure(url, fast_scan=True) if url else None

        # 3. Sender Behavior Result
        s_feat = {
            "send_hour": row.get("send_hour", row.get("login_hour", 12)),
            "recipients": row.get("recipients", ""),
            "has_attachment": row.get("has_attachment", False),
            "email_text": row.get("email_text", ""),
        }
        sender_id = row.get("sender_id", row.get("user_id", "staff_user"))
        sender_res = analyze_sender_behavior(sender_id, s_feat)

        # 4. Attachment Result
        att_name = row.get("attachment_name", "")
        att_res = analyze_attachment(att_name) if att_name else None

        # 5. System Telemetry Anomaly Result
        anomaly_res = {
            "anomaly_flag": bool(row.get("anomaly_flag", 0)),
            "anomaly_score": float(row.get("anomaly_score", 0.0)),
        }

        # Multi-layer independent evaluation
        decision = evaluate_multilayer_threat(
            content_result=content_res,
            infra_result=infra_res,
            visual_result=None,  # Available manually in the Visual Lab tab
            sender_result=sender_res,
            attachment_result=att_res,
            anomaly_result=anomaly_res,
        )

        risk_scores.append(decision["max_confidence"])
        risk_levels.append(decision["risk_level"])
        layers_fired_list.append(", ".join(decision["firing_layers"]) if decision["firing_layers"] else "None")

    df_scored["risk_score"] = risk_scores
    df_scored["risk_level"] = risk_levels
    df_scored["layers_fired"] = layers_fired_list
    return df_scored

# ── Session State ────────────────────────────────────────────────────────────
if "event_log" not in st.session_state:
    baseline = generate_normal_activity(80)
    baseline = evaluate_events_pipeline(baseline)
    st.session_state.event_log = baseline
    st.session_state.incidents = process_incidents(baseline)
    st.session_state.attack_history = []

# ── 3D Interactive Threat Globe (Hero Section) ────────────────────────────────
render_3d_globe(pd.DataFrame(st.session_state.incidents), height=550)

df = st.session_state.event_log

# ── KPI Row ──────────────────────────────────────────────────────────────────
active_threats = int((df["risk_level"].isin(["HIGH", "CRITICAL"])).sum())
avg_risk = float(df["risk_score"].mean())
incidents_today = len(st.session_state.incidents)
max_risk = float(df["risk_score"].max())

risk_color = "kpi-critical" if avg_risk > 60 else ("kpi-warn" if avg_risk > 35 else "kpi-ok")

col1, col2, col3, col4 = st.columns(4)
with col1:
    st.markdown(f"""<div class="cyber-card fade-in" style="animation-delay:0.1s">
        <div class="kpi-wrapper">
            <div class="kpi-title">YOUR NODE IP</div>
            <div class="kpi-val monospace">103.95.154.13</div>
        </div>
    </div>""", unsafe_allow_html=True)
with col2:
    st.markdown(f"""<div class="cyber-card fade-in" style="animation-delay:0.2s">
        <div class="kpi-wrapper">
            <div class="kpi-title">ACTIVE THREATS</div>
            <div class="kpi-val monospace">{active_threats:02d}</div>
        </div>
    </div>""", unsafe_allow_html=True)
with col3:
    st.markdown(f"""<div class="cyber-card fade-in" style="animation-delay:0.3s">
        <div class="kpi-wrapper">
            <div class="kpi-title">ATTACKS BLOCKED</div>
            <div class="kpi-val monospace">08</div>
        </div>
    </div>""", unsafe_allow_html=True)
with col4:
    st.markdown(f"""<div class="cyber-card fade-in" style="animation-delay:0.4s">
        <div class="kpi-wrapper">
            <div class="kpi-title">ORIGIN COUNTRIES</div>
            <div class="kpi-val monospace">10</div>
        </div>
    </div>""", unsafe_allow_html=True)

st.markdown("")

# ── Charts Row ───────────────────────────────────────────────────────────────
chart_left, chart_right = st.columns([1, 1])

with chart_left:
    st.markdown("""
    <div class="chart-container fade-in" style="animation-delay:0.5s">
        <div class="chart-header">
            <div class="chart-title"><span>📡</span> System Risk Gauge</div>
            <div class="live-badge"><div class="pulse-dot" style="width:6px; height:6px;"></div> LIVE</div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    fig_gauge = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=avg_risk,
        delta={"reference": 35, "increasing": {"color": "#ff3a3a"}, "decreasing": {"color": "#00d4ff"}},
        title={"text": "SYSTEM RISK_LVL", "font": {"color": "#94a3b8", "size": 11, "family": "JetBrains Mono"}},
        number={"font": {"color": "#00d4ff", "size": 48, "family": "JetBrains Mono"}},
        gauge={
            "axis": {"range": [0, 100], "tickcolor": "#1e293b", "tickfont": {"color": "#475569"}},
            "bar": {"color": "#00d4ff"},
            "bgcolor": "#000000",
            "bordercolor": "rgba(0, 212, 255, 0.2)",
            "steps": [
                {"range": [0, 40], "color": "rgba(0, 212, 255, 0.05)"},
                {"range": [40, 75], "color": "rgba(255, 200, 0, 0.05)"},
                {"range": [75, 100], "color": "rgba(255, 58, 58, 0.05)"},
            ],
            "threshold": {
                "line": {"color": "#ff3a3a", "width": 2},
                "thickness": 0.8,
                "value": 85,
            },
        },
    ))
    fig_gauge.update_layout(
        height=260,
        margin=dict(t=30, b=10, l=30, r=30),
        paper_bgcolor="#000000",
        plot_bgcolor="#000000",
        font={"color": "#e2e8f0"},
    )
    st.plotly_chart(fig_gauge, use_container_width=True)

with chart_right:
    st.markdown("""
    <div class="chart-container fade-in" style="animation-delay:0.6s">
        <div class="chart-header">
            <div class="chart-title"><span>📉</span> Neural Threat Trend</div>
            <div class="live-badge"><div class="pulse-dot" style="width:6px; height:6px; background:#00d4ff; box-shadow:0 0 10px #00d4ff;"></div> ACTIVE</div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    # Business logic preserved
    trend_df = df.copy()
    trend_df["timestamp"] = pd.to_datetime(trend_df["timestamp"])
    trend_df = trend_df.sort_values("timestamp")
    trend_df["cumulative_risk"] = trend_df["risk_score"].expanding().mean()

    fig_trend = go.Figure()
    fig_trend.add_trace(go.Scatter(
        x=trend_df["timestamp"].tolist(),
        y=trend_df["risk_score"].tolist(),
        mode="markers",
        marker=dict(
            size=6,
            color=trend_df["risk_score"].tolist(),
            colorscale=[[0, "#10b981"], [0.4, "#f59e0b"], [0.7, "#fb923c"], [1, "#ef4444"]],
            opacity=0.6,
        ),
        name="Telemetry",
    ))
    fig_trend.add_trace(go.Scatter(
        x=trend_df["timestamp"].tolist(),
        y=trend_df["cumulative_risk"].tolist(),
        mode="lines",
        line=dict(color="#00d4ff", width=3, shape='spline'),
        name="AI Baseline",
    ))
    fig_trend.update_layout(
        height=260,
        margin=dict(t=10, b=30, l=40, r=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        xaxis=dict(gridcolor="rgba(255,255,255,0.05)", tickfont={"color": "#64748b"}),
        yaxis=dict(gridcolor="rgba(255,255,255,0.05)", tickfont={"color": "#64748b"}),
        legend=dict(font={"color": "#94a3b8"}, bgcolor="rgba(0,0,0,0)", orientation="h", y=1.1),
        font={"color": "#e2e8f0"},
    )
    st.plotly_chart(fig_trend, use_container_width=True)

# ── Department Risk Breakdown ────────────────────────────────────────────────
st.markdown("""
<div class="chart-container fade-in" style="animation-delay:0.7s">
    <div class="chart-header">
        <div class="chart-title"><span>🏢</span> Departmental Vulnerability Index</div>
        <div class="live-badge" style="color:var(--accent-violet); border-color:rgba(108,99,255,0.2); background:rgba(108,99,255,0.05);">
            <div class="pulse-dot" style="width:6px; height:6px; background:var(--accent-violet); box-shadow:0 0 10px var(--accent-violet);"></div> STATIC
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

dept_risk = df.groupby("department")["risk_score"].mean().sort_values(ascending=True)
fig_dept = go.Figure(go.Bar(
    x=dept_risk.values.tolist(),
    y=dept_risk.index.tolist(),
    orientation="h",
    marker=dict(
        color=dept_risk.values.tolist(),
        colorscale=[[0, "rgba(16, 185, 129, 0.4)"], [0.5, "rgba(245, 158, 11, 0.4)"], [1, "rgba(239, 68, 68, 0.4)"]],
        line=dict(color="var(--accent-cyan)", width=1)
    ),
))
fig_dept.update_layout(
    height=300,
    margin=dict(t=10, b=30, l=100, r=20),
    paper_bgcolor="#000000",
    plot_bgcolor="#000000",
    xaxis=dict(gridcolor="rgba(255,255,255,0.03)", tickfont={"color": "#475569"}),
    yaxis=dict(tickfont={"color": "#94a3b8", "family": "JetBrains Mono"}),
    font={"color": "#e2e8f0"},
)
st.plotly_chart(fig_dept, use_container_width=True)

# ── Attack Simulation ────────────────────────────────────────────────────────
st.markdown("""
<div class="section-header fade-in" style="animation-delay:0.8s; border-bottom:none; margin-bottom:0.5rem;">
    📡 Attack Test Console
</div>
<div style="font-size:0.7rem; color:var(--text-secondary); margin-bottom:1.5rem; letter-spacing:1px; text-transform:uppercase;">
    Authorized Personnel Only // Threat Injection Subsystem
</div>
""", unsafe_allow_html=True)

sim_col1, sim_col2, sim_col3 = st.columns(3)

def run_simulation(attack_fn, attack_name):
    """Run an attack simulation through all independent detection layers and update state."""
    new_events = attack_fn()
    new_events = evaluate_events_pipeline(new_events)
    st.session_state.event_log = pd.concat([st.session_state.event_log, new_events], ignore_index=True)
    new_incidents = process_incidents(new_events)
    st.session_state.incidents.extend(new_incidents)
    st.session_state.attack_history.append({
        "type": attack_name,
        "time": datetime.datetime.now().strftime("%H:%M:%S"),
        "events": len(new_events),
        "incidents": len(new_incidents),
    })

with sim_col1:
    if st.button("⚡ Test Phishing Attack", use_container_width=True):
        run_simulation(simulate_phishing_attack, "Phishing")
        st.rerun()

with sim_col2:
    if st.button("🔓 Test Credential Breach", use_container_width=True):
        run_simulation(simulate_credential_breach, "Credential Breach")
        st.rerun()

with sim_col3:
    if st.button("👤 Test Insider Threat", use_container_width=True):
        run_simulation(simulate_insider_threat, "Insider Threat")
        st.rerun()

if st.session_state.attack_history:
    st.markdown("<div style='background:rgba(0, 212, 255, 0.05); border:1px solid rgba(0, 212, 255, 0.1); border-radius:8px; padding:1rem; margin-top:1rem;'>", unsafe_allow_html=True)
    for atk in reversed(st.session_state.attack_history[-5:]):
        st.markdown(
            f"<div style='font-size:0.8rem; margin-bottom:4px;'>"
            f"<span style='color:var(--text-muted); font-family:monospace;'>[{atk['time']}]</span> "
            f"<span style='color:var(--accent-cyan); font-weight:700;'>{atk['type'].upper()}</span> "
            f"<span style='color:var(--text-secondary);'>— {atk['events']} telemetry packets injected, {atk['incidents']} alerts triggered</span>"
            f"</div>",
            unsafe_allow_html=True,
        )
    st.markdown("</div>", unsafe_allow_html=True)

# ── Alert / Incident Table ──────────────────────────────────────────────────
st.markdown("""
<div class="section-header fade-in" style="animation-delay:0.9s; margin-top:3rem;">
    📋 Real-Time Threat Ledger
</div>
""", unsafe_allow_html=True)

if st.session_state.incidents:
    inc_df = pd.DataFrame(st.session_state.incidents)
    inc_df = inc_df.sort_values("risk_score", ascending=False)

    display_df = inc_df[["timestamp", "user_id", "department", "event_type", "layers_fired", "risk_score", "risk_level", "action"]].copy()
    display_df.columns = ["Timestamp", "User", "Department", "Threat Type", "Fired Layer(s)", "Risk Score", "Severity", "Action"]

    def color_severity(val):
        colors = {"CRITICAL": "#ff2d55", "HIGH": "#ff6b35", "MEDIUM": "#ffaa00", "LOW": "#00e676"}
        return f"color: {colors.get(val, '#e0e6ed')}"

    st.dataframe(
        display_df.head(20).style.applymap(color_severity, subset=["Severity"]),
        use_container_width=True,
        height=350,
    )
else:
    st.info("No incidents detected. System operating within normal parameters.")

# ── Incident Detail Panel ───────────────────────────────────────────────────
st.markdown("""
<div class="section-header fade-in" style="animation-delay:1s; margin-top:3rem;">
    📂 Intelligence Briefings
</div>
""", unsafe_allow_html=True)

if st.session_state.incidents:
    for i, inc in enumerate(reversed(st.session_state.incidents[-10:])):
        severity_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(inc["risk_level"], "⚪")
        inc_id = inc.get("incident_id", f"INC-{i+1000}")
        with st.expander(
            f"{severity_emoji} {inc['risk_level']} — {inc['user_id']} — {inc['event_type']} (Risk: {inc['risk_score']:.0f}) [{inc_id}]"
        ):
            st.code(inc["summary"], language=None)
            
            # Analyst Review & Feedback Action Row
            st.markdown("<div style='font-size:0.75rem; color:#94A3B8; font-weight:700; margin-top:8px;'>SOC ANALYST VERDICT & FEEDBACK LOOP</div>", unsafe_allow_html=True)
            fb_c1, fb_c2, fb_c3 = st.columns([1.5, 1.5, 3])
            with fb_c1:
                if st.button(f"✅ Confirm Threat", key=f"conf_{inc_id}_{i}"):
                    log_analyst_feedback(
                        incident_id=inc_id,
                        analyst_decision="CONFIRMED",
                        layer_fired=inc.get("layers_fired", "Telemetry"),
                        original_risk_level=inc["risk_level"],
                        analyst_verdict="MALICIOUS",
                        analyst_notes=f"Confirmed malicious activity by SOC analyst for {inc['user_id']}",
                    )
                    st.success(f"{inc_id} confirmed as true threat.")
                    st.rerun()
            with fb_c2:
                if st.button(f"⚠️ Override (False Pos)", key=f"over_{inc_id}_{i}"):
                    log_analyst_feedback(
                        incident_id=inc_id,
                        analyst_decision="OVERRIDDEN",
                        layer_fired=inc.get("layers_fired", "Telemetry"),
                        original_risk_level=inc["risk_level"],
                        analyst_verdict="FALSE_POSITIVE",
                        analyst_notes=f"Overridden by SOC analyst - benign operational deviation",
                    )
                    st.warning(f"{inc_id} marked as false positive.")
                    st.rerun()
            with fb_c3:
                st.caption(f"Fired Layer(s): **{inc.get('layers_fired', 'Telemetry')}**")
else:
    st.info("No incident reports to display.")

# ── Multi-Vector Threat Analysis Lab ─────────────────────────────────────────
st.markdown("""
<div class="section-header fade-in" style="animation-delay:1.1s; margin-top:3.5rem;">
    🔬 Multi-Vector Threat Inspection Lab
</div>
<div style="font-size:0.7rem; color:var(--text-secondary); margin-bottom:1.5rem; letter-spacing:1px; text-transform:uppercase;">
    Autonomous Inspection Engines // Independent Layer Evaluation // Highest-Confidence Resolution
</div>
""", unsafe_allow_html=True)

tab_infra, tab_visual, tab_sender, tab_attach, tab_feedback = st.tabs([
    "🌐 Infrastructure & Lookalike",
    "🖼️ Visual Page Similarity",
    "👤 Sender Behavior Baseline",
    "📎 Attachment & QR Inspection",
    "📊 SOC Analyst Feedback & Accuracy"
])

with tab_infra:
    st.markdown("#### 🌐 Lookalike Domain, WHOIS Age & Redirect-Chain Inspector")
    st.caption("Inspects homoglyph domain mutations against brand allowlists, queries registration age, and traces redirect chains for credential-form signatures.")
    
    infra_col1, infra_col2 = st.columns([3, 1])
    with infra_col1:
        test_url = st.text_input(
            "Target URL or Domain to Analyze",
            value="http://paypa1-security-update.xyz/login",
            help="Enter a test URL or domain name (e.g. paypa1.com, login.microsoftonline.com, internal-portal.tk)"
        )
    with infra_col2:
        max_age = st.number_input("Max Age Threshold (days)", min_value=1, max_value=365, value=30)

    if st.button("🚀 Run Infrastructure Scan", use_container_width=True):
        with st.spinner("Analyzing domain homoglyphs, querying WHOIS, and tracing redirect chain..."):
            infra_res = analyze_infrastructure(test_url, max_domain_age_days=max_age)
            
            res_col1, res_col2 = st.columns([1, 2])
            with res_col1:
                st.metric("Detection Verdict", "FLAGGED THREAT" if infra_res["flagged"] else "BENIGN")
                st.metric("Engine Confidence", f"{infra_res['confidence']:.1f}%")
                if infra_res["signals"]:
                    st.write("**Active Signals:**")
                    for sig in infra_res["signals"]:
                        st.markdown(f"- 🔴 `{sig}`")
            with res_col2:
                st.write("**Technical Explanation:**")
                if infra_res["flagged"]:
                    st.error(infra_res["explanation"])
                else:
                    st.success(infra_res["explanation"])
                
                with st.expander("Detailed Telemetry Breakdown"):
                    st.json(infra_res["details"])

with tab_visual:
    st.markdown("#### 🖼️ Visual Perceptual Hashing (Page Similarity)")
    st.caption("Compares screenshot perceptual hashes (pHash & dHash) against reference login templates to detect visual credential phishing.")
    
    vis_col1, vis_col2 = st.columns([1, 1])
    with vis_col1:
        preset_choice = st.selectbox(
            "Select a Test Screenshot or Upload Custom",
            options=[
                "Microsoft 365 Reference Template",
                "PayPal Reference Template",
                "Civic Citizen Portal Reference Template",
                "Upload Custom Image"
            ]
        )
        threshold_val = st.slider("Visual Impersonation Threshold (%)", min_value=50.0, max_value=95.0, value=75.0, step=1.0)
        
        test_image = None
        if preset_choice == "Microsoft 365 Reference Template":
            test_img_path = "templates/reference_logins/microsoft365.png"
            if os.path.exists(test_img_path):
                test_image = Image.open(test_img_path)
        elif preset_choice == "PayPal Reference Template":
            test_img_path = "templates/reference_logins/paypal.png"
            if os.path.exists(test_img_path):
                test_image = Image.open(test_img_path)
        elif preset_choice == "Civic Citizen Portal Reference Template":
            test_img_path = "templates/reference_logins/civic_portal.png"
            if os.path.exists(test_img_path):
                test_image = Image.open(test_img_path)
        else:
            uploaded_file = st.file_uploader("Upload Page Screenshot (.png, .jpg)", type=["png", "jpg", "jpeg"])
            if uploaded_file:
                test_image = Image.open(uploaded_file)

    with vis_col2:
        if test_image:
            st.image(test_image, caption="Loaded Screenshot Input", width=260)
            if st.button("🔍 Execute Perceptual Hash Analysis", use_container_width=True):
                vis_res = analyze_page_similarity(test_image, threshold=threshold_val)
                st.markdown("---")
                if vis_res["flagged"]:
                    st.error(f"⚠️ **Visual Impersonation Detected!** Closest brand: **{vis_res['matched_brand']}** ({vis_res['similarity_score']:.1f}% match)")
                    st.caption(vis_res["explanation"])
                else:
                    st.success(f"✅ **Visual Layout Appears Distinct.** (Top similarity: {vis_res['similarity_score']:.1f}%)")
                    st.caption(vis_res["explanation"])
                
                if vis_res.get("all_matches"):
                    st.dataframe(pd.DataFrame(vis_res["all_matches"]), use_container_width=True)
        else:
            st.info("Select or upload an image to run perceptual hash verification.")

with tab_sender:
    st.markdown("#### 👤 Per-Account Sender-Behavior Modeling")
    st.caption("Maintains isolated Isolation Forest baselines per sender, modeling typical sending hours, recipient domains, and writing-style fingerprints.")
    
    sb_col1, sb_col2 = st.columns([1, 1])
    with sb_col1:
        test_sender = st.text_input("Sender Account ID", value="fin_204")
        test_hour = st.slider("Transmission Hour (24h)", min_value=0, max_value=23, value=2)
        test_recips = st.text_input("Recipient Addresses (comma-separated)", value="external_audit@darknet.xyz, anon_drop@relay.to")
        test_att = st.checkbox("Message Includes Attachment", value=True)
        test_msg_text = st.text_area(
            "Outbound Email Content",
            value="URGENT! Transfer pending payroll authorization codes right now! Do not delay or accounts will freeze.",
            height=100
        )
    
    with sb_col2:
        st.markdown("**Baseline Overview:**")
        st.caption("Sender baselines learn typical business hours (8-18), municipal recipient sets (@cityhall.gov), and routine administrative tone.")
        if st.button("📊 Evaluate Sender Baseline Deviation", use_container_width=True):
            features = {
                "send_hour": test_hour,
                "recipients": test_recips,
                "has_attachment": test_att,
                "email_text": test_msg_text,
            }
            sb_res = analyze_sender_behavior(test_sender, features)
            st.markdown("---")
            if sb_res["flagged"]:
                st.error(f"🚨 **Sender Anomaly Detected!** Confidence: {sb_res['confidence']:.1f}%")
                st.write(sb_res["explanation"])
                if sb_res["signals"]:
                    for s in sb_res["signals"]:
                        st.markdown(f"- 🔴 `{s}`")
            else:
                st.success(f"✅ **Normal Sender Behavior.** Activity conforms to {test_sender}'s historical baseline.")
                st.caption(sb_res["explanation"])

with tab_attach:
    st.markdown("#### 📎 Risky Extension & QR Code Inspection")
    st.caption("Screens file attachments for dangerous executable/dropper extensions and extracts QR codes to trace embedded destinations.")
    
    at_col1, at_col2 = st.columns([1, 1])
    with at_col1:
        test_filename = st.text_input("Simulated Attachment Filename", value="invoice_payment_report.scr")
        st.caption("Try extensions like: `.exe`, `.scr`, `.bat`, `.js`, `.ps1`, `.pdf`")
        uploaded_qr = st.file_uploader("Upload Image to inspect for QR Code (optional)", type=["png", "jpg", "jpeg"])
    
    with at_col2:
        if st.button("🛡️ Scan Attachment Payload", use_container_width=True):
            test_payload = uploaded_qr if uploaded_qr else None
            att_res = analyze_attachment(test_filename, file_bytes_or_path=test_payload)
            st.markdown("---")
            if att_res["flagged"]:
                st.error(f"⚠️ **Threat Found in Attachment!** Confidence: {att_res['confidence']:.1f}%")
                st.write(att_res["explanation"])
                for s in att_res["signals"]:
                    st.markdown(f"- 🔴 `{s}`")
            else:
                st.success("✅ **Attachment Payload Cleared.** No dangerous extensions or malicious QR codes detected.")
                st.caption(att_res["explanation"])

with tab_feedback:
    st.markdown("#### 📊 SOC Analyst Feedback Loop & Live Accuracy")
    st.caption("Persistent SQLite tracking of SOC analyst Confirmations and False-Positive Overrides to evaluate detection precision.")
    
    metrics = get_live_accuracy_metrics()
    fb_k1, fb_k2, fb_k3, fb_k4 = st.columns(4)
    with fb_k1:
        st.metric("Total Reviews", f"{metrics['total_reviews']}")
    with fb_k2:
        st.metric("Confirmed True Positive", f"{metrics['confirmed_count']}")
    with fb_k3:
        st.metric("Overridden False Positive", f"{metrics['overridden_count']}")
    with fb_k4:
        st.metric("Analyst Concordance", f"{metrics['accuracy_rate']:.1f}%")
    
    if metrics["records"]:
        st.dataframe(pd.DataFrame(metrics["records"]), use_container_width=True)
    else:
        st.info("No feedback decisions logged yet. Use the 'Confirm Threat' or 'Override' buttons under Intelligence Briefings to log analyst decisions.")

# ── Footer ───────────────────────────────────────────────────────────────────
st.markdown("---")
st.markdown(
    "<div style='text-align:center; color:#3a4a5a; font-size:0.8rem;'>"
    "Argus — AI-Powered Phishing Detection & Civic Cyber Shield • Multi-Layer Independent Architecture • "
    f"Events Processed: {len(df)} • {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    "</div>",
    unsafe_allow_html=True,
)
