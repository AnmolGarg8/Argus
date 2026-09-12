"""
Argus — AI-Powered Phishing Detection for Organisations
Main Streamlit Defense Console
"""

import os
import datetime
import pandas as pd
import numpy as np
import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
from PIL import Image

# Argus Core Detection Engines
from content_intelligence import analyze_content, train_content_model
from domain_analyzer import analyze_domain, detect_lookalike_domain, check_domain_age, trace_redirect_chain
from page_similarity import analyze_page_similarity
from sender_behavior import analyze_sender_behavior
from attachment_qr_inspection import analyze_attachment
from verdict_engine import (
    evaluate_message_verdict,
    evaluate_message_pipeline,
    log_analyst_feedback,
    compute_live_feedback_metrics,
    get_all_feedback,
)
from threat_origin_map import render_threat_origin_map
from simulator import generate_enterprise_stream, get_training_emails

# ── Streamlit Page Configuration ─────────────────────────────────────────────
st.set_page_config(
    page_title="Argus — AI-Powered Phishing Detection for Organisations",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── Cyber Theme Stylesheet Injection ─────────────────────────────────────────
try:
    with open("cyber-theme.css", "r", encoding="utf-8") as f:
        theme_css = f.read()
        st.markdown(f"<style>{theme_css}</style>", unsafe_allow_html=True)
except Exception:
    pass

# Custom styling adjustments
st.markdown("""
<style>
    header[data-testid="stHeader"], [data-testid="stToolbar"], footer, #MainMenu {
        display: none !important;
        visibility: hidden !important;
        height: 0 !important;
    }
    .stApp {
        background-color: #000000 !important;
    }
    .block-container {
        padding-top: 1rem !important;
        padding-bottom: 2rem !important;
        max-width: 96% !important;
    }
    .verdict-badge {
        font-family: 'JetBrains Mono', monospace;
        font-weight: 800;
        padding: 4px 12px;
        border-radius: 4px;
        letter-spacing: 1px;
        font-size: 0.8rem;
        display: inline-block;
    }
    .verdict-block {
        background: rgba(255, 45, 85, 0.15);
        color: #ff2d55;
        border: 1px solid rgba(255, 45, 85, 0.4);
    }
    .verdict-flag {
        background: rgba(245, 158, 11, 0.15);
        color: #f59e0b;
        border: 1px solid rgba(245, 158, 11, 0.4);
    }
    .verdict-allow {
        background: rgba(16, 185, 129, 0.15);
        color: #10b981;
        border: 1px solid rgba(16, 185, 129, 0.4);
    }
    .intel-card {
        background: rgba(4, 8, 15, 0.9);
        border: 1px solid rgba(0, 212, 255, 0.2);
        border-radius: 6px;
        padding: 1.25rem;
        margin-bottom: 1rem;
    }
</style>
""", unsafe_allow_html=True)

# ── Cyber Navbar ─────────────────────────────────────────────────────────────
st.markdown("""
<div class="cyber-navbar">
    <div class="nav-left">
        <div style="font-size:1.4rem; color:#00D4FF; margin-right:0.5rem;">🛡️</div>
        <div class="nav-logo">ARGUS // PHISHING DEFENSE PLATFORM</div>
    </div>
    <div class="nav-right">
        <div class="status-indicator">
            <div class="pulse-dot"></div>
            PRE_INTERACTION_SHIELD_ONLINE
        </div>
        <div style="color:#94A3B8; font-size:0.8rem; font-family:'JetBrains Mono',monospace;">CORP_GATEWAY // v4.2</div>
        <div style="width:32px; height:32px; background:#00D4FF; border-radius:3px; display:flex; align-items:center; justify-content:center; color:#000; font-weight:900; font-size:0.8rem;">AR</div>
    </div>
</div>
""", unsafe_allow_html=True)

# ── Session State Initialization ─────────────────────────────────────────────
if "event_stream" not in st.session_state:
    with st.spinner("Initializing Argus multi-layer detection pipelines..."):
        initial_stream = generate_enterprise_stream(n=50, attack_ratio=0.35)
        st.session_state.event_stream = evaluate_message_pipeline(initial_stream)
        st.session_state.simulation_history = []

if "custom_test_result" not in st.session_state:
    st.session_state.custom_test_result = None

df_events = st.session_state.event_stream

# ── Platform Mission & Problem Statement Banner ──────────────────────────────
st.markdown("""
<div class="cyber-card" style="margin-bottom:1.5rem; border-left: 3px solid #00D4FF;">
    <div style="display:flex; justify-content:space-between; align-items:flex-start;">
        <div>
            <div style="font-size:0.7rem; color:#00D4FF; font-weight:800; letter-spacing:2px; text-transform:uppercase; margin-bottom:4px;">
                ORGANISATIONAL PRE-INTERACTION DEFENSE LAYER
            </div>
            <div style="font-size:0.95rem; color:#E2E8F0; font-weight:500; line-height:1.5;">
                Modern phishing defeats traditional reputation filters with generative AI phrasing, homoglyph domains, visual login clones, and compromised internal accounts. 
                <b style="color:#00D4FF;">Argus</b> neutralises these vectors before employee interaction across four independent AI layers with correlated verdicts and human-explainable signals.
            </div>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

# ── Live KPI Metrics Row ─────────────────────────────────────────────────────
total_messages = len(df_events)
blocked_count = int((df_events["verdict"] == "BLOCK").sum())
flagged_count = int((df_events["verdict"] == "FLAG_FOR_REVIEW").sum())
allowed_count = int((df_events["verdict"] == "ALLOW").sum())
threat_ratio = ((blocked_count + flagged_count) / total_messages * 100) if total_messages > 0 else 0.0

# Calculate empirical metrics from hidden ground truth
ground_truth_threats = sum(1 for gt in df_events.get("_ground_truth", []) if isinstance(gt, dict) and gt.get("is_phishing"))
true_positives = sum(1 for _, r in df_events.iterrows() if r.get("_ground_truth", {}).get("is_phishing") and r.get("verdict") in ["BLOCK", "FLAG_FOR_REVIEW"])
false_positives = sum(1 for _, r in df_events.iterrows() if not r.get("_ground_truth", {}).get("is_phishing") and r.get("verdict") in ["BLOCK", "FLAG_FOR_REVIEW"])
empirical_fpr = (false_positives / (total_messages - ground_truth_threats) * 100) if (total_messages - ground_truth_threats) > 0 else 0.0

# Retrieve SOC analyst feedback loop metrics
feedback_metrics = compute_live_feedback_metrics()

kpi1, kpi2, kpi3, kpi4, kpi5 = st.columns(5)
with kpi1:
    st.markdown(f"""<div class="cyber-card">
        <div class="kpi-wrapper">
            <div class="kpi-title">MESSAGES SCANNED</div>
            <div class="kpi-val monospace">{total_messages}</div>
        </div>
    </div>""", unsafe_allow_html=True)
with kpi2:
    st.markdown(f"""<div class="cyber-card">
        <div class="kpi-wrapper">
            <div class="kpi-title">THREAT DETECTION RATE</div>
            <div class="kpi-val monospace" style="color:#FF2D55;">{threat_ratio:.1f}%</div>
        </div>
    </div>""", unsafe_allow_html=True)
with kpi3:
    st.markdown(f"""<div class="cyber-card">
        <div class="kpi-wrapper">
            <div class="kpi-title">ACTIVE WEAPONIZED BLOCKS</div>
            <div class="kpi-val monospace" style="color:#FF2D55;">{blocked_count}</div>
        </div>
    </div>""", unsafe_allow_html=True)
with kpi4:
    st.markdown(f"""<div class="cyber-card">
        <div class="kpi-wrapper">
            <div class="kpi-title">ANALYST CONFIRMATIONS</div>
            <div class="kpi-val monospace" style="color:#00D4FF;">{feedback_metrics['confirmed_count']}/{feedback_metrics['total_reviews']}</div>
        </div>
    </div>""", unsafe_allow_html=True)
with kpi5:
    st.markdown(f"""<div class="cyber-card">
        <div class="kpi-wrapper">
            <div class="kpi-title">LIVE FALSE POSITIVE RATE</div>
            <div class="kpi-val monospace" style="color:#10B981;">{feedback_metrics['false_positive_rate']:.1f}%</div>
        </div>
    </div>""", unsafe_allow_html=True)

st.markdown("<div style='margin-bottom:1.5rem;'></div>", unsafe_allow_html=True)

# ── Interactive Live Test Console ────────────────────────────────────────────
st.markdown("""
<div class="section-header" style="font-size:1.1rem; margin-bottom:0.25rem;">
    ⚡ Interactive Multi-Layer Inspection Console
</div>
<div style="font-size:0.75rem; color:#94A3B8; margin-bottom:1rem; text-transform:uppercase; letter-spacing:1px;">
    Test arbitrary corporate communications through all 4 independent detection layers in real-time
</div>
""", unsafe_allow_html=True)

# Preset scenario loaders
preset_col1, preset_col2, preset_col3, preset_col4 = st.columns(4)
with preset_col1:
    if st.button("🎯 M365 Credential Harvester", use_container_width=True):
        st.session_state.tc_sender = "no-reply@micros0ft-online-verify.com"
        st.session_state.tc_recip = "sarah.jenkins@acme-corp.internal"
        st.session_state.tc_hour = 14
        st.session_state.tc_url = "http://login.micros0ft-online-verify.com/auth/login"
        st.session_state.tc_subject = "URGENT: Microsoft 365 Password Expiration Notice"
        st.session_state.tc_text = "FINAL NOTICE: Your enterprise Microsoft 365 password expires in 2 hours. Access to corporate mail and OneDrive will be terminated unless verified immediately at http://login.micros0ft-online-verify.com/auth/login."
        st.session_state.tc_att = ""
with preset_col2:
    if st.button("💼 Executive Wire Fraud", use_container_width=True):
        st.session_state.tc_sender = "marcus.vance@acme-corp-executive.com"
        st.session_state.tc_recip = "elena.rostova@acme-corp.internal"
        st.session_state.tc_hour = 11
        st.session_state.tc_url = "http://secure-wire-clearing.net/settlement/form"
        st.session_state.tc_subject = "Strictly Confidential - Immediate Wire Settlement"
        st.session_state.tc_text = "Elena, I am in an executive offsite board meeting with zero voice reception. We need an immediate wire transfer of $142,500 executed today for an unannounced acquisition. Do not discuss with team. Reply with swift confirmation."
        st.session_state.tc_att = "wire_instructions_confidential.pdf"
with preset_col3:
    if st.button("🚨 Compromised Internal Account", use_container_width=True):
        st.session_state.tc_sender = "sarah.jenkins@acme-corp.internal"
        st.session_state.tc_recip = "all-staff@acme-corp.internal, offshore-dev@partner-vendor.com"
        st.session_state.tc_hour = 3
        st.session_state.tc_url = "http://portal-acme-payroll.biz/login"
        st.session_state.tc_subject = "Urgent: Updated Employee Bonus Compensation Schedule"
        st.session_state.tc_text = "Team, management has approved mid-year retention bonuses. Review your revised allocation and enter your direct deposit credentials on the compensation portal within 24 hours."
        st.session_state.tc_att = "bonus_calc_macro.xlsm"
with preset_col4:
    if st.button("✅ Benign Planning Sync", use_container_width=True):
        st.session_state.tc_sender = "david.chen@acme-corp.internal"
        st.session_state.tc_recip = "sarah.jenkins@acme-corp.internal"
        st.session_state.tc_hour = 10
        st.session_state.tc_url = "https://wiki.acme-corp.internal/planning/q3"
        st.session_state.tc_subject = "Quarterly Planning Sync - Agenda & Notes"
        st.session_state.tc_text = "Hi team, please review the attached slides before tomorrow's Q3 planning session at 10 AM. Let me know if any items should be added to the backlog."
        st.session_state.tc_att = "q3_planning_deck.pdf"

# Input fields
with st.container():
    c_in1, c_in2, c_in3 = st.columns([1.5, 1.5, 1])
    with c_in1:
        test_sender = st.text_input("Sender Account", value=st.session_state.get("tc_sender", "billing@paypa1-security-update.xyz"))
    with c_in2:
        test_recips = st.text_input("Recipient(s)", value=st.session_state.get("tc_recip", "elena.rostova@acme-corp.internal"))
    with c_in3:
        test_hour = st.slider("Send Hour (24h)", min_value=0, max_value=23, value=st.session_state.get("tc_hour", 14))

    c_in4, c_in5 = st.columns([2, 1])
    with c_in4:
        test_url = st.text_input("Target URL / Link in Message", value=st.session_state.get("tc_url", "http://paypa1-security-update.xyz/login"))
    with c_in5:
        test_att_name = st.text_input("Attachment Filename", value=st.session_state.get("tc_att", "invoice_overdue.scr"))

    test_body = st.text_area(
        "Message Body / Email Text",
        value=st.session_state.get("tc_text", "Security Alert: An unauthorized transaction of $4,850.00 was attempted from your corporate card. Verify your credentials immediately to halt payment."),
        height=90,
    )

    if st.button("🚀 Execute Multi-Layer Argus Analysis", use_container_width=True):
        with st.spinner("Evaluating across Content Intelligence, Domain Infrastructure, Sender Behavioral Baseline, and Attachment screening..."):
            # 1. Content NLP
            content_out = analyze_content(test_body)
            # 2. Domain Infrastructure
            domain_out = analyze_domain(test_url, fast_scan=False) if test_url.strip() else None
            # 3. Sender Behavioral Baseline
            sender_feats = {
                "send_hour": test_hour,
                "recipients": test_recips,
                "has_attachment": bool(test_att_name.strip()),
                "email_text": test_body,
            }
            sender_out = analyze_sender_behavior(test_sender, sender_feats)
            # 4. Attachment payload
            attach_out = analyze_attachment(test_att_name) if test_att_name.strip() else None

            # Correlate into unified verdict
            verdict_out = evaluate_message_verdict(
                content_result=content_out,
                domain_result=domain_out,
                visual_result=None,
                sender_result=sender_out,
                attachment_result=attach_out,
            )
            st.session_state.custom_test_result = verdict_out

# Display Live Test Result Card
if st.session_state.custom_test_result:
    res = st.session_state.custom_test_result
    v_class = "verdict-block" if res["verdict"] == "BLOCK" else ("verdict-flag" if res["verdict"] == "FLAG_FOR_REVIEW" else "verdict-allow")
    
    st.markdown(f"""
    <div class="intel-card" style="border-top: 3px solid {'#FF2D55' if res['verdict']=='BLOCK' else ('#F59E0B' if res['verdict']=='FLAG_FOR_REVIEW' else '#10B981')};">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
            <div style="font-size:1.1rem; font-weight:800; color:#FFFFFF;">
                CORRELATED DECISION VERDICT: <span class="verdict-badge {v_class}">{res['verdict']}</span>
            </div>
            <div style="font-family:'JetBrains Mono',monospace; font-size:1.2rem; font-weight:800; color:{'#FF2D55' if res['composite_score']>=75 else ('#F59E0B' if res['composite_score']>=35 else '#10B981')};">
                COMPOSITE RISK: {res['composite_score']:.1f}/100
            </div>
        </div>
        <div style="font-size:0.85rem; color:#94A3B8; margin-bottom:12px; font-family:'Inter',sans-serif;">
            <b>Structured Explanation:</b> {res['explanation']}
        </div>
        <div style="font-size:0.75rem; color:#475569; font-family:'JetBrains Mono',monospace;">
            FIRING DETECTOR LAYERS: <span style="color:#00D4FF;">{', '.join(res['firing_layers']) if res['firing_layers'] else 'None (All Layers Passed)'}</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Layer-by-layer breakdown display
    lay_cols = st.columns(4)
    layers = [
        ("Content Intelligence", res["layer_breakdown"].get("Content_Intelligence")),
        ("Domain Infrastructure", res["layer_breakdown"].get("Domain_Infrastructure")),
        ("Sender Behavior", res["layer_breakdown"].get("Sender_Behavior")),
        ("Attachment Screening", res["layer_breakdown"].get("Attachment_Inspection")),
    ]
    for idx, (lname, ldata) in enumerate(layers):
        with lay_cols[idx]:
            if ldata:
                flag = ldata.get("flagged", False)
                score = ldata.get("risk_score", 0.0)
                color = "#FF2D55" if flag else "#10B981"
                st.markdown(f"""
                <div style="background:rgba(255,255,255,0.02); border:1px solid {'rgba(255,45,85,0.3)' if flag else 'rgba(0,212,255,0.1)'}; border-radius:4px; padding:10px;">
                    <div style="font-size:0.7rem; color:#94A3B8; font-weight:700;">{lname.upper()}</div>
                    <div style="font-size:1.1rem; font-family:'JetBrains Mono',monospace; color:{color}; font-weight:800; margin:4px 0;">
                        {'FLAGGED' if flag else 'CLEARED'} ({score:.0f}%)
                    </div>
                    <div style="font-size:0.75rem; color:#CBD5E1; line-height:1.3;">
                        {ldata.get('explanation', '')[:90]}...
                    </div>
                </div>
                """, unsafe_allow_html=True)

st.markdown("<div style='margin-bottom:2rem;'></div>", unsafe_allow_html=True)

# ── Telemetry Charts & Risk Topology ─────────────────────────────────────────
chart_col1, chart_col2 = st.columns([1, 1])

with chart_col1:
    st.markdown("""
    <div class="chart-container">
        <div class="chart-header">
            <div class="chart-title"><span>📡</span> Organisational Phishing Risk Gauge</div>
            <div class="live-badge"><div class="pulse-dot" style="width:6px; height:6px;"></div> LIVE CORRELATION</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    avg_risk = float(df_events["risk_score"].mean()) if not df_events.empty else 0.0
    fig_gauge = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=avg_risk,
        delta={"reference": 30, "increasing": {"color": "#ff3a3a"}, "decreasing": {"color": "#10b981"}},
        title={"text": "ORGANISATION RISK POSTURE", "font": {"color": "#94a3b8", "size": 11, "family": "JetBrains Mono"}},
        number={"font": {"color": "#00d4ff", "size": 44, "family": "JetBrains Mono"}},
        gauge={
            "axis": {"range": [0, 100], "tickcolor": "#1e293b", "tickfont": {"color": "#475569"}},
            "bar": {"color": "#00d4ff"},
            "bgcolor": "#000000",
            "bordercolor": "rgba(0, 212, 255, 0.2)",
            "steps": [
                {"range": [0, 35], "color": "rgba(16, 185, 129, 0.08)"},
                {"range": [35, 75], "color": "rgba(245, 158, 11, 0.08)"},
                {"range": [75, 100], "color": "rgba(255, 45, 85, 0.08)"},
            ],
            "threshold": {
                "line": {"color": "#ff2d55", "width": 2},
                "thickness": 0.8,
                "value": 75,
            },
        },
    ))
    fig_gauge.update_layout(
        height=250,
        margin=dict(t=25, b=10, l=25, r=25),
        paper_bgcolor="#000000",
        plot_bgcolor="#000000",
        font={"color": "#e2e8f0"},
    )
    st.plotly_chart(fig_gauge, use_container_width=True)

with chart_col2:
    st.markdown("""
    <div class="chart-container">
        <div class="chart-header">
            <div class="chart-title"><span>🧬</span> Multi-Layer Threat Vector Distribution</div>
            <div class="live-badge" style="color:#00d4ff; border-color:rgba(0,212,255,0.2);"><div class="pulse-dot" style="width:6px; height:6px;"></div> ACTIVE</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Count which layers fired
    layer_counts = {"Content NLP": 0, "Lookalike Domain": 0, "Sender Anomaly": 0, "Attachment Screening": 0}
    for _, row in df_events.iterrows():
        fl = str(row.get("firing_layers", ""))
        if "Content_Intelligence" in fl:
            layer_counts["Content NLP"] += 1
        if "Domain_Infrastructure" in fl:
            layer_counts["Lookalike Domain"] += 1
        if "Sender_Behavior" in fl:
            layer_counts["Sender Anomaly"] += 1
        if "Attachment_Inspection" in fl:
            layer_counts["Attachment Screening"] += 1

    fig_bar = go.Figure(go.Bar(
        x=list(layer_counts.values()),
        y=list(layer_counts.keys()),
        orientation="h",
        marker=dict(
            color=["#00D4FF", "#6C63FF", "#F59E0B", "#FF2D55"],
            line=dict(color="rgba(255,255,255,0.1)", width=1)
        ),
    ))
    fig_bar.update_layout(
        height=250,
        margin=dict(t=20, b=25, l=140, r=20),
        paper_bgcolor="#000000",
        plot_bgcolor="#000000",
        xaxis=dict(gridcolor="rgba(255,255,255,0.05)", tickfont={"color": "#64748b"}),
        yaxis=dict(tickfont={"color": "#94a3b8", "family": "JetBrains Mono"}),
        font={"color": "#e2e8f0"},
    )
    st.plotly_chart(fig_bar, use_container_width=True)

# ── Simulation Ingestion Controls ────────────────────────────────────────────
st.markdown("""
<div class="section-header" style="font-size:1.1rem; margin-top:1.5rem; margin-bottom:0.25rem;">
    🧪 Telemetry Stream Simulation & Attack Ingestion
</div>
<div style="font-size:0.75rem; color:#94A3B8; margin-bottom:1rem; text-transform:uppercase; letter-spacing:1px;">
    Inject synthetic enterprise communication streams with hidden ground truth to stress-test accuracy
</div>
""", unsafe_allow_html=True)

sim_c1, sim_c2, sim_c3 = st.columns(3)
with sim_c1:
    if st.button("⚡ Ingest 40 Benign Corporate Emails", use_container_width=True):
        new_batch = generate_enterprise_stream(n=40, attack_ratio=0.05)
        new_scored = evaluate_message_pipeline(new_batch)
        st.session_state.event_stream = pd.concat([new_scored, st.session_state.event_stream], ignore_index=True)
        st.rerun()

with sim_c2:
    if st.button("🎯 Inject Targeted Phishing Wave (25 Attacks)", use_container_width=True):
        new_attacks = generate_enterprise_stream(n=25, attack_ratio=0.90)
        new_scored = evaluate_message_pipeline(new_attacks)
        st.session_state.event_stream = pd.concat([new_scored, st.session_state.event_stream], ignore_index=True)
        st.rerun()

with sim_c3:
    if st.button("🔄 Reset Telemetry Stream", use_container_width=True):
        fresh = generate_enterprise_stream(n=50, attack_ratio=0.35)
        st.session_state.event_stream = evaluate_message_pipeline(fresh)
        st.rerun()

# ── Real-Time Threat Stream & Ledger ─────────────────────────────────────────
st.markdown("""
<div class="section-header" style="font-size:1.1rem; margin-top:2.5rem; margin-bottom:0.25rem;">
    📋 Real-Time Threat Stream & Inspection Ledger
</div>
""", unsafe_allow_html=True)

# Filter controls
f_col1, f_col2 = st.columns([1, 2])
with f_col1:
    verdict_filter = st.selectbox("Filter by Verdict", ["ALL", "BLOCK", "FLAG_FOR_REVIEW", "ALLOW"])
with f_col2:
    search_query = st.text_input("Search (Sender, Recipient, Subject, or Indicator)", "")

filtered_df = df_events.copy()
if verdict_filter != "ALL":
    filtered_df = filtered_df[filtered_df["verdict"] == verdict_filter]

if search_query.strip():
    q = search_query.lower()
    filtered_df = filtered_df[
        filtered_df["sender_id"].astype(str).str.lower().str.contains(q) |
        filtered_df["recipients"].astype(str).str.lower().str.contains(q) |
        filtered_df["subject"].astype(str).str.lower().str.contains(q) |
        filtered_df["firing_layers"].astype(str).str.lower().str.contains(q)
    ]

# Render interactive table
display_columns = ["id", "timestamp", "sender_id", "subject", "firing_layers", "risk_score", "verdict"]
display_df = filtered_df[display_columns].copy()
display_df.columns = ["Message ID", "Timestamp", "Sender", "Subject", "Firing Layers", "Risk Score", "Verdict"]

def style_verdict(val):
    if val == "BLOCK":
        return "color: #FF2D55; font-weight: bold;"
    elif val == "FLAG_FOR_REVIEW":
        return "color: #F59E0B; font-weight: bold;"
    return "color: #10B981; font-weight: bold;"

styler = display_df.head(25).style
if hasattr(styler, "map"):
    styled_table = styler.map(style_verdict, subset=["Verdict"])
else:
    styled_table = styler.applymap(style_verdict, subset=["Verdict"])

st.dataframe(styled_table, use_container_width=True, height=350)

# ── Threat Origin Map: Geographic Distribution of Flagged Phishing Infrastructure ─
st.markdown("""
<div class="section-header" style="font-size:1.1rem; margin-top:2.5rem; margin-bottom:0.25rem;">
    🌍 Threat Origin Map — Geographic Distribution of Flagged Phishing Infrastructure
</div>
<div style="font-size:0.75rem; color:#94A3B8; margin-bottom:1rem; text-transform:uppercase; letter-spacing:1px;">
    Geographic hosting infrastructure and interception trajectories behind active phishing threats flagged across detection layers
</div>
""", unsafe_allow_html=True)

map_events = filtered_df if not filtered_df[filtered_df["verdict"].isin(["BLOCK", "FLAG_FOR_REVIEW"])].empty else df_events
render_threat_origin_map(
    df_events=map_events,
    custom_test_result=st.session_state.get("custom_test_result"),
    height=540,
)

# ── Expandable Threat Intelligence Briefings & Analyst Feedback ───────────────
st.markdown("""
<div class="section-header" style="font-size:1.1rem; margin-top:2.5rem; margin-bottom:0.25rem;">
    📂 Threat Intelligence Briefings & Analyst Feedback Loop
</div>
<div style="font-size:0.75rem; color:#94A3B8; margin-bottom:1rem; text-transform:uppercase; letter-spacing:1px;">
    Inspect explainable signals and log SOC analyst confirmations or overrides to adjust precision live
</div>
""", unsafe_allow_html=True)

threat_records = filtered_df[filtered_df["verdict"].isin(["BLOCK", "FLAG_FOR_REVIEW"])].head(10)

if not threat_records.empty:
    for idx, (_, row) in enumerate(threat_records.iterrows()):
        mid = row.get("id", f"MSG-{idx}")
        score = row.get("risk_score", 0.0)
        verdict = row.get("verdict", "FLAG_FOR_REVIEW")
        sender = row.get("sender_id", "Unknown")
        subj = row.get("subject", "No Subject")
        layers = row.get("firing_layers", "None")
        expl = row.get("explanation", "No explanation available.")

        v_icon = "🛑" if verdict == "BLOCK" else "⚠️"

        with st.expander(f"{v_icon} [{verdict}] {mid} — {subj} (Sender: {sender}, Score: {score:.0f})"):
            st.markdown(f"**Structured Justification:**")
            st.info(expl)

            c_det1, c_det2 = st.columns(2)
            with c_det1:
                st.markdown(f"**Message URL:** `{row.get('url', 'None')}`")
                st.markdown(f"**Attachment:** `{row.get('attachment_name', 'None')}`")
            with c_det2:
                st.markdown(f"**Recipient(s):** `{row.get('recipients', 'None')}`")
                st.markdown(f"**Send Hour:** `{row.get('send_hour', 12)}:00`")

            # Analyst feedback button row
            st.markdown("<div style='font-size:0.75rem; color:#94A3B8; font-weight:700; margin-top:8px;'>SOC ANALYST ACTIONS</div>", unsafe_allow_html=True)
            fb_col1, fb_col2, fb_col3 = st.columns([1.5, 1.5, 3])
            with fb_col1:
                if st.button(f"✅ Confirm Threat", key=f"btn_conf_{mid}_{idx}"):
                    log_analyst_feedback(
                        message_id=mid,
                        analyst_decision="CONFIRMED_THREAT",
                        original_verdict=verdict,
                        firing_layers=layers.split(", ") if layers else [],
                        composite_score=score,
                        notes=f"Confirmed as genuine malicious phishing by analyst",
                    )
                    st.success(f"Feedback recorded: {mid} confirmed as genuine threat.")
                    st.rerun()
            with fb_col2:
                if st.button(f"⚠️ Override (False Pos)", key=f"btn_over_{mid}_{idx}"):
                    log_analyst_feedback(
                        message_id=mid,
                        analyst_decision="FALSE_POSITIVE",
                        original_verdict=verdict,
                        firing_layers=layers.split(", ") if layers else [],
                        composite_score=score,
                        notes=f"Analyst override: Legitimate corporate communication flagged erroneously",
                    )
                    st.warning(f"Feedback recorded: {mid} marked as False Positive. Live FPR updated.")
                    st.rerun()
            with fb_col3:
                st.caption(f"Firing Layers: **{layers}**")
else:
    st.info("No active threat flags matching current filter criteria.")

# ── Deep-Dive Multi-Vector Inspection Labs ───────────────────────────────────
st.markdown("""
<div class="section-header" style="font-size:1.1rem; margin-top:3rem; margin-bottom:0.25rem;">
    🔬 Multi-Vector Threat Inspection Labs
</div>
<div style="font-size:0.75rem; color:#94A3B8; margin-bottom:1.5rem; text-transform:uppercase; letter-spacing:1px;">
    Dedicated testing environments for each independent detection engine
</div>
""", unsafe_allow_html=True)

tab_content, tab_infra, tab_visual, tab_sender, tab_attach, tab_feedback = st.tabs([
    "📝 Content Intelligence (NLP)",
    "🌐 Domain & Lookalike Analyzer",
    "🖼️ Visual Page Similarity",
    "👤 Sender Behavioral Baseline",
    "📎 Attachment & QR Inspection",
    "📊 SOC Feedback & Accuracy",
])

# ── Tab 1: Content Intelligence
with tab_content:
    st.markdown("#### 📝 NLP Intent Pattern & Classification Lab")
    st.caption("TF-IDF Vectorizer + Logistic Regression model trained on labeled phishing intent (urgency, authority impersonation, credential harvesting, wire redirection).")
    
    ci_col1, ci_col2 = st.columns([2, 1])
    with ci_col1:
        ci_sample = st.text_area(
            "Target Message Body",
            value="CRITICAL ALERT: Your Microsoft 365 enterprise license has been suspended due to an unauthorized sign-in. Click here to confirm your credentials immediately.",
            height=120,
        )
    with ci_col2:
        st.markdown("**Intent Heuristic Screen:**")
        st.caption("Extracts regex signatures for high-urgency keywords, fake authority signatures, and credential prompts.")
        if st.button("🚀 Analyze Content Intent", use_container_width=True):
            ci_res = analyze_content(ci_sample)
            st.markdown("---")
            ci_flagged = ci_res.get("flagged", False)
            ci_conf = ci_res.get("confidence", ci_res.get("risk_score", 0.0))
            ci_patterns = ci_res.get("intent_patterns", [])
            ci_expl = ci_res.get("explanation", "")
            if ci_flagged:
                st.error(f"🚨 **Phishing Intent Detected!** Confidence: {ci_conf:.1f}%")
                st.write(f"**Intent Patterns Found:** {', '.join(ci_patterns) if ci_patterns else 'Statistical Phishing Distribution'}")
                st.caption(ci_expl)
            else:
                st.success(f"✅ **Message Appears Clean.** (Risk: {ci_conf:.1f}%)")
                st.caption(ci_expl)

# ── Tab 2: Domain Infrastructure
with tab_infra:
    st.markdown("#### 🌐 Lookalike Domain, WHOIS Age & Redirect-Chain Inspector")
    st.caption("Compares domain mutations against brand allowlists using homoglyph mapping and Levenshtein distance, checks registration age, and traces HTTP redirect chains.")
    
    inf_c1, inf_c2 = st.columns([3, 1])
    with inf_c1:
        inf_url = st.text_input("Domain or URL to Inspect", value="http://paypa1-security-update.xyz/login")
    with inf_c2:
        inf_age_limit = st.number_input("Max Age Threshold (days)", min_value=1, max_value=365, value=30)
        
    if st.button("🚀 Run Full Domain Audit", use_container_width=True):
        with st.spinner("Analyzing homoglyphs, querying registration age, and probing redirect chain..."):
            dom_res = analyze_domain(inf_url, max_domain_age_days=inf_age_limit, fast_scan=False)
            res_c1, res_c2 = st.columns([1, 2])
            with res_c1:
                st.metric("Domain Verdict", "FLAGGED THREAT" if dom_res["flagged"] else "BENIGN")
                st.metric("Threat Confidence", f"{dom_res['confidence']:.1f}%")
                if dom_res["signals"]:
                    st.write("**Fired Signals:**")
                    for sig in dom_res["signals"]:
                        st.markdown(f"- 🔴 `{sig}`")
            with res_c2:
                st.write("**Technical Explanation:**")
                if dom_res["flagged"]:
                    st.error(dom_res["explanation"])
                else:
                    st.success(dom_res["explanation"])
                with st.expander("Detailed Telemetry Breakdown"):
                    st.json(dom_res["details"])

# ── Tab 3: Visual Page Similarity
with tab_visual:
    st.markdown("#### 🖼️ Visual Perceptual Hashing (Page Similarity)")
    st.caption("Compares screenshot perceptual hashes (pHash & dHash) against reference login templates to detect visual credential harvesting clones.")
    
    vis_c1, vis_c2 = st.columns([1, 1])
    with vis_c1:
        preset_choice = st.selectbox(
            "Select Reference Template or Upload Test Screenshot",
            options=[
                "Microsoft 365 Reference Template",
                "PayPal Reference Template",
                "Corporate Internal SSO Template",
                "Upload Custom Screenshot"
            ]
        )
        sim_threshold = st.slider("Similarity Threshold (%)", min_value=50.0, max_value=95.0, value=75.0, step=1.0)

        test_img = None
        if preset_choice == "Microsoft 365 Reference Template":
            p = "templates/reference_logins/microsoft365.png"
            if os.path.exists(p):
                test_img = Image.open(p)
        elif preset_choice == "PayPal Reference Template":
            p = "templates/reference_logins/paypal.png"
            if os.path.exists(p):
                test_img = Image.open(p)
        elif preset_choice == "Corporate Internal SSO Template":
            p = "templates/reference_logins/internal_sso_portal.png"
            if os.path.exists(p):
                test_img = Image.open(p)
        else:
            up_f = st.file_uploader("Upload Page Screenshot (.png, .jpg)", type=["png", "jpg", "jpeg"])
            if up_f:
                test_img = Image.open(up_f)

    with vis_c2:
        if test_img:
            st.image(test_img, caption="Loaded Screenshot Input", width=260)
            if st.button("🔍 Execute Perceptual Hash Match", use_container_width=True):
                vis_res = analyze_page_similarity(test_img, threshold=sim_threshold)
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
            st.info("Select or upload a screenshot to execute perceptual hash comparison.")

# ── Tab 4: Sender Behavioral Baseline
with tab_sender:
    st.markdown("#### 👤 Per-Account Sender Behavioral Baseline")
    st.caption("Maintains isolated Isolation Forest models per sender account, modeling sending hours, recipient domains, and stylistic tone to detect compromised accounts.")
    
    sb_c1, sb_c2 = st.columns([1, 1])
    with sb_c1:
        s_sender = st.text_input("Sender Account ID", value="sarah.jenkins@acme-corp.internal")
        s_hour = st.slider("Send Hour (24h)", min_value=0, max_value=23, value=3)
        s_recips = st.text_input("Recipient Addresses", value="all-staff@acme-corp.internal, offshore-dev@partner-vendor.com")
        s_att = st.checkbox("Includes Attachment", value=True)
        s_body = st.text_area("Message Body", value="Urgent: Updated Employee Bonus Compensation Schedule. Click and enter direct deposit.", height=80)
    with sb_c2:
        st.markdown("**Account Profile Baseline:**")
        st.caption("Sarah normally sends between 9 AM and 5 PM to internal HR colleagues with benign corporate documents.")
        if st.button("📊 Evaluate Baseline Deviation", use_container_width=True):
            s_feats = {"send_hour": s_hour, "recipients": s_recips, "has_attachment": s_att, "email_text": s_body}
            sb_out = analyze_sender_behavior(s_sender, s_feats)
            st.markdown("---")
            if sb_out["flagged"]:
                st.error(f"🚨 **Account Compromise Anomaly Detected!** Confidence: {sb_out['confidence']:.1f}%")
                st.write(sb_out["explanation"])
                for s in sb_out["signals"]:
                    st.markdown(f"- 🔴 `{s}`")
            else:
                st.success(f"✅ **Activity Conforms to Baseline.** Activity is normal for {s_sender}.")
                st.caption(sb_out["explanation"])

# ── Tab 5: Attachment & QR Inspection
with tab_attach:
    st.markdown("#### 📎 Attachment Screening & QR Quishing Scanner")
    st.caption("Screens for dangerous executable / script extensions and decodes embedded QR codes to inspect their destination links.")
    
    at_c1, at_c2 = st.columns([1, 1])
    with at_c1:
        at_name = st.text_input("Attachment Filename", value="remittance_advice_392.scr")
        up_qr = st.file_uploader("Upload Image to Screen for QR Code (optional)", type=["png", "jpg", "jpeg"])
    with at_c2:
        if st.button("🛡️ Run Attachment Payload Scan", use_container_width=True):
            at_res = analyze_attachment(at_name, file_bytes_or_path=up_qr)
            st.markdown("---")
            if at_res["flagged"]:
                st.error(f"⚠️ **Threat Found in Attachment!** Confidence: {at_res['confidence']:.1f}%")
                st.write(at_res["explanation"])
                for s in at_res["signals"]:
                    st.markdown(f"- 🔴 `{s}`")
            else:
                st.success("✅ **Attachment Payload Cleared.** No weaponized extensions or dangerous QR targets detected.")
                st.caption(at_res["explanation"])

# ── Tab 6: SOC Feedback Loop & Live Accuracy
with tab_feedback:
    st.markdown("#### 📊 SOC Analyst Feedback Loop & Live Accuracy")
    st.caption("Live metrics updated automatically whenever an analyst confirms a threat or overrides a false positive in the Threat Stream.")
    
    f_metrics = compute_live_feedback_metrics()
    fb_k1, fb_k2, fb_k3, fb_k4 = st.columns(4)
    with fb_k1:
        st.metric("Total Analyst Reviews", f"{f_metrics['total_reviews']}")
    with fb_k2:
        st.metric("Confirmed True Positives", f"{f_metrics['confirmed_count']}")
    with fb_k3:
        st.metric("Overridden False Positives", f"{f_metrics['false_positive_count']}")
    with fb_k4:
        st.metric("Live False Positive Rate", f"{f_metrics['false_positive_rate']:.1f}%")

    if f_metrics["records"]:
        st.markdown("**Analyst Decision Ledger:**")
        st.dataframe(pd.DataFrame(f_metrics["records"]), use_container_width=True)
    else:
        st.info("No analyst decisions logged yet. Use the 'Confirm Threat' or 'Override' buttons under Threat Intelligence Briefings to log decisions.")

# ── Clean Footer ─────────────────────────────────────────────────────────────
st.markdown("---")
st.markdown(
    f"<div style='text-align:center; color:#3a4a5a; font-size:0.8rem; font-family:\"JetBrains Mono\",monospace;'>"
    f"ARGUS DEFENSE PLATFORM // AI-POWERED PHISHING DETECTION FOR ORGANISATIONS • "
    f"MESSAGES EVALUATED: {len(df_events)} • {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    f"</div>",
    unsafe_allow_html=True,
)

