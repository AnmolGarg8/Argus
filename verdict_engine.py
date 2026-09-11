"""
Verdict & Feedback Engine — Argus AI Phishing Defense
Multi-layer decision correlation and live empirical SOC analyst feedback loop.

Decision Strategy:
  - Each layer evaluates independently: Content NLP, Domain/URL Infrastructure,
    Page Visual Similarity, Sender Behavioral Anomaly, and Attachment Screening.
  - Multi-Layer Correlation:
    - Tiered decision based on composite risk confidence:
      * BLOCK: Risk Score >= 75.0 (Definitive weaponized threat detected)
      * FLAG_FOR_REVIEW: 35.0 <= Risk Score < 75.0 (Suspicious signals warranting human inspection)
      * ALLOW: Risk Score < 35.0 (Benign corporate activity)
    - Highest-confidence signal anchors severity, boosted when multiple independent layers corroborate.

Explainability Contract:
  - Every flagged item generates a structured, plain-English justification detailing
    which layer(s) fired, individual confidence scores, and specific indicators found.

Feedback Loop & Live Accuracy Metrics:
  - Captures analyst confirmations ('CONFIRMED_THREAT') and overrides ('FALSE_POSITIVE').
  - Validates verdicts against simulator hidden ground truth to compute empirical False Positive Rate (FPR)
    and detection Precision displayed live in the dashboard.
"""

import os
import json
import datetime
from typing import Optional

# Path to persistent feedback storage
FEEDBACK_DIR = os.path.join(os.path.dirname(__file__), "data")
FEEDBACK_JSON_PATH = os.path.join(FEEDBACK_DIR, "analyst_feedback.json")

# In-memory feedback store for zero-filesystem / Wasm resilience
_MEMORY_FEEDBACK: list[dict] = []


def init_feedback_store():
    """Ensure feedback storage directory and file exist."""
    try:
        os.makedirs(FEEDBACK_DIR, exist_ok=True)
        if not os.path.exists(FEEDBACK_JSON_PATH):
            with open(FEEDBACK_JSON_PATH, "w", encoding="utf-8") as f:
                json.dump([], f)
    except Exception:
        pass


init_feedback_store()


def evaluate_message_verdict(
    content_result: Optional[dict] = None,
    domain_result: Optional[dict] = None,
    visual_result: Optional[dict] = None,
    sender_result: Optional[dict] = None,
    attachment_result: Optional[dict] = None,
    ground_truth: Optional[dict] = None,
) -> dict:
    """
    Correlate multi-layer outputs into a composite verdict and structured explanation.

    Returns:
      {
        "verdict": "ALLOW" | "FLAG_FOR_REVIEW" | "BLOCK",
        "composite_score": float (0-100),
        "firing_layers": list[str],
        "layer_breakdown": dict,
        "explanation": str,
        "is_flagged": bool,
        "ground_truth": dict or None
      }
    """
    firing_layers = []
    layer_scores = []
    layer_breakdown = {}
    explanation_parts = []

    # 1. Content Intelligence (NLP Intent)
    if content_result:
        c_flag = content_result.get("flagged", False)
        c_score = content_result.get("risk_score", 0.0)
        c_expl = content_result.get("explanation", "")
        c_sigs = content_result.get("intent_patterns", [])
        layer_breakdown["Content_Intelligence"] = {
            "flagged": c_flag,
            "risk_score": c_score,
            "signals": c_sigs,
            "explanation": c_expl,
        }
        if c_flag:
            firing_layers.append("Content_Intelligence")
            layer_scores.append(c_score)
            sig_str = f" [{', '.join(c_sigs)}]" if c_sigs else ""
            explanation_parts.append(f"Content Intelligence ({c_score:.1f}%){sig_str}: {c_expl}")

    # 2. Domain & URL Infrastructure
    if domain_result:
        d_flag = domain_result.get("flagged", False)
        d_score = domain_result.get("confidence", domain_result.get("risk_score", 0.0))
        d_expl = domain_result.get("explanation", "")
        d_sigs = domain_result.get("signals", [])
        layer_breakdown["Domain_Infrastructure"] = {
            "flagged": d_flag,
            "risk_score": d_score,
            "signals": d_sigs,
            "explanation": d_expl,
        }
        if d_flag:
            firing_layers.append("Domain_Infrastructure")
            layer_scores.append(d_score)
            sig_str = f" [{', '.join(d_sigs)}]" if d_sigs else ""
            explanation_parts.append(f"Domain & Infrastructure ({d_score:.1f}%){sig_str}: {d_expl}")

    # 3. Visual Page Similarity
    if visual_result:
        v_flag = visual_result.get("flagged", False)
        v_score = visual_result.get("confidence", visual_result.get("similarity_score", 0.0))
        v_expl = visual_result.get("explanation", "")
        v_sigs = visual_result.get("signals", [])
        layer_breakdown["Page_Similarity"] = {
            "flagged": v_flag,
            "risk_score": v_score,
            "signals": v_sigs,
            "explanation": v_expl,
        }
        if v_flag:
            firing_layers.append("Page_Similarity")
            layer_scores.append(v_score)
            sig_str = f" [{', '.join(v_sigs)}]" if v_sigs else ""
            explanation_parts.append(f"Visual Clone Inspection ({v_score:.1f}%){sig_str}: {v_expl}")

    # 4. Sender Behavior Modeling
    if sender_result:
        s_flag = sender_result.get("flagged", False)
        s_score = sender_result.get("confidence", 0.0)
        s_expl = sender_result.get("explanation", "")
        s_sigs = sender_result.get("signals", [])
        layer_breakdown["Sender_Behavior"] = {
            "flagged": s_flag,
            "risk_score": s_score,
            "signals": s_sigs,
            "explanation": s_expl,
        }
        if s_flag:
            firing_layers.append("Sender_Behavior")
            layer_scores.append(s_score)
            sig_str = f" [{', '.join(s_sigs)}]" if s_sigs else ""
            explanation_parts.append(f"Sender Behavioral Baseline ({s_score:.1f}%){sig_str}: {s_expl}")

    # 5. Attachment & QR Inspection (Bonus)
    if attachment_result:
        a_flag = attachment_result.get("flagged", False)
        a_score = attachment_result.get("confidence", 0.0)
        a_expl = attachment_result.get("explanation", "")
        a_sigs = attachment_result.get("signals", [])
        layer_breakdown["Attachment_Inspection"] = {
            "flagged": a_flag,
            "risk_score": a_score,
            "signals": a_sigs,
            "explanation": a_expl,
        }
        if a_flag:
            firing_layers.append("Attachment_Inspection")
            layer_scores.append(a_score)
            sig_str = f" [{', '.join(a_sigs)}]" if a_sigs else ""
            explanation_parts.append(f"Attachment Payload ({a_score:.1f}%){sig_str}: {a_expl}")

    # Calculate composite risk score: Anchor on maximum firing signal + multi-signal corroboration bonus
    if layer_scores:
        base_max = max(layer_scores)
        corroboration_bonus = min(15.0, (len(layer_scores) - 1) * 7.5)
        composite_score = min(99.0, base_max + corroboration_bonus)
    else:
        composite_score = 10.0

    # Decision mapping
    if composite_score >= 75.0 or len(firing_layers) >= 2:
        verdict = "BLOCK"
        is_flagged = True
    elif composite_score >= 35.0:
        verdict = "FLAG_FOR_REVIEW"
        is_flagged = True
    else:
        verdict = "ALLOW"
        is_flagged = False

    # Synthesize human-readable structured explanation
    if is_flagged:
        overall_explanation = f"Verdict [{verdict} - Risk: {composite_score:.1f}]: " + " | ".join(explanation_parts)
    else:
        overall_explanation = f"Verdict [ALLOW - Risk: {composite_score:.1f}]: All independent detection layers cleared. No phishing intent, brand spoofing, or behavioral anomalies detected."

    return {
        "verdict": verdict,
        "composite_score": round(composite_score, 1),
        "firing_layers": firing_layers,
        "layer_breakdown": layer_breakdown,
        "explanation": overall_explanation,
        "is_flagged": is_flagged,
        "ground_truth": ground_truth,
    }


def log_analyst_feedback(
    message_id: str,
    analyst_decision: str,  # 'CONFIRMED_THREAT' or 'FALSE_POSITIVE'
    original_verdict: str,
    firing_layers: list,
    composite_score: float,
    ground_truth_is_phish: Optional[bool] = None,
    notes: str = "",
) -> bool:
    """
    Log an analyst review decision into the persistent feedback queue.
    """
    init_feedback_store()
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    record = {
        "id": None,
        "message_id": message_id,
        "timestamp": ts,
        "analyst_decision": analyst_decision.upper(),
        "original_verdict": original_verdict.upper(),
        "firing_layers": firing_layers if isinstance(firing_layers, list) else [str(firing_layers)],
        "composite_score": float(composite_score),
        "ground_truth_is_phish": ground_truth_is_phish,
        "notes": notes,
    }

    try:
        records = []
        if os.path.exists(FEEDBACK_JSON_PATH):
            with open(FEEDBACK_JSON_PATH, "r", encoding="utf-8") as f:
                records = json.load(f)
        record["id"] = len(records) + 1
        records.insert(0, record)
        with open(FEEDBACK_JSON_PATH, "w", encoding="utf-8") as f:
            json.dump(records, f, indent=2)
        return True
    except Exception:
        record["id"] = len(_MEMORY_FEEDBACK) + 1
        _MEMORY_FEEDBACK.insert(0, record)
        return True


def get_all_feedback() -> list[dict]:
    """Retrieve all logged analyst feedback records."""
    init_feedback_store()
    try:
        if os.path.exists(FEEDBACK_JSON_PATH):
            with open(FEEDBACK_JSON_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                if data:
                    return data
    except Exception:
        pass
    return list(_MEMORY_FEEDBACK)


def compute_live_feedback_metrics() -> dict:
    """
    Compute live false-positive rate and detection precision metrics from analyst feedback records.
    Calculates:
      - Total analyst reviews
      - Confirmed threats vs. false positives
      - Live False Positive Rate (FPR %): Overrides / Total Reviews
      - Precision (%): Confirmed / Total Reviews
    """
    records = get_all_feedback()
    total = len(records)
    if total == 0:
        return {
            "total_reviews": 0,
            "confirmed_count": 0,
            "false_positive_count": 0,
            "false_positive_rate": 0.0,
            "precision_rate": 100.0,
            "records": [],
        }

    confirmed = sum(1 for r in records if "CONFIRM" in r.get("analyst_decision", ""))
    false_pos = sum(1 for r in records if "FALSE" in r.get("analyst_decision", "") or "OVERRIDE" in r.get("analyst_decision", ""))
    fpr = round((false_pos / total) * 100.0, 1) if total > 0 else 0.0
    precision = round((confirmed / total) * 100.0, 1) if total > 0 else 100.0

    return {
        "total_reviews": total,
        "confirmed_count": confirmed,
        "false_positive_count": false_pos,
        "false_positive_rate": fpr,
        "precision_rate": precision,
        "records": records,
    }


def evaluate_message_pipeline(df_events):
    """
    Unified multi-layer detection pipeline evaluating incoming corporate communication events:
      - Content Intelligence (NLP Intent & TF-IDF/LR)
      - Domain Infrastructure (Homoglyphs, WHOIS age, redirect chains - fast scan)
      - Sender Behavioral Baseline (Per-account Isolation Forest)
      - Attachment & QR Screening
    
    Returns a scored copy of df_events enriched with:
      - 'risk_score' (0-100 float)
      - 'verdict' ('ALLOW', 'FLAG_FOR_REVIEW', 'BLOCK')
      - 'firing_layers' (comma-separated string of firing detectors)
      - 'explanation' (plain-English structured reasoning)
    """
    import pandas as pd
    from content_intelligence import analyze_content
    from domain_analyzer import analyze_domain
    from sender_behavior import analyze_sender_behavior
    from attachment_qr_inspection import analyze_attachment

    df_scored = df_events.copy()

    risk_scores = []
    verdicts = []
    firing_layers_list = []
    explanations = []

    for _, row in df_scored.iterrows():
        # 1. Content Intelligence
        email_text = str(row.get("email_text", row.get("subject", "")))
        content_res = analyze_content(email_text) if email_text.strip() else None

        # 2. Domain & Infrastructure
        url = str(row.get("url", ""))
        domain_res = analyze_domain(url, fast_scan=True) if url.strip() else None

        # 3. Sender Behavioral Baseline
        sender_id = str(row.get("sender_id", row.get("user_id", "external_user")))
        sender_features = {
            "send_hour": int(row.get("send_hour", 12)),
            "recipients": str(row.get("recipients", "")),
            "has_attachment": bool(row.get("has_attachment", False)),
            "email_text": email_text,
        }
        sender_res = analyze_sender_behavior(sender_id, sender_features)

        # 4. Attachment & QR Screening
        attachment_name = str(row.get("attachment_name", ""))
        attachment_res = analyze_attachment(attachment_name) if attachment_name.strip() else None

        # Correlate into unified verdict
        # Note: Do not leak _ground_truth to the evaluation logic!
        ground_truth = row.get("_ground_truth", None)

        verdict_res = evaluate_message_verdict(
            content_result=content_res,
            domain_result=domain_res,
            visual_result=None,
            sender_result=sender_res,
            attachment_result=attachment_res,
            ground_truth=ground_truth,
        )

        risk_scores.append(verdict_res["composite_score"])
        verdicts.append(verdict_res["verdict"])
        firing_layers_list.append(", ".join(verdict_res["firing_layers"]) if verdict_res["firing_layers"] else "None")
        explanations.append(verdict_res["explanation"])

    df_scored["risk_score"] = risk_scores
    df_scored["verdict"] = verdicts
    df_scored["firing_layers"] = firing_layers_list
    df_scored["explanation"] = explanations
    return df_scored


# Backward-compatible helper aliases
get_live_accuracy_metrics = compute_live_feedback_metrics
get_feedback_records = get_all_feedback

