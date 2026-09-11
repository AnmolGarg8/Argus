"""
Risk Correlation & Decision Engine
Multi-layer threat architecture where each layer can independently flag threats.
Supports highest-confidence flag resolution and SQLite analyst feedback logging.
"""

import os
import json
import datetime
import numpy as np
import pandas as pd

# Safe import for sqlite3 (unavailable in Pyodide/stlite on Vercel)
try:
    import sqlite3
except ImportError:
    sqlite3 = None

# Paths to persistent analyst feedback databases
FEEDBACK_DB_PATH = os.path.join(os.path.dirname(__file__), "data", "analyst_feedback.db")
FEEDBACK_JSON_PATH = os.path.join(os.path.dirname(__file__), "data", "analyst_feedback.json")

# In-memory storage for environments where both SQLite and local file writes are restricted
_IN_MEMORY_FEEDBACK: list[dict] = []


def init_feedback_db():
    """Ensure feedback database and table exist (SQLite or JSON fallback)."""
    try:
        os.makedirs(os.path.dirname(FEEDBACK_DB_PATH), exist_ok=True)
    except Exception:
        pass

    if sqlite3 is not None:
        try:
            with sqlite3.connect(FEEDBACK_DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS analyst_feedback (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        incident_id TEXT,
                        timestamp TEXT,
                        analyst_decision TEXT,     -- 'CONFIRMED' or 'OVERRIDDEN'
                        layer_fired TEXT,          -- comma-separated layers
                        original_risk_level TEXT,
                        analyst_verdict TEXT,      -- 'MALICIOUS', 'BENIGN', 'FALSE_POSITIVE'
                        analyst_notes TEXT
                    )
                """)
                conn.commit()
            return
        except Exception:
            pass

    # JSON fallback initialization (for serverless/Wasm environments without sqlite3)
    try:
        if not os.path.exists(FEEDBACK_JSON_PATH):
            with open(FEEDBACK_JSON_PATH, "w", encoding="utf-8") as f:
                json.dump([], f)
    except Exception:
        pass


# Initialize table or fallback storage on load
init_feedback_db()


def log_analyst_feedback(
    incident_id: str,
    analyst_decision: str,
    layer_fired: str,
    original_risk_level: str,
    analyst_verdict: str,
    analyst_notes: str = "",
) -> bool:
    """Log an analyst confirm/override decision into the feedback database (SQLite or JSON fallback)."""
    init_feedback_db()
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    record = {
        "incident_id": incident_id,
        "timestamp": ts,
        "analyst_decision": analyst_decision.upper(),
        "layer_fired": layer_fired,
        "original_risk_level": original_risk_level.upper(),
        "analyst_verdict": analyst_verdict.upper(),
        "analyst_notes": analyst_notes,
    }

    # 1. Attempt SQLite first if module is available
    if sqlite3 is not None:
        try:
            with sqlite3.connect(FEEDBACK_DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO analyst_feedback (
                        incident_id, timestamp, analyst_decision, layer_fired,
                        original_risk_level, analyst_verdict, analyst_notes
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        incident_id,
                        ts,
                        record["analyst_decision"],
                        layer_fired,
                        record["original_risk_level"],
                        record["analyst_verdict"],
                        analyst_notes,
                    ),
                )
                conn.commit()
            return True
        except Exception:
            pass

    # 2. Fallback to persistent JSON storage
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
        # 3. Fallback to in-memory list
        record["id"] = len(_IN_MEMORY_FEEDBACK) + 1
        _IN_MEMORY_FEEDBACK.insert(0, record)
        return True


def get_feedback_records() -> list[dict]:
    """Retrieve all logged feedback records for live accuracy calculation (SQLite or JSON fallback)."""
    init_feedback_db()
    if sqlite3 is not None:
        try:
            with sqlite3.connect(FEEDBACK_DB_PATH) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM analyst_feedback ORDER BY id DESC")
                rows = cursor.fetchall()
                if rows:
                    return [dict(r) for r in rows]
        except Exception:
            pass

    # JSON fallback
    try:
        if os.path.exists(FEEDBACK_JSON_PATH):
            with open(FEEDBACK_JSON_PATH, "r", encoding="utf-8") as f:
                records = json.load(f)
                if records:
                    return records
    except Exception:
        pass

    return list(_IN_MEMORY_FEEDBACK)


def get_live_accuracy_metrics() -> dict:
    """Compute SOC analyst confirmation rate and accuracy metrics."""
    records = get_feedback_records()
    total = len(records)
    if total == 0:
        return {
            "total_reviews": 0,
            "confirmed_count": 0,
            "overridden_count": 0,
            "accuracy_rate": 100.0,
            "records": [],
        }

    confirmed = sum(1 for r in records if r["analyst_decision"] == "CONFIRMED")
    overridden = sum(1 for r in records if r["analyst_decision"] == "OVERRIDDEN")
    acc = round((confirmed / total) * 100.0, 1)

    return {
        "total_reviews": total,
        "confirmed_count": confirmed,
        "overridden_count": overridden,
        "accuracy_rate": acc,
        "records": records,
    }


def evaluate_multilayer_threat(
    content_result: dict = None,
    infra_result: dict = None,
    visual_result: dict = None,
    sender_result: dict = None,
    attachment_result: dict = None,
    anomaly_result: dict = None,
) -> dict:
    """
    Evaluate independent signals across detection layers.
    A single strong signal from any layer independently triggers an alert without
    being diluted by non-firing layers.

    Decision Strategy:
      - 'Highest confidence flag wins' for overall severity:
        confidence >= 85 -> CRITICAL
        confidence >= 70 -> HIGH
        confidence >= 45 -> MEDIUM
        otherwise       -> LOW
    """
    layers_evaluated = {}
    firing_layers = []
    max_confidence = 0.0

    # 1. Content / Phishing NLP Layer
    if content_result:
        p_prob = content_result.get("phishing_probability", 0.0)
        p_flag = p_prob >= 60.0
        conf = p_prob if p_flag else (100.0 - p_prob) * 0.2
        layers_evaluated["Content_NLP"] = {
            "flagged": p_flag,
            "confidence": round(conf, 1),
            "explanation": f"NLP model estimated {p_prob:.1f}% phishing probability." if p_flag else "Content vocabulary matches routine enterprise communication.",
            "signals": ["SUSPICIOUS_PHISHING_LANGUAGE"] if p_flag else [],
        }
        if p_flag:
            firing_layers.append("Content_NLP")
            max_confidence = max(max_confidence, conf)

    # 2. Infrastructure Analysis Layer
    if infra_result:
        layers_evaluated["Infrastructure"] = {
            "flagged": infra_result.get("flagged", False),
            "confidence": infra_result.get("confidence", 0.0),
            "explanation": infra_result.get("explanation", ""),
            "signals": infra_result.get("signals", []),
        }
        if infra_result.get("flagged"):
            firing_layers.append("Infrastructure")
            max_confidence = max(max_confidence, infra_result.get("confidence", 0.0))

    # 3. Page Visual Similarity Layer
    if visual_result:
        layers_evaluated["Page_Visual"] = {
            "flagged": visual_result.get("flagged", False),
            "confidence": visual_result.get("confidence", 0.0),
            "explanation": visual_result.get("explanation", ""),
            "signals": visual_result.get("signals", []),
        }
        if visual_result.get("flagged"):
            firing_layers.append("Page_Visual")
            max_confidence = max(max_confidence, visual_result.get("confidence", 0.0))

    # 4. Sender Behavior Layer
    if sender_result:
        layers_evaluated["Sender_Behavior"] = {
            "flagged": sender_result.get("flagged", False),
            "confidence": sender_result.get("confidence", 0.0),
            "explanation": sender_result.get("explanation", ""),
            "signals": sender_result.get("signals", []),
        }
        if sender_result.get("flagged"):
            firing_layers.append("Sender_Behavior")
            max_confidence = max(max_confidence, sender_result.get("confidence", 0.0))

    # 5. Attachment & QR Layer
    if attachment_result:
        layers_evaluated["Attachment_QR"] = {
            "flagged": attachment_result.get("flagged", False),
            "confidence": attachment_result.get("confidence", 0.0),
            "explanation": attachment_result.get("explanation", ""),
            "signals": attachment_result.get("signals", []),
        }
        if attachment_result.get("flagged"):
            firing_layers.append("Attachment_QR")
            max_confidence = max(max_confidence, attachment_result.get("confidence", 0.0))

    # 6. Telemetry Anomaly Layer
    if anomaly_result:
        a_flag = bool(anomaly_result.get("anomaly_flag", False))
        a_score = anomaly_result.get("anomaly_score", 0.0)
        layers_evaluated["Telemetry_Anomaly"] = {
            "flagged": a_flag,
            "confidence": round(a_score, 1),
            "explanation": f"Isolation Forest identified systemic telemetry anomaly (score: {a_score:.1f})." if a_flag else "Device telemetry within normal baseline variance.",
            "signals": ["SYSTEM_TELEMETRY_ANOMALY"] if a_flag else [],
        }
        if a_flag:
            firing_layers.append("Telemetry_Anomaly")
            max_confidence = max(max_confidence, a_score)

    # Derive overall Risk Level: Highest Confidence Flag Wins
    if max_confidence >= 85.0:
        risk_level = "CRITICAL"
    elif max_confidence >= 70.0:
        risk_level = "HIGH"
    elif max_confidence >= 45.0:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"
        max_confidence = max(15.0, max_confidence)

    # Multi-flag escalation boost
    if len(firing_layers) >= 3 and risk_level != "CRITICAL":
        risk_level = "CRITICAL"
        max_confidence = min(99.0, max_confidence + 10.0)

    overall_flagged = len(firing_layers) > 0

    return {
        "overall_flagged": overall_flagged,
        "risk_level": risk_level,
        "max_confidence": round(max_confidence, 1),
        "firing_layers": firing_layers,
        "layer_reports": layers_evaluated,
    }


def compute_risk_scores(df: pd.DataFrame) -> pd.DataFrame:
    """
    Compute composite risk scores for incoming telemetry batch.
    Uses multi-layer independent evaluation: the highest confidence flag
    from any detection layer determines the risk level, while preserving
    a quantitative risk_score and layer transparency.
    """
    result = df.copy()

    anomaly = result.get("anomaly_score", pd.Series(0.0, index=result.index))
    phishing = result.get("phishing_probability", pd.Series(0.0, index=result.index))
    ip_risk = result.get("ip_risk_score", pd.Series(0.0, index=result.index))

    scores = []
    levels = []
    layers_fired_col = []

    for idx, row in result.iterrows():
        a_score = float(anomaly.get(idx, 0.0))
        p_prob = float(phishing.get(idx, 0.0))
        ip_score = float(ip_risk.get(idx, 0.0))

        # Check for individual layer signals
        flags = []
        confidences = []

        # Content/Phishing signal
        if p_prob >= 55.0:
            flags.append("Content_NLP")
            confidences.append(p_prob)

        # Anomaly signal
        if a_score >= 60.0:
            flags.append("Telemetry_Anomaly")
            confidences.append(a_score)

        # IP Risk signal
        if ip_score >= 65.0:
            flags.append("Threat_Intel_IP")
            confidences.append(ip_score)

        if confidences:
            # Highest confidence flag wins
            winning_score = max(confidences)
            if len(confidences) > 1:
                winning_score = min(100.0, winning_score + 5.0 * (len(confidences) - 1))
        else:
            # Low baseline
            winning_score = max(a_score * 0.3, p_prob * 0.2, ip_score * 0.2, 10.0)

        winning_score = round(float(np.clip(winning_score, 0, 100)), 1)
        scores.append(winning_score)

        if winning_score >= 80:
            levels.append("CRITICAL")
        elif winning_score >= 65:
            levels.append("HIGH")
        elif winning_score >= 40:
            levels.append("MEDIUM")
        else:
            levels.append("LOW")

        layers_fired_col.append(", ".join(flags) if flags else "None")

    result["risk_score"] = scores
    result["risk_level"] = levels
    result["layers_fired"] = layers_fired_col

    return result


def get_response_action(risk_score: float) -> str:
    """Determine automated response based on risk score."""
    if risk_score > 85:
        return "ISOLATE_DEVICE"
    elif risk_score > 75:
        return "LOCK_ACCOUNT"
    elif risk_score > 60:
        return "GENERATE_ALERT"
    else:
        return "MONITOR"
