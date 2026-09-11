"""
Risk Correlation Engine
Combines anomaly, phishing, and IP risk signals into a unified risk score.
"""

import numpy as np
import pandas as pd


def compute_risk_scores(df):
    """
    Compute composite risk score from multiple signals.

    risk_score = 0.5 * anomaly_score + 0.3 * phishing_probability + 0.2 * ip_risk_score
    """
    result = df.copy()
    anomaly = result.get("anomaly_score", pd.Series(0, index=result.index))
    phishing = result.get("phishing_probability", pd.Series(0, index=result.index))
    ip_risk = result.get("ip_risk_score", pd.Series(0, index=result.index))

    result["risk_score"] = np.round(
        0.5 * anomaly + 0.3 * phishing + 0.2 * ip_risk, 1
    )
    result["risk_score"] = result["risk_score"].clip(0, 100)

    result["risk_level"] = pd.cut(
        result["risk_score"],
        bins=[-1, 30, 55, 75, 100],
        labels=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
    )
    return result


def get_response_action(risk_score):
    """Determine automated response based on risk score."""
    if risk_score > 85:
        return "ISOLATE_DEVICE"
    elif risk_score > 75:
        return "LOCK_ACCOUNT"
    elif risk_score > 60:
        return "GENERATE_ALERT"
    else:
        return "MONITOR"
