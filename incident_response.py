"""
Incident Response Module
Generates incident summaries and simulates containment actions.
"""

import datetime
import random
from risk_engine import get_response_action


def generate_incident_summary(row):
    """Generate an AI-style incident summary for a high-risk event."""
    action = get_response_action(row["risk_score"])
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    action_descriptions = {
        "ISOLATE_DEVICE": f"Device {row.get('device_id', 'N/A')} has been isolated from the network. "
                          f"All active sessions terminated. Network ACLs updated to block device MAC address.",
        "LOCK_ACCOUNT": f"Account {row['user_id']} has been locked. "
                        f"Active tokens revoked. Password reset required via verified channel.",
        "GENERATE_ALERT": f"Alert dispatched to SOC team. "
                          f"Event queued for priority review. Monitoring escalated to 1-minute intervals.",
        "MONITOR": f"Event logged for baseline monitoring. No immediate action required.",
    }

    threat_types = {
        "phishing": "Phishing Campaign",
        "credential_breach": "Credential Stuffing Attack",
        "insider_threat": "Insider Data Exfiltration",
        "normal": "Anomalous Behavior",
    }
    event_type = row.get("event_type", "normal")
    threat_label = threat_types.get(event_type, "Unknown Threat")

    summary = (
        f"═══ INCIDENT REPORT ═══\n"
        f"Timestamp     : {ts}\n"
        f"Incident ID   : INC-{random.randint(10000, 99999)}\n"
        f"Threat Type   : {threat_label}\n"
        f"Risk Score    : {row['risk_score']:.1f}/100 [{row['risk_level']}]\n"
        f"Affected User : {row['user_id']} ({row.get('department', 'N/A')})\n"
        f"Device        : {row.get('device_id', 'N/A')}\n"
        f"Source IP     : {row.get('ip_address', 'N/A')}\n"
        f"───────────────────────\n"
        f"ANOMALY SCORE : {row.get('anomaly_score', 0):.1f}\n"
        f"PHISHING PROB : {row.get('phishing_probability', 0):.1f}%\n"
        f"IP RISK       : {row.get('ip_risk_score', 0):.1f}\n"
        f"───────────────────────\n"
        f"ACTION TAKEN  : {action}\n"
        f"{action_descriptions[action]}\n"
        f"═══════════════════════\n"
    )
    return summary, action


def process_incidents(df):
    """Process all events, generate incidents for high-risk ones."""
    incidents = []
    for _, row in df.iterrows():
        if row["risk_score"] > 60:
            summary, action = generate_incident_summary(row)
            incidents.append({
                "user_id": row["user_id"],
                "department": row.get("department", "N/A"),
                "risk_score": row["risk_score"],
                "risk_level": str(row["risk_level"]),
                "action": action,
                "summary": summary,
                "event_type": row.get("event_type", "normal"),
                "timestamp": row.get("timestamp", datetime.datetime.now().isoformat()),
            })
    return incidents
