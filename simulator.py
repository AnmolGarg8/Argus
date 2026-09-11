"""
Synthetic Log & Attack Simulation Engine
Generates realistic cybersecurity telemetry for the XDR system.
"""

import random
import string
import datetime
import pandas as pd
import numpy as np


NORMAL_EMAILS = [
    "Hi team, please find the quarterly report attached. Let me know if you have questions.",
    "Reminder: Staff meeting tomorrow at 10 AM in conference room B.",
    "The new parking policy takes effect next Monday. See attached memo.",
    "Could you review the budget proposal and send feedback by Friday?",
    "IT maintenance window scheduled for Saturday 2-6 AM. Expect brief outages.",
    "Happy birthday! The team got you a cake in the break room.",
    "Please submit your timesheets by end of day Thursday.",
    "Congratulations on the successful project launch last week!",
    "Attached is the updated employee handbook for your review.",
    "The water fountain on floor 3 is fixed. Thanks for your patience.",
    "Weekly sync notes from today's standup are in the shared drive.",
    "Reminder to complete your annual cybersecurity awareness training.",
    "New printer installed on floor 2. Driver instructions attached.",
    "Team lunch this Friday at noon. RSVP by Wednesday.",
    "Please update your emergency contact information in the HR portal.",
]

PHISHING_EMAILS = [
    "URGENT: Your account has been compromised! Click here immediately to verify your identity: http://secure-login.xyz/verify",
    "You have won a $1000 gift card! Claim now before it expires: http://free-rewards.biz/claim",
    "Your password expires in 24 hours. Reset it NOW at http://password-update.tk/reset to avoid lockout.",
    "ALERT: Unauthorized login detected on your account. Confirm your credentials here: http://account-secure.cc/login",
    "Invoice #38291 attached. Payment overdue - wire transfer required immediately to avoid penalties.",
    "Dear employee, IT requires you to re-enter your credentials at http://internal-portal.ml/auth for system upgrade.",
    "ACTION REQUIRED: Your direct deposit information needs verification. Update at http://hr-payroll.ga/update",
    "Your package could not be delivered. Track and reschedule at http://delivery-update.tk/track",
    "CEO has approved your expense claim. Download receipt from http://finance-docs.xyz/download",
    "Security Notice: Multiple failed login attempts. Verify your account or it will be suspended: http://verify-now.cc",
    "Congratulations! You've been selected for a salary bonus. Fill form at http://bonus-claim.ml/form",
    "IMMEDIATE ACTION: Tax refund of $3,247 pending. Submit details at http://irs-refund.biz/submit",
    "Your cloud storage is 98% full. Upgrade free at http://cloud-upgrade.tk/free",
    "Board meeting documents attached. Password: company123. Open immediately.",
    "HR Update: New remote work policy requires VPN re-registration at http://vpn-setup.ga/register",
]

DEPARTMENTS = ["Finance", "IT", "Public Works", "Police", "Fire", "City Council", "Parks & Rec", "Water Utility", "HR", "Legal"]
DEVICE_TYPES = ["workstation", "laptop", "mobile", "server", "iot_sensor"]


def _random_ip():
    return f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"


def _random_user_id(dept=None):
    dept = dept or random.choice(DEPARTMENTS)
    prefix = dept[:3].lower()
    num = random.randint(100, 999)
    return f"{prefix}_{num}", dept


def _random_device_id():
    dtype = random.choice(DEVICE_TYPES)
    return f"{dtype}-{random.randint(1000,9999)}", dtype


def generate_normal_activity(n=50):
    """Generate normal baseline telemetry logs."""
    records = []
    now = datetime.datetime.now()
    for i in range(n):
        user_id, dept = _random_user_id()
        device_id, device_type = _random_device_id()
        login_hour = random.choice(list(range(7, 19)))  # business hours
        records.append({
            "timestamp": (now - datetime.timedelta(minutes=random.randint(0, 1440))).isoformat(),
            "user_id": user_id,
            "department": dept,
            "login_hour": login_hour,
            "failed_attempts": random.choices([0, 0, 0, 1], weights=[70, 10, 10, 10])[0],
            "ip_address": _random_ip(),
            "ip_risk_score": round(random.uniform(0, 25), 1),
            "email_text": random.choice(NORMAL_EMAILS),
            "device_id": device_id,
            "device_type": device_type,
            "bytes_transferred": random.randint(100, 50000),
            "event_type": "normal",
        })
    return pd.DataFrame(records)


def simulate_phishing_attack(n=10):
    """Simulate a phishing campaign targeting municipal employees."""
    records = []
    now = datetime.datetime.now()
    for i in range(n):
        user_id, dept = _random_user_id()
        device_id, device_type = _random_device_id()
        login_hour = random.randint(0, 23)
        records.append({
            "timestamp": now.isoformat(),
            "user_id": user_id,
            "department": dept,
            "login_hour": login_hour,
            "failed_attempts": random.randint(0, 2),
            "ip_address": _random_ip(),
            "ip_risk_score": round(random.uniform(30, 80), 1),
            "email_text": random.choice(PHISHING_EMAILS),
            "device_id": device_id,
            "device_type": device_type,
            "bytes_transferred": random.randint(500, 20000),
            "event_type": "phishing",
        })
    return pd.DataFrame(records)


def simulate_credential_breach(n=8):
    """Simulate brute-force credential stuffing attack."""
    records = []
    now = datetime.datetime.now()
    target_user, dept = _random_user_id()
    for i in range(n):
        device_id, device_type = _random_device_id()
        login_hour = random.choice([0, 1, 2, 3, 4, 22, 23])  # off-hours
        records.append({
            "timestamp": (now - datetime.timedelta(seconds=random.randint(0, 300))).isoformat(),
            "user_id": target_user,
            "department": dept,
            "login_hour": login_hour,
            "failed_attempts": random.randint(5, 20),
            "ip_address": _random_ip(),
            "ip_risk_score": round(random.uniform(60, 100), 1),
            "email_text": random.choice(NORMAL_EMAILS),
            "device_id": device_id,
            "device_type": device_type,
            "bytes_transferred": random.randint(50, 500),
            "event_type": "credential_breach",
        })
    return pd.DataFrame(records)


def simulate_insider_threat(n=6):
    """Simulate insider data exfiltration behavior."""
    records = []
    now = datetime.datetime.now()
    user_id, dept = _random_user_id()
    device_id, device_type = _random_device_id()
    for i in range(n):
        login_hour = random.choice([0, 1, 2, 3, 22, 23])
        records.append({
            "timestamp": (now - datetime.timedelta(minutes=random.randint(0, 120))).isoformat(),
            "user_id": user_id,
            "department": dept,
            "login_hour": login_hour,
            "failed_attempts": random.randint(0, 2),
            "ip_address": _random_ip(),
            "ip_risk_score": round(random.uniform(20, 60), 1),
            "email_text": random.choice(NORMAL_EMAILS),
            "device_id": device_id,
            "device_type": device_type,
            "bytes_transferred": random.randint(500000, 5000000),  # large transfers
            "event_type": "insider_threat",
        })
    return pd.DataFrame(records)


def get_training_emails():
    """Return labeled email data for phishing model training."""
    emails = []
    labels = []
    for e in NORMAL_EMAILS:
        emails.append(e)
        labels.append(0)
    for e in PHISHING_EMAILS:
        emails.append(e)
        labels.append(1)
    # augment with variations
    for _ in range(3):
        for e in NORMAL_EMAILS:
            words = e.split()
            random.shuffle(words)
            emails.append(" ".join(words))
            labels.append(0)
        for e in PHISHING_EMAILS:
            words = e.split()
            random.shuffle(words)
            emails.append(" ".join(words))
            labels.append(1)
    return emails, labels
