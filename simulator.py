"""
Argus — Synthetic Enterprise Communications & Phishing Telemetry Generator
Generates realistic corporate email and message streams with hidden ground-truth
labels to evaluate multi-layer phishing detection accuracy, false positive rates,
and explainability.
"""

import random
import datetime
import pandas as pd
from typing import List, Dict, Tuple, Any

# Standard corporate departments & accounts
DEPARTMENTS = ["Finance", "Engineering", "HR", "Sales", "Legal", "Executive", "Operations"]

INTERNAL_DOMAIN = "acme-corp.internal"

NORMAL_USERS = [
    ("sarah.jenkins@acme-corp.internal", "HR", 9, 17),
    ("david.chen@acme-corp.internal", "Engineering", 10, 19),
    ("elena.rostova@acme-corp.internal", "Finance", 8, 17),
    ("marcus.vance@acme-corp.internal", "Executive", 8, 18),
    ("rachel.adams@acme-corp.internal", "Legal", 9, 18),
    ("kevin.wright@acme-corp.internal", "Sales", 8, 20),
    ("priya.patel@acme-corp.internal", "Operations", 9, 17),
]

# Normal corporate email templates
BENIGN_TEMPLATES = [
    {
        "subject": "Quarterly Planning Sync - Agenda & Notes",
        "text": "Hi team, please review the attached slides before tomorrow's Q3 planning session at 10 AM. Let me know if any items should be added to the backlog.",
        "url": "https://wiki.acme-corp.internal/planning/q3",
        "attachment": "q3_planning_deck.pdf",
    },
    {
        "subject": "Updated Expense Policy Guidelines",
        "text": "Please note that all travel and meal receipts for client meetings must now be submitted through the internal expensing portal by the last business day of the month.",
        "url": "https://portal.acme-corp.internal/expenses",
        "attachment": "",
    },
    {
        "subject": "Code Review: PR #1042 - Auth Token Refresh",
        "text": "Hey David, when you have a moment, could you take a look at the pull request for the session timeout handler? We want to merge before the staging freeze.",
        "url": "https://github.com/acme-org/backend-service/pull/1042",
        "attachment": "",
    },
    {
        "subject": "Welcome our new Data Science hire!",
        "text": "Everyone please join me in welcoming Liam to the analytics team starting Monday. We will do a team coffee walk at 2 PM.",
        "url": "",
        "attachment": "",
    },
    {
        "subject": "Office Facilities Maintenance Window",
        "text": "HVAC filter replacement is scheduled for Saturday 8 AM to 12 PM on floors 4 and 5. Noise will be minimal but access may be restricted.",
        "url": "https://intranet.acme-corp.internal/facilities",
        "attachment": "maintenance_schedule.pdf",
    },
    {
        "subject": "Vendor Contract Draft for Review",
        "text": "Attached is the redlined version of the Cloudflare SLA renewal contract. Please review Section 4 regarding data sovereignty before we sign.",
        "url": "https://drive.acme-corp.internal/legal/cloudflare_sla.pdf",
        "attachment": "cloudflare_sla_v2_clean.pdf",
    },
    {
        "subject": "Weekly Standup Notes & Blockers",
        "text": "Summary of today's sync: billing service deployment was successful. Marcus is following up with enterprise tier customer on SSO setup.",
        "url": "https://slack.acme-corp.internal/archives/eng-sync",
        "attachment": "",
    }
]

# Phishing and attack scenarios
ATTACK_SCENARIOS = [
    {
        "vector": "credential_harvesting_lookalike",
        "subject": "URGENT: Microsoft 365 Password Expiration Notice",
        "text": "FINAL NOTICE: Your enterprise Microsoft 365 password expires in 2 hours. Access to corporate mail and OneDrive will be terminated unless verified immediately.",
        "url": "http://login.micros0ft-online-verify.com/auth/login",
        "sender": "no-reply@micros0ft-online-verify.com",
        "recipients": "sarah.jenkins@acme-corp.internal, all-staff@acme-corp.internal",
        "attachment": "",
        "is_phishing": True,
    },
    {
        "vector": "brand_homoglyph_paypal",
        "subject": "Account Suspension Warning: Suspicious Wire Transfer",
        "text": "Security Alert: An unauthorized transaction of $4,850.00 was attempted from your corporate card. Verify your credentials immediately to halt payment.",
        "url": "http://paypa1-security-update.xyz/login",
        "sender": "fraud-prevention@paypa1-security-update.xyz",
        "recipients": "elena.rostova@acme-corp.internal",
        "attachment": "transaction_hold_notice.pdf",
        "is_phishing": True,
    },
    {
        "vector": "executive_wire_fraud",
        "subject": "Strictly Confidential - Immediate Wire Settlement",
        "text": "Elena, I am currently in an offsite executive board meeting with limited voice connectivity. We need an urgent wire transfer of $142,500 executed today for an unannounced acquisition. Do not discuss with team. Reply with confirmation.",
        "url": "http://secure-wire-clearing.net/settlement/form",
        "sender": "marcus.vance@acme-corp-executive.com",
        "recipients": "elena.rostova@acme-corp.internal",
        "attachment": "wire_instructions_confidential.pdf",
        "is_phishing": True,
    },
    {
        "vector": "compromised_internal_account",
        "subject": "Urgent: Updated Employee Bonus Compensation Schedule",
        "text": "Team, management has approved mid-year retention bonuses. Review your revised allocation and enter your direct deposit credentials on the compensation portal within 24 hours.",
        "url": "http://portal-acme-payroll.biz/login",
        "sender": "sarah.jenkins@acme-corp.internal",  # Real internal user compromised!
        "recipients": "all-staff@acme-corp.internal, offshore-dev@partner-vendor.com",
        "attachment": "bonus_calc_macro.xlsm",
        "is_phishing": True,
        "anomalous_hour": 3,  # 3 AM off-hours anomaly
    },
    {
        "vector": "malicious_attachment_executable",
        "subject": "Overdue Invoice #INV-88392 Payment Required",
        "text": "Please find attached the signed purchase order and overdue remittance voucher. Execute payment immediately to prevent vendor service disconnection.",
        "url": "http://vendor-invoice-storage.cloud/download",
        "sender": "billing@cloud-billing-solutions.info",
        "recipients": "elena.rostova@acme-corp.internal, david.chen@acme-corp.internal",
        "attachment": "invoice_88392_remittance.scr",
        "is_phishing": True,
    },
    {
        "vector": "qr_code_quishing",
        "subject": "Mandatory Duo Two-Factor Authentication Reset",
        "text": "IT Security policy update: Our Multi-Factor Authentication token has been revoked. Scan the attached QR code with your mobile camera to re-enroll your authenticator app immediately.",
        "url": "http://authenticator-sync-mfa.tk/qr-verify",
        "sender": "it-support@authenticator-sync-mfa.tk",
        "recipients": "david.chen@acme-corp.internal, rachel.adams@acme-corp.internal",
        "attachment": "mfa_enrollment_qr.png",
        "is_phishing": True,
    },
    {
        "vector": "it_admin_impersonation",
        "subject": "URGENT ACTION: VPN Security Certificate Expired",
        "text": "IT Helpdesk alert: Your remote work VPN certificate expired at 00:00 UTC. To maintain access to internal corporate databases, click below and authenticate with your network credentials.",
        "url": "http://vpn-acme-portal.tk/sso/login",
        "sender": "helpdesk@acme-internal-support.xyz",
        "recipients": "david.chen@acme-corp.internal, priya.patel@acme-corp.internal",
        "attachment": "vpn_fix_patch.iso",
        "is_phishing": True,
    },
]


def generate_enterprise_stream(n: int = 60, attack_ratio: float = 0.35) -> pd.DataFrame:
    """
    Generate a realistic stream of enterprise communications with hidden ground-truth labels.
    
    Parameters:
    - n: Total number of messages to generate.
    - attack_ratio: Proportion of simulated phishing/attack messages.
    
    Returns:
    - pd.DataFrame containing communications telemetry and a strictly separated
      `_ground_truth` dictionary column for post-verdict empirical validation.
    """
    records = []
    now = datetime.datetime.now()
    
    n_attacks = int(n * attack_ratio)
    n_benign = n - n_attacks
    
    # Generate Benign Records
    for i in range(n_benign):
        sender_email, dept, start_h, end_h = random.choice(NORMAL_USERS)
        template = random.choice(BENIGN_TEMPLATES)
        
        # Senders normally operate during their business hours
        send_hour = random.randint(start_h, end_h)
        delta_minutes = random.randint(5, 720)
        timestamp = (now - datetime.timedelta(minutes=delta_minutes)).strftime("%Y-%m-%d %H:%M:%S")
        
        recip_pool = [u[0] for u in NORMAL_USERS if u[0] != sender_email]
        recipients = ", ".join(random.sample(recip_pool, k=random.randint(1, 2)))
        
        records.append({
            "id": f"MSG-{1000 + i}",
            "timestamp": timestamp,
            "sender_id": sender_email,
            "department": dept,
            "send_hour": send_hour,
            "subject": template["subject"],
            "email_text": template["text"],
            "url": template["url"],
            "has_attachment": bool(template["attachment"]),
            "attachment_name": template["attachment"],
            "recipients": recipients,
            "_ground_truth": {
                "is_phishing": False,
                "vector": "benign_corporate",
            }
        })
        
    # Generate Phishing / Attack Records
    for j in range(n_attacks):
        scenario = random.choice(ATTACK_SCENARIOS)
        delta_minutes = random.randint(2, 360)
        timestamp = (now - datetime.timedelta(minutes=delta_minutes)).strftime("%Y-%m-%d %H:%M:%S")
        
        if scenario.get("vector") == "compromised_internal_account":
            send_hour = scenario.get("anomalous_hour", 3)
            sender_id = scenario["sender"]
            dept = "HR"
        else:
            send_hour = random.randint(0, 23)
            sender_id = scenario["sender"]
            dept = "External"
            
        records.append({
            "id": f"MSG-{2000 + j}",
            "timestamp": timestamp,
            "sender_id": sender_id,
            "department": dept,
            "send_hour": send_hour,
            "subject": scenario["subject"],
            "email_text": scenario["text"],
            "url": scenario["url"],
            "has_attachment": bool(scenario["attachment"]),
            "attachment_name": scenario["attachment"],
            "recipients": scenario["recipients"],
            "_ground_truth": {
                "is_phishing": scenario["is_phishing"],
                "vector": scenario["vector"],
            }
        })
        
    random.shuffle(records)
    return pd.DataFrame(records)


def get_training_emails() -> Tuple[List[str], List[int]]:
    """
    Return corporate training dataset of text and binary labels for model re-training.
    """
    texts = []
    labels = []
    
    for t in BENIGN_TEMPLATES:
        texts.append(f"{t['subject']}. {t['text']}")
        labels.append(0)
        
    for a in ATTACK_SCENARIOS:
        texts.append(f"{a['subject']}. {a['text']}")
        labels.append(1)
        
    # Data augmentation for robust baseline
    augmented_texts = list(texts)
    augmented_labels = list(labels)
    for _ in range(3):
        for text, label in zip(texts, labels):
            words = text.split()
            if len(words) > 6:
                sample_words = words[:]
                idx1, idx2 = random.sample(range(len(sample_words)), 2)
                sample_words[idx1], sample_words[idx2] = sample_words[idx2], sample_words[idx1]
                augmented_texts.append(" ".join(sample_words))
                augmented_labels.append(label)
                
    return augmented_texts, augmented_labels


if __name__ == "__main__":
    df = generate_enterprise_stream(n=10)
    print(f"Generated {len(df)} enterprise messages.")
    print("Sample record:")
    print(df.iloc[0].to_dict())

