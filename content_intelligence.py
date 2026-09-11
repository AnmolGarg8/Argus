"""
Content Intelligence Module — Argus AI Phishing Defense
NLP-based intent detection analyzing message bodies for:
  - Urgency & coercion framing ("immediate action required", "account suspension within 24h")
  - Authority impersonation ("IT Security Helpdesk", "Executive Leadership", "HR Compliance")
  - Credential harvesting prompts ("verify password", "confirm login details", "session expired")
  - Financial/wire redirection ("wire payment immediately", "update payroll direct deposit")

Architecture:
  - TF-IDF Vectorizer + Logistic Regression classifier trained on high-signal phishing intent vs. normal corporate correspondence.
  - Heuristic intent pattern extraction providing explainable, plain-English justifications for analyst verification.
"""

import re
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression


# Labeled training corpus: Phishing intent vs. Legitimate corporate communications
_TRAINING_CORPUS = [
    # ── Phishing: Credential Harvesting & Account Suspension ────────────────
    ("URGENT: Your Microsoft 365 password expires today. Click here to verify your account credentials immediately or access will be revoked.", 1),
    ("Action Required: Unauthorized sign-in attempt detected from IP 192.168.1.1. Confirm your identity to prevent account lockout.", 1),
    ("Security Alert: Your corporate email mailbox has exceeded storage quota. Re-authenticate your session at the link to restore access.", 1),
    ("Final Notice: Multi-factor authentication reset requested for your profile. Login here to cancel this unauthorized request.", 1),
    ("IT Helpdesk Notice: We are migrating email servers. Enter your current password and domain username to keep your mailbox active.", 1),
    ("Critical Security Update: Security certificate update required for your workstation. Click the portal link and enter your credentials.", 1),
    ("Google Workspace Alert: Suspicious activity detected on your account. Review security events and confirm your login details now.", 1),
    ("Your payroll portal account is locked. Verify your credentials within 2 hours to prevent disruption to your direct deposit.", 1),
    ("Urgent: VPN access certificate expired. Re-authenticate via the internal portal link to continue connecting to company servers.", 1),
    ("System Administrator: Mandatory security check required for all employees today. Verify your user credentials immediately.", 1),

    # ── Phishing: Authority Impersonation & Executive Wire Fraud ────────────
    ("From the Office of the CEO: I am currently in an executive meeting with board members. I need you to process an urgent wire transfer.", 1),
    ("Confidential Request from Executive Director: Please purchase 10 Apple gift cards for the client appreciation event and send codes.", 1),
    ("HR Compliance Alert: Mandatory harassment policy update document attached. Review and sign via the external link before end of day.", 1),
    ("Legal Department Notice: You have been named in a confidential arbitration proceeding. Download and review the attached summons immediately.", 1),
    ("From Chief Financial Officer: Please review the attached invoice from our vendor and wire payment to the updated account number today.", 1),
    ("Executive Leadership: Do not call my cell as I am in an all-day conference. Process the attached international wire transfer right away.", 1),
    ("Internal Audit Committee: Discrepancy identified in your department expense reports. Enter your credentials on the audit portal.", 1),
    ("Payroll Department: We are updating employee banking details for the upcoming cycle. Confirm your bank account and routing number.", 1),
    ("Urgent message from IT Director: Critical malware detected on your corporate laptop. Follow the link to install the remote cleanup utility.", 1),
    ("HR Department: Your annual performance review summary is available. Enter your domain credentials to view your compensation adjustment.", 1),

    # ── Phishing: Urgent Financial & Invoice Fraud ───────────────────────────
    ("OVERDUE INVOICE #94821: Payment was due 3 days ago. Click here to pay immediately and avoid 25% penalty fee and legal action.", 1),
    ("Wire Transfer Confirmation: Payment of $42,500 pending approval. If you did not authorize this, cancel the transaction immediately here.", 1),
    ("Vendor Banking Change: Please note our account number has changed. Update all pending invoices to the new routing details attached.", 1),
    ("Immediate Action: Tax refund documentation ready for processing. Submit your company tax ID and banking credentials to release funds.", 1),
    ("Payment Failure Notification: Your corporate credit card transaction failed. Update your billing details now to prevent service interruption.", 1),

    # ── Legitimate: Routine Enterprise Communications ───────────────────────
    ("Hi team, sharing the weekly engineering standup notes and sprint backlog items. Let me know if you have any questions.", 0),
    ("Quarterly roadmap planning session scheduled for this Thursday at 2 PM in Conference Room C. Please review the deck beforehand.", 0),
    ("Thanks for the feedback on the pull request. I have addressed the review comments and added the requested unit tests.", 0),
    ("Please find the meeting minutes from yesterday's product sync attached for your reference.", 0),
    ("Reminder: Departmental timesheet submission window closes on Friday at 5:00 PM. Have a great weekend everyone.", 0),
    ("The enterprise project timeline has been updated on the shared drive. Let me know if your team needs additional resources.", 0),
    ("Could you review the updated proposal when you have a chance? No rush, sometime before next Tuesday would be great.", 0),
    ("Lunch and learn presentation on cloud architecture patterns this Friday at noon. Pizza will be provided in the cafeteria.", 0),
    ("Hey Sarah, do you have 10 minutes this afternoon for a quick sync regarding the Q3 budget estimates?", 0),
    ("Attached is the draft report for the upcoming stakeholder presentation. Looking forward to your input and suggestions.", 0),
    ("The design system documentation has been updated with the new color palette tokens. Check it out on the wiki.", 0),
    ("Team, congratulations on successfully completing the customer onboarding milestone ahead of schedule!", 0),
    ("Please remember to complete the annual benefits enrollment survey before the end of the month if you wish to change plans.", 0),
    ("Customer feedback from last week's beta release has been compiled into the spreadsheet linked in the project channel.", 0),
    ("Quick heads up: Scheduled network maintenance in the Chicago office this Saturday from 2 AM to 6 AM.", 0),
    ("Here are the slides from today's all-hands meeting for anyone who was unable to attend live.", 0),
    ("Great presentation today! Could you share the reference links you mentioned regarding the API architecture?", 0),
    ("The marketing team is looking for 2 engineering volunteers to review technical blog posts next week.", 0),
    ("All-hands retrospective will take place tomorrow at 10 AM. Please add your discussion topics to the shared document.", 0),
    ("Thank you for submitting your travel expense report. It has been approved and forwarded to accounting for reimbursement.", 0),
]

# High-signal intent heuristics
_INTENT_PATTERNS = {
    "URGENCY_PRESSURE": [
        r"\b(?:urgent|immediately|action required|final notice|critical|within \d+ hours?|expir(?:es?|ing) today|act now|suspended?|locked out)\b",
        r"\b(?:without delay|immediate response|penalty|legal action|consequences)\b",
    ],
    "AUTHORITY_IMPERSONATION": [
        r"\b(?:office of the ceo|executive director|it helpdesk|it security|system administrator|payroll department|hr compliance|legal department|cfo|chief financial officer)\b",
        r"\b(?:management request|board of directors|audit committee|compliance team)\b",
    ],
    "CREDENTIAL_REQUEST": [
        r"\b(?:verify your (?:account|identity|credentials|password)|re-authenticate|enter your password|confirm your login|sign-?in to verify)\b",
        r"\b(?:login details|domain username|reset (?:password|credentials|mfa)|access revoked)\b",
    ],
    "FINANCIAL_ACTION": [
        r"\b(?:wire transfer|wire payment|gift cards?|update banking|direct deposit|overdue invoice|routing number|release funds)\b",
        r"\b(?:unauthorized transaction|billing details|payroll routing)\b",
    ],
}


class ContentIntelligenceClassifier:
    """TF-IDF + Logistic Regression NLP classifier with intent pattern extraction."""

    def __init__(self):
        self.vectorizer = TfidfVectorizer(ngram_range=(1, 2), max_features=1200, stop_words="english")
        self.model = LogisticRegression(C=2.0, max_iter=300, random_state=42)
        self.is_trained = False

    def train(self):
        texts = [text for text, _ in _TRAINING_CORPUS]
        labels = [label for _, label in _TRAINING_CORPUS]
        X = self.vectorizer.fit_transform(texts)
        self.model.fit(X, labels)
        self.is_trained = True

    def extract_intent_patterns(self, text: str) -> list[str]:
        """Detect specific intent indicators via regex pattern matching."""
        detected = []
        text_lower = text.lower()
        for intent_name, patterns in _INTENT_PATTERNS.items():
            if any(re.search(pat, text_lower) for pat in patterns):
                detected.append(intent_name)
        return detected

    def predict(self, text: str) -> dict:
        """
        Analyze text for phishing intent.
        Returns:
          {
            "risk_score": float (0-100),
            "phishing_probability": float (0.0-1.0),
            "intent_patterns": list[str],
            "flagged": bool,
            "explanation": str,
            "details": dict
          }
        """
        if not self.is_trained:
            self.train()

        text_clean = text.strip() if text else ""
        if not text_clean:
            return {
                "risk_score": 0.0,
                "confidence": 0.0,
                "phishing_probability": 0.0,
                "intent_patterns": [],
                "flagged": False,
                "explanation": "Empty message body provided; no content risk detected.",
                "details": {"intent_tags": []},
            }

        # 1. Statistical NLP prediction
        X = self.vectorizer.transform([text_clean])
        prob = float(self.model.predict_proba(X)[0][1])

        # 2. Rule-based intent patterns
        patterns = self.extract_intent_patterns(text_clean)

        # Composite score combining statistical probability and fired patterns
        base_score = prob * 100.0
        pattern_boost = len(patterns) * 8.0
        risk_score = min(100.0, base_score + pattern_boost)

        flagged = risk_score >= 50.0 or len(patterns) >= 2

        # Structured, plain-English explanation
        if flagged:
            explanations = []
            if "URGENCY_PRESSURE" in patterns:
                explanations.append("High urgency and artificial pressure framing detected (e.g. deadline or threat of revocation).")
            if "AUTHORITY_IMPERSONATION" in patterns:
                explanations.append("Impersonation of corporate authority detected (e.g. IT Security, HR, or Executive leadership).")
            if "CREDENTIAL_REQUEST" in patterns:
                explanations.append("Explicit credential solicitation or re-authentication request identified.")
            if "FINANCIAL_ACTION" in patterns:
                explanations.append("High-risk financial action or banking redirection requested.")
            if not explanations:
                explanations.append(f"NLP intent classifier scored message text at {risk_score:.1f}% phishing probability.")

            explanation = " | ".join(explanations)
        else:
            explanation = "Message language aligns with routine enterprise communication (no coercive urgency or credential prompts)."

        return {
            "risk_score": round(risk_score, 1),
            "confidence": round(risk_score, 1),
            "phishing_probability": round(prob, 3),
            "intent_patterns": patterns,
            "flagged": flagged,
            "explanation": explanation,
            "details": {
                "intent_tags": patterns,
                "raw_probability": round(prob, 4),
                "pattern_count": len(patterns),
            },
        }


# Global singleton instance
_CONTENT_CLASSIFIER = ContentIntelligenceClassifier()


def analyze_content(text: str) -> dict:
    """Primary module interface for Content Intelligence Layer."""
    return _CONTENT_CLASSIFIER.predict(text)


def train_content_model(extra_texts: list = None, extra_labels: list = None):
    """Retrain or reload the content intelligence classifier."""
    global _CONTENT_CLASSIFIER
    _CONTENT_CLASSIFIER = ContentIntelligenceClassifier()
    _CONTENT_CLASSIFIER.train()
    return _CONTENT_CLASSIFIER

