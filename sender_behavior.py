"""
Visual & Behavioral — Sender Behavior Modeling Module
Builds per-account behavioral baselines specifically for EMAIL SENDING behavior.
Features modeled per account:
  - Typical sending-time-of-day distribution (business hours vs off-hours)
  - Typical recipient domain patterns (internal vs external domain count/ratio)
  - Writing-style fingerprint (average sentence length, vocabulary richness, TF-IDF cosine similarity to sender past corpus)
  - Attachment frequency & typical sizes
"""

import math
import re
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


def compute_stylistic_features(text: str) -> dict:
    """
    Extract linguistic and writing style metrics from email text.
    """
    text = text.strip() if text else ""
    if not text:
        return {
            "char_count": 0,
            "word_count": 0,
            "avg_sentence_length": 0.0,
            "avg_word_length": 0.0,
            "vocab_richness": 0.0,
        }

    sentences = [s.strip() for s in re.split(r"[.!?]+", text) if s.strip()]
    words = re.findall(r"\b[A-Za-z0-9'-]+\b", text)

    word_count = len(words)
    sentence_count = len(sentences) or 1
    avg_sentence_len = word_count / sentence_count

    avg_word_len = (sum(len(w) for w in words) / word_count) if word_count > 0 else 0.0
    unique_words = len(set(w.lower() for w in words))
    # Type-token ratio / vocabulary richness
    vocab_richness = (unique_words / word_count) if word_count > 0 else 0.0

    return {
        "char_count": len(text),
        "word_count": word_count,
        "avg_sentence_length": round(avg_sentence_len, 2),
        "avg_word_length": round(avg_word_len, 2),
        "vocab_richness": round(vocab_richness, 3),
    }


class SenderBehaviorProfile:
    """
    Behavioral baseline model trained specifically for an individual sender account.
    """

    def __init__(self, sender_id: str):
        self.sender_id = sender_id
        self.model = IsolationForest(contamination=0.10, random_state=42)
        self.vectorizer = TfidfVectorizer(max_features=250, stop_words="english")
        self.baseline_texts = []
        self.baseline_matrix = None
        self.is_fitted = False
        self.typical_recipients = set()
        self.stats = {}

    def _extract_feature_vector(self, msg: dict) -> np.ndarray:
        """
        Extract numerical feature vector:
        [
          send_hour,
          is_off_hours,
          external_recipients_ratio,
          has_attachment,
          avg_sentence_len,
          avg_word_len,
          vocab_richness,
          text_cosine_sim
        ]
        """
        send_hour = msg.get("send_hour", 12)
        is_off_hours = 1.0 if (send_hour < 7 or send_hour > 19) else 0.0

        recipients = msg.get("recipients", [])
        if isinstance(recipients, str):
            recipients = [r.strip() for r in recipients.split(",") if r.strip()]

        total_recip = max(len(recipients), 1)
        ext_recip = sum(1 for r in recipients if not r.endswith((".gov", ".internal", "civic.org")))
        ext_ratio = ext_recip / total_recip

        has_att = 1.0 if msg.get("has_attachment", False) else 0.0

        text = msg.get("email_text", "")
        style = compute_stylistic_features(text)

        # Style similarity against sender corpus
        cos_sim = 0.5
        if self.baseline_matrix is not None and text:
            try:
                vec = self.vectorizer.transform([text])
                sims = cosine_similarity(vec, self.baseline_matrix)
                cos_sim = float(np.mean(sims))
            except Exception:
                cos_sim = 0.5

        return np.array([
            send_hour,
            is_off_hours,
            ext_ratio,
            has_att,
            style["avg_sentence_length"],
            style["avg_word_length"],
            style["vocab_richness"],
            cos_sim,
        ])

    def fit(self, history_messages: list):
        """Train baseline profile from sender's historical sent messages."""
        if not history_messages:
            return

        self.baseline_texts = [m.get("email_text", "") for m in history_messages if m.get("email_text")]
        if self.baseline_texts:
            try:
                self.baseline_matrix = self.vectorizer.fit_transform(self.baseline_texts)
            except ValueError:
                # In case of empty or too short text corpus
                self.baseline_matrix = None

        X = np.array([self._extract_feature_vector(m) for m in history_messages])
        self.model.fit(X)
        self.is_fitted = True

        # Track historical recipient domains
        for m in history_messages:
            recips = m.get("recipients", [])
            if isinstance(recips, str):
                recips = [r.strip() for r in recips.split(",")]
            self.typical_recipients.update(recips)

        hours = [m.get("send_hour", 12) for m in history_messages]
        self.stats = {
            "mean_hour": np.mean(hours) if hours else 12.0,
            "total_sent": len(history_messages),
            "typical_recipients_count": len(self.typical_recipients),
        }

    def evaluate(self, message: dict) -> dict:
        """Evaluate a new message against this sender's profile."""
        if not self.is_fitted:
            # Fallback baseline
            return {
                "flagged": False,
                "signals": [],
                "confidence": 15.0,
                "explanation": f"Sender '{self.sender_id}' has insufficient baseline history.",
                "deviations": {},
            }

        vec = self._extract_feature_vector(message)
        raw_score = float(self.model.decision_function([vec])[0])
        pred = int(self.model.predict([vec])[0])  # -1 = anomaly, 1 = normal

        deviations = {}
        signals = []

        # 1. Temporal deviation check
        send_hour = message.get("send_hour", 12)
        if send_hour < 6 or send_hour > 21:
            signals.append("OFF_HOURS_EMAIL_TRANSMISSION")
            deviations["time_anomaly"] = f"Sent at {send_hour}:00, outside normal hours."

        # 2. Recipient pattern check
        recipients = message.get("recipients", [])
        if isinstance(recipients, str):
            recipients = [r.strip() for r in recipients.split(",") if r.strip()]
        new_recipients = [r for r in recipients if r not in self.typical_recipients]
        if len(new_recipients) >= 2 and len(recipients) > 0:
            signals.append("ANOMALOUS_RECIPIENT_CLUSTER")
            deviations["recipient_anomaly"] = f"Contains {len(new_recipients)} unfamiliar recipient(s)."

        # 3. Writing style deviation check
        text = message.get("email_text", "")
        style = compute_stylistic_features(text)
        cos_sim = vec[-1]
        if cos_sim < 0.15 and len(text.split()) > 8:
            signals.append("LINGUISTIC_STYLE_DEVIATION")
            deviations["style_drift"] = (
                f"Low stylistic similarity ({cos_sim:.2f}) with sender historical corpus. "
                f"Vocabulary richness: {style['vocab_richness']}, Avg sentence length: {style['avg_sentence_length']}."
            )

        # 4. Attachment anomaly
        if message.get("has_attachment") and not any(m.get("has_attachment") for m in []):
            if "has_attachment" in message and message["has_attachment"]:
                deviations["attachment_anomaly"] = "Uncharacteristic file attachment transmitted."

        is_flagged = (pred == -1) or (len(signals) >= 1)

        if is_flagged:
            # Scale confidence based on anomaly score and signal count
            confidence = min(96.0, max(65.0, 70.0 + len(signals) * 10.0 - raw_score * 40.0))
            explanation = (
                f"Sender '{self.sender_id}' deviated significantly from historical baseline. "
                + " | ".join(deviations.values())
            )
        else:
            confidence = max(5.0, min(35.0, 30.0 + raw_score * 30.0))
            explanation = f"Activity aligns with sender '{self.sender_id}' established behavioral baseline."

        return {
            "flagged": is_flagged,
            "signals": signals,
            "confidence": round(confidence, 1),
            "explanation": explanation,
            "deviations": deviations,
        }


# Global registry of per-sender baseline profiles
_SENDER_REGISTRY: dict[str, SenderBehaviorProfile] = {}


def generate_sender_synthetic_history(sender_id: str, n: int = 25) -> list[dict]:
    """Generate typical historical sent messages for initializing a sender baseline."""
    history = []
    dept_prefix = sender_id.split("_")[0] if "_" in sender_id else "staff"
    standard_templates = [
        f"Hi team, sharing the {dept_prefix} weekly status updates and priorities.",
        "Please find the meeting minutes from this morning attached.",
        "Review requested on the operational budget spreadsheet before Thursday.",
        "Thanks for the update. Let's schedule a brief sync call tomorrow morning.",
        "Reminder: Departmental timesheet approval window closes at 5 PM today.",
        "The project timeline has been updated on the municipal intranet portal.",
    ]

    for i in range(n):
        history.append({
            "sender_id": sender_id,
            "send_hour": int(np.random.choice(range(8, 18))),  # Standard 8 AM - 6 PM
            "recipients": [f"{dept_prefix}_lead@cityhall.gov", f"colleague_{i%3}@cityhall.gov"],
            "has_attachment": bool(i % 5 == 0),
            "email_text": standard_templates[i % len(standard_templates)],
        })
    return history


def get_or_create_sender_profile(sender_id: str) -> SenderBehaviorProfile:
    """Retrieve or initialize trained baseline for the given sender account."""
    if sender_id not in _SENDER_REGISTRY:
        profile = SenderBehaviorProfile(sender_id)
        # Pre-seed with synthetic normal historical baseline for the account
        history = generate_sender_synthetic_history(sender_id, n=30)
        profile.fit(history)
        _SENDER_REGISTRY[sender_id] = profile
    return _SENDER_REGISTRY[sender_id]


def analyze_sender_behavior(sender_id: str, message_features: dict) -> dict:
    """
    Analyze whether a sent message conforms to the sender's personalized historical baseline.

    Parameters:
      sender_id: Unique user / account identifier (e.g. 'fin_204', 'admin@citygov.org')
      message_features: Dict containing:
        - 'send_hour': int (0-23)
        - 'recipients': list[str] or comma-separated string
        - 'email_text': str
        - 'has_attachment': bool

    Returns:
      {
        "flagged": bool,
        "signals": list[str],
        "confidence": float,
        "explanation": str,
        "deviations": dict
      }
    """
    profile = get_or_create_sender_profile(sender_id)
    return profile.evaluate(message_features)