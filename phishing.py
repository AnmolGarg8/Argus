"""
Phishing Detection Module
Uses TF-IDF + Logistic Regression to classify emails as phishing or legitimate.
"""

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
import numpy as np

from simulator import get_training_emails


class PhishingDetector:
    def __init__(self):
        self.pipeline = Pipeline([
            ("tfidf", TfidfVectorizer(
                max_features=500,
                ngram_range=(1, 2),
                stop_words="english",
            )),
            ("clf", LogisticRegression(
                max_iter=1000,
                C=1.0,
                random_state=42,
            )),
        ])
        self.is_trained = False

    def train(self):
        """Train on synthetic email corpus."""
        emails, labels = get_training_emails()
        self.pipeline.fit(emails, labels)
        self.is_trained = True

    def predict(self, df):
        """Add phishing_probability column to dataframe."""
        if not self.is_trained:
            self.train()

        emails = df["email_text"].fillna("").tolist()
        probas = self.pipeline.predict_proba(emails)[:, 1]

        result = df.copy()
        result["phishing_probability"] = np.round(probas * 100, 1)
        return result
