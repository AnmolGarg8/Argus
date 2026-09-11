"""
AI Anomaly Detection Module
Uses Isolation Forest to detect anomalous cybersecurity events.
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


class AnomalyDetector:
    def __init__(self, contamination=0.15):
        self.model = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=42,
        )
        self.scaler = StandardScaler()
        self.is_fitted = False

    def _extract_features(self, df):
        """Engineer features for anomaly detection."""
        features = pd.DataFrame()
        features["login_hour_deviation"] = abs(df["login_hour"] - 12)  # deviation from noon
        features["failed_attempts"] = df["failed_attempts"]
        features["ip_risk_score"] = df["ip_risk_score"]
        features["bytes_transferred_log"] = np.log1p(df["bytes_transferred"])
        features["off_hours"] = ((df["login_hour"] < 6) | (df["login_hour"] > 20)).astype(int)
        return features

    def fit(self, df):
        """Fit the anomaly detection model on baseline data."""
        features = self._extract_features(df)
        X = self.scaler.fit_transform(features)
        self.model.fit(X)
        self.is_fitted = True

    def predict(self, df):
        """Predict anomaly scores for new data. Returns df with anomaly_score and anomaly_flag."""
        if not self.is_fitted:
            # Auto-fit on provided data as baseline
            self.fit(df)

        features = self._extract_features(df)
        X = self.scaler.transform(features)

        # Raw scores from isolation forest (negative = more anomalous)
        raw_scores = self.model.decision_function(X)
        predictions = self.model.predict(X)

        # Scale to 0-100 where higher = more anomalous
        min_s, max_s = raw_scores.min(), raw_scores.max()
        if max_s - min_s > 0:
            anomaly_score = 100 * (1 - (raw_scores - min_s) / (max_s - min_s))
        else:
            anomaly_score = np.where(predictions == -1, 75.0, 25.0)

        result = df.copy()
        result["anomaly_score"] = np.round(anomaly_score, 1)
        result["anomaly_flag"] = (predictions == -1).astype(int)
        return result
