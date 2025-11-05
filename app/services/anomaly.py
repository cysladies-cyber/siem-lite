"""Anomaly detection powered by IsolationForest."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from services import ingestion

MODEL_PATH = Path(__file__).resolve().parent.parent / 'data' / 'isoforest.joblib'


@dataclass
class DetectionResult:
    total: int
    anomalies: int
    threshold: float


FEATURE_COLUMNS = ['status_code', 'bytes', 'hour']


def _prepare_features(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame]:
    working = df.copy()
    working['timestamp'] = pd.to_datetime(working['timestamp'], utc=True)
    working['hour'] = working['timestamp'].dt.hour
    # event type one-hot encoding
    ohe = pd.get_dummies(working['event_type'], prefix='event')
    feature_df = pd.concat([working[['status_code', 'bytes', 'hour']].apply(pd.to_numeric), ohe], axis=1)
    feature_df['bytes'] = np.log1p(feature_df['bytes'].astype(float))
    feature_df['status_code'] = feature_df['status_code'].astype(float)
    feature_df['hour'] = feature_df['hour'].astype(float)
    feature_df = feature_df.fillna(0)
    return working, feature_df


def _load_model() -> IsolationForest | None:
    if MODEL_PATH.exists():
        try:
            return joblib.load(MODEL_PATH)
        except Exception:  # pragma: no cover - if corrupted, fall back
            return None
    return None


def _train_model(features: pd.DataFrame, window: int) -> IsolationForest:
    if window and len(features) > window:
        features = features.tail(window)
    model = IsolationForest(contamination='auto', random_state=42)
    model.fit(features)
    joblib.dump(model, MODEL_PATH)
    return model


def detect(threshold: float, train_window: int) -> DetectionResult:
    df = ingestion.load_logs()
    if df.empty:
        return DetectionResult(total=0, anomalies=0, threshold=threshold)
    working, features = _prepare_features(df)
    model = _load_model()
    if model is None:
        model = _train_model(features, train_window)
    else:
        # retrain on sliding window for simplicity
        model = _train_model(features, train_window)
    scores = model.decision_function(features)
    working['anomaly_score'] = scores
    working['is_anomaly'] = (scores < threshold).astype(int)
    ingestion.save_logs(working)
    anomalies = working[working['is_anomaly'] == 1]
    ingestion.save_anomalies(anomalies)
    return DetectionResult(total=len(working), anomalies=len(anomalies), threshold=threshold)
