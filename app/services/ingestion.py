"""Log ingestion and KPI helpers."""
from __future__ import annotations

import io
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pandas as pd

LOG_PATH = Path(__file__).resolve().parent.parent / 'data' / 'sample_logs.csv'
ANOMALIES_PATH = Path(__file__).resolve().parent.parent / 'data' / 'anomalies.csv'

EXPECTED_COLUMNS = [
    'timestamp',
    'source',
    'host',
    'ip',
    'event_type',
    'status_code',
    'bytes',
    'message',
]


def _read_csv(path: Path) -> pd.DataFrame:
    if not path.exists():
        return pd.DataFrame(columns=EXPECTED_COLUMNS)
    return pd.read_csv(path, parse_dates=['timestamp'], infer_datetime_format=True)


def load_logs() -> pd.DataFrame:
    df = _read_csv(LOG_PATH)
    if 'anomaly_score' in df.columns:
        if not df.empty and not pd.api.types.is_datetime64tz_dtype(df['timestamp']):
            df['timestamp'] = pd.to_datetime(df['timestamp'], utc=True, errors='coerce')
        return df
    # placeholder columns if detection not yet run
    if not df.empty:
        df['timestamp'] = pd.to_datetime(df['timestamp'], utc=True, errors='coerce')
        df['anomaly_score'] = 0.0
        df['is_anomaly'] = 0
    else:
        df = pd.DataFrame(columns=EXPECTED_COLUMNS + ['anomaly_score', 'is_anomaly'])
    return df


def load_anomalies() -> pd.DataFrame:
    df = _read_csv(ANOMALIES_PATH)
    if df.empty:
        return df
    if 'is_anomaly' not in df.columns:
        df['anomaly_score'] = df.get('anomaly_score', 0)
        df['is_anomaly'] = df.get('is_anomaly', 1)
    if not pd.api.types.is_datetime64tz_dtype(df['timestamp']):
        df['timestamp'] = pd.to_datetime(df['timestamp'], utc=True, errors='coerce')
    return df


def save_logs(df: pd.DataFrame) -> None:
    df.to_csv(LOG_PATH, index=False)


def save_anomalies(df: pd.DataFrame) -> None:
    df.to_csv(ANOMALIES_PATH, index=False)


def validate_upload(stream: io.BytesIO) -> Tuple[bool, str, pd.DataFrame]:
    try:
        df = pd.read_csv(stream)
    except Exception as exc:  # pragma: no cover - defensive
        return False, f'Failed to read CSV: {exc}', pd.DataFrame()
    missing = [col for col in EXPECTED_COLUMNS if col not in df.columns]
    if missing:
        return False, f'Missing columns: {", ".join(missing)}', pd.DataFrame()
    try:
        df['timestamp'] = pd.to_datetime(df['timestamp'], utc=True)
        df['status_code'] = df['status_code'].astype(int)
        df['bytes'] = df['bytes'].astype(int)
    except Exception as exc:
        return False, f'Column type error: {exc}', pd.DataFrame()
    return True, 'OK', df


def append_logs(df: pd.DataFrame) -> None:
    df_copy = df.copy()
    if pd.api.types.is_datetime64tz_dtype(df_copy['timestamp']):
        df_copy['timestamp'] = df_copy['timestamp'].dt.tz_convert('UTC')
    else:
        df_copy['timestamp'] = pd.to_datetime(df_copy['timestamp'], utc=True, errors='coerce')
    existing = load_logs()
    if existing.empty:
        combined = df_copy
    else:
        combined = pd.concat([existing, df_copy], ignore_index=True)
    combined.to_csv(LOG_PATH, index=False)


def get_recent_logs(limit: int = 100, only_anomalies: bool = False) -> List[Dict[str, str]]:
    df = load_logs().sort_values('timestamp', ascending=False)
    if only_anomalies and 'is_anomaly' in df.columns:
        df = df[df['is_anomaly'] == 1]
    if limit:
        df = df.head(limit)
    if not df.empty:
        if pd.api.types.is_datetime64tz_dtype(df['timestamp']):
            df['timestamp'] = df['timestamp'].dt.tz_convert(timezone.utc)
        else:
            df['timestamp'] = pd.to_datetime(df['timestamp'], utc=True, errors='coerce')
    return df.fillna('').to_dict(orient='records')


def kpis() -> Dict[str, Any]:
    df = load_logs()
    total_logs = int(len(df))
    now = datetime.now(timezone.utc)
    anomalies_today = 0
    anomaly_rate = 0.0
    top_event_types: List[Tuple[str, int]] = []
    top_ips: List[Tuple[str, int]] = []
    if not df.empty:
        today = df[df['timestamp'].dt.date == now.date()]
        anomalies_today = int(today[today.get('is_anomaly', 0) == 1].shape[0])
        anomaly_count = int(df[df.get('is_anomaly', 0) == 1].shape[0])
        anomaly_rate = float(anomaly_count / total_logs) if total_logs else 0.0
        top_event_types = df['event_type'].value_counts().head(5).items()
        top_ips = df['ip'].value_counts().head(5).items()
    anomalies_df = load_anomalies()
    last_alert_time = None
    if not anomalies_df.empty:
        last_alert_time = anomalies_df['timestamp'].max()
        if pd.api.types.is_datetime64_any_dtype(anomalies_df['timestamp']):
            last_alert_time = last_alert_time.isoformat()
    return {
        'total_logs': total_logs,
        'anomalies_today': anomalies_today,
        'anomaly_rate': anomaly_rate,
        'top_event_types': [{'event_type': k, 'count': int(v)} for k, v in top_event_types],
        'top_ips': [{'ip': k, 'count': int(v)} for k, v in top_ips],
        'last_alert_time': last_alert_time,
    }


def time_series(freq: str = 'H') -> Dict[str, List[Dict[str, Any]]]:
    df = load_logs()
    if df.empty:
        return {'series': []}
    df = df.set_index('timestamp').sort_index()
    if not isinstance(df.index, pd.DatetimeIndex):
        df.index = pd.to_datetime(df.index, utc=True, errors='coerce')
    if df.index.tz is None:
        df.index = df.index.tz_localize('UTC')
    grouped = df.resample(freq).agg({'event_type': 'count', 'is_anomaly': 'sum'})
    grouped = grouped.rename(columns={'event_type': 'total_logs', 'is_anomaly': 'anomalies'})
    if grouped.index.tz is None:
        grouped.index = grouped.index.tz_localize('UTC')
    else:
        grouped.index = grouped.index.tz_convert('UTC')
    series = [
        {
            'timestamp': idx.isoformat(),
            'total_logs': int(row['total_logs']),
            'anomalies': int(row['anomalies']),
        }
        for idx, row in grouped.iterrows()
    ]
    return {'series': series}


def recent_alerts(limit: int = 10) -> List[Dict[str, Any]]:
    df = load_anomalies().sort_values('timestamp', ascending=False)
    if df.empty:
        return []
    df = df.head(limit)
    if not pd.api.types.is_datetime64_any_dtype(df['timestamp']):
        df['timestamp'] = pd.to_datetime(df['timestamp'], utc=True, errors='coerce')
    df['severity'] = df['anomaly_score'].apply(lambda score: 'High' if score < -0.3 else 'Medium' if score < -0.1 else 'Low')
    df['timestamp'] = df['timestamp'].dt.tz_convert('UTC')
    return df.fillna('').to_dict(orient='records')
