"""Evidence preservation helpers."""
from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Dict, List

LOG_PATH = Path(__file__).resolve().parent.parent / 'data' / 'sample_logs.csv'
EVIDENCE_DIR = Path(__file__).resolve().parent.parent / 'data' / 'evidence'


def freeze_logs(created_by: str) -> Dict[str, str]:
    if not LOG_PATH.exists():
        raise FileNotFoundError('Log dataset not found')
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    with LOG_PATH.open('rb') as source:
        data = source.read()
    digest = sha256(data).hexdigest()
    row_count = sum(1 for _ in LOG_PATH.open()) - 1  # subtract header
    archive_name = f'logs_{timestamp}.csv'
    archive_path = EVIDENCE_DIR / archive_name
    shutil.copy2(LOG_PATH, archive_path)
    record = {
        'hash': digest,
        'file': archive_name,
        'created_by': created_by,
        'created_at': timestamp,
        'row_count': row_count,
    }
    evidence_file = EVIDENCE_DIR / f'evidence_{timestamp}.json'
    evidence_file.write_text(json.dumps(record, indent=2))
    return record


def list_records() -> List[Dict[str, str]]:
    records: List[Dict[str, str]] = []
    for path in sorted(EVIDENCE_DIR.glob('evidence_*.json'), reverse=True):
        try:
            records.append(json.loads(path.read_text()))
        except json.JSONDecodeError:
            continue
    return records


def verify_evidence(file_path: Path, expected_hash: str) -> bool:
    with file_path.open('rb') as f:
        data = f.read()
    return sha256(data).hexdigest() == expected_hash
