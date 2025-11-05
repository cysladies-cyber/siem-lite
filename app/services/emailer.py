"""Email alert helper."""
from __future__ import annotations

import smtplib
from email.message import EmailMessage
from typing import Dict


def send_alert(config: Dict[str, str], payload: Dict[str, str]) -> bool:
    if not config.get('SMTP_HOST') or not config.get('SMTP_TO') or not config.get('SMTP_FROM'):
        return False
    msg = EmailMessage()
    msg['Subject'] = '[SIEM-lite] Anomaly Alert'
    msg['From'] = config.get('SMTP_FROM')
    msg['To'] = config.get('SMTP_TO')
    body = (
        "Anomaly summary:\n"
        f"Total logs: {payload.get('total_logs')}\n"
        f"New anomalies: {payload.get('new_anomalies')}\n"
        f"Anomaly rate: {payload.get('anomaly_rate')}\n"
        f"Top IPs: {', '.join(payload.get('top_ips', []))}\n"
        f"Top Events: {', '.join(payload.get('top_events', []))}\n"
        "Visit the dashboard for more details."
    )
    msg.set_content(body)
    try:
        with smtplib.SMTP(config['SMTP_HOST'], int(config.get('SMTP_PORT', 587))) as server:
            server.starttls()
            if config.get('SMTP_USER'):
                server.login(config['SMTP_USER'], config['SMTP_PASSWORD'])
            server.send_message(msg)
        return True
    except Exception:  # pragma: no cover - network dependent
        return False
