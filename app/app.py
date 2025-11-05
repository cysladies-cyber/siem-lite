from __future__ import annotations

import os
import secrets
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Dict

from dotenv import load_dotenv
from flask import (
    Flask,
    abort,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from models import init_db, seed_users
from services import anomaly, evidence, ingestion
from services import emailer
from services.auth import current_user, login_user, logout_user, require_role

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / '.env')

app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'replace-this-key')

DEFAULT_CONFIG: Dict[str, Any] = {
    'ANOMALY_THRESHOLD': '-0.15',
    'ALERT_RATE_THRESHOLD': '0.2',
    'ALERT_COUNT_THRESHOLD': '10',
    'MODEL_TRAIN_WINDOW': '300',
    'SMTP_HOST': '',
    'SMTP_PORT': '587',
    'SMTP_USER': '',
    'SMTP_PASSWORD': '',
    'SMTP_FROM': '',
    'SMTP_TO': '',
}

runtime_config: Dict[str, Any] = {
    key: os.getenv(key, default) for key, default in DEFAULT_CONFIG.items()
}

CSRF_EXEMPT = {'/api/auth/login'}


def generate_csrf_token() -> str:
    token = session.get('_csrf_token')
    if not token:
        token = secrets.token_hex(16)
        session['_csrf_token'] = token
    return token


app.jinja_env.globals['csrf_token'] = generate_csrf_token


@app.before_request
def apply_security() -> None:
    generate_csrf_token()
    if request.method in {'POST', 'PUT', 'DELETE'} and request.path not in CSRF_EXEMPT:
        token = request.headers.get('X-CSRFToken') or request.form.get('csrf_token')
        if not token or token != session.get('_csrf_token'):
            abort(400, 'Invalid CSRF token')


@app.before_first_request
def bootstrap() -> None:
    init_db()
    seed_users()


def login_required(func: Callable) -> Callable:
    @wraps(func)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user:
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Unauthorized'}), 401
            return redirect(url_for('login'))
        return func(*args, **kwargs)

    return wrapper


def admin_required(func: Callable) -> Callable:
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not current_user():
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Unauthorized'}), 401
            return redirect(url_for('login'))
        if not require_role('admin'):
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Forbidden'}), 403
            abort(403)
        return func(*args, **kwargs)

    return wrapper


@app.route('/')
def index():
    if current_user():
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login')
def login():
    if current_user():
        return redirect(url_for('dashboard'))
    return render_template('login.html')


@app.post('/logout')
@login_required
def logout() -> Any:
    logout_user()
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/logs')
@login_required
def logs_view():
    return render_template('logs.html')


@app.route('/forensics')
@login_required
def forensics_view():
    return render_template('forensics.html')


@app.route('/settings')
@admin_required
def settings_view():
    return render_template('settings.html')


@app.post('/api/auth/login')
def api_login():
    ip = request.remote_addr or 'unknown'
    data = request.get_json() or {}
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    user = login_user(email, password, ip)
    if not user:
        return jsonify({'error': 'Invalid credentials'}), 401
    return jsonify({'email': user['email'], 'role': user['role']})


@app.get('/api/kpis')
@login_required
def api_kpis():
    data = ingestion.kpis()
    return jsonify(data)


@app.get('/api/charts/series')
@login_required
def api_chart_series():
    range_param = request.args.get('range', '24h')
    freq = 'H' if range_param == '24h' else 'D'
    data = ingestion.time_series(freq)
    return jsonify(data)


@app.get('/api/logs')
@login_required
def api_logs():
    limit = int(request.args.get('limit', 100))
    only_anomalies = request.args.get('only_anomalies', '0') == '1'
    logs = ingestion.get_recent_logs(limit=limit, only_anomalies=only_anomalies)
    return jsonify({'logs': logs})


@app.post('/api/logs/upload')
@admin_required
def api_upload_logs():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    file = request.files['file']
    if file.filename == '' or not file.filename.endswith('.csv'):
        return jsonify({'error': 'Invalid file type'}), 400
    success, message, df = ingestion.validate_upload(file.stream)
    if not success:
        return jsonify({'error': message}), 400
    ingestion.append_logs(df)
    return jsonify({'status': 'ok'})


@app.post('/api/detect/run')
@admin_required
def api_detect_run():
    threshold = float(runtime_config.get('ANOMALY_THRESHOLD', '-0.15'))
    window = int(runtime_config.get('MODEL_TRAIN_WINDOW', '300'))
    before = ingestion.load_anomalies()
    prev_count = len(before)
    result = anomaly.detect(threshold=threshold, train_window=window)
    after = ingestion.load_anomalies()
    new_anomalies = max(len(after) - prev_count, 0)
    kpi = ingestion.kpis()
    anomaly_rate = kpi.get('anomaly_rate', 0)
    should_alert = False
    try:
        rate_threshold = float(runtime_config.get('ALERT_RATE_THRESHOLD', '0'))
        count_threshold = int(runtime_config.get('ALERT_COUNT_THRESHOLD', '0'))
        if new_anomalies >= count_threshold or anomaly_rate >= rate_threshold:
            should_alert = new_anomalies > 0
    except ValueError:
        should_alert = False
    if should_alert:
        payload = {
            'total_logs': kpi.get('total_logs'),
            'new_anomalies': new_anomalies,
            'anomaly_rate': f"{anomaly_rate:.2%}",
            'top_ips': [item['ip'] for item in kpi.get('top_ips', [])],
            'top_events': [item['event_type'] for item in kpi.get('top_event_types', [])],
        }
        emailer.send_alert(runtime_config, payload)
    return jsonify({'total': result.total, 'anomalies': result.anomalies, 'new_anomalies': new_anomalies})


@app.post('/api/alerts/test')
@admin_required
def api_alert_test():
    payload = {
        'total_logs': 0,
        'new_anomalies': 0,
        'anomaly_rate': '0%',
        'top_ips': [],
        'top_events': [],
    }
    success = emailer.send_alert(runtime_config, payload)
    if not success:
        return jsonify({'status': 'failed'}), 500
    return jsonify({'status': 'sent'})


@app.post('/api/evidence/freeze')
@admin_required
def api_evidence_freeze():
    user = current_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    record = evidence.freeze_logs(user['email'])
    return jsonify({'record': record})


@app.get('/api/evidence/records')
@login_required
def api_evidence_records():
    records = evidence.list_records()
    return jsonify({'records': records})


@app.get('/api/anomalies')
@login_required
def api_recent_anomalies():
    records = ingestion.recent_alerts()
    return jsonify(records)


@app.get('/api/settings')
@admin_required
def api_get_settings():
    return jsonify({'settings': runtime_config})


@app.post('/api/settings')
@admin_required
def api_save_settings():
    data = request.get_json() or {}
    for key in runtime_config.keys():
        value = data.get(key)
        if value is not None:
            runtime_config[key] = str(value)
    return jsonify({'status': 'saved'})


# Stretch stubs
@app.post('/api/auth/refresh')
def api_refresh_stub():
    return jsonify({'message': 'Refresh token endpoint not implemented yet'}), 501


@app.post('/api/agent/ingest')
def api_agent_stub():
    return jsonify({'message': 'Agent ingestion endpoint reserved for future use'}), 501


if __name__ == '__main__':
    app.run(debug=True)
