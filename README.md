# SIEM-lite Dashboard

SIEM-lite is a lightweight, AI-assisted security information and event management dashboard tailored for small and medium enterprises. It ingests CSV log data, performs anomaly detection with IsolationForest, visualises KPIs with Bootstrap + Chart.js, delivers threshold-based email alerts, and preserves forensic evidence via SHA-256 hashes and chain-of-custody records.

## Features

- 🔐 Session-based authentication with admin and analyst roles (seeded accounts).
- 📥 CSV log ingestion with schema validation and anomaly toggles.
- 🤖 IsolationForest detection with configurable threshold and training window.
- 📊 Real-time KPIs and charts (totals, anomaly rate, top event types/IPs).
- ✉️ SMTP-driven alerting when anomaly thresholds are exceeded.
- 🧾 Evidence freezing that hashes and archives log snapshots for forensics.
- 🧰 Admin settings panel to adjust detection thresholds and SMTP details.
- 🪪 Stretch stubs for JWT refresh tokens and agent ingestion.

## Project Structure

```
app/
  app.py                # Flask application entrypoint
  models.py             # SQLite helpers and user seeding
  services/             # Domain-specific helpers
    anomaly.py          # IsolationForest training/detection
    auth.py             # Session login and rate limiting
    emailer.py          # SMTP alert helper
    evidence.py         # Hashing & chain-of-custody routines
    ingestion.py        # CSV loading, KPIs, charts
  templates/            # Jinja2 HTML templates (Bootstrap + Chart.js)
  static/               # Styles and browser scripts
  data/                 # Sample datasets, anomaly outputs, evidence
    sample_logs.csv
    anomalies.csv
    evidence/
  requirements.txt
  .env.example
README.md
```

## Getting Started

### 1. Prerequisites

- Python 3.10+
- Virtual environment tool (recommended: `venv`)

### 2. Setup

```bash
cd app
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
cp .env.example .env
```

Edit `.env` with your SMTP server details and preferred detection thresholds.

### 3. Run the application

```bash
python app.py
```

Visit [http://127.0.0.1:5000](http://127.0.0.1:5000) to access the dashboard.

### 4. Demo credentials

| Role   | Email                | Password    |
|--------|----------------------|-------------|
| Admin  | `admin@example.com`  | `Admin@123` |
| Analyst| `analyst@example.com`| `Analyst@123` |

The admin role can upload logs, run detections, manage settings, trigger alerts, and freeze evidence. The analyst role has read-only access to dashboards, logs, and evidence records.

## Workflow Highlights

1. **Upload Logs:** Admins can upload CSV files that match the schema `timestamp, source, host, ip, event_type, status_code, bytes, message`. A ready-to-use sample upload file is provided at `app/data/upload_sample.csv` so you can try the ingestion flow immediately.
2. **Run Detection:** IsolationForest computes anomaly scores, flags suspicious entries, and stores anomalies in `data/anomalies.csv`.
3. **Monitor KPIs:** Bootstrap cards and Chart.js charts refresh via REST endpoints to visualise totals, anomaly rate, and top offenders.
4. **Alerting:** When detection results exceed configured thresholds, SIEM-lite sends summary emails through the configured SMTP server.
5. **Freeze Evidence:** Admins can hash the current log dataset, archive it, and produce a JSON chain-of-custody record (hash, creator, timestamp, row count).

## API Endpoints (selected)

| Method | Endpoint                | Description |
|--------|-------------------------|-------------|
| POST   | `/api/auth/login`       | Authenticate and create a session. |
| GET    | `/api/kpis`             | Current KPI metrics. |
| GET    | `/api/charts/series`    | Hourly/daily totals vs anomalies. |
| GET    | `/api/logs`             | Recent logs (optional anomalies-only filter). |
| POST   | `/api/logs/upload`      | Upload and append CSV logs (admin). |
| POST   | `/api/detect/run`       | Execute anomaly detection (admin). |
| POST   | `/api/alerts/test`      | Send a test SMTP alert (admin). |
| POST   | `/api/evidence/freeze`  | Hash and archive logs (admin). |
| GET    | `/api/evidence/records` | List evidence packages. |
| GET    | `/api/settings`         | Read runtime configuration (admin). |
| POST   | `/api/settings`         | Update runtime configuration (admin). |

## Screenshots

Example dashboard views:

![Dashboard overview](docs/screenshots/dashboard.png)
![Log explorer](docs/screenshots/logs.png)
![Forensics workflow](docs/screenshots/forensics.png)

_Add your own screenshots by capturing the UI after running the app locally._

## Notes

- The app stores logs in CSV and user data in SQLite (`data/siem.db`).
- SMTP credentials are read from environment variables at startup but can be updated in-session via the Settings page.
- Email alerts are skipped if SMTP fields are blank; the test endpoint will return a 500 error until configured.
- Evidence archives live in `app/data/evidence/` alongside their JSON records and can be independently hash-verified.

## License

This project is provided as-is for educational and SME evaluation purposes.
