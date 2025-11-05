(function () {
  const csrfToken = () => {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') : '';
  };

  const toastEl = document.getElementById('toast');
  const toastBody = document.getElementById('toast-body');
  let toast;
  if (toastEl) {
    toast = new bootstrap.Toast(toastEl, { delay: 3000 });
  }

  function showToast(message, variant = 'primary') {
    if (!toastEl) return;
    toastEl.classList.remove('text-bg-primary', 'text-bg-danger', 'text-bg-success');
    toastEl.classList.add(`text-bg-${variant}`);
    toastBody.textContent = message;
    toast.show();
  }

  async function api(url, options = {}) {
    const headers = options.headers || {};
    if (!('Content-Type' in headers) && !(options.body instanceof FormData)) {
      headers['Content-Type'] = 'application/json';
    }
    headers['X-CSRFToken'] = csrfToken();
    options.headers = headers;
    const response = await fetch(url, options);
    if (!response.ok) {
      const text = await response.text();
      throw new Error(text || 'Request failed');
    }
    const contentType = response.headers.get('Content-Type') || '';
    if (contentType.includes('application/json')) {
      return response.json();
    }
    return response.text();
  }

  function formatRate(value) {
    return `${(Number(value) * 100).toFixed(2)}%`;
  }

  async function loadKpis() {
    const data = await api('/api/kpis');
    document.getElementById('kpi-total').textContent = data.total_logs;
    document.getElementById('kpi-anomalies').textContent = data.anomalies_today;
    document.getElementById('kpi-rate').textContent = formatRate(data.anomaly_rate || 0);
    document.getElementById('kpi-alert').textContent = data.last_alert_time || 'No alerts yet';
    renderBarChart('chart-events', data.top_event_types.map(t => t.event_type), data.top_event_types.map(t => t.count));
    renderHorizontalChart('chart-ips', data.top_ips.map(t => t.ip), data.top_ips.map(t => t.count));
  }

  let trendChart;
  function renderTrend(series) {
    const ctx = document.getElementById('chart-trend');
    if (!ctx) return;
    const labels = series.map(item => new Date(item.timestamp).toLocaleString());
    const totals = series.map(item => item.total_logs);
    const anomalies = series.map(item => item.anomalies);
    if (trendChart) trendChart.destroy();
    trendChart = new Chart(ctx, {
      type: 'line',
      data: {
        labels,
        datasets: [
          { label: 'Total Logs', data: totals, borderColor: '#0d6efd', tension: 0.3 },
          { label: 'Anomalies', data: anomalies, borderColor: '#dc3545', tension: 0.3 }
        ]
      }
    });
  }

  let eventsChart;
  function renderBarChart(id, labels, data) {
    const ctx = document.getElementById(id);
    if (!ctx) return;
    if (eventsChart && id === 'chart-events') eventsChart.destroy();
    eventsChart = new Chart(ctx, {
      type: 'bar',
      data: { labels, datasets: [{ label: 'Count', data, backgroundColor: '#20c997' }] },
      options: { responsive: true, maintainAspectRatio: false }
    });
  }

  let ipsChart;
  function renderHorizontalChart(id, labels, data) {
    const ctx = document.getElementById(id);
    if (!ctx) return;
    if (ipsChart && id === 'chart-ips') ipsChart.destroy();
    ipsChart = new Chart(ctx, {
      type: 'bar',
      data: { labels, datasets: [{ label: 'Count', data, backgroundColor: '#ffc107' }] },
      options: {
        indexAxis: 'y',
        responsive: true,
        maintainAspectRatio: false
      }
    });
  }

  async function loadTrend(range = '24h') {
    const data = await api(`/api/charts/series?range=${range}`);
    renderTrend(data.series);
  }

  async function loadAlerts() {
    const tbody = document.querySelector('#alerts-table tbody');
    if (!tbody) return;
    const data = await api('/api/anomalies');
    tbody.innerHTML = '';
    data.forEach(item => {
      const row = document.createElement('tr');
      row.innerHTML = `
        <td>${new Date(item.timestamp).toLocaleString()}</td>
        <td>${item.ip || '-'}</td>
        <td>${item.event_type}</td>
        <td>${Number(item.anomaly_score).toFixed(3)}</td>
        <td><span class="badge bg-${severityClass(item.severity)}">${item.severity}</span></td>
      `;
      tbody.appendChild(row);
    });
  }

  function severityClass(severity) {
    if (severity === 'High') return 'danger';
    if (severity === 'Medium') return 'warning';
    return 'info';
  }

  async function detect() {
    try {
      const data = await api('/api/detect/run', { method: 'POST' });
      showToast(`Detection completed: ${data.anomalies} anomalies`, 'success');
      await Promise.all([loadKpis(), loadTrend(window.currentRange || '24h'), loadAlerts(), loadLogs()]);
    } catch (error) {
      showToast('Detection failed', 'danger');
    }
  }

  async function sendTestAlert() {
    try {
      await api('/api/alerts/test', { method: 'POST' });
      showToast('Test alert sent (check SMTP logs)', 'success');
    } catch (error) {
      showToast('Failed to send test alert', 'danger');
    }
  }

  async function loadLogs(onlyAnomalies = false) {
    const table = document.querySelector('#logs-table tbody');
    if (!table) return;
    const data = await api(`/api/logs?limit=200&only_anomalies=${onlyAnomalies ? 1 : 0}`);
    table.innerHTML = '';
    data.logs.forEach(log => {
      const row = document.createElement('tr');
      if (Number(log.is_anomaly) === 1) row.classList.add('is-anomaly');
      row.innerHTML = `
        <td>${new Date(log.timestamp).toLocaleString()}</td>
        <td>${log.source}</td>
        <td>${log.host}</td>
        <td>${log.ip}</td>
        <td>${log.event_type}</td>
        <td>${log.status_code}</td>
        <td>${log.bytes}</td>
        <td>${log.message}</td>
      `;
      table.appendChild(row);
    });
  }

  async function uploadLogs(file) {
    const form = new FormData();
    form.append('file', file);
    try {
      await api('/api/logs/upload', { method: 'POST', body: form });
      showToast('Log file uploaded', 'success');
      await loadLogs(document.getElementById('toggle-anomalies')?.checked);
    } catch (error) {
      showToast('Upload failed', 'danger');
    }
  }

  async function freezeEvidence() {
    if (!confirm('Freeze current logs and create an evidence package?')) return;
    try {
      await api('/api/evidence/freeze', { method: 'POST' });
      showToast('Evidence frozen', 'success');
      await loadEvidence();
    } catch (error) {
      showToast('Failed to freeze evidence', 'danger');
    }
  }

  async function loadEvidence() {
    const tbody = document.querySelector('#evidence-table tbody');
    if (!tbody) return;
    const data = await api('/api/evidence/records');
    tbody.innerHTML = '';
    data.records.forEach(record => {
      const row = document.createElement('tr');
      row.innerHTML = `
        <td><code>${record.hash}</code></td>
        <td>${record.file}</td>
        <td>${record.created_by}</td>
        <td>${record.created_at}</td>
        <td>${record.row_count}</td>
      `;
      tbody.appendChild(row);
    });
  }

  async function loadSettings() {
    const form = document.getElementById('settings-form');
    if (!form) return;
    const data = await api('/api/settings');
    Object.entries(data.settings).forEach(([key, value]) => {
      const field = form.querySelector(`[name="${key}"]`);
      if (field) field.value = value ?? '';
    });
  }

  async function saveSettings(form) {
    const data = Object.fromEntries(new FormData(form).entries());
    await api('/api/settings', { method: 'POST', body: JSON.stringify(data) });
    showToast('Settings saved', 'success');
  }

  window.SIEM = {
    initDashboard() {
      window.currentRange = '24h';
      loadKpis();
      loadTrend('24h');
      loadAlerts();
      document.querySelectorAll('[data-range]').forEach(btn => {
        btn.addEventListener('click', async (event) => {
          document.querySelectorAll('[data-range]').forEach(b => b.classList.remove('active'));
          event.target.classList.add('active');
          window.currentRange = event.target.dataset.range;
          await loadTrend(window.currentRange);
        });
      });
      document.getElementById('btn-detect')?.addEventListener('click', detect);
      document.getElementById('btn-alert-test')?.addEventListener('click', sendTestAlert);
    },
    initLogs() {
      const toggle = document.getElementById('toggle-anomalies');
      loadLogs();
      toggle?.addEventListener('change', () => loadLogs(toggle.checked));
      const upload = document.getElementById('file-upload');
      upload?.addEventListener('change', (event) => {
        const file = event.target.files[0];
        if (file) uploadLogs(file);
      });
    },
    initForensics() {
      loadEvidence();
      document.getElementById('btn-freeze')?.addEventListener('click', freezeEvidence);
    },
    initSettings() {
      const form = document.getElementById('settings-form');
      loadSettings();
      form?.addEventListener('submit', async (event) => {
        event.preventDefault();
        await saveSettings(form);
      });
    }
  };
})();
