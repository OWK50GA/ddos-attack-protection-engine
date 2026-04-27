"""
dashboard.py — Live metrics web dashboard (Flask).

Exposes two routes:
  GET /              HTML shell that auto-refreshes via JavaScript fetch
  GET /api/metrics   JSON snapshot of all live system metrics

The dashboard auto-refreshes every 3 seconds using a client-side
setInterval loop that calls /api/metrics and updates the DOM in place.

All /api/metrics handler code is wrapped in a broad try/except so the
endpoint never returns HTTP 500 — it always returns a valid JSON body
with zero/empty defaults for any unavailable metric.

Metrics served:
  - banned_ips:       list of active bans with metadata
  - global_rps:       current global requests per second
  - top_ips:          top 10 source IPs by current req/s
  - cpu_percent:      host CPU usage %
  - memory_percent:   host memory usage %
  - baseline_mean:    effective mean req/s
  - baseline_stddev:  standard deviation
  - uptime_seconds:   seconds since daemon start
  - parse_errors:     cumulative JSON parse error count
"""

from datetime import datetime, timezone

import psutil
from flask import Flask, jsonify, render_template_string

from detector.models import SharedState

# ---------------------------------------------------------------------------
# HTML template (single-page, no external files needed)
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>DDoS Detection Dashboard</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', sans-serif; background: #0f1117; color: #e2e8f0; padding: 24px; }
    h1 { font-size: 1.6rem; margin-bottom: 4px; color: #f8fafc; }
    .subtitle { font-size: 0.85rem; color: #64748b; margin-bottom: 24px; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }
    .card { background: #1e2130; border-radius: 10px; padding: 18px; }
    .card-label { font-size: 0.75rem; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 6px; }
    .card-value { font-size: 1.8rem; font-weight: 700; color: #38bdf8; }
    .card-value.warn { color: #f59e0b; }
    .card-value.danger { color: #ef4444; }
    table { width: 100%; border-collapse: collapse; background: #1e2130; border-radius: 10px; overflow: hidden; margin-bottom: 24px; }
    th { background: #2d3148; padding: 10px 14px; text-align: left; font-size: 0.75rem; color: #94a3b8; text-transform: uppercase; }
    td { padding: 10px 14px; font-size: 0.875rem; border-top: 1px solid #2d3148; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }
    .badge-red { background: #7f1d1d; color: #fca5a5; }
    .badge-yellow { background: #78350f; color: #fcd34d; }
    #status { font-size: 0.75rem; color: #475569; margin-top: 16px; }
    .section-title { font-size: 1rem; font-weight: 600; color: #cbd5e1; margin-bottom: 12px; }
  </style>
</head>
<body>
  <h1>🛡️ DDoS Detection Dashboard</h1>
  <p class="subtitle" id="last-updated">Loading…</p>

  <div class="grid">
    <div class="card">
      <div class="card-label">Global Req/s</div>
      <div class="card-value" id="global-rps">—</div>
    </div>
    <div class="card">
      <div class="card-label">Baseline Mean</div>
      <div class="card-value" id="baseline-mean">—</div>
    </div>
    <div class="card">
      <div class="card-label">Baseline Stddev</div>
      <div class="card-value" id="baseline-stddev">—</div>
    </div>
    <div class="card">
      <div class="card-label">Banned IPs</div>
      <div class="card-value danger" id="banned-count">—</div>
    </div>
    <div class="card">
      <div class="card-label">CPU Usage</div>
      <div class="card-value" id="cpu-percent">—</div>
    </div>
    <div class="card">
      <div class="card-label">Memory Usage</div>
      <div class="card-value" id="mem-percent">—</div>
    </div>
    <div class="card">
      <div class="card-label">Uptime</div>
      <div class="card-value" id="uptime">—</div>
    </div>
    <div class="card">
      <div class="card-label">Parse Errors</div>
      <div class="card-value warn" id="parse-errors">—</div>
    </div>
  </div>

  <div class="section-title">🚫 Banned IPs</div>
  <table id="banned-table">
    <thead><tr><th>IP</th><th>Condition</th><th>Rate at Ban</th><th>Backoff Level</th><th>Duration</th><th>Banned At</th></tr></thead>
    <tbody id="banned-tbody"><tr><td colspan="6" style="color:#475569">No active bans</td></tr></tbody>
  </table>

  <div class="section-title">📊 Top 10 Source IPs</div>
  <table id="top-ips-table">
    <thead><tr><th>IP</th><th>Req/s</th></tr></thead>
    <tbody id="top-ips-tbody"><tr><td colspan="2" style="color:#475569">No data yet</td></tr></tbody>
  </table>

  <div id="status">Refreshing every 3 seconds…</div>

  <script>
    function fmt(n, decimals=1) { return (n ?? 0).toFixed(decimals); }
    function fmtUptime(s) {
      s = Math.floor(s || 0);
      const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
      return `${h}h ${m}m ${sec}s`;
    }

    async function refresh() {
      try {
        const r = await fetch('/api/metrics');
        const d = await r.json();

        document.getElementById('global-rps').textContent = fmt(d.global_rps) + '/s';
        document.getElementById('baseline-mean').textContent = fmt(d.baseline_mean) + '/s';
        document.getElementById('baseline-stddev').textContent = fmt(d.baseline_stddev);
        document.getElementById('banned-count').textContent = (d.banned_ips || []).length;
        document.getElementById('cpu-percent').textContent = fmt(d.cpu_percent) + '%';
        document.getElementById('mem-percent').textContent = fmt(d.memory_percent) + '%';
        document.getElementById('uptime').textContent = fmtUptime(d.uptime_seconds);
        document.getElementById('parse-errors').textContent = d.parse_errors ?? 0;
        document.getElementById('last-updated').textContent =
          'Last updated: ' + new Date().toLocaleTimeString();

        // Banned IPs table
        const bans = d.banned_ips || [];
        const btbody = document.getElementById('banned-tbody');
        if (bans.length === 0) {
          btbody.innerHTML = '<tr><td colspan="6" style="color:#475569">No active bans</td></tr>';
        } else {
          btbody.innerHTML = bans.map(b => `
            <tr>
              <td><code>${b.ip}</code></td>
              <td><span class="badge badge-red">${b.condition}</span></td>
              <td>${fmt(b.rate_at_ban)}/s</td>
              <td>${b.backoff_level}</td>
              <td>${b.duration_seconds === 0 ? '♾ permanent' : b.duration_seconds + 's'}</td>
              <td>${b.banned_at}</td>
            </tr>`).join('');
        }

        // Top IPs table
        const tops = d.top_ips || [];
        const ttbody = document.getElementById('top-ips-tbody');
        if (tops.length === 0) {
          ttbody.innerHTML = '<tr><td colspan="2" style="color:#475569">No data yet</td></tr>';
        } else {
          ttbody.innerHTML = tops.map(t =>
            `<tr><td><code>${t.ip}</code></td><td>${fmt(t.rps)}/s</td></tr>`
          ).join('');
        }
      } catch(e) {
        document.getElementById('status').textContent = 'Error fetching metrics: ' + e;
      }
    }

    refresh();
    setInterval(refresh, 3000);
  </script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Flask app factory
# ---------------------------------------------------------------------------

def create_app(shared: SharedState) -> Flask:
    """
    Create and return a configured Flask application.

    *shared* is the SharedState instance from which all metrics are read.
    The app is intended to run in a daemon thread via app.run(threaded=True).
    """
    app = Flask(__name__)
    app.config["shared"] = shared

    @app.route("/")
    def index():
        return render_template_string(_HTML_TEMPLATE)

    @app.route("/api/metrics")
    def metrics():
        """
        Return a JSON snapshot of all live system metrics.
        All errors are caught; missing values default to 0/0.0/[].
        """
        try:
            s: SharedState = app.config["shared"]
            now = datetime.now(timezone.utc)

            # --- Banned IPs ---
            with s.ban_lock:
                banned_ips = [
                    {
                        "ip": rec.ip,
                        "banned_at": rec.banned_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "duration_seconds": rec.duration_seconds,
                        "backoff_level": rec.backoff_level,
                        "condition": rec.condition,
                        "rate_at_ban": round(rec.rate_at_ban, 2),
                    }
                    for rec in s.ban_registry.values()
                ]

            # --- Global req/s ---
            with s.windows_lock:
                global_rps = s.global_window.rate()

                # Top 10 IPs by current rate
                ip_rates = [
                    {"ip": ip, "rps": round(win.rate(), 2)}
                    for ip, win in s.ip_windows.items()
                ]
            top_ips = sorted(ip_rates, key=lambda x: x["rps"], reverse=True)[:10]

            # --- Baseline ---
            with s.baseline_lock:
                mean = s.baseline_state.mean
                stddev = s.baseline_state.stddev

            # --- System metrics ---
            cpu = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory().percent

            # --- Uptime ---
            uptime = (now - s.daemon_start_time).total_seconds()

            return jsonify(
                banned_ips=banned_ips,
                global_rps=round(global_rps, 2),
                top_ips=top_ips,
                cpu_percent=round(cpu, 1),
                memory_percent=round(mem, 1),
                baseline_mean=round(mean, 4),
                baseline_stddev=round(stddev, 4),
                uptime_seconds=round(uptime, 1),
                parse_errors=s.parse_error_count,
            )

        except Exception as exc:
            # Degraded response — never return HTTP 500
            return jsonify(
                banned_ips=[],
                global_rps=0.0,
                top_ips=[],
                cpu_percent=0.0,
                memory_percent=0.0,
                baseline_mean=0.0,
                baseline_stddev=0.0,
                uptime_seconds=0.0,
                parse_errors=0,
                error=str(exc),
            )

    return app
