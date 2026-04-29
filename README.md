# HNG DDoS Anomaly Detection Engine

A real-time security watchdog for a Nextcloud cloud storage platform. It tails Nginx access logs, learns what normal traffic looks like using rolling statistical baselines, and automatically blocks attackers via iptables — all without hardcoded thresholds, rate-limiting libraries, or Fail2Ban.

---

## Server Details

> **Fill these in before submission**

- **Server IP:** `YOUR_SERVER_IP`
- **Dashboard URL:** `http://monitor.yourdomain.com:5000`
- **GitHub Repo:** `https://github.com/YOUR_USERNAME/YOUR_REPO`
- **Blog Post:** `https://YOUR_BLOG_URL`

---

## Language Choice

**Python 3.11**

Python was chosen because:
- `collections.deque` provides O(1) append and automatic eviction for sliding windows — no external library needed
- `statistics.mean` / `statistics.stdev` handle baseline computation cleanly
- `subprocess` runs iptables commands directly
- `Flask` serves the dashboard with minimal boilerplate
- The logic is readable and auditable — important for a security tool

---

## Architecture

```
Internet Traffic
       ↓
   [Nginx]  ←── reverse proxy, writes JSON logs to HNG-nginx-logs volume
       ↓
 [Nextcloud] ←── kefaslungu/hng-nextcloud (untouched)
       ↓
[Detector Daemon] ←── reads logs, detects anomalies, blocks IPs
   ├── monitor.py      tail -f the log file
   ├── baseline.py     rolling 30-min statistical baseline
   ├── detector.py     z-score + rate-multiplier anomaly detection
   ├── blocker.py      iptables DROP rules
   ├── unbanner.py     exponential backoff auto-unban
   ├── notifier.py     Slack webhook alerts
   ├── dashboard.py    Flask live metrics UI
   └── main.py         orchestrator + supervisor loop
```

All three containers share a named Docker volume (`HNG-nginx-logs`). Nginx writes to it; Nextcloud and the Detector mount it read-only.

---

## How the Sliding Window Works

The sliding window is the core data structure that tracks request rates in real time. It is implemented using `collections.deque` — a double-ended queue that supports O(1) appends and pops from both ends.

```
deque: [ts1, ts2, ts3, ts4, ts5, ..., tsN]
        ↑                              ↑
     oldest                         newest
```

**Two windows are maintained:**
- One **global** window — counts all requests across all IPs
- One **per-IP** window — one deque per source IP

**Eviction logic (time-based, not count-based):**

Every time a new event is added, the deque pops entries from the left until the oldest entry is within the last `window_seconds` (default 60 seconds):

```python
def add(self, ts: datetime) -> None:
    self._events.append(ts)
    cutoff = ts.timestamp() - self.window_seconds
    while self._events and self._events[0].timestamp() < cutoff:
        self._events.popleft()
```

**Rate calculation:**

```python
def rate(self) -> float:
    count = sum(1 for e in self._events if e.timestamp() >= cutoff)
    return count / self.window_seconds  # events per second
```

This gives a true rolling rate — not a per-minute counter, not a fixed bucket. If 300 requests arrive in the last 60 seconds, the rate is 5.0 req/s.

---

## How the Baseline Works

The baseline answers: *"What is normal traffic for this server right now?"*

It cannot be hardcoded because traffic varies by time of day — a server might see 2 req/s at 3am and 20 req/s at 2pm. A hardcoded value would either miss attacks during busy hours or generate false positives during quiet ones.

**Rolling 30-minute window:**

Every 60 seconds, `BaselineCalculator` snapshots the current global req/s and appends it to a 30-minute rolling collection. Samples older than 30 minutes are evicted.

**Per-hour slots:**

Samples are also stored in hourly buckets (keyed by UTC hour-of-day). When the current hour's bucket has ≥ 60 samples (1 hour of data), the baseline uses that bucket instead of the full 30-minute window. This makes the baseline time-of-day-aware.

**Statistics:**

```python
mean   = statistics.mean(samples)    # average req/s
stddev = statistics.stdev(samples)   # spread of req/s
mean   = max(1.0, mean)              # floor: never below 1.0 req/s
```

The floor of 1.0 prevents division-by-zero in the z-score calculation during very quiet periods.

**Recalculation interval:** every 60 seconds (configurable via `config.yaml`).

Every recalculation writes a `BASELINE_RECALC` entry to the audit log:
```
[2025-04-26T14:00:00Z] BASELINE_RECALC ip=global | mean=3.1000 | stddev=0.8000
```

---

## How Anomaly Detection Works

The detector runs a tight loop every 1 second, evaluating every active IP and the global rate.

**Two conditions — whichever fires first:**

### 1. Z-Score (statistical deviation)

```
z = (current_rate - mean) / stddev
```

If `z > 3.0`, the IP is flagged. A z-score of 3.0 means the current rate is 3 standard deviations above the mean — statistically, this happens by chance less than 0.3% of the time under normal conditions.

This catches gradual ramp-up attacks that stay below an absolute threshold but are clearly abnormal relative to the server's own history.

### 2. Rate Multiplier (absolute burst)

```
if current_rate > 5.0 × mean → flag
```

This catches sudden burst attacks that happen before the baseline has enough variance to produce a meaningful z-score (e.g. in the first few minutes of operation).

### 3. Error Surge (tightened thresholds)

If an IP's 4xx/5xx error rate exceeds `3 × baseline_error_rate`, both thresholds are halved for that IP:
- z-score threshold: 3.0 → 1.5
- rate multiplier: 5.0 → 2.5

This catches credential-stuffing and scanning attacks that generate lots of errors even at moderate request rates.

### Global vs Per-IP

- **Per-IP anomaly** → iptables DROP rule + Slack alert
- **Global anomaly** → Slack alert only (no block — could be legitimate traffic surge)

---

## How Blocking Works

When an IP is flagged:

1. **Idempotency check** — if already in `ban_registry`, skip
2. **iptables rule** — `iptables -A INPUT -s <IP> -j DROP` (kernel-level packet drop, zero application overhead)
3. **BanRecord** stored with: IP, timestamp, condition, rate at ban, backoff level
4. **Audit log entry** written
5. **Slack alert** sent

The backoff level determines ban duration:

| Backoff Level | Duration | Auto-unban? |
|---|---|---|
| 0 | 10 minutes | Yes |
| 1 | 30 minutes | Yes |
| 2 | 2 hours | Yes |
| 3 | Permanent | No |

Each time an IP is unbanned and re-offends, its next ban is longer. After 3 offences, the ban is permanent.

---

## How Auto-Unban Works

The `Unbanner` runs every 30 seconds and checks every active `BanRecord`:

```python
elapsed = (now - record.banned_at).total_seconds()
if elapsed >= record.duration_seconds:
    unban(ip)
```

On unban:
1. `iptables -D INPUT -s <IP> -j DROP` (removes the rule)
2. `ban_history[ip]` incremented (persists the escalated backoff level)
3. `BanRecord` removed from active registry
4. Audit log entry written
5. Slack alert sent

Permanent bans (`duration_seconds == 0`) are never touched by the unbanner.

---

## Audit Log

Every significant event is written to `/var/log/detector/audit.log` in a structured pipe-delimited format:

```
[2025-04-26T14:32:01Z] BAN ip=1.2.3.4 | condition=zscore | rate=47.0/s | baseline=3.2/s | duration=600s
[2025-04-26T14:42:01Z] UNBAN ip=1.2.3.4 | condition=backoff-0 | rate=N/A | baseline=3.2/s | duration=1800s
[2025-04-26T14:00:00Z] BASELINE_RECALC ip=global | mean=3.1000 | stddev=0.8000
[2025-04-26T14:05:00Z] ERROR subsystem=monitor | msg=Log file not found — retrying in 5s
```

The log is append-only and thread-safe (protected by a `threading.Lock`).

---

## Live Dashboard

The Flask dashboard is served at port 5000 (configurable) and auto-refreshes every 3 seconds via JavaScript `fetch`.

**Metrics displayed:**
- Global req/s
- Baseline mean and stddev
- Number of currently banned IPs
- CPU and memory usage
- Daemon uptime
- Parse error count
- Table of active bans with condition, rate, backoff level, and duration
- Top 10 source IPs by current req/s
- Baseline mean over time (Chart.js line graph, updates every 60s)

**API endpoints:**
- `GET /` — HTML dashboard
- `GET /api/metrics` — JSON snapshot of all live metrics
- `GET /api/baseline-history` — JSON array of baseline recalculation history

---

## Configuration

All thresholds live in `config.yaml`. Nothing is hardcoded in source:

```yaml
slack_webhook_url: "https://hooks.slack.com/services/..."

zscore_threshold: 3.0          # flag if z-score exceeds this
rate_multiplier: 5.0           # flag if rate > N × mean
error_rate_multiplier: 3.0     # tighten thresholds if error rate > N × baseline

sliding_window_seconds: 60     # deque window size
baseline_window_minutes: 30    # rolling baseline window
baseline_recalc_interval_seconds: 60

dashboard_port: 5000
log_file_path: "/var/log/nginx/hng-access.log"
audit_log_path: "/var/log/detector/audit.log"
```

The Slack webhook URL can also be provided via the `SLACK_WEBHOOK_URL` environment variable (set in `.env`, which is gitignored).

---

## Repository Structure

```
.
├── docker-compose.yml
├── config.yaml
├── nginx/
│   └── nginx.conf
├── detector/
│   ├── main.py          # orchestrator + supervisor loop
│   ├── monitor.py       # log tailer
│   ├── baseline.py      # rolling baseline calculator
│   ├── detector.py      # anomaly detection engine
│   ├── blocker.py       # iptables blocking
│   ├── unbanner.py      # auto-unban with backoff
│   ├── notifier.py      # Slack alerts
│   ├── dashboard.py     # Flask live UI
│   ├── audit_log.py     # thread-safe audit log writer
│   ├── models.py        # shared data structures
│   ├── config.py        # config loader
│   ├── requirements.txt
│   ├── Dockerfile
│   └── tests/
│       ├── test_monitor.py
│       ├── test_baseline.py
│       ├── test_detector.py
│       ├── test_blocker.py
│       ├── test_unbanner.py
│       ├── test_notifier.py
│       ├── test_dashboard.py
│       ├── test_audit_log.py
│       ├── test_config.py
│       ├── test_main.py
│       ├── test_docker_config.py
│       └── test_integration.py
└── docs/
    └── architecture.png
```

---

## Setup: Fresh VPS to Running Stack

### 1. Provision the VPS

- Ubuntu 22.04 LTS, minimum 2 vCPU / 2 GB RAM
- Open ports: 80, 443, 5000

### 2. Install Docker

```bash
apt update && apt upgrade -y
apt install -y ca-certificates curl gnupg
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
  > /etc/apt/sources.list.d/docker.list
apt update
apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
systemctl enable docker && systemctl start docker
```

### 3. Clone the repo

```bash
git clone https://github.com/YOUR_USERNAME/YOUR_REPO.git
cd YOUR_REPO
```

### 4. Configure secrets

```bash
cp .env.example .env   # or create .env manually
# Add your Slack webhook URL:
echo "SLACK_WEBHOOK_URL=https://hooks.slack.com/services/..." >> .env
```

Or edit `config.yaml` directly and replace the `slack_webhook_url` placeholder.

### 5. Start the stack

```bash
docker compose up -d
docker compose logs -f detector
```

### 6. Verify

```bash
# Check all containers are running
docker compose ps

# Tail the audit log
docker compose exec detector tail -f /var/log/detector/audit.log

# Check iptables rules
docker compose exec detector iptables -L INPUT -n

# Open the dashboard
curl http://localhost:5000/api/metrics
```

### 7. Point your domain

Create an A record at your DNS provider:
```
monitor.yourdomain.com → YOUR_SERVER_IP
```

The dashboard is then accessible at `http://monitor.yourdomain.com:5000`.

---

## Running Tests

```bash
# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r detector/requirements.txt

# Run all tests
python -m pytest detector/tests/ -v

# Run only integration tests
python -m pytest detector/tests/test_integration.py -v
```

184 tests covering:
- 19 correctness properties verified via Hypothesis property-based testing (200 examples each)
- Unit tests for every module
- Integration tests for the full detection pipeline, timing guarantees, backoff escalation, audit format, and Slack payload content

---

## What This Tool Does NOT Use

| Prohibited | Why it's absent |
|---|---|
| Fail2Ban | Built from scratch — all detection logic is custom |
| `slowapi`, `limits`, or any rate-limiting library | Sliding windows are hand-rolled using `collections.deque` |
| Hardcoded `effective_mean` | Baseline is computed from live traffic every 60 seconds |
| Per-minute counters | True time-based deque eviction, not bucket counting |

---

## Blog Post

> Link: `https://YOUR_BLOG_URL`
