"""
test_integration.py — End-to-end integration tests.

These tests wire real subsystem instances together (no mocks for the core
data flow) and verify that the components interact correctly as a system.

Test scenarios:
  1. Log ingestion → sliding window:
     Write a JSON log line to a temp file, start a LogTailer thread, and
     assert the event appears in the sliding window within 1 second.

  2. Ban trigger → registry + audit log:
     Call Blocker.ban() with a mocked subprocess.run, assert the BanRecord
     is in ban_registry and the audit log contains a correctly formatted
     BAN entry.

  3. Baseline recalculation timing:
     Seed the baseline window with samples, call recalculate() directly,
     and assert baseline_state is updated with the correct mean/stddev.

  4. Full detection pipeline:
     Write high-rate log lines to a temp file, run LogTailer + Detector
     together, and assert Blocker.ban() is called within a reasonable time.

  5. Unban after expiry:
     Ban an IP, advance its ban time to be expired, run _check_expired(),
     and assert the IP is removed from ban_registry and ban_history is
     updated.

  6. Dashboard reflects live ban state:
     Ban an IP via Blocker, then call GET /api/metrics and assert the
     banned IP appears in the response.
"""

import json
import os
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _make_config(**overrides):
    from detector.config import Config
    defaults = dict(
        slack_webhook_url="https://hooks.slack.com/x",
        sliding_window_seconds=60,
        baseline_window_minutes=30,
        baseline_recalc_interval_seconds=60,
        dashboard_port=5001,
        log_file_path="/tmp/test-access.log",
        audit_log_path="/tmp/test-audit.log",
    )
    defaults.update(overrides)
    return Config(**defaults)


def _make_shared(config=None):
    from detector.models import SharedState
    if config is None:
        config = _make_config()
    return SharedState(config=config)


def _valid_log_line(
    source_ip="1.2.3.4",
    status=200,
    method="GET",
    path="/index.html",
    response_size=512,
) -> str:
    return json.dumps({
        "source_ip": source_ip,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00"),
        "method": method,
        "path": path,
        "status": status,
        "response_size": response_size,
    }) + "\n"


def _mock_iptables():
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stderr = ""
    return patch("detector.blocker.subprocess.run", return_value=mock_result)


def _mock_iptables_delete():
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stderr = ""
    return patch("detector.unbanner.subprocess.run", return_value=mock_result)


# ---------------------------------------------------------------------------
# Test 1: Log ingestion → sliding window
# ---------------------------------------------------------------------------

class TestLogIngestionToSlidingWindow:
    def test_log_line_appears_in_window_within_1_second(self, tmp_path):
        """
        Write a JSON log line to a temp file, start a LogTailer thread,
        and assert the event appears in the global sliding window within 1s.
        Requirements: 2.2, 2.5, 1.3
        """
        from detector.monitor import LogTailer

        log_path = str(tmp_path / "access.log")
        # Create the file first (empty) so LogTailer doesn't retry
        open(log_path, "w").close()

        config = _make_config(log_file_path=log_path)
        shared = _make_shared(config)

        tailer = LogTailer(shared)
        t = threading.Thread(target=tailer.run, daemon=True)
        t.start()

        # Give the tailer a moment to open and seek to EOF
        time.sleep(0.2)

        # Append a log line
        with open(log_path, "a") as f:
            f.write(_valid_log_line(source_ip="10.0.0.1"))

        # Assert it appears in the window within 1 second
        deadline = time.time() + 1.0
        while time.time() < deadline:
            with shared.windows_lock:
                if len(shared.global_window) >= 1:
                    break
            time.sleep(0.05)

        with shared.windows_lock:
            assert len(shared.global_window) >= 1, (
                "Log line did not appear in global_window within 1 second"
            )
            assert "10.0.0.1" in shared.ip_windows, (
                "Source IP not found in ip_windows"
            )

    def test_multiple_ips_each_get_own_window(self, tmp_path):
        """Multiple IPs in the log each get their own sliding window."""
        from detector.monitor import LogTailer

        log_path = str(tmp_path / "access.log")
        open(log_path, "w").close()

        config = _make_config(log_file_path=log_path)
        shared = _make_shared(config)

        tailer = LogTailer(shared)
        t = threading.Thread(target=tailer.run, daemon=True)
        t.start()
        time.sleep(0.2)

        ips = ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
        with open(log_path, "a") as f:
            for ip in ips:
                f.write(_valid_log_line(source_ip=ip))

        deadline = time.time() + 1.0
        while time.time() < deadline:
            with shared.windows_lock:
                if len(shared.ip_windows) >= 3:
                    break
            time.sleep(0.05)

        with shared.windows_lock:
            for ip in ips:
                assert ip in shared.ip_windows, f"{ip} not in ip_windows"

    def test_error_lines_populate_error_window(self, tmp_path):
        """4xx/5xx log lines populate ip_error_windows."""
        from detector.monitor import LogTailer

        log_path = str(tmp_path / "access.log")
        open(log_path, "w").close()

        config = _make_config(log_file_path=log_path)
        shared = _make_shared(config)

        tailer = LogTailer(shared)
        t = threading.Thread(target=tailer.run, daemon=True)
        t.start()
        time.sleep(0.2)

        with open(log_path, "a") as f:
            f.write(_valid_log_line(source_ip="5.5.5.5", status=404))

        deadline = time.time() + 1.0
        while time.time() < deadline:
            with shared.windows_lock:
                if "5.5.5.5" in shared.ip_error_windows:
                    break
            time.sleep(0.05)

        with shared.windows_lock:
            assert "5.5.5.5" in shared.ip_error_windows


# ---------------------------------------------------------------------------
# Test 2: Ban trigger → registry + audit log
# ---------------------------------------------------------------------------

class TestBanTrigger:
    def test_ban_creates_registry_entry_and_audit_line(self, tmp_path):
        """
        Blocker.ban() with mocked iptables creates a BanRecord in
        ban_registry and writes a BAN line to the audit log.
        Requirements: 5.1, 5.2, 5.4
        """
        from detector.audit_log import AuditLog
        from detector.blocker import Blocker
        from detector.notifier import Notifier

        audit_path = str(tmp_path / "audit.log")
        config = _make_config(audit_log_path=audit_path)
        shared = _make_shared(config)
        shared.audit_log = AuditLog(audit_path)

        notifier = Notifier(config, shared.audit_log)
        # Silence Slack POST in tests
        with patch("detector.notifier.requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            blocker = Blocker(shared, notifier)

            with _mock_iptables():
                blocker.ban("192.168.1.100", "zscore", 87.3)

        # BanRecord in registry
        assert "192.168.1.100" in shared.ban_registry
        record = shared.ban_registry["192.168.1.100"]
        assert record.condition == "zscore"
        assert record.rate_at_ban == pytest.approx(87.3)
        assert record.backoff_level == 0
        assert record.duration_seconds == 600

        # Audit log entry
        shared.audit_log.close()
        with open(audit_path) as f:
            content = f.read()
        assert "BAN" in content
        assert "192.168.1.100" in content
        assert "zscore" in content

    def test_second_ban_same_ip_is_noop(self, tmp_path):
        """Calling ban() twice for the same IP results in one registry entry."""
        from detector.audit_log import AuditLog
        from detector.blocker import Blocker
        from detector.notifier import Notifier

        audit_path = str(tmp_path / "audit.log")
        config = _make_config(audit_log_path=audit_path)
        shared = _make_shared(config)
        shared.audit_log = AuditLog(audit_path)
        notifier = Notifier(config, shared.audit_log)

        with patch("detector.notifier.requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            blocker = Blocker(shared, notifier)

            with _mock_iptables() as mock_run:
                blocker.ban("10.0.0.1", "zscore", 50.0)
                blocker.ban("10.0.0.1", "zscore", 60.0)  # duplicate

        assert mock_run.call_count == 1
        assert len(shared.ban_registry) == 1


# ---------------------------------------------------------------------------
# Test 3: Baseline recalculation
# ---------------------------------------------------------------------------

class TestBaselineRecalculation:
    def test_recalculate_updates_baseline_state(self):
        """
        After seeding the baseline window and calling recalculate(),
        baseline_state reflects the seeded samples.
        Requirements: 3.2, 3.4
        """
        from detector.baseline import BaselineCalculator

        shared = _make_shared()
        calc = BaselineCalculator(shared)

        now = datetime.now(timezone.utc)
        # Seed with known values: mean should be ~10.0
        for i in range(10):
            shared.baseline_window.add_sample(
                now - timedelta(seconds=i + 1), 10.0
            )
        # Also seed global window so live snapshot is ~10.0
        for _ in range(600):
            shared.global_window.add(now - timedelta(seconds=1))

        calc.recalculate()

        with shared.baseline_lock:
            assert shared.baseline_state.mean >= 1.0
            assert shared.baseline_state.mean == pytest.approx(10.0, abs=1.5)

    def test_recalculate_never_produces_mean_below_floor(self):
        """
        Even with all-zero samples, baseline_state.mean >= 1.0.
        Requirements: 3.4
        """
        from detector.baseline import BaselineCalculator

        shared = _make_shared()
        calc = BaselineCalculator(shared)

        now = datetime.now(timezone.utc)
        for i in range(5):
            shared.baseline_window.add_sample(
                now - timedelta(seconds=i + 1), 0.0
            )

        calc.recalculate()

        with shared.baseline_lock:
            assert shared.baseline_state.mean >= 1.0

    def test_recalculate_writes_audit_entry(self, tmp_path):
        """recalculate() writes a BASELINE_RECALC entry to the audit log."""
        from detector.audit_log import AuditLog
        from detector.baseline import BaselineCalculator

        audit_path = str(tmp_path / "audit.log")
        shared = _make_shared()
        shared.audit_log = AuditLog(audit_path)
        calc = BaselineCalculator(shared)

        calc.recalculate()
        shared.audit_log.close()

        with open(audit_path) as f:
            content = f.read()
        assert "BASELINE_RECALC" in content
        assert "mean=" in content
        assert "stddev=" in content


# ---------------------------------------------------------------------------
# Test 4: Full detection pipeline (LogTailer + Detector → Blocker.ban)
# ---------------------------------------------------------------------------

class TestFullDetectionPipeline:
    def test_high_rate_ip_gets_banned(self, tmp_path):
        """
        Write many log lines from one IP to a temp file.
        LogTailer feeds them into the sliding window.
        Detector evaluates and calls Blocker.ban() for the high-rate IP.
        Requirements: 4.3, 5.1, 1.3
        """
        from detector.blocker import Blocker
        from detector.detector import Detector
        from detector.models import BaselineState
        from detector.monitor import LogTailer
        from detector.notifier import Notifier

        log_path = str(tmp_path / "access.log")
        open(log_path, "w").close()

        config = _make_config(log_file_path=log_path)
        shared = _make_shared(config)
        # Set a low baseline so the high-rate IP triggers detection
        shared.baseline_state = BaselineState(
            mean=1.0, stddev=0.1, last_updated=datetime.now(timezone.utc)
        )

        notifier = MagicMock()
        ban_calls = []

        with patch("detector.notifier.requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            blocker = Blocker(shared, notifier)

        original_ban = blocker.ban
        def tracking_ban(ip, condition, rate):
            ban_calls.append(ip)
            with _mock_iptables():
                original_ban(ip, condition, rate)

        blocker.ban = tracking_ban

        detector = Detector(shared, blocker, notifier)

        # Start log tailer
        tailer = LogTailer(shared)
        tailer_thread = threading.Thread(target=tailer.run, daemon=True)
        tailer_thread.start()
        time.sleep(0.2)

        # Write 300 log lines from the attack IP (300/60s = 5 req/s,
        # which is 5x the mean of 1.0 — triggers rate_multiplier)
        attack_ip = "99.99.99.99"
        with open(log_path, "a") as f:
            for _ in range(300):
                f.write(_valid_log_line(source_ip=attack_ip))

        # Give tailer time to ingest
        time.sleep(0.5)

        # Run one detector evaluation cycle
        detector._evaluate_all()

        assert attack_ip in ban_calls, (
            f"Expected {attack_ip} to be banned, ban_calls={ban_calls}"
        )


# ---------------------------------------------------------------------------
# Test 5: Unban after expiry
# ---------------------------------------------------------------------------

class TestUnbanAfterExpiry:
    def test_expired_ban_removed_and_history_updated(self, tmp_path):
        """
        Ban an IP, set its ban time to be expired, run _check_expired(),
        and assert the IP is removed from ban_registry and ban_history updated.
        Requirements: 6.1, 6.2, 6.3
        """
        from detector.audit_log import AuditLog
        from detector.blocker import Blocker
        from detector.models import BanRecord
        from detector.notifier import Notifier
        from detector.unbanner import Unbanner

        audit_path = str(tmp_path / "audit.log")
        config = _make_config(audit_log_path=audit_path)
        shared = _make_shared(config)
        shared.audit_log = AuditLog(audit_path)

        notifier = MagicMock()

        # Manually insert an expired BanRecord (level 0, 600s, banned 700s ago)
        expired_record = BanRecord(
            ip="7.7.7.7",
            banned_at=datetime.now(timezone.utc) - timedelta(seconds=700),
            duration_seconds=600,
            backoff_level=0,
            condition="zscore",
            rate_at_ban=50.0,
            mean_at_ban=5.0,
        )
        with shared.ban_lock:
            shared.ban_registry["7.7.7.7"] = expired_record

        unbanner = Unbanner(shared, notifier)

        with _mock_iptables_delete():
            unbanner._check_expired()

        # IP removed from active registry
        with shared.ban_lock:
            assert "7.7.7.7" not in shared.ban_registry
            # ban_history updated to level 1
            assert shared.ban_history.get("7.7.7.7") == 1

        # Slack unban alert sent
        notifier.send_unban_alert.assert_called_once()

        # Audit log has UNBAN entry
        shared.audit_log.close()
        with open(audit_path) as f:
            content = f.read()
        assert "UNBAN" in content
        assert "7.7.7.7" in content

    def test_permanent_ban_not_removed(self):
        """Level-3 (permanent) bans are never removed by _check_expired()."""
        from detector.models import BanRecord
        from detector.unbanner import Unbanner

        shared = _make_shared()
        notifier = MagicMock()

        permanent_record = BanRecord(
            ip="8.8.8.8",
            banned_at=datetime.now(timezone.utc) - timedelta(days=365),
            duration_seconds=0,  # permanent
            backoff_level=3,
            condition="zscore",
            rate_at_ban=100.0,
            mean_at_ban=5.0,
        )
        with shared.ban_lock:
            shared.ban_registry["8.8.8.8"] = permanent_record

        unbanner = Unbanner(shared, notifier)

        with patch("detector.unbanner.subprocess.run") as mock_run:
            unbanner._check_expired()

        mock_run.assert_not_called()
        with shared.ban_lock:
            assert "8.8.8.8" in shared.ban_registry


# ---------------------------------------------------------------------------
# Test 6: Dashboard reflects live ban state
# ---------------------------------------------------------------------------

class TestDashboardReflectsBanState:
    def test_banned_ip_appears_in_metrics(self, tmp_path):
        """
        After banning an IP via Blocker, GET /api/metrics returns that IP
        in the banned_ips list.
        Requirements: 8.3
        """
        from detector.audit_log import AuditLog
        from detector.blocker import Blocker
        from detector.dashboard import create_app
        from detector.notifier import Notifier

        audit_path = str(tmp_path / "audit.log")
        config = _make_config(audit_log_path=audit_path)
        shared = _make_shared(config)
        shared.audit_log = AuditLog(audit_path)

        notifier = Notifier(config, shared.audit_log)
        blocker = Blocker(shared, notifier)

        with patch("detector.notifier.requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            with _mock_iptables():
                blocker.ban("55.55.55.55", "rate_multiplier", 42.0)

        # Query the dashboard
        app = create_app(shared)
        app.config["TESTING"] = True
        client = app.test_client()

        with patch("detector.dashboard.psutil.cpu_percent", return_value=5.0):
            with patch("detector.dashboard.psutil.virtual_memory") as m:
                m.return_value = MagicMock(percent=30.0)
                resp = client.get("/api/metrics")

        data = json.loads(resp.data)
        banned_ips = [b["ip"] for b in data["banned_ips"]]
        assert "55.55.55.55" in banned_ips, (
            f"Banned IP not in dashboard response. banned_ips={banned_ips}"
        )

    def test_unbanned_ip_disappears_from_metrics(self, tmp_path):
        """
        After unbanning an IP, it no longer appears in /api/metrics.
        Requirements: 8.3
        """
        from detector.audit_log import AuditLog
        from detector.blocker import Blocker
        from detector.dashboard import create_app
        from detector.models import BanRecord
        from detector.notifier import Notifier
        from detector.unbanner import Unbanner

        audit_path = str(tmp_path / "audit.log")
        config = _make_config(audit_log_path=audit_path)
        shared = _make_shared(config)
        shared.audit_log = AuditLog(audit_path)

        notifier = MagicMock()

        # Insert an expired ban
        record = BanRecord(
            ip="66.66.66.66",
            banned_at=datetime.now(timezone.utc) - timedelta(seconds=700),
            duration_seconds=600,
            backoff_level=0,
            condition="zscore",
            rate_at_ban=50.0,
            mean_at_ban=5.0,
        )
        with shared.ban_lock:
            shared.ban_registry["66.66.66.66"] = record

        unbanner = Unbanner(shared, notifier)
        with _mock_iptables_delete():
            unbanner._check_expired()

        # Query dashboard
        app = create_app(shared)
        app.config["TESTING"] = True
        client = app.test_client()

        with patch("detector.dashboard.psutil.cpu_percent", return_value=5.0):
            with patch("detector.dashboard.psutil.virtual_memory") as m:
                m.return_value = MagicMock(percent=30.0)
                resp = client.get("/api/metrics")

        data = json.loads(resp.data)
        banned_ips = [b["ip"] for b in data["banned_ips"]]
        assert "66.66.66.66" not in banned_ips, (
            "Unbanned IP still appears in dashboard response"
        )


# ===========================================================================
# Additional coverage — 10 gap scenarios
# ===========================================================================

# ---------------------------------------------------------------------------
# Gap 1: Z-score path fires independently (rate < 5x but z-score > 3.0)
# ---------------------------------------------------------------------------

class TestZscorePathIndependent:
    def test_zscore_triggers_ban_without_rate_multiplier(self):
        """
        Set mean=10.0, stddev=0.1 so that a rate of 10.4 req/s produces
        z-score = (10.4 - 10.0) / 0.1 = 4.0 > 3.0, but 10.4 < 5 * 10.0 = 50.
        Only the z-score condition should fire.
        """
        from detector.blocker import Blocker
        from detector.detector import Detector
        from detector.models import BaselineState, SlidingWindow
        from detector.notifier import Notifier

        shared = _make_shared()
        # mean=10.0, stddev=0.1 → z-score fires at rate ~10.4, rate_mult fires at 50
        shared.baseline_state = BaselineState(
            mean=10.0, stddev=0.1, last_updated=datetime.now(timezone.utc)
        )

        notifier = MagicMock()
        blocker = Blocker(shared, notifier)

        ban_calls = []
        original_ban = blocker.ban
        def tracking_ban(ip, condition, rate):
            ban_calls.append((ip, condition))
            with _mock_iptables():
                original_ban(ip, condition, rate)
        blocker.ban = tracking_ban

        detector = Detector(shared, blocker, notifier)

        # Inject a window with rate = 10.4 req/s (well below 5x=50, but z>3)
        now = datetime.now(timezone.utc)
        w = SlidingWindow(window_seconds=60)
        for _ in range(624):  # 624 / 60 = 10.4 req/s
            w.add(now - timedelta(seconds=1))
        with shared.windows_lock:
            shared.ip_windows["zscore-ip"] = w

        with patch("detector.notifier.requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            detector._evaluate_all()

        assert any(ip == "zscore-ip" for ip, _ in ban_calls), (
            "IP was not banned via z-score path"
        )
        # Condition must be zscore, not rate_multiplier
        for ip, condition in ban_calls:
            if ip == "zscore-ip":
                assert condition == "zscore", (
                    f"Expected condition='zscore', got '{condition}'"
                )


# ---------------------------------------------------------------------------
# Gap 2: Global anomaly → Slack only, no iptables
# ---------------------------------------------------------------------------

class TestGlobalAnomalySlackOnly:
    def test_global_spike_sends_slack_but_no_iptables(self):
        """
        A global traffic spike must trigger a Slack alert but must NOT
        add any iptables rule or create a BanRecord.
        Requirements: 4.3 (global), 5.1
        """
        from detector.blocker import Blocker
        from detector.detector import Detector
        from detector.models import BaselineState, SlidingWindow
        from detector.notifier import Notifier

        shared = _make_shared()
        shared.baseline_state = BaselineState(
            mean=1.0, stddev=0.1, last_updated=datetime.now(timezone.utc)
        )

        notifier = MagicMock()
        blocker = Blocker(shared, notifier)
        detector = Detector(shared, blocker, notifier)

        # Inject a very high global rate (well above 5x mean=1.0)
        now = datetime.now(timezone.utc)
        for _ in range(600):  # 600/60 = 10 req/s → 10x mean
            shared.global_window.add(now - timedelta(seconds=1))

        with patch("detector.blocker.subprocess.run") as mock_iptables:
            detector._evaluate_global()

        # Slack alert sent
        notifier.send_global_anomaly_alert.assert_called_once()

        # No iptables call
        mock_iptables.assert_not_called()

        # No ban registry entries
        with shared.ban_lock:
            assert len(shared.ban_registry) == 0, (
                "Global anomaly must not create ban registry entries"
            )


# ---------------------------------------------------------------------------
# Gap 3: Error surge tightens thresholds
# ---------------------------------------------------------------------------

class TestErrorSurgeTightensThresholds:
    def test_error_heavy_ip_banned_at_lower_threshold(self):
        """
        An IP with elevated 4xx/5xx rate should be banned at a lower
        rate threshold (half of normal) due to tightened thresholds.
        """
        from detector.blocker import Blocker
        from detector.detector import Detector, _BASELINE_ERROR_FRACTION
        from detector.models import BaselineState, SlidingWindow
        from detector.notifier import Notifier

        shared = _make_shared()
        # mean=10.0, stddev=0 → only rate_multiplier can fire
        # Normal threshold: 5x * 10 = 50 req/s
        # Tightened threshold: 2.5x * 10 = 25 req/s
        shared.baseline_state = BaselineState(
            mean=10.0, stddev=0.0, last_updated=datetime.now(timezone.utc)
        )

        notifier = MagicMock()
        blocker = Blocker(shared, notifier)
        ban_calls = []
        original_ban = blocker.ban
        def tracking_ban(ip, condition, rate):
            ban_calls.append(ip)
            with _mock_iptables():
                original_ban(ip, condition, rate)
        blocker.ban = tracking_ban

        detector = Detector(shared, blocker, notifier)

        now = datetime.now(timezone.utc)
        target_ip = "error-heavy-ip"

        # Request rate = 30 req/s — above tightened (25) but below normal (50)
        w = SlidingWindow(window_seconds=60)
        for _ in range(1800):  # 1800/60 = 30 req/s
            w.add(now - timedelta(seconds=1))
        with shared.windows_lock:
            shared.ip_windows[target_ip] = w

        # Error rate = 3x * baseline_error_rate + 1 to trigger tightening
        baseline_error_rate = 10.0 * _BASELINE_ERROR_FRACTION  # 0.5 req/s
        trigger_error_rate = shared.config.error_rate_multiplier * baseline_error_rate + 1
        ew = SlidingWindow(window_seconds=60)
        for _ in range(int(trigger_error_rate * 60) + 10):
            ew.add(now - timedelta(seconds=1))
        with shared.windows_lock:
            shared.ip_error_windows[target_ip] = ew

        with patch("detector.notifier.requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            detector._evaluate_all()

        assert target_ip in ban_calls, (
            "Error-heavy IP was not banned despite rate exceeding tightened threshold"
        )

    def test_normal_error_rate_ip_not_banned_at_intermediate_rate(self):
        """
        An IP with normal error rate and rate between tightened and normal
        threshold should NOT be banned.
        """
        from detector.blocker import Blocker
        from detector.detector import Detector
        from detector.models import BaselineState, SlidingWindow
        from detector.notifier import Notifier

        shared = _make_shared()
        shared.baseline_state = BaselineState(
            mean=10.0, stddev=0.0, last_updated=datetime.now(timezone.utc)
        )

        notifier = MagicMock()
        blocker = Blocker(shared, notifier)
        detector = Detector(shared, blocker, notifier)

        now = datetime.now(timezone.utc)
        target_ip = "normal-error-ip"

        # Rate = 30 req/s — above tightened (25) but below normal (50)
        w = SlidingWindow(window_seconds=60)
        for _ in range(1800):
            w.add(now - timedelta(seconds=1))
        with shared.windows_lock:
            shared.ip_windows[target_ip] = w
        # No error window → normal thresholds apply

        with patch("detector.blocker.subprocess.run") as mock_iptables:
            detector._evaluate_all()

        mock_iptables.assert_not_called()


# ---------------------------------------------------------------------------
# Gap 4: Sliding window eviction
# ---------------------------------------------------------------------------

class TestSlidingWindowEviction:
    def test_events_older_than_window_are_evicted(self):
        """
        Events older than window_seconds must be evicted from the deque
        so they don't inflate the rate calculation.
        """
        from detector.models import SlidingWindow

        w = SlidingWindow(window_seconds=60)
        now = datetime.now(timezone.utc)

        # Add 100 events that are 120 seconds old (outside the 60s window)
        old_ts = now - timedelta(seconds=120)
        for _ in range(100):
            w.add(old_ts)

        # Add 1 fresh event — this triggers eviction of old events
        w.add(now)

        # Only the 1 fresh event should remain
        assert len(w) == 1, (
            f"Expected 1 event after eviction, got {len(w)}"
        )
        assert w.rate() == pytest.approx(1 / 60, abs=0.01)

    def test_rate_reflects_only_recent_events(self):
        """
        rate() must only count events within the last window_seconds,
        not historical events.
        """
        from detector.models import SlidingWindow

        w = SlidingWindow(window_seconds=60)
        now = datetime.now(timezone.utc)

        # Add 600 old events (outside window)
        for _ in range(600):
            w.add(now - timedelta(seconds=90))

        # Add 60 fresh events (inside window)
        for _ in range(60):
            w.add(now - timedelta(seconds=1))

        # Trigger eviction by adding one more fresh event
        w.add(now)

        # Rate should reflect only the 61 fresh events
        assert w.rate() == pytest.approx(61 / 60, abs=0.1)

    def test_empty_window_returns_zero_rate(self):
        from detector.models import SlidingWindow

        w = SlidingWindow(window_seconds=60)
        assert w.rate() == 0.0


# ---------------------------------------------------------------------------
# Gap 5: Unban backoff full escalation chain
# ---------------------------------------------------------------------------

class TestUnbanBackoffEscalation:
    def _ban_at_level(self, shared, ip: str, level: int, elapsed: float):
        from detector.blocker import BACKOFF_DURATIONS
        from detector.models import BanRecord

        duration = BACKOFF_DURATIONS[level]
        record = BanRecord(
            ip=ip,
            banned_at=datetime.now(timezone.utc) - timedelta(seconds=elapsed),
            duration_seconds=duration,
            backoff_level=level,
            condition="zscore",
            rate_at_ban=50.0,
            mean_at_ban=5.0,
        )
        with shared.ban_lock:
            shared.ban_registry[ip] = record

    def test_level_1_to_2_escalation(self):
        """Level 1 (30min) ban expires → history updated to level 2."""
        from detector.unbanner import Unbanner

        shared = _make_shared()
        notifier = MagicMock()
        self._ban_at_level(shared, "1.2.3.4", level=1, elapsed=1900)

        unbanner = Unbanner(shared, notifier)
        with _mock_iptables_delete():
            unbanner._check_expired()

        with shared.ban_lock:
            assert "1.2.3.4" not in shared.ban_registry
            assert shared.ban_history.get("1.2.3.4") == 2

    def test_level_2_to_3_escalation(self):
        """Level 2 (2hr) ban expires → history updated to level 3 (permanent)."""
        from detector.unbanner import Unbanner

        shared = _make_shared()
        notifier = MagicMock()
        self._ban_at_level(shared, "2.3.4.5", level=2, elapsed=7300)

        unbanner = Unbanner(shared, notifier)
        with _mock_iptables_delete():
            unbanner._check_expired()

        with shared.ban_lock:
            assert "2.3.4.5" not in shared.ban_registry
            assert shared.ban_history.get("2.3.4.5") == 3

    def test_next_ban_after_level_3_history_is_permanent(self):
        """
        After ban_history reaches 3, the next Blocker.ban() creates a
        permanent BanRecord (duration_seconds=0).
        """
        from detector.blocker import Blocker
        from detector.notifier import Notifier

        shared = _make_shared()
        # Pre-set history to level 3
        with shared.ban_lock:
            shared.ban_history["3.4.5.6"] = 3

        notifier = MagicMock()
        blocker = Blocker(shared, notifier)

        with patch("detector.notifier.requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            with _mock_iptables():
                blocker.ban("3.4.5.6", "zscore", 50.0)

        record = shared.ban_registry["3.4.5.6"]
        assert record.duration_seconds == 0, (
            "Expected permanent ban (duration_seconds=0) at backoff level 3"
        )
        assert record.backoff_level == 3


# ---------------------------------------------------------------------------
# Gap 6: Slack alert content validation
# ---------------------------------------------------------------------------

class TestSlackAlertContent:
    def test_ban_alert_contains_all_required_fields(self):
        """
        The Slack ban alert payload must contain condition, rate, mean,
        stddev, timestamp, and duration.
        """
        from detector.notifier import Notifier

        config = _make_config()
        captured = {}

        def fake_post(url, json=None, timeout=None):
            captured["payload"] = json
            return MagicMock(status_code=200)

        notifier = Notifier(config)
        with patch("detector.notifier.requests.post", side_effect=fake_post):
            notifier.send_ban_alert(
                ip="1.2.3.4",
                condition="zscore",
                rate=47.3,
                mean=3.2,
                stddev=0.8,
                duration="600s",
            )

        assert "payload" in captured
        payload_str = str(captured["payload"])
        for required in ["zscore", "47.3", "3.2", "0.8", "600s", "1.2.3.4"]:
            assert required in payload_str, (
                f"Required field value '{required}' missing from ban alert payload"
            )

    def test_unban_alert_contains_all_required_fields(self):
        """Unban alert must contain ip, backoff_level, timestamp, next_duration."""
        from detector.notifier import Notifier

        config = _make_config()
        captured = {}

        def fake_post(url, json=None, timeout=None):
            captured["payload"] = json
            return MagicMock(status_code=200)

        notifier = Notifier(config)
        with patch("detector.notifier.requests.post", side_effect=fake_post):
            notifier.send_unban_alert(
                ip="5.6.7.8",
                backoff_level=1,
                next_duration="7200s",
            )

        payload_str = str(captured["payload"])
        for required in ["5.6.7.8", "1", "7200s"]:
            assert required in payload_str, (
                f"Required value '{required}' missing from unban alert payload"
            )

    def test_global_anomaly_alert_contains_all_required_fields(self):
        """Global anomaly alert must contain rate, mean, stddev, timestamp."""
        from detector.notifier import Notifier

        config = _make_config()
        captured = {}

        def fake_post(url, json=None, timeout=None):
            captured["payload"] = json
            return MagicMock(status_code=200)

        notifier = Notifier(config)
        with patch("detector.notifier.requests.post", side_effect=fake_post):
            notifier.send_global_anomaly_alert(rate=88.5, mean=4.1, stddev=1.2)

        payload_str = str(captured["payload"])
        for required in ["88.5", "4.1", "1.2"]:
            assert required in payload_str, (
                f"Required value '{required}' missing from global anomaly payload"
            )


# ---------------------------------------------------------------------------
# Gap 7: Audit log format exactness (pipe-delimited structure)
# ---------------------------------------------------------------------------

class TestAuditLogFormatExactness:
    def test_ban_entry_matches_exact_pipe_format(self, tmp_path):
        """
        BAN audit entry must match:
        [ISO8601Z] BAN ip=X | condition=Y | rate=Z/s | baseline=W/s | duration=D
        """
        import re
        from detector.audit_log import AuditLog

        path = str(tmp_path / "audit.log")
        log = AuditLog(path)
        log.ban("1.2.3.4", "zscore", 47.0, 3.2, "600s",
                ts="2025-04-26T14:32:01Z")
        log.close()

        with open(path) as f:
            line = f.read().strip()

        pattern = re.compile(
            r"^\[2025-04-26T14:32:01Z\] BAN ip=1\.2\.3\.4 \| "
            r"condition=zscore \| rate=47\.0/s \| baseline=3\.2/s \| duration=600s$"
        )
        assert pattern.match(line), (
            f"BAN entry does not match exact pipe-delimited format:\n{line!r}"
        )

    def test_unban_entry_matches_exact_pipe_format(self, tmp_path):
        """
        UNBAN audit entry must match:
        [ISO8601Z] UNBAN ip=X | condition=backoff-N | rate=N/A | baseline=W/s | duration=D
        """
        import re
        from detector.audit_log import AuditLog

        path = str(tmp_path / "audit.log")
        log = AuditLog(path)
        log.unban("1.2.3.4", 0, 3.2, "1800s", ts="2025-04-26T14:42:01Z")
        log.close()

        with open(path) as f:
            line = f.read().strip()

        pattern = re.compile(
            r"^\[2025-04-26T14:42:01Z\] UNBAN ip=1\.2\.3\.4 \| "
            r"condition=backoff-0 \| rate=N/A \| baseline=3\.2/s \| duration=1800s$"
        )
        assert pattern.match(line), (
            f"UNBAN entry does not match exact pipe-delimited format:\n{line!r}"
        )

    def test_baseline_recalc_entry_matches_exact_format(self, tmp_path):
        """
        BASELINE_RECALC entry must match:
        [ISO8601Z] BASELINE_RECALC ip=global | mean=X | stddev=Y
        """
        import re
        from detector.audit_log import AuditLog

        path = str(tmp_path / "audit.log")
        log = AuditLog(path)
        log.baseline_recalc(3.1, 0.8, ts="2025-04-26T14:00:00Z")
        log.close()

        with open(path) as f:
            line = f.read().strip()

        pattern = re.compile(
            r"^\[2025-04-26T14:00:00Z\] BASELINE_RECALC ip=global \| "
            r"mean=3\.1000 \| stddev=0\.8000$"
        )
        assert pattern.match(line), (
            f"BASELINE_RECALC entry does not match exact format:\n{line!r}"
        )


# ---------------------------------------------------------------------------
# Gap 8: Ban must fire within 10 seconds of detection
# ---------------------------------------------------------------------------

class TestBanWithin10Seconds:
    def test_ban_fires_within_10_seconds_of_detection(self, tmp_path):
        """
        From the moment anomalous log lines are written, iptables must be
        called within 10 seconds.
        Requirements: 5.1
        """
        from detector.blocker import Blocker
        from detector.detector import Detector
        from detector.models import BaselineState
        from detector.monitor import LogTailer
        from detector.notifier import Notifier

        log_path = str(tmp_path / "access.log")
        open(log_path, "w").close()

        config = _make_config(log_file_path=log_path)
        shared = _make_shared(config)
        shared.baseline_state = BaselineState(
            mean=1.0, stddev=0.1, last_updated=datetime.now(timezone.utc)
        )

        notifier = MagicMock()
        ban_event = threading.Event()

        with patch("detector.notifier.requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            blocker = Blocker(shared, notifier)

        original_ban = blocker.ban
        def tracking_ban(ip, condition, rate):
            with _mock_iptables():
                original_ban(ip, condition, rate)
            ban_event.set()
        blocker.ban = tracking_ban

        detector = Detector(shared, blocker, notifier)

        # Start tailer
        tailer = LogTailer(shared)
        tailer_thread = threading.Thread(target=tailer.run, daemon=True)
        tailer_thread.start()

        # Start detector loop
        detector_thread = threading.Thread(target=detector.run, daemon=True)
        detector_thread.start()

        time.sleep(0.3)

        # Record the time attack starts
        attack_start = time.time()

        # Write attack traffic
        with open(log_path, "a") as f:
            for _ in range(300):
                f.write(_valid_log_line(source_ip="attack-ip"))

        # Wait for ban to fire
        fired = ban_event.wait(timeout=10.0)
        elapsed = time.time() - attack_start

        assert fired, "Ban did not fire within 10 seconds of attack traffic"
        assert elapsed <= 10.0, (
            f"Ban took {elapsed:.2f}s — must fire within 10 seconds"
        )


# ---------------------------------------------------------------------------
# Gap 9: Per-hour baseline slot preference
# ---------------------------------------------------------------------------

class TestPerHourBaselineSlotPreference:
    def test_current_hour_slot_preferred_when_sufficient(self):
        """
        When the current hour's slot has >= 60 samples, preferred_samples()
        returns those samples rather than the full rolling window.
        """
        from detector.models import BaselineWindow

        bw = BaselineWindow(window_minutes=30)
        now = datetime.now(timezone.utc)
        current_hour = now.hour

        # Populate current hour slot with 60 samples of rate=20.0
        for i in range(60):
            bw._samples.append((now - timedelta(seconds=i + 1), 20.0))
            bw._hourly_slots.setdefault(current_hour, []).append(20.0)

        # Add some samples for a different hour with rate=5.0
        other_hour = (current_hour + 1) % 24
        for i in range(10):
            bw._hourly_slots.setdefault(other_hour, []).append(5.0)

        result = bw.preferred_samples(current_hour)

        assert len(result) == 60
        assert all(r == 20.0 for r in result), (
            "preferred_samples() returned samples from wrong hour slot"
        )

    def test_falls_back_to_rolling_window_when_slot_insufficient(self):
        """
        When the current hour's slot has < 60 samples, preferred_samples()
        falls back to the full rolling window.
        """
        from detector.models import BaselineWindow

        bw = BaselineWindow(window_minutes=30)
        now = datetime.now(timezone.utc)
        current_hour = now.hour

        # Only 30 samples in current hour slot
        for i in range(30):
            bw._samples.append((now - timedelta(seconds=i + 1), 10.0))
            bw._hourly_slots.setdefault(current_hour, []).append(10.0)

        result = bw.preferred_samples(current_hour)
        full = bw.current_samples()

        assert result == full, (
            "Should fall back to full rolling window when slot has < 60 samples"
        )

    def test_baseline_calculator_uses_hourly_slot_in_recalculate(self):
        """
        BaselineCalculator.recalculate() uses the hourly slot when it has
        >= 60 samples, producing a mean close to the slot's rate.
        """
        from detector.baseline import BaselineCalculator

        shared = _make_shared()
        calc = BaselineCalculator(shared)
        now = datetime.now(timezone.utc)
        current_hour = now.hour

        # Populate current hour slot with 60 samples of rate=15.0
        for i in range(60):
            shared.baseline_window._samples.append(
                (now - timedelta(seconds=i + 1), 15.0)
            )
            shared.baseline_window._hourly_slots.setdefault(
                current_hour, []
            ).append(15.0)

        # Also add rolling window samples with a very different rate
        for i in range(5):
            shared.baseline_window._samples.append(
                (now - timedelta(seconds=i + 61), 1.0)
            )

        calc.recalculate()

        with shared.baseline_lock:
            # Mean should be close to 15.0 (hourly slot preferred)
            assert shared.baseline_state.mean == pytest.approx(15.0, abs=1.0), (
                "Baseline did not prefer the current hour's slot"
            )


# ---------------------------------------------------------------------------
# Gap 10: Stddev floor — z-score never divides by zero
# ---------------------------------------------------------------------------

class TestStddevFloor:
    def test_compute_zscore_returns_zero_when_stddev_is_zero(self):
        """
        compute_zscore() must return 0.0 when stddev == 0 to prevent
        division by zero.
        """
        from detector.detector import Detector

        shared = _make_shared()
        det = Detector(shared, MagicMock())
        result = det.compute_zscore(rate=100.0, mean=5.0, stddev=0.0)
        assert result == 0.0

    def test_baseline_with_identical_samples_has_zero_stddev(self):
        """
        When all baseline samples are identical AND the live snapshot matches,
        stddev=0.0. More importantly, the detector must not crash when stddev=0.
        This test verifies the zero-division guard in compute_zscore().
        """
        from detector.baseline import BaselineCalculator
        from detector.blocker import Blocker
        from detector.detector import Detector
        from detector.models import BaselineState, SlidingWindow

        shared = _make_shared()

        # Directly set baseline_state with stddev=0 to test the guard
        shared.baseline_state = BaselineState(
            mean=5.0, stddev=0.0, last_updated=datetime.now(timezone.utc)
        )

        # Run detector — must not raise ZeroDivisionError
        notifier = MagicMock()
        blocker = Blocker(shared, notifier)
        detector = Detector(shared, blocker, notifier)

        now = datetime.now(timezone.utc)
        w = SlidingWindow(window_seconds=60)
        w.add(now - timedelta(seconds=1))
        with shared.windows_lock:
            shared.ip_windows["safe-ip"] = w

        # Should not raise
        with patch("detector.blocker.subprocess.run"):
            detector._evaluate_all()  # no exception = pass

    def test_single_baseline_sample_produces_zero_stddev(self):
        """
        With only one baseline sample, _compute_stats() returns stddev=0.0
        (not enough data for stdev calculation).
        """
        from detector.baseline import BaselineCalculator

        shared = _make_shared()
        calc = BaselineCalculator(shared)
        mean, stddev = calc._compute_stats([7.5])
        assert stddev == 0.0
        assert mean == pytest.approx(7.5)
