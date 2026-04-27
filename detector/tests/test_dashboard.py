"""
test_dashboard.py — Tests for dashboard.py (Flask Dashboard).

Sub-task 11.1: Property 17 — Metrics endpoint returns all required fields
               for any system state (including completely empty state).
Sub-task 11.2: Unit tests for dashboard routes and degraded response.

Tests cover:
  - GET / returns HTTP 200 with HTML content
  - GET /api/metrics returns HTTP 200 with valid JSON
  - All required fields present in /api/metrics response
  - Missing/zero values use defaults (0, 0.0, []) not exceptions
  - Degraded response on SharedState error still returns HTTP 200
  - top_ips is sorted by rps descending and capped at 10
  - banned_ips contains all required sub-fields
"""

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_shared():
    from detector.config import Config
    from detector.models import SharedState

    cfg = Config(slack_webhook_url="https://hooks.slack.com/x")
    return SharedState(config=cfg)


def _make_client(shared=None):
    """Return a Flask test client backed by *shared* (or a fresh empty one)."""
    from detector.dashboard import create_app

    if shared is None:
        shared = _make_shared()
    app = create_app(shared)
    app.config["TESTING"] = True
    return app.test_client(), shared


def _add_ban(shared, ip: str, backoff_level: int = 0):
    from detector.models import BanRecord

    record = BanRecord(
        ip=ip,
        banned_at=datetime.now(timezone.utc),
        duration_seconds=600,
        backoff_level=backoff_level,
        condition="zscore",
        rate_at_ban=50.0,
        mean_at_ban=5.0,
    )
    with shared.ban_lock:
        shared.ban_registry[ip] = record


# ---------------------------------------------------------------------------
# Sub-task 11.1 — Property 17: Metrics endpoint returns all required fields
# Feature: ddos-anomaly-detection-engine, Property 17:
#   For any SharedState (including completely empty), GET /api/metrics
#   returns HTTP 200 with a valid JSON body containing all required fields,
#   with missing values as 0, 0.0, or [] rather than raising an exception.
# ---------------------------------------------------------------------------

REQUIRED_FIELDS = {
    "banned_ips", "global_rps", "top_ips", "cpu_percent",
    "memory_percent", "baseline_mean", "baseline_stddev",
    "uptime_seconds", "parse_errors",
}


@settings(max_examples=200, deadline=None)
@given(
    n_bans=st.integers(min_value=0, max_value=10),
    n_ips=st.integers(min_value=0, max_value=20),
    parse_errors=st.integers(min_value=0, max_value=1000),
    mean=st.floats(min_value=1.0, max_value=100.0, allow_nan=False, allow_infinity=False),
    stddev=st.floats(min_value=0.0, max_value=20.0, allow_nan=False, allow_infinity=False),
)
def test_property17_metrics_returns_all_required_fields(
    n_bans, n_ips, parse_errors, mean, stddev
):
    """
    Property 17: /api/metrics always returns HTTP 200 with all required
    fields for any combination of system state.
    """
    from detector.models import BaselineState, SlidingWindow

    shared = _make_shared()
    shared.parse_error_count = parse_errors
    shared.baseline_state = BaselineState(
        mean=mean, stddev=stddev, last_updated=datetime.now(timezone.utc)
    )

    # Add bans
    for i in range(n_bans):
        _add_ban(shared, f"10.0.0.{i + 1}")

    # Add IP windows
    now = datetime.now(timezone.utc)
    for i in range(n_ips):
        ip = f"192.168.1.{i + 1}"
        w = SlidingWindow(window_seconds=60)
        w.add(now - timedelta(seconds=1))
        with shared.windows_lock:
            shared.ip_windows[ip] = w

    with patch("detector.dashboard.psutil.cpu_percent", return_value=10.0):
        with patch("detector.dashboard.psutil.virtual_memory") as mock_mem:
            mock_mem.return_value = MagicMock(percent=50.0)
            client, _ = _make_client(shared)
            resp = client.get("/api/metrics")

    assert resp.status_code == 200
    data = json.loads(resp.data)

    for field in REQUIRED_FIELDS:
        assert field in data, f"Required field '{field}' missing from /api/metrics response"

    # Types must be correct
    assert isinstance(data["banned_ips"], list)
    assert isinstance(data["top_ips"], list)
    assert isinstance(data["global_rps"], (int, float))
    assert isinstance(data["cpu_percent"], (int, float))
    assert isinstance(data["memory_percent"], (int, float))
    assert isinstance(data["baseline_mean"], (int, float))
    assert isinstance(data["baseline_stddev"], (int, float))
    assert isinstance(data["uptime_seconds"], (int, float))
    assert isinstance(data["parse_errors"], int)


# ---------------------------------------------------------------------------
# Sub-task 11.2 — Unit tests for routes and degraded response
# ---------------------------------------------------------------------------

class TestIndexRoute:
    def test_returns_200(self):
        client, _ = _make_client()
        resp = client.get("/")
        assert resp.status_code == 200

    def test_returns_html(self):
        client, _ = _make_client()
        resp = client.get("/")
        assert b"<!DOCTYPE html>" in resp.data or b"<html" in resp.data

    def test_contains_dashboard_title(self):
        client, _ = _make_client()
        resp = client.get("/")
        assert b"Dashboard" in resp.data or b"DDoS" in resp.data


class TestMetricsRoute:
    def test_returns_200_on_empty_state(self):
        with patch("detector.dashboard.psutil.cpu_percent", return_value=0.0):
            with patch("detector.dashboard.psutil.virtual_memory") as m:
                m.return_value = MagicMock(percent=0.0)
                client, _ = _make_client()
                resp = client.get("/api/metrics")
        assert resp.status_code == 200

    def test_empty_state_uses_zero_defaults(self):
        with patch("detector.dashboard.psutil.cpu_percent", return_value=0.0):
            with patch("detector.dashboard.psutil.virtual_memory") as m:
                m.return_value = MagicMock(percent=0.0)
                client, _ = _make_client()
                resp = client.get("/api/metrics")
        data = json.loads(resp.data)
        assert data["banned_ips"] == []
        assert data["top_ips"] == []
        assert data["global_rps"] == 0.0
        assert data["parse_errors"] == 0

    def test_banned_ips_contains_required_subfields(self):
        shared = _make_shared()
        _add_ban(shared, "1.2.3.4")
        with patch("detector.dashboard.psutil.cpu_percent", return_value=5.0):
            with patch("detector.dashboard.psutil.virtual_memory") as m:
                m.return_value = MagicMock(percent=30.0)
                client, _ = _make_client(shared)
                resp = client.get("/api/metrics")
        data = json.loads(resp.data)
        assert len(data["banned_ips"]) == 1
        ban = data["banned_ips"][0]
        for key in ("ip", "banned_at", "duration_seconds", "backoff_level",
                    "condition", "rate_at_ban"):
            assert key in ban, f"Missing key '{key}' in banned_ips entry"

    def test_top_ips_sorted_by_rps_descending(self):
        from detector.models import SlidingWindow

        shared = _make_shared()
        now = datetime.now(timezone.utc)
        # Add IPs with different rates
        for i, n_events in enumerate([10, 50, 30, 5, 20]):
            ip = f"10.0.0.{i + 1}"
            w = SlidingWindow(window_seconds=60)
            for _ in range(n_events):
                w.add(now - timedelta(seconds=1))
            with shared.windows_lock:
                shared.ip_windows[ip] = w

        with patch("detector.dashboard.psutil.cpu_percent", return_value=5.0):
            with patch("detector.dashboard.psutil.virtual_memory") as m:
                m.return_value = MagicMock(percent=30.0)
                client, _ = _make_client(shared)
                resp = client.get("/api/metrics")

        data = json.loads(resp.data)
        rps_values = [entry["rps"] for entry in data["top_ips"]]
        assert rps_values == sorted(rps_values, reverse=True)

    def test_top_ips_capped_at_10(self):
        from detector.models import SlidingWindow

        shared = _make_shared()
        now = datetime.now(timezone.utc)
        for i in range(15):
            ip = f"10.0.{i}.1"
            w = SlidingWindow(window_seconds=60)
            w.add(now - timedelta(seconds=1))
            with shared.windows_lock:
                shared.ip_windows[ip] = w

        with patch("detector.dashboard.psutil.cpu_percent", return_value=5.0):
            with patch("detector.dashboard.psutil.virtual_memory") as m:
                m.return_value = MagicMock(percent=30.0)
                client, _ = _make_client(shared)
                resp = client.get("/api/metrics")

        data = json.loads(resp.data)
        assert len(data["top_ips"]) <= 10

    def test_degraded_response_on_exception(self):
        """If SharedState raises unexpectedly, /api/metrics still returns 200."""
        from detector.dashboard import create_app

        shared = MagicMock()
        shared.ban_lock = MagicMock()
        shared.ban_lock.__enter__ = MagicMock(side_effect=RuntimeError("boom"))
        shared.ban_lock.__exit__ = MagicMock(return_value=False)
        shared.daemon_start_time = datetime.now(timezone.utc)

        app = create_app(shared)
        app.config["TESTING"] = True
        client = app.test_client()

        resp = client.get("/api/metrics")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        # Degraded response must still have all required fields
        for field in REQUIRED_FIELDS:
            assert field in data
        assert "error" in data  # error field present in degraded response
