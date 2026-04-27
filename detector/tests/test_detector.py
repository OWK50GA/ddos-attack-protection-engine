"""
test_detector.py — Tests for detector.py (Detector).

Sub-task 6.1: Property 8  — Z-score formula is computed correctly.
Sub-task 6.2: Property 9  — Anomaly detection triggers on threshold violations.
Sub-task 6.3: Property 10 — Error-heavy IPs receive tightened thresholds.

Additional unit tests cover:
  - compute_zscore() returns 0.0 when stddev == 0
  - evaluate_ip() returns DetectionResult with correct fields
  - _evaluate_all() calls blocker.ban() for anomalous IPs
  - _evaluate_global() calls notifier.send_global_anomaly_alert() on spike
  - Already-banned IPs are skipped
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, call, patch

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_shared(mean: float = 5.0, stddev: float = 1.0, window_seconds: int = 60):
    from detector.config import Config
    from detector.models import BaselineState, SharedState

    cfg = Config(slack_webhook_url="https://hooks.slack.com/x")
    cfg.sliding_window_seconds = window_seconds
    shared = SharedState(config=cfg)
    shared.baseline_state = BaselineState(
        mean=mean, stddev=stddev, last_updated=datetime.now(timezone.utc)
    )
    return shared


def _make_detector(mean: float = 5.0, stddev: float = 1.0):
    from detector.detector import Detector

    shared = _make_shared(mean=mean, stddev=stddev)
    blocker = MagicMock()
    notifier = MagicMock()
    det = Detector(shared, blocker, notifier)
    return det, shared, blocker, notifier


def _window_with_rate(target_rps: float, window_seconds: int = 60):
    """Return a SlidingWindow pre-populated to produce ~target_rps."""
    from detector.models import SlidingWindow

    w = SlidingWindow(window_seconds=window_seconds)
    now = datetime.now(timezone.utc)
    n_events = int(target_rps * window_seconds)
    for i in range(n_events):
        w.add(now - timedelta(seconds=i % window_seconds))
    return w


# ---------------------------------------------------------------------------
# Sub-task 6.1 — Property 8: Z-score formula is computed correctly
# Feature: ddos-anomaly-detection-engine, Property 8:
#   For any (rate, mean, stddev) where stddev > 0,
#   compute_zscore() == (rate - mean) / stddev within float tolerance.
# ---------------------------------------------------------------------------

@settings(max_examples=200)
@given(
    rate=st.floats(min_value=0.0, max_value=10_000.0, allow_nan=False, allow_infinity=False),
    mean=st.floats(min_value=1.0, max_value=1_000.0, allow_nan=False, allow_infinity=False),
    stddev=st.floats(min_value=0.001, max_value=500.0, allow_nan=False, allow_infinity=False),
)
def test_property8_zscore_formula_correct(rate, mean, stddev):
    """
    Property 8: compute_zscore(rate, mean, stddev) == (rate - mean) / stddev
    for any stddev > 0.
    """
    from detector.detector import Detector

    det, _, _, _ = _make_detector()
    result = det.compute_zscore(rate, mean, stddev)
    expected = (rate - mean) / stddev
    assert result == pytest.approx(expected, rel=1e-9), (
        f"zscore({rate}, {mean}, {stddev}) = {result}, expected {expected}"
    )


def test_property8_zscore_zero_when_stddev_zero():
    """compute_zscore() returns 0.0 when stddev == 0 (no variance)."""
    det, _, _, _ = _make_detector()
    assert det.compute_zscore(100.0, 5.0, 0.0) == 0.0


# ---------------------------------------------------------------------------
# Sub-task 6.2 — Property 9: Anomaly detection triggers on threshold violations
# Feature: ddos-anomaly-detection-engine, Property 9:
#   evaluate_ip() returns anomalous=True when z-score > threshold OR
#   rate > rate_multiplier * mean; anomalous=False otherwise.
# ---------------------------------------------------------------------------

@settings(max_examples=200)
@given(
    mean=st.floats(min_value=1.0, max_value=100.0, allow_nan=False, allow_infinity=False),
    stddev=st.floats(min_value=0.1, max_value=20.0, allow_nan=False, allow_infinity=False),
    zscore_multiplier=st.floats(
        min_value=3.1, max_value=10.0, allow_nan=False, allow_infinity=False
    ),
)
def test_property9_anomaly_triggers_on_zscore_violation(mean, stddev, zscore_multiplier):
    """
    Property 9a: When z-score > threshold, evaluate_ip() returns anomalous=True
    with condition='zscore'.
    """
    from detector.detector import Detector
    from detector.models import BaselineState, SlidingWindow

    shared = _make_shared(mean=mean, stddev=stddev)
    # Set rate so z-score = zscore_multiplier * threshold (well above threshold)
    threshold = shared.config.zscore_threshold  # default 3.0
    target_rate = mean + (zscore_multiplier * threshold * stddev)

    det = Detector(shared, MagicMock())
    window = _window_with_rate(target_rate)

    result = det.evaluate_ip("1.2.3.4", window)
    assert result.anomalous is True
    assert result.condition in ("zscore", "rate_multiplier")


@settings(max_examples=200, deadline=None)
@given(
    mean=st.floats(min_value=1.0, max_value=100.0, allow_nan=False, allow_infinity=False),
    rate_multiplier_factor=st.floats(
        min_value=5.1, max_value=20.0, allow_nan=False, allow_infinity=False
    ),
)
def test_property9_anomaly_triggers_on_rate_multiplier_violation(
    mean, rate_multiplier_factor
):
    """
    Property 9b: When rate > rate_multiplier * mean, evaluate_ip() returns
    anomalous=True regardless of z-score.
    Uses a mock window so the rate is exact — avoids slow event-loop population.
    """
    from detector.detector import Detector

    # Use stddev=0 so z-score is always 0 — only rate_multiplier can fire
    shared = _make_shared(mean=mean, stddev=0.0)
    target_rate = rate_multiplier_factor * mean  # above 5x threshold

    det = Detector(shared, MagicMock())

    # Mock the window so .rate() returns exactly target_rate
    mock_window = MagicMock()
    mock_window.rate.return_value = target_rate

    result = det.evaluate_ip("1.2.3.4", mock_window)
    assert result.anomalous is True
    assert result.condition == "rate_multiplier"


@settings(max_examples=200)
@given(
    mean=st.floats(min_value=2.0, max_value=50.0, allow_nan=False, allow_infinity=False),
    stddev=st.floats(min_value=0.1, max_value=5.0, allow_nan=False, allow_infinity=False),
    # Rate is below both thresholds
    rate_fraction=st.floats(min_value=0.0, max_value=0.5, allow_nan=False, allow_infinity=False),
)
def test_property9_no_anomaly_below_both_thresholds(mean, stddev, rate_fraction):
    """
    Property 9c: When neither z-score nor rate_multiplier threshold is
    exceeded, evaluate_ip() returns anomalous=False.
    """
    from detector.detector import Detector

    shared = _make_shared(mean=mean, stddev=stddev)
    # Rate is a fraction of mean — well below both thresholds
    target_rate = mean * rate_fraction  # max 0.5 * mean → z-score negative

    det = Detector(shared, MagicMock())
    window = _window_with_rate(max(0.0, target_rate))

    result = det.evaluate_ip("1.2.3.4", window)
    assert result.anomalous is False
    assert result.condition == ""


# ---------------------------------------------------------------------------
# Sub-task 6.3 — Property 10: Error-heavy IPs receive tightened thresholds
# Feature: ddos-anomaly-detection-engine, Property 10:
#   When an IP's error rate > error_rate_multiplier * baseline_error_rate,
#   the effective z-score threshold and rate_multiplier are each halved.
# ---------------------------------------------------------------------------

@settings(max_examples=200)
@given(
    mean=st.floats(min_value=2.0, max_value=100.0, allow_nan=False, allow_infinity=False),
    error_rate_factor=st.floats(
        min_value=3.1, max_value=10.0, allow_nan=False, allow_infinity=False
    ),
)
def test_property10_tightened_thresholds_for_error_heavy_ips(mean, error_rate_factor):
    """
    Property 10: _effective_thresholds() returns thresholds strictly less
    than the configured defaults when the IP's error rate is elevated.
    """
    from detector.detector import Detector, _BASELINE_ERROR_FRACTION

    shared = _make_shared(mean=mean, stddev=1.0)
    det = Detector(shared, MagicMock())

    cfg = shared.config
    baseline_error_rate = mean * _BASELINE_ERROR_FRACTION
    # Build an error window with rate above the trigger threshold
    elevated_error_rate = error_rate_factor * cfg.error_rate_multiplier * baseline_error_rate
    error_window = _window_with_rate(elevated_error_rate)

    zscore_thresh, rate_mult = det._effective_thresholds(
        "1.2.3.4", mean, mean, error_window
    )

    assert zscore_thresh < cfg.zscore_threshold, (
        f"Expected tightened zscore_thresh < {cfg.zscore_threshold}, got {zscore_thresh}"
    )
    assert rate_mult < cfg.rate_multiplier, (
        f"Expected tightened rate_mult < {cfg.rate_multiplier}, got {rate_mult}"
    )
    # Specifically, they should be halved
    assert zscore_thresh == pytest.approx(cfg.zscore_threshold * 0.5)
    assert rate_mult == pytest.approx(cfg.rate_multiplier * 0.5)


def test_property10_normal_error_rate_uses_default_thresholds():
    """
    Property 10 (inverse): When error rate is normal, thresholds are unchanged.
    """
    from detector.detector import Detector

    det, shared, _, _ = _make_detector(mean=10.0, stddev=1.0)
    # Error window with very low rate
    error_window = _window_with_rate(0.01)

    zscore_thresh, rate_mult = det._effective_thresholds(
        "1.2.3.4", 10.0, 10.0, error_window
    )

    assert zscore_thresh == shared.config.zscore_threshold
    assert rate_mult == shared.config.rate_multiplier


# ---------------------------------------------------------------------------
# Unit tests — evaluate_ip() result fields
# ---------------------------------------------------------------------------

class TestEvaluateIp:
    def test_returns_detection_result(self):
        from detector.detector import DetectionResult

        det, _, _, _ = _make_detector()
        window = _window_with_rate(0.1)
        result = det.evaluate_ip("1.2.3.4", window)
        assert isinstance(result, DetectionResult)

    def test_rate_field_matches_window_rate(self):
        det, _, _, _ = _make_detector(mean=5.0, stddev=1.0)
        window = _window_with_rate(0.5)
        result = det.evaluate_ip("1.2.3.4", window)
        assert result.rate == pytest.approx(window.rate(), rel=0.05)

    def test_no_error_window_uses_default_thresholds(self):
        """evaluate_ip() with error_window=None should not crash."""
        det, _, _, _ = _make_detector()
        window = _window_with_rate(0.1)
        result = det.evaluate_ip("1.2.3.4", window, error_window=None)
        assert isinstance(result.anomalous, bool)


# ---------------------------------------------------------------------------
# Unit tests — _evaluate_all() calls blocker.ban()
# ---------------------------------------------------------------------------

class TestEvaluateAll:
    def test_ban_called_for_anomalous_ip(self):
        from detector.models import SlidingWindow

        det, shared, blocker, _ = _make_detector(mean=5.0, stddev=1.0)
        # Add an IP with a very high rate (well above 5x mean)
        high_rate_window = _window_with_rate(200.0)
        with shared.windows_lock:
            shared.ip_windows["9.9.9.9"] = high_rate_window

        det._evaluate_all()
        blocker.ban.assert_called_once()
        args = blocker.ban.call_args[0]
        assert args[0] == "9.9.9.9"

    def test_already_banned_ip_skipped(self):
        from detector.models import BanRecord, SlidingWindow

        det, shared, blocker, _ = _make_detector(mean=5.0, stddev=1.0)
        high_rate_window = _window_with_rate(200.0)
        with shared.windows_lock:
            shared.ip_windows["9.9.9.9"] = high_rate_window

        # Pre-populate ban registry
        with shared.ban_lock:
            shared.ban_registry["9.9.9.9"] = BanRecord(
                ip="9.9.9.9",
                banned_at=datetime.now(timezone.utc),
                duration_seconds=600,
                backoff_level=0,
                condition="zscore",
                rate_at_ban=200.0,
                mean_at_ban=5.0,
            )

        det._evaluate_all()
        blocker.ban.assert_not_called()

    def test_normal_ip_not_banned(self):
        det, shared, blocker, _ = _make_detector(mean=5.0, stddev=1.0)
        normal_window = _window_with_rate(5.0)  # exactly at mean
        with shared.windows_lock:
            shared.ip_windows["1.1.1.1"] = normal_window

        det._evaluate_all()
        blocker.ban.assert_not_called()


# ---------------------------------------------------------------------------
# Unit tests — _evaluate_global() sends alert on spike
# ---------------------------------------------------------------------------

class TestEvaluateGlobal:
    def test_global_spike_triggers_notifier(self):
        det, shared, _, notifier = _make_detector(mean=5.0, stddev=1.0)
        # Inject a very high global rate
        high_rate_window = _window_with_rate(200.0)
        with shared.windows_lock:
            shared.global_window._events = high_rate_window._events

        det._evaluate_global()
        notifier.send_global_anomaly_alert.assert_called_once()

    def test_normal_global_rate_no_alert(self):
        det, shared, _, notifier = _make_detector(mean=5.0, stddev=1.0)
        # Global window is empty → rate = 0.0, below threshold
        det._evaluate_global()
        notifier.send_global_anomaly_alert.assert_not_called()

    def test_no_notifier_does_not_crash(self):
        from detector.detector import Detector

        shared = _make_shared(mean=5.0, stddev=1.0)
        det = Detector(shared, MagicMock(), notifier=None)
        high_rate_window = _window_with_rate(200.0)
        with shared.windows_lock:
            shared.global_window._events = high_rate_window._events
        det._evaluate_global()  # should not raise
