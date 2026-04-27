"""
test_baseline.py — Tests for baseline.py (BaselineCalculator).

Sub-task 5.1: Property 4 — Baseline window evicts stale samples.
Sub-task 5.2: Property 5 — Effective mean is always at least 1.0.
Sub-task 5.3: Property 6 — Hourly slot preference is applied correctly.
Sub-task 5.4: Property 7 — Baseline recalculation writes a correctly
              formatted audit entry.

Additional unit tests cover:
  - _compute_stats() edge cases (empty, single sample, normal distribution)
  - recalculate() updates shared.baseline_state under the lock
  - recalculate() returns the new BaselineState
"""

import re
import statistics
import tempfile
import time
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


def _make_calculator():
    from detector.baseline import BaselineCalculator

    shared = _make_shared()
    return BaselineCalculator(shared), shared


def _ts(offset_seconds: float = 0.0) -> datetime:
    """Return a UTC datetime offset by *offset_seconds* from now."""
    return datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)


# ---------------------------------------------------------------------------
# Sub-task 5.1 — Property 4: Baseline window evicts stale samples
# Feature: ddos-anomaly-detection-engine, Property 4:
#   For any sequence of timestamped rate samples spanning more than
#   baseline_window_minutes, current_samples() contains only samples
#   within the last window_minutes — no older samples remain.
# ---------------------------------------------------------------------------

@settings(max_examples=200)
@given(
    window_minutes=st.integers(min_value=1, max_value=60),
    n_old=st.integers(min_value=1, max_value=20),
    n_fresh=st.integers(min_value=1, max_value=20),
    rates=st.lists(
        st.floats(min_value=0.0, max_value=1000.0, allow_nan=False, allow_infinity=False),
        min_size=2,
        max_size=40,
    ),
)
def test_property4_baseline_window_evicts_stale_samples(
    window_minutes, n_old, n_fresh, rates
):
    """
    Property 4: current_samples() never returns samples older than
    window_minutes regardless of how many stale samples were added.
    """
    from detector.models import BaselineWindow

    bw = BaselineWindow(window_minutes=window_minutes)
    now = datetime.now(timezone.utc)

    # Add stale samples (older than the window)
    stale_ts = now - timedelta(minutes=window_minutes + 1)
    for i in range(n_old):
        bw.add_sample(stale_ts - timedelta(seconds=i), rates[i % len(rates)])

    # Add fresh samples (within the window)
    fresh_rates = []
    for i in range(n_fresh):
        r = rates[(n_old + i) % len(rates)]
        bw.add_sample(now - timedelta(seconds=i), r)
        fresh_rates.append(r)

    result = bw.current_samples()

    # All returned samples must be fresh (stale ones evicted)
    # We can't check exact values because fresh_rates may have duplicates,
    # but the count must equal n_fresh (stale ones gone).
    assert len(result) == n_fresh, (
        f"Expected {n_fresh} fresh samples, got {len(result)}"
    )


# ---------------------------------------------------------------------------
# Sub-task 5.2 — Property 5: Effective mean is always at least 1.0
# Feature: ddos-anomaly-detection-engine, Property 5:
#   For any set of rate samples (including all-zero, empty, or sub-1.0),
#   BaselineState.mean produced by recalculate() is always >= 1.0.
# ---------------------------------------------------------------------------

@settings(max_examples=200)
@given(
    samples=st.lists(
        st.floats(min_value=0.0, max_value=0.99, allow_nan=False, allow_infinity=False),
        min_size=0,
        max_size=50,
    )
)
def test_property5_effective_mean_always_at_least_1(samples):
    """
    Property 5: _compute_stats() always returns mean >= 1.0, even when
    all samples are below 1.0 or the list is empty.
    """
    from detector.baseline import BaselineCalculator

    calc, _ = _make_calculator()
    mean, stddev = calc._compute_stats(samples)
    assert mean >= 1.0, f"mean {mean} is below the 1.0 floor for samples={samples}"
    assert stddev >= 0.0


# ---------------------------------------------------------------------------
# Sub-task 5.3 — Property 6: Hourly slot preference is applied correctly
# Feature: ddos-anomaly-detection-engine, Property 6:
#   When the current hour's slot has >= 60 samples, preferred_samples()
#   returns exactly those samples rather than the full rolling window.
# ---------------------------------------------------------------------------

@settings(max_examples=200)
@given(
    hour=st.integers(min_value=0, max_value=23),
    n_hourly=st.integers(min_value=60, max_value=120),
    n_other=st.integers(min_value=1, max_value=30),
    rate=st.floats(min_value=1.0, max_value=100.0, allow_nan=False, allow_infinity=False),
)
def test_property6_hourly_slot_preferred_when_sufficient(hour, n_hourly, n_other, rate):
    """
    Property 6: preferred_samples() returns the current hour's slot when
    it has >= 60 samples, ignoring the rest of the rolling window.
    """
    from detector.models import BaselineWindow

    bw = BaselineWindow(window_minutes=30)
    now = datetime.now(timezone.utc)

    # Build a timestamp that:
    #   a) has the target hour-of-day
    #   b) is within the 30-minute rolling window (i.e. in the past)
    # We use "now minus a few seconds" and override the hour field only
    # for the _hourly_slots dict — we pass the real `now` as the timestamp
    # so current_samples() doesn't evict it, but manually set the hour.
    # The simplest approach: add samples with timestamps that are recent
    # (within window) but whose .hour attribute equals `hour`.
    # We achieve this by subtracting enough days to land on a past time
    # with the right hour, staying within 30 minutes.
    # Easiest: just use `now` directly and monkey-patch the hour via a
    # subclass — but that's complex.  Instead, use a fixed recent offset
    # and directly manipulate _hourly_slots to simulate the slot being full.

    # Direct approach: populate _hourly_slots[hour] manually and add
    # fresh timestamps to _samples so current_samples() returns them.
    fresh_ts = now - timedelta(seconds=10)  # definitely within 30 min window

    for i in range(n_hourly):
        # Add to _samples with a fresh timestamp
        bw._samples.append((fresh_ts - timedelta(seconds=i), rate))
        # Add to the target hourly slot
        bw._hourly_slots.setdefault(hour, []).append(rate)

    # Add some samples for a different hour slot (should be ignored)
    other_hour = (hour + 1) % 24
    for i in range(n_other):
        bw._hourly_slots.setdefault(other_hour, []).append(rate * 2)

    result = bw.preferred_samples(hour)

    # Should return exactly the hourly slot samples
    assert len(result) == n_hourly, (
        f"Expected {n_hourly} hourly samples, got {len(result)}"
    )
    assert all(s == rate for s in result), (
        "preferred_samples() returned samples from the wrong slot"
    )


@settings(max_examples=100)
@given(
    hour=st.integers(min_value=0, max_value=23),
    n_hourly=st.integers(min_value=1, max_value=59),  # below threshold
)
def test_property6_falls_back_when_hourly_slot_insufficient(hour, n_hourly):
    """
    Property 6 (inverse): When the current hour's slot has < 60 samples,
    preferred_samples() falls back to the full rolling window.
    """
    from detector.models import BaselineWindow

    bw = BaselineWindow(window_minutes=30)
    now = datetime.now(timezone.utc)
    fake_ts = now.replace(hour=hour, minute=0, second=0, microsecond=0)

    for i in range(n_hourly):
        bw.add_sample(fake_ts - timedelta(seconds=i), 5.0)

    result = bw.preferred_samples(hour)
    full = bw.current_samples()

    # Should equal the full rolling window (same object contents)
    assert result == full


# ---------------------------------------------------------------------------
# Sub-task 5.4 — Property 7: Baseline recalculation writes a correctly
#                formatted audit entry
# Feature: ddos-anomaly-detection-engine, Property 7:
#   For any recalculation producing mean m and stddev s, the audit log
#   receives exactly one line matching the BASELINE_RECALC format.
# ---------------------------------------------------------------------------

BASELINE_RECALC_RE = re.compile(
    r"^\[\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\] "
    r"BASELINE_RECALC ip=global \| mean=[\d.]+ \| stddev=[\d.]+$"
)


@settings(max_examples=200)
@given(
    rates=st.lists(
        st.floats(min_value=0.0, max_value=500.0, allow_nan=False, allow_infinity=False),
        min_size=0,
        max_size=100,
    )
)
def test_property7_recalc_writes_correctly_formatted_audit_entry(rates):
    """
    Property 7: recalculate() writes exactly one BASELINE_RECALC line to
    the audit log in the correct format for any set of baseline samples.
    """
    import os
    from detector.audit_log import AuditLog
    from detector.baseline import BaselineCalculator

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".log", delete=False
    ) as fh:
        path = fh.name

    try:
        shared = _make_shared()
        shared.audit_log = AuditLog(path)
        calc = BaselineCalculator(shared)

        # Pre-populate the baseline window with the given rates
        now = datetime.now(timezone.utc)
        for i, r in enumerate(rates):
            shared.baseline_window.add_sample(
                now - timedelta(seconds=i + 1), r
            )

        calc.recalculate()
        shared.audit_log.close()

        with open(path) as f:
            lines = [l.rstrip("\n") for l in f if l.strip()]

        assert len(lines) == 1, f"Expected 1 audit line, got {len(lines)}: {lines}"
        assert BASELINE_RECALC_RE.match(lines[0]), (
            f"Audit line does not match expected format: {lines[0]!r}"
        )
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# Unit tests — _compute_stats()
# ---------------------------------------------------------------------------

class TestComputeStats:
    def test_empty_samples_returns_floor(self):
        calc, _ = _make_calculator()
        mean, stddev = calc._compute_stats([])
        assert mean == 1.0
        assert stddev == 0.0

    def test_single_sample_above_floor(self):
        calc, _ = _make_calculator()
        mean, stddev = calc._compute_stats([5.0])
        assert mean == 5.0
        assert stddev == 0.0

    def test_single_sample_below_floor(self):
        calc, _ = _make_calculator()
        mean, stddev = calc._compute_stats([0.3])
        assert mean == 1.0
        assert stddev == 0.0

    def test_multiple_samples_correct_stats(self):
        calc, _ = _make_calculator()
        samples = [2.0, 4.0, 6.0, 8.0, 10.0]
        mean, stddev = calc._compute_stats(samples)
        assert mean == pytest.approx(statistics.mean(samples))
        assert stddev == pytest.approx(statistics.stdev(samples))

    def test_all_zero_samples_returns_floor(self):
        calc, _ = _make_calculator()
        mean, stddev = calc._compute_stats([0.0, 0.0, 0.0])
        assert mean == 1.0


# ---------------------------------------------------------------------------
# Unit tests — recalculate()
# ---------------------------------------------------------------------------

class TestRecalculate:
    def test_updates_shared_baseline_state(self):
        calc, shared = _make_calculator()
        # Seed some samples so we get a non-trivial result
        now = datetime.now(timezone.utc)
        for i in range(10):
            shared.baseline_window.add_sample(
                now - timedelta(seconds=i + 1), float(i + 2)
            )

        state = calc.recalculate()

        with shared.baseline_lock:
            assert shared.baseline_state.mean == state.mean
            assert shared.baseline_state.stddev == state.stddev

    def test_returns_baseline_state_instance(self):
        from detector.models import BaselineState

        calc, _ = _make_calculator()
        state = calc.recalculate()
        assert isinstance(state, BaselineState)

    def test_mean_reflects_seeded_samples(self):
        calc, shared = _make_calculator()
        now = datetime.now(timezone.utc)
        # All baseline window samples are 10.0
        for i in range(5):
            shared.baseline_window.add_sample(
                now - timedelta(seconds=i + 1), 10.0
            )
        # Also seed the global window so the live snapshot is also ~10.0
        for _ in range(600):  # 600 events in 60s window = 10 req/s
            shared.global_window.add(now - timedelta(seconds=1))

        state = calc.recalculate()
        # Mean should be close to 10.0 (6 samples: 5 seeded + 1 live snapshot)
        assert state.mean == pytest.approx(10.0, abs=1.0)

    def test_no_audit_log_does_not_raise(self):
        """recalculate() must not crash when audit_log is None."""
        calc, shared = _make_calculator()
        shared.audit_log = None
        calc.recalculate()  # should not raise

    def test_with_audit_log_writes_entry(self, tmp_path):
        from detector.audit_log import AuditLog

        calc, shared = _make_calculator()
        path = str(tmp_path / "audit.log")
        shared.audit_log = AuditLog(path)

        calc.recalculate()
        shared.audit_log.close()

        with open(path) as f:
            content = f.read()
        assert "BASELINE_RECALC" in content
