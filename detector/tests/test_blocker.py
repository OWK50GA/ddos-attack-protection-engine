"""
test_blocker.py — Tests for blocker.py (Blocker).

Sub-task 7.1: Property 11 — Ban operation is idempotent.
Sub-task 7.2: Property 12 — Ban record completeness and audit log correctness.

Additional unit tests cover:
  - _run_iptables() constructs the correct command string
  - _run_iptables() returns False and logs on non-zero exit code
  - _run_iptables() handles FileNotFoundError (iptables not installed)
  - ban() does not raise when audit_log is None
  - Backoff level lookup from history
"""

import re
import subprocess
import tempfile
from datetime import datetime, timezone
from unittest.mock import MagicMock, call, patch

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_shared(mean: float = 5.0, stddev: float = 1.0):
    from detector.config import Config
    from detector.models import BaselineState, SharedState

    cfg = Config(slack_webhook_url="https://hooks.slack.com/x")
    shared = SharedState(config=cfg)
    shared.baseline_state = BaselineState(
        mean=mean, stddev=stddev, last_updated=datetime.now(timezone.utc)
    )
    return shared


def _make_blocker(mean: float = 5.0):
    from detector.blocker import Blocker

    shared = _make_shared(mean=mean)
    notifier = MagicMock()
    blocker = Blocker(shared, notifier)
    return blocker, shared, notifier


def _mock_iptables_success(blocker):
    """Patch subprocess.run to simulate a successful iptables call."""
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stderr = ""
    return patch("detector.blocker.subprocess.run", return_value=mock_result)


# ---------------------------------------------------------------------------
# Sub-task 7.1 — Property 11: Ban operation is idempotent
# Feature: ddos-anomaly-detection-engine, Property 11:
#   Calling ban() twice for the same IP results in exactly one entry in
#   ban_registry and exactly one iptables subprocess call.
# ---------------------------------------------------------------------------

@settings(max_examples=200)
@given(
    ip=st.ip_addresses(v=4).map(str),
    condition=st.sampled_from(["zscore", "rate_multiplier"]),
    rate=st.floats(min_value=1.0, max_value=1000.0, allow_nan=False, allow_infinity=False),
)
def test_property11_ban_is_idempotent(ip, condition, rate):
    """
    Property 11: Calling ban() twice for the same IP results in exactly
    one ban_registry entry and exactly one iptables call.
    """
    blocker, shared, notifier = _make_blocker()

    with _mock_iptables_success(blocker) as mock_run:
        blocker.ban(ip, condition, rate)
        blocker.ban(ip, condition, rate)  # second call — should be no-op

    # Exactly one iptables call
    assert mock_run.call_count == 1, (
        f"Expected 1 iptables call, got {mock_run.call_count}"
    )

    # Exactly one registry entry
    assert len(shared.ban_registry) == 1, (
        f"Expected 1 ban_registry entry, got {len(shared.ban_registry)}"
    )
    assert ip in shared.ban_registry

    # Notifier called exactly once
    assert notifier.send_ban_alert.call_count == 1


# ---------------------------------------------------------------------------
# Sub-task 7.2 — Property 12: Ban record completeness and audit log correctness
# Feature: ddos-anomaly-detection-engine, Property 12:
#   After ban() completes:
#   (a) ban_registry[ip] contains all six required fields.
#   (b) The audit log contains exactly one BAN line in the correct format.
# ---------------------------------------------------------------------------

BAN_AUDIT_RE = re.compile(
    r"^\[\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\] "
    r"BAN ip=[\d.]+ \| condition=\w+ \| rate=[\d.]+/s \| "
    r"baseline=[\d.]+/s \| duration=\w+$"
)


@settings(max_examples=200)
@given(
    ip=st.ip_addresses(v=4).map(str),
    condition=st.sampled_from(["zscore", "rate_multiplier"]),
    rate=st.floats(min_value=0.1, max_value=1000.0, allow_nan=False, allow_infinity=False),
    mean=st.floats(min_value=1.0, max_value=100.0, allow_nan=False, allow_infinity=False),
)
def test_property12_ban_record_complete_and_audit_correct(ip, condition, rate, mean):
    """
    Property 12: ban() stores a complete BanRecord and writes exactly one
    correctly formatted BAN audit entry.
    """
    import os
    from detector.audit_log import AuditLog
    from detector.blocker import Blocker
    from detector.models import BanRecord

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".log", delete=False
    ) as fh:
        path = fh.name

    try:
        shared = _make_shared(mean=mean)
        shared.audit_log = AuditLog(path)
        blocker = Blocker(shared, MagicMock())

        with _mock_iptables_success(blocker):
            blocker.ban(ip, condition, rate)

        # (a) BanRecord completeness
        assert ip in shared.ban_registry
        record = shared.ban_registry[ip]
        assert isinstance(record, BanRecord)
        assert record.ip == ip
        assert record.condition == condition
        assert record.rate_at_ban == pytest.approx(rate)
        assert record.mean_at_ban == pytest.approx(mean)
        assert record.backoff_level in (0, 1, 2, 3)
        assert isinstance(record.banned_at, datetime)

        # (b) Audit log format
        shared.audit_log.close()
        with open(path) as f:
            lines = [l.rstrip("\n") for l in f if l.strip()]

        ban_lines = [l for l in lines if "] BAN " in l]
        assert len(ban_lines) == 1, f"Expected 1 BAN line, got {len(ban_lines)}: {lines}"
        assert BAN_AUDIT_RE.match(ban_lines[0]), (
            f"BAN line does not match format: {ban_lines[0]!r}"
        )
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# Unit tests — _run_iptables()
# ---------------------------------------------------------------------------

class TestRunIptables:
    def test_correct_command_constructed(self):
        blocker, _, _ = _make_blocker()
        with patch("detector.blocker.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            blocker._run_iptables("1.2.3.4")

        mock_run.assert_called_once_with(
            ["iptables", "-A", "INPUT", "-s", "1.2.3.4", "-j", "DROP"],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_returns_true_on_success(self):
        blocker, _, _ = _make_blocker()
        with patch("detector.blocker.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            result = blocker._run_iptables("1.2.3.4")
        assert result is True

    def test_returns_false_on_nonzero_exit(self, tmp_path):
        from detector.audit_log import AuditLog

        blocker, shared, _ = _make_blocker()
        shared.audit_log = AuditLog(str(tmp_path / "audit.log"))

        with patch("detector.blocker.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="Operation not permitted")
            result = blocker._run_iptables("1.2.3.4")

        assert result is False

    def test_returns_false_when_iptables_not_found(self, tmp_path):
        from detector.audit_log import AuditLog

        blocker, shared, _ = _make_blocker()
        shared.audit_log = AuditLog(str(tmp_path / "audit.log"))

        with patch("detector.blocker.subprocess.run", side_effect=FileNotFoundError):
            result = blocker._run_iptables("1.2.3.4")

        assert result is False


# ---------------------------------------------------------------------------
# Unit tests — ban() behaviour
# ---------------------------------------------------------------------------

class TestBan:
    def test_ban_stores_record_in_registry(self):
        blocker, shared, _ = _make_blocker()
        with _mock_iptables_success(blocker):
            blocker.ban("10.0.0.1", "zscore", 50.0)
        assert "10.0.0.1" in shared.ban_registry

    def test_ban_calls_notifier(self):
        blocker, _, notifier = _make_blocker()
        with _mock_iptables_success(blocker):
            blocker.ban("10.0.0.1", "zscore", 50.0)
        notifier.send_ban_alert.assert_called_once()

    def test_ban_notifier_receives_correct_args(self):
        blocker, _, notifier = _make_blocker(mean=4.0)
        with _mock_iptables_success(blocker):
            blocker.ban("10.0.0.1", "rate_multiplier", 25.0)

        kwargs = notifier.send_ban_alert.call_args.kwargs
        assert kwargs["ip"] == "10.0.0.1"
        assert kwargs["condition"] == "rate_multiplier"
        assert kwargs["rate"] == pytest.approx(25.0)
        assert kwargs["mean"] == pytest.approx(4.0)

    def test_ban_without_audit_log_does_not_raise(self):
        blocker, shared, _ = _make_blocker()
        shared.audit_log = None
        with _mock_iptables_success(blocker):
            blocker.ban("10.0.0.1", "zscore", 50.0)  # should not raise

    def test_backoff_level_zero_for_first_ban(self):
        blocker, shared, _ = _make_blocker()
        with _mock_iptables_success(blocker):
            blocker.ban("10.0.0.1", "zscore", 50.0)

        assert shared.ban_registry["10.0.0.1"].backoff_level == 0
        assert shared.ban_registry["10.0.0.1"].duration_seconds == 600
