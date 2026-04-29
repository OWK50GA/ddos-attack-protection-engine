"""
test_unbanner.py — Tests for unbanner.py (Unbanner).

Sub-task 9.1: Property 13 — Unban correctness: rule removal, level increment,
              and audit entry.
Sub-task 9.2: Property 14 — Permanent bans are never automatically removed.

Additional unit tests cover:
  - _remove_iptables_rule() constructs the correct -D command
  - _remove_iptables_rule() returns False on non-zero exit / missing binary
  - unban() sends Slack alert via notifier
  - unban() is a no-op for an IP not in the registry
  - _check_expired() only unbans IPs whose elapsed time >= duration
  - _check_expired() skips sentinel keys
"""

import re
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, call, patch

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_shared(mean: float = 5.0):
    from detector.config import Config
    from detector.models import BaselineState, SharedState

    cfg = Config(slack_webhook_url="https://hooks.slack.com/x")
    shared = SharedState(config=cfg)
    shared.baseline_state = BaselineState(
        mean=mean, stddev=1.0, last_updated=datetime.now(timezone.utc)
    )
    return shared


def _make_unbanner(mean: float = 5.0):
    from detector.unbanner import Unbanner

    shared = _make_shared(mean=mean)
    notifier = MagicMock()
    unbanner = Unbanner(shared, notifier)
    return unbanner, shared, notifier


def _add_ban(shared, ip: str, backoff_level: int, elapsed_seconds: float):
    """Insert a BanRecord into shared.ban_registry with a controlled age."""
    from detector.blocker import BACKOFF_DURATIONS
    from detector.models import BanRecord

    duration = BACKOFF_DURATIONS[backoff_level]
    banned_at = datetime.now(timezone.utc) - timedelta(seconds=elapsed_seconds)
    record = BanRecord(
        ip=ip,
        banned_at=banned_at,
        duration_seconds=duration,
        backoff_level=backoff_level,
        condition="zscore",
        rate_at_ban=50.0,
        mean_at_ban=5.0,
    )
    with shared.ban_lock:
        shared.ban_registry[ip] = record
    return record


def _mock_iptables_success(unbanner):
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stderr = ""
    return patch("detector.unbanner.subprocess.run", return_value=mock_result)


# ---------------------------------------------------------------------------
# Sub-task 9.1 — Property 13: Unban correctness
# Feature: ddos-anomaly-detection-engine, Property 13:
#   For any BanRecord at backoff level 0, 1, or 2 whose elapsed time meets
#   or exceeds duration_seconds, unban() should:
#   (a) call _remove_iptables_rule(ip)
#   (b) set backoff level to old_level + 1
#   (c) write an UNBAN audit entry in the correct format
# ---------------------------------------------------------------------------

UNBAN_AUDIT_RE = re.compile(
    r"^\[\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\] "
    r"UNBAN ip=[\d.]+ \| condition=backoff-\d \| "
    r"rate=N/A \| baseline=[\d.]+/s \| duration=\w+$"
)


@settings(max_examples=200)
@given(
    ip=st.ip_addresses(v=4).map(str),
    backoff_level=st.integers(min_value=0, max_value=2),  # 0-2 are auto-unbannable
)
def test_property13_unban_correctness(ip, backoff_level):
    """
    Property 13: unban() removes the iptables rule, increments the backoff
    level, and writes a correctly formatted UNBAN audit entry.
    """
    import os
    from detector.audit_log import AuditLog
    from detector.blocker import BACKOFF_DURATIONS

    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as fh:
        path = fh.name

    try:
        unbanner, shared, notifier = _make_unbanner()
        shared.audit_log = AuditLog(path)

        # Add a ban that has fully elapsed
        duration = BACKOFF_DURATIONS[backoff_level]
        _add_ban(shared, ip, backoff_level, elapsed_seconds=duration + 1)

        with _mock_iptables_success(unbanner) as mock_run:
            unbanner.unban(ip)

        # (a) iptables -D was called twice (DOCKER-USER + INPUT)
        assert mock_run.call_count == 2
        cmds = [c[0][0] for c in mock_run.call_args_list]
        assert any("-D" in cmd and "DOCKER-USER" in cmd for cmd in cmds)
        assert any("-D" in cmd and "INPUT" in cmd for cmd in cmds)
        assert all(ip in cmd for cmd in cmds)

        # (b) backoff level incremented in ban_history
        with shared.ban_lock:
            new_level = shared.ban_history.get(ip)
        assert new_level == backoff_level + 1

        # (c) IP removed from active ban registry
        with shared.ban_lock:
            assert ip not in shared.ban_registry

        # (d) UNBAN audit entry written
        shared.audit_log.close()
        with open(path) as f:
            lines = [l.rstrip("\n") for l in f if l.strip()]
        unban_lines = [l for l in lines if "] UNBAN " in l]
        assert len(unban_lines) == 1
        assert UNBAN_AUDIT_RE.match(unban_lines[0]), (
            f"UNBAN line does not match format: {unban_lines[0]!r}"
        )

        # (e) Slack alert sent
        notifier.send_unban_alert.assert_called_once()

    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# Sub-task 9.2 — Property 14: Permanent bans are never automatically removed
# Feature: ddos-anomaly-detection-engine, Property 14:
#   For any BanRecord at backoff level 3, regardless of elapsed time,
#   _check_expired() must never call _remove_iptables_rule for that IP.
# ---------------------------------------------------------------------------

@settings(max_examples=200)
@given(
    ip=st.ip_addresses(v=4).map(str),
    elapsed_hours=st.floats(
        min_value=0.0, max_value=8760.0,  # up to 1 year
        allow_nan=False, allow_infinity=False
    ),
)
def test_property14_permanent_bans_never_removed(ip, elapsed_hours):
    """
    Property 14: _check_expired() never unbans an IP at backoff level 3,
    regardless of how much time has elapsed.
    """
    unbanner, shared, notifier = _make_unbanner()

    # Add a permanent ban (level 3, duration_seconds=0)
    _add_ban(shared, ip, backoff_level=3, elapsed_seconds=elapsed_hours * 3600)

    with patch("detector.unbanner.subprocess.run") as mock_run:
        unbanner._check_expired()

    # iptables -D must never be called
    mock_run.assert_not_called()

    # IP must still be in the ban registry
    with shared.ban_lock:
        assert ip in shared.ban_registry

    # Notifier must not be called
    notifier.send_unban_alert.assert_not_called()


# ---------------------------------------------------------------------------
# Unit tests — _remove_iptables_rule()
# ---------------------------------------------------------------------------

class TestRemoveIptablesRule:
    def test_correct_delete_command(self):
        unbanner, _, _ = _make_unbanner()
        with patch("detector.unbanner.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            unbanner._remove_iptables_rule("1.2.3.4")

        assert mock_run.call_count == 2
        calls = [c[0][0] for c in mock_run.call_args_list]
        assert ["iptables", "-D", "DOCKER-USER", "-s", "1.2.3.4", "-j", "DROP"] in calls
        assert ["iptables", "-D", "INPUT", "-s", "1.2.3.4", "-j", "DROP"] in calls

    def test_returns_true_on_success(self):
        unbanner, _, _ = _make_unbanner()
        with patch("detector.unbanner.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            assert unbanner._remove_iptables_rule("1.2.3.4") is True

    def test_returns_false_on_nonzero_exit(self, tmp_path):
        from detector.audit_log import AuditLog

        unbanner, shared, _ = _make_unbanner()
        shared.audit_log = AuditLog(str(tmp_path / "audit.log"))
        with patch("detector.unbanner.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="No such rule")
            assert unbanner._remove_iptables_rule("1.2.3.4") is False

    def test_returns_false_when_iptables_not_found(self, tmp_path):
        from detector.audit_log import AuditLog

        unbanner, shared, _ = _make_unbanner()
        shared.audit_log = AuditLog(str(tmp_path / "audit.log"))
        with patch("detector.unbanner.subprocess.run", side_effect=FileNotFoundError):
            assert unbanner._remove_iptables_rule("1.2.3.4") is False


# ---------------------------------------------------------------------------
# Unit tests — unban() edge cases
# ---------------------------------------------------------------------------

class TestUnban:
    def test_noop_for_ip_not_in_registry(self):
        unbanner, _, notifier = _make_unbanner()
        with _mock_iptables_success(unbanner) as mock_run:
            unbanner.unban("9.9.9.9")  # not in registry
        mock_run.assert_not_called()
        notifier.send_unban_alert.assert_not_called()

    def test_no_audit_log_does_not_raise(self):
        unbanner, shared, _ = _make_unbanner()
        shared.audit_log = None
        _add_ban(shared, "1.2.3.4", backoff_level=0, elapsed_seconds=700)
        with _mock_iptables_success(unbanner):
            unbanner.unban("1.2.3.4")  # should not raise

    def test_level_2_increments_to_3(self):
        unbanner, shared, _ = _make_unbanner()
        _add_ban(shared, "1.2.3.4", backoff_level=2, elapsed_seconds=7300)
        with _mock_iptables_success(unbanner):
            unbanner.unban("1.2.3.4")
        with shared.ban_lock:
            assert shared.ban_history.get("1.2.3.4") == 3


# ---------------------------------------------------------------------------
# Unit tests — _check_expired()
# ---------------------------------------------------------------------------

class TestCheckExpired:
    def test_expired_ban_is_unbanned(self):
        unbanner, shared, _ = _make_unbanner()
        _add_ban(shared, "1.2.3.4", backoff_level=0, elapsed_seconds=700)
        with _mock_iptables_success(unbanner):
            unbanner._check_expired()
        with shared.ban_lock:
            assert "1.2.3.4" not in shared.ban_registry

    def test_unexpired_ban_is_not_unbanned(self):
        unbanner, shared, _ = _make_unbanner()
        _add_ban(shared, "1.2.3.4", backoff_level=0, elapsed_seconds=100)  # < 600s
        with _mock_iptables_success(unbanner) as mock_run:
            unbanner._check_expired()
        mock_run.assert_not_called()
        with shared.ban_lock:
            assert "1.2.3.4" in shared.ban_registry

    def test_sentinel_keys_are_skipped(self):
        """ban_history entries must not be treated as active bans."""
        unbanner, shared, _ = _make_unbanner()
        with shared.ban_lock:
            shared.ban_history["1.2.3.4"] = 1  # history only, not active ban
        with _mock_iptables_success(unbanner) as mock_run:
            unbanner._check_expired()
        mock_run.assert_not_called()

    def test_multiple_ips_only_expired_ones_unbanned(self):
        unbanner, shared, _ = _make_unbanner()
        _add_ban(shared, "1.1.1.1", backoff_level=0, elapsed_seconds=700)   # expired
        _add_ban(shared, "2.2.2.2", backoff_level=0, elapsed_seconds=100)   # not yet
        with _mock_iptables_success(unbanner):
            unbanner._check_expired()
        with shared.ban_lock:
            assert "1.1.1.1" not in shared.ban_registry
            assert "2.2.2.2" in shared.ban_registry
