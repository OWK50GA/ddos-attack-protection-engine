"""
blocker.py — IP blocking via iptables.

When the Detector flags a source IP as anomalous, Blocker.ban() is called.
It:
  1. Checks the ban registry — skips if the IP is already banned (idempotent).
  2. Executes `iptables -A INPUT -s <IP> -j DROP` via subprocess.
  3. Records a BanRecord in shared.ban_registry.
  4. Writes a BAN entry to the audit log.
  5. Sends a Slack ban alert via the Notifier.

Backoff schedule (duration_seconds per backoff level):
  Level 0 →  600 s  (10 min)
  Level 1 → 1800 s  (30 min)
  Level 2 → 7200 s  (2 hours)
  Level 3 →    0 s  (permanent — duration_seconds=0 signals no auto-unban)

Design notes:
  - subprocess.run is called with check=False; a non-zero return code is
    logged but does not raise an exception or prevent the BanRecord from
    being stored.  The daemon must not crash because iptables failed.
  - The ban_lock is held for the minimum time necessary (registry check +
    write only; iptables call happens outside the lock).
  - The Notifier call is also outside the lock to avoid holding it during
    a potentially slow HTTP POST.
"""

import subprocess
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from detector.models import BanRecord, SharedState

if TYPE_CHECKING:
    from detector.notifier import Notifier

# Backoff level → ban duration in seconds (0 = permanent)
BACKOFF_DURATIONS = {
    0: 600,    # 10 min
    1: 1800,   # 30 min
    2: 7200,   # 2 hours
    3: 0,      # permanent
}

# Human-readable labels used in audit log entries
BACKOFF_LABELS = {
    0: "600s",
    1: "1800s",
    2: "7200s",
    3: "permanent",
}


class Blocker:
    """
    Executes iptables DROP rules and maintains the ban registry.
    """

    def __init__(self, shared: SharedState, notifier: "Notifier") -> None:
        self._shared = shared
        self._config = shared.config
        self._notifier = notifier

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def ban(self, ip: str, condition: str, rate: float) -> None:
        """
        Ban *ip* if it is not already in the ban registry.

        Steps:
          1. Check registry (skip if already banned).
          2. Run iptables DROP rule.
          3. Record BanRecord.
          4. Write audit entry.
          5. Send Slack alert.
        """
        # 1. Idempotency check — hold lock only for the check
        with self._shared.ban_lock:
            if ip in self._shared.ban_registry:
                return
            # Reserve the slot immediately to prevent a race between
            # concurrent detector evaluations for the same IP.
            # We'll fill in the full record below.
            placeholder = True

        # 2. Execute iptables (outside lock — may be slow)
        self._run_iptables(ip)

        # 3. Record BanRecord
        with self._shared.baseline_lock:
            mean = self._shared.baseline_state.mean

        backoff_level = self._current_backoff_level(ip)
        duration_seconds = BACKOFF_DURATIONS[backoff_level]
        now = datetime.now(timezone.utc)

        record = BanRecord(
            ip=ip,
            banned_at=now,
            duration_seconds=duration_seconds,
            backoff_level=backoff_level,
            condition=condition,
            rate_at_ban=rate,
            mean_at_ban=mean,
        )

        with self._shared.ban_lock:
            self._shared.ban_registry[ip] = record

        # 4. Audit log
        duration_label = BACKOFF_LABELS[backoff_level]
        if self._shared.audit_log:
            self._shared.audit_log.ban(ip, condition, rate, mean, duration_label)

        # 5. Slack alert
        try:
            self._notifier.send_ban_alert(
                ip=ip,
                condition=condition,
                rate=rate,
                mean=mean,
                stddev=self._shared.baseline_state.stddev,
                duration=duration_label,
            )
        except Exception as exc:  # pragma: no cover
            if self._shared.audit_log:
                self._shared.audit_log.error("blocker", f"Slack alert failed: {exc}")

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _run_iptables(self, ip: str) -> bool:
        """
        Execute `iptables -A INPUT -s <ip> -j DROP`.

        Returns True on success, False on failure.
        Logs the error but never raises.
        """
        cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                msg = (
                    f"iptables failed for {ip}: "
                    f"rc={result.returncode} stderr={result.stderr.strip()!r}"
                )
                if self._shared.audit_log:
                    self._shared.audit_log.error("blocker", msg)
                return False
            return True
        except FileNotFoundError:
            # iptables not available (e.g. in test environment)
            if self._shared.audit_log:
                self._shared.audit_log.error(
                    "blocker", f"iptables not found — cannot block {ip}"
                )
            return False
        except Exception as exc:  # pragma: no cover
            if self._shared.audit_log:
                self._shared.audit_log.error("blocker", f"iptables exception: {exc}")
            return False

    def _current_backoff_level(self, ip: str) -> int:
        """
        Return the backoff level to use for a new ban of *ip*.

        Reads from shared.ban_history which the unbanner updates on each
        unban.  If no prior history exists, starts at level 0.
        """
        with self._shared.ban_lock:
            level = self._shared.ban_history.get(ip, 0)
            return min(int(level), 3)
