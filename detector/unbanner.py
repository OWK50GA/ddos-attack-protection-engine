"""
unbanner.py — Automatic IP unban with exponential backoff.

The Unbanner runs a loop every 30 seconds, checks every active BanRecord,
and releases bans whose elapsed time meets or exceeds their duration.

Backoff schedule:
  Level 0 →  600 s (10 min)  → unban, next level = 1
  Level 1 → 1800 s (30 min)  → unban, next level = 2
  Level 2 → 7200 s (2 hours) → unban, next level = 3
  Level 3 → permanent        → never automatically unbanned

On unban:
  1. Remove the iptables DROP rule via subprocess.
  2. Increment the backoff level (stored as __backoff__<ip> sentinel).
  3. Remove the BanRecord from ban_registry.
  4. Write an UNBAN audit entry.
  5. Send a Slack unban alert via the Notifier.

Design notes:
  - duration_seconds == 0 signals a permanent ban; the unbanner skips it.
  - The ban_lock is held only for registry reads/writes, not during the
    iptables call or Slack POST.
  - A snapshot of the registry is taken at the start of each loop cycle
    to avoid mutating the dict while iterating.
"""

import subprocess
import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from detector.blocker import BACKOFF_DURATIONS, BACKOFF_LABELS
from detector.models import SharedState

if TYPE_CHECKING:
    from detector.notifier import Notifier

# How often the unbanner loop checks for expired bans (seconds)
_CHECK_INTERVAL = 30


class Unbanner:
    """
    Periodically scans the ban registry and releases expired bans.
    """

    def __init__(self, shared: SharedState, notifier: "Notifier") -> None:
        self._shared = shared
        self._config = shared.config
        self._notifier = notifier

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def run(self) -> None:
        """
        Blocking loop — intended to run inside a daemon thread.
        Checks for expired bans every _CHECK_INTERVAL seconds.
        """
        while True:
            time.sleep(_CHECK_INTERVAL)
            try:
                self._check_expired()
            except Exception as exc:  # pragma: no cover
                if self._shared.audit_log:
                    self._shared.audit_log.error("unbanner", str(exc))

    def unban(self, ip: str) -> None:
        """
        Unban a single IP:
          1. Remove iptables rule.
          2. Increment backoff level in history sentinel.
          3. Remove BanRecord from registry.
          4. Write UNBAN audit entry.
          5. Send Slack alert.
        """
        # Retrieve the current record before removing it
        with self._shared.ban_lock:
            record = self._shared.ban_registry.get(ip)
            if record is None:
                return  # already unbanned by another thread

        # 1. Remove iptables rule (outside lock)
        self._remove_iptables_rule(ip)

        # 2. Increment backoff level in ban_history
        new_level = min(record.backoff_level + 1, 3)

        # 3. Remove BanRecord from active registry; update history
        with self._shared.ban_lock:
            # Double-check it's still there (race guard)
            if ip not in self._shared.ban_registry:
                return
            del self._shared.ban_registry[ip]
            # Persist the new backoff level so Blocker uses it on next ban
            self._shared.ban_history[ip] = new_level

        # 4. Audit log
        with self._shared.baseline_lock:
            mean = self._shared.baseline_state.mean

        next_duration_label = BACKOFF_LABELS[new_level]
        if self._shared.audit_log:
            self._shared.audit_log.unban(
                ip=ip,
                level=record.backoff_level,
                mean=mean,
                next_duration=next_duration_label,
            )

        # 5. Slack alert
        try:
            self._notifier.send_unban_alert(
                ip=ip,
                backoff_level=record.backoff_level,
                next_duration=next_duration_label,
            )
        except Exception as exc:  # pragma: no cover
            if self._shared.audit_log:
                self._shared.audit_log.error("unbanner", f"Slack alert failed: {exc}")

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _check_expired(self) -> None:
        """
        Snapshot the ban registry and unban any IPs whose ban has expired.
        Skips permanent bans (duration_seconds == 0).
        """
        now = datetime.now(timezone.utc)

        with self._shared.ban_lock:
            snapshot = dict(self._shared.ban_registry)

        for ip, record in snapshot.items():
            # Skip permanent bans
            if record.duration_seconds == 0:
                continue
            elapsed = (now - record.banned_at).total_seconds()
            if elapsed >= record.duration_seconds:
                self.unban(record.ip)

    def _remove_iptables_rule(self, ip: str) -> bool:
        """
        Remove iptables rules for *ip* from both DOCKER-USER and INPUT chains.

        Returns True if all removals succeeded, False if any failed.
        Logs errors but never raises.
        """
        cmds = [
            ["iptables", "-D", "DOCKER-USER", "-s", ip, "-j", "DROP"],
            ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
        ]
        success = True
        for cmd in cmds:
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if result.returncode != 0:
                    msg = (
                        f"iptables -D failed for {ip} ({' '.join(cmd)}): "
                        f"rc={result.returncode} stderr={result.stderr.strip()!r}"
                    )
                    if self._shared.audit_log:
                        self._shared.audit_log.error("unbanner", msg)
                    success = False
            except FileNotFoundError:
                if self._shared.audit_log:
                    self._shared.audit_log.error(
                        "unbanner", f"iptables not found — cannot unban {ip}"
                    )
                return False
            except Exception as exc:  # pragma: no cover
                if self._shared.audit_log:
                    self._shared.audit_log.error("unbanner", f"iptables exception: {exc}")
                return False
        return success
