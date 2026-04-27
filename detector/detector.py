"""
detector.py — Anomaly detection engine.

The Detector runs a tight loop (every 1 second) evaluating every active
source IP and the global traffic rate against the current baseline.

Detection logic (two conditions, whichever fires first):
  1. Z-score:          (current_rate - mean) / stddev  > zscore_threshold
  2. Rate multiplier:  current_rate > rate_multiplier * mean

Error-surge tightening:
  If an IP's 4xx/5xx rate exceeds error_rate_multiplier * baseline_error_rate,
  both thresholds are halved for that IP during the current evaluation cycle.

Global anomaly:
  The global rate is evaluated with the same logic.  A global anomaly
  triggers a Slack alert only — no iptables block.

Design notes:
  - No rate-limiting library is used.  All logic is hand-rolled.
  - stddev == 0 → z-score is 0.0 (not anomalous by z-score alone).
  - The Blocker is called synchronously; it handles duplicate-ban checks.
  - A Notifier reference is needed for global anomaly alerts.
"""

import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

from detector.models import SharedState

if TYPE_CHECKING:
    from detector.blocker import Blocker
    from detector.notifier import Notifier


# Assumed baseline error rate fraction when no explicit baseline exists.
# 5 % of mean traffic is treated as the normal error rate.
_BASELINE_ERROR_FRACTION = 0.05


@dataclass
class DetectionResult:
    """Result of evaluating a single IP or the global window."""
    anomalous: bool
    condition: str   # "zscore", "rate_multiplier", or "" if not anomalous
    rate: float      # current req/s at time of evaluation


class Detector:
    """
    Evaluates per-IP and global request rates every second and calls
    Blocker.ban() for any IP that crosses a detection threshold.
    """

    def __init__(
        self,
        shared: SharedState,
        blocker: "Blocker",
        notifier: Optional["Notifier"] = None,
    ) -> None:
        self._shared = shared
        self._config = shared.config
        self._blocker = blocker
        self._notifier = notifier

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def run(self) -> None:
        """
        Blocking loop — intended to run inside a daemon thread.
        Evaluates all active IPs and the global rate every 1 second.
        """
        while True:
            try:
                self._evaluate_all()
            except Exception as exc:  # pragma: no cover
                if self._shared.audit_log:
                    self._shared.audit_log.error("detector", str(exc))
            time.sleep(1)

    def evaluate_ip(self, ip: str, window, error_window=None) -> DetectionResult:
        """
        Evaluate a single IP's sliding window against the current baseline.

        Returns a DetectionResult indicating whether the IP is anomalous,
        which condition fired, and the current rate.
        """
        with self._shared.baseline_lock:
            mean = self._shared.baseline_state.mean
            stddev = self._shared.baseline_state.stddev

        current_rate = window.rate()

        # Determine effective thresholds (may be tightened for error-heavy IPs)
        zscore_thresh, rate_mult = self._effective_thresholds(
            ip, current_rate, mean, error_window
        )

        # Condition 1: z-score
        zscore = self.compute_zscore(current_rate, mean, stddev)
        if zscore > zscore_thresh:
            return DetectionResult(anomalous=True, condition="zscore", rate=current_rate)

        # Condition 2: rate multiplier
        if current_rate > rate_mult * mean:
            return DetectionResult(
                anomalous=True, condition="rate_multiplier", rate=current_rate
            )

        return DetectionResult(anomalous=False, condition="", rate=current_rate)

    def compute_zscore(self, rate: float, mean: float, stddev: float) -> float:
        """
        Compute z-score: (rate - mean) / stddev.
        Returns 0.0 when stddev is 0 (no variance → not anomalous by z-score).
        """
        if stddev == 0.0:
            return 0.0
        return (rate - mean) / stddev

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _evaluate_all(self) -> None:
        """Snapshot active IPs and evaluate each one plus the global rate."""
        # Snapshot window keys under lock to avoid dict-size-change during iteration
        with self._shared.windows_lock:
            ip_list = list(self._shared.ip_windows.keys())

        for ip in ip_list:
            # Skip already-banned IPs — no need to re-evaluate
            with self._shared.ban_lock:
                if ip in self._shared.ban_registry:
                    continue

            with self._shared.windows_lock:
                window = self._shared.ip_windows.get(ip)
                error_window = self._shared.ip_error_windows.get(ip)

            if window is None:
                continue

            result = self.evaluate_ip(ip, window, error_window)
            if result.anomalous:
                with self._shared.baseline_lock:
                    mean = self._shared.baseline_state.mean
                self._blocker.ban(ip, result.condition, result.rate)

        # Evaluate global rate — alert only, no block
        self._evaluate_global()

    def _evaluate_global(self) -> None:
        """Evaluate the global request rate; send Slack alert if anomalous."""
        with self._shared.windows_lock:
            global_rate = self._shared.global_window.rate()

        with self._shared.baseline_lock:
            mean = self._shared.baseline_state.mean
            stddev = self._shared.baseline_state.stddev

        zscore = self.compute_zscore(global_rate, mean, stddev)
        rate_anomalous = global_rate > self._config.rate_multiplier * mean
        zscore_anomalous = zscore > self._config.zscore_threshold

        if (zscore_anomalous or rate_anomalous) and self._notifier:
            try:
                self._notifier.send_global_anomaly_alert(global_rate, mean, stddev)
            except Exception as exc:  # pragma: no cover
                if self._shared.audit_log:
                    self._shared.audit_log.error("detector", f"global alert failed: {exc}")

    def _effective_thresholds(
        self, ip: str, current_rate: float, mean: float, error_window
    ) -> tuple:
        """
        Return (zscore_threshold, rate_multiplier) for this IP.

        If the IP's error rate exceeds error_rate_multiplier * baseline_error_rate,
        both thresholds are halved (tightened) for this evaluation cycle.
        """
        zscore_thresh = self._config.zscore_threshold
        rate_mult = self._config.rate_multiplier

        if error_window is not None:
            baseline_error_rate = mean * _BASELINE_ERROR_FRACTION
            ip_error_rate = error_window.rate()
            if ip_error_rate > self._config.error_rate_multiplier * baseline_error_rate:
                zscore_thresh = zscore_thresh * 0.5
                rate_mult = rate_mult * 0.5

        return zscore_thresh, rate_mult
