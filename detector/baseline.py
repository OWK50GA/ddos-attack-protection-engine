"""
baseline.py — Rolling traffic baseline calculator.

BaselineCalculator runs in its own daemon thread and recalculates the
effective mean and standard deviation of global request rates every
`baseline_recalc_interval_seconds` (default 60 s).

How it works:
  1. Every recalc interval, snapshot the current global req/s from the
     shared sliding window.
  2. Append the snapshot to the 30-minute BaselineWindow (stale samples
     are evicted automatically).
  3. Also store the snapshot in the per-hour slot for the current UTC hour.
  4. Select the preferred sample set:
       - If the current hour's slot has >= 60 samples → use that slot
         (time-of-day-aware baseline).
       - Otherwise → use the full 30-minute rolling window.
  5. Compute mean and stddev over the selected samples.
  6. Clamp mean to >= 1.0 (floor prevents division-by-zero in detector).
  7. Update shared.baseline_state under baseline_lock.
  8. Write a BASELINE_RECALC audit entry.

Design notes:
  - statistics.mean / statistics.stdev are used directly — no external deps.
  - stddev is 0.0 when fewer than 2 samples exist (not enough data yet).
  - The recalc loop sleeps for the full interval between runs; it does not
    attempt to compensate for drift.  Millisecond precision is not required.
"""

import statistics
import time
from datetime import datetime, timezone

from detector.models import BaselineState, SharedState


class BaselineCalculator:
    """
    Periodically recalculates the rolling traffic baseline and updates
    shared.baseline_state.
    """

    def __init__(self, shared: SharedState) -> None:
        self._shared = shared
        self._config = shared.config

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def run(self) -> None:
        """
        Blocking loop — intended to run inside a daemon thread.
        Sleeps for baseline_recalc_interval_seconds between recalculations.
        """
        interval = self._config.baseline_recalc_interval_seconds
        while True:
            time.sleep(interval)
            try:
                self.recalculate()
            except Exception as exc:  # pragma: no cover
                if self._shared.audit_log:
                    self._shared.audit_log.error("baseline", str(exc))

    def recalculate(self) -> BaselineState:
        """
        Perform one baseline recalculation cycle.

        Snapshots the current global rate, updates the baseline window,
        computes stats, clamps the mean, updates shared state, and writes
        an audit entry.  Returns the new BaselineState.
        """
        now = datetime.now(timezone.utc)

        # 1. Snapshot current global req/s
        with self._shared.windows_lock:
            snapshot_rate = self._shared.global_window.rate()

        # 2 & 3. Append to baseline window (handles eviction + hourly slot)
        self._shared.baseline_window.add_sample(now, snapshot_rate)

        # 4. Select preferred sample set
        samples = self._shared.baseline_window.preferred_samples(now.hour)

        # 5 & 6. Compute stats with floor
        mean, stddev = self._compute_stats(samples)

        # 7. Update shared baseline state under lock
        new_state = BaselineState(mean=mean, stddev=stddev, last_updated=now)
        with self._shared.baseline_lock:
            self._shared.baseline_state = new_state

        # 7b. Append to baseline history for the dashboard graph
        self._shared.baseline_history.append({
            "timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "mean": round(mean, 4),
            "stddev": round(stddev, 4),
            "hour": now.hour,
        })

        # 8. Write audit entry
        if self._shared.audit_log:
            self._shared.audit_log.baseline_recalc(mean, stddev)

        return new_state

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _compute_stats(self, samples: list) -> tuple:
        """
        Compute (mean, stddev) from *samples*.

        Rules:
          - Empty list or single sample → (1.0, 0.0)
          - Computed mean < 1.0 → clamped to 1.0
          - stddev is 0.0 when fewer than 2 samples exist
        """
        if len(samples) < 2:
            raw_mean = samples[0] if samples else 0.0
            mean = max(1.0, float(raw_mean))
            return mean, 0.0

        raw_mean = statistics.mean(samples)
        stddev = statistics.stdev(samples)
        mean = max(1.0, float(raw_mean))
        return mean, float(stddev)
