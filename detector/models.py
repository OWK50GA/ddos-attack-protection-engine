"""
models.py — Shared data models for the DDoS Anomaly Detection Engine.

All mutable shared state lives in SharedState and is protected by the
locks defined here. Lock acquisition order (to prevent deadlock):
  windows_lock → baseline_lock → ban_lock
"""

import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Optional

from detector.config import Config

from detector.audit_log import AuditLog

# ---------------------------------------------------------------------------
# Log entry
# ---------------------------------------------------------------------------

@dataclass
class LogEntry:
    """One parsed line from the Nginx JSON access log."""
    source_ip: str
    timestamp: datetime
    method: str
    path: str
    status: int
    response_size: int


# ---------------------------------------------------------------------------
# Sliding window (deque-based, time-based eviction)
# ---------------------------------------------------------------------------

# Generous upper bound on events stored per window.
# At 100 k req/s for 60 s that is 6 M entries — we cap at 500 k to bound RAM.
_DEQUE_MAXLEN = 500_000


@dataclass
class SlidingWindow:
    """
    Tracks request timestamps over a rolling time window.

    Internally stores a deque of datetime objects (one per event).
    Eviction is time-based: stale entries are popped from the left on
    every add() call so the deque always contains only events within
    the last *window_seconds* seconds.
    """

    window_seconds: int
    # Each element is a UTC datetime of one request event.
    _events: deque = field(default_factory=lambda: deque(maxlen=_DEQUE_MAXLEN))

    def add(self, ts: datetime) -> None:
        """Append *ts* and evict events older than window_seconds."""
        self._events.append(ts)
        cutoff = ts.timestamp() - self.window_seconds
        # Pop from the left while the oldest event is outside the window.
        while self._events and self._events[0].timestamp() < cutoff:
            self._events.popleft()

    def rate(self) -> float:
        """
        Return the request rate (events per second) over the current window.

        Uses the actual elapsed time between the oldest and newest event
        when the window is not yet full; falls back to window_seconds once
        the window is saturated.
        """
        if not self._events:
            return 0.0
        now = datetime.now(timezone.utc)
        cutoff = now.timestamp() - self.window_seconds
        # Count only events within the window relative to *now*.
        count = sum(1 for e in self._events if e.timestamp() >= cutoff)
        return count / self.window_seconds

    def error_rate(self, error_events: "deque") -> float:
        """
        Return the error event rate (events per second) for *error_events*
        using the same window_seconds denominator.
        """
        if not error_events:
            return 0.0
        now = datetime.now(timezone.utc)
        cutoff = now.timestamp() - self.window_seconds
        count = sum(1 for e in error_events if e.timestamp() >= cutoff)
        return count / self.window_seconds

    def __len__(self) -> int:
        return len(self._events)


# ---------------------------------------------------------------------------
# Baseline window (30-minute rolling, per-hour slots)
# ---------------------------------------------------------------------------

@dataclass
class BaselineWindow:
    """
    Maintains a rolling 30-minute collection of per-second request-rate
    snapshots and per-hour slots for time-of-day-aware baseline selection.
    """

    window_minutes: int = 30
    # Each element: (UTC datetime of snapshot, req/s value)
    _samples: deque = field(default_factory=lambda: deque(maxlen=10_000))
    # hour-of-day (0–23) → list of req/s samples collected in that hour
    _hourly_slots: Dict[int, list] = field(default_factory=dict)

    def add_sample(self, ts: datetime, rate: float) -> None:
        """
        Append a new (timestamp, rate) sample and record it in the
        appropriate hourly slot.  Stale samples are evicted lazily in
        current_samples().
        """
        self._samples.append((ts, rate))
        hour = ts.hour
        self._hourly_slots.setdefault(hour, []).append(rate)

    def current_samples(self) -> list:
        """
        Return req/s values for samples within the last *window_minutes*,
        evicting stale entries from the deque as a side-effect.
        """
        if not self._samples:
            return []
        now = datetime.now(timezone.utc)
        cutoff = now.timestamp() - self.window_minutes * 60
        # Evict from the left
        while self._samples and self._samples[0][0].timestamp() < cutoff:
            self._samples.popleft()
        return [rate for _, rate in self._samples]

    def preferred_samples(self, current_hour: int) -> list:
        """
        Return the current hour's samples when that slot has >= 60 entries
        (enough data to be statistically meaningful); otherwise fall back
        to the full rolling window.
        """
        hourly = self._hourly_slots.get(current_hour, [])
        if len(hourly) >= 60:
            return list(hourly)
        return self.current_samples()


# ---------------------------------------------------------------------------
# Baseline state (computed result, updated every recalc interval)
# ---------------------------------------------------------------------------

@dataclass
class BaselineState:
    """
    The most recently computed baseline statistics.
    mean is always >= 1.0 (floor enforced by BaselineCalculator).
    stddev is 0.0 when fewer than 2 samples are available.
    """
    mean: float = 1.0
    stddev: float = 0.0
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Ban record
# ---------------------------------------------------------------------------

@dataclass
class BanRecord:
    """Metadata for a single active IP ban."""
    ip: str
    banned_at: datetime
    duration_seconds: int   # 0 = permanent
    backoff_level: int      # 0–3
    condition: str          # e.g. "zscore", "rate_multiplier"
    rate_at_ban: float
    mean_at_ban: float


# ---------------------------------------------------------------------------
# Shared state (single object passed to every subsystem)
# ---------------------------------------------------------------------------

@dataclass
class SharedState:
    """
    Central shared-state container.  Every subsystem receives a reference
    to this object.  All mutable fields are protected by their associated
    lock.  Acquire locks in order: windows_lock → baseline_lock → ban_lock.
    """

    config: Config

    # --- Sliding windows ---
    global_window: SlidingWindow = field(init=False)
    # source_ip → SlidingWindow of all requests
    ip_windows: Dict[str, SlidingWindow] = field(default_factory=dict)
    # source_ip → SlidingWindow of 4xx/5xx error events
    ip_error_windows: Dict[str, SlidingWindow] = field(default_factory=dict)
    windows_lock: threading.Lock = field(default_factory=threading.Lock)

    # --- Baseline ---
    baseline_window: BaselineWindow = field(init=False)
    baseline_state: BaselineState = field(default_factory=BaselineState)
    baseline_lock: threading.Lock = field(default_factory=threading.Lock)

    # --- Ban registry (active bans only) ---
    # source_ip → BanRecord for IPs currently blocked by iptables
    ban_registry: Dict[str, BanRecord] = field(default_factory=dict)
    # source_ip → next backoff level (persists across ban/unban cycles)
    # Level 0 = first offence, 3 = permanent on next ban
    ban_history: Dict[str, int] = field(default_factory=dict)
    ban_lock: threading.Lock = field(default_factory=threading.Lock)

    # --- Baseline history (for dashboard graph) ---
    # Each entry: {"timestamp": ISO8601 str, "mean": float, "stddev": float, "hour": int}
    # Capped at 500 entries (~8+ hours at 60s recalc interval)
    baseline_history: deque = field(
        default_factory=lambda: deque(maxlen=500)
    )

    # --- Diagnostics ---
    parse_error_count: int = 0
    daemon_start_time: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    # Set after AuditLog is instantiated in main.py
    audit_log: Optional[AuditLog] = None

    def __post_init__(self) -> None:
        self.global_window = SlidingWindow(
            window_seconds=self.config.sliding_window_seconds
        )
        self.baseline_window = BaselineWindow(
            window_minutes=self.config.baseline_window_minutes
        )
