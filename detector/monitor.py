"""
monitor.py — Real-time Nginx JSON log tailer.

LogTailer opens the Nginx access log in tail mode (seeks to end on first
open), reads new lines as they arrive, parses each as JSON, and feeds
parsed LogEntry objects into the shared sliding windows.

Design decisions:
  - Seek to EOF on open so we don't replay historical log lines on restart.
  - Sleep 0.1 s when no new data is available to avoid busy-waiting.
  - Retry every 5 s if the log file does not exist yet (handles the race
    where the nginx container starts slightly after the detector).
  - Parse errors increment parse_error_count and are skipped silently;
    they never halt ingestion.
  - 4xx/5xx responses are also recorded in ip_error_windows for the
    error-surge detection logic in detector.py.
"""

import json
import time
from datetime import datetime, timezone
from typing import Optional

from detector.models import LogEntry, SharedState, SlidingWindow


class LogTailer:
    """
    Continuously tails the Nginx JSON access log and populates the shared
    sliding windows in SharedState.
    """

    def __init__(self, shared: SharedState) -> None:
        self._shared = shared
        self._config = shared.config
        self._log_path = self._config.log_file_path

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def run(self) -> None:
        """
        Blocking loop — intended to run inside a daemon thread.
        Opens the log file (retrying every 5 s if absent), seeks to the
        end, then reads new lines indefinitely.
        """
        fh = self._open_with_retry()
        try:
            while True:
                line = fh.readline()
                if line:
                    entry = self.parse_line(line)
                    if entry is not None:
                        self._feed(entry)
                else:
                    # No new data — yield the CPU briefly
                    time.sleep(0.1)
        finally:
            fh.close()

    def parse_line(self, line: str) -> Optional[LogEntry]:
        """
        Parse a single JSON log line into a LogEntry.

        Returns None (and increments parse_error_count) if:
          - The line is not valid JSON
          - Any required field is missing or has an unexpected type
        """
        try:
            obj = json.loads(line.strip())
            return LogEntry(
                source_ip=str(obj["source_ip"]),
                timestamp=self._parse_timestamp(obj["timestamp"]),
                method=str(obj["method"]),
                path=str(obj["path"]),
                status=int(obj["status"]),
                response_size=int(obj["response_size"]),
            )
        except (json.JSONDecodeError, KeyError, ValueError, TypeError):
            self._shared.parse_error_count += 1
            return None

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _open_with_retry(self):
        """
        Open the log file in read mode, seeking to the end (tail mode).
        Retries every 5 seconds if the file does not exist yet.
        """
        import os

        while True:
            try:
                fh = open(self._log_path, "r", encoding="utf-8", errors="replace")
                fh.seek(0, 2)  # seek to EOF
                return fh
            except FileNotFoundError:
                if self._shared.audit_log:
                    self._shared.audit_log.error(
                        "monitor",
                        f"Log file not found: {self._log_path} — retrying in 5s",
                    )
                time.sleep(5)

    def _parse_timestamp(self, value: str) -> datetime:
        """
        Parse an ISO 8601 timestamp string from the Nginx log into a
        timezone-aware UTC datetime.

        Nginx emits timestamps like '2025-04-26T14:32:01+00:00' or
        '2025-04-26T14:32:01+01:00'.  We normalise to UTC.
        """
        # Python 3.7+ fromisoformat handles offsets like +00:00
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            # Treat naive timestamps as UTC
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt

    def _feed(self, entry: LogEntry) -> None:
        """
        Insert the parsed entry into the global and per-IP sliding windows.
        Also records error events (4xx/5xx) in ip_error_windows.
        Acquires windows_lock for the duration of the update.
        """
        shared = self._shared
        ws = self._config.sliding_window_seconds
        ts = entry.timestamp

        with shared.windows_lock:
            # Global window
            shared.global_window.add(ts)

            # Per-IP request window
            if entry.source_ip not in shared.ip_windows:
                shared.ip_windows[entry.source_ip] = SlidingWindow(
                    window_seconds=ws
                )
            shared.ip_windows[entry.source_ip].add(ts)

            # Per-IP error window (4xx / 5xx only)
            if entry.status >= 400:
                if entry.source_ip not in shared.ip_error_windows:
                    shared.ip_error_windows[entry.source_ip] = SlidingWindow(
                        window_seconds=ws
                    )
                shared.ip_error_windows[entry.source_ip].add(ts)
