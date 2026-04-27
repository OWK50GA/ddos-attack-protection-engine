"""
audit_log.py — Thread-safe, append-only audit log writer.

Every ban, unban, baseline recalculation, and subsystem error is recorded
here in a structured single-line format.  All writes are serialised through
a threading.Lock so concurrent subsystem threads never interleave lines.

Entry formats (from the spec):
  BAN:            [<ISO8601Z>] BAN ip=<IP> | condition=<cond> | rate=<r>/s | baseline=<m>/s | duration=<d>
  UNBAN:          [<ISO8601Z>] UNBAN ip=<IP> | condition=backoff-<lvl> | rate=N/A | baseline=<m>/s | duration=<next>
  BASELINE_RECALC:[<ISO8601Z>] BASELINE_RECALC ip=global | mean=<m> | stddev=<s>
  ERROR:          [<ISO8601Z>] ERROR subsystem=<sub> | msg=<message>
"""

import os
import threading
from datetime import datetime, timezone
from typing import Optional


def _utcnow_iso() -> str:
    """Return the current UTC time as an ISO 8601 string ending in 'Z'."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class AuditLog:
    """
    Append-only audit log backed by a plain text file.

    The file is opened (and created if necessary) in append mode at
    construction time and kept open for the lifetime of the daemon.
    A threading.Lock serialises all writes.
    """

    def __init__(self, path: str) -> None:
        self._path = path
        self._lock = threading.Lock()
        # Ensure the parent directory exists before opening.
        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
        # Open in append mode; 'a' creates the file if it does not exist.
        self._fh = open(path, "a", buffering=1, encoding="utf-8", errors="replace")

    # ------------------------------------------------------------------
    # Low-level write
    # ------------------------------------------------------------------

    def write(self, entry: str) -> None:
        """
        Append *entry* (without a trailing newline) to the log file.
        Thread-safe: acquires the internal lock before writing.
        """
        with self._lock:
            self._fh.write(entry + "\n")
            self._fh.flush()

    # ------------------------------------------------------------------
    # Structured helpers
    # ------------------------------------------------------------------

    def ban(
        self,
        ip: str,
        condition: str,
        rate: float,
        mean: float,
        duration: str,
        ts: Optional[str] = None,
    ) -> None:
        """
        Write a BAN entry.

        Example:
          [2025-04-26T14:32:01Z] BAN ip=1.2.3.4 | condition=zscore | rate=47.0/s | baseline=3.2/s | duration=600s
        """
        ts = ts or _utcnow_iso()
        self.write(
            f"[{ts}] BAN ip={ip} | condition={condition} | "
            f"rate={rate:.1f}/s | baseline={mean:.1f}/s | duration={duration}"
        )

    def unban(
        self,
        ip: str,
        level: int,
        mean: float,
        next_duration: str,
        ts: Optional[str] = None,
    ) -> None:
        """
        Write an UNBAN entry.

        Example:
          [2025-04-26T14:42:01Z] UNBAN ip=1.2.3.4 | condition=backoff-0 | rate=N/A | baseline=3.2/s | duration=1800s
        """
        ts = ts or _utcnow_iso()
        self.write(
            f"[{ts}] UNBAN ip={ip} | condition=backoff-{level} | "
            f"rate=N/A | baseline={mean:.1f}/s | duration={next_duration}"
        )

    def baseline_recalc(
        self,
        mean: float,
        stddev: float,
        ts: Optional[str] = None,
    ) -> None:
        """
        Write a BASELINE_RECALC entry.

        Example:
          [2025-04-26T14:00:00Z] BASELINE_RECALC ip=global | mean=3.1 | stddev=0.8
        """
        ts = ts or _utcnow_iso()
        self.write(
            f"[{ts}] BASELINE_RECALC ip=global | mean={mean:.4f} | stddev={stddev:.4f}"
        )

    def error(
        self,
        subsystem: str,
        msg: str,
        ts: Optional[str] = None,
    ) -> None:
        """
        Write an ERROR entry for subsystem exceptions caught by the supervisor.

        Example:
          [2025-04-26T14:00:00Z] ERROR subsystem=monitor | msg=Failed to open log file
        """
        ts = ts or _utcnow_iso()
        self.write(f"[{ts}] ERROR subsystem={subsystem} | msg={msg}")

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Flush and close the underlying file handle."""
        with self._lock:
            self._fh.flush()
            self._fh.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass
