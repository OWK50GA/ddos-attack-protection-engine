"""
test_audit_log.py — Tests for audit_log.py.

Sub-task 2.1: Property 18 — Audit log entries are append-only.
              Feature: ddos-anomaly-detection-engine, Property 18:
              For any sequence of N writes followed by M additional writes,
              the first N entries must be byte-for-byte identical after the
              second batch — no prior entry is modified or deleted.

Additional unit tests cover:
  - Correct format for each entry type (ban, unban, baseline_recalc, error)
  - Thread-safety: concurrent writes produce no interleaved lines
  - Timestamp injection via the optional ts parameter
"""

import os
import re
import tempfile
import threading

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_log(tmp_path) -> tuple:
    """Return (AuditLog instance, path string) backed by a temp file."""
    from detector.audit_log import AuditLog

    path = str(tmp_path / "audit.log")
    return AuditLog(path), path


def _read_lines(path: str) -> list:
    with open(path) as fh:
        # Strip only the trailing newline; preserve lines that are whitespace-only
        return [line.rstrip("\n") for line in fh]


# ---------------------------------------------------------------------------
# Sub-task 2.1 — Property 18: Audit log entries are append-only
# ---------------------------------------------------------------------------

@settings(max_examples=200)
@given(
    first_batch=st.lists(
        st.text(
            alphabet=st.characters(
                blacklist_characters="\n\r",
                blacklist_categories=("Cs",),  # exclude surrogates
            ),
            min_size=1,
            max_size=80,
        ),
        min_size=1,
        max_size=20,
    ),
    second_batch=st.lists(
        st.text(
            alphabet=st.characters(
                blacklist_characters="\n\r",
                blacklist_categories=("Cs",),  # exclude surrogates
            ),
            min_size=1,
            max_size=80,
        ),
        min_size=0,
        max_size=20,
    ),
)
def test_property18_append_only(first_batch, second_batch):
    """
    Property 18: After N writes then M more writes, the first N lines in the
    file are byte-for-byte identical to the original first batch.
    Uses tempfile directly to avoid function-scoped fixture issues with Hypothesis.
    """
    from detector.audit_log import AuditLog

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".log", delete=False
    ) as fh:
        path = fh.name

    try:
        log = AuditLog(path)

        # Write first batch
        for entry in first_batch:
            log.write(entry)

        # Snapshot the first N lines
        snapshot = _read_lines(path)
        assert snapshot == first_batch, "First batch not written correctly"

        # Write second batch
        for entry in second_batch:
            log.write(entry)

        # Re-read and verify first N lines are unchanged
        all_lines = _read_lines(path)
        assert all_lines[: len(first_batch)] == first_batch, (
            "Earlier entries were modified or deleted after subsequent writes"
        )
        assert len(all_lines) == len(first_batch) + len(second_batch)

        log.close()
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# Unit tests — entry format correctness
# ---------------------------------------------------------------------------

TIMESTAMP_RE = re.compile(r"^\[\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\]")
FIXED_TS = "2025-04-26T14:32:01Z"


class TestBanEntry:
    def test_format(self, tmp_path):
        log, path = _make_log(tmp_path)
        log.ban("1.2.3.4", "zscore", 47.0, 3.2, "600s", ts=FIXED_TS)
        lines = _read_lines(path)
        assert len(lines) == 1
        assert lines[0] == (
            "[2025-04-26T14:32:01Z] BAN ip=1.2.3.4 | condition=zscore | "
            "rate=47.0/s | baseline=3.2/s | duration=600s"
        )

    def test_auto_timestamp(self, tmp_path):
        log, path = _make_log(tmp_path)
        log.ban("1.2.3.4", "rate_multiplier", 100.0, 5.0, "600s")
        lines = _read_lines(path)
        assert TIMESTAMP_RE.match(lines[0])

    def test_contains_all_fields(self, tmp_path):
        log, path = _make_log(tmp_path)
        log.ban("10.0.0.1", "zscore", 55.5, 4.1, "1800s", ts=FIXED_TS)
        line = _read_lines(path)[0]
        assert "BAN" in line
        assert "ip=10.0.0.1" in line
        assert "condition=zscore" in line
        assert "rate=55.5/s" in line
        assert "baseline=4.1/s" in line
        assert "duration=1800s" in line


class TestUnbanEntry:
    def test_format(self, tmp_path):
        log, path = _make_log(tmp_path)
        log.unban("1.2.3.4", 0, 3.2, "1800s", ts=FIXED_TS)
        lines = _read_lines(path)
        assert lines[0] == (
            "[2025-04-26T14:32:01Z] UNBAN ip=1.2.3.4 | condition=backoff-0 | "
            "rate=N/A | baseline=3.2/s | duration=1800s"
        )

    def test_backoff_level_in_condition(self, tmp_path):
        log, path = _make_log(tmp_path)
        log.unban("5.6.7.8", 2, 2.0, "7200s", ts=FIXED_TS)
        line = _read_lines(path)[0]
        assert "condition=backoff-2" in line

    def test_rate_is_na(self, tmp_path):
        log, path = _make_log(tmp_path)
        log.unban("5.6.7.8", 1, 2.0, "7200s", ts=FIXED_TS)
        line = _read_lines(path)[0]
        assert "rate=N/A" in line


class TestBaselineRecalcEntry:
    def test_format(self, tmp_path):
        log, path = _make_log(tmp_path)
        log.baseline_recalc(3.1, 0.8, ts=FIXED_TS)
        lines = _read_lines(path)
        assert lines[0] == (
            "[2025-04-26T14:32:01Z] BASELINE_RECALC ip=global | mean=3.1000 | stddev=0.8000"
        )

    def test_ip_is_global(self, tmp_path):
        log, path = _make_log(tmp_path)
        log.baseline_recalc(1.0, 0.0, ts=FIXED_TS)
        line = _read_lines(path)[0]
        assert "ip=global" in line


class TestErrorEntry:
    def test_format(self, tmp_path):
        log, path = _make_log(tmp_path)
        log.error("monitor", "Failed to open log file", ts=FIXED_TS)
        lines = _read_lines(path)
        assert lines[0] == (
            "[2025-04-26T14:32:01Z] ERROR subsystem=monitor | msg=Failed to open log file"
        )


# ---------------------------------------------------------------------------
# Thread-safety test
# ---------------------------------------------------------------------------

class TestThreadSafety:
    def test_concurrent_writes_no_interleaving(self, tmp_path):
        """
        50 threads each write 20 entries concurrently.
        Every line in the file must be a complete, non-interleaved entry.
        """
        log, path = _make_log(tmp_path)
        n_threads = 50
        entries_per_thread = 20

        def writer(thread_id: int):
            for i in range(entries_per_thread):
                log.write(f"thread={thread_id} entry={i}")

        threads = [threading.Thread(target=writer, args=(t,)) for t in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        lines = _read_lines(path)
        assert len(lines) == n_threads * entries_per_thread
        # Every line must match the expected pattern — no partial writes
        for line in lines:
            assert re.match(r"^thread=\d+ entry=\d+$", line), (
                f"Unexpected line (possible interleaving): {line!r}"
            )
