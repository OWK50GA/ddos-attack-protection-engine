"""
test_monitor.py — Tests for monitor.py (LogTailer).

Sub-task 3.1: Property 1  — Log line parsing extracts all required fields.
Sub-task 3.2: Property 2  — Invalid log lines are skipped and counted.
Sub-task 3.3: Property 3  — Parsed entries are fed into both sliding windows.

Additional unit tests cover:
  - Timestamp parsing (UTC offsets, naive timestamps)
  - Error events (4xx/5xx) are recorded in ip_error_windows
  - File-not-found retry behaviour (mocked)
  - Tail mode: file is seeked to EOF on open
"""

import json
import threading
import time
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

# ---------------------------------------------------------------------------
# Shared helpers / fixtures
# ---------------------------------------------------------------------------

def _make_shared(window_seconds: int = 60):
    """Return a minimal SharedState backed by a real Config."""
    from detector.config import Config
    from detector.models import SharedState

    cfg = Config(slack_webhook_url="https://hooks.slack.com/x")
    cfg.sliding_window_seconds = window_seconds
    return SharedState(config=cfg)


def _make_tailer(window_seconds: int = 60):
    """Return a (LogTailer, SharedState) pair."""
    from detector.monitor import LogTailer

    shared = _make_shared(window_seconds)
    return LogTailer(shared), shared


def _valid_json_line(
    source_ip="1.2.3.4",
    timestamp="2025-04-26T14:32:01+00:00",
    method="GET",
    path="/index.html",
    status=200,
    response_size=512,
) -> str:
    return json.dumps(
        {
            "source_ip": source_ip,
            "timestamp": timestamp,
            "method": method,
            "path": path,
            "status": status,
            "response_size": response_size,
        }
    )


# ---------------------------------------------------------------------------
# Sub-task 3.1 — Property 1: Log line parsing extracts all required fields
# Feature: ddos-anomaly-detection-engine, Property 1:
#   For any valid JSON log line containing the six required fields,
#   parse_line() returns a LogEntry with all fields correctly typed.
# ---------------------------------------------------------------------------

# Strategy: generate realistic-looking log line dicts
_ip_strategy = st.ip_addresses(v=4).map(str)
_method_strategy = st.sampled_from(["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"])
_path_strategy = st.text(
    alphabet=st.characters(blacklist_characters="\n\r\"\\", blacklist_categories=("Cs",)),
    min_size=1,
    max_size=100,
).map(lambda p: "/" + p)
_status_strategy = st.integers(min_value=100, max_value=599)
_size_strategy = st.integers(min_value=0, max_value=10_000_000)
_ts_strategy = st.just("2025-04-26T14:32:01+00:00")


@settings(max_examples=200)
@given(
    source_ip=_ip_strategy,
    method=_method_strategy,
    path=_path_strategy,
    status=_status_strategy,
    response_size=_size_strategy,
)
def test_property1_parse_line_extracts_all_fields(
    source_ip, method, path, status, response_size
):
    """
    Property 1: parse_line() on a valid JSON line returns a LogEntry with
    all six fields correctly typed and populated.
    """
    from detector.models import LogEntry
    from detector.monitor import LogTailer

    tailer, _ = _make_tailer()
    line = _valid_json_line(
        source_ip=source_ip,
        method=method,
        path=path,
        status=status,
        response_size=response_size,
    )
    entry = tailer.parse_line(line)

    assert entry is not None, "parse_line() returned None for a valid line"
    assert isinstance(entry, LogEntry)
    assert entry.source_ip == source_ip
    assert entry.method == method
    assert entry.path == path
    assert entry.status == status
    assert entry.response_size == response_size
    assert isinstance(entry.timestamp, datetime)
    assert entry.timestamp.tzinfo is not None  # must be timezone-aware


# ---------------------------------------------------------------------------
# Sub-task 3.2 — Property 2: Invalid log lines are skipped and counted
# Feature: ddos-anomaly-detection-engine, Property 2:
#   For any string that is not valid JSON or is missing required fields,
#   parse_line() returns None and increments parse_error_count by exactly 1.
# ---------------------------------------------------------------------------

@settings(max_examples=200)
@given(
    bad_line=st.one_of(
        # Pure garbage
        st.text(min_size=0, max_size=200).filter(
            lambda s: not _is_valid_log_json(s)
        ),
        # Valid JSON but missing one or more required fields
        st.fixed_dictionaries({"source_ip": st.ip_addresses(v=4).map(str)}).map(
            json.dumps
        ),
        # Empty string
        st.just(""),
        # Valid JSON but wrong types
        st.just(json.dumps({"source_ip": 123, "timestamp": None,
                            "method": [], "path": {}, "status": "ok",
                            "response_size": "big"})),
    )
)
def test_property2_invalid_lines_skipped_and_counted(bad_line):
    """
    Property 2: parse_line() on an invalid line returns None and increments
    parse_error_count by exactly 1 without raising an exception.
    """
    tailer, shared = _make_tailer()
    before = shared.parse_error_count
    result = tailer.parse_line(bad_line)
    assert result is None
    assert shared.parse_error_count == before + 1


def _is_valid_log_json(s: str) -> bool:
    """Return True if s is a JSON object with all six required fields."""
    try:
        obj = json.loads(s)
        required = {"source_ip", "timestamp", "method", "path", "status", "response_size"}
        return isinstance(obj, dict) and required.issubset(obj.keys())
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Sub-task 3.3 — Property 3: Parsed entries are fed into both sliding windows
# Feature: ddos-anomaly-detection-engine, Property 3:
#   For any valid LogEntry, after feeding it into shared state, both
#   ip_windows[source_ip] and global_window contain a record of that event.
# ---------------------------------------------------------------------------

@settings(max_examples=200)
@given(
    source_ip=_ip_strategy,
    status=_status_strategy,
    response_size=_size_strategy,
)
def test_property3_entry_fed_into_both_windows(source_ip, status, response_size):
    """
    Property 3: After parse_line() + _feed(), both global_window and
    ip_windows[source_ip] contain the event.
    """
    tailer, shared = _make_tailer()
    line = _valid_json_line(source_ip=source_ip, status=status, response_size=response_size)
    entry = tailer.parse_line(line)
    assert entry is not None

    tailer._feed(entry)

    with shared.windows_lock:
        assert len(shared.global_window) >= 1, "global_window is empty after feed"
        assert source_ip in shared.ip_windows, f"{source_ip} not in ip_windows"
        assert len(shared.ip_windows[source_ip]) >= 1


# ---------------------------------------------------------------------------
# Unit tests — timestamp parsing
# ---------------------------------------------------------------------------

class TestTimestampParsing:
    def test_utc_offset_zero(self):
        tailer, _ = _make_tailer()
        dt = tailer._parse_timestamp("2025-04-26T14:32:01+00:00")
        assert dt.tzinfo is not None
        assert dt.hour == 14

    def test_positive_offset_normalised_to_utc(self):
        tailer, _ = _make_tailer()
        # +01:00 means UTC is one hour earlier
        dt = tailer._parse_timestamp("2025-04-26T15:32:01+01:00")
        assert dt.hour == 14  # normalised to UTC

    def test_naive_timestamp_treated_as_utc(self):
        tailer, _ = _make_tailer()
        dt = tailer._parse_timestamp("2025-04-26T14:32:01")
        assert dt.tzinfo == timezone.utc


# ---------------------------------------------------------------------------
# Unit tests — error event tracking
# ---------------------------------------------------------------------------

class TestErrorWindowPopulation:
    @pytest.mark.parametrize("status", [400, 401, 403, 404, 429, 500, 502, 503])
    def test_error_status_populates_error_window(self, status):
        tailer, shared = _make_tailer()
        line = _valid_json_line(source_ip="10.0.0.1", status=status)
        entry = tailer.parse_line(line)
        tailer._feed(entry)
        with shared.windows_lock:
            assert "10.0.0.1" in shared.ip_error_windows
            assert len(shared.ip_error_windows["10.0.0.1"]) == 1

    @pytest.mark.parametrize("status", [200, 201, 204, 301, 302])
    def test_success_status_does_not_populate_error_window(self, status):
        tailer, shared = _make_tailer()
        line = _valid_json_line(source_ip="10.0.0.2", status=status)
        entry = tailer.parse_line(line)
        tailer._feed(entry)
        with shared.windows_lock:
            assert "10.0.0.2" not in shared.ip_error_windows


# ---------------------------------------------------------------------------
# Unit tests — multiple IPs get separate windows
# ---------------------------------------------------------------------------

class TestMultipleIPs:
    def test_separate_windows_per_ip(self):
        tailer, shared = _make_tailer()
        for ip in ["1.1.1.1", "2.2.2.2", "3.3.3.3"]:
            entry = tailer.parse_line(_valid_json_line(source_ip=ip))
            tailer._feed(entry)

        with shared.windows_lock:
            assert len(shared.ip_windows) == 3
            for ip in ["1.1.1.1", "2.2.2.2", "3.3.3.3"]:
                assert ip in shared.ip_windows

    def test_global_window_counts_all_ips(self):
        tailer, shared = _make_tailer()
        for ip in ["1.1.1.1", "2.2.2.2", "3.3.3.3"]:
            entry = tailer.parse_line(_valid_json_line(source_ip=ip))
            tailer._feed(entry)

        with shared.windows_lock:
            assert len(shared.global_window) == 3


# ---------------------------------------------------------------------------
# Unit tests — file retry behaviour
# ---------------------------------------------------------------------------

class TestFileRetry:
    def test_retries_until_file_exists(self, tmp_path):
        """
        LogTailer._open_with_retry() should keep retrying until the file
        appears.  We mock time.sleep to avoid actual delays and create the
        file after the first failed attempt.
        """
        from detector.monitor import LogTailer

        log_path = str(tmp_path / "access.log")
        tailer, shared = _make_tailer()
        tailer._log_path = log_path

        retry_count = {"n": 0}

        def fake_sleep(secs):
            # Only count sleeps that are the 5-second retry delay
            if secs == 5:
                retry_count["n"] += 1
                # Create the file on the first retry so the loop exits
                if retry_count["n"] == 1:
                    with open(log_path, "w") as f:
                        f.write("")

        with patch("detector.monitor.time.sleep", side_effect=fake_sleep):
            fh = tailer._open_with_retry()

        assert fh is not None
        assert retry_count["n"] == 1, (
            f"Expected exactly 1 retry sleep, got {retry_count['n']}"
        )
        fh.close()
