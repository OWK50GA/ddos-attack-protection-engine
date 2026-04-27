"""
test_notifier.py — Tests for notifier.py (Notifier).

Sub-task 10.1: Property 15 — Alert payloads contain all required fields.
Sub-task 10.2: Property 16 — Slack webhook retry count never exceeds 3.

Additional unit tests cover:
  - send_ban_alert() calls _post() with correct payload structure
  - send_unban_alert() calls _post() with correct payload structure
  - send_global_anomaly_alert() calls _post() with correct payload structure
  - _post() returns True on HTTP 200
  - _post() returns False and writes one audit ERROR after all retries fail
  - Webhook URL is read from config, never hardcoded
"""

import json
import time
from datetime import datetime, timezone
from unittest.mock import MagicMock, call, patch

import pytest
import requests
from hypothesis import given, settings
from hypothesis import strategies as st

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_notifier(webhook_url: str = "https://hooks.slack.com/services/T/B/X"):
    from detector.config import Config
    from detector.notifier import Notifier

    cfg = Config(slack_webhook_url=webhook_url)
    audit_log = MagicMock()
    notifier = Notifier(cfg, audit_log)
    return notifier, audit_log


def _mock_post_success():
    """Patch requests.post to return HTTP 200."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "ok"
    return patch("detector.notifier.requests.post", return_value=mock_resp)


def _mock_post_failure(status_code: int = 500):
    """Patch requests.post to always return a non-200 status."""
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.text = "error"
    return patch("detector.notifier.requests.post", return_value=mock_resp)


def _extract_fields_from_payload(payload: dict) -> dict:
    """Flatten all Block Kit field texts into a single dict for easy assertion."""
    fields = {}
    for block in payload.get("blocks", []):
        for field in block.get("fields", []):
            text = field.get("text", "")
            # Extract key from "*Key:*\nvalue" format
            if text.startswith("*") and "*\n" in text:
                key, value = text.split("*\n", 1)
                key = key.strip("*").strip(":")
                fields[key] = value
    return fields


# ---------------------------------------------------------------------------
# Sub-task 10.1 — Property 15: Alert payloads contain all required fields
# Feature: ddos-anomaly-detection-engine, Property 15:
#   For any alert event, the JSON payload sent to the Slack webhook must
#   contain all fields required by the spec for that event type.
# ---------------------------------------------------------------------------

@settings(max_examples=200)
@given(
    ip=st.ip_addresses(v=4).map(str),
    condition=st.sampled_from(["zscore", "rate_multiplier"]),
    rate=st.floats(min_value=0.1, max_value=1000.0, allow_nan=False, allow_infinity=False),
    mean=st.floats(min_value=1.0, max_value=100.0, allow_nan=False, allow_infinity=False),
    stddev=st.floats(min_value=0.0, max_value=20.0, allow_nan=False, allow_infinity=False),
    duration=st.sampled_from(["600s", "1800s", "7200s", "permanent"]),
)
def test_property15_ban_alert_contains_all_required_fields(
    ip, condition, rate, mean, stddev, duration
):
    """
    Property 15a: Ban alert payload contains condition, rate, mean, stddev,
    timestamp, and duration.
    """
    notifier, _ = _make_notifier()
    captured = {}

    def fake_post(url, json=None, timeout=None):
        captured["payload"] = json
        resp = MagicMock()
        resp.status_code = 200
        return resp

    with patch("detector.notifier.requests.post", side_effect=fake_post):
        notifier.send_ban_alert(ip, condition, rate, mean, stddev, duration)

    assert "payload" in captured
    payload_str = str(captured["payload"])

    # All required fields must appear somewhere in the payload
    assert ip in payload_str, "IP missing from ban alert payload"
    assert condition in payload_str, "condition missing from ban alert payload"
    assert duration in payload_str, "duration missing from ban alert payload"

    fields = _extract_fields_from_payload(captured["payload"])
    assert "IP" in fields
    assert "Condition" in fields
    assert "Current Rate" in fields
    assert "Baseline Mean" in fields
    assert "Baseline Stddev" in fields
    assert "Ban Duration" in fields
    assert "Timestamp" in fields


@settings(max_examples=200)
@given(
    ip=st.ip_addresses(v=4).map(str),
    backoff_level=st.integers(min_value=0, max_value=3),
    next_duration=st.sampled_from(["600s", "1800s", "7200s", "permanent"]),
)
def test_property15_unban_alert_contains_all_required_fields(
    ip, backoff_level, next_duration
):
    """
    Property 15b: Unban alert payload contains ip, backoff_level, timestamp,
    and next_duration.
    """
    notifier, _ = _make_notifier()
    captured = {}

    def fake_post(url, json=None, timeout=None):
        captured["payload"] = json
        resp = MagicMock()
        resp.status_code = 200
        return resp

    with patch("detector.notifier.requests.post", side_effect=fake_post):
        notifier.send_unban_alert(ip, backoff_level, next_duration)

    assert "payload" in captured
    payload_str = str(captured["payload"])

    assert ip in payload_str, "IP missing from unban alert payload"
    assert next_duration in payload_str, "next_duration missing from unban alert payload"

    fields = _extract_fields_from_payload(captured["payload"])
    assert "IP" in fields
    assert "Backoff Level Applied" in fields
    assert "Next Ban Duration" in fields
    assert "Timestamp" in fields


@settings(max_examples=200)
@given(
    rate=st.floats(min_value=0.1, max_value=1000.0, allow_nan=False, allow_infinity=False),
    mean=st.floats(min_value=1.0, max_value=100.0, allow_nan=False, allow_infinity=False),
    stddev=st.floats(min_value=0.0, max_value=20.0, allow_nan=False, allow_infinity=False),
)
def test_property15_global_anomaly_alert_contains_all_required_fields(
    rate, mean, stddev
):
    """
    Property 15c: Global anomaly alert payload contains rate, mean, stddev,
    and timestamp.
    """
    notifier, _ = _make_notifier()
    captured = {}

    def fake_post(url, json=None, timeout=None):
        captured["payload"] = json
        resp = MagicMock()
        resp.status_code = 200
        return resp

    with patch("detector.notifier.requests.post", side_effect=fake_post):
        notifier.send_global_anomaly_alert(rate, mean, stddev)

    assert "payload" in captured
    fields = _extract_fields_from_payload(captured["payload"])
    assert "Global Rate" in fields
    assert "Baseline Mean" in fields
    assert "Baseline Stddev" in fields
    assert "Timestamp" in fields


# ---------------------------------------------------------------------------
# Sub-task 10.2 — Property 16: Slack webhook retry count never exceeds 3
# Feature: ddos-anomaly-detection-engine, Property 16:
#   For any webhook POST that fails, _post() attempts the request at most
#   3 times total, then writes exactly one failure entry to the audit log.
# ---------------------------------------------------------------------------

@settings(max_examples=200, deadline=None)
@given(
    failure_mode=st.sampled_from(["http_error", "network_error"]),
    status_code=st.integers(min_value=400, max_value=599),
)
def test_property16_retry_count_never_exceeds_3(failure_mode, status_code):
    """
    Property 16: _post() makes at most 3 attempts and writes exactly one
    audit ERROR entry after all retries are exhausted.
    """
    notifier, audit_log = _make_notifier()

    call_count = {"n": 0}

    def fake_post(url, json=None, timeout=None):
        call_count["n"] += 1
        if failure_mode == "network_error":
            raise requests.ConnectionError("connection refused")
        resp = MagicMock()
        resp.status_code = status_code
        resp.text = "error"
        return resp

    with patch("detector.notifier.requests.post", side_effect=fake_post):
        with patch("detector.notifier.time.sleep"):  # skip actual delays
            result = notifier._post({"text": "test"}, context="test")

    assert result is False
    assert call_count["n"] == 3, (
        f"Expected exactly 3 attempts, got {call_count['n']}"
    )
    # Exactly one audit ERROR entry written
    assert audit_log.error.call_count == 1


# ---------------------------------------------------------------------------
# Unit tests — _post() success path
# ---------------------------------------------------------------------------

class TestPost:
    def test_returns_true_on_200(self):
        notifier, _ = _make_notifier()
        with _mock_post_success():
            result = notifier._post({"text": "hello"})
        assert result is True

    def test_posts_to_configured_webhook_url(self):
        url = "https://hooks.slack.com/services/T/B/MYWEBHOOK"
        notifier, _ = _make_notifier(webhook_url=url)
        with _mock_post_success() as mock_post:
            notifier._post({"text": "hello"})
        mock_post.assert_called_once()
        assert mock_post.call_args[0][0] == url

    def test_stops_retrying_on_first_success(self):
        notifier, _ = _make_notifier()
        call_count = {"n": 0}

        def fake_post(url, json=None, timeout=None):
            call_count["n"] += 1
            resp = MagicMock()
            resp.status_code = 200
            return resp

        with patch("detector.notifier.requests.post", side_effect=fake_post):
            notifier._post({"text": "hello"})

        assert call_count["n"] == 1

    def test_no_audit_log_does_not_raise_on_failure(self):
        from detector.config import Config
        from detector.notifier import Notifier

        cfg = Config(slack_webhook_url="https://hooks.slack.com/x")
        notifier = Notifier(cfg, audit_log=None)

        with _mock_post_failure():
            with patch("detector.notifier.time.sleep"):
                result = notifier._post({"text": "hello"})
        assert result is False  # should not raise


# ---------------------------------------------------------------------------
# Unit tests — webhook URL comes from config
# ---------------------------------------------------------------------------

class TestWebhookUrl:
    def test_webhook_url_from_config(self):
        url = "https://hooks.slack.com/services/CUSTOM/URL"
        notifier, _ = _make_notifier(webhook_url=url)
        assert notifier._webhook_url == url

    def test_different_configs_use_different_urls(self):
        from detector.config import Config
        from detector.notifier import Notifier

        url_a = "https://hooks.slack.com/services/A"
        url_b = "https://hooks.slack.com/services/B"
        n_a = Notifier(Config(slack_webhook_url=url_a))
        n_b = Notifier(Config(slack_webhook_url=url_b))
        assert n_a._webhook_url != n_b._webhook_url
