"""
notifier.py — Slack alert sender.

Sends structured HTTP POST requests to a Slack incoming webhook URL for
three event types:
  - Ban:            an IP was blocked by iptables
  - Unban:          an IP was released from a ban
  - Global anomaly: the global request rate spiked (no block, alert only)

All payloads use Slack Block Kit for readable formatting.

Retry behaviour:
  - Up to 3 attempts per event (configurable via MAX_RETRIES).
  - 1-second delay between attempts.
  - After all retries are exhausted, exactly one ERROR entry is written
    to the audit log and the method returns without raising.

Design notes:
  - The webhook URL is read exclusively from Config; never hardcoded.
  - The Notifier does not run its own thread; it is called synchronously
    from Blocker and Unbanner threads.
  - requests.post is used directly — no rate-limiting library.
"""

import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional

import requests

if TYPE_CHECKING:
    from detector.audit_log import AuditLog
    from detector.config import Config

MAX_RETRIES = 3
RETRY_DELAY = 1  # seconds between retries


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Notifier:
    """
    Sends Slack alerts for ban, unban, and global anomaly events.
    """

    def __init__(self, config: "Config", audit_log: Optional["AuditLog"] = None) -> None:
        self._webhook_url = config.slack_webhook_url
        self._audit_log = audit_log

    # ------------------------------------------------------------------
    # Public alert methods
    # ------------------------------------------------------------------

    def send_ban_alert(
        self,
        ip: str,
        condition: str,
        rate: float,
        mean: float,
        stddev: float,
        duration: str,
    ) -> None:
        """
        Send a Slack alert when an IP is banned.

        Required fields: condition, current rate, baseline mean/stddev,
        UTC timestamp, ban duration.
        """
        ts = _utcnow_iso()
        payload = {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "🚨 IP Banned",
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*IP:*\n`{ip}`"},
                        {"type": "mrkdwn", "text": f"*Condition:*\n{condition}"},
                        {"type": "mrkdwn", "text": f"*Current Rate:*\n{rate:.1f} req/s"},
                        {"type": "mrkdwn", "text": f"*Baseline Mean:*\n{mean:.2f} req/s"},
                        {"type": "mrkdwn", "text": f"*Baseline Stddev:*\n{stddev:.2f}"},
                        {"type": "mrkdwn", "text": f"*Ban Duration:*\n{duration}"},
                        {"type": "mrkdwn", "text": f"*Timestamp:*\n{ts}"},
                    ],
                },
            ]
        }
        self._post(payload, context=f"ban alert for {ip}")

    def send_unban_alert(
        self,
        ip: str,
        backoff_level: int,
        next_duration: str,
    ) -> None:
        """
        Send a Slack alert when an IP is unbanned.

        Required fields: source IP, backoff level applied, UTC timestamp,
        next ban duration if re-banned.
        """
        ts = _utcnow_iso()
        payload = {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "✅ IP Unbanned",
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*IP:*\n`{ip}`"},
                        {"type": "mrkdwn", "text": f"*Backoff Level Applied:*\n{backoff_level}"},
                        {"type": "mrkdwn", "text": f"*Next Ban Duration:*\n{next_duration}"},
                        {"type": "mrkdwn", "text": f"*Timestamp:*\n{ts}"},
                    ],
                },
            ]
        }
        self._post(payload, context=f"unban alert for {ip}")

    def send_global_anomaly_alert(
        self,
        rate: float,
        mean: float,
        stddev: float,
    ) -> None:
        """
        Send a Slack alert when the global request rate is anomalous.
        No IP block is applied — alert only.

        Required fields: global rate, baseline mean/stddev, UTC timestamp.
        """
        ts = _utcnow_iso()
        payload = {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "⚠️ Global Traffic Spike Detected",
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Global Rate:*\n{rate:.1f} req/s"},
                        {"type": "mrkdwn", "text": f"*Baseline Mean:*\n{mean:.2f} req/s"},
                        {"type": "mrkdwn", "text": f"*Baseline Stddev:*\n{stddev:.2f}"},
                        {"type": "mrkdwn", "text": f"*Timestamp:*\n{ts}"},
                    ],
                },
            ]
        }
        self._post(payload, context="global anomaly alert")

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _post(self, payload: dict, context: str = "", retries: int = MAX_RETRIES) -> bool:
        """
        POST *payload* as JSON to the Slack webhook URL.

        Retries up to *retries* times (default MAX_RETRIES = 3) with a
        1-second delay between attempts.  After all retries are exhausted,
        writes exactly one ERROR entry to the audit log and returns False.

        Returns True on the first successful (2xx) response.
        """
        last_error = ""
        for attempt in range(1, retries + 1):
            try:
                resp = requests.post(
                    self._webhook_url,
                    json=payload,
                    timeout=5,
                )
                if resp.status_code == 200:
                    return True
                last_error = f"HTTP {resp.status_code}: {resp.text[:200]}"
            except requests.RequestException as exc:
                last_error = str(exc)

            if attempt < retries:
                time.sleep(RETRY_DELAY)

        # All retries exhausted — log exactly one error entry
        if self._audit_log:
            self._audit_log.error(
                "notifier",
                f"Slack POST failed after {retries} attempts ({context}): {last_error}",
            )
        return False
