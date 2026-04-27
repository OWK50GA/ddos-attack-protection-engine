"""
config.py — Config dataclass and YAML loader.

All tunable parameters live here. load_config() is the single entry point;
it exits with code 1 if any required field is missing or empty.
"""

import sys
from dataclasses import dataclass, field

import yaml
import os


@dataclass
class Config:
    # Required — no default; load_config() enforces presence
    slack_webhook_url: str

    # Detection thresholds
    zscore_threshold: float = 3.0
    rate_multiplier: float = 5.0
    error_rate_multiplier: float = 3.0

    # Window sizes
    sliding_window_seconds: int = 60
    baseline_window_minutes: int = 30
    baseline_recalc_interval_seconds: int = 60

    # Infrastructure
    dashboard_port: int = 5000
    log_file_path: str = "/var/log/nginx/hng-access.log"
    audit_log_path: str = "/var/log/detector/audit.log"


def load_config(path: str) -> Config:
    """
    Load config.yaml from *path* and return a Config instance.

    Exits with code 1 (writing to stderr) if:
      - The file cannot be read
      - slack_webhook_url is absent or empty
    Invalid numeric types fall back to their dataclass defaults with a warning.
    """
    try:
        with open(path, "r") as fh:
            raw = yaml.safe_load(fh) or {}
    except FileNotFoundError:
        print(f"ERROR: config file not found: {path}", file=sys.stderr)
        sys.exit(1)
    except yaml.YAMLError as exc:
        print(f"ERROR: failed to parse config YAML: {exc}", file=sys.stderr)
        sys.exit(1)

    # Validate required field
    # webhook = raw.get("slack_webhook_url", "")
    # if not webhook or not str(webhook).strip():
    #     print(
    #         "ERROR: 'slack_webhook_url' is required in config.yaml but is missing or empty.",
    #         file=sys.stderr,
    #     )
    #     sys.exit(1)
    webhook = os.environ.get("SLACK_WEBHOOK_URL") or raw.get("slack_webhook_url", "")
    if not webhook or not str(webhook).strip() or "REPLACE" in str(webhook):
        print(
            "ERROR: 'slack_webhook_url' is missing. Set SLACK_WEBHOOK_URL in .env or config.yaml.",
            file=sys.stderr,
        )
        sys.exit(1)

    def _get(key: str, default, cast):
        """Return raw[key] cast to *cast*, or *default* on type error."""
        val = raw.get(key, default)
        try:
            return cast(val)
        except (TypeError, ValueError):
            print(
                f"WARNING: invalid value for '{key}' ({val!r}); using default {default!r}",
                file=sys.stderr,
            )
            return default

    return Config(
        slack_webhook_url=str(webhook).strip(),
        zscore_threshold=_get("zscore_threshold", 3.0, float),
        rate_multiplier=_get("rate_multiplier", 5.0, float),
        error_rate_multiplier=_get("error_rate_multiplier", 3.0, float),
        sliding_window_seconds=_get("sliding_window_seconds", 60, int),
        baseline_window_minutes=_get("baseline_window_minutes", 30, int),
        baseline_recalc_interval_seconds=_get(
            "baseline_recalc_interval_seconds", 60, int
        ),
        dashboard_port=_get("dashboard_port", 5000, int),
        log_file_path=_get("log_file_path", "/var/log/nginx/hng-access.log", str),
        audit_log_path=_get("audit_log_path", "/var/log/detector/audit.log", str),
    )
