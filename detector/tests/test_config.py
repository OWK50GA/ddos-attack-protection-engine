"""
test_config.py — Unit and property-based tests for config.py.

Sub-task 1.1: Property 19 — Missing required config causes non-zero exit
Sub-task 1.2: Unit tests for config loading (valid, missing keys, invalid types, defaults)
"""

import sys
import tempfile
import textwrap
from unittest.mock import patch

import pytest
import yaml
from hypothesis import given, settings
from hypothesis import strategies as st

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_yaml(tmp_path, data: dict) -> str:
    """Write *data* as YAML to a temp file and return the path."""
    p = tmp_path / "config.yaml"
    p.write_text(yaml.dump(data))
    return str(p)


# ---------------------------------------------------------------------------
# Sub-task 1.1 — Property 19: Missing required config causes non-zero exit
# Feature: ddos-anomaly-detection-engine, Property 19:
#   For any config.yaml missing slack_webhook_url (or containing it as empty),
#   load_config() should raise SystemExit with a non-zero exit code and write
#   a descriptive message to stderr.
# ---------------------------------------------------------------------------

@settings(max_examples=200)
@given(
    # Generate arbitrary dicts that either lack the key entirely or have
    # an empty / whitespace-only value.
    missing_or_empty=st.one_of(
        # Key absent: generate a dict without slack_webhook_url
        st.fixed_dictionaries({}),
        # Key present but empty string
        st.just({"slack_webhook_url": ""}),
        # Key present but whitespace only
        st.just({"slack_webhook_url": "   "}),
        # Key present but None
        st.just({"slack_webhook_url": None}),
    )
)
def test_property19_missing_webhook_causes_system_exit(missing_or_empty):
    """Property 19: any config without a valid slack_webhook_url exits non-zero."""
    import os
    from detector.config import load_config

    # Use tempfile directly — tmp_path is function-scoped and incompatible
    # with Hypothesis's repeated invocation model.
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False
    ) as fh:
        yaml.dump(missing_or_empty, fh)
        path = fh.name

    try:
        with pytest.raises(SystemExit) as exc_info:
            load_config(path)
        assert exc_info.value.code != 0, (
            f"Expected non-zero exit code, got {exc_info.value.code}"
        )
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# Sub-task 1.2 — Unit tests for config loading
# ---------------------------------------------------------------------------

class TestLoadConfigValid:
    def test_all_fields_loaded(self, tmp_path):
        """A fully specified config.yaml populates every Config field."""
        from detector.config import load_config

        data = {
            "slack_webhook_url": "https://hooks.slack.com/services/T/B/X",
            "zscore_threshold": 2.5,
            "rate_multiplier": 4.0,
            "error_rate_multiplier": 2.0,
            "sliding_window_seconds": 30,
            "baseline_window_minutes": 15,
            "baseline_recalc_interval_seconds": 45,
            "dashboard_port": 8080,
            "log_file_path": "/tmp/access.log",
            "audit_log_path": "/tmp/audit.log",
        }
        cfg = load_config(_write_yaml(tmp_path, data))

        assert cfg.slack_webhook_url == "https://hooks.slack.com/services/T/B/X"
        assert cfg.zscore_threshold == 2.5
        assert cfg.rate_multiplier == 4.0
        assert cfg.error_rate_multiplier == 2.0
        assert cfg.sliding_window_seconds == 30
        assert cfg.baseline_window_minutes == 15
        assert cfg.baseline_recalc_interval_seconds == 45
        assert cfg.dashboard_port == 8080
        assert cfg.log_file_path == "/tmp/access.log"
        assert cfg.audit_log_path == "/tmp/audit.log"

    def test_defaults_applied_for_optional_fields(self, tmp_path):
        """Only slack_webhook_url provided — all other fields use defaults."""
        from detector.config import Config, load_config

        data = {"slack_webhook_url": "https://hooks.slack.com/services/T/B/X"}
        cfg = load_config(_write_yaml(tmp_path, data))

        defaults = Config(slack_webhook_url="x")
        assert cfg.zscore_threshold == defaults.zscore_threshold
        assert cfg.rate_multiplier == defaults.rate_multiplier
        assert cfg.error_rate_multiplier == defaults.error_rate_multiplier
        assert cfg.sliding_window_seconds == defaults.sliding_window_seconds
        assert cfg.baseline_window_minutes == defaults.baseline_window_minutes
        assert cfg.dashboard_port == defaults.dashboard_port

    def test_webhook_url_is_stripped(self, tmp_path):
        """Leading/trailing whitespace in the webhook URL is stripped."""
        from detector.config import load_config

        data = {"slack_webhook_url": "  https://hooks.slack.com/services/T/B/X  "}
        cfg = load_config(_write_yaml(tmp_path, data))
        assert cfg.slack_webhook_url == "https://hooks.slack.com/services/T/B/X"


class TestLoadConfigMissingRequired:
    def test_missing_webhook_exits_1(self, tmp_path):
        """Config without slack_webhook_url exits with code 1."""
        from detector.config import load_config

        path = _write_yaml(tmp_path, {"zscore_threshold": 3.0})
        with pytest.raises(SystemExit) as exc_info:
            load_config(path)
        assert exc_info.value.code == 1

    def test_empty_webhook_exits_1(self, tmp_path):
        """Config with empty slack_webhook_url exits with code 1."""
        from detector.config import load_config

        path = _write_yaml(tmp_path, {"slack_webhook_url": ""})
        with pytest.raises(SystemExit) as exc_info:
            load_config(path)
        assert exc_info.value.code == 1

    def test_missing_file_exits_1(self, tmp_path):
        """Non-existent config file exits with code 1."""
        from detector.config import load_config

        with pytest.raises(SystemExit) as exc_info:
            load_config(str(tmp_path / "nonexistent.yaml"))
        assert exc_info.value.code == 1

    def test_invalid_yaml_exits_1(self, tmp_path):
        """Malformed YAML exits with code 1."""
        from detector.config import load_config

        p = tmp_path / "bad.yaml"
        p.write_text("key: [unclosed bracket")
        with pytest.raises(SystemExit) as exc_info:
            load_config(str(p))
        assert exc_info.value.code == 1


class TestLoadConfigInvalidTypes:
    def test_invalid_float_uses_default(self, tmp_path, capsys):
        """A non-numeric zscore_threshold falls back to the default (3.0)."""
        from detector.config import load_config

        data = {
            "slack_webhook_url": "https://hooks.slack.com/services/T/B/X",
            "zscore_threshold": "not-a-number",
        }
        cfg = load_config(_write_yaml(tmp_path, data))
        assert cfg.zscore_threshold == 3.0
        captured = capsys.readouterr()
        assert "WARNING" in captured.err

    def test_invalid_int_uses_default(self, tmp_path, capsys):
        """A non-integer dashboard_port falls back to the default (5000)."""
        from detector.config import load_config

        data = {
            "slack_webhook_url": "https://hooks.slack.com/services/T/B/X",
            "dashboard_port": "eighty-eighty",
        }
        cfg = load_config(_write_yaml(tmp_path, data))
        assert cfg.dashboard_port == 5000
        captured = capsys.readouterr()
        assert "WARNING" in captured.err
