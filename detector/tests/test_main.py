"""
test_main.py — Tests for main.py (orchestrator and supervisor loop).

Sub-task 12.1: Unit tests for supervisor thread liveness monitoring.
  - A dead thread is detected and restarted within one supervisor cycle.
  - Restart is logged to the audit log.
  - Live threads are not restarted.

Additional unit tests cover:
  - start_all_threads() starts the expected number of threads
  - All started threads are alive immediately after start_all_threads()
  - SIGTERM sets the shutdown event (tested via _handle_signal directly)
  - main() exits with code 1 when config is invalid (missing webhook URL)
"""

import signal
import sys
import threading
import time
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_shared():
    from detector.config import Config
    from detector.models import SharedState

    cfg = Config(slack_webhook_url="https://hooks.slack.com/x")
    shared = SharedState(config=cfg)
    shared.audit_log = MagicMock()
    return shared


def _make_blocker_notifier(shared):
    from detector.blocker import Blocker
    from detector.notifier import Notifier

    notifier = Notifier(shared.config, shared.audit_log)
    blocker = Blocker(shared, notifier)
    return blocker, notifier


# ---------------------------------------------------------------------------
# Sub-task 12.1 — Supervisor thread liveness monitoring
# ---------------------------------------------------------------------------

class TestSupervisor:
    def test_dead_thread_is_restarted(self):
        """
        A thread that has died (.is_alive() == False) must be restarted
        within one supervisor cycle.
        """
        from detector.main import supervise, _shutdown

        shared = _make_shared()
        _shutdown.clear()

        # Create a thread that exits immediately
        dead_thread = threading.Thread(target=lambda: None, daemon=True)
        dead_thread.start()
        dead_thread.join()  # ensure it's dead
        assert not dead_thread.is_alive()

        restart_count = {"n": 0}

        def factory():
            restart_count["n"] += 1
            # Return a thread that stays alive long enough for the test
            t = threading.Thread(target=lambda: time.sleep(10), daemon=True)
            return t

        threads = [("TestThread", dead_thread, factory)]

        # Run one supervisor cycle then shut down
        def run_supervisor():
            supervise(threads, shared)

        _shutdown.clear()
        sup_thread = threading.Thread(target=run_supervisor, daemon=True)
        sup_thread.start()

        # Wait for one cycle (supervisor sleeps 5s, give it 7s)
        time.sleep(7)
        _shutdown.set()
        sup_thread.join(timeout=3)

        assert restart_count["n"] >= 1, "Dead thread was not restarted"

    def test_restart_logged_to_audit_log(self):
        """
        When a dead thread is restarted, an ERROR entry is written to
        the audit log.
        """
        from detector.main import supervise, _shutdown

        shared = _make_shared()
        _shutdown.clear()

        dead_thread = threading.Thread(target=lambda: None, daemon=True)
        dead_thread.start()
        dead_thread.join()

        def factory():
            t = threading.Thread(target=lambda: time.sleep(10), daemon=True)
            return t

        threads = [("DeadSubsystem", dead_thread, factory)]

        def run_supervisor():
            supervise(threads, shared)

        _shutdown.clear()
        sup_thread = threading.Thread(target=run_supervisor, daemon=True)
        sup_thread.start()

        time.sleep(7)
        _shutdown.set()
        sup_thread.join(timeout=3)

        shared.audit_log.error.assert_called()
        call_args = shared.audit_log.error.call_args_list
        assert any("DeadSubsystem" in str(c) for c in call_args), (
            "Audit log error entry did not mention the dead thread name"
        )

    def test_live_thread_not_restarted(self):
        """
        A thread that is still alive must not be restarted.
        """
        from detector.main import supervise, _shutdown

        shared = _make_shared()
        _shutdown.clear()

        restart_count = {"n": 0}

        def factory():
            restart_count["n"] += 1
            t = threading.Thread(target=lambda: time.sleep(10), daemon=True)
            return t

        # Start a thread that stays alive
        live_thread = threading.Thread(target=lambda: time.sleep(30), daemon=True)
        live_thread.start()
        assert live_thread.is_alive()

        threads = [("LiveThread", live_thread, factory)]

        def run_supervisor():
            supervise(threads, shared)

        _shutdown.clear()
        sup_thread = threading.Thread(target=run_supervisor, daemon=True)
        sup_thread.start()

        time.sleep(7)
        _shutdown.set()
        sup_thread.join(timeout=3)

        assert restart_count["n"] == 0, (
            f"Live thread was incorrectly restarted {restart_count['n']} time(s)"
        )


# ---------------------------------------------------------------------------
# Unit tests — start_all_threads()
# ---------------------------------------------------------------------------

class TestStartAllThreads:
    def test_starts_five_threads(self):
        from detector.main import start_all_threads

        shared = _make_shared()
        blocker, notifier = _make_blocker_notifier(shared)

        # Patch Flask app.run to avoid actually binding a port
        with patch("detector.main.create_app") as mock_create_app:
            mock_app = MagicMock()
            mock_app.run = MagicMock()
            mock_create_app.return_value = mock_app

            threads = start_all_threads(shared, blocker, notifier)

        assert len(threads) == 5, f"Expected 5 threads, got {len(threads)}"

    def test_all_threads_alive_after_start(self):
        from detector.main import start_all_threads

        shared = _make_shared()
        blocker, notifier = _make_blocker_notifier(shared)

        with patch("detector.main.create_app") as mock_create_app:
            mock_app = MagicMock()
            # Make app.run block so the Dashboard thread stays alive
            mock_app.run = MagicMock(side_effect=lambda **kw: time.sleep(30))
            mock_create_app.return_value = mock_app

            threads = start_all_threads(shared, blocker, notifier)

        # Give threads a moment to start
        time.sleep(0.2)
        for name, thread, _ in threads:
            assert thread.is_alive(), f"Thread '{name}' is not alive after start"

    def test_thread_names_are_correct(self):
        from detector.main import start_all_threads

        shared = _make_shared()
        blocker, notifier = _make_blocker_notifier(shared)

        with patch("detector.main.create_app") as mock_create_app:
            mock_app = MagicMock()
            mock_app.run = MagicMock()
            mock_create_app.return_value = mock_app

            threads = start_all_threads(shared, blocker, notifier)

        names = {name for name, _, _ in threads}
        expected = {"LogTailer", "BaselineCalculator", "Detector", "Unbanner", "Dashboard"}
        assert names == expected


# ---------------------------------------------------------------------------
# Unit tests — signal handling
# ---------------------------------------------------------------------------

class TestSignalHandling:
    def test_handle_signal_sets_shutdown_event(self):
        from detector.main import _handle_signal, _shutdown

        _shutdown.clear()
        assert not _shutdown.is_set()
        _handle_signal(signal.SIGTERM, None)
        assert _shutdown.is_set()
        _shutdown.clear()  # reset for other tests


# ---------------------------------------------------------------------------
# Unit tests — main() config validation
# ---------------------------------------------------------------------------

class TestMainConfigValidation:
    def test_main_exits_on_missing_webhook(self, tmp_path):
        """main() must exit with code 1 when slack_webhook_url is missing."""
        import yaml
        from detector.main import main

        cfg_path = str(tmp_path / "config.yaml")
        with open(cfg_path, "w") as f:
            yaml.dump({"zscore_threshold": 3.0}, f)

        with patch.dict("os.environ", {"DETECTOR_CONFIG": cfg_path}):
            with pytest.raises(SystemExit) as exc_info:
                main()
        assert exc_info.value.code == 1
