"""
main.py — Daemon orchestrator and supervisor loop.

Entry point for the DDoS Anomaly Detection Engine.  Responsibilities:
  1. Load and validate config.yaml (exits with code 1 on invalid config).
  2. Instantiate all shared data structures (SharedState + AuditLog).
  3. Wire subsystem dependencies: Notifier → Blocker → Detector,
     Notifier → Unbanner.
  4. Start all subsystem threads as daemon threads.
  5. Run a supervisor loop that monitors thread liveness every 5 seconds,
     restarts any dead thread, and logs the restart to the audit log.
  6. Handle SIGTERM / SIGINT for clean shutdown.

Thread startup order:
  LogTailer → BaselineCalculator → Detector → Unbanner → Dashboard (Flask)

All threads are daemon threads so they die automatically when main exits.
The supervisor loop in the main thread keeps the process alive.
"""

import os
import signal
import sys
import threading
import time
from typing import List, Tuple

from detector.audit_log import AuditLog
from detector.baseline import BaselineCalculator
from detector.blocker import Blocker
from detector.config import load_config
from detector.dashboard import create_app
from detector.detector import Detector
from detector.models import SharedState
from detector.monitor import LogTailer
from detector.notifier import Notifier
from detector.unbanner import Unbanner

# How often the supervisor checks thread liveness (seconds)
_SUPERVISOR_INTERVAL = 5

# Global shutdown flag — set by signal handlers
_shutdown = threading.Event()


def _handle_signal(signum, frame):
    """Signal handler for SIGTERM and SIGINT — triggers clean shutdown."""
    _shutdown.set()


def start_all_threads(
    shared: SharedState,
    blocker: Blocker,
    notifier: Notifier,
) -> List[Tuple[str, threading.Thread, callable]]:
    """
    Instantiate all subsystems and start them as daemon threads.

    Returns a list of (name, thread, factory_fn) tuples so the supervisor
    can restart dead threads by calling factory_fn() to get a fresh target.
    """
    def _make_tailer():
        t = LogTailer(shared)
        return threading.Thread(target=t.run, name="LogTailer", daemon=True)

    def _make_baseline():
        b = BaselineCalculator(shared)
        return threading.Thread(target=b.run, name="BaselineCalculator", daemon=True)

    def _make_detector():
        d = Detector(shared, blocker, notifier)
        return threading.Thread(target=d.run, name="Detector", daemon=True)

    def _make_unbanner():
        u = Unbanner(shared, notifier)
        return threading.Thread(target=u.run, name="Unbanner", daemon=True)

    def _make_dashboard():
        app = create_app(shared)
        port = shared.config.dashboard_port
        return threading.Thread(
            target=lambda: app.run(
                host="0.0.0.0",
                port=port,
                threaded=True,
                use_reloader=False,
            ),
            name="Dashboard",
            daemon=True,
        )

    factories = [
        ("LogTailer", _make_tailer),
        ("BaselineCalculator", _make_baseline),
        ("Detector", _make_detector),
        ("Unbanner", _make_unbanner),
        ("Dashboard", _make_dashboard),
    ]

    threads = []
    for name, factory in factories:
        t = factory()
        t.start()
        threads.append((name, t, factory))

    return threads


def supervise(
    threads: List[Tuple[str, threading.Thread, callable]],
    shared: SharedState,
) -> None:
    """
    Supervisor loop — runs in the main thread until _shutdown is set.

    Every _SUPERVISOR_INTERVAL seconds:
      - Check each thread's liveness via .is_alive().
      - If a thread has died, log an ERROR entry and restart it using
        the stored factory function.
    """
    while not _shutdown.is_set():
        time.sleep(_SUPERVISOR_INTERVAL)
        for i, (name, thread, factory) in enumerate(threads):
            if not thread.is_alive():
                if shared.audit_log:
                    shared.audit_log.error(
                        "supervisor",
                        f"Thread '{name}' died unexpectedly — restarting",
                    )
                new_thread = factory()
                new_thread.start()
                threads[i] = (name, new_thread, factory)


def main():
    """
    Main entry point.  Loads config, wires all subsystems, starts threads,
    and runs the supervisor loop until SIGTERM/SIGINT.
    """
    # Register signal handlers
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    # 1. Load config
    config_path = os.environ.get("DETECTOR_CONFIG", "config.yaml")
    config = load_config(config_path)

    # 2. Instantiate shared state + audit log
    shared = SharedState(config=config)
    shared.audit_log = AuditLog(config.audit_log_path)

    # 3. Wire subsystem dependencies
    notifier = Notifier(config, shared.audit_log)
    blocker = Blocker(shared, notifier)

    # 4 & 5. Start threads and supervise
    threads = start_all_threads(shared, blocker, notifier)
    supervise(threads, shared)

    # Clean shutdown
    if shared.audit_log:
        shared.audit_log.error("supervisor", "Daemon shutting down (signal received)")
    sys.exit(0)


if __name__ == "__main__":
    main()
