"""One unprivileged monitor per state directory. No model calls, no web server."""
from __future__ import annotations
import json
import os
from pathlib import Path
import signal
import tempfile
import threading
import time

from . import _platform


def run_monitor(engine, state_dir: Path, once=False, stop_event=None):
    settings = engine.settings()
    interval = max(10, int(settings.get('interval_seconds', 60)))
    state_dir = Path(state_dir)
    _platform.ensure_private_dir(state_dir)
    lock_fd = _platform.open_private_file(state_dir / 'monitor.lock', write=True, create=True)
    stop = stop_event or threading.Event()
    previous_signals = {}
    health = {'pid': os.getpid(), 'running': True, 'started_at': time.time(), 'last_result': None, 'error': None}

    def publish():
        health['heartbeat_at'] = time.time()
        fd, name = tempfile.mkstemp(prefix='.monitor-', dir=state_dir)
        try:
            with os.fdopen(fd, 'w') as stream:
                json.dump(health, stream, ensure_ascii=True)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, state_dir / 'monitor.json')
        finally:
            if os.path.exists(name):
                os.unlink(name)

    try:
        if not _platform.try_lock_exclusive(lock_fd):
            raise RuntimeError('A monitor is already running for this state directory')
        if threading.current_thread() is threading.main_thread():
            for sig in _platform.terminate_signals():
                previous_signals[sig] = signal.getsignal(sig)
                signal.signal(sig, lambda *_: stop.set())
        try:
            while not stop.is_set():
                health['running'] = True
                publish()
                try:
                    result = engine.scan()
                    health['last_result'] = {key: result.get(key) for key in ('scan_id', 'complete', 'files_checked', 'finished_at')}
                    health['error'] = None
                except Exception as exc:
                    health['error'] = type(exc).__name__ + ': monitoring cycle failed'
                publish()
                if once:
                    break
                try:
                    interval = max(10, int(engine.settings().get('interval_seconds', 60)))
                except Exception:
                    pass
                # Heartbeat remains fresh between expensive reconciliations.
                deadline = time.monotonic() + interval
                while not stop.is_set() and time.monotonic() < deadline:
                    stop.wait(min(5, max(0, deadline - time.monotonic())))
                    publish()
        finally:
            health['running'] = False
            publish()
    finally:
        for sig, previous in previous_signals.items():
            signal.signal(sig, previous)
        _platform.unlock(lock_fd)
        os.close(lock_fd)
