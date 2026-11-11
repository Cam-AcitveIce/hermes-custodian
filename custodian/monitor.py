"""One unprivileged monitor per state directory. No model calls, no web server."""
from __future__ import annotations
import fcntl
import json
import os
from pathlib import Path
import signal
import tempfile
import threading
import time


def run_monitor(engine, state_dir: Path, once=False, stop_event=None):
    settings = engine.settings()
    interval = max(10, int(settings.get('interval_seconds', 60)))
    state_dir = Path(state_dir)
    if state_dir.is_symlink():
        raise ValueError('State directory must not be a symlink')
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    if state_dir.stat().st_uid != os.getuid():
        raise ValueError('State directory must belong to the current user')
    os.chmod(state_dir, 0o700)
    lock_fd = os.open(state_dir / 'monitor.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
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
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError('A monitor is already running for this state directory') from exc
        if threading.current_thread() is threading.main_thread():
            for sig in (signal.SIGTERM, signal.SIGINT):
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
        os.close(lock_fd)
