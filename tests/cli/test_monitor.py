import json
import pytest


def test_monitor_once_scans_and_records_stopped_health(tmp_path):
    from custodian.monitor import run_monitor
    class Engine:
        called = 0
        def settings(self): return {'interval_seconds': 10}
        def scan(self):
            self.called += 1
            return {'complete': True, 'files_checked': 1}
    engine = Engine()
    run_monitor(engine, tmp_path, once=True)
    assert engine.called == 1
    health = json.loads((tmp_path / 'monitor.json').read_text())
    assert health['running'] is False
    assert health['last_result']['complete'] is True
    assert (tmp_path / 'monitor.json').stat().st_mode & 0o777 == 0o600


def test_duplicate_monitor_is_rejected(tmp_path):
    import fcntl
    from custodian.monitor import run_monitor
    class Engine:
        def settings(self): return {'interval_seconds': 10}
    with (tmp_path / 'monitor.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(RuntimeError, match='already running'):
            run_monitor(Engine(), tmp_path, once=True)


def test_monitor_rereads_interval_each_cycle_and_enforces_minimum(tmp_path, monkeypatch):
    import custodian.monitor as monitor_mod
    from custodian.monitor import run_monitor

    now = [1000.0]
    waits = []
    monkeypatch.setattr(monitor_mod.time, 'monotonic', lambda: now[0])

    class FakeStop:
        def __init__(self):
            self.stopped = False

        def is_set(self):
            return self.stopped

        def set(self):
            self.stopped = True

        def wait(self, seconds):
            waits.append(seconds)
            now[0] += seconds

    class Engine:
        intervals = [120, 25, 3]
        scans = 0

        def settings(self):
            idx = min(self.scans, len(self.intervals) - 1)
            return {'interval_seconds': self.intervals[idx]}

        def scan(self):
            self.scans += 1
            if self.scans >= 3:
                stop.set()
            return {'complete': True, 'files_checked': 1}

    stop = FakeStop()
    engine = Engine()
    run_monitor(engine, tmp_path, once=False, stop_event=stop)
    assert engine.scans == 3
    # Cycle 1 after scan 1 uses updated interval 25s (5 x 5s heartbeats);
    # Cycle 2 after scan 2 clamps 3s to the 10s minimum (2 x 5s heartbeats).
    assert waits == [5, 5, 5, 5, 5, 5, 5]

