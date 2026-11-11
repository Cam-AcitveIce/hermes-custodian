"""Portable contract tests; these do not exercise Win32 ACLs."""
import json
from unittest.mock import Mock

import pytest
from custodian import web, _platform


def server(tmp_path):
    obj = object.__new__(web.CustodianDashboardServer)
    obj.state_dir = tmp_path
    obj.session_key_path = tmp_path / 'dashboard-session-key.json'
    return obj


def test_windows_key_reader_requires_secure_operation(monkeypatch, tmp_path):
    monkeypatch.setattr(_platform, 'IS_WINDOWS', True)
    monkeypatch.delattr(_platform, 'read_private_file', raising=False)
    obj = server(tmp_path)
    obj.session_key_path.write_text('{}')
    with pytest.raises(OSError, match='secure platform operation'):
        obj._read_key_record_unlocked()


def test_windows_key_operations_delegate(monkeypatch, tmp_path):
    monkeypatch.setattr(_platform, 'IS_WINDOWS', True)
    record = json.dumps(dict(schema_version=1, signing_key='ab' * 32, epoch='cd' * 16)).encode()
    read = Mock(return_value=record)
    write = Mock()
    monkeypatch.setattr(_platform, 'read_private_file', read, raising=False)
    monkeypatch.setattr(_platform, 'atomic_write_private_file', write, raising=False)
    sync = Mock()
    monkeypatch.setattr(_platform, 'fsync_directory', sync)
    obj = server(tmp_path)
    assert obj._read_key_record_unlocked() == (bytes.fromhex('ab' * 32), 'cd' * 16)
    obj._write_key_record_unlocked('ab' * 32, 'cd' * 16)
    read.assert_called_once_with(obj.session_key_path, max_bytes=4096)
    assert write.call_args.args[0] == obj.session_key_path
    assert json.loads(write.call_args.args[1]) == json.loads(record)
    sync.assert_called_once_with(tmp_path)


def test_windows_asset_reader_requires_secure_operation(monkeypatch, tmp_path):
    monkeypatch.setattr(_platform, 'IS_WINDOWS', True)
    monkeypatch.delattr(_platform, 'read_file_nofollow', raising=False)
    with pytest.raises(OSError):
        web._read_static_asset(tmp_path / 'index.html')


def test_asset_bound_and_symlink(tmp_path):
    asset = tmp_path / 'index.html'
    asset.write_bytes(b'x' * (1048576 + 1))
    with pytest.raises(ValueError):
        web._read_static_asset(asset)
    link = tmp_path / 'link'
    try:
        link.symlink_to(asset)
    except OSError:
        pytest.skip('symlink creation unavailable')
    with pytest.raises((OSError, ValueError)):
        web._read_static_asset(link)


def test_windows_unsafe_key_is_not_replaced(monkeypatch, tmp_path):
    import threading
    monkeypatch.setattr(_platform, 'IS_WINDOWS', True)
    read = Mock(side_effect=ValueError('unsafe ACL'))
    write = Mock()
    monkeypatch.setattr(_platform, 'read_private_file', read, raising=False)
    monkeypatch.setattr(_platform, 'atomic_write_private_file', write, raising=False)
    obj = server(tmp_path)
    obj._lock = threading.Lock()
    with pytest.raises(ValueError, match='unsafe ACL'):
        obj._load_or_create_key_and_epoch()
    write.assert_not_called()


def test_windows_missing_key_writer_refuses(monkeypatch, tmp_path):
    monkeypatch.setattr(_platform, 'IS_WINDOWS', True)
    monkeypatch.delattr(_platform, 'atomic_write_private_file', raising=False)
    with pytest.raises(OSError, match='secure platform operation'):
        server(tmp_path)._write_key_record_unlocked('ab' * 32, 'cd' * 16)
    assert not list(tmp_path.iterdir())


def test_windows_asset_delegation_and_growth_bound(monkeypatch, tmp_path):
    monkeypatch.setattr(_platform, 'IS_WINDOWS', True)
    reader = Mock(return_value=b'asset')
    monkeypatch.setattr(_platform, 'read_file_nofollow', reader, raising=False)
    path = tmp_path / 'index.html'
    assert web._read_static_asset(path) == b'asset'
    reader.assert_called_once_with(path, max_bytes=1048576)
    reader.return_value = b'x' * 1048577
    with pytest.raises(ValueError):
        web._read_static_asset(path)


@pytest.mark.skipif(_platform.IS_WINDOWS, reason='POSIX fixture permissions')
def test_posix_key_persistence_and_epoch_rotation(tmp_path):
    import threading
    obj = server(tmp_path)
    obj._lock = threading.Lock()
    first = obj._load_or_create_key_and_epoch()
    restarted = server(tmp_path)
    restarted._lock = threading.Lock()
    assert restarted._load_or_create_key_and_epoch() == first
    restarted._write_key_record_unlocked(first[0].hex(), 'ab' * 16)
    assert obj._read_key_record_unlocked() == (first[0], 'ab' * 16)


def test_windows_session_restart_refresh_logout_with_capabilities(monkeypatch, tmp_path):
    import threading
    from types import SimpleNamespace
    monkeypatch.setattr(_platform, 'IS_WINDOWS', True)
    records = {}
    def read(path, *, max_bytes):
        if path not in records:
            raise FileNotFoundError(path)
        return records[path]
    def write(path, raw):
        records[path] = raw
    monkeypatch.setattr(_platform, 'read_private_file', read, raising=False)
    monkeypatch.setattr(_platform, 'atomic_write_private_file', write, raising=False)
    monkeypatch.setattr(_platform, 'fsync_directory', Mock())
    now = [1000]
    def instance():
        obj = server(tmp_path)
        obj._lock = threading.Lock()
        obj._failed_logins = []
        obj.clock = lambda: now[0]
        obj.session_ttl_seconds = 100
        obj.absolute_session_seconds = 1000
        obj.auth = SimpleNamespace(revision=lambda: 'fixture-revision')
        return obj
    first = instance()
    token, age = first.create_session_cookie_value()
    assert age == 100
    restarted = instance()
    assert restarted.validate_session(token)
    now[0] += 50
    valid, refreshed, age = restarted.validate_and_refresh_session(token)
    assert valid and refreshed != token and age == 100
    restarted.revoke_session(refreshed)
    assert not first.validate_session(refreshed)
