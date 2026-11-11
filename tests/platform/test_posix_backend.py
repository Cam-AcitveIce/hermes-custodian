from contextlib import contextmanager
import errno
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import threading
import time
import pytest

# Gate before importing the POSIX backend or its optional OS modules.
if os.name == 'nt':
    pytest.skip('native POSIX backend contracts', allow_module_level=True)

from custodian._platform import posix


def test_current_principal():
    assert posix.current_principal() == str(os.getuid())


def test_owner_of(tmp_path):
    target = tmp_path / 'target.txt'
    target.write_text('content')
    assert posix.owner_of(target) == str(os.getuid())

    fd = os.open(target, os.O_RDONLY)
    try:
        assert posix.owner_of(fd) == str(os.getuid())
    finally:
        os.close(fd)

    # Symlink must not follow target for owner_of
    link = tmp_path / 'link.txt'
    link.symlink_to(target)
    assert posix.owner_of(link) == str(os.lstat(link).st_uid)


def test_ensure_private_dir(tmp_path):
    p = tmp_path / 'private_dir'
    posix.ensure_private_dir(p)
    assert p.is_dir()
    assert p.stat().st_mode & 0o777 == 0o700

    # Idempotent
    posix.ensure_private_dir(p)

    # Refuse symlink
    link = tmp_path / 'link_dir'
    link.symlink_to(p)
    with pytest.raises(ValueError, match='symlink'):
        posix.ensure_private_dir(link)


def test_ensure_private_file(tmp_path):
    p = tmp_path / 'private.txt'
    p.write_text('safe')
    p.chmod(0o644)
    posix.ensure_private_file(p)
    assert p.stat().st_mode & 0o777 == 0o600


def test_open_private_file_create_and_read(tmp_path):
    p = tmp_path / 'new_private.txt'
    fd = posix.open_private_file(p, write=True, create=True)
    try:
        os.write(fd, b'hello')
    finally:
        os.close(fd)

    assert p.stat().st_mode & 0o777 == 0o600

    # Read existing
    rfd = posix.open_private_file(p, write=False, create=False, max_bytes=100)
    try:
        data = os.read(rfd, 100)
        assert data == b'hello'
    finally:
        os.close(rfd)


def test_open_private_file_refusals(tmp_path, monkeypatch):
    # 1. Symlink refusal
    real = tmp_path / 'real.txt'
    real.write_text('real')
    link = tmp_path / 'symlink.txt'
    link.symlink_to(real)
    with pytest.raises(ValueError, match='symlink'):
        posix.open_private_file(link, write=False, create=False)

    # 2. Hard link refusal
    hard = tmp_path / 'hard.txt'
    os.link(real, hard)
    with pytest.raises(ValueError, match='hard-linked'):
        posix.open_private_file(real, write=False, create=False)

    # 3. Non-regular / FIFO refusal
    fifo = tmp_path / 'test.fifo'
    try:
        os.mkfifo(fifo)
        with pytest.raises(ValueError, match='regular file'):
            posix.open_private_file(fifo, write=False, create=False)
    except OSError:
        pass  # If filesystem does not support mkfifo

    # 4. Wrong owner refusal via fake fstat
    dummy = tmp_path / 'dummy.txt'
    dummy.write_text('test')
    real_fstat = os.fstat

    class FakeStat:
        def __init__(self, orig):
            self.orig = orig
            self.st_mode = orig.st_mode
            self.st_uid = 99999  # wrong owner
            self.st_nlink = orig.st_nlink
            self.st_size = orig.st_size

    def fake_fstat(fd):
        orig = real_fstat(fd)
        return FakeStat(orig)

    monkeypatch.setattr(os, 'fstat', fake_fstat)
    with pytest.raises(ValueError, match='owned by the current user'):
        posix.open_private_file(dummy, write=False, create=False)


def test_open_private_file_size_limit(tmp_path):
    p = tmp_path / 'large.txt'
    p.write_bytes(b'x' * 100)
    with pytest.raises(ValueError, match='exceeds size limit'):
        posix.open_private_file(p, write=False, create=False, max_bytes=50)


def test_validate_state_root(tmp_path):
    state_dir = tmp_path / 'state'
    posix.validate_state_root(state_dir)
    assert state_dir.is_dir()
    assert state_dir.stat().st_mode & 0o777 == 0o700

    # Refuse root or home
    with pytest.raises(ValueError, match='dedicated state directory'):
        posix.validate_state_root(Path('/'))
    with pytest.raises(ValueError, match='dedicated state directory'):
        posix.validate_state_root(Path.home())

    # Refuse traversal
    with pytest.raises(ValueError, match='traversal'):
        posix.validate_state_root(Path(str(state_dir) + '/../other'))


def test_fsync_directory(tmp_path):
    posix.fsync_directory(tmp_path)


def test_interprocess_lock(tmp_path):
    lock_file = tmp_path / 'test.lock'
    with posix.interprocess_lock(lock_file, timeout=1.0):
        # Already locked: trying to lock in same thread / same fd region
        fd = posix.open_private_file(lock_file, write=True, create=False)
        try:
            assert posix.try_lock_exclusive(fd) is False
        finally:
            os.close(fd)


def test_interprocess_lock_timeout(tmp_path):
    lock_file = tmp_path / 'timeout.lock'
    fd = posix.open_private_file(lock_file, write=True, create=True)
    assert posix.try_lock_exclusive(fd) is True
    try:
        started = time.monotonic()
        with pytest.raises(TimeoutError, match='in progress'):
            with posix.interprocess_lock(lock_file, timeout=0.1):
                pass
        assert time.monotonic() - started >= 0.08
    finally:
        posix.unlock(fd)
        os.close(fd)


def test_process_is_running_as_current_user_linux(monkeypatch):
    # Current process is running as current user
    assert posix.process_is_running_as_current_user(os.getpid()) is True
    # Non-existent PID
    assert posix.process_is_running_as_current_user(2147483647) is False
    # Invalid PID
    assert posix.process_is_running_as_current_user(-1) is False
    assert posix.process_is_running_as_current_user(0) is False


def test_process_is_running_as_current_user_macos_branch(monkeypatch):
    import custodian._platform.posix as pmod
    monkeypatch.setattr(pmod, 'NAME', 'macos')

    class FakeCompletedProcess:
        def __init__(self, stdout, returncode=0):
            self.stdout = stdout
            self.returncode = returncode

    # Success case: ps outputs current UID
    def fake_runner_ok(args, **kwargs):
        assert args == ['ps', '-o', 'uid=', '-p', str(os.getpid())]
        assert kwargs.get('timeout') == 5.0
        return FakeCompletedProcess(f'{os.getuid()}\n')

    monkeypatch.setattr(pmod, '_ps_runner', fake_runner_ok)
    assert pmod.process_is_running_as_current_user(os.getpid()) is True

    # Different UID case
    def fake_runner_diff_uid(args, **kwargs):
        return FakeCompletedProcess('9999\n')

    monkeypatch.setattr(pmod, '_ps_runner', fake_runner_diff_uid)
    assert pmod.process_is_running_as_current_user(os.getpid()) is False

    # Process not found / nonzero returncode
    def fake_runner_err(args, **kwargs):
        return FakeCompletedProcess('', returncode=1)

    monkeypatch.setattr(pmod, '_ps_runner', fake_runner_err)
    assert pmod.process_is_running_as_current_user(os.getpid()) is False

    # Timeout
    def fake_runner_timeout(args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args, timeout=5.0)

    monkeypatch.setattr(pmod, '_ps_runner', fake_runner_timeout)
    assert pmod.process_is_running_as_current_user(os.getpid()) is False


def test_terminate_signals():
    import signal
    sigs = posix.terminate_signals()
    assert signal.SIGTERM in sigs
    assert signal.SIGINT in sigs
    assert signal.SIGHUP in sigs


def test_default_state_dir(monkeypatch, tmp_path):
    # 1. HERMES_HOME wins
    monkeypatch.setenv('HERMES_HOME', str(tmp_path / 'hermes'))
    assert posix.default_state_dir() == tmp_path / 'hermes' / 'plugin-data' / 'hermes-custodian'

    monkeypatch.delenv('HERMES_HOME', raising=False)

    # 2. Linux XDG_STATE_HOME
    monkeypatch.setenv('XDG_STATE_HOME', str(tmp_path / 'xdg'))
    monkeypatch.setattr(posix, 'NAME', 'linux')
    assert posix.default_state_dir() == tmp_path / 'xdg' / 'hermes-custodian'

    monkeypatch.delenv('XDG_STATE_HOME', raising=False)

    # 3. macOS
    monkeypatch.setattr(posix, 'NAME', 'macos')
    assert posix.default_state_dir() == Path.home() / 'Library' / 'Application Support' / 'hermes-custodian'


def test_access_exposure():
    # Private mode
    assert posix.access_exposure({'mode': 0o600}) is None
    assert posix.access_exposure({'mode': 0o700}) is None

    # Group readable
    res1 = posix.access_exposure({'mode': 0o640})
    assert res1 is not None
    assert res1['severity'] == 'high'
    assert res1['mode'] == 0o640
    assert 'summary' in res1

    # World readable
    res2 = posix.access_exposure({'mode': 0o644})
    assert res2 is not None
    assert res2['severity'] == 'high'
    assert res2['mode'] == 0o644


def test_bounded_snapshot(tmp_path):
    (tmp_path / 'file.py').write_text('print("hello")')
    (tmp_path / 'doc.md').write_text('# Title')
    (tmp_path / 'ignored.txt').write_text('text')

    res = posix.bounded_snapshot(tmp_path, exclusions=['*.txt'], max_files=10, max_file_bytes=1024)
    assert res['complete'] is True
    assert res['errors'] == []
    paths = {f['path'] for f in res['files']}
    assert str(tmp_path / 'file.py') in paths
    assert str(tmp_path / 'doc.md') in paths
    assert str(tmp_path / 'ignored.txt') not in paths

    # SHA256 hashed for .py and .md
    for f in res['files']:
        if f['path'].endswith('.py') or f['path'].endswith('.md'):
            assert 'sha256' in f
