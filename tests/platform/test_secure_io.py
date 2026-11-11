"""Secure I/O contracts: adversarial Win32 adapters and native filesystem checks."""
from contextlib import contextmanager
import os
from pathlib import Path
import stat
import sys

import pytest

from custodian import _platform
from custodian._platform import posix, windows


class FakeWin:
    def __init__(self):
        self.nodes = {'root': self.info_value(directory=True)}
        self.contents = {}
        self.positions = {}
        self.closed = []
        self.events = []
        self.security = {'owner': 'me', 'dacl': []}
        self.fail_write = False
        self.fail_replace = False

    @staticmethod
    def info_value(directory=False, reparse=False, size=0, links=1):
        return windows.FileInfo(0x400 if reparse else 0,
                                stat.S_IFDIR if directory else stat.S_IFREG,
                                1, 2, links, size, 0)

    def add(self, name, data=b'x', **kwargs):
        self.nodes[name] = self.info_value(size=len(data), **kwargs)
        self.contents[name] = data

    def info(self, handle):
        return self.nodes[handle]

    def current_user_sid(self):
        return 'me'

    def get_dacl_entries(self, handle):
        return self.security

    def set_private_dacl(self, handle, is_dir, me):
        self.events.append('restrict')
        self.security = {'owner': me, 'dacl': []}

    def open_child(self, parent, name, mode):
        assert parent == 'root'
        windows._component(name)
        if name not in self.nodes:
            raise FileNotFoundError(name)
        self.positions[name] = 0
        self.events.append(('open', name, mode))
        return name

    def read(self, handle, count):
        self.events.append(('read', count))
        start = self.positions.get(handle, 0)
        self.positions[handle] = start + count
        return self.contents[handle][start:start + count]

    def list_names(self, handle, limit):
        self.events.append(('list', limit))
        return [n for n in self.nodes if n != 'root'][:limit]

    def close(self, handle):
        self.closed.append(handle)

    def create_atomic(self, parent, name):
        assert parent == 'root'
        self.add(name, b'')
        return name

    def write(self, handle, data):
        self.events.append('write')
        if self.fail_write:
            raise OSError('write failed')
        self.contents[handle] += data[:2]
        return min(2, len(data))

    def flush(self, handle):
        self.events.append('flush')

    def replace(self, handle, parent, name):
        self.events.append('replace')
        if self.fail_replace:
            raise OSError('replace failed')
        self.contents[name] = self.contents.pop(handle)
        self.nodes.pop(handle)

    def discard(self, handle):
        self.events.append('discard')
        self.nodes.pop(handle)
        self.contents.pop(handle)


@pytest.fixture
def fake(monkeypatch):
    win = FakeWin()
    @contextmanager
    def directory(path):
        yield windows._IODirectory(win, 'root')
    monkeypatch.setattr(windows, 'open_directory_nofollow', directory)
    return win


@pytest.mark.parametrize('kwargs', [dict(reparse=True), dict(directory=True), dict(links=2)])
def test_windows_private_unsafe_before_read(fake, kwargs):
    fake.add('key', **kwargs)
    with pytest.raises(ValueError):
        windows.read_private_file('/key', max_bytes=10)
    assert not any(isinstance(e, tuple) and e[0] == 'read' for e in fake.events)
    assert fake.closed == ['key']


@pytest.mark.parametrize('mask', [windows.GENERIC_READ, windows.GENERIC_WRITE])
def test_windows_private_acl_rejected_without_repair(fake, mask):
    fake.add('key')
    fake.security['dacl'] = [dict(type='allow', sid=windows.SID_EVERYONE, mask=mask)]
    with pytest.raises(ValueError):
        windows.read_private_file('/key', max_bytes=10)
    assert 'restrict' not in fake.events
    assert not any(isinstance(e, tuple) and e[0] == 'read' for e in fake.events)
    assert windows.read_file_nofollow('/key', max_bytes=10) == b'x'


def test_windows_growth_and_pre_read_bound(fake):
    fake.add('key', b'12345')
    with pytest.raises(ValueError):
        windows.read_file_nofollow('/key', max_bytes=4)
    assert not any(isinstance(e, tuple) and e[0] == 'read' for e in fake.events)
    fake.nodes['key'] = fake.info_value(size=0)
    with pytest.raises(ValueError):
        windows.read_file_nofollow('/key', max_bytes=4)
    assert ('read', 5) in fake.events
    assert fake.closed == ['key', 'key']


@pytest.mark.parametrize('failure', [None, 'fail_write', 'fail_replace'])
def test_windows_atomic_privacy_partial_write_cleanup(fake, failure):
    if failure:
        setattr(fake, failure, True)
        with pytest.raises(OSError):
            windows.atomic_write_private_file('/key', b'abcdef')
        assert 'discard' in fake.events
        assert list(fake.nodes) == ['root']
    else:
        windows.atomic_write_private_file('/key', b'abcdef')
        assert fake.contents['key'] == b'abcdef'
        assert fake.events.index('restrict') < fake.events.index('write')
        assert fake.events.index('flush') < fake.events.index('replace')
    assert len(fake.closed) == 1


def test_windows_directory_budget_names_and_reparse(fake):
    fake.add('public')
    fake.add('directory', directory=True)
    fake.add('junction', directory=True, reparse=True)
    directory = windows._IODirectory(fake, 'root')
    assert directory.directory_names(limit=3) == [None, 'directory', None]
    assert ('list', 3) in fake.events
    with pytest.raises(ValueError):
        with directory.open_directory('junction'):
            pytest.fail('reparse directory entered')
    for name in ('../escape', 'a/b', 'stream:ads', '..', '\\escape'):
        with pytest.raises(ValueError):
            directory.read_file(name, max_bytes=1)
    directory.handle = None
    with pytest.raises(ValueError):
        directory.directory_names(limit=1)


def test_windows_pins_and_cleanup_on_reparse(monkeypatch):
    win = FakeWin()
    win.open_path = lambda path, mode: 'root'
    win.add('unsafe', directory=True, reparse=True)
    monkeypatch.setattr(windows, '_WIN', win)
    with pytest.raises(ValueError):
        with windows.open_directory_nofollow(Path('/unsafe')):
            pytest.fail('entered reparse')
    assert win.closed == ['unsafe', 'root']


@pytest.mark.skipif(os.name == 'nt', reason='native POSIX descriptors')
def test_native_posix_private_atomic_and_public(tmp_path):
    key = tmp_path / 'key'
    posix.atomic_write_private_file(key, b'first')
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    assert posix.read_private_file(key, max_bytes=5) == b'first'
    posix.atomic_write_private_file(key, b'next')
    assert posix.read_private_file(key, max_bytes=4) == b'next'
    key.chmod(0o644)
    with pytest.raises(ValueError):
        posix.read_private_file(key, max_bytes=4)
    assert posix.read_file_nofollow(key, max_bytes=4) == b'next'
    assert key.stat().st_mode & 0o077 == 0o044
    with pytest.raises(ValueError):
        posix.read_file_nofollow(key, max_bytes=3)
    os.link(key, tmp_path / 'hardlink')
    key.chmod(0o600)
    with pytest.raises(ValueError):
        posix.read_private_file(key, max_bytes=4)
    assert sorted(p.name for p in tmp_path.iterdir()) == ['hardlink', 'key']


@pytest.mark.skipif(os.name == 'nt', reason='native POSIX descriptors')
def test_native_posix_capability_pinned_and_closed(tmp_path):
    root = tmp_path / 'root'
    root.mkdir()
    (root / 'data').write_bytes(b'original')
    (root / 'child').mkdir()
    (tmp_path / 'link').symlink_to(root, target_is_directory=True)
    with pytest.raises(OSError):
        posix.read_file_nofollow(tmp_path / 'link' / 'data', max_bytes=20)
    with posix.open_directory_nofollow(root) as directory:
        assert len(directory.directory_names(limit=1)) == 1
        root.rename(tmp_path / 'moved')
        root.mkdir()
        (root / 'data').write_bytes(b'attacker')
        assert directory.read_file('data', max_bytes=20) == b'original'
        for name in ('../data', '/data', 'a/b'):
            with pytest.raises(ValueError):
                directory.read_file(name, max_bytes=20)
        with directory.open_directory('child') as child:
            assert child.directory_names(limit=10) == []
        with pytest.raises(ValueError):
            child.directory_names(limit=1)
    with pytest.raises(ValueError):
        directory.read_file('data', max_bytes=20)


@pytest.mark.skipif(os.name == 'nt', reason='native POSIX descriptors')
def test_native_posix_atomic_failure_and_symlink_replace(tmp_path, monkeypatch):
    path = tmp_path / 'key'
    outside = tmp_path / 'outside'
    outside.write_bytes(b'untouched')
    path.symlink_to(outside)
    posix.atomic_write_private_file(path, b'private')
    assert not path.is_symlink()
    assert outside.read_bytes() == b'untouched'
    def fail(*args, **kwargs):
        raise OSError('injected replacement failure')
    monkeypatch.setattr(posix.os, 'replace', fail)
    with pytest.raises(OSError):
        posix.atomic_write_private_file(path, b'failed')
    assert path.read_bytes() == b'private'
    assert sorted(p.name for p in tmp_path.iterdir()) == ['key', 'outside']


@pytest.mark.skipif(sys.platform != 'win32', reason='requires native Win32 handles and ACLs')
def test_native_windows_secure_io(tmp_path):
    path = tmp_path / 'key'
    windows.atomic_write_private_file(path, b'first')
    assert windows.read_private_file(path, max_bytes=5) == b'first'
    windows.atomic_write_private_file(path, b'second')
    assert windows.read_private_file(path, max_bytes=6) == b'second'
    with pytest.raises(ValueError):
        windows.read_file_nofollow(path, max_bytes=5)
    with windows.open_directory_nofollow(tmp_path) as directory:
        assert directory.read_file('key', max_bytes=6) == b'second'
        assert directory.directory_names(limit=1) == [None]
    with pytest.raises(ValueError):
        directory.directory_names(limit=1)


def test_seam_exports():
    for name in ('read_private_file', 'read_file_nofollow', 'atomic_write_private_file',
                 'open_directory_nofollow'):
        assert callable(getattr(_platform, name))


@pytest.mark.skipif(os.name == 'nt', reason='native POSIX special files')
def test_native_posix_child_links_fifo_and_write_failure(tmp_path, monkeypatch):
    (tmp_path / 'file').write_bytes(b'public')
    (tmp_path / 'link').symlink_to(tmp_path / 'file')
    os.mkfifo(tmp_path / 'fifo')
    with posix.open_directory_nofollow(tmp_path) as directory:
        for name in ('link', 'fifo'):
            with pytest.raises((OSError, ValueError)):
                directory.read_file(name, max_bytes=10)
    def fail(*args):
        raise OSError('injected write failure')
    monkeypatch.setattr(posix.os, 'write', fail)
    with pytest.raises(OSError):
        posix.atomic_write_private_file(tmp_path / 'key', b'private')
    assert sorted(p.name for p in tmp_path.iterdir()) == ['fifo', 'file', 'link']


@pytest.mark.parametrize('backend', [posix, windows])
def test_invalid_limits_fail_before_access(backend):
    for limit in (-1, True, 1.5, None):
        with pytest.raises(ValueError):
            backend.read_file_nofollow('/missing', max_bytes=limit)


@pytest.mark.skipif(sys.platform != 'win32', reason='requires native Windows symlink support')
def test_native_windows_reparse_rejected(tmp_path):
    target = tmp_path / 'target'
    target.mkdir()
    (target / 'data').write_bytes(b'public')
    link = tmp_path / 'link'
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f'native symlink creation unavailable: {exc}')
    with pytest.raises((OSError, ValueError)):
        windows.read_file_nofollow(link / 'data', max_bytes=10)
    with windows.open_directory_nofollow(tmp_path) as directory:
        with pytest.raises((OSError, ValueError)):
            with directory.open_directory('link'):
                pytest.fail('reparse child entered')
