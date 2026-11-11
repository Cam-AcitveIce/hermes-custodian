"""Windows backend tests. All but the last three run on any OS with a fake adapter."""
import hashlib
import inspect
import os
from pathlib import Path
import re
import signal
import stat
import sys
import time

import pytest

from custodian._platform import windows as W

ME = 'S-1-5-21-1-2-3-1001'
OTHER = 'S-1-5-21-1-2-3-1002'
FULL, MODIFY, READ, RX = 0x1F01FF, 0x1301BF, 0x120089, 0x1200A9
BASE = Path(os.path.abspath(os.sep)) / 'fake-vol'
DEFAULT = object()
GENERIC_ERROR = 'Filesystem entry unavailable, changed, or unsafe'
WINDOWS_ONLY = pytest.mark.skipif(sys.platform != 'win32', reason='exercises the real Win32 backend')


def ace(sid, mask, kind='allow', *, inherited=False, inherit_only=False):
    return {'type': kind, 'sid': sid, 'mask': mask, 'inherited': inherited, 'inherit_only': inherit_only}


def private_dacl(owner=ME):
    return [ace(owner, FULL), ace(W.SID_SYSTEM, FULL), ace(W.SID_ADMINISTRATORS, FULL)]


def make_info(kind='file', *, size=0, nlink=1, ino=1, mtime_ns=1000):
    attributes = {'file': 0x80, 'dir': 0x10, 'link': 0x400, 'junction': 0x410}[kind]
    mode = {'file': stat.S_IFREG, 'dir': stat.S_IFDIR, 'link': stat.S_IFLNK, 'junction': stat.S_IFDIR}[kind]
    return W.FileInfo(attributes, mode, 7, ino, nlink, size, mtime_ns)


class FakeWin:
    """In-memory stand-in for windows._Win; records every call."""

    def __init__(self):
        self.nodes, self.calls, self.fds = {}, [], {}
        self.fail_ops, self.locked, self.names, self.processes = set(), set(), {}, {}
        self.handle_info, self.after_scandir = {}, {}
        self._counter = 100
        self.hooks, self.denied, self.enforce_pins = {}, [], True

    def add(self, path, kind='file', data=b'', owner=ME, dacl=DEFAULT, nlink=1):
        path = str(path)
        parent = os.path.dirname(path)
        if parent != path:
            if parent not in self.nodes:
                self.add(parent, 'dir')
            self.nodes[parent]['children'].append(os.path.basename(path))
        self._counter += 1
        self.nodes[path] = {'info': make_info(kind, size=len(data), nlink=nlink, ino=self._counter),
                            'data': data, 'owner': owner, 'children': [], 'path': path,
                            'dacl': private_dacl(owner) if dacl is DEFAULT else dacl}
        return path

    def paths(self, op):
        return [call[1] for call in self.calls if call[0] == op]

    def _op(self, op, path, *extra):
        self.calls.append((op, path, *extra))
        if op in self.fail_ops:
            raise OSError(f'injected {op} failure')

    def _node(self, path):
        if path not in self.nodes:
            raise FileNotFoundError(path)
        return self.nodes[path]

    def stat_info(self, path):
        self._op('stat', path)
        return self._node(path)['info']

    def scandir_info(self, path, limit):
        self._op('scandir', path)
        names = list(self._node(path)['children'])[:limit]
        if path in self.after_scandir:
            self.nodes[path]['info'] = self.after_scandir[path]
        return names

    def make_dir(self, path):
        self._op('mkdir', path)
        if path in self.nodes:
            raise FileExistsError(path)
        self.add(path, 'dir', dacl=[ace(ME, FULL), ace(W.SID_USERS, MODIFY, inherited=True)])

    def create_file(self, path, *, write=False, create_new=False):
        self._op('open', path)
        if create_new:
            if path in self.nodes:
                raise FileExistsError(path)
            self.add(path, dacl=[ace(ME, FULL), ace(W.SID_USERS, READ, inherited=True)])
        self._node(path)
        self._counter += 1
        self.fds[self._counter] = {'path': path, 'pos': 0}
        return self._counter

    def get_file_information(self, fd):
        path = self.fds[fd]['path']
        return self.handle_info.get(path, self.nodes[path]['info'])

    def read(self, fd, count):
        handle = self.fds[fd]
        node = self.nodes[handle['path']]
        chunk = node['data'][handle['pos']:handle['pos'] + count]
        handle['pos'] += len(chunk)
        if node.get('mutate_on_read'):
            node['info'] = node['info']._replace(mtime_ns=node['info'].mtime_ns + 1)
        return chunk

    def close(self, fd):
        del self.fds[fd]

    def get_dacl_entries(self, target):
        path = self.fds[target]['path'] if isinstance(target, int) else target
        self._op('acl', path)
        node = self._node(path)
        return {'owner': node['owner'], 'dacl': node['dacl']}

    def set_private_dacl(self, path, is_dir, user_sid):
        self._op('private', path, is_dir)
        self._node(path)['dacl'] = [ace(user_sid, FULL), ace(W.SID_SYSTEM, FULL)]

    # --- handle-based adapter API. These definitions supersede the path-based
    # ones above (same class body); ops keep the legacy names in `calls`.
    def _op(self, op, path, *extra):
        self.calls.append((op, path, *extra))
        hook = self.hooks.pop((op, path), None)
        if hook:
            hook()
        if op in self.fail_ops:
            raise OSError(f'injected {op} failure')

    def _h(self, handle):
        entry = self.fds[handle]
        return entry.get('node') or self.nodes[entry['path']]

    def _new(self, node, mode):
        self._counter += 1
        self.fds[self._counter] = {'node': node, 'path': node['path'], 'pos': 0, 'mode': mode}
        return self._counter

    def swap(self, path, replacement):
        """Rebind a name to another object; refused while a pin/dir handle holds it."""
        current = self.nodes[str(path)]
        if self.enforce_pins and any(h.get('node') is current and h.get('mode') in ('pin', 'dir')
                                     for h in self.fds.values()):
            self.denied.append(str(path))
            raise PermissionError(str(path))
        self.nodes[str(path)] = self.nodes[str(replacement)]

    def open_path(self, path, mode='pin'):
        self._op('stat', path)
        return self._new(self._node(path), mode)

    def open_child(self, parent, name, mode):
        path = os.path.join(self._h(parent)['path'], name)
        self._op({'read': 'open', 'dir': 'opendir'}.get(mode, 'stat'), path)
        node = self._node(path)
        if mode in ('pin', 'dir') and not stat.S_ISDIR(node['info'].mode):
            raise NotADirectoryError(path)
        return self._new(node, mode)

    def open_file(self, parent, name, *, write=False, create_new=False):
        path = os.path.join(self._h(parent)['path'], name)
        self._op('file', path)
        if create_new:
            if path in self.nodes:
                raise FileExistsError(path)
            self.add(path, dacl=[ace(ME, FULL), ace(W.SID_USERS, READ, inherited=True)])
        return self._new(self._node(path), 'file')

    def make_dir(self, parent, name):
        path = os.path.join(self._h(parent)['path'], name)
        self._op('mkdir', path)
        if path in self.nodes:
            raise FileExistsError(path)
        self.add(path, 'dir', dacl=[ace(ME, FULL), ace(W.SID_USERS, MODIFY, inherited=True)])
        return self._new(self.nodes[path], 'pin')

    def info(self, handle):
        node = self._h(handle)
        if self.fds[handle].get('mode') == 'read' and node['path'] in self.handle_info:
            return self.handle_info[node['path']]
        return node['info']

    def list_names(self, handle, limit):
        node = self._h(handle)
        self._op('scandir', node['path'])
        names = list(node['children'])[:limit]
        if node['path'] in self.after_scandir:
            node['info'] = self.after_scandir[node['path']]
        return names

    def read(self, handle, count):
        node, entry = self._h(handle), self.fds[handle]
        self._op('read', node['path'])
        chunk = node['data'][entry['pos']:entry['pos'] + count]
        entry['pos'] += len(chunk)
        if node.get('mutate_on_read'):
            node['info'] = node['info']._replace(mtime_ns=node['info'].mtime_ns + 1)
        return chunk

    def get_dacl_entries(self, handle):
        node = self._h(handle)
        self._op('acl', node['path'])
        return {'owner': node['owner'], 'dacl': node['dacl']}

    def set_private_dacl(self, handle, is_dir, user_sid):
        node = self._h(handle)
        self._op('private', node['path'], is_dir)
        if not node.get('dacl_locked'):
            node['dacl'] = [ace(user_sid, FULL), ace(W.SID_SYSTEM, FULL)]

    def to_fd(self, handle, write):
        return handle

    def fd_handle(self, fd):
        return fd

    def close_fd(self, fd):
        del self.fds[fd]

    def lookup_sid(self, sid):
        self._op('lookup', sid)
        if sid not in self.names:
            raise OSError('no mapping')
        return self.names[sid]

    def current_user_sid(self):
        self._op('me', '')
        return ME

    def open_process_owner_sid(self, pid):
        self._op('process', pid)
        if pid not in self.processes:
            raise OSError('no such process')
        return self.processes[pid]

    def lock_region(self, fd):
        path = self.fds[fd]['path']
        if path in self.locked:
            return False
        self.locked.add(path)
        return True

    def unlock_region(self, fd):
        self.locked.discard(self.fds[fd]['path'])


@pytest.fixture
def fake(monkeypatch):
    adapter = FakeWin()
    monkeypatch.setattr(W, '_WIN', adapter)
    return adapter


def build_tree(fake):
    scope = BASE / 'scope'
    fake.add(scope, 'dir')
    fake.add(scope / 'a.py', data=b'print(1)\n')
    fake.add(scope / 'notes.md', data=b'# hi\n')
    fake.add(scope / 'data.bin', data=b'\x00' * 10)
    fake.add(scope / 'sub', 'dir')
    fake.add(scope / 'sub' / 'deep.py', data=b'x = 1\n')
    fake.add(scope / 'hard.py', data=b'linked\n', nlink=2)
    fake.add(scope / 'link.py', 'link')
    fake.add(scope / 'jn', 'junction')
    fake.add(scope / 'jn' / 'outside.py', data=b'never\n')
    fake.add(scope / '.env', data=b'KEY=1\n', dacl=[ace(ME, FULL), ace(W.SID_USERS, READ)])
    fake.add(scope / '.ssh', 'dir')
    fake.add(scope / '.ssh' / 'id_rsa', data=b'k')
    return scope


def by_name(result):
    return {Path(item['path']).name: item for item in result['files']}


# ------------------------------------------------------------ interface/import
def test_seam_interface_is_complete():
    assert W.NAME == 'windows' and W.IS_WINDOWS is True
    for name in ('current_principal', 'owner_of', 'ensure_private_dir', 'ensure_private_file',
                 'open_private_file', 'validate_state_root', 'fsync_directory', 'interprocess_lock',
                 'try_lock_exclusive', 'unlock', 'process_is_running_as_current_user',
                 'terminate_signals', 'default_state_dir', 'bounded_snapshot', 'access_exposure'):
        assert callable(getattr(W, name)), name
    assert (W.MAX_ENTRIES, W.MAX_SECONDS, W.MAX_DEPTH, W.MAX_TOTAL_BYTES) == (20000, 5.0, 64, 64 * 1024 * 1024)


def test_no_posix_only_or_windows_only_module_imported_at_top_level():
    source = inspect.getsource(W)
    assert not re.search(r'^(?:import|from)\s+(?:fcntl|grp|pwd|msvcrt|_winapi)\b', source, re.MULTILINE)
    assert 'O_NOFOLLOW' not in source and 'getuid' not in source


def test_default_state_dir_and_pure_helpers_never_touch_win32(monkeypatch):
    def forbidden():
        raise AssertionError('Win32 must not be touched')
    monkeypatch.setattr(W, '_api', forbidden)
    monkeypatch.setattr(W, '_WIN', None)
    monkeypatch.setenv('HERMES_HOME', str(BASE / 'hermes'))
    monkeypatch.setenv('LOCALAPPDATA', str(BASE / 'local'))
    assert W.default_state_dir() == BASE / 'hermes' / 'plugin-data' / 'hermes-custodian'
    monkeypatch.delenv('HERMES_HOME')
    assert W.default_state_dir() == BASE / 'local' / 'hermes-custodian'
    monkeypatch.delenv('LOCALAPPDATA')
    assert W.default_state_dir() == Path.home() / 'AppData' / 'Local' / 'hermes-custodian'
    assert W.fsync_directory(BASE) is None
    assert signal.SIGINT in W.terminate_signals()
    assert all(isinstance(item, signal.Signals) for item in W.terminate_signals())
    assert W.access_exposure({'mode': 0o600}) is None
    if sys.platform != 'win32':
        assert W._API is None


@pytest.mark.skipif(sys.platform == 'win32', reason='checks the non-Windows failure mode')
def test_real_adapter_fails_soft_off_windows(monkeypatch, tmp_path):
    monkeypatch.setattr(W, '_WIN', None)
    with pytest.raises(OSError):
        W._api()
    with pytest.raises(OSError):
        W.current_principal()
    assert W.process_is_running_as_current_user(os.getpid()) is False
    result = W.bounded_snapshot(tmp_path, [], 10, 1000)
    assert result == {'files': [], 'errors': [GENERIC_ERROR], 'complete': False}


# --------------------------------------------------------- DACL classification
def test_private_dacl_is_private_and_owner_system_admins_allowed():
    verdict = W.classify_dacl(ME, private_dacl())
    assert verdict == {'level': 'private', 'principals': []}
    assert W.synthetic_mode('private') == 0o600
    assert W.classify_dacl(ME, [])['level'] == 'private'      # empty DACL: owner only


@pytest.mark.parametrize('sid', [W.SID_EVERYONE, W.SID_USERS, W.SID_AUTHENTICATED_USERS])
@pytest.mark.parametrize('mask,level,mode', [(READ, 'read', 0o644), (RX, 'read', 0o644),
                                             (MODIFY, 'write', 0o666), (FULL, 'write', 0o666),
                                             (W.GENERIC_READ, 'read', 0o644), (W.GENERIC_ALL, 'write', 0o666),
                                             (W.GENERIC_WRITE, 'write', 0o666)])
def test_broad_principals_read_and_write(sid, mask, level, mode):
    verdict = W.classify_dacl(ME, private_dacl() + [ace(sid, mask)])
    assert verdict == {'level': level, 'principals': [sid]}
    assert W.synthetic_mode(verdict['level']) == mode


def test_deny_aces_only_help_when_they_precede_the_allow():
    users_read = ace(W.SID_USERS, READ)
    assert W.classify_dacl(ME, [ace(W.SID_USERS, FULL, 'deny'), users_read])['level'] == 'private'
    assert W.classify_dacl(ME, [users_read, ace(W.SID_USERS, FULL, 'deny')])['level'] == 'read'
    assert W.classify_dacl(ME, [ace(W.SID_EVERYONE, W.GENERIC_ALL, 'deny'), users_read])['level'] == 'private'
    assert W.classify_dacl(ME, [ace(W.SID_USERS, FULL, 'deny')])['level'] == 'private'
    partial = W.classify_dacl(ME, [ace(W.SID_USERS, 0x116, 'deny'), ace(W.SID_USERS, MODIFY)])
    assert partial['level'] == 'write'                         # DELETE survives the partial deny
    assert W.classify_dacl(ME, [ace(OTHER, FULL, 'deny'), users_read])['level'] == 'read'


def test_inherited_aces_count_and_inherit_only_aces_do_not():
    assert W.classify_dacl(ME, [ace(W.SID_USERS, READ, inherited=True)])['level'] == 'read'
    assert W.classify_dacl(ME, [ace(W.SID_USERS, FULL, inherit_only=True)])['level'] == 'private'


def test_unknown_sids_null_dacl_and_unparsed_aces_are_exposed():
    assert W.classify_dacl(ME, private_dacl() + [ace(OTHER, READ)]) == {'level': 'read', 'principals': [OTHER]}
    assert W.classify_dacl(ME, None) == {'level': 'write', 'principals': [W.SID_EVERYONE]}
    assert W.classify_dacl(ME, [ace('', 0, 'other')]) == {'level': 'write', 'principals': ['']}
    assert W.principal_name('') == 'unrecognised access rule'


def test_scanning_user_is_trusted_only_when_passed_and_writers_sort_first():
    dacl = [ace(ME, FULL), ace(W.SID_ADMINISTRATORS, FULL)]
    assert W.classify_dacl(W.SID_ADMINISTRATORS, dacl)['principals'] == [ME]
    assert W.classify_dacl(W.SID_ADMINISTRATORS, dacl, (ME,))['level'] == 'private'
    mixed = W.classify_dacl(ME, [ace(W.SID_USERS, READ), ace(OTHER, MODIFY)])
    assert mixed == {'level': 'write', 'principals': [OTHER, W.SID_USERS]}
    assert W.classify_dacl(W.SID_EVERYONE, [ace(W.SID_EVERYONE, READ)])['level'] == 'read'


def test_principal_names_are_fixed_looked_up_or_bounded_sid_fallback():
    def failing(sid):
        raise OSError('lookup failed')
    assert W.principal_name(W.SID_EVERYONE, failing) == 'Everyone'
    assert W.principal_name(W.SID_USERS) == 'BUILTIN\\Users'
    assert W.principal_name(OTHER, failing) == OTHER
    assert W.principal_name(OTHER, lambda sid: 'PC\\bob\x1b[31m\x07') == 'PC\\bob'
    assert W.principal_name(OTHER, lambda sid: '') == OTHER
    assert len(W.principal_name(OTHER, lambda sid: 'n' * 5000)) == W.MAX_NAME_CHARS


def test_access_exposure_synthetic_modes_and_severity():
    assert W.access_exposure({'type': 'file', 'mode': 0o600}) is None
    assert W.access_exposure({'type': 'symlink', 'mode': 0o777}) is None
    assert W.access_exposure('not a dict') is None
    broad = W.access_exposure({'type': 'file', 'mode': 0o644, 'exposed_to': ['Everyone']})
    assert broad['severity'] == 'high' and broad['mode'] == 0o644
    assert broad['exposed_to'] == ['Everyone'] and 'readable by: Everyone' in broad['summary']
    narrow = W.access_exposure({'type': 'file', 'mode': 0o644, 'exposed_to': ['PC\\bob\x1b[2J']})
    assert narrow['severity'] == 'medium' and narrow['exposed_to'] == ['PC\\bob']
    writable = W.access_exposure({'type': 'file', 'mode': 0o666, 'exposed_to': ['PC\\bob']})
    assert writable['severity'] == 'high' and 'writable by: PC\\bob' in writable['summary']
    unknown = W.access_exposure({'type': 'file', 'mode': 0o644})
    assert unknown['severity'] == 'high' and unknown['exposed_to'] == ['other principals']


# ------------------------------------------------------------ bounded_snapshot
def test_snapshot_schema_hashing_and_traversal_policy(fake):
    scope = build_tree(fake)
    result = W.bounded_snapshot(scope, [], 100, 1 << 20)
    assert result['complete'] is True and result['errors'] == []
    files = by_name(result)
    assert set(files) == {'a.py', 'notes.md', 'data.bin', 'deep.py', 'hard.py', 'link.py', 'jn', '.env', '.ssh'}
    for item in result['files']:
        assert set(item) - {'sha256', 'exposed_to'} == {'path', 'type', 'mode', 'uid', 'size', 'mtime_ns'}
    assert files['a.py']['sha256'] == hashlib.sha256(b'print(1)\n').hexdigest()
    assert files['deep.py']['sha256'] == hashlib.sha256(b'x = 1\n').hexdigest()
    assert files['notes.md']['sha256'] == hashlib.sha256(b'# hi\n').hexdigest()
    assert files['a.py'] | {'sha256': ''} == {'path': str(scope / 'a.py'), 'type': 'file', 'mode': 0o600,
                                              'uid': ME, 'size': 9, 'mtime_ns': 1000, 'sha256': ''}
    assert 'sha256' not in files['data.bin']
    # hard links are never hashed
    assert files['hard.py']['type'] == 'file' and 'sha256' not in files['hard.py']
    # reparse points: typed symlink, never traversed, never opened, ACL never resolved through them
    assert files['link.py']['type'] == 'symlink' and files['jn']['type'] == 'symlink'
    assert files['jn']['mode'] == 0 and files['jn']['uid'] == ''
    assert str(scope / 'jn') not in fake.paths('scandir') + fake.paths('acl')
    assert not any('outside.py' in str(call[1]) for call in fake.calls)
    # sensitive file: metadata only, exposure from the DACL
    assert 'sha256' not in files['.env'] and files['.env']['mode'] == 0o644
    assert files['.env']['exposed_to'] == ['BUILTIN\\Users'] and files['.env']['uid'] == ME
    assert W.access_exposure(files['.env'])['severity'] == 'high'
    # sensitive directory: recorded, never enumerated
    assert files['.ssh']['type'] == 'other' and str(scope / '.ssh') not in fake.paths('scandir')
    assert not any('id_rsa' in str(call[1]) for call in fake.calls)
    assert sorted(fake.paths('open')) == sorted(str(p) for p in (scope / 'a.py', scope / 'notes.md',
                                                                 scope / 'sub' / 'deep.py'))
    assert fake.fds == {}


def test_snapshot_exposed_to_uses_lookup_then_sid_fallback(fake):
    scope = BASE / 'scope'
    fake.add(scope / '.env', dacl=[ace(ME, FULL), ace(OTHER, MODIFY)])
    assert by_name(W.bounded_snapshot(scope, [], 10, 100))['.env']['exposed_to'] == [OTHER]
    fake.names[OTHER] = 'PC\\bob'
    item = by_name(W.bounded_snapshot(scope, [], 10, 100))['.env']
    assert item['exposed_to'] == ['PC\\bob'] and item['mode'] == 0o666


@pytest.mark.parametrize('constant,value,message', [
    ('MAX_ENTRIES', 2, 'Traversal entry budget exhausted'),
    ('MAX_DEPTH', 0, 'Directory depth budget exhausted'),
    ('MAX_TOTAL_BYTES', 3, 'Aggregate byte budget exhausted'),
    ('MAX_SECONDS', -1, 'Scan time budget exhausted')])
def test_snapshot_global_budgets(fake, monkeypatch, constant, value, message):
    scope = build_tree(fake)
    monkeypatch.setattr(W, constant, value)
    result = W.bounded_snapshot(scope, [], 100, 1 << 20)
    assert result['complete'] is False and result['errors'] == [message]
    assert fake.fds == {}


def test_snapshot_file_and_byte_budgets(fake):
    scope = build_tree(fake)
    limited = W.bounded_snapshot(scope, [], 2, 1 << 20)
    assert len(limited['files']) == 2 and limited['complete'] is False
    assert 'File budget exhausted' in limited['errors']
    small = W.bounded_snapshot(scope, [], 100, 6)
    files = by_name(small)
    assert small['complete'] is False and small['errors'] == ['File byte budget exceeded']
    assert 'sha256' not in files['a.py'] and 'sha256' in files['deep.py'] and 'sha256' in files['notes.md']


@pytest.mark.parametrize('args', [(0, 10), (10, 0), (True, 10), (10, 1.5)])
def test_snapshot_rejects_invalid_limits(fake, args):
    invalid = {'files': [], 'errors': ['Invalid scan scope or limits'], 'complete': False}
    assert W.bounded_snapshot(BASE, [], *args) == invalid
    assert W.bounded_snapshot(BASE / '..' / 'x', [], 10, 10) == invalid
    assert W.bounded_snapshot(BASE, ['x'] * 101, 10, 10) == invalid
    assert W.bounded_snapshot(BASE, [7], 10, 10) == invalid
    assert fake.calls == []


def test_snapshot_exclusions_are_case_insensitive(fake):
    scope = build_tree(fake)
    names = set(by_name(W.bounded_snapshot(scope, ['A.PY', 'SUB', str(scope / 'notes.md').upper()], 100, 1 << 20)))
    assert not names & {'a.py', 'deep.py', 'notes.md'} and 'hard.py' in names
    assert str(scope / 'sub') not in fake.paths('scandir')
    assert 'deep.py' not in by_name(W.bounded_snapshot(scope, ['SUB/DEEP.PY'], 100, 1 << 20))
    assert W.is_excluded(('Dir\\File.PY',), ['dir/*.py']) and not W.is_excluded(('a.txt',), ['*.py'])


@pytest.mark.parametrize('when', ['before', 'during'])
def test_snapshot_identity_recheck_failure_marks_incomplete(fake, when):
    scope = build_tree(fake)
    target = str(scope / 'a.py')
    if when == 'before':
        fake.handle_info[target] = fake.nodes[target]['info']._replace(ino=999999)
    else:
        fake.nodes[target]['mutate_on_read'] = True
    result = W.bounded_snapshot(scope, [], 100, 1 << 20)
    assert result['complete'] is False and result['errors'] == [GENERIC_ERROR]
    assert 'sha256' not in by_name(result).get('a.py', {})
    assert fake.fds == {}


def test_snapshot_directory_swapped_for_junction_is_not_trusted(fake):
    scope = build_tree(fake)
    sub = str(scope / 'sub')
    fake.after_scandir[sub] = make_info('junction', ino=fake.nodes[sub]['info'].ino)
    result = W.bounded_snapshot(scope, [], 100, 1 << 20)
    assert result['complete'] is False and result['errors'] == [GENERIC_ERROR]
    assert 'deep.py' not in by_name(result)


def test_snapshot_root_rules(fake):
    fake.add(BASE / 'jn', 'junction')
    fake.add(BASE / 'jn' / 'scope', 'dir')
    fake.add(BASE / 'jn' / 'scope' / 'a.py', data=b'1')
    through = W.bounded_snapshot(BASE / 'jn' / 'scope', [], 10, 100)
    assert through == {'files': [], 'errors': [GENERIC_ERROR], 'complete': False}
    assert W.bounded_snapshot(BASE / 'jn', [], 10, 100)['complete'] is False
    fake.add(BASE / '.ssh', 'dir')
    fake.add(BASE / '.ssh' / 'id_ed25519', data=b'k')
    sensitive = W.bounded_snapshot(BASE / '.ssh', [], 10, 100)
    assert sensitive['complete'] is True and [f['type'] for f in sensitive['files']] == ['other']
    assert fake.paths('scandir') == [] and fake.paths('open') == []


@pytest.mark.parametrize('op', ['stat', 'scandir', 'me', 'open'])
def test_snapshot_fails_soft_when_adapter_raises(fake, op):
    scope = build_tree(fake)
    fake.fail_ops.add(op)
    result = W.bounded_snapshot(scope, [], 100, 1 << 20)
    assert result['complete'] is False and result['errors'] == [GENERIC_ERROR]
    assert fake.fds == {}


def test_snapshot_acl_failure_degrades_without_claiming_exposure(fake):
    scope = build_tree(fake)
    fake.fail_ops.add('acl')
    result = W.bounded_snapshot(scope, [], 100, 1 << 20)
    assert result['complete'] is False and result['errors'] == ['Access control list unavailable']
    env = by_name(result)['.env']
    assert env['mode'] == 0o600 and env['uid'] == '' and 'exposed_to' not in env
    assert 'sha256' in by_name(result)['a.py']


# ----------------------------------------------------------------- state root
def dir_security(owner=ME, dacl=DEFAULT):
    return {'owner': owner, 'dacl': private_dacl(owner) if dacl is DEFAULT else dacl}


def test_state_root_rules_are_pure():
    folder = make_info('dir')
    check = W.state_root_violation
    assert check(folder, dir_security(), is_last=True, me=ME) is None
    assert check(folder, dir_security(W.SID_ADMINISTRATORS), is_last=True, me=ME) is None
    assert check(folder, dir_security(OTHER), is_last=True, me=ME) == 'state_dir owner must be the current user'
    assert check(folder, dir_security(W.SID_SYSTEM), is_last=True, me=ME) is not None
    for kind in ('junction', 'link', 'file'):
        assert 'nonsymlink' in check(make_info(kind), dir_security(), is_last=False, me=ME)
    for owner in (ME, W.SID_SYSTEM, W.SID_ADMINISTRATORS, W.SID_TRUSTED_INSTALLER):
        assert check(folder, dir_security(owner), is_last=False, me=ME) is None
    assert check(folder, dir_security(OTHER), is_last=False, me=ME) == \
        'state_dir ancestor owner must be the current user or root'
    writable = 'state_dir ancestor must not be writable by other users'
    for sid in (W.SID_EVERYONE, W.SID_USERS, W.SID_AUTHENTICATED_USERS):
        assert check(folder, dir_security(dacl=[ace(sid, MODIFY)]), is_last=False, me=ME) == writable
    assert check(folder, dir_security(dacl=None), is_last=False, me=ME) == writable
    # stock drive-root ACL: Users read, Authenticated Users create-folder + inherit-only modify
    stock = [ace(W.SID_USERS, RX), ace(W.SID_AUTHENTICATED_USERS, 0x4),
             ace(W.SID_AUTHENTICATED_USERS, MODIFY, inherit_only=True)]
    assert check(folder, dir_security(W.SID_TRUSTED_INSTALLER, stock), is_last=False, me=ME) is None


def test_validate_state_root_creates_missing_directories_private(fake):
    fake.add(BASE, 'dir')
    root = BASE / 'data' / 'custodian'
    W.validate_state_root(root)
    assert fake.paths('mkdir') == [str(BASE / 'data'), str(root)]
    assert (('private', str(BASE / 'data'), True) in fake.calls and ('private', str(root), True) in fake.calls)
    assert fake.nodes[str(root)]['dacl'] == [ace(ME, FULL), ace(W.SID_SYSTEM, FULL)]
    fake.calls.clear()
    W.validate_state_root(root)                                  # idempotent
    assert fake.paths('mkdir') == []


def test_validate_state_root_rejections(fake):
    with pytest.raises(ValueError, match='traversal'):
        W.validate_state_root(Path(str(BASE / 'a') + os.sep + '..' + os.sep + 'b'))
    with pytest.raises(ValueError, match='dedicated'):
        W.validate_state_root(Path(BASE.anchor))
    with pytest.raises(ValueError, match='dedicated'):
        W.validate_state_root(Path.home())
    assert fake.paths('mkdir') == []
    fake.add(BASE / 'jn', 'junction')
    with pytest.raises(ValueError, match='nonsymlink'):
        W.validate_state_root(BASE / 'jn' / 'state')
    fake.add(BASE / 'theirs', 'dir', owner=OTHER)
    with pytest.raises(ValueError, match='owner must be the current user$'):
        W.validate_state_root(BASE / 'theirs')
    with pytest.raises(ValueError, match='ancestor owner'):
        W.validate_state_root(BASE / 'theirs' / 'state')
    fake.add(BASE / 'pub', 'dir', dacl=[ace(ME, FULL), ace(W.SID_USERS, MODIFY)])
    with pytest.raises(ValueError, match='writable by other users'):
        W.validate_state_root(BASE / 'pub' / 'state')
    assert fake.paths('mkdir') == []


def test_validate_state_root_checks_existing_state_files(fake):
    root = BASE / 'state'
    fake.add(root / 'state.sqlite3', dacl=[ace(ME, FULL), ace(W.SID_USERS, READ)])
    W.validate_state_root(root)
    assert W.classify_dacl(ME, fake.nodes[str(root / 'state.sqlite3')]['dacl'])['level'] == 'private'
    for kwargs in ({'nlink': 2}, {'owner': OTHER}, {'kind': 'link'}):
        fake.nodes.pop(str(root / 'settings.json'), None)
        fake.add(root / 'settings.json', **kwargs)
        with pytest.raises(ValueError, match='State files must be current-user regular files'):
            W.validate_state_root(root)


# ---------------------------------------------------------------- private files
def test_open_private_file_create_and_reopen(fake):
    fake.add(BASE / 'state', 'dir')
    path = BASE / 'state' / 'settings.json'
    fd = W.open_private_file(path, write=True, create=True)
    assert fd in fake.fds and ('private', str(path), False) in fake.calls
    fake.close(fd)
    fake.calls.clear()
    fd = W.open_private_file(path, write=False, create=True, max_bytes=10)   # exists: plain open
    assert fd in fake.fds and fake.paths('private') == []
    fake.close(fd)
    with pytest.raises(FileNotFoundError):
        W.open_private_file(BASE / 'state' / 'absent.json', write=False, create=False)


@pytest.mark.parametrize('kwargs', [{'kind': 'link'}, {'kind': 'junction'}, {'kind': 'dir'},
                                    {'nlink': 2}, {'owner': OTHER}])
def test_open_private_file_refusals_leak_no_handles(fake, kwargs):
    path = fake.add(BASE / 'state' / 'settings.json', **kwargs)
    with pytest.raises(ValueError, match='State files must be current-user regular files'):
        W.open_private_file(Path(path), write=True, create=True)
    assert fake.fds == {}


def test_open_private_file_size_limit_and_admin_owner(fake):
    path = fake.add(BASE / 'state' / 'big.json', data=b'x' * 11, owner=W.SID_ADMINISTRATORS)
    with pytest.raises(ValueError, match='size'):
        W.open_private_file(Path(path), write=False, create=False, max_bytes=10)
    assert fake.fds == {}
    fake.close(W.open_private_file(Path(path), write=False, create=False, max_bytes=11))


def test_ensure_private_dir_file_and_owner_of(fake):
    fake.add(BASE, 'dir')
    target = BASE / 'private'
    W.ensure_private_dir(target)
    W.ensure_private_dir(target)
    assert fake.paths('mkdir') == [str(target)] and fake.paths('private') == [str(target)] * 2
    link = fake.add(BASE / 'jn', 'junction')
    with pytest.raises(ValueError):
        W.ensure_private_dir(Path(link))
    with pytest.raises(ValueError):
        W.owner_of(Path(link))
    file_path = fake.add(target / 'k.bin', dacl=[ace(W.SID_EVERYONE, FULL)])
    W.ensure_private_file(Path(file_path))
    assert W.classify_dacl(ME, fake.nodes[file_path]['dacl'])['level'] == 'private'
    with pytest.raises(ValueError):
        W.ensure_private_file(Path(fake.add(target / 'two.bin', nlink=2)))
    with pytest.raises(OSError):
        W.ensure_private_file(target / 'absent.bin')
    assert W.owner_of(Path(file_path)) == ME == W.current_principal()
    fd = fake.create_file(file_path)
    assert W.owner_of(fd) == ME
    fake.close(fd)


# --------------------------------------------------------------------- locking
def test_interprocess_lock_times_out_and_closes_its_handle(fake):
    path = BASE / 'state' / 'scan.lock'
    fake.add(path)
    fake.locked.add(str(path))
    started = time.monotonic()
    with pytest.raises(TimeoutError, match='Operation in progress.*scan.lock.*0.12s'):
        with W.interprocess_lock(path, 0.12):
            raise AssertionError('lock must not be acquired')
    assert 0.1 <= time.monotonic() - started < 3
    assert fake.fds == {} and fake.locked == {str(path)}


def test_interprocess_lock_acquires_releases_and_try_lock(fake):
    fake.add(BASE / 'state', 'dir')
    path = BASE / 'state' / 'monitor.lock'
    with W.interprocess_lock(path, 1.0):
        assert str(path) in fake.locked
        other = fake.create_file(str(path))
        assert W.try_lock_exclusive(other) is False
        fake.close(other)
    assert fake.locked == set() and fake.fds == {}
    with pytest.raises(RuntimeError):
        with W.interprocess_lock(path, 1.0):
            raise RuntimeError('body failed')
    assert fake.locked == set() and fake.fds == {}
    fd = fake.create_file(str(path))
    assert W.try_lock_exclusive(fd) is True
    W.unlock(fd)
    assert fake.locked == set()


# ------------------------------------------------------------------- processes
def test_process_identity_checks_fail_closed(fake):
    fake.processes.update({10: ME, 11: OTHER, 12: None})
    assert W.process_is_running_as_current_user(10) is True
    assert W.process_is_running_as_current_user(11) is False
    assert W.process_is_running_as_current_user(12) is False       # exited
    assert W.process_is_running_as_current_user(13) is False       # adapter raises OSError
    fake.calls.clear()
    for bad in (0, -1, True, '10', 1.0, None, 2 ** 40):
        assert W.process_is_running_as_current_user(bad) is False
    assert fake.calls == []


# ------------------------------------------------- real backend (Windows only)
@WINDOWS_ONLY
def test_real_state_root_and_private_file(tmp_path, monkeypatch):
    monkeypatch.setattr(W, '_WIN', None)
    me = W.current_principal()
    assert me.startswith('S-1-5-')
    state = tmp_path / 'state' / 'custodian'
    W.validate_state_root(state)
    W.validate_state_root(state)
    assert state.is_dir() and W.owner_of(state) in (me, W.SID_ADMINISTRATORS)
    path = state / 'settings.json'
    fd = W.open_private_file(path, write=True, create=True)
    try:
        assert os.write(fd, b'{}') == 2
    finally:
        os.close(fd)
    for target in (state, path):
        security = W._win().get_dacl_entries(str(target))
        assert {entry['sid'] for entry in security['dacl']} == {me, W.SID_SYSTEM}
        assert W.classify_dacl(security['owner'], security['dacl'], (me,))['level'] == 'private'
    fd = W.open_private_file(path, write=False, create=False, max_bytes=10)
    try:
        assert os.read(fd, 10) == b'{}' and W.owner_of(fd) in (me, W.SID_ADMINISTRATORS)
    finally:
        os.close(fd)
    with pytest.raises(ValueError):
        W.open_private_file(path, write=False, create=False, max_bytes=1)
    os.link(path, state / 'second-name.json')
    with pytest.raises(ValueError):
        W.open_private_file(path, write=False, create=False)


@WINDOWS_ONLY
def test_real_snapshot_hashes_source_and_skips_links(tmp_path, monkeypatch):
    import _winapi
    monkeypatch.setattr(W, '_WIN', None)
    scope, outside = tmp_path / 'scope', tmp_path / 'outside'
    (scope / 'pkg').mkdir(parents=True)
    outside.mkdir()
    (scope / 'pkg' / 'mod.py').write_bytes(b'x = 1\n')
    (scope / 'pkg' / 'Readme.MD').write_bytes(b'# doc\n')
    (scope / '.env').write_bytes(b'K=V\n')
    (outside / 'leak.py').write_bytes(b'no\n')
    _winapi.CreateJunction(str(outside), str(scope / 'jn'))
    result = W.bounded_snapshot(scope, ['README.md'], 100, 1 << 20)
    assert result['errors'] == [] and result['complete'] is True
    files = by_name(result)
    assert set(files) == {'mod.py', '.env', 'jn'}
    assert files['mod.py']['sha256'] == hashlib.sha256(b'x = 1\n').hexdigest()
    assert files['mod.py']['type'] == 'file' and files['mod.py']['uid'].startswith('S-1-')
    assert files['mod.py']['size'] == 6 and files['mod.py']['mode'] in (0o600, 0o644, 0o666)
    assert 'sha256' not in files['.env'] and files['.env']['uid'].startswith('S-1-')
    assert files['jn']['type'] == 'symlink' and 'sha256' not in files['jn']
    through = W.bounded_snapshot(scope / 'jn', [], 100, 1 << 20)
    assert through['complete'] is False and through['files'] == []


@WINDOWS_ONLY
def test_real_lock_and_process_identity(tmp_path, monkeypatch):
    monkeypatch.setattr(W, '_WIN', None)
    path = tmp_path / 'scan.lock'
    with W.interprocess_lock(path, 2.0):
        with pytest.raises(TimeoutError):
            with W.interprocess_lock(path, 0.2):
                raise AssertionError('second holder must not get the lock')
    with W.interprocess_lock(path, 2.0):
        pass
    fd = W.open_private_file(path, write=True, create=True)
    try:
        assert W.try_lock_exclusive(fd) is True
        W.unlock(fd)
    finally:
        os.close(fd)
    assert W.process_is_running_as_current_user(os.getpid()) is True
    assert W.process_is_running_as_current_user(0) is False
    assert signal.SIGBREAK in W.terminate_signals()
    assert W.default_state_dir().name == 'hermes-custodian'


# ------------------------------------- review blockers 1-3 (fake Win32 adapter)
GROUP = 'S-1-5-21-1-2-3-2001'
ORIGINAL = hashlib.sha256(b'x = 1\n').hexdigest()


def make_outside(fake):
    outside = BASE / 'outside'
    fake.add(outside / 'deep.py', data=b'SECRET = 1\n')
    fake.add(outside / '.env', data=b'K=1\n', dacl=[ace(W.SID_EVERYONE, FULL)])
    return outside


def outside_reads(fake):
    return [c for c in fake.calls if 'outside' in str(c[1]) and c[0] in ('scandir', 'acl', 'read', 'lookup')]


def pinned(fake):
    return {h['path'] for h in fake.fds.values() if h.get('mode') in ('pin', 'dir')}


def rel(base, text):
    return base.joinpath(*text.split('/')) if text else base


@pytest.mark.parametrize('op,leaf', [('scandir', 'sub'), ('stat', 'sub/deep.py'), ('open', 'sub/deep.py'),
                                     ('read', 'sub/deep.py'), ('acl', 'sub/deep.py'), ('acl', '.env')])
def test_snapshot_pins_every_ancestor_for_each_child_operation(fake, op, leaf):
    scope = build_tree(fake)
    target, seen = rel(scope, leaf), []
    fake.hooks[(op, str(target))] = lambda: seen.append(pinned(fake))
    assert W.bounded_snapshot(scope, [], 100, 1 << 20)['complete'] is True
    expected = {str(parent) for parent in target.parents} | ({str(target)} if op == 'scandir' else set())
    assert len(seen) == 1 and expected <= seen[0] and fake.fds == {}


def test_snapshot_refuses_replacement_of_pinned_ancestors(fake):
    scope, outside = build_tree(fake), make_outside(fake)

    def attack():
        for victim in (scope / 'sub', scope, BASE):
            with pytest.raises(PermissionError):
                fake.swap(victim, outside)
    for op in ('stat', 'open', 'read'):
        fake.hooks[(op, str(scope / 'sub' / 'deep.py'))] = attack
    result = W.bounded_snapshot(scope, [], 100, 1 << 20)
    assert result['complete'] is True and by_name(result)['deep.py']['sha256'] == ORIGINAL
    assert len(fake.denied) == 9 and outside_reads(fake) == []


@pytest.mark.parametrize('op,at,victim,replacement,complete', [
    ('opendir', 'sub', 'sub', 'outside', False),            # swapped before the listing handle opens
    ('opendir', 'sub', 'sub', 'scope/jn', False),           # ... for a junction
    ('scandir', 'sub', 'sub', 'outside', True),             # swapped after identity verification
    ('open', 'sub/deep.py', 'sub', 'outside', True),        # parent swapped before the content open
    ('open', 'sub/deep.py', 'sub/deep.py', 'outside/deep.py', False),
    ('acl', '.env', '', 'outside', True)])                  # scope root swapped before an ACL lookup
def test_snapshot_swap_cannot_redirect_handle_bound_operations(fake, op, at, victim, replacement, complete):
    scope = build_tree(fake)
    make_outside(fake)
    fake.enforce_pins = False       # even if the OS let the swap happen, nothing may follow it
    fake.hooks[(op, str(rel(scope, at)))] = lambda: fake.swap(rel(scope, victim), rel(BASE, replacement))
    result = W.bounded_snapshot(scope, [], 100, 1 << 20)
    files = by_name(result)
    assert result['complete'] is complete and outside_reads(fake) == [] and fake.fds == {}
    assert str(scope / 'jn') not in fake.paths('scandir')
    assert not any('outside.py' in str(call[1]) for call in fake.calls)
    if complete:
        assert files['deep.py']['sha256'] == ORIGINAL and files['.env']['exposed_to'] == ['BUILTIN\\Users']
    else:
        assert 'sha256' not in files.get('deep.py', {})


@pytest.mark.parametrize('name', ['', '.', '..', 'a\\b', 'a/b', 'a.py:stream', 'a\x00b'])
def test_child_names_cannot_escape_the_parent_handle(name):
    with pytest.raises(ValueError):
        W._component(name)
    assert W._component('ok name.py') == 'ok name.py'


def test_native_structures_and_buffer_parsers():
    import ctypes
    import struct
    if ctypes.sizeof(ctypes.c_void_p) == 8:
        assert [ctypes.sizeof(t) for t in (W._UnicodeString, W._ObjectAttributes, W._IoStatusBlock)] == [16, 48, 16]
        assert W._ObjectAttributes.ObjectName.offset == 16 and W._UnicodeString.Buffer.offset == 8
    raw = struct.pack('<I8s8sQIIIIII', 0x10, b'', b'', 116444736000000000 + 5, 9, 1, 2, 1, 3, 4)
    assert W.parse_file_information(raw) == W.FileInfo(0x10, stat.S_IFDIR, 9, (3 << 32) | 4, 1, (1 << 32) | 2, 500)
    assert W.parse_file_information(raw[:4].replace(b'\x10', b'\x20') + raw[4:]).is_regular

    def record(name, more):
        text = name.encode('utf-16-le')
        body = struct.pack('<I56xI40x', 0, len(text)) + text
        body += b'\0' * (-len(body) % 8)
        return struct.pack('<I', len(body) if more else 0) + body[4:]
    data = record('..', True) + record('a.py', True) + record('é.md', False)
    assert W.parse_directory_names(data) == ['a.py', 'é.md']
    with pytest.raises(OSError):
        W.parse_directory_names(record('a.py', False)[:106])


@pytest.mark.parametrize('sid,kind', [(OTHER, 'allow'), (GROUP, 'allow'), (W.SID_USERS, 'allow'), ('', 'other')])
@pytest.mark.parametrize('mask', [0x10000, 0x40000, 0x80000, 0x40, FULL, W.GENERIC_ALL])
def test_state_ancestor_rejects_replacement_rights_for_any_untrusted_principal(fake, sid, kind, mask):
    dacl = private_dacl() + [ace(sid, mask, kind)]
    assert W.state_root_violation(make_info('dir'), dir_security(dacl=dacl), is_last=False, me=ME) == \
        'state_dir ancestor must not be writable by other users'
    fake.add(BASE / 'shared', 'dir', dacl=dacl)
    with pytest.raises(ValueError, match='writable by other users'):
        W.validate_state_root(BASE / 'shared' / 'state')
    assert fake.paths('mkdir') == [] and fake.fds == {}


def test_state_ancestor_trusted_grants_and_fail_closed_parsing():
    def check(dacl):
        return W.state_root_violation(make_info('dir'), dir_security(dacl=dacl), is_last=False, me=ME)
    assert check([ace(sid, FULL) for sid in (ME, W.SID_SYSTEM, W.SID_ADMINISTRATORS,
                                             W.SID_TRUSTED_INSTALLER, W.SID_OWNER_RIGHTS)]) is None
    assert check([ace(OTHER, RX), ace(GROUP, READ | 0x4)]) is None
    assert check([ace(OTHER, FULL, 'deny'), ace(OTHER, FULL)]) is None
    assert check([ace(OTHER, FULL, inherit_only=True)]) is None
    assert check([ace(ME, FULL)] * (W.MAX_ACES + 1)) is not None
    assert check([ace(OTHER, FULL, 'mystery')]) is not None
    assert [W.ace_label(kind) for kind in (0, 1, 2, 4, 5, 9, 10, 17, 99)] == \
        ['allow', 'deny', None, 'other', 'other', 'other', None, None, 'other']


@pytest.mark.parametrize('name', ['dashboard-login.json', 'settings.json', 'session.key'])
def test_open_private_file_restricts_existing_readable_file_on_the_handle(fake, name):
    path = fake.add(BASE / 'state' / name, data=b'secret', dacl=private_dacl() + [ace(OTHER, READ)])
    fd = W.open_private_file(Path(path), write=False, create=False)
    assert W.classify_dacl(ME, fake.nodes[path]['dacl'], (ME,))['level'] == 'private'
    assert ('private', path, False) in fake.calls and fake.paths('read') == []
    fake.close(fd)
    assert fake.fds == {} and 'dashboard-login.json' in W.STATE_FILES


@pytest.mark.parametrize('extra,locked', [([ace(OTHER, MODIFY)], False), ([ace(W.SID_USERS, 0x2)], False),
                                          ([ace('', 0, 'other')], False), (None, False),
                                          ([ace(GROUP, READ)], True)])
def test_open_private_file_rejects_tampered_or_unfixable_existing_file(fake, extra, locked):
    dacl = None if extra is None else private_dacl() + extra
    path = fake.add(BASE / 'state' / 'dashboard-login.json', data=b'secret', dacl=dacl)
    fake.nodes[path]['dacl_locked'] = locked
    with pytest.raises(ValueError, match='private'):
        W.open_private_file(Path(path), write=False, create=True)
    assert fake.fds == {} and fake.paths('read') == []


def test_new_private_file_is_verified_and_state_root_enforces_existing_files(fake):
    fake.add(BASE / 'state', 'dir')
    fake.close(W.open_private_file(BASE / 'state' / 'new.json', write=True, create=True))
    assert W.classify_dacl(ME, fake.nodes[str(BASE / 'state' / 'new.json')]['dacl'])['level'] == 'private'
    login = fake.add(BASE / 'state' / 'dashboard-login.json', dacl=private_dacl() + [ace(OTHER, MODIFY)])
    with pytest.raises(ValueError, match='private'):
        W.validate_state_root(BASE / 'state')
    fake.nodes[login]['dacl'] = private_dacl() + [ace(OTHER, READ)]
    W.validate_state_root(BASE / 'state')
    assert W.classify_dacl(ME, fake.nodes[login]['dacl'])['level'] == 'private' and fake.fds == {}


@WINDOWS_ONLY
def test_real_pins_block_replacement_and_existing_exposure_is_enforced(tmp_path, monkeypatch):
    import subprocess
    monkeypatch.setattr(W, '_WIN', None)
    win, me = W._win(), W.current_principal()
    scope = tmp_path / 'scope'
    (scope / 'sub').mkdir(parents=True)
    pins = []
    try:
        W._pin_directory(win, scope / 'sub', pins)
        for victim in (scope / 'sub', scope):
            with pytest.raises(OSError):
                os.rename(victim, tmp_path / 'moved')
    finally:
        for handle in reversed(pins):
            win.close(handle)
    os.rename(scope, tmp_path / 'moved')
    state = tmp_path / 'state'
    W.validate_state_root(state)
    login = state / 'dashboard-login.json'
    login.write_bytes(b'{}')

    def level(right=None):
        if right:
            subprocess.run(['icacls', str(login), '/grant', f'*{W.SID_USERS}:{right}'],
                           check=True, capture_output=True, timeout=30)
        security = win.get_dacl_entries(str(login))
        return W.classify_dacl(security['owner'], security['dacl'], (me,))['level']
    assert level('R') == 'read'
    os.close(W.open_private_file(login, write=False, create=False))
    assert level() == 'private' and level('M') == 'write'
    with pytest.raises(ValueError):
        W.open_private_file(login, write=True, create=False)


def test_state_root_closes_new_directory_if_private_dacl_fails(fake):
    fake.add(BASE, 'dir')
    fake.fail_ops.add('private')
    with pytest.raises(ValueError, match='private'):
        W.validate_state_root(BASE / 'new-state')
    assert fake.fds == {}


def test_buffer_parsers_reject_truncated_and_escaping_records():
    import struct
    with pytest.raises(OSError):
        W.parse_file_information(b'\0' * 51)
    for name in ('a/b', 'a\\b', 'a:stream', 'a\0b'):
        encoded = name.encode('utf-16-le')
        raw = struct.pack('<I56xI40x', 0, len(encoded)) + encoded
        with pytest.raises(ValueError):
            W.parse_directory_names(raw)
    for size, more in ((1, 0), (1000, 0), (2, 8), (2, 104)):
        raw = struct.pack('<I56xI40x', more, size) + b'a\0'
        with pytest.raises(OSError):
            W.parse_directory_names(raw)


@pytest.mark.parametrize('kind,label', [(0, 'allow'), (4, 'other'), (99, 'other')])
def test_native_acl_buffer_parser_preserves_unknown_grants(monkeypatch, kind, label):
    import ctypes
    import struct
    # One actual ACCESS_ACE buffer; only GetAce's pointer lookup is substituted.
    entry = ctypes.create_string_buffer(struct.pack('<BBHI', kind, 0, 20, READ) + b'\x01\x01' + b'\0' * 6 + b'\0' * 4)
    acl = ctypes.create_string_buffer(struct.pack('<BBHHH', 2, 0, 28, 1, 0))

    class Api:
        def GetAce(self, address, index, output):
            ctypes.cast(output, ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.addressof(entry)
            return True

    monkeypatch.setattr(W, '_api', lambda: (None, Api()))
    adapter = W._Win()
    monkeypatch.setattr(adapter, '_sid_string', lambda address: OTHER)
    parsed = adapter._read_acl(ctypes.addressof(acl))
    assert parsed == [ace(OTHER if label == 'allow' else '', READ, label)]
    assert W.classify_dacl(ME, parsed)['level'] == ('read' if label == 'allow' else 'write')


def test_native_acl_buffer_parser_rejects_short_access_ace(monkeypatch):
    import ctypes
    import struct
    entry = ctypes.create_string_buffer(struct.pack('<BBH', 0, 0, 4))
    acl = ctypes.create_string_buffer(struct.pack('<BBHHH', 2, 0, 12, 1, 0))

    class Api:
        def GetAce(self, address, index, output):
            ctypes.cast(output, ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.addressof(entry)
            return True

    monkeypatch.setattr(W, '_api', lambda: (None, Api()))
    with pytest.raises(OSError, match='Malformed'):
        W._Win()._read_acl(ctypes.addressof(acl))
