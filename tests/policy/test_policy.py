import hashlib
import os
from pathlib import Path
import stat
import socket

import pytest

from custodian import policy


def test_sensitive_credentials_and_private_areas():
    names = ['.env', '.env.local', '.envrc', 'auth.json', 'tokens.json',
             'id_rsa', 'id_ed25519.pub', 'server.key', 'client.pem',
             'browser/Default/Cookies', '.ssh/config', 'credentials.json',
             'profiles/x/memories/note.md', 'history/chat.json', 'SOUL.md']
    assert all(policy.is_sensitive(Path(n)) for n in names)
    assert not policy.is_sensitive(Path('skills/example/SKILL.md'))
    assert not policy.is_sensitive(Path('plugins/code.py'))


def test_sanitise_text_strips_terminal_and_bidi_injection():
    assert policy.sanitise_text('a\x1b[31mRED\x1b[0m\x1b]0;evil\x07\n\t\u202e\u2066\x00z') == 'aREDz'
    assert policy.sanitise_text('café/日本.md') == 'café/日本.md'


def test_config_allowlist_excludes_nested_execution_and_credentials():
    config = {'model': {'default': 'model-one', 'provider': 'provider-one',
                        'api_key': 'NEVER', 'base_url': 'https://secret'},
              'provider': 'provider-two',
              'plugins': ['plugin-one', {'name': 'plugin-two', 'env': {'K': 'NEVER'}}],
              'mcp_servers': {'server-one': {'command': 'NEVER', 'args': ['NEVER'],
                                               'env': {'TOKEN': 'NEVER'}}},
              'env': {'TOKEN': 'NEVER'}, 'unrecognised': 'NEVER'}
    assert policy.redact_config(config) == {
        'model': 'model-one', 'provider': 'provider-two',
        'plugins': ['plugin-one', 'plugin-two'], 'mcp_servers': ['server-one']}
    assert policy.redact_config({'model': 'https://user:pass@host',
                                 'provider': {'env': 'NEVER'}}) == {}


def test_snapshot_hashes_selected_python_and_markdown(tmp_path):
    (tmp_path / 'skill').mkdir()
    (tmp_path / 'skill' / 'run.py').write_bytes(b'print(1)\n')
    (tmp_path / 'SKILL.md').write_bytes(b'# fixture\n')
    snapshot = policy.bounded_snapshot(tmp_path, [], 10, 1024)
    assert snapshot['complete'] is True
    assert snapshot['errors'] == []
    by_name = {Path(f['path']).name: f for f in snapshot['files']}
    assert by_name['run.py']['sha256'] == hashlib.sha256(b'print(1)\n').hexdigest()
    assert by_name['SKILL.md']['sha256'] == hashlib.sha256(b'# fixture\n').hexdigest()


def test_snapshot_never_opens_credentials_or_special_entries(tmp_path, monkeypatch):
    for name in ('.env.production', 'auth.json', 'tokens.md', 'server.key', 'config.yaml'):
        (tmp_path / name).write_text('fixture-secret')
    (tmp_path / 'memories').mkdir()
    (tmp_path / 'memories' / 'private.md').write_text('fixture-private')
    if hasattr(os, 'mkfifo'):
        os.mkfifo(tmp_path / 'pipe.py')
    (tmp_path / 'alias.py').symlink_to(tmp_path / '.env.production')
    opened = []
    original = os.open
    def spy(path, flags, *args, **kwargs):
        opened.append(str(path))
        return original(path, flags, *args, **kwargs)
    monkeypatch.setattr(os, 'open', spy)
    snapshot = policy.bounded_snapshot(tmp_path, [], 20, 1024)
    assert not any('sha256' in item for item in snapshot['files'])
    assert not set(opened) & {'.env.production', 'auth.json', 'tokens.md', 'server.key',
                              'config.yaml', 'memories', 'private.md', 'pipe.py', 'alias.py'}


def test_snapshot_enforces_file_and_byte_budgets(tmp_path):
    for n in range(3):
        (tmp_path / f'{n}.py').write_bytes(b'x' * 33)
    limited = policy.bounded_snapshot(tmp_path, [], 1, 32)
    assert limited['complete'] is False
    assert limited['errors']
    assert len(limited['files']) <= 1
    assert not any('sha256' in f for f in limited['files'])


def test_snapshot_rejects_symlinked_roots_and_reports_errors(tmp_path):
    real = tmp_path / 'real'
    real.mkdir()
    (real / 'code.py').write_text('fixture')
    (tmp_path / 'link').symlink_to(real, target_is_directory=True)
    for root in (tmp_path / 'link', tmp_path / 'link' / 'nested', tmp_path / 'absent'):
        snapshot = policy.bounded_snapshot(root, [], 10, 1024)
        assert snapshot['complete'] is False
        assert snapshot['errors']
        assert snapshot['files'] == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX syscall/metadata regression; Win32 adversarial coverage in test_windows_backend")
def test_snapshot_file_swap_to_fifo_never_reads_special_file(tmp_path, monkeypatch):
    target = tmp_path / 'code.py'
    target.write_text('fixture')
    original_open, original_read = os.open, os.read
    special_fds = set()
    def swap(path, flags, *args, **kwargs):
        if path == 'code.py':
            target.unlink()
            os.mkfifo(target)
        fd = original_open(path, flags, *args, **kwargs)
        if stat.S_ISFIFO(os.fstat(fd).st_mode):
            special_fds.add(fd)
        return fd
    def guarded_read(fd, size):
        assert fd not in special_fds, 'special file read attempted'
        return original_read(fd, size)
    monkeypatch.setattr(os, 'open', swap)
    monkeypatch.setattr(os, 'read', guarded_read)
    snapshot = policy.bounded_snapshot(tmp_path, [], 10, 1024)
    assert snapshot['complete'] is False
    assert not any('sha256' in f for f in snapshot['files'])


def test_snapshot_hardlinked_source_is_metadata_only(tmp_path, monkeypatch):
    (tmp_path / 'auth.json').write_text('fixture-credential')
    os.link(tmp_path / 'auth.json', tmp_path / 'innocent.py')
    def forbidden_read(*args):
        raise AssertionError('hardlink contents must not be read')
    monkeypatch.setattr(os, 'read', forbidden_read)
    snapshot = policy.bounded_snapshot(tmp_path, [], 10, 1024)
    assert not any('sha256' in f for f in snapshot['files'])


def test_snapshot_entry_budget_counts_excluded_and_empty_directories(tmp_path, monkeypatch):
    for n in range(20):
        (tmp_path / str(n)).mkdir()
    from custodian import _platform
    monkeypatch.setattr(policy, 'MAX_ENTRIES', 3, raising=False)
    monkeypatch.setattr(_platform._backend, 'MAX_ENTRIES', 3)
    calls = []
    original = os.stat
    def count(*args, **kwargs):
        if kwargs.get('dir_fd') is not None:
            calls.append(args[0])
        return original(*args, **kwargs)
    monkeypatch.setattr(os, 'stat', count)
    snapshot = policy.bounded_snapshot(tmp_path, ['*'], 10, 1024)
    assert snapshot['complete'] is False
    assert len(calls) <= 3


def test_snapshot_exclusions_prune_before_open(tmp_path, monkeypatch):
    (tmp_path / 'excluded').mkdir()
    (tmp_path / 'excluded' / 'code.py').write_text('fixture')
    (tmp_path / 'skip.md').write_text('fixture')
    (tmp_path / 'keep.py').write_text('fixture')
    snapshot = policy.bounded_snapshot(tmp_path, ['excluded', '*.md'], 10, 1024)
    assert snapshot['complete']
    assert [Path(f['path']).name for f in snapshot['files']] == ['keep.py']


def test_snapshot_time_guard_stops_before_content_read(tmp_path, monkeypatch):
    (tmp_path / 'code.py').write_text('fixture')
    from custodian import _platform
    monkeypatch.setattr(policy, 'MAX_SECONDS', 0, raising=False)
    monkeypatch.setattr(_platform._backend, 'MAX_SECONDS', 0)
    def forbidden_read(*args):
        raise AssertionError('time budget expired before content read')
    monkeypatch.setattr(os, 'read', forbidden_read)
    snapshot = policy.bounded_snapshot(tmp_path, [], 10, 1024)
    assert not snapshot['complete']
    assert snapshot['errors']


@pytest.mark.skipif(os.name == "nt", reason="POSIX syscall/metadata regression; Win32 adversarial coverage in test_windows_backend")
def test_snapshot_mutation_during_hash_discards_digest(tmp_path, monkeypatch):
    target = tmp_path / 'code.py'
    target.write_bytes(b'a' * 64)
    original = os.read
    def changing_read(fd, count):
        chunk = original(fd, count)
        target.write_bytes(b'b' * 128)
        return chunk
    monkeypatch.setattr(os, 'read', changing_read)
    snapshot = policy.bounded_snapshot(tmp_path, [], 10, 64)
    assert not snapshot['complete']
    assert not any('sha256' in f for f in snapshot['files'])


def test_snapshot_depth_budget_bounds_open_descriptors(tmp_path, monkeypatch):
    (tmp_path / 'a' / 'b' / 'c').mkdir(parents=True)
    from custodian import _platform
    monkeypatch.setattr(policy, 'MAX_DEPTH', 1, raising=False)
    monkeypatch.setattr(_platform._backend, 'MAX_DEPTH', 1)
    snapshot = policy.bounded_snapshot(tmp_path, [], 10, 1024)
    assert not snapshot['complete']
    assert snapshot['errors']


@pytest.mark.skipif(os.name == "nt", reason="POSIX syscall/metadata regression; Win32 adversarial coverage in test_windows_backend")
def test_snapshot_directory_replacement_is_not_traversed(tmp_path, monkeypatch):
    root = tmp_path / 'root'
    root.mkdir()
    target = root / 'skill'
    target.mkdir()
    replacement = tmp_path / 'replacement'
    replacement.mkdir()
    (replacement / 'unexpected.py').write_text('fixture-private')
    original = os.open
    def swapped_open(path, flags, *args, **kwargs):
        if path == 'skill':
            target.rename(tmp_path / 'saved')
            replacement.rename(target)
        return original(path, flags, *args, **kwargs)
    monkeypatch.setattr(os, 'open', swapped_open)
    snapshot = policy.bounded_snapshot(root, [], 10, 1024)
    assert not snapshot['complete']
    assert snapshot['files'] == []


def test_sensitive_credential_backups_passwords_and_browser_stores():
    names = ['auth.json.bak', '.netrc', '.aws/config', '.azure/settings.md',
             'api_keys.md', 'passwords.md', 'oauth-cache/data.md',
             '.config/google-chrome/Default/README.md',
             '.config/BraveSoftware/Default/data.md', 'private-key.md',
             '.config/microsoft-edge/Default/readme.md', 'USER.md',
             'MEMORY.md', 'logs/chat.md', 'conversations/chat.md']
    assert all(policy.is_sensitive(Path(n)) for n in names)


def test_snapshot_sensitive_root_is_not_enumerated(tmp_path, monkeypatch):
    root = tmp_path / 'memories'
    root.mkdir()
    (root / 'private.md').write_text('fixture-private')
    def forbidden(*args):
        raise AssertionError('sensitive root must not be enumerated')
    monkeypatch.setattr(os, 'scandir', forbidden)
    snapshot = policy.bounded_snapshot(root, [], 10, 1024)
    if os.name != 'nt':
        assert snapshot['files'] == [policy.safe_metadata(root)]
    else:
        assert len(snapshot['files']) == 1
        item = snapshot['files'][0]
        assert item['path'] == str(root) and 'sha256' not in item
        assert item['size'] == root.stat().st_size


def test_snapshot_invalid_limits_and_traversal_fail_closed(tmp_path):
    for files, size in ((-1, 1024), (True, 1024), (2, -1), (2, 0), ('2', 1024)):
        result = policy.bounded_snapshot(tmp_path, [], files, size)
        assert not result['complete']
        assert result['files'] == []
        assert result['errors']
    result = policy.bounded_snapshot(tmp_path / '..' / tmp_path.name, [], 2, 1024)
    assert not result['complete']


def test_snapshot_aggregate_byte_budget(tmp_path, monkeypatch):
    (tmp_path / 'a.py').write_bytes(b'a' * 10)
    (tmp_path / 'b.py').write_bytes(b'b' * 10)
    from custodian import _platform
    monkeypatch.setattr(policy, 'MAX_TOTAL_BYTES', 16, raising=False)
    monkeypatch.setattr(_platform._backend, 'MAX_TOTAL_BYTES', 16)
    read_bytes = []
    original = os.read
    def counted_read(fd, count):
        data = original(fd, count)
        read_bytes.append(len(data))
        return data
    monkeypatch.setattr(os, 'read', counted_read)
    snapshot = policy.bounded_snapshot(tmp_path, [], 10, 1024)
    assert not snapshot['complete']
    assert sum(read_bytes) <= 16


def test_sensitive_root_metadata_rejects_symlinked_parent(tmp_path):
    real = tmp_path / 'real'
    real.mkdir()
    (real / 'memories').mkdir()
    (tmp_path / 'link').symlink_to(real, target_is_directory=True)
    result = policy.bounded_snapshot(tmp_path / 'link' / 'memories', [], 10, 1024)
    assert not result['complete']
    assert result['files'] == []


def test_config_enabled_plugins_only_names_not_container_keys():
    config = {'model': {'default': 'org/model', 'provider': 'vendor'},
              'plugins': {'enabled': ['plugin-a', {'name': 'plugin-b', 'args': ['NEVER']}],
                          'env': {'KEY': 'NEVER'}}}
    assert policy.redact_config(config) == {
        'model': 'org/model', 'provider': 'vendor', 'plugins': ['plugin-a', 'plugin-b']}


@pytest.mark.parametrize('directory', [False, True])
@pytest.mark.skipif(os.name == "nt", reason="POSIX syscall/metadata regression; Win32 adversarial coverage in test_windows_backend")
def test_symlink_swap_at_open_is_blocked(tmp_path, monkeypatch, directory):
    root = tmp_path / 'root'
    root.mkdir()
    target = root / ('skill' if directory else 'code.py')
    outside = tmp_path / 'outside'
    if directory:
        target.mkdir()
        outside.mkdir()
        (outside / 'code.py').write_text('fixture-private')
    else:
        target.write_text('fixture')
        outside.write_text('fixture-private')
    original = os.open
    def swapped_open(path, flags, *args, **kwargs):
        if path == target.name:
            target.rename(tmp_path / 'saved')
            target.symlink_to(outside, target_is_directory=directory)
        return original(path, flags, *args, **kwargs)
    def forbidden_read(*args):
        raise AssertionError('symlink swap must not expose content')
    monkeypatch.setattr(os, 'open', swapped_open)
    monkeypatch.setattr(os, 'read', forbidden_read)
    result = policy.bounded_snapshot(root, [], 10, 1024)
    assert not result['complete']
    assert result['files'] == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX syscall/metadata regression; Win32 adversarial coverage in test_windows_backend")
def test_socket_is_metadata_only(tmp_path, monkeypatch):
    # Short relative name avoids the AF_UNIX platform path-length limit.
    monkeypatch.chdir(tmp_path)
    with socket.socket(socket.AF_UNIX) as endpoint:
        endpoint.bind('socket.py')
        def forbidden_read(*args):
            raise AssertionError('socket must not be read')
        monkeypatch.setattr(os, 'read', forbidden_read)
        result = policy.bounded_snapshot(tmp_path, [], 10, 1024)
        assert result['complete']
        assert result['files'] == [policy.safe_metadata(tmp_path / 'socket.py')]


def test_config_nested_reserved_fields_are_not_display_names():
    config = {'plugins': {'env': {'TOKEN': 'NEVER'}, 'args': ['NEVER'],
                          'command': 'NEVER', 'api_key': 'NEVER', 'safe-plugin': {}},
              'mcp_servers': {'safe-server': {'url': 'https://NEVER'},
                              'env': {'TOKEN': 'NEVER'}, 'url': 'https://NEVER'}}
    assert policy.redact_config(config) == {'plugins': ['safe-plugin'],
                                            'mcp_servers': ['safe-server']}


def test_sensitive_auth_directories_and_keychain_variants():
    assert all(policy.is_sensitive(Path(n)) for n in (
        'auth/data.md', 'auth-cache/data.md', 'privkey.md', 'apikey.md',
        'keychain/store.md', 'wallet/backup.md', '.config/gcloud/README.md'))
    assert not policy.is_sensitive(Path('authors.md'))


def test_snapshot_malformed_path_returns_incomplete_not_exception():
    result = policy.bounded_snapshot(Path('invalid\x00root'), [], 10, 1024)
    assert not result['complete']
    assert result['errors']
    assert result['files'] == []


def test_safe_metadata_is_lstat_only(tmp_path):
    link = tmp_path / 'link'
    link.symlink_to(tmp_path / 'absent')
    info = policy.safe_metadata(link)
    assert info == {'path': str(link), 'type': 'symlink',
                    'mode': stat.S_IMODE(link.lstat().st_mode),
                    'uid': link.lstat().st_uid, 'size': link.lstat().st_size,
                    'mtime_ns': link.lstat().st_mtime_ns}


def test_snapshot_metadata_retains_entry_type(tmp_path):
    (tmp_path / 'regular.txt').write_text('fixture')
    (tmp_path / 'link.txt').symlink_to(tmp_path / 'regular.txt')
    if hasattr(os, 'mkfifo'):
        os.mkfifo(tmp_path / 'fifo')
    snapshot = policy.bounded_snapshot(tmp_path, [], 10, 1024)
    by_name = {Path(f['path']).name: f for f in snapshot['files']}
    assert by_name['regular.txt']['type'] == 'file'
    assert by_name['link.txt']['type'] == 'symlink'
    if hasattr(os, 'mkfifo'):
        assert by_name['fifo']['type'] == 'other'
    for entry in by_name.values():
        assert {'path', 'type', 'mode', 'uid', 'size', 'mtime_ns'} <= set(entry)


