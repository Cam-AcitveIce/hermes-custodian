"""Path-only regressions; all paths are synthetic, never live secrets."""
from pathlib import Path

import pytest

from custodian import policy


@pytest.mark.parametrize('name', [
    'auth-context.ts', 'test_setup_credentials.py', 'tokens.css', 'tokens.py',
    'src/auth-context/provider.py', 'src/tokenizer.py', 'secrets-manager.py',
    'password-validator.ts', 'oauth-client.ts', 'credential-types.ts',
    'private_key_utils.py', 'api_key_parser.py',
])
def test_source_names_are_not_secret_artifacts(name):
    assert not policy.is_finding_sensitive(Path(name), 'file')


@pytest.mark.parametrize('name', [
    '.env', '.env.local', '.env.production', '.envrc', '.env.example',
    'auth.json', 'AUTH.YAML', 'auth.json.bak', 'tokens.json', 'tokens.md',
    'credentials.json', 'credentials.json.backup', 'secrets.yaml',
    'api_keys.md', 'passwords.md', 'private-key.md', 'id_rsa', 'id_ed25519',
    'server.key', 'client.pem', 'backup.p12', 'vault.kdbx',
    '.ssh/config', '.gnupg/data', '.aws/config', 'auth/data.md',
    'auth-cache/data.md', 'oauth-cache/data.md', 'memories/note.md',
    'browser/Default/Cookies', '.config/google-chrome/Default/data',
])
def test_established_secret_artifacts_and_private_areas_stay_protected(name):
    assert policy.is_sensitive(Path(name))


def test_classifier_never_reads_or_stats_paths(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('classification must use path text only')

    for method in ('open', 'read_text', 'read_bytes', 'stat', 'lstat', 'is_file', 'is_dir'):
        monkeypatch.setattr(Path, method, forbidden)
    assert policy.is_sensitive(Path('synthetic/auth.json'))
    assert policy.is_sensitive(Path('synthetic/tokens.py'))
    assert not policy.is_finding_sensitive(Path('synthetic/tokens.py'), 'file')


def test_artifacts_remain_metadata_only(tmp_path, monkeypatch):
    for name in ('tokens.md', 'credentials.md', 'private-key.md', '.env'):
        (tmp_path / name).write_text('synthetic fixture only')

    def forbidden(*args, **kwargs):
        raise AssertionError('credential content must never be read')

    import os
    monkeypatch.setattr(os, 'read', forbidden)
    snapshot = policy.bounded_snapshot(tmp_path, [], 20, 1024)
    assert snapshot['complete']
    assert len(snapshot['files']) == 4
    assert all('sha256' not in entry for entry in snapshot['files'])
