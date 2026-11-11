import os
from custodian import _platform
import json
import pytest


def test_persistent_password_verifier_never_stores_plaintext(tmp_path):
    from custodian.dashboard_auth import DashboardAuth
    auth = DashboardAuth(tmp_path / 'state')
    assert not auth.configured()
    auth.configure('cam-test', 'synthetic-password-for-tests-only')
    record = (tmp_path / 'state' / 'dashboard-login.json').read_text()
    assert 'synthetic-password-for-tests-only' not in record
    if os.name != "nt":
        assert (tmp_path / 'state' / 'dashboard-login.json').stat().st_mode & 0o777 == 0o600
    else:
        assert _platform.read_private_file(tmp_path / 'state' / 'dashboard-login.json', max_bytes=65536)
    restored = DashboardAuth(tmp_path / 'state')
    assert restored.configured()
    assert restored.authenticate('cam-test', 'synthetic-password-for-tests-only')
    assert not restored.authenticate('cam-test', 'wrong')
    assert not restored.authenticate('someone-else', 'synthetic-password-for-tests-only')


def test_verifier_symlink_and_expensive_parameter_tampering_fail_closed(tmp_path, monkeypatch):
    from custodian.dashboard_auth import DashboardAuth
    import hashlib
    auth = DashboardAuth(tmp_path / 'state')
    auth.configure('cam-test', 'synthetic-password-for-tests-only')
    path = tmp_path / 'state' / 'dashboard-login.json'
    record = json.loads(path.read_text())
    record['scrypt']['n'] = 1073741824
    path.write_text(json.dumps(record))
    monkeypatch.setattr(hashlib, 'scrypt', lambda *a, **k: pytest.fail('Invalid parameters must never reach hashing'))
    assert not auth.authenticate('cam-test', 'anything')
    path.unlink()
    path.symlink_to(tmp_path / 'outside')
    with pytest.raises(OSError):
        auth.configure('cam-test', 'synthetic-password-for-tests-only')
    assert not (tmp_path / 'outside').exists()


def test_reset_rotates_revision_and_revokes_old_password(tmp_path):
    from custodian.dashboard_auth import DashboardAuth
    auth = DashboardAuth(tmp_path / 'state')
    auth.configure('cam-test', 'synthetic-password-for-tests-only')
    revision = auth.revision()
    auth.configure('cam-test', 'different-synthetic-passphrase')
    assert auth.revision() != revision
    assert not auth.authenticate('cam-test', 'synthetic-password-for-tests-only')
    assert auth.authenticate('cam-test', 'different-synthetic-passphrase')


def test_short_password_and_invalid_username_are_rejected(tmp_path):
    from custodian.dashboard_auth import DashboardAuth
    auth = DashboardAuth(tmp_path / 'state')
    with pytest.raises(ValueError):
        auth.configure('cam', 'short')
    with pytest.raises(ValueError):
        auth.configure('bad\nuser', 'synthetic-password-for-tests-only')
