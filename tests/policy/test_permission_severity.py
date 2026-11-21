"""Permission triage describes mode evidence, never proven effective access."""
import pytest

from custodian._platform import posix


@pytest.mark.parametrize('mode,severity,basis', [
    (0o600, None, None),
    (0o640, 'low', 'group_read_execute_or_other_execute'),
    (0o644, 'medium', 'group_write_or_other_read'),
    (0o660, 'medium', 'group_write_or_other_read'),
    (0o664, 'medium', 'group_write_or_other_read'),
    (0o666, 'high', 'other_write_potential_tamper'),
    (0o700, None, None),
    (0o710, 'low', 'group_read_execute_or_other_execute'),
    (0o755, 'medium', 'group_write_or_other_read'),
    (0o775, 'medium', 'group_write_or_other_read'),
    (0o777, 'high', 'other_write_potential_tamper'),
])
def test_mode_evidence_tiers(mode, severity, basis):
    exposure = posix.access_exposure({'mode': mode})
    if severity is None:
        assert exposure is None
        return
    assert exposure is not None
    assert exposure['severity'] == severity
    assert exposure['mode'] == mode
    assert exposure['severity_basis'] == basis
    assert exposure['access_verified'] is False
    assert 'mode' in exposure['summary'].lower()
    assert 'effective access unknown' in exposure['summary'].lower()
    assert 'exposed_to' not in exposure


@pytest.mark.parametrize('mode', range(0o1000))
def test_all_modes_preserve_coverage_without_access_claims(mode, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('Mode triage must not resolve effective access')
    monkeypatch.setattr(posix.os, 'access', forbidden)
    monkeypatch.setattr(posix, '_group_is_private', forbidden)
    exposure = posix.access_exposure({'mode': mode, 'path': '/not-inspected/.env'})
    assert (exposure is not None) == bool(mode & 0o077)
    if exposure:
        expected = 'high' if mode & 0o002 else 'medium' if mode & 0o024 else 'low'
        assert exposure['severity'] == expected
        assert exposure['access_verified'] is False


@pytest.mark.skipif(__import__('os').name == 'nt', reason='POSIX fixture')
def test_engine_versions_mode_evidence_and_preserves_history(tmp_path, monkeypatch):
    from custodian import _platform
    from custodian.engine import Engine
    import hashlib

    scope = tmp_path / 'scope'
    scope.mkdir()
    secret = scope / '.env'
    secret.write_text('SYNTHETIC TEST FIXTURE')
    secret.chmod(0o640)
    engine = Engine(tmp_path / 'state')
    engine.setup({'watched_paths': [str(scope)], 'check_permissions': True})
    # Seed a legacy finding through the old backend contract.
    with monkeypatch.context() as patch:
        patch.setattr(_platform, 'access_exposure', lambda item: {'mode': 0o640})
        legacy = engine.scan()['findings'][0]
    assert legacy['severity'] == 'high'
    finding = engine.scan()['findings'][0]
    assert finding['severity'] == 'low'
    assert finding['evidence'] == {
        'mode': '0o640', 'assessment_version': 2,
        'severity_basis': 'group_read_execute_or_other_execute',
        'access_verified': False,
    }
    assert finding['id'] == legacy['id'] == hashlib.sha256(
        ('sensitive_permissions:' + str(secret)).encode()).hexdigest()
    stored = engine.findings()[0]
    assert stored['first_seen'] == legacy['first_seen']
    assert stored['status'] == 'open'
    recommendation = finding['recommendation'].lower()
    for term in ('group', 'parent', 'acl', 'effective access', 'unknown'):
        assert term in recommendation
    assert 'chmod' not in recommendation
    assert not any(e['kind'] == 'finding_resolved' for e in engine.events())
