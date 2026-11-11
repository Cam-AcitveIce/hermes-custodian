import importlib
import json
import sys

import pytest


@pytest.fixture
def fake_apt(tmp_path, monkeypatch):
    executable = tmp_path / 'apt'
    log = tmp_path / 'apt.json'
    executable.write_text('#!' + sys.executable + '\nimport os, sys, json\n'
        'with open(os.environ["APT_LOG"], "w") as f: json.dump({"args":sys.argv[1:], "locale":os.environ.get("LC_ALL")}, f)\n'
        'print(os.environ.get("APT_OUTPUT", "Listing..."))\n'
        'sys.exit(int(os.environ.get("APT_EXIT", "0")))\n')
    executable.chmod(0o700)
    monkeypatch.setenv('PATH', str(tmp_path))
    monkeypatch.setenv('APT_LOG', str(log))
    return lambda: json.loads(log.read_text())


def test_detects_native_cached_upgrades_without_refresh(fake_apt, monkeypatch):
    updates = importlib.import_module('custodian.updates')
    monkeypatch.setenv('APT_OUTPUT', 'Listing... Done\nopenssl/stable-security 3.0.18-1 arm64 [upgradable from: 3.0.17-1]\nnano/stable 8.0-1 arm64 [upgradable from: 7.0-1]')
    result = updates.check_updates()
    assert result['status'] == 'ok'
    assert result['upgradable_count'] == 2
    assert result['security_count'] == 1
    assert result['security_unknown_count'] == 1
    assert result['packages'][0] == {'name': 'openssl', 'candidate_version': '3.0.18-1', 'installed_version': '3.0.17-1', 'architecture': 'arm64', 'suites': ['stable-security'], 'security': True}
    assert result['packages'][1]['security'] is None
    assert result['cache_only'] is True
    assert fake_apt() == {'args': ['list', '--upgradable'], 'locale': 'C'}


def test_nonzero_apt_exit_does_not_report_partial_counts(fake_apt, monkeypatch):
    updates = importlib.import_module('custodian.updates')
    monkeypatch.setenv('APT_EXIT', '100')
    monkeypatch.setenv('APT_OUTPUT', 'openssl/stable-security 3.0.18-1 arm64 [upgradable from: 3.0.17-1]')
    result = updates.check_updates()
    assert result['status'] == 'failed'
    assert result['returncode'] == 100
    assert result['upgradable_count'] is None
    assert result['security_count'] is None



@pytest.mark.parametrize('kind,expected', [('missing', 'unavailable'), ('timeout', 'failed'), ('permission', 'unavailable')])
def test_apt_process_errors_are_truthful(monkeypatch, kind, expected):
    updates = importlib.import_module('custodian.updates')
    def fail(args, **kwargs):
        assert args == ['apt', 'list', '--upgradable']
        assert kwargs['timeout'] == 30
        assert kwargs['check'] is False
        assert not kwargs.get('shell')
        assert kwargs['env']['LC_ALL'] == 'C'
        if kind == 'timeout':
            raise updates.subprocess.TimeoutExpired(args, kwargs['timeout'])
        if kind == 'permission':
            raise PermissionError('not executable')
        raise FileNotFoundError('apt unavailable')
    monkeypatch.setattr(updates.subprocess, 'run', fail)
    result = updates.check_updates()
    assert result['status'] == expected
    assert result['upgradable_count'] is None
    assert result['security_count'] is None


@pytest.mark.parametrize('output', ['', 'unrecognized output', 'Listing... Done\nlibc6/stable 2.0 arm64 [unexpected format]'])
def test_unrecognized_listing_is_unknown_not_zero(fake_apt, monkeypatch, output):
    updates = importlib.import_module('custodian.updates')
    monkeypatch.setenv('APT_OUTPUT', output)
    result = updates.check_updates()
    assert result['status'] == 'unknown'
    assert result['upgradable_count'] is None


def test_empty_listing_is_known_zero(fake_apt):
    updates = importlib.import_module('custodian.updates')
    result = updates.check_updates()
    assert result['status'] == 'ok'
    assert result['upgradable_count'] == 0


@pytest.mark.parametrize('enabled', [False, True])
def test_configure_security_updates_denies_untrusted_callers_without_subprocess(monkeypatch, enabled):
    updates = importlib.import_module('custodian.updates')
    def forbidden(*args, **kwargs):
        pytest.fail('No subprocess may run when trusted_cli is False')
    monkeypatch.setattr(updates.subprocess, 'run', forbidden)
    result = updates.configure_security_updates(enabled, trusted_cli=False)
    assert result['status'] == 'denied'
    assert result['changed'] is False
    assert result['enabled'] is None


def test_configure_security_updates_wraps_plan_and_apply_for_trusted_cli(monkeypatch):
    updates = importlib.import_module('custodian.updates')
    seen = []
    fake_plan = {'status': 'ready', 'enabled': True, 'plan_id': 'a' * 64}
    monkeypatch.setattr(updates, 'plan_security_updates', lambda enabled: (seen.append(('plan', enabled)) or fake_plan))
    monkeypatch.setattr(updates, 'apply_security_update_policy',
                        lambda plan, approval: (seen.append(('apply', plan, approval)) or {'status': 'applied', 'changed': True, 'enabled': True}))
    assert updates.configure_security_updates(True, trusted_cli=True) == fake_plan
    assert updates.configure_security_updates(False, trusted_cli=True, plan=fake_plan, approval='APPLY')['status'] == 'mismatch'
    applied = updates.configure_security_updates(True, trusted_cli=True, plan=fake_plan, approval='APPLY SECURITY POLICY ' + 'a' * 64)
    assert applied['status'] == 'applied'
    assert seen == [('plan', True), ('apply', fake_plan, 'APPLY SECURITY POLICY ' + 'a' * 64)]


def test_import_updates_succeeds_on_win32_with_fcntl_blocked(monkeypatch):
    import sys
    monkeypatch.setattr(sys, 'platform', 'win32')
    monkeypatch.setitem(sys.modules, 'fcntl', None)
    monkeypatch.delitem(sys.modules, 'custodian.updates', raising=False)
    import custodian.updates
    assert custodian.updates is not None
