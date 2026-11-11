import importlib
import platform
import subprocess
import pytest


def test_security_policy_unsupported_on_macos(monkeypatch):
    updates = importlib.import_module('custodian.updates')
    monkeypatch.setattr(updates, 'NAME', 'macos')
    
    plan = updates.plan_security_updates(True)
    assert plan == {'status': 'unsupported', 'changed': False, 'error': 'Security-update automation is Linux-only'}
    
    apply_res = updates.apply_security_update_policy({}, 'APPLY')
    assert apply_res == {'status': 'unsupported', 'changed': False, 'error': 'Security-update automation is Linux-only'}
    
    config_res = updates.configure_security_updates(True, trusted_cli=True)
    assert config_res == {'status': 'unsupported', 'changed': False, 'error': 'Security-update automation is Linux-only'}


def test_check_updates_macos_parses_softwareupdate_output(monkeypatch):
    updates = importlib.import_module('custodian.updates')
    monkeypatch.setattr(updates, 'NAME', 'macos')
    
    sample_output = (
        "Software Update Tool\n\n"
        "Finding available software\n"
        "Software Update found the following new or updated software:\n"
        "* Label: Safari16.6-16.6\n"
        "\tTitle: Safari, Version: 16.6, Size: 123456K, Recommended: YES,\n"
        "* Label: Command Line Tools for Xcode-14.3\n"
        "\tTitle: Command Line Tools for Xcode, Version: 14.3, Recommended: YES,\n"
    )
    
    called = []
    def fake_run(args, **kwargs):
        called.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0, stdout=sample_output, stderr='')
        
    monkeypatch.setattr(updates.subprocess, 'run', fake_run)
    
    result = updates.check_updates()
    assert result['status'] == 'ok'
    assert result['backend'] == 'softwareupdate'
    assert result['upgradable_count'] == 2
    assert result['security_count'] == 0
    assert result['security_unknown_count'] == 2
    assert len(result['packages']) == 2
    
    assert result['packages'][0] == {
        'name': 'Safari16.6-16.6',
        'candidate_version': '16.6',
        'installed_version': None,
        'architecture': platform.machine(),
        'suites': ['softwareupdate'],
        'security': None,
    }
    assert result['packages'][1] == {
        'name': 'Command Line Tools for Xcode-14.3',
        'candidate_version': '14.3',
        'installed_version': None,
        'architecture': platform.machine(),
        'suites': ['softwareupdate'],
        'security': None,
    }
    
    assert called[0][0] == ['softwareupdate', '-l']
    assert called[0][1]['timeout'] == 60
    assert not called[0][1].get('shell')


def test_check_updates_macos_empty_output(monkeypatch):
    updates = importlib.import_module('custodian.updates')
    monkeypatch.setattr(updates, 'NAME', 'macos')
    
    sample_output = "Software Update Tool\n\nFinding available software\nNo new software available.\n"
    
    def fake_run(args, **kwargs):
        return subprocess.CompletedProcess(args, 0, stdout=sample_output, stderr='')
        
    monkeypatch.setattr(updates.subprocess, 'run', fake_run)
    
    result = updates.check_updates()
    assert result['status'] == 'ok'
    assert result['packages'] == []
    assert result['upgradable_count'] == 0
    assert result['security_count'] == 0
    assert result['security_unknown_count'] == 0


@pytest.mark.parametrize('kind', ['missing', 'timeout', 'nonzero'])
def test_check_updates_macos_failures(monkeypatch, kind):
    updates = importlib.import_module('custodian.updates')
    monkeypatch.setattr(updates, 'NAME', 'macos')
    
    def fake_run(args, **kwargs):
        if kind == 'missing':
            raise FileNotFoundError('softwareupdate not found')
        if kind == 'timeout':
            raise subprocess.TimeoutExpired(args, kwargs.get('timeout', 60))
        return subprocess.CompletedProcess(args, 1, stdout='', stderr='Software update server error')
        
    monkeypatch.setattr(updates.subprocess, 'run', fake_run)
    
    result = updates.check_updates()
    assert result['status'] == 'unavailable'
    assert result['packages'] == []
    assert result['error']
