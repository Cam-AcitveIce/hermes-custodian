import importlib
import json
import platform
import subprocess
import pytest


def test_security_policy_unsupported_on_windows(monkeypatch):
    updates = importlib.import_module('custodian.updates')
    monkeypatch.setattr(updates, 'NAME', 'windows')
    
    plan = updates.plan_security_updates(True)
    assert plan == {'status': 'unsupported', 'changed': False, 'error': 'Security-update automation is Linux-only'}
    
    apply_res = updates.apply_security_update_policy({}, 'APPLY')
    assert apply_res == {'status': 'unsupported', 'changed': False, 'error': 'Security-update automation is Linux-only'}
    
    config_res = updates.configure_security_updates(True, trusted_cli=True)
    assert config_res == {'status': 'unsupported', 'changed': False, 'error': 'Security-update automation is Linux-only'}


def test_check_updates_windows_powershell_invocation_and_parsing(monkeypatch):
    updates = importlib.import_module('custodian.updates')
    monkeypatch.setattr(updates, 'NAME', 'windows')
    
    sample_json = json.dumps([
        {
            'Title': 'Security Update for Windows (KB5001234)',
            'KB': '5001234',
            'Categories': ['Security Updates', 'Windows 11'],
            'MsrcSeverity': 'Critical',
        },
        {
            'Title': 'Update for Windows (KB5005678)',
            'KB': '5005678',
            'Categories': ['Updates'],
            'MsrcSeverity': 'Important',
        },
        {
            'Title': 'Device Driver Update',
            'KB': '',
            'Categories': ['Drivers'],
            'MsrcSeverity': '',
        },
    ])
    
    called = []
    def fake_run(args, **kwargs):
        called.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0, stdout=sample_json, stderr='')
        
    monkeypatch.setattr(updates.subprocess, 'run', fake_run)
    
    result = updates.check_updates()
    assert result['status'] == 'ok'
    assert result['backend'] == 'windowsupdate'
    assert result['upgradable_count'] == 3
    assert result['security_count'] == 2
    assert result['security_unknown_count'] == 1
    
    pkgs = result['packages']
    assert len(pkgs) == 3
    assert pkgs[0]['name'] == 'Security Update for Windows (KB5001234)'
    assert pkgs[0]['candidate_version'] == '5001234'
    assert pkgs[0]['installed_version'] is None
    assert pkgs[0]['architecture'] == platform.machine()
    assert pkgs[0]['security'] is True
    assert pkgs[0]['suites'] == ['Security Updates', 'Windows 11']
    
    assert pkgs[1]['security'] is True
    assert pkgs[2]['security'] is None
    assert pkgs[2]['candidate_version'] == 'Device Driver Update'
    
    assert called[0][0][0] == 'powershell.exe'
    assert called[0][0][1:6] == ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command']
    command_str = called[0][0][6]
    assert 'Microsoft.Update.Session' in command_str
    assert 'CreateUpdateSearcher' in command_str
    assert 'IsInstalled=0 and IsHidden=0' in command_str
    assert 'ConvertTo-Json' in command_str
    assert called[0][1]['timeout'] == 90
    assert not called[0][1].get('shell')


def test_check_updates_windows_single_object_json(monkeypatch):
    updates = importlib.import_module('custodian.updates')
    monkeypatch.setattr(updates, 'NAME', 'windows')
    
    sample_json = json.dumps({
        'Title': 'Standalone Hotfix (KB9999999)',
        'KB': '9999999',
        'Categories': ['Hotfix'],
        'MsrcSeverity': None,
    })
    
    def fake_run(args, **kwargs):
        return subprocess.CompletedProcess(args, 0, stdout=sample_json, stderr='')
        
    monkeypatch.setattr(updates.subprocess, 'run', fake_run)
    
    result = updates.check_updates()
    assert result['status'] == 'ok'
    assert result['upgradable_count'] == 1
    assert result['packages'][0]['security'] is None
    assert result['packages'][0]['candidate_version'] == '9999999'


def test_check_updates_windows_empty_updates(monkeypatch):
    updates = importlib.import_module('custodian.updates')
    monkeypatch.setattr(updates, 'NAME', 'windows')
    
    def fake_run(args, **kwargs):
        return subprocess.CompletedProcess(args, 0, stdout='', stderr='')
        
    monkeypatch.setattr(updates.subprocess, 'run', fake_run)
    
    result = updates.check_updates()
    assert result['status'] == 'ok'
    assert result['packages'] == []
    assert result['upgradable_count'] == 0
    assert result['security_count'] == 0
    assert result['security_unknown_count'] == 0


@pytest.mark.parametrize('kind', ['missing', 'timeout', 'nonzero', 'bad_json'])
def test_check_updates_windows_failures(monkeypatch, kind):
    updates = importlib.import_module('custodian.updates')
    monkeypatch.setattr(updates, 'NAME', 'windows')
    
    def fake_run(args, **kwargs):
        if kind == 'missing':
            raise FileNotFoundError('powershell.exe not found')
        if kind == 'timeout':
            raise subprocess.TimeoutExpired(args, kwargs.get('timeout', 90))
        if kind == 'nonzero':
            return subprocess.CompletedProcess(args, 1, stdout='', stderr='HRESULT 0x80240020')
        return subprocess.CompletedProcess(args, 0, stdout='[Not Valid JSON]', stderr='')
        
    monkeypatch.setattr(updates.subprocess, 'run', fake_run)
    
    result = updates.check_updates()
    assert result['status'] == 'unavailable'
    assert result['packages'] == []
    assert result['error']
