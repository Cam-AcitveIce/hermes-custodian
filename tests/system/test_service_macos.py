import importlib
import plistlib
from pathlib import Path, PurePosixPath
import subprocess
import pytest


def test_build_macos_plist_keys_and_hardening():
    service = importlib.import_module('custodian.service')
    py = PurePosixPath('/usr/local/bin/python3')
    state = PurePosixPath('/Users/testuser/.local/state/hermes-custodian')
    
    # Test with enable=False
    plist = service.build_macos_plist(py, state, enable=False)
    assert plist['Label'] == 'com.hermes.custodian'
    assert plist['ProgramArguments'] == [str(py), '-m', 'custodian.cli', '--state-dir', str(state), 'monitor']
    assert plist['KeepAlive'] is False
    assert plist['ProcessType'] == 'Background'
    assert plist['StandardOutPath'] == str(state / 'monitor.stdout.log')
    assert plist['StandardErrorPath'] == str(state / 'monitor.stderr.log')
    assert 'PATH' in plist['EnvironmentVariables']
    assert plist.get('RunAtLoad') is not True
    
    # Test with enable=True
    plist_enabled = service.build_macos_plist(py, state, enable=True)
    assert plist_enabled['RunAtLoad'] is True
    
    # Test validation: relative paths or control characters
    with pytest.raises(ValueError):
        service.build_macos_plist(Path('relative/python'), state)
    with pytest.raises(ValueError):
        service.build_macos_plist(py, PurePosixPath('/bad\x01path'))


@pytest.fixture
def fake_launchctl(tmp_path, monkeypatch):
    import json
    import sys
    if sys.platform == "win32":
        pytest.skip("LaunchAgent installation uses POSIX descriptor chmod")
    calls = []
    
    # Redirect HOME to tmp_path so ~/Library/LaunchAgents is isolated
    monkeypatch.setenv('HOME', str(tmp_path))
    monkeypatch.setattr(Path, 'home', lambda: tmp_path)
    
    def fake_run(args, **kwargs):
        calls.append(list(args))
        if args[0] != 'launchctl':
            return subprocess.CompletedProcess(args, 1, stdout='', stderr='not launchctl')
        cmd = args[1]
        if cmd == 'print':
            out = os_environ_get = kwargs.get('env', {}).get('PRINT_OUT', 'state = not running\nlast exit code = 0')
            return subprocess.CompletedProcess(args, 0, stdout=out, stderr='')
        if cmd == 'bootstrap':
            return subprocess.CompletedProcess(args, 0, stdout='', stderr='')
        if cmd == 'kickstart':
            return subprocess.CompletedProcess(args, 0, stdout='', stderr='')
        if cmd == 'bootout':
            return subprocess.CompletedProcess(args, 0, stdout='', stderr='')
        return subprocess.CompletedProcess(args, 0, stdout='', stderr='')
        
    service = importlib.import_module('custodian.service')
    monkeypatch.setattr(service.subprocess, 'run', fake_run)
    monkeypatch.setattr(service, 'NAME', 'macos')
    return tmp_path, lambda: list(calls)


def test_install_service_macos_writes_plist_mode_0600(fake_launchctl):
    tmp_path, get_calls = fake_launchctl
    service = importlib.import_module('custodian.service')
    
    state = tmp_path / 'state'
    state.mkdir()
    py = PurePosixPath('/usr/bin/python3')
    
    res = service.install_service(state, py, enable=False)
    assert res['ok'] is True
    assert res['installed'] is True
    plist_path = tmp_path / 'Library/LaunchAgents/com.hermes.custodian.plist'
    assert plist_path.exists()
    assert (plist_path.stat().st_mode & 0o777) == 0o600
    
    # Verify content
    data = plistlib.loads(plist_path.read_bytes())
    assert data['Label'] == 'com.hermes.custodian'
    assert data.get('RunAtLoad') is not True
    # When enable=False, install must never start or enable
    assert not any('kickstart' in c for c in get_calls())
    assert not any('bootstrap' in c for c in get_calls())


def test_install_service_macos_with_enable(fake_launchctl):
    tmp_path, get_calls = fake_launchctl
    service = importlib.import_module('custodian.service')
    
    state = tmp_path / 'state'
    state.mkdir()
    py = PurePosixPath('/usr/bin/python3')
    
    res = service.install_service(state, py, enable=True)
    assert res['ok'] is True
    assert res['installed'] is True
    assert res['enabled'] is True
    
    plist_path = tmp_path / 'Library/LaunchAgents/com.hermes.custodian.plist'
    data = plistlib.loads(plist_path.read_bytes())
    assert data['RunAtLoad'] is True
    
    calls = get_calls()
    assert any(c[0] == 'launchctl' and c[1] == 'bootstrap' for c in calls)
    assert not any('kickstart' in c for c in calls)


def test_macos_service_status_parsing(monkeypatch):
    service = importlib.import_module('custodian.service')
    monkeypatch.setattr(service, 'NAME', 'macos')
    
    def fake_run(args, **kwargs):
        assert args[0] == 'launchctl'
        assert args[1] == 'print'
        out = "state = running\npid = 4321\nlast exit code = 0\n"
        return subprocess.CompletedProcess(args, 0, stdout=out, stderr='')
        
    monkeypatch.setattr(service.subprocess, 'run', fake_run)
    status = service.service_status()
    assert status['ok'] is True
    assert status['active'] is True
    assert status['exec_main_status'] == 0


def test_start_service_macos(fake_launchctl, monkeypatch):
    tmp_path, _ = fake_launchctl
    service = importlib.import_module('custodian.service')
    
    calls = []
    def fake_run(args, **kwargs):
        calls.append(list(args))
        if args[1] == 'print':
            return subprocess.CompletedProcess(args, 0, stdout="state = running\nlast exit code = 0\n", stderr='')
        return subprocess.CompletedProcess(args, 0, stdout='', stderr='')
        
    monkeypatch.setattr(service.subprocess, 'run', fake_run)
    
    res = service.start_service()
    assert res['ok'] is True
    assert any(c[0] == 'launchctl' and c[1] == 'kickstart' for c in calls)


def test_stop_service_macos(fake_launchctl, monkeypatch):
    tmp_path, _ = fake_launchctl
    service = importlib.import_module('custodian.service')
    
    calls = []
    def fake_run(args, **kwargs):
        calls.append(list(args))
        if args[1] == 'print':
            return subprocess.CompletedProcess(args, 0, stdout="state = not running\nlast exit code = 0\n", stderr='')
        return subprocess.CompletedProcess(args, 0, stdout='', stderr='')
        
    monkeypatch.setattr(service.subprocess, 'run', fake_run)
    
    res = service.stop_service()
    assert res['ok'] is True
    assert any(c[0] == 'launchctl' and c[1] == 'bootout' for c in calls)


def test_uninstall_service_macos(fake_launchctl):
    tmp_path, get_calls = fake_launchctl
    service = importlib.import_module('custodian.service')
    
    plist_path = tmp_path / 'Library/LaunchAgents/com.hermes.custodian.plist'
    plist_path.parent.mkdir(parents=True, exist_ok=True)
    plist_path.write_text('dummy')
    
    res = service.uninstall_service()
    assert res['ok'] is True
    assert res['removed'] is True
    assert not plist_path.exists()


def test_macos_missing_tool_returns_unsupported(monkeypatch):
    service = importlib.import_module('custodian.service')
    monkeypatch.setattr(service, 'NAME', 'macos')
    
    def fake_run(args, **kwargs):
        raise FileNotFoundError('launchctl not found')
        
    monkeypatch.setattr(service.subprocess, 'run', fake_run)
    res = service.service_status()
    assert res['ok'] is False
    assert res['error'] == 'unsupported on this system'
