import importlib
from pathlib import Path
import subprocess
import pytest


def test_build_schtasks_argv_pure_builder():
    service = importlib.import_module('custodian.service')
    py = Path('C:/Python311/python.exe')
    state = Path('C:/Users/testuser/AppData/Local/hermes-custodian')
    
    # Enable = True: single /Create command
    cmds_enabled = service.build_schtasks_create_argv(py, state, enable=True)
    assert len(cmds_enabled) == 1
    create_cmd = cmds_enabled[0]
    assert create_cmd[0] == 'schtasks.exe'
    assert create_cmd[1:5] == ['/Create', '/TN', 'HermesCustodianMonitor', '/TR']
    assert create_cmd[5] == f'"{py}" -m custodian.cli --state-dir "{state}" monitor'
    assert create_cmd[6:] == ['/SC', 'ONLOGON', '/RL', 'LIMITED', '/F']
    
    # Enable = False: /Create followed by /Change /DISABLE
    cmds_disabled = service.build_schtasks_create_argv(py, state, enable=False)
    assert len(cmds_disabled) == 2
    assert cmds_disabled[0] == create_cmd
    assert cmds_disabled[1] == ['schtasks.exe', '/Change', '/TN', 'HermesCustodianMonitor', '/DISABLE']
    
    # Path validation
    with pytest.raises(ValueError):
        service.build_schtasks_create_argv(Path('relative/python.exe'), state)
    with pytest.raises(ValueError):
        service.build_schtasks_create_argv(py, Path('C:/bad\x01path'))


@pytest.fixture
def fake_schtasks(tmp_path, monkeypatch):
    calls = []
    
    def fake_run(args, **kwargs):
        calls.append(list(args))
        cmd = args[1] if len(args) > 1 else ''
        if cmd == '/Query':
            out = kwargs.get('env', {}).get('QUERY_OUT', 'TaskName: HermesCustodianMonitor\nStatus: Ready\nScheduled Task State: Disabled\nLast Result: 0\n')
            return subprocess.CompletedProcess(args, 0, stdout=out, stderr='')
        return subprocess.CompletedProcess(args, 0, stdout='', stderr='')
        
    service = importlib.import_module('custodian.service')
    monkeypatch.setattr(service.subprocess, 'run', fake_run)
    monkeypatch.setattr(service, 'NAME', 'windows')
    return tmp_path, lambda: list(calls)


def test_install_service_windows_with_enable(fake_schtasks):
    tmp_path, get_calls = fake_schtasks
    service = importlib.import_module('custodian.service')
    
    # Mock query output to show enabled
    def fake_run(args, **kwargs):
        get_calls  # just record
        if args[1] == '/Query':
            out = 'TaskName: HermesCustodianMonitor\nStatus: Ready\nScheduled Task State: Enabled\nLast Result: 0\n'
            return subprocess.CompletedProcess(args, 0, stdout=out, stderr='')
        return subprocess.CompletedProcess(args, 0, stdout='', stderr='')
        
    service.subprocess.run = fake_run
    
    state = Path('C:/data/state')
    py = Path('C:/data/py.exe')
    res = service.install_service(state, py, enable=True)
    assert res['ok'] is True
    assert res['installed'] is True
    assert res['enabled'] is True


def test_install_service_windows_without_enable(fake_schtasks, monkeypatch):
    tmp_path, get_calls = fake_schtasks
    service = importlib.import_module('custodian.service')
    
    calls = []
    def fake_run(args, **kwargs):
        calls.append(list(args))
        if args[1] == '/Query':
            out = 'TaskName: HermesCustodianMonitor\nStatus: Ready\nScheduled Task State: Disabled\nLast Result: 0\n'
            return subprocess.CompletedProcess(args, 0, stdout=out, stderr='')
        return subprocess.CompletedProcess(args, 0, stdout='', stderr='')
        
    monkeypatch.setattr(service.subprocess, 'run', fake_run)
    
    state = Path('C:/data/state')
    py = Path('C:/data/py.exe')
    res = service.install_service(state, py, enable=False)
    assert res['ok'] is True
    assert res['installed'] is True
    assert res['enabled'] is False
    
    # Must have called /Create then /Change /DISABLE
    assert any('/Create' in c for c in calls)
    assert any('/Change' in c and '/DISABLE' in c for c in calls)


def test_windows_service_status_parsing_defensive(monkeypatch):
    service = importlib.import_module('custodian.service')
    monkeypatch.setattr(service, 'NAME', 'windows')
    
    sample_query = (
        "Folder: \\\n"
        "HostName: WINPC\n"
        "TaskName: \\HermesCustodianMonitor\n"
        "Status: Running\n"
        "Scheduled Task State: Enabled\n"
        "Last Result: 0\n"
    )
    def fake_run(args, **kwargs):
        return subprocess.CompletedProcess(args, 0, stdout=sample_query, stderr='')
        
    monkeypatch.setattr(service.subprocess, 'run', fake_run)
    status = service.service_status()
    assert status['ok'] is True
    assert status['active'] is True
    assert status['enabled'] is True
    assert status['exec_main_status'] == 0


def test_start_service_windows(monkeypatch):
    service = importlib.import_module('custodian.service')
    monkeypatch.setattr(service, 'NAME', 'windows')
    
    calls = []
    def fake_run(args, **kwargs):
        calls.append(list(args))
        if args[1] == '/Query':
            out = 'TaskName: HermesCustodianMonitor\nStatus: Running\nScheduled Task State: Enabled\nLast Result: 0\n'
            return subprocess.CompletedProcess(args, 0, stdout=out, stderr='')
        return subprocess.CompletedProcess(args, 0, stdout='', stderr='')
        
    monkeypatch.setattr(service.subprocess, 'run', fake_run)
    res = service.start_service()
    assert res['ok'] is True
    assert any('/Run' in c for c in calls)


def test_stop_service_windows(monkeypatch):
    service = importlib.import_module('custodian.service')
    monkeypatch.setattr(service, 'NAME', 'windows')
    
    calls = []
    def fake_run(args, **kwargs):
        calls.append(list(args))
        if args[1] == '/Query':
            out = 'TaskName: HermesCustodianMonitor\nStatus: Ready\nScheduled Task State: Enabled\nLast Result: 0\n'
            return subprocess.CompletedProcess(args, 0, stdout=out, stderr='')
        return subprocess.CompletedProcess(args, 0, stdout='', stderr='')
        
    monkeypatch.setattr(service.subprocess, 'run', fake_run)
    res = service.stop_service()
    assert res['ok'] is True
    assert any('/End' in c for c in calls)


def test_uninstall_service_windows(monkeypatch):
    service = importlib.import_module('custodian.service')
    monkeypatch.setattr(service, 'NAME', 'windows')
    
    calls = []
    def fake_run(args, **kwargs):
        calls.append(list(args))
        return subprocess.CompletedProcess(args, 0, stdout='', stderr='')
        
    monkeypatch.setattr(service.subprocess, 'run', fake_run)
    res = service.uninstall_service()
    assert res['ok'] is True
    assert res['removed'] is True
    assert any('/Delete' in c and '/F' in c for c in calls)


def test_windows_missing_tool_returns_unsupported(monkeypatch):
    service = importlib.import_module('custodian.service')
    monkeypatch.setattr(service, 'NAME', 'windows')
    
    def fake_run(args, **kwargs):
        raise FileNotFoundError('schtasks.exe not found')
        
    monkeypatch.setattr(service.subprocess, 'run', fake_run)
    res = service.service_status()
    assert res['ok'] is False
    assert res['error'] == 'unsupported on this system'
