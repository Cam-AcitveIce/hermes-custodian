import importlib
from pathlib import Path, PurePosixPath

import pytest


def test_unit_escapes_arguments_and_has_nonrestrictive_hardening():
    service = importlib.import_module('custodian.service')
    unit = service.build_unit(PurePosixPath('/opt/Py thon%/$bin/python'), PurePosixPath('/data/a "b"%/$HOME'))
    assert 'ExecStart="/opt/Py thon%%/$bin/python" -m custodian.cli --state-dir "/data/a \\"b\\"%%/$$HOME" monitor' in unit
    for directive in ('NoNewPrivileges=yes', 'PrivateTmp=yes', 'UMask=0077', 'MemoryMax=192M', 'Restart=on-failure'):
        assert directive in unit
    assert 'ReadOnlyPaths=' not in unit
    assert 'ProtectHome=' not in unit
    assert 'WantedBy=default.target' in unit


@pytest.fixture
def fake_systemctl(tmp_path, monkeypatch):
    if __import__('os').name == 'nt':
        import os
        from custodian import service
        calls = []
        def run(args, **kwargs):
            assert args[0] == 'systemctl'
            calls.append(args[1:])
            return service.subprocess.CompletedProcess(args, int(os.environ.get('CTL_EXIT', '0')),
                stdout=os.environ.get('CTL_OUTPUT', '') + '\n', stderr='')
        monkeypatch.setattr(service.subprocess, 'run', run)
        monkeypatch.setenv('XDG_CONFIG_HOME', str(tmp_path / 'config'))
        return tmp_path, lambda: calls
    import json
    import sys
    executable = tmp_path / 'systemctl'
    log = tmp_path / 'calls.jsonl'
    executable.write_text('#!' + sys.executable + '\nimport json, os, sys\n'
        'with open(os.environ["CALL_LOG"], "a") as f: f.write(json.dumps(sys.argv[1:])+"\\n")\n'
        'print(os.environ.get("CTL_OUTPUT", ""))\n'
        'sys.exit(int(os.environ.get("CTL_EXIT", "0")))\n')
    executable.chmod(0o700)
    monkeypatch.setenv('PATH', str(tmp_path))
    monkeypatch.setenv('CALL_LOG', str(log))
    monkeypatch.setenv('XDG_CONFIG_HOME', str(tmp_path / 'config'))
    return tmp_path, lambda: [json.loads(line) for line in log.read_text().splitlines()]


@pytest.mark.skipif(__import__("os").name == "nt", reason="Linux unit installation requires POSIX descriptor chmod")
def test_install_writes_unit_and_reloads_without_implicit_enable(fake_systemctl):
    service = importlib.import_module('custodian.service')
    root, calls = fake_systemctl
    result = service.install_service(root / 'state', PurePosixPath('/usr/bin/python3'))
    assert result['ok'] is True
    assert (root / 'config/systemd/user' / service.UNIT_NAME).read_text() == service.build_unit(PurePosixPath('/usr/bin/python3'), root / 'state')
    assert calls() == [['--user', 'daemon-reload']]


def test_status_reports_manager_properties_not_just_command_success(fake_systemctl, monkeypatch):
    service = importlib.import_module('custodian.service')
    monkeypatch.setenv('CTL_OUTPUT', 'LoadState=loaded\nActiveState=inactive\nSubState=dead\nUnitFileState=enabled\nExecMainStatus=3\nResult=exit-code')
    result = service.service_status()
    assert result['ok'] is True
    assert result['active'] is False
    assert result['enabled'] is True
    assert result['exec_main_status'] == 3
    assert result['result'] == 'exit-code'


@pytest.mark.skipif(__import__("os").name == "nt", reason="Linux unit installation requires POSIX descriptor chmod")
def test_enable_is_explicit_and_verified(fake_systemctl, monkeypatch):
    service = importlib.import_module('custodian.service')
    root, calls = fake_systemctl
    monkeypatch.setenv('CTL_OUTPUT', 'LoadState=loaded\nActiveState=inactive\nUnitFileState=enabled')
    result = service.install_service(root / 'state', PurePosixPath('/usr/bin/python3'), enable=True)
    assert result['ok'] is True
    assert result['enabled'] is True
    assert calls()[1] == ['--user', 'enable', service.UNIT_NAME]
    assert calls()[2][1] == 'show'
    assert not any('start' in call or '--now' in call for call in calls())


@pytest.mark.skipif(__import__("os").name == "nt", reason="Linux unit installation requires POSIX descriptor chmod")
def test_enable_does_not_claim_success_without_readback(fake_systemctl):
    service = importlib.import_module('custodian.service')
    root, _ = fake_systemctl
    result = service.install_service(root / 'state', PurePosixPath('/usr/bin/python3'), enable=True)
    assert result['ok'] is False


@pytest.mark.parametrize('active,expected', [('inactive', True), ('active', False), ('deactivating', False)])
def test_stop_verifies_child_is_not_running(fake_systemctl, monkeypatch, active, expected):
    service = importlib.import_module('custodian.service')
    monkeypatch.setenv('CTL_OUTPUT', f'ActiveState={active}')
    result = service.stop_service()
    assert result['ok'] is expected
    assert fake_systemctl[1]()[0] == ['--user', 'stop', service.UNIT_NAME]


@pytest.mark.parametrize('properties,expected', [
    ('LoadState=loaded\nActiveState=active\nSubState=running\nExecMainStatus=0\nResult=success', True),
    ('LoadState=loaded\nActiveState=failed\nExecMainStatus=1\nResult=exit-code', False),
    ('LoadState=loaded\nActiveState=active\nExecMainStatus=3\nResult=exit-code', False),
    ('LoadState=loaded\nActiveState=activating\nExecMainStatus=0\nResult=success', False),
    ('ActiveState=active', False),
])
def test_start_verifies_active_and_child_status(fake_systemctl, monkeypatch, properties, expected):
    service = importlib.import_module('custodian.service')
    monkeypatch.setenv('CTL_OUTPUT', properties)
    result = service.start_service()
    assert result['ok'] is expected
    calls = fake_systemctl[1]()
    assert calls[0] == ['--user', 'start', service.UNIT_NAME]
    assert calls[1][1] == 'show'
    assert len(calls) == 2


def test_start_propagates_child_exit_failure_without_installing(fake_systemctl, monkeypatch):
    service = importlib.import_module('custodian.service')
    root, calls = fake_systemctl
    monkeypatch.setenv('CTL_EXIT', '5')
    result = service.start_service()
    assert result['ok'] is False
    assert result['returncode'] == 5
    assert calls() == [['--user', 'start', service.UNIT_NAME]]
    assert not (root / 'config/systemd/user' / service.UNIT_NAME).exists()


def test_stop_propagates_child_exit_failure(fake_systemctl, monkeypatch):
    service = importlib.import_module('custodian.service')
    monkeypatch.setenv('CTL_EXIT', '9')
    result = service.stop_service()
    assert result['ok'] is False
    assert result['returncode'] == 9
    assert len(fake_systemctl[1]()) == 1


def test_uninstall_stops_disables_and_removes_only_unit(fake_systemctl, monkeypatch):
    service = importlib.import_module('custodian.service')
    root, calls = fake_systemctl
    unit = root / 'config/systemd/user' / service.UNIT_NAME
    unit.parent.mkdir(parents=True)
    unit.write_text('fixture')
    state = root / 'state'
    state.mkdir()
    (state / 'keep').write_text('keep')
    monkeypatch.setenv('CTL_OUTPUT', 'ActiveState=inactive\nUnitFileState=disabled')
    result = service.uninstall_service()
    assert result['ok'] is True
    assert not unit.exists()
    assert (state / 'keep').read_text() == 'keep'
    assert ['--user', 'disable', service.UNIT_NAME] in calls()
    assert calls()[-1] == ['--user', 'daemon-reload']


def test_uninstall_keeps_unit_when_stop_fails(fake_systemctl, monkeypatch):
    service = importlib.import_module('custodian.service')
    root, _ = fake_systemctl
    unit = root / 'config/systemd/user' / service.UNIT_NAME
    unit.parent.mkdir(parents=True)
    unit.write_text('fixture')
    monkeypatch.setenv('CTL_EXIT', '5')
    result = service.uninstall_service()
    assert result['ok'] is False
    assert unit.read_text() == 'fixture'


def test_unit_literal_executable_is_accepted_by_systemd_parser(tmp_path):
    import shutil
    import subprocess
    import sys
    if not shutil.which('systemd-analyze'):
        pytest.skip('systemd parser is not installed')
    service = importlib.import_module('custodian.service')
    python = tmp_path / 'py % $literal'
    python.symlink_to(sys.executable)
    unit = tmp_path / service.UNIT_NAME
    unit.write_text(service.build_unit(python, tmp_path / 'state % ${HOME}'))
    child = subprocess.run(['systemd-analyze', '--user', 'verify', '--man=no', str(unit)], capture_output=True, text=True, timeout=15)
    assert child.returncode == 0, child.stderr


def test_empty_status_is_unknown_not_success(fake_systemctl):
    service = importlib.import_module('custodian.service')
    result = service.service_status()
    assert result['ok'] is False
    assert result['active'] is None
    assert result['enabled'] is None


@pytest.mark.parametrize('error', [FileNotFoundError('missing'), PermissionError('denied')])
def test_status_subprocess_unavailable_is_not_inactive(monkeypatch, error):
    service = importlib.import_module('custodian.service')
    def fail(args, **kwargs):
        assert args[0:2] == ['systemctl', '--user']
        assert kwargs['timeout'] == 15
        assert kwargs['env']['LC_ALL'] == 'C'
        assert not kwargs.get('shell')
        raise error
    monkeypatch.setattr(service.subprocess, 'run', fail)
    result = service.service_status()
    assert result['ok'] is False
    assert result['active'] is None
    assert result['returncode'] is None


@pytest.mark.parametrize('state,expected', [('reloading', True), ('refreshing', True), ('activating', None), ('deactivating', None), ('unexpected', None)])
def test_transitional_status_never_claims_inactive(fake_systemctl, monkeypatch, state, expected):
    service = importlib.import_module('custodian.service')
    monkeypatch.setenv('CTL_OUTPUT', f'ActiveState={state}\nUnitFileState=unexpected')
    result = service.service_status()
    assert result['active'] is expected
    assert result['enabled'] is None


def test_status_subprocess_timeout_is_unknown(monkeypatch):
    service = importlib.import_module('custodian.service')
    def fail(args, **kwargs):
        raise service.subprocess.TimeoutExpired(args, kwargs['timeout'])
    monkeypatch.setattr(service.subprocess, 'run', fail)
    result = service.service_status()
    assert result['ok'] is False
    assert result['active'] is None


@pytest.fixture(autouse=True)
def select_linux_backend(monkeypatch):
    from custodian import service
    monkeypatch.setattr(service, 'NAME', 'linux')
