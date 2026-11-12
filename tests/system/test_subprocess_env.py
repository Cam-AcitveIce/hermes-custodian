"""Every production child process gets an explicit, minimal, allowlisted environment.

All values here are synthetic fixtures. Nothing reads a real credential: the
parent environment is emptied first and repopulated with fake markers.
"""
import ast
import importlib
import os
from pathlib import Path
import subprocess

import pytest

from custodian import _subprocess_env as envmod

POSIX_PATH = '/usr/sbin:/usr/bin:/sbin:/bin'
POSIX_BASE = {'PATH': POSIX_PATH, 'LC_ALL': 'C', 'LANG': 'C'}

# Fake markers only. Names mirror the classes of variable that must never leak.
FAKE_SECRETS = {
    'ANTHROPIC_API_KEY': 'fixture-not-a-real-key-1',
    'OPENAI_API_KEY': 'fixture-not-a-real-key-2',
    'OPENROUTER_API_KEY': 'fixture-not-a-real-key-3',
    'AWS_SECRET_ACCESS_KEY': 'fixture-not-a-real-key-4',
    'GITHUB_TOKEN': 'fixture-not-a-real-token',
    'HTTPS_PROXY': 'http://fixture-user:fixture-pass@proxy.invalid:8080',
    'http_proxy': 'http://fixture-user:fixture-pass@proxy.invalid:8080',
    'ALL_PROXY': 'socks5://fixture-user:fixture-pass@proxy.invalid:1080',
    'PYTHONPATH': '/fixture/unsafe/pythonpath',
    'PYTHONSTARTUP': '/fixture/unsafe/startup.py',
    'LD_PRELOAD': '/fixture/unsafe/preload.so',
    'LD_LIBRARY_PATH': '/fixture/unsafe/lib',
    'DYLD_INSERT_LIBRARIES': '/fixture/unsafe/insert.dylib',
    'DYLD_LIBRARY_PATH': '/fixture/unsafe/dyld',
    'APT_CONFIG': '/fixture/unsafe/apt.conf',
    'SYSTEMD_PAGER': '/fixture/unsafe/pager',
    'PSModulePath': 'C:\\fixture\\unsafe\\modules',
    'PATHEXT': '.FIXTURE',
    'ComSpec': 'C:\\fixture\\unsafe\\cmd.exe',
    'HERMES_HOME': '/fixture/hermes-home',
    'UNRELATED_PARENT_VAR': 'fixture-unrelated',
}
UNSAFE_PATH = '/fixture/unsafe/bin:/fixture/secret-token-in-path'

WIN_ROOT = 'D:\\WinNT'
WIN_PATH = ';'.join([
    WIN_ROOT + '\\System32',
    WIN_ROOT,
    WIN_ROOT + '\\System32\\Wbem',
    WIN_ROOT + '\\System32\\WindowsPowerShell\\v1.0',
])
WIN_BASE = {
    'SystemRoot': WIN_ROOT, 'WINDIR': WIN_ROOT, 'SystemDrive': 'D:',
    'TEMP': 'D:\\Scratch\\t', 'TMP': 'D:\\Scratch\\t', 'PATH': WIN_PATH,
}
WIN_PROFILE = {
    'USERPROFILE': 'D:\\Users\\fixture',
    'LOCALAPPDATA': 'D:\\Users\\fixture\\AppData\\Local',
    'APPDATA': 'D:\\Users\\fixture\\AppData\\Roaming',
    'ProgramData': 'D:\\ProgramData',
}


@pytest.fixture
def parent(monkeypatch):
    """Empty the parent environment, then plant fake secrets and an unsafe PATH."""
    for key in list(os.environ):
        monkeypatch.delenv(key, raising=False)
    for key, value in FAKE_SECRETS.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv('PATH', UNSAFE_PATH)
    return monkeypatch.setenv


@pytest.fixture
def capture(monkeypatch):
    """Record subprocess.run calls made through the service and updates modules."""
    service = importlib.import_module('custodian.service')
    updates = importlib.import_module('custodian.updates')
    seen = []

    def run(args, **kwargs):
        seen.append((list(args), kwargs))
        return subprocess.CompletedProcess(args, 0, stdout='', stderr='')
    monkeypatch.setattr(service.subprocess, 'run', run)
    monkeypatch.setattr(updates.subprocess, 'run', run)
    return seen


def _assert_no_leak(env):
    assert all(type(k) is str and type(v) is str for k, v in env.items())
    lowered = {key.lower() for key in env}
    for key, value in FAKE_SECRETS.items():
        assert key.lower() not in lowered
        assert value not in env.values()
    assert 'fixture/unsafe' not in env['PATH'] and 'secret-token' not in env['PATH']


def _plant_windows(setenv, *, mixed_case):
    values = {**{k: v for k, v in WIN_BASE.items() if k != 'PATH'}, **WIN_PROFILE}
    for index, (key, value) in enumerate(values.items()):
        # Windows names are case-insensitive: SYSTEMROOT, systemroot and
        # SystemRoot are the same variable and must all be recognised.
        name = (key.lower() if index % 2 else key.upper()) if mixed_case else key
        setenv(name, value)


# --- Linux -----------------------------------------------------------------

def test_systemctl_user_gets_only_session_bus_variables(parent, capture):
    service = importlib.import_module('custodian.service')
    parent('HOME', '/home/fixture')
    parent('XDG_RUNTIME_DIR', '/run/user/4242')
    parent('DBUS_SESSION_BUS_ADDRESS', 'unix:path=/run/user/4242/bus')
    assert service._systemctl('daemon-reload')['ok'] is True
    argv, kwargs = capture[0]
    assert argv == ['systemctl', '--user', 'daemon-reload']
    assert kwargs['env'] == {
        'PATH': POSIX_PATH + ':/run/current-system/sw/bin', 'LC_ALL': 'C', 'LANG': 'C',
        'HOME': '/home/fixture', 'XDG_RUNTIME_DIR': '/run/user/4242',
        'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/run/user/4242/bus',
    }
    assert not kwargs.get('shell')
    _assert_no_leak(kwargs['env'])


def test_systemctl_user_omits_absent_session_variables(parent, capture):
    service = importlib.import_module('custodian.service')
    service._systemctl('show', service.UNIT_NAME)
    assert capture[0][1]['env'] == {
        'PATH': POSIX_PATH + ':/run/current-system/sw/bin', 'LC_ALL': 'C', 'LANG': 'C'}


def test_apt_listing_gets_base_environment_only(parent, capture, monkeypatch):
    updates = importlib.import_module('custodian.updates')
    monkeypatch.setattr(updates, 'NAME', 'linux')
    parent('HOME', '/home/fixture')
    parent('XDG_RUNTIME_DIR', '/run/user/4242')
    updates.check_updates()
    argv, kwargs = capture[0]
    assert argv == ['apt', 'list', '--upgradable']
    assert kwargs['env'] == POSIX_BASE
    _assert_no_leak(kwargs['env'])


def test_native_policy_query_keeps_its_exact_environment(parent, monkeypatch):
    updates = importlib.import_module('custodian.updates')
    seen = []

    def run(argv, **kwargs):
        seen.append(kwargs)
        return subprocess.CompletedProcess(argv, 0, 'install ok installed\n', '')
    monkeypatch.setattr(updates.subprocess, 'run', run)
    parent('HOME', '/home/fixture')
    updates._native_policy_query(list(updates._NATIVE_QUERIES[0]))
    assert seen[0]['env'] == POSIX_BASE
    _assert_no_leak(seen[0]['env'])


# --- macOS -----------------------------------------------------------------

def test_launchctl_gets_base_environment_only(parent, capture):
    service = importlib.import_module('custodian.service')
    parent('HOME', '/Users/fixture')
    parent('XPC_SERVICE_NAME', 'fixture.unrelated')
    parent('SSH_AUTH_SOCK', '/fixture/agent.sock')
    assert service._launchctl('print', 'gui/501/' + service.MACOS_LABEL)['ok'] is True
    argv, kwargs = capture[0]
    assert argv == ['launchctl', 'print', 'gui/501/' + service.MACOS_LABEL]
    assert kwargs['env'] == POSIX_BASE
    _assert_no_leak(kwargs['env'])


def test_softwareupdate_gets_base_environment_only(parent, capture, monkeypatch):
    updates = importlib.import_module('custodian.updates')
    monkeypatch.setattr(updates, 'NAME', 'macos')
    parent('HOME', '/Users/fixture')
    updates.check_updates()
    argv, kwargs = capture[0]
    assert argv == ['softwareupdate', '-l']
    assert kwargs['env'] == POSIX_BASE
    _assert_no_leak(kwargs['env'])


# --- Windows ---------------------------------------------------------------

@pytest.mark.parametrize('mixed_case', [False, True])
def test_schtasks_gets_exact_windows_system_environment(parent, capture, mixed_case):
    service = importlib.import_module('custodian.service')
    _plant_windows(parent, mixed_case=mixed_case)
    assert service._schtasks('/Query', '/TN', service.WINDOWS_TASK_NAME)['ok'] is True
    argv, kwargs = capture[0]
    assert argv == ['schtasks.exe', '/Query', '/TN', service.WINDOWS_TASK_NAME]
    assert kwargs['env'] == WIN_BASE
    assert kwargs['executable'] == WIN_ROOT + '\\System32\\schtasks.exe'
    assert not kwargs.get('shell')
    _assert_no_leak(kwargs['env'])


@pytest.mark.parametrize('mixed_case', [False, True])
def test_powershell_gets_exact_windows_system_and_profile_environment(parent, capture, monkeypatch, mixed_case):
    updates = importlib.import_module('custodian.updates')
    monkeypatch.setattr(updates, 'NAME', 'windows')
    _plant_windows(parent, mixed_case=mixed_case)
    updates.check_updates()
    argv, kwargs = capture[0]
    assert argv[0] == 'powershell.exe'
    assert kwargs['env'] == {**WIN_BASE, **WIN_PROFILE}
    assert kwargs['executable'] == WIN_ROOT + '\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'
    assert not kwargs.get('shell')
    _assert_no_leak(kwargs['env'])


def test_windows_environment_never_copies_parent_path():
    env = envmod.minimal_env('schtasks', {
        'Path': 'C:\\fixture\\unsafe;C:\\fixture\\token', 'SYSTEMROOT': 'C:\\Windows'})
    assert env == {'SystemRoot': 'C:\\Windows', 'WINDIR': 'C:\\Windows',
                   'PATH': 'C:\\Windows\\System32;C:\\Windows;C:\\Windows\\System32\\Wbem;'
                           'C:\\Windows\\System32\\WindowsPowerShell\\v1.0'}


@pytest.mark.parametrize('parent_env', [
    {},
    {'SystemRoot': 'relative\\dir'},
    {'SystemRoot': 'C:\\Win;C:\\fixture\\unsafe'},
    {'SystemRoot': '\\\\fixture-host\\share\\Windows'},
    {'SystemRoot': 'C:\\Win\x01dows'},
    {'SystemRoot': ''},
])
def test_windows_system_root_falls_back_when_missing_or_unsafe(parent_env):
    env = envmod.minimal_env('schtasks', parent_env)
    assert env['SystemRoot'] == 'C:\\Windows'
    assert env['WINDIR'] == 'C:\\Windows'
    assert env['PATH'].startswith('C:\\Windows\\System32;')
    assert envmod.windows_system_executable('schtasks.exe', parent_env) == 'C:\\Windows\\System32\\schtasks.exe'


def test_windows_system_root_falls_back_to_windir_spelling():
    assert envmod.minimal_env('schtasks', {'windir': 'E:\\Windows'})['SystemRoot'] == 'E:\\Windows'


def test_windows_executables_are_a_fixed_set():
    with pytest.raises(ValueError):
        envmod.windows_system_executable('cmd.exe', {'SystemRoot': 'C:\\Windows'})


# --- helper contract -------------------------------------------------------

def test_unknown_command_is_rejected_rather_than_inheriting():
    with pytest.raises(ValueError):
        envmod.minimal_env('bash', {'HOME': '/home/fixture'})


def test_helper_defaults_to_reading_the_live_parent(parent):
    parent('HOME', '/home/fixture')
    assert envmod.minimal_env('systemctl-user')['HOME'] == '/home/fixture'


def test_values_that_cannot_be_environment_strings_are_dropped():
    env = envmod.minimal_env('systemctl-user', {
        'HOME': '/home/fix\x00ture', 'XDG_RUNTIME_DIR': '', 'DBUS_SESSION_BUS_ADDRESS': 7})
    assert set(env) == {'PATH', 'LC_ALL', 'LANG'}


def test_every_allowlist_is_free_of_loader_proxy_and_credential_names():
    forbidden = ('KEY', 'TOKEN', 'SECRET', 'PASSWORD', 'PROXY', 'PYTHON', 'LD_', 'DYLD_', 'PSMODULEPATH')
    for command in envmod.COMMANDS:
        for name in envmod.allowed_names(command):
            assert not any(part in name.upper() for part in forbidden), (command, name)


# --- static audit: no production call site may inherit ---------------------

_SPAWNERS = {'run', 'Popen', 'call', 'check_call', 'check_output', 'getoutput', 'getstatusoutput'}
_OS_SPAWNERS = {'system', 'popen', 'startfile'}
_INJECTED_RUNNERS = {'_ps_runner'}


def _production_sources():
    root = Path(__file__).resolve().parents[2]
    yield root / '__init__.py'
    yield from sorted((root / 'custodian').rglob('*.py'))


def test_every_production_subprocess_call_passes_an_explicit_env():
    spawn_calls = 0
    for path in _production_sources():
        tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            where = f'{path.name}:{node.lineno}'
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                if func.value.id == 'os':
                    assert func.attr not in _OS_SPAWNERS, where
                    assert not func.attr.startswith(('exec', 'spawn', 'posix_spawn')), where
                if func.value.id == 'subprocess' and func.attr in _SPAWNERS:
                    spawn_calls += 1
                    env = [kw.value for kw in node.keywords if kw.arg == 'env']
                    assert len(env) == 1, f'{where} spawns without an explicit env'
                    assert _is_minimal_env_call(env[0]), f'{where} env is not minimal_env(...)'
                    assert not any(kw.arg == 'shell' for kw in node.keywords), where
            if isinstance(func, ast.Name) and func.id in _INJECTED_RUNNERS:
                spawn_calls += 1
                env = [kw.value for kw in node.keywords if kw.arg == 'env']
                assert len(env) == 1 and _is_minimal_env_call(env[0]), where
    # systemctl, launchctl, schtasks, native policy, apt, softwareupdate, powershell, ps
    assert spawn_calls == 8


def _is_minimal_env_call(node):
    return (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id == 'minimal_env'
            and len(node.args) == 1 and isinstance(node.args[0], ast.Constant)
            and node.args[0].value in envmod.COMMANDS)


def test_production_never_aliases_subprocess_entrypoints_outside_the_reviewed_runner():
    for path in _production_sources():
        tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == 'subprocess':
                pytest.fail(f'{path.name}:{node.lineno} imports subprocess names directly')
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Attribute):
                value = node.value
                if isinstance(value.value, ast.Name) and value.value.id == 'subprocess' and value.attr in _SPAWNERS:
                    names = {t.id for t in node.targets if isinstance(t, ast.Name)}
                    assert names <= _INJECTED_RUNNERS, f'{path.name}:{node.lineno}'
