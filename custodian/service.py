"""Explicit, unprivileged service management across platforms."""
from pathlib import Path
import os
import plistlib
import subprocess
from custodian._platform import NAME
from ._subprocess_env import minimal_env, windows_system_executable

UNIT_NAME = 'hermes-custodian.service'
MACOS_LABEL = 'com.hermes.custodian'
MACOS_PLIST_NAME = f'{MACOS_LABEL}.plist'
WINDOWS_TASK_NAME = 'HermesCustodianMonitor'


# =============================================================================
# Linux Backend (systemd --user)
# =============================================================================

def _systemctl(*args: str) -> dict:
    try:
        child = subprocess.run(['systemctl', '--user', *args], capture_output=True,
                               text=True, timeout=15, check=False,
                               env=minimal_env('systemctl-user'))
        return {'ok': child.returncode == 0, 'returncode': child.returncode,
                'stdout': child.stdout.strip(), 'stderr': child.stderr.strip()}
    except FileNotFoundError:
        return {'ok': False, 'returncode': None, 'stdout': '', 'stderr': 'systemctl not found',
                'error': 'unsupported on this system'}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {'ok': False, 'returncode': None, 'stdout': '', 'stderr': str(exc), 'error': str(exc)}


def _unit_path() -> Path:
    config = Path(os.environ.get('XDG_CONFIG_HOME') or Path.home() / '.config')
    if not config.is_absolute():
        raise ValueError('XDG_CONFIG_HOME must be absolute')
    return config / 'systemd' / 'user' / UNIT_NAME


def _is_absolute_path(path: Path) -> bool:
    if path.is_absolute():
        return True
    text = str(path)
    if len(text) >= 3 and text[0].isalpha() and text[1] == ':' and text[2] in ('/', '\\'):
        return True
    if text.startswith('\\\\') or text.startswith('//'):
        return True
    return False


def _quote(path: Path, *, executable: bool = False) -> str:
    text = str(path)
    if not _is_absolute_path(path) or any(ord(c) < 32 or ord(c) == 127 for c in text):
        raise ValueError('Service paths must be absolute and contain no control characters')
    text = text.replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%')
    if not executable:
        text = text.replace('$', '$$')
    return '"' + text + '"'


def build_unit(python_executable: Path, state_dir: Path) -> str:
    """Build a unit without writing anything; paths are literal, not shell code."""
    return f'''[Unit]
Description=Hermes Custodian local monitor

[Service]
Type=simple
ExecStart={_quote(python_executable, executable=True)} -m custodian.cli --state-dir {_quote(state_dir)} monitor
NoNewPrivileges=yes
PrivateTmp=yes
UMask=0077
MemoryMax=192M
Restart=on-failure
RestartSec=10

[Install]
WantedBy=default.target
'''


def _install_service_linux(state_dir: Path, python_executable: Path, enable: bool = False) -> dict:
    unit = build_unit(python_executable, state_dir)
    path = _unit_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.is_symlink():
            raise OSError('Refusing symlink unit')
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, delete=False) as file:
            temporary = Path(file.name)
            file.write(unit)
        try:
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)
        if path.read_text() != unit:
            raise OSError('Unit read-back mismatch')
    except OSError as exc:
        return {'ok': False, 'installed': False, 'error': str(exc)}
    result = _systemctl('daemon-reload')
    if enable and result['ok']:
        result = _systemctl('enable', UNIT_NAME)
        if result['ok']:
            verification = _service_status_linux()
            result = {**result, 'ok': verification['ok'] and verification['enabled'] is True,
                      'enabled': verification['enabled'], 'verification': verification}
    return {**result, 'installed': True, 'unit_path': str(path)}


def _uninstall_service_linux() -> dict:
    stopped = _stop_service_linux()
    if not stopped['ok']:
        return {**stopped, 'removed': False}
    disabled = _systemctl('disable', UNIT_NAME)
    if not disabled['ok']:
        return {**disabled, 'removed': False}
    verification = _service_status_linux()
    if not verification['ok'] or verification['enabled'] is not False:
        return {'ok': False, 'removed': False, 'verification': verification,
                'error': 'Could not verify service is disabled'}
    path = _unit_path()
    try:
        path.unlink(missing_ok=True)
        if path.exists() or path.is_symlink():
            raise OSError('Unit still exists after removal')
    except OSError as exc:
        return {'ok': False, 'removed': False, 'error': str(exc)}
    return {**_systemctl('daemon-reload'), 'removed': True}


def _start_service_linux() -> dict:
    result = _systemctl('start', UNIT_NAME)
    if not result['ok']:
        return result
    verification = _service_status_linux()
    healthy = (verification['ok'] and verification['load_state'] == 'loaded'
               and verification['active_state'] == 'active'
               and verification['exec_main_status'] == 0
               and verification['result'] == 'success')
    return {**result, 'ok': bool(healthy), 'verification': verification}


def _stop_service_linux() -> dict:
    result = _systemctl('stop', UNIT_NAME)
    if not result['ok']:
        return result
    verification = _service_status_linux()
    return {**result, 'ok': verification['ok'] and verification['active_state'] in ('inactive', 'failed'),
            'verification': verification}


def _service_status_linux() -> dict:
    result = _systemctl('show', UNIT_NAME, '--no-pager',
                        '--property=LoadState,ActiveState,SubState,UnitFileState,ExecMainStatus,Result')
    properties = dict(line.split('=', 1) for line in result['stdout'].splitlines() if '=' in line)
    active_state = properties.get('ActiveState') if result['ok'] else None
    enabled_state = properties.get('UnitFileState') if result['ok'] else None
    status = properties.get('ExecMainStatus', '') if result['ok'] else ''
    if result['ok'] and not active_state:
        result = {**result, 'ok': False, 'error': 'Manager returned no ActiveState; status unknown'}
    return {**result, 'unit': UNIT_NAME, 'load_state': properties.get('LoadState'),
            'active_state': active_state, 'sub_state': properties.get('SubState'),
            'active': {'active': True, 'reloading': True, 'refreshing': True,
                       'inactive': False, 'failed': False}.get(active_state or ''),
            'enabled': {'enabled': True, 'enabled-runtime': True,
                        'disabled': False, 'static': False, 'indirect': False,
                        'masked': False, 'masked-runtime': False, 'generated': False,
                        'transient': False, 'linked': False, 'linked-runtime': False,
                        'alias': False}.get(enabled_state or ''),
            'unit_file_state': enabled_state,
            'exec_main_status': int(status) if status.isdigit() else None,
            'result': properties.get('Result')}


# =============================================================================
# macOS Backend (LaunchAgents launchd)
# =============================================================================

def _macos_plist_path() -> Path:
    return Path.home() / 'Library' / 'LaunchAgents' / MACOS_PLIST_NAME


def _current_uid() -> int:
    return os.getuid() if hasattr(os, 'getuid') else 501


def build_macos_plist(python_executable: Path, state_dir: Path, enable: bool = False) -> dict:
    """Build LaunchAgent plist dict without writing anything; paths are validated."""
    for p in (python_executable, state_dir):
        text = str(p)
        if not _is_absolute_path(p) or any(ord(c) < 32 or ord(c) == 127 for c in text):
            raise ValueError('Service paths must be absolute and contain no control characters')
    plist = {
        'Label': MACOS_LABEL,
        'ProgramArguments': [str(python_executable), '-m', 'custodian.cli', '--state-dir', str(state_dir), 'monitor'],
        'KeepAlive': False,
        'ProcessType': 'Background',
        'StandardOutPath': str(state_dir / 'monitor.stdout.log'),
        'StandardErrorPath': str(state_dir / 'monitor.stderr.log'),
        'EnvironmentVariables': {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'},
    }
    if enable:
        plist['RunAtLoad'] = True
    return plist


def _launchctl(*args: str) -> dict:
    try:
        child = subprocess.run(['launchctl', *args], capture_output=True,
                               text=True, timeout=15, check=False,
                               env=minimal_env('launchctl'))
        return {'ok': child.returncode == 0, 'returncode': child.returncode,
                'stdout': child.stdout.strip(), 'stderr': child.stderr.strip()}
    except FileNotFoundError:
        return {'ok': False, 'returncode': None, 'stdout': '', 'stderr': 'launchctl not found',
                'error': 'unsupported on this system'}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {'ok': False, 'returncode': None, 'stdout': '', 'stderr': str(exc), 'error': str(exc)}


def _install_service_macos(state_dir: Path, python_executable: Path, enable: bool = False) -> dict:
    try:
        plist = build_macos_plist(python_executable, state_dir, enable=enable)
    except ValueError as exc:
        return {'ok': False, 'installed': False, 'error': str(exc)}
    path = _macos_plist_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.is_symlink():
            raise OSError('Refusing symlink plist')
        plist_bytes = plistlib.dumps(plist, fmt=plistlib.FMT_XML)
        import tempfile
        with tempfile.NamedTemporaryFile(mode='wb', dir=path.parent, delete=False) as file:
            temporary = Path(file.name)
            os.chmod(file.fileno(), 0o600)
            file.write(plist_bytes)
            file.flush()
            os.fsync(file.fileno())
        try:
            os.chmod(temporary, 0o600)
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)
        if path.read_bytes() != plist_bytes:
            raise OSError('Plist read-back mismatch')
    except OSError as exc:
        return {'ok': False, 'installed': False, 'error': str(exc)}

    uid = _current_uid()
    if enable:
        res = _launchctl('bootstrap', f'gui/{uid}', str(path))
        if res['ok']:
            verification = _service_status_macos()
            return {**res, 'ok': verification['ok'] and verification['enabled'] is True,
                    'installed': True, 'unit_path': str(path), 'enabled': verification['enabled'],
                    'verification': verification}
        return {**res, 'installed': True, 'unit_path': str(path), 'enabled': None}
    return {'ok': True, 'installed': True, 'unit_path': str(path), 'enabled': False}


def _service_status_macos() -> dict:
    uid = _current_uid()
    res = _launchctl('print', f'gui/{uid}/{MACOS_LABEL}')
    path = _macos_plist_path()
    enabled = False
    if path.exists():
        try:
            with open(path, 'rb') as f:
                d = plistlib.load(f)
            enabled = d.get('RunAtLoad', False) is True
        except Exception:
            enabled = None
    else:
        enabled = None

    if not res['ok']:
        return {**res, 'unit': MACOS_LABEL, 'active': None, 'enabled': enabled,
                'active_state': None, 'load_state': None, 'exec_main_status': None, 'result': None,
                'error': res.get('error') or res.get('stderr') or 'Failed to query launchd status'}

    active_state = None
    exec_main_status = None
    active = None
    for line in res['stdout'].splitlines():
        line = line.strip()
        if line.startswith('state ='):
            active_state = line.split('=', 1)[1].strip()
        elif line.startswith('last exit code ='):
            code_str = line.split('=', 1)[1].strip()
            if code_str.isdigit() or (code_str.startswith('-') and code_str[1:].isdigit()):
                exec_main_status = int(code_str)

    if active_state:
        if active_state == 'running':
            active = True
        elif active_state in ('not running', 'waiting'):
            active = False

    return {
        **res,
        'unit': MACOS_LABEL,
        'load_state': 'loaded',
        'active_state': active_state,
        'active': active,
        'enabled': enabled,
        'exec_main_status': exec_main_status,
        'result': 'success' if exec_main_status == 0 else (str(exec_main_status) if exec_main_status is not None else None),
    }


def _start_service_macos() -> dict:
    uid = _current_uid()
    res = _launchctl('kickstart', f'gui/{uid}/{MACOS_LABEL}')
    if not res['ok']:
        return res
    verification = _service_status_macos()
    healthy = verification['ok'] and verification['active'] is True
    return {**res, 'ok': bool(healthy), 'verification': verification}


def _stop_service_macos() -> dict:
    uid = _current_uid()
    res = _launchctl('bootout', f'gui/{uid}/{MACOS_LABEL}')
    if not res['ok']:
        return res
    verification = _service_status_macos()
    stopped = verification['active'] is False or not verification['ok']
    return {**res, 'ok': bool(stopped), 'verification': verification}


def _uninstall_service_macos() -> dict:
    _stop_service_macos()
    path = _macos_plist_path()
    try:
        path.unlink(missing_ok=True)
        if path.exists() or path.is_symlink():
            raise OSError('Unit still exists after removal')
    except OSError as exc:
        return {'ok': False, 'removed': False, 'error': str(exc)}
    return {'ok': True, 'removed': True}


# =============================================================================
# Windows Backend (schtasks.exe)
# =============================================================================

def build_schtasks_create_argv(python_executable: Path, state_dir: Path, enable: bool = False) -> list[list[str]]:
    """Build schtasks.exe argv lists for creating the scheduled task."""
    for p in (python_executable, state_dir):
        text = str(p)
        if not _is_absolute_path(p) or any(ord(c) < 32 or ord(c) == 127 for c in text):
            raise ValueError('Service paths must be absolute and contain no control characters')
    tr = f'"{python_executable}" -m custodian.cli --state-dir "{state_dir}" monitor'
    create = [
        'schtasks.exe', '/Create', '/TN', WINDOWS_TASK_NAME,
        '/TR', tr, '/SC', 'ONLOGON', '/RL', 'LIMITED', '/F'
    ]
    if enable:
        return [create]
    return [
        create,
        ['schtasks.exe', '/Change', '/TN', WINDOWS_TASK_NAME, '/DISABLE']
    ]


def _schtasks(*args: str) -> dict:
    try:
        child = subprocess.run(['schtasks.exe', *args], capture_output=True,
                               text=True, timeout=15, check=False,
                               executable=windows_system_executable('schtasks.exe'),
                               env=minimal_env('schtasks'))
        return {'ok': child.returncode == 0, 'returncode': child.returncode,
                'stdout': child.stdout.strip(), 'stderr': child.stderr.strip()}
    except FileNotFoundError:
        return {'ok': False, 'returncode': None, 'stdout': '', 'stderr': 'schtasks.exe not found',
                'error': 'unsupported on this system'}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {'ok': False, 'returncode': None, 'stdout': '', 'stderr': str(exc), 'error': str(exc)}


def _parse_schtasks_query(stdout: str) -> dict:
    """Parse schtasks /Query /V /FO LIST output defensively without raising."""
    props = {}
    for line in stdout.splitlines():
        if ':' in line:
            k, v = line.split(':', 1)
            props[k.strip().lower()] = v.strip()

    status_val = props.get('status', '').lower()
    state_val = props.get('scheduled task state', '').lower()

    active = None
    if 'running' in status_val or any('running' in v.lower() for k, v in props.items() if 'status' in k):
        active = True
    elif 'ready' in status_val or 'disabled' in status_val:
        active = False

    enabled = None
    if 'enabled' in state_val:
        enabled = True
    elif 'disabled' in state_val:
        enabled = False
    elif 'disabled' in status_val:
        enabled = False

    last_res_str = props.get('last result', '')
    exec_main_status = int(last_res_str) if last_res_str.isdigit() else None

    return {
        'active': active,
        'enabled': enabled,
        'active_state': props.get('status') or ('running' if active else ('ready' if active is False else None)),
        'load_state': 'loaded' if props else None,
        'exec_main_status': exec_main_status,
        'result': last_res_str if last_res_str else None,
    }


def _install_service_windows(state_dir: Path, python_executable: Path, enable: bool = False) -> dict:
    try:
        cmds = build_schtasks_create_argv(python_executable, state_dir, enable=enable)
    except ValueError as exc:
        return {'ok': False, 'installed': False, 'error': str(exc)}
    for cmd in cmds:
        res = _schtasks(*cmd[1:])
        if not res['ok']:
            return {**res, 'installed': False, 'error': res.get('error') or res.get('stderr') or 'schtasks failed'}

    verification = _service_status_windows()
    if enable:
        ok = verification['ok'] and verification['enabled'] is True
        return {'ok': ok, 'installed': True, 'unit_path': WINDOWS_TASK_NAME, 'enabled': True, 'verification': verification}
    ok = verification['ok'] and verification['enabled'] is False
    return {'ok': ok, 'installed': True, 'unit_path': WINDOWS_TASK_NAME, 'enabled': False, 'verification': verification}


def _service_status_windows() -> dict:
    res = _schtasks('/Query', '/TN', WINDOWS_TASK_NAME, '/V', '/FO', 'LIST')
    if not res['ok']:
        return {**res, 'unit': WINDOWS_TASK_NAME, 'active': None, 'enabled': None,
                'active_state': None, 'load_state': None, 'exec_main_status': None, 'result': None,
                'error': res.get('error') or res.get('stderr') or 'schtasks query failed'}
    parsed = _parse_schtasks_query(res['stdout'])
    return {**res, 'unit': WINDOWS_TASK_NAME, **parsed}


def _start_service_windows() -> dict:
    res = _schtasks('/Run', '/TN', WINDOWS_TASK_NAME)
    if not res['ok']:
        return res
    verification = _service_status_windows()
    healthy = verification['ok'] and (verification['active'] is True or verification['active_state'] in ('running', 'Ready', 'ready'))
    return {**res, 'ok': bool(healthy), 'verification': verification}


def _stop_service_windows() -> dict:
    res = _schtasks('/End', '/TN', WINDOWS_TASK_NAME)
    if not res['ok']:
        return res
    verification = _service_status_windows()
    stopped = verification['ok'] and verification['active'] is False
    return {**res, 'ok': bool(stopped), 'verification': verification}


def _uninstall_service_windows() -> dict:
    _stop_service_windows()
    res = _schtasks('/Delete', '/TN', WINDOWS_TASK_NAME, '/F')
    if not res['ok']:
        return {**res, 'removed': False, 'error': res.get('error') or res.get('stderr')}
    return {**res, 'removed': True}


# =============================================================================
# Public Dispatch
# =============================================================================

def install_service(state_dir: Path, python_executable: Path, enable: bool = False) -> dict:
    """Install the background service for the current platform."""
    if NAME == 'macos':
        return _install_service_macos(state_dir, python_executable, enable=enable)
    if NAME == 'windows':
        return _install_service_windows(state_dir, python_executable, enable=enable)
    return _install_service_linux(state_dir, python_executable, enable=enable)


def uninstall_service() -> dict:
    """Uninstall the background service for the current platform."""
    if NAME == 'macos':
        return _uninstall_service_macos()
    if NAME == 'windows':
        return _uninstall_service_windows()
    return _uninstall_service_linux()


def start_service() -> dict:
    """Start the background service for the current platform."""
    if NAME == 'macos':
        return _start_service_macos()
    if NAME == 'windows':
        return _start_service_windows()
    return _start_service_linux()


def stop_service() -> dict:
    """Stop the background service for the current platform."""
    if NAME == 'macos':
        return _stop_service_macos()
    if NAME == 'windows':
        return _stop_service_windows()
    return _stop_service_linux()


def service_status() -> dict:
    """Query manager state for the current platform."""
    if NAME == 'macos':
        return _service_status_macos()
    if NAME == 'windows':
        return _service_status_windows()
    return _service_status_linux()
