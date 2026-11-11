"""Explicit, unprivileged systemd user-service management."""
from pathlib import Path
import os
import subprocess


def _systemctl(*args: str) -> dict:
    try:
        child = subprocess.run(['systemctl', '--user', *args], capture_output=True,
                               text=True, timeout=15, check=False,
                               env={**os.environ, 'LC_ALL': 'C', 'LANG': 'C'})
        return {'ok': child.returncode == 0, 'returncode': child.returncode,
                'stdout': child.stdout.strip(), 'stderr': child.stderr.strip()}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {'ok': False, 'returncode': None, 'stdout': '', 'stderr': str(exc)}


def _unit_path() -> Path:
    config = Path(os.environ.get('XDG_CONFIG_HOME') or Path.home() / '.config')
    if not config.is_absolute():
        raise ValueError('XDG_CONFIG_HOME must be absolute')
    return config / 'systemd' / 'user' / UNIT_NAME


def install_service(state_dir: Path, python_executable: Path, enable: bool = False) -> dict:
    """Write a user unit and reload. Never start; enable only when explicit."""
    unit = build_unit(python_executable, state_dir)
    path = _unit_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.is_symlink():
            raise OSError('Refusing symlink unit')
        # Atomic replacement also avoids following a raced final symlink.
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
            verification = service_status()
            result = {**result, 'ok': verification['ok'] and verification['enabled'] is True,
                      'enabled': verification['enabled'], 'verification': verification}
    return {**result, 'installed': True, 'unit_path': str(path)}

def uninstall_service() -> dict:
    """Stop, disable, verify, remove only this unit, and reload. Keep state data."""
    stopped = stop_service()
    if not stopped['ok']:
        return {**stopped, 'removed': False}
    disabled = _systemctl('disable', UNIT_NAME)
    if not disabled['ok']:
        return {**disabled, 'removed': False}
    verification = service_status()
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


def start_service() -> dict:
    """Explicit start only; neither install nor enable is implied.

    A successful systemctl submission alone does not prove a healthy child.
    This is a point-in-time check, not a guarantee of continued monitoring.
    """
    result = _systemctl('start', UNIT_NAME)
    if not result['ok']:
        return result
    verification = service_status()
    healthy = (verification['ok'] and verification['load_state'] == 'loaded'
               and verification['active_state'] == 'active'
               and verification['exec_main_status'] == 0
               and verification['result'] == 'success')
    return {**result, 'ok': bool(healthy), 'verification': verification}


def stop_service() -> dict:
    """Stop the user unit and verify it reached a terminal nonrunning state."""
    result = _systemctl('stop', UNIT_NAME)
    if not result['ok']:
        return result
    verification = service_status()
    return {**result, 'ok': verification['ok'] and verification['active_state'] in ('inactive', 'failed'),
            'verification': verification}


def service_status() -> dict:
    """Query manager state; unknown is None, never silently inactive/disabled."""
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


UNIT_NAME = 'hermes-custodian.service'


def _quote(path: Path, *, executable: bool = False) -> str:
    text = str(path)
    if not path.is_absolute() or any(ord(c) < 32 or ord(c) == 127 for c in text):
        raise ValueError('Service paths must be absolute and contain no control characters')
    text = text.replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%')
    # systemd expands environment only in argv, never in the executable path.
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
