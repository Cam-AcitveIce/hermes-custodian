"""The one reviewed place that decides what a child process may see.

Custodian runs inside an agent process whose environment routinely holds
provider API keys, proxy credentials and loader overrides. None of that is
any business of ``systemctl``, ``apt`` or ``schtasks.exe``, so no child ever
inherits the parent environment or receives it merged wholesale. Each command
gets a fresh mapping built from:

* fixed values chosen here (a system-directory ``PATH``, a ``C`` locale), and
* a short per-command allowlist of names copied from the parent because the
  command cannot work without them.

``PATH`` is never copied: a parent ``PATH`` can carry writable or attacker
chosen directories, and occasionally secrets. Anything not listed below
(``*_API_KEY``, ``*_PROXY``, ``PYTHONPATH``, ``LD_PRELOAD``, ``DYLD_*``,
``APT_CONFIG``, ``PSModulePath`` ...) is dropped by construction.

This module is pure standard library and imports no platform backend, so both
backends and the platform-neutral modules can use it.
"""
from __future__ import annotations

import ntpath
import os
from typing import Mapping, Optional

# Root-owned system directories only, matching the native policy query.
POSIX_SYSTEM_PATH = '/usr/sbin:/usr/bin:/sbin:/bin'
# NixOS keeps systemctl here. /run is root-owned, so on other distributions
# the directory simply does not exist and cannot be created by the user.
_NIXOS_SYSTEM_PATH = '/run/current-system/sw/bin'
_POSIX_LOCALE = {'LC_ALL': 'C', 'LANG': 'C'}

_WINDOWS_DEFAULT_ROOT = 'C:\\Windows'
# The stock machine PATH, rebuilt from the system root rather than copied.
_WINDOWS_PATH_SUFFIXES = ('System32', '', 'System32\\Wbem', 'System32\\WindowsPowerShell\\v1.0')
# Loader, Winsock and temp-file basics every Windows system tool expects.
_WINDOWS_SYSTEM_NAMES = ('SystemDrive', 'TEMP', 'TMP')
# Per-user and machine data roots that .NET and COM resolve while PowerShell
# starts and talks to the Windows Update agent. Directory paths, not secrets.
_WINDOWS_PROFILE_NAMES = ('USERPROFILE', 'LOCALAPPDATA', 'APPDATA', 'ProgramData')
_WINDOWS_EXECUTABLES = {
    'schtasks.exe': 'System32\\schtasks.exe',
    'powershell.exe': 'System32\\WindowsPowerShell\\v1.0\\powershell.exe',
}

# command -> (family, PATH override or None, names copied from the parent)
_SPECS = {
    # Fixed absolute-path read-only queries (dpkg-query, systemctl show, apt-config).
    'native-policy': ('posix', None, ()),
    # `systemctl --user` finds the user manager through the runtime dir or the
    # session bus address, and falls back to HOME-relative lookups.
    'systemctl-user': ('posix', POSIX_SYSTEM_PATH + ':' + _NIXOS_SYSTEM_PATH,
                       ('HOME', 'XDG_RUNTIME_DIR', 'DBUS_SESSION_BUS_ADDRESS')),
    # `apt list --upgradable` reads root-owned system state only.
    'apt': ('posix', None, ()),
    # launchctl is always given an explicit gui/<uid> domain target and reaches
    # launchd over the inherited bootstrap port, not through variables.
    'launchctl': ('posix', None, ()),
    'softwareupdate': ('posix', None, ()),
    'ps': ('posix', None, ()),
    'schtasks': ('windows', None, _WINDOWS_SYSTEM_NAMES),
    'powershell': ('windows', None, _WINDOWS_SYSTEM_NAMES + _WINDOWS_PROFILE_NAMES),
}
COMMANDS = frozenset(_SPECS)


def _spec(command: str):
    try:
        return _SPECS[command]
    except (KeyError, TypeError):
        raise ValueError('No reviewed environment for this command') from None


def allowed_names(command: str) -> tuple:
    """Every variable name a child of ``command`` can ever receive."""
    family, _path, names = _spec(command)
    fixed = ('PATH', 'LC_ALL', 'LANG') if family == 'posix' else ('PATH', 'SystemRoot', 'WINDIR')
    return fixed + tuple(names)


def _usable(value) -> bool:
    return type(value) is str and value != '' and '\x00' not in value


def _lookup(parent: Mapping, name: str, *, ignore_case: bool) -> Optional[str]:
    value = parent.get(name)
    if _usable(value):
        return value
    if ignore_case:
        wanted = name.upper()
        for key in sorted(k for k in parent if type(k) is str):
            if key.upper() == wanted and _usable(parent[key]):
                return parent[key]
    return None


def _windows_root(parent: Mapping) -> str:
    """The Windows directory, taken from the parent only if it is a plain local path."""
    for name in ('SystemRoot', 'WINDIR'):
        value = _lookup(parent, name, ignore_case=True)
        if value is None:
            continue
        drive, tail = ntpath.splitdrive(value)
        if (len(drive) == 2 and drive[0].isalpha() and drive[1] == ':'
                and tail[:1] in ('\\', '/')
                and not any(ord(c) < 32 or c in ';"<>|*?' for c in value)):
            return ntpath.normpath(value)
    return _WINDOWS_DEFAULT_ROOT


def windows_system_executable(name: str, parent: Optional[Mapping] = None) -> str:
    """Absolute path of a fixed Windows system tool.

    Passed as ``executable=`` so CreateProcess does not search the application
    directory or the current directory for a bare ``schtasks.exe``.
    """
    try:
        relative = _WINDOWS_EXECUTABLES[name]
    except (KeyError, TypeError):
        raise ValueError('Not a reviewed Windows system executable') from None
    return ntpath.join(_windows_root(os.environ if parent is None else parent), relative)


def minimal_env(command: str, parent: Optional[Mapping] = None) -> dict:
    """Build the complete environment for one reviewed command.

    ``parent`` defaults to ``os.environ`` and is only ever read for the names
    allowlisted for ``command``. The result is a new dict; nothing else from
    the parent can reach the child.
    """
    family, path, names = _spec(command)
    source = os.environ if parent is None else parent
    if family == 'posix':
        env = {'PATH': path or POSIX_SYSTEM_PATH, **_POSIX_LOCALE}
        ignore_case = False
    else:
        root = _windows_root(source)
        env = {
            'SystemRoot': root,
            'WINDIR': root,
            'PATH': ';'.join(ntpath.join(root, suffix) if suffix else root
                             for suffix in _WINDOWS_PATH_SUFFIXES),
        }
        ignore_case = True
    for name in names:
        value = _lookup(source, name, ignore_case=ignore_case)
        if value is not None:
            env[name] = value
    return env
