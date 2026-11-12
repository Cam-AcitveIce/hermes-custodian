"""Read-only Debian APT cache inspection; no refresh, installs or self-updates."""
import os
import re
import subprocess
import hashlib
import json
import stat
try:
    import fcntl
except ImportError:
    fcntl = None
import secrets
from contextlib import contextmanager
from pathlib import Path
from custodian._platform import NAME
from ._subprocess_env import minimal_env, windows_system_executable


_POLICY_NAME = '99hermes-custodian-security'
_POLICY_PATH = '/etc/apt/apt.conf.d/' + _POLICY_NAME


def _policy_content(origins: list[str]) -> str:
    return ('# Managed by Hermes Custodian; security updates only.\n'
            '#clear Unattended-Upgrade::Allowed-Origins;\n'
            '#clear Unattended-Upgrade::Origins-Pattern;\n'
            'Unattended-Upgrade::Allowed-Origins {\n'
            + ''.join(f'  "{origin}";\n' for origin in origins)
            + '};\n'
            'Unattended-Upgrade::Automatic-Reboot "false";\n'
            'APT::Periodic::Enable "1";\n'
            'APT::Periodic::Update-Package-Lists "1";\n'
            'APT::Periodic::Unattended-Upgrade "1";\n')


def _plan_hash(plan: dict) -> str:
    return hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


class _SecurityPolicy:
    """Private fixture-injectable backend, never a CLI base-directory option."""

    def __init__(self, base_dir: Path, *, owner_uid: int, query):
        if base_dir != Path('/etc') and os.geteuid() == 0:
            raise PermissionError('Fixture base directories are forbidden for privileged callers')
        self.base = base_dir
        self.owner_uid = owner_uid
        self.query = query

    def _check(self, info, *, directory=False):
        valid_type = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
        if (not valid_type or info.st_uid != self.owner_uid or info.st_mode & 0o022
                or (not directory and info.st_nlink != 1)):
            raise OSError('Unsafe policy path: ownership, type, links or permissions')

    @contextmanager
    def _directory(self):
        fds = []
        try:
            fd = os.open(self.base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            fds.append(fd)
            self._check(os.fstat(fd), directory=True)
            for name in ('apt', 'apt.conf.d'):
                fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                fds.append(fd)
                self._check(os.fstat(fd), directory=True)
            yield fds
        finally:
            for fd in reversed(fds):
                os.close(fd)

    def _read(self, fd, name):
        file = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        try:
            info = os.fstat(file)
            self._check(info)
            if info.st_size > 1048576:
                raise OSError('Policy file exceeds read limit')
            with os.fdopen(os.dup(file), 'r', encoding='utf-8') as stream:
                content = stream.read(1048577)
            after = os.fstat(file)
            if (len(content) > 1048576 or (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                    != (info.st_size, info.st_mtime_ns, info.st_ctime_ns)):
                raise OSError('Policy changed while reading')
            return {'content': content, 'uid': info.st_uid, 'gid': info.st_gid,
                    'mode': stat.S_IMODE(info.st_mode), 'inode': info.st_ino,
                    'device': info.st_dev, 'mtime_ns': info.st_mtime_ns}
        finally:
            os.close(file)

    def _release(self, etc_fd):
        info = os.stat('os-release', dir_fd=etc_fd, follow_symlinks=False)
        if not stat.S_ISLNK(info.st_mode):
            return self._read(etc_fd, 'os-release')
        target = os.readlink('os-release', dir_fd=etc_fd)
        if info.st_uid != self.owner_uid or target not in ('../usr/lib/os-release', '/usr/lib/os-release'):
            raise OSError('Untrusted os-release symlink')
        # Do not follow the link. Open only the fixed distro path, component by
        # component with O_NOFOLLOW. Fixtures map /usr beneath their private root.
        fds = []
        try:
            fd = os.open(self.base.parent / 'usr', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            fds.append(fd)
            self._check(os.fstat(fd), directory=True)
            fd = os.open('lib', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            fds.append(fd)
            self._check(os.fstat(fd), directory=True)
            return {**self._read(fd, 'os-release'), 'canonical_link': target,
                    'link_inode': info.st_ino, 'link_mtime_ns': info.st_mtime_ns}
        finally:
            for fd in reversed(fds):
                os.close(fd)

    def _snapshot(self):
        with self._directory() as fds:
            snapshot = {'os-release': self._release(fds[0])}
            for name in sorted(os.listdir(fds[-1])):
                snapshot['apt/apt.conf.d/' + name] = self._read(fds[-1], name)
            try:
                snapshot['apt/apt.conf'] = self._read(fds[1], 'apt.conf')
            except FileNotFoundError:
                snapshot['apt/apt.conf'] = None
            return snapshot

    def _config(self, text, origins):
        if not text or not text.strip():
            raise ValueError('Unrecognized apt-config dump syntax')
        parsed = {}
        current_key = None
        current_val = []
        for line in text.splitlines():
            if current_key is None:
                match = re.match(r'^([A-Za-z0-9][A-Za-z0-9_:./+~@-]*) "(.*)$', line)
                if not match:
                    raise ValueError('Unrecognized apt-config dump syntax')
                key, rest = match.groups()
                if rest.endswith('";'):
                    parsed.setdefault(key.lower(), []).append(rest[:-2])
                elif rest.endswith('"') and not rest.endswith('\\"'):
                    raise ValueError('Unrecognized apt-config dump syntax')
                else:
                    current_key = key.lower()
                    current_val = [rest]
            else:
                if re.match(r'^[A-Za-z0-9][A-Za-z0-9_:./+~@-]*::[A-Za-z0-9_:./+~@-]* "', line):
                    raise ValueError('Unrecognized apt-config dump syntax')
                if line.endswith('";'):
                    current_val.append(line[:-2])
                    parsed.setdefault(current_key, []).append('\n'.join(current_val))
                    current_key = None
                    current_val = []
                else:
                    current_val.append(line)
        if current_key is not None:
            raise ValueError('Unrecognized apt-config dump syntax')
        for key, values in parsed.items():
            values = [value for value in values if value]
            if key.startswith('unattended-upgrade::allowed-origins'):
                if any(value not in origins for value in values):
                    raise ValueError('Existing Allowed-Origins includes nonsecurity or unknown origins')
            if key.startswith('unattended-upgrade::origins-pattern') and values:
                raise ValueError('Existing Origins-Pattern cannot be proven security-only')
            if key == 'unattended-upgrade::automatic-reboot' and any(v.lower() not in ('false', '0', 'no') for v in values):
                raise ValueError('Existing automatic reboot policy conflicts')
            fixed = {'dir': '/', 'dir::etc': 'etc/apt', 'dir::etc::parts': 'apt.conf.d',
                     'dir::etc::main': 'apt.conf'}
            if key in fixed and any(value != fixed[key] for value in values):
                raise ValueError('Custom APT configuration paths are unsupported')
        return parsed

    def _replace(self, fd, content):
        name = '.hermes-custodian-' + secrets.token_hex(16)
        file = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                       0o600, dir_fd=fd)
        try:
            with os.fdopen(file, 'w', encoding='utf-8') as stream:
                stream.write(content)
                stream.flush()
                os.fchmod(stream.fileno(), 0o644)
                if self.owner_uid == 0:
                    os.fchown(stream.fileno(), 0, 0)
                os.fsync(stream.fileno())
            os.replace(name, _POLICY_NAME, src_dir_fd=fd, dst_dir_fd=fd)
            os.fsync(fd)
        finally:
            try:
                os.unlink(name, dir_fd=fd)
            except FileNotFoundError:
                pass

    def apply(self, plan, approval):
        if (not isinstance(plan, dict) or not isinstance(plan.get('plan_id'), str)
                or approval != 'APPLY SECURITY POLICY ' + plan['plan_id']):
            return {'status': 'denied', 'changed': False, 'error': 'Exact plan-specific administrator approval required'}
        if (not re.fullmatch('[0-9a-f]{64}', plan['plan_id'])
                or plan['plan_id'] != _plan_hash({k: v for k, v in plan.items() if k != 'plan_id'})):
            return {'status': 'mismatch', 'changed': False, 'error': 'Plan hash mismatch'}
        fresh = self.plan(plan.get('enabled'))
        if fresh != plan or fresh.get('status') != 'ready':
            return {'status': 'stale', 'changed': False, 'error': 'State or plan changed; preview and approve a new plan'}
        content = _policy_content(fresh['origins'])
        with self._directory() as fds:
            try:
                fcntl.flock(fds[-1], fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return {'status': 'busy', 'changed': False, 'error': 'Another policy writer holds the directory lock'}
            if self._snapshot() != fresh['preconditions']['files']:
                return {'status': 'stale', 'changed': False, 'error': 'State changed immediately before apply'}
            if not fresh['enabled']:
                try:
                    os.unlink(_POLICY_NAME, dir_fd=fds[-1])
                    changed = True
                    os.fsync(fds[-1])
                except FileNotFoundError:
                    changed = False
                except OSError as exc:
                    return {'status': 'failed', 'changed': False, 'error': str(exc)}
                verified = _POLICY_NAME not in os.listdir(fds[-1])
                return {'status': 'applied' if verified else 'verification_failed', 'changed': changed,
                        'enabled': False if verified else None, 'verified': verified,
                        'native_updates_enabled': None,
                        'limits': 'Only our drop-in removed. Other administrator updates/reboot policy may remain enabled.'}
            previous = fresh['preconditions']['files'].get('apt/apt.conf.d/' + _POLICY_NAME)
            replaced = False
            try:
                self._replace(fds[-1], content)
                replaced = True
                readback = self._read(fds[-1], _POLICY_NAME)
                config = self._config(self.query(['/usr/bin/apt-config', 'dump']), fresh['origins'])
                verified = (readback['content'] == content and
                            config.get('unattended-upgrade::allowed-origins::') == fresh['origins']
                            and config.get('unattended-upgrade::automatic-reboot') == ['false']
                            and all(config.get('apt::periodic::' + key) == ['1']
                                    for key in ('enable', 'update-package-lists', 'unattended-upgrade')))
                if not verified:
                    raise ValueError('Native policy read-back did not match security origins')
            except (OSError, ValueError, UnicodeError) as exc:
                if not replaced:
                    return {'status': 'failed', 'changed': False, 'error': str(exc)}
                restored = False
                try:
                    if previous is None:
                        os.unlink(_POLICY_NAME, dir_fd=fds[-1])
                    else:
                        self._replace(fds[-1], previous['content'])
                    os.fsync(fds[-1])
                    restored = (_POLICY_NAME not in os.listdir(fds[-1]) if previous is None
                                else self._read(fds[-1], _POLICY_NAME)['content'] == previous['content'])
                except OSError:
                    restored = False
                return {'status': 'verification_failed', 'changed': not restored,
                        'rolled_back': restored, 'enabled': None, 'error': str(exc)}
        return {'status': 'applied', 'changed': True,
                'enabled': True, 'verified': True,
                'limits': 'Policy only: no update installation or reboot performed.'}

    def plan(self, enabled: bool) -> dict:
        try:
            snapshot = self._snapshot()
        except (OSError, UnicodeError) as exc:
            return {'status': 'unsafe', 'changed': False, 'error': str(exc)}
        release = {}
        for line in snapshot['os-release']['content'].splitlines():
            if not line.strip() or line.lstrip().startswith('#'):
                continue
            match = re.fullmatch(r'([A-Z_]+)=(?:"([^"\n]*)"|\'([^\'\n]*)\'|([^\s"\']+))', line)
            if not match or match[1] in release:
                return {'status': 'unsupported', 'changed': False, 'error': 'Invalid or duplicate os-release fields'}
            release[match[1]] = next(v for v in match.groups()[1:] if v is not None)
        codename = release.get('VERSION_CODENAME', '')
        distro = release.get('ID', '')
        supported = {'debian': {'bookworm', 'trixie'}, 'ubuntu': {'jammy', 'noble'}}
        if codename not in supported.get(distro, set()):
            return {'status': 'unsupported', 'changed': False, 'error': 'Only Debian bookworm/trixie and Ubuntu jammy/noble are supported'}
        origins = ([f'Debian:{codename}-security', f'Debian-Security:{codename}-security']
                   if distro == 'debian' else [f'Ubuntu:{codename}-security'])
        for path, entry in snapshot.items():
            if entry is None or path == 'os-release':
                continue
            text = entry['content']
            if path == 'apt/apt.conf.d/' + _POLICY_NAME:
                if text != _policy_content(origins):
                    return {'status': 'conflict', 'changed': False, 'error': 'Fixed policy path is not an exact Custodian-managed file'}
                continue
            if (re.search(r'#\s*include', text, re.IGNORECASE)
                    or (text.strip() and (path == 'apt/apt.conf' or Path(path).name > _POLICY_NAME))):
                return {'status': 'conflict', 'changed': False,
                        'error': 'Untracked includes or later APT policy require independent administrator review: ' + path}
        try:
            package = self.query(list(_NATIVE_QUERIES[0]))
            timers = self.query(list(_NATIVE_QUERIES[1]))
            config = self.query(list(_NATIVE_QUERIES[2]))
        except OSError as exc:
            return {'status': 'prerequisite_missing', 'changed': False, 'error': str(exc)}
        if enabled and (package.strip() != 'install ok installed'
                        or timers.count('LoadState=loaded\n') != 2
                        or timers.count('ActiveState=active\n') != 2
                        or timers.count('UnitFileState=enabled\n') != 2):
            return {'status': 'prerequisite_missing', 'changed': False,
                    'error': 'Install unattended-upgrades and enable/start both APT timers independently as administrator; no packages or timers changed'}
        try:
            self._config(config, origins)
        except ValueError as exc:
            return {'status': 'conflict', 'changed': False, 'error': str(exc)}
        try:
            if self._snapshot() != snapshot:
                return {'status': 'stale', 'changed': False, 'error': 'Policy state changed during inspection'}
        except (OSError, UnicodeError) as exc:
            return {'status': 'stale', 'changed': False, 'error': str(exc)}
        files = {_POLICY_PATH: _policy_content(origins) if enabled else None}
        plan = {'status': 'ready', 'enabled': enabled, 'origins': origins, 'files': files,
                'preconditions': {'files': snapshot, 'package': package, 'timers': timers, 'apt_config': config},
                'effects': ['Enable daily native security updates and package-list refresh; Automatic-Reboot stays false (never reboot).'
                            if enabled else 'Remove only the Custodian drop-in; reveal underlying administrator policy.'],
                'limits': 'No update installation or reboot is performed by applying this policy.'}
        return {**plan, 'plan_id': _plan_hash(plan)}

_NATIVE_QUERIES = (
    ('/usr/bin/dpkg-query', '-W', '-f=${Status}\\n', 'unattended-upgrades'),
    ('/usr/bin/systemctl', 'show', 'apt-daily.timer', 'apt-daily-upgrade.timer',
     '--no-pager', '--property=LoadState,ActiveState,UnitFileState'),
    ('/usr/bin/apt-config', 'dump'),
)


def _native_policy_query(argv: list[str]) -> str:
    if tuple(argv) not in _NATIVE_QUERIES:
        raise ValueError('Only fixed read-only native policy queries are allowed')
    try:
        child = subprocess.run(argv, capture_output=True, text=True, timeout=15,
                               check=False, env=minimal_env('native-policy'))
    except subprocess.TimeoutExpired as exc:
        raise OSError('Native policy query timed out') from exc
    if child.returncode:
        raise OSError('Native policy query failed: ' + child.stderr.strip())
    return child.stdout


def plan_security_updates(enabled: bool) -> dict:
    """Read-only native security-policy preview. Production paths are pinned."""
    if NAME != 'linux':
        return {'status': 'unsupported', 'changed': False, 'error': 'Security-update automation is Linux-only'}
    if type(enabled) is not bool:
        return {'status': 'invalid', 'changed': False, 'error': 'enabled must be a boolean'}
    return _SecurityPolicy(Path('/etc'), owner_uid=0, query=_native_policy_query).plan(enabled)


def apply_security_update_policy(plan: dict, approval: str) -> dict:
    """ADMIN CLI ONLY. Never register as an AI tool or expose through HTTP.

    CLI must collect exact typed consent from an administrator's terminal and
    execute from a separately trusted root-owned installation, not a user venv.
    No sudo invocation, packages, shell, or model runtime is involved here.
    """
    if NAME != 'linux':
        return {'status': 'unsupported', 'changed': False, 'error': 'Security-update automation is Linux-only'}
    if os.geteuid() != 0 or os.getuid() != 0:
        return {'status': 'denied', 'changed': False, 'error': 'Requires a real root administrator CLI; no privilege escalation is provided'}
    return _SecurityPolicy(Path('/etc'), owner_uid=0, query=_native_policy_query).apply(plan, approval)


_ROW = re.compile(r'^(?P<name>[a-z0-9][a-z0-9+.:\-]*)/(?P<suites>\S+)\s+'
                  r'(?P<candidate>\S+)\s+(?P<architecture>\S+)\s+'
                  r'\[upgradable from: (?P<installed>[^\]\s]+)\]$')
_SECURITY_SUITE = re.compile(r'^(?:stable|oldstable|oldoldstable|buster|bullseye|bookworm|trixie|forky|'
                             r'xenial|bionic|focal|jammy|noble|questing|resolute)-security$')


def _failure(status: str, error: str, returncode: int | None = None) -> dict:
    return {'status': status, 'backend': 'apt', 'cache_only': True,
            'cache_freshness': 'unknown', 'error': error, 'returncode': returncode,
            'packages': [], 'upgradable_count': None, 'security_count': None,
            'security_unknown_count': None}


def configure_security_updates(enabled: bool, *, trusted_cli: bool = False,
                               plan: dict | None = None, approval: str | None = None) -> dict:
    """Thin admin-CLI wrapper around plan_security_updates and apply_security_update_policy.

    Never callable from AI tools or web surfaces; requires explicit trusted_cli=True.
    Without plan/approval, returns the read-only plan_security_updates(enabled) preview.
    With plan and approval, verifies plan['enabled'] matches enabled and delegates to
    apply_security_update_policy(plan, approval) (which requires real and effective root).
    """
    if NAME != 'linux':
        return {'status': 'unsupported', 'changed': False, 'error': 'Security-update automation is Linux-only'}
    if type(enabled) is not bool:
        return {'status': 'invalid', 'changed': False, 'enabled': None, 'error': 'enabled must be a boolean'}
    if not trusted_cli:
        return {'status': 'denied', 'changed': False, 'enabled': None,
                'error': 'trusted_cli=True required; model, tool and web surfaces may never configure updates'}
    if plan is None and approval is None:
        return plan_security_updates(enabled)
    if not isinstance(plan, dict) or plan.get('enabled') is not enabled:
        return {'status': 'mismatch', 'changed': False, 'enabled': None,
                'error': 'Supplied plan does not match requested enabled state'}
    return apply_security_update_policy(plan, approval)


def _check_updates_linux() -> dict:
    try:
        child = subprocess.run(['apt', 'list', '--upgradable'], capture_output=True,
                               text=True, timeout=30, check=False,
                               env=minimal_env('apt'))
    except OSError as exc:
        return _failure('unavailable', str(exc))
    except subprocess.TimeoutExpired:
        return _failure('failed', 'APT listing timed out after 30 seconds')
    if child.returncode != 0:
        return _failure('failed', child.stderr.strip() or 'APT exited unsuccessfully', child.returncode)
    packages = []
    saw_header = False
    for line in child.stdout.splitlines():
        line = line.strip()
        if line in ('Listing...', 'Listing... Done'):
            saw_header = True
            continue
        if not line:
            continue
        match = _ROW.fullmatch(line)
        if not match:
            return _failure('unknown', 'Unrecognized APT listing format; counts are unavailable')
        row = match.groupdict()
        suites = row['suites'].split(',')
        packages.append({'name': row['name'], 'candidate_version': row['candidate'],
                         'installed_version': row['installed'], 'architecture': row['architecture'],
                         'suites': suites, 'security': True if any(_SECURITY_SUITE.fullmatch(s) for s in suites) else None})
    if not saw_header and not packages:
        return _failure('unknown', 'APT returned no recognizable listing')
    return {'status': 'ok', 'backend': 'apt', 'cache_only': True,
            'cache_freshness': 'unknown', 'packages': packages,
            'upgradable_count': len(packages),
            'security_count': sum(p['security'] is True for p in packages),
            'security_unknown_count': sum(p['security'] is None for p in packages),
            'security_basis': 'recognized repository suite name, not origin authentication'}


def _check_updates_macos() -> dict:
    try:
        child = subprocess.run(['softwareupdate', '-l'], capture_output=True,
                               text=True, timeout=60, check=False,
                               env=minimal_env('softwareupdate'))
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {'status': 'unavailable', 'backend': 'softwareupdate', 'cache_only': True,
                'cache_freshness': 'unknown', 'error': str(exc), 'packages': [],
                'upgradable_count': None, 'security_count': None, 'security_unknown_count': None}
    if child.returncode != 0:
        return {'status': 'unavailable', 'backend': 'softwareupdate', 'cache_only': True,
                'cache_freshness': 'unknown', 'error': child.stderr.strip() or 'softwareupdate exited unsuccessfully',
                'returncode': child.returncode, 'packages': [],
                'upgradable_count': None, 'security_count': None, 'security_unknown_count': None}

    import platform
    arch = platform.machine()
    packages = []
    current = None
    for raw_line in child.stdout.splitlines():
        line = raw_line.strip()
        if line.startswith('* Label:'):
            if current:
                packages.append(current)
            label = line.split('* Label:', 1)[1].strip()
            current = {'name': label, 'candidate_version': 'unknown',
                       'installed_version': None, 'architecture': arch,
                       'suites': ['softwareupdate'], 'security': None}
        elif current is not None:
            version_m = re.search(r'Version:\s*([^,\s]+)', line)
            if version_m:
                current['candidate_version'] = version_m.group(1).strip()
    if current:
        packages.append(current)

    return {'status': 'ok', 'backend': 'softwareupdate', 'cache_only': True,
            'cache_freshness': 'unknown', 'packages': packages,
            'upgradable_count': len(packages),
            'security_count': 0,
            'security_unknown_count': len(packages),
            'security_basis': 'recognized repository suite name, not origin authentication'}


_WIN_UPDATE_SCRIPT = (
    "$session = New-Object -ComObject Microsoft.Update.Session; "
    "$searcher = $session.CreateUpdateSearcher(); "
    "$result = $searcher.Search('IsInstalled=0 and IsHidden=0'); "
    "$updates = @(); "
    "foreach ($u in $result.Updates) { "
    "  $kbs = @(); foreach ($k in $u.KBArticleIDs) { $kbs += $k }; "
    "  $cats = @(); foreach ($c in $u.Categories) { $cats += $c.Name }; "
    "  $updates += [PSCustomObject]@{ "
    "    Title = $u.Title; "
    "    KB = ($kbs -join ','); "
    "    Categories = $cats; "
    "    MsrcSeverity = $u.MsrcSeverity; "
    "  } "
    "}; "
    "ConvertTo-Json -Compress -InputObject @($updates)"
)


def _check_updates_windows() -> dict:
    try:
        child = subprocess.run([
            'powershell.exe', '-NoProfile', '-NonInteractive',
            '-ExecutionPolicy', 'Bypass', '-Command', _WIN_UPDATE_SCRIPT
        ], capture_output=True, text=True, timeout=90, check=False,
            executable=windows_system_executable('powershell.exe'),
            env=minimal_env('powershell'))
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {'status': 'unavailable', 'backend': 'windowsupdate', 'cache_only': True,
                'cache_freshness': 'unknown', 'error': str(exc), 'packages': [],
                'upgradable_count': None, 'security_count': None, 'security_unknown_count': None}
    if child.returncode != 0:
        return {'status': 'unavailable', 'backend': 'windowsupdate', 'cache_only': True,
                'cache_freshness': 'unknown', 'error': child.stderr.strip() or 'PowerShell exited unsuccessfully',
                'returncode': child.returncode, 'packages': [],
                'upgradable_count': None, 'security_count': None, 'security_unknown_count': None}

    stdout = child.stdout.strip()
    if not stdout:
        raw_items = []
    else:
        try:
            data = json.loads(stdout)
            if isinstance(data, dict):
                raw_items = [data]
            elif isinstance(data, list):
                raw_items = data
            else:
                raw_items = []
        except (json.JSONDecodeError, ValueError) as exc:
            return {'status': 'unavailable', 'backend': 'windowsupdate', 'cache_only': True,
                    'cache_freshness': 'unknown', 'error': f'Invalid JSON from PowerShell: {exc}',
                    'packages': [], 'upgradable_count': None, 'security_count': None, 'security_unknown_count': None}

    import platform
    arch = platform.machine()
    packages = []
    for item in raw_items:
        if not isinstance(item, dict):
            continue
        title = item.get('Title') or 'unknown'
        kb = item.get('KB') or ''
        categories = item.get('Categories') or []
        if isinstance(categories, str):
            categories = [categories]
        severity = item.get('MsrcSeverity')

        is_security = ('Security Updates' in categories) or bool(severity and str(severity).strip())
        security = True if is_security else None
        candidate_version = kb if kb else title

        packages.append({
            'name': title,
            'candidate_version': candidate_version,
            'installed_version': None,
            'architecture': arch,
            'suites': categories,
            'security': security,
        })

    return {
        'status': 'ok',
        'backend': 'windowsupdate',
        'cache_only': True,
        'cache_freshness': 'unknown',
        'packages': packages,
        'upgradable_count': len(packages),
        'security_count': sum(p['security'] is True for p in packages),
        'security_unknown_count': sum(p['security'] is None for p in packages),
        'security_basis': 'Category or MsrcSeverity',
    }


def check_updates() -> dict:
    """List cached upgrades. Security=True only for recognized security suites.

    Other origins are unknown, not asserted non-security. Cache age and origin
    authenticity are not established by this read-only operation.
    """
    if NAME == 'macos':
        return _check_updates_macos()
    if NAME == 'windows':
        return _check_updates_windows()
    return _check_updates_linux()
