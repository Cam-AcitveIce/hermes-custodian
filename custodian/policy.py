"""Conservative, credential-free filesystem observation. No execution helpers."""
import hashlib
from fnmatch import fnmatchcase
from itertools import islice
import os
from pathlib import Path
import re
import stat
import time
import unicodedata


_ANSI = re.compile(r'(?:\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\|$)|\x1b[P^_X].*?(?:\x1b\\|$)|\x1b[@-_])', re.DOTALL)


def sanitise_text(value: str) -> str:
    """Remove terminal escapes, controls, surrogate and formatting characters."""
    text = _ANSI.sub('', value)
    return ''.join(c for c in text if not unicodedata.category(c).startswith('C')
                   and c not in '\u2028\u2029')


def _entry_type(mode: int) -> str:
    if stat.S_ISREG(mode):
        return 'file'
    if stat.S_ISLNK(mode):
        return 'symlink'
    return 'other'


def _metadata(path: Path, info: os.stat_result) -> dict:
    return {'path': str(path), 'type': _entry_type(info.st_mode),
            'mode': stat.S_IMODE(info.st_mode),
            'uid': info.st_uid, 'size': info.st_size, 'mtime_ns': info.st_mtime_ns}


def safe_metadata(path: Path) -> dict:
    """Return lstat metadata, never opening the final entry or following it."""
    return _metadata(path, Path(path).lstat())


def _display_name(value):
    if (isinstance(value, str) and len(value) <= 128
            and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_. /:@+-]*', value)
            and '://' not in value and '@' not in value
            and not value.startswith(('/', '.'))):
        return value
    return None


def redact_config(config: dict) -> dict:
    """Extract display names only; never recursively copy arbitrary config."""
    result = {}
    model = config.get('model')
    for key, value in (('model', model.get('default') if isinstance(model, dict) else model),
                       ('provider', config.get('provider', model.get('provider')
                        if isinstance(model, dict) else None))):
        name = _display_name(value)
        if name:
            result[key] = name
    for key in ('plugins', 'mcp_servers'):
        value = config.get(key)
        if key == 'plugins' and isinstance(value, dict) and 'enabled' in value:
            value = value['enabled']
        if isinstance(value, dict):
            reserved = {'env', 'args', 'command', 'commands', 'api_key', 'api_keys',
                        'token', 'tokens', 'secret', 'secrets', 'url', 'urls', 'base_url',
                        'headers', 'credentials', 'password', 'enabled', 'disabled'}
            candidates = [name for name in islice(value, 100)
                          if isinstance(name, str) and name.casefold() not in reserved]
        elif isinstance(value, list):
            candidates = [v.get('name') if isinstance(v, dict) else v for v in value[:100]]
        else:
            continue
        names = [name for v in candidates if (name := _display_name(v))]
        if names:
            result[key] = list(dict.fromkeys(names))
    return result


def _signature(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _open_root(root: Path) -> int:
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in root.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


MAX_ENTRIES = 20000
MAX_SECONDS = 5.0
MAX_DEPTH = 64
MAX_TOTAL_BYTES = 64 * 1024 * 1024


class _BudgetExceeded(Exception):
    pass


def bounded_snapshot(root: Path, exclusions: list[str], max_files: int,
                     max_file_bytes: int) -> dict:
    """Snapshot selected scope with descriptor-relative no-follow traversal.

    Only non-sensitive, singly-linked .py/.md files are content-hashed. Other
    entries are metadata-only; sensitive directories are never enumerated.
    A cooperative deadline cannot interrupt a stalled kernel filesystem call.
    """
    result = {'files': [], 'errors': [], 'complete': True}
    if (type(max_files) is not int or max_files <= 0
            or type(max_file_bytes) is not int or max_file_bytes <= 0
            or '..' in Path(root).parts
            or not isinstance(exclusions, list) or len(exclusions) > 100
            or any(not isinstance(p, str) or len(p) > 4096 for p in exclusions)):
        return {'files': [], 'errors': ['Invalid scan scope or limits'], 'complete': False}
    root = Path(os.path.abspath(root))

    def error(message):
        result['complete'] = False
        if len(result['errors']) < 100:
            result['errors'].append(message)

    visited = 0
    total_bytes = 0
    deadline = time.monotonic() + MAX_SECONDS

    def check_time():
        if time.monotonic() >= deadline:
            raise _BudgetExceeded('Scan time budget exhausted')

    def walk(fd, path, depth=0):
        nonlocal visited, total_bytes
        check_time()
        with os.scandir(fd) as entries:
            for entry in entries:
                check_time()
                if visited >= MAX_ENTRIES:
                    raise _BudgetExceeded('Traversal entry budget exhausted')
                visited += 1
                if len(result['files']) >= max_files:
                    error('File budget exhausted')
                    return
                child = path / entry.name
                relative = str(child.relative_to(root))
                if any(fnmatchcase(relative, pattern) or fnmatchcase(str(child), pattern)
                       or fnmatchcase(entry.name, pattern) for pattern in exclusions):
                    continue
                info = os.stat(entry.name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode) and not is_sensitive(child):
                    if depth >= MAX_DEPTH:
                        raise _BudgetExceeded('Directory depth budget exhausted')
                    directory = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    try:
                        opened = os.fstat(directory)
                        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                            raise OSError('Directory replaced before traversal')
                        walk(directory, child, depth + 1)
                    finally:
                        os.close(directory)
                else:
                    item = _metadata(child, info)
                    if (stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and not is_sensitive(child)
                            and child.suffix.lower() in {'.py', '.md'}):
                        if info.st_size > max_file_bytes:
                            error('File byte budget exceeded')
                            result['files'].append(item)
                            continue
                        if total_bytes + info.st_size > MAX_TOTAL_BYTES:
                            raise _BudgetExceeded('Aggregate byte budget exhausted')
                        handle = os.open(entry.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                        try:
                            opened = os.fstat(handle)
                            if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                                    or _signature(opened) != _signature(info)):
                                raise OSError('Entry replaced before read')
                            digest = hashlib.sha256()
                            remaining = info.st_size
                            while remaining:
                                check_time()
                                chunk = os.read(handle, min(65536, remaining))
                                if not chunk:
                                    break
                                total_bytes += len(chunk)
                                digest.update(chunk)
                                remaining -= len(chunk)
                            if remaining or _signature(os.fstat(handle)) != _signature(info):
                                raise OSError('File changed during hashing')
                            check_time()
                            item['sha256'] = digest.hexdigest()
                        finally:
                            os.close(handle)
                    result['files'].append(item)
    try:
        if is_sensitive(root):
            parent = _open_root(root.parent)
            try:
                result['files'].append(_metadata(root, os.stat(root.name, dir_fd=parent,
                                                              follow_symlinks=False)))
            finally:
                os.close(parent)
            return result
        fd = _open_root(root)
        try:
            walk(fd, root)
        finally:
            os.close(fd)
    except _BudgetExceeded as exc:
        error(str(exc))
    except (OSError, ValueError):
        error('Filesystem entry unavailable, changed, or unsafe')
    return result


def is_sensitive(path: Path) -> bool:
    """Classify by path only; never inspect potentially secret contents."""
    for part in Path(path).parts:
        name = part.casefold()
        if (name.startswith(('.env', 'auth.', 'auth-', 'auth_', 'oauth', 'id_rsa', 'id_ed25519', 'id_ecdsa', 'id_dsa'))
                or any(word in name for word in ('credential', 'token', 'secret', 'private_key',
                                                 'private-key', 'privkey', 'keychain', 'apikey',
                                                 'password', 'api_key', 'api-key',
                                                 'google-chrome', 'bravesoftware', 'microsoft-edge'))
                or name in {'auth', 'wallet', 'gcloud', '.netrc', '.npmrc', '.pypirc', '.aws', '.azure', '.docker',
                            'user.md', 'memory.md', 'logs', 'conversations',
                            'auth.json', 'auth.yaml', 'auth.yml', '.ssh', '.gnupg',
                            'browser', 'browsers', 'cookies', 'login data', 'web data',
                            'local state', 'key4.db', 'logins.json', 'cert9.db',
                            'memories', 'memory', 'history', 'sessions', 'soul.md',
                            'chrome', 'chromium', 'firefox', '.mozilla'}
                or name.endswith(('.pem', '.key', '.p12', '.pfx', '.keystore', '.kdbx'))):
            return True
    return False
