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


MAX_ENTRIES = 20000
MAX_SECONDS = 5.0
MAX_DEPTH = 64
MAX_TOTAL_BYTES = 64 * 1024 * 1024


def bounded_snapshot(root: Path, exclusions: list[str], max_files: int,
                     max_file_bytes: int) -> dict:
    """Snapshot selected scope via the platform backend."""
    from . import _platform
    return _platform.bounded_snapshot(root, exclusions, max_files, max_file_bytes)


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
