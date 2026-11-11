"""Custodian-owned local login verifier, not a reader of Hermes credentials.

The standalone dashboard uses this module. Hermes tools never read this store.
A same-user shell can still replace local application state; this is not a sandbox.
"""
from __future__ import annotations
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
import tempfile
import threading
from .storage import Storage

_HASH_LOCK = threading.BoundedSemaphore(1)
_PARAMS = {'n': 16384, 'r': 8, 'p': 1, 'dklen': 32}


class DashboardAuth:
    def __init__(self, state_dir: Path):
        self.root = Storage(state_dir).root
        self.path = self.root / 'dashboard-login.json'

    def _record(self):
        fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(fd, 'r', encoding='utf-8') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_mode & 0o077 or info.st_size > 4096:
                raise ValueError('Dashboard login verifier must be a private, singly-linked regular file')
            record = json.loads(stream.read(4097))
        if not isinstance(record, dict) or record.get('schema_version') != 1 or record.get('scrypt') != _PARAMS:
            raise ValueError('Unsupported dashboard login verifier')
        if not re.fullmatch(r'[A-Za-z0-9_.-]{3,64}', record.get('username', '')):
            raise ValueError('Invalid dashboard username record')
        for field, length in [('salt', 64), ('verifier', 64), ('revision', 32)]:
            if not isinstance(record.get(field), str) or not re.fullmatch('[0-9a-f]{' + str(length) + '}', record[field]):
                raise ValueError('Invalid dashboard verifier format')
        return record

    def configured(self):
        try:
            self._record()
            return True
        except (OSError, ValueError, TypeError):
            return False

    def revision(self):
        return self._record()['revision']

    def configure(self, username: str, password: str):
        if not isinstance(username, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{3,64}', username):
            raise ValueError('Username must be 3–64 letters, numbers, dots, hyphens or underscores')
        if not isinstance(password, str) or not 12 <= len(password) <= 1024:
            raise ValueError('Use a unique password or passphrase of 12–1024 characters')
        # Refuse an unsafe existing target rather than following or silently replacing it.
        try:
            self._record()
        except FileNotFoundError:
            pass
        salt = secrets.token_bytes(32)
        with _HASH_LOCK:
            verifier = hashlib.scrypt(password.encode('utf-8'), salt=salt, maxmem=32 * 1024 * 1024, **_PARAMS)
        record = {'schema_version': 1, 'username': username, 'salt': salt.hex(), 'verifier': verifier.hex(), 'scrypt': _PARAMS, 'revision': secrets.token_hex(16)}
        fd, name = tempfile.mkstemp(prefix='.dashboard-login-', dir=self.root)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as output:
                json.dump(record, output)
                output.flush()
                os.fsync(output.fileno())
            os.replace(name, self.path)
            directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(name):
                os.unlink(name)

    def authenticate(self, username: str, password: str):
        if not isinstance(username, str) or not isinstance(password, str) or len(username) > 64 or len(password) > 1024:
            return False
        try:
            record = self._record()
            # Fixed parameters and bounded concurrency prevent attacker-controlled scrypt costs.
            if not _HASH_LOCK.acquire(blocking=False):
                return False
            try:
                verifier = hashlib.scrypt(password.encode('utf-8'), salt=bytes.fromhex(record['salt']), maxmem=32 * 1024 * 1024, **_PARAMS)
            finally:
                _HASH_LOCK.release()
            return hmac.compare_digest(username.encode('utf-8'), record['username'].encode('utf-8')) & hmac.compare_digest(verifier.hex(), record['verifier'])
        except (OSError, ValueError, TypeError, KeyError, UnicodeError):
            return False
