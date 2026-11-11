"""Private atomic settings and local SQLite persistence."""
import json
import os
from pathlib import Path
import tempfile
import sqlite3
import stat
import fcntl
import grp
import pwd
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone


def _group_is_private(gid, uid):
    """True when only the current user can ever act through this group.

    That means no other listed members and no other account that has it as its
    primary group. Unknown groups are never private.
    """
    try:
        group = grp.getgrgid(gid)
        me = pwd.getpwuid(uid).pw_name
        if any(member != me for member in group.gr_mem):
            return False
        return all(account.pw_uid == uid for account in pwd.getpwall() if account.pw_gid == gid)
    except (KeyError, OSError):
        return False


class Storage:
    def __init__(self, state_dir):
        self.root = Path(os.path.abspath(state_dir))
        if self.root in (Path('/'), Path.home()):
            raise ValueError('Select a dedicated state directory, not root or home')
        if '..' in Path(state_dir).parts:
            raise ValueError('state_dir must not contain traversal components')
        # Reject any ancestor directory writable by another uid unless it is both
        # sticky (S_ISVTX) and root-owned (uid 0), preventing non-root ancestor
        # rename/replacement races before pathname-based SQLite reopens.
        uid = os.getuid()
        gid = os.getgid()
        parts = self.root.parts[1:]
        directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
        try:
            for index, component in enumerate(parts):
                is_last = index == len(parts) - 1
                ancestor = os.fstat(directory)
                if ancestor.st_uid not in (uid, 0):
                    raise ValueError('state_dir ancestor owner must be the current user or root')
                ancestor_mode = getattr(ancestor, 'st_mode', 0o700)
                sticky_root = bool((ancestor_mode & stat.S_ISVTX) and ancestor.st_uid == 0)
                if (ancestor_mode & stat.S_IWOTH) and not sticky_root:
                    raise ValueError('state_dir ancestor must not be writable by other users unless sticky and root-owned')
                # Stock Ubuntu/Raspberry Pi OS use umask 002, so ordinary folders are 775.
                # Group write is harmless when the directory is ours and nobody else is
                # in that group; any other group-writable ancestor stays rejected.
                group_ok = ancestor.st_uid == uid and _group_is_private(getattr(ancestor, 'st_gid', gid), uid)
                if (ancestor_mode & stat.S_IWGRP) and not sticky_root and not group_ok:
                    raise ValueError('state_dir ancestor must not be writable by other users unless sticky and root-owned')
                try:
                    os.mkdir(component, mode=0o700, dir_fd=directory)
                except FileExistsError:
                    pass
                try:
                    child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                    dir_fd=directory)
                except OSError as exc:
                    raise ValueError('state_dir must have only accessible nonsymlink directories') from exc
                os.close(directory)
                directory = child
            if os.fstat(directory).st_uid != uid:
                raise ValueError('state_dir owner must be the current user')
            os.fchmod(directory, 0o700)
            for name in ('settings.json', 'state.sqlite3', 'monitor.json', 'monitor.lock', 'scan.lock',
                         'state.sqlite3-journal', 'state.sqlite3-wal', 'state.sqlite3-shm'):
                try:
                    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
                except FileNotFoundError:
                    continue
                try:
                    info = os.fstat(fd)
                    if info.st_uid != os.getuid() or info.st_nlink != 1 or not stat.S_ISREG(info.st_mode):
                        raise ValueError('State files must be current-user regular files without hard links')
                    os.fchmod(fd, 0o600)
                finally:
                    os.close(fd)
        finally:
            os.close(directory)
        self.config_path = self.root / 'settings.json'

    def settings(self):
        try:
            fd = os.open(self.config_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            raise ValueError('Custodian is not configured; run setup first') from None
        with os.fdopen(fd, 'r', encoding='utf-8') as handle:
            info = os.fstat(handle.fileno())
            if info.st_uid != os.getuid() or info.st_nlink != 1:
                raise ValueError('Settings must be owned by the current user without hard links')
            if not stat.S_ISREG(info.st_mode) or info.st_size > 1048576:
                raise ValueError('Settings must be a bounded regular file')
            os.fchmod(handle.fileno(), 0o600)
            text = handle.read(1048577)
            if len(text) > 1048576:
                raise ValueError('Settings byte budget exceeded')
            return json.loads(text)

    def monitor(self):
        try:
            fd = os.open(self.root / 'monitor.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            return None
        with os.fdopen(fd, 'r', encoding='utf-8') as handle:
            info = os.fstat(handle.fileno())
            if (info.st_uid != os.getuid() or info.st_nlink != 1 or
                    not stat.S_ISREG(info.st_mode) or info.st_size > 65536):
                raise ValueError('Monitor metadata must be a bounded current-user regular file')
            os.fchmod(handle.fileno(), 0o600)
            text = handle.read(65537)
            if len(text) > 65536:
                raise ValueError('Monitor metadata exceeds byte budget')
            value = json.loads(text)
            if not isinstance(value, dict):
                raise ValueError('Monitor metadata must be an object')
            return value

    def save_settings(self, settings):
        fd, name = tempfile.mkstemp(prefix='.settings-', dir=self.root)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as handle:
                json.dump(settings, handle, sort_keys=True, indent=2)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(name, self.config_path)
            directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(name):
                os.unlink(name)

    @contextmanager
    def scan_lock(self, timeout=30.0):
        """Per-state-directory interprocess lock serialising scan and setup.

        Uses ``scan.lock`` (never the monitor's lifetime ``monitor.lock``) so a
        monitor holding its singleton lock can still scan. Waits at most
        ``timeout`` seconds, then raises TimeoutError instead of hanging.
        """
        fd = os.open(self.root / 'scan.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            info = os.fstat(fd)
            if info.st_uid != os.getuid() or info.st_nlink != 1 or not stat.S_ISREG(info.st_mode):
                raise ValueError('Scan lock must be a current-user regular file without hard links')
            os.fchmod(fd, 0o600)
            deadline = time.monotonic() + max(0.0, float(timeout))
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError('Another Custodian scan or setup is in progress for this '
                                           f'state directory; gave up after {timeout:g}s') from None
                    time.sleep(0.05)
            try:
                yield
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    @contextmanager
    def connection(self):
        path = self.root / 'state.sqlite3'
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if info.st_uid != os.getuid() or info.st_nlink != 1 or not stat.S_ISREG(info.st_mode):
                raise ValueError('Database must be a current-user regular file without hard links')
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
        db = sqlite3.connect(path, timeout=5)
        try:
            db.execute('PRAGMA secure_delete=ON')
            db.executescript('''
                CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, data TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, timestamp TEXT, data TEXT);
                CREATE TABLE IF NOT EXISTS findings (id TEXT PRIMARY KEY, data TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT, kind TEXT, path TEXT, summary TEXT);
            ''')
            with db:
                yield db
        finally:
            db.close()

    def baseline(self, signature):
        with self.connection() as db:
            row = db.execute('SELECT data FROM state WHERE key=?', ('baseline',)).fetchone()
        if not row:
            return None
        value = json.loads(row[0])
        return value['files'] if value['signature'] == signature else None

    def record_scan(self, result, files, signature, retention_days, covered=None):
        with self.connection() as db:
            previous = {row[0]: json.loads(row[1]) for row in db.execute('SELECT id,data FROM findings')}
            seen = set()
            for finding in result['findings']:
                seen.add(finding['id'])
                old = previous.get(finding['id'])
                if old:
                    finding['first_seen'] = old['first_seen']
                db.execute('INSERT OR REPLACE INTO findings VALUES (?,?)',
                           (finding['id'], json.dumps(finding)))
                if not old or old['status'] != 'open':
                    db.execute('INSERT INTO events(timestamp,kind,path,summary) VALUES (?,?,?,?)',
                               (result['finished_at'], 'finding_opened', finding['path'], finding['title']))
            if result['complete']:
                for key, old in previous.items():
                    if key in seen or old['status'] not in ('open', 'out_of_scope'):
                        continue
                    is_covered = covered(old['path']) if covered is not None else (
                        old.get('scope_signature', signature) == signature
                    )
                    if is_covered:
                        old['status'] = 'resolved'
                        old['last_seen'] = result['finished_at']
                        old['scope_signature'] = signature
                        db.execute('UPDATE findings SET data=? WHERE id=?', (json.dumps(old), key))
                        db.execute('INSERT INTO events(timestamp,kind,path,summary) VALUES (?,?,?,?)',
                                   (result['finished_at'], 'finding_resolved', old['path'], old['title']))
                    elif old['status'] != 'out_of_scope':
                        old['status'] = 'out_of_scope'
                        db.execute('UPDATE findings SET data=? WHERE id=?', (json.dumps(old), key))
                        db.execute('INSERT INTO events(timestamp,kind,path,summary) VALUES (?,?,?,?)',
                                   (result['finished_at'], 'finding_out_of_scope', old['path'], old['title']))
                db.execute('INSERT OR REPLACE INTO state VALUES (?,?)',
                           ('baseline', json.dumps({'signature': signature, 'files': files})))
            for change in result['changes']:
                db.execute('INSERT INTO events(timestamp,kind,path,summary) VALUES (?,?,?,?)',
                           (result['finished_at'], change['kind'], change['path'], 'File metadata changed'))
            db.execute('INSERT INTO events(timestamp,kind,path,summary) VALUES (?,?,?,?)',
                       (result['finished_at'], 'scan_completed' if result['complete'] else 'scan_degraded',
                        '', f"Checked {result['files_checked']} files"))
            db.execute('INSERT INTO scans VALUES (?,?,?)',
                       (result['scan_id'], result['finished_at'], json.dumps(result)))
            cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()
            db.execute('DELETE FROM events WHERE timestamp < ?', (cutoff,))
            db.execute('DELETE FROM scans WHERE timestamp < ?', (cutoff,))
            db.execute('DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT 10000)')
            db.execute('DELETE FROM scans WHERE id NOT IN (SELECT id FROM scans ORDER BY timestamp DESC LIMIT 1000)')
            for key, old in previous.items():
                if old['status'] == 'resolved' and old['last_seen'] < cutoff:
                    db.execute('DELETE FROM findings WHERE id=?', (key,))

    def findings(self):
        with self.connection() as db:
            return [json.loads(row[0]) for row in db.execute('SELECT data FROM findings ORDER BY id')]

    def last_scan(self):
        with self.connection() as db:
            row = db.execute('SELECT data FROM scans ORDER BY timestamp DESC LIMIT 1').fetchone()
        return json.loads(row[0]) if row else None

    def events(self, limit):
        with self.connection() as db:
            rows = db.execute('SELECT id,timestamp,kind,path,summary FROM events ORDER BY id DESC LIMIT ?', (limit,))
            return [dict(zip(('id', 'timestamp', 'kind', 'path', 'summary'), row)) for row in rows]
