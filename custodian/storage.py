"""Private atomic settings and local SQLite persistence."""
import json
import os
from pathlib import Path
import tempfile
import sqlite3
import stat
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

from . import _platform

try:
    from ._platform import posix as _posix
    grp = getattr(_posix, 'grp', None)
    pwd = getattr(_posix, 'pwd', None)
except ImportError:
    grp = None
    pwd = None


def _group_is_private(gid, uid):
    return _platform.posix._group_is_private(gid, uid)


class Storage:
    def __init__(self, state_dir):
        self.root = Path(os.path.abspath(state_dir))
        if self.root in (Path('/'), Path.home()):
            raise ValueError('Select a dedicated state directory, not root or home')
        if '..' in Path(state_dir).parts:
            raise ValueError('state_dir must not contain traversal components')
        _platform.validate_state_root(self.root)
        self.config_path = self.root / 'settings.json'

    def settings(self):
        try:
            fd = _platform.open_private_file(self.config_path, write=False, create=False, max_bytes=1048576)
        except FileNotFoundError:
            raise ValueError('Custodian is not configured; run setup first') from None
        with os.fdopen(fd, 'r', encoding='utf-8') as handle:
            text = handle.read(1048577)
            if len(text) > 1048576:
                raise ValueError('Settings byte budget exceeded')
            return json.loads(text)

    def monitor(self):
        try:
            fd = _platform.open_private_file(self.root / 'monitor.json', write=False, create=False, max_bytes=65536)
        except FileNotFoundError:
            return None
        with os.fdopen(fd, 'r', encoding='utf-8') as handle:
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
            _platform.fsync_directory(self.root)
        finally:
            if os.path.exists(name):
                os.unlink(name)

    @contextmanager
    def scan_lock(self, timeout=30.0):
        """Per-state-directory interprocess lock serialising scan and setup."""
        with _platform.interprocess_lock(self.root / 'scan.lock', timeout):
            yield

    @contextmanager
    def connection(self):
        path = self.root / 'state.sqlite3'
        fd = _platform.open_private_file(path, write=True, create=True)
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
