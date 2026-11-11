import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from custodian.storage import Storage


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.store = Storage(self.root / 'state')

    def test_failed_atomic_replace_preserves_previous_settings_and_removes_temp(self):
        self.store.save_settings({'value': 'old'})
        with patch('custodian.storage.os.replace', side_effect=OSError('synthetic failure')):
            with self.assertRaises(OSError):
                self.store.save_settings({'value': 'new'})
        self.assertEqual(self.store.settings(), {'value': 'old'})
        self.assertEqual(list(self.store.root.glob('.settings-*')), [])

    def test_state_directory_rejects_symlink_parent_before_creating_external_directory(self):
        target = self.root / 'outside'
        target.mkdir()
        link = self.root / 'linked'
        link.symlink_to(target, target_is_directory=True)
        with self.assertRaises(ValueError):
            Storage(link / 'state')
        self.assertFalse((target / 'state').exists())

    def test_scan_retention_removes_expired_rows_and_caps_history(self):
        from datetime import datetime, timezone
        import json
        old = '2000-01-01T00:00:00+00:00'
        finding = {'id': 'old', 'status': 'resolved', 'last_seen': old}
        with self.store.connection() as db:
            db.execute('INSERT INTO scans VALUES (?,?,?)', ('old', old, '{}'))
            db.execute('INSERT INTO findings VALUES (?,?)', ('old', json.dumps(finding)))
            db.executemany('INSERT INTO events(timestamp,kind,path,summary) VALUES (?,?,?,?)',
                           [(old, 'test', '', '')] +
                           [(datetime.now(timezone.utc).isoformat(), 'test', '', '')] * 10001)
        now = datetime.now(timezone.utc).isoformat()
        result = {'scan_id': 'new', 'started_at': now, 'finished_at': now, 'complete': True,
                  'findings': [], 'changes': [], 'files_checked': 0, 'errors': []}
        self.store.record_scan(result, {}, 'fixture', 30)
        with self.store.connection() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM scans').fetchone()[0], 1)
            self.assertEqual(db.execute('SELECT count(*) FROM events').fetchone()[0], 10000)
            self.assertEqual(db.execute('SELECT count(*) FROM findings').fetchone()[0], 0)
        self.assertEqual(self.store.last_scan()['scan_id'], 'new')
        self.assertEqual((self.store.root / 'state.sqlite3').stat().st_mode & 0o777, 0o600)

    def test_existing_state_root_and_database_permissions_are_hardened(self):
        self.store.root.chmod(0o755)
        self.store.save_settings({'value': 'fixture'})
        self.store.config_path.chmod(0o644)
        with self.store.connection():
            pass
        database = self.store.root / 'state.sqlite3'
        database.chmod(0o644)
        monitor = self.store.root / 'monitor.json'
        monitor.write_text('{}')
        monitor.chmod(0o644)
        store = Storage(self.store.root)
        self.assertEqual(monitor.stat().st_mode & 0o777, 0o600)
        self.assertEqual(store.root.stat().st_mode & 0o777, 0o700)
        self.assertEqual(store.config_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(database.stat().st_mode & 0o777, 0o600)

    def test_wrong_owner_state_root_is_rejected(self):
        import types
        with patch('custodian.storage.os.fstat', return_value=types.SimpleNamespace(st_uid=-1)):
            with self.assertRaisesRegex(ValueError, 'owner'):
                Storage(self.store.root)

    def test_home_cannot_be_used_as_state_directory(self):
        self.root.chmod(0o755)
        with patch('custodian.storage.Path.home', return_value=self.root):
            with self.assertRaises(ValueError):
                Storage(self.root)
        self.assertEqual(self.root.stat().st_mode & 0o777, 0o755)

    def test_settings_symlink_is_not_followed(self):
        external = self.root / 'external.json'
        external.write_text('{"value":"not allowed"}')
        self.store.config_path.symlink_to(external)
        with self.assertRaises((OSError, ValueError)):
            self.store.settings()


if __name__ == '__main__':
    unittest.main()
