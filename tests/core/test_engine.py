from custodian import _platform
import json
import os
from pathlib import Path
import tempfile
import unittest

from custodian.engine import Engine


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.scope = self.root / 'fixture'
        self.scope.mkdir()
        self.engine = Engine(self.root / 'state')

    def test_explicit_setup_persists_across_instances(self):
        with self.assertRaisesRegex(ValueError, 'configured'):
            self.engine.settings()
        settings = self.engine.setup({'watched_paths': [str(self.scope)]})
        self.assertEqual(settings['schema_version'], 1)
        self.assertGreaterEqual(settings['interval_seconds'], 10)
        self.assertEqual(Engine(self.root / 'state').settings(), settings)
        if os.name != "nt":
            self.assertEqual((self.root / 'state' / 'settings.json').stat().st_mode & 0o777, 0o600)
        else:
            self.assertIsInstance(_platform.read_private_file((self.root / 'state' / 'settings.json'), max_bytes=1048576), bytes)
        json.dumps(self.engine.status())
        self.assertFalse(self.engine.status()['monitoring'])

    def test_scan_persists_baseline_detects_changes_and_deduplicates_findings(self):
        from unittest.mock import patch
        import types
        item = {'path': str(self.scope / '.env'), 'mode': 0o100644, 'uid': _platform.current_principal(),
                'size': 8, 'mtime_ns': 1}
        policy = types.SimpleNamespace(
            bounded_snapshot=lambda *args, **kwargs: {'files': [dict(item)], 'errors': [], 'complete': True},
            is_sensitive=lambda path: path.name == '.env', sanitise_text=lambda value: str(value))
        self.engine.setup({'watched_paths': [str(self.scope)]})
        with patch.dict('sys.modules', {'custodian.policy': policy}):
            first = self.engine.scan()
            self.assertTrue(first['complete'])
            self.assertEqual(first['files_checked'], 1)
            self.assertEqual(first['changes'], [])
            self.assertEqual(len(first['findings']), 1)
            second = Engine(self.root / 'state').scan()
            self.assertEqual(second['findings'][0]['id'], first['findings'][0]['id'])
            self.assertEqual(second['changes'], [])
            item['mtime_ns'] = 2
            changed = self.engine.scan()
            self.assertEqual(changed['changes'][0]['kind'], 'modified')
            self.assertEqual(len(self.engine.findings()), 1)
            self.assertEqual(self.engine.status()['last_scan']['scan_id'], changed['scan_id'])
            self.assertEqual(len(self.engine.events(limit=2)), 2)
            json.dumps(changed)

    def test_policy_io_failure_is_persisted_as_degraded_not_raised(self):
        from unittest.mock import patch
        import types
        def broken(*args, **kwargs):
            raise OSError('synthetic denied')
        policy = types.SimpleNamespace(bounded_snapshot=broken, sanitise_text=str)
        self.engine.setup({'watched_paths': [str(self.scope)]})
        with patch.dict('sys.modules', {'custodian.policy': policy}):
            result = self.engine.scan()
        self.assertFalse(result['complete'])
        self.assertTrue(result['errors'])
        self.assertEqual(self.engine.status()['coverage'], 'degraded')

    def test_profiles_canonical_key_and_consented_discovery_root_persist(self):
        settings = self.engine.setup({'profiles': [str(self.scope)], 'hermes_root': str(self.scope)})
        self.assertEqual(settings['profiles'], [str(self.scope)])
        self.assertNotIn('profile_paths', settings)
        self.assertEqual(self.engine.settings()['hermes_root'], str(self.scope))

    def test_scope_change_does_not_report_old_complete_coverage(self):
        from unittest.mock import patch
        import types
        policy = types.SimpleNamespace(bounded_snapshot=lambda *args, **kwargs:
            {'files': [], 'errors': [], 'complete': True}, sanitise_text=str)
        self.engine.setup({'watched_paths': [str(self.scope)]})
        with patch.dict('sys.modules', {'custodian.policy': policy}):
            self.engine.scan()
        other = self.root / 'other'
        other.mkdir()
        self.engine.setup({'watched_paths': [str(other)]})
        self.assertEqual(self.engine.status()['coverage'], 'scope_changed')
        self.assertTrue(self.engine.status()['stale'])

    def test_updates_delegates_to_parent_read_only_adapter(self):
        from unittest.mock import patch
        expected = {'status': 'unavailable', 'upgradable_count': None}
        with patch('custodian.updates.check_updates', return_value=expected) as check:
            self.assertEqual(self.engine.updates(), expected)
            check.assert_called_once_with()

    @unittest.skipIf(os.name == "nt", "POSIX chmod exposure transitions; native Windows scan coverage in plugin smoke")
    def test_real_policy_end_to_end_never_reads_sensitive_fixture_contents(self):
        from unittest.mock import patch
        secret = self.scope / '.env'
        secret.write_text('DO-NOT-READ-THIS-CREDENTIAL')
        secret.chmod(0o644)
        document = self.scope / 'notes.md'
        document.write_text('first')
        private = self.scope / 'memories'
        private.mkdir()
        (private / 'private.md').write_text('DO-NOT-READ-THIS-MEMORY')
        real_open = os.open
        def guarded(path, *args, **kwargs):
            if str(path) in {'.env', 'memories', 'private.md'}:
                self.fail('Attempted to open sensitive fixture: ' + str(path))
            return real_open(path, *args, **kwargs)
        self.engine.setup({'watched_paths': [str(self.scope)]})
        with patch('os.open', side_effect=guarded):
            first = self.engine.scan()
            self.assertTrue(first['complete'], first['errors'])
            self.assertEqual(len(first['findings']), 2)
            document.write_text('second')
            second = self.engine.scan()
            self.assertTrue(any(c['kind'] == 'modified' and c['path'] == str(document) for c in second['changes']))
            secret.chmod(0o600)
            third = self.engine.scan()
            self.assertTrue(third['complete'])
            self.assertEqual(self.engine.status()['findings_open'], 1)
        self.assertNotIn('DO-NOT-READ', json.dumps(self.engine.events()) + json.dumps(self.engine.findings()))
        self.assertEqual(len([f for f in self.engine.findings() if f['status'] == 'resolved']), 1)

    def test_incomplete_scan_preserves_complete_baseline_and_open_findings(self):
        from unittest.mock import patch
        import types
        item = {'path': str(self.scope / '.env'), 'mode': 0o644, 'uid': _platform.current_principal(), 'size': 3, 'mtime_ns': 1}
        snapshot = {'files': [item], 'errors': [], 'complete': True}
        policy = types.SimpleNamespace(bounded_snapshot=lambda *args, **kwargs: snapshot,
                                       is_sensitive=lambda path: path.name == '.env', sanitise_text=str)
        self.engine.setup({'watched_paths': [str(self.scope)]})
        with patch.dict('sys.modules', {'custodian.policy': policy}):
            self.engine.scan()
            snapshot.update(files=[], errors=['synthetic budget exhausted'], complete=False)
            incomplete = self.engine.scan()
            self.assertFalse(incomplete['complete'])
            self.assertEqual(incomplete['changes'], [])
            self.assertEqual(self.engine.status()['findings_open'], 1)
            snapshot.update(files=[], errors=[], complete=True)
            complete = self.engine.scan()
            self.assertEqual(complete['changes'], [{'kind': 'removed', 'path': item['path']}])
            self.assertEqual(self.engine.status()['findings_open'], 0)

    def test_global_file_budget_applies_across_selected_roots(self):
        from unittest.mock import patch
        import types
        other = self.root / 'other'
        other.mkdir()
        calls = []
        def snapshot(root, **kwargs):
            calls.append(kwargs['max_files'])
            return {'files': [{'path': str(root / 'file'), 'mode': 0o600, 'uid': _platform.current_principal(),
                               'size': 0, 'mtime_ns': 1}], 'errors': [], 'complete': True}
        policy = types.SimpleNamespace(bounded_snapshot=snapshot, is_sensitive=lambda path: False, sanitise_text=str)
        self.engine.setup({'watched_paths': [str(self.scope), str(other)], 'max_files': 1})
        with patch.dict('sys.modules', {'custodian.policy': policy}):
            result = self.engine.scan()
        self.assertEqual(calls, [1])
        self.assertEqual(result['files_checked'], 1)
        self.assertFalse(result['complete'])

    def test_setup_rejects_individual_file_scope_until_policy_supports_it(self):
        file = self.scope / 'notes.md'
        file.write_text('fixture')
        with self.assertRaisesRegex(ValueError, 'director'):
            self.engine.setup({'watched_paths': [str(file)]})

    def test_namespaced_plugin_load_uses_relative_policy_imports(self):
        import importlib
        import types
        from unittest.mock import patch
        package = types.ModuleType('_custodian_plugin_fixture')
        package.__path__ = [str(Path(__file__).resolve().parents[2] / 'custodian')]
        real_import = importlib.import_module
        with patch.dict('sys.modules', {'_custodian_plugin_fixture': package}):
            module = real_import('_custodian_plugin_fixture.engine')
            engine = module.Engine(self.root / 'plugin_state')
            engine.setup({'watched_paths': [str(self.scope)]})
            def guarded(name, package=None):
                if name == 'custodian.policy':
                    raise ModuleNotFoundError('Standalone package not installed')
                return real_import(name, package)
            with patch('importlib.import_module', side_effect=guarded):
                self.assertTrue(engine.scan()['complete'])
                self.assertEqual(engine.inventory(self.scope)[0]['name'], 'default')

    def test_monitor_heartbeat_requires_fresh_owned_live_pid_and_reports_errors(self):
        import time
        self.engine.setup({'watched_paths': [str(self.scope)]})
        path = self.engine.store.root / 'monitor.json'
        health = {'pid': os.getpid(), 'running': True, 'started_at': time.time(),
                  'last_result': None, 'error': None, 'heartbeat_at': time.time()}
        path.write_text(json.dumps(health))
        self.assertTrue(self.engine.status()['monitoring'])
        if os.name != "nt":
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        else:
            self.assertIsInstance(_platform.read_private_file(path, max_bytes=1048576), bytes)
        health['error'] = 'RuntimeError: monitoring cycle failed'
        path.write_text(json.dumps(health))
        self.assertEqual(self.engine.status()['service_health'], 'degraded')
        self.assertIn('RuntimeError', self.engine.status()['monitor']['error'])
        health.update(error=None, heartbeat_at=time.time() - 100000)
        path.write_text(json.dumps(health))
        self.assertFalse(self.engine.status()['monitoring'])
        self.assertEqual(self.engine.status()['monitor']['state'], 'stale')
        health.update(heartbeat_at=time.time(), pid=2147483647)
        path.write_text(json.dumps(health))
        self.assertFalse(self.engine.status()['monitoring'])
        health.update(pid=os.getpid(), running=False)
        path.write_text(json.dumps(health))
        self.assertEqual(self.engine.status()['monitor']['state'], 'stopped')

    def test_invalid_or_symlink_monitor_metadata_never_claims_running(self):
        path = self.engine.store.root / 'monitor.json'
        for value in ('{broken', '[]', json.dumps({'pid': os.getpid(), 'running': True,
                                                'heartbeat_at': 10 ** 1000})):
            path.write_text(value)
            status = self.engine.status()
            self.assertFalse(status['monitoring'])
            self.assertEqual(status['monitor']['state'], 'unavailable')
        external = self.root / 'outside-monitor.json'
        external.write_text('{}')
        path.unlink()
        path.symlink_to(external)
        self.assertEqual(self.engine.status()['monitor']['state'], 'unavailable')

    def test_setup_rejects_unsafe_or_unbounded_input_without_replacing_settings(self):
        good = self.engine.setup({'watched_paths': [str(self.scope)]})
        link = self.root / 'linked'
        link.symlink_to(self.scope, target_is_directory=True)
        invalid = [{}, {'watched_paths': ['/']}, {'watched_paths': ['relative']},
                   {'watched_paths': [str(link)]}, {'watched_paths': [str(self.root / 'missing')]},
                   {'watched_paths': [str(self.scope)], 'interval_seconds': 9},
                   {'watched_paths': [str(self.scope)], 'max_files': True},
                   {'watched_paths': [str(self.scope)], 'max_files': 100001},
                   {'watched_paths': [str(self.scope)], 'retention_days': 0},
                   {'watched_paths': [str(self.scope)], 'exclusions': 'wrong'},
                   {'watched_paths': [str(self.scope)], 'execute_updates': True},
                   {'watched_paths': [str(self.scope)], 'schema_version': 99}]
        for settings in invalid:
            with self.subTest(settings=settings):
                with self.assertRaises(ValueError):
                    self.engine.setup(settings)
                self.assertEqual(self.engine.settings(), good)


if __name__ == '__main__':
    unittest.main()
