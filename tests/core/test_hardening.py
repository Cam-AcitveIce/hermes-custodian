"""Regression tests for independent-review findings R1, R2, R4, R5."""
import os
from pathlib import Path
import tempfile
import threading
import types
import unittest
from unittest.mock import patch

from custodian import _platform
from custodian import policy as real_policy
from custodian.engine import Engine

if os.name != 'nt':
    import pwd

posix_only = unittest.skipIf(os.name == 'nt', 'requires POSIX permission semantics')


class _PausingPolicy:
    """Wrap the real policy; the thread named 'A' pauses after its snapshot."""

    def __init__(self):
        self.captured = threading.Event()
        self.resume = threading.Event()

    def module(self):
        def bounded_snapshot(*args, **kwargs):
            result = real_policy.bounded_snapshot(*args, **kwargs)
            if threading.current_thread().name == 'A':
                self.captured.set()
                self.resume.wait(10)
            return result
        return types.SimpleNamespace(bounded_snapshot=bounded_snapshot,
                                     is_sensitive=real_policy.is_sensitive,
                                     sanitise_text=real_policy.sanitise_text)


class ScanSerialisationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.scope = self.root / 'fixture'
        self.scope.mkdir()
        self.secret = self.scope / '.env'
        self.secret.write_text('FIXTURE')
        self.state = self.root / 'state'
        Engine(self.state).setup({'watched_paths': [str(self.scope)]})

    def _overlap(self, mutate):
        """Scan A captures, mutate(), scan B runs, then A resumes."""
        wrapper = _PausingPolicy()
        errors = []

        def run():
            try:
                Engine(self.state).scan()
            except Exception as exc:  # surfaced via assertion below
                errors.append(exc)
        with patch.dict('sys.modules', {'custodian.policy': wrapper.module()}):
            a = threading.Thread(target=run, name='A')
            a.start()
            self.assertTrue(wrapper.captured.wait(10))
            mutate()
            b = threading.Thread(target=run, name='B')
            b.start()
            b.join(1.5)  # unserialised B would finish here, before A persists
            wrapper.resume.set()
            a.join(15)
            b.join(15)
        self.assertFalse(a.is_alive() or b.is_alive())
        self.assertEqual(errors, [])
        return Engine(self.state)

    @posix_only
    def test_stale_clean_scan_cannot_resolve_newer_live_exposure(self):
        self.secret.chmod(0o600)
        Engine(self.state).scan()
        engine = self._overlap(lambda: self.secret.chmod(0o644))
        self.assertEqual(self.secret.stat().st_mode & 0o777, 0o644)
        self.assertEqual(engine.status()['findings_open'], 1)

    @posix_only
    def test_stale_exposed_scan_cannot_reopen_after_newer_clean_scan(self):
        self.secret.chmod(0o644)
        Engine(self.state).scan()
        self.assertEqual(Engine(self.state).status()['findings_open'], 1)
        engine = self._overlap(lambda: self.secret.chmod(0o600))
        self.assertEqual(engine.status()['findings_open'], 0)

    def _hold(self, name):
        fd = _platform.open_private_file(self.state / name, write=True, create=True)
        self.addCleanup(os.close, fd)
        self.assertTrue(_platform.try_lock_exclusive(fd))
        self.addCleanup(_platform.unlock, fd)

    def test_busy_scan_lock_times_out_clearly_for_scan_and_setup(self):
        import time
        before = Engine(self.state).settings()
        self._hold('scan.lock')
        engine = Engine(self.state)
        engine.lock_timeout = 0.2
        started = time.monotonic()
        with self.assertRaisesRegex(TimeoutError, 'in progress'):
            engine.scan()
        other = self.root / 'other'
        other.mkdir()
        with self.assertRaisesRegex(TimeoutError, 'in progress'):
            engine.setup({'watched_paths': [str(other)]})
        self.assertLess(time.monotonic() - started, 5)
        self.assertEqual(Engine(self.state).settings(), before)
        if os.name != 'nt':
            self.assertEqual((self.state / 'scan.lock').stat().st_mode & 0o777, 0o600)

    def test_monitor_lifetime_lock_does_not_block_scan(self):
        self._hold('monitor.lock')
        engine = Engine(self.state)
        engine.lock_timeout = 0.2
        self.assertTrue(engine.scan()['complete'])


class ScopeLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.scope_a = self.root / 'a'
        self.scope_b = self.root / 'b'
        self.scope_a.mkdir()
        self.scope_b.mkdir()
        self.secret = self.scope_a / '.env'
        self.secret.write_text('FIXTURE')
        self.exposed = True
        exposure = patch('custodian.engine._platform.access_exposure',
                         side_effect=lambda item: {'mode': 0o644} if self.exposed else None)
        exposure.start()
        self.addCleanup(exposure.stop)
        self.engine = Engine(self.root / 'state')
        self.engine.setup({'watched_paths': [str(self.scope_a)]})
        self.assertEqual(len(self.engine.scan()['findings']), 1)

    def _only(self):
        findings = self.engine.findings()
        self.assertEqual(len(findings), 1)
        return findings[0]

    def test_dropping_scope_marks_unchanged_finding_out_of_scope_not_resolved(self):
        self.engine.setup({'watched_paths': [str(self.scope_b)]})
        self.assertTrue(self.engine.scan()['complete'])
        self.assertEqual(self._only()['status'], 'out_of_scope')
        status = self.engine.status()
        self.assertEqual(status['findings_open'], 0)
        self.assertEqual(status['findings_out_of_scope'], 1)
        kinds = [event['kind'] for event in self.engine.events()]
        self.assertIn('finding_out_of_scope', kinds)
        self.assertNotIn('finding_resolved', kinds)

    def test_excluding_path_marks_finding_out_of_scope(self):
        self.engine.setup({'watched_paths': [str(self.scope_a)], 'exclusions': ['.env']})
        self.assertTrue(self.engine.scan()['complete'])
        self.assertEqual(self._only()['status'], 'out_of_scope')

    def test_reevaluated_under_broader_covering_scope_still_resolves(self):
        self.exposed = False
        self.engine.setup({'watched_paths': [str(self.scope_a), str(self.scope_b)], 'max_files': 500})
        self.assertTrue(self.engine.scan()['complete'])
        self.assertEqual(self._only()['status'], 'resolved')

    def test_out_of_scope_finding_reopens_or_resolves_when_scope_returns(self):
        self.engine.setup({'watched_paths': [str(self.scope_b)]})
        self.engine.scan()
        self.engine.setup({'watched_paths': [str(self.scope_a)]})
        self.engine.scan()
        self.assertEqual(self._only()['status'], 'open')
        self.engine.setup({'watched_paths': [str(self.scope_b)]})
        self.engine.scan()
        self.exposed = False
        self.engine.setup({'watched_paths': [str(self.scope_a)]})
        self.engine.scan()
        self.assertEqual(self._only()['status'], 'resolved')


@posix_only
class StateAncestorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_rejects_writable_or_unowned_state_ancestors_except_sticky_root(self):
        parent = self.root / 'shared'
        parent.mkdir(mode=0o700)
        self.addCleanup(lambda: parent.chmod(0o700) if parent.exists() else None)
        for bad_mode in (0o757, 0o777, 0o1777):
            os.chmod(parent, bad_mode)
            with self.subTest(mode=oct(bad_mode)):
                with self.assertRaisesRegex(ValueError, 'writable|sticky'):
                    Engine(parent / 'state')
                self.assertFalse((parent / 'state').exists())
        os.chmod(parent, 0o775)
        with patch('custodian.storage._group_is_private', return_value=False):
            with self.assertRaisesRegex(ValueError, 'writable|sticky'):
                Engine(parent / 'state')
        self.assertFalse((parent / 'state').exists())
        os.chmod(parent, 0o755)
        parent_ino = parent.stat().st_ino
        real_fstat = os.fstat

        def synthetic_fstat(fd):
            info = real_fstat(fd)
            if info.st_ino == parent_ino:
                return synthetic
            return info

        synthetic = types.SimpleNamespace(st_uid=os.getuid() + 1000, st_mode=0o40755,
                                          st_nlink=1, st_size=0)
        with patch('custodian.storage.os.fstat', side_effect=synthetic_fstat):
            with self.assertRaisesRegex(ValueError, 'owner'):
                Engine(parent / 'state')
        synthetic = types.SimpleNamespace(st_uid=0, st_mode=0o40777, st_nlink=1, st_size=0)
        with patch('custodian.storage.os.fstat', side_effect=synthetic_fstat):
            with self.assertRaisesRegex(ValueError, 'writable|sticky'):
                Engine(parent / 'state')
        synthetic = types.SimpleNamespace(st_uid=0, st_mode=0o41777, st_nlink=1, st_size=0)
        with patch('custodian.storage.os.fstat', side_effect=synthetic_fstat):
            engine = Engine(parent / 'state')
        self.assertTrue((parent / 'state').is_dir())
        self.assertEqual((parent / 'state').stat().st_mode & 0o777, 0o700)
        self.assertFalse(engine.status()['configured'])


@posix_only
class DefaultUmaskAncestorTests(unittest.TestCase):
    """Stock Ubuntu/Raspberry Pi OS use umask 002, so ordinary folders are 775.

    A group-writable ancestor is only a risk when someone else is in that group.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_group_writable_ancestor_with_private_group_is_accepted_on_every_level(self):
        outer = self.root / 'outer'
        inner = outer / 'inner'
        inner.mkdir(parents=True)
        os.chmod(outer, 0o775)
        os.chmod(inner, 0o775)
        with patch('custodian.storage._group_is_private', return_value=True):
            engine = Engine(inner / 'state')
        self.assertTrue((inner / 'state').is_dir())
        self.assertEqual((inner / 'state').stat().st_mode & 0o777, 0o700)
        self.assertFalse(engine.status()['configured'])

    def test_world_writable_ancestor_is_still_rejected_even_with_private_group(self):
        outer = self.root / 'outer'
        outer.mkdir()
        os.chmod(outer, 0o777)
        with patch('custodian.storage._group_is_private', return_value=True):
            with self.assertRaisesRegex(ValueError, 'writable|sticky'):
                Engine(outer / 'state')
        self.assertFalse((outer / 'state').exists())

    def test_group_privacy_requires_no_other_members_and_no_other_primary_users(self):
        from custodian.storage import _group_is_private
        uid = os.getuid()
        me = pwd.getpwuid(uid).pw_name

        def group(members):
            return types.SimpleNamespace(gr_name='g', gr_gid=4242, gr_mem=list(members))

        def user(name, user_id, gid):
            return types.SimpleNamespace(pw_name=name, pw_uid=user_id, pw_gid=gid)

        with patch('custodian.storage.grp.getgrgid', return_value=group([])), \
                patch('custodian.storage.pwd.getpwall', return_value=[user(me, uid, 4242)]):
            self.assertTrue(_group_is_private(4242, uid))
        with patch('custodian.storage.grp.getgrgid', return_value=group([me])), \
                patch('custodian.storage.pwd.getpwall', return_value=[user(me, uid, 4242)]):
            self.assertTrue(_group_is_private(4242, uid))
        with patch('custodian.storage.grp.getgrgid', return_value=group([me, 'someone'])), \
                patch('custodian.storage.pwd.getpwall', return_value=[user(me, uid, 4242)]):
            self.assertFalse(_group_is_private(4242, uid))
        with patch('custodian.storage.grp.getgrgid', return_value=group([])), \
                patch('custodian.storage.pwd.getpwall',
                      return_value=[user(me, uid, 4242), user('other', uid + 1, 4242)]):
            self.assertFalse(_group_is_private(4242, uid))
        with patch('custodian.storage.grp.getgrgid', side_effect=KeyError(4242)):
            self.assertFalse(_group_is_private(4242, uid))


@posix_only
class SensitiveSymlinkTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.scope = self.root / 'scope'
        self.scope.mkdir()
        self.engine = Engine(self.root / 'state')
        self.engine.setup({'watched_paths': [str(self.scope)]})

    def test_sensitive_symlink_is_low_informational_and_regular_file_reworded(self):
        target = self.root / 'real-secret'
        target.write_text('FIXTURE')
        target.chmod(0o600)
        link = self.scope / '.env'
        link.symlink_to(target)
        regular = self.scope / 'auth.json'
        regular.write_text('{}')
        regular.chmod(0o644)
        result = self.engine.scan()
        self.assertTrue(result['complete'])
        by_path = {f['path']: f for f in result['findings']}
        link_finding = by_path[str(link)]
        self.assertEqual(link_finding['severity'], 'low')
        self.assertEqual(link_finding['title'], 'sensitive path is a symlink, target not followed')
        self.assertNotIn('mode', link_finding['evidence'])
        self.assertNotIn('chmod', link_finding['recommendation'].lower())
        reg_finding = by_path[str(regular)]
        self.assertEqual(reg_finding['severity'], 'high')
        self.assertEqual(reg_finding['title'], 'sensitive-path file has group/other permission bits set')


if __name__ == '__main__':
    unittest.main()
