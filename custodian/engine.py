"""Deterministic, read-only Custodian application facade."""
from pathlib import Path
from datetime import datetime, timezone
from fnmatch import fnmatchcase
import hashlib
import importlib
import json
import uuid
import os
import time
import math

from .storage import Storage
from . import _platform


def _is_excluded(candidates, patterns):
    """Use the walker's platform semantics for persisted finding coverage."""
    if _platform.NAME == 'windows':
        from ._platform.windows import is_excluded
        return is_excluded(candidates, patterns)
    return any(fnmatchcase(candidate, pattern)
               for candidate in candidates for pattern in patterns)


class Engine:
    #: Bounded wait (seconds) for the per-state scan/setup lock.
    lock_timeout = 30.0

    def __init__(self, state_dir: Path):
        self.store = Storage(state_dir)

    def setup(self, settings: dict) -> dict:
        result: dict = dict(schema_version=1, profiles=[], watched_paths=[], exclusions=[],
                      hermes_root=None, interval_seconds=60, max_files=10000, max_file_bytes=1048576,
                      retention_days=30)
        if not isinstance(settings, dict) or set(settings) - set(result):
            raise ValueError('Unknown settings fields')
        result.update(settings)
        if result['schema_version'] != 1:
            raise ValueError('Unsupported schema_version')
        for key, low, high in [('interval_seconds', 10, 86400), ('max_files', 1, 100000),
                               ('max_file_bytes', 1, 16777216), ('retention_days', 1, 365)]:
            value = result[key]
            if type(value) is not int or not low <= value <= high:
                raise ValueError(f'{key} must be an integer between {low} and {high}')
        for key in ('profiles', 'watched_paths', 'exclusions'):
            value = result[key]
            if not isinstance(value, list) or len(value) > 100 or any(
                    not isinstance(item, str) or not item or len(item) > 4096 or
                    any(ord(c) < 32 or ord(c) == 127 for c in item) for item in value):
                raise ValueError(f'{key} must be a bounded list of strings')
        paths = result['profiles'] + result['watched_paths']
        if not paths:
            raise ValueError('Explicit profiles or watched_paths required')
        for value in paths:
            path = Path(value)
            if not path.is_absolute() or '..' in path.parts or path == Path('/') or path == Path.home():
                raise ValueError('Select a specific absolute scope, not root or home')
            if any(part.is_symlink() for part in (path, *path.parents)) or not path.exists():
                raise ValueError('Scope must exist and have no symlink components')
            if not path.is_dir():
                raise ValueError('Scope must be a directory; individual file roots are not supported')
            if path == self.store.root or self.store.root in path.parents:
                raise ValueError('State directory cannot be monitored')
        if result['hermes_root'] is not None:
            value = result['hermes_root']
            if not isinstance(value, str) or not value or len(value) > 4096 or any(ord(c) < 32 for c in value):
                raise ValueError('hermes_root must be an explicit absolute directory')
            path = Path(value)
            if not path.is_absolute() or '..' in path.parts or not path.is_dir() or any(
                    part.is_symlink() for part in (path, *path.parents)):
                raise ValueError('hermes_root must be an existing nonsymlink absolute directory')
        # Same lock as scan(): a settings change cannot interleave with a scan.
        with self.store.scan_lock(self.lock_timeout):
            self.store.save_settings(result)
        return result

    def settings(self) -> dict:
        return self.store.settings()

    def inventory(self, hermes_root: Path) -> list[dict]:
        from .discovery import inventory
        return inventory(hermes_root)

    @staticmethod
    def _scope(settings):
        roots = []
        for path in sorted(set(settings['profiles'] + settings['watched_paths'])):
            candidate = Path(path)
            if not any(root == candidate or root in candidate.parents for root in roots):
                roots.append(candidate)
        payload = [list(map(str, roots)), settings['exclusions'], settings['max_file_bytes'], settings['max_files']]
        signature = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        return roots, signature

    @staticmethod
    def _is_covered(path_str: str, roots: list[Path], exclusions: list[str]) -> bool:
        path = Path(path_str)
        for root in roots:
            if path == root or root in path.parents:
                current = path
                while current != root:
                    rel = str(current.relative_to(root))
                    if _is_excluded((rel, str(current), current.name), exclusions):
                        return False
                    current = current.parent
                return True
        return False

    def scan(self) -> dict:
        # Baseline read, snapshot and persistence form one serialised unit so an
        # older snapshot can never overwrite a newer scan's finding lifecycle.
        with self.store.scan_lock(self.lock_timeout):
            return self._scan_locked()

    def _scan_locked(self) -> dict:
        settings = self.settings()
        policy = importlib.import_module('.policy', __package__)
        started = datetime.now(timezone.utc).isoformat()
        roots, signature = self._scope(settings)
        baseline = self.store.baseline(signature)
        files, errors, complete = {}, [], True
        for root in roots:
            remaining = settings['max_files'] - len(files)
            if remaining <= 0:
                complete = False
                errors.append('Global file budget exhausted; remaining scopes not scanned')
                break
            try:
                snapshot = policy.bounded_snapshot(root, exclusions=settings['exclusions'] + [str(self.store.root)],
                                                   max_files=remaining, max_file_bytes=settings['max_file_bytes'])
            except (OSError, ValueError):
                complete = False
                errors.append(f'Scope unavailable or rejected by policy: {root}')
                continue
            complete = complete and snapshot['complete']
            errors.extend(snapshot['errors'])
            for item in snapshot['files']:
                files[item['path']] = item
        findings = []
        for raw_path, item in sorted(files.items()):
            if not policy.is_sensitive(Path(raw_path)):
                continue
            path = policy.sanitise_text(raw_path)
            if item.get('type') == 'symlink':
                findings.append({'id': hashlib.sha256(('sensitive_symlink:' + raw_path).encode()).hexdigest(),
                                 'severity': 'low',
                                 'title': 'sensitive path is a symlink, target not followed',
                                 'path': path, 'evidence': {'type': 'symlink'},
                                 'recommendation': 'Inspect the symlink target manually; link mode does not control target permissions.',
                                 'first_seen': started, 'last_seen': started, 'status': 'open',
                                 'scope_signature': signature})
            else:
                exposure = _platform.access_exposure(item)
                if exposure:
                    title = 'sensitive-path file is accessible beyond its owner' if _platform.NAME == 'windows' else 'sensitive-path file has group/other permission bits set'
                    evidence = {'mode': oct(exposure['mode'])}
                    if 'exposed_to' in exposure:
                        evidence['exposed_to'] = exposure['exposed_to']
                    findings.append({'id': hashlib.sha256(('sensitive_permissions:' + raw_path).encode()).hexdigest(),
                                     'severity': exposure.get('severity', 'high'),
                                     'title': title,
                                     'path': path, 'evidence': evidence,
                                     'recommendation': 'Review ownership and restrict permissions manually.',
                                     'first_seen': started, 'last_seen': started, 'status': 'open',
                                     'scope_signature': signature})
        changes = []
        if baseline is not None:
            for path, item in sorted(files.items()):
                if path not in baseline:
                    changes.append({'kind': 'added', 'path': policy.sanitise_text(path)})
                elif item != baseline[path]:
                    changes.append({'kind': 'modified', 'path': policy.sanitise_text(path)})
            if complete:
                changes.extend({'kind': 'removed', 'path': policy.sanitise_text(path)}
                               for path in sorted(set(baseline) - set(files)))
        result = {'scan_id': uuid.uuid4().hex, 'started_at': started, 'scope_signature': signature,
                  'finished_at': datetime.now(timezone.utc).isoformat(), 'complete': bool(complete),
                  'files_checked': len(files), 'findings': findings, 'changes': changes,
                  'errors': [policy.sanitise_text(str(error)) for error in errors]}
        all_exclusions = settings['exclusions'] + [str(self.store.root)]
        self.store.record_scan(result, files, signature, settings['retention_days'],
                               covered=lambda p: self._is_covered(p, roots, all_exclusions))
        return result

    def updates(self) -> dict:
        from .updates import check_updates
        return check_updates()

    def findings(self) -> list[dict]:
        return self.store.findings()

    def events(self, limit=100) -> list[dict]:
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError('limit must be between 1 and 1000')
        return self.store.events(limit)

    def status(self) -> dict:
        last = self.store.last_scan()
        configured = self.store.config_path.exists()
        scope_changed = bool(last and configured and last.get('scope_signature') != self._scope(self.settings())[1])
        stale = bool(scope_changed or (last and configured and
                     (datetime.now(timezone.utc) - datetime.fromisoformat(last['finished_at'])).total_seconds()
                     > self.settings()['interval_seconds'] * 2))
        coverage = 'not_scanned' if last is None else ('scope_changed' if scope_changed else
            ('degraded' if not last['complete'] else ('stale' if stale else 'complete')))
        monitor = self._monitor_status()
        findings = self.findings()
        return {'configured': configured, 'monitoring': monitor['state'] == 'running',
                'last_scan': last, 'findings_open': sum(item['status'] == 'open' for item in findings),
                'findings_out_of_scope': sum(item['status'] == 'out_of_scope' for item in findings),
                'coverage': coverage, 'stale': stale,
                'monitor': monitor,
                'service_health': 'degraded' if monitor.get('error') else monitor['state']}

    def _monitor_status(self):
        try:
            value = self.store.monitor()
            if value is None:
                return {'state': 'stopped', 'error': None}
            pid, heartbeat = value.get('pid'), value.get('heartbeat_at')
            if (type(pid) is not int or not 1 <= pid <= 2147483647 or
                    not isinstance(heartbeat, (int, float)) or isinstance(heartbeat, bool) or
                    not 0 <= heartbeat <= 1000000000000 or not math.isfinite(heartbeat) or
                    type(value.get('running')) is not bool):
                raise ValueError('Invalid monitor heartbeat fields')
            error = value.get('error')
            if error is not None:
                policy = importlib.import_module('.policy', __package__)
                error = policy.sanitise_text(str(error))[:512]
            result = {'state': 'stopped', 'pid': pid, 'heartbeat_at': heartbeat, 'error': error}
            if not value['running']:
                return result
            if not -5 <= time.time() - heartbeat <= 30:
                result['state'] = 'stale'
                return result
            owned = _platform.process_is_running_as_current_user(pid)
            result['state'] = 'running' if owned else 'unavailable'
            return result
        except (OSError, ValueError, TypeError, UnicodeError):
            return {'state': 'unavailable', 'error': 'Monitor metadata unavailable or invalid'}
