"""Windows exclusion and lifecycle contracts, runnable without Win32 APIs."""
from pathlib import Path
import subprocess
import sys

import pytest

from custodian import _platform, policy
from custodian._platform import windows
from custodian.engine import Engine


@pytest.mark.parametrize("relative,pattern", [
    (".env", ".ENV"),
    ("nested/.env", "NESTED\\.ENV"),
    ("nested/.env", "NESTED"),
    ("nested/.env", "*/NESTED\\.ENV"),
])
def test_windows_excluded_finding_leaves_scope(tmp_path, monkeypatch, relative, pattern):
    scope = tmp_path / "scope"
    scope.mkdir()
    secret = scope / relative
    secret.parent.mkdir(parents=True, exist_ok=True)
    secret.write_text("FIXTURE")
    engine = Engine(tmp_path / "state")

    # Simulate walker output with its real matcher; storage remains real.
    def snapshot(root, *, exclusions, **kwargs):
        candidates = (str(secret.relative_to(root)), str(secret), secret.name)
        excluded = windows.is_excluded(candidates, exclusions)
        if secret.parent != root:
            excluded |= windows.is_excluded(
                (str(secret.parent.relative_to(root)), str(secret.parent), secret.parent.name), exclusions)
        return {"files": [] if excluded else [{"path": str(secret), "mode": 0o644}],
                "complete": True, "errors": []}

    monkeypatch.setattr(_platform, "NAME", "windows")
    monkeypatch.setattr(policy, "bounded_snapshot", snapshot)
    monkeypatch.setattr(_platform, "access_exposure", lambda item: {"mode": 0o644})
    engine.setup({"watched_paths": [str(scope)]})
    assert len(engine.scan()["findings"]) == 1
    assert engine.findings()[0]["status"] == "open"
    engine.setup({"watched_paths": [str(scope)], "exclusions": [pattern]})
    assert engine.scan()["complete"]
    assert Engine(engine.store.root).findings()[0]["status"] == "out_of_scope"
    kinds = [event["kind"] for event in engine.events()]
    assert "finding_out_of_scope" in kinds
    assert "finding_resolved" not in kinds


@pytest.mark.parametrize("name,pattern,covered", [
    ("windows", ".ENV", False), ("linux", ".ENV", True),
    ("macos", ".ENV", True), ("linux", ".env", False),
])
def test_platform_matching_preserves_posix_case(monkeypatch, tmp_path, name, pattern, covered):
    monkeypatch.setattr(_platform, "NAME", name)
    assert Engine._is_covered(str(tmp_path / ".env"), [tmp_path], [pattern]) is covered


@pytest.mark.parametrize("filename,skipped", [
    ("tests/core/test_hardening.py", False),
    ("tests/platform/test_posix_backend.py", True),
])
def test_collection_without_posix_modules(filename, skipped):
    # Isolate OS simulation so pytest itself keeps the real host platform.
    script = """
import runpy
import sys
import pytest
from unittest.mock import patch
from custodian.engine import Engine
with patch.dict(sys.modules, {'pwd': None, 'fcntl': None}):
    with patch('os.name', 'nt'):
        try:
            namespace = runpy.run_path(sys.argv[1])
        except pytest.skip.Exception:
            assert sys.argv[2] == 'True'
        else:
            assert sys.argv[2] == 'False'
            assert not namespace['ScopeLifecycleTests'].__dict__.get('__unittest_skip__', False)
            assert not getattr(namespace['ScanSerialisationTests'].test_monitor_lifetime_lock_does_not_block_scan,
                               '__unittest_skip__', False)
            assert namespace['StateAncestorTests'].__unittest_skip__
"""
    result = subprocess.run([sys.executable, "-c", script, filename, str(skipped)],
                            capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stdout + result.stderr
