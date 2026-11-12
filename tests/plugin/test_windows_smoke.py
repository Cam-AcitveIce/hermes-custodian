import importlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import pytest


def _load_plugin_module():
    root = Path(__file__).resolve().parents[2]
    spec = importlib.util.spec_from_file_location(
        'custodian_plugin',
        root / '__init__.py',
        submodule_search_locations=[str(root)]
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeContext:
    def __init__(self):
        self.tools = {}

    def register_tool(self, **kwargs):
        self.tools[kwargs['name']] = kwargs


def test_windows_simulation_missing_backend_fallback_smoke(monkeypatch, tmp_path):
    """Simulate Windows with missing backend: tools must fail soft with structured unsupported status."""
    orig_modules = dict(sys.modules)
    try:
        # Purge custodian modules to test fresh import under win32 simulation
        for mod_name in list(sys.modules):
            if mod_name.startswith('custodian') or mod_name == 'custodian_plugin':
                del sys.modules[mod_name]

        monkeypatch.setattr(sys, 'platform', 'win32')
        # Explicitly block windows and posix backends
        monkeypatch.setitem(sys.modules, 'custodian._platform.windows', None)
        monkeypatch.setitem(sys.modules, 'custodian._platform.posix', None)
        monkeypatch.setitem(sys.modules, 'fcntl', None)
        monkeypatch.setitem(sys.modules, 'grp', None)
        monkeypatch.setitem(sys.modules, 'pwd', None)

        # Create dummy hermes_constants providing get_hermes_home
        class FakeHermesConstants:
            @staticmethod
            def get_hermes_home():
                return tmp_path

        monkeypatch.setitem(sys.modules, 'hermes_constants', FakeHermesConstants)

        # State dir structure
        state_dir = tmp_path / 'plugin-data' / 'hermes-custodian'
        state_dir.mkdir(parents=True, exist_ok=True)
        (state_dir / 'settings.json').write_text(json.dumps({'schema_version': 1}))

        plugin = _load_plugin_module()
        ctx = FakeContext()
        plugin.register(ctx)

        assert set(ctx.tools) == {'warden_status', 'warden_findings', 'warden_changes', 'warden_scan'}

        for tool_name, tool_def in ctx.tools.items():
            handler = tool_def['handler']
            raw = handler({})
            result = json.loads(raw)
            assert 'status' in result
            assert result['status'] == 'unsupported'
            assert result['ok'] is False
            assert result['platform'] == 'windows'
            assert result['tool'] == tool_name
            assert 'reason' in result
            assert isinstance(result['reason'], str) and len(result['reason']) > 0
    finally:
        # Undo simulated module entries before restoring the native module graph.
        monkeypatch.undo()
        sys.modules.clear()
        sys.modules.update(orig_modules)


def test_windows_simulation_smoke(monkeypatch, tmp_path):
    """Backward-compatible alias for the missing-backend simulation smoke test."""
    test_windows_simulation_missing_backend_fallback_smoke(monkeypatch, tmp_path)


def test_windows_simulation_backend_import(monkeypatch):
    """Simulate Windows with backend present: plugin registration and backend import succeed."""
    orig_modules = dict(sys.modules)
    try:
        for mod_name in list(sys.modules):
            if mod_name.startswith('custodian') or mod_name == 'custodian_plugin':
                del sys.modules[mod_name]

        monkeypatch.setattr(sys, 'platform', 'win32')
        # Posix blocked, windows backend allowed
        monkeypatch.setitem(sys.modules, 'custodian._platform.posix', None)
        monkeypatch.setitem(sys.modules, 'fcntl', None)
        monkeypatch.setitem(sys.modules, 'grp', None)
        monkeypatch.setitem(sys.modules, 'pwd', None)

        import custodian._platform as plat
        assert plat.NAME == 'windows'
        assert plat.IS_WINDOWS is True
        assert plat.BACKEND_READY is True

        plugin = _load_plugin_module()
        ctx = FakeContext()
        plugin.register(ctx)
        assert set(ctx.tools) == {'warden_status', 'warden_findings', 'warden_changes', 'warden_scan'}
    finally:
        # Undo simulated module entries before restoring the native module graph.
        monkeypatch.undo()
        sys.modules.clear()
        sys.modules.update(orig_modules)


def test_real_os_smoke(monkeypatch, tmp_path):
    class FakeHermesConstants:
        @staticmethod
        def get_hermes_home():
            return tmp_path

    monkeypatch.setitem(sys.modules, 'hermes_constants', FakeHermesConstants)

    state_dir = tmp_path / 'plugin-data' / 'hermes-custodian'
    from custodian.engine import Engine
    scope_dir = tmp_path / 'scope'
    scope_dir.mkdir()
    engine = Engine(state_dir)
    engine.setup({'watched_paths': [str(scope_dir)]})

    plugin = _load_plugin_module()
    ctx = FakeContext()
    plugin.register(ctx)

    assert set(ctx.tools) == {'warden_status', 'warden_findings', 'warden_changes', 'warden_scan'}

    for tool_name, tool_def in ctx.tools.items():
        handler = tool_def['handler']
        raw = handler({})
        result = json.loads(raw)
        assert 'status' in result
        assert result['ok'] is True
        assert 'data' in result


@pytest.mark.skipif(sys.platform != 'win32', reason='Native Windows test only')
def test_windows_native_plugin_smoke(monkeypatch, tmp_path):
    """Native Windows test: configure fixture scope, scan, and verify all four handlers return ok True, never unsupported."""
    class FakeHermesConstants:
        @staticmethod
        def get_hermes_home():
            return tmp_path

    monkeypatch.setitem(sys.modules, 'hermes_constants', FakeHermesConstants)

    state_dir = tmp_path / 'plugin-data' / 'hermes-custodian'
    scope_dir = tmp_path / 'scope'
    scope_dir.mkdir(parents=True, exist_ok=True)
    (scope_dir / 'fixture.py').write_text('print("windows test")\n', encoding='utf-8')

    from custodian.engine import Engine
    engine = Engine(state_dir)
    engine.setup({'watched_paths': [str(scope_dir)]})

    plugin = _load_plugin_module()
    ctx = FakeContext()
    plugin.register(ctx)

    assert set(ctx.tools) == {'warden_status', 'warden_findings', 'warden_changes', 'warden_scan'}

    assert not any(name.startswith('custodian_') for name in ctx.tools)

    scan_handler = ctx.tools['warden_scan']['handler']
    scan_result = json.loads(scan_handler({}))
    assert scan_result['ok'] is True, f"warden_scan returned ok=False: {scan_result}"
    assert scan_result.get('status') != 'unsupported', f"warden_scan returned unsupported: {scan_result}"
    assert 'data' in scan_result

    for tool_name in ('warden_scan', 'warden_status'):
        rejected = json.loads(ctx.tools[tool_name]['handler']({'watched_paths': [str(tmp_path)]}))
        assert rejected['ok'] is False and rejected['status'] == 'error', rejected

    for tool_name in ('warden_status', 'warden_findings', 'warden_changes'):
        handler = ctx.tools[tool_name]['handler']
        raw = handler({})
        result = json.loads(raw)
        assert result['ok'] is True, f"{tool_name} returned ok=False: {result}"
        assert result.get('status') != 'unsupported', f"{tool_name} returned unsupported: {result}"
        assert 'data' in result


@pytest.mark.skipif(sys.platform != 'win32', reason='requires native Win32 ACLs and handles')
def test_windows_native_dashboard_and_discovery(tmp_path):
    """Real filesystem/ACL coverage, independent of simulated capability tests."""
    import threading
    from custodian import _platform
    from custodian._platform import windows
    from custodian.dashboard_auth import DashboardAuth
    from custodian.engine import Engine
    from custodian.web import CustodianDashboardServer, _read_static_asset

    assert _platform.validate_state_root is windows.validate_state_root
    state = tmp_path / 'state'
    auth = DashboardAuth(state)
    auth.configure('operator', 'native-fixture-passphrase')
    restored = DashboardAuth(state)
    assert restored.authenticate('operator', 'native-fixture-passphrase')
    assert not restored.authenticate('operator', 'wrong-password')

    def session_server():
        server = object.__new__(CustodianDashboardServer)
        server.state_dir = state
        server.session_key_path = state / 'dashboard-session-key.json'
        server._lock = threading.Lock()
        server._failed_logins = []
        server.auth = restored
        server.clock = lambda: 1000
        server.session_ttl_seconds = 100
        server.absolute_session_seconds = 1000
        return server

    server = session_server()
    token, _ = server.create_session_cookie_value()
    restarted = session_server()
    assert restarted.validate_session(token)
    assert restarted._read_key_record_unlocked() == server._read_key_record_unlocked()
    restarted.revoke_session(token)
    assert not server.validate_session(token)
    for name in ('dashboard-login.json', 'dashboard-session-key.json'):
        raw = windows.read_private_file(state / name, max_bytes=65536)
        assert b'native-fixture-passphrase' not in raw

    asset = tmp_path / 'index.html'
    asset.write_bytes(b'<p>native asset fixture</p>')
    assert _read_static_asset(asset) == asset.read_bytes()
    hermes = tmp_path / 'hermes'
    (hermes / 'profiles' / 'demo').mkdir(parents=True)
    (hermes / 'config.json').write_text(json.dumps({'model': 'safe-model', 'api_key': 'PRIVATE-FIXTURE'}))
    (hermes / 'profiles' / 'demo' / 'config.json').write_text('{"model":"demo-model"}')
    entries = Engine(state).inventory(hermes)
    assert [entry['name'] for entry in entries] == ['default', 'demo']
    assert 'PRIVATE-FIXTURE' not in json.dumps(entries)
    assert 'safe-model' in json.dumps(entries)
