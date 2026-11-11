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

        assert set(ctx.tools) == {'custodian_status', 'custodian_findings', 'custodian_changes', 'custodian_scan'}

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
        assert set(ctx.tools) == {'custodian_status', 'custodian_findings', 'custodian_changes', 'custodian_scan'}
    finally:
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

    assert set(ctx.tools) == {'custodian_status', 'custodian_findings', 'custodian_changes', 'custodian_scan'}

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

    assert set(ctx.tools) == {'custodian_status', 'custodian_findings', 'custodian_changes', 'custodian_scan'}

    scan_handler = ctx.tools['custodian_scan']['handler']
    scan_result = json.loads(scan_handler({}))
    assert scan_result['ok'] is True, f"custodian_scan returned ok=False: {scan_result}"
    assert scan_result.get('status') != 'unsupported', f"custodian_scan returned unsupported: {scan_result}"
    assert 'data' in scan_result

    for tool_name in ('custodian_status', 'custodian_findings', 'custodian_changes'):
        handler = ctx.tools[tool_name]['handler']
        raw = handler({})
        result = json.loads(raw)
        assert result['ok'] is True, f"{tool_name} returned ok=False: {result}"
        assert result.get('status') != 'unsupported', f"{tool_name} returned unsupported: {result}"
        assert 'data' in result
