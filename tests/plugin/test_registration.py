import importlib.util
import json
from pathlib import Path
import re
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
WARDEN_TOOLS = {'warden_status', 'warden_findings', 'warden_changes', 'warden_scan'}
LEGACY_TOOLS = {'custodian_status', 'custodian_findings', 'custodian_changes', 'custodian_scan'}


def _register():
    spec = importlib.util.spec_from_file_location('custodian_plugin_test', ROOT / '__init__.py', submodule_search_locations=[str(ROOT)])
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    class Context:
        def __init__(self):
            self.tools = {}
            self.registrations = []

        def register_tool(self, **kwargs):
            self.registrations.append(kwargs['name'])
            self.tools[kwargs['name']] = kwargs
    context = Context()
    module.register(context)
    return context


def test_registration_is_pure_and_tools_have_no_mutation_authority():
    context = _register()
    assert set(context.tools) == WARDEN_TOOLS
    for tool in context.tools.values():
        assert tool['schema']['parameters']['additionalProperties'] is False
        assert 'approved' not in tool['schema']['parameters'].get('properties', {})


def test_only_warden_tools_are_registered_and_legacy_names_are_absent():
    context = _register()
    # Exactly four registrations: no duplicate and no legacy alias, which would
    # keep colliding with the other plugin that owns the custodian_* names.
    assert sorted(context.registrations) == sorted(WARDEN_TOOLS)
    assert not LEGACY_TOOLS & set(context.tools)
    assert not any(name.startswith('custodian_') for name in context.tools)
    for name, tool in context.tools.items():
        assert tool['schema']['name'] == name
        assert tool['schema']['parameters'] == {'type': 'object', 'properties': {}, 'additionalProperties': False}
        assert not any(legacy in json.dumps(tool['schema']) for legacy in LEGACY_TOOLS)


def test_plugin_source_and_manifest_declare_exactly_the_warden_tools():
    source = (ROOT / '__init__.py').read_text(encoding='utf-8')
    manifest = (ROOT / 'plugin.yaml').read_text(encoding='utf-8')
    for legacy in LEGACY_TOOLS:
        assert legacy not in source
        assert legacy not in manifest
    block = manifest.split('provides_tools:', 1)[1].split('provides_hooks:', 1)[0]
    assert set(re.findall(r'^\s*-\s*(\S+)\s*$', block, re.MULTILINE)) == WARDEN_TOOLS
    assert len(re.findall(r'^\s*-\s', block, re.MULTILINE)) == 4
    # Identity is unchanged: only the tool names moved.
    assert re.search(r'^name: hermes-custodian$', manifest, re.MULTILINE)
    assert "'plugin-data' / 'hermes-custodian'" in source


@pytest.mark.parametrize('args', [
    {'watched_paths': ['/']}, {'approved': True}, {'scope': 'everything'}, {'enable': True}, ['x'], 'x',
])
def test_every_warden_tool_still_rejects_arguments_before_touching_state(monkeypatch, args):
    class Forbidden:
        @staticmethod
        def get_hermes_home():
            pytest.fail('arguments must be rejected before any state lookup')
    monkeypatch.setitem(sys.modules, 'hermes_constants', Forbidden)
    context = _register()
    for name in WARDEN_TOOLS:
        result = json.loads(context.tools[name]['handler'](args))
        assert result == {'ok': False, 'status': 'error',
                          'error': 'This tool takes no arguments; change scope through trusted setup.'}


def test_warden_tools_map_only_to_read_only_engine_methods(monkeypatch, tmp_path):
    class Constants:
        @staticmethod
        def get_hermes_home():
            return tmp_path
    monkeypatch.setitem(sys.modules, 'hermes_constants', Constants)
    state_dir = tmp_path / 'plugin-data' / 'hermes-custodian'
    state_dir.mkdir(parents=True)
    (state_dir / 'settings.json').write_text('{}')
    called = []

    class RecordingEngine:
        def __init__(self, path):
            assert Path(path) == state_dir

        def __getattr__(self, method):
            def call(*args, **kwargs):
                assert not args and not kwargs
                called.append(method)
                return {'method': method}
            return call

    import custodian.engine as engine_module
    monkeypatch.setattr(engine_module, 'Engine', RecordingEngine)
    context = _register()
    seen = {}
    for name in sorted(WARDEN_TOOLS):
        result = json.loads(context.tools[name]['handler']({}))
        assert result['ok'] is True and result['status'] == 'ok'
        seen[name] = result['data']['method']
    assert seen == {'warden_status': 'status', 'warden_findings': 'findings',
                    'warden_changes': 'events', 'warden_scan': 'scan'}
    # No setup, approval, service or update-policy entry point is reachable.
    assert sorted(called) == ['events', 'findings', 'scan', 'status']
