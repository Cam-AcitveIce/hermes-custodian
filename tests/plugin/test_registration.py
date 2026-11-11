import importlib.util
import json
from pathlib import Path


def test_registration_is_pure_and_tools_have_no_mutation_authority():
    root = Path(__file__).resolve().parents[2]
    spec = importlib.util.spec_from_file_location('custodian_plugin_test', root / '__init__.py', submodule_search_locations=[str(root)])
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    class Context:
        tools = {}
        def register_tool(self, **kwargs): self.tools[kwargs['name']] = kwargs
    context = Context()
    module.register(context)
    assert set(context.tools) == {'custodian_status', 'custodian_findings', 'custodian_changes', 'custodian_scan'}
    for tool in context.tools.values():
        assert tool['schema']['parameters']['additionalProperties'] is False
        assert 'approved' not in tool['schema']['parameters'].get('properties', {})
