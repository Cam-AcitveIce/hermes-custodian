"""Marketplace installs must expose setup through Hermes, without a second venv."""
import argparse
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def registered():
    spec = importlib.util.spec_from_file_location('warden_cli_install_test', ROOT / '__init__.py', submodule_search_locations=[str(ROOT)])
    module = importlib.util.module_from_spec(spec)
    # Real package loading, matching Hermes's package-relative imports.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    class Context:
        def __init__(self): self.commands = {}; self.tools = {}
        def register_tool(self, **kw): self.tools[kw['name']] = kw
        def register_cli_command(self, **kw): self.commands[kw['name']] = kw
    ctx = Context()
    module.register(ctx)
    return ctx


def command():
    ctx = registered()
    assert 'warden' in ctx.commands, 'Marketplace plugin has no Hermes CLI setup command'
    return ctx.commands['warden']


def parser_and_args(argv):
    entry = command()
    parser = argparse.ArgumentParser(prog='hermes')
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser(entry['name'])
    entry['setup_fn'](p)
    p.set_defaults(func=entry['handler_fn'])
    return parser.parse_args(['warden', *argv])


@pytest.fixture(autouse=True)
def profile_home(monkeypatch, tmp_path):
    from types import SimpleNamespace
    home = tmp_path / 'selected-profile'
    monkeypatch.setitem(sys.modules, 'hermes_constants', SimpleNamespace(get_hermes_home=lambda: home))
    return home


def test_unconfigured_agent_tool_recommends_native_setup():
    import json
    response = json.loads(registered().tools['warden_status']['handler']({}))
    assert response['ok'] is False
    assert 'hermes warden setup' in response['error']


def test_native_command_uses_selected_hermes_profile_state(profile_home):
    args = parser_and_args(['status'])
    assert args.state_dir == profile_home / 'plugin-data' / 'hermes-custodian'


def test_package_exports_warden_launcher_and_keeps_legacy_alias():
    import tomllib
    scripts = tomllib.loads((ROOT / 'pyproject.toml').read_text())['project']['scripts']
    assert scripts.get('warden') == 'custodian.cli:main'
    assert scripts.get('custodian') == scripts['warden']


def test_marketplace_declares_setup_ui_as_required_dependency():
    import tomllib
    project = tomllib.loads((ROOT / 'pyproject.toml').read_text())['project']
    assert any(dep.startswith('textual') for dep in project['dependencies']), 'setup uses Textual, so plain marketplace install must prepare it'


def test_marketplace_registers_setup_command_without_scanning(monkeypatch):
    def forbidden(*args, **kw): pytest.fail('Registration must not inspect user state')
    monkeypatch.setattr(Path, 'iterdir', forbidden)
    assert command()['name'] == 'warden'


def test_native_command_exposes_real_setup_help(capsys):
    with pytest.raises(SystemExit) as result:
        parser_and_args(['setup', '--help'])
    assert result.value.code == 0
    output = capsys.readouterr().out
    assert 'setup' in output and 'hermes warden' in output


def test_native_command_reaches_cli_and_uses_isolated_state(tmp_path, capsys):
    args = parser_and_args(['--state-dir', str(tmp_path / 'state'), 'status'])
    assert args.command == 'warden', 'Nested parser must preserve Hermes top-level command identity'
    assert args.func(args) == 0
    assert 'configured' in capsys.readouterr().out


def test_native_setup_requires_interactive_consent(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(sys.stdin, 'isatty', lambda: False)
    monkeypatch.setattr(sys.stdout, 'isatty', lambda: False)
    args = parser_and_args(['--state-dir', str(tmp_path / 'state'), 'setup'])
    with pytest.raises(SystemExit) as result:
        args.func(args)
    assert result.value.code == 2
    assert 'interactive terminal' in capsys.readouterr().err
    assert not (tmp_path / 'state' / 'settings.json').exists()
