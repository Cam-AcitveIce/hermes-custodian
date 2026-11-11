import os
import subprocess
import sys
from pathlib import Path


def test_default_state_follows_explicit_profile(monkeypatch, tmp_path):
    from custodian.cli import default_state_dir
    monkeypatch.setenv('HERMES_HOME', str(tmp_path / 'profile'))
    assert default_state_dir() == tmp_path / 'profile' / 'plugin-data' / 'hermes-custodian'
    monkeypatch.delenv('HERMES_HOME')
    monkeypatch.setenv('XDG_STATE_HOME', str(tmp_path / 'state'))
    assert default_state_dir() == tmp_path / 'state' / 'hermes-custodian'


def test_service_failure_has_nonzero_exit(monkeypatch, tmp_path, capsys):
    from custodian.cli import main
    from custodian import service
    monkeypatch.setattr(service, 'service_status', lambda: {'ok': False, 'error': 'not available'})
    assert main(['--state-dir', str(tmp_path), 'service', 'status']) == 1
    assert 'not available' in capsys.readouterr().out


def test_unattended_credential_setup_fails_without_accepting_password_flags(tmp_path):
    result = subprocess.run([sys.executable, '-m', 'custodian.cli', '--state-dir', str(tmp_path), 'dashboard-credentials'], input='', capture_output=True, text=True, timeout=5)
    assert result.returncode == 2
    assert 'interactive terminal' in result.stderr.lower()


def test_cli_help_lists_user_workflows():
    result = subprocess.run([sys.executable, '-m', 'custodian.cli', '--help'], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    for command in ('setup', 'tui', 'scan', 'monitor', 'dashboard', 'service', 'updates'):
        assert command in result.stdout


def test_unattended_setup_fails_instead_of_hanging(tmp_path):
    result = subprocess.run([sys.executable, '-m', 'custodian.cli', '--state-dir', str(tmp_path / 'state'), 'setup'], input='', capture_output=True, text=True, timeout=5)
    assert result.returncode == 2
    assert 'interactive terminal' in result.stderr.lower()


def test_service_start_wires_to_start_service_and_propagates_status(monkeypatch, tmp_path, capsys):
    from custodian.cli import main
    from custodian import service
    calls = []
    monkeypatch.setattr(service, 'start_service', lambda: (calls.append('start') or {'ok': True, 'active_state': 'active'}))
    monkeypatch.setattr(service, 'install_service', lambda *a, **kw: (_ for _ in ()).throw(AssertionError('must not install')))
    assert main(['--state-dir', str(tmp_path), 'service', 'start']) == 0
    assert calls == ['start']
    assert '"active_state": "active"' in capsys.readouterr().out
    monkeypatch.setattr(service, 'start_service', lambda: {'ok': False, 'active_state': 'failed'})
    assert main(['--state-dir', str(tmp_path), 'service', 'start']) == 1


def test_updates_security_plan_wires_enable_and_disable(monkeypatch, tmp_path, capsys):
    import json
    from custodian.cli import main
    from custodian import updates
    seen = []
    def fake_plan(enabled):
        seen.append(enabled)
        return {'status': 'ready', 'enabled': enabled, 'plan_id': 'a' * 64,
                'files': {'/etc/apt/apt.conf.d/99hermes-custodian-security': 'content' if enabled else None},
                'effects': ['Automatic-Reboot stays false']}
    monkeypatch.setattr(updates, 'plan_security_updates', fake_plan)
    assert main(['--state-dir', str(tmp_path), 'updates', 'security-plan', '--enable']) == 0
    out = json.loads(capsys.readouterr().out)
    assert out['plan_id'] == 'a' * 64
    assert '/etc/apt/apt.conf.d/99hermes-custodian-security' in out['files']
    assert out['effects'] == ['Automatic-Reboot stays false']
    assert main(['--state-dir', str(tmp_path), 'updates', 'security-plan', '--disable']) == 0
    assert seen == [True, False]
    monkeypatch.setattr(updates, 'plan_security_updates', lambda enabled: {'status': 'conflict', 'changed': False, 'error': 'conflict'})
    assert main(['--state-dir', str(tmp_path), 'updates', 'security-plan', '--enable']) == 1


def test_updates_security_apply_enforces_root_install_tty_replan_and_confirmation(monkeypatch, tmp_path, capsys):
    import builtins
    import json
    import pytest
    from custodian import cli, updates
    plan_id = 'b' * 64
    fake_plan = {'status': 'ready', 'enabled': True, 'plan_id': plan_id, 'files': {}, 'effects': []}
    applied = []
    monkeypatch.setattr(updates, 'plan_security_updates', lambda enabled: fake_plan if enabled else {'status': 'ready', 'enabled': False, 'plan_id': 'c' * 64})
    monkeypatch.setattr(updates, 'apply_security_update_policy', lambda plan, approval: (applied.append((plan, approval)) or {'status': 'applied', 'changed': True, 'enabled': True}))

    # 1. Refuses non-root or partial root (real and effective UID must both be 0)
    for uid, euid in [(1000, 1000), (0, 1000), (1000, 0)]:
        monkeypatch.setattr(cli.os, 'getuid', lambda u=uid: u)
        monkeypatch.setattr(cli.os, 'geteuid', lambda e=euid: e)
        assert cli.main(['--state-dir', str(tmp_path), 'updates', 'security-apply', '--plan-id', plan_id, '--enable']) == 1
        assert json.loads(capsys.readouterr().out)['status'] == 'denied'
        assert not applied

    # 2. Refuses when UID/EUID are 0 but install is not root-owned (e.g. user checkout/venv)
    monkeypatch.setattr(cli.os, 'getuid', lambda: 0)
    monkeypatch.setattr(cli.os, 'geteuid', lambda: 0)
    assert cli._is_root_owned_install() is False
    assert cli.main(['--state-dir', str(tmp_path), 'updates', 'security-apply', '--plan-id', plan_id, '--enable']) == 1
    assert json.loads(capsys.readouterr().out)['status'] == 'denied'
    assert not applied

    # 3. Refuses non-interactive terminal
    monkeypatch.setattr(cli, '_is_root_owned_install', lambda: True)
    monkeypatch.setattr(cli.sys.stdin, 'isatty', lambda: False)
    monkeypatch.setattr(cli.sys.stdout, 'isatty', lambda: True)
    assert cli.main(['--state-dir', str(tmp_path), 'updates', 'security-apply', '--plan-id', plan_id, '--enable']) == 1
    assert json.loads(capsys.readouterr().out)['status'] == 'denied'
    assert not applied

    # 4. Never accepts --yes or --approve flags
    monkeypatch.setattr(cli.sys.stdin, 'isatty', lambda: True)
    for flag in ('--yes', '--approve'):
        with pytest.raises(SystemExit) as exc:
            cli.main(['--state-dir', str(tmp_path), 'updates', 'security-apply', '--plan-id', plan_id, flag])
        assert exc.value.code == 2
    capsys.readouterr()

    # 5. Refuses when recomputed plan_id differs from --plan-id
    assert cli.main(['--state-dir', str(tmp_path), 'updates', 'security-apply', '--plan-id', 'd' * 64, '--enable']) == 1
    assert json.loads(capsys.readouterr().out)['status'] == 'stale'
    assert not applied

    # 6. Refuses when interactive confirmation does not match exact phrase
    monkeypatch.setattr(builtins, 'input', lambda prompt='': 'yes')
    assert cli.main(['--state-dir', str(tmp_path), 'updates', 'security-apply', '--plan-id', plan_id, '--enable']) == 1
    assert json.loads(capsys.readouterr().out)['status'] == 'denied'
    assert not applied

    # 7. Calls apply_security_update_policy only after all checks and exact confirmation pass
    monkeypatch.setattr(builtins, 'input', lambda prompt='': 'APPLY SECURITY POLICY ' + plan_id)
    assert cli.main(['--state-dir', str(tmp_path), 'updates', 'security-apply', '--plan-id', plan_id]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out['status'] == 'applied'
    assert applied == [(fake_plan, 'APPLY SECURITY POLICY ' + plan_id)]


def test_plugin_registers_only_four_readonly_tools_and_excludes_admin_actions():
    import importlib.util
    from custodian import web
    root = Path(__file__).resolve().parents[2]
    spec = importlib.util.spec_from_file_location('custodian_plugin_cli_check', root / '__init__.py', submodule_search_locations=[str(root)])
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    tools = {}
    class Context:
        def register_tool(self, **kwargs):
            tools[kwargs['name']] = kwargs
    module.register(Context())
    assert set(tools) == {'custodian_status', 'custodian_findings', 'custodian_changes', 'custodian_scan'}
    assert len(tools) == 4
    plugin_source = (root / '__init__.py').read_text()
    web_source = Path(web.__file__).read_text()
    for forbidden in ('start_service', 'plan_security_updates', 'apply_security_update_policy', 'configure_security_updates'):
        assert forbidden not in plugin_source
        assert forbidden not in web_source
