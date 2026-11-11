"""First-run setup offers to create the dashboard login so a new user is never left guessing."""
import builtins
import getpass

from custodian import cli
from custodian.dashboard_auth import DashboardAuth
from custodian.engine import Engine

PASSWORD = 'correct horse battery staple'


def _interactive(monkeypatch):
    monkeypatch.setattr(cli.sys.stdin, 'isatty', lambda: True)
    monkeypatch.setattr(cli.sys.stdout, 'isatty', lambda: True)


def _fake_tui(monkeypatch, state, *, finishes_setup):
    class FakeApp:
        def __init__(self, state_dir, force_setup=False):
            self.state_dir = state_dir

        def run(self):
            if finishes_setup:
                scope = state.parent / 'scope'
                scope.mkdir(exist_ok=True)
                Engine(self.state_dir).setup({'watched_paths': [str(scope)]})

    import custodian.tui as tui
    monkeypatch.setattr(tui, 'CustodianApp', FakeApp)


def _answers(monkeypatch, inputs, passwords):
    asked = []
    seq_in, seq_pw = iter(inputs), iter(passwords)

    def fake_input(prompt=''):
        asked.append(prompt)
        return next(seq_in)

    monkeypatch.setattr(builtins, 'input', fake_input)
    monkeypatch.setattr(getpass, 'getpass', lambda prompt='': next(seq_pw))
    return asked


def test_setup_offers_dashboard_login_and_saves_it_when_accepted(monkeypatch, tmp_path, capsys):
    state = tmp_path / 'state'
    _interactive(monkeypatch)
    _fake_tui(monkeypatch, state, finishes_setup=True)
    asked = _answers(monkeypatch, ['y', 'cam'], [PASSWORD, PASSWORD])
    assert cli.main(['--state-dir', str(state), 'setup']) == 0
    assert any('dashboard login' in prompt.lower() for prompt in asked)
    auth = DashboardAuth(state)
    assert auth.configured()
    assert auth.authenticate('cam', PASSWORD)
    assert PASSWORD not in capsys.readouterr().out


def test_declining_leaves_no_login_and_says_how_to_set_it_later(monkeypatch, tmp_path, capsys):
    state = tmp_path / 'state'
    _interactive(monkeypatch)
    _fake_tui(monkeypatch, state, finishes_setup=True)
    _answers(monkeypatch, ['n'], [])
    assert cli.main(['--state-dir', str(state), 'setup']) == 0
    assert not DashboardAuth(state).configured()
    assert 'custodian dashboard-credentials' in capsys.readouterr().out


def test_no_prompt_when_login_already_configured(monkeypatch, tmp_path):
    state = tmp_path / 'state'
    state.mkdir()
    DashboardAuth(state).configure('cam', PASSWORD)
    _interactive(monkeypatch)
    _fake_tui(monkeypatch, state, finishes_setup=True)
    asked = _answers(monkeypatch, [], [])
    assert cli.main(['--state-dir', str(state), 'setup']) == 0
    assert asked == []


def test_no_prompt_when_setup_was_abandoned(monkeypatch, tmp_path):
    state = tmp_path / 'state'
    _interactive(monkeypatch)
    _fake_tui(monkeypatch, state, finishes_setup=False)
    asked = _answers(monkeypatch, [], [])
    assert cli.main(['--state-dir', str(state), 'setup']) == 0
    assert asked == []
    assert not DashboardAuth(state).configured()


def test_mismatched_passwords_keep_scope_but_report_failure(monkeypatch, tmp_path, capsys):
    state = tmp_path / 'state'
    _interactive(monkeypatch)
    _fake_tui(monkeypatch, state, finishes_setup=True)
    _answers(monkeypatch, ['y', 'cam'], [PASSWORD, 'something else entirely'])
    assert cli.main(['--state-dir', str(state), 'setup']) == 1
    assert Engine(state).status()['configured']
    assert not DashboardAuth(state).configured()
    assert 'custodian dashboard-credentials' in capsys.readouterr().err
