import builtins
from pathlib import Path


def test_default_setup_dispatches_to_cli_without_textual(monkeypatch, tmp_path):
    from custodian import cli
    monkeypatch.setattr(cli.sys.stdin, 'isatty', lambda: True)
    monkeypatch.setattr(cli.sys.stdout, 'isatty', lambda: True)
    from custodian import setup_cli
    calls = []
    monkeypatch.setattr(setup_cli, 'run_setup', lambda engine: calls.append(engine) or False)
    monkeypatch.setattr(cli, '_offer_dashboard_login', lambda path: (_ for _ in ()).throw(AssertionError('cancelled')))
    assert cli.main(['--state-dir', str(tmp_path / 'state'), 'setup']) == 0
    assert len(calls) == 1


def test_cli_setup_discovers_profiles_only_after_consent(monkeypatch, tmp_path):
    from custodian.setup_cli import run_setup
    class Engine:
        def __init__(self): self.saved = None; self.discovered = []
        def settings(self): raise RuntimeError('not configured')
        def inventory(self, root):
            self.discovered.append(str(root))
            return [{'name': 'ivy', 'path': str(tmp_path / 'profiles' / 'ivy'), 'errors': []}]
        def setup(self, settings): self.saved = settings
    answers = iter(['p', str(tmp_path), 'yes', '1', 'done', '', 'yes'])
    monkeypatch.setattr(builtins, 'input', lambda prompt='': next(answers))
    engine = Engine()
    assert run_setup(engine, home=tmp_path)
    assert engine.discovered == [str(tmp_path)]
    assert engine.saved['profiles'] == [str(tmp_path / 'profiles' / 'ivy')]
    assert engine.saved['hermes_root'] == str(tmp_path)


def test_cli_cancel_and_declined_discovery_write_nothing(monkeypatch, tmp_path):
    from custodian.setup_cli import run_setup
    class Engine:
        def settings(self): raise RuntimeError('not configured')
        def inventory(self, root): raise AssertionError('no consent')
        def setup(self, settings): raise AssertionError('cancelled')
    answers = iter(['p', str(tmp_path), 'n', 'q'])
    monkeypatch.setattr(builtins, 'input', lambda prompt='': next(answers))
    assert run_setup(Engine(), home=tmp_path) is False


def test_cli_real_engine_manual_scope_and_cancel_preserve_settings(monkeypatch, tmp_path):
    from custodian.setup_cli import run_setup
    from custodian.engine import Engine
    home = tmp_path / 'home'; home.mkdir()
    project = home / 'project'; project.mkdir()
    engine = Engine(tmp_path / 'state')
    answers = iter(['a', str(project), 'done', '30', 'yes'])
    monkeypatch.setattr(builtins, 'input', lambda prompt='': next(answers))
    assert run_setup(engine, home=home)
    saved = engine.settings()
    assert saved['watched_paths'] == [str(project)]
    assert saved['interval_seconds'] == 30
    answers = iter(['r', '1', 'q'])
    assert not run_setup(engine, home=home)
    assert engine.settings() == saved


def test_numbered_browser_adds_folder_without_discovery(monkeypatch, tmp_path):
    from custodian.setup_cli import run_setup
    from custodian.engine import Engine
    home = tmp_path / 'home'; home.mkdir()
    project = home / 'project'; project.mkdir()
    engine = Engine(tmp_path / 'state')
    monkeypatch.setattr(engine, 'inventory', lambda root: (_ for _ in ()).throw(AssertionError('no consent')))
    answers = iter(['2', '1', 'select', 'finish', '5', '', 'yes'])
    monkeypatch.setattr(builtins, 'input', lambda prompt='': next(answers))
    assert run_setup(engine, home=home)
    assert engine.settings()['watched_paths'] == [str(project)]


def test_declined_save_and_eof_do_not_configure(monkeypatch, tmp_path):
    from custodian.setup_cli import run_setup
    from custodian.engine import Engine
    home = tmp_path / 'home'; home.mkdir()
    project = home / 'project'; project.mkdir()
    engine = Engine(tmp_path / 'state')
    answers = iter(['a', str(project), 'done', '', 'n'])
    monkeypatch.setattr(builtins, 'input', lambda prompt='': next(answers))
    assert not run_setup(engine, home=home)
    assert not engine.status()['configured']
    monkeypatch.setattr(builtins, 'input', lambda prompt='': (_ for _ in ()).throw(EOFError()))
    assert not run_setup(engine, home=home)
    assert not engine.status()['configured']
