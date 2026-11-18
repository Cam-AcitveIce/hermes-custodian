"""Integration of arrow prompts with the real scope-saving engine."""
from custodian import setup_cli
from custodian.engine import Engine


def test_arrow_setup_saves_only_after_confirmation(monkeypatch, tmp_path):
    home = tmp_path / 'home'; home.mkdir()
    project = home / 'project'; project.mkdir()
    engine = Engine(tmp_path / 'state')
    monkeypatch.setattr(setup_cli, '_interactive', lambda: True)
    choices = iter(['a', 'done', 'yes'])
    def select(title, options, **kwargs):
        value = next(choices)
        assert value in [v for v, label in options]
        return value
    monkeypatch.setattr(setup_cli, '_select', select)
    answers = iter([str(project), ''])
    monkeypatch.setattr('builtins.input', lambda prompt='': next(answers))
    assert setup_cli.run_setup(engine, home=home)
    assert engine.settings()['watched_paths'] == [str(project)]


def test_arrow_profile_selection_requires_separate_discovery_consent(monkeypatch, tmp_path):
    monkeypatch.setattr(setup_cli, '_interactive', lambda: True)
    calls = []
    class Engine:
        def inventory(self, root):
            calls.append(root)
            return [{'name': 'ivy', 'path': str(tmp_path / 'ivy'), 'errors': []},
                    {'name': 'athena', 'path': str(tmp_path / 'athena'), 'errors': []}]
    choices = iter(['yes', [str(tmp_path / 'ivy'), str(tmp_path / 'athena')]])
    monkeypatch.setattr(setup_cli, '_select', lambda *a, **kw: next(choices))
    monkeypatch.setattr('builtins.input', lambda prompt='': '')
    root, profiles = setup_cli._choose_profiles(Engine(), str(tmp_path))
    assert root == str(tmp_path)
    assert len(profiles) == 2
    assert calls == [tmp_path]


def test_arrow_cancel_writes_nothing(monkeypatch, tmp_path):
    monkeypatch.setattr(setup_cli, '_interactive', lambda: True)
    monkeypatch.setattr(setup_cli, '_select', lambda *a, **kw: None)
    engine = Engine(tmp_path / 'state')
    assert not setup_cli.run_setup(engine, home=tmp_path)
    assert not engine.status()['configured']


def test_arrow_folder_browser_ticks_then_returns_selected(monkeypatch, tmp_path):
    from custodian.folder_picker import PickerModel
    home = tmp_path / 'home'; home.mkdir()
    project = home / 'project'; project.mkdir()
    model = PickerModel(home=home, start=home)
    monkeypatch.setattr(setup_cli, '_interactive', lambda: True)
    def select(title, options, **kwargs):
        assert kwargs['on_toggle'](str(project))[0]
        assert not kwargs['on_toggle']('s')[0]  # selecting the whole home stays blocked
        return 'd'
    monkeypatch.setattr(setup_cli, '_select', select)
    assert setup_cli._browse(model) == [str(project)]
