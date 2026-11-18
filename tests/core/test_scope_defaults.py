from custodian.engine import Engine


def test_default_scope_skips_generated_dependencies_before_spending_budget(tmp_path):
    project = tmp_path / 'project'; project.mkdir()
    for name in ('vendor', 'venv', 'node_modules', 'dist', 'build'):
        folder = project / name; folder.mkdir()
        for index in range(5): (folder / str(index)).write_text('synthetic dependency')
    (project / 'source.txt').write_text('synthetic source')
    engine = Engine(tmp_path / 'state')
    settings = engine.setup({'watched_paths': [str(project)], 'max_files': 2})
    result = engine.scan()
    assert result['complete'], result['errors']
    assert result['files_checked'] == 1
    assert 'vendor' in settings['exclusions']


def test_explicit_exclusions_are_preserved(tmp_path):
    project = tmp_path / 'project'; project.mkdir()
    engine = Engine(tmp_path / 'state')
    settings = engine.setup({'watched_paths': [str(project)], 'exclusions': ['custom-cache']})
    assert settings['exclusions'] == ['custom-cache']
