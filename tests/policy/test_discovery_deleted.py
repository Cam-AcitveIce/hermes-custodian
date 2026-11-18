"""Administrative profile storage must never become an inventory target."""
from contextlib import nullcontext
import json
import os

import pytest

from custodian import _platform, discovery


@pytest.mark.skipif(_platform.IS_WINDOWS, reason='POSIX no-follow fixtures')
def test_inventory_never_opens_administrative_profile_directories(tmp_path, monkeypatch):
    root = tmp_path / 'hermes'
    root.mkdir()
    (root / 'config.json').write_text('{"model":"default-model"}')
    for name in ('default', 'ivy', 'athena', '.deleted', '.administrative'):
        profile = root / 'profiles' / name
        profile.mkdir(parents=True)
        (profile / 'config.json').write_text(json.dumps({'model': name + '-model'}))
    archived = root / 'profiles' / '.deleted' / 'old-profile'
    archived.mkdir()
    (archived / 'config.json').write_text('{"model":"ARCHIVED"}')
    (root / 'profiles' / 'linked').symlink_to(archived, target_is_directory=True)
    real_open = os.open

    def guarded_open(path, *args, **kwargs):
        if str(path) in ('.deleted', '.administrative'):
            pytest.fail('Inventory opened administrative profile directory: ' + str(path))
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(os, 'open', guarded_open)
    result = discovery.inventory(root)
    assert [entry['name'] for entry in result] == ['default', 'athena', 'default', 'ivy']
    assert [entry['metadata']['model'] for entry in result] == [
        'default-model', 'athena-model', 'default-model', 'ivy-model']
    assert 'ARCHIVED' not in json.dumps(result)
    assert not any(entry['errors'] for entry in result)


@pytest.mark.parametrize('budget', [3, 5])
def test_administrative_entries_still_count_toward_discovery_budget(tmp_path, monkeypatch, budget):
    class Directory:
        def __init__(self, names=()):
            self.names = names

        def read_file(self, name, *, max_bytes):
            if name != 'config.json':
                raise FileNotFoundError(name)
            return b'{"model":"fixture"}'

        def directory_names(self, *, limit):
            assert limit == budget + 1
            return self.names[:limit]

        def open_directory(self, name):
            if name == 'profiles':
                return nullcontext(profiles)
            assert not name.startswith('.'), 'Administrative directory opened'
            opened.append(name)
            return nullcontext(Directory())

    opened = []
    profiles = Directory(['.deleted', '.administrative', 'athena', 'default', 'ivy'])
    monkeypatch.setattr(discovery, 'MAX_PROFILES', budget)
    monkeypatch.setattr(_platform, 'IS_WINDOWS', True)
    monkeypatch.setattr(_platform, 'open_directory_nofollow',
                        lambda path: nullcontext(Directory()), raising=False)
    result = discovery.inventory(tmp_path)
    expected = ['athena'] if budget == 3 else ['athena', 'default', 'ivy']
    assert opened == expected
    assert [entry['name'] for entry in result] == ['default', *expected]
    assert result[0]['errors'] == (
        ['Profile discovery entry budget exhausted'] if budget == 3 else [])
