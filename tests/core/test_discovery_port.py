"""Windows seam contracts tested with synthetic directory capabilities."""
from contextlib import nullcontext
from unittest.mock import Mock
import json
import pytest
from custodian import discovery, _platform


class Directory:
    def __init__(self, files=None, children=None):
        self.files = files or {}
        self.children = children or {}
        self.reads = []

    def read_file(self, name, *, max_bytes):
        self.reads.append(name)
        if name not in self.files:
            raise FileNotFoundError(name)
        return self.files[name]

    def open_directory(self, name):
        if name not in self.children:
            raise FileNotFoundError(name)
        return nullcontext(self.children[name])

    def directory_names(self, *, limit):
        return list(self.children)[:limit]


def test_windows_discovery_requires_secure_directory(monkeypatch, tmp_path):
    monkeypatch.setattr(_platform, 'IS_WINDOWS', True)
    monkeypatch.delattr(_platform, 'open_directory_nofollow', raising=False)
    with pytest.raises(OSError, match='secure platform operation'):
        discovery.inventory(tmp_path)


def test_windows_discovery_redacts_and_skips_private_profiles(monkeypatch, tmp_path):
    private = Directory({'config.json': b'{"model":"PRIVATE"}'})
    named = Directory({'config.json': b'{"model":"named","api_key":"SECRET"}'})
    profiles = Directory(children={'demo': named, 'memories': private})
    root = Directory({'config.json': b'{"model":"default"}'}, {'profiles': profiles})
    monkeypatch.setattr(_platform, 'IS_WINDOWS', True)
    opener = Mock(return_value=nullcontext(root))
    monkeypatch.setattr(_platform, 'open_directory_nofollow', opener, raising=False)
    result = discovery.inventory(tmp_path)
    assert [e['name'] for e in result] == ['default', 'demo', 'memories']
    assert result[1]['metadata']['model'] == 'named'
    assert 'SECRET' not in json.dumps(result)
    assert not private.reads


def test_windows_oversized_config_rejected(monkeypatch, tmp_path):
    root = Directory({'config.json': b' ' * (discovery.MAX_CONFIG_BYTES + 1)})
    monkeypatch.setattr(_platform, 'IS_WINDOWS', True)
    monkeypatch.setattr(_platform, 'open_directory_nofollow', lambda path: nullcontext(root), raising=False)
    assert discovery.inventory(tmp_path)[0]['errors']


def test_windows_unsafe_child_is_not_read(monkeypatch, tmp_path):
    profiles = Directory(children={'junction': Directory()})
    profiles.open_directory = Mock(side_effect=OSError('reparse point'))
    root = Directory(children={'profiles': profiles})
    monkeypatch.setattr(_platform, 'IS_WINDOWS', True)
    monkeypatch.setattr(_platform, 'open_directory_nofollow', lambda path: nullcontext(root), raising=False)
    result = discovery.inventory(tmp_path)
    assert len(result) == 1
    assert result[0]['errors']


@pytest.mark.skipif(_platform.IS_WINDOWS, reason='POSIX no-follow fixtures')
def test_posix_discovery_redaction_and_link_rejection(tmp_path):
    (tmp_path / 'config.json').write_text('{"model":"fixture","api_key":"SECRET"}')
    named = tmp_path / 'profiles' / 'demo'
    named.mkdir(parents=True)
    (named / 'config.json').write_text('{"model":"named"}')
    (tmp_path / 'profiles' / 'linked').symlink_to(named, target_is_directory=True)
    result = discovery.inventory(tmp_path)
    assert [e['name'] for e in result] == ['default', 'demo']
    assert 'SECRET' not in json.dumps(result)
    (named / 'config.json').unlink()
    (named / 'config.json').symlink_to(tmp_path / 'config.json')
    result = discovery.inventory(tmp_path)
    assert result[1]['errors']
    assert result[1]['metadata'] == {}
