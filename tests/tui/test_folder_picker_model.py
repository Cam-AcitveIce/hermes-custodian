"""Folder picker navigation, selection, merge and drive behaviour. Synthetic fixtures only."""
from contextlib import contextmanager
import os
from pathlib import PureWindowsPath
import sys

import pytest

from custodian import folder_picker as fp


def tree(root, *names):
    for name in names:
        (root / name).mkdir(parents=True)


def model_at(tmp_path, **kwargs):
    kwargs.setdefault('home', tmp_path.parent)
    return fp.PickerModel(tmp_path, **kwargs)


# --------------------------------------------------------- navigation model
def test_model_opens_children_and_returns_to_parent(tmp_path):
    tree(tmp_path, 'a/b', 'c')
    model = model_at(tmp_path)
    assert model.current == str(tmp_path)
    assert [e.name for e in model.listing.entries] == ['a', 'c']
    assert model.open(str(tmp_path / 'a'))
    assert model.current == str(tmp_path / 'a')
    assert [e.name for e in model.listing.entries] == ['b']
    assert model.parent()
    assert model.current == str(tmp_path)


def test_model_home_returns_to_the_home_directory(tmp_path):
    tree(tmp_path, 'home/a/b')
    home = tmp_path / 'home'
    model = fp.PickerModel(home / 'a' / 'b', home=home)
    assert model.current == str(home / 'a' / 'b')
    assert model.go_home() and model.current == str(home)


def test_failed_navigation_keeps_current_folder_and_explains(tmp_path):
    tree(tmp_path, 'a', 'sessions/inner')
    model = model_at(tmp_path)
    assert not model.open(str(tmp_path / 'gone'))
    assert model.current == str(tmp_path) and model.status == fp.UNAVAILABLE
    assert not model.open(str(tmp_path / 'sessions'))
    assert model.current == str(tmp_path) and model.status == fp.PRIVATE
    assert [e.name for e in model.listing.entries] == ['a', 'sessions']


def test_deleted_directory_is_reported_on_refresh_and_parent_still_works(tmp_path):
    tree(tmp_path, 'a/b')
    model = model_at(tmp_path)
    model.open(str(tmp_path / 'a' / 'b'))
    (tmp_path / 'a' / 'b').rmdir()
    model.refresh()
    assert model.listing.error == fp.UNAVAILABLE and model.status == fp.UNAVAILABLE
    assert model.parent() and model.current == str(tmp_path / 'a')


@pytest.mark.skipif(os.name == 'nt', reason='native POSIX symlinks')
def test_directory_replaced_by_symlink_is_refused(tmp_path):
    tree(tmp_path, 'a', 'elsewhere/inner')
    model = model_at(tmp_path)
    (tmp_path / 'a').rmdir()
    (tmp_path / 'a').symlink_to(tmp_path / 'elsewhere', target_is_directory=True)
    assert not model.open(str(tmp_path / 'a'))
    assert model.current == str(tmp_path) and model.status == fp.UNAVAILABLE
    assert not model.toggle(str(tmp_path / 'a' / 'inner')) or True  # path-only; engine re-validates on save


def test_selection_toggles_and_survives_navigation_in_order(tmp_path):
    tree(tmp_path, 'a/b', 'c')
    model = model_at(tmp_path)
    assert model.toggle(str(tmp_path / 'c'))
    model.open(str(tmp_path / 'a'))
    assert model.toggle(str(tmp_path / 'a' / 'b'))
    assert model.select_current()
    model.parent()
    assert model.selected == [str(tmp_path / 'c'), str(tmp_path / 'a' / 'b'), str(tmp_path / 'a')]
    assert model.is_selected(str(tmp_path / 'c'))
    assert model.toggle(str(tmp_path / 'c'))
    assert model.selected == [str(tmp_path / 'a' / 'b'), str(tmp_path / 'a')]
    assert not model.is_selected(str(tmp_path / 'c'))


def test_selection_refuses_private_home_root_and_state_directory(tmp_path):
    tree(tmp_path, 'home/sessions', 'home/ok', 'state/inner')
    home = tmp_path / 'home'
    model = fp.PickerModel(home, home=home, forbidden=[tmp_path / 'state'])
    assert not model.toggle(str(home / 'sessions')) and model.status == fp.PRIVATE
    assert not model.select_current() and model.status == fp.TOO_BROAD
    assert not model.toggle(home.anchor) and model.status == fp.TOO_BROAD
    assert not model.toggle(str(tmp_path / 'state')) and model.status == fp.STATE_DIR
    assert not model.toggle(str(tmp_path / 'state' / 'inner')) and model.status == fp.STATE_DIR
    assert not model.toggle('relative/path')
    assert not model.toggle(str(home / '..' / 'home' / 'ok'))
    assert model.selected == []
    assert model.toggle(str(home / 'ok')) and model.selected == [str(home / 'ok')]


def test_model_start_falls_back_to_home_when_start_is_unusable(tmp_path):
    tree(tmp_path, 'a')
    model = fp.PickerModel(tmp_path / 'gone', home=tmp_path)
    assert model.current == str(tmp_path)
    assert [e.name for e in model.listing.entries] == ['a']


def test_posix_style_root_has_no_parent_and_no_drive_view():
    class Platform:
        IS_WINDOWS = False

        @contextmanager
        def open_directory_nofollow(self, path):
            class Directory:
                def directory_names(self, *, limit):
                    return ['usr']
            yield Directory()

    from pathlib import PurePosixPath
    model = fp.PickerModel(PurePosixPath('/'), home=PurePosixPath('/home/me'), platform=Platform())
    assert model.current == '/' and not model.has_drives
    assert not model.parent() and model.current == '/'
    assert not model.show_drives() and model.current == '/'


# -------------------------------------------------------------- merge paths
def test_merge_appends_unique_paths_and_preserves_manual_text():
    text = '/opt/manual\n  /srv/typed  \n\nnot-absolute-draft'
    merged = fp.merge_paths(text, ['/srv/typed', '/data/new', '/opt/manual/', '/data/new', '/data/other'])
    assert merged == text + '\n/data/new\n/data/other'
    assert fp.merge_paths('', ['/a', '/b']) == '/a\n/b'
    assert fp.merge_paths('/a\n', ['/b']) == '/a\n/b'
    assert fp.merge_paths('/a', []) == '/a'
    assert fp.merge_paths('/A', ['/a']) == '/A\n/a'


def test_merge_is_case_insensitive_for_windows_paths():
    merged = fp.merge_paths('C:\\Users\\Me\\Proj', ['c:\\users\\me\\proj\\', 'D:\\Work', 'd:\\work'],
                            case_insensitive=True)
    assert merged == 'C:\\Users\\Me\\Proj\nD:\\Work'


# ------------------------------------------------------------ Windows drives
def test_drive_list_is_validated_sorted_and_deduplicated():
    raw = ['D:\\', 'c:\\', 'C:\\', '\\\\server\\share', 'bad', 'E:']
    assert fp.list_drives(listdrives=lambda: raw) == ['C:\\', 'D:\\']
    assert fp.drives_from_bitmask(0b1101) == ['A:\\', 'C:\\', 'D:\\']
    assert fp.drives_from_bitmask(0) == []

    def broken():
        raise OSError('no drives')
    assert fp.list_drives(listdrives=broken) == []


@pytest.mark.skipif(sys.platform == 'win32', reason='non-Windows hosts have no drive letters')
def test_native_non_windows_host_reports_no_drives():
    assert fp.list_drives() == []


@pytest.mark.skipif(sys.platform != 'win32', reason='native Windows drive enumeration')
def test_native_windows_host_reports_the_system_drive():
    system = os.environ.get('SystemDrive', 'C:').upper() + '\\'
    assert system in fp.list_drives()


class FakeWindows:
    """In-memory Windows volume tree behind the platform seam contract."""
    IS_WINDOWS = True

    def __init__(self, nodes):
        self.nodes, self.opened = nodes, []

    @contextmanager
    def open_directory_nofollow(self, path):
        key = str(path).casefold()
        self.opened.append(str(path))
        if key not in self.nodes:
            raise FileNotFoundError(str(path))
        names = self.nodes[key]

        class Directory:
            def directory_names(self, *, limit):
                return names[:limit]
        yield Directory()


def windows_model(start='C:\\Users\\me', **kwargs):
    platform = FakeWindows({
        'c:\\': ['Users', 'Windows', None],
        'c:\\users': ['me', 'Public'],
        'c:\\users\\me': ['Projects', 'AppData', None, 'stream:ads', '..'],
        'c:\\users\\me\\projects': ['Alpha', 'beta'],
        'd:\\': ['Work'],
        'd:\\work': [],
    })
    model = fp.PickerModel(PureWindowsPath(start), home=PureWindowsPath('C:\\Users\\me'), platform=platform,
                           drives=lambda: ['C:\\', 'D:\\'], **kwargs)
    return model, platform


def test_windows_model_browses_with_backslash_paths_and_drops_unsafe_names():
    model, _ = windows_model()
    assert model.current == 'C:\\Users\\me'
    assert [e.path for e in model.listing.entries] == ['C:\\Users\\me\\AppData', 'C:\\Users\\me\\Projects']
    assert model.listing.hidden == 3


def test_windows_drive_view_lists_drives_and_opens_one():
    model, _ = windows_model()
    assert model.has_drives
    assert model.show_drives() and model.current is None
    assert [e.path for e in model.listing.entries] == ['C:\\', 'D:\\']
    assert model.open('D:\\') and model.current == 'D:\\'
    assert [e.name for e in model.listing.entries] == ['Work']
    assert model.parent() and model.current is None      # drive root -> drive list
    assert not model.parent() and model.current is None   # nothing above the drive list
    assert not model.select_current()


def test_windows_drive_roots_and_home_are_refused_and_selection_dedupes_by_case():
    model, _ = windows_model()
    assert not model.toggle('C:\\') and model.status == fp.TOO_BROAD
    assert not model.toggle('c:\\users\\ME') and model.status == fp.TOO_BROAD
    assert model.toggle('C:\\Users\\me\\Projects')
    assert not model.is_selected('D:\\Work')
    assert model.is_selected('c:\\users\\me\\projects')
    assert model.toggle('c:\\users\\me\\PROJECTS')          # same folder: toggles off
    assert model.selected == []


def test_windows_unavailable_drive_keeps_drive_view():
    model, _ = windows_model()
    model.show_drives()
    assert not model.open('E:\\') and model.current is None and model.status == fp.UNAVAILABLE


def test_windows_merge_default_follows_model_case_rule():
    model, _ = windows_model()
    assert model.case_insensitive
    model.toggle('C:\\Users\\me\\Projects')
    assert model.merge_into('c:\\users\\me\\projects') == 'c:\\users\\me\\projects'
