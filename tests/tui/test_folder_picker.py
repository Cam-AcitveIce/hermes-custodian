"""Folder picker model: bounded, no-follow, names-only browsing. Synthetic fixtures only."""
from contextlib import contextmanager
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import sys

import pytest

from custodian import folder_picker as fp


def tree(root, *names):
    for name in names:
        (root / name).mkdir(parents=True)


# ------------------------------------------------------------------ listing
def test_lists_immediate_child_directories_sorted_and_never_recurses(tmp_path):
    tree(tmp_path, 'beta/inner/deeper', 'Alpha', 'gamma')
    (tmp_path / 'notes.md').write_text('never read')
    listing = fp.list_children(tmp_path)
    assert [e.name for e in listing.entries] == ['Alpha', 'beta', 'gamma']
    assert [e.path for e in listing.entries] == [str(tmp_path / n) for n in ('Alpha', 'beta', 'gamma')]
    assert listing.error is None and not listing.truncated
    assert listing.hidden == 1


def test_listing_keeps_unicode_and_bracket_names_verbatim(tmp_path):
    names = ['[bold red]x', 'déjà vu', '日本語', '[link=x]y', 'a [b] c']
    tree(tmp_path, *names)
    listing = fp.list_children(tmp_path)
    assert sorted(e.name for e in listing.entries) == sorted(names)
    assert all(e.blocked is None for e in listing.entries)


# ------------------------------------------------- links, missing, replaced
@pytest.mark.skipif(os.name == 'nt', reason='native POSIX symlinks')
def test_symlinked_child_is_not_offered_and_symlink_path_is_refused(tmp_path):
    tree(tmp_path, 'real/inside', 'target/private-inner')
    (tmp_path / 'link').symlink_to(tmp_path / 'target', target_is_directory=True)
    listing = fp.list_children(tmp_path)
    assert [e.name for e in listing.entries] == ['real', 'target']
    assert listing.hidden == 1
    through_link = fp.list_children(tmp_path / 'link')
    assert through_link.entries == () and through_link.error == fp.UNAVAILABLE
    ancestor = fp.list_children(tmp_path / 'link' / 'private-inner')
    assert ancestor.entries == () and ancestor.error == fp.UNAVAILABLE


def test_missing_relative_and_traversal_paths_report_error_without_raising(tmp_path):
    assert fp.list_children(tmp_path / 'gone').error == fp.UNAVAILABLE
    assert fp.list_children(Path('relative/dir')).error == fp.UNAVAILABLE
    assert fp.list_children(tmp_path / '..' / tmp_path.name).error == fp.UNAVAILABLE
    (tmp_path / 'file.txt').write_text('x')
    assert fp.list_children(tmp_path / 'file.txt').error == fp.UNAVAILABLE


# ------------------------------------------------------- private agent data
class RecordingPlatform:
    """Wraps the real seam and records every directory that gets opened."""
    def __init__(self):
        from custodian import _platform
        self.real, self.opened = _platform, []

    @contextmanager
    def open_directory_nofollow(self, path):
        self.opened.append(str(path))
        with self.real.open_directory_nofollow(path) as directory:
            yield directory


def test_private_agent_data_children_are_blocked_with_a_reason(tmp_path):
    tree(tmp_path, 'project', 'sessions/s1', 'memories/m1', '.ssh', 'credentials', 'history')
    listing = fp.list_children(tmp_path)
    by_name = {e.name: e for e in listing.entries}
    assert by_name['project'].blocked is None
    for name in ('sessions', 'memories', '.ssh', 'credentials', 'history'):
        assert by_name[name].blocked == fp.PRIVATE


def test_private_agent_data_directory_is_never_opened_or_enumerated(tmp_path):
    tree(tmp_path, 'sessions/s1/deep')
    platform = RecordingPlatform()
    for target in (tmp_path / 'sessions', tmp_path / 'sessions' / 's1'):
        listing = fp.list_children(target, platform=platform)
        assert listing.entries == () and listing.error == fp.PRIVATE
    assert platform.opened == []


# ------------------------------------------------------------------- bounds
def test_enumeration_is_bounded_and_reports_truncation(tmp_path):
    tree(tmp_path, *[f'd{i:03d}' for i in range(12)])
    listing = fp.list_children(tmp_path, limit=5)
    assert len(listing.entries) == 5 and listing.truncated
    assert [e.name for e in listing.entries] == sorted(e.name for e in listing.entries)
    exact = fp.list_children(tmp_path, limit=12)
    assert len(exact.entries) == 12 and not exact.truncated


def test_enumeration_never_asks_the_platform_for_more_than_limit_plus_one(tmp_path):
    asked = []

    class Directory:
        def directory_names(self, *, limit):
            asked.append(limit)
            return [f'x{i}' for i in range(limit)]

    class Platform:
        @contextmanager
        def open_directory_nofollow(self, path):
            yield Directory()

    listing = fp.list_children(tmp_path, platform=Platform(), limit=7)
    assert asked == [8] and len(listing.entries) == 7 and listing.truncated
