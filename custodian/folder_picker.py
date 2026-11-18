"""Folder-picker model: names-only, bounded, no-follow directory browsing.

Nothing here reads file contents, writes anything, touches settings or starts a
scan. Directories are opened through the platform seam's handle-relative
no-follow capability, so symlinks, junctions and symlinked ancestors are never
traversed. Textual is not imported; the widget lives in ``custodian.tui``.
"""
from __future__ import annotations
from dataclasses import dataclass
import os
from pathlib import Path, PurePath, PureWindowsPath
import re
import sys

MAX_ENTRIES = 1000

UNAVAILABLE = ('Folder is unavailable, unreadable, was replaced, or is reached through a link. '
               'Links and junctions are never followed.')
PRIVATE = ('Private agent data (credentials, history, sessions, memories and similar) '
           'is never browsed, listed or added.')
TOO_BROAD = ('Too broad: the engine does not accept a filesystem root, drive root or your home '
             'folder as a monitoring scope. Open it and choose a specific folder inside.')
STATE_DIR = "The Warden's own state directory cannot be monitored."
INVALID = 'Only absolute folder paths without traversal can be selected.'
TOP = 'Already at the top folder.'


@dataclass(frozen=True)
class Entry:
    name: str
    path: str
    blocked: str | None = None


@dataclass(frozen=True)
class Listing:
    path: str
    entries: tuple = ()
    hidden: int = 0
    truncated: bool = False
    error: str | None = None


def _platform_default():
    from . import _platform
    return _platform


def _sort_key(name):
    return (name.casefold(), name)


def is_private(path) -> bool:
    """Same path-only classification the engine uses for sensitive data."""
    from . import policy
    # Classify component by component so Windows-flavoured paths are split correctly on any host.
    parts = (path if isinstance(path, PurePath) else Path(path)).parts[1:]
    return bool(parts) and policy.is_sensitive(Path(*parts))


def _safe_name(name):
    return (isinstance(name, str) and name not in ('', '.', '..')
            and not any(c in name for c in '/\\:\0'))


def list_children(path, *, platform=None, limit=MAX_ENTRIES) -> Listing:
    """List the immediate child directories of ``path``; never recurse or follow links."""
    platform = platform or _platform_default()
    path = path if isinstance(path, PurePath) else Path(path)
    opener = getattr(platform, 'open_directory_nofollow', None)
    if is_private(path):
        return Listing(str(path), error=PRIVATE)
    try:
        if not callable(opener) or not path.is_absolute() or '..' in path.parts:
            raise ValueError('unsafe')
        with opener(path) as directory:
            # One extra entry is requested only to learn whether more exist.
            names = list(directory.directory_names(limit=limit + 1))[:limit + 1]
    except (OSError, ValueError):
        return Listing(str(path), error=UNAVAILABLE)
    truncated = len(names) > limit
    names = names[:limit]
    found = sorted({n for n in names if _safe_name(n)}, key=_sort_key)
    entries = tuple(Entry(name, str(path / name), PRIVATE if is_private(path / name) else None)
                    for name in found)
    return Listing(str(path), entries, hidden=len(names) - len(found), truncated=truncated)


# ------------------------------------------------------------------ drives
def drives_from_bitmask(mask: int) -> list[str]:
    """Decode a GetLogicalDrives bitmask into drive roots."""
    return [f'{chr(65 + bit)}:\\' for bit in range(26) if mask >> bit & 1]


def _native_drives():
    lister = getattr(os, 'listdrives', None)  # Python 3.12+, Windows only
    if lister is not None:
        return lister()
    import ctypes
    return drives_from_bitmask(ctypes.windll.kernel32.GetLogicalDrives())


def list_drives(listdrives=None) -> list[str]:
    """Local drive roots (``C:\\``) from the standard library; empty off Windows. No network calls."""
    if listdrives is None:
        if sys.platform != 'win32':
            return []
        listdrives = _native_drives
    try:
        raw = list(listdrives())
    except (OSError, AttributeError, ValueError):
        return []
    return sorted({d[0].upper() + ':\\' for d in raw
                   if isinstance(d, str) and re.fullmatch(r'[A-Za-z]:\\', d)})


# ------------------------------------------------------------------- merge
def _line_key(line, case_insensitive):
    text = line.strip()
    text = text.rstrip('/\\') or text
    return text.casefold() if case_insensitive else text


def merge_paths(text: str, selected, *, case_insensitive=False) -> str:
    """Append selected paths not already present; existing text and order are kept verbatim."""
    seen = {_line_key(line, case_insensitive) for line in text.splitlines() if line.strip()}
    added = []
    for path in selected:
        key = _line_key(path, case_insensitive)
        if key and key not in seen:
            seen.add(key)
            added.append(path.strip())
    if not added:
        return text
    base = text.rstrip('\r\n')
    return '\n'.join(([base] if base else []) + added)


# ------------------------------------------------------------------- model
class PickerModel:
    """Navigation and multi-selection state. Purely in memory; never persists anything."""

    def __init__(self, start=None, *, home=None, platform=None, drives=None, forbidden=(),
                 limit=MAX_ENTRIES, autoload=True):
        self.platform = platform or _platform_default()
        home = home if home is not None else Path.home()
        start = start if start is not None else home
        self._flavour = type(start) if isinstance(start, PurePath) else Path
        self.case_insensitive = issubclass(self._flavour, PureWindowsPath)
        self.home = self._flavour(home)
        if drives is None and getattr(self.platform, 'IS_WINDOWS', False):
            drives = list_drives
        self._drives = drives
        self.forbidden = [self._flavour(item) for item in forbidden]
        self.limit = limit
        self.current: str | None = None
        self.listing = Listing('', error=UNAVAILABLE)
        self.status = ''
        self.selected: list[str] = []
        if autoload:
            for candidate in (start, self.home, self._flavour(self.home.anchor or str(self.home))):
                if self.open(str(candidate)):
                    break
            else:
                if not self.show_drives():
                    self.current = str(self._flavour(start))
                    self.status = UNAVAILABLE
        else:
            self.current = str(self._flavour(start))
            self.listing = Listing(self.current)

    # -- navigation: probe() may run in a worker thread; apply() commits on the UI thread
    @property
    def has_drives(self) -> bool:
        return self._drives is not None

    def probe(self, target) -> Listing:
        if target is None:
            drives = list(self._drives()) if self.has_drives else []
            return Listing('', tuple(Entry(d, d) for d in drives),
                           error=None if drives else UNAVAILABLE)
        return list_children(self._flavour(target), platform=self.platform, limit=self.limit)

    def apply(self, target, listing: Listing) -> bool:
        if listing.error:
            self.status = listing.error
            return False
        self.current = None if target is None else listing.path
        self.listing = listing
        self.status = ''
        return True

    def open(self, target) -> bool:
        return self.apply(target, self.probe(target))

    def refresh(self) -> bool:
        listing = self.probe(self.current)
        if listing.error:
            self.listing, self.status = listing, listing.error
            return False
        return self.apply(self.current, listing)

    def parent_target(self):
        """Where Parent leads: a path, None for the drive list, or False at the top."""
        if self.current is None:
            return False
        path = self._flavour(self.current)
        if path.parent != path:
            return str(path.parent)
        return None if self.has_drives else False

    def parent(self) -> bool:
        target = self.parent_target()
        if target is False:
            self.status = TOP
            return False
        return self.open(target)

    def go_home(self) -> bool:
        return self.open(str(self.home))

    def show_drives(self) -> bool:
        return self.has_drives and self.open(None)

    # -- selection
    def _key(self, path) -> str:
        text = str(path)
        return text.casefold() if self.case_insensitive else text

    def selection_problem(self, value) -> str | None:
        path = self._flavour(value)
        if not path.is_absolute() or '..' in path.parts:
            return INVALID
        if is_private(path):
            return PRIVATE
        if path.parent == path or self._key(path) == self._key(self.home):
            return TOO_BROAD
        blocked = {self._key(item) for item in self.forbidden}
        if blocked & {self._key(item) for item in (path, *path.parents)}:
            return STATE_DIR
        return None

    def is_selected(self, value) -> bool:
        key = self._key(self._flavour(value))
        return any(self._key(item) == key for item in self.selected)

    def toggle(self, value) -> bool:
        problem = self.selection_problem(value)
        if problem:
            self.status = problem
            return False
        path = str(self._flavour(value))
        key = self._key(path)
        kept = [item for item in self.selected if self._key(item) != key]
        if len(kept) == len(self.selected):
            kept.append(path)
        self.selected = kept
        self.status = ''
        return True

    def select_current(self) -> bool:
        if self.current is None:
            self.status = TOO_BROAD
            return False
        if self.is_selected(self.current):
            return True
        return self.toggle(self.current)

    def merge_into(self, text: str) -> str:
        return merge_paths(text, self.selected, case_insensitive=self.case_insensitive)
