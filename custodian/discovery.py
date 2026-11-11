"""Opt-in, bounded profile metadata discovery; never a general filesystem scan."""
from contextlib import contextmanager
import importlib
import json
import os
from pathlib import Path
import stat

from . import _platform

MAX_CONFIG_BYTES = 262144
MAX_PROFILES = 100


def _open_directory(path):
    """Anchor every component with no-follow descriptors, including parents."""
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('Inventory root must be an absolute path without traversal')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


class _PosixDirectory:
    def __init__(self, fd):
        self.fd = fd

    @contextmanager
    def open_directory(self, name):
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.fd)
        try:
            yield _PosixDirectory(fd)
        finally:
            os.close(fd)

    def directory_names(self, *, limit):
        names = []
        with os.scandir(self.fd) as iterator:
            for index, child in enumerate(iterator):
                if index >= limit:
                    break
                # Budget counts all entries, including non-directories.
                names.append(child.name if child.is_dir(follow_symlinks=False) else None)
        return names

    def read_file(self, name, *, max_bytes):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.fd)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > max_bytes:
                raise ValueError('Config is nonregular or exceeds metadata byte budget')
            chunks, remaining = [], max_bytes + 1
            while remaining:
                chunk = os.read(fd, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            return b''.join(chunks)
        finally:
            os.close(fd)


@contextmanager
def _directory(path):
    """Windows capability must pin ancestors and reject every reparse point.

    open_directory returns a context manager for a similarly pinned child;
    directory_names(limit=) counts *all* entries and returns directory names
    (None for other entries). read_file(name, max_bytes=) rejects nonregular
    files and oversize files before reading, then reads at most max_bytes + 1.
    No operation may resolve children through a replaceable path ancestor.
    """
    if _platform.IS_WINDOWS:
        operation = getattr(_platform, 'open_directory_nofollow', None)
        if not callable(operation):
            raise OSError('Required secure platform operation unavailable: open_directory_nofollow')
        with operation(path) as directory:
            yield directory
    else:
        fd = _open_directory(path)
        try:
            yield _PosixDirectory(fd)
        finally:
            os.close(fd)


def _config(directory):
    for name in ('config.yaml', 'config.yml', 'config.json'):
        try:
            raw = directory.read_file(name, max_bytes=MAX_CONFIG_BYTES)
        except FileNotFoundError:
            continue
        if len(raw) > MAX_CONFIG_BYTES:
            raise ValueError('Config exceeds metadata byte budget')
        if name.endswith('.json'):
            value = json.loads(raw)
        else:
            import yaml
            try:
                for token in yaml.scan(raw):
                    if isinstance(token, (yaml.tokens.AliasToken, yaml.tokens.AnchorToken, yaml.tokens.TagToken)):
                        raise ValueError('Config aliases and tags are not supported for metadata inventory')
                value = yaml.safe_load(raw)
            except yaml.YAMLError:
                raise ValueError('Config YAML is invalid') from None
        if not isinstance(value, dict):
            raise ValueError('Config must be a mapping')
        return value
    return {}


def inventory(hermes_root: Path) -> list[dict]:
    policy = importlib.import_module('.policy', __package__)
    root = Path(hermes_root)
    if not root.is_absolute() or '..' in root.parts:
        raise ValueError('Inventory root must be an absolute path without traversal')
    entries = []
    with _directory(root) as directory:
        def add(name, path, handle):
            entry = {'name': policy.sanitise_text(name), 'path': policy.sanitise_text(str(path)),
                     'metadata': {}, 'errors': []}
            if policy.is_sensitive(path):
                entry['errors'].append('Private profile config metadata excluded by policy')
                entries.append(entry)
                return
            try:
                entry['metadata'] = policy.redact_config(_config(handle))
            except (OSError, ValueError, ImportError, RecursionError):
                entry['errors'].append('Config metadata unavailable, invalid, or exceeds safety budget')
            entries.append(entry)
        add('default', root, directory)
        try:
            with directory.open_directory('profiles') as profiles:
                names = profiles.directory_names(limit=MAX_PROFILES + 1)
                if len(names) > MAX_PROFILES:
                    entries[0]['errors'].append('Profile discovery entry budget exhausted')
                for name in sorted(n for n in names[:MAX_PROFILES] if n is not None):
                    # Treat backend names as untrusted path components.
                    if name in ('.', '..') or '/' in name or '\\' in name or ':' in name:
                        entries[0]['errors'].append('Profile changed or is unavailable')
                        continue
                    try:
                        with profiles.open_directory(name) as child:
                            add(name, root / 'profiles' / name, child)
                    except (OSError, ValueError):
                        entries[0]['errors'].append('Profile changed or is unavailable')
        except FileNotFoundError:
            pass
        except (OSError, ValueError):
            entries[0]['errors'].append('Named profile directory unavailable or unsafe')
        return entries
