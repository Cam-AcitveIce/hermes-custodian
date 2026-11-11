"""Opt-in, bounded profile metadata discovery; never a general filesystem scan."""
import importlib
import json
import os
from pathlib import Path
import stat

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


def _config(fd):
    for name in ('config.yaml', 'config.yml', 'config.json'):
        try:
            handle = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        except FileNotFoundError:
            continue
        try:
            info = os.fstat(handle)
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_CONFIG_BYTES:
                raise ValueError('Config is nonregular or exceeds metadata byte budget')
            chunks, remaining = [], MAX_CONFIG_BYTES + 1
            while remaining:
                chunk = os.read(handle, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b''.join(chunks)
            if len(raw) > MAX_CONFIG_BYTES:
                raise ValueError('Config exceeds metadata byte budget')
            if name.endswith('.json'):
                value = json.loads(raw)
            else:
                import yaml
                # Reject aliases/tags up front: avoid recursive or expanding graphs.
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
        finally:
            os.close(handle)
    return {}


def inventory(hermes_root: Path) -> list[dict]:
    policy = importlib.import_module('.policy', __package__)
    root = Path(hermes_root)
    fd = _open_directory(root)
    entries = []
    try:
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
        add('default', root, fd)
        try:
            profiles = os.open('profiles', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
        except FileNotFoundError:
            return entries
        except OSError:
            entries[0]['errors'].append('Named profile directory unavailable or unsafe')
            return entries
        try:
            names = []
            with os.scandir(profiles) as iterator:
                for index, child in enumerate(iterator):
                    if index >= MAX_PROFILES:
                        entries[0]['errors'].append('Profile discovery entry budget exhausted')
                        break
                    if child.is_dir(follow_symlinks=False):
                        names.append(child.name)
            for name in sorted(names):
                try:
                    handle = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=profiles)
                except OSError:
                    entries[0]['errors'].append('Profile changed or is unavailable')
                    continue
                try:
                    add(name, root / 'profiles' / name, handle)
                finally:
                    os.close(handle)
        finally:
            os.close(profiles)
        return entries
    finally:
        os.close(fd)
