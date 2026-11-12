"""POSIX platform backend for Linux and macOS."""
from __future__ import annotations
from contextlib import contextmanager
from fnmatch import fnmatchcase
import errno
import hashlib
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
from .._subprocess_env import minimal_env

NAME ='macos' if sys.platform == 'darwin' else 'linux'

try:
    import fcntl
except ImportError:
    fcntl = None
try:
    import grp
except ImportError:
    grp = None
try:
    import pwd
except ImportError:
    pwd = None


class PrivateFileError(ValueError, OSError):
    """Raised when private file constraints (permissions, symlink, nlink, type) are violated."""
    pass


def current_principal() -> str:
    """Return the current user UID as a string."""
    return str(os.getuid())


def owner_of(path_or_fd) -> str:
    """Return the owner UID of path or fd as a string, never following symlinks."""
    if isinstance(path_or_fd, int):
        return str(os.fstat(path_or_fd).st_uid)
    return str(os.lstat(path_or_fd).st_uid)


def ensure_private_dir(path: Path) -> None:
    """Create directory if missing with mode 0700; verify current user ownership."""
    path = Path(path)
    if path.is_symlink():
        raise ValueError('State directory must not be a symlink')
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.lstat(path).st_uid != os.getuid():
        raise ValueError('State directory must belong to the current user')
    os.chmod(path, 0o700)


def ensure_private_file(path: Path) -> None:
    """Verify private regular file (owned by current user, st_nlink == 1) and chmod 0600."""
    fd = open_private_file(path, write=False, create=False)
    os.close(fd)


def open_private_file(path: Path, *, write: bool, create: bool, max_bytes: int | None = None) -> int:
    """Return an OS-level fd to a private file.

    Refuses (ValueError): symlink, non-regular, owned by another principal, hard-linked (st_nlink != 1).
    Applies fchmod 0600 when creating or opening.
    """
    path = Path(path)
    if os.path.islink(path):
        raise PrivateFileError('Private file must not be a symlink')

    flags = os.O_RDWR if write else os.O_RDONLY
    if create:
        flags |= os.O_CREAT
    flags |= getattr(os, 'O_NOFOLLOW', 0)
    flags |= getattr(os, 'O_CLOEXEC', 0)
    if not write:
        flags |= getattr(os, 'O_NONBLOCK', 0)

    try:
        fd = os.open(path, flags, 0o600)
    except FileNotFoundError:
        raise
    except OSError as exc:
        if exc.errno in (getattr(errno, 'ELOOP', 40), getattr(errno, 'EMLINK', 31)):
            raise PrivateFileError('Private file must not be a symlink') from exc
        raise

    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise PrivateFileError('Private file must be a regular file')
        if info.st_uid != os.getuid():
            raise PrivateFileError('Private file must be owned by the current user')
        if info.st_nlink != 1:
            raise PrivateFileError('Private file must not be hard-linked')
        if max_bytes is not None and info.st_size > max_bytes:
            raise PrivateFileError('Private file exceeds size limit')
        try:
            os.fchmod(fd, 0o600)
        except OSError:
            pass
        return fd
    except BaseException:
        os.close(fd)
        raise


def _group_is_private(gid, uid):
    """True when only the current user can ever act through this group."""
    try:
        storage_mod = sys.modules.get('custodian.storage')
        _grp = getattr(storage_mod, 'grp', None) or grp
        _pwd = getattr(storage_mod, 'pwd', None) or pwd
        if _grp is None or _pwd is None:
            return False
        group = _grp.getgrgid(gid)
        me = _pwd.getpwuid(uid).pw_name
        if any(member != me for member in group.gr_mem):
            return False
        return all(account.pw_uid == uid for account in _pwd.getpwall() if account.pw_gid == gid)
    except (KeyError, OSError, AttributeError):
        return False


def validate_state_root(path: Path) -> None:
    """Ancestor walk, group privacy checks, mkdir 0700, and state files verification."""
    root = Path(os.path.abspath(path))
    if root in (Path('/'), Path.home()):
        raise ValueError('Select a dedicated state directory, not root or home')
    if '..' in Path(path).parts:
        raise ValueError('state_dir must not contain traversal components')

    uid = os.getuid()
    gid = os.getgid()
    parts = root.parts[1:]
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for index, component in enumerate(parts):
            ancestor = os.fstat(directory)
            if ancestor.st_uid not in (uid, 0):
                raise ValueError('state_dir ancestor owner must be the current user or root')
            ancestor_mode = getattr(ancestor, 'st_mode', 0o700)
            sticky_root = bool((ancestor_mode & stat.S_ISVTX) and ancestor.st_uid == 0)
            if (ancestor_mode & stat.S_IWOTH) and not sticky_root:
                raise ValueError('state_dir ancestor must not be writable by other users unless sticky and root-owned')
            storage_mod = sys.modules.get('custodian.storage')
            checker = getattr(storage_mod, '_group_is_private', _group_is_private) if storage_mod else _group_is_private
            group_ok = ancestor.st_uid == uid and checker(getattr(ancestor, 'st_gid', gid), uid)
            if (ancestor_mode & stat.S_IWGRP) and not sticky_root and not group_ok:
                raise ValueError('state_dir ancestor must not be writable by other users unless sticky and root-owned')
            try:
                os.mkdir(component, mode=0o700, dir_fd=directory)
            except FileExistsError:
                pass
            try:
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | getattr(os, 'O_NOFOLLOW', 0),
                                dir_fd=directory)
            except OSError as exc:
                raise ValueError('state_dir must have only accessible nonsymlink directories') from exc
            os.close(directory)
            directory = child
        if os.fstat(directory).st_uid != uid:
            raise ValueError('state_dir owner must be the current user')
        os.fchmod(directory, 0o700)
        for name in ('settings.json', 'state.sqlite3', 'monitor.json', 'monitor.lock', 'scan.lock',
                     'state.sqlite3-journal', 'state.sqlite3-wal', 'state.sqlite3-shm'):
            try:
                fd = os.open(name, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0),
                             dir_fd=directory)
            except FileNotFoundError:
                continue
            try:
                info = os.fstat(fd)
                if info.st_uid != os.getuid() or info.st_nlink != 1 or not stat.S_ISREG(info.st_mode):
                    raise ValueError('State files must be current-user regular files without hard links')
                os.fchmod(fd, 0o600)
            finally:
                os.close(fd)
    finally:
        os.close(directory)


def fsync_directory(path: Path) -> None:
    """Fsync directory descriptor to persist metadata/renames."""
    directory = os.open(str(path), os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def try_lock_exclusive(fd: int) -> bool:
    """Non-blocking exclusive flock; False if held elsewhere."""
    if fcntl is None:
        return False
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except (BlockingIOError, OSError):
        return False


def unlock(fd: int) -> None:
    """Unlock flock."""
    if fcntl is None:
        return
    try:
        fcntl.flock(fd, fcntl.LOCK_UN)
    except OSError:
        pass


@contextmanager
def interprocess_lock(path: Path, timeout: float):
    """Exclusive flock; raises TimeoutError after timeout (poll 50 ms)."""
    fd = open_private_file(path, write=True, create=True)
    try:
        deadline = time.monotonic() + max(0.0, float(timeout))
        while True:
            if try_lock_exclusive(fd):
                break
            if time.monotonic() >= deadline:
                raise TimeoutError(f'Operation in progress for {path}; gave up after {timeout:g}s')
            time.sleep(0.05)
        try:
            yield
        finally:
            unlock(fd)
    finally:
        os.close(fd)


_ps_runner = subprocess.run


def process_is_running_as_current_user(pid: int) -> bool:
    """Check if process is active and belongs to current user.

    Linux: /proc/<pid> owner + kill 0.
    macOS: ps -o uid= -p <pid> (argv array, timeout 5s, no shell) + kill 0.
    """
    if type(pid) is not int or pid <= 0:
        return False

    is_macos = NAME == 'macos' or sys.platform == 'darwin'

    try:
        os.kill(pid, 0)
    except (ProcessLookupError, OverflowError, ValueError):
        return False
    except PermissionError:
        return False
    except OSError:
        return False

    if is_macos:
        try:
            res = _ps_runner(['ps', '-o', 'uid=', '-p', str(pid)],
                             capture_output=True, text=True, timeout=5.0,
                             env=minimal_env('ps'))
            if res.returncode != 0:
                return False
            output = res.stdout.strip()
            if not output:
                return False
            return int(output.split()[0]) == os.getuid()
        except (OSError, OverflowError, ValueError, subprocess.SubprocessError):
            return False
    else:
        try:
            return Path(f'/proc/{pid}').stat().st_uid == os.getuid()
        except (OSError, OverflowError, ValueError):
            return False


def terminate_signals() -> list:
    """Return signals monitor should handle: POSIX [SIGTERM, SIGINT, SIGHUP]."""
    import signal
    sigs = []
    for name in ('SIGTERM', 'SIGINT', 'SIGHUP'):
        sig = getattr(signal, name, None)
        if sig is not None:
            sigs.append(sig)
    return sigs


def default_state_dir() -> Path:
    """Default state directory path."""
    profile = os.environ.get('HERMES_HOME')
    if profile:
        return Path(profile) / 'plugin-data' / 'hermes-custodian'

    if NAME == 'macos' or sys.platform == 'darwin':
        return Path.home() / 'Library' / 'Application Support' / 'hermes-custodian'

    xdg = os.environ.get('XDG_STATE_HOME')
    base = Path(xdg) if xdg else Path.home() / '.local' / 'state'
    return base / 'hermes-custodian'


MAX_ENTRIES = 20000
MAX_SECONDS = 5.0
MAX_DEPTH = 64
MAX_TOTAL_BYTES = 64 * 1024 * 1024


class _BudgetExceeded(Exception):
    pass


def _signature(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _open_root(root: Path) -> int:
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | getattr(os, 'O_NOFOLLOW', 0))
    try:
        for part in root.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | getattr(os, 'O_NOFOLLOW', 0), dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _entry_type(mode: int) -> str:
    if stat.S_ISREG(mode):
        return 'file'
    if stat.S_ISLNK(mode):
        return 'symlink'
    return 'other'


def _metadata(path: Path, info: os.stat_result) -> dict:
    return {'path': str(path), 'type': _entry_type(info.st_mode),
            'mode': stat.S_IMODE(info.st_mode),
            'uid': info.st_uid, 'size': info.st_size, 'mtime_ns': info.st_mtime_ns}


def bounded_snapshot(root: Path, exclusions: list[str], max_files: int, max_file_bytes: int) -> dict:
    """Snapshot selected scope with descriptor-relative no-follow traversal."""
    from .. import policy as _policy_mod
    is_sensitive = _policy_mod.is_sensitive

    max_entries = getattr(_policy_mod, 'MAX_ENTRIES', MAX_ENTRIES)
    max_seconds = getattr(_policy_mod, 'MAX_SECONDS', MAX_SECONDS)
    max_depth = getattr(_policy_mod, 'MAX_DEPTH', MAX_DEPTH)
    max_total_bytes = getattr(_policy_mod, 'MAX_TOTAL_BYTES', MAX_TOTAL_BYTES)

    result = {'files': [], 'errors': [], 'complete': True}
    if (type(max_files) is not int or max_files <= 0
            or type(max_file_bytes) is not int or max_file_bytes <= 0
            or '..' in Path(root).parts
            or not isinstance(exclusions, list) or len(exclusions) > 100
            or any(not isinstance(p, str) or len(p) > 4096 for p in exclusions)):
        return {'files': [], 'errors': ['Invalid scan scope or limits'], 'complete': False}
    root = Path(os.path.abspath(root))

    def error(message):
        result['complete'] = False
        if len(result['errors']) < 100:
            result['errors'].append(message)

    visited = 0
    total_bytes = 0
    deadline = time.monotonic() + max_seconds

    def check_time():
        if time.monotonic() >= deadline:
            raise _BudgetExceeded('Scan time budget exhausted')

    def walk(fd, path, depth=0):
        nonlocal visited, total_bytes
        check_time()
        with os.scandir(fd) as entries:
            for entry in entries:
                check_time()
                if visited >= max_entries:
                    raise _BudgetExceeded('Traversal entry budget exhausted')
                visited += 1
                if len(result['files']) >= max_files:
                    error('File budget exhausted')
                    return
                child = path / entry.name
                relative = str(child.relative_to(root))
                if any(fnmatchcase(relative, pattern) or fnmatchcase(str(child), pattern)
                       or fnmatchcase(entry.name, pattern) for pattern in exclusions):
                    continue
                info = os.stat(entry.name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode) and not is_sensitive(child):
                    if depth >= max_depth:
                        raise _BudgetExceeded('Directory depth budget exhausted')
                    directory = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | getattr(os, 'O_NOFOLLOW', 0), dir_fd=fd)
                    try:
                        opened = os.fstat(directory)
                        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                            raise OSError('Directory replaced before traversal')
                        walk(directory, child, depth + 1)
                    finally:
                        os.close(directory)
                else:
                    item = _metadata(child, info)
                    if (stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and not is_sensitive(child)
                            and child.suffix.lower() in {'.py', '.md'}):
                        if info.st_size > max_file_bytes:
                            error('File byte budget exceeded')
                            result['files'].append(item)
                            continue
                        if total_bytes + info.st_size > max_total_bytes:
                            raise _BudgetExceeded('Aggregate byte budget exhausted')
                        handle = os.open(entry.name, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0), dir_fd=fd)
                        try:
                            opened = os.fstat(handle)
                            if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                                    or _signature(opened) != _signature(info)):
                                raise OSError('Entry replaced before read')
                            digest = hashlib.sha256()
                            remaining = info.st_size
                            while remaining:
                                check_time()
                                chunk = os.read(handle, min(65536, remaining))
                                if not chunk:
                                    break
                                total_bytes += len(chunk)
                                digest.update(chunk)
                                remaining -= len(chunk)
                            if remaining or _signature(os.fstat(handle)) != _signature(info):
                                raise OSError('File changed during hashing')
                            check_time()
                            item['sha256'] = digest.hexdigest()
                        finally:
                            os.close(handle)
                    result['files'].append(item)
    try:
        if is_sensitive(root):
            parent = _open_root(root.parent)
            try:
                result['files'].append(_metadata(root, os.stat(root.name, dir_fd=parent,
                                                              follow_symlinks=False)))
            finally:
                os.close(parent)
            return result
        fd = _open_root(root)
        try:
            walk(fd, root)
        finally:
            os.close(fd)
    except _BudgetExceeded as exc:
        error(str(exc))
    except (OSError, ValueError):
        error('Filesystem entry unavailable, changed, or unsafe')
    return result


def access_exposure(meta: dict) -> dict | None:
    """Evaluate permission exposure for sensitive file.

    None if private to owner (0o600).
    Else dict with severity, mode, summary.
    """
    mode = meta.get('mode', 0) & 0o777
    if mode & 0o077:
        return {
            'severity': 'high',
            'mode': mode,
            'summary': 'sensitive-path file has group/other permission bits set',
        }
    return None


# Secure I/O capabilities used by dashboard keys and metadata discovery.
def _io_limit(value):
    if type(value) is not int or value < 0:
        raise ValueError('Invalid byte or entry limit')
    return value


def _io_component(name):
    if not isinstance(name, str) or not name or name in ('.', '..') or any(c in name for c in '/\\:\0'):
        raise ValueError('Unsafe child name')
    return name


def _io_path(path):
    path = Path(path)
    if '..' in path.parts:
        raise ValueError('Traversal is forbidden')
    return Path(os.path.abspath(path))


def _read_io_fd(fd, max_bytes, private=False):
    _io_limit(max_bytes)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_size > max_bytes:
        raise ValueError('File is nonregular or exceeds byte limit')
    if private and (info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_mode & 0o077):
        raise PrivateFileError('File must be private, current-user owned and singly linked')
    chunks, remaining = [], max_bytes + 1
    while remaining:
        chunk = os.read(fd, min(65536, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    if not remaining:
        raise ValueError('File exceeds byte limit')
    if _signature(info) != _signature(os.fstat(fd)):
        raise ValueError('File changed during read')
    return b''.join(chunks)


class _IODirectory:
    def __init__(self, fd):
        self.fd = fd

    def _active(self):
        if self.fd is None:
            raise ValueError('Directory capability is closed')
        return self.fd

    @contextmanager
    def open_directory(self, name):
        fd = os.open(_io_component(name), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=self._active())
        child = _IODirectory(fd)
        try:
            yield child
        finally:
            child.fd = None
            os.close(fd)

    def read_file(self, name, *, max_bytes):
        _io_limit(max_bytes)
        fd = os.open(_io_component(name), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=self._active())
        try:
            return _read_io_fd(fd, max_bytes)
        finally:
            os.close(fd)

    def directory_names(self, *, limit):
        _io_limit(limit)
        names = []
        with os.scandir(self._active()) as entries:
            for entry in entries:
                if len(names) == limit:
                    break
                names.append(entry.name if entry.is_dir(follow_symlinks=False) else None)
        return names


@contextmanager
def open_directory_nofollow(path):
    fd = _open_root(_io_path(path))
    directory = _IODirectory(fd)
    try:
        yield directory
    finally:
        directory.fd = None
        os.close(fd)


def _read_io_path(path, max_bytes, private):
    _io_limit(max_bytes)
    path = _io_path(path)
    with open_directory_nofollow(path.parent) as parent:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=parent.fd)
        try:
            return _read_io_fd(fd, max_bytes, private)
        finally:
            os.close(fd)


def read_private_file(path, *, max_bytes):
    return _read_io_path(path, max_bytes, True)


def read_file_nofollow(path, *, max_bytes):
    return _read_io_path(path, max_bytes, False)


def atomic_write_private_file(path, data):
    import secrets
    if not isinstance(data, bytes):
        raise TypeError('data must be bytes')
    path = _io_path(path)
    with open_directory_nofollow(path.parent) as parent:
        name = '.custodian-' + secrets.token_hex(16)
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent.fd)
        replaced = False
        try:
            os.fchmod(fd, 0o600)
            view = memoryview(data)
            while view:
                count = os.write(fd, view)
                if count <= 0:
                    raise OSError('Short write')
                view = view[count:]
            os.fsync(fd)
            os.replace(name, path.name, src_dir_fd=parent.fd, dst_dir_fd=parent.fd)
            replaced = True
            os.fsync(parent.fd)
        finally:
            os.close(fd)
            if not replaced:
                try:
                    os.unlink(name, dir_fd=parent.fd)
                except FileNotFoundError:
                    pass
