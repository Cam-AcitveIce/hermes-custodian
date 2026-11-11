"""Platform seam. Backends are selected by operating system; see .hermes/briefs/platform-contract.md."""
import sys

if sys.platform == 'win32':
    NAME = 'windows'
elif sys.platform == 'darwin':
    NAME = 'macos'
else:
    NAME = 'linux'

IS_WINDOWS = NAME == 'windows'

if IS_WINDOWS:
    try:
        from . import windows as _backend
        BACKEND_READY = True
    except ImportError:
        _backend = None
        BACKEND_READY = False
else:
    from . import posix as _backend
    BACKEND_READY = True

if _backend is not None:
    current_principal = _backend.current_principal
    owner_of = _backend.owner_of
    ensure_private_dir = _backend.ensure_private_dir
    ensure_private_file = _backend.ensure_private_file
    open_private_file = _backend.open_private_file
    validate_state_root = _backend.validate_state_root
    fsync_directory = _backend.fsync_directory
    interprocess_lock = _backend.interprocess_lock
    try_lock_exclusive = _backend.try_lock_exclusive
    unlock = _backend.unlock
    process_is_running_as_current_user = _backend.process_is_running_as_current_user
    terminate_signals = _backend.terminate_signals
    default_state_dir = _backend.default_state_dir
    bounded_snapshot = _backend.bounded_snapshot
    access_exposure = _backend.access_exposure
else:
    current_principal = None
    owner_of = None
    ensure_private_dir = None
    ensure_private_file = None
    open_private_file = None
    validate_state_root = None
    fsync_directory = None
    interprocess_lock = None
    try_lock_exclusive = None
    unlock = None
    process_is_running_as_current_user = None
    terminate_signals = None
    default_state_dir = None
    bounded_snapshot = None
    access_exposure = None

for _name in ("read_private_file", "atomic_write_private_file", "read_file_nofollow", "open_directory_nofollow"):
    globals()[_name] = getattr(_backend, _name, None)
