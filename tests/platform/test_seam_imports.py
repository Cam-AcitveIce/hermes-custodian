import ast
import importlib
from pathlib import Path
import sys
import pytest

CONTRACT_FUNCTIONS = [
    'current_principal',
    'owner_of',
    'ensure_private_dir',
    'ensure_private_file',
    'open_private_file',
    'validate_state_root',
    'fsync_directory',
    'interprocess_lock',
    'try_lock_exclusive',
    'unlock',
    'process_is_running_as_current_user',
    'terminate_signals',
    'default_state_dir',
    'bounded_snapshot',
    'access_exposure',
]


def test_windows_simulation_with_backend_imports_cleanly(monkeypatch):
    """Prove import custodian and import custodian._platform succeed with windows backend and do not import fcntl/grp/pwd."""
    orig_modules = dict(sys.modules)
    try:
        for mod in list(sys.modules):
            if mod.startswith('custodian'):
                del sys.modules[mod]

        monkeypatch.setattr(sys, 'platform', 'win32')
        # Posix module blocked, windows backend allowed
        monkeypatch.setitem(sys.modules, 'custodian._platform.posix', None)
        monkeypatch.setitem(sys.modules, 'fcntl', None)
        monkeypatch.setitem(sys.modules, 'grp', None)
        monkeypatch.setitem(sys.modules, 'pwd', None)

        import custodian
        import custodian._platform

        assert custodian._platform.NAME == 'windows'
        assert custodian._platform.IS_WINDOWS is True
        assert custodian._platform.BACKEND_READY is True

        for fn in CONTRACT_FUNCTIONS:
            assert hasattr(custodian._platform, fn), f'Missing {fn} in custodian._platform'

        assert sys.modules.get('fcntl') is None or 'fcntl' not in sys.modules
        assert sys.modules.get('grp') is None or 'grp' not in sys.modules
        assert sys.modules.get('pwd') is None or 'pwd' not in sys.modules
    finally:
        sys.modules.clear()
        sys.modules.update(orig_modules)


def test_windows_simulation_missing_backend_fallback(monkeypatch):
    """Prove when windows backend is missing, fallback re-exports None and BACKEND_READY is False without posix imports."""
    orig_modules = dict(sys.modules)
    try:
        for mod in list(sys.modules):
            if mod.startswith('custodian'):
                del sys.modules[mod]

        monkeypatch.setattr(sys, 'platform', 'win32')
        # Both posix and windows backend explicitly blocked
        monkeypatch.setitem(sys.modules, 'custodian._platform.windows', None)
        monkeypatch.setitem(sys.modules, 'custodian._platform.posix', None)
        monkeypatch.setitem(sys.modules, 'fcntl', None)
        monkeypatch.setitem(sys.modules, 'grp', None)
        monkeypatch.setitem(sys.modules, 'pwd', None)

        import custodian
        import custodian._platform

        assert custodian._platform.NAME == 'windows'
        assert custodian._platform.IS_WINDOWS is True
        assert custodian._platform.BACKEND_READY is False

        for fn in CONTRACT_FUNCTIONS:
            assert hasattr(custodian._platform, fn), f'Missing {fn} in custodian._platform'
    finally:
        sys.modules.clear()
        sys.modules.update(orig_modules)


def test_windows_simulation_does_not_import_posix_modules(monkeypatch):
    """Backward-compatible alias verifying windows backend imports without posix modules."""
    test_windows_simulation_with_backend_imports_cleanly(monkeypatch)


def test_ast_no_module_level_posix_imports():
    """Prove no module in custodian/ EXCEPT custodian/_platform/posix.py and updates.py imports fcntl, grp, pwd at module level."""
    root = Path(__file__).resolve().parents[2] / 'custodian'
    forbidden = {'fcntl', 'grp', 'pwd'}

    for path in root.rglob('*.py'):
        rel = path.relative_to(root).as_posix()
        # Allowed exceptions
        if rel in ('_platform/posix.py', 'updates.py'):
            continue

        tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
        for node in tree.body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.name.split('.')[0]
                    assert name not in forbidden, f"{rel} imports {name} at module level"
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    name = node.module.split('.')[0]
                    assert name not in forbidden, f"{rel} imports {name} at module level"
            elif isinstance(node, ast.Try):
                # Check imports inside top-level try blocks
                for sub in node.body + [s for handler in node.handlers for s in handler.body] + node.orelse + node.finalbody:
                    if isinstance(sub, ast.Import):
                        for alias in sub.names:
                            name = alias.name.split('.')[0]
                            assert name not in forbidden, f"{rel} imports {name} inside top-level try"
                    elif isinstance(sub, ast.ImportFrom):
                        if sub.module:
                            name = sub.module.split('.')[0]
                            assert name not in forbidden, f"{rel} imports {name} inside top-level try"
