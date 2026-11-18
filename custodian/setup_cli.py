"""Numbered, plain-terminal setup. No Textual, automatic scans or service changes."""
from __future__ import annotations
import os
from pathlib import Path
from .folder_picker import PickerModel, merge_paths
from .selection_prompt import select as _select


def _interactive():
    import sys
    return sys.stdin.isatty() and sys.stdout.isatty()


def _confirm(question):
    if _interactive():
        return _select(question, [('no', 'Go back — do not approve'), ('yes', 'Yes, approve')]) == 'yes'
    return input(question + ' [y/N] ').strip().lower() in ('y', 'yes')


def _say(value=''):
    # Filenames and discovery metadata are untrusted terminal text.
    print(''.join(c if c in '\n\t' or (ord(c) >= 32 and not 127 <= ord(c) < 160) else '?' for c in str(value)))


def _choose_profiles(engine, current_root):
    candidate = Path(current_root)
    if candidate.parent.name == 'profiles':
        _say(f'Your active profile is {candidate.name}. To find sibling profiles, the suggested root is {candidate.parent.parent}.')
        current_root = str(candidate.parent.parent)
    _say('\nFind Hermes profiles\nPress Enter to use the suggested location, or type a different Hermes root.')
    raw = input(f'Hermes folder [{current_root}] (q cancels): ').strip()
    if raw.lower() == 'q':
        return None
    root = Path(raw or current_root).expanduser()
    if not root.is_absolute() or '..' in root.parts:
        _say('Use an absolute Hermes root without .. traversal.')
        return None
    _say(f'Discovery root: {root}')
    if root.parent.name == 'profiles':
        _say(f'This is one named profile. Shared profiles are under {root.parent.parent}; no root is changed automatically.')
    _say('Discovery reads allowlisted config metadata in this root and its profiles. It does not select or scan them.')
    if not _confirm('Allow metadata discovery in exactly this root?'):
        _say('Discovery skipped. Existing selection unchanged.')
        return None
    try:
        entries = engine.inventory(root)
    except (ValueError, OSError, RuntimeError) as exc:
        _say(f'Discovery unavailable: {exc}')
        return None
    if not entries:
        _say('No Hermes profiles found here. Try the shared Hermes folder or choose project folders instead.')
        return None
    if _interactive():
        for entry in entries:
            for error in entry.get('errors', []):
                _say(f"{entry.get('name', 'Profile')}: {error}")
        paths = _select('Choose profiles to monitor',
                        [(str(e['path']), f"{e.get('name', 'profile')} — {e['path']}") for e in entries],
                        multiple=True)
        return None if paths is None else (str(root), paths)
    for i, entry in enumerate(entries, 1):
        _say(f"  {i}. {entry.get('name', 'profile')}  {entry.get('path', '')}")
        for error in entry.get('errors', []):
            _say(f'     Note: {error}')
    while True:
        choice = input('Select profile numbers, separated by commas (blank keeps existing; q cancels): ').strip()
        if not choice or choice.lower() == 'q':
            return None
        try:
            indices = list(dict.fromkeys(int(n.strip()) - 1 for n in choice.split(',')))
            if any(i < 0 or i >= len(entries) for i in indices):
                raise ValueError
            paths = [str(entries[i]['path']) for i in indices]
            return str(root), paths
        except (ValueError, KeyError):
            _say('Choose only numbers shown above.')


def _browse_keys(model):
    model.refresh()
    while True:
        entries = model.listing.entries
        available = {entry.path for entry in entries if not entry.blocked}
        def toggle(value):
            target = model.current if value == 's' else value
            if value not in available and value != 's':
                return False, 'Press Enter to use this action.'
            if not target or not model.toggle(target):
                return False, model.status
            return model.is_selected(target), f'{len(model.selected)} folders selected'
        options = [('d', 'Use selected folders and return to setup'),
                   ('s', 'Select this folder'), ('..', 'Go up one folder')]
        options += [(e.path, e.name + (' — unavailable' if e.blocked else '/')) for e in entries]
        options += [('p', 'Enter a different folder path'), ('h', 'Go to home folder'), ('q', 'Cancel browsing')]
        selected = list(model.selected)
        if model.current and model.is_selected(model.current):
            selected.append('s')
        choice = _select(f'Choose folders — {model.current or "Drives"}', options,
                         selected=selected, on_toggle=toggle, checkable=available | {'s'})
        if choice is None or choice == 'q':
            return None
        if choice == 'd':
            return list(model.selected)
        if choice == 's':
            toggle(choice)
        elif choice == '..':
            model.parent()
        elif choice == 'h':
            model.go_home()
        elif choice == 'p':
            raw = input('Folder path (blank goes back): ').strip()
            if raw:
                model.open(str(Path(raw).expanduser()))
        elif choice in available:
            model.open(choice)
        else:
            model.status = 'This folder is unavailable.'
        if model.status:
            _say(model.status)


def _browse(model):
    if _interactive():
        return _browse_keys(model)
    if not model.refresh():
        _say(model.status)
    while True:
        _say(f'\nFolder: {model.current or "Drives"}')
        entries = model.listing.entries
        for i, entry in enumerate(entries, 1):
            mark = 'x' if model.is_selected(entry.path) else ' '
            _say(f'  {i}. [{mark}] {entry.name}' + (' (private; unavailable)' if entry.blocked else ''))
        if model.listing.truncated:
            _say('Listing truncated; use an explicit path for folders beyond this listing.')
        _say(f'Selected: {len(model.selected)}')
        _say('\nType a folder number to open it. Then choose “select” to add that folder.\n  select  Add the folder shown above\n  back    Go up one folder\n  home    Return to your home folder\n  path    Open a folder by its full path\n  finish  Return to setup with your choices\n  cancel  Discard this browsing session')
        raw_choice = input('\nFolder number or action: ').strip().lower()
        choice = {'select': 's', 'back': '..', 'home': 'h', 'path': 'p', 'finish': 'd', 'cancel': 'q'}.get(raw_choice, raw_choice)
        if choice.lower() == 'q':
            return None
        if choice.lower() == 'd':
            return list(model.selected)
        if choice.lower() == 's':
            if not model.select_current():
                _say(model.status)
        elif choice == '..':
            if not model.parent():
                _say(model.status)
        elif choice.lower() == 'h':
            if not model.go_home():
                _say(model.status)
        elif choice.lower() == 'p':
            target = input('Absolute folder path (q cancels): ').strip()
            if target.lower() != 'q' and not model.open(str(Path(target).expanduser())):
                _say(model.status)
        elif choice.isdigit() and 1 <= int(choice) <= len(entries):
            entry = entries[int(choice) - 1]
            if entry.blocked:
                _say(entry.blocked)
            elif not model.open(entry.path):
                _say(model.status)
        else:
            _say('Choose a listed number or one of the commands above.')


def run_setup(engine, *, home=None):
    """Persist scope only after final confirmation. EOF/Ctrl+C leave settings alone."""
    home = Path(home) if home is not None else Path.home()
    try:
        saved = engine.settings()
    except (ValueError, OSError, RuntimeError):
        saved = {}
    # Copy mutable lists: cancelling must not mutate a store-owned object.
    profiles = list(saved.get('profiles', []))
    watched = list(saved.get('watched_paths', []))
    root = saved.get('hermes_root') or os.environ.get('HERMES_HOME') or str(home / '.hermes')
    discovery_approved = bool(saved.get('hermes_root'))
    _say('\nHermes Security Warden — setup')
    _say('Choose profiles and folders. No scans, services or updates are started here.')
    try:
        while True:
            _say(f'\nSelected: {len(profiles)} profiles, {len(watched)} folders')
            for path in profiles:
                _say(f'  Profile: {path}')
            for path in watched:
                _say(f'  Folder:  {path}')
            if _interactive():
                choice = _select('What would you like to monitor?', [
                    ('p', 'Choose Hermes profiles'), ('b', 'Choose project folders'),
                    ('a', 'Enter a folder path'), ('r', 'Remove a selection'),
                    ('done', 'Review and save'), ('q', 'Cancel setup')])
                choice = choice or 'q'
            else:
                _say('\n  1. Find and choose Hermes profiles\n  2. Browse and choose project folders\n  3. Add a folder by typing its path\n  4. Remove a selected profile or folder\n  5. Review and save\n  0. Cancel — keep existing settings')
                raw_choice = input('\nChoose an option [1]: ').strip().lower()
                choice = {'1': 'p', '2': 'b', '3': 'a', '4': 'r', '5': 'done', '0': 'q', '': 'p'}.get(raw_choice, raw_choice)
            if choice == 'q':
                _say('Cancelled. Nothing saved.')
                return False
            if choice == 'p':
                result = _choose_profiles(engine, root)
                if result is not None:
                    root, profiles = result
                    discovery_approved = True
            elif choice in ('a', 'b'):
                model = PickerModel(home=home, start=home, forbidden=[getattr(getattr(engine, 'store', None), 'root', home / '.warden-state')], autoload=False)
                if choice == 'b':
                    selected = _browse(model)
                else:
                    path = input('Absolute folder to watch (q cancels): ').strip()
                    if path.lower() == 'q':
                        continue
                    target = str(Path(path).expanduser())
                    if not model.open(target):
                        _say(model.status)
                        continue
                    selected = [target] if model.select_current() else []
                    if not selected:
                        _say(model.status)
                if selected:
                    watched = merge_paths('\n'.join(watched), selected, case_insensitive=model.case_insensitive).splitlines()
            elif choice == 'r':
                combined = [('profile', p) for p in profiles] + [('folder', p) for p in watched]
                if _interactive():
                    raw = _select('Remove a selection', [(str(i), f'{kind}: {path}') for i, (kind, path) in enumerate(combined, 1)]) or ''
                else:
                    for i, (kind, path) in enumerate(combined, 1):
                        _say(f'  {i}. {kind}: {path}')
                    raw = input('Remove number (blank cancels): ').strip()
                if raw.isdigit() and 1 <= int(raw) <= len(combined):
                    kind, path = combined[int(raw) - 1]
                    (profiles if kind == 'profile' else watched).remove(path)
            elif choice == 'done':
                if profiles or watched:
                    break
                _say('Select at least one profile or folder.')
            else:
                _say('Choose p, b, a, r, done or q.')
        while True:
            default = saved.get('interval_seconds', 60)
            raw = input(f'Check every how many seconds? [{default}] ').strip()
            try:
                interval = int(raw or default)
                if interval < 10:
                    raise ValueError
                break
            except ValueError:
                _say('Enter a whole number of at least 10 seconds.')
        _say('\n  REVIEW MONITORING SCOPE\n')
        if profiles:
            _say('  Hermes profiles')
            for path in profiles:
                name = 'Default' if str(path) == str(root) else Path(path).name
                _say(f'    {name}\n      {path}')
        if watched:
            _say('\n  Project folders')
            for path in watched:
                _say(f'    {path}')
        from .engine import RECOMMENDED_EXCLUSIONS
        _say(f'\n  File budget: {saved.get("max_files", 10000)} entries per scan')
        _say('  Exclusions: ' + ', '.join(saved.get('exclusions', RECOMMENDED_EXCLUSIONS)))
        _say(f'\n  Check interval: {interval} seconds while the monitor runs.')
        _say('  Saving does not start a scan or install a startup service.\n  Content reads remain limited by scan policy.\n')
        if not _confirm('Approve and save exactly this scope?'):
            _say('Cancelled. Nothing saved.')
            return False
        settings = dict(saved)
        settings.update(profiles=profiles, watched_paths=watched, interval_seconds=interval)
        if discovery_approved:
            settings['hermes_root'] = str(root)
        engine.setup(settings)
        _say('Scope saved. Run custodian scan, custodian monitor, or custodian dashboard when ready.')
        return True
    except (EOFError, KeyboardInterrupt):
        _say('\nCancelled. Nothing saved.')
        return False
