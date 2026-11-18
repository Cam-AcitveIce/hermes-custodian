"""Folder picker driven through the real Textual widgets with Pilot. Synthetic fixtures only."""
import asyncio
from contextlib import contextmanager
import os
from pathlib import PureWindowsPath
import threading

import pytest

from custodian import folder_picker as fp


class Engine:
    """Records every engine call; anything beyond settings() would be a consent violation."""
    def __init__(self, saved=None):
        self.calls, self.saved = [], saved

    def settings(self):
        self.calls.append('settings')
        if self.saved is None:
            raise RuntimeError('not configured')
        return dict(self.saved)

    def setup(self, settings):
        self.calls.append('setup')
        return settings

    def inventory(self, root):
        self.calls.append('inventory')
        return []

    def scan(self):
        self.calls.append('scan')

    def status(self):
        self.calls.append('status')
        return {}

    def findings(self):
        self.calls.append('findings')
        return []

    def events(self, limit=15):
        self.calls.append('events')
        return []


def fixture(tmp_path, *names):
    home = tmp_path / 'home'
    home.mkdir()
    for name in names:
        (home / name).mkdir(parents=True)
    return home


def make_app(tmp_path, home, engine=None):
    from custodian.tui import CustodianApp
    return CustodianApp(tmp_path / 'state', force_setup=True, engine=engine or Engine(), browse_home=home)


async def settle(pilot):
    await pilot.pause()
    await pilot.app.workers.wait_for_complete()
    await pilot.pause()


async def open_picker(app, pilot):
    from textual.widgets import Button
    await pilot.pause()
    app.screen.query_one('#browse', Button).focus()
    await pilot.press('enter')
    await settle(pilot)


def labels(app):
    from textual.widgets import OptionList
    listing = app.screen.query_one('#picker-list', OptionList)
    return [listing.get_option_at_index(i).prompt.plain for i in range(listing.option_count)]


def text_of(app, selector):
    from textual.widgets import Static
    return str(app.screen.query_one(selector, Static).render())


def watched(app):
    from textual.widgets import TextArea
    return app.screen.query_one('#watched', TextArea)


def run(check):
    asyncio.run(check())


# ----------------------------------------------------------- open and close
def test_browse_button_opens_modal_listing_child_folders(tmp_path):
    from custodian.tui_folder_picker import FolderPickerScreen
    home = fixture(tmp_path, 'beta/inner', 'alpha')
    (home / 'file.txt').write_text('never read')

    async def check():
        app = make_app(tmp_path, home)
        async with app.run_test(size=(110, 40)) as pilot:
            await open_picker(app, pilot)
            assert isinstance(app.screen, FolderPickerScreen)
            assert str(home) in text_of(app, '#picker-path')
            assert labels(app) == ['[ ] alpha', '[ ] beta']
            assert 'not monitoring approval' in text_of(app, '#picker-note')
            assert 'Selected: 0' in text_of(app, '#picker-selected')
            # Windows lists drives above the home folder; POSIX has none.
            assert bool(app.screen.query('#picker-drives')) == (os.name == 'nt')
    run(check)


@pytest.mark.parametrize('how', ['escape', 'cancel'])
def test_cancel_and_escape_leave_the_form_unchanged(tmp_path, how):
    from custodian.tui import SetupScreen
    from textual.widgets import Button
    home = fixture(tmp_path, 'alpha')

    async def check():
        engine = Engine()
        app = make_app(tmp_path, home, engine)
        async with app.run_test(size=(110, 40)) as pilot:
            await pilot.pause()
            watched(app).text = '/opt/manual\n  typed draft'
            await open_picker(app, pilot)
            await pilot.press('space')
            assert 'Selected: 1' in text_of(app, '#picker-selected')
            if how == 'escape':
                await pilot.press('escape')
            else:
                app.screen.query_one('#picker-cancel', Button).focus()
                await pilot.press('enter')
            await settle(pilot)
            assert isinstance(app.screen, SetupScreen)
            assert watched(app).text == '/opt/manual\n  typed draft'
            assert engine.calls == ['settings', 'settings']
    run(check)


# --------------------------------------------------------------- navigation
def test_keyboard_navigation_enter_right_left_backspace(tmp_path):
    home = fixture(tmp_path, 'alpha/one', 'beta/two/three')

    async def check():
        app = make_app(tmp_path, home)
        async with app.run_test(size=(110, 40)) as pilot:
            await open_picker(app, pilot)
            await pilot.press('enter')
            await settle(pilot)
            assert text_of(app, '#picker-path').endswith(str(home / 'alpha'))
            assert labels(app) == ['[ ] one']
            await pilot.press('left')
            await settle(pilot)
            assert text_of(app, '#picker-path').endswith(str(home))
            await pilot.press('down', 'right')
            await settle(pilot)
            assert labels(app) == ['[ ] two']
            await pilot.press('right')
            await settle(pilot)
            assert labels(app) == ['[ ] three']
            await pilot.press('backspace')
            await settle(pilot)
            await pilot.press('backspace')
            await settle(pilot)
            assert text_of(app, '#picker-path').endswith(str(home))
            assert labels(app) == ['[ ] alpha', '[ ] beta']
    run(check)


def test_home_and_parent_buttons(tmp_path):
    from textual.widgets import Button
    home = fixture(tmp_path, 'alpha/one/two')

    async def check():
        app = make_app(tmp_path, home)
        async with app.run_test(size=(110, 40)) as pilot:
            await open_picker(app, pilot)
            await pilot.press('enter')
            await settle(pilot)
            await pilot.press('enter')
            await settle(pilot)
            assert labels(app) == ['[ ] two']
            app.screen.query_one('#picker-parent', Button).focus()
            await pilot.press('enter')
            await settle(pilot)
            assert text_of(app, '#picker-path').endswith(str(home / 'alpha'))
            app.screen.query_one('#picker-home', Button).focus()
            await pilot.press('enter')
            await settle(pilot)
            assert text_of(app, '#picker-path').endswith(str(home))
    run(check)


def test_folder_names_are_read_off_the_ui_thread(tmp_path, monkeypatch):
    from custodian import _platform
    home = fixture(tmp_path, 'alpha')
    real, threads = _platform.open_directory_nofollow, []

    @contextmanager
    def recording(path):
        threads.append(threading.current_thread())
        with real(path) as directory:
            yield directory
    monkeypatch.setattr(_platform, 'open_directory_nofollow', recording)

    async def check():
        app = make_app(tmp_path, home)
        async with app.run_test(size=(110, 40)) as pilot:
            await open_picker(app, pilot)
            await pilot.press('enter')
            await settle(pilot)
    run(check)
    assert len(threads) == 2 and threading.main_thread() not in threads


# -------------------------------------------------- selection and adding
def test_multi_select_survives_navigation_and_add_merges_into_form(tmp_path):
    from custodian.tui import SetupScreen
    from textual.widgets import Button, Checkbox
    home = fixture(tmp_path, 'alpha', 'beta/inner')

    async def check():
        engine = Engine()
        app = make_app(tmp_path, home, engine)
        async with app.run_test(size=(110, 40)) as pilot:
            await pilot.pause()
            manual = f'/opt/manual\n{home / "alpha"}\n  draft line'
            watched(app).text = manual
            await open_picker(app, pilot)
            await pilot.press('space')                 # alpha (already typed manually)
            await pilot.press('down', 'enter')         # into beta
            await settle(pilot)
            await pilot.press('space')                 # beta/inner
            await pilot.press('left')
            await settle(pilot)
            assert labels(app) == ['[x] alpha', '[ ] beta']
            selected = text_of(app, '#picker-selected')
            assert 'Selected: 2' in selected
            assert str(home / 'alpha') in selected and str(home / 'beta' / 'inner') in selected
            app.screen.query_one('#picker-add', Button).focus()
            await pilot.press('enter')
            await settle(pilot)
            assert isinstance(app.screen, SetupScreen)
            assert watched(app).text == manual + f'\n{home / "beta" / "inner"}'
            # Adding is not approval: no consent granted, nothing saved, scanned or discovered.
            assert not app.screen.query_one('#scope-consent', Checkbox).value
            assert not app.screen.query_one('#consent', Checkbox).value
            assert app.screen.query_one('#discover', Button).disabled
            assert engine.calls == ['settings', 'settings']
            assert 'Nothing is monitored' in text_of(app, '#setup-message')
            assert not (tmp_path / 'state').exists()
    run(check)


def test_space_toggles_off_and_add_with_nothing_selected_stays_open(tmp_path):
    from custodian.tui_folder_picker import FolderPickerScreen
    from textual.widgets import Button
    home = fixture(tmp_path, 'alpha')

    async def check():
        app = make_app(tmp_path, home)
        async with app.run_test(size=(110, 40)) as pilot:
            await open_picker(app, pilot)
            await pilot.press('space')
            assert labels(app) == ['[x] alpha']
            await pilot.press('space')
            assert labels(app) == ['[ ] alpha']
            app.screen.query_one('#picker-add', Button).focus()
            await pilot.press('enter')
            await settle(pilot)
            assert isinstance(app.screen, FolderPickerScreen)
            assert 'Nothing selected' in text_of(app, '#picker-status')
    run(check)


def test_select_current_adds_the_open_folder_and_refuses_home(tmp_path):
    from textual.widgets import Button
    home = fixture(tmp_path, 'alpha/one')

    async def check():
        app = make_app(tmp_path, home)
        async with app.run_test(size=(110, 40)) as pilot:
            await open_picker(app, pilot)
            current = app.screen.query_one('#picker-select-current', Button)
            current.focus()
            await pilot.press('enter')
            await settle(pilot)
            assert text_of(app, '#picker-status') == fp.TOO_BROAD
            assert 'Selected: 0' in text_of(app, '#picker-selected')
            app.screen.query_one('#picker-list').focus()
            await pilot.press('enter')
            await settle(pilot)
            assert str(home / 'alpha') in text_of(app, '#picker-path')
            current.focus()
            await pilot.press('enter')
            await settle(pilot)
            assert 'Selected: 1' in text_of(app, '#picker-selected')
            app.screen.query_one('#picker-add', Button).focus()
            await pilot.press('enter')
            await settle(pilot)
            assert watched(app).text == str(home / 'alpha')
    run(check)


def test_saved_settings_are_kept_and_engine_untouched_by_adding(tmp_path):
    from textual.widgets import Button
    home = fixture(tmp_path, 'alpha')

    async def check():
        engine = Engine({'watched_paths': ['/opt/example'], 'profiles': [], 'exclusions': ['.git'],
                         'interval_seconds': 90})
        app = make_app(tmp_path, home, engine)
        async with app.run_test(size=(110, 40)) as pilot:
            await open_picker(app, pilot)
            await pilot.press('space')
            app.screen.query_one('#picker-add', Button).focus()
            await pilot.press('enter')
            await settle(pilot)
            assert watched(app).text == f'/opt/example\n{home / "alpha"}'
            assert engine.saved['watched_paths'] == ['/opt/example']
            assert set(engine.calls) == {'settings'}
    run(check)


# ------------------------------------------------------- refusal and safety
def test_private_agent_data_is_shown_disabled_and_never_opened(tmp_path, monkeypatch):
    from custodian import _platform
    from textual.widgets import OptionList
    home = fixture(tmp_path, 'sessions/chat-1', 'memories', 'work')
    real, opened = _platform.open_directory_nofollow, []

    @contextmanager
    def recording(path):
        opened.append(str(path))
        with real(path) as directory:
            yield directory
    monkeypatch.setattr(_platform, 'open_directory_nofollow', recording)

    async def check():
        app = make_app(tmp_path, home)
        async with app.run_test(size=(110, 40)) as pilot:
            await open_picker(app, pilot)
            rows = labels(app)
            assert rows[0].startswith('[-] memories') and 'private agent data' in rows[0]
            assert rows[1].startswith('[-] sessions') and rows[2] == '[ ] work'
            listing = app.screen.query_one('#picker-list', OptionList)
            assert listing.get_option_at_index(0).disabled and listing.get_option_at_index(1).disabled
            assert listing.highlighted == 2
            await pilot.press('up', 'up', 'space', 'enter')
            await settle(pilot)
            assert text_of(app, '#picker-path').endswith(str(home))
            assert 'chat-1' not in ' '.join(labels(app))
            assert 'private agent data' in text_of(app, '#picker-status')
    run(check)
    assert opened and all('sessions' not in path and 'memories' not in path for path in opened)


@pytest.mark.skipif(os.name == 'nt', reason='native POSIX symlinks')
def test_symlinked_folders_are_not_offered(tmp_path):
    home = fixture(tmp_path, 'real')
    outside = tmp_path / 'outside'
    (outside / 'inner').mkdir(parents=True)
    (home / 'link').symlink_to(outside, target_is_directory=True)

    async def check():
        app = make_app(tmp_path, home)
        async with app.run_test(size=(110, 40)) as pilot:
            await open_picker(app, pilot)
            assert labels(app) == ['[ ] real']
            status = text_of(app, '#picker-status')
            assert '1 other entry' in status and 'never opened or followed' in status
    run(check)


def test_folder_deleted_before_opening_reports_and_stays(tmp_path):
    home = fixture(tmp_path, 'alpha')

    async def check():
        app = make_app(tmp_path, home)
        async with app.run_test(size=(110, 40)) as pilot:
            await open_picker(app, pilot)
            (home / 'alpha').rmdir()
            await pilot.press('enter')
            await settle(pilot)
            assert text_of(app, '#picker-path').endswith(str(home))
            assert text_of(app, '#picker-status') == fp.UNAVAILABLE
    run(check)


def test_unicode_and_bracket_names_render_and_add_verbatim(tmp_path):
    from textual.widgets import Button
    names = ['[bold red]x', '[link=x]y', 'déjà [vu]', '日本語']
    home = fixture(tmp_path, *names)

    async def check():
        app = make_app(tmp_path, home)
        async with app.run_test(size=(110, 40)) as pilot:
            await open_picker(app, pilot)
            assert labels(app) == [f'[ ] {name}' for name in sorted(names, key=str.casefold)]
            for _ in names:
                await pilot.press('space', 'down')
            selected = text_of(app, '#picker-selected')
            assert all(name in selected for name in names)
            app.screen.query_one('#picker-add', Button).focus()
            await pilot.press('enter')
            await settle(pilot)
            assert watched(app).text.splitlines() == [str(home / name) for name in sorted(names, key=str.casefold)]
    run(check)


def test_truncated_listing_says_so(tmp_path):
    from custodian.tui_folder_picker import FolderPickerScreen
    home = fixture(tmp_path, *[f'd{i:02d}' for i in range(9)])

    async def check():
        app = make_app(tmp_path, home)
        async with app.run_test(size=(110, 40)) as pilot:
            await pilot.pause()
            model = fp.PickerModel(home, home=home, limit=4, autoload=False)
            app.push_screen(FolderPickerScreen(model))
            await settle(pilot)
            assert len(labels(app)) == 4
            assert 'first 4' in text_of(app, '#picker-status')
    run(check)


# ------------------------------------------------------------------ Windows
class FakeWindows:
    IS_WINDOWS = True

    def __init__(self, nodes):
        self.nodes = nodes

    @contextmanager
    def open_directory_nofollow(self, path):
        key = str(path).casefold()
        if key not in self.nodes:
            raise FileNotFoundError(str(path))
        names = self.nodes[key]

        class Directory:
            def directory_names(self, *, limit):
                return names[:limit]
        yield Directory()


def test_windows_drive_choice_and_backslash_paths_through_the_widget(tmp_path):
    from custodian.tui_folder_picker import FolderPickerScreen
    from textual.widgets import Button
    home = fixture(tmp_path)
    platform = FakeWindows({'c:\\': ['Users'], 'c:\\users': ['me'], 'c:\\users\\me': ['Projects'],
                            'd:\\': ['Work', 'work-2'], 'd:\\work': []})

    async def check():
        app = make_app(tmp_path, home)
        results = []
        async with app.run_test(size=(110, 40)) as pilot:
            await pilot.pause()
            model = fp.PickerModel(PureWindowsPath('C:\\Users\\me'), home=PureWindowsPath('C:\\Users\\me'),
                                   platform=platform, drives=lambda: ['C:\\', 'D:\\'], autoload=False)
            app.push_screen(FolderPickerScreen(model), results.append)
            await settle(pilot)
            assert text_of(app, '#picker-path').endswith('C:\\Users\\me')
            assert labels(app) == ['[ ] Projects']
            app.screen.query_one('#picker-drives', Button).focus()
            await pilot.press('enter')
            await settle(pilot)
            assert labels(app) == ['    C:\\', '    D:\\']
            assert 'drive' in text_of(app, '#picker-path').lower()
            await pilot.press('space')
            assert text_of(app, '#picker-status') == fp.TOO_BROAD
            await pilot.press('down', 'enter')
            await settle(pilot)
            assert labels(app) == ['[ ] Work', '[ ] work-2']
            await pilot.press('space')
            await pilot.press('backspace')              # drive root -> drive list
            await settle(pilot)
            assert labels(app) == ['    C:\\', '    D:\\']
            app.screen.query_one('#picker-add', Button).focus()
            await pilot.press('enter')
            await settle(pilot)
        assert results == [['D:\\Work']]
    run(check)
