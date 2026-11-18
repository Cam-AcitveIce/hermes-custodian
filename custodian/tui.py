"""Optional, keyboard-first terminal interface. Monitoring never imports Textual."""
from __future__ import annotations
import json
import os
from pathlib import Path
from textual.app import App, ComposeResult
from textual.containers import Horizontal, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Checkbox, Footer, Header, Input, Label, SelectionList, Static, TextArea


class SetupScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Header()
        with VerticalScroll(id='setup-body'):
            yield Label('YOUR DEVICE. YOUR BOUNDARIES.', classes='eyebrow')
            yield Label('Set up Hermes Security Warden', classes='title')
            yield Static('Choose exactly what I may inspect. Monitoring is local, read-only, and uses no AI calls.', classes='muted')
            yield Label('1 / Find your Hermes profiles')
            yield Input(value=str(Path(os.environ.get('HERMES_HOME', Path.home() / '.hermes'))), placeholder='Hermes root directory', id='hermes-root')
            yield Static('', id='root-guidance', classes='muted')
            yield Button('Use shared Hermes root', id='use-shared-root', classes='hidden')
            yield Checkbox('Allow metadata discovery in this Hermes root (no memories or credentials)', id='consent')
            yield Button('Discover profiles', id='discover', disabled=True)
            yield SelectionList(id='profiles')
            yield Label('2 / Watch selected directories — one absolute path per line')
            yield Button('Browse folders', id='browse')
            yield TextArea('', id='watched', show_line_numbers=False)
            yield Label('Excluded directory names — comma separated')
            yield Input(value='.git,node_modules,.venv,__pycache__,sessions,memories', id='excluded')
            yield Label('3 / Reconciliation interval in seconds (minimum 10)')
            yield Input(value='60', id='interval', type='integer')
            yield Static('No service is installed here. Enable startup separately with custodian service install --enable.\nSoftware updates are report-only in this release. Credential files are metadata-only.', classes='muted')
            yield Checkbox('Approve monitoring only the selected profiles and paths', id='scope-consent')
            yield Button('Save scope & open control centre', variant='primary', id='save')
            yield Static('', id='setup-message', markup=False)
        yield Footer()

    def on_mount(self):
        try:
            saved = self.app.engine.settings()
        except (ValueError, RuntimeError, OSError):
            saved = {}
        if saved.get('watched_paths'):
            self.query_one('#watched', TextArea).text = '\n'.join(saved['watched_paths'])
        if saved.get('interval_seconds'):
            self.query_one('#interval', Input).value = str(saved['interval_seconds'])
        if saved.get('exclusions'):
            self.query_one('#excluded', Input).value = ','.join(saved['exclusions'])
        if saved.get('hermes_root'):
            self.query_one('#hermes-root', Input).value = saved['hermes_root']
        for path in saved.get('profiles', []):
            self.query_one('#profiles', SelectionList).add_option((Path(path).name, path, True))
        self._check_hermes_root(self.query_one('#hermes-root', Input).value)
        self.call_after_refresh(self._enable_change_listener)

    def _enable_change_listener(self):
        self._setup_ready = True

    def _check_hermes_root(self, root_str: str) -> None:
        try:
            p = Path(root_str).expanduser()
            is_profile = len(p.parts) >= 2 and p.parts[-2] == 'profiles'
        except Exception:
            is_profile = False

        try:
            guidance = self.query_one('#root-guidance', Static)
            btn = self.query_one('#use-shared-root', Button)
            if is_profile:
                shared = str(p.parent.parent)
                guidance.update(f"Selected root is an individual profile ('{p.name}'). Use the shared root '{shared}' to discover all profiles.")
                btn.display = True
            else:
                guidance.update("")
                btn.display = False
        except Exception:
            pass

    def on_input_changed(self, event: Input.Changed):
        if event.input.id == 'hermes-root':
            self._check_hermes_root(event.value)
            if getattr(self, '_setup_ready', False):
                self.query_one('#consent', Checkbox).value = False
                self.query_one('#discover', Button).disabled = True
                self.query_one('#profiles', SelectionList).clear_options()

    def on_checkbox_changed(self, event: Checkbox.Changed):
        if event.checkbox.id == 'consent':
            self.query_one('#discover', Button).disabled = not event.value

    def on_button_pressed(self, event: Button.Pressed):
        app = self.app
        message = self.query_one('#setup-message', Static)
        try:
            if event.button.id == 'use-shared-root':
                curr = Path(self.query_one('#hermes-root', Input).value).expanduser()
                if len(curr.parts) >= 2 and curr.parts[-2] == 'profiles':
                    self.query_one('#hermes-root', Input).value = str(curr.parent.parent)
            elif event.button.id == 'browse':
                from . import folder_picker as fp
                from .tui_folder_picker import FolderPickerScreen
                home_dir = getattr(app, 'browse_home', None) or Path.home()
                model = fp.PickerModel(
                    home_dir,
                    home=home_dir,
                    forbidden=[app.state_dir],
                    autoload=False,
                )
                def on_picker_closed(selected: list[str] | None):
                    if selected:
                        area = self.query_one('#watched', TextArea)
                        area.text = fp.merge_paths(
                            area.text,
                            selected,
                            case_insensitive=model.case_insensitive,
                        )
                        message.update(f"Added {len(selected)} folder(s). Nothing is monitored until you approve scope and save.")
                app.push_screen(FolderPickerScreen(model), on_picker_closed)
            if event.button.id == 'discover':
                if not self.query_one('#consent', Checkbox).value:
                    raise ValueError('Approve discovery first.')
                root = Path(self.query_one('#hermes-root', Input).value).expanduser()
                if not root.is_absolute():
                    raise ValueError('Use an absolute Hermes root path.')
                entries = app.engine.inventory(root)
                listing = self.query_one('#profiles', SelectionList)
                listing.clear_options()
                for profile in entries:
                    path = str(profile.get('path', profile.get('home', '')))
                    if path:
                        listing.add_option((str(profile.get('name', Path(path).name)), path, False))
                message.update(f'Found {len(entries)} profiles. Nothing is selected automatically.')
            elif event.button.id == 'save':
                if not self.query_one('#scope-consent', Checkbox).value:
                    raise ValueError('Approve the selected monitoring scope before saving.')
                profiles = list(self.query_one('#profiles', SelectionList).selected)
                watched = [line.strip() for line in self.query_one('#watched', TextArea).text.splitlines() if line.strip()]
                if not (profiles or watched):
                    raise ValueError('Select at least one profile or directory.')
                settings = {'schema_version': 1, 'profiles': profiles, 'watched_paths': watched,
                    'exclusions': [part.strip() for part in self.query_one('#excluded', Input).value.split(',') if part.strip()],
                    'interval_seconds': int(self.query_one('#interval', Input).value),
                    'max_files': 2000, 'max_file_bytes': 2 * 1024 * 1024, 'retention_days': 30}
                if self.query_one('#consent', Checkbox).value:
                    settings['hermes_root'] = self.query_one('#hermes-root', Input).value
                app.engine.setup(settings)
                app.switch_screen(ControlScreen())
        except (ValueError, RuntimeError, OSError) as exc:
            message.update(str(exc))


class ControlScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Header()
        with VerticalScroll(id='control-body'):
            yield Label('CUSTODIAN / LOCAL SECURITY', classes='eyebrow')
            yield Label('A quieter kind of protection.', classes='title')
            yield Static('', id='health', markup=False)
            with Horizontal(classes='actions'):
                yield Button('Scan approved scope', id='scan', variant='primary')
                yield Button('Refresh', id='refresh')
                yield Button('Edit scope', id='edit')
            yield Label('Findings & evidence')
            yield Static('', id='findings', markup=False)
            yield Label('Recent changes')
            yield Static('', id='changes', markup=False)
            yield Label('Your coverage')
            yield Static('', id='coverage', markup=False)
            yield Static('Web: run custodian dashboard in another terminal.\nStartup: custodian service install --enable (explicit opt-in).\nSame-user software cannot prevent an unrestricted same-user agent from tampering.', classes='muted')
        yield Footer()

    def on_mount(self):
        self.refresh_data()

    def refresh_data(self):
        try:
            status = self.app.engine.status()
            coverage_labels = {'not_scanned': 'not yet scanned', 'complete': 'checked within selected policy', 'degraded': 'incomplete — review scan errors', 'stale': 'out of date — scan again', 'scope_changed': 'scope changed — new baseline needed'}
            last = status.get('last_scan') or {}
            health = ('running' if status.get('monitoring') else 'not running — manual scans available')
            self.query_one('#health', Static).update(
                f"Monitor / {health}\nCoverage / {coverage_labels.get(status.get('coverage'), 'unknown')}\n"
                f"Last check / {last.get('finished_at', 'no completed scan')}\n"
                f"Open findings / {status.get('findings_open', 0)}\n"
                f"Service / {status.get('service_health', 'not inspected')}")
            findings = self.app.engine.findings()
            self.query_one('#findings', Static).update('\n\n'.join(f"{str(f.get('severity','info')).upper()} / {f.get('title','Finding')}\n{f.get('path','')}\nEvidence: {json.dumps(f.get('evidence',{}), ensure_ascii=True)}\nNext step: {f.get('recommendation','Review evidence')}" for f in findings) or 'No recorded findings. Check coverage and last successful scan before treating this as an all-clear.')
            events = self.app.engine.events(limit=15)
            self.query_one('#changes', Static).update('\n'.join(f"{e.get('timestamp','')}  {e.get('kind','change')}  {e.get('summary', e.get('path',''))}" for e in events) or 'No changes recorded yet.')
            settings = self.app.engine.settings()
            self.query_one('#coverage', Static).update(
                f"Profiles / {len(settings.get('profiles', []))} explicitly selected\n"
                f"Reconciliation / every {settings.get('interval_seconds', 60)} seconds while monitor runs\n"
                f"Directory scope /\n  " + '\n  '.join(settings.get('profiles', []) + settings.get('watched_paths', [])) +
                '\nExcluded names / ' + ', '.join(settings.get('exclusions', [])) +
                '\nIntegrity / admitted .py and .md content; other types metadata-only; sensitive directories not enumerated')
        except (ValueError, RuntimeError, OSError) as exc:
            self.query_one('#health', Static).update(f'Monitoring needs attention: {exc}')

    async def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == 'edit':
            self.app.switch_screen(SetupScreen())
        elif event.button.id == 'refresh':
            self.refresh_data()
        elif event.button.id == 'scan':
            self.run_worker(self.scan_scope(), exclusive=True)

    async def scan_scope(self):
        import asyncio
        button = self.query_one('#scan', Button)
        button.disabled = True
        self.query_one('#health', Static).update('Checking approved scope…')
        try:
            await asyncio.to_thread(self.app.engine.scan)
            self.refresh_data()
        except Exception as exc:
            self.query_one('#health', Static).update(f'Scan failed: {exc}')
        finally:
            button.disabled = False


class CustodianApp(App):
    TITLE = 'Hermes Security Warden'
    SUB_TITLE = 'Local. Scoped. Under your control.'
    BINDINGS = [('q', 'quit', 'Quit'), ('ctrl+c', 'quit', 'Quit')]
    CSS = '''
    Screen { background: #0b0e12; color: #d1d7df; }
    Header, Footer { background: #121820; }
    #setup-body, #control-body { padding: 1 3; max-width: 130; margin: 0 1; }
    Label { margin-top: 1; color: #c9d1dc; }
    .eyebrow { color: #73b5ae; text-style: bold; }
    .title { text-style: bold; color: #e6dfca; margin-bottom: 1; }
    .muted { color: #8994a4; margin: 1 0; }
    Input, TextArea, SelectionList { background: #121820; border: solid #29333f; margin: 1 0; }
    #profiles { height: 6; }
    #watched { height: 5; }
    Button { margin: 1 1 1 0; background: #19222d; border: solid #344352; }
    Button.-primary { background: #183b3a; color: #b1e0d7; }
    .actions { height: 5; }
    .hidden { display: none; }
    #health, #findings, #changes, #coverage { padding: 1 2; border-left: solid #31444b; background: #10161c; margin: 1 0; }
    #setup-message { color: #dbbb80; }
    '''

    def __init__(self, state_dir: Path, force_setup=False, engine=None, browse_home: Path | None = None):
        super().__init__()
        self.state_dir = state_dir
        self.force_setup = force_setup
        if engine is None:
            from .engine import Engine
            engine = Engine(state_dir)
        self.engine = engine
        self.browse_home = Path(browse_home) if browse_home is not None else Path.home()

    def on_mount(self):
        configured = False
        try:
            self.engine.settings()
            configured = True
        except (ValueError, RuntimeError, OSError):
            pass
        self.push_screen(SetupScreen() if self.force_setup or not configured else ControlScreen())
