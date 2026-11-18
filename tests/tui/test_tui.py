import asyncio
from pathlib import Path


def test_edit_scope_preserves_saved_paths_without_regranting_consent(tmp_path):
    from custodian.tui import CustodianApp
    from textual.widgets import TextArea, Checkbox, Input
    class Engine:
        def settings(self):
            return {'watched_paths': ['/opt/example'], 'profiles': [], 'exclusions': ['.git'], 'interval_seconds': 90}
    async def check():
        app = CustodianApp(tmp_path, force_setup=True, engine=Engine())
        async with app.run_test(size=(110, 38)):
            assert app.screen.query_one('#watched', TextArea).text == '/opt/example'
            assert app.screen.query_one('#interval', Input).value == '90'
            assert not app.screen.query_one('#scope-consent', Checkbox).value
    asyncio.run(check())


def test_control_centre_uses_human_readable_health(tmp_path):
    from custodian.tui import CustodianApp
    from textual.widgets import Static
    class Engine:
        def settings(self): return {'profiles': [], 'watched_paths': ['/opt/example'], 'interval_seconds': 60}
        def status(self): return {'configured': True, 'monitoring': False, 'coverage': 'not_scanned', 'last_scan': None, 'findings_open': 0}
        def findings(self): return []
        def events(self, limit=15): return []
    async def check():
        app = CustodianApp(tmp_path, engine=Engine())
        async with app.run_test(size=(110, 38)):
            health = str(app.screen.query_one('#health', Static).render())
            assert 'Coverage /' in health
            assert 'not yet scanned' in health
            assert '"configured"' not in health
    asyncio.run(check())


def test_setup_requires_explicit_discovery_consent(tmp_path):
    from custodian.tui import CustodianApp
    from textual.widgets import Button, Checkbox
    class Engine:
        def settings(self):
            raise RuntimeError('not configured')
    async def check():
        app = CustodianApp(tmp_path, engine=Engine())
        async with app.run_test(size=(110, 38)) as pilot:
            assert app.screen.query_one('#discover', Button).disabled
            app.screen.query_one('#consent', Checkbox).value = True
            await pilot.pause()
            assert not app.screen.query_one('#discover', Button).disabled
    asyncio.run(check())


def test_named_profile_root_shows_guidance_and_shared_root_action(tmp_path):
    from custodian.tui import CustodianApp
    from textual.widgets import Button, Input, Static
    shared = str(Path('/synthetic/hermes'))  # native separators, as the TUI shows them
    class Engine:
        def settings(self):
            raise RuntimeError('not configured')
    async def check():
        app = CustodianApp(tmp_path, engine=Engine())
        async with app.run_test(size=(110, 38)) as pilot:
            await pilot.pause()
            root_input = app.screen.query_one('#hermes-root', Input)
            root_input.value = '/synthetic/hermes/profiles/argo'
            await pilot.pause()
            guidance = str(app.screen.query_one('#root-guidance', Static).render())
            assert 'individual profile' in guidance
            assert shared in guidance
            btn = app.screen.query_one('#use-shared-root', Button)
            assert btn.display
            btn.focus()
            await pilot.press('enter')
            await pilot.pause()
            assert root_input.value == shared
            assert not btn.display
    asyncio.run(check())


def test_changing_root_resets_consent_and_clears_inventory_options(tmp_path):
    from custodian.tui import CustodianApp
    from textual.widgets import Button, Checkbox, Input, SelectionList
    class Engine:
        def settings(self):
            raise RuntimeError('not configured')
        def inventory(self, root):
            return [{'name': 'p1', 'path': str(root / 'profiles' / 'p1')}]
    async def check():
        app = CustodianApp(tmp_path, engine=Engine())
        async with app.run_test(size=(110, 38)) as pilot:
            await pilot.pause()
            root_input = app.screen.query_one('#hermes-root', Input)
            root_input.value = str(tmp_path / 'hermes')
            await pilot.pause()
            consent = app.screen.query_one('#consent', Checkbox)
            consent.value = True
            await pilot.pause()
            discover = app.screen.query_one('#discover', Button)
            assert not discover.disabled
            discover.focus()
            await pilot.press('enter')
            await pilot.pause()
            profiles = app.screen.query_one('#profiles', SelectionList)
            assert profiles.option_count == 1
            # Changing root resets discovery consent and clears inventory options
            root_input.value = str(tmp_path / 'other_hermes')
            await pilot.pause()
            assert not consent.value
            assert discover.disabled
            assert profiles.option_count == 0
    asyncio.run(check())


def test_saved_selected_profiles_preserved_on_setup_open(tmp_path):
    from custodian.tui import CustodianApp
    from textual.widgets import SelectionList
    class Engine:
        def settings(self):
            return {
                'hermes_root': str(tmp_path / 'hermes'),
                'profiles': [str(tmp_path / 'hermes' / 'profiles' / 'ivy')],
                'watched_paths': [],
                'exclusions': [],
                'interval_seconds': 60,
            }
    async def check():
        app = CustodianApp(tmp_path, force_setup=True, engine=Engine())
        async with app.run_test(size=(110, 38)) as pilot:
            await pilot.pause()
            profiles = app.screen.query_one('#profiles', SelectionList)
            assert profiles.option_count == 1
            assert list(profiles.selected) == [str(tmp_path / 'hermes' / 'profiles' / 'ivy')]
    asyncio.run(check())
