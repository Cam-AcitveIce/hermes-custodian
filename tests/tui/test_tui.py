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
