"""The folder picker's actions must remain usable on ordinary terminals."""
import asyncio
import pytest


@pytest.mark.parametrize('size', [(110, 38), (80, 30)])
def test_picker_actions_fit_terminal(tmp_path, size):
    from custodian.tui import CustodianApp
    from textual.widgets import Button

    class Engine:
        def settings(self):
            raise RuntimeError('not configured')

    home = tmp_path / 'demo'
    home.mkdir()
    (home / 'Projects').mkdir()

    async def check():
        app = CustodianApp(tmp_path / 'state', force_setup=True,
                           engine=Engine(), browse_home=home)
        async with app.run_test(size=size) as pilot:
            browse = next(b for b in app.screen.query(Button)
                          if 'browse' in str(b.label).lower())
            browse.scroll_visible(animate=False)
            await pilot.pause()
            await pilot.click('#' + browse.id)
            await pilot.pause(0.5)
            for name in ('picker-add', 'picker-cancel', 'picker-parent', 'picker-home'):
                button = app.screen.query_one('#' + name, Button)
                region = button.region
                assert button.display
                assert region.width > 0 and region.height > 0
                assert region.x >= 0 and region.y >= 0
                assert region.right <= size[0] and region.bottom <= size[1], (name, region)

    asyncio.run(check())
