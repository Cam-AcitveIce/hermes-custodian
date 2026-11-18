"""Exercise real prompt-toolkit key handling, without touching real profiles."""
from prompt_toolkit.input.defaults import create_pipe_input
from prompt_toolkit.output import DummyOutput


def test_arrows_space_and_enter_select_multiple_profiles():
    from custodian.selection_prompt import select
    with create_pipe_input() as keys:
        keys.send_text(' \x1b[B \r')
        assert select('Profiles', [('default', 'Default'), ('ivy', 'Ivy'), ('athena', 'Athena')],
                      multiple=True, input=keys, output=DummyOutput()) == ['default', 'ivy']


def test_escape_cancels_without_returning_selection():
    from custodian.selection_prompt import select
    with create_pipe_input() as keys:
        keys.send_text(' \x1b')
        assert select('Profiles', [('ivy', 'Ivy')], multiple=True,
                      input=keys, output=DummyOutput()) is None


def test_arrows_enter_choose_action():
    from custodian.selection_prompt import select
    with create_pipe_input() as keys:
        keys.send_text('\x1b[B\r')
        assert select('Setup', [('profiles', 'Choose profiles'), ('folders', 'Choose folders')],
                      input=keys, output=DummyOutput()) == 'folders'
