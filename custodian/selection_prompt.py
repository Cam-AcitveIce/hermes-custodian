"""Small inline arrow-key prompts. Never use the alternate-screen/full-screen TUI."""
from __future__ import annotations
import unicodedata


def plain(value):
    return ''.join('?' if unicodedata.category(c).startswith('C') else c for c in str(value))


def select(title, options, *, multiple=False, selected=(), on_toggle=None, checkable=None, input=None, output=None):
    """Return one value, checked values, or None on Esc/Ctrl+C.

    on_toggle(value) is for policy-aware folder selection; it returns
    (checked, status). Enter still navigates, rather than selecting a folder.
    """
    from prompt_toolkit.application import Application
    from prompt_toolkit.key_binding import KeyBindings
    from prompt_toolkit.layout import Layout, HSplit, VSplit, Window
    from prompt_toolkit.layout.controls import FormattedTextControl
    from prompt_toolkit.styles import Style
    options = list(options)
    if not options:
        return [] if multiple else None
    cursor = 0
    checked = set(selected)
    status = ''
    bindings = KeyBindings()

    @bindings.add('up')
    def up(event):
        nonlocal cursor
        cursor = (cursor - 1) % len(options)

    @bindings.add('down')
    def down(event):
        nonlocal cursor
        cursor = (cursor + 1) % len(options)

    @bindings.add('space')
    def toggle(event):
        nonlocal status
        value = options[cursor][0]
        if on_toggle is not None:
            now_checked, status = on_toggle(value)
            if now_checked:
                checked.add(value)
            else:
                checked.discard(value)
        elif multiple:
            if value in checked:
                checked.remove(value)
            else:
                checked.add(value)

    @bindings.add('enter')
    def done(event):
        event.app.exit(result=[v for v, _ in options if v in checked] if multiple else options[cursor][0])

    @bindings.add('escape')
    @bindings.add('c-c')
    @bindings.add('c-d')
    def cancel(event):
        event.app.exit(result=None)

    def lines():
        height = max(1, min(10, app.output.get_size().rows - 6))
        start = max(0, min(cursor - height + 1, len(options) - height))
        fragments = []
        for index in range(start, min(len(options), start + height)):
            value, label = options[index]
            tickable = multiple or (on_toggle and (checkable is None or value in checkable))
            marker = ('[x] ' if value in checked else '[ ] ') if tickable else ''
            fragments.append(('class:active' if index == cursor else '',
                              ('  › ' if index == cursor else '    ') + marker + plain(label) + '\n'))
        return fragments

    hint = '↑/↓ Move · Space Select · Enter Confirm · Esc Back' if multiple else (
        '↑/↓ Move · Space Select folder · Enter Open / Continue · Esc Back' if on_toggle else
        '↑/↓ Move · Enter Select · Esc Back')
    container = HSplit([
        Window(height=1),
        Window(FormattedTextControl(lambda: [('class:title', plain(title))]), height=1, always_hide_cursor=True),
        Window(height=1),
        Window(FormattedTextControl(lines), height=lambda: max(1, min(len(options), 10, app.output.get_size().rows - 6)), dont_extend_height=True),
        Window(FormattedTextControl(lambda: [('class:hint', plain(status) if status else hint)]), height=2, wrap_lines=True),
    ])
    app = Application(layout=Layout(VSplit([Window(width=2), container]), focused_element=container.children[1]),
                      key_bindings=bindings, full_screen=False, erase_when_done=True,
                      mouse_support=False, input=input, output=output,
                      style=Style.from_dict({'title': 'bold #d5b56c', 'active': 'bold #d5b56c', 'hint': '#888888'}))
    app.ttimeoutlen = 0.1
    return app.run()
