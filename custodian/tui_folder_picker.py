"""Textual modal screen for keyboard-friendly folder browsing."""
from __future__ import annotations
import asyncio
from pathlib import PurePath
from rich.text import Text
from textual import events
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, OptionList, Static
from textual.widgets.option_list import Option
from . import folder_picker as fp


class FolderPickerScreen(ModalScreen[list[str] | None]):
    """Modal dialog allowing users to browse and multi-select directories safely."""

    DEFAULT_CSS = """
    FolderPickerScreen {
        align: center middle;
    }
    #picker-dialog {
        width: 100;
        max-width: 96%;
        height: 36;
        max-height: 96%;
        border: thick #31444b;
        background: #0b0e12;
        padding: 1 2;
    }
    .picker-title {
        text-style: bold;
        color: #e6dfca;
    }
    #picker-path {
        color: #73b5ae;
        margin: 1 0;
    }
    #picker-list {
        height: 1fr;
        min-height: 3;
        border: solid #29333f;
        background: #121820;
    }
    #picker-status {
        color: #dbbb80;
        height: 2;
        margin-top: 1;
    }
    #picker-selected {
        color: #d1d7df;
        height: 4;
    }
    #picker-note {
        color: #8994a4;
        margin: 1 0;
    }
    .picker-nav, .picker-actions {
        height: 3;
    }
    Button {
        margin-right: 1;
        background: #19222d;
        border: solid #344352;
    }
    Button.-primary {
        background: #183b3a;
        color: #b1e0d7;
    }
    """

    BINDINGS = [("escape", "cancel", "Cancel")]

    def __init__(self, model: fp.PickerModel):
        super().__init__()
        self.model = model
        self._entries: list[fp.Entry] = []
        self._status_text: str = ""

    def compose(self) -> ComposeResult:
        with Vertical(id="picker-dialog"):
            yield Static("Browse folders", classes="picker-title")
            yield Static(str(self.model.current or "Select a drive"), id="picker-path", markup=False)
            yield OptionList(id="picker-list")
            yield Static("", id="picker-status", markup=False)
            yield Static(self._render_selected(), id="picker-selected", markup=False)
            yield Static(
                "Adding folders is not monitoring approval. "
                "You must approve scope and save before monitoring begins.",
                id="picker-note",
            )
            with Horizontal(classes="picker-nav"):
                yield Button("Parent", id="picker-parent")
                yield Button("Home", id="picker-home")
                if self.model.has_drives:
                    yield Button("Drives", id="picker-drives")
                yield Button("Select current", id="picker-select-current")
            with Horizontal(classes="picker-actions"):
                yield Button("Add selected", variant="primary", id="picker-add")
                yield Button("Cancel", id="picker-cancel")

    def on_mount(self) -> None:
        self._load_target(self.model.current)

    def _render_selected(self) -> str:
        lines = [f"Selected: {len(self.model.selected)}"]
        if self.model.selected:
            lines.extend(self.model.selected)
        return "\n".join(lines)

    def _compute_status(self) -> str:
        if self._status_text:
            return self._status_text
        if self.model.listing.error:
            return self.model.listing.error
        if self.model.status:
            return self.model.status
        if self.model.listing.truncated:
            return f"Showing first {self.model.limit} entries; directory contains more."
        if self.model.listing.hidden > 0:
            count = self.model.listing.hidden
            word = "entry" if count == 1 else "entries"
            return f"{count} other {word} (links or non-directories) never opened or followed."
        return ""

    def _update_status(self) -> None:
        self.query_one("#picker-status", Static).update(self._compute_status())

    def _update_selected(self) -> None:
        self.query_one("#picker-selected", Static).update(self._render_selected())

    def _refresh_options(self, keep_highlight: bool = False) -> None:
        listing_widget = self.query_one("#picker-list", OptionList)
        old_highlight = listing_widget.highlighted if keep_highlight else None
        listing_widget.clear_options()
        self._entries = list(self.model.listing.entries)
        first_enabled = None

        for idx, entry in enumerate(self._entries):
            if self.model.current is None:
                label = f"    {entry.name}"
                listing_widget.add_option(Option(Text(label), id=str(idx)))
                if first_enabled is None:
                    first_enabled = idx
            elif entry.blocked:
                label = f"[-] {entry.name} (private agent data)"
                listing_widget.add_option(Option(Text(label), id=str(idx), disabled=True))
            else:
                mark = "x" if self.model.is_selected(entry.path) else " "
                label = f"[{mark}] {entry.name}"
                listing_widget.add_option(Option(Text(label), id=str(idx)))
                if first_enabled is None:
                    first_enabled = idx

        if keep_highlight and old_highlight is not None and old_highlight < len(self._entries):
            listing_widget.highlighted = old_highlight
        elif first_enabled is not None:
            listing_widget.highlighted = first_enabled
        else:
            listing_widget.highlighted = 0 if self._entries else None

    def _update_ui(self, keep_highlight: bool = False) -> None:
        path_text = self.model.current if self.model.current is not None else "Select a drive"
        self.query_one("#picker-path", Static).update(path_text)
        self._refresh_options(keep_highlight=keep_highlight)
        self._update_status()
        self._update_selected()

    def _load_target(self, target: str | None) -> None:
        self.run_worker(self._async_load_target(target), exclusive=True)

    async def _async_load_target(self, target: str | None) -> None:
        listing = await asyncio.to_thread(self.model.probe, target)
        self._status_text = ""
        applied = self.model.apply(target, listing)
        if not applied and listing.error:
            self._status_text = listing.error
        self._update_ui()
        self.query_one("#picker-list", OptionList).focus()

    def on_key(self, event: events.Key) -> None:
        if event.key == "escape":
            event.prevent_default()
            event.stop()
            self.dismiss(None)
            return

        focused = self.focused
        if focused is not None and focused.id == "picker-list":
            listing_widget = self.query_one("#picker-list", OptionList)
            if event.key == "up":
                if listing_widget.highlighted is not None and listing_widget.highlighted > 0:
                    event.prevent_default()
                    event.stop()
                    listing_widget.highlighted -= 1
            elif event.key == "down":
                if listing_widget.highlighted is not None and listing_widget.highlighted < len(self._entries) - 1:
                    event.prevent_default()
                    event.stop()
                    listing_widget.highlighted += 1
            elif event.key in ("left", "backspace"):
                event.prevent_default()
                event.stop()
                self._go_parent()
            elif event.key in ("enter", "right"):
                event.prevent_default()
                event.stop()
                self._open_highlighted()
            elif event.key == "space":
                event.prevent_default()
                event.stop()
                self._toggle_highlighted()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id
        if button_id == "picker-cancel":
            self.dismiss(None)
        elif button_id == "picker-add":
            self._handle_add()
        elif button_id == "picker-parent":
            self._go_parent()
        elif button_id == "picker-home":
            self._go_home()
        elif button_id == "picker-drives":
            self._go_drives()
        elif button_id == "picker-select-current":
            self._select_current()

    def _handle_add(self) -> None:
        if not self.model.selected:
            self._status_text = "Nothing selected"
            self._update_status()
            return
        self.dismiss(list(self.model.selected))

    def _select_current(self) -> None:
        self._status_text = ""
        ok = self.model.select_current()
        if not ok:
            self._status_text = self.model.status
        self._update_ui(keep_highlight=True)

    def _go_parent(self) -> None:
        target = self.model.parent_target()
        if target is False:
            self._status_text = fp.TOP
            self._update_status()
            return
        self._load_target(target)

    def _go_home(self) -> None:
        self._load_target(str(self.model.home))

    def _go_drives(self) -> None:
        if self.model.has_drives:
            self._load_target(None)

    def _open_highlighted(self) -> None:
        listing_widget = self.query_one("#picker-list", OptionList)
        idx = listing_widget.highlighted
        if idx is None or idx < 0 or idx >= len(self._entries):
            return
        entry = self._entries[idx]
        if entry.blocked:
            self._status_text = f"{entry.blocked} (private agent data)"
            self._update_status()
            return
        self._load_target(entry.path)

    def _toggle_highlighted(self) -> None:
        if self.model.current is None:
            self._status_text = fp.TOO_BROAD
            self._update_status()
            return
        listing_widget = self.query_one("#picker-list", OptionList)
        idx = listing_widget.highlighted
        if idx is None or idx < 0 or idx >= len(self._entries):
            return
        entry = self._entries[idx]
        if entry.blocked:
            self._status_text = f"{entry.blocked} (private agent data)"
            self._update_status()
            return
        self._status_text = ""
        self.model.toggle(entry.path)
        self._update_ui(keep_highlight=True)
