"""Select dialog — single-choice list modal that returns a string or None."""

from __future__ import annotations

from typing import Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Label, ListView, ListItem, Static


class SelectDialog(ModalScreen[Optional[str]]):
    """A modal single-select dialog backed by a ListView.

    Args:
        prompt: Header text displayed above the list.
        choices: List of string values the user can pick from.
    """

    CSS = """
    SelectDialog {
        align: center middle;
    }

    SelectDialog > Vertical {
        width: 60;
        max-width: 90%;
        height: auto;
        max-height: 80%;
        border: thick $accent;
        background: $surface;
        padding: 1 2;
    }

    SelectDialog #prompt {
        width: 100%;
        margin-bottom: 1;
    }

    SelectDialog ListView {
        width: 100%;
        height: auto;
        max-height: 20;
        margin-bottom: 1;
    }

    SelectDialog ListItem {
        padding: 0 1;
    }
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=False),
    ]

    def __init__(self, prompt: str, choices: list[str], **kwargs) -> None:
        super().__init__(classes="dialog", **kwargs)
        self._prompt = prompt
        self._choices = choices

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static(self._prompt, id="prompt")
            yield ListView(
                *[ListItem(Label(choice), name=choice) for choice in self._choices],
                id="select-list",
            )

    def on_mount(self) -> None:
        self.query_one("#select-list", ListView).focus()

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        """User pressed Enter on a highlighted item."""
        # The name attribute stores the original choice string.
        self.dismiss(event.item.name)

    def action_cancel(self) -> None:
        self.dismiss(None)
