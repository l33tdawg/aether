"""Confirm dialog — Yes / No modal that returns a bool."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Center, Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Static


class ConfirmDialog(ModalScreen[bool]):
    """A modal Yes/No confirmation dialog.

    Args:
        message: The question or message to display.
    """

    CSS = """
    ConfirmDialog {
        align: center middle;
    }

    ConfirmDialog > Vertical {
        width: 60;
        max-width: 80%;
        height: auto;
        max-height: 80%;
        border: thick $accent;
        background: $surface;
        padding: 1 2;
    }

    ConfirmDialog #message {
        width: 100%;
        text-align: center;
        margin-bottom: 1;
    }

    ConfirmDialog Horizontal {
        width: 100%;
        height: auto;
        align-horizontal: center;
    }

    ConfirmDialog Button {
        margin: 0 1;
        min-width: 10;
    }
    """

    BINDINGS = [
        Binding("y", "yes", "Yes", show=False),
        Binding("n", "no", "No", show=False),
        Binding("escape", "no", "Cancel", show=False),
    ]

    def __init__(self, message: str, **kwargs) -> None:
        super().__init__(classes="dialog", **kwargs)
        self._message = message

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static(self._message, id="message")
            with Center():
                with Horizontal():
                    yield Button("Yes", variant="primary", id="yes")
                    yield Button("No", id="no")

    def on_mount(self) -> None:
        self.query_one("#yes", Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "yes")

    def action_yes(self) -> None:
        self.dismiss(True)

    def action_no(self) -> None:
        self.dismiss(False)
