"""Text input dialog — free-text entry modal that returns a string or None."""

from __future__ import annotations

from typing import Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Center, Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Static


class TextInputDialog(ModalScreen[Optional[str]]):
    """A modal dialog with a single-line text input.

    Args:
        prompt: Label text displayed above the input.
        default: Initial value for the input field.
    """

    CSS = """
    TextInputDialog {
        align: center middle;
    }

    TextInputDialog > Vertical {
        width: 70;
        max-width: 90%;
        height: auto;
        max-height: 80%;
        border: thick $accent;
        background: $surface;
        padding: 1 2;
    }

    TextInputDialog #prompt {
        width: 100%;
        margin-bottom: 1;
    }

    TextInputDialog Input {
        width: 100%;
        margin-bottom: 1;
    }

    TextInputDialog Horizontal {
        width: 100%;
        height: auto;
        align-horizontal: center;
    }

    TextInputDialog Button {
        margin: 0 1;
        min-width: 10;
    }
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=False),
    ]

    def __init__(self, prompt: str, default: str = "", **kwargs) -> None:
        super().__init__(classes="dialog", **kwargs)
        self._prompt = prompt
        self._default = default

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static(self._prompt, id="prompt")
            yield Input(value=self._default, id="text-input")
            with Center():
                with Horizontal():
                    yield Button("OK", variant="primary", id="ok")
                    yield Button("Cancel", id="cancel")

    def on_mount(self) -> None:
        self.query_one("#text-input", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Enter key inside the Input submits the dialog."""
        self.dismiss(event.value)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "ok":
            value = self.query_one("#text-input", Input).value
            self.dismiss(value)
        else:
            self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)
