"""Checkbox (multi-select) dialog — returns a list of selected values or None."""

from __future__ import annotations

from typing import Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Center, Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, SelectionList, Static


class CheckboxDialog(ModalScreen[Optional[list[str]]]):
    """A modal multi-select dialog backed by Textual's SelectionList.

    Args:
        prompt: Header text displayed above the selection list.
        choices: List of ``(label, value, checked)`` tuples describing each option.
    """

    CSS = """
    CheckboxDialog {
        align: center middle;
    }

    CheckboxDialog > Vertical {
        width: 70;
        max-width: 90%;
        height: auto;
        max-height: 80%;
        border: thick $accent;
        background: $surface;
        padding: 1 2;
    }

    CheckboxDialog #prompt {
        width: 100%;
        margin-bottom: 1;
    }

    CheckboxDialog SelectionList {
        width: 100%;
        height: auto;
        max-height: 20;
        margin-bottom: 1;
    }

    CheckboxDialog Horizontal {
        width: 100%;
        height: auto;
        align-horizontal: center;
    }

    CheckboxDialog Button {
        margin: 0 1;
        min-width: 10;
    }
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=False),
    ]

    def __init__(
        self,
        prompt: str,
        choices: list[tuple[str, str, bool]],
        **kwargs,
    ) -> None:
        super().__init__(classes="dialog", **kwargs)
        self._prompt = prompt
        self._choices = choices

    def compose(self) -> ComposeResult:
        # SelectionList accepts (label, value, initial_state) tuples directly.
        with Vertical():
            yield Static(self._prompt, id="prompt")
            yield SelectionList[str](
                *self._choices,
                id="checkbox-list",
            )
            with Center():
                with Horizontal():
                    yield Button("OK", variant="primary", id="ok")
                    yield Button("Cancel", id="cancel")

    def on_mount(self) -> None:
        self.query_one("#checkbox-list", SelectionList).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "ok":
            selection_list = self.query_one("#checkbox-list", SelectionList)
            self.dismiss(list(selection_list.selected))
        else:
            self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)
