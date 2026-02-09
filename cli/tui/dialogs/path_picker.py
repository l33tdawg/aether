"""Path picker dialog — directory/file browser modal that returns a path string or None."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Center, Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, DirectoryTree, Input, Static


class PathDialog(ModalScreen[Optional[str]]):
    """A modal path picker with a DirectoryTree browser and a text Input.

    Selecting a directory or file in the tree updates the Input field.
    The user can also type or paste a path directly.

    Args:
        prompt: Label text displayed above the browser.
        default: Initial path value for the input field.
    """

    CSS = """
    PathDialog {
        align: center middle;
    }

    PathDialog > Vertical {
        width: 80;
        max-width: 95%;
        height: 36;
        max-height: 90%;
        border: thick $accent;
        background: $surface;
        padding: 1 2;
    }

    PathDialog #prompt {
        width: 100%;
        margin-bottom: 1;
    }

    PathDialog DirectoryTree {
        width: 100%;
        height: 1fr;
        margin-bottom: 1;
    }

    PathDialog #path-input {
        width: 100%;
        margin-bottom: 1;
    }

    PathDialog Horizontal {
        width: 100%;
        height: auto;
        align-horizontal: center;
    }

    PathDialog Button {
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
        # Determine the root directory for the tree browser.
        start = Path(self._default).expanduser() if self._default else Path.cwd()
        if start.is_file():
            tree_root = start.parent
        elif start.is_dir():
            tree_root = start
        else:
            tree_root = Path.cwd()

        with Vertical():
            yield Static(self._prompt, id="prompt")
            yield DirectoryTree(str(tree_root), id="dir-tree")
            yield Input(value=self._default, placeholder="Enter path...", id="path-input")
            with Center():
                with Horizontal():
                    yield Button("OK", variant="primary", id="ok")
                    yield Button("Cancel", id="cancel")

    def on_mount(self) -> None:
        self.query_one("#dir-tree", DirectoryTree).focus()

    def on_directory_tree_file_selected(
        self, event: DirectoryTree.FileSelected
    ) -> None:
        """When a file is selected in the tree, update the input."""
        self.query_one("#path-input", Input).value = str(event.path)

    def on_directory_tree_directory_selected(
        self, event: DirectoryTree.DirectorySelected
    ) -> None:
        """When a directory is selected in the tree, update the input."""
        self.query_one("#path-input", Input).value = str(event.path)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Enter inside the Input submits the dialog."""
        self.dismiss(event.value)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "ok":
            value = self.query_one("#path-input", Input).value
            self.dismiss(value)
        else:
            self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)
