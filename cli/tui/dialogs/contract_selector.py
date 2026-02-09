"""Contract selector dialog — near-fullscreen multi-select with filtering.

Replaces the curses-based contract selector from core/scope_manager.py with
a Textual ModalScreen that provides:
- Filterable DataTable of contracts
- Space to toggle selection, 'a' to select all visible, 'n' to deselect all
- Color-coded previously-audited rows
- Returns Optional[List[int]] (selected indices) or None on cancel
"""

from __future__ import annotations

from typing import Dict, List, Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Input, Static


class ContractSelectorDialog(ModalScreen[Optional[List[int]]]):
    """A near-fullscreen modal for selecting contracts from a list.

    Args:
        contracts: List of dicts with at least 'contract_name' and 'file_path'.
        disabled_indices: Indices that cannot be toggled.
        pre_selected: Indices that start as selected.
        previously_audited_indices: Indices shown with a green marker.
    """

    CSS = """
    ContractSelectorDialog {
        align: center middle;
    }

    ContractSelectorDialog > Vertical {
        width: 90%;
        height: 90%;
        border: thick $accent;
        background: $surface;
        padding: 1 2;
    }

    ContractSelectorDialog #cs-prompt {
        width: 100%;
        margin-bottom: 1;
    }

    ContractSelectorDialog #cs-filter {
        width: 100%;
        margin-bottom: 1;
    }

    ContractSelectorDialog #cs-table {
        width: 100%;
        height: 1fr;
        margin-bottom: 1;
    }

    ContractSelectorDialog #cs-summary {
        width: 100%;
        height: 2;
        margin-bottom: 1;
    }

    ContractSelectorDialog Horizontal {
        width: 100%;
        height: auto;
        align-horizontal: center;
    }

    ContractSelectorDialog Button {
        margin: 0 1;
        min-width: 12;
    }
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=False),
    ]

    def __init__(
        self,
        contracts: List[Dict],
        disabled_indices: Optional[List[int]] = None,
        pre_selected: Optional[List[int]] = None,
        previously_audited_indices: Optional[List[int]] = None,
        **kwargs,
    ) -> None:
        super().__init__(classes="dialog", **kwargs)
        self._contracts = contracts
        self._disabled = set(disabled_indices or [])
        self._selected = set(pre_selected or [])
        self._audited = set(previously_audited_indices or [])
        self._filter_text = ""
        # Maps visible table row index -> original contract index
        self._visible_indices: List[int] = list(range(len(contracts)))

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static(
                "[bold cyan]Select Contracts[/bold cyan]  "
                "[dim](Space: toggle, a: all, n: none, Enter: confirm, Esc: cancel)[/dim]",
                id="cs-prompt",
            )
            yield Input(placeholder="Filter by name or path...", id="cs-filter")
            yield DataTable(id="cs-table")
            yield Static("", id="cs-summary")
            with Horizontal():
                yield Button("Confirm", variant="primary", id="cs-ok")
                yield Button("Cancel", id="cs-cancel")

    def on_mount(self) -> None:
        table = self.query_one("#cs-table", DataTable)
        table.cursor_type = "row"
        table.add_columns("Sel", "#", "Contract Name", "File Path", "Status")
        self._rebuild_table()
        table.focus()

    # ── Table rebuilding ──────────────────────────────────────────

    def _rebuild_table(self) -> None:
        """Rebuild the table rows based on the current filter."""
        table = self.query_one("#cs-table", DataTable)
        table.clear()
        self._visible_indices.clear()

        ft = self._filter_text.lower()
        for i, c in enumerate(self._contracts):
            name = c.get("contract_name", c.get("name", ""))
            path = c.get("file_path", "")
            if ft and ft not in name.lower() and ft not in path.lower():
                continue

            self._visible_indices.append(i)
            check = "[X]" if i in self._selected else "[ ]"
            status = ""
            if i in self._disabled:
                status = "[dim]disabled[/dim]"
            elif i in self._audited:
                status = "[green]audited[/green]"

            table.add_row(check, str(i + 1), name, path, status)

        self._update_summary()

    def _update_summary(self) -> None:
        total = len(self._contracts)
        selected = len(self._selected)
        visible = len(self._visible_indices)
        summary = self.query_one("#cs-summary", Static)
        summary.update(
            f"[bold]{selected}[/bold] of {total} selected  |  "
            f"{visible} shown"
        )

    def _update_row_check(self, row_idx: int, original_idx: int) -> None:
        """Update just the checkbox column for a row."""
        table = self.query_one("#cs-table", DataTable)
        check = "[X]" if original_idx in self._selected else "[ ]"
        row_key = table.get_row_at(row_idx)
        # DataTable stores row data; we update by replacing the row
        c = self._contracts[original_idx]
        name = c.get("contract_name", c.get("name", ""))
        path = c.get("file_path", "")
        status = ""
        if original_idx in self._disabled:
            status = "[dim]disabled[/dim]"
        elif original_idx in self._audited:
            status = "[green]audited[/green]"
        table.update_cell(row_key, "Sel", check)

    # ── Filtering ─────────────────────────────────────────────────

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "cs-filter":
            self._filter_text = event.value
            self._rebuild_table()

    # ── Keyboard actions ──────────────────────────────────────────

    def on_key(self, event) -> None:
        # Only handle keys when table is focused
        table = self.query_one("#cs-table", DataTable)
        if not table.has_focus:
            return

        if event.key == "space":
            event.prevent_default()
            self._toggle_current()
        elif event.key == "a":
            event.prevent_default()
            self._select_all_visible()
        elif event.key == "n":
            event.prevent_default()
            self._deselect_all_visible()

    def _toggle_current(self) -> None:
        """Toggle the selection of the currently highlighted row."""
        table = self.query_one("#cs-table", DataTable)
        row_idx = table.cursor_row
        if row_idx < 0 or row_idx >= len(self._visible_indices):
            return
        original_idx = self._visible_indices[row_idx]
        if original_idx in self._disabled:
            return
        if original_idx in self._selected:
            self._selected.discard(original_idx)
        else:
            self._selected.add(original_idx)
        self._rebuild_table()
        # Restore cursor position
        if row_idx < len(self._visible_indices):
            table.move_cursor(row=row_idx)

    def _select_all_visible(self) -> None:
        """Select all visible (non-disabled) contracts."""
        for idx in self._visible_indices:
            if idx not in self._disabled:
                self._selected.add(idx)
        self._rebuild_table()

    def _deselect_all_visible(self) -> None:
        """Deselect all visible contracts."""
        for idx in self._visible_indices:
            self._selected.discard(idx)
        self._rebuild_table()

    # ── Buttons ───────────────────────────────────────────────────

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Enter key on a row toggles selection."""
        # Don't toggle — Enter should confirm
        pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cs-ok":
            self.dismiss(sorted(self._selected))
        else:
            self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)
