"""Discovery Results dialog — ranked contract selection with scoring.

A near-fullscreen ModalScreen that displays contracts ranked by
audit-worthiness score.  Pre-selects CRITICAL + HIGH + MEDIUM contracts.
Toggle 't' to show/hide LOW + SKIP entries (hidden by default).

Returns Optional[List[Path]] — selected file paths, or None on cancel.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Input, Static

from core.contract_scanner import (
    DiscoveryReport,
    PriorityTier,
    ScanResult,
)


_PRIORITY_LABEL = {
    PriorityTier.CRITICAL: "[bold red]CRITICAL[/]",
    PriorityTier.HIGH: "[yellow]HIGH[/]",
    PriorityTier.MEDIUM: "[cyan]MEDIUM[/]",
    PriorityTier.LOW: "[dim]LOW[/]",
    PriorityTier.SKIP: "[dim]SKIP[/]",
}

_RECOMMENDED = {PriorityTier.CRITICAL, PriorityTier.HIGH, PriorityTier.MEDIUM}


class DiscoveryResultsDialog(ModalScreen[Optional[List[Path]]]):
    """Near-fullscreen ranked contract selector.

    Args:
        report: A DiscoveryReport from ContractScanner.scan_directory().
    """

    CSS = """
    DiscoveryResultsDialog {
        align: center middle;
    }

    DiscoveryResultsDialog > Vertical {
        width: 90%;
        height: 90%;
        border: thick $accent;
        background: $surface;
        padding: 1 2;
    }

    DiscoveryResultsDialog #dr-prompt {
        width: 100%;
        margin-bottom: 1;
    }

    DiscoveryResultsDialog #dr-filter {
        width: 100%;
        margin-bottom: 1;
    }

    DiscoveryResultsDialog #dr-table {
        width: 100%;
        height: 1fr;
        margin-bottom: 1;
    }

    DiscoveryResultsDialog #dr-summary {
        width: 100%;
        height: 2;
        margin-bottom: 1;
    }

    DiscoveryResultsDialog Horizontal {
        width: 100%;
        height: auto;
        align-horizontal: center;
    }

    DiscoveryResultsDialog Button {
        margin: 0 1;
        min-width: 12;
    }
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=False),
    ]

    def __init__(self, report: DiscoveryReport, **kwargs) -> None:
        super().__init__(classes="dialog", **kwargs)
        self._report = report
        self._results = report.results
        # Pre-select recommended contracts
        self._selected: set[int] = {
            i for i, r in enumerate(self._results) if r.priority in _RECOMMENDED
        }
        self._filter_text = ""
        self._show_low = False  # hide LOW + SKIP by default
        self._visible_indices: List[int] = []

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static(
                "[bold cyan]Auto-Discover Results[/bold cyan]  "
                "[dim](Space: toggle, a: all, n: none, t: show/hide low, "
                "Enter: confirm, Esc: cancel)[/dim]",
                id="dr-prompt",
            )
            yield Input(placeholder="Filter by name or path...", id="dr-filter")
            yield DataTable(id="dr-table")
            yield Static("", id="dr-summary")
            with Horizontal():
                yield Button("Confirm", variant="primary", id="dr-ok")
                yield Button("Cancel", id="dr-cancel")

    def on_mount(self) -> None:
        table = self.query_one("#dr-table", DataTable)
        table.cursor_type = "row"
        table.add_columns("Sel", "#", "Priority", "Score", "Contract", "Path", "Top Signals")
        self._rebuild_table()
        table.focus()

    # ── Table rebuilding ──────────────────────────────────────────

    def _rebuild_table(self) -> None:
        table = self.query_one("#dr-table", DataTable)
        table.clear()
        self._visible_indices.clear()

        ft = self._filter_text.lower()
        for i, r in enumerate(self._results):
            # Optionally hide LOW / SKIP
            if not self._show_low and r.priority in (PriorityTier.LOW, PriorityTier.SKIP):
                continue
            # Apply text filter
            if ft and ft not in r.contract_name.lower() and ft not in str(r.file_path).lower():
                continue

            self._visible_indices.append(i)
            check = "[X]" if i in self._selected else "[ ]"
            priority_label = _PRIORITY_LABEL.get(r.priority, str(r.priority.value))
            try:
                rel_path = str(r.file_path.relative_to(self._report.root_path))
            except ValueError:
                rel_path = r.file_path.name
            top_signals = ", ".join(r.signals[:3]) if r.signals else "-"

            table.add_row(
                check,
                str(i + 1),
                priority_label,
                str(r.score),
                r.contract_name,
                rel_path,
                top_signals,
            )

        self._update_summary()

    def _update_summary(self) -> None:
        selected = len(self._selected)
        by_tier = {}
        for i in self._selected:
            tier = self._results[i].priority
            by_tier[tier] = by_tier.get(tier, 0) + 1

        parts = [f"[bold]{selected}[/bold] selected"]
        for tier in (PriorityTier.CRITICAL, PriorityTier.HIGH, PriorityTier.MEDIUM):
            count = by_tier.get(tier, 0)
            if count:
                parts.append(f"{count} {tier.value}")

        low_tag = "[dim](t: show low/skip)[/dim]" if not self._show_low else "[dim](t: hide low/skip)[/dim]"
        parts.append(f"Scan: {self._report.scan_time_ms}ms")
        parts.append(low_tag)

        summary = self.query_one("#dr-summary", Static)
        summary.update("  |  ".join(parts))

    # ── Filtering ─────────────────────────────────────────────────

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "dr-filter":
            self._filter_text = event.value
            self._rebuild_table()

    # ── Keyboard actions ──────────────────────────────────────────

    def on_key(self, event) -> None:
        table = self.query_one("#dr-table", DataTable)
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
        elif event.key == "t":
            event.prevent_default()
            self._toggle_low_visibility()

    def _toggle_current(self) -> None:
        table = self.query_one("#dr-table", DataTable)
        row_idx = table.cursor_row
        if row_idx < 0 or row_idx >= len(self._visible_indices):
            return
        original_idx = self._visible_indices[row_idx]
        if original_idx in self._selected:
            self._selected.discard(original_idx)
        else:
            self._selected.add(original_idx)
        self._rebuild_table()
        if row_idx < len(self._visible_indices):
            table.move_cursor(row=row_idx)

    def _select_all_visible(self) -> None:
        for idx in self._visible_indices:
            self._selected.add(idx)
        self._rebuild_table()

    def _deselect_all_visible(self) -> None:
        for idx in self._visible_indices:
            self._selected.discard(idx)
        self._rebuild_table()

    def _toggle_low_visibility(self) -> None:
        self._show_low = not self._show_low
        self._rebuild_table()

    # ── Buttons ───────────────────────────────────────────────────

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "dr-ok":
            paths = [self._results[i].file_path for i in sorted(self._selected)]
            self.dismiss(paths)
        else:
            self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)
