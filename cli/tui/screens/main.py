"""
Main dashboard screen for the Aether v3.0 Textual TUI.

Displays the jobs table, session cost bar, and footer key-binding hints.
This is the default screen pushed by AetherApp on startup.
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.timer import Timer
from textual.widgets import Footer, Header

from cli.tui.widgets.cost_bar import CostBar
from cli.tui.widgets.jobs_table import JobsTable


class MainScreen(Screen):
    """Primary dashboard screen showing all audit jobs and session costs."""

    BINDINGS = [
        Binding("n", "new_audit", "New Audit", show=True),
        Binding("d", "discover", "Discover", show=True),
        Binding("r", "resume", "Resume", show=True),
        Binding("h", "history", "History", show=True),
        Binding("p", "pocs", "PoCs", show=True),
        Binding("o", "reports", "Reports", show=True),
        Binding("f", "fetch", "Fetch", show=True),
        Binding("s", "settings", "Settings", show=True),
        Binding("q", "quit", "Quit", show=True),
    ]

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._refresh_timer: Timer | None = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield JobsTable(id="jobs-table")
        yield CostBar(id="cost-bar", classes="cost-bar")
        yield Footer()

    def on_mount(self) -> None:
        """Set up a 1-second periodic refresh for jobs table and cost bar."""
        self.title = "AETHER v3.0 \u2014 Smart Contract Security Analysis"
        self._refresh_timer = self.set_interval(1.0, self._refresh)
        # Do an immediate refresh so the screen isn't blank on first paint
        self._refresh()

    def on_screen_suspend(self) -> None:
        """Pause refresh timer when this screen is hidden by another screen."""
        if self._refresh_timer is not None:
            self._refresh_timer.pause()

    def on_screen_resume(self) -> None:
        """Resume refresh timer when this screen becomes active again."""
        if self._refresh_timer is not None:
            self._refresh_timer.resume()
        # Immediate refresh to catch up on any changes while suspended
        self._refresh()

    def _refresh(self) -> None:
        """Poll JobManager and LLMUsageTracker to update widgets."""
        try:
            self.query_one("#jobs-table", JobsTable).refresh_jobs()
        except Exception:
            pass

        try:
            self.query_one("#cost-bar", CostBar).refresh_cost()
        except Exception:
            pass

    # ── Handle job selection from the table ──────────────────────

    def on_jobs_table_job_selected(self, message: JobsTable.JobSelected) -> None:
        """When user presses Enter on a job row, push the detail screen."""
        from cli.tui.screens.job_detail import JobDetailScreen

        self.app.push_screen(JobDetailScreen(job_id=message.job_id))

    # ── Action handlers (delegate to app-level actions) ──────────

    def action_new_audit(self) -> None:
        self.app.action_new_audit()

    def action_discover(self) -> None:
        self.app.action_discover()

    def action_resume(self) -> None:
        self.app.action_resume_audit()

    def action_history(self) -> None:
        self.app.action_history()

    def action_pocs(self) -> None:
        self.app.action_pocs()

    def action_reports(self) -> None:
        self.app.action_reports()

    def action_fetch(self) -> None:
        self.app.action_fetch()

    def action_settings(self) -> None:
        self.app.action_settings()

    def action_quit(self) -> None:
        self.app.action_quit()
