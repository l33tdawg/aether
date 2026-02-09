"""
Aether v3.5 — Textual TUI Application

Main Textual App class that drives the persistent full-screen dashboard.
Replaces the Rich-based AetherDashboard with a proper reactive TUI built
on Textual's widget/screen architecture.

Launch via `python aether.py`.
"""

from pathlib import Path

from textual.app import App
from textual.binding import Binding
from textual.css.query import NoMatches

from core.job_manager import JobManager
from core.llm_usage_tracker import LLMUsageTracker


VERSION = "3.5"


class AetherApp(App):
    """Aether v3.5 Textual TUI — persistent full-screen security dashboard."""

    TITLE = f"Aether v{VERSION}"
    SUB_TITLE = "Smart Contract Security Analysis Framework"
    CSS_PATH = Path(__file__).parent / "theme.tcss"

    BINDINGS = [
        Binding("n", "new_audit", "New Audit", show=True),
        Binding("r", "resume_audit", "Resume", show=True),
        Binding("h", "history", "History", show=True),
        Binding("p", "pocs", "PoCs", show=True),
        Binding("o", "reports", "Reports", show=True),
        Binding("f", "fetch", "Fetch", show=True),
        Binding("s", "settings", "Settings", show=True),
        Binding("q", "quit", "Quit", show=True),
    ]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._job_manager = JobManager.get_instance()
        self._tracker = LLMUsageTracker.get_instance()
        self._refresh_timer = None

    def on_mount(self) -> None:
        """Push MainScreen as the default screen and start the refresh timer."""
        from cli.tui.screens.main import MainScreen

        self.push_screen(MainScreen())
        self._refresh_timer = self.set_interval(1.0, self._refresh_jobs)

    def _refresh_jobs(self) -> None:
        """Periodically refresh the jobs table and cost bar on the active screen."""
        try:
            from cli.tui.widgets.jobs_table import JobsTable
            jobs_table = self.query_one(JobsTable)
            jobs_table.refresh_jobs()
        except (NoMatches, Exception):
            pass

        try:
            from cli.tui.widgets.cost_bar import CostBar
            cost_bar = self.query_one(CostBar)
            cost_bar.refresh_cost()
        except (NoMatches, Exception):
            pass

    # ── Action handlers ──────────────────────────────────────────

    def action_new_audit(self) -> None:
        from cli.tui.screens.new_audit import NewAuditScreen
        self.push_screen(NewAuditScreen())

    def action_resume_audit(self) -> None:
        from cli.tui.screens.resume import ResumeScreen
        self.push_screen(ResumeScreen())

    def action_history(self) -> None:
        from cli.tui.screens.history import HistoryScreen
        self.push_screen(HistoryScreen())

    def action_pocs(self) -> None:
        from cli.tui.screens.pocs import PoCScreen
        self.push_screen(PoCScreen())

    def action_reports(self) -> None:
        from cli.tui.screens.reports import ReportsScreen
        self.push_screen(ReportsScreen())

    def action_fetch(self) -> None:
        from cli.tui.screens.fetch import FetchScreen
        self.push_screen(FetchScreen())

    def action_settings(self) -> None:
        from cli.tui.screens.settings import SettingsScreen
        self.push_screen(SettingsScreen())

    def action_quit(self) -> None:
        """Quit the app, with confirmation if jobs are running."""
        if self._job_manager.has_active_jobs:
            active_count = len(self._job_manager.get_active_jobs())
            from cli.tui.dialogs.confirm import ConfirmDialog

            def _handle_quit_result(confirmed: bool) -> None:
                if confirmed:
                    self.exit(return_code=0)

            self.push_screen(
                ConfirmDialog(
                    message=(
                        f"{active_count} job(s) still running. "
                        "Running jobs will be abandoned.\n\n"
                        "Quit anyway?"
                    ),
                ),
                callback=_handle_quit_result,
            )
        else:
            self.exit(return_code=0)

    # ── Properties for child widgets ─────────────────────────────

    @property
    def job_manager(self) -> JobManager:
        return self._job_manager

    @property
    def tracker(self) -> LLMUsageTracker:
        return self._tracker
