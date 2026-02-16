"""
Job detail screen for the Aether v3.0 Textual TUI.

Shows a live-updating view of a single audit job with log output,
phase progress, and metadata. Accessed by pressing Enter on a job
row in the MainScreen jobs table.
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container
from textual.screen import Screen
from textual.timer import Timer
from textual.widgets import Footer, Header, Static

from core.audit_progress import TOTAL_PHASES
from core.job_manager import AuditJob, JobManager, JobStatus
from cli.tui.widgets.log_viewer import LogViewer
from cli.tui.widgets.phase_bar import PhaseBar


class JobDetailScreen(Screen):
    """Detail view for a single audit job with live log, phase bar, and metadata."""

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("c", "cancel", "Cancel Job", show=True),
    ]

    CSS = """
    JobDetailScreen #detail-layout {
        layout: horizontal;
        height: 1fr;
        overflow: hidden;
    }

    JobDetailScreen #log-panel {
        width: 1fr;
        height: 100%;
        padding: 0;
        overflow: hidden;
    }

    JobDetailScreen #side-panel {
        layout: vertical;
        width: 40;
        height: 100%;
        padding: 0 1;
        overflow: hidden;
    }

    JobDetailScreen #phase-bar {
        height: auto;
        margin-bottom: 1;
    }

    JobDetailScreen #metadata {
        height: auto;
        max-height: 100%;
        padding: 1;
        border: tall $border;
        border-title-color: cyan;
        border-title-style: bold;
        background: $surface;
        overflow: hidden;
    }

    JobDetailScreen .log-viewer {
        height: 100%;
    }
    """

    def __init__(self, job_id: str, **kwargs) -> None:
        super().__init__(**kwargs)
        self.job_id = job_id
        self._refresh_timer: Timer | None = None

    def compose(self) -> ComposeResult:
        # Get the job for the header title
        jm = JobManager.get_instance()
        job = jm.get_job(self.job_id)
        job_name = job.display_name if job else self.job_id

        yield Header(show_clock=True)

        with Container(id="detail-layout"):
            # Left panel: log viewer (70%)
            with Container(id="log-panel"):
                yield LogViewer(id="log-viewer", classes="log-viewer")

            # Right panel: phase bar + metadata (30%)
            with Container(id="side-panel"):
                yield PhaseBar(id="phase-bar")
                meta = Static(self._build_metadata_text(job), id="metadata")
                meta.border_title = "Job Details"
                yield meta

        yield Footer()

    def on_mount(self) -> None:
        """Load initial log lines and start the live-refresh timer."""
        jm = JobManager.get_instance()
        job = jm.get_job(self.job_id)

        # Set screen title to show the job name
        job_name = job.display_name if job else self.job_id
        self.title = f"Job: {job_name}"

        # Load the log viewer with the job's existing log output
        log_viewer = self.query_one("#log-viewer", LogViewer)
        log_viewer.job_id = self.job_id

        # Set initial phase bar state
        if job and job.audit_status:
            phase_bar = self.query_one("#phase-bar", PhaseBar)
            phase_bar.update_from_job(job)

        # Start a 0.5s refresh timer for live updates
        self._refresh_timer = self.set_interval(0.5, self._refresh)

    def on_screen_suspend(self) -> None:
        """Pause refresh timer when this screen is hidden by another screen."""
        if self._refresh_timer is not None:
            self._refresh_timer.pause()

    def on_screen_resume(self) -> None:
        """Resume refresh timer when this screen becomes active again."""
        if self._refresh_timer is not None:
            self._refresh_timer.resume()

    def _refresh(self) -> None:
        """Fetch new log lines, update phase bar and metadata panel."""
        jm = JobManager.get_instance()
        job = jm.get_job(self.job_id)

        if job is None:
            return

        # Update log viewer with new lines
        try:
            log_viewer = self.query_one("#log-viewer", LogViewer)
            log_viewer.refresh_log()
        except Exception:
            pass

        # Update phase bar
        try:
            phase_bar = self.query_one("#phase-bar", PhaseBar)
            phase_bar.update_from_job(job)
        except Exception:
            pass

        # Update metadata panel
        try:
            metadata = self.query_one("#metadata", Static)
            metadata.update(self._build_metadata_text(job))
        except Exception:
            pass

        # If the job is done, stop the refresh timer to save resources
        if not job.is_active and self._refresh_timer is not None:
            self._refresh_timer.stop()
            self._refresh_timer = None

    # Max visible chars for a value in the metadata panel
    _META_MAX = 28

    def _trunc(self, text: str, max_len: int | None = None) -> str:
        """Truncate text to fit the metadata panel width."""
        limit = max_len or self._META_MAX
        if len(text) > limit:
            return text[: limit - 1] + "\u2026"
        return text

    def _build_metadata_text(self, job: AuditJob | None) -> str:
        """Build the Rich markup for the metadata panel."""
        if job is None:
            return "[dim]Job not found[/]"

        lines: list[str] = []

        # Status
        status_display = self._format_status(job.status)
        lines.append(f"[bold]Status:[/]  {status_display}")

        # Target
        target = job.target or "-"
        lines.append(f"[bold]Target:[/]  {self._trunc(target)}")

        # Job type
        lines.append(f"[bold]Type:[/]    {job.job_type}")

        lines.append("")

        # Findings — prefer live count from audit_status while running
        fc = job.findings_count
        if job.audit_status and job.audit_status.findings_count > fc:
            fc = job.audit_status.findings_count
        findings = str(fc) if fc > 0 else "-"
        lines.append(f"[bold]Finds:[/]   {findings}")

        # Cost
        cost_str = f"${job.cost_delta:.2f}" if job.cost_delta > 0 else "-"
        lines.append(f"[bold]Cost:[/]    {cost_str}")

        # LLM calls and cost from audit_status
        if job.audit_status:
            llm_calls = job.audit_status.llm_calls
            llm_cost = job.audit_status.llm_cost
            lines.append(f"[bold]LLM:[/]     {llm_calls} calls, ${llm_cost:.2f}")

        lines.append("")

        # Elapsed time
        elapsed = job.elapsed
        if elapsed is not None:
            minutes = int(elapsed) // 60
            seconds = int(elapsed) % 60
            lines.append(f"[bold]Elapsed:[/] {minutes}:{seconds:02d}")
        else:
            lines.append("[bold]Elapsed:[/] -")

        # Phase progress
        if job.audit_status:
            phase_idx = job.audit_status.phase_index
            phase_name = self._trunc(job.audit_status.phase.value, 18)
            lines.append(f"[bold]Phase:[/]   {phase_name} ({phase_idx}/{TOTAL_PHASES})")

        lines.append("")

        # Features
        if job.features:
            features_str = ", ".join(job.features)
            lines.append(f"[bold]Features:[/] {self._trunc(features_str)}")
        else:
            lines.append("[bold]Features:[/] -")

        # Error (only if present)
        if job.error:
            lines.append("")
            error_display = self._trunc(job.error)
            lines.append(f"[bold red]Error:[/] [red]{error_display}[/]")

        # Child jobs (for parallel audits)
        if job.child_job_ids:
            lines.append("")
            lines.append(f"[bold]Children:[/] {len(job.child_job_ids)} sub-jobs")

        return "\n".join(lines)

    @staticmethod
    def _format_status(status: JobStatus) -> str:
        """Return Rich-markup status string."""
        status_map = {
            JobStatus.COMPLETED: "[green bold]COMPLETED[/]",
            JobStatus.FAILED: "[red bold]FAILED[/]",
            JobStatus.CANCELLED: "[yellow bold]CANCELLED[/]",
            JobStatus.RUNNING: "[bold cyan]RUNNING[/]",
            JobStatus.QUEUED: "[dim]QUEUED[/]",
        }
        return status_map.get(status, str(status.value))

    # ── Actions ──────────────────────────────────────────────────

    def action_back(self) -> None:
        """Return to the main screen."""
        self.app.pop_screen()

    def action_cancel(self) -> None:
        """Cancel the running job after user confirmation."""
        jm = JobManager.get_instance()
        job = jm.get_job(self.job_id)

        if job is None or not job.is_active:
            self.notify("Job is not active.", severity="warning")
            return

        from cli.tui.dialogs.confirm import ConfirmDialog

        def _handle_cancel_result(confirmed: bool) -> None:
            if confirmed:
                JobManager.get_instance().cancel_job(self.job_id)
                self.notify(
                    f"Job '{job.display_name}' cancelled.",
                    severity="information",
                )
                # Force one last metadata refresh
                self._refresh()

        self.app.push_screen(
            ConfirmDialog(
                message=(
                    f"Cancel job [bold]{job.display_name}[/]?\n\n"
                    "The audit thread will be marked as cancelled."
                ),
            ),
            callback=_handle_cancel_result,
        )
