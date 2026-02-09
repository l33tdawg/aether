"""
Job detail screen for the Aether v3.0 Textual TUI.

Shows a live-updating view of a single audit job with log output,
phase progress, and metadata. Accessed by pressing Enter on a job
row in the MainScreen jobs table.
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
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
    }

    JobDetailScreen #log-panel {
        width: 70%;
        height: 100%;
        padding: 0 1 0 0;
    }

    JobDetailScreen #side-panel {
        width: 30%;
        height: 100%;
        padding: 0 0 0 1;
        border-left: tall $border;
    }

    JobDetailScreen #phase-bar {
        height: auto;
        margin-bottom: 1;
    }

    JobDetailScreen #metadata {
        height: auto;
        padding: 1;
        border: tall $border;
        background: $surface;
    }

    JobDetailScreen #metadata .meta-title {
        color: cyan;
        text-style: bold;
        margin-bottom: 1;
    }

    JobDetailScreen #metadata .meta-row {
        height: 1;
    }

    JobDetailScreen #metadata .meta-label {
        color: $text-muted;
    }

    JobDetailScreen #metadata .meta-value {
        color: $text;
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

        with Horizontal(id="detail-layout"):
            # Left panel: log viewer (70%)
            with Vertical(id="log-panel"):
                yield LogViewer(id="log-viewer", classes="log-viewer")

            # Right panel: phase bar + metadata (30%)
            with Vertical(id="side-panel"):
                yield PhaseBar(id="phase-bar")
                yield Static(self._build_metadata_text(job), id="metadata")

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

    def _build_metadata_text(self, job: AuditJob | None) -> str:
        """Build the Rich markup for the metadata panel."""
        if job is None:
            return "[dim]Job not found[/]"

        lines: list[str] = []
        lines.append("[bold cyan]Job Details[/]")
        lines.append("")

        # Status
        status_display = self._format_status(job.status)
        lines.append(f"[bold]Status:[/]   {status_display}")

        # Target
        target = job.target or "-"
        if len(target) > 35:
            target = "\u2026" + target[-34:]
        lines.append(f"[bold]Target:[/]   {target}")

        # Job type
        lines.append(f"[bold]Type:[/]     {job.job_type}")

        lines.append("")

        # Findings
        findings = str(job.findings_count) if job.findings_count > 0 else "-"
        lines.append(f"[bold]Findings:[/] {findings}")

        # Cost
        cost_str = f"${job.cost_delta:.2f}" if job.cost_delta > 0 else "-"
        lines.append(f"[bold]Cost:[/]     {cost_str}")

        # LLM calls and cost from audit_status
        if job.audit_status:
            llm_calls = job.audit_status.llm_calls
            llm_cost = job.audit_status.llm_cost
            lines.append(f"[bold]LLM Calls:[/] {llm_calls}")
            lines.append(f"[bold]LLM Cost:[/]  ${llm_cost:.2f}")

        lines.append("")

        # Elapsed time
        elapsed = job.elapsed
        if elapsed is not None:
            minutes = int(elapsed) // 60
            seconds = int(elapsed) % 60
            lines.append(f"[bold]Elapsed:[/]  {minutes}:{seconds:02d}")
        else:
            lines.append("[bold]Elapsed:[/]  -")

        # Phase progress
        if job.audit_status:
            phase_idx = job.audit_status.phase_index
            lines.append(f"[bold]Phase:[/]    {job.audit_status.phase.value} ({phase_idx}/{TOTAL_PHASES})")

        lines.append("")

        # Features
        if job.features:
            features_str = ", ".join(job.features)
            if len(features_str) > 35:
                features_str = features_str[:32] + "\u2026"
            lines.append(f"[bold]Features:[/] {features_str}")
        else:
            lines.append("[bold]Features:[/] -")

        # Error (only if present)
        if job.error:
            lines.append("")
            error_display = job.error
            if len(error_display) > 60:
                error_display = error_display[:57] + "\u2026"
            lines.append(f"[bold red]Error:[/]    [red]{error_display}[/]")

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
