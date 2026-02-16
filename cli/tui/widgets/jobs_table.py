"""
Jobs table widget for the Aether v3.0 Textual TUI dashboard.

Displays all audit jobs in a DataTable with live-updating status,
phase progress, findings count, cost, and elapsed time.
"""

from __future__ import annotations

from textual.message import Message
from textual.widgets import DataTable

from core.job_manager import AuditJob, JobManager, JobStatus


class JobsTable(DataTable):
    """DataTable showing all audit jobs in the current session."""

    class JobSelected(Message):
        """Emitted when a job row is selected via Enter."""

        def __init__(self, job_id: str) -> None:
            super().__init__()
            self.job_id = job_id

    def on_mount(self) -> None:
        """Set up columns on mount."""
        self.add_columns("#", "Contract", "Type", "Status", "Phase", "Findings", "Cost", "Time")
        self.cursor_type = "row"
        self.zebra_stripes = True
        self._placeholder_visible = False

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Emit JobSelected message when user presses Enter on a row."""
        row_key = event.row_key
        if row_key is not None and str(row_key.value) != "__placeholder__":
            self.post_message(self.JobSelected(str(row_key.value)))

    def refresh_jobs(self) -> None:
        """Poll JobManager and update the table rows."""
        jm = JobManager.get_instance()
        jobs = jm.get_all_jobs()

        if not jobs:
            self._show_placeholder()
            return

        # Remove placeholder if it was showing
        if self._placeholder_visible:
            self._remove_placeholder()

        existing_keys = set(str(k.value) for k in self.rows)
        current_keys = set()

        for idx, job in enumerate(jobs, start=1):
            job_id = job.job_id
            current_keys.add(job_id)

            row_num = str(idx)
            contract = self._truncate(job.display_name, 30)
            job_type = self._format_type(job, jm)
            status = self._format_status(job)
            phase = self._format_phase(job)
            findings = self._format_findings(job, jm)
            cost = self._format_cost(job, jm)
            elapsed = self._format_time(job)

            cells = (row_num, contract, job_type, status, phase, findings, cost, elapsed)

            if job_id in existing_keys:
                # Update existing row cells in-place
                for col_idx, value in enumerate(cells):
                    col_key = list(self.columns.keys())[col_idx]
                    self.update_cell(job_id, col_key, value, update_width=True)
            else:
                # Add new row
                self.add_row(*cells, key=job_id)

        # Remove rows for jobs that no longer exist (shouldn't happen normally)
        stale_keys = existing_keys - current_keys
        for key in stale_keys:
            if key != "__placeholder__":
                self.remove_row(key)

    def _show_placeholder(self) -> None:
        """Show placeholder row when no jobs exist."""
        if self._placeholder_visible:
            return
        # Clear any existing rows
        self.clear()
        self.add_row(
            "",
            "[bold cyan]No jobs yet -- press n to start[/]",
            "", "", "", "", "", "",
            key="__placeholder__",
        )
        self._placeholder_visible = True

    def _remove_placeholder(self) -> None:
        """Remove the placeholder row."""
        try:
            self.remove_row("__placeholder__")
        except Exception:
            pass
        self._placeholder_visible = False

    @staticmethod
    def _truncate(text: str, max_len: int) -> str:
        if len(text) > max_len:
            return text[: max_len - 1] + "\u2026"
        return text

    @staticmethod
    def _format_type(job: AuditJob, jm: JobManager) -> str:
        """Format job type, showing Par(N) for parent jobs with children."""
        if job.child_job_ids:
            return f"Par({len(job.child_job_ids)})"
        return job.job_type

    @staticmethod
    def _format_status(job: AuditJob) -> str:
        status_map = {
            JobStatus.COMPLETED: "[green]DONE[/]",
            JobStatus.FAILED: "[red]FAILED[/]",
            JobStatus.CANCELLED: "[yellow]CANCEL[/]",
            JobStatus.RUNNING: "[bold cyan]RUNNING[/]",
            JobStatus.QUEUED: "[dim]QUEUED[/]",
        }
        return status_map.get(job.status, str(job.status.value))

    @staticmethod
    def _format_phase(job: AuditJob) -> str:
        if job.status == JobStatus.FAILED:
            error_text = job.error or "Unknown error"
            return f"[red]{error_text[:20]}[/]"
        if job.audit_status:
            return job.audit_status.phase.value
        return ""

    @staticmethod
    def _format_findings(job: AuditJob, jm: JobManager) -> str:
        """Format findings count; aggregate children for parent jobs."""
        if job.child_job_ids:
            children = jm.get_children(job.job_id)
            total = sum(
                max(c.findings_count,
                    c.audit_status.findings_count if c.audit_status else 0)
                for c in children
            )
            return str(total) if total > 0 else "-"
        fc = job.findings_count
        if job.audit_status and job.audit_status.findings_count > fc:
            fc = job.audit_status.findings_count
        return str(fc) if fc > 0 else "-"

    @staticmethod
    def _format_cost(job: AuditJob, jm: JobManager) -> str:
        """Format cost; aggregate children for parent jobs."""
        if job.child_job_ids:
            children = jm.get_children(job.job_id)
            total = sum(c.cost_delta for c in children)
        else:
            total = job.cost_delta
        if total > 0:
            return f"${total:.2f}"
        return "-"

    @staticmethod
    def _format_time(job: AuditJob) -> str:
        elapsed = job.elapsed
        if elapsed is None:
            return "-"
        minutes = int(elapsed) // 60
        seconds = int(elapsed) % 60
        return f"{minutes}:{seconds:02d}"
