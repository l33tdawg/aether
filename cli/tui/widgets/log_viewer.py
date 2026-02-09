"""
Log viewer widget for the Aether v3.0 Textual TUI dashboard.

Displays live-scrolling log output for a selected audit job,
fetching new lines incrementally from the JobManager log buffer.
"""

from __future__ import annotations

from textual.reactive import reactive
from textual.widgets import RichLog

from core.job_manager import JobManager


class LogViewer(RichLog):
    """Scrolling log viewer that tails output for a specific job."""

    job_id: reactive[str | None] = reactive(None)

    def watch_job_id(self, old_value: str | None, new_value: str | None) -> None:
        """When job_id changes, clear the log and load existing lines."""
        self.clear()
        if new_value is not None:
            # Reset the read index by fetching all existing lines first
            jm = JobManager.get_instance()
            all_lines = jm.get_job_log(new_value)
            for line in all_lines:
                self.write(line)
            # Now consume those lines from the "new" cursor so refresh_log
            # doesn't re-emit them
            jm.get_new_job_log(new_value)

    def refresh_log(self) -> None:
        """Fetch and display new log lines for the current job."""
        if self.job_id is None:
            return

        jm = JobManager.get_instance()
        new_lines = jm.get_new_job_log(self.job_id)

        for line in new_lines:
            self.write(line)
