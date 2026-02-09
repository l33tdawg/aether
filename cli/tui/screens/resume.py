"""
Resume Audit screen — shows active audit scopes from the GitHub audit DB
and allows the user to resume an in-progress audit.

Ports the resume_audit flow from cli/subflows.py to a Textual Screen
with a DataTable.  Resumes are launched as background jobs via AuditRunner.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Dict, List

from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Static

from cli.tui.dialogs.confirm import ConfirmDialog


class ResumeScreen(Screen):
    """Displays active (in-progress) audit scopes and allows resuming."""

    BINDINGS = [
        Binding("escape", "go_back", "Back", show=True),
        Binding("r", "refresh", "Refresh", show=True),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("[bold cyan]Resume Audit[/bold cyan]", id="resume-title")
        yield DataTable(id="resume-table")
        yield Footer()

    def on_mount(self) -> None:
        self._active_items: List[Dict[str, Any]] = []
        table = self.query_one("#resume-table", DataTable)
        table.cursor_type = "row"
        table.add_columns("Project", "Scope", "Progress", "Last Updated")
        self._load_data()

    # ── Data loading ──────────────────────────────────────────────

    def _load_data(self) -> None:
        """Query active audit scopes from the GitHub audit database."""
        self._active_items.clear()
        table = self.query_one("#resume-table", DataTable)
        table.clear()

        try:
            db_path = Path.home() / ".aether" / "aether_github_audit.db"
            if not db_path.exists():
                self._show_empty()
                return

            conn = sqlite3.connect(str(db_path))
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT s.id AS scope_id, s.project_id, s.scope_name, s.status, "
                "s.total_selected, s.total_audited, s.modified_at, "
                "p.repo_name, p.url "
                "FROM audit_scopes s JOIN projects p ON s.project_id = p.id "
                "WHERE s.status = 'active' ORDER BY s.modified_at DESC"
            ).fetchall()
            for r in rows:
                self._active_items.append(dict(r))
            conn.close()
        except Exception as e:
            title = self.query_one("#resume-title", Static)
            title.update(f"[bold cyan]Resume Audit[/bold cyan]\n[red]Database error: {e}[/red]")
            return

        if not self._active_items:
            self._show_empty()
            return

        for item in self._active_items:
            total = item.get("total_selected") or 0
            done = item.get("total_audited") or 0
            progress_str = f"{done}/{total}" if total else "?"
            date_str = str(item.get("modified_at", ""))[:16]
            table.add_row(
                item.get("repo_name", "Unknown"),
                item.get("scope_name", "default"),
                progress_str,
                date_str,
            )

    def _show_empty(self) -> None:
        title = self.query_one("#resume-title", Static)
        title.update(
            "[bold cyan]Resume Audit[/bold cyan]\n"
            "[yellow]No audits in progress. Start a New Audit first.[/yellow]"
        )

    # ── Row selection ─────────────────────────────────────────────

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """When a row is selected, resume that audit."""
        row_index = event.cursor_row
        if row_index < 0 or row_index >= len(self._active_items):
            return
        selected = self._active_items[row_index]
        self.run_worker(self._resume_audit(selected), exclusive=True)

    async def _resume_audit(self, item: Dict[str, Any]) -> None:
        """Resume an audit as a background job."""
        github_url = item.get("url", "")
        repo_name = item.get("repo_name", "Unknown")
        scope_id = item.get("scope_id")
        project_id = item.get("project_id")

        if not github_url:
            await self.app.push_screen_wait(
                ConfirmDialog("No URL found for this project.\n\nOK?")
            )
            return

        # Verify pending work exists
        from cli.tui.github_audit_helper import GitHubAuditHelper
        helper = GitHubAuditHelper()
        pending = helper.get_pending_contracts(scope_id) if scope_id else []

        if not pending:
            await self.app.push_screen_wait(
                ConfirmDialog(
                    f"No pending contracts found for {repo_name}.\n\n"
                    "The scope may already be complete."
                )
            )
            self._load_data()
            return

        confirmed = await self.app.push_screen_wait(
            ConfirmDialog(
                f"Resume audit for {repo_name}?\n\n"
                f"{len(pending)} contracts remaining."
            )
        )
        if not confirmed:
            return

        # Launch as background job
        from core.job_manager import JobManager
        from cli.audit_runner import AuditRunner

        jm = JobManager.get_instance()
        job = jm.create_job(
            display_name=f"GH: {repo_name}",
            job_type="github",
            target=github_url,
        )
        runner = AuditRunner()
        runner.start_github_audit(
            job_id=job.job_id,
            github_url=github_url,
            project_id=project_id,
            scope_id=scope_id,
        )

        self.app.pop_screen()

    # ── Bindings ──────────────────────────────────────────────────

    def action_go_back(self) -> None:
        self.app.pop_screen()

    def action_refresh(self) -> None:
        self._load_data()
