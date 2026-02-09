"""
Reports screen — async wizard to select a project, choose scope and format,
and generate audit reports.

Ports the reports flow from cli/subflows.py to a Textual Screen with
dialog-based input.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import Footer, Header, Static

from cli.tui.dialogs.confirm import ConfirmDialog
from cli.tui.dialogs.select import SelectDialog
from cli.tui.dialogs.text_input import TextInputDialog


class ReportsScreen(Screen):
    """Wizard for generating audit reports in various formats."""

    BINDINGS = [
        Binding("escape", "go_back", "Back", show=True),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(
            "[bold cyan]Generate Reports[/bold cyan]\n\nInitializing...",
            id="reports-status",
        )
        yield Footer()

    def on_mount(self) -> None:
        self.run_worker(self._wizard(), exclusive=True)

    # ── Helpers ───────────────────────────────────────────────────

    def _load_projects(self) -> List[Dict[str, Any]]:
        """Load projects from both databases."""
        projects: List[Dict[str, Any]] = []

        # GitHub audit projects
        try:
            db_path = Path.home() / ".aether" / "aether_github_audit.db"
            if db_path.exists():
                conn = sqlite3.connect(str(db_path))
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT id, repo_name, url, owner, framework, created_at "
                    "FROM projects ORDER BY created_at DESC"
                ).fetchall()
                for r in rows:
                    projects.append({
                        "id": r["id"],
                        "name": r["repo_name"] or "Unknown",
                        "source": r["url"],
                        "date": str(r["created_at"] or "")[:10],
                        "db": "github",
                    })
                conn.close()
        except Exception:
            pass

        # Local audit results
        try:
            from core.database_manager import DatabaseManager
            db_manager = DatabaseManager()
            results = db_manager.get_audit_results(limit=50)
            for r in results:
                projects.append({
                    "id": r.get("id"),
                    "name": r.get("contract_name", r.get("contract_path", "Unknown")),
                    "source": r.get("contract_path", "local"),
                    "date": str(r.get("created_at", ""))[:10],
                    "db": "local",
                })
        except Exception:
            pass

        return projects

    def _get_scopes_for_project(self, project_id: int) -> List[Dict[str, Any]]:
        """Get all audit scopes for a GitHub project."""
        try:
            db_path = Path.home() / ".aether" / "aether_github_audit.db"
            if not db_path.exists():
                return []
            conn = sqlite3.connect(str(db_path))
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT id, scope_name, status, total_selected, total_audited "
                "FROM audit_scopes WHERE project_id = ? ORDER BY modified_at DESC",
                (project_id,),
            ).fetchall()
            scopes = [
                {
                    "id": r["id"],
                    "scope_name": r["scope_name"],
                    "status": r["status"],
                    "total_selected": r["total_selected"] or 0,
                    "total_audited": r["total_audited"] or 0,
                }
                for r in rows
            ]
            conn.close()
            return scopes
        except Exception:
            return []

    # ── Async wizard ──────────────────────────────────────────────

    async def _wizard(self) -> None:
        status = self.query_one("#reports-status", Static)

        # Step 1 — select project
        status.update(
            "[bold cyan]Generate Reports[/bold cyan]\n\n"
            "Step 1: Select a project"
        )
        projects = self._load_projects()
        if not projects:
            status.update(
                "[bold cyan]Generate Reports[/bold cyan]\n\n"
                "[yellow]No projects found. Run a New Audit first.[/yellow]"
            )
            return

        choices = []
        for p in projects:
            tag = "[GH]" if p.get("db") == "github" else "[Local]"
            date_str = p.get("date", "")
            choices.append(f"{tag} {p['name']}  ({date_str})")
        choices.append("Cancel")

        selected = await self.app.push_screen_wait(
            SelectDialog("Select project for report generation", choices)
        )
        if selected is None or selected == "Cancel":
            self.app.pop_screen()
            return

        idx = choices.index(selected)
        project = projects[idx]

        # For local projects, report generation is currently GitHub-only
        if project.get("db") != "github":
            status.update(
                "[bold cyan]Generate Reports[/bold cyan]\n\n"
                "[yellow]Report generation is currently supported for GitHub audit projects.[/yellow]"
            )
            await self.app.push_screen_wait(ConfirmDialog("Reports require a GitHub audit project.\n\nOK?"))
            self.app.pop_screen()
            return

        # Step 2 — scope selection
        scope_id: Optional[int] = None
        scopes = self._get_scopes_for_project(project["id"])
        if scopes:
            scope_choices = [
                f"{s['scope_name'] or 'default'} (ID: {s['id']})"
                for s in scopes
            ]
            scope_choices.append("All scopes (no filter)")

            status.update(
                f"[bold cyan]Generate Reports[/bold cyan]\n\n"
                f"[bold]Project:[/bold] {project['name']}\n"
                f"Step 2: Select scope"
            )
            scope_sel = await self.app.push_screen_wait(
                SelectDialog("Select scope", scope_choices)
            )
            if scope_sel is None:
                self.app.pop_screen()
                return
            if scope_sel != "All scopes (no filter)":
                idx = scope_choices.index(scope_sel)
                scope_id = scopes[idx]["id"]

        # Step 3 — report format
        status.update(
            f"[bold cyan]Generate Reports[/bold cyan]\n\n"
            f"[bold]Project:[/bold] {project['name']}\n"
            f"Step 3: Select report format"
        )
        fmt = await self.app.push_screen_wait(
            SelectDialog(
                "Report format",
                ["markdown", "json", "html", "all"],
            )
        )
        if fmt is None:
            self.app.pop_screen()
            return

        # Step 4 — output directory
        status.update(
            f"[bold cyan]Generate Reports[/bold cyan]\n\n"
            f"[bold]Project:[/bold] {project['name']}\n"
            f"[bold]Format:[/bold]  {fmt}\n"
            f"Step 4: Choose output directory"
        )
        output_dir = await self.app.push_screen_wait(
            TextInputDialog("Output directory", default="./output/reports")
        )
        if output_dir is None:
            self.app.pop_screen()
            return
        output_dir = output_dir or "./output/reports"

        # Launch report generation as a background job
        from core.job_manager import JobManager
        from cli.audit_runner import AuditRunner

        jm = JobManager.get_instance()
        job = jm.create_job(
            display_name=f"Report: {project['name']}",
            job_type="report",
            target=str(project.get("source", "")),
            output_dir=output_dir,
        )
        runner = AuditRunner()
        runner.start_report_generation(
            job_id=job.job_id,
            project_id=project["id"],
            scope_id=scope_id,
            output_dir=output_dir,
            fmt=fmt,
        )

        self.app.pop_screen()

    # ── Bindings ──────────────────────────────────────────────────

    def action_go_back(self) -> None:
        self.app.pop_screen()
