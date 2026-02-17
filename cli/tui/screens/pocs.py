"""
PoC Generation screen — async wizard to select a project, configure options,
and generate Foundry proof-of-concept exploit tests.

Ports the generate_pocs flow from cli/subflows.py to a Textual Screen
with dialog-based input.
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


class PoCScreen(Screen):
    """Wizard for generating Foundry PoC exploit tests."""

    BINDINGS = [
        Binding("escape", "go_back", "Back", show=True),
    ]

    def __init__(self, preselected_project: Optional[Dict[str, Any]] = None, **kwargs) -> None:
        super().__init__(**kwargs)
        self._preselected_project = preselected_project

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(
            "[bold cyan]Generate PoCs[/bold cyan]\n\nInitializing...",
            id="poc-status",
        )
        yield Footer()

    def on_mount(self) -> None:
        self.run_worker(self._wizard(), exclusive=True)

    # ── Project selection helper ──────────────────────────────────

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
                    "findings_count": r.get("total_vulnerabilities", 0),
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
        status = self.query_one("#poc-status", Static)

        # Step 1 — select project
        if self._preselected_project:
            project = self._preselected_project
        else:
            status.update(
                "[bold cyan]Generate PoCs[/bold cyan]\n\n"
                "Step 1: Select a project"
            )
            projects = self._load_projects()
            if not projects:
                status.update(
                    "[bold cyan]Generate PoCs[/bold cyan]\n\n"
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
                SelectDialog("Select project for PoC generation", choices)
            )
            if selected is None or selected == "Cancel":
                self.app.pop_screen()
                return

            idx = choices.index(selected)
            project = projects[idx]

        # Step 2 — scope selection (GitHub projects only)
        scope_id: Optional[int] = None
        if project.get("db") == "github":
            scopes = self._get_scopes_for_project(project["id"])
            if scopes:
                scope_choices = [
                    f"{s['scope_name'] or 'default'} (ID: {s['id']})"
                    for s in scopes
                ]
                scope_choices.append("All scopes")

                status.update(
                    f"[bold cyan]Generate PoCs[/bold cyan]\n\n"
                    f"[bold]Project:[/bold] {project['name']}\n"
                    f"Step 2: Select scope"
                )
                scope_sel = await self.app.push_screen_wait(
                    SelectDialog("Select scope", scope_choices)
                )
                if scope_sel is None:
                    self.app.pop_screen()
                    return
                if scope_sel != "All scopes":
                    idx = scope_choices.index(scope_sel)
                    scope_id = scopes[idx]["id"]

        # Step 3 — configure options
        status.update(
            f"[bold cyan]Generate PoCs[/bold cyan]\n\n"
            f"[bold]Project:[/bold] {project['name']}\n"
            f"Step 3: Configure options"
        )

        max_items_str = await self.app.push_screen_wait(
            TextInputDialog("Max items to generate", default="20")
        )
        if max_items_str is None:
            self.app.pop_screen()
            return
        try:
            max_items = int(max_items_str)
        except ValueError:
            max_items = 20

        severity = await self.app.push_screen_wait(
            SelectDialog(
                "Minimum severity",
                ["critical", "high", "medium", "low"],
            )
        )
        if severity is None:
            self.app.pop_screen()
            return

        consensus_only = await self.app.push_screen_wait(
            ConfirmDialog("Only consensus findings?")
        )
        if consensus_only is None:
            consensus_only = False

        # Step 4 — run generation
        status.update(
            f"[bold cyan]Generate PoCs[/bold cyan]\n\n"
            f"[bold]Project:[/bold]     {project['name']}\n"
            f"[bold]Max items:[/bold]   {max_items}\n"
            f"[bold]Min severity:[/bold] {severity}\n"
            f"[bold]Consensus only:[/bold] {'Yes' if consensus_only else 'No'}\n\n"
            f"[cyan]Generating PoCs (tests will auto-run after compilation)...[/cyan]"
        )

        if project.get("db") == "github":
            await self._generate_github_pocs(
                status, project, scope_id, max_items, severity, consensus_only
            )
        else:
            await self._generate_local_pocs(
                status, project, max_items, severity, consensus_only
            )

    async def _generate_github_pocs(
        self,
        status: Static,
        project: Dict[str, Any],
        scope_id: Optional[int],
        max_items: int,
        severity: str,
        consensus_only: bool,
    ) -> None:
        """Generate PoCs for a GitHub project as a background job."""
        from core.job_manager import JobManager
        from cli.audit_runner import AuditRunner

        jm = JobManager.get_instance()
        job = jm.create_job(
            display_name=f"PoC: {project['name']}",
            job_type="poc",
            target=str(project.get("source", "")),
        )
        runner = AuditRunner()
        runner.start_poc_generation(
            job_id=job.job_id,
            project_id=project["id"],
            scope_id=scope_id,
            max_items=max_items,
            min_severity=severity,
            only_consensus=consensus_only,
        )

        self.app.pop_screen()

    async def _generate_local_pocs(
        self,
        status: Static,
        project: Dict[str, Any],
        max_items: int,
        severity: str,
        consensus_only: bool,
    ) -> None:
        """Generate PoCs from local audit results JSON as a background job."""
        results_file = await self.app.push_screen_wait(
            TextInputDialog(
                "Path to results JSON (or leave blank to cancel)",
                default="",
            )
        )
        if not results_file:
            self.app.pop_screen()
            return

        out_dir = await self.app.push_screen_wait(
            TextInputDialog("Output directory", default="./output/pocs")
        )
        if out_dir is None:
            self.app.pop_screen()
            return
        out_dir = out_dir or "./output/pocs"

        from core.job_manager import JobManager
        from cli.audit_runner import AuditRunner

        jm = JobManager.get_instance()
        job = jm.create_job(
            display_name=f"PoC: {project['name']}",
            job_type="poc",
            target=results_file,
            output_dir=out_dir,
        )
        runner = AuditRunner()
        runner.start_poc_generation(
            job_id=job.job_id,
            from_results=results_file,
            out_dir=out_dir,
            max_items=max_items,
            min_severity=severity,
            only_consensus=consensus_only,
        )

        self.app.pop_screen()

    # ── Bindings ──────────────────────────────────────────────────

    def action_go_back(self) -> None:
        self.app.pop_screen()
