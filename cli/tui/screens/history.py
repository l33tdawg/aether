"""
Audit History screen — displays completed audits from both SQLite databases.

Ports the audit_history flow from cli/subflows.py to a Textual Screen
with a DataTable and dialog-based submenu for actions.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Static

from cli.tui.dialogs.confirm import ConfirmDialog
from cli.tui.dialogs.select import SelectDialog


class HistoryScreen(Screen):
    """Displays audit history from both local and GitHub databases."""

    BINDINGS = [
        Binding("escape", "go_back", "Back", show=True),
        Binding("r", "refresh", "Refresh", show=True),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("[bold cyan]Audit History[/bold cyan]", id="history-title")
        yield DataTable(id="history-table")
        yield Footer()

    def on_mount(self) -> None:
        self._projects: List[Dict[str, Any]] = []
        table = self.query_one("#history-table", DataTable)
        table.cursor_type = "row"
        table.add_columns("Name", "Source", "Findings", "Date")
        self._load_data()

    # ── Data loading ──────────────────────────────────────────────

    def _load_data(self) -> None:
        """Load audit history from both databases and populate the table."""
        self._projects.clear()
        table = self.query_one("#history-table", DataTable)
        table.clear()

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
                    findings = self._get_findings_count(conn, r["id"])
                    self._projects.append({
                        "id": r["id"],
                        "name": r["repo_name"] or "Unknown",
                        "source": "GitHub",
                        "findings": findings,
                        "date": str(r["created_at"] or "")[:10],
                        "url": r["url"],
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
                self._projects.append({
                    "id": r.get("id"),
                    "name": r.get("contract_name", r.get("contract_path", "Unknown")),
                    "source": "Local",
                    "findings": r.get("total_vulnerabilities", 0),
                    "date": str(r.get("created_at", ""))[:10],
                    "db": "local",
                })
        except Exception:
            pass

        if not self._projects:
            title = self.query_one("#history-title", Static)
            title.update("[bold cyan]Audit History[/bold cyan]\n[yellow]No audit history found. Run a New Audit first.[/yellow]")
            return

        for p in self._projects:
            table.add_row(
                p["name"],
                p["source"],
                str(p["findings"]),
                p["date"],
            )

    @staticmethod
    def _get_findings_count(conn: sqlite3.Connection, project_id: int) -> int:
        """Count total findings for a GitHub project."""
        try:
            rows = conn.execute(
                "SELECT findings FROM analysis_results WHERE contract_id IN "
                "(SELECT id FROM contracts WHERE project_id = ?) AND status = 'success'",
                (project_id,),
            ).fetchall()
            count = 0
            for r in rows:
                raw = r["findings"] if isinstance(r, sqlite3.Row) else r[0]
                if raw:
                    try:
                        findings = json.loads(raw)
                        count += len(findings) if isinstance(findings, list) else 0
                    except (json.JSONDecodeError, TypeError):
                        pass
            return count
        except Exception:
            return 0

    @staticmethod
    def _get_scopes_for_project(project_id: int) -> List[Dict[str, Any]]:
        """Get all audit scopes for a GitHub project."""
        try:
            db_path = Path.home() / ".aether" / "aether_github_audit.db"
            if not db_path.exists():
                return []
            conn = sqlite3.connect(str(db_path))
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT id, scope_name, status, total_selected, total_audited, total_pending, "
                "created_at, modified_at FROM audit_scopes WHERE project_id = ? ORDER BY modified_at DESC",
                (project_id,),
            ).fetchall()
            scopes = [
                {
                    "id": r["id"],
                    "scope_name": r["scope_name"],
                    "status": r["status"],
                    "total_selected": r["total_selected"] or 0,
                    "total_audited": r["total_audited"] or 0,
                    "total_pending": r["total_pending"] or 0,
                    "created_at": r["created_at"] or "",
                    "modified_at": r["modified_at"] or "",
                }
                for r in rows
            ]
            conn.close()
            return scopes
        except Exception:
            return []

    # ── Row selection ─────────────────────────────────────────────

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """When a row is selected, open the submenu."""
        row_index = event.cursor_row
        if row_index < 0 or row_index >= len(self._projects):
            return
        project = self._projects[row_index]
        self.run_worker(self._show_submenu(project), exclusive=True)

    async def _show_submenu(self, project: Dict[str, Any]) -> None:
        """Show an action submenu for the selected project."""
        action = await self.app.push_screen_wait(
            SelectDialog(
                f"{project['name']} ({project['source']})",
                ["View Details", "Generate PoCs", "Re-audit", "Back"],
            )
        )
        if action is None or action == "Back":
            return

        if action == "View Details":
            await self._view_details(project)
        elif action == "Generate PoCs":
            await self._generate_pocs(project)
        elif action == "Re-audit":
            await self._re_audit(project)

    async def _view_details(self, project: Dict[str, Any]) -> None:
        """Display project details inline or as scopes table."""
        if project.get("db") == "github":
            scopes = self._get_scopes_for_project(project["id"])
            if not scopes:
                await self.app.push_screen_wait(
                    ConfirmDialog("No scopes found for this project.\n\nOK?")
                )
                return

            lines = [f"[bold]Scopes for {project['name']}[/bold]\n"]
            for s in scopes:
                total = s["total_selected"] or 0
                done = s["total_audited"] or 0
                status_tag = "[green]" if s["status"] == "completed" else "[yellow]"
                lines.append(
                    f"  {s['scope_name'] or 'default':24s}  "
                    f"{status_tag}{s['status']}[/]  "
                    f"{done}/{total} audited  "
                    f"({str(s['created_at'] or '')[:10]})"
                )

            detail_text = "\n".join(lines)
            title = self.query_one("#history-title", Static)
            title.update(f"[bold cyan]Audit History[/bold cyan]\n\n{detail_text}")
        else:
            detail_text = (
                f"[bold]ID:[/bold]       {project['id']}\n"
                f"[bold]Name:[/bold]     {project['name']}\n"
                f"[bold]Findings:[/bold] {project.get('findings', 0)}\n"
                f"[bold]Date:[/bold]     {project.get('date', '')}"
            )
            title = self.query_one("#history-title", Static)
            title.update(f"[bold cyan]Audit History[/bold cyan]\n\n{detail_text}")

    async def _generate_pocs(self, project: Dict[str, Any]) -> None:
        """Redirect to PoC generation for this project."""
        from cli.tui.screens.pocs import PoCScreen

        self.app.pop_screen()
        self.app.push_screen(PoCScreen(preselected_project=project))

    async def _re_audit(self, project: Dict[str, Any]) -> None:
        """Re-audit the selected project."""
        if project.get("db") == "github":
            url = project.get("url", "")
            if not url:
                await self.app.push_screen_wait(
                    ConfirmDialog("No URL found for this project.\n\nOK?")
                )
                return

            confirmed = await self.app.push_screen_wait(
                ConfirmDialog(f"Re-audit {project['name']}?")
            )
            if not confirmed:
                return

            from cli.tui.github_audit_helper import GitHubAuditHelper

            helper = GitHubAuditHelper()

            # Get contracts from DB (no clone needed for re-audit)
            contracts_raw = helper.get_contracts_for_project(project["id"])
            contracts = []
            for c in contracts_raw:
                contracts.append({
                    "contract_name": c.get("contract_name", c.get("file_path", "Unknown")),
                    "file_path": c.get("file_path", ""),
                })

            if not contracts:
                await self.app.push_screen_wait(
                    ConfirmDialog("No contracts found for this project.\n\nOK?")
                )
                return

            # Choose selection method
            repo_dir = helper.get_repo_dir(project["id"])
            method = await self.app.push_screen_wait(
                SelectDialog(
                    f"Select contracts from {project['name']} ({len(contracts)} found)",
                    [
                        "Auto-Discover (scan & rank)",
                        "Manual selection (show all)",
                    ],
                )
            )
            if method is None:
                return

            if method == "Auto-Discover (scan & rank)" and repo_dir:
                import asyncio
                from pathlib import Path as _Path
                from core.contract_scanner import ContractScanner
                from cli.tui.dialogs.discovery_results import DiscoveryResultsDialog

                scanner = ContractScanner()
                try:
                    loop = asyncio.get_event_loop()
                    report = await loop.run_in_executor(
                        None, scanner.scan_directory, _Path(repo_dir)
                    )
                except Exception as e:
                    await self.app.push_screen_wait(
                        ConfirmDialog(f"Scan failed: {e}\n\nOK?")
                    )
                    return

                if not report.results:
                    await self.app.push_screen_wait(
                        ConfirmDialog("No contracts found after scanning.\n\nOK?")
                    )
                    return

                discovered_paths = await self.app.push_screen_wait(
                    DiscoveryResultsDialog(report)
                )
                if discovered_paths is None or len(discovered_paths) == 0:
                    return
                selected_paths = [str(p) for p in discovered_paths]
            else:
                # Manual selection flow
                from cli.tui.dialogs.contract_selector import ContractSelectorDialog

                audited_paths = helper.get_previously_audited_paths(project["id"])
                audited_indices = [
                    i for i, c in enumerate(contracts)
                    if c.get("file_path") in audited_paths
                ]

                selected_indices = await self.app.push_screen_wait(
                    ContractSelectorDialog(
                        contracts=contracts,
                        pre_selected=list(range(len(contracts))),
                        previously_audited_indices=audited_indices,
                    )
                )
                if selected_indices is None or len(selected_indices) == 0:
                    return

                selected_paths = [contracts[i]["file_path"] for i in selected_indices]

            scope_id = helper.save_new_scope(project["id"], selected_paths)

            # Launch as background job
            from core.job_manager import JobManager
            from cli.audit_runner import AuditRunner

            jm = JobManager.get_instance()
            job = jm.create_job(
                display_name=f"GH: {project['name']}",
                job_type="github",
                target=url,
            )
            runner = AuditRunner()
            runner.start_github_audit(
                job_id=job.job_id,
                github_url=url,
                project_id=project["id"],
                scope_id=scope_id,
                fresh=True,
                reanalyze=True,
            )

            self.app.pop_screen()
        else:
            await self.app.push_screen_wait(
                ConfirmDialog(
                    "Re-audit for local projects:\nRun a New Audit on the same path.\n\nOK?"
                )
            )

    # ── Bindings ──────────────────────────────────────────────────

    def action_go_back(self) -> None:
        self.app.pop_screen()

    def action_refresh(self) -> None:
        self._load_data()
