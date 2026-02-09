"""
Interactive menu-driven TUI for Aether.

Provides a guided experience for all Aether operations without requiring
memorization of CLI flags. Launch via `python aether.py`.
"""

import asyncio
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
import questionary
from questionary import Choice, Separator, Style

# Questionary style matching setup.py theme
custom_style = Style([
    ('qmark', 'fg:#00d7ff bold'),
    ('question', 'bold'),
    ('answer', 'fg:#00d7ff bold'),
    ('pointer', 'fg:#00d7ff bold'),
    ('highlighted', 'fg:#00d7ff bold'),
    ('selected', 'fg:#00d7ff'),
    ('separator', 'fg:#666666'),
    ('instruction', ''),
    ('text', ''),
])


def _select(prompt_text: str, choices: list, default: Optional[str] = None) -> Optional[str]:
    """Arrow-key selector wrapping questionary.select."""
    try:
        # Build list of valid default candidates (string choices and Choice values)
        valid_defaults = []
        for c in choices:
            if isinstance(c, str):
                valid_defaults.append(c)
            elif isinstance(c, questionary.Choice):
                valid_defaults.append(c.value)
        resolved_default = default if default in valid_defaults else (valid_defaults[0] if valid_defaults else None)

        result = questionary.select(
            prompt_text,
            choices=choices,
            default=resolved_default,
            style=custom_style,
            use_shortcuts=False,
            use_arrow_keys=True,
            use_jk_keys=False,
        ).ask()
        return result
    except (KeyboardInterrupt, EOFError):
        return None


def _checkbox(prompt_text: str, choices: List[questionary.Choice]) -> Optional[List[str]]:
    """Arrow-key multi-select wrapping questionary.checkbox."""
    try:
        result = questionary.checkbox(
            prompt_text,
            choices=choices,
            style=custom_style,
        ).ask()
        return result
    except (KeyboardInterrupt, EOFError):
        return None


class AetherInteractiveMenu:
    """Menu-driven interactive TUI for Aether."""

    VERSION = "2.0.0"

    BANNER = r"""
[bold cyan]╔══════════════════════════════════════════════════════════════╗
║               A E T H E R   v 2 . 0                          ║
║      Smart Contract Security Analysis Framework              ║
╚══════════════════════════════════════════════════════════════╝[/bold cyan]
"""

    MENU_ITEMS = [
        ("1", "\U0001f6e1  New Audit",      "Start a new security audit"),
        ("2", "\u23ef  Resume Audit",    "Continue an in-progress audit"),
        ("3", "\U0001f4dc  Audit History",   "Browse past audits & results"),
        ("4", "\U0001f9ea  Generate PoCs",   "Create Foundry exploit proofs"),
        ("5", "\U0001f4ca  Reports",         "Generate/view audit reports"),
        ("6", "\U0001f310  Fetch Contract",  "Fetch from blockchain explorers"),
        ("7", "\u2699\ufe0f  Settings",        "Configure API keys, models, tools"),
        ("8", "\U0001f4bb  Console",         "Launch advanced Metasploit-style console"),
        ("0", "\U0001f6aa  Exit",            ""),
    ]

    def __init__(self):
        self.console = Console()
        # Lazy-loaded heavy objects
        self._cli = None
        self._aether_db = None
        self._db_manager = None
        self._config_manager = None

    # ── Lazy properties ───────────────────────────────────────────

    @property
    def cli(self):
        if self._cli is None:
            from cli.main import AetherCLI
            self._cli = AetherCLI()
        return self._cli

    @property
    def aether_db(self):
        if self._aether_db is None:
            from core.database_manager import AetherDatabase
            self._aether_db = AetherDatabase()
        return self._aether_db

    @property
    def db_manager(self):
        if self._db_manager is None:
            from core.database_manager import DatabaseManager
            self._db_manager = DatabaseManager()
        return self._db_manager

    @property
    def config_manager(self):
        if self._config_manager is None:
            from core.config_manager import ConfigManager
            self._config_manager = ConfigManager()
        return self._config_manager

    # ── Main loop ─────────────────────────────────────────────────

    def run(self):
        """Main menu loop."""
        self._show_banner()
        self._check_first_run()

        # Build questionary Choice list once
        menu_choices = []
        for key, label, desc in self.MENU_ITEMS:
            if key == "0":
                menu_choices.append(Separator("  ──────────────────────────────────"))
                menu_choices.append(Choice(title=f"{label}", value=key))
            else:
                menu_choices.append(Choice(title=f"{label:<22s} {desc}", value=key))

        while True:
            try:
                self.console.print()
                choice = _select("Select an option", menu_choices, default="1")

                if choice is None or choice == "0":
                    self.console.print("\n[bold cyan]Goodbye![/bold cyan]")
                    break

                handler = {
                    "1": self._handle_new_audit,
                    "2": self._handle_resume_audit,
                    "3": self._handle_audit_history,
                    "4": self._handle_generate_pocs,
                    "5": self._handle_reports,
                    "6": self._handle_fetch_contract,
                    "7": self._handle_settings,
                    "8": self._handle_console,
                }.get(choice)

                if handler:
                    handler()

            except KeyboardInterrupt:
                self.console.print("\n[yellow]Interrupted — returning to menu[/yellow]")
                continue
            except EOFError:
                self.console.print("\n[bold cyan]Goodbye![/bold cyan]")
                break

    def _show_banner(self):
        self.console.print(self.BANNER)

    def _check_first_run(self):
        """Hint at Settings if no config exists."""
        config_file = Path.home() / ".aether" / "config.yaml"
        if not config_file.exists():
            self.console.print(
                Panel(
                    "[yellow]No configuration found. Select [bold][7] Settings[/bold] to run the setup wizard.[/yellow]",
                    border_style="yellow",
                )
            )

    # ── Helpers ───────────────────────────────────────────────────

    def _select_project(self, prompt: str = "Select a project") -> Optional[Dict[str, Any]]:
        """Unified project selector across both databases. Returns project dict or None."""
        projects = []

        # GitHub audit projects (AetherDatabase)
        try:
            import sqlite3
            db_path = Path.home() / ".aether" / "aether_github_audit.db"
            if db_path.exists():
                conn = sqlite3.connect(db_path)
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT id, repo_name, url, owner, framework, created_at FROM projects ORDER BY created_at DESC"
                ).fetchall()
                for r in rows:
                    projects.append({
                        "id": r["id"],
                        "name": r["repo_name"],
                        "source": r["url"],
                        "owner": r["owner"],
                        "framework": r["framework"] or "",
                        "date": r["created_at"] or "",
                        "db": "github",
                    })
                conn.close()
        except Exception:
            pass

        # Local audit results (DatabaseManager)
        try:
            results = self.db_manager.get_audit_results(limit=50)
            for r in results:
                projects.append({
                    "id": r.get("id"),
                    "name": r.get("name", r.get("contract_path", "Unknown")),
                    "source": r.get("contract_path", "local"),
                    "date": r.get("created_at", ""),
                    "db": "local",
                    "findings_count": r.get("total_findings", 0),
                })
        except Exception:
            pass

        if not projects:
            self.console.print("[yellow]No projects found. Run a New Audit first.[/yellow]")
            return None

        # Build display choices
        choices = []
        for i, p in enumerate(projects):
            tag = "[GH]" if p.get("db") == "github" else "[Local]"
            name = p["name"] or "Unknown"
            date_str = str(p.get("date", ""))[:10]
            choices.append(f"{tag} {name}  ({date_str})")
        choices.append("Cancel")

        selected = _select(prompt, choices)
        if selected is None or selected == "Cancel":
            return None

        idx = choices.index(selected)
        return projects[idx]

    def _get_scopes_for_project(self, project_id: int) -> List[Dict[str, Any]]:
        """Get all audit scopes for a GitHub project."""
        try:
            import sqlite3, json
            db_path = Path.home() / ".aether" / "aether_github_audit.db"
            if not db_path.exists():
                return []
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT id, scope_name, status, total_selected, total_audited, total_pending, "
                "created_at, modified_at FROM audit_scopes WHERE project_id = ? ORDER BY modified_at DESC",
                (project_id,),
            ).fetchall()
            scopes = []
            for r in rows:
                scopes.append({
                    "id": r["id"],
                    "scope_name": r["scope_name"],
                    "status": r["status"],
                    "total_selected": r["total_selected"] or 0,
                    "total_audited": r["total_audited"] or 0,
                    "total_pending": r["total_pending"] or 0,
                    "created_at": r["created_at"] or "",
                    "modified_at": r["modified_at"] or "",
                })
            conn.close()
            return scopes
        except Exception:
            return []

    def _get_findings_count(self, project_id: int) -> int:
        """Count total findings for a GitHub project."""
        try:
            import sqlite3, json
            db_path = Path.home() / ".aether" / "aether_github_audit.db"
            if not db_path.exists():
                return 0
            conn = sqlite3.connect(db_path)
            rows = conn.execute(
                "SELECT findings FROM analysis_results WHERE contract_id IN "
                "(SELECT id FROM contracts WHERE project_id = ?) AND status = 'success'",
                (project_id,),
            ).fetchall()
            count = 0
            for r in rows:
                if r[0]:
                    try:
                        findings = json.loads(r[0])
                        count += len(findings) if isinstance(findings, list) else 0
                    except (json.JSONDecodeError, TypeError):
                        pass
            conn.close()
            return count
        except Exception:
            return 0

    # ── [1] New Audit ─────────────────────────────────────────────

    def _handle_new_audit(self):
        self.console.print("\n[bold cyan]── New Audit ──[/bold cyan]\n")

        # Step 1: Source type
        source_type = _select(
            "Audit source",
            ["Local file or directory", "GitHub URL", "Block explorer URL / address", "Cancel"],
        )
        if source_type is None or source_type == "Cancel":
            return

        # Step 2: Target input
        if source_type == "Local file or directory":
            target = self._prompt_local_target()
        elif source_type == "GitHub URL":
            target = self._prompt_github_target()
        else:
            target = self._prompt_explorer_target()

        if not target:
            return

        # Step 3: Feature selection (for local/github audits)
        if source_type in ("Local file or directory", "Block explorer URL / address"):
            features = self._prompt_audit_features()
            if features is None:
                return
            output_dir = Prompt.ask("Output directory", default="./output")

            # Step 3b: Contract picker for directories with multiple .sol files
            target_path = Path(target)
            sol_files = []
            if target_path.is_dir():
                sol_files = sorted(target_path.rglob("*.sol"))

            use_parallel = False
            selected_paths = []

            if len(sol_files) >= 2:
                selected_paths = self._prompt_contract_selection(sol_files, target_path)
                if selected_paths is None:
                    return
                if len(selected_paths) == 0:
                    self.console.print("[yellow]No contracts selected.[/yellow]")
                    return
                if len(selected_paths) > 1:
                    use_parallel = Confirm.ask(
                        f"Run {len(selected_paths)} contracts in parallel?",
                        default=True,
                    )

            # Confirm
            self.console.print(f"\n[bold]Target:[/bold]  {target}")
            if selected_paths:
                self.console.print(f"[bold]Contracts:[/bold] {len(selected_paths)} selected")
            self.console.print(f"[bold]Features:[/bold] {', '.join(features) if features else 'default'}")
            self.console.print(f"[bold]Output:[/bold]  {output_dir}")
            if use_parallel:
                self.console.print("[bold]Mode:[/bold]   Parallel")
            if not Confirm.ask("\nStart audit?", default=True):
                return

            if use_parallel and len(selected_paths) > 1:
                self._run_parallel_audit(
                    [str(p) for p in selected_paths], features, output_dir
                )
            elif len(selected_paths) == 1:
                self._run_local_audit(str(selected_paths[0]), features, output_dir)
            elif selected_paths:
                # Multiple selected but user declined parallel — run sequentially
                for p in selected_paths:
                    self.console.print(f"\n[cyan]Auditing {p.name}...[/cyan]")
                    self._run_local_audit(str(p), features, output_dir)
            else:
                # Original behavior: single file or directory as-is
                self._run_local_audit(target, features, output_dir)

        elif source_type == "GitHub URL":
            features = self._prompt_github_features()
            output_dir = Prompt.ask("Output directory (optional, press Enter to skip)", default="")

            self.console.print(f"\n[bold]Repository:[/bold]  {target}")
            if not Confirm.ask("\nStart audit?", default=True):
                return

            self._run_github_audit(target, output_dir or None)

    def _prompt_local_target(self) -> Optional[str]:
        try:
            path = Prompt.ask("Path to Solidity file or directory")
        except (KeyboardInterrupt, EOFError):
            return None
        if not path:
            return None
        resolved = Path(path).expanduser().resolve()
        if not resolved.exists():
            self.console.print(f"[red]Path not found: {resolved}[/red]")
            return None
        return str(resolved)

    def _prompt_github_target(self) -> Optional[str]:
        try:
            url = Prompt.ask("GitHub repository URL")
        except (KeyboardInterrupt, EOFError):
            return None
        if not url or "github.com" not in url.lower():
            self.console.print("[red]Please enter a valid GitHub URL.[/red]")
            return None
        return url

    def _prompt_explorer_target(self) -> Optional[str]:
        """Prompt for block explorer URL or address, fetch & return local path."""
        try:
            url_or_addr = Prompt.ask("Block explorer URL or contract address")
        except (KeyboardInterrupt, EOFError):
            return None
        if not url_or_addr:
            return None

        from core.etherscan_fetcher import EtherscanFetcher

        fetcher = EtherscanFetcher(self.config_manager)
        network, address = fetcher.parse_explorer_url(url_or_addr)
        if not address:
            self.console.print("[red]Could not parse address from input.[/red]")
            return None

        if network and network != fetcher.current_network:
            fetcher.set_network(network)

        self.console.print(f"[cyan]Fetching contract {address} from {network or 'ethereum'}...[/cyan]")
        result = fetcher.fetch_contract_source(address, network)
        if not result.get("success"):
            self.console.print(f"[red]Fetch failed: {result.get('error', 'Unknown error')}[/red]")
            return None

        save_path = fetcher.save_contract_source(result)
        self.console.print(f"[green]Contract saved to: {save_path}[/green]")
        return save_path

    def _prompt_audit_features(self) -> Optional[List[str]]:
        result = _checkbox(
            "Select audit features",
            [
                questionary.Choice("Enhanced analysis", value="enhanced", checked=True),
                questionary.Choice("AI Ensemble (multi-model consensus)", value="ai_ensemble", checked=True),
                questionary.Choice("LLM Validation (false-positive reduction)", value="llm_validation", checked=True),
                questionary.Choice("Foundry PoC generation", value="foundry", checked=False),
                questionary.Choice("Enhanced Reports", value="enhanced_reports", checked=False),
            ],
        )
        return result

    def _prompt_github_features(self) -> Optional[List[str]]:
        """Minimal feature selection for GitHub audits (handled by GitHubAuditor)."""
        return []

    def _run_local_audit(self, target: str, features: List[str], output_dir: str):
        try:
            from core.audit_dashboard import SingleAuditDashboard
            from core.post_audit_summary import PostAuditSummary

            dashboard = SingleAuditDashboard()
            dashboard.run_audit_with_dashboard(
                audit_fn=self.cli.run_audit,
                contract_path=target,
                output_dir=output_dir,
                enhanced="enhanced" in features,
                ai_ensemble="ai_ensemble" in features,
                llm_validation="llm_validation" in features,
                foundry="foundry" in features,
                enhanced_reports="enhanced_reports" in features,
            )
            status = dashboard.get_status()
            if status:
                PostAuditSummary.render(
                    self.console, [status], status.elapsed or 0
                )
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Audit interrupted.[/yellow]")
        except Exception as e:
            self.console.print(f"\n[red]Audit error: {e}[/red]")

    def _prompt_contract_selection(
        self, sol_files: List[Path], base_dir: Path
    ) -> Optional[List[Path]]:
        """Show a checkbox picker for .sol files in a directory."""
        choices = []
        for f in sol_files:
            try:
                rel = f.relative_to(base_dir)
            except ValueError:
                rel = f.name
            choices.append(
                questionary.Choice(
                    title=f"{f.stem}  ({rel})",
                    value=str(f),
                    checked=True,
                )
            )

        self.console.print(
            f"\n[bold]Found {len(sol_files)} Solidity files in directory:[/bold]"
        )
        selected = _checkbox("Select contracts to audit", choices)
        if selected is None:
            return None
        return [Path(p) for p in selected]

    def _run_parallel_audit(
        self, contract_paths: List[str], features: List[str], output_dir: str
    ):
        """Launch parallel audits with a live dashboard."""
        try:
            from core.parallel_audit_manager import ParallelAuditManager
            from core.config_manager import ConfigManager

            # Read max_concurrent_contracts from config
            try:
                cfg = ConfigManager()
                max_workers = min(cfg.config.max_concurrent_contracts, len(contract_paths), 8)
            except Exception:
                max_workers = min(5, len(contract_paths))

            manager = ParallelAuditManager(max_workers=max_workers)

            self.console.print(
                f"\n[bold cyan]Starting parallel audit of {len(contract_paths)} contracts "
                f"({max_workers} workers)...[/bold cyan]\n"
            )

            os.makedirs(output_dir, exist_ok=True)
            manager.run_parallel_audits(contract_paths, features, output_dir)

            # Post-run summary
            summary = manager.get_summary()
            self.console.print()

            if summary["completed"]:
                table = Table(title="Audit Summary", show_header=True, header_style="bold green")
                table.add_column("Contract", style="bold")
                table.add_column("Findings", justify="right", style="yellow")
                table.add_column("Time", justify="right")
                table.add_column("Output")

                for c in summary["completed"]:
                    elapsed = c.get("elapsed")
                    if elapsed is not None:
                        mins, secs = divmod(int(elapsed), 60)
                        time_str = f"{mins}:{secs:02d}"
                    else:
                        time_str = "-"
                    table.add_row(
                        c["contract"],
                        str(c["findings"]),
                        time_str,
                        c.get("output_dir", ""),
                    )
                self.console.print(table)

            if summary["failed"]:
                self.console.print("\n[bold red]Failed audits:[/bold red]")
                for f in summary["failed"]:
                    self.console.print(
                        f"  [red]{f['contract']}[/red]: {f.get('error', 'Unknown error')}"
                    )

            total = summary["total_contracts"]
            ok = len(summary["completed"])
            self.console.print(
                f"\n[bold]{ok}/{total} contracts audited successfully, "
                f"{summary['total_findings']} total findings[/bold]"
            )
            if summary.get("wall_time"):
                mins, secs = divmod(int(summary["wall_time"]), 60)
                self.console.print(f"[dim]Wall time: {mins}:{secs:02d}[/dim]")

            # Post-audit LLM cost summary
            from core.post_audit_summary import PostAuditSummary
            PostAuditSummary.render(
                self.console,
                list(manager._statuses.values()),
                summary.get("wall_time", 0),
            )

        except KeyboardInterrupt:
            self.console.print("\n[yellow]Parallel audit interrupted.[/yellow]")
        except Exception as e:
            self.console.print(f"\n[red]Parallel audit error: {e}[/red]")

    def _run_github_audit(self, github_url: str, output: Optional[str] = None):
        try:
            self.cli.run_github_audit_command(
                github_url=github_url,
                output=output,
                interactive_scope=True,
            )
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Audit interrupted.[/yellow]")
        except Exception as e:
            self.console.print(f"\n[red]Audit error: {e}[/red]")

    # ── [2] Resume Audit ──────────────────────────────────────────

    def _handle_resume_audit(self):
        self.console.print("\n[bold cyan]── Resume Audit ──[/bold cyan]\n")

        # Find active scopes across all projects
        active_items = []
        try:
            import sqlite3, json
            db_path = Path.home() / ".aether" / "aether_github_audit.db"
            if not db_path.exists():
                self.console.print("[yellow]No audit history found.[/yellow]")
                return

            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT s.id as scope_id, s.project_id, s.scope_name, s.status, "
                "s.total_selected, s.total_audited, s.modified_at, p.repo_name, p.url "
                "FROM audit_scopes s JOIN projects p ON s.project_id = p.id "
                "WHERE s.status = 'active' ORDER BY s.modified_at DESC"
            ).fetchall()
            for r in rows:
                active_items.append(dict(r))
            conn.close()
        except Exception as e:
            self.console.print(f"[red]Database error: {e}[/red]")
            return

        if not active_items:
            self.console.print("[yellow]No audits in progress. Start a New Audit first.[/yellow]")
            return

        # Show table
        table = Table(title="Active Audits")
        table.add_column("#", style="cyan", width=4)
        table.add_column("Project", style="bold")
        table.add_column("Scope", style="white")
        table.add_column("Progress", style="green")
        table.add_column("Last Updated", style="dim")

        for i, item in enumerate(active_items, 1):
            total = item.get("total_selected") or 0
            done = item.get("total_audited") or 0
            progress_str = f"{done}/{total}" if total else "?"
            date_str = str(item.get("modified_at", ""))[:16]
            table.add_row(
                str(i),
                item.get("repo_name", "Unknown"),
                item.get("scope_name", "default"),
                progress_str,
                date_str,
            )
        self.console.print(table)

        # Select via arrow-key navigation
        resume_choices = []
        for i, item in enumerate(active_items):
            total = item.get("total_selected") or 0
            done = item.get("total_audited") or 0
            progress_str = f"{done}/{total}" if total else "?"
            name = item.get("repo_name", "Unknown")
            scope = item.get("scope_name", "default")
            resume_choices.append(Choice(
                title=f"{name:<24s} [{scope}]  {progress_str} done",
                value=str(i),
            ))
        resume_choices.append(Separator("  ──────────────────────────────────"))
        resume_choices.append(Choice(title="Cancel", value="cancel"))

        pick = _select("Select audit to resume", resume_choices)
        if pick is None or pick == "cancel":
            return

        selected = active_items[int(pick)]
        github_url = selected.get("url", "")
        if not github_url:
            self.console.print("[red]No URL found for this project.[/red]")
            return

        self.console.print(f"\n[cyan]Resuming audit for {selected['repo_name']}...[/cyan]")
        try:
            self.cli.run_github_audit_command(
                github_url=github_url,
                interactive_scope=True,
                skip_scope_selector=True,
            )
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Audit interrupted.[/yellow]")
        except Exception as e:
            self.console.print(f"\n[red]Resume error: {e}[/red]")

    # ── [3] Audit History ─────────────────────────────────────────

    def _handle_audit_history(self):
        self.console.print("\n[bold cyan]── Audit History ──[/bold cyan]\n")

        projects = []

        # GitHub projects
        try:
            import sqlite3, json
            db_path = Path.home() / ".aether" / "aether_github_audit.db"
            if db_path.exists():
                conn = sqlite3.connect(db_path)
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT id, repo_name, url, owner, framework, created_at FROM projects "
                    "ORDER BY created_at DESC"
                ).fetchall()
                for r in rows:
                    findings = self._get_findings_count(r["id"])
                    projects.append({
                        "id": r["id"],
                        "name": r["repo_name"],
                        "source": "GitHub",
                        "findings": findings,
                        "date": str(r["created_at"] or "")[:10],
                        "url": r["url"],
                        "db": "github",
                    })
                conn.close()
        except Exception:
            pass

        # Local audits
        try:
            results = self.db_manager.get_audit_results(limit=50)
            for r in results:
                projects.append({
                    "id": r.get("id"),
                    "name": r.get("name", r.get("contract_path", "Unknown")),
                    "source": "Local",
                    "findings": r.get("total_findings", 0),
                    "date": str(r.get("created_at", ""))[:10],
                    "db": "local",
                })
        except Exception:
            pass

        if not projects:
            self.console.print("[yellow]No audit history. Run a New Audit first.[/yellow]")
            return

        # Display table
        table = Table(title="Audit History")
        table.add_column("#", style="cyan", width=4)
        table.add_column("Name", style="bold")
        table.add_column("Source", style="white")
        table.add_column("Findings", style="yellow", justify="right")
        table.add_column("Date", style="dim")

        for i, p in enumerate(projects, 1):
            table.add_row(str(i), p["name"], p["source"], str(p["findings"]), p["date"])
        self.console.print(table)

        # Select via arrow-key navigation
        history_choices = []
        for i, p in enumerate(projects):
            tag = f"[{p['source']}]"
            findings = p.get("findings", 0)
            history_choices.append(Choice(
                title=f"{tag:<10s} {p['name']:<28s} {findings} findings  {p['date']}",
                value=str(i),
            ))
        history_choices.append(Separator("  ──────────────────────────────────"))
        history_choices.append(Choice(title="Back", value="back"))

        pick = _select("Select a project for details", history_choices)
        if pick is None or pick == "back":
            return

        selected = projects[int(pick)]
        self._history_submenu(selected)

    def _history_submenu(self, project: Dict[str, Any]):
        """Submenu for a selected audit history entry."""
        self.console.print(f"\n[bold]{project['name']}[/bold] ({project['source']})")

        actions = ["View scopes & details", "Generate PoCs", "Re-audit", "Back"]
        if project.get("db") != "github":
            actions = ["View details", "Re-audit", "Back"]

        action = _select("Action", actions)
        if action is None or action == "Back":
            return

        if action == "View scopes & details" and project.get("db") == "github":
            scopes = self._get_scopes_for_project(project["id"])
            if not scopes:
                self.console.print("[yellow]No scopes found for this project.[/yellow]")
                return
            table = Table(title=f"Scopes for {project['name']}")
            table.add_column("ID", style="cyan", width=5)
            table.add_column("Scope Name", style="bold")
            table.add_column("Status", style="white")
            table.add_column("Progress", style="green")
            table.add_column("Created", style="dim")
            for s in scopes:
                total = s["total_selected"] or 0
                done = s["total_audited"] or 0
                status_style = "green" if s["status"] == "completed" else "yellow"
                table.add_row(
                    str(s["id"]),
                    s["scope_name"] or "default",
                    f"[{status_style}]{s['status']}[/{status_style}]",
                    f"{done}/{total}",
                    str(s["created_at"] or "")[:10],
                )
            self.console.print(table)

        elif action == "View details" and project.get("db") == "local":
            self.console.print(f"  [bold]ID:[/bold]       {project['id']}")
            self.console.print(f"  [bold]Name:[/bold]     {project['name']}")
            self.console.print(f"  [bold]Findings:[/bold] {project.get('findings', 0)}")
            self.console.print(f"  [bold]Date:[/bold]     {project.get('date', '')}")

        elif action == "Generate PoCs":
            self._run_generate_pocs_for_project(project)

        elif action == "Re-audit":
            if project.get("db") == "github":
                url = project.get("url", "")
                if url:
                    self.console.print(f"[cyan]Re-auditing {project['name']}...[/cyan]")
                    try:
                        self.cli.run_github_audit_command(
                            github_url=url, fresh=True, interactive_scope=True
                        )
                    except KeyboardInterrupt:
                        self.console.print("\n[yellow]Audit interrupted.[/yellow]")
                    except Exception as e:
                        self.console.print(f"\n[red]Error: {e}[/red]")
            else:
                self.console.print("[yellow]Re-audit for local projects: run a New Audit on the same path.[/yellow]")

    # ── [4] Generate PoCs ─────────────────────────────────────────

    def _handle_generate_pocs(self):
        self.console.print("\n[bold cyan]── Generate PoCs ──[/bold cyan]\n")

        project = self._select_project("Select project for PoC generation")
        if not project:
            return

        self._run_generate_pocs_for_project(project)

    def _run_generate_pocs_for_project(self, project: Dict[str, Any]):
        """Configure and run PoC generation for a project."""
        # Configuration
        max_items_str = Prompt.ask("Max items to generate", default="20")
        try:
            max_items = int(max_items_str)
        except ValueError:
            max_items = 20

        severity = _select(
            "Minimum severity",
            ["critical", "high", "medium", "low"],
            default="medium",
        )
        if severity is None:
            severity = "medium"

        consensus_only = Confirm.ask("Only consensus findings?", default=False)

        if project.get("db") == "github":
            # Select scope
            scopes = self._get_scopes_for_project(project["id"])
            scope_id = None
            if scopes:
                scope_choices = [f"{s['scope_name'] or 'default'} (ID: {s['id']})" for s in scopes]
                scope_choices.append("All scopes")
                scope_sel = _select("Select scope", scope_choices)
                if scope_sel and scope_sel != "All scopes":
                    idx = scope_choices.index(scope_sel)
                    scope_id = scopes[idx]["id"]

            self.console.print(f"\n[cyan]Generating PoCs for {project['name']}...[/cyan]")
            try:
                asyncio.run(
                    self.cli.run_generate_foundry(
                        project_id=project["id"],
                        scope_id=scope_id,
                        max_items=max_items,
                        min_severity=severity,
                        only_consensus=consensus_only,
                    )
                )
            except KeyboardInterrupt:
                self.console.print("\n[yellow]Generation interrupted.[/yellow]")
            except Exception as e:
                self.console.print(f"\n[red]Error: {e}[/red]")
        else:
            self.console.print("[yellow]PoC generation from local audit results requires a results JSON file.[/yellow]")
            results_file = Prompt.ask("Path to results JSON (or press Enter to cancel)", default="")
            if not results_file:
                return
            out_dir = Prompt.ask("Output directory", default="./output/pocs")
            try:
                asyncio.run(
                    self.cli.run_generate_foundry(
                        from_results=results_file,
                        out_dir=out_dir,
                        max_items=max_items,
                        min_severity=severity,
                        only_consensus=consensus_only,
                    )
                )
            except KeyboardInterrupt:
                self.console.print("\n[yellow]Generation interrupted.[/yellow]")
            except Exception as e:
                self.console.print(f"\n[red]Error: {e}[/red]")

    # ── [5] Reports ───────────────────────────────────────────────

    def _handle_reports(self):
        self.console.print("\n[bold cyan]── Reports ──[/bold cyan]\n")

        project = self._select_project("Select project for report generation")
        if not project:
            return

        if project.get("db") != "github":
            self.console.print("[yellow]Report generation is currently supported for GitHub audit projects.[/yellow]")
            return

        # Select scope
        scopes = self._get_scopes_for_project(project["id"])
        scope_id = None
        if scopes:
            scope_choices = [f"{s['scope_name'] or 'default'} (ID: {s['id']})" for s in scopes]
            scope_choices.append("All scopes (no filter)")
            scope_sel = _select("Select scope", scope_choices)
            if scope_sel and scope_sel != "All scopes (no filter)":
                idx = scope_choices.index(scope_sel)
                scope_id = scopes[idx]["id"]

        # Format
        fmt = _select(
            "Report format",
            ["markdown", "json", "html", "all"],
            default="markdown",
        )
        if fmt is None:
            fmt = "markdown"

        output_dir = Prompt.ask("Output directory", default="./output/reports")

        self.console.print(f"\n[cyan]Generating {fmt} report for {project['name']}...[/cyan]")
        try:
            asyncio.run(
                self.cli.run_generate_report(
                    output_dir=output_dir,
                    format=fmt,
                    project_id=project["id"],
                    scope_id=scope_id,
                )
            )
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Report generation interrupted.[/yellow]")
        except Exception as e:
            self.console.print(f"\n[red]Error: {e}[/red]")

    # ── [6] Fetch Contract ────────────────────────────────────────

    def _handle_fetch_contract(self):
        self.console.print("\n[bold cyan]── Fetch Contract ──[/bold cyan]\n")

        from core.etherscan_fetcher import EtherscanFetcher

        fetcher = EtherscanFetcher(self.config_manager)

        # Network selection
        evm_networks = list(fetcher.SUPPORTED_NETWORKS.keys())
        non_evm = list(fetcher.NON_EVM_NETWORKS.keys())
        all_networks = evm_networks + non_evm

        network_display = []
        for net in all_networks:
            info = fetcher.SUPPORTED_NETWORKS.get(net) or fetcher.NON_EVM_NETWORKS.get(net, {})
            name = info.get("name", net)
            network_display.append(f"{net} - {name}")

        selected_net = _select("Select network", network_display, default=network_display[0])
        if selected_net is None:
            return
        network = selected_net.split(" - ")[0]

        # Address input
        try:
            addr_input = Prompt.ask("Contract address or explorer URL")
        except (KeyboardInterrupt, EOFError):
            return
        if not addr_input:
            return

        # Parse if URL
        parsed_network, address = fetcher.parse_explorer_url(addr_input)
        if not address:
            self.console.print("[red]Could not parse a valid address.[/red]")
            return

        # Use detected network from URL if available, otherwise use selected
        final_network = parsed_network or network
        if final_network != fetcher.current_network:
            fetcher.set_network(final_network)

        self.console.print(f"[cyan]Fetching from {final_network}: {address}...[/cyan]")
        result = fetcher.fetch_contract_source(address, final_network)
        if not result.get("success"):
            self.console.print(f"[red]Fetch failed: {result.get('error', 'Unknown error')}[/red]")
            return

        save_path = fetcher.save_contract_source(result)
        self.console.print(f"[green]Contract saved to: {save_path}[/green]")

        if Confirm.ask("Audit this contract now?", default=False):
            features = self._prompt_audit_features()
            if features is None:
                return
            output_dir = Prompt.ask("Output directory", default="./output")
            self._run_local_audit(save_path, features, output_dir)

    # ── [7] Settings ──────────────────────────────────────────────

    def _handle_settings(self):
        self.console.print("\n[bold cyan]── Settings ──[/bold cyan]\n")

        settings_choices = [
            Choice(title="\U0001f9d9  Run full setup wizard", value="wizard"),
            Choice(title="\U0001f50d  View current configuration", value="view"),
            Choice(title="\U0001f511  Reconfigure API keys", value="keys"),
            Choice(title="\U0001f916  Reconfigure model selections", value="models"),
            Choice(title="\U0001f4cb  Triage settings", value="triage"),
            Separator("  ──────────────────────────────────"),
            Choice(title="\u2b05  Back to main menu", value="back"),
        ]

        while True:
            choice = _select("Settings", settings_choices, default="wizard")

            if choice is None or choice == "back":
                break
            elif choice == "wizard":
                self._run_setup_wizard()
            elif choice == "view":
                self._view_config()
            elif choice == "keys":
                self._run_setup_wizard(reconfigure_keys=True)
            elif choice == "models":
                self._run_setup_wizard(reconfigure_models=True)
            elif choice == "triage":
                self._edit_triage_settings()

    def _run_setup_wizard(self, reconfigure_keys: bool = False, reconfigure_models: bool = False):
        try:
            from setup import AetherSetup
            if reconfigure_keys:
                setup = AetherSetup(reconfigure_keys=True)
            elif reconfigure_models:
                setup = AetherSetup(reconfigure_models=True)
            else:
                setup = AetherSetup()
            setup.run()
            # Reload config after setup
            self._config_manager = None
            self._cli = None
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Setup cancelled.[/yellow]")
        except Exception as e:
            self.console.print(f"[red]Setup error: {e}[/red]")

    def _view_config(self):
        try:
            self.config_manager.show_config()
        except Exception as e:
            self.console.print(f"[red]Error displaying config: {e}[/red]")

    def _edit_triage_settings(self):
        """Edit triage-related settings inline."""
        try:
            config = self.config_manager.config
            self.console.print("\n[bold]Current Triage Settings:[/bold]")
            self.console.print(f"  Min severity:        {getattr(config, 'triage_min_severity', 'medium')}")
            self.console.print(f"  Confidence threshold: {getattr(config, 'triage_confidence_threshold', 0.5)}")
            self.console.print(f"  Max findings:        {getattr(config, 'triage_max_findings', 50)}")
            self.console.print()

            new_severity = _select(
                "Minimum severity for triage",
                ["critical", "high", "medium", "low", "informational"],
                default=getattr(config, 'triage_min_severity', 'medium'),
            )
            if new_severity:
                config.triage_min_severity = new_severity

            try:
                threshold_str = Prompt.ask(
                    "Confidence threshold (0.0 - 1.0)",
                    default=str(getattr(config, 'triage_confidence_threshold', 0.5)),
                )
                threshold = float(threshold_str)
                if 0.0 <= threshold <= 1.0:
                    config.triage_confidence_threshold = threshold
            except (ValueError, KeyboardInterrupt, EOFError):
                pass

            try:
                max_str = Prompt.ask(
                    "Max findings to display",
                    default=str(getattr(config, 'triage_max_findings', 50)),
                )
                config.triage_max_findings = int(max_str)
            except (ValueError, KeyboardInterrupt, EOFError):
                pass

            self.config_manager.save_config()
            self.console.print("[green]Triage settings saved.[/green]")
        except Exception as e:
            self.console.print(f"[red]Error editing triage settings: {e}[/red]")

    # ── [8] Console ───────────────────────────────────────────────

    def _handle_console(self):
        self.console.print("\n[cyan]Launching Aether Console... (type 'exit' to return to menu)[/cyan]\n")
        try:
            from cli.console import main as console_main
            console_main()
        except KeyboardInterrupt:
            pass
        except Exception as e:
            self.console.print(f"[red]Console error: {e}[/red]")
        self.console.print("\n[cyan]Returned to main menu.[/cyan]")


def main():
    """Entry point for interactive menu."""
    menu = AetherInteractiveMenu()
    try:
        menu.run()
    except Exception as e:
        Console().print(f"[red]Fatal error: {e}[/red]")
        return 1
    return 0
