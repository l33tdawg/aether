"""
New Audit screen — multi-step wizard for launching local, GitHub, or explorer audits.

Ports the new_audit flow from cli/subflows.py to a Textual Screen with
async dialog-based input. Each wizard step uses push_screen_wait on the
appropriate ModalScreen dialog.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import List, Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import Footer, Header, Static

from cli.tui.dialogs.confirm import ConfirmDialog
from cli.tui.dialogs.text_input import TextInputDialog
from cli.tui.dialogs.select import SelectDialog
from cli.tui.dialogs.checkbox import CheckboxDialog
from cli.tui.dialogs.path_picker import PathDialog


class NewAuditScreen(Screen):
    """Multi-step wizard for configuring and launching a new audit.

    Args:
        auto_discover: If True, skip source-type selection and go straight
            to PathDialog -> Auto-Discover flow.
    """

    BINDINGS = [
        Binding("escape", "go_back", "Back", show=True),
    ]

    def __init__(self, auto_discover: bool = False, **kwargs) -> None:
        super().__init__(**kwargs)
        self._auto_discover = auto_discover

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(
            "[bold cyan]New Audit Wizard[/bold cyan]\n\nInitializing...",
            id="wizard-status",
        )
        yield Footer()

    def on_mount(self) -> None:
        """Kick off the wizard flow after the screen is mounted."""
        self._run_wizard()

    # ── Async wizard entrypoint ──────────────────────────────────

    @staticmethod
    def _update_status(widget: Static, text: str) -> None:
        widget.update(text)

    async def _wizard(self) -> None:
        """Top-level wizard coroutine.  Any cancel pops back to main."""
        status = self.query_one("#wizard-status", Static)

        if self._auto_discover:
            # Skip step 1 — go straight to auto-discover local flow
            result = await self._step_local(status, force_discover=True)
        else:
            # Step 1 — source type
            self._update_status(status, "[bold cyan]New Audit Wizard[/bold cyan]\n\nStep 1/5: Select audit source")
            source_type = await self.app.push_screen_wait(
                SelectDialog(
                    "Select audit source",
                    [
                        "Local file or directory",
                        "GitHub URL",
                        "Block explorer URL / address",
                    ],
                )
            )
            if source_type is None:
                self.app.pop_screen()
                return

            # Step 2 — target (varies by source type)
            if source_type == "Local file or directory":
                result = await self._step_local(status)
            elif source_type == "GitHub URL":
                result = await self._step_github(status)
            else:
                result = await self._step_explorer(status)

        if result is None:
            self.app.pop_screen()
            return

        target, sol_files, use_parallel = result

        # Step 3 — features
        self._update_status(
            status,
            f"[bold cyan]New Audit Wizard[/bold cyan]\n\n"
            f"[bold]Target:[/bold] {target}\n"
            f"Step 3/5: Select audit features",
        )
        features = await self.app.push_screen_wait(
            CheckboxDialog(
                "Select audit features",
                [
                    ("Enhanced analysis", "enhanced", True),
                    ("LLM Validation (false-positive reduction)", "llm_validation", True),
                    ("Foundry PoC generation", "foundry", False),
                    ("Halmos symbolic verification", "halmos", False),
                    ("Enhanced Reports", "enhanced_reports", False),
                ],
            )
        )
        if features is None:
            self.app.pop_screen()
            return

        # Step 4 — output directory
        self._update_status(
            status,
            f"[bold cyan]New Audit Wizard[/bold cyan]\n\n"
            f"[bold]Target:[/bold] {target}\n"
            f"[bold]Features:[/bold] {', '.join(features) if features else 'default'}\n"
            f"Step 4/5: Choose output directory",
        )
        output_dir = await self.app.push_screen_wait(
            TextInputDialog("Output directory", default="./output")
        )
        if output_dir is None:
            self.app.pop_screen()
            return
        output_dir = output_dir or "./output"

        # Step 5 — confirmation
        contracts_info = ""
        if sol_files:
            contracts_info = f"\n[bold]Contracts:[/bold] {len(sol_files)} selected"
        parallel_info = "\n[bold]Mode:[/bold] Parallel" if use_parallel else ""

        summary = (
            f"[bold cyan]New Audit Wizard[/bold cyan]\n\n"
            f"[bold]Target:[/bold]   {target}{contracts_info}\n"
            f"[bold]Features:[/bold] {', '.join(features) if features else 'default'}\n"
            f"[bold]Output:[/bold]   {output_dir}{parallel_info}\n\n"
            f"Step 5/5: Confirm and launch"
        )
        self._update_status(status, summary)

        confirmed = await self.app.push_screen_wait(
            ConfirmDialog("Start audit?")
        )
        if not confirmed:
            self.app.pop_screen()
            return

        # Launch the audit
        self._update_status(status, summary + "\n\n[green]Launching audit...[/green]")
        self._launch_audit(target, sol_files, use_parallel, features, output_dir)
        self.app.pop_screen()

    # ── Step 2 variants ──────────────────────────────────────────

    async def _step_local(
        self, status: Static, force_discover: bool = False,
    ) -> Optional[tuple[str, List[Path], bool]]:
        """Local file/directory wizard step.  Returns (target, selected_files, use_parallel) or None."""
        self._update_status(
            status,
            "[bold cyan]New Audit Wizard[/bold cyan]\n\n"
            "Step 2/5: Select file or directory",
        )
        path_str = await self.app.push_screen_wait(
            PathDialog("Path to Solidity file or directory")
        )
        if not path_str:
            return None

        resolved = Path(path_str).expanduser().resolve()
        if not resolved.exists():
            self._update_status(status, f"[red]Path not found: {resolved}[/red]")
            await self.app.push_screen_wait(ConfirmDialog(f"Path not found: {resolved}\n\nGo back?"))
            return None

        target = str(resolved)
        sol_files: List[Path] = []
        use_parallel = False

        if resolved.is_dir():
            sol_files_all = sorted(resolved.rglob("*.sol"))
            if len(sol_files_all) >= 2:
                # Choose selection method
                use_discover = force_discover
                if not force_discover:
                    method = await self.app.push_screen_wait(
                        SelectDialog(
                            "How would you like to select contracts?",
                            [
                                "Auto-Discover (scan & rank)",
                                "Manual selection (show all)",
                            ],
                        )
                    )
                    if method is None:
                        return None
                    use_discover = method == "Auto-Discover (scan & rank)"

                if use_discover:
                    sol_files = await self._auto_discover_flow(status, resolved)
                    if sol_files is None:
                        return None
                    if not sol_files:
                        self._update_status(status, "[yellow]No contracts selected.[/yellow]")
                        return None
                    # Auto-enable parallel for 2+ contracts
                    use_parallel = len(sol_files) > 1
                else:
                    # Original manual selection flow
                    choices = []
                    for f in sol_files_all:
                        try:
                            rel = f.relative_to(resolved)
                        except ValueError:
                            rel = f.name
                        choices.append((f"{f.stem}  ({rel})", str(f), True))

                    self._update_status(
                        status,
                        f"[bold cyan]New Audit Wizard[/bold cyan]\n\n"
                        f"[bold]Directory:[/bold] {target}\n"
                        f"Found {len(sol_files_all)} Solidity files — select contracts to audit",
                    )
                    selected = await self.app.push_screen_wait(
                        CheckboxDialog(
                            f"Select contracts to audit ({len(sol_files_all)} found)",
                            choices,
                        )
                    )
                    if selected is None:
                        return None
                    if not selected:
                        self._update_status(status, "[yellow]No contracts selected.[/yellow]")
                        return None
                    sol_files = [Path(p) for p in selected]

                    if len(sol_files) > 1:
                        use_parallel_result = await self.app.push_screen_wait(
                            ConfirmDialog(f"Run {len(sol_files)} contracts in parallel?")
                        )
                        use_parallel = use_parallel_result if use_parallel_result is not None else False

            elif len(sol_files_all) == 1:
                sol_files = sol_files_all

        return target, sol_files, use_parallel

    async def _auto_discover_flow(
        self, status: Static, resolved: Path,
    ) -> Optional[List[Path]]:
        """Run ContractScanner and present DiscoveryResultsDialog.

        Returns selected paths, empty list, or None on cancel.
        """
        self._update_status(
            status,
            f"[bold cyan]New Audit Wizard[/bold cyan]\n\n"
            f"[bold]Directory:[/bold] {resolved}\n\n"
            "[cyan]Scanning contracts...[/cyan]",
        )

        from core.contract_scanner import ContractScanner
        scanner = ContractScanner()

        try:
            loop = asyncio.get_event_loop()
            report = await loop.run_in_executor(None, scanner.scan_directory, resolved)
        except Exception as e:
            self._update_status(status, f"[red]Scan failed: {e}[/red]")
            await self.app.push_screen_wait(ConfirmDialog(f"Scan failed: {e}\n\nGo back?"))
            return None

        if not report.results:
            self._update_status(status, "[yellow]No contracts found after scanning.[/yellow]")
            await self.app.push_screen_wait(ConfirmDialog("No contracts found.\n\nGo back?"))
            return None

        self._update_status(
            status,
            f"[bold cyan]New Audit Wizard[/bold cyan]\n\n"
            f"[bold]Directory:[/bold] {resolved}\n"
            f"[bold]Scanned:[/bold] {report.scanned} contracts in {report.scan_time_ms}ms\n\n"
            "[cyan]Select contracts to audit...[/cyan]",
        )

        from cli.tui.dialogs.discovery_results import DiscoveryResultsDialog
        selected_paths = await self.app.push_screen_wait(
            DiscoveryResultsDialog(report)
        )
        return selected_paths

    async def _step_github(
        self, status: Static
    ) -> Optional[tuple[str, List[Path], bool]]:
        """GitHub URL wizard step with inline contract selection."""
        self._update_status(
            status,
            "[bold cyan]New Audit Wizard[/bold cyan]\n\n"
            "Step 2/5: Enter GitHub repository URL",
        )
        url = await self.app.push_screen_wait(
            TextInputDialog("GitHub repository URL")
        )
        if not url or "github.com" not in url.lower():
            return None

        # Clone and discover contracts in a worker thread
        self._update_status(
            status,
            f"[bold cyan]New Audit Wizard[/bold cyan]\n\n"
            f"[bold]Repository:[/bold] {url}\n\n"
            "[cyan]Cloning repository and discovering contracts...[/cyan]",
        )

        from cli.tui.github_audit_helper import GitHubAuditHelper
        helper = GitHubAuditHelper()

        try:
            discovery = await asyncio.get_event_loop().run_in_executor(
                None, helper.clone_and_discover, url
            )
        except Exception as e:
            self._update_status(status, f"[red]Clone failed: {e}[/red]")
            await self.app.push_screen_wait(ConfirmDialog(f"Clone failed: {e}\n\nGo back?"))
            return None

        project_id = discovery["project_id"]
        contracts = discovery["contracts"]
        repo_name = discovery["repo_name"]

        if not contracts:
            self._update_status(status, "[yellow]No Solidity contracts found in repository.[/yellow]")
            await self.app.push_screen_wait(ConfirmDialog("No contracts found.\n\nGo back?"))
            return None

        # Check scope state
        scope_state = helper.get_scope_state(project_id)

        scope_id = None
        selected_paths = None

        if scope_state["active_scope"]:
            active = scope_state["active_scope"]
            total = active.get("total_selected", 0)
            done = active.get("total_audited", 0)
            action = await self.app.push_screen_wait(
                SelectDialog(
                    f"Active scope found ({done}/{total} audited)",
                    [
                        "Continue with existing scope",
                        "Re-audit (reset progress)",
                        "Create new scope",
                        "Cancel",
                    ],
                )
            )
            if action is None or action == "Cancel":
                return None
            if action == "Continue with existing scope":
                scope_id = active["id"]
            elif action == "Re-audit (reset progress)":
                helper.handle_reaudit(active["id"])
                scope_id = active["id"]
            # else: fall through to contract selection
        elif scope_state["completed_scopes"]:
            action = await self.app.push_screen_wait(
                SelectDialog(
                    f"Previous audits found for {repo_name}",
                    [
                        "Create new scope",
                        "Cancel",
                    ],
                )
            )
            if action is None or action == "Cancel":
                return None

        # Select contracts if no scope chosen yet
        if scope_id is None:
            repo_dir = discovery.get("repo_dir", "")

            # Choose selection method
            method = await self.app.push_screen_wait(
                SelectDialog(
                    f"Select contracts from {repo_name} ({len(contracts)} found)",
                    [
                        "Auto-Discover (scan & rank)",
                        "Manual selection (show all)",
                    ],
                )
            )
            if method is None:
                return None

            if method == "Auto-Discover (scan & rank)" and repo_dir:
                # Run scanner on cloned repo directory
                discovered_paths = await self._auto_discover_flow(
                    status, Path(repo_dir)
                )
                if discovered_paths is None or len(discovered_paths) == 0:
                    return None
                selected_paths = [str(p) for p in discovered_paths]
            else:
                # Original manual selection flow
                from cli.tui.dialogs.contract_selector import ContractSelectorDialog

                # Find previously audited contracts
                audited_paths = helper.get_previously_audited_paths(project_id)
                audited_indices = []
                for i, c in enumerate(contracts):
                    if c.get("file_path") in audited_paths:
                        audited_indices.append(i)

                pre_selected = list(range(len(contracts)))

                self._update_status(
                    status,
                    f"[bold cyan]New Audit Wizard[/bold cyan]\n\n"
                    f"[bold]Repository:[/bold] {url}\n"
                    f"[bold]Contracts:[/bold] {len(contracts)} found\n\n"
                    "[cyan]Select contracts to audit...[/cyan]",
                )
                selected_indices = await self.app.push_screen_wait(
                    ContractSelectorDialog(
                        contracts=contracts,
                        pre_selected=pre_selected,
                        previously_audited_indices=audited_indices,
                    )
                )
                if selected_indices is None or len(selected_indices) == 0:
                    return None

                selected_paths = [contracts[i]["file_path"] for i in selected_indices]

            scope_id = helper.save_new_scope(project_id, selected_paths)

        # Launch GitHub audit as background job
        from core.job_manager import JobManager
        from cli.audit_runner import AuditRunner

        jm = JobManager.get_instance()
        job = jm.create_job(
            display_name=f"GH: {repo_name}",
            job_type="github",
            target=url,
        )
        runner = AuditRunner()
        runner.start_github_audit(
            job_id=job.job_id,
            github_url=url,
            project_id=project_id,
            scope_id=scope_id,
        )

        # Return None — _wizard() will pop_screen() once back to MainScreen
        return None

    async def _step_explorer(
        self, status: Static
    ) -> Optional[tuple[str, List[Path], bool]]:
        """Block explorer URL/address wizard step."""
        self._update_status(
            status,
            "[bold cyan]New Audit Wizard[/bold cyan]\n\n"
            "Step 2/5: Enter block explorer URL or contract address",
        )
        addr_input = await self.app.push_screen_wait(
            TextInputDialog("Block explorer URL or contract address")
        )
        if not addr_input:
            return None

        self._update_status(
            status,
            f"[bold cyan]New Audit Wizard[/bold cyan]\n\n"
            f"[cyan]Parsing and fetching contract...[/cyan]",
        )

        try:
            from core.config_manager import ConfigManager
            from core.etherscan_fetcher import EtherscanFetcher

            config_mgr = ConfigManager()
            fetcher = EtherscanFetcher(config_mgr)
            network, address = fetcher.parse_explorer_url(addr_input)
            if not address:
                self._update_status(status, "[red]Could not parse address from input.[/red]")
                await self.app.push_screen_wait(ConfirmDialog("Could not parse address. Go back?"))
                return None

            if network and network != fetcher.current_network:
                fetcher.set_network(network)

            self._update_status(
                status,
                f"[bold cyan]New Audit Wizard[/bold cyan]\n\n"
                f"[cyan]Fetching contract {address} from {network or 'ethereum'}...[/cyan]",
            )

            result = fetcher.fetch_contract_source(address, network)
            if not result.get("success"):
                err = result.get("error", "Unknown error")
                self._update_status(status, f"[red]Fetch failed: {err}[/red]")
                await self.app.push_screen_wait(ConfirmDialog(f"Fetch failed: {err}\n\nGo back?"))
                return None

            save_path = fetcher.save_contract_source(result)
            target = str(save_path)
        except Exception as e:
            self._update_status(status, f"[red]Error: {e}[/red]")
            await self.app.push_screen_wait(ConfirmDialog(f"Error: {e}\n\nGo back?"))
            return None

        self._update_status(
            status,
            f"[bold cyan]New Audit Wizard[/bold cyan]\n\n"
            f"[green]Contract saved to: {target}[/green]",
        )
        return target, [], False

    # ── Launch helpers ────────────────────────────────────────────

    def _launch_audit(
        self,
        target: str,
        sol_files: List[Path],
        use_parallel: bool,
        features: List[str],
        output_dir: str,
    ) -> None:
        """Create jobs via JobManager and start via AuditRunner."""
        from core.job_manager import JobManager
        from cli.audit_runner import AuditRunner

        jm = JobManager.get_instance()
        runner = AuditRunner()

        if use_parallel and len(sol_files) > 1:
            paths = [str(p) for p in sol_files]
            parent = jm.create_job(
                display_name=f"{Path(target).name} ({len(paths)} contracts)",
                job_type="local",
                target=target,
                features=features,
                output_dir=output_dir,
            )
            try:
                from core.config_manager import ConfigManager
                cfg = ConfigManager()
                max_w = min(cfg.config.max_concurrent_contracts, len(paths), 8)
            except Exception:
                max_w = min(5, len(paths))
            runner.start_parallel_audit(parent.job_id, paths, features, output_dir, max_w)

        elif len(sol_files) == 1:
            t = str(sol_files[0])
            job = jm.create_job(
                display_name=Path(t).stem,
                job_type="local",
                target=t,
                features=features,
                output_dir=output_dir,
            )
            runner.start_single_audit(job.job_id, t, features, output_dir)

        elif sol_files:
            # Multiple selected but user declined parallel -- run sequentially
            for p in sol_files:
                t = str(p)
                job = jm.create_job(
                    display_name=Path(t).stem,
                    job_type="local",
                    target=t,
                    features=features,
                    output_dir=output_dir,
                )
                runner.start_single_audit(job.job_id, t, features, output_dir)

        else:
            # Single file target (not a directory)
            job = jm.create_job(
                display_name=Path(target).stem,
                job_type="local",
                target=target,
                features=features,
                output_dir=output_dir,
            )
            runner.start_single_audit(job.job_id, target, features, output_dir)

    # ── Worker wrapper ────────────────────────────────────────────

    def _run_wizard(self) -> None:
        """Schedule the wizard coroutine as a Textual worker."""
        self.run_worker(self._wizard(), exclusive=True)

    # ── Bindings ──────────────────────────────────────────────────

    def action_go_back(self) -> None:
        self.app.pop_screen()
