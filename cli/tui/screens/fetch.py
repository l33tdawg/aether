"""
Fetch Contract screen — async wizard to download verified contract source
from a block explorer and optionally launch an audit.

Ports the fetch_contract flow from cli/subflows.py to a Textual Screen
with dialog-based input.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import Footer, Header, Static

from cli.tui.dialogs.confirm import ConfirmDialog
from cli.tui.dialogs.select import SelectDialog
from cli.tui.dialogs.text_input import TextInputDialog


class FetchScreen(Screen):
    """Wizard for fetching a verified contract from a block explorer."""

    BINDINGS = [
        Binding("escape", "go_back", "Back", show=True),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(
            "[bold cyan]Fetch Contract[/bold cyan]\n\nInitializing...",
            id="fetch-status",
        )
        yield Footer()

    def on_mount(self) -> None:
        self.run_worker(self._wizard(), exclusive=True)

    # ── Async wizard ──────────────────────────────────────────────

    async def _wizard(self) -> None:
        status = self.query_one("#fetch-status", Static)

        # Build network list lazily
        try:
            from core.etherscan_fetcher import EtherscanFetcher
            from core.config_manager import ConfigManager

            config_mgr = ConfigManager()
            fetcher = EtherscanFetcher(config_mgr)
        except Exception as e:
            status.update(f"[red]Failed to initialize fetcher: {e}[/red]")
            return

        evm_networks = list(fetcher.SUPPORTED_NETWORKS.keys())
        non_evm = list(fetcher.NON_EVM_NETWORKS.keys())
        all_networks = evm_networks + non_evm

        network_display: List[str] = []
        for net in all_networks:
            info = fetcher.SUPPORTED_NETWORKS.get(net) or fetcher.NON_EVM_NETWORKS.get(net, {})
            name = info.get("name", net)
            network_display.append(f"{net} - {name}")

        # Step 1 — select network
        status.update(
            "[bold cyan]Fetch Contract[/bold cyan]\n\n"
            "Step 1/4: Select blockchain network"
        )
        selected_net = await self.app.push_screen_wait(
            SelectDialog("Select network", network_display)
        )
        if selected_net is None:
            self.app.pop_screen()
            return

        network = selected_net.split(" - ")[0]

        # Step 2 — contract address or URL
        status.update(
            f"[bold cyan]Fetch Contract[/bold cyan]\n\n"
            f"[bold]Network:[/bold] {network}\n"
            f"Step 2/4: Enter contract address or explorer URL"
        )
        addr_input = await self.app.push_screen_wait(
            TextInputDialog("Contract address or explorer URL")
        )
        if not addr_input:
            self.app.pop_screen()
            return

        # Parse address
        parsed_network, address = fetcher.parse_explorer_url(addr_input)
        if not address:
            status.update("[red]Could not parse a valid address from the input.[/red]")
            await self.app.push_screen_wait(ConfirmDialog("Could not parse address.\n\nGo back?"))
            self.app.pop_screen()
            return

        final_network = parsed_network or network
        if final_network != fetcher.current_network:
            fetcher.set_network(final_network)

        # Step 3 — fetch
        status.update(
            f"[bold cyan]Fetch Contract[/bold cyan]\n\n"
            f"[bold]Network:[/bold] {final_network}\n"
            f"[bold]Address:[/bold] {address}\n\n"
            f"[cyan]Fetching contract source...[/cyan]"
        )

        result = fetcher.fetch_contract_source(address, final_network)
        if not result.get("success"):
            err = result.get("error", "Unknown error")
            status.update(
                f"[bold cyan]Fetch Contract[/bold cyan]\n\n"
                f"[red]Fetch failed: {err}[/red]"
            )
            await self.app.push_screen_wait(ConfirmDialog(f"Fetch failed: {err}\n\nGo back?"))
            self.app.pop_screen()
            return

        save_path = fetcher.save_contract_source(result)
        contract_name = result.get("contract_name", address)

        # Step 4 — offer to audit
        status.update(
            f"[bold cyan]Fetch Contract[/bold cyan]\n\n"
            f"[bold]Network:[/bold]  {final_network}\n"
            f"[bold]Contract:[/bold] {contract_name}\n"
            f"[green]Saved to: {save_path}[/green]"
        )

        audit_now = await self.app.push_screen_wait(
            ConfirmDialog("Audit this contract now?")
        )
        if audit_now:
            self._launch_audit(str(save_path))

        self.app.pop_screen()

    # ── Audit helper ──────────────────────────────────────────────

    def _launch_audit(self, target: str) -> None:
        """Create a job and start a single audit for the fetched contract."""
        from core.job_manager import JobManager
        from cli.audit_runner import AuditRunner

        jm = JobManager.get_instance()
        runner = AuditRunner()

        features = ["enhanced", "llm_validation"]
        output_dir = "./output"

        job = jm.create_job(
            display_name=Path(target).stem,
            job_type="explorer",
            target=target,
            features=features,
            output_dir=output_dir,
        )
        runner.start_single_audit(job.job_id, target, features, output_dir)

    # ── Bindings ──────────────────────────────────────────────────

    def action_go_back(self) -> None:
        self.app.pop_screen()
