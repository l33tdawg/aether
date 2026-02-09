"""
Single-audit Rich Live dashboard.

Runs the audit in a background thread while the main thread renders a
real-time status panel (phase progress bar, findings, LLM calls & cost).
"""

import asyncio
import os
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from core.audit_progress import (
    AuditPhase,
    ContractAuditStatus,
    ThreadDemuxWriter,
    TOTAL_PHASES,
)


class SingleAuditDashboard:
    """Rich Live dashboard for a single contract audit."""

    def __init__(self):
        self._status: Optional[ContractAuditStatus] = None
        self._result: Optional[Dict[str, Any]] = None
        self._error: Optional[str] = None
        self._cancelled = False
        self._original_stdout = None
        self._demuxer: Optional[ThreadDemuxWriter] = None
        self._original_sigint = None

    def get_status(self) -> Optional[ContractAuditStatus]:
        return self._status

    def run_audit_with_dashboard(
        self,
        audit_fn: Callable,
        contract_path: str,
        output_dir: str,
        enhanced: bool = False,
        ai_ensemble: bool = False,
        llm_validation: bool = False,
        foundry: bool = False,
        enhanced_reports: bool = False,
    ) -> Optional[Dict[str, Any]]:
        """Run audit with a live dashboard. Returns the audit result dict."""
        # Reset tracker for this run
        from core.llm_usage_tracker import LLMUsageTracker
        LLMUsageTracker.reset()

        contract_name = Path(contract_path).stem
        self._status = ContractAuditStatus(
            contract_name=contract_name,
            contract_path=contract_path,
        )

        # Install stdout demuxer
        self._original_stdout = sys.stdout
        self._demuxer = ThreadDemuxWriter(self._original_stdout)
        sys.stdout = self._demuxer

        # Install Ctrl+C handler
        self._install_signal_handler()

        # Launch audit in background thread
        audit_thread = threading.Thread(
            target=self._audit_worker,
            args=(audit_fn, contract_path, output_dir, enhanced,
                  ai_ensemble, llm_validation, foundry, enhanced_reports),
            daemon=True,
        )
        audit_thread.start()

        try:
            self._run_dashboard(audit_thread)
        finally:
            sys.stdout = self._original_stdout
            self._restore_signal_handler()

        return self._result

    def _audit_worker(
        self,
        audit_fn: Callable,
        contract_path: str,
        output_dir: str,
        enhanced: bool,
        ai_ensemble: bool,
        llm_validation: bool,
        foundry: bool,
        enhanced_reports: bool,
    ) -> None:
        """Background thread: runs the actual audit."""
        if self._demuxer and self._status:
            self._demuxer.register(self._status)

        self._status.set_phase(AuditPhase.STARTING)

        try:
            asyncio.run(
                audit_fn(
                    contract_path=contract_path,
                    output_dir=output_dir,
                    enhanced=enhanced,
                    ai_ensemble=ai_ensemble,
                    llm_validation=llm_validation,
                    foundry=foundry,
                    enhanced_reports=enhanced_reports,
                )
            )
            self._status.set_completed(self._status.findings_count)
            self._result = {
                "success": True,
                "findings_count": self._status.findings_count,
                "elapsed": self._status.elapsed,
                "output_dir": output_dir,
            }
        except Exception as e:
            error_msg = str(e)[:200]
            self._status.set_failed(error_msg)
            self._error = error_msg
            self._result = {
                "success": False,
                "findings_count": self._status.findings_count,
                "error": error_msg,
                "elapsed": self._status.elapsed,
                "output_dir": output_dir,
            }
        finally:
            # Final LLM stats sync
            self._status.sync_llm_stats()
            if self._demuxer:
                self._demuxer.unregister()

    def _run_dashboard(self, audit_thread: threading.Thread) -> None:
        """Main-thread dashboard loop using Rich Live."""
        console = Console(file=self._original_stdout)

        with Live(
            self._build_dashboard(),
            console=console,
            refresh_per_second=2,
            transient=False,
        ) as live:
            while audit_thread.is_alive():
                if self._cancelled:
                    break
                live.update(self._build_dashboard())
                time.sleep(0.5)

            # Final render
            live.update(self._build_dashboard())

    def _build_dashboard(self) -> Panel:
        """Build the Rich dashboard panel."""
        status = self._status
        if status is None:
            return Panel("Initializing...", title="[bold cyan]Aether Audit[/bold cyan]")

        table = Table(show_header=False, expand=True, pad_edge=True, box=None)
        table.add_column("Key", style="bold", width=14)
        table.add_column("Value")

        # Contract
        table.add_row("Contract", f"[bold]{status.contract_name}[/bold]")
        table.add_row("Path", f"[dim]{status.contract_path}[/dim]")

        # Status
        if status.phase == AuditPhase.COMPLETED:
            status_text = Text("COMPLETED", style="bold green")
        elif status.phase == AuditPhase.FAILED:
            status_text = Text(f"FAILED: {status.error or 'Unknown'}", style="bold red")
        elif status.phase == AuditPhase.QUEUED:
            status_text = Text("QUEUED", style="dim")
        else:
            status_text = Text(f"RUNNING - {status.phase.value}", style="bold cyan")
        table.add_row("Status", status_text)

        # Phase progress bar
        idx = status.phase_index
        filled = int((idx / (TOTAL_PHASES - 1)) * 20) if TOTAL_PHASES > 1 else 0
        empty = 20 - filled
        bar = f"[cyan]{'█' * filled}[/cyan][dim]{'░' * empty}[/dim]  {idx}/{TOTAL_PHASES - 1}"
        table.add_row("Progress", Text.from_markup(bar))

        # Findings
        table.add_row("Findings", f"[yellow]{status.findings_count}[/yellow]")

        # Elapsed time
        elapsed = status.elapsed
        if elapsed is not None:
            mins, secs = divmod(int(elapsed), 60)
            table.add_row("Elapsed", f"{mins}:{secs:02d}")
        else:
            table.add_row("Elapsed", "-")

        # LLM stats
        table.add_row("LLM Calls", str(status.llm_calls))
        cost_str = f"[yellow]${status.llm_cost:.4f}[/yellow]" if status.llm_cost > 0 else "$0.00"
        table.add_row("Cost", Text.from_markup(cost_str))

        # Last message (truncated)
        if status.last_message:
            table.add_row("Activity", f"[dim]{status.last_message[:80]}[/dim]")

        subtitle = ""
        if self._cancelled:
            subtitle = "[yellow bold]CANCELLING...[/yellow bold]"

        return Panel(
            table,
            title="[bold cyan]Aether Audit[/bold cyan]",
            border_style="cyan",
            padding=(0, 1),
            subtitle=subtitle or None,
        )

    def _install_signal_handler(self) -> None:
        self._original_sigint = signal.getsignal(signal.SIGINT)
        self._ctrl_c_count = 0

        def _handler(signum, frame):
            self._ctrl_c_count += 1
            if self._ctrl_c_count >= 2:
                os._exit(1)
            self._cancelled = True

        signal.signal(signal.SIGINT, _handler)

    def _restore_signal_handler(self) -> None:
        if self._original_sigint is not None:
            signal.signal(signal.SIGINT, self._original_sigint)
