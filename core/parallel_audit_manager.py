"""
Parallel audit manager for running multiple contract audits concurrently.

Provides a ThreadPoolExecutor-based orchestrator with a Rich Live dashboard
that shows real-time status of each contract audit.
"""

import asyncio
import os
import signal
import sys
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from core.audit_progress import (
    AuditPhase,
    ContractAuditStatus,
    ThreadDemuxWriter,
)


class ParallelAuditManager:
    """Orchestrates parallel contract audits with a live dashboard."""

    def __init__(self, max_workers: int = 5):
        self.max_workers = max(1, min(max_workers, 8))
        self._statuses: Dict[str, ContractAuditStatus] = {}
        self._results: Dict[str, Any] = {}
        self._cancelled = False
        self._original_stdout = None
        self._demuxer: Optional[ThreadDemuxWriter] = None
        self._original_sigint = None

    # ── Public entry point ──────────────────────────────────────

    def run_parallel_audits(
        self,
        contract_paths: List[str],
        features: List[str],
        output_dir: str,
    ) -> Dict[str, Any]:
        """
        Run audits on multiple contracts in parallel.

        Returns dict mapping contract_path -> result dict with keys:
            success: bool, findings_count: int, error: Optional[str],
            elapsed: float, output_dir: str
        """
        # Clamp workers to number of contracts
        num_workers = min(self.max_workers, len(contract_paths))

        # Create per-contract status trackers
        for path in contract_paths:
            name = Path(path).stem
            self._statuses[path] = ContractAuditStatus(
                contract_name=name,
                contract_path=path,
            )

        # Install stdout demuxer
        self._original_stdout = sys.stdout
        self._demuxer = ThreadDemuxWriter(self._original_stdout)
        sys.stdout = self._demuxer

        # Install Ctrl+C handler
        self._install_signal_handler()

        futures: Dict[Future, str] = {}

        try:
            with ThreadPoolExecutor(max_workers=num_workers) as executor:
                for path in contract_paths:
                    if self._cancelled:
                        break
                    future = executor.submit(
                        self._audit_worker,
                        path,
                        features,
                        output_dir,
                    )
                    futures[future] = path

                # Run dashboard on main thread (blocks until done)
                self._run_dashboard(futures)

        finally:
            # Restore stdout and signal handler
            sys.stdout = self._original_stdout
            self._restore_signal_handler()

        return self._results

    # ── Worker ──────────────────────────────────────────────────

    def _audit_worker(
        self,
        contract_path: str,
        features: List[str],
        base_output_dir: str,
    ) -> None:
        """Per-thread audit worker. Creates a fresh AetherCLI per thread."""
        status = self._statuses[contract_path]

        # Register this thread with the demuxer
        if self._demuxer:
            self._demuxer.register(status)

        status.set_phase(AuditPhase.STARTING)

        # Per-contract output subdirectory
        contract_name = Path(contract_path).stem
        contract_output = os.path.join(base_output_dir, contract_name)
        os.makedirs(contract_output, exist_ok=True)

        try:
            # Fresh AetherCLI per thread — avoids shared _contract_path state
            from cli.main import AetherCLI
            cli = AetherCLI()

            asyncio.run(
                cli.run_audit(
                    contract_path=contract_path,
                    output_dir=contract_output,
                    enhanced="enhanced" in features,
                    ai_ensemble="ai_ensemble" in features,
                    llm_validation="llm_validation" in features,
                    foundry="foundry" in features,
                    enhanced_reports="enhanced_reports" in features,
                )
            )

            status.set_completed(status.findings_count)
            self._results[contract_path] = {
                "success": True,
                "findings_count": status.findings_count,
                "error": None,
                "elapsed": status.elapsed,
                "output_dir": contract_output,
            }

        except Exception as e:
            error_msg = str(e)[:200]
            status.set_failed(error_msg)
            self._results[contract_path] = {
                "success": False,
                "findings_count": status.findings_count,
                "error": error_msg,
                "elapsed": status.elapsed,
                "output_dir": contract_output,
            }

        finally:
            if self._demuxer:
                self._demuxer.unregister()

    # ── Dashboard ───────────────────────────────────────────────

    def _run_dashboard(self, futures: Dict[Future, str]) -> None:
        """
        Main-thread dashboard loop using Rich Live.
        Blocks until all futures complete or are cancelled.
        """
        # Use the original stdout so Rich doesn't go through the demuxer
        console = Console(file=self._original_stdout)

        with Live(
            self._build_dashboard(),
            console=console,
            refresh_per_second=2,
            transient=False,
        ) as live:
            while True:
                # Check if all done
                all_done = all(s.is_done for s in self._statuses.values())
                if all_done:
                    live.update(self._build_dashboard())
                    break

                # Check if cancelled and all running are done
                if self._cancelled:
                    # Cancel pending futures
                    for f in futures:
                        f.cancel()
                    # Wait a bit for running workers to finish
                    still_running = any(
                        not s.is_done
                        for s in self._statuses.values()
                        if s.phase != AuditPhase.QUEUED
                    )
                    if not still_running:
                        # Mark queued as failed
                        for s in self._statuses.values():
                            if s.phase == AuditPhase.QUEUED:
                                s.set_failed("Cancelled by user")
                                self._results[s.contract_path] = {
                                    "success": False,
                                    "findings_count": 0,
                                    "error": "Cancelled by user",
                                    "elapsed": None,
                                    "output_dir": "",
                                }
                        live.update(self._build_dashboard())
                        break

                live.update(self._build_dashboard())
                time.sleep(0.5)

    def _build_dashboard(self) -> Panel:
        """Build the Rich dashboard table."""
        table = Table(
            show_header=True,
            header_style="bold cyan",
            expand=True,
            pad_edge=True,
        )
        table.add_column("#", style="dim", width=4, justify="right")
        table.add_column("Contract", style="bold", min_width=20)
        table.add_column("Status", width=10, justify="center")
        table.add_column("Phase", min_width=16)
        table.add_column("Findings", width=8, justify="right")
        table.add_column("Time", width=8, justify="right")

        done_count = 0
        running_count = 0
        failed_count = 0
        total_findings = 0

        for i, (path, status) in enumerate(self._statuses.items(), 1):
            # Status badge
            if status.phase == AuditPhase.COMPLETED:
                status_text = Text("DONE", style="bold green")
                done_count += 1
            elif status.phase == AuditPhase.FAILED:
                status_text = Text("FAILED", style="bold red")
                failed_count += 1
            elif status.phase == AuditPhase.QUEUED:
                status_text = Text("QUEUED", style="dim")
            else:
                status_text = Text("RUNNING", style="bold cyan")
                running_count += 1

            # Phase display
            if status.phase == AuditPhase.FAILED and status.error:
                phase_text = Text(status.error[:30], style="red")
            else:
                phase_text = Text(status.phase.value)

            # Findings
            if status.phase == AuditPhase.QUEUED:
                finds_text = "-"
            else:
                finds_text = str(status.findings_count)
                total_findings += status.findings_count

            # Elapsed time
            elapsed = status.elapsed
            if elapsed is not None:
                mins, secs = divmod(int(elapsed), 60)
                time_text = f"{mins}:{secs:02d}"
            else:
                time_text = "-"

            table.add_row(
                str(i),
                status.contract_name,
                status_text,
                phase_text,
                finds_text,
                time_text,
            )

        # Summary footer
        queued_count = len(self._statuses) - done_count - running_count - failed_count
        parts = []
        if done_count:
            parts.append(f"[green]{done_count} done[/green]")
        if running_count:
            parts.append(f"[cyan]{running_count} running[/cyan]")
        if failed_count:
            parts.append(f"[red]{failed_count} failed[/red]")
        if queued_count > 0:
            parts.append(f"[dim]{queued_count} queued[/dim]")
        parts.append(f"{total_findings} total findings")
        summary = "  ".join(parts)

        if self._cancelled:
            summary += "  [yellow bold]CANCELLING...[/yellow bold]"

        return Panel(
            table,
            title="[bold cyan]Aether Parallel Audit[/bold cyan]",
            subtitle=summary,
            border_style="cyan",
            padding=(0, 1),
        )

    # ── Signal handling ─────────────────────────────────────────

    def _install_signal_handler(self) -> None:
        self._original_sigint = signal.getsignal(signal.SIGINT)
        self._ctrl_c_count = 0

        def _handler(signum, frame):
            self._ctrl_c_count += 1
            if self._ctrl_c_count >= 2:
                # Force exit on second Ctrl+C
                os._exit(1)
            self._cancelled = True

        signal.signal(signal.SIGINT, _handler)

    def _restore_signal_handler(self) -> None:
        if self._original_sigint is not None:
            signal.signal(signal.SIGINT, self._original_sigint)

    # ── Summary ─────────────────────────────────────────────────

    def get_summary(self) -> Dict[str, Any]:
        """Return a post-run summary dict."""
        completed = []
        failed = []
        total_findings = 0
        total_elapsed = 0.0

        for path, status in self._statuses.items():
            result = self._results.get(path, {})
            entry = {
                "contract": status.contract_name,
                "path": path,
                "findings": status.findings_count,
                "elapsed": status.elapsed,
                "output_dir": result.get("output_dir", ""),
            }
            if status.phase == AuditPhase.COMPLETED:
                completed.append(entry)
                total_findings += status.findings_count
            else:
                entry["error"] = status.error
                failed.append(entry)

            if status.elapsed:
                total_elapsed = max(total_elapsed, status.elapsed)

        return {
            "total_contracts": len(self._statuses),
            "completed": completed,
            "failed": failed,
            "total_findings": total_findings,
            "wall_time": total_elapsed,
            "cancelled": self._cancelled,
        }
