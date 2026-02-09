"""
Post-audit summary panel with LLM cost breakdown.

Shared by both single-audit and parallel-audit flows.
"""

from typing import List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from core.audit_progress import AuditPhase, ContractAuditStatus


class PostAuditSummary:
    """Renders a post-audit summary panel with LLM usage breakdown."""

    @staticmethod
    def render(
        console: Console,
        statuses: List[ContractAuditStatus],
        wall_time: float = 0.0,
    ) -> None:
        """Print a Rich panel summarizing the audit run."""
        from core.llm_usage_tracker import LLMUsageTracker

        tracker = LLMUsageTracker.get_instance()
        summary = tracker.get_summary()

        completed = sum(1 for s in statuses if s.phase == AuditPhase.COMPLETED)
        failed = sum(1 for s in statuses if s.phase == AuditPhase.FAILED)
        total_findings = sum(s.findings_count for s in statuses)

        table = Table(show_header=False, expand=True, box=None, pad_edge=True)
        table.add_column("Key", style="bold", width=20)
        table.add_column("Value")

        # Contracts
        total_contracts = len(statuses)
        parts = []
        if completed:
            parts.append(f"[green]{completed} completed[/green]")
        if failed:
            parts.append(f"[red]{failed} failed[/red]")
        table.add_row("Contracts", f"{total_contracts} total ({', '.join(parts)})" if parts else str(total_contracts))

        # Total findings
        table.add_row("Total Findings", f"[yellow]{total_findings}[/yellow]")

        # LLM Usage section
        table.add_row("", "")  # spacer
        table.add_row("[bold]LLM Usage[/bold]", "")
        table.add_row("  API Calls", str(summary["total_calls"]))

        input_k = summary["total_input_tokens"] / 1000
        output_k = summary["total_output_tokens"] / 1000
        table.add_row(
            "  Tokens",
            f"{summary['total_tokens']:,} ({input_k:,.1f}K in / {output_k:,.1f}K out)",
        )

        # Cost by Provider
        by_provider = summary.get("by_provider", {})
        if by_provider:
            table.add_row("", "")  # spacer
            table.add_row("[bold]Cost by Provider[/bold]", "")
            for provider, pdata in sorted(by_provider.items()):
                prov_name = provider.capitalize()
                calls = int(pdata["calls"])
                cost = pdata["cost"]
                table.add_row(
                    f"  {prov_name}",
                    f"{calls} calls  ${cost:.4f}",
                )

        # Total Cost
        table.add_row("", "")  # spacer
        total_cost = summary["total_cost_usd"]
        table.add_row(
            "[bold]Total Cost[/bold]",
            Text(f"${total_cost:.4f}", style="bold yellow"),
        )

        # Wall Time
        if wall_time and wall_time > 0:
            mins, secs = divmod(int(wall_time), 60)
            table.add_row("Wall Time", f"{mins}:{secs:02d}")

        console.print()
        console.print(
            Panel(
                table,
                title="[bold cyan]Audit Summary[/bold cyan]",
                border_style="cyan",
                padding=(0, 1),
            )
        )
