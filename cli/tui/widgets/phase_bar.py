"""
Phase progress bar widget for the Aether v3.0 Textual TUI dashboard.

Displays a visual block-based progress bar showing the current audit
phase out of TOTAL_PHASES, with the phase name alongside.
"""

from __future__ import annotations

from textual.widgets import Static

from core.audit_progress import TOTAL_PHASES, AuditPhase, _PHASE_INDEX

# Block characters for the progress bar
_FILLED = "\u2588"   # Full block
_EMPTY = "\u2591"    # Light shade block

# Phase names in order (for display alongside the bar)
_PHASE_NAMES = [p for p in AuditPhase if p != AuditPhase.FAILED]


class PhaseBar(Static):
    """Visual block-based progress indicator for audit phases."""

    def on_mount(self) -> None:
        self.update_phase(0)

    def update_phase(self, phase_index: int, total: int = TOTAL_PHASES) -> None:
        """Render the phase bar with the given progress.

        Args:
            phase_index: Zero-based index of the current phase (0 = QUEUED).
            total: Total number of phases (default 12).
        """
        blocks: list[str] = []

        for i in range(total):
            if i < phase_index:
                # Completed phase: cyan filled block
                blocks.append(f"[cyan]{_FILLED}[/]")
            elif i == phase_index:
                # Current phase: bold cyan filled block
                blocks.append(f"[bold cyan]{_FILLED}[/]")
            else:
                # Remaining phase: dim empty block
                blocks.append(f"[dim]{_EMPTY}[/]")

        bar = "".join(blocks)

        # Determine the phase name to display
        phase_name = ""
        if 0 <= phase_index < len(_PHASE_NAMES):
            phase_name = _PHASE_NAMES[phase_index].value
        elif phase_index >= len(_PHASE_NAMES):
            phase_name = "Completed"

        display = f"{bar}  [bold]{phase_name}[/] ({phase_index}/{total})"
        self.update(display)

    def update_from_job(self, job) -> None:
        """Convenience method: update the bar from an AuditJob instance.

        Args:
            job: An AuditJob with an audit_status attribute.
        """
        if job.audit_status is not None:
            self.update_phase(job.audit_status.phase_index)
        else:
            self.update_phase(0)
