"""
Cost bar widget for the Aether v3.0 Textual TUI dashboard.

Displays a single-line summary of session LLM costs broken down by provider,
plus SAGE institutional memory connection status.
"""

from __future__ import annotations

from rich.text import Text
from textual.widgets import Static

from core.llm_usage_tracker import LLMUsageTracker


# Canonical display order for providers
_PROVIDER_ORDER = ["openai", "gemini", "anthropic"]

# Display-friendly provider names
_PROVIDER_NAMES = {
    "openai": "OpenAI",
    "gemini": "Gemini",
    "anthropic": "Anthropic",
}


class CostBar(Static):
    """Single-line cost summary bar showing session totals by provider."""

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._sage_status: str | None = None  # Cache to avoid hitting SAGE every second
        self._sage_check_counter: int = 0

    def on_mount(self) -> None:
        self.refresh_cost()

    def refresh_cost(self) -> None:
        """Read LLMUsageTracker and update the display."""
        tracker = LLMUsageTracker.get_instance()
        summary = tracker.get_summary()

        total_cost = summary.get("total_cost_usd", 0.0)
        by_provider = summary.get("by_provider", {})

        parts: list[str] = []
        parts.append(f"[bold]Session: ${total_cost:.2f}[/bold]")

        # Show each provider in canonical order, then any extras
        shown = set()
        for key in _PROVIDER_ORDER:
            if key in by_provider:
                prov = by_provider[key]
                name = _PROVIDER_NAMES.get(key, key.title())
                cost = prov.get("cost", 0.0)
                calls = int(prov.get("calls", 0))
                parts.append(f"[bold]{name}:[/bold] ${cost:.2f} ({calls})")
                shown.add(key)

        # Any providers not in canonical order
        for key, prov in by_provider.items():
            if key not in shown:
                name = _PROVIDER_NAMES.get(key, key.title())
                cost = prov.get("cost", 0.0)
                calls = int(prov.get("calls", 0))
                parts.append(f"[bold]{name}:[/bold] ${cost:.2f} ({calls})")

        # SAGE status — check every 30 refreshes (~30s) to avoid overhead
        self._sage_check_counter += 1
        if self._sage_status is None or self._sage_check_counter >= 30:
            self._sage_check_counter = 0
            self._sage_status = self._get_sage_status()
        parts.append(self._sage_status)

        display = "  |  ".join(parts)
        self.update(display)

    @staticmethod
    def _get_sage_status() -> str:
        """Return a short SAGE status string for the cost bar."""
        try:
            from core.sage_client import SageClient
            client = SageClient.get_instance()
            if client.health_check():
                status = client.get_status()
                mem_count = status.get("total_memories", "?")
                return f"[bold]SAGE:[/bold] [green]ON[/green] ({mem_count})"
            return "[bold]SAGE:[/bold] [dim]OFF[/dim]"
        except Exception:
            return "[bold]SAGE:[/bold] [dim]OFF[/dim]"
