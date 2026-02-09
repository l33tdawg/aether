"""
Interactive menu-driven TUI for Aether.

This module serves as the entry point that launches the Textual-based
persistent full-screen dashboard. All UI lives in cli/tui/.

Launch via `python aether.py`.
"""

from core.job_manager import JobManager


def main():
    """Entry point for the Textual TUI dashboard."""
    # Ensure singleton is fresh
    JobManager.reset()

    from cli.tui.app import AetherApp
    app = AetherApp()
    app.run()
    return 0
