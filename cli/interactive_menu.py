"""
Interactive menu-driven TUI for Aether.

This module serves as the entry point that launches the Textual-based
persistent full-screen dashboard. All UI lives in cli/tui/.

Launch via `python aether.py`.
"""

import logging
import threading

from core.job_manager import JobManager

logger = logging.getLogger(__name__)


def _sage_auto_seed():
    """Check SAGE availability and seed if needed (runs in background)."""
    try:
        from core.sage_client import SageClient
        client = SageClient.get_instance()
        if not client.health_check():
            logger.debug("SAGE not available, skipping auto-seed")
            return
        from core.sage_seeder import SageSeeder
        seeder = SageSeeder(sage_client=client)
        result = seeder.seed_all()
        if result.get("status") != "already_seeded":
            total = sum(v for v in result.values() if isinstance(v, int))
            logger.info("SAGE auto-seeded %d memories", total)
    except Exception as exc:
        logger.debug("SAGE auto-seed failed: %s", exc)


def main():
    """Entry point for the Textual TUI dashboard."""
    # Ensure singleton is fresh
    JobManager.reset()

    # Auto-seed SAGE in background (non-blocking)
    threading.Thread(target=_sage_auto_seed, daemon=True, name="sage-seed").start()

    from cli.tui.app import AetherApp
    app = AetherApp()
    app.run()
    return 0
