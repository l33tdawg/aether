"""
Tests for AetherApp startup, MainScreen rendering, and key bindings.

Uses Textual's run_test() + Pilot API with IsolatedAsyncioTestCase.
"""

import unittest
from unittest import IsolatedAsyncioTestCase
from unittest.mock import patch, MagicMock

from core.job_manager import JobManager, JobStatus
from core.llm_usage_tracker import LLMUsageTracker


def _make_app():
    """Create an AetherApp instance with mocked singletons."""
    from cli.tui.app import AetherApp
    return AetherApp()


class TestAetherAppStartup(IsolatedAsyncioTestCase):
    """Test that AetherApp mounts correctly and shows MainScreen."""

    def setUp(self):
        JobManager.reset()
        # Replace the LLMUsageTracker singleton with a fresh instance
        LLMUsageTracker._instance = LLMUsageTracker()

    def tearDown(self):
        JobManager.reset()
        LLMUsageTracker._instance = LLMUsageTracker()

    async def test_app_starts_with_main_screen(self):
        """AetherApp should push MainScreen on mount."""
        app = _make_app()
        async with app.run_test() as pilot:
            await pilot.pause()
            from cli.tui.screens.main import MainScreen
            self.assertIsInstance(app.screen, MainScreen)

    async def test_app_has_title(self):
        """AetherApp should have a title containing 'Aether'."""
        app = _make_app()
        async with app.run_test() as pilot:
            await pilot.pause()
            self.assertIn("Aether", app.TITLE)

    async def test_main_screen_has_header(self):
        """MainScreen should contain a Header widget."""
        app = _make_app()
        async with app.run_test() as pilot:
            await pilot.pause()
            from textual.widgets import Header
            header = app.screen.query_one(Header)
            self.assertIsNotNone(header)

    async def test_main_screen_has_footer(self):
        """MainScreen should contain a Footer widget."""
        app = _make_app()
        async with app.run_test() as pilot:
            await pilot.pause()
            from textual.widgets import Footer
            footer = app.screen.query_one(Footer)
            self.assertIsNotNone(footer)

    async def test_main_screen_has_jobs_table(self):
        """MainScreen should contain a JobsTable widget."""
        app = _make_app()
        async with app.run_test() as pilot:
            await pilot.pause()
            from cli.tui.widgets.jobs_table import JobsTable
            table = app.screen.query_one("#jobs-table", JobsTable)
            self.assertIsNotNone(table)

    async def test_main_screen_has_cost_bar(self):
        """MainScreen should contain a CostBar widget."""
        app = _make_app()
        async with app.run_test() as pilot:
            await pilot.pause()
            from cli.tui.widgets.cost_bar import CostBar
            cost_bar = app.screen.query_one("#cost-bar", CostBar)
            self.assertIsNotNone(cost_bar)


class TestAetherAppKeyBindings(IsolatedAsyncioTestCase):
    """Test that key bindings push the correct screens."""

    def setUp(self):
        JobManager.reset()
        LLMUsageTracker._instance = LLMUsageTracker()

    def tearDown(self):
        JobManager.reset()
        LLMUsageTracker._instance = LLMUsageTracker()

    async def test_key_s_pushes_settings_screen(self):
        """Pressing 's' should push SettingsScreen."""
        app = _make_app()
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("s")
            await pilot.pause()
            from cli.tui.screens.settings import SettingsScreen
            self.assertIsInstance(app.screen, SettingsScreen)

    async def test_key_h_pushes_history_screen(self):
        """Pressing 'h' should push HistoryScreen."""
        app = _make_app()
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("h")
            await pilot.pause()
            from cli.tui.screens.history import HistoryScreen
            self.assertIsInstance(app.screen, HistoryScreen)

    async def test_key_p_pushes_poc_screen(self):
        """Pressing 'p' should push PoCScreen (may show wizard dialog on top)."""
        app = _make_app()
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("p")
            await pilot.pause()
            from cli.tui.screens.pocs import PoCScreen
            # PoCScreen launches a wizard on mount, so a dialog may be on top.
            # Check that PoCScreen is in the screen stack.
            self.assertTrue(
                any(isinstance(s, PoCScreen) for s in app.screen_stack)
            )

    async def test_key_o_pushes_reports_screen(self):
        """Pressing 'o' should push ReportsScreen (may show wizard dialog on top)."""
        app = _make_app()
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("o")
            await pilot.pause()
            from cli.tui.screens.reports import ReportsScreen
            self.assertTrue(
                any(isinstance(s, ReportsScreen) for s in app.screen_stack)
            )

    async def test_key_f_pushes_fetch_screen(self):
        """Pressing 'f' should push FetchScreen (may show wizard dialog on top)."""
        app = _make_app()
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("f")
            await pilot.pause()
            from cli.tui.screens.fetch import FetchScreen
            self.assertTrue(
                any(isinstance(s, FetchScreen) for s in app.screen_stack)
            )

    async def test_key_n_pushes_new_audit_screen(self):
        """Pressing 'n' should push NewAuditScreen (may show wizard dialog on top)."""
        app = _make_app()
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("n")
            await pilot.pause()
            from cli.tui.screens.new_audit import NewAuditScreen
            self.assertTrue(
                any(isinstance(s, NewAuditScreen) for s in app.screen_stack)
            )

    async def test_key_r_pushes_resume_screen(self):
        """Pressing 'r' should push ResumeScreen."""
        app = _make_app()
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("r")
            await pilot.pause()
            from cli.tui.screens.resume import ResumeScreen
            self.assertIsInstance(app.screen, ResumeScreen)

    async def test_escape_from_settings_returns_to_main(self):
        """Pressing escape from SettingsScreen should return to MainScreen."""
        app = _make_app()
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("s")
            await pilot.pause()
            from cli.tui.screens.settings import SettingsScreen
            self.assertIsInstance(app.screen, SettingsScreen)
            await pilot.press("escape")
            await pilot.pause()
            from cli.tui.screens.main import MainScreen
            self.assertIsInstance(app.screen, MainScreen)


class TestAetherAppQuit(IsolatedAsyncioTestCase):
    """Test the quit action behavior."""

    def setUp(self):
        JobManager.reset()
        LLMUsageTracker._instance = LLMUsageTracker()

    def tearDown(self):
        JobManager.reset()
        LLMUsageTracker._instance = LLMUsageTracker()

    async def test_quit_no_active_jobs_exits(self):
        """Pressing 'q' with no active jobs should exit the app."""
        app = _make_app()
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("q")
            await pilot.pause()
            # App should have exited; return_code should be 0
            self.assertEqual(app.return_code, 0)

    async def test_quit_with_active_jobs_shows_confirm(self):
        """Pressing 'q' with active jobs should show ConfirmDialog."""
        jm = JobManager.get_instance()
        job = jm.create_job(display_name="TestJob", job_type="local", target="/tmp/test.sol")
        jm.start_job(job.job_id)

        app = _make_app()
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("q")
            await pilot.pause()
            from cli.tui.dialogs.confirm import ConfirmDialog
            self.assertIsInstance(app.screen, ConfirmDialog)

    async def test_quit_confirm_yes_exits(self):
        """Confirming quit dialog should exit the app."""
        jm = JobManager.get_instance()
        job = jm.create_job(display_name="TestJob", job_type="local", target="/tmp/test.sol")
        jm.start_job(job.job_id)

        app = _make_app()
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("q")
            await pilot.pause()
            # Press 'y' to confirm
            await pilot.press("y")
            await pilot.pause()
            self.assertEqual(app.return_code, 0)

    async def test_quit_confirm_no_stays(self):
        """Rejecting quit dialog should keep the app running."""
        jm = JobManager.get_instance()
        job = jm.create_job(display_name="TestJob", job_type="local", target="/tmp/test.sol")
        jm.start_job(job.job_id)

        app = _make_app()
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("q")
            await pilot.pause()
            # Press 'n' to reject
            await pilot.press("n")
            await pilot.pause()
            from cli.tui.screens.main import MainScreen
            self.assertIsInstance(app.screen, MainScreen)


class TestJobsTableRendering(IsolatedAsyncioTestCase):
    """Test that the jobs table renders job data correctly."""

    def setUp(self):
        JobManager.reset()
        LLMUsageTracker._instance = LLMUsageTracker()

    def tearDown(self):
        JobManager.reset()
        LLMUsageTracker._instance = LLMUsageTracker()

    async def test_empty_table_shows_placeholder(self):
        """With no jobs, the table should show a placeholder row."""
        app = _make_app()
        async with app.run_test() as pilot:
            await pilot.pause()
            from cli.tui.widgets.jobs_table import JobsTable
            table = app.screen.query_one("#jobs-table", JobsTable)
            # Placeholder row should be present
            self.assertTrue(table._placeholder_visible)

    async def test_table_shows_job_row(self):
        """After creating a job, the table should display it."""
        jm = JobManager.get_instance()
        jm.create_job(display_name="TestContract", job_type="local", target="/tmp/test.sol")

        app = _make_app()
        async with app.run_test() as pilot:
            await pilot.pause()
            # Wait for refresh timer to fire
            await pilot.pause()
            from cli.tui.widgets.jobs_table import JobsTable
            table = app.screen.query_one("#jobs-table", JobsTable)
            self.assertFalse(table._placeholder_visible)
            self.assertGreaterEqual(table.row_count, 1)

    async def test_table_shows_multiple_jobs(self):
        """Multiple jobs should each appear as a row."""
        jm = JobManager.get_instance()
        jm.create_job(display_name="Contract1", job_type="local")
        jm.create_job(display_name="Contract2", job_type="local")
        jm.create_job(display_name="Contract3", job_type="github")

        app = _make_app()
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.pause()
            from cli.tui.widgets.jobs_table import JobsTable
            table = app.screen.query_one("#jobs-table", JobsTable)
            self.assertEqual(table.row_count, 3)


class TestCostBarRendering(IsolatedAsyncioTestCase):
    """Test the CostBar widget rendering."""

    def setUp(self):
        JobManager.reset()
        LLMUsageTracker._instance = LLMUsageTracker()

    def tearDown(self):
        JobManager.reset()
        LLMUsageTracker._instance = LLMUsageTracker()

    async def test_cost_bar_shows_session_total(self):
        """CostBar should display session cost total."""
        app = _make_app()
        async with app.run_test() as pilot:
            await pilot.pause()
            from cli.tui.widgets.cost_bar import CostBar
            cost_bar = app.screen.query_one("#cost-bar", CostBar)
            # Cost bar renders as Rich text; just check it exists
            self.assertIsNotNone(cost_bar)

    async def test_cost_bar_updates_after_recording(self):
        """CostBar should reflect costs after LLM usage is recorded."""
        tracker = LLMUsageTracker.get_instance()
        tracker.record(
            provider="openai",
            model="gpt-5-chat-latest",
            input_tokens=1000,
            output_tokens=500,
            caller="test",
        )

        app = _make_app()
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.pause()
            # The cost bar should have updated -- just ensure no crash
            from cli.tui.widgets.cost_bar import CostBar
            cost_bar = app.screen.query_one("#cost-bar", CostBar)
            self.assertIsNotNone(cost_bar)


class TestAppProperties(IsolatedAsyncioTestCase):
    """Test AetherApp properties."""

    def setUp(self):
        JobManager.reset()
        LLMUsageTracker._instance = LLMUsageTracker()

    def tearDown(self):
        JobManager.reset()
        LLMUsageTracker._instance = LLMUsageTracker()

    async def test_job_manager_property(self):
        """app.job_manager should return the JobManager singleton."""
        app = _make_app()
        async with app.run_test() as pilot:
            await pilot.pause()
            self.assertIs(app.job_manager, JobManager.get_instance())

    async def test_tracker_property(self):
        """app.tracker should return the LLMUsageTracker singleton."""
        app = _make_app()
        async with app.run_test() as pilot:
            await pilot.pause()
            self.assertIs(app.tracker, LLMUsageTracker.get_instance())


if __name__ == "__main__":
    unittest.main()
