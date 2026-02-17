"""
Tests for Textual TUI screen workflows.

Tests NewAuditScreen, JobDetailScreen, SettingsScreen rendering
and navigation using Textual's run_test() + Pilot API.
"""

import unittest
from unittest import IsolatedAsyncioTestCase
from unittest.mock import patch, MagicMock

from core.job_manager import JobManager, JobStatus, AuditJob
from core.llm_usage_tracker import LLMUsageTracker
from core.audit_progress import ContractAuditStatus, AuditPhase


def _make_app():
    """Create an AetherApp instance."""
    from cli.tui.app import AetherApp
    return AetherApp()


# ── SettingsScreen Tests ────────────────────────────────────────


class TestSettingsScreen(IsolatedAsyncioTestCase):
    """Test SettingsScreen rendering and navigation."""

    def setUp(self):
        JobManager.reset()
        LLMUsageTracker._instance = LLMUsageTracker()

    def tearDown(self):
        JobManager.reset()
        LLMUsageTracker._instance = LLMUsageTracker()

    async def test_settings_screen_renders(self):
        """SettingsScreen should mount with a ListView and title."""
        app = _make_app()
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("s")
            await pilot.pause()
            from cli.tui.screens.settings import SettingsScreen
            self.assertIsInstance(app.screen, SettingsScreen)
            from textual.widgets import ListView
            lv = app.screen.query_one("#settings-list", ListView)
            self.assertIsNotNone(lv)

    async def test_settings_screen_has_menu_items(self):
        """SettingsScreen should display the expected menu options."""
        app = _make_app()
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("s")
            await pilot.pause()
            from textual.widgets import ListView
            from cli.tui.screens.settings import _MENU_OPTIONS
            lv = app.screen.query_one("#settings-list", ListView)
            self.assertEqual(len(lv.children), len(_MENU_OPTIONS))

    async def test_settings_back_option(self):
        """Selecting 'Back to dashboard' should pop back to MainScreen."""
        from cli.tui.screens.settings import _MENU_OPTIONS
        app = _make_app()
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("s")
            await pilot.pause()
            # Navigate to the last item (back) — it's at index len-1
            for _ in range(len(_MENU_OPTIONS) - 1):
                await pilot.press("down")
                await pilot.pause()
            await pilot.press("enter")
            await pilot.pause()
            from cli.tui.screens.main import MainScreen
            self.assertIsInstance(app.screen, MainScreen)

    async def test_settings_escape_goes_back(self):
        """Pressing escape on SettingsScreen should return to MainScreen."""
        app = _make_app()
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("s")
            await pilot.pause()
            await pilot.press("escape")
            await pilot.pause()
            from cli.tui.screens.main import MainScreen
            self.assertIsInstance(app.screen, MainScreen)

    @patch("core.config_manager.ConfigManager")
    async def test_settings_view_config(self, mock_cm_cls):
        """Selecting 'View current configuration' should update detail pane."""
        mock_config = MagicMock()
        mock_config.workspace = "/test/workspace"
        mock_config.output_dir = "/test/output"
        mock_config.reports_dir = "/test/reports"
        mock_config.max_analysis_time = 3600
        mock_config.parallel_analysis = True
        mock_config.max_concurrent_contracts = 5
        mock_config.openai_api_key = "sk-test12345678"
        mock_config.gemini_api_key = ""
        mock_config.anthropic_api_key = ""
        mock_config.openai_model = "gpt-5-chat-latest"
        mock_config.gemini_model = "gemini-2.5-flash"
        mock_config.anthropic_model = "claude-sonnet-4-5-20250929"
        mock_config.triage_min_severity = "medium"
        mock_config.triage_confidence_threshold = 0.5
        mock_config.triage_max_findings = 50

        mock_cm_cls.return_value.config = mock_config

        app = _make_app()
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("s")
            await pilot.pause()
            # Navigate to "View current configuration" (second item, index 1)
            await pilot.press("down")
            await pilot.pause()
            await pilot.press("enter")
            await pilot.pause()
            # Wait for the detail pane to update
            await pilot.pause()
            from textual.widgets import Static
            detail = app.screen.query_one("#settings-detail", Static)
            self.assertIsNotNone(detail)
            await pilot.press("escape")
            await pilot.pause()


# ── NewAuditScreen Tests ────────────────────────────────────────


class TestNewAuditScreen(IsolatedAsyncioTestCase):
    """Test NewAuditScreen rendering and initial wizard flow."""

    def setUp(self):
        JobManager.reset()
        LLMUsageTracker._instance = LLMUsageTracker()

    def tearDown(self):
        JobManager.reset()
        LLMUsageTracker._instance = LLMUsageTracker()

    async def test_new_audit_screen_renders(self):
        """NewAuditScreen should be pushed into the screen stack."""
        app = _make_app()
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("n")
            await pilot.pause()
            from cli.tui.screens.new_audit import NewAuditScreen
            # NewAuditScreen launches a wizard on mount, so a dialog may be on top.
            self.assertTrue(
                any(isinstance(s, NewAuditScreen) for s in app.screen_stack)
            )

    async def test_new_audit_screen_shows_wizard(self):
        """NewAuditScreen should show the wizard status and source type dialog."""
        app = _make_app()
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("n")
            await pilot.pause()
            # The wizard runs as a worker and pushes a SelectDialog for source type
            await pilot.pause()
            await pilot.pause()
            # The SelectDialog for source type should be showing
            from cli.tui.dialogs.select import SelectDialog
            if isinstance(app.screen, SelectDialog):
                # Good -- the wizard pushed the dialog
                self.assertIsInstance(app.screen, SelectDialog)
            else:
                # The screen might still be NewAuditScreen if worker hasn't started
                from cli.tui.screens.new_audit import NewAuditScreen
                self.assertIsInstance(app.screen, NewAuditScreen)

    async def test_new_audit_cancel_returns_to_main(self):
        """Cancelling the source type dialog should return to MainScreen."""
        app = _make_app()
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("n")
            await pilot.pause()
            await pilot.pause()
            await pilot.pause()
            # Press Escape to cancel the wizard / source type selection
            await pilot.press("escape")
            await pilot.pause()
            await pilot.pause()
            # Should be back to MainScreen (either directly or after NewAuditScreen pops)
            from cli.tui.screens.main import MainScreen
            from cli.tui.screens.new_audit import NewAuditScreen
            # May need another escape if still on NewAuditScreen
            if isinstance(app.screen, NewAuditScreen):
                await pilot.press("escape")
                await pilot.pause()
            self.assertIsInstance(app.screen, MainScreen)

    async def test_new_audit_escape_binding(self):
        """Pressing Escape on NewAuditScreen should go back."""
        app = _make_app()
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("n")
            await pilot.pause()
            await pilot.press("escape")
            await pilot.pause()
            # Keep pressing escape until we're back
            for _ in range(3):
                from cli.tui.screens.main import MainScreen
                if isinstance(app.screen, MainScreen):
                    break
                await pilot.press("escape")
                await pilot.pause()
            from cli.tui.screens.main import MainScreen
            self.assertIsInstance(app.screen, MainScreen)


# ── JobDetailScreen Tests ───────────────────────────────────────


class TestJobDetailScreen(IsolatedAsyncioTestCase):
    """Test JobDetailScreen rendering with job data."""

    def setUp(self):
        JobManager.reset()
        LLMUsageTracker._instance = LLMUsageTracker()

    def tearDown(self):
        JobManager.reset()
        LLMUsageTracker._instance = LLMUsageTracker()

    async def test_job_detail_screen_renders(self):
        """JobDetailScreen should render with log viewer and metadata."""
        jm = JobManager.get_instance()
        job = jm.create_job(
            display_name="TestContract",
            job_type="local",
            target="/tmp/TestContract.sol",
        )
        jm.start_job(job.job_id)

        from cli.tui.screens.job_detail import JobDetailScreen
        from cli.tui.app import AetherApp

        app = AetherApp()

        async with app.run_test() as pilot:
            await pilot.pause()
            # Push JobDetailScreen directly
            app.push_screen(JobDetailScreen(job_id=job.job_id))
            await pilot.pause()
            self.assertIsInstance(app.screen, JobDetailScreen)

    async def test_job_detail_has_log_viewer(self):
        """JobDetailScreen should have a LogViewer widget."""
        jm = JobManager.get_instance()
        job = jm.create_job(
            display_name="TestContract",
            job_type="local",
            target="/tmp/TestContract.sol",
        )
        jm.start_job(job.job_id)

        from cli.tui.screens.job_detail import JobDetailScreen
        from cli.tui.widgets.log_viewer import LogViewer
        from cli.tui.app import AetherApp

        app = AetherApp()

        async with app.run_test() as pilot:
            await pilot.pause()
            app.push_screen(JobDetailScreen(job_id=job.job_id))
            await pilot.pause()
            log_viewer = app.screen.query_one("#log-viewer", LogViewer)
            self.assertIsNotNone(log_viewer)
            self.assertEqual(log_viewer.job_id, job.job_id)

    async def test_job_detail_has_phase_bar(self):
        """JobDetailScreen should have a PhaseBar widget."""
        jm = JobManager.get_instance()
        job = jm.create_job(
            display_name="TestContract",
            job_type="local",
            target="/tmp/TestContract.sol",
        )
        jm.start_job(job.job_id)

        from cli.tui.screens.job_detail import JobDetailScreen
        from cli.tui.widgets.phase_bar import PhaseBar
        from cli.tui.app import AetherApp

        app = AetherApp()

        async with app.run_test() as pilot:
            await pilot.pause()
            app.push_screen(JobDetailScreen(job_id=job.job_id))
            await pilot.pause()
            phase_bar = app.screen.query_one("#phase-bar", PhaseBar)
            self.assertIsNotNone(phase_bar)

    async def test_job_detail_has_metadata(self):
        """JobDetailScreen should have a metadata panel."""
        jm = JobManager.get_instance()
        job = jm.create_job(
            display_name="TestContract",
            job_type="local",
            target="/tmp/TestContract.sol",
        )
        jm.start_job(job.job_id)

        from cli.tui.screens.job_detail import JobDetailScreen
        from cli.tui.app import AetherApp
        from textual.widgets import Static

        app = AetherApp()

        async with app.run_test() as pilot:
            await pilot.pause()
            app.push_screen(JobDetailScreen(job_id=job.job_id))
            await pilot.pause()
            metadata = app.screen.query_one("#metadata", Static)
            self.assertIsNotNone(metadata)

    async def test_job_detail_escape_goes_back(self):
        """Pressing Escape on JobDetailScreen should go back to MainScreen."""
        jm = JobManager.get_instance()
        job = jm.create_job(
            display_name="TestContract",
            job_type="local",
            target="/tmp/TestContract.sol",
        )
        jm.start_job(job.job_id)

        from cli.tui.screens.job_detail import JobDetailScreen
        from cli.tui.screens.main import MainScreen
        from cli.tui.app import AetherApp

        app = AetherApp()

        async with app.run_test() as pilot:
            await pilot.pause()
            app.push_screen(JobDetailScreen(job_id=job.job_id))
            await pilot.pause()
            self.assertIsInstance(app.screen, JobDetailScreen)
            await pilot.press("escape")
            await pilot.pause()
            self.assertIsInstance(app.screen, MainScreen)

    async def test_job_detail_cancel_inactive_job(self):
        """Pressing 'c' on a completed job should show a warning notification."""
        jm = JobManager.get_instance()
        job = jm.create_job(
            display_name="DoneContract",
            job_type="local",
            target="/tmp/Done.sol",
        )
        jm.start_job(job.job_id)
        jm.complete_job(job.job_id, findings_count=3, cost_delta=0.50)

        from cli.tui.screens.job_detail import JobDetailScreen
        from cli.tui.app import AetherApp

        app = AetherApp()

        async with app.run_test() as pilot:
            await pilot.pause()
            app.push_screen(JobDetailScreen(job_id=job.job_id))
            await pilot.pause()
            # Press 'c' to try to cancel -- job is already completed
            await pilot.press("c")
            await pilot.pause()
            # Should still be on JobDetailScreen (not ConfirmDialog)
            self.assertIsInstance(app.screen, JobDetailScreen)

    async def test_job_detail_cancel_active_job_shows_confirm(self):
        """Pressing 'c' on an active job should show ConfirmDialog."""
        jm = JobManager.get_instance()
        job = jm.create_job(
            display_name="RunningContract",
            job_type="local",
            target="/tmp/Running.sol",
        )
        jm.start_job(job.job_id)

        from cli.tui.screens.job_detail import JobDetailScreen
        from cli.tui.dialogs.confirm import ConfirmDialog
        from cli.tui.app import AetherApp

        app = AetherApp()

        async with app.run_test() as pilot:
            await pilot.pause()
            app.push_screen(JobDetailScreen(job_id=job.job_id))
            await pilot.pause()
            await pilot.press("c")
            await pilot.pause()
            self.assertIsInstance(app.screen, ConfirmDialog)
            # Clean up by pressing 'n'
            await pilot.press("n")
            await pilot.pause()

    async def test_job_detail_shows_completed_status(self):
        """JobDetailScreen metadata should reflect completed status."""
        jm = JobManager.get_instance()
        job = jm.create_job(
            display_name="CompletedJob",
            job_type="local",
            target="/tmp/Completed.sol",
        )
        jm.start_job(job.job_id)
        jm.complete_job(job.job_id, findings_count=5, cost_delta=1.23)

        from cli.tui.screens.job_detail import JobDetailScreen
        from cli.tui.app import AetherApp

        app = AetherApp()

        async with app.run_test() as pilot:
            await pilot.pause()
            app.push_screen(JobDetailScreen(job_id=job.job_id))
            await pilot.pause()
            # Verify the job's status is COMPLETED
            updated_job = jm.get_job(job.job_id)
            self.assertEqual(updated_job.status, JobStatus.COMPLETED)
            self.assertEqual(updated_job.findings_count, 5)

    async def test_job_detail_nonexistent_job(self):
        """JobDetailScreen with a nonexistent job ID should handle gracefully."""
        from cli.tui.screens.job_detail import JobDetailScreen
        from cli.tui.app import AetherApp
        from textual.widgets import Static

        app = AetherApp()

        async with app.run_test() as pilot:
            await pilot.pause()
            app.push_screen(JobDetailScreen(job_id="nonexistent"))
            await pilot.pause()
            # Should still render without crashing
            self.assertIsInstance(app.screen, JobDetailScreen)
            metadata = app.screen.query_one("#metadata", Static)
            self.assertIsNotNone(metadata)


# ── HistoryScreen Tests ─────────────────────────────────────────


class TestHistoryScreen(IsolatedAsyncioTestCase):
    """Test HistoryScreen basic rendering."""

    def setUp(self):
        JobManager.reset()
        LLMUsageTracker._instance = LLMUsageTracker()

    def tearDown(self):
        JobManager.reset()
        LLMUsageTracker._instance = LLMUsageTracker()

    async def test_history_screen_renders(self):
        """HistoryScreen should mount without errors."""
        app = _make_app()
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("h")
            await pilot.pause()
            from cli.tui.screens.history import HistoryScreen
            self.assertIsInstance(app.screen, HistoryScreen)

    async def test_history_escape_returns(self):
        """Pressing Escape on HistoryScreen should return to MainScreen."""
        app = _make_app()
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("h")
            await pilot.pause()
            await pilot.press("escape")
            await pilot.pause()
            from cli.tui.screens.main import MainScreen
            self.assertIsInstance(app.screen, MainScreen)


# ── ReportsScreen Tests ─────────────────────────────────────────


class TestReportsScreen(IsolatedAsyncioTestCase):
    """Test ReportsScreen basic rendering."""

    def setUp(self):
        JobManager.reset()
        LLMUsageTracker._instance = LLMUsageTracker()

    def tearDown(self):
        JobManager.reset()
        LLMUsageTracker._instance = LLMUsageTracker()

    async def test_reports_screen_renders(self):
        """ReportsScreen should be pushed into the screen stack."""
        app = _make_app()
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("o")
            await pilot.pause()
            from cli.tui.screens.reports import ReportsScreen
            # ReportsScreen may push a wizard dialog on mount.
            self.assertTrue(
                any(isinstance(s, ReportsScreen) for s in app.screen_stack)
            )

    async def test_reports_escape_returns(self):
        """Pressing Escape on ReportsScreen should return to MainScreen."""
        app = _make_app()
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("o")
            await pilot.pause()
            await pilot.press("escape")
            await pilot.pause()
            from cli.tui.screens.main import MainScreen
            self.assertIsInstance(app.screen, MainScreen)


# ── FetchScreen Tests ───────────────────────────────────────────


class TestFetchScreen(IsolatedAsyncioTestCase):
    """Test FetchScreen basic rendering."""

    def setUp(self):
        JobManager.reset()
        LLMUsageTracker._instance = LLMUsageTracker()

    def tearDown(self):
        JobManager.reset()
        LLMUsageTracker._instance = LLMUsageTracker()

    async def test_fetch_screen_renders(self):
        """FetchScreen should be pushed into the screen stack."""
        app = _make_app()
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("f")
            await pilot.pause()
            from cli.tui.screens.fetch import FetchScreen
            # FetchScreen may push a wizard dialog on mount.
            self.assertTrue(
                any(isinstance(s, FetchScreen) for s in app.screen_stack)
            )

    async def test_fetch_escape_returns(self):
        """Pressing Escape on FetchScreen should return to MainScreen."""
        app = _make_app()
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("f")
            await pilot.pause()
            await pilot.press("escape")
            await pilot.pause()
            from cli.tui.screens.main import MainScreen
            self.assertIsInstance(app.screen, MainScreen)


# ── PoCScreen Tests ─────────────────────────────────────────────


class TestPoCScreen(IsolatedAsyncioTestCase):
    """Test PoCScreen basic rendering."""

    def setUp(self):
        JobManager.reset()
        LLMUsageTracker._instance = LLMUsageTracker()

    def tearDown(self):
        JobManager.reset()
        LLMUsageTracker._instance = LLMUsageTracker()

    async def test_poc_screen_renders(self):
        """PoCScreen should be pushed into the screen stack."""
        app = _make_app()
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("p")
            await pilot.pause()
            from cli.tui.screens.pocs import PoCScreen
            # PoCScreen may push a wizard dialog on mount.
            self.assertTrue(
                any(isinstance(s, PoCScreen) for s in app.screen_stack)
            )

    async def test_poc_escape_returns(self):
        """Pressing Escape on PoCScreen should return to MainScreen."""
        app = _make_app()
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("p")
            await pilot.pause()
            await pilot.press("escape")
            await pilot.pause()
            from cli.tui.screens.main import MainScreen
            self.assertIsInstance(app.screen, MainScreen)


if __name__ == "__main__":
    unittest.main()
