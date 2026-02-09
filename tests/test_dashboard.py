"""Tests for the Aether v3.0 Textual TUI dashboard."""

import unittest
from unittest.mock import patch, MagicMock

from core.job_manager import JobManager, JobStatus
from core.llm_usage_tracker import LLMUsageTracker
from core.audit_progress import ContractAuditStatus, AuditPhase, ThreadDemuxWriter


class TestLogBuffer(unittest.TestCase):
    """Test the log buffer added to ContractAuditStatus."""

    def test_append_log(self):
        status = ContractAuditStatus("Test", "/path/test.sol")
        status.append_log("line 1")
        status.append_log("line 2")
        lines = status.get_all_log_lines()
        self.assertEqual(lines, ["line 1", "line 2"])

    def test_get_new_log_lines(self):
        status = ContractAuditStatus("Test", "/path/test.sol")
        status.append_log("line 1")
        status.append_log("line 2")

        # First call gets all lines
        new = status.get_new_log_lines()
        self.assertEqual(new, ["line 1", "line 2"])

        # Second call with no new lines
        new = status.get_new_log_lines()
        self.assertEqual(new, [])

        # Add more and check
        status.append_log("line 3")
        new = status.get_new_log_lines()
        self.assertEqual(new, ["line 3"])

    def test_log_buffer_trim(self):
        """Log buffer trims when exceeding max size."""
        from core.audit_progress import LOG_BUFFER_MAX, LOG_BUFFER_TRIM

        status = ContractAuditStatus("Test", "/path/test.sol")
        for i in range(LOG_BUFFER_MAX + 100):
            status.append_log(f"line {i}")

        lines = status.get_all_log_lines()
        self.assertLessEqual(len(lines), LOG_BUFFER_MAX)

    def test_get_all_log_lines_returns_copy(self):
        status = ContractAuditStatus("Test", "/path/test.sol")
        status.append_log("line 1")
        lines = status.get_all_log_lines()
        lines.append("extra")
        self.assertEqual(len(status.get_all_log_lines()), 1)


class TestThreadDemuxWriterLogBuffer(unittest.TestCase):
    """Test that ThreadDemuxWriter stores lines in the log buffer."""

    def test_write_stores_in_log_buffer(self):
        import io
        import threading

        original = io.StringIO()
        demux = ThreadDemuxWriter(original)

        status = ContractAuditStatus("Test", "/path/test.sol")
        # Simulate a registered thread
        tid = threading.current_thread().ident
        demux._registry[tid] = status
        demux._buffers[tid] = ""

        demux.write("Hello World\n")
        lines = status.get_all_log_lines()
        self.assertEqual(len(lines), 1)
        self.assertIn("Hello World", lines[0])

        # Cleanup
        del demux._registry[tid]
        del demux._buffers[tid]


class TestJobManagerConvenienceMethods(unittest.TestCase):
    """Test new convenience methods on JobManager."""

    def setUp(self):
        JobManager.reset()
        self.jm = JobManager.get_instance()

    def test_get_job_log(self):
        job = self.jm.create_job("Test", "local")
        job.audit_status.append_log("log line 1")
        log = self.jm.get_job_log(job.job_id)
        self.assertEqual(log, ["log line 1"])

    def test_get_job_log_nonexistent(self):
        log = self.jm.get_job_log("nonexistent")
        self.assertEqual(log, [])

    def test_get_new_job_log(self):
        job = self.jm.create_job("Test", "local")
        job.audit_status.append_log("log line 1")

        new = self.jm.get_new_job_log(job.job_id)
        self.assertEqual(new, ["log line 1"])

        new = self.jm.get_new_job_log(job.job_id)
        self.assertEqual(new, [])

    def test_get_children(self):
        parent = self.jm.create_job("Parent", "local")
        c1 = self.jm.create_job("C1", "local", parent_job_id=parent.job_id)
        c2 = self.jm.create_job("C2", "local", parent_job_id=parent.job_id)

        children = self.jm.get_children(parent.job_id)
        child_ids = [c.job_id for c in children]
        self.assertIn(c1.job_id, child_ids)
        self.assertIn(c2.job_id, child_ids)

    def test_get_children_no_children(self):
        job = self.jm.create_job("Solo", "local")
        children = self.jm.get_children(job.job_id)
        self.assertEqual(children, [])


class TestTUIImports(unittest.TestCase):
    """Test that all TUI modules can be imported without error."""

    def test_import_app(self):
        from cli.tui.app import AetherApp
        self.assertTrue(callable(AetherApp))

    def test_import_screens(self):
        from cli.tui.screens.main import MainScreen
        from cli.tui.screens.job_detail import JobDetailScreen
        from cli.tui.screens.new_audit import NewAuditScreen
        from cli.tui.screens.history import HistoryScreen
        from cli.tui.screens.resume import ResumeScreen
        from cli.tui.screens.pocs import PoCScreen
        from cli.tui.screens.reports import ReportsScreen
        from cli.tui.screens.fetch import FetchScreen
        from cli.tui.screens.settings import SettingsScreen
        self.assertTrue(callable(MainScreen))
        self.assertTrue(callable(JobDetailScreen))

    def test_import_widgets(self):
        from cli.tui.widgets.jobs_table import JobsTable
        from cli.tui.widgets.cost_bar import CostBar
        from cli.tui.widgets.log_viewer import LogViewer
        from cli.tui.widgets.phase_bar import PhaseBar
        self.assertTrue(callable(JobsTable))

    def test_import_dialogs(self):
        from cli.tui.dialogs.confirm import ConfirmDialog
        from cli.tui.dialogs.text_input import TextInputDialog
        from cli.tui.dialogs.select import SelectDialog
        from cli.tui.dialogs.checkbox import CheckboxDialog
        from cli.tui.dialogs.path_picker import PathDialog
        self.assertTrue(callable(ConfirmDialog))


class TestAetherAppPilot(unittest.IsolatedAsyncioTestCase):
    """Test the Textual app using the Pilot API."""

    async def test_app_launches_main_screen(self):
        from cli.tui.app import AetherApp

        JobManager.reset()
        LLMUsageTracker.reset()

        app = AetherApp()
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            # The main screen should be pushed by on_mount
            from cli.tui.screens.main import MainScreen
            self.assertIsInstance(app.screen, MainScreen)

    async def test_app_shows_header(self):
        from cli.tui.app import AetherApp

        JobManager.reset()
        LLMUsageTracker.reset()

        app = AetherApp()
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            from textual.widgets import Header
            header = app.screen.query_one(Header)
            self.assertIsNotNone(header)

    async def test_jobs_table_empty_state(self):
        from cli.tui.app import AetherApp

        JobManager.reset()
        LLMUsageTracker.reset()

        app = AetherApp()
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            from cli.tui.widgets.jobs_table import JobsTable
            jobs_table = app.screen.query_one(JobsTable)
            self.assertIsNotNone(jobs_table)

    async def test_jobs_table_with_jobs(self):
        from cli.tui.app import AetherApp

        JobManager.reset()
        LLMUsageTracker.reset()
        jm = JobManager.get_instance()
        j1 = jm.create_job("Token", "local", target="/path/Token.sol")
        jm.start_job(j1.job_id)
        j2 = jm.create_job("Vault", "local", target="/path/Vault.sol")
        jm.complete_job(j2.job_id, findings_count=12, cost_delta=0.45)

        app = AetherApp()
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            from cli.tui.widgets.jobs_table import JobsTable
            jobs_table = app.screen.query_one(JobsTable)
            # Force a refresh
            jobs_table.refresh_jobs()
            self.assertGreater(len(jobs_table.rows), 0)

    async def test_cost_bar_present(self):
        from cli.tui.app import AetherApp

        JobManager.reset()
        LLMUsageTracker.reset()

        app = AetherApp()
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            from cli.tui.widgets.cost_bar import CostBar
            cost_bar = app.screen.query_one(CostBar)
            self.assertIsNotNone(cost_bar)

    async def test_quit_no_active_jobs(self):
        from cli.tui.app import AetherApp

        JobManager.reset()
        LLMUsageTracker.reset()

        app = AetherApp()
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await pilot.press("q")
            await pilot.pause()
            # App should exit since no active jobs
            self.assertTrue(app.return_code == 0 or not app.is_running)


class TestLLMUsageTrackerSnapshot(unittest.TestCase):
    """Test the snapshot() method on LLMUsageTracker."""

    def setUp(self):
        LLMUsageTracker.reset()

    def test_snapshot_empty(self):
        tracker = LLMUsageTracker.get_instance()
        snap = tracker.snapshot()
        self.assertEqual(snap["total_cost"], 0.0)
        self.assertEqual(snap["total_calls"], 0)

    def test_snapshot_after_records(self):
        tracker = LLMUsageTracker.get_instance()
        tracker.record("openai", "gpt-4o-mini", 1000, 500, "test")
        snap = tracker.snapshot()
        self.assertGreater(snap["total_cost"], 0.0)
        self.assertEqual(snap["total_calls"], 1)
        self.assertEqual(snap["total_input_tokens"], 1000)
        self.assertEqual(snap["total_output_tokens"], 500)

    def test_snapshot_delta(self):
        tracker = LLMUsageTracker.get_instance()
        before = tracker.snapshot()
        tracker.record("openai", "gpt-4o-mini", 1000, 500, "test")
        after = tracker.snapshot()
        delta = after["total_cost"] - before["total_cost"]
        self.assertGreater(delta, 0.0)


if __name__ == "__main__":
    unittest.main()
