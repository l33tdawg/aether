"""Tests for core.job_manager — session job registry."""

import threading
import time
import unittest

from core.job_manager import AuditJob, JobManager, JobStatus
from core.audit_progress import AuditPhase


class TestJobManager(unittest.TestCase):
    """Test the JobManager singleton."""

    def setUp(self):
        JobManager.reset()
        self.jm = JobManager.get_instance()

    def test_singleton(self):
        jm2 = JobManager.get_instance()
        self.assertIs(self.jm, jm2)

    def test_reset(self):
        self.jm.create_job("Test", "local")
        JobManager.reset()
        jm2 = JobManager.get_instance()
        self.assertIsNot(self.jm, jm2)
        self.assertEqual(jm2.job_count, 0)

    def test_create_job(self):
        job = self.jm.create_job("MyToken", "local", target="/path/MyToken.sol")
        self.assertEqual(job.display_name, "MyToken")
        self.assertEqual(job.job_type, "local")
        self.assertEqual(job.status, JobStatus.QUEUED)
        self.assertIsNotNone(job.audit_status)
        self.assertEqual(job.audit_status.contract_name, "MyToken")
        self.assertEqual(self.jm.job_count, 1)

    def test_start_job(self):
        job = self.jm.create_job("Token", "local")
        self.jm.start_job(job.job_id)
        self.assertEqual(job.status, JobStatus.RUNNING)
        self.assertIsNotNone(job.started_at)

    def test_complete_job(self):
        job = self.jm.create_job("Token", "local")
        self.jm.start_job(job.job_id)
        self.jm.complete_job(job.job_id, findings_count=5, cost_delta=0.12)
        self.assertEqual(job.status, JobStatus.COMPLETED)
        self.assertEqual(job.findings_count, 5)
        self.assertAlmostEqual(job.cost_delta, 0.12)
        self.assertIsNotNone(job.ended_at)

    def test_fail_job(self):
        job = self.jm.create_job("Token", "local")
        self.jm.start_job(job.job_id)
        self.jm.fail_job(job.job_id, "timeout")
        self.assertEqual(job.status, JobStatus.FAILED)
        self.assertEqual(job.error, "timeout")

    def test_cancel_job(self):
        job = self.jm.create_job("Token", "local")
        self.jm.cancel_job(job.job_id)
        self.assertEqual(job.status, JobStatus.CANCELLED)

    def test_get_all_jobs_excludes_children(self):
        parent = self.jm.create_job("Multi", "local")
        child1 = self.jm.create_job("Child1", "local", parent_job_id=parent.job_id)
        child2 = self.jm.create_job("Child2", "local", parent_job_id=parent.job_id)
        standalone = self.jm.create_job("Solo", "local")

        all_jobs = self.jm.get_all_jobs()
        job_ids = [j.job_id for j in all_jobs]
        self.assertIn(parent.job_id, job_ids)
        self.assertIn(standalone.job_id, job_ids)
        self.assertNotIn(child1.job_id, job_ids)
        self.assertNotIn(child2.job_id, job_ids)

    def test_get_active_jobs(self):
        j1 = self.jm.create_job("A", "local")
        j2 = self.jm.create_job("B", "local")
        self.jm.start_job(j1.job_id)
        self.jm.complete_job(j2.job_id)

        active = self.jm.get_active_jobs()
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0].job_id, j1.job_id)

    def test_session_cost_and_findings(self):
        j1 = self.jm.create_job("A", "local")
        j2 = self.jm.create_job("B", "local")
        self.jm.complete_job(j1.job_id, findings_count=3, cost_delta=0.10)
        self.jm.complete_job(j2.job_id, findings_count=7, cost_delta=0.25)

        self.assertAlmostEqual(self.jm.get_session_cost(), 0.35)
        self.assertEqual(self.jm.get_session_findings(), 10)

    def test_has_active_jobs(self):
        self.assertFalse(self.jm.has_active_jobs)
        job = self.jm.create_job("A", "local")
        self.assertTrue(self.jm.has_active_jobs)  # QUEUED counts as active
        self.jm.complete_job(job.job_id)
        self.assertFalse(self.jm.has_active_jobs)

    def test_elapsed(self):
        job = self.jm.create_job("A", "local")
        self.assertIsNone(job.elapsed)
        self.jm.start_job(job.job_id)
        time.sleep(0.05)
        self.assertIsNotNone(job.elapsed)
        self.assertGreater(job.elapsed, 0)

    def test_child_job_ids_populated(self):
        parent = self.jm.create_job("Parent", "local")
        c1 = self.jm.create_job("C1", "local", parent_job_id=parent.job_id)
        c2 = self.jm.create_job("C2", "local", parent_job_id=parent.job_id)
        self.assertEqual(parent.child_job_ids, [c1.job_id, c2.job_id])

    def test_thread_safety(self):
        """Multiple threads creating and updating jobs concurrently."""
        errors = []

        def worker(idx):
            try:
                job = self.jm.create_job(f"Job{idx}", "local")
                self.jm.start_job(job.job_id)
                time.sleep(0.01)
                self.jm.complete_job(job.job_id, findings_count=idx)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0)
        self.assertEqual(self.jm.job_count, 20)


class TestAuditJob(unittest.TestCase):
    """Test AuditJob properties."""

    def test_is_active(self):
        job = AuditJob(job_id="x", display_name="T", job_type="local")
        self.assertTrue(job.is_active)  # QUEUED
        job.status = JobStatus.RUNNING
        self.assertTrue(job.is_active)
        job.status = JobStatus.COMPLETED
        self.assertFalse(job.is_active)
        job.status = JobStatus.FAILED
        self.assertFalse(job.is_active)

    def test_elapsed_not_started(self):
        job = AuditJob(job_id="x", display_name="T", job_type="local")
        self.assertIsNone(job.elapsed)

    def test_elapsed_running(self):
        job = AuditJob(job_id="x", display_name="T", job_type="local")
        job.started_at = time.time() - 5.0
        self.assertGreaterEqual(job.elapsed, 4.5)

    def test_elapsed_completed(self):
        now = time.time()
        job = AuditJob(job_id="x", display_name="T", job_type="local")
        job.started_at = now - 10.0
        job.ended_at = now - 5.0
        self.assertAlmostEqual(job.elapsed, 5.0, places=1)


if __name__ == "__main__":
    unittest.main()
