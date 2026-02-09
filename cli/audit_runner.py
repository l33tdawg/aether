"""
Background audit runner for the Aether dashboard.

Runs audits in daemon threads, reports progress to JobManager.
A single ThreadDemuxWriter is installed once at startup and shared
across all concurrent audit threads.
"""

import asyncio
import logging
import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, List, Optional

from core.audit_progress import AuditPhase, ContractAuditStatus, ThreadDemuxWriter
from core.job_manager import AuditJob, JobManager, JobStatus
from core.llm_usage_tracker import LLMUsageTracker


class JobLogHandler(logging.Handler):
    """Routes logging module output to per-job log buffers via thread ID."""

    def __init__(self):
        super().__init__()
        self._lock_registry = threading.Lock()
        self._registry: Dict[int, ContractAuditStatus] = {}

    def register(self, status: ContractAuditStatus) -> None:
        tid = threading.current_thread().ident
        with self._lock_registry:
            self._registry[tid] = status

    def unregister(self) -> None:
        tid = threading.current_thread().ident
        with self._lock_registry:
            self._registry.pop(tid, None)

    def emit(self, record: logging.LogRecord) -> None:
        tid = record.thread
        with self._lock_registry:
            status = self._registry.get(tid)
        if status is not None:
            try:
                msg = self.format(record)
                status.append_log(msg)
            except Exception:
                pass


class AuditRunner:
    """Runs audits in background threads, reporting to JobManager."""

    def __init__(self):
        self._job_manager = JobManager.get_instance()
        self._demuxer: Optional[ThreadDemuxWriter] = None
        self._stderr_demuxer: Optional[ThreadDemuxWriter] = None
        self._log_handler: Optional[JobLogHandler] = None
        self._install_demuxer()
        self._install_log_handler()

    def _install_demuxer(self) -> None:
        """Install ThreadDemuxWriters on sys.stdout and sys.stderr if not already installed."""
        if isinstance(sys.stdout, ThreadDemuxWriter):
            self._demuxer = sys.stdout
        else:
            self._demuxer = ThreadDemuxWriter(sys.stdout)
            sys.stdout = self._demuxer

        if isinstance(sys.stderr, ThreadDemuxWriter):
            self._stderr_demuxer = sys.stderr
        else:
            self._stderr_demuxer = ThreadDemuxWriter(sys.stderr)
            sys.stderr = self._stderr_demuxer

    def _install_log_handler(self) -> None:
        """Install a JobLogHandler on the root logger."""
        self._log_handler = JobLogHandler()
        self._log_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
        logging.getLogger().addHandler(self._log_handler)

    def start_single_audit(
        self,
        job_id: str,
        target: str,
        features: List[str],
        output_dir: str,
    ) -> None:
        """Start a single audit in a background daemon thread."""
        job = self._job_manager.get_job(job_id)
        if not job:
            return

        thread = threading.Thread(
            target=self._audit_worker,
            args=(job, target, features, output_dir),
            daemon=True,
            name=f"audit-{job_id}",
        )
        job.thread = thread
        thread.start()

    def start_parallel_audit(
        self,
        parent_job_id: str,
        targets: List[str],
        features: List[str],
        output_dir: str,
        max_workers: int = 5,
    ) -> None:
        """Start N child audit threads for parallel execution."""
        parent_job = self._job_manager.get_job(parent_job_id)
        if not parent_job:
            return

        self._job_manager.start_job(parent_job_id)
        num_workers = min(max_workers, len(targets), 8)

        # Create child jobs
        child_jobs = []
        for target in targets:
            name = Path(target).stem
            child = self._job_manager.create_job(
                display_name=name,
                job_type="local",
                target=target,
                features=features,
                output_dir=os.path.join(output_dir, name),
                parent_job_id=parent_job_id,
            )
            child_jobs.append(child)

        # Launch in a coordinator thread
        coord_thread = threading.Thread(
            target=self._parallel_coordinator,
            args=(parent_job, child_jobs, features, output_dir, num_workers),
            daemon=True,
            name=f"parallel-{parent_job_id}",
        )
        parent_job.thread = coord_thread
        coord_thread.start()

    def _parallel_coordinator(
        self,
        parent_job: AuditJob,
        child_jobs: List[AuditJob],
        features: List[str],
        output_dir: str,
        num_workers: int,
    ) -> None:
        """Coordinator thread that uses ThreadPoolExecutor for child audits."""
        try:
            with ThreadPoolExecutor(max_workers=num_workers) as executor:
                futures = {}
                for child in child_jobs:
                    child_output = os.path.join(output_dir, child.display_name)
                    os.makedirs(child_output, exist_ok=True)
                    future = executor.submit(
                        self._audit_worker,
                        child,
                        child.target,
                        features,
                        child_output,
                    )
                    futures[future] = child

                # Wait for all futures
                for future in futures:
                    try:
                        future.result()
                    except Exception:
                        pass

            # Aggregate parent stats
            total_findings = sum(c.findings_count for c in child_jobs)
            total_cost = sum(c.cost_delta for c in child_jobs)
            all_done = all(
                c.status in (JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED)
                for c in child_jobs
            )
            any_failed = any(c.status == JobStatus.FAILED for c in child_jobs)

            if all_done and not any_failed:
                self._job_manager.complete_job(parent_job.job_id, total_findings, total_cost)
            elif all_done:
                completed = sum(1 for c in child_jobs if c.status == JobStatus.COMPLETED)
                self._job_manager.fail_job(
                    parent_job.job_id,
                    f"{completed}/{len(child_jobs)} completed",
                    total_cost,
                )
        except Exception as e:
            self._job_manager.fail_job(parent_job.job_id, str(e)[:200])

    def _audit_worker(
        self,
        job: AuditJob,
        target: str,
        features: List[str],
        output_dir: str,
    ) -> None:
        """Background thread: runs a single audit via AetherCLI."""
        tracker = LLMUsageTracker.get_instance()
        snapshot_before = tracker.snapshot()

        # Register with demuxers for stdout/stderr capture
        if job.audit_status:
            if self._demuxer:
                self._demuxer.register(job.audit_status)
            if self._stderr_demuxer:
                self._stderr_demuxer.register(job.audit_status)
            if self._log_handler:
                self._log_handler.register(job.audit_status)

        self._job_manager.start_job(job.job_id)
        os.makedirs(output_dir, exist_ok=True)

        try:
            from cli.main import AetherCLI
            cli = AetherCLI()

            asyncio.run(
                cli.run_audit(
                    contract_path=target,
                    output_dir=output_dir,
                    enhanced="enhanced" in features,
                    ai_ensemble="ai_ensemble" in features,
                    llm_validation="llm_validation" in features,
                    foundry="foundry" in features,
                    enhanced_reports="enhanced_reports" in features,
                )
            )

            # Compute cost delta
            snapshot_after = tracker.snapshot()
            cost_delta = snapshot_after["total_cost"] - snapshot_before["total_cost"]

            findings = job.audit_status.findings_count if job.audit_status else 0
            self._job_manager.complete_job(job.job_id, findings, cost_delta)

        except Exception as e:
            snapshot_after = tracker.snapshot()
            cost_delta = snapshot_after["total_cost"] - snapshot_before["total_cost"]
            self._job_manager.fail_job(job.job_id, str(e)[:200], cost_delta)

        finally:
            if job.audit_status:
                job.audit_status.sync_llm_stats()
            if self._demuxer:
                self._demuxer.unregister()
            if self._stderr_demuxer:
                self._stderr_demuxer.unregister()
            if self._log_handler:
                self._log_handler.unregister()

    # ── PoC generation ────────────────────────────────────────────

    def start_poc_generation(
        self,
        job_id: str,
        project_id: Optional[int] = None,
        scope_id: Optional[int] = None,
        from_results: Optional[str] = None,
        out_dir: Optional[str] = None,
        max_items: int = 20,
        min_severity: str = "medium",
        only_consensus: bool = False,
    ) -> None:
        """Start PoC generation in a background daemon thread."""
        job = self._job_manager.get_job(job_id)
        if not job:
            return

        thread = threading.Thread(
            target=self._poc_worker,
            args=(job, project_id, scope_id, from_results, out_dir,
                  max_items, min_severity, only_consensus),
            daemon=True,
            name=f"poc-{job_id}",
        )
        job.thread = thread
        thread.start()

    def _poc_worker(
        self,
        job: AuditJob,
        project_id: Optional[int],
        scope_id: Optional[int],
        from_results: Optional[str],
        out_dir: Optional[str],
        max_items: int,
        min_severity: str,
        only_consensus: bool,
    ) -> None:
        """Background thread: runs PoC generation via AetherCLI."""
        tracker = LLMUsageTracker.get_instance()
        snapshot_before = tracker.snapshot()

        if job.audit_status:
            if self._demuxer:
                self._demuxer.register(job.audit_status)
            if self._stderr_demuxer:
                self._stderr_demuxer.register(job.audit_status)
            if self._log_handler:
                self._log_handler.register(job.audit_status)

        self._job_manager.start_job(job.job_id)

        try:
            from cli.main import AetherCLI
            cli = AetherCLI()

            asyncio.run(
                cli.run_generate_foundry(
                    project_id=project_id,
                    scope_id=scope_id,
                    from_results=from_results,
                    out_dir=out_dir,
                    max_items=max_items,
                    min_severity=min_severity,
                    only_consensus=only_consensus,
                )
            )

            snapshot_after = tracker.snapshot()
            cost_delta = snapshot_after["total_cost"] - snapshot_before["total_cost"]
            self._job_manager.complete_job(job.job_id, 0, cost_delta)

        except Exception as e:
            snapshot_after = tracker.snapshot()
            cost_delta = snapshot_after["total_cost"] - snapshot_before["total_cost"]
            self._job_manager.fail_job(job.job_id, str(e)[:200], cost_delta)

        finally:
            if job.audit_status:
                job.audit_status.sync_llm_stats()
            if self._demuxer:
                self._demuxer.unregister()
            if self._stderr_demuxer:
                self._stderr_demuxer.unregister()
            if self._log_handler:
                self._log_handler.unregister()

    # ── Report generation ─────────────────────────────────────────

    def start_report_generation(
        self,
        job_id: str,
        project_id: int,
        scope_id: Optional[int] = None,
        output_dir: str = "./output/reports",
        fmt: str = "markdown",
    ) -> None:
        """Start report generation in a background daemon thread."""
        job = self._job_manager.get_job(job_id)
        if not job:
            return

        thread = threading.Thread(
            target=self._report_worker,
            args=(job, project_id, scope_id, output_dir, fmt),
            daemon=True,
            name=f"report-{job_id}",
        )
        job.thread = thread
        thread.start()

    def _report_worker(
        self,
        job: AuditJob,
        project_id: int,
        scope_id: Optional[int],
        output_dir: str,
        fmt: str,
    ) -> None:
        """Background thread: runs report generation via AetherCLI."""
        tracker = LLMUsageTracker.get_instance()
        snapshot_before = tracker.snapshot()

        if job.audit_status:
            if self._demuxer:
                self._demuxer.register(job.audit_status)
            if self._stderr_demuxer:
                self._stderr_demuxer.register(job.audit_status)
            if self._log_handler:
                self._log_handler.register(job.audit_status)

        self._job_manager.start_job(job.job_id)
        os.makedirs(output_dir, exist_ok=True)

        try:
            from cli.main import AetherCLI
            cli = AetherCLI()

            asyncio.run(
                cli.run_generate_report(
                    output_dir=output_dir,
                    format=fmt,
                    project_id=project_id,
                    scope_id=scope_id,
                )
            )

            snapshot_after = tracker.snapshot()
            cost_delta = snapshot_after["total_cost"] - snapshot_before["total_cost"]
            self._job_manager.complete_job(job.job_id, 0, cost_delta)

        except Exception as e:
            snapshot_after = tracker.snapshot()
            cost_delta = snapshot_after["total_cost"] - snapshot_before["total_cost"]
            self._job_manager.fail_job(job.job_id, str(e)[:200], cost_delta)

        finally:
            if job.audit_status:
                job.audit_status.sync_llm_stats()
            if self._demuxer:
                self._demuxer.unregister()
            if self._stderr_demuxer:
                self._stderr_demuxer.unregister()
            if self._log_handler:
                self._log_handler.unregister()

    # ── GitHub audit ──────────────────────────────────────────────

    def start_github_audit(
        self,
        job_id: str,
        github_url: str,
        project_id: Optional[int] = None,
        scope_id: Optional[int] = None,
        fresh: bool = False,
    ) -> None:
        """Start a GitHub audit in a background daemon thread.

        The scope is already selected via the TUI dialogs, so
        interactive_scope=False and skip_scope_selector=True.
        """
        job = self._job_manager.get_job(job_id)
        if not job:
            return

        thread = threading.Thread(
            target=self._github_audit_worker,
            args=(job, github_url, project_id, scope_id, fresh),
            daemon=True,
            name=f"github-{job_id}",
        )
        job.thread = thread
        thread.start()

    def _github_audit_worker(
        self,
        job: AuditJob,
        github_url: str,
        project_id: Optional[int],
        scope_id: Optional[int],
        fresh: bool,
    ) -> None:
        """Background thread: runs a GitHub audit via AetherCLI."""
        tracker = LLMUsageTracker.get_instance()
        snapshot_before = tracker.snapshot()

        if job.audit_status:
            if self._demuxer:
                self._demuxer.register(job.audit_status)
            if self._stderr_demuxer:
                self._stderr_demuxer.register(job.audit_status)
            if self._log_handler:
                self._log_handler.register(job.audit_status)

        self._job_manager.start_job(job.job_id)

        try:
            from cli.main import AetherCLI
            cli = AetherCLI()

            cli.run_github_audit_command(
                github_url=github_url,
                fresh=fresh,
                interactive_scope=False,
                skip_scope_selector=True,
                resume_scope_id=scope_id,
            )

            snapshot_after = tracker.snapshot()
            cost_delta = snapshot_after["total_cost"] - snapshot_before["total_cost"]

            findings = job.audit_status.findings_count if job.audit_status else 0
            self._job_manager.complete_job(job.job_id, findings, cost_delta)

        except Exception as e:
            snapshot_after = tracker.snapshot()
            cost_delta = snapshot_after["total_cost"] - snapshot_before["total_cost"]
            self._job_manager.fail_job(job.job_id, str(e)[:200], cost_delta)

        finally:
            if job.audit_status:
                job.audit_status.sync_llm_stats()
            if self._demuxer:
                self._demuxer.unregister()
            if self._stderr_demuxer:
                self._stderr_demuxer.unregister()
            if self._log_handler:
                self._log_handler.unregister()
