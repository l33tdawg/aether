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

        results = None  # Hoist for SAGE feedback in finally block
        try:
            from cli.main import AetherCLI
            cli = AetherCLI()

            results = asyncio.run(
                cli.run_audit(
                    contract_path=target,
                    output_dir=output_dir,
                    enhanced="enhanced" in features,
                    llm_validation="llm_validation" in features,
                    foundry="foundry" in features,
                    enhanced_reports="enhanced_reports" in features,
                )
            )

            # Compute cost delta from snapshot
            snapshot_after = tracker.snapshot()
            cost_delta = snapshot_after["total_cost"] - snapshot_before["total_cost"]

            # Extract findings from the returned results dict
            findings = 0
            if isinstance(results, dict) and "error" not in results:
                summary = results.get("summary", {})
                if isinstance(summary, dict) and "total_vulnerabilities" in summary:
                    findings = summary["total_vulnerabilities"]
                elif "results" in results:
                    vulns = results["results"]
                    if isinstance(vulns, dict):
                        vulns = vulns.get("vulnerabilities", [])
                    if isinstance(vulns, list):
                        findings = len(vulns)
            # Fall back to stdout-parsed count if higher
            if job.audit_status and job.audit_status.findings_count > findings:
                findings = job.audit_status.findings_count

            # Store per-job LLM stats from snapshot deltas
            if job.audit_status:
                calls_delta = snapshot_after["total_calls"] - snapshot_before["total_calls"]
                job.audit_status.llm_calls = calls_delta
                job.audit_status.llm_cost = cost_delta

            self._job_manager.complete_job(job.job_id, findings, cost_delta)

        except Exception as e:
            snapshot_after = tracker.snapshot()
            cost_delta = snapshot_after["total_cost"] - snapshot_before["total_cost"]
            # Store per-job LLM stats even on failure
            if job.audit_status:
                calls_delta = snapshot_after["total_calls"] - snapshot_before["total_calls"]
                job.audit_status.llm_calls = calls_delta
                job.audit_status.llm_cost = cost_delta
            self._job_manager.fail_job(job.job_id, str(e)[:200], cost_delta)

        finally:
            # SAGE: store audit learnings with real dos/donts from findings
            self._sage_post_audit(job, target, results)

            if self._demuxer:
                self._demuxer.unregister()
            if self._stderr_demuxer:
                self._stderr_demuxer.unregister()
            if self._log_handler:
                self._log_handler.unregister()

    # ── PoC generation ────────────────────────────────────────────

    @staticmethod
    def _sage_post_audit(job, target: str, results) -> None:
        """Store audit learnings in SAGE with actionable dos/donts.

        Extracts vulnerability patterns, severity distribution, detector
        performance, and validation pipeline stats from the audit results
        to feed SAGE's institutional learning loop.
        """
        try:
            from core.sage_feedback import SageFeedbackManager
            fm = SageFeedbackManager()
            contract_name = os.path.basename(target)

            # Extract detailed findings from results
            vuln_list = []
            severity_counts: dict[str, int] = {}
            vuln_types: set[str] = set()
            filtered_count = 0
            archetype = getattr(job, "archetype", "unknown")

            if isinstance(results, dict) and "error" not in results:
                raw_vulns = results.get("results", {})
                if isinstance(raw_vulns, dict):
                    raw_vulns = raw_vulns.get("vulnerabilities", [])
                if isinstance(raw_vulns, list):
                    vuln_list = raw_vulns

                for v in vuln_list:
                    sev = v.get("severity", "unknown").lower()
                    severity_counts[sev] = severity_counts.get(sev, 0) + 1
                    vuln_types.add(v.get("vulnerability_type", "unknown"))

                # Get validation stats if available
                summary = results.get("summary", {})
                if isinstance(summary, dict):
                    filtered_count = summary.get("false_positives_filtered", 0)
                    if not archetype or archetype == "unknown":
                        archetype = summary.get("archetype", "unknown")

            total_findings = sum(severity_counts.values()) or (
                job.audit_status.findings_count if job.audit_status else 0
            )

            # Record audit completion with real severity breakdown
            fm.record_audit_completion(
                contract_name=contract_name,
                archetype=archetype,
                findings_summary=severity_counts if severity_counts else {"total": total_findings},
                validation_stats={"filtered": filtered_count, "total_raw": total_findings + filtered_count}
                if filtered_count else None,
            )

            # Build actionable dos/donts from actual findings
            dos: list[str] = []
            donts: list[str] = []

            if total_findings > 0:
                # What vulnerability types were found
                type_str = ", ".join(list(vuln_types)[:5])
                dos.append(
                    f"Found {total_findings} findings in {contract_name} ({archetype}): "
                    f"types [{type_str}]. These patterns are worth checking in similar contracts."
                )

                # High-confidence findings are patterns to remember
                for v in vuln_list[:5]:
                    if v.get("confidence", 0) >= 0.7:
                        dos.append(
                            f"High-confidence {v.get('severity', '?')} finding: "
                            f"{v.get('vulnerability_type', '?')} — {v.get('description', '')[:150]}"
                        )

            if filtered_count > 0:
                donts.append(
                    f"{filtered_count} false positives were filtered during validation "
                    f"for {contract_name}. The validation pipeline is working."
                )

            # If audit failed, record that
            completed_job = None
            try:
                from core.job_manager import JobManager
                completed_job = JobManager.get_instance().get_job(job.job_id)
            except Exception:
                pass
            if completed_job and completed_job.status == "FAILED":
                donts.append(
                    f"Audit of {contract_name} failed: {completed_job.error_message[:100] if completed_job.error_message else 'unknown error'}"
                )

            if dos or donts:
                fm._client.reflect(dos=dos, donts=donts, domain=f"audit-{archetype}")

            # Also sync detector accuracy periodically
            if total_findings >= 5:
                fm.sync_detector_accuracy()

        except Exception:
            pass  # SAGE is optional — never break audit cleanup

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
            if job.audit_status:
                calls_delta = snapshot_after["total_calls"] - snapshot_before["total_calls"]
                job.audit_status.llm_calls = calls_delta
                job.audit_status.llm_cost = cost_delta
            self._job_manager.complete_job(job.job_id, 0, cost_delta)

        except Exception as e:
            snapshot_after = tracker.snapshot()
            cost_delta = snapshot_after["total_cost"] - snapshot_before["total_cost"]
            if job.audit_status:
                calls_delta = snapshot_after["total_calls"] - snapshot_before["total_calls"]
                job.audit_status.llm_calls = calls_delta
                job.audit_status.llm_cost = cost_delta
            self._job_manager.fail_job(job.job_id, str(e)[:200], cost_delta)

        finally:
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
            if job.audit_status:
                calls_delta = snapshot_after["total_calls"] - snapshot_before["total_calls"]
                job.audit_status.llm_calls = calls_delta
                job.audit_status.llm_cost = cost_delta
            self._job_manager.complete_job(job.job_id, 0, cost_delta)

        except Exception as e:
            snapshot_after = tracker.snapshot()
            cost_delta = snapshot_after["total_cost"] - snapshot_before["total_cost"]
            if job.audit_status:
                calls_delta = snapshot_after["total_calls"] - snapshot_before["total_calls"]
                job.audit_status.llm_calls = calls_delta
                job.audit_status.llm_cost = cost_delta
            self._job_manager.fail_job(job.job_id, str(e)[:200], cost_delta)

        finally:
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
        reanalyze: bool = False,
    ) -> None:
        """Start a GitHub audit in a background daemon thread.

        The scope is already selected via the TUI dialogs, so
        interactive_scope=False and skip_scope_selector=True.

        Args:
            reanalyze: If True, force re-analysis even for cached contracts.
        """
        job = self._job_manager.get_job(job_id)
        if not job:
            return

        thread = threading.Thread(
            target=self._github_audit_worker,
            args=(job, github_url, project_id, scope_id, fresh, reanalyze),
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
        reanalyze: bool = False,
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

            result_count = cli.run_github_audit_command(
                github_url=github_url,
                fresh=fresh,
                reanalyze=reanalyze or fresh,  # Re-run full pipeline when requested or fresh
                interactive_scope=False,
                skip_scope_selector=True,
                resume_scope_id=scope_id,
            )

            snapshot_after = tracker.snapshot()
            cost_delta = snapshot_after["total_cost"] - snapshot_before["total_cost"]

            # Use return value (actual vulnerability count), fall back to stdout-parsed
            findings = result_count if isinstance(result_count, int) and result_count > 0 else 0
            if job.audit_status and job.audit_status.findings_count > findings:
                findings = job.audit_status.findings_count

            # Store per-job LLM stats from snapshot deltas
            if job.audit_status:
                calls_delta = snapshot_after["total_calls"] - snapshot_before["total_calls"]
                job.audit_status.llm_calls = calls_delta
                job.audit_status.llm_cost = cost_delta

            self._job_manager.complete_job(job.job_id, findings, cost_delta)

        except Exception as e:
            snapshot_after = tracker.snapshot()
            cost_delta = snapshot_after["total_cost"] - snapshot_before["total_cost"]
            if job.audit_status:
                calls_delta = snapshot_after["total_calls"] - snapshot_before["total_calls"]
                job.audit_status.llm_calls = calls_delta
                job.audit_status.llm_cost = cost_delta
            self._job_manager.fail_job(job.job_id, str(e)[:200], cost_delta)

        finally:
            if self._demuxer:
                self._demuxer.unregister()
            if self._stderr_demuxer:
                self._stderr_demuxer.unregister()
            if self._log_handler:
                self._log_handler.unregister()
