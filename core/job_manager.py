"""
Session job registry for tracking audit jobs across the dashboard.

Thread-safe singleton that tracks all audit jobs (queued, running, completed,
failed) within a single Aether session. Used by the dashboard for rendering
and by AuditRunner for status updates.
"""

import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

from core.audit_progress import ContractAuditStatus, AuditPhase


class JobStatus(Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


@dataclass
class AuditJob:
    """Represents a single audit job in the session."""

    job_id: str
    display_name: str
    job_type: str  # "local", "github", "explorer"
    status: JobStatus = JobStatus.QUEUED
    audit_status: Optional[ContractAuditStatus] = None
    thread: Optional[threading.Thread] = field(default=None, repr=False)
    features: List[str] = field(default_factory=list)
    target: str = ""
    output_dir: str = ""
    cost_snapshot_start: float = 0.0
    cost_delta: float = 0.0
    findings_count: int = 0
    error: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    ended_at: Optional[float] = None
    # For parallel audit grouping
    parent_job_id: Optional[str] = None
    child_job_ids: List[str] = field(default_factory=list)

    @property
    def elapsed(self) -> Optional[float]:
        if self.started_at is None:
            return None
        end = self.ended_at or time.time()
        return end - self.started_at

    @property
    def is_active(self) -> bool:
        return self.status in (JobStatus.QUEUED, JobStatus.RUNNING)


class JobManager:
    """Thread-safe singleton registry for all audit jobs in the session."""

    _instance: Optional["JobManager"] = None
    _instance_lock = threading.Lock()

    @classmethod
    def get_instance(cls) -> "JobManager":
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        with cls._instance_lock:
            cls._instance = cls()

    def __init__(self):
        self._lock = threading.Lock()
        self._jobs: Dict[str, AuditJob] = {}
        self._job_order: List[str] = []  # Insertion order

    def create_job(
        self,
        display_name: str,
        job_type: str,
        target: str = "",
        features: Optional[List[str]] = None,
        output_dir: str = "",
        parent_job_id: Optional[str] = None,
    ) -> AuditJob:
        """Create and register a new job. Returns the job."""
        job_id = uuid.uuid4().hex[:8]
        contract_status = ContractAuditStatus(
            contract_name=display_name,
            contract_path=target,
        )
        job = AuditJob(
            job_id=job_id,
            display_name=display_name,
            job_type=job_type,
            target=target,
            features=features or [],
            output_dir=output_dir,
            audit_status=contract_status,
            parent_job_id=parent_job_id,
        )
        with self._lock:
            self._jobs[job_id] = job
            self._job_order.append(job_id)
            if parent_job_id and parent_job_id in self._jobs:
                self._jobs[parent_job_id].child_job_ids.append(job_id)
        return job

    def start_job(self, job_id: str) -> None:
        """Mark a job as running."""
        with self._lock:
            job = self._jobs.get(job_id)
            if job:
                job.status = JobStatus.RUNNING
                job.started_at = time.time()
                if job.audit_status:
                    job.audit_status.set_phase(AuditPhase.STARTING)

    def complete_job(self, job_id: str, findings_count: int = 0, cost_delta: float = 0.0) -> None:
        """Mark a job as completed."""
        with self._lock:
            job = self._jobs.get(job_id)
            if job:
                job.status = JobStatus.COMPLETED
                job.ended_at = time.time()
                job.findings_count = findings_count
                job.cost_delta = cost_delta
                if job.audit_status:
                    job.audit_status.set_completed(findings_count)

    def fail_job(self, job_id: str, error: str, cost_delta: float = 0.0) -> None:
        """Mark a job as failed."""
        with self._lock:
            job = self._jobs.get(job_id)
            if job:
                job.status = JobStatus.FAILED
                job.ended_at = time.time()
                job.error = error
                job.cost_delta = cost_delta
                if job.audit_status:
                    job.audit_status.set_failed(error)

    def cancel_job(self, job_id: str) -> None:
        """Mark a job as cancelled."""
        with self._lock:
            job = self._jobs.get(job_id)
            if job:
                job.status = JobStatus.CANCELLED
                job.ended_at = time.time()
                if job.audit_status:
                    job.audit_status.set_failed("Cancelled by user")

    def get_job(self, job_id: str) -> Optional[AuditJob]:
        with self._lock:
            return self._jobs.get(job_id)

    def get_all_jobs(self) -> List[AuditJob]:
        """Return all jobs in insertion order (excludes child jobs of parallel groups)."""
        with self._lock:
            return [
                self._jobs[jid]
                for jid in self._job_order
                if jid in self._jobs and self._jobs[jid].parent_job_id is None
            ]

    def get_active_jobs(self) -> List[AuditJob]:
        """Return jobs that are QUEUED or RUNNING."""
        with self._lock:
            return [
                self._jobs[jid]
                for jid in self._job_order
                if jid in self._jobs and self._jobs[jid].is_active
            ]

    def get_session_cost(self) -> float:
        """Total LLM cost across all jobs in this session."""
        with self._lock:
            return sum(j.cost_delta for j in self._jobs.values())

    def get_session_findings(self) -> int:
        """Total findings across all completed jobs."""
        with self._lock:
            return sum(
                j.findings_count
                for j in self._jobs.values()
                if j.status == JobStatus.COMPLETED
            )

    def get_job_log(self, job_id: str) -> list:
        """Return the log buffer for a job (empty list if not found)."""
        with self._lock:
            job = self._jobs.get(job_id)
        if job and job.audit_status:
            return job.audit_status.get_all_log_lines()
        return []

    def get_new_job_log(self, job_id: str) -> list:
        """Return new log lines since last call for a job."""
        with self._lock:
            job = self._jobs.get(job_id)
        if job and job.audit_status:
            return job.audit_status.get_new_log_lines()
        return []

    def get_children(self, job_id: str) -> list:
        """Return child AuditJob objects for a parallel parent."""
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return []
            return [self._jobs[cid] for cid in job.child_job_ids if cid in self._jobs]

    @property
    def has_active_jobs(self) -> bool:
        with self._lock:
            return any(j.is_active for j in self._jobs.values())

    @property
    def job_count(self) -> int:
        with self._lock:
            return len(self._jobs)
