"""
Audit progress tracking for parallel contract auditing.

Provides thread-safe status tracking and stdout multiplexing so that
parallel audit workers can report progress independently while a
Rich Live dashboard on the main thread renders a unified view.
"""

import re
import sys
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, IO, Optional


class AuditPhase(Enum):
    """Phases of a single contract audit."""
    QUEUED = "Queued"
    STARTING = "Starting"
    STATIC_ANALYSIS = "Static Analysis"
    LLM_ANALYSIS = "LLM Analysis"
    AI_ENSEMBLE = "AI Ensemble"
    DEEP_DIVE = "Deep Dive"
    CROSS_CONTRACT = "Cross-Contract"
    VALIDATION = "Validation"
    FOUNDRY = "Foundry"
    REPORTING = "Reporting"
    SAVING = "Saving"
    COMPLETED = "Completed"
    FAILED = "Failed"


# Map substrings found in engine print() output to audit phases.
# Order matters: first match wins when scanning a line.
PHASE_MARKERS: Dict[str, AuditPhase] = {
    "Starting enhanced AetherAudit": AuditPhase.STARTING,
    "Starting AetherAudit": AuditPhase.STARTING,
    "Running Slither": AuditPhase.STATIC_ANALYSIS,
    "Running enhanced static": AuditPhase.STATIC_ANALYSIS,
    "enhanced pattern-based": AuditPhase.STATIC_ANALYSIS,
    "Building call graph": AuditPhase.STATIC_ANALYSIS,
    "proxy delegation": AuditPhase.STATIC_ANALYSIS,
    "Deduplicating": AuditPhase.STATIC_ANALYSIS,
    "access control context": AuditPhase.STATIC_ANALYSIS,
    "Running enhanced LLM": AuditPhase.LLM_ANALYSIS,
    "Phase 3 AI ensemble": AuditPhase.AI_ENSEMBLE,
    "AI ensemble found": AuditPhase.AI_ENSEMBLE,
    "deep-dive analysis": AuditPhase.DEEP_DIVE,
    "cross-contract interactions": AuditPhase.CROSS_CONTRACT,
    "enhanced validation": AuditPhase.VALIDATION,
    "LLM-based false positive": AuditPhase.VALIDATION,
    "proxy pattern filter": AuditPhase.VALIDATION,
    "Foundry verification": AuditPhase.FOUNDRY,
    "Foundry validation": AuditPhase.FOUNDRY,
    "Generating per-contract": AuditPhase.REPORTING,
    "comprehensive report": AuditPhase.REPORTING,
    "audit_report": AuditPhase.REPORTING,
    "Audit result saved": AuditPhase.SAVING,
    "Audit result updated": AuditPhase.SAVING,
    "vulnerability findings saved": AuditPhase.SAVING,
}

# Regex to extract finding counts from engine output
_FINDINGS_RE = re.compile(
    r"(?:(\d+)\s+(?:findings?|vulnerabilit|consensus findings))"
    r"|(?:Reduced from \d+ to (\d+))"
    r"|(?:Collected (\d+) findings)"
)


@dataclass
class ContractAuditStatus:
    """Thread-safe per-contract progress tracker."""

    contract_name: str
    contract_path: str
    phase: AuditPhase = AuditPhase.QUEUED
    findings_count: int = 0
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    error: Optional[str] = None
    last_message: str = ""
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def set_phase(self, phase: AuditPhase) -> None:
        with self._lock:
            self.phase = phase
            if phase == AuditPhase.STARTING and self.start_time is None:
                self.start_time = time.time()

    def set_completed(self, findings: int = 0) -> None:
        with self._lock:
            self.phase = AuditPhase.COMPLETED
            self.end_time = time.time()
            if findings > 0:
                self.findings_count = findings

    def set_failed(self, error_msg: str) -> None:
        with self._lock:
            self.phase = AuditPhase.FAILED
            self.end_time = time.time()
            self.error = error_msg

    def update_from_line(self, line: str) -> None:
        """Parse an output line for phase markers and finding counts."""
        with self._lock:
            self.last_message = line.rstrip()[:120]

        # Phase detection
        for marker, phase in PHASE_MARKERS.items():
            if marker in line:
                self.set_phase(phase)
                break

        # Finding count extraction
        m = _FINDINGS_RE.search(line)
        if m:
            for g in m.groups():
                if g is not None:
                    count = int(g)
                    with self._lock:
                        if count > self.findings_count:
                            self.findings_count = count

    @property
    def elapsed(self) -> Optional[float]:
        with self._lock:
            if self.start_time is None:
                return None
            end = self.end_time or time.time()
            return end - self.start_time

    @property
    def is_done(self) -> bool:
        with self._lock:
            return self.phase in (AuditPhase.COMPLETED, AuditPhase.FAILED)


class ThreadDemuxWriter:
    """
    Replacement for sys.stdout that routes write() calls by thread ID.

    Worker threads register their ContractAuditStatus; output lines are
    parsed for phase markers and finding counts.  Unregistered threads
    (including the main thread) pass through to the original stdout.
    """

    def __init__(self, original: IO):
        self._original = original
        self._lock = threading.Lock()
        # thread_ident -> ContractAuditStatus
        self._registry: Dict[int, ContractAuditStatus] = {}
        # Buffer partial lines per thread
        self._buffers: Dict[int, str] = {}

    @property
    def original(self) -> IO:
        return self._original

    def register(self, status: ContractAuditStatus) -> None:
        tid = threading.current_thread().ident
        with self._lock:
            self._registry[tid] = status
            self._buffers[tid] = ""

    def unregister(self) -> None:
        tid = threading.current_thread().ident
        with self._lock:
            self._registry.pop(tid, None)
            self._buffers.pop(tid, None)

    def write(self, data: str) -> int:
        if not data:
            return 0

        tid = threading.current_thread().ident

        with self._lock:
            status = self._registry.get(tid)

        if status is None:
            # Main thread or unregistered — pass through
            return self._original.write(data)

        # Buffer and process complete lines
        with self._lock:
            buf = self._buffers.get(tid, "") + data
            lines = buf.split("\n")
            # Last element is incomplete (or empty if data ended with \n)
            self._buffers[tid] = lines[-1]
            complete_lines = lines[:-1]

        for line in complete_lines:
            if line.strip():
                status.update_from_line(line)

        return len(data)

    def flush(self) -> None:
        self._original.flush()

    # Forward all other attributes to the original stream so that
    # libraries checking for .encoding, .isatty(), etc. still work.
    def __getattr__(self, name):
        return getattr(self._original, name)
