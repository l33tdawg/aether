"""
Halmos Symbolic Execution Runner for Aether.

Discovers the halmos binary, executes symbolic tests against
Solidity contracts, parses output, and reports results.
Gracefully degrades when halmos is not installed.
"""

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class HalmosResult(Enum):
    """Outcome of a single halmos symbolic test."""
    PASS = "pass"
    FAIL = "fail"
    TIMEOUT = "timeout"
    ERROR = "error"
    SKIP = "skip"


@dataclass
class HalmosTestResult:
    """Result from running a single halmos symbolic test function."""
    function_name: str
    result: HalmosResult
    counterexample: Optional[str] = None
    duration_seconds: float = 0.0
    error_message: Optional[str] = None
    raw_output: str = ""


@dataclass
class HalmosRunResult:
    """Aggregated result from running halmos on a test contract."""
    test_contract: str
    test_results: List[HalmosTestResult] = field(default_factory=list)
    total_duration_seconds: float = 0.0
    halmos_version: Optional[str] = None
    success: bool = True
    error_message: Optional[str] = None

    @property
    def passed(self) -> int:
        return sum(1 for t in self.test_results if t.result == HalmosResult.PASS)

    @property
    def failed(self) -> int:
        return sum(1 for t in self.test_results if t.result == HalmosResult.FAIL)

    @property
    def timed_out(self) -> int:
        return sum(1 for t in self.test_results if t.result == HalmosResult.TIMEOUT)

    @property
    def errors(self) -> int:
        return sum(1 for t in self.test_results if t.result == HalmosResult.ERROR)


class HalmosRunner:
    """Discovers and runs halmos symbolic execution on Solidity test contracts.

    Gracefully degrades when halmos is not available — callers should check
    ``is_available()`` before attempting to run symbolic tests.
    """

    DEFAULT_TIMEOUT = 120  # seconds per test function
    DEFAULT_LOOP_BOUND = 3
    DEFAULT_SOLVER_TIMEOUT = 30000  # milliseconds

    def __init__(
        self,
        timeout: int = DEFAULT_TIMEOUT,
        loop_bound: int = DEFAULT_LOOP_BOUND,
        solver_timeout_ms: int = DEFAULT_SOLVER_TIMEOUT,
    ):
        self._halmos_path: Optional[str] = None
        self._version: Optional[str] = None
        self.timeout = timeout
        self.loop_bound = loop_bound
        self.solver_timeout_ms = solver_timeout_ms
        self._discover_binary()

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    def _discover_binary(self) -> None:
        """Locate halmos on PATH or in common install locations."""
        path = shutil.which("halmos")
        if path:
            self._halmos_path = path
            self._version = self._get_version(path)
            logger.info("Found halmos at %s (version %s)", path, self._version)
            return

        # Check common pip/pipx locations
        candidates = [
            Path.home() / ".local" / "bin" / "halmos",
            Path.home() / ".local" / "pipx" / "venvs" / "halmos" / "bin" / "halmos",
        ]
        for candidate in candidates:
            if candidate.exists() and os.access(candidate, os.X_OK):
                self._halmos_path = str(candidate)
                self._version = self._get_version(str(candidate))
                logger.info("Found halmos at %s (version %s)", candidate, self._version)
                return

        logger.info("halmos not found — symbolic execution will be skipped")

    def _get_version(self, binary_path: str) -> Optional[str]:
        """Return halmos version string, or None on failure."""
        try:
            result = subprocess.run(
                [binary_path, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            version_text = result.stdout.strip() or result.stderr.strip()
            # e.g. "halmos 0.2.1" -> "0.2.1"
            match = re.search(r"(\d+\.\d+\.\d+)", version_text)
            return match.group(1) if match else version_text
        except Exception:
            return None

    def is_available(self) -> bool:
        """Return True if halmos binary was discovered and is executable."""
        return self._halmos_path is not None

    @property
    def version(self) -> Optional[str]:
        return self._version

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def run_symbolic_test(
        self,
        project_dir: str,
        test_contract: Optional[str] = None,
        test_function: Optional[str] = None,
        extra_args: Optional[List[str]] = None,
    ) -> HalmosRunResult:
        """Run halmos symbolic execution.

        Args:
            project_dir: Root of the Foundry project (must contain foundry.toml).
            test_contract: Optional contract name filter (e.g. ``VaultHalmosTest``).
            test_function: Optional function name filter (e.g. ``check_noShareInflation``).
            extra_args: Additional CLI flags for halmos.

        Returns:
            HalmosRunResult with per-function outcomes.
        """
        if not self.is_available():
            return HalmosRunResult(
                test_contract=test_contract or "",
                success=False,
                error_message="halmos is not installed",
            )

        project_path = Path(project_dir)
        if not (project_path / "foundry.toml").exists():
            return HalmosRunResult(
                test_contract=test_contract or "",
                success=False,
                error_message=f"No foundry.toml in {project_dir}",
            )

        cmd = [
            self._halmos_path,
            "--root", str(project_path),
            "--loop", str(self.loop_bound),
            "--solver-timeout-assertion", str(self.solver_timeout_ms),
        ]

        if test_contract:
            cmd.extend(["--contract", test_contract])
        if test_function:
            cmd.extend(["--function", test_function])
        if extra_args:
            cmd.extend(extra_args)

        start = time.monotonic()
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout * max(1, 10),  # overall timeout
                cwd=str(project_path),
            )
            elapsed = time.monotonic() - start
            raw = result.stdout + "\n" + result.stderr

            test_results = self._parse_output(raw)

            return HalmosRunResult(
                test_contract=test_contract or "",
                test_results=test_results,
                total_duration_seconds=elapsed,
                halmos_version=self._version,
                success=True,
            )
        except subprocess.TimeoutExpired:
            elapsed = time.monotonic() - start
            return HalmosRunResult(
                test_contract=test_contract or "",
                total_duration_seconds=elapsed,
                halmos_version=self._version,
                success=False,
                error_message="halmos global timeout expired",
            )
        except Exception as exc:
            elapsed = time.monotonic() - start
            logger.warning("halmos execution error: %s", exc)
            return HalmosRunResult(
                test_contract=test_contract or "",
                total_duration_seconds=elapsed,
                halmos_version=self._version,
                success=False,
                error_message=str(exc),
            )

    # ------------------------------------------------------------------
    # Output parsing
    # ------------------------------------------------------------------

    def _parse_output(self, raw_output: str) -> List[HalmosTestResult]:
        """Parse halmos stdout/stderr into structured test results.

        Halmos output looks like:
            Running 3 tests for test/VaultTest.t.sol:VaultHalmosTest
            [PASS] check_noShareInflation(uint256) (time: 1.23s)
            [FAIL] check_conservedAssets(uint256,uint256) (counterexample: ...)
            [ERROR] check_broken() (error: CompilationError(...))
        """
        results: List[HalmosTestResult] = []

        # Pattern: [PASS|FAIL|ERROR] functionName(args) (details)
        line_pattern = re.compile(
            r"\[(PASS|FAIL|ERROR)\]\s+"
            r"(\w+)\([^)]*\)"
            r"(?:\s+\((.+?)\))?"
        )

        for line in raw_output.splitlines():
            match = line_pattern.search(line)
            if not match:
                continue

            status_str, func_name, details = match.groups()
            details = details or ""

            if status_str == "PASS":
                result = HalmosResult.PASS
            elif status_str == "FAIL":
                result = HalmosResult.FAIL
            else:
                result = HalmosResult.ERROR

            # Extract duration
            duration = 0.0
            dur_match = re.search(r"time:\s*([\d.]+)s", details)
            if dur_match:
                duration = float(dur_match.group(1))

            # Extract counterexample
            counterexample = None
            ce_match = re.search(r"counterexample:\s*(.+)", details)
            if ce_match:
                counterexample = ce_match.group(1).strip()

            # Extract error message
            error_msg = None
            err_match = re.search(r"error:\s*(.+)", details)
            if err_match:
                error_msg = err_match.group(1).strip()

            results.append(HalmosTestResult(
                function_name=func_name,
                result=result,
                counterexample=counterexample,
                duration_seconds=duration,
                error_message=error_msg,
                raw_output=line.strip(),
            ))

        # Detect timeout lines like "WARNING: ... timed out"
        timeout_pattern = re.compile(r"(\w+)\([^)]*\).*timed?\s*out", re.IGNORECASE)
        for line in raw_output.splitlines():
            tm = timeout_pattern.search(line)
            if tm:
                func_name = tm.group(1)
                # Only add if not already captured
                if not any(r.function_name == func_name for r in results):
                    results.append(HalmosTestResult(
                        function_name=func_name,
                        result=HalmosResult.TIMEOUT,
                        raw_output=line.strip(),
                    ))

        return results

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    def check_property(
        self,
        project_dir: str,
        test_contract: str,
        property_function: str,
    ) -> HalmosTestResult:
        """Run a single property check and return its result.

        This is the high-level API used by the validation pipeline to verify
        one finding at a time.
        """
        run_result = self.run_symbolic_test(
            project_dir=project_dir,
            test_contract=test_contract,
            test_function=property_function,
        )

        if not run_result.success:
            return HalmosTestResult(
                function_name=property_function,
                result=HalmosResult.ERROR,
                error_message=run_result.error_message,
            )

        # Find the matching result
        for tr in run_result.test_results:
            if tr.function_name == property_function:
                return tr

        # Function not found in output — likely compilation error
        return HalmosTestResult(
            function_name=property_function,
            result=HalmosResult.SKIP,
            error_message="Function not found in halmos output",
        )
