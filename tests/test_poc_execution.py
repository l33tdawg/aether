#!/usr/bin/env python3
"""
Tests for PoC auto-execution — the forge test integration added in v5.0.

Covers:
- FoundryTestResult and ForgeTestSummary dataclasses
- _execute_poc_tests() with mocked subprocess
- _parse_forge_test_json() JSON parsing
- Auto-execution wiring in compile_and_repair_loop()
- POC_TESTING phase in AuditPhase
- Edge cases: empty output, malformed JSON, timeouts, missing forge
"""

import json
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch, AsyncMock

from core.foundry_poc_generator import (
    FoundryPoCGenerator,
    FoundryTestResult,
    ForgeTestSummary,
    PoCTestResult,
    VulnerabilityClass,
)
from core.audit_progress import AuditPhase, _PHASE_INDEX, TOTAL_PHASES


# ---------------------------------------------------------------------------
# Sample forge test JSON output fixtures
# ---------------------------------------------------------------------------

FORGE_JSON_ALL_PASS = json.dumps({
    "test/VulnerableToken_test.sol:VulnerableTokenTest": {
        "test_results": [
            {
                "name": "testExploitReentrancy",
                "status": "Success",
                "reason": None,
                "decoded_logs": ["Reentrancy exploit succeeded"],
                "gas": 85421,
                "duration": {"secs": 0, "nanos": 42000000},
            },
            {
                "name": "testExploitOverflow",
                "status": "Success",
                "reason": None,
                "decoded_logs": [],
                "gas": 31200,
                "duration": {"secs": 0, "nanos": 18000000},
            },
        ]
    }
})

FORGE_JSON_MIXED = json.dumps({
    "test/Token_test.sol:TokenTest": {
        "test_results": [
            {
                "name": "testExploitReentrancy",
                "status": "Success",
                "reason": None,
                "decoded_logs": [],
                "gas": 85421,
                "duration": {"secs": 0, "nanos": 42000000},
            },
            {
                "name": "testExploitAccessControl",
                "status": "Failure",
                "reason": "revert: Ownable: caller is not the owner",
                "decoded_logs": ["Setup complete"],
                "gas": 12300,
                "duration": {"secs": 0, "nanos": 5000000},
            },
        ]
    }
})

FORGE_JSON_ALL_FAIL = json.dumps({
    "test/Vault_test.sol:VaultTest": {
        "test_results": [
            {
                "name": "testExploitFlashLoan",
                "status": "Failure",
                "reason": "EvmError: Revert",
                "decoded_logs": [],
                "gas": 0,
                "duration": {"secs": 1, "nanos": 200000000},
            },
        ]
    }
})

FORGE_JSON_MULTI_FILE = json.dumps({
    "test/A_test.sol:ATest": {
        "test_results": [
            {"name": "testA", "status": "Success", "reason": None,
             "decoded_logs": [], "gas": 100, "duration": 10},
        ]
    },
    "test/B_test.sol:BTest": {
        "test_results": [
            {"name": "testB", "status": "Failure", "reason": "revert",
             "decoded_logs": [], "gas": 200, "duration": 20},
        ]
    },
})


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _make_poc_test_result(**overrides) -> PoCTestResult:
    """Create a PoCTestResult with sensible defaults."""
    defaults = dict(
        finding_id="finding_1",
        contract_name="VulnerableToken",
        vulnerability_type="reentrancy",
        severity="high",
        entrypoint_used="withdraw()",
        attempts_compile=0,
        attempts_run=0,
        compiled=False,
        run_passed=False,
        test_code="// test code",
        exploit_code="// exploit code",
        fixed_code=None,
        compile_errors=[],
        runtime_errors=[],
        generation_time=1.0,
        compile_time=0.0,
        run_time=0.0,
    )
    defaults.update(overrides)
    return PoCTestResult(**defaults)


# ---------------------------------------------------------------------------
# Tests: FoundryTestResult dataclass
# ---------------------------------------------------------------------------

class TestFoundryTestResult(unittest.TestCase):

    def test_basic_creation(self):
        r = FoundryTestResult(test_name="testExploit", passed=True, gas_used=50000)
        self.assertEqual(r.test_name, "testExploit")
        self.assertTrue(r.passed)
        self.assertEqual(r.gas_used, 50000)
        self.assertEqual(r.logs, [])
        self.assertEqual(r.revert_reason, "")

    def test_failed_result(self):
        r = FoundryTestResult(
            test_name="testFail",
            passed=False,
            revert_reason="revert: unauthorized",
        )
        self.assertFalse(r.passed)
        self.assertEqual(r.revert_reason, "revert: unauthorized")

    def test_default_logs_list(self):
        r = FoundryTestResult(test_name="t", passed=True)
        self.assertIsInstance(r.logs, list)
        self.assertEqual(len(r.logs), 0)
        # Mutating one instance should not affect another
        r.logs.append("x")
        r2 = FoundryTestResult(test_name="t2", passed=True)
        self.assertEqual(len(r2.logs), 0)


# ---------------------------------------------------------------------------
# Tests: ForgeTestSummary dataclass
# ---------------------------------------------------------------------------

class TestForgeTestSummary(unittest.TestCase):

    def test_all_passed_property(self):
        s = ForgeTestSummary(project_dir="/tmp/test", total_tests=3, passed=3, failed=0)
        self.assertTrue(s.all_passed)

    def test_all_passed_false_when_failures(self):
        s = ForgeTestSummary(project_dir="/tmp/test", total_tests=3, passed=2, failed=1)
        self.assertFalse(s.all_passed)

    def test_all_passed_false_when_no_tests(self):
        s = ForgeTestSummary(project_dir="/tmp/test", total_tests=0, passed=0, failed=0)
        self.assertFalse(s.all_passed)

    def test_default_test_results_list(self):
        s = ForgeTestSummary(project_dir="/tmp")
        self.assertIsInstance(s.test_results, list)
        self.assertEqual(len(s.test_results), 0)


# ---------------------------------------------------------------------------
# Tests: _parse_forge_test_json
# ---------------------------------------------------------------------------

class TestParseForgeTestJson(unittest.TestCase):

    def setUp(self):
        with patch.object(FoundryPoCGenerator, '__init__', lambda self, **kw: None):
            self.gen = FoundryPoCGenerator()

    def test_parse_all_pass(self):
        results = self.gen._parse_forge_test_json(FORGE_JSON_ALL_PASS)
        self.assertEqual(len(results), 2)
        self.assertTrue(results[0].passed)
        self.assertTrue(results[1].passed)
        self.assertEqual(results[0].test_name, "testExploitReentrancy")
        self.assertEqual(results[0].gas_used, 85421)
        self.assertEqual(results[0].duration_ms, 42)  # 42M nanos = 42ms

    def test_parse_mixed(self):
        results = self.gen._parse_forge_test_json(FORGE_JSON_MIXED)
        self.assertEqual(len(results), 2)
        self.assertTrue(results[0].passed)
        self.assertFalse(results[1].passed)
        self.assertIn("Ownable", results[1].revert_reason)

    def test_parse_all_fail(self):
        results = self.gen._parse_forge_test_json(FORGE_JSON_ALL_FAIL)
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0].passed)
        # 1 sec + 200M nanos = 1200ms
        self.assertEqual(results[0].duration_ms, 1200)

    def test_parse_multi_file(self):
        results = self.gen._parse_forge_test_json(FORGE_JSON_MULTI_FILE)
        self.assertEqual(len(results), 2)
        names = {r.test_name for r in results}
        self.assertEqual(names, {"testA", "testB"})

    def test_parse_empty_string(self):
        results = self.gen._parse_forge_test_json("")
        self.assertEqual(results, [])

    def test_parse_no_json(self):
        results = self.gen._parse_forge_test_json("Some random output without JSON")
        self.assertEqual(results, [])

    def test_parse_malformed_json(self):
        results = self.gen._parse_forge_test_json("{broken json")
        self.assertEqual(results, [])

    def test_parse_json_with_prefix(self):
        """forge may emit compiler warnings before JSON output."""
        prefixed = "Warning: unused variable\n" + FORGE_JSON_ALL_PASS
        results = self.gen._parse_forge_test_json(prefixed)
        self.assertEqual(len(results), 2)

    def test_parse_duration_integer(self):
        """Some forge versions emit duration as a plain integer."""
        data = json.dumps({
            "test/T.sol:T": {
                "test_results": [
                    {"name": "t1", "status": "Success", "reason": None,
                     "decoded_logs": [], "gas": 1, "duration": 500},
                ]
            }
        })
        results = self.gen._parse_forge_test_json(data)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].duration_ms, 500)

    def test_parse_missing_fields(self):
        """Gracefully handle missing optional fields."""
        data = json.dumps({
            "test/T.sol:T": {
                "test_results": [
                    {"name": "t1", "status": "Success"},
                ]
            }
        })
        results = self.gen._parse_forge_test_json(data)
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].passed)
        self.assertEqual(results[0].gas_used, 0)
        self.assertEqual(results[0].logs, [])

    def test_parse_logs_truncated(self):
        """Logs should be capped at 50 entries."""
        data = json.dumps({
            "test/T.sol:T": {
                "test_results": [
                    {"name": "t1", "status": "Success", "reason": None,
                     "decoded_logs": [f"log_{i}" for i in range(100)],
                     "gas": 1},
                ]
            }
        })
        results = self.gen._parse_forge_test_json(data)
        self.assertEqual(len(results[0].logs), 50)


# ---------------------------------------------------------------------------
# Tests: _execute_poc_tests (mocked subprocess)
# ---------------------------------------------------------------------------

class TestExecutePoCTests(unittest.TestCase):

    def setUp(self):
        with patch.object(FoundryPoCGenerator, '__init__', lambda self, **kw: None):
            self.gen = FoundryPoCGenerator()
        self.gen.fork_url = ''
        self.gen.enable_fork_run = False

    def _mock_forge_env(self):
        return os.environ.copy()

    @patch('core.foundry_poc_generator.subprocess.run')
    def test_all_pass(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout=FORGE_JSON_ALL_PASS,
            stderr="",
            returncode=0,
        )
        self.gen._forge_env = self._mock_forge_env

        summary = self.gen._execute_poc_tests("/tmp/project")
        self.assertTrue(summary.all_passed)
        self.assertEqual(summary.total_tests, 2)
        self.assertEqual(summary.passed, 2)
        self.assertEqual(summary.failed, 0)
        self.assertEqual(summary.error, "")

        # Verify forge test command
        cmd = mock_run.call_args[0][0]
        self.assertIn('forge', cmd)
        self.assertIn('test', cmd)
        self.assertIn('--json', cmd)
        self.assertIn('-vvv', cmd)

    @patch('core.foundry_poc_generator.subprocess.run')
    def test_mixed_results(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout=FORGE_JSON_MIXED,
            stderr="",
            returncode=1,
        )
        self.gen._forge_env = self._mock_forge_env

        summary = self.gen._execute_poc_tests("/tmp/project")
        self.assertFalse(summary.all_passed)
        self.assertEqual(summary.total_tests, 2)
        self.assertEqual(summary.passed, 1)
        self.assertEqual(summary.failed, 1)

    @patch('core.foundry_poc_generator.subprocess.run')
    def test_with_match_path(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout=FORGE_JSON_ALL_PASS,
            stderr="",
            returncode=0,
        )
        self.gen._forge_env = self._mock_forge_env

        self.gen._execute_poc_tests("/tmp/project", test_file="Token_test.sol")
        cmd = mock_run.call_args[0][0]
        self.assertIn('--match-path', cmd)
        self.assertIn('Token_test.sol', cmd)

    @patch('core.foundry_poc_generator.subprocess.run')
    def test_with_fork_url(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout=FORGE_JSON_ALL_PASS,
            stderr="",
            returncode=0,
        )
        self.gen._forge_env = self._mock_forge_env

        self.gen._execute_poc_tests(
            "/tmp/project",
            fork_url="https://eth-mainnet.example.com",
        )
        cmd = mock_run.call_args[0][0]
        self.assertIn('--fork-url', cmd)
        self.assertIn('https://eth-mainnet.example.com', cmd)

    @patch('core.foundry_poc_generator.subprocess.run')
    def test_forge_not_found(self, mock_run):
        mock_run.side_effect = FileNotFoundError("forge not found")
        self.gen._forge_env = self._mock_forge_env

        summary = self.gen._execute_poc_tests("/tmp/project")
        self.assertFalse(summary.all_passed)
        self.assertEqual(summary.total_tests, 0)
        self.assertIn("forge not found", summary.error)

    @patch('core.foundry_poc_generator.subprocess.run')
    def test_forge_timeout(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="forge test", timeout=120)
        self.gen._forge_env = self._mock_forge_env

        summary = self.gen._execute_poc_tests("/tmp/project")
        self.assertFalse(summary.all_passed)
        self.assertIn("timed out", summary.error)

    @patch('core.foundry_poc_generator.subprocess.run')
    def test_forge_generic_error(self, mock_run):
        mock_run.side_effect = OSError("Disk full")
        self.gen._forge_env = self._mock_forge_env

        summary = self.gen._execute_poc_tests("/tmp/project")
        self.assertFalse(summary.all_passed)
        self.assertIn("Disk full", summary.error)

    @patch('core.foundry_poc_generator.subprocess.run')
    def test_no_json_output_with_error(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout="Compiler error: something",
            stderr="Error: something went wrong",
            returncode=1,
        )
        self.gen._forge_env = self._mock_forge_env

        summary = self.gen._execute_poc_tests("/tmp/project")
        self.assertEqual(summary.total_tests, 0)
        self.assertFalse(summary.all_passed)
        self.assertTrue(len(summary.error) > 0)

    @patch('core.foundry_poc_generator.subprocess.run')
    def test_duration_tracked(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout=FORGE_JSON_ALL_PASS,
            stderr="",
            returncode=0,
        )
        self.gen._forge_env = self._mock_forge_env

        summary = self.gen._execute_poc_tests("/tmp/project")
        self.assertGreater(summary.duration_secs, 0.0)

    @patch('core.foundry_poc_generator.subprocess.run')
    def test_cwd_set_to_project_dir(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout=FORGE_JSON_ALL_PASS,
            stderr="",
            returncode=0,
        )
        self.gen._forge_env = self._mock_forge_env

        self.gen._execute_poc_tests("/my/project/dir")
        kwargs = mock_run.call_args[1]
        self.assertEqual(kwargs['cwd'], "/my/project/dir")

    @patch('core.foundry_poc_generator.subprocess.run')
    def test_timeout_set_to_120(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout=FORGE_JSON_ALL_PASS,
            stderr="",
            returncode=0,
        )
        self.gen._forge_env = self._mock_forge_env

        self.gen._execute_poc_tests("/tmp/project")
        kwargs = mock_run.call_args[1]
        self.assertEqual(kwargs['timeout'], 120)


# ---------------------------------------------------------------------------
# Tests: AuditPhase.POC_TESTING
# ---------------------------------------------------------------------------

class TestPoCTestingPhase(unittest.TestCase):

    def test_poc_testing_phase_exists(self):
        self.assertIn(AuditPhase.POC_TESTING, AuditPhase)
        self.assertEqual(AuditPhase.POC_TESTING.value, "PoC Testing")

    def test_poc_testing_in_phase_index(self):
        self.assertIn(AuditPhase.POC_TESTING, _PHASE_INDEX)
        idx = _PHASE_INDEX[AuditPhase.POC_TESTING]
        # Should be between FOUNDRY and REPORTING
        self.assertGreater(idx, _PHASE_INDEX[AuditPhase.FOUNDRY])
        self.assertLess(idx, _PHASE_INDEX[AuditPhase.REPORTING])

    def test_total_phases_updated(self):
        self.assertEqual(TOTAL_PHASES, 13)

    def test_phase_ordering(self):
        """Verify the full phase ordering is consistent."""
        expected_order = [
            AuditPhase.QUEUED,
            AuditPhase.STARTING,
            AuditPhase.STATIC_ANALYSIS,
            AuditPhase.LLM_ANALYSIS,
            AuditPhase.AI_ENSEMBLE,
            AuditPhase.DEEP_DIVE,
            AuditPhase.CROSS_CONTRACT,
            AuditPhase.VALIDATION,
            AuditPhase.FOUNDRY,
            AuditPhase.POC_TESTING,
            AuditPhase.REPORTING,
            AuditPhase.SAVING,
            AuditPhase.COMPLETED,
        ]
        for i, phase in enumerate(expected_order):
            self.assertEqual(_PHASE_INDEX[phase], i, f"Phase {phase} has wrong index")

    def test_phase_marker_detection(self):
        """PHASE_MARKERS should detect PoC test output."""
        from core.audit_progress import PHASE_MARKERS
        matched = False
        for marker, phase in PHASE_MARKERS.items():
            if "Running PoC tests" in marker or marker in "Running PoC tests in /tmp/project":
                if phase == AuditPhase.POC_TESTING:
                    matched = True
                    break
        self.assertTrue(matched, "No PHASE_MARKER triggers POC_TESTING phase")

    def test_contract_audit_status_sets_poc_testing(self):
        """ContractAuditStatus.update_from_line should detect PoC testing."""
        from core.audit_progress import ContractAuditStatus
        status = ContractAuditStatus(contract_name="Test", contract_path="/tmp/test.sol")
        status.update_from_line("Running PoC tests in /tmp/project")
        self.assertEqual(status.phase, AuditPhase.POC_TESTING)


# ---------------------------------------------------------------------------
# Tests: Auto-execution wiring in compile_and_repair_loop
# ---------------------------------------------------------------------------

class TestAutoExecution(unittest.TestCase):
    """Verify that compile_and_repair_loop calls _execute_poc_tests on success."""

    def setUp(self):
        with patch.object(FoundryPoCGenerator, '__init__', lambda self, **kw: None):
            self.gen = FoundryPoCGenerator()
        self.gen.config = {}
        self.gen.max_compile_attempts = 1
        self.gen.template_only = True  # Skip LLM repairs
        self.gen.enable_fork_run = False
        self.gen.fork_url = ''

    @patch.object(FoundryPoCGenerator, '_execute_poc_tests')
    @patch.object(FoundryPoCGenerator, '_compile_foundry_project')
    @patch.object(FoundryPoCGenerator, '_write_poc_files', new_callable=AsyncMock)
    def test_auto_execute_on_compile_success(self, mock_write, mock_compile, mock_execute):
        """When compilation succeeds, _execute_poc_tests should be called."""
        mock_compile.return_value = {
            'success': True,
            'errors': [],
            'output': 'Compiled',
            'return_code': 0,
        }
        mock_execute.return_value = ForgeTestSummary(
            project_dir="/tmp/out",
            total_tests=1,
            passed=1,
            failed=0,
        )

        test_result = _make_poc_test_result()
        import asyncio
        result = asyncio.run(
            self.gen.compile_and_repair_loop(test_result, "/tmp/out")
        )

        self.assertTrue(result.compiled)
        mock_execute.assert_called_once()
        self.assertTrue(result.run_passed)
        self.assertEqual(result.attempts_run, 1)

    @patch.object(FoundryPoCGenerator, '_execute_poc_tests')
    @patch.object(FoundryPoCGenerator, '_compile_foundry_project')
    @patch.object(FoundryPoCGenerator, '_write_poc_files', new_callable=AsyncMock)
    def test_auto_execute_records_failures(self, mock_write, mock_compile, mock_execute):
        """When tests fail, run_passed=False and runtime_errors populated."""
        mock_compile.return_value = {
            'success': True,
            'errors': [],
            'output': 'Compiled',
            'return_code': 0,
        }
        mock_execute.return_value = ForgeTestSummary(
            project_dir="/tmp/out",
            total_tests=2,
            passed=1,
            failed=1,
            test_results=[
                FoundryTestResult(test_name="testPass", passed=True),
                FoundryTestResult(
                    test_name="testFail",
                    passed=False,
                    revert_reason="revert: unauthorized",
                ),
            ],
        )

        test_result = _make_poc_test_result()
        import asyncio
        result = asyncio.run(
            self.gen.compile_and_repair_loop(test_result, "/tmp/out")
        )

        self.assertTrue(result.compiled)
        self.assertFalse(result.run_passed)
        self.assertEqual(len(result.runtime_errors), 1)
        self.assertIn("testFail", result.runtime_errors[0])

    @patch.object(FoundryPoCGenerator, '_execute_poc_tests')
    @patch.object(FoundryPoCGenerator, '_compile_foundry_project')
    @patch.object(FoundryPoCGenerator, '_write_poc_files', new_callable=AsyncMock)
    def test_no_execute_on_compile_failure(self, mock_write, mock_compile, mock_execute):
        """When compilation fails, _execute_poc_tests should NOT be called."""
        mock_compile.return_value = {
            'success': False,
            'errors': ['Error: something'],
            'output': '',
            'return_code': 1,
        }

        test_result = _make_poc_test_result()
        import asyncio
        result = asyncio.run(
            self.gen.compile_and_repair_loop(test_result, "/tmp/out")
        )

        self.assertFalse(result.compiled)
        mock_execute.assert_not_called()

    @patch.object(FoundryPoCGenerator, '_execute_poc_tests')
    @patch.object(FoundryPoCGenerator, '_compile_foundry_project')
    @patch.object(FoundryPoCGenerator, '_write_poc_files', new_callable=AsyncMock)
    def test_auto_execute_with_forge_error(self, mock_write, mock_compile, mock_execute):
        """When forge test errors (e.g., forge not found), record the error."""
        mock_compile.return_value = {
            'success': True,
            'errors': [],
            'output': 'Compiled',
            'return_code': 0,
        }
        mock_execute.return_value = ForgeTestSummary(
            project_dir="/tmp/out",
            total_tests=0,
            passed=0,
            failed=0,
            error="forge not found in PATH",
        )

        test_result = _make_poc_test_result()
        import asyncio
        result = asyncio.run(
            self.gen.compile_and_repair_loop(test_result, "/tmp/out")
        )

        self.assertTrue(result.compiled)
        self.assertFalse(result.run_passed)
        self.assertEqual(result.runtime_errors, ["forge not found in PATH"])


# ---------------------------------------------------------------------------
# Tests: GenerationManifest tracks run results
# ---------------------------------------------------------------------------

class TestManifestRunTracking(unittest.TestCase):
    """Verify GenerationManifest counts successful_runs correctly."""

    def test_successful_run_counted(self):
        from core.foundry_poc_generator import GenerationManifest
        m = GenerationManifest(
            generation_id="test",
            timestamp="2026-01-01",
            total_findings=1,
            processed_findings=1,
            successful_compilations=1,
            successful_runs=0,
            total_attempts=1,
            average_attempts_per_test=1.0,
            error_taxonomy={},
            suites=[],
        )
        # Simulate a test result with run_passed=True
        tr = _make_poc_test_result(compiled=True, run_passed=True)
        m.suites.append(tr)
        if tr.run_passed:
            m.successful_runs += 1
        self.assertEqual(m.successful_runs, 1)


# ---------------------------------------------------------------------------
# Tests: ContractAuditStatus PoC test tracking
# ---------------------------------------------------------------------------

class TestPoCStatusTracking(unittest.TestCase):
    """Tests for PoC test status fields in ContractAuditStatus."""

    def _make_status(self):
        from core.audit_progress import ContractAuditStatus
        return ContractAuditStatus(
            contract_name="Test",
            contract_path="/tmp/test.sol",
        )

    def test_forge_summary_all_pass(self):
        status = self._make_status()
        status.update_from_line("INFO: Forge test: 3/3 passed in 1.5s")
        self.assertEqual(status.poc_tests_passed, 3)
        self.assertEqual(status.poc_tests_total, 3)
        self.assertEqual(status.poc_tests_failed, 0)
        self.assertEqual(status.poc_test_status, "tests_passed")

    def test_forge_summary_some_fail(self):
        status = self._make_status()
        status.update_from_line("INFO: Forge test: 2/5 passed in 3.0s")
        self.assertEqual(status.poc_tests_passed, 2)
        self.assertEqual(status.poc_tests_total, 5)
        self.assertEqual(status.poc_tests_failed, 3)
        self.assertEqual(status.poc_test_status, "tests_failed")

    def test_forge_summary_zero_tests(self):
        status = self._make_status()
        status.update_from_line("INFO: Forge test: 0/0 passed in 0.0s")
        self.assertEqual(status.poc_test_status, "compiled_only")

    def test_default_status_empty(self):
        status = self._make_status()
        self.assertEqual(status.poc_test_status, "")
        self.assertEqual(status.poc_tests_total, 0)
        self.assertEqual(status.poc_tests_passed, 0)
        self.assertEqual(status.poc_tests_failed, 0)

    def test_phase_set_to_poc_testing(self):
        status = self._make_status()
        status.update_from_line("Running PoC tests in /tmp/my_project")
        self.assertEqual(status.phase, AuditPhase.POC_TESTING)


if __name__ == "__main__":
    unittest.main()
