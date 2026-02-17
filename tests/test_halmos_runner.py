"""
Tests for core/halmos_runner.py — HalmosRunner, output parsing, binary discovery.
"""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

from core.halmos_runner import (
    HalmosRunner,
    HalmosResult,
    HalmosRunResult,
    HalmosTestResult,
)


class TestHalmosResultEnum(unittest.TestCase):
    """Test the HalmosResult enum values."""

    def test_enum_values(self):
        self.assertEqual(HalmosResult.PASS.value, "pass")
        self.assertEqual(HalmosResult.FAIL.value, "fail")
        self.assertEqual(HalmosResult.TIMEOUT.value, "timeout")
        self.assertEqual(HalmosResult.ERROR.value, "error")
        self.assertEqual(HalmosResult.SKIP.value, "skip")


class TestHalmosTestResult(unittest.TestCase):
    """Test the HalmosTestResult dataclass."""

    def test_defaults(self):
        r = HalmosTestResult(function_name="check_foo", result=HalmosResult.PASS)
        self.assertEqual(r.function_name, "check_foo")
        self.assertEqual(r.result, HalmosResult.PASS)
        self.assertIsNone(r.counterexample)
        self.assertEqual(r.duration_seconds, 0.0)
        self.assertIsNone(r.error_message)
        self.assertEqual(r.raw_output, "")

    def test_with_counterexample(self):
        r = HalmosTestResult(
            function_name="check_bar",
            result=HalmosResult.FAIL,
            counterexample="p_amount = 0x01",
        )
        self.assertEqual(r.counterexample, "p_amount = 0x01")


class TestHalmosRunResult(unittest.TestCase):
    """Test the HalmosRunResult dataclass."""

    def test_empty_results(self):
        r = HalmosRunResult(test_contract="Test")
        self.assertEqual(r.passed, 0)
        self.assertEqual(r.failed, 0)
        self.assertEqual(r.timed_out, 0)
        self.assertEqual(r.errors, 0)
        self.assertTrue(r.success)

    def test_counts(self):
        r = HalmosRunResult(
            test_contract="Test",
            test_results=[
                HalmosTestResult("a", HalmosResult.PASS),
                HalmosTestResult("b", HalmosResult.PASS),
                HalmosTestResult("c", HalmosResult.FAIL),
                HalmosTestResult("d", HalmosResult.TIMEOUT),
                HalmosTestResult("e", HalmosResult.ERROR),
            ],
        )
        self.assertEqual(r.passed, 2)
        self.assertEqual(r.failed, 1)
        self.assertEqual(r.timed_out, 1)
        self.assertEqual(r.errors, 1)


class TestHalmosRunnerDiscovery(unittest.TestCase):
    """Test binary discovery logic."""

    @patch("shutil.which", return_value=None)
    def test_not_available_when_not_installed(self, mock_which):
        runner = HalmosRunner()
        self.assertFalse(runner.is_available())
        self.assertIsNone(runner.version)

    @patch("shutil.which", return_value="/usr/local/bin/halmos")
    @patch("subprocess.run")
    def test_available_when_on_path(self, mock_run, mock_which):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="halmos 0.2.1\n", stderr=""
        )
        runner = HalmosRunner()
        self.assertTrue(runner.is_available())
        self.assertEqual(runner.version, "0.2.1")

    @patch("shutil.which", return_value="/usr/local/bin/halmos")
    @patch("subprocess.run")
    def test_version_parse_edge_case(self, mock_run, mock_which):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr="halmos version 0.3.0-dev"
        )
        runner = HalmosRunner()
        self.assertEqual(runner.version, "0.3.0")

    @patch("shutil.which", return_value="/usr/local/bin/halmos")
    @patch("subprocess.run", side_effect=Exception("binary broken"))
    def test_version_failure_graceful(self, mock_run, mock_which):
        runner = HalmosRunner()
        self.assertTrue(runner.is_available())
        self.assertIsNone(runner.version)


class TestHalmosRunnerExecution(unittest.TestCase):
    """Test run_symbolic_test and check_property."""

    def _make_runner(self, available=True):
        """Create a runner with mocked discovery."""
        with patch("shutil.which", return_value="/usr/bin/halmos" if available else None):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = subprocess.CompletedProcess(
                    args=[], returncode=0, stdout="halmos 0.2.1", stderr=""
                )
                runner = HalmosRunner()
        return runner

    def test_run_not_available(self):
        runner = self._make_runner(available=False)
        result = runner.run_symbolic_test("/tmp/project")
        self.assertFalse(result.success)
        self.assertIn("not installed", result.error_message)

    def test_run_no_foundry_toml(self):
        runner = self._make_runner(available=True)
        with tempfile.TemporaryDirectory() as td:
            result = runner.run_symbolic_test(td)
            self.assertFalse(result.success)
            self.assertIn("foundry.toml", result.error_message)

    @patch("subprocess.run")
    def test_run_success(self, mock_run):
        runner = self._make_runner(available=True)

        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=(
                "Running 2 tests for test/Vault.t.sol:VaultHalmosTest\n"
                "[PASS] check_noInflation(uint256) (time: 1.23s)\n"
                "[FAIL] check_conserved(uint256,uint256) (counterexample: p_a = 0x00, p_b = 0xff)\n"
            ),
            stderr="",
        )

        with tempfile.TemporaryDirectory() as td:
            Path(td, "foundry.toml").touch()
            result = runner.run_symbolic_test(td, test_contract="VaultHalmosTest")

        self.assertTrue(result.success)
        self.assertEqual(len(result.test_results), 2)
        self.assertEqual(result.test_results[0].result, HalmosResult.PASS)
        self.assertEqual(result.test_results[0].function_name, "check_noInflation")
        self.assertAlmostEqual(result.test_results[0].duration_seconds, 1.23)
        self.assertEqual(result.test_results[1].result, HalmosResult.FAIL)
        self.assertIn("0xff", result.test_results[1].counterexample)

    @patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="halmos", timeout=60))
    def test_run_global_timeout(self, mock_run):
        runner = self._make_runner(available=True)
        with tempfile.TemporaryDirectory() as td:
            Path(td, "foundry.toml").touch()
            result = runner.run_symbolic_test(td)
        self.assertFalse(result.success)
        self.assertIn("timeout", result.error_message)

    @patch("subprocess.run", side_effect=OSError("exec failed"))
    def test_run_os_error(self, mock_run):
        runner = self._make_runner(available=True)
        with tempfile.TemporaryDirectory() as td:
            Path(td, "foundry.toml").touch()
            result = runner.run_symbolic_test(td)
        self.assertFalse(result.success)
        self.assertIn("exec failed", result.error_message)


class TestHalmosRunnerOutputParsing(unittest.TestCase):
    """Test _parse_output with various halmos output formats."""

    def _make_runner(self):
        with patch("shutil.which", return_value=None):
            return HalmosRunner()

    def test_empty_output(self):
        runner = self._make_runner()
        results = runner._parse_output("")
        self.assertEqual(results, [])

    def test_pass_lines(self):
        runner = self._make_runner()
        output = "[PASS] check_foo(uint256) (time: 0.50s)\n"
        results = runner._parse_output(output)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].function_name, "check_foo")
        self.assertEqual(results[0].result, HalmosResult.PASS)
        self.assertAlmostEqual(results[0].duration_seconds, 0.50)

    def test_fail_with_counterexample(self):
        runner = self._make_runner()
        output = "[FAIL] check_bar(uint256,address) (counterexample: p_x = 0, p_addr = 0xdead)\n"
        results = runner._parse_output(output)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].result, HalmosResult.FAIL)
        self.assertIn("0xdead", results[0].counterexample)

    def test_error_line(self):
        runner = self._make_runner()
        output = "[ERROR] check_broken() (error: CompilationError)\n"
        results = runner._parse_output(output)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].result, HalmosResult.ERROR)
        self.assertIn("CompilationError", results[0].error_message)

    def test_mixed_output(self):
        runner = self._make_runner()
        output = (
            "Compiling...\n"
            "Running 3 tests for test/X.t.sol:XTest\n"
            "[PASS] check_a(uint256) (time: 0.1s)\n"
            "[PASS] check_b(uint256) (time: 0.2s)\n"
            "[FAIL] check_c(uint256) (counterexample: p_x = 42)\n"
            "Done.\n"
        )
        results = runner._parse_output(output)
        self.assertEqual(len(results), 3)
        passes = [r for r in results if r.result == HalmosResult.PASS]
        fails = [r for r in results if r.result == HalmosResult.FAIL]
        self.assertEqual(len(passes), 2)
        self.assertEqual(len(fails), 1)

    def test_timeout_detection(self):
        runner = self._make_runner()
        output = "WARNING: check_slow(uint256) timed out after 120s\n"
        results = runner._parse_output(output)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].function_name, "check_slow")
        self.assertEqual(results[0].result, HalmosResult.TIMEOUT)

    def test_no_duplicate_timeout(self):
        runner = self._make_runner()
        output = (
            "[PASS] check_ok(uint256) (time: 0.1s)\n"
            "WARNING: check_ok(uint256) timed out after 120s\n"
        )
        results = runner._parse_output(output)
        # check_ok already captured as PASS, timeout should not duplicate
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].result, HalmosResult.PASS)


class TestHalmosRunnerCheckProperty(unittest.TestCase):
    """Test the high-level check_property convenience method."""

    def _make_runner(self):
        with patch("shutil.which", return_value="/usr/bin/halmos"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = subprocess.CompletedProcess(
                    args=[], returncode=0, stdout="halmos 0.2.1", stderr=""
                )
                runner = HalmosRunner()
        return runner

    @patch.object(HalmosRunner, "run_symbolic_test")
    def test_check_property_found(self, mock_run):
        runner = self._make_runner()
        mock_run.return_value = HalmosRunResult(
            test_contract="VaultTest",
            success=True,
            test_results=[
                HalmosTestResult("check_foo", HalmosResult.PASS),
                HalmosTestResult("check_bar", HalmosResult.FAIL, counterexample="x=0"),
            ],
        )
        result = runner.check_property("/tmp/proj", "VaultTest", "check_bar")
        self.assertEqual(result.result, HalmosResult.FAIL)
        self.assertEqual(result.counterexample, "x=0")

    @patch.object(HalmosRunner, "run_symbolic_test")
    def test_check_property_not_found(self, mock_run):
        runner = self._make_runner()
        mock_run.return_value = HalmosRunResult(
            test_contract="VaultTest",
            success=True,
            test_results=[
                HalmosTestResult("check_other", HalmosResult.PASS),
            ],
        )
        result = runner.check_property("/tmp/proj", "VaultTest", "check_missing")
        self.assertEqual(result.result, HalmosResult.SKIP)
        self.assertIn("not found", result.error_message)

    @patch.object(HalmosRunner, "run_symbolic_test")
    def test_check_property_run_failed(self, mock_run):
        runner = self._make_runner()
        mock_run.return_value = HalmosRunResult(
            test_contract="VaultTest",
            success=False,
            error_message="compilation failed",
        )
        result = runner.check_property("/tmp/proj", "VaultTest", "check_foo")
        self.assertEqual(result.result, HalmosResult.ERROR)
        self.assertIn("compilation failed", result.error_message)


class TestHalmosRunnerCustomConfig(unittest.TestCase):
    """Test custom timeout/loop_bound/solver_timeout_ms."""

    @patch("shutil.which", return_value=None)
    def test_custom_values(self, mock_which):
        runner = HalmosRunner(timeout=60, loop_bound=5, solver_timeout_ms=10000)
        self.assertEqual(runner.timeout, 60)
        self.assertEqual(runner.loop_bound, 5)
        self.assertEqual(runner.solver_timeout_ms, 10000)

    @patch("shutil.which", return_value=None)
    def test_default_values(self, mock_which):
        runner = HalmosRunner()
        self.assertEqual(runner.timeout, 120)
        self.assertEqual(runner.loop_bound, 3)
        self.assertEqual(runner.solver_timeout_ms, 30000)


if __name__ == "__main__":
    unittest.main()
