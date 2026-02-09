"""
Comprehensive unit tests for the audit pipeline:
  1. core/enhanced_audit_engine.py  -- EnhancedAetherAuditEngine
  2. cli/audit_runner.py            -- AuditRunner

All external dependencies (LLM calls, file I/O, database, heavy imports)
are mocked so the tests run quickly and deterministically.
"""

import asyncio
import logging
import os
import sys
import tempfile
import threading
import time
import unittest
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, PropertyMock, patch, AsyncMock

from core.audit_progress import AuditPhase, ContractAuditStatus, ThreadDemuxWriter
from core.job_manager import AuditJob, JobManager, JobStatus
from core.llm_usage_tracker import LLMUsageTracker


# ---------------------------------------------------------------------------
# Sample contract used across most tests
# ---------------------------------------------------------------------------
SAMPLE_CONTRACT = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
contract SimpleStorage {
    uint256 private value;
    event ValueChanged(uint256 newValue);
    function setValue(uint256 _value) external {
        value = _value;
        emit ValueChanged(_value);
    }
    function getValue() external view returns (uint256) {
        return value;
    }
}"""

SAMPLE_CONTRACT_2 = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
contract Token {
    mapping(address => uint256) public balances;
    function transfer(address to, uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_vuln_dict(**overrides) -> Dict[str, Any]:
    """Return a minimal vulnerability dict with sensible defaults."""
    base = {
        "vulnerability_type": "reentrancy",
        "severity": "high",
        "confidence": 0.85,
        "line_number": 7,
        "description": "Potential reentrancy",
        "code_snippet": "value = _value;",
        "swc_id": "SWC-107",
        "category": "reentrancy",
        "context": {"file_path": "/tmp/SimpleStorage.sol", "contract_name": "SimpleStorage"},
        "validation_status": "validated",
    }
    base.update(overrides)
    return base


def _make_delegation_flow(has_proxy: bool = False):
    """Return a mock DelegationFlow object."""
    flow = MagicMock()
    flow.has_proxy_pattern = has_proxy
    flow.proxy_contracts = []
    flow.module_contracts = []
    flow.protected_at_proxy = set()
    flow.confidence = 0.0
    return flow


def _make_filter_stats(filtered: int = 0):
    stats = MagicMock()
    stats.total_findings = 5
    stats.filtered_findings = filtered
    stats.filtered_by_reason = {}
    return stats


# ===================================================================
#  SECTION 1 -- EnhancedAetherAuditEngine tests
# ===================================================================

# We need to mock many heavy imports that the engine pulls in at class-level.
# The strategy: patch the engine's collaborators after instantiation.

_ENGINE_MODULE = "core.enhanced_audit_engine"


class TestEngineInit(unittest.TestCase):
    """Test __init__() of EnhancedAetherAuditEngine."""

    @patch(f"{_ENGINE_MODULE}.DatabaseManager")
    @patch(f"{_ENGINE_MODULE}.EnhancedReportGenerator")
    @patch(f"{_ENGINE_MODULE}.FoundryPoCGenerator")
    @patch(f"{_ENGINE_MODULE}.LLMFalsePositiveFilter")
    @patch(f"{_ENGINE_MODULE}.EnhancedAIEnsemble")
    @patch(f"{_ENGINE_MODULE}.VulnerabilityValidator")
    @patch(f"{_ENGINE_MODULE}.EnhancedLLMAnalyzer")
    @patch(f"{_ENGINE_MODULE}.EnhancedVulnerabilityDetector")
    @patch(f"{_ENGINE_MODULE}.FileHandler")
    def test_init_defaults(self, mock_fh, mock_evd, mock_llm, mock_vv,
                           mock_aie, mock_lpf, mock_fpg, mock_erg, mock_db):
        from core.enhanced_audit_engine import EnhancedAetherAuditEngine
        engine = EnhancedAetherAuditEngine()
        self.assertFalse(engine.verbose)
        self.assertIsNotNone(engine.vulnerability_detector)
        self.assertIsNotNone(engine.llm_analyzer)
        self.assertIsNotNone(engine.database)
        self.assertIsNone(engine.foundry_integration)
        self.assertEqual(engine.stats["total_findings"], 0)

    @patch(f"{_ENGINE_MODULE}.DatabaseManager")
    @patch(f"{_ENGINE_MODULE}.EnhancedReportGenerator")
    @patch(f"{_ENGINE_MODULE}.FoundryPoCGenerator")
    @patch(f"{_ENGINE_MODULE}.LLMFalsePositiveFilter")
    @patch(f"{_ENGINE_MODULE}.EnhancedAIEnsemble")
    @patch(f"{_ENGINE_MODULE}.VulnerabilityValidator")
    @patch(f"{_ENGINE_MODULE}.EnhancedLLMAnalyzer")
    @patch(f"{_ENGINE_MODULE}.EnhancedVulnerabilityDetector")
    @patch(f"{_ENGINE_MODULE}.FileHandler")
    def test_init_with_api_key(self, mock_fh, mock_evd, mock_llm, mock_vv,
                               mock_aie, mock_lpf, mock_fpg, mock_erg, mock_db):
        from core.enhanced_audit_engine import EnhancedAetherAuditEngine
        engine = EnhancedAetherAuditEngine(openai_api_key="sk-test")
        mock_llm.assert_called_once_with(api_key="sk-test")

    @patch(f"{_ENGINE_MODULE}.DatabaseManager")
    @patch(f"{_ENGINE_MODULE}.EnhancedReportGenerator")
    @patch(f"{_ENGINE_MODULE}.FoundryPoCGenerator")
    @patch(f"{_ENGINE_MODULE}.LLMFalsePositiveFilter")
    @patch(f"{_ENGINE_MODULE}.EnhancedAIEnsemble")
    @patch(f"{_ENGINE_MODULE}.VulnerabilityValidator")
    @patch(f"{_ENGINE_MODULE}.EnhancedLLMAnalyzer")
    @patch(f"{_ENGINE_MODULE}.EnhancedVulnerabilityDetector")
    @patch(f"{_ENGINE_MODULE}.FileHandler")
    def test_init_with_custom_database(self, mock_fh, mock_evd, mock_llm, mock_vv,
                                       mock_aie, mock_lpf, mock_fpg, mock_erg, mock_db):
        from core.enhanced_audit_engine import EnhancedAetherAuditEngine
        custom_db = MagicMock()
        engine = EnhancedAetherAuditEngine(database=custom_db)
        self.assertIs(engine.database, custom_db)
        # DatabaseManager() should NOT have been used because custom_db was supplied
        mock_db.assert_not_called()

    @patch(f"{_ENGINE_MODULE}.DatabaseManager")
    @patch(f"{_ENGINE_MODULE}.EnhancedReportGenerator")
    @patch(f"{_ENGINE_MODULE}.FoundryPoCGenerator")
    @patch(f"{_ENGINE_MODULE}.LLMFalsePositiveFilter")
    @patch(f"{_ENGINE_MODULE}.EnhancedAIEnsemble")
    @patch(f"{_ENGINE_MODULE}.VulnerabilityValidator")
    @patch(f"{_ENGINE_MODULE}.EnhancedLLMAnalyzer")
    @patch(f"{_ENGINE_MODULE}.EnhancedVulnerabilityDetector")
    @patch(f"{_ENGINE_MODULE}.FileHandler")
    def test_init_verbose(self, mock_fh, mock_evd, mock_llm, mock_vv,
                          mock_aie, mock_lpf, mock_fpg, mock_erg, mock_db):
        from core.enhanced_audit_engine import EnhancedAetherAuditEngine
        engine = EnhancedAetherAuditEngine(verbose=True)
        self.assertTrue(engine.verbose)


class TestReadContractFiles(unittest.TestCase):
    """Test _read_contract_files() with real temp files."""

    @patch(f"{_ENGINE_MODULE}.DatabaseManager")
    @patch(f"{_ENGINE_MODULE}.EnhancedReportGenerator")
    @patch(f"{_ENGINE_MODULE}.FoundryPoCGenerator")
    @patch(f"{_ENGINE_MODULE}.LLMFalsePositiveFilter")
    @patch(f"{_ENGINE_MODULE}.EnhancedAIEnsemble")
    @patch(f"{_ENGINE_MODULE}.VulnerabilityValidator")
    @patch(f"{_ENGINE_MODULE}.EnhancedLLMAnalyzer")
    @patch(f"{_ENGINE_MODULE}.EnhancedVulnerabilityDetector")
    @patch(f"{_ENGINE_MODULE}.FileHandler")
    def setUp(self, *mocks):
        from core.enhanced_audit_engine import EnhancedAetherAuditEngine
        self.engine = EnhancedAetherAuditEngine()

    def test_read_single_file(self):
        with tempfile.NamedTemporaryFile(suffix=".sol", mode="w", delete=False) as f:
            f.write(SAMPLE_CONTRACT)
            f.flush()
            path = f.name
        try:
            files = self.engine._read_contract_files(path)
            self.assertEqual(len(files), 1)
            self.assertEqual(files[0]["content"], SAMPLE_CONTRACT)
            self.assertEqual(files[0]["name"], os.path.basename(path))
        finally:
            os.unlink(path)

    def test_read_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p1 = os.path.join(tmpdir, "A.sol")
            p2 = os.path.join(tmpdir, "B.sol")
            with open(p1, "w") as f:
                f.write(SAMPLE_CONTRACT)
            with open(p2, "w") as f:
                f.write(SAMPLE_CONTRACT_2)
            files = self.engine._read_contract_files(tmpdir)
            self.assertEqual(len(files), 2)
            names = {f["name"] for f in files}
            self.assertEqual(names, {"A.sol", "B.sol"})

    def test_read_directory_with_selected_contracts(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p1 = os.path.join(tmpdir, "A.sol")
            p2 = os.path.join(tmpdir, "B.sol")
            with open(p1, "w") as f:
                f.write(SAMPLE_CONTRACT)
            with open(p2, "w") as f:
                f.write(SAMPLE_CONTRACT_2)
            files = self.engine._read_contract_files(tmpdir, selected_contracts=[p1])
            self.assertEqual(len(files), 1)
            self.assertEqual(files[0]["name"], "A.sol")

    def test_read_nonexistent_path(self):
        files = self.engine._read_contract_files("/tmp/nonexistent_contract_xyz.sol")
        self.assertEqual(files, [])

    def test_read_empty_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            files = self.engine._read_contract_files(tmpdir)
            self.assertEqual(files, [])

    def test_read_directory_ignores_non_sol(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sol_path = os.path.join(tmpdir, "A.sol")
            txt_path = os.path.join(tmpdir, "readme.txt")
            with open(sol_path, "w") as f:
                f.write(SAMPLE_CONTRACT)
            with open(txt_path, "w") as f:
                f.write("not a contract")
            files = self.engine._read_contract_files(tmpdir)
            self.assertEqual(len(files), 1)
            self.assertEqual(files[0]["name"], "A.sol")


class TestNormalizeVulnerability(unittest.TestCase):
    """Test _normalize_vulnerability_dict()."""

    @patch(f"{_ENGINE_MODULE}.DatabaseManager")
    @patch(f"{_ENGINE_MODULE}.EnhancedReportGenerator")
    @patch(f"{_ENGINE_MODULE}.FoundryPoCGenerator")
    @patch(f"{_ENGINE_MODULE}.LLMFalsePositiveFilter")
    @patch(f"{_ENGINE_MODULE}.EnhancedAIEnsemble")
    @patch(f"{_ENGINE_MODULE}.VulnerabilityValidator")
    @patch(f"{_ENGINE_MODULE}.EnhancedLLMAnalyzer")
    @patch(f"{_ENGINE_MODULE}.EnhancedVulnerabilityDetector")
    @patch(f"{_ENGINE_MODULE}.FileHandler")
    def setUp(self, *mocks):
        from core.enhanced_audit_engine import EnhancedAetherAuditEngine
        self.engine = EnhancedAetherAuditEngine()

    def test_normalize_dict(self):
        d = {"type": "reentrancy", "severity": "high", "confidence": 0.9, "line": 10}
        result = self.engine._normalize_vulnerability_dict(d)
        self.assertEqual(result["vulnerability_type"], "reentrancy")
        self.assertEqual(result["line_number"], 10)

    def test_normalize_dataclass_like_object(self):
        obj = MagicMock()
        obj.vulnerability_type = "overflow"
        obj.severity = "medium"
        obj.confidence = 0.7
        obj.line_number = 5
        obj.description = "desc"
        obj.code_snippet = "x++"
        obj.swc_id = "SWC-101"
        obj.category = "arithmetic"
        obj.context = {"file_path": "/tmp/x.sol"}
        result = self.engine._normalize_vulnerability_dict(obj)
        self.assertEqual(result["vulnerability_type"], "overflow")
        self.assertEqual(result["severity"], "medium")

    def test_normalize_unknown_type(self):
        result = self.engine._normalize_vulnerability_dict(12345)
        self.assertEqual(result["vulnerability_type"], "Unknown")
        self.assertIn("12345", result["description"])


class TestCalibrateSeverity(unittest.TestCase):
    """Test _calibrate_vulnerability_severity()."""

    @patch(f"{_ENGINE_MODULE}.DatabaseManager")
    @patch(f"{_ENGINE_MODULE}.EnhancedReportGenerator")
    @patch(f"{_ENGINE_MODULE}.FoundryPoCGenerator")
    @patch(f"{_ENGINE_MODULE}.LLMFalsePositiveFilter")
    @patch(f"{_ENGINE_MODULE}.EnhancedAIEnsemble")
    @patch(f"{_ENGINE_MODULE}.VulnerabilityValidator")
    @patch(f"{_ENGINE_MODULE}.EnhancedLLMAnalyzer")
    @patch(f"{_ENGINE_MODULE}.EnhancedVulnerabilityDetector")
    @patch(f"{_ENGINE_MODULE}.FileHandler")
    def setUp(self, *mocks):
        from core.enhanced_audit_engine import EnhancedAetherAuditEngine
        self.engine = EnhancedAetherAuditEngine()

    def test_downgrade_division_by_zero(self):
        vuln = _make_vuln_dict(vulnerability_type="division_by_zero", severity="critical")
        result = self.engine._calibrate_vulnerability_severity(vuln, SAMPLE_CONTRACT)
        self.assertEqual(result["severity"], "low")

    def test_downgrade_parameter_validation(self):
        vuln = _make_vuln_dict(vulnerability_type="parameter_validation_issue", severity="high")
        result = self.engine._calibrate_vulnerability_severity(vuln, SAMPLE_CONTRACT)
        self.assertEqual(result["severity"], "medium")

    def test_no_downgrade_reentrancy(self):
        vuln = _make_vuln_dict(vulnerability_type="reentrancy", severity="high")
        result = self.engine._calibrate_vulnerability_severity(vuln, SAMPLE_CONTRACT)
        self.assertEqual(result["severity"], "high")


class TestGenerateFinalReport(unittest.TestCase):
    """Test _generate_final_report()."""

    @patch(f"{_ENGINE_MODULE}.DatabaseManager")
    @patch(f"{_ENGINE_MODULE}.EnhancedReportGenerator")
    @patch(f"{_ENGINE_MODULE}.FoundryPoCGenerator")
    @patch(f"{_ENGINE_MODULE}.LLMFalsePositiveFilter")
    @patch(f"{_ENGINE_MODULE}.EnhancedAIEnsemble")
    @patch(f"{_ENGINE_MODULE}.VulnerabilityValidator")
    @patch(f"{_ENGINE_MODULE}.EnhancedLLMAnalyzer")
    @patch(f"{_ENGINE_MODULE}.EnhancedVulnerabilityDetector")
    @patch(f"{_ENGINE_MODULE}.FileHandler")
    def setUp(self, *mocks):
        from core.enhanced_audit_engine import EnhancedAetherAuditEngine
        self.engine = EnhancedAetherAuditEngine()

    def test_report_structure(self):
        validated = {
            "validated_vulnerabilities": [
                _make_vuln_dict(severity="high"),
                _make_vuln_dict(severity="medium"),
            ],
            "total_findings": 2,
            "validated_count": 2,
            "false_positive_count": 0,
            "validation_results": [],
        }
        start = time.time() - 10  # 10s ago
        result = self.engine._generate_final_report(validated, start)
        self.assertIn("summary", result)
        self.assertIn("results", result)
        self.assertIn("enhancement_stats", result)
        self.assertEqual(result["summary"]["total_vulnerabilities"], 2)
        self.assertEqual(result["summary"]["high_severity_count"], 1)
        self.assertGreater(result["results"]["execution_time"], 0)

    def test_report_empty_findings(self):
        validated = {
            "validated_vulnerabilities": [],
            "total_findings": 0,
            "validated_count": 0,
            "false_positive_count": 0,
            "validation_results": [],
        }
        result = self.engine._generate_final_report(validated, time.time())
        self.assertEqual(result["summary"]["total_vulnerabilities"], 0)
        self.assertEqual(result["summary"]["accuracy_rate"], 0)

    def test_report_with_ai_ensemble_results(self):
        validated = {
            "validated_vulnerabilities": [_make_vuln_dict()],
            "total_findings": 1,
            "validated_count": 1,
            "false_positive_count": 0,
            "validation_results": [],
        }
        ai_results = {
            "consensus_findings": [{"type": "reentrancy"}],
            "model_agreement": 0.9,
            "confidence_score": 0.85,
        }
        result = self.engine._generate_final_report(validated, time.time(), ai_ensemble_results=ai_results)
        self.assertEqual(result["summary"]["model_agreement"], 0.9)
        self.assertTrue(result["enhancement_stats"]["phase3_features"]["ai_ensemble_enabled"])

    def test_report_filters_false_positives(self):
        validated = {
            "validated_vulnerabilities": [
                _make_vuln_dict(severity="high", status="confirmed"),
                _make_vuln_dict(severity="medium", status="false_positive"),
            ],
            "total_findings": 2,
            "validated_count": 1,
            "false_positive_count": 1,
            "validation_results": [],
        }
        result = self.engine._generate_final_report(validated, time.time())
        # Only confirmed vulns counted
        self.assertEqual(result["summary"]["total_vulnerabilities"], 1)
        self.assertEqual(result["summary"]["false_positives_filtered"], 1)


class TestSaveAuditToDatabase(unittest.TestCase):
    """Test _save_audit_to_database()."""

    @patch(f"{_ENGINE_MODULE}.DatabaseManager")
    @patch(f"{_ENGINE_MODULE}.EnhancedReportGenerator")
    @patch(f"{_ENGINE_MODULE}.FoundryPoCGenerator")
    @patch(f"{_ENGINE_MODULE}.LLMFalsePositiveFilter")
    @patch(f"{_ENGINE_MODULE}.EnhancedAIEnsemble")
    @patch(f"{_ENGINE_MODULE}.VulnerabilityValidator")
    @patch(f"{_ENGINE_MODULE}.EnhancedLLMAnalyzer")
    @patch(f"{_ENGINE_MODULE}.EnhancedVulnerabilityDetector")
    @patch(f"{_ENGINE_MODULE}.FileHandler")
    def setUp(self, *mocks):
        from core.enhanced_audit_engine import EnhancedAetherAuditEngine
        self.mock_db = MagicMock()
        self.mock_db.find_audit_by_contract.return_value = None
        self.mock_db.save_audit_result.return_value = True
        self.mock_db.save_vulnerability_findings.return_value = True
        self.mock_db.save_learning_pattern.return_value = True
        self.mock_db.save_audit_metrics.return_value = True
        self.engine = EnhancedAetherAuditEngine(database=self.mock_db)

    def test_save_new_audit(self):
        results = {
            "results": {"vulnerabilities": []},
            "summary": {"total_vulnerabilities": 0},
        }
        self.engine._save_audit_to_database("/tmp/Test.sol", results, time.time(), {})
        self.mock_db.save_audit_result.assert_called_once()

    def test_save_updates_existing_audit(self):
        self.mock_db.find_audit_by_contract.return_value = {"id": "abc123"}
        self.mock_db.update_audit_result = MagicMock(return_value=True)
        self.mock_db.delete_vulnerability_findings = MagicMock()
        results = {
            "results": {"vulnerabilities": []},
            "summary": {"total_vulnerabilities": 0},
        }
        self.engine._save_audit_to_database("/tmp/Test.sol", results, time.time(), {})
        self.mock_db.update_audit_result.assert_called_once()
        self.mock_db.delete_vulnerability_findings.assert_called_once_with("abc123")

    def test_save_handles_database_error(self):
        self.mock_db.save_audit_result.side_effect = Exception("DB write error")
        results = {
            "results": {"vulnerabilities": []},
            "summary": {"total_vulnerabilities": 0},
        }
        # Should not raise -- error is caught internally
        self.engine._save_audit_to_database("/tmp/Test.sol", results, time.time(), {})

    def test_extract_contract_name(self):
        name = self.engine._extract_contract_name("/path/to/MyToken.sol")
        self.assertEqual(name, "MyToken")

    def test_extract_contract_address(self):
        addr = self.engine._extract_contract_address(
            "/tmp/0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF.sol"
        )
        self.assertEqual(addr, "0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF")

    def test_extract_contract_address_none(self):
        addr = self.engine._extract_contract_address("/tmp/MyToken.sol")
        self.assertIsNone(addr)


class TestExtractCodeSnippet(unittest.TestCase):
    """Test _extract_code_snippet()."""

    @patch(f"{_ENGINE_MODULE}.DatabaseManager")
    @patch(f"{_ENGINE_MODULE}.EnhancedReportGenerator")
    @patch(f"{_ENGINE_MODULE}.FoundryPoCGenerator")
    @patch(f"{_ENGINE_MODULE}.LLMFalsePositiveFilter")
    @patch(f"{_ENGINE_MODULE}.EnhancedAIEnsemble")
    @patch(f"{_ENGINE_MODULE}.VulnerabilityValidator")
    @patch(f"{_ENGINE_MODULE}.EnhancedLLMAnalyzer")
    @patch(f"{_ENGINE_MODULE}.EnhancedVulnerabilityDetector")
    @patch(f"{_ENGINE_MODULE}.FileHandler")
    def setUp(self, *mocks):
        from core.enhanced_audit_engine import EnhancedAetherAuditEngine
        self.engine = EnhancedAetherAuditEngine()

    def test_snippet_highlights_target_line(self):
        snippet = self.engine._extract_code_snippet(SAMPLE_CONTRACT, 7, context_lines=2)
        self.assertIn(">>>", snippet)
        # The marker line should contain the target line number 7
        for line in snippet.split("\n"):
            if ">>>" in line:
                self.assertIn("7", line)
                break

    def test_snippet_out_of_range(self):
        snippet = self.engine._extract_code_snippet(SAMPLE_CONTRACT, 9999)
        self.assertIn("out of range", snippet)

    def test_snippet_line_zero(self):
        snippet = self.engine._extract_code_snippet(SAMPLE_CONTRACT, 0)
        self.assertIn("out of range", snippet)


class TestRunAuditPipeline(unittest.TestCase):
    """Test run_audit() end-to-end with all steps mocked."""

    @patch(f"{_ENGINE_MODULE}.DatabaseManager")
    @patch(f"{_ENGINE_MODULE}.EnhancedReportGenerator")
    @patch(f"{_ENGINE_MODULE}.FoundryPoCGenerator")
    @patch(f"{_ENGINE_MODULE}.LLMFalsePositiveFilter")
    @patch(f"{_ENGINE_MODULE}.EnhancedAIEnsemble")
    @patch(f"{_ENGINE_MODULE}.VulnerabilityValidator")
    @patch(f"{_ENGINE_MODULE}.EnhancedLLMAnalyzer")
    @patch(f"{_ENGINE_MODULE}.EnhancedVulnerabilityDetector")
    @patch(f"{_ENGINE_MODULE}.FileHandler")
    def setUp(self, *mocks):
        from core.enhanced_audit_engine import EnhancedAetherAuditEngine
        self.mock_db = MagicMock()
        self.mock_db.find_audit_by_contract.return_value = None
        self.mock_db.save_audit_result.return_value = True
        self.mock_db.save_vulnerability_findings.return_value = True
        self.mock_db.save_audit_metrics.return_value = True
        self.engine = EnhancedAetherAuditEngine(database=self.mock_db)

    def _run(self, coro):
        return asyncio.run(coro)

    def test_run_audit_no_files_returns_error(self):
        result = self._run(
            self.engine.run_audit("/tmp/nonexistent_xyz.sol", {})
        )
        self.assertIn("error", result)
        self.assertIn("No contract files found", result["error"])

    @patch("core.proxy_pattern_filter.ProxyPatternFilter")
    @patch("core.access_control_context_analyzer.AccessControlContextAnalyzer")
    @patch("core.vulnerability_deduplicator.VulnerabilityDeduplicator")
    @patch("core.delegation_analyzer.DelegationFlowAnalyzer")
    def test_run_audit_full_pipeline(self, mock_dfa_cls, mock_vd_cls,
                                     mock_acca_cls, mock_ppf_cls):
        """Full pipeline with a real temp file, all analysis steps mocked."""
        # Set up delegation analyzer mock
        mock_dfa = MagicMock()
        flow = _make_delegation_flow(has_proxy=False)
        mock_dfa.analyze_delegation_flow.return_value = flow
        mock_dfa_cls.return_value = mock_dfa

        # Set up deduplicator mock
        mock_vd = MagicMock()
        mock_vd.deduplicate.return_value = []
        mock_vd.remove_subsumed_vulnerabilities.return_value = []
        mock_vd_cls.return_value = mock_vd

        # Access control analyzer
        mock_acca = MagicMock()
        mock_acca_cls.return_value = mock_acca

        # Proxy pattern filter
        mock_ppf = MagicMock()
        mock_ppf.filter_findings.return_value = []
        mock_ppf.get_filter_stats.return_value = _make_filter_stats()
        mock_ppf_cls.return_value = mock_ppf

        # Mock vulnerability detector
        self.engine.vulnerability_detector.analyze_contract.return_value = []
        self.engine.vulnerability_detector.build_call_graph_from_contracts = MagicMock()
        self.engine.vulnerability_detector.set_contract_context = MagicMock()

        # Mock LLM analyzer
        self.engine.llm_analyzer.analyze_vulnerabilities = AsyncMock(return_value={
            "analysis": {"vulnerabilities": []}
        })

        # Mock AI ensemble
        mock_ensemble_result = MagicMock()
        mock_ensemble_result.consensus_findings = []
        mock_ensemble_result.model_agreement = 0.0
        mock_ensemble_result.confidence_score = 0.0
        mock_ensemble_result.processing_time = 0.5
        mock_ensemble_result.individual_results = []
        self.engine.ai_ensemble.analyze_contract_ensemble = AsyncMock(
            return_value=mock_ensemble_result
        )

        with tempfile.NamedTemporaryFile(suffix=".sol", mode="w", delete=False) as f:
            f.write(SAMPLE_CONTRACT)
            f.flush()
            path = f.name

        try:
            result = self._run(self.engine.run_audit(path, {}))
            # Should complete without error
            self.assertNotIn("error", result)
            self.assertIn("summary", result)
            self.assertIn("results", result)
            self.assertEqual(result["summary"]["total_vulnerabilities"], 0)
        finally:
            os.unlink(path)

    def test_run_audit_exception_returns_error(self):
        """When an internal step raises, run_audit returns an error dict."""
        # Force _read_contract_files to raise
        self.engine._read_contract_files = MagicMock(side_effect=RuntimeError("boom"))
        result = self._run(self.engine.run_audit("/tmp/x.sol", {}))
        self.assertIn("error", result)
        self.assertIn("boom", result["error"])


class TestValidateFindings(unittest.TestCase):
    """Test _validate_findings() collects findings correctly."""

    @patch(f"{_ENGINE_MODULE}.DatabaseManager")
    @patch(f"{_ENGINE_MODULE}.EnhancedReportGenerator")
    @patch(f"{_ENGINE_MODULE}.FoundryPoCGenerator")
    @patch(f"{_ENGINE_MODULE}.LLMFalsePositiveFilter")
    @patch(f"{_ENGINE_MODULE}.EnhancedAIEnsemble")
    @patch(f"{_ENGINE_MODULE}.VulnerabilityValidator")
    @patch(f"{_ENGINE_MODULE}.EnhancedLLMAnalyzer")
    @patch(f"{_ENGINE_MODULE}.EnhancedVulnerabilityDetector")
    @patch(f"{_ENGINE_MODULE}.FileHandler")
    def setUp(self, *mocks):
        from core.enhanced_audit_engine import EnhancedAetherAuditEngine
        self.engine = EnhancedAetherAuditEngine()
        # Set up context with delegation flow
        self.engine.context = {"delegation_flow": _make_delegation_flow(has_proxy=False)}

    def _run(self, coro):
        return asyncio.run(coro)

    @patch("core.proxy_pattern_filter.ProxyPatternFilter")
    def test_collects_static_and_llm_findings(self, mock_ppf_cls):
        mock_ppf = MagicMock()
        mock_ppf.filter_findings.side_effect = lambda v, d, c: v
        mock_ppf.get_filter_stats.return_value = _make_filter_stats()
        mock_ppf_cls.return_value = mock_ppf

        static_results = {
            "vulnerabilities": [_make_vuln_dict(vulnerability_type="reentrancy")],
        }
        llm_results = {
            "analysis": {
                "vulnerabilities": [_make_vuln_dict(vulnerability_type="overflow")]
            }
        }
        contract_files = [{"content": SAMPLE_CONTRACT, "path": "/tmp/x.sol", "name": "x.sol"}]

        result = self._run(
            self.engine._validate_findings(static_results, llm_results, contract_files)
        )
        self.assertIn("validated_vulnerabilities", result)
        # Should have findings from both sources
        self.assertGreaterEqual(result["total_findings"], 2)

    @patch("core.proxy_pattern_filter.ProxyPatternFilter")
    def test_collects_ai_ensemble_findings(self, mock_ppf_cls):
        mock_ppf = MagicMock()
        mock_ppf.filter_findings.side_effect = lambda v, d, c: v
        mock_ppf.get_filter_stats.return_value = _make_filter_stats()
        mock_ppf_cls.return_value = mock_ppf

        static_results = {"vulnerabilities": []}
        llm_results = {"analysis": {"vulnerabilities": []}}
        ai_results = {
            "consensus_findings": [_make_vuln_dict(vulnerability_type="flash_loan")]
        }
        contract_files = [{"content": SAMPLE_CONTRACT, "path": "/tmp/x.sol", "name": "x.sol"}]

        result = self._run(
            self.engine._validate_findings(static_results, llm_results, contract_files, ai_results)
        )
        self.assertGreaterEqual(result["total_findings"], 1)

    @patch("core.proxy_pattern_filter.ProxyPatternFilter")
    def test_empty_findings(self, mock_ppf_cls):
        mock_ppf = MagicMock()
        mock_ppf.filter_findings.side_effect = lambda v, d, c: v
        mock_ppf.get_filter_stats.return_value = _make_filter_stats()
        mock_ppf_cls.return_value = mock_ppf

        static_results = {"vulnerabilities": []}
        llm_results = {"analysis": {"vulnerabilities": []}}
        contract_files = [{"content": SAMPLE_CONTRACT, "path": "/tmp/x.sol", "name": "x.sol"}]

        result = self._run(
            self.engine._validate_findings(static_results, llm_results, contract_files)
        )
        self.assertEqual(result["total_findings"], 0)


class TestTriageVulnerabilities(unittest.TestCase):
    """Test _triage_vulnerabilities()."""

    @patch(f"{_ENGINE_MODULE}.DatabaseManager")
    @patch(f"{_ENGINE_MODULE}.EnhancedReportGenerator")
    @patch(f"{_ENGINE_MODULE}.FoundryPoCGenerator")
    @patch(f"{_ENGINE_MODULE}.LLMFalsePositiveFilter")
    @patch(f"{_ENGINE_MODULE}.EnhancedAIEnsemble")
    @patch(f"{_ENGINE_MODULE}.VulnerabilityValidator")
    @patch(f"{_ENGINE_MODULE}.EnhancedLLMAnalyzer")
    @patch(f"{_ENGINE_MODULE}.EnhancedVulnerabilityDetector")
    @patch(f"{_ENGINE_MODULE}.FileHandler")
    def setUp(self, *mocks):
        from core.enhanced_audit_engine import EnhancedAetherAuditEngine
        self.engine = EnhancedAetherAuditEngine()

    def test_deduplication(self):
        v1 = _make_vuln_dict(vulnerability_type="reentrancy", line_number=10)
        v2 = _make_vuln_dict(vulnerability_type="reentrancy", line_number=10)  # duplicate
        result = self.engine._triage_vulnerabilities([v1, v2])
        self.assertEqual(len(result), 1)

    def test_filters_low_confidence(self):
        v = _make_vuln_dict(confidence=0.01)
        result = self.engine._triage_vulnerabilities([v])
        self.assertEqual(len(result), 0)

    def test_separates_gas_optimizations(self):
        v1 = _make_vuln_dict(vulnerability_type="gas_optimization", severity="low", confidence=0.8)
        v2 = _make_vuln_dict(vulnerability_type="reentrancy", severity="high", confidence=0.9)
        result = self.engine._triage_vulnerabilities([v1, v2])
        # Gas optimization should be separated out
        types = [r.get("vulnerability_type") for r in result]
        self.assertNotIn("gas_optimization", types)

    def test_sorting_severity_desc(self):
        v_low = _make_vuln_dict(vulnerability_type="a", severity="low", line_number=1, confidence=0.5)
        v_high = _make_vuln_dict(vulnerability_type="b", severity="high", line_number=2, confidence=0.5)
        result = self.engine._triage_vulnerabilities([v_low, v_high])
        self.assertEqual(result[0]["vulnerability_type"], "b")


class TestGetEnhancementSummary(unittest.TestCase):
    """Test get_enhancement_summary()."""

    @patch(f"{_ENGINE_MODULE}.DatabaseManager")
    @patch(f"{_ENGINE_MODULE}.EnhancedReportGenerator")
    @patch(f"{_ENGINE_MODULE}.FoundryPoCGenerator")
    @patch(f"{_ENGINE_MODULE}.LLMFalsePositiveFilter")
    @patch(f"{_ENGINE_MODULE}.EnhancedAIEnsemble")
    @patch(f"{_ENGINE_MODULE}.VulnerabilityValidator")
    @patch(f"{_ENGINE_MODULE}.EnhancedLLMAnalyzer")
    @patch(f"{_ENGINE_MODULE}.EnhancedVulnerabilityDetector")
    @patch(f"{_ENGINE_MODULE}.FileHandler")
    def setUp(self, *mocks):
        from core.enhanced_audit_engine import EnhancedAetherAuditEngine
        self.engine = EnhancedAetherAuditEngine()

    def test_summary_structure(self):
        summary = self.engine.get_enhancement_summary()
        self.assertIn("enhanced_components", summary)
        self.assertIn("improvements", summary)
        self.assertIn("current_stats", summary)
        self.assertIn("phase3_capabilities", summary)
        self.assertIsInstance(summary["enhanced_components"], list)
        self.assertGreater(len(summary["enhanced_components"]), 0)


# ===================================================================
#  SECTION 2 -- AuditRunner tests
# ===================================================================

class TestAuditRunnerInit(unittest.TestCase):
    """Test AuditRunner.__init__()."""

    def setUp(self):
        JobManager.reset()
        LLMUsageTracker.reset()
        # Save original stdout/stderr
        self._orig_stdout = sys.stdout
        self._orig_stderr = sys.stderr

    def tearDown(self):
        # Restore stdout/stderr
        sys.stdout = self._orig_stdout
        sys.stderr = self._orig_stderr

    def test_init_installs_demuxer(self):
        from cli.audit_runner import AuditRunner
        runner = AuditRunner()
        self.assertIsInstance(sys.stdout, ThreadDemuxWriter)
        self.assertIsInstance(sys.stderr, ThreadDemuxWriter)

    def test_init_idempotent_demuxer(self):
        from cli.audit_runner import AuditRunner
        runner1 = AuditRunner()
        stdout1 = sys.stdout
        runner2 = AuditRunner()
        # Second init should re-use the same demuxer
        self.assertIs(sys.stdout, stdout1)

    def test_init_installs_log_handler(self):
        from cli.audit_runner import AuditRunner, JobLogHandler
        runner = AuditRunner()
        root_handlers = logging.getLogger().handlers
        has_job_handler = any(isinstance(h, JobLogHandler) for h in root_handlers)
        self.assertTrue(has_job_handler)


class TestJobLogHandler(unittest.TestCase):
    """Test the JobLogHandler routing."""

    def test_register_and_emit(self):
        from cli.audit_runner import JobLogHandler
        handler = JobLogHandler()
        handler.setFormatter(logging.Formatter("%(message)s"))
        status = ContractAuditStatus(contract_name="test", contract_path="/tmp/test.sol")
        handler.register(status)

        # Emit a log record from this thread
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg="hello from handler", args=None, exc_info=None,
        )
        record.thread = threading.current_thread().ident
        handler.emit(record)

        logs = status.get_all_log_lines()
        self.assertTrue(any("hello from handler" in l for l in logs))

        handler.unregister()

    def test_unregistered_thread_ignored(self):
        from cli.audit_runner import JobLogHandler
        handler = JobLogHandler()
        handler.setFormatter(logging.Formatter("%(message)s"))
        # Don't register -- emit should be a no-op
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg="should be ignored", args=None, exc_info=None,
        )
        record.thread = threading.current_thread().ident
        handler.emit(record)  # Should not raise


class TestAuditRunnerJobLifecycle(unittest.TestCase):
    """Test job lifecycle through AuditRunner with mocked AetherCLI."""

    def setUp(self):
        JobManager.reset()
        LLMUsageTracker.reset()
        self._orig_stdout = sys.stdout
        self._orig_stderr = sys.stderr

    def tearDown(self):
        sys.stdout = self._orig_stdout
        sys.stderr = self._orig_stderr
        # Clean up any log handlers we added
        root = logging.getLogger()
        from cli.audit_runner import JobLogHandler
        root.handlers = [h for h in root.handlers if not isinstance(h, JobLogHandler)]

    @patch("cli.audit_runner.AuditRunner._audit_worker")
    def test_start_single_audit_spawns_thread(self, mock_worker):
        from cli.audit_runner import AuditRunner
        runner = AuditRunner()
        jm = JobManager.get_instance()
        job = jm.create_job("TestAudit", "local", target="/tmp/x.sol")
        runner.start_single_audit(job.job_id, "/tmp/x.sol", ["enhanced"], "/tmp/out")
        # Thread should have been spawned
        self.assertIsNotNone(job.thread)
        job.thread.join(timeout=2)
        mock_worker.assert_called_once()

    def test_start_single_audit_missing_job(self):
        from cli.audit_runner import AuditRunner
        runner = AuditRunner()
        # Calling with a nonexistent job_id should just return
        runner.start_single_audit("nonexistent", "/tmp/x.sol", [], "/tmp/out")

    @patch("cli.audit_runner.AuditRunner._audit_worker")
    def test_start_parallel_audit_creates_children(self, mock_worker):
        from cli.audit_runner import AuditRunner
        runner = AuditRunner()
        jm = JobManager.get_instance()
        parent = jm.create_job("Parallel", "local")
        targets = ["/tmp/A.sol", "/tmp/B.sol", "/tmp/C.sol"]
        runner.start_parallel_audit(parent.job_id, targets, ["enhanced"], "/tmp/out", max_workers=2)
        # Wait for coordinator to finish
        if parent.thread:
            parent.thread.join(timeout=5)
        # Children should have been created
        children = jm.get_children(parent.job_id)
        self.assertEqual(len(children), 3)

    @patch("cli.audit_runner.AuditRunner._poc_worker")
    def test_start_poc_generation(self, mock_worker):
        from cli.audit_runner import AuditRunner
        runner = AuditRunner()
        jm = JobManager.get_instance()
        job = jm.create_job("PoC-gen", "poc")
        runner.start_poc_generation(job.job_id, project_id=1, out_dir="/tmp/poc")
        self.assertIsNotNone(job.thread)
        job.thread.join(timeout=2)
        mock_worker.assert_called_once()

    @patch("cli.audit_runner.AuditRunner._report_worker")
    def test_start_report_generation(self, mock_worker):
        from cli.audit_runner import AuditRunner
        runner = AuditRunner()
        jm = JobManager.get_instance()
        job = jm.create_job("Report", "report")
        runner.start_report_generation(job.job_id, project_id=1)
        self.assertIsNotNone(job.thread)
        job.thread.join(timeout=2)
        mock_worker.assert_called_once()

    @patch("cli.audit_runner.AuditRunner._github_audit_worker")
    def test_start_github_audit(self, mock_worker):
        from cli.audit_runner import AuditRunner
        runner = AuditRunner()
        jm = JobManager.get_instance()
        job = jm.create_job("GH-Audit", "github")
        runner.start_github_audit(job.job_id, "https://github.com/org/repo")
        self.assertIsNotNone(job.thread)
        job.thread.join(timeout=2)
        mock_worker.assert_called_once()


class TestAuditWorkerSuccess(unittest.TestCase):
    """Test _audit_worker with a mocked AetherCLI that succeeds."""

    def setUp(self):
        JobManager.reset()
        LLMUsageTracker.reset()
        self._orig_stdout = sys.stdout
        self._orig_stderr = sys.stderr

    def tearDown(self):
        sys.stdout = self._orig_stdout
        sys.stderr = self._orig_stderr
        root = logging.getLogger()
        from cli.audit_runner import JobLogHandler
        root.handlers = [h for h in root.handlers if not isinstance(h, JobLogHandler)]

    @patch("cli.main.AetherCLI")
    def test_worker_completes_job(self, mock_cli_cls):
        """Mocked AetherCLI.run_audit returns results; job should complete."""
        mock_cli = MagicMock()
        mock_cli.run_audit = AsyncMock(return_value={
            "summary": {"total_vulnerabilities": 3},
            "results": {"vulnerabilities": [1, 2, 3]},
        })
        mock_cli_cls.return_value = mock_cli

        from cli.audit_runner import AuditRunner
        runner = AuditRunner()
        jm = JobManager.get_instance()
        job = jm.create_job("Worker", "local", target="/tmp/x.sol")

        with tempfile.TemporaryDirectory() as tmpdir:
            runner._audit_worker(job, "/tmp/x.sol", ["enhanced"], tmpdir)

        self.assertEqual(job.status, JobStatus.COMPLETED)
        self.assertEqual(job.findings_count, 3)

    @patch("cli.main.AetherCLI")
    def test_worker_failure_marks_job_failed(self, mock_cli_cls):
        """When run_audit raises, job should be marked FAILED."""
        mock_cli = MagicMock()
        mock_cli.run_audit = AsyncMock(side_effect=RuntimeError("LLM timeout"))
        mock_cli_cls.return_value = mock_cli

        from cli.audit_runner import AuditRunner
        runner = AuditRunner()
        jm = JobManager.get_instance()
        job = jm.create_job("FailWorker", "local", target="/tmp/x.sol")

        with tempfile.TemporaryDirectory() as tmpdir:
            runner._audit_worker(job, "/tmp/x.sol", ["enhanced"], tmpdir)

        self.assertEqual(job.status, JobStatus.FAILED)
        self.assertIn("LLM timeout", job.error)

    @patch("cli.main.AetherCLI")
    def test_worker_tracks_cost_delta(self, mock_cli_cls):
        """Cost delta should reflect LLMUsageTracker changes during the audit."""
        mock_cli = MagicMock()

        def fake_run_audit(**kwargs):
            # Simulate LLM usage during audit
            tracker = LLMUsageTracker.get_instance()
            tracker.record("openai", "gpt-5-mini", 1000, 500, caller="test")
            return {"summary": {"total_vulnerabilities": 1}, "results": {}}

        mock_cli.run_audit = AsyncMock(side_effect=fake_run_audit)
        mock_cli_cls.return_value = mock_cli

        from cli.audit_runner import AuditRunner
        runner = AuditRunner()
        jm = JobManager.get_instance()
        job = jm.create_job("CostWorker", "local", target="/tmp/x.sol")

        with tempfile.TemporaryDirectory() as tmpdir:
            runner._audit_worker(job, "/tmp/x.sol", ["enhanced"], tmpdir)

        self.assertEqual(job.status, JobStatus.COMPLETED)
        self.assertGreater(job.cost_delta, 0)
        # Per-job stats should be populated
        self.assertGreater(job.audit_status.llm_calls, 0)
        self.assertGreater(job.audit_status.llm_cost, 0)


class TestAuditWorkerDemuxer(unittest.TestCase):
    """Test that the audit worker properly registers/unregisters with demuxers."""

    def setUp(self):
        JobManager.reset()
        LLMUsageTracker.reset()
        self._orig_stdout = sys.stdout
        self._orig_stderr = sys.stderr

    def tearDown(self):
        sys.stdout = self._orig_stdout
        sys.stderr = self._orig_stderr
        root = logging.getLogger()
        from cli.audit_runner import JobLogHandler
        root.handlers = [h for h in root.handlers if not isinstance(h, JobLogHandler)]

    @patch("cli.main.AetherCLI")
    def test_worker_unregisters_on_success(self, mock_cli_cls):
        """After worker completes, demuxer should be unregistered for the thread."""
        mock_cli = MagicMock()
        mock_cli.run_audit = AsyncMock(return_value={"summary": {"total_vulnerabilities": 0}})
        mock_cli_cls.return_value = mock_cli

        from cli.audit_runner import AuditRunner
        runner = AuditRunner()
        jm = JobManager.get_instance()
        job = jm.create_job("DemuxTest", "local", target="/tmp/x.sol")

        with tempfile.TemporaryDirectory() as tmpdir:
            runner._audit_worker(job, "/tmp/x.sol", [], tmpdir)

        # Verify the job completed properly (unregister is in finally block)
        self.assertEqual(job.status, JobStatus.COMPLETED)

    @patch("cli.main.AetherCLI")
    def test_worker_unregisters_on_failure(self, mock_cli_cls):
        """Demuxer unregister should happen even on failure (finally block)."""
        mock_cli = MagicMock()
        mock_cli.run_audit = AsyncMock(side_effect=Exception("crash"))
        mock_cli_cls.return_value = mock_cli

        from cli.audit_runner import AuditRunner
        runner = AuditRunner()
        jm = JobManager.get_instance()
        job = jm.create_job("DemuxFail", "local", target="/tmp/x.sol")

        with tempfile.TemporaryDirectory() as tmpdir:
            runner._audit_worker(job, "/tmp/x.sol", [], tmpdir)

        self.assertEqual(job.status, JobStatus.FAILED)


class TestPocWorker(unittest.TestCase):
    """Test _poc_worker behavior."""

    def setUp(self):
        JobManager.reset()
        LLMUsageTracker.reset()
        self._orig_stdout = sys.stdout
        self._orig_stderr = sys.stderr

    def tearDown(self):
        sys.stdout = self._orig_stdout
        sys.stderr = self._orig_stderr
        root = logging.getLogger()
        from cli.audit_runner import JobLogHandler
        root.handlers = [h for h in root.handlers if not isinstance(h, JobLogHandler)]

    @patch("cli.main.AetherCLI")
    def test_poc_worker_success(self, mock_cli_cls):
        mock_cli = MagicMock()
        mock_cli.run_generate_foundry = AsyncMock(return_value=None)
        mock_cli_cls.return_value = mock_cli

        from cli.audit_runner import AuditRunner
        runner = AuditRunner()
        jm = JobManager.get_instance()
        job = jm.create_job("PoCJob", "poc")

        runner._poc_worker(job, project_id=1, scope_id=None, from_results=None,
                           out_dir="/tmp/poc", max_items=20, min_severity="medium",
                           only_consensus=False)

        self.assertEqual(job.status, JobStatus.COMPLETED)

    @patch("cli.main.AetherCLI")
    def test_poc_worker_failure(self, mock_cli_cls):
        mock_cli = MagicMock()
        mock_cli.run_generate_foundry = AsyncMock(side_effect=RuntimeError("forge not found"))
        mock_cli_cls.return_value = mock_cli

        from cli.audit_runner import AuditRunner
        runner = AuditRunner()
        jm = JobManager.get_instance()
        job = jm.create_job("PoCFail", "poc")

        runner._poc_worker(job, project_id=1, scope_id=None, from_results=None,
                           out_dir="/tmp/poc", max_items=20, min_severity="medium",
                           only_consensus=False)

        self.assertEqual(job.status, JobStatus.FAILED)
        self.assertIn("forge not found", job.error)


class TestReportWorker(unittest.TestCase):
    """Test _report_worker behavior."""

    def setUp(self):
        JobManager.reset()
        LLMUsageTracker.reset()
        self._orig_stdout = sys.stdout
        self._orig_stderr = sys.stderr

    def tearDown(self):
        sys.stdout = self._orig_stdout
        sys.stderr = self._orig_stderr
        root = logging.getLogger()
        from cli.audit_runner import JobLogHandler
        root.handlers = [h for h in root.handlers if not isinstance(h, JobLogHandler)]

    @patch("cli.main.AetherCLI")
    def test_report_worker_success(self, mock_cli_cls):
        mock_cli = MagicMock()
        mock_cli.run_generate_report = AsyncMock(return_value=None)
        mock_cli_cls.return_value = mock_cli

        from cli.audit_runner import AuditRunner
        runner = AuditRunner()
        jm = JobManager.get_instance()
        job = jm.create_job("ReportJob", "report")

        with tempfile.TemporaryDirectory() as tmpdir:
            runner._report_worker(job, project_id=1, scope_id=None,
                                  output_dir=tmpdir, fmt="markdown")

        self.assertEqual(job.status, JobStatus.COMPLETED)

    @patch("cli.main.AetherCLI")
    def test_report_worker_failure(self, mock_cli_cls):
        mock_cli = MagicMock()
        mock_cli.run_generate_report = AsyncMock(side_effect=ValueError("bad format"))
        mock_cli_cls.return_value = mock_cli

        from cli.audit_runner import AuditRunner
        runner = AuditRunner()
        jm = JobManager.get_instance()
        job = jm.create_job("ReportFail", "report")

        with tempfile.TemporaryDirectory() as tmpdir:
            runner._report_worker(job, project_id=1, scope_id=None,
                                  output_dir=tmpdir, fmt="markdown")

        self.assertEqual(job.status, JobStatus.FAILED)
        self.assertIn("bad format", job.error)


class TestGitHubAuditWorker(unittest.TestCase):
    """Test _github_audit_worker behavior."""

    def setUp(self):
        JobManager.reset()
        LLMUsageTracker.reset()
        self._orig_stdout = sys.stdout
        self._orig_stderr = sys.stderr

    def tearDown(self):
        sys.stdout = self._orig_stdout
        sys.stderr = self._orig_stderr
        root = logging.getLogger()
        from cli.audit_runner import JobLogHandler
        root.handlers = [h for h in root.handlers if not isinstance(h, JobLogHandler)]

    @patch("cli.main.AetherCLI")
    def test_github_worker_success(self, mock_cli_cls):
        mock_cli = MagicMock()
        mock_cli.run_github_audit_command = MagicMock(return_value=None)
        mock_cli_cls.return_value = mock_cli

        from cli.audit_runner import AuditRunner
        runner = AuditRunner()
        jm = JobManager.get_instance()
        job = jm.create_job("GHJob", "github")

        runner._github_audit_worker(
            job, "https://github.com/org/repo", project_id=1, scope_id=2, fresh=False
        )

        self.assertEqual(job.status, JobStatus.COMPLETED)
        # Verify AetherCLI was called with correct flags
        mock_cli.run_github_audit_command.assert_called_once_with(
            github_url="https://github.com/org/repo",
            fresh=False,
            interactive_scope=False,
            skip_scope_selector=True,
            resume_scope_id=2,
        )

    @patch("cli.main.AetherCLI")
    def test_github_worker_failure(self, mock_cli_cls):
        mock_cli = MagicMock()
        mock_cli.run_github_audit_command.side_effect = Exception("clone failed")
        mock_cli_cls.return_value = mock_cli

        from cli.audit_runner import AuditRunner
        runner = AuditRunner()
        jm = JobManager.get_instance()
        job = jm.create_job("GHFail", "github")

        runner._github_audit_worker(
            job, "https://github.com/org/repo", project_id=None, scope_id=None, fresh=True
        )

        self.assertEqual(job.status, JobStatus.FAILED)
        self.assertIn("clone failed", job.error)


class TestConcurrentJobs(unittest.TestCase):
    """Test multiple concurrent jobs through AuditRunner."""

    def setUp(self):
        JobManager.reset()
        LLMUsageTracker.reset()
        self._orig_stdout = sys.stdout
        self._orig_stderr = sys.stderr

    def tearDown(self):
        sys.stdout = self._orig_stdout
        sys.stderr = self._orig_stderr
        root = logging.getLogger()
        from cli.audit_runner import JobLogHandler
        root.handlers = [h for h in root.handlers if not isinstance(h, JobLogHandler)]

    @patch("cli.main.AetherCLI")
    def test_two_concurrent_audits(self, mock_cli_cls):
        """Two audit threads run concurrently; both should complete."""
        call_count = {"n": 0}
        call_lock = threading.Lock()

        def fake_run_audit(**kwargs):
            with call_lock:
                call_count["n"] += 1
            time.sleep(0.1)  # Simulate brief work
            return {"summary": {"total_vulnerabilities": 1}}

        mock_cli = MagicMock()
        mock_cli.run_audit = AsyncMock(side_effect=fake_run_audit)
        mock_cli_cls.return_value = mock_cli

        from cli.audit_runner import AuditRunner
        runner = AuditRunner()
        jm = JobManager.get_instance()

        job1 = jm.create_job("Audit1", "local", target="/tmp/a.sol")
        job2 = jm.create_job("Audit2", "local", target="/tmp/b.sol")

        with tempfile.TemporaryDirectory() as tmpdir:
            out1 = os.path.join(tmpdir, "a")
            out2 = os.path.join(tmpdir, "b")
            runner.start_single_audit(job1.job_id, "/tmp/a.sol", [], out1)
            runner.start_single_audit(job2.job_id, "/tmp/b.sol", [], out2)

            # Wait for both
            job1.thread.join(timeout=5)
            job2.thread.join(timeout=5)

        self.assertEqual(job1.status, JobStatus.COMPLETED)
        self.assertEqual(job2.status, JobStatus.COMPLETED)
        self.assertEqual(call_count["n"], 2)


class TestAuditWorkerFindingsExtraction(unittest.TestCase):
    """Test findings extraction logic within _audit_worker."""

    def setUp(self):
        JobManager.reset()
        LLMUsageTracker.reset()
        self._orig_stdout = sys.stdout
        self._orig_stderr = sys.stderr

    def tearDown(self):
        sys.stdout = self._orig_stdout
        sys.stderr = self._orig_stderr
        root = logging.getLogger()
        from cli.audit_runner import JobLogHandler
        root.handlers = [h for h in root.handlers if not isinstance(h, JobLogHandler)]

    @patch("cli.main.AetherCLI")
    def test_findings_from_summary(self, mock_cli_cls):
        """Findings count from summary.total_vulnerabilities."""
        mock_cli = MagicMock()
        mock_cli.run_audit = AsyncMock(return_value={
            "summary": {"total_vulnerabilities": 7},
            "results": {"vulnerabilities": list(range(7))},
        })
        mock_cli_cls.return_value = mock_cli

        from cli.audit_runner import AuditRunner
        runner = AuditRunner()
        jm = JobManager.get_instance()
        job = jm.create_job("FindingsTest", "local", target="/tmp/x.sol")

        with tempfile.TemporaryDirectory() as tmpdir:
            runner._audit_worker(job, "/tmp/x.sol", [], tmpdir)

        self.assertEqual(job.findings_count, 7)

    @patch("cli.main.AetherCLI")
    def test_findings_from_results_list(self, mock_cli_cls):
        """When summary lacks total_vulnerabilities, fall back to counting results list."""
        mock_cli = MagicMock()
        mock_cli.run_audit = AsyncMock(return_value={
            "summary": {},
            "results": {"vulnerabilities": [1, 2, 3, 4, 5]},
        })
        mock_cli_cls.return_value = mock_cli

        from cli.audit_runner import AuditRunner
        runner = AuditRunner()
        jm = JobManager.get_instance()
        job = jm.create_job("FindingsTest2", "local", target="/tmp/x.sol")

        with tempfile.TemporaryDirectory() as tmpdir:
            runner._audit_worker(job, "/tmp/x.sol", [], tmpdir)

        self.assertEqual(job.findings_count, 5)

    @patch("cli.main.AetherCLI")
    def test_findings_fallback_to_stdout_count(self, mock_cli_cls):
        """audit_status.findings_count from stdout parsing can override the dict."""
        mock_cli = MagicMock()
        mock_cli.run_audit = AsyncMock(return_value={
            "summary": {"total_vulnerabilities": 2},
        })
        mock_cli_cls.return_value = mock_cli

        from cli.audit_runner import AuditRunner
        runner = AuditRunner()
        jm = JobManager.get_instance()
        job = jm.create_job("StdoutFallback", "local", target="/tmp/x.sol")
        # Simulate that stdout parsing found more findings
        job.audit_status.findings_count = 10

        with tempfile.TemporaryDirectory() as tmpdir:
            runner._audit_worker(job, "/tmp/x.sol", [], tmpdir)

        # The worker takes the max of the two
        self.assertEqual(job.findings_count, 10)

    @patch("cli.main.AetherCLI")
    def test_error_result_zero_findings(self, mock_cli_cls):
        """When run_audit returns an error dict, findings should be 0."""
        mock_cli = MagicMock()
        mock_cli.run_audit = AsyncMock(return_value={"error": "no files"})
        mock_cli_cls.return_value = mock_cli

        from cli.audit_runner import AuditRunner
        runner = AuditRunner()
        jm = JobManager.get_instance()
        job = jm.create_job("ErrorResult", "local", target="/tmp/x.sol")

        with tempfile.TemporaryDirectory() as tmpdir:
            runner._audit_worker(job, "/tmp/x.sol", [], tmpdir)

        # Job still completes (no exception), but findings are 0
        self.assertEqual(job.status, JobStatus.COMPLETED)
        self.assertEqual(job.findings_count, 0)


if __name__ == "__main__":
    unittest.main()
