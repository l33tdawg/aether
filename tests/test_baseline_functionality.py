"""
Baseline tests to ensure existing functionality remains intact during roadmap implementation.
These tests verify that core features continue to work as expected.
"""

import pytest
import json
import asyncio
from pathlib import Path
from typing import Dict, List, Any
from unittest.mock import Mock, patch

from core.enhanced_vulnerability_detector import EnhancedVulnerabilityDetector, VulnerabilityMatch
from core.vulnerability_detector import VulnerabilityDetector
from core.file_handler import FileHandler
from utils.file_handler import FileHandler as UtilsFileHandler


class TestBaselineVulnerabilityDetection:
    """Test that basic vulnerability detection still works."""

    def setup_method(self):
        """Set up test fixtures."""
        self.detector = VulnerabilityDetector()
        self.enhanced_detector = EnhancedVulnerabilityDetector()

        # Test contract with known vulnerabilities
        self.vulnerable_contract = '''
        pragma solidity ^0.8.0;

        contract VulnerableContract {
            uint256 public value;
            bool public locked;

            function withdraw() public {
                require(!locked, "Contract is locked");
                locked = true;

                // Reentrancy vulnerability
                msg.sender.call{value: address(this).balance}("");

                locked = false;
            }

            function setValue(uint256 _value) public {
                value = _value; // No access control
            }

            receive() external payable {}
        }
        '''

    def test_basic_vulnerability_detection(self):
        """Test that basic vulnerability detection still works."""
        vulnerabilities = self.detector.analyze_contract("test.sol", self.vulnerable_contract)

        # Should detect reentrancy vulnerability
        reentrancy_vulns = [v for v in vulnerabilities if v.vulnerability_type == 'reentrancy']
        assert len(reentrancy_vulns) > 0, "Should detect reentrancy vulnerability"

        # Should detect access control vulnerability
        access_control_vulns = [v for v in vulnerabilities if v.vulnerability_type == 'access_control']
        assert len(access_control_vulns) > 0, "Should detect access control vulnerability"

    def test_enhanced_vulnerability_detection(self):
        """Test that enhanced vulnerability detection still works."""
        vulnerabilities = self.enhanced_detector.analyze_contract(self.vulnerable_contract)

        # Should detect vulnerabilities
        assert len(vulnerabilities) > 0, "Should detect vulnerabilities"

        # All vulnerabilities should have validation status
        for vuln in vulnerabilities:
            assert vuln.validation_status in ['pending', 'validated', 'false_positive'], "Should have validation status"

    def test_vulnerability_match_structure(self):
        """Test that VulnerabilityMatch structure remains intact."""
        vuln = VulnerabilityMatch(
            vulnerability_type='test',
            severity='high',
            confidence=0.8,
            line_number=10,
            description='Test vulnerability',
            code_snippet='test code',
            swc_id='SWC-000',
            category='test'
        )

        # Test basic properties
        assert vuln.vulnerability_type == 'test'
        assert vuln.severity == 'high'
        assert vuln.confidence == 0.8
        assert vuln.line_number == 10
        assert vuln.description == 'Test vulnerability'
        assert vuln.code_snippet == 'test code'
        assert vuln.swc_id == 'SWC-000'
        assert vuln.category == 'test'

        # Test enhanced properties
        assert vuln.context is not None
        assert vuln.validation_status == 'pending'

    def test_pattern_initialization(self):
        """Test that pattern initialization still works."""
        patterns = self.detector.patterns
        assert isinstance(patterns, dict), "Patterns should be a dictionary"
        assert len(patterns) > 0, "Should have patterns"

        # Check for common vulnerability types
        expected_types = ['reentrancy', 'access_control', 'arithmetic']
        for vuln_type in expected_types:
            assert vuln_type in patterns, f"Should have {vuln_type} patterns"

    def test_contract_context_setting(self):
        """Test that contract context setting still works."""
        context = {'contract_path': 'test.sol', 'protocol_type': 'test'}

        self.detector.set_contract_context(context)
        assert self.detector.contract_context == context

        self.enhanced_detector.set_contract_context(context)
        assert self.enhanced_detector.contract_context == context


class TestBaselineFileHandling:
    """Test that file handling functionality still works."""

    def setup_method(self):
        """Set up test fixtures."""
        self.file_handler = FileHandler()
        self.utils_file_handler = UtilsFileHandler()

    def test_solidity_file_reading(self):
        """Test that Solidity file reading still works."""
        test_content = '''
        pragma solidity ^0.8.0;

        contract TestContract {
            uint256 public value;
        }
        '''

        test_file = Path("test_contract.sol")
        test_file.write_text(test_content)

        try:
            # Test utils file handler
            files_data = self.utils_file_handler.read_contract_files(str(test_file))
            assert len(files_data) == 1
            assert test_content.strip() in files_data[0][1]

        finally:
            test_file.unlink()

    def test_directory_reading(self):
        """Test that directory reading still works."""
        test_dir = Path("test_contracts")
        test_dir.mkdir()

        contract1_content = '''
        pragma solidity ^0.8.0;
        contract Contract1 {
            uint256 public value;
        }
        '''

        contract2_content = '''
        pragma solidity ^0.8.0;
        contract Contract2 {
            string public name;
        }
        '''

        (test_dir / "Contract1.sol").write_text(contract1_content)
        (test_dir / "Contract2.sol").write_text(contract2_content)

        try:
            files_data = self.utils_file_handler.read_contract_files(str(test_dir))
            assert len(files_data) == 2

            file_names = [Path(f[0]).name for f in files_data]
            assert "Contract1.sol" in file_names
            assert "Contract2.sol" in file_names

        finally:
            for file in test_dir.glob("*.sol"):
                file.unlink()
            test_dir.rmdir()

    def test_file_metrics_calculation(self):
        """Test that file metrics calculation still works."""
        content = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// This is a comment
contract TestContract {
    uint256 public value; // Another comment

    function test() public {
        // Function code
        value = 42;
    }
}'''

        metrics = self.utils_file_handler.calculate_file_metrics(content)

        assert metrics['total_lines'] > 0
        assert metrics['code_lines'] > 0
        assert metrics['comment_lines'] > 0
        assert 'comment_ratio' in metrics
        assert 'code_ratio' in metrics


class TestBaselineAuditEngine:
    """Test that enhanced audit engine functionality still works."""

    @patch('core.enhanced_audit_engine.DatabaseManager')
    @patch('core.enhanced_audit_engine.EnhancedReportGenerator')
    @patch('core.enhanced_audit_engine.FoundryPoCGenerator')
    @patch('core.enhanced_audit_engine.LLMFalsePositiveFilter')
    @patch('core.enhanced_audit_engine.VulnerabilityValidator')
    @patch('core.enhanced_audit_engine.EnhancedLLMAnalyzer')
    @patch('core.enhanced_audit_engine.EnhancedVulnerabilityDetector')
    @patch('core.enhanced_audit_engine.FileHandler')
    def setup_method(self, method, *mocks):
        """Set up test fixtures."""
        from core.enhanced_audit_engine import EnhancedAetherAuditEngine
        self.audit_engine = EnhancedAetherAuditEngine(verbose=False)

    def test_audit_engine_initialization(self):
        """Test that audit engine initializes correctly."""
        assert self.audit_engine.verbose == False
        assert self.audit_engine.file_handler is not None
        assert self.audit_engine.vulnerability_detector is not None

    def test_detector_initialization(self):
        """Test that key detectors are properly initialized."""
        assert hasattr(self.audit_engine, 'vulnerability_detector')
        assert self.audit_engine.vulnerability_detector is not None

    def test_audit_engine_tools(self):
        """Test that audit engine tools are properly initialized."""
        assert hasattr(self.audit_engine, 'llm_analyzer')
        assert hasattr(self.audit_engine, 'foundry_poc_generator')
        assert self.audit_engine.llm_analyzer is not None
        assert self.audit_engine.foundry_poc_generator is not None


class TestBaselineIntegration:
    """Test that baseline integration still works."""

    def setup_method(self):
        """Set up test fixtures."""
        self.detector = VulnerabilityDetector()
        self.enhanced_detector = EnhancedVulnerabilityDetector()
        self.test_contract = '''
        pragma solidity ^0.8.0;

        contract IntegrationTestContract {
            uint256 public value;
            mapping(address => uint256) public balances;

            function deposit() public payable {
                balances[msg.sender] += msg.value;
            }

            function withdraw(uint256 amount) public {
                require(balances[msg.sender] >= amount, "Insufficient balance");
                balances[msg.sender] -= amount;
                payable(msg.sender).transfer(amount);
            }

            function setValue(uint256 _value) public {
                value = _value;
            }
        }
        '''

    def test_end_to_end_analysis(self):
        """Test that end-to-end analysis still works."""
        vulnerabilities = self.detector.analyze_contract("test.sol", self.test_contract)
        assert isinstance(vulnerabilities, list), "Should return list of vulnerabilities"

    def test_vulnerability_validation(self):
        """Test that vulnerability validation still works."""
        vulnerabilities = self.detector.analyze_contract("test.sol", self.test_contract)

        if vulnerabilities:
            vuln = vulnerabilities[0]
            is_valid = self.detector.validate_vulnerability_context(vuln)
            assert isinstance(is_valid, bool), "Validation should return boolean"

    def test_file_handler_integration(self):
        """Test that file handler integrates properly with detectors."""
        test_file = Path("integration_test.sol")
        test_file.write_text(self.test_contract)

        try:
            from utils.file_handler import FileHandler as UtilsFileHandler
            utils_handler = UtilsFileHandler()
            files_data = utils_handler.read_contract_files(str(test_file))
            assert len(files_data) == 1

            file_path, file_content = files_data[0]
            vulnerabilities = self.detector.analyze_contract(file_path, file_content)
            assert isinstance(vulnerabilities, list), "Should analyze file content"

        finally:
            test_file.unlink()

    def test_detector_compatibility(self):
        """Test that detectors are compatible with each other."""
        vulns1 = self.detector.analyze_contract("test.sol", self.test_contract)
        vulns2 = self.enhanced_detector.analyze_contract(self.test_contract)

        assert isinstance(vulns1, list), "First detector should return list"
        assert isinstance(vulns2, list), "Second detector should return list"


class TestBackwardCompatibility:
    """Test that backward compatibility is maintained."""

    def setup_method(self):
        """Set up test fixtures."""
        self.detector = VulnerabilityDetector()
        self.enhanced_detector = EnhancedVulnerabilityDetector()

    def test_api_compatibility(self):
        """Test that API remains compatible."""
        test_contract = '''
        pragma solidity ^0.8.0;
        contract TestContract {
            uint256 public value;
            function setValue(uint256 _value) public {
                value = _value;
            }
        }
        '''

        # Test original API
        vulns = self.detector.analyze_contract("test.sol", test_contract)
        assert isinstance(vulns, list), "Original API should work"

        # Test enhanced API
        enhanced_vulns = self.enhanced_detector.analyze_contract(test_contract)
        assert isinstance(enhanced_vulns, list), "Enhanced API should work"

    def test_data_structure_compatibility(self):
        """Test that data structures remain compatible."""
        vuln = VulnerabilityMatch(
            vulnerability_type='test',
            severity='high',
            confidence=0.8,
            line_number=10,
            description='Test',
            code_snippet='test code'
        )

        assert hasattr(vuln, 'vulnerability_type')
        assert hasattr(vuln, 'severity')
        assert hasattr(vuln, 'confidence')
        assert hasattr(vuln, 'line_number')
        assert hasattr(vuln, 'description')
        assert hasattr(vuln, 'code_snippet')
        assert hasattr(vuln, 'context')
        assert hasattr(vuln, 'validation_status')

    def test_configuration_compatibility(self):
        """Test that configuration remains compatible."""
        detector = VulnerabilityDetector()
        assert detector.patterns is not None
        assert isinstance(detector.patterns, dict)

        enhanced_detector = EnhancedVulnerabilityDetector()
        assert enhanced_detector.patterns is not None
        assert isinstance(enhanced_detector.patterns, dict)

        assert hasattr(enhanced_detector, 'protocol_patterns')
        assert hasattr(enhanced_detector, 'severity_matrix')
        assert isinstance(enhanced_detector.protocol_patterns, dict)
        assert isinstance(enhanced_detector.severity_matrix, dict)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
