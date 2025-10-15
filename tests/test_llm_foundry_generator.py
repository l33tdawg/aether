#!/usr/bin/env python3
"""
Unit tests for the enhanced LLM Foundry Generator functionality.

Tests the new vulnerability-specific exploit and test generation features.
"""

import sys
import os
sys.path.insert(0, '/Users/l33tdawg/nodejs-projects/bugbounty')

import unittest
from unittest.mock import Mock, patch, MagicMock
import tempfile
from pathlib import Path

try:
    from core.llm_foundry_generator import LLMFoundryGenerator, TestGenerationResult
except ImportError as e:
    print(f"Import error: {e}")
    sys.exit(1)


class TestLLMFoundryGenerator(unittest.TestCase):
    """Test cases for the enhanced LLM Foundry Generator."""

    def setUp(self):
        """Set up test fixtures."""
        self.generator = LLMFoundryGenerator()
        self.contract_name = "TestContract"

        # Sample vulnerability data
        self.access_control_vuln = {
            'vulnerability_type': 'Access Control',
            'line_number': 42,
            'severity': 'high',
            'description': 'Owner can be front-run during ownership transfer'
        }

        self.reentrancy_vuln = {
            'vulnerability_type': 'Reentrancy',
            'line_number': 128,
            'severity': 'critical',
            'description': 'No reentrancy guard on withdraw function'
        }

        self.overflow_vuln = {
            'vulnerability_type': 'Integer Overflow',
            'line_number': 256,
            'severity': 'medium',
            'description': 'Unchecked arithmetic in balance calculation'
        }

    def test_vulnerability_specific_exploit_generation(self):
        """Test that exploits are generated based on vulnerability type."""
        # Test access control exploit
        access_control_exploit = self.generator._generate_exploit_by_vulnerability_type(
            self.access_control_vuln, self.contract_name
        )

        self.assertIn("AccessControlExploit", access_control_exploit)
        self.assertIn("exploitBypassAccessControl", access_control_exploit)
        self.assertIn("isAccessControlBypassed", access_control_exploit)
        self.assertIn("constructor(address _target)", access_control_exploit)

        # Test reentrancy exploit
        reentrancy_exploit = self.generator._generate_exploit_by_vulnerability_type(
            self.reentrancy_vuln, self.contract_name
        )

        self.assertIn("ReentrancyExploit", reentrancy_exploit)
        self.assertIn("exploitReentrancy", reentrancy_exploit)
        self.assertIn("isReentrancyExploited", reentrancy_exploit)
        self.assertIn("receive() external payable", reentrancy_exploit)

        # Test overflow exploit
        overflow_exploit = self.generator._generate_exploit_by_vulnerability_type(
            self.overflow_vuln, self.contract_name
        )

        self.assertIn("OverflowExploit", overflow_exploit)
        self.assertIn("exploitOverflow", overflow_exploit)
        self.assertIn("isOverflowExploited", overflow_exploit)

    def test_vulnerability_specific_test_generation(self):
        """Test that tests are generated based on vulnerability type."""
        # Test access control test
        access_control_test = self.generator._generate_test_by_vulnerability_type(
            self.access_control_vuln, self.contract_name
        )

        self.assertIn("AccessControlTest", access_control_test)
        self.assertIn("testAccessControlBypass", access_control_test)
        self.assertIn("exploitBypassAccessControl", access_control_test)
        self.assertIn("isAccessControlBypassed", access_control_test)

        # Test reentrancy test
        reentrancy_test = self.generator._generate_test_by_vulnerability_type(
            self.reentrancy_vuln, self.contract_name
        )

        self.assertIn("ReentrancyTest", reentrancy_test)
        self.assertIn("testReentrancyAttack", reentrancy_test)
        self.assertIn("exploitReentrancy", reentrancy_test)

        # Test overflow test
        overflow_test = self.generator._generate_test_by_vulnerability_type(
            self.overflow_vuln, self.contract_name
        )

        self.assertIn("OverflowTest", overflow_test)
        self.assertIn("testOverflowExploit", overflow_test)
        self.assertIn("exploitOverflow", overflow_test)

    def test_exploit_contract_structure(self):
        """Test that generated exploits have proper contract structure."""
        exploit_code = self.generator._generate_access_control_exploit(self.contract_name)

        # Check for proper SPDX license
        self.assertIn("// SPDX-License-Identifier: MIT", exploit_code)

        # Check for proper pragma
        self.assertIn("pragma solidity ^0.8.19", exploit_code)

        # Check for contract declaration
        self.assertIn(f"contract {self.contract_name}AccessControlExploit", exploit_code)

        # Check for constructor
        self.assertIn("constructor(address _target)", exploit_code)

        # Check for exploit function
        self.assertIn("function exploitBypassAccessControl", exploit_code)

        # Check for verification function
        self.assertIn("function isAccessControlBypassed", exploit_code)

    def test_test_contract_structure(self):
        """Test that generated tests have proper contract structure."""
        test_code = self.generator._generate_access_control_test(self.contract_name)

        # Check for proper SPDX license
        self.assertIn("// SPDX-License-Identifier: MIT", test_code)

        # Check for proper pragma
        self.assertIn("pragma solidity ^0.8.19", test_code)

        # Check for test contract declaration
        self.assertIn(f"contract {self.contract_name}AccessControlTest", test_code)

        # Check for inheritance from Test
        self.assertIn("is Test", test_code)

        # Check for setUp function
        self.assertIn("function setUp() public", test_code)

        # Check for test functions
        self.assertIn("function testAccessControlBypass", test_code)

        # Check for exploit deployment and execution
        self.assertIn(f"new {self.contract_name}Exploit", test_code)
        self.assertIn("exploitBypassAccessControl", test_code)
        self.assertIn("isAccessControlBypassed", test_code)

    def test_fallback_behavior(self):
        """Test that fallback generation works when LLM fails."""
        # Mock a vulnerability that doesn't match any specific type
        generic_vuln = {
            'vulnerability_type': 'Generic Vulnerability',
            'line_number': 1,
            'severity': 'low',
            'description': 'Some generic issue'
        }

        # Test generic exploit generation
        generic_exploit = self.generator._generate_exploit_by_vulnerability_type(
            generic_vuln, self.contract_name
        )

        self.assertIn("GenericExploit", generic_exploit)
        self.assertIn("function exploit", generic_exploit)
        self.assertIn("function isExploitAttempted", generic_exploit)

        # Test generic test generation
        generic_test = self.generator._generate_test_by_vulnerability_type(
            generic_vuln, self.contract_name
        )

        self.assertIn("GenericTest", generic_test)
        self.assertIn("testExploitExecution", generic_test)
        self.assertIn("testVulnerabilityDemonstration", generic_test)

    def test_oracle_exploit_generation(self):
        """Test oracle manipulation exploit generation."""
        oracle_vuln = {
            'vulnerability_type': 'Oracle Manipulation',
            'line_number': 100,
            'severity': 'high',
            'description': 'Price oracle can be manipulated'
        }

        oracle_exploit = self.generator._generate_exploit_by_vulnerability_type(
            oracle_vuln, self.contract_name
        )

        self.assertIn("OracleExploit", oracle_exploit)
        self.assertIn("exploitOracle", oracle_exploit)
        self.assertIn("isOracleManipulated", oracle_exploit)

    def test_flash_loan_exploit_generation(self):
        """Test flash loan exploit generation."""
        flash_loan_vuln = {
            'vulnerability_type': 'Flash Loan Attack',
            'line_number': 200,
            'severity': 'critical',
            'description': 'Contract vulnerable to flash loan attacks'
        }

        flash_loan_exploit = self.generator._generate_exploit_by_vulnerability_type(
            flash_loan_vuln, self.contract_name
        )

        self.assertIn("FlashLoanExploit", flash_loan_exploit)
        self.assertIn("exploitFlashLoan", flash_loan_exploit)
        self.assertIn("isFlashLoanExploited", flash_loan_exploit)

    def test_exploit_contains_realistic_logic(self):
        """Test that exploits contain realistic exploitation patterns."""
        access_control_exploit = self.generator._generate_access_control_exploit(self.contract_name)

        # Should contain TODO comments for actual implementation
        self.assertIn("// TODO: Implement specific access control bypass", access_control_exploit)

        # Should contain realistic attack patterns
        self.assertIn("// For example, if there's an owner-only function", access_control_exploit)

        # Should have proper state management
        self.assertIn("TestContract public target", access_control_exploit)

    def test_test_contains_proper_assertions(self):
        """Test that tests contain proper assertions and verification."""
        access_control_test = self.generator._generate_access_control_test(self.contract_name)

        # Should contain assertion for exploit success
        self.assertIn("assertTrue(exploit.isAccessControlBypassed()", access_control_test)

        # Should contain proper test structure
        self.assertIn("function testAccessControlBypass() public", access_control_test)

    def test_contract_imports_are_correct(self):
        """Test that generated code has correct import statements."""
        exploit_code = self.generator._generate_access_control_exploit(self.contract_name)

        # Should import the target contract
        self.assertIn(f'import "./{self.contract_name}.sol";', exploit_code)

        test_code = self.generator._generate_access_control_test(self.contract_name)

        # Should import both target and exploit contracts
        self.assertIn(f'import "./{self.contract_name}.sol";', test_code)
        self.assertIn(f'import "./{self.contract_name}Exploit.sol";', test_code)

    def test_solc_version_is_correct(self):
        """Test that generated code uses correct Solidity version."""
        exploit_code = self.generator._generate_access_control_exploit(self.contract_name)
        test_code = self.generator._generate_access_control_test(self.contract_name)

        # Should use Solidity 0.8.19
        self.assertIn("pragma solidity ^0.8.19", exploit_code)
        self.assertIn("pragma solidity ^0.8.19", test_code)

    def test_exploit_contract_naming_convention(self):
        """Test that exploit contracts follow proper naming conventions."""
        access_control_exploit = self.generator._generate_access_control_exploit("MyContract")
        reentrancy_exploit = self.generator._generate_reentrancy_exploit("MyContract")
        overflow_exploit = self.generator._generate_overflow_exploit("MyContract")

        # Should follow pattern: ContractName + ExploitType + Exploit
        self.assertIn("MyContractAccessControlExploit", access_control_exploit)
        self.assertIn("MyContractReentrancyExploit", reentrancy_exploit)
        self.assertIn("MyContractOverflowExploit", overflow_exploit)


class TestExploitGenerationIntegration(unittest.TestCase):
    """Integration tests for the complete exploit generation pipeline."""

    def setUp(self):
        """Set up integration test fixtures."""
        self.generator = LLMFoundryGenerator()

    def test_complete_generation_pipeline(self):
        """Test the complete exploit and test generation pipeline."""
        vulnerabilities = [
            {
                'vulnerability_type': 'Access Control',
                'line_number': 42,
                'severity': 'high',
                'description': 'Owner can be bypassed'
            },
            {
                'vulnerability_type': 'Reentrancy',
                'line_number': 128,
                'severity': 'critical',
                'description': 'No reentrancy protection'
            }
        ]

        contract_code = "// Sample contract code"
        contract_name = "TestContract"

        # Test that generation doesn't crash
        try:
            # This would normally be async, but we're testing the core logic
            for vuln in vulnerabilities:
                exploit = self.generator._generate_exploit_by_vulnerability_type(vuln, contract_name)
                test = self.generator._generate_test_by_vulnerability_type(vuln, contract_name)

                # Basic validation
                self.assertIsInstance(exploit, str)
                self.assertIsInstance(test, str)
                self.assertGreater(len(exploit), 100)  # Should be substantial code
                self.assertGreater(len(test), 100)    # Should be substantial code

        except Exception as e:
            self.fail(f"Generation pipeline failed: {e}")


if __name__ == '__main__':
    # Run the tests
    unittest.main(verbosity=2)
