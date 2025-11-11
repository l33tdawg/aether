"""
Tests for Access Control Context Analyzer improvements

These tests validate that the improvements correctly:
1. Detect admin-only functions
2. Adjust severity appropriately
3. Reduce false positives for protected functions
"""

import unittest
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.access_control_context_analyzer import (
    AccessControlContextAnalyzer,
    AccessLevel
)
from core.vulnerability_deduplicator import VulnerabilityDeduplicator


class TestAccessControlContextAnalyzer(unittest.TestCase):
    """Test access control context analysis"""
    
    def setUp(self):
        self.analyzer = AccessControlContextAnalyzer()
    
    def test_detect_onlyRole_modifier(self):
        """Test detection of onlyRole modifier"""
        function_code = """
        function updateConfig(uint256 value) 
            external 
            onlyRole(ADMIN_ROLE)
        {
            config = value;
        }
        """
        
        result = self.analyzer.analyze_function_access_control(
            function_code, "updateConfig", ""
        )
        
        self.assertTrue(result['has_access_control'])
        self.assertEqual(result['access_level'], AccessLevel.RESTRICTED)
        self.assertLess(result['severity_adjustment'], 1.0)
        self.assertGreater(result['confidence'], 0.9)
    
    def test_detect_fungible_module_pattern(self):
        """Test detection of FUNGIBLE_MODULE_ADDRESS pattern (ZetaChain)"""
        function_code = """
        function setGasCoinZRC20(uint256 chainID, address zrc20) external {
            if (msg.sender != FUNGIBLE_MODULE_ADDRESS) revert CallerIsNotFungibleModule();
            gasCoinZRC20ByChainId[chainID] = zrc20;
        }
        """
        
        result = self.analyzer.analyze_function_access_control(
            function_code, "setGasCoinZRC20", ""
        )
        
        self.assertTrue(result['has_access_control'])
        self.assertEqual(result['access_level'], AccessLevel.MODULE_ONLY)
        self.assertEqual(result['role_name'], 'FUNGIBLE_MODULE_ADDRESS')
        # Should have very low severity adjustment (0.1 = 90% reduction)
        self.assertLess(result['severity_adjustment'], 0.2)
        self.assertGreater(result['confidence'], 0.95)
    
    def test_detect_onlyOwner_modifier(self):
        """Test detection of onlyOwner modifier"""
        function_code = """
        function setWzetaAddress(address wzeta_) external onlyFungibleModule {
            wzeta = wzeta_;
        }
        """
        
        result = self.analyzer.analyze_function_access_control(
            function_code, "setWzetaAddress", ""
        )
        
        self.assertTrue(result['has_access_control'])
        # Note: onlyFungibleModule is a custom modifier, should be detected
        self.assertLess(result['severity_adjustment'], 1.0)
    
    def test_detect_admin_function_by_name(self):
        """Test detection of admin functions by name"""
        function_names = [
            'setConfig',
            'updateRegistry',
            'configureSystem',
            'initializeContract',
            'changeOwner',
            'setupProtocol'
        ]
        
        for func_name in function_names:
            result = self.analyzer.analyze_function_access_control(
                f"function {func_name}() external {{}}",
                func_name,
                ""
            )
            self.assertTrue(result['is_admin_function'], 
                          f"{func_name} should be detected as admin function")
    
    def test_severity_adjustment_for_admin_only(self):
        """Test that severity is properly adjusted for admin-only functions"""
        vulnerability = {
            'vulnerability_type': 'missing_zero_check',
            'severity': 'high',
            'confidence': 0.8,
            'description': 'Missing zero address validation',
            'line': 129
        }
        
        access_control_info = {
            'has_access_control': True,
            'access_level': AccessLevel.MODULE_ONLY,
            'role_name': 'FUNGIBLE_MODULE_ADDRESS',
            'severity_adjustment': 0.1,
            'confidence': 0.98,
            'is_admin_function': True
        }
        
        adjusted = self.analyzer.adjust_vulnerability_severity(
            vulnerability,
            access_control_info
        )
        
        # High severity (3) * 0.1 * 0.5 (admin bonus) = 0.15 -> rounds to 0 (info)
        self.assertIn(adjusted['severity'], ['low', 'info'])
        self.assertIn('NOT exploitable by external attackers', adjusted['description'])
        self.assertEqual(adjusted['original_severity'], 'high')
    
    def test_no_adjustment_for_public_functions(self):
        """Test that public functions without access control get no adjustment"""
        function_code = """
        function send(SendInput calldata input) external {
            // No access control
        }
        """
        
        result = self.analyzer.analyze_function_access_control(
            function_code, "send", ""
        )
        
        self.assertFalse(result['has_access_control'])
        self.assertEqual(result['severity_adjustment'], 1.0)  # No adjustment
        self.assertEqual(result['access_level'], AccessLevel.PUBLIC)


class TestVulnerabilityDeduplicator(unittest.TestCase):
    """Test vulnerability deduplication"""
    
    def setUp(self):
        self.deduplicator = VulnerabilityDeduplicator()
    
    def test_deduplicate_same_line_same_type(self):
        """Test deduplication of vulnerabilities at same location"""
        vulnerabilities = [
            {
                'vulnerability_type': 'missing_validation',
                'severity': 'medium',
                'confidence': 0.7,
                'line': 138,
                'description': 'Send without validation'
            },
            {
                'vulnerability_type': 'missing_input_validation',
                'severity': 'medium',
                'confidence': 0.65,
                'line': 138,
                'description': 'The send function lacks comprehensive input validation'
            },
            {
                'vulnerability_type': 'input_validation',
                'severity': 'medium',
                'confidence': 0.9,
                'line': 138,
                'description': 'The send() function lacks input validation for critical cross-chain parameters'
            }
        ]
        
        deduplicated = self.deduplicator.deduplicate(vulnerabilities)
        
        # Should merge into 1 vulnerability
        self.assertEqual(len(deduplicated), 1)
        
        # Should have increased confidence (multiple detections)
        self.assertGreater(deduplicated[0]['confidence'], 0.7)
        
        # Should have the most detailed description
        self.assertIn('cross-chain parameters', deduplicated[0]['description'])
        
        # Should note multiple detections
        self.assertIn('multiple analyzers', deduplicated[0]['description'])
    
    def test_no_deduplication_different_lines(self):
        """Test that vulnerabilities on different lines are not deduplicated"""
        vulnerabilities = [
            {
                'vulnerability_type': 'missing_validation',
                'severity': 'medium',
                'confidence': 0.7,
                'line': 138,
                'description': 'Send without validation'
            },
            {
                'vulnerability_type': 'missing_validation',
                'severity': 'medium',
                'confidence': 0.8,
                'line': 129,
                'description': 'Missing zero address check'
            }
        ]
        
        deduplicated = self.deduplicator.deduplicate(vulnerabilities)
        
        # Should keep both
        self.assertEqual(len(deduplicated), 2)
    
    def test_normalize_vulnerability_types(self):
        """Test that similar vulnerability types are normalized"""
        test_cases = [
            ('missing_validation', 'input_validation'),
            ('missing_input_validation', 'input_validation'),
            ('send_without_validation', 'input_validation'),
            ('missing_zero_check', 'zero_address'),
            ('zero_address', 'zero_address'),
            ('null_address', 'zero_address'),
        ]
        
        for input_type, expected_output in test_cases:
            normalized = self.deduplicator._normalize_vulnerability_type(input_type)
            self.assertEqual(normalized, expected_output,
                           f"{input_type} should normalize to {expected_output}")
    
    def test_remove_subsumed_vulnerabilities(self):
        """Test removal of generic vulnerabilities when specific ones exist"""
        vulnerabilities = [
            {
                'vulnerability_type': 'missing_validation',
                'severity': 'medium',
                'line': 129,
                'description': 'Missing validation'
            },
            {
                'vulnerability_type': 'zero_address',
                'severity': 'medium',
                'line': 129,
                'description': 'Missing zero address check'
            }
        ]
        
        filtered = self.deduplicator.remove_subsumed_vulnerabilities(vulnerabilities)
        
        # Should keep only the specific one (zero_address)
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]['vulnerability_type'], 'zero_address')
    
    def test_confidence_boosting(self):
        """Test that multiple detections boost confidence"""
        test_cases = [
            ([0.7], 0.7),  # Single detection: no boost
            ([0.7, 0.7], 0.8),  # Two detections: +0.1 boost
            ([0.7, 0.7, 0.7], 0.9),  # Three detections: +0.2 boost
            ([0.7, 0.7, 0.7, 0.7], 1.0),  # Four+ detections: +0.3 boost (capped at 1.0)
        ]
        
        for confidences, expected_min in test_cases:
            vulns = [{'confidence': c} for c in confidences]
            merged = self.deduplicator._calculate_merged_confidence(vulns)
            self.assertGreaterEqual(merged, expected_min - 0.05,  # Allow small margin
                                  f"Failed for {len(confidences)} detections")


class TestIntegration(unittest.TestCase):
    """Integration tests for the complete improvement pipeline"""
    
    def setUp(self):
        self.analyzer = AccessControlContextAnalyzer()
        self.deduplicator = VulnerabilityDeduplicator()
    
    def test_zetachain_scenario(self):
        """Test the complete pipeline with ZetaChain-like scenarios"""
        # Simulate the ZetaChain findings
        raw_vulnerabilities = [
            {
                'vulnerability_type': 'missing_validation',
                'severity': 'medium',
                'confidence': 0.9,
                'line': 77,
                'description': 'The send() function lacks input validation',
                'function_name': 'send'
            },
            {
                'vulnerability_type': 'send_without_validation',
                'severity': 'medium',
                'confidence': 0.7,
                'line': 77,
                'description': 'Send without validation',
                'function_name': 'send'
            },
            {
                'vulnerability_type': 'input_validation',
                'severity': 'medium',
                'confidence': 0.65,
                'line': 77,
                'description': 'The send function lacks comprehensive input validation',
                'function_name': 'send'
            },
            {
                'vulnerability_type': 'missing_zero_check',
                'severity': 'medium',
                'confidence': 0.8,
                'line': 129,
                'description': 'The setWzetaAddress function allows setting to address(0)',
                'function_name': 'setWzetaAddress'
            }
        ]
        
        # Step 1: Deduplicate
        deduplicated = self.deduplicator.deduplicate(raw_vulnerabilities)
        
        # Should merge the 3 send() findings into 1
        self.assertLessEqual(len(deduplicated), 2)
        
        # Step 2: Apply access control adjustments
        # Simulate setWzetaAddress having onlyFungibleModule
        function_codes = {
            'send': 'function send(SendInput calldata input) external { }',
            'setWzetaAddress': '''function setWzetaAddress(address wzeta_) external onlyFungibleModule {
                wzeta = wzeta_;
            }'''
        }
        
        adjusted_vulnerabilities = []
        for vuln in deduplicated:
            func_name = vuln.get('function_name', '')
            if func_name in function_codes:
                access_info = self.analyzer.analyze_function_access_control(
                    function_codes[func_name],
                    func_name,
                    ""
                )
                adjusted = self.analyzer.adjust_vulnerability_severity(vuln, access_info)
                adjusted_vulnerabilities.append(adjusted)
            else:
                adjusted_vulnerabilities.append(vuln)
        
        # Verify adjustments
        for vuln in adjusted_vulnerabilities:
            if vuln.get('function_name') == 'setWzetaAddress':
                # Should be downgraded
                self.assertIn(vuln['severity'], ['low', 'info'])
                self.assertIn('access_control', vuln)
            elif vuln.get('function_name') == 'send':
                # Should remain medium (no access control)
                self.assertEqual(vuln['severity'], 'medium')


if __name__ == '__main__':
    unittest.main()

