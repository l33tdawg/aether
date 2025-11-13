"""
Unit tests for Architectural Pattern Recognizer
Tests the configurable DeFi pattern detection and vulnerability filtering.
"""

import unittest
import tempfile
import json
import os
from core.architectural_pattern_recognizer import (
    ArchitecturalPatternRecognizer,
    DeFiPattern,
    ValidationRule
)


class TestArchitecturalPatternRecognizer(unittest.TestCase):
    """Test the architectural pattern recognition system."""

    def setUp(self):
        """Set up test fixtures."""
        # Create temporary config files
        self.temp_dir = tempfile.mkdtemp()
        self.patterns_file = os.path.join(self.temp_dir, 'patterns.json')
        self.rules_file = os.path.join(self.temp_dir, 'rules.json')

        # Create test patterns
        self.test_patterns = {
            'test_vault_pattern': {
                'description': 'Test vault manager separation',
                'contracts': ['*Vault*', '*Manager*'],
                'trust_relationships': {
                    'vault': ['manager'],
                    'manager': ['vault']
                },
                'validation_rules': ['test_external_calls']
            }
        }

        # Create test rules
        self.test_rules = {
            'test_external_calls': {
                'description': 'Test external call validation',
                'reason': 'Test reason for filtering',
                'vulnerability_patterns': ['external_call', 'unvalidated_call'],
                'code_patterns': [r'manager\..*\('],
                'function_patterns': [r'deposit', r'withdraw']
            }
        }

        # Write config files
        with open(self.patterns_file, 'w') as f:
            json.dump(self.test_patterns, f)

        with open(self.rules_file, 'w') as f:
            json.dump(self.test_rules, f)

    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir)

    def test_initialization_with_config_files(self):
        """Test that the recognizer loads from config files."""
        recognizer = ArchitecturalPatternRecognizer(self.patterns_file)

        self.assertIn('test_vault_pattern', recognizer.patterns)
        self.assertIn('test_external_calls', recognizer.validation_rules)

        pattern = recognizer.patterns['test_vault_pattern']
        self.assertEqual(pattern.description, 'Test vault manager separation')
        self.assertEqual(pattern.contracts, ['*Vault*', '*Manager*'])

    def test_initialization_fallback_to_defaults(self):
        """Test fallback to defaults when config files don't exist."""
        recognizer = ArchitecturalPatternRecognizer('/nonexistent/file.json')

        # Should have default patterns
        self.assertIn('vault_manager_separation', recognizer.patterns)
        self.assertIn('external_calls_to_manager', recognizer.validation_rules)

    def test_pattern_detection(self):
        """Test pattern detection from contract names."""
        recognizer = ArchitecturalPatternRecognizer(self.patterns_file)

        # Should detect test pattern
        contract_files = [
            {'name': 'AsyncVault'},
            {'name': 'TestManager'},
            {'name': 'OtherContract'}
        ]

        pattern = recognizer.detect_pattern(contract_files)
        self.assertEqual(pattern, 'test_vault_pattern')

        # Should not detect when contracts don't match
        contract_files_no_match = [
            {'name': 'RandomContract'},
            {'name': 'AnotherContract'}
        ]

        pattern = recognizer.detect_pattern(contract_files_no_match)
        self.assertIsNone(pattern)

    def test_vulnerability_filtering(self):
        """Test that vulnerabilities are correctly filtered based on patterns."""
        recognizer = ArchitecturalPatternRecognizer(self.patterns_file)

        # Test case 1: Should filter external call to manager
        should_skip, reason = recognizer.should_skip_vulnerability(
            'external_call',
            {
                'code_snippet': 'manager.deposit(amount);',
                'function_name': 'deposit'
            },
            'test_vault_pattern'
        )

        self.assertTrue(should_skip)
        self.assertEqual(reason, 'Test reason for filtering')

        # Test case 2: Should filter by function name
        should_skip, reason = recognizer.should_skip_vulnerability(
            'unvalidated_call',
            {
                'code_snippet': 'someOtherCall();',
                'function_name': 'withdraw'
            },
            'test_vault_pattern'
        )

        self.assertTrue(should_skip)

        # Test case 3: Should not filter non-matching vulnerability
        should_skip, reason = recognizer.should_skip_vulnerability(
            'reentrancy',
            {
                'code_snippet': 'manager.deposit(amount);',
                'function_name': 'deposit'
            },
            'test_vault_pattern'
        )

        self.assertFalse(should_skip)

    def test_real_world_centrifuge_pattern(self):
        """Test with real Centrifuge protocol contract names."""
        # Use default patterns (no custom config)
        recognizer = ArchitecturalPatternRecognizer()

        contract_files = [
            {'name': 'AsyncVault'},
            {'name': 'AsyncRequestManager'},
            {'name': 'BalanceSheet'},
            {'name': 'VaultRouter'}
        ]

        pattern = recognizer.detect_pattern(contract_files)
        self.assertEqual(pattern, 'vault_manager_separation')

        # Test that it would filter the actual false positives
        should_skip, reason = recognizer.should_skip_vulnerability(
            'unvalidated_external_call',
            {
                'code_snippet': 'shares = asyncManager().deposit(this, assets, receiver, controller);',
                'function_name': 'deposit'
            },
            pattern
        )

        self.assertTrue(should_skip)
        self.assertIn('Manager contracts perform their own validation', reason)

    def test_validation_rule_matching(self):
        """Test the validation rule matching logic."""
        recognizer = ArchitecturalPatternRecognizer(self.patterns_file)

        rule = recognizer.validation_rules['test_external_calls']

        # Should match vulnerability pattern
        self.assertTrue(recognizer._vulnerability_matches_rule(
            'external_call', {'code_snippet': 'test'}, rule
        ))

        # Should not match wrong vulnerability type
        self.assertFalse(recognizer._vulnerability_matches_rule(
            'reentrancy', {'code_snippet': 'test'}, rule
        ))

        # Should match code pattern
        self.assertTrue(recognizer._vulnerability_matches_rule(
            'external_call', {'code_snippet': 'manager.deposit(123);'}, rule
        ))

        # Should match function pattern
        self.assertTrue(recognizer._vulnerability_matches_rule(
            'external_call', {'function_name': 'withdraw'}, rule
        ))

    def test_pattern_descriptions(self):
        """Test pattern description retrieval."""
        recognizer = ArchitecturalPatternRecognizer(self.patterns_file)

        desc = recognizer.get_pattern_description('test_vault_pattern')
        self.assertEqual(desc, 'Test vault manager separation')

        desc = recognizer.get_pattern_description('nonexistent')
        self.assertEqual(desc, 'Unknown pattern')

    def test_trust_relationships(self):
        """Test trust relationship queries."""
        recognizer = ArchitecturalPatternRecognizer(self.patterns_file)

        relationships = recognizer.get_trust_relationships('test_vault_pattern')
        self.assertEqual(relationships['vault'], ['manager'])
        self.assertEqual(relationships['manager'], ['vault'])

        # Test trusted call checking
        self.assertTrue(recognizer.is_trusted_call('vault', 'manager', 'test_vault_pattern'))
        self.assertFalse(recognizer.is_trusted_call('vault', 'random', 'test_vault_pattern'))

    def test_contract_name_extraction(self):
        """Test contract name extraction from file paths."""
        recognizer = ArchitecturalPatternRecognizer()

        self.assertEqual(recognizer._extract_contract_name('/path/to/Contract.sol'), 'Contract.sol')
        self.assertEqual(recognizer._extract_contract_name('Contract.sol'), 'Contract.sol')


if __name__ == '__main__':
    unittest.main()
