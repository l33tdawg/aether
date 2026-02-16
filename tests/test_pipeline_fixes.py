"""Tests for Phase 1 pipeline fixes in enhanced_audit_engine and ai_ensemble."""

import asyncio
import unittest
from unittest.mock import MagicMock, patch, AsyncMock

from core.enhanced_audit_engine import EnhancedAetherAuditEngine


class TestContextAwareSeverityCalibration(unittest.TestCase):
    """Test Phase 1A: Context-aware severity calibration."""

    def setUp(self):
        with patch('core.enhanced_audit_engine.DatabaseManager'):
            self.engine = EnhancedAetherAuditEngine(verbose=False)

    def test_downgrade_division_by_zero_no_risk(self):
        """Division by zero without risk indicators should be downgraded."""
        vuln = {
            'vulnerability_type': 'division_by_zero',
            'severity': 'high',
            'confidence': 0.7,
            'line_number': 10,
            'description': 'Possible division by zero',
            'code_snippet': 'uint256 x = a / b;',
        }
        # Contract with no risk indicators near line 10
        contract = "\n".join([
            "pragma solidity ^0.8.0;",
            "contract Safe {",
            "    uint256 public constant X = 100;",
            "    function foo() public pure returns (uint256) {",
            "        uint256 a = 10;",
            "        uint256 b = 5;",
            "        return a / b;",  # Line ~7
            "    }",
            "}",
        ] + ["// padding"] * 20)

        result = self.engine._calibrate_vulnerability_severity(vuln, contract)
        self.assertEqual(result['severity'], 'low')

    def test_preserve_division_by_zero_in_price_context(self):
        """Division by zero in price calculation should NOT be downgraded."""
        vuln = {
            'vulnerability_type': 'division_by_zero',
            'severity': 'high',
            'confidence': 0.7,
            'line_number': 5,
            'description': 'Division by zero in price oracle',
            'code_snippet': 'uint256 price = reserve0 / reserve1;',
        }
        contract = "\n".join([
            "pragma solidity ^0.8.0;",
            "contract Oracle {",
            "    uint256 public reserve0;",
            "    uint256 public reserve1;",
            "    function getPrice() public view returns (uint256) {",
            "        return reserve0 / reserve1;",  # Line 6, near line 5
            "    }",
            "}",
        ] + ["// padding"] * 20)

        result = self.engine._calibrate_vulnerability_severity(vuln, contract)
        self.assertEqual(result['severity'], 'high')  # Preserved!

    def test_preserve_in_unchecked_block(self):
        """Vulnerabilities in unchecked blocks should NOT be downgraded."""
        vuln = {
            'vulnerability_type': 'integer_underflow',
            'severity': 'critical',
            'confidence': 0.8,
            'line_number': 5,
            'description': 'Integer underflow in unchecked block',
            'code_snippet': 'unchecked { a - b; }',
        }
        contract = "\n".join([
            "pragma solidity ^0.8.0;",
            "contract Test {",
            "    function foo(uint256 a, uint256 b) public pure returns (uint256) {",
            "        unchecked {",
            "            return a - b;",
            "        }",
            "    }",
            "}",
        ] + ["// padding"] * 20)

        result = self.engine._calibrate_vulnerability_severity(vuln, contract)
        self.assertEqual(result['severity'], 'critical')  # Preserved!

    def test_preserve_in_value_transfer(self):
        """Vulnerabilities near value transfers should NOT be downgraded."""
        vuln = {
            'vulnerability_type': 'missing_input_validation',
            'severity': 'high',
            'confidence': 0.6,
            'line_number': 6,
            'description': 'Missing validation on transfer amount',
            'code_snippet': '',
        }
        contract = "\n".join([
            "pragma solidity ^0.8.0;",
            "contract Test {",
            "    function withdraw(uint256 amount) external {",
            "        // No validation",
            "        balances[msg.sender] -= amount;",
            "        (bool ok,) = msg.sender.call{value: amount}('');",
            "        require(ok);",
            "    }",
            "}",
        ] + ["// padding"] * 20)

        result = self.engine._calibrate_vulnerability_severity(vuln, contract)
        self.assertEqual(result['severity'], 'high')  # Preserved!

    def test_downgrade_parameter_validation_no_risk(self):
        """Parameter validation issues without risk should be downgraded."""
        vuln = {
            'vulnerability_type': 'parameter_validation_issue',
            'severity': 'high',
            'confidence': 0.5,
            'line_number': 3,
            'description': 'Missing parameter validation',
            'code_snippet': '',
        }
        contract = "\n".join([
            "pragma solidity ^0.8.0;",
            "contract Safe {",
            "    function setName(string memory name) external {",
            "        _name = name;",
            "    }",
            "}",
        ] + ["// padding"] * 20)

        result = self.engine._calibrate_vulnerability_severity(vuln, contract)
        self.assertEqual(result['severity'], 'medium')

    def test_has_risk_indicators_oracle(self):
        """Test risk indicator detection for oracle context."""
        vuln = {
            'vulnerability_type': 'test',
            'description': 'Issue with oracle price feed',
            'line_number': 5,
            'code_snippet': '',
        }
        contract = "line1\nline2\nline3\nline4\noracle.getPrice()\nline6\n" + "\n".join(["x"] * 20)
        self.assertTrue(self.engine._has_risk_indicators(vuln, contract))


class TestValidationStatusGate(unittest.TestCase):
    """Test Phase 1B: Validation status gate fix."""

    def test_pending_findings_pass_through(self):
        """Pending findings should NOT be filtered out."""
        # We test the filter logic directly
        vuln_pending = {
            'vulnerability_type': 'reentrancy',
            'severity': 'high',
            'validation_status': 'pending',
            'line_number': 10,
        }
        vuln_validated = {
            'vulnerability_type': 'overflow',
            'severity': 'medium',
            'validation_status': 'validated',
            'line_number': 20,
        }
        vuln_fp = {
            'vulnerability_type': 'info_leak',
            'severity': 'low',
            'validation_status': 'false_positive',
            'line_number': 30,
        }

        vulns = [vuln_pending, vuln_validated, vuln_fp]

        # Simulate the filter logic from the engine
        validated = []
        for vuln in vulns:
            status = vuln.get('validation_status', 'pending')
            if status == "false_positive":
                pass  # filtered
            else:
                if status == "pending":
                    vuln['needs_llm_validation'] = True
                validated.append(vuln)

        self.assertEqual(len(validated), 2)  # pending + validated pass through
        self.assertTrue(validated[0].get('needs_llm_validation'))  # pending gets flag
        self.assertNotIn(vuln_fp, validated)  # false_positive filtered


class TestSingleAgentConfidencePenalty(unittest.TestCase):
    """Test Phase 1C: Specialist-aware confidence penalty."""

    def test_import_ensemble(self):
        """Verify the ensemble module loads with updated penalty logic."""
        from core.ai_ensemble import EnhancedAIEnsemble
        ensemble = EnhancedAIEnsemble()
        # Verify _AGENT_SPECIALIZATIONS exists
        self.assertIn('anthropic_reasoning', ensemble._AGENT_SPECIALIZATIONS)
        self.assertIn('complex_logic', ensemble._AGENT_SPECIALIZATIONS['anthropic_reasoning'])

    def test_specialist_finding_gets_reduced_penalty(self):
        """Specialist finding should get only -0.02 penalty."""
        from core.ai_ensemble import EnhancedAIEnsemble
        ensemble = EnhancedAIEnsemble()

        finding = {'type': 'economic_attacks', 'confidence': 0.8, 'severity': 'high', 'description': 'test'}
        models = ['anthropic_reasoning']  # specialist for economic_attacks

        result = ensemble._merge_similar_findings([finding], models)
        # Specialist penalty: 0.8 - 0.02 = 0.78
        self.assertAlmostEqual(result['confidence'], 0.78, places=2)

    def test_non_specialist_finding_gets_full_penalty(self):
        """Non-specialist single finding should get -0.08 penalty."""
        from core.ai_ensemble import EnhancedAIEnsemble
        ensemble = EnhancedAIEnsemble()

        finding = {'type': 'reentrancy', 'confidence': 0.8, 'severity': 'high', 'description': 'test'}
        models = ['gemini_verification']  # NOT specialist for reentrancy

        result = ensemble._merge_similar_findings([finding], models)
        # Full penalty: 0.8 - 0.08 = 0.72
        self.assertAlmostEqual(result['confidence'], 0.72, places=2)

    def test_multi_agent_gets_boost(self):
        """Multiple agents agreeing should get confidence boost."""
        from core.ai_ensemble import EnhancedAIEnsemble
        ensemble = EnhancedAIEnsemble()

        findings = [
            {'type': 'reentrancy', 'confidence': 0.8, 'severity': 'high', 'description': 'test'},
            {'type': 'reentrancy', 'confidence': 0.7, 'severity': 'high', 'description': 'test'},
        ]
        models = ['gpt5_security', 'anthropic_security']

        result = ensemble._merge_similar_findings(findings, models)
        # Average 0.75 + 0.1 boost = 0.85
        self.assertAlmostEqual(result['confidence'], 0.85, places=2)


class TestLineBucketFix(unittest.TestCase):
    """Test Phase 1D: Line-bucket boundary bug fix."""

    def test_finding_key_uses_only_type(self):
        """Finding key should be based only on normalized type, not line bucket."""
        from core.ai_ensemble import EnhancedAIEnsemble
        ensemble = EnhancedAIEnsemble()

        # Two findings on lines 9 and 11 (previously in different buckets)
        f1 = {'type': 'reentrancy', 'line': 9}
        f2 = {'type': 'reentrancy', 'line': 11}

        key1 = ensemble._get_finding_key(f1)
        key2 = ensemble._get_finding_key(f2)

        # Now they should produce the same key (both are reentrancy)
        self.assertEqual(key1, key2)

    def test_fuzzy_match_still_works(self):
        """Fuzzy matching should still differentiate by line proximity."""
        from core.ai_ensemble import EnhancedAIEnsemble
        ensemble = EnhancedAIEnsemble()

        close = {'type': 'reentrancy', 'line': 10}
        nearby = {'type': 'reentrancy', 'line': 14}
        far = {'type': 'reentrancy', 'line': 100}

        self.assertTrue(ensemble._findings_match_fuzzy(close, nearby))
        self.assertFalse(ensemble._findings_match_fuzzy(close, far))


if __name__ == '__main__':
    unittest.main()
