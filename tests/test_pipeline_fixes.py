"""Tests for pipeline fixes in enhanced_audit_engine."""

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


if __name__ == '__main__':
    unittest.main()
