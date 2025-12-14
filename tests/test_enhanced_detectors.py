"""
Comprehensive test suite for enhanced vulnerability detectors.

This module tests all the new analyzers implemented in the tool improvement plan:
- ArithmeticAnalyzer
- MathExpressionParser
- VariableDependencyTracker
- ExternalTrustAnalyzer
- ContractInterfaceValidator
- InputValidationDetector
- DataDecodingAnalyzer
- PrecisionAnalyzer
- GasAnalyzer
"""

import unittest
import sys
import os
from typing import List, Dict, Any

# Add the project root to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.arithmetic_analyzer import ArithmeticAnalyzer, VulnerabilityType
from core.math_expression_parser import MathExpressionParser
from core.variable_dependency_tracker import VariableDependencyTracker
from core.external_trust_analyzer import ExternalTrustAnalyzer
from core.contract_interface_validator import ContractInterfaceValidator
from core.input_validation_detector import InputValidationDetector
from core.data_decoding_analyzer import DataDecodingAnalyzer
from core.precision_analyzer import PrecisionAnalyzer
from core.gas_analyzer import GasAnalyzer
from core.enhanced_vulnerability_detector import EnhancedVulnerabilityDetector


class TestArithmeticAnalyzer(unittest.TestCase):
    """Test cases for ArithmeticAnalyzer."""
    
    def setUp(self):
        self.analyzer = ArithmeticAnalyzer()
    
    def test_overflow_detection(self):
        """Test integer overflow detection."""
        contract = """
        contract Test {
            function testOverflow(uint256 a, uint256 b) public {
                uint256 result = a * b;  // Potential overflow
                return result;
            }
        }
        """
        
        vulnerabilities = self.analyzer.analyze_arithmetic_operations(contract)
        
        # Should detect multiplication overflow
        overflow_vulns = [v for v in vulnerabilities if v.vulnerability_type == VulnerabilityType.INTEGER_OVERFLOW]
        self.assertGreater(len(overflow_vulns), 0)
        
        # Check severity and confidence
        self.assertEqual(overflow_vulns[0].severity, 'high')
        self.assertGreater(overflow_vulns[0].confidence, 0.5)
    
    def test_underflow_detection(self):
        """Test integer underflow detection."""
        contract = """
        contract Test {
            function testUnderflow(uint256 a, uint256 b) public {
                uint256 result = a - b;  // Potential underflow
                return result;
            }
        }
        """
        
        vulnerabilities = self.analyzer.analyze_arithmetic_operations(contract)
        
        # Should detect subtraction underflow
        underflow_vulns = [v for v in vulnerabilities if v.vulnerability_type == VulnerabilityType.INTEGER_UNDERFLOW]
        self.assertGreater(len(underflow_vulns), 0)
    
    def test_division_by_zero(self):
        """Test division by zero detection."""
        contract = """
        contract Test {
            function testDivision(uint256 a, uint256 b) public {
                uint256 result = a / b;  // Potential division by zero
                return result;
            }
        }
        """
        
        vulnerabilities = self.analyzer.analyze_arithmetic_operations(contract)
        
        # Should detect division by zero
        division_vulns = [v for v in vulnerabilities if v.vulnerability_type == VulnerabilityType.DIVISION_BY_ZERO]
        self.assertGreater(len(division_vulns), 0)
    
    def test_false_positive_filtering(self):
        """Test false positive filtering."""
        contract = """
        contract Test {
            using SafeMath for uint256;
            
            function testSafeMath(uint256 a, uint256 b) public {
                uint256 result = a.mul(b);  // SafeMath prevents overflow
                return result;
            }
        }
        """
        
        vulnerabilities = self.analyzer.analyze_arithmetic_operations(contract)
        
        # Should not detect vulnerabilities when using SafeMath
        self.assertEqual(len(vulnerabilities), 0)


class TestMathExpressionParser(unittest.TestCase):
    """Test cases for MathExpressionParser."""
    
    def setUp(self):
        self.parser = MathExpressionParser()
    
    def test_expression_parsing(self):
        """Test mathematical expression parsing."""
        expression = "a + b * c"
        tree = self.parser.parse_expression(expression, 1)
        
        self.assertIsNotNone(tree.root)
        self.assertIn('a', tree.variables)
        self.assertIn('b', tree.variables)
        self.assertIn('c', tree.variables)
        self.assertIn('+', tree.operators)
        self.assertIn('*', tree.operators)
    
    def test_vulnerability_analysis(self):
        """Test expression vulnerability analysis."""
        tree = self.parser.parse_expression("a * b", 1)
        vulnerabilities = self.parser.analyze_expression_vulnerabilities(tree)
        
        # Should detect overflow risk for multiplication
        overflow_vulns = [v for v in vulnerabilities if v['type'] == 'overflow_risk']
        self.assertGreater(len(overflow_vulns), 0)
    
    def test_complex_expression(self):
        """Test complex expression analysis."""
        expression = "(a - b) * c / d"
        tree = self.parser.parse_expression(expression, 1)
        
        # Should have high complexity score
        self.assertGreater(tree.complexity_score, 0.5)


class TestVariableDependencyTracker(unittest.TestCase):
    """Test cases for VariableDependencyTracker."""
    
    def setUp(self):
        self.tracker = VariableDependencyTracker()
    
    def test_dependency_tracking(self):
        """Test variable dependency tracking."""
        contract = """
        contract Test {
            uint256 public totalSupply;
            uint256 public balance;
            
            function updateBalance(uint256 amount) public {
                balance = amount;
                totalSupply = totalSupply + balance;
            }
        }
        """
        
        graph = self.tracker.track_variable_dependencies(contract)
        
        # Should track variables
        self.assertIn('totalSupply', graph.variables)
        self.assertIn('balance', graph.variables)
        
        # Should track dependencies
        self.assertGreater(len(graph.dependencies), 0)
    
    def test_cycle_detection(self):
        """Test dependency cycle detection."""
        contract = """
        contract Test {
            uint256 a;
            uint256 b;
            
            function test() public {
                a = b + 1;
                b = a + 1;  // Creates cycle
            }
        }
        """
        
        graph = self.tracker.track_variable_dependencies(contract)
        
        # Should detect cycles
        self.assertGreater(len(graph.cycles), 0)


class TestExternalTrustAnalyzer(unittest.TestCase):
    """Test cases for ExternalTrustAnalyzer."""
    
    def setUp(self):
        self.analyzer = ExternalTrustAnalyzer()
    
    def test_unvalidated_external_calls(self):
        """Test unvalidated external call detection."""
        contract = """
        contract Test {
            function callExternal(address target) public {
                target.call("");  // Unvalidated external call
            }
        }
        """
        
        vulnerabilities = self.analyzer.analyze_external_dependencies(contract)
        
        # Should detect unvalidated external call
        unvalidated_vulns = [v for v in vulnerabilities if v.vulnerability_type == 'unvalidated_external_call']
        self.assertGreater(len(unvalidated_vulns), 0)
    
    def test_delegate_call_vulnerability(self):
        """Test delegate call vulnerability detection."""
        contract = """
        contract Test {
            function delegateCall(address target) public {
                target.delegatecall("");  // Dangerous delegate call
            }
        }
        """
        
        vulnerabilities = self.analyzer.analyze_external_dependencies(contract)
        
        # Should detect delegate call vulnerability
        delegate_vulns = [v for v in vulnerabilities if v.vulnerability_type == 'delegate_call_vulnerability']
        self.assertGreater(len(delegate_vulns), 0)
        self.assertEqual(delegate_vulns[0].severity, 'critical')


class TestContractInterfaceValidator(unittest.TestCase):
    """Test cases for ContractInterfaceValidator."""
    
    def setUp(self):
        self.validator = ContractInterfaceValidator()
    
    def test_erc20_interface_validation(self):
        """Test ERC20 interface validation."""
        contract = """
        interface IERC20 {
            function totalSupply() external view returns (uint256);
            function balanceOf(address account) external view returns (uint256);
            function transfer(address to, uint256 amount) external returns (bool);
        }
        """
        
        validations = self.validator.validate_external_interfaces(contract)
        
        # Should validate ERC20 interface
        self.assertGreater(len(validations), 0)
    
    def test_interface_mismatch_detection(self):
        """Test interface mismatch detection."""
        contract = """
        contract Test {
            IERC20 token;
            
            function callToken() public {
                token.nonExistentFunction();  // Interface mismatch
            }
        }
        """
        
        mismatches = self.validator.detect_interface_mismatches(contract)
        
        # Should detect interface mismatch
        self.assertGreater(len(mismatches), 0)


class TestInputValidationDetector(unittest.TestCase):
    """Test cases for InputValidationDetector."""
    
    def setUp(self):
        self.detector = InputValidationDetector()
    
    def test_missing_input_validation(self):
        """Test missing input validation detection."""
        contract = """
        contract Test {
            function transfer(address to, uint256 amount) public {
                // Missing input validation
                _transfer(msg.sender, to, amount);
            }
        }
        """
        
        vulnerabilities = self.detector.analyze_input_validation(contract)
        
        # Should detect missing input validation
        validation_vulns = [v for v in vulnerabilities if v.vulnerability_type == 'missing_input_validation']
        self.assertGreater(len(validation_vulns), 0)
    
    def test_bounds_checking_issues(self):
        """Test bounds checking issue detection."""
        contract = """
        contract Test {
            uint256[] public balances;
            
            function getBalance(uint256 index) public view returns (uint256) {
                return balances[index];  // No bounds checking
            }
        }
        """
        
        vulnerabilities = self.detector.analyze_input_validation(contract)
        
        # Should detect bounds checking issues
        bounds_vulns = [v for v in vulnerabilities if v.vulnerability_type == 'bounds_checking_issue']
        self.assertGreater(len(bounds_vulns), 0)


class TestDataDecodingAnalyzer(unittest.TestCase):
    """Test cases for DataDecodingAnalyzer."""
    
    def setUp(self):
        self.analyzer = DataDecodingAnalyzer()
    
    def test_malformed_input_handling(self):
        """Test malformed input handling detection."""
        contract = """
        contract Test {
            function decodeData(bytes memory data) public {
                (uint256 value) = abi.decode(data, (uint256));  // No validation
            }
        }
        """
        
        vulnerabilities = self.analyzer.analyze_decoding_operations(contract)
        
        # Should detect malformed input handling
        malformed_vulns = [v for v in vulnerabilities if v.vulnerability_type == 'malformed_input_handling']
        self.assertGreater(len(malformed_vulns), 0)
    
    def test_msg_data_decoding(self):
        """Test msg.data decoding vulnerability detection."""
        contract = """
        contract Test {
            function processData() public {
                uint256 value = abi.decode(msg.data[4:], (uint256));  // Direct msg.data decoding
            }
        }
        """
        
        vulnerabilities = self.analyzer.analyze_decoding_operations(contract)
        
        # Should detect direct msg.data decoding
        msg_data_vulns = [v for v in vulnerabilities if v.vulnerability_type == 'unvalidated_decoding']
        self.assertGreater(len(msg_data_vulns), 0)


class TestPrecisionAnalyzer(unittest.TestCase):
    """Test cases for PrecisionAnalyzer."""
    
    def setUp(self):
        self.analyzer = PrecisionAnalyzer()
    
    def test_precision_loss_detection(self):
        """Test precision loss detection."""
        contract = """
        contract Test {
            function calculate(uint256 a, uint256 b) public {
                uint256 result = a / b;  // Potential precision loss
            }
        }
        """
        
        vulnerabilities = self.analyzer.analyze_precision_loss(contract)
        
        # Should detect precision loss
        precision_vulns = [v for v in vulnerabilities if v.vulnerability_type == 'precision_loss_division']
        self.assertGreater(len(precision_vulns), 0)
    
    def test_rounding_error_detection(self):
        """Test rounding error detection."""
        contract = """
        contract Test {
            function calculate(uint256 a, uint256 b, uint256 c) public {
                uint256 result = a / b * c;  // Potential rounding error
            }
        }
        """
        
        vulnerabilities = self.analyzer.analyze_precision_loss(contract)
        
        # Should detect rounding errors
        rounding_vulns = [v for v in vulnerabilities if v.vulnerability_type == 'rounding_error']
        self.assertGreater(len(rounding_vulns), 0)


class TestGasAnalyzer(unittest.TestCase):
    """Test cases for GasAnalyzer."""
    
    def setUp(self):
        self.analyzer = GasAnalyzer()
    
    def test_unlimited_gas_calls(self):
        """Test unlimited gas call detection."""
        contract = """
        contract Test {
            function callExternal(address target) public {
                target.call("");  // No gas limit
            }
        }
        """
        
        vulnerabilities = self.analyzer.analyze_gas_consumption(contract)
        
        # Should detect unlimited gas calls
        gas_vulns = [v for v in vulnerabilities if v.vulnerability_type == 'unlimited_gas_call']
        self.assertGreater(len(gas_vulns), 0)
    
    def test_loop_gas_issues(self):
        """Test loop gas consumption issues."""
        contract = """
        contract Test {
            uint256[] public data;
            
            function processAll() public {
                for (uint256 i = 0; i < data.length; i++) {  // Potential gas issue
                    data[i] = data[i] + 1;
                }
            }
        }
        """
        
        vulnerabilities = self.analyzer.analyze_gas_consumption(contract)
        
        # Should detect loop gas issues
        loop_vulns = [v for v in vulnerabilities if v.vulnerability_type == 'loop_gas_issue']
        self.assertGreater(len(loop_vulns), 0)


class TestEnhancedVulnerabilityDetector(unittest.TestCase):
    """Test cases for EnhancedVulnerabilityDetector integration."""
    
    def setUp(self):
        self.detector = EnhancedVulnerabilityDetector()
    
    def test_integrated_analysis(self):
        """Test integrated analysis with all new detectors."""
        contract = """
        contract Test {
            uint256 public totalSupply;
            
            function transfer(address to, uint256 amount) public {
                totalSupply = totalSupply - amount;  // Potential underflow
                // Missing input validation
            }
            
            function callExternal(address target) public {
                target.call("");  // Unvalidated external call
            }
            
            function decodeData(bytes memory data) public {
                (uint256 value) = abi.decode(data, (uint256));  // No validation
            }
        }
        """
        
        vulnerabilities = self.detector.analyze_contract(contract)
        
        # Should detect multiple types of vulnerabilities
        vuln_types = {v.vulnerability_type for v in vulnerabilities}
        
        # Should include new vulnerability types
        expected_types = {'integer_underflow', 'missing_input_validation', 'unvalidated_external_call', 'malformed_input_handling'}
        self.assertTrue(expected_types.intersection(vuln_types))
    
    def test_vulnerability_conversion(self):
        """Test vulnerability format conversion."""
        contract = """
        contract Test {
            function test(uint256 a, uint256 b) public {
                uint256 result = a * b;  // Arithmetic vulnerability
            }
        }
        """
        
        vulnerabilities = self.detector.analyze_contract(contract)
        
        # All vulnerabilities should be in standard format
        for vuln in vulnerabilities:
            self.assertIsNotNone(vuln.vulnerability_type)
            self.assertIsNotNone(vuln.severity)
            self.assertIsNotNone(vuln.confidence)
            self.assertIsNotNone(vuln.line_number)
            self.assertIsNotNone(vuln.description)
            self.assertIsNotNone(vuln.code_snippet)


class TestPerformance(unittest.TestCase):
    """Performance tests for the enhanced detectors."""
    
    def setUp(self):
        self.detector = EnhancedVulnerabilityDetector()
    
    def test_large_contract_analysis(self):
        """Test analysis performance on large contracts."""
        # Generate a large contract for testing
        large_contract = self._generate_large_contract(1000)  # 1000 lines
        
        import time
        start_time = time.time()
        
        vulnerabilities = self.detector.analyze_contract(large_contract)
        
        end_time = time.time()
        analysis_time = end_time - start_time
        
        # Should complete analysis within reasonable time (< 30 seconds)
        self.assertLess(analysis_time, 30)
        
        # Should detect vulnerabilities
        self.assertGreater(len(vulnerabilities), 0)
    
    def _generate_large_contract(self, lines: int) -> str:
        """Generate a large contract for testing."""
        # Note: Use 'func' prefix instead of 'test' to avoid Foundry test pattern filtering
        contract = "contract LargeContract {\n"

        for i in range(lines):
            if i % 10 == 0:
                contract += f"    function process{i}() public {{\n"
                contract += f"        uint256 a = {i};\n"
                contract += f"        uint256 b = a * 2;  // Potential overflow\n"
                contract += f"        uint256 c = a / b;  // Potential division by zero\n"
                contract += f"    }}\n"
            else:
                contract += f"    uint256 var{i} = {i};\n"

        contract += "}\n"
        return contract


class TestShipmentPlannerVulnerabilities(unittest.TestCase):
    """Test cases based on ShipmentPlanner contract vulnerabilities."""
    
    def setUp(self):
        self.detector = EnhancedVulnerabilityDetector()
    
    def test_shipment_planner_arithmetic(self):
        """Test arithmetic vulnerabilities from ShipmentPlanner."""
        contract = """
        contract ShipmentPlanner {
            uint256 public maxBeanPerField;
            
            function getPaybackFieldPlan(uint256 fieldId) public view returns (ShipmentPlan memory) {
                uint256 cap = min(beanstalk.totalUnharvestable(fieldId), maxBeanPerField);
                uint256 result = beanstalk.totalUnharvestable(fieldId) * 2;  // Potential overflow
                uint256 division = result / 3;  // Potential precision loss
                // ... other code ...
                return ShipmentPlan({
                    beanAmount: beanstalk.totalUnharvestable(fieldId),  // Should return cap
                    // ... other fields ...
                });
            }
            
            function calculate(uint256 a, uint256 b) public pure returns (uint256) {
                return a / b;  // Division by zero risk
            }
        }
        """
        
        vulnerabilities = self.detector.analyze_contract(contract)
        
        # Should detect arithmetic and logic issues
        arithmetic_vulns = [v for v in vulnerabilities if 'arithmetic' in v.category or 'logic' in v.category]
        self.assertGreater(len(arithmetic_vulns), 0)
    
    def test_shipment_planner_external_calls(self):
        """Test external call vulnerabilities from ShipmentPlanner."""
        contract = """
        contract ShipmentPlanner {
            function checkPaybackContract(address paybackContract) public view returns (bool) {
                return paybackContract.staticcall("");  // No gas limit
            }
        }
        """
        
        vulnerabilities = self.detector.analyze_contract(contract)
        
        # Should detect external call issues
        external_vulns = [v for v in vulnerabilities if 'external' in v.category or 'gas' in v.category]
        self.assertGreater(len(external_vulns), 0)


if __name__ == '__main__':
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test classes
    test_classes = [
        TestArithmeticAnalyzer,
        TestMathExpressionParser,
        TestVariableDependencyTracker,
        TestExternalTrustAnalyzer,
        TestContractInterfaceValidator,
        TestInputValidationDetector,
        TestDataDecodingAnalyzer,
        TestPrecisionAnalyzer,
        TestGasAnalyzer,
        TestEnhancedVulnerabilityDetector,
        TestPerformance,
        TestShipmentPlannerVulnerabilities
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Print summary
    print(f"\n{'='*50}")
    print(f"Test Summary:")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success rate: {((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100):.1f}%")
    print(f"{'='*50}")
    
    if result.failures:
        print("\nFailures:")
        for test, traceback in result.failures:
            print(f"- {test}: {traceback}")
    
    if result.errors:
        print("\nErrors:")
        for test, traceback in result.errors:
            print(f"- {test}: {traceback}")
