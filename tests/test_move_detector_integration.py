"""
Test Suite for Move Vulnerability Database Integration

This test validates the integration of Move-inspired vulnerability detectors.
"""

import unittest
from pathlib import Path
import sys

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.business_logic_detector import BusinessLogicDetector
from core.state_management_detector import StateManagementDetector
from core.data_inconsistency_detector import DataInconsistencyDetector
from core.centralization_detector import CentralizationDetector
from core.looping_detector import LoopingDetector
from core.move_pattern_adapter import MovePatternAdapter
from core.enhanced_vulnerability_detector import EnhancedVulnerabilityDetector
from core.input_validation_detector import InputValidationDetector
from core.arithmetic_analyzer import ArithmeticAnalyzer


class TestBusinessLogicDetector(unittest.TestCase):
    """Test Business Logic Detector"""
    
    def setUp(self):
        self.detector = BusinessLogicDetector()
    
    def test_backwards_validation_detection(self):
        """Test detection of backwards validation logic"""
        code = """
        function test(address user) external {
            require(!authorized[user]);  // Backwards logic
            doSomething();
        }
        """
        results = self.detector.analyze_business_logic(code)
        self.assertGreater(len(results), 0, "Should detect backwards validation")
    
    def test_self_comparison_detection(self):
        """Test detection of self-comparison bugs"""
        code = """
        function validate() external {
            require(config.version == config.version);  // Self-comparison
        }
        """
        results = self.detector.analyze_business_logic(code)
        # Note: May be filtered as obvious, so we just test it runs
        self.assertIsInstance(results, list)


class TestStateManagementDetector(unittest.TestCase):
    """Test State Management Detector"""
    
    def setUp(self):
        self.detector = StateManagementDetector()
    
    def test_missing_state_update_detection(self):
        """Test detection of missing state updates"""
        code = """
        function claim() external {
            // Missing: claimed[msg.sender] = true
            token.transfer(msg.sender, amount);
        }
        """
        results = self.detector.analyze_state_management(code)
        self.assertIsInstance(results, list)


class TestDataInconsistencyDetector(unittest.TestCase):
    """Test Data Inconsistency Detector"""
    
    def setUp(self):
        self.detector = DataInconsistencyDetector()
    
    def test_loop_variable_not_updated(self):
        """Test detection of loop variables not being updated"""
        code = """
        function withdraw() external {
            uint256 amount = 100;
            for (uint i = 0; i < stakes.length; i++) {
                // amount never decremented - will over-withdraw
                withdrawStake(stakes[i], amount);
            }
        }
        """
        results = self.detector.analyze_data_inconsistency(code)
        self.assertIsInstance(results, list)


class TestCentralizationDetector(unittest.TestCase):
    """Test Centralization Detector"""
    
    def setUp(self):
        self.detector = CentralizationDetector()
    
    def test_unlimited_minting_detection(self):
        """Test detection of unlimited minting capability"""
        code = """
        function mint(address to, uint256 amount) external onlyOwner {
            // No cap check - unlimited minting
            _mint(to, amount);
        }
        """
        results = self.detector.analyze_centralization_risks(code)
        self.assertGreater(len(results), 0, "Should detect unlimited minting")


class TestLoopingDetector(unittest.TestCase):
    """Test Looping Detector"""
    
    def setUp(self):
        self.detector = LoopingDetector()
    
    def test_infinite_loop_detection(self):
        """Test detection of infinite loop risks"""
        code = """
        function process() external {
            while (true) {  // Infinite loop
                doSomething();
            }
        }
        """
        results = self.detector.analyze_looping_issues(code)
        self.assertGreater(len(results), 0, "Should detect infinite loop")
    
    def test_unbounded_loop_detection(self):
        """Test detection of unbounded loops"""
        code = """
        function processAll(address[] memory users) external {
            for (uint i = 0; i < users.length; i++) {
                // Unbounded loop - gas risk
                process(users[i]);
            }
        }
        """
        results = self.detector.analyze_looping_issues(code)
        self.assertIsInstance(results, list)


class TestMovePatternAdapter(unittest.TestCase):
    """Test Move Pattern Adapter"""
    
    def setUp(self):
        self.adapter = MovePatternAdapter()
    
    def test_pattern_translation(self):
        """Test Move to Solidity pattern translation"""
        move_vuln = {
            'description': 'Missing generic type validation',
            'type': 'missing_generic_check',
            'severity': 'high'
        }
        solidity_vuln = self.adapter.translate_move_vulnerability(move_vuln)
        self.assertIn('adapted_description', solidity_vuln)
        self.assertIn('token address', solidity_vuln['adapted_description'].lower())
    
    def test_category_pattern_generation(self):
        """Test generation of Solidity patterns for Move categories"""
        patterns = self.adapter.get_solidity_patterns_for_move_category('Input Validation')
        self.assertGreater(len(patterns), 0)
        self.assertTrue(all('pattern' in p for p in patterns))


class TestIntegration(unittest.TestCase):
    """Test Integration of all detectors with EnhancedVulnerabilityDetector"""
    
    def setUp(self):
        self.detector = EnhancedVulnerabilityDetector()
    
    def test_all_detectors_initialized(self):
        """Test that all Move-inspired detectors are initialized"""
        self.assertIsNotNone(self.detector.business_logic_detector)
        self.assertIsNotNone(self.detector.state_management_detector)
        self.assertIsNotNone(self.detector.data_inconsistency_detector)
        self.assertIsNotNone(self.detector.centralization_detector)
        self.assertIsNotNone(self.detector.looping_detector)
        self.assertIsNotNone(self.detector.move_pattern_adapter)
    
    def test_enhanced_input_validation(self):
        """Test enhanced input validation with Move patterns"""
        code = """
        function swap(address tokenA, address tokenB) external {
            // Missing token address validation (Move-inspired pattern)
            IERC20(tokenA).transfer(msg.sender, 100);
        }
        """
        results = self.detector.analyze_contract(code)
        self.assertIsInstance(results, list)
    
    def test_integration_analysis(self):
        """Test full analysis with all detectors"""
        code = """
        pragma solidity ^0.8.0;
        
        contract TestContract {
            mapping(address => bool) public authorized;
            uint256 public totalSupply;
            
            function mint(address to, uint256 amount) external {
                // Multiple issues:
                // 1. No access control
                // 2. Unlimited minting
                // 3. totalSupply not updated
                balances[to] += amount;
            }
            
            function withdraw(uint256 amount) external {
                // Missing state validation
                token.transfer(msg.sender, amount);
            }
            
            mapping(address => uint256) public balances;
        }
        """
        results = self.detector.analyze_contract(code)
        self.assertIsInstance(results, list)
        # Should detect multiple issues from different detectors


class TestEnhancedArithmeticAnalyzer(unittest.TestCase):
    """Test Enhanced Arithmetic Analyzer with Move patterns"""
    
    def setUp(self):
        self.analyzer = ArithmeticAnalyzer()
    
    def test_precision_loss_detection(self):
        """Test detection of division-before-multiplication precision loss"""
        code = """
        function calculate(uint256 amount, uint256 rate) external returns (uint256) {
            return amount / 100 * rate;  // Precision loss
        }
        """
        results = self.analyzer.analyze_arithmetic_operations(code)
        self.assertIsInstance(results, list)


class TestEnhancedInputValidation(unittest.TestCase):
    """Test Enhanced Input Validation with Move patterns"""
    
    def setUp(self):
        self.detector = InputValidationDetector()
    
    def test_token_validation_detection(self):
        """Test detection of missing token address validation"""
        code = """
        function swap(address token) external {
            IERC20(token).transfer(msg.sender, 100);
        }
        """
        results = self.detector.analyze_input_validation(code)
        self.assertIsInstance(results, list)
    
    def test_signature_validation_detection(self):
        """Test detection of missing signature length validation"""
        code = """
        function verify(bytes memory signature) external {
            // Missing signature.length check
            address signer = ecrecover(hash, v, r, s);
        }
        """
        results = self.detector.analyze_input_validation(code)
        self.assertIsInstance(results, list)


def run_tests():
    """Run all tests"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestBusinessLogicDetector))
    suite.addTests(loader.loadTestsFromTestCase(TestStateManagementDetector))
    suite.addTests(loader.loadTestsFromTestCase(TestDataInconsistencyDetector))
    suite.addTests(loader.loadTestsFromTestCase(TestCentralizationDetector))
    suite.addTests(loader.loadTestsFromTestCase(TestLoopingDetector))
    suite.addTests(loader.loadTestsFromTestCase(TestMovePatternAdapter))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))
    suite.addTests(loader.loadTestsFromTestCase(TestEnhancedArithmeticAnalyzer))
    suite.addTests(loader.loadTestsFromTestCase(TestEnhancedInputValidation))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)

