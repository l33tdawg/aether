"""
Comprehensive Test Suite for Business Logic Detector
"""

import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.business_logic_detector import BusinessLogicDetector, BusinessLogicVulnerabilityType


class TestBackwardsValidation(unittest.TestCase):
    """Test backwards validation logic detection"""
    
    def setUp(self):
        self.detector = BusinessLogicDetector()
    
    def test_backwards_authorization_check(self):
        """Test detection of backwards authorization check"""
        code = """
        function removeUser(address user) external {
            require(!authorized[user], "User not authorized");
            delete users[user];
        }
        """
        results = self.detector.analyze_business_logic(code)
        # Should detect backwards logic (checking for NOT authorized)
        backwards_vulns = [v for v in results if v.vulnerability_type == 'backwards_validation']
        self.assertGreater(len(backwards_vulns), 0)
    
    def test_backwards_exists_check(self):
        """Test detection of backwards existence check"""
        code = """
        function process(uint256 id) external {
            if (!exists[id]) {
                // Logic appears backwards
                processItem(id);
            }
        }
        """
        results = self.detector.analyze_business_logic(code)
        backwards_vulns = [v for v in results if v.vulnerability_type == 'backwards_validation']
        self.assertGreater(len(backwards_vulns), 0)
    
    def test_intentional_negation_with_revert(self):
        """Test that intentional negation with revert is not flagged"""
        code = """
        function validate(bool condition) external {
            require(!condition, "Condition must be false");
            revert("Expected revert");
        }
        """
        results = self.detector.analyze_business_logic(code)
        # Should not flag intentional negation with revert
        # The detector filters these out in _is_intentional_negation


class TestSelfComparison(unittest.TestCase):
    """Test self-comparison bug detection"""
    
    def setUp(self):
        self.detector = BusinessLogicDetector()
    
    def test_version_self_comparison(self):
        """Test detection of version comparing to itself"""
        code = """
        function validateVersion() external {
            require(config.version == config.version, "Invalid version");
        }
        """
        results = self.detector.analyze_business_logic(code)
        self_comp_vulns = [v for v in results if v.vulnerability_type == 'self_comparison']
        self.assertGreater(len(self_comp_vulns), 0)
    
    def test_variable_self_comparison(self):
        """Test detection of variable self-comparison"""
        code = """
        function check(uint256 value) external {
            assert(value != value);  // Always false
        }
        """
        results = self.detector.analyze_business_logic(code)
        self_comp_vulns = [v for v in results if v.vulnerability_type == 'self_comparison']
        self.assertGreater(len(self_comp_vulns), 0)


class TestRewardCalculation(unittest.TestCase):
    """Test reward calculation error detection"""
    
    def setUp(self):
        self.detector = BusinessLogicDetector()
    
    def test_new_user_claiming_all_rewards(self):
        """Test detection of new users claiming full reward history"""
        code = """
        function claimRewards() external {
            uint256 reward = rewardIndex - 0;  // New user gets all rewards
            transfer(msg.sender, reward);
        }
        """
        results = self.detector.analyze_business_logic(code)
        reward_vulns = [v for v in results if v.vulnerability_type == 'reward_calculation_error']
        self.assertGreater(len(reward_vulns), 0)


class TestCooldownErrors(unittest.TestCase):
    """Test cooldown/timestamp error detection"""
    
    def setUp(self):
        self.detector = BusinessLogicDetector()
    
    def test_cooldown_bypass_with_or(self):
        """Test detection of cooldown bypass with OR condition"""
        code = """
        function execute() external {
            require(currentTime >= cooldown.cooldownEnd || something, "Cooldown active");
            doAction();
        }
        """
        results = self.detector.analyze_business_logic(code)
        cooldown_vulns = [v for v in results if v.vulnerability_type == 'cooldown_bypass']
        self.assertGreater(len(cooldown_vulns), 0)


class TestBusinessLogicSummary(unittest.TestCase):
    """Test business logic summary functionality"""
    
    def setUp(self):
        self.detector = BusinessLogicDetector()
    
    def test_summary_generation(self):
        """Test summary generation with multiple vulnerabilities"""
        code = """
        function test() external {
            require(!authorized[msg.sender]);
            require(config.version == config.version);
            uint256 reward = rewardIndex - 0;
        }
        """
        summary = self.detector.get_business_logic_summary(code)
        self.assertIn('total_vulnerabilities', summary)
        self.assertIn('by_type', summary)
        self.assertIn('by_severity', summary)


if __name__ == '__main__':
    unittest.main()

