"""
Comprehensive Test Suite for Looping Detector
"""

import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.looping_detector import LoopingDetector


class TestInfiniteLoops(unittest.TestCase):
    """Test infinite loop detection"""
    
    def setUp(self):
        self.detector = LoopingDetector()
    
    def test_while_true_loop(self):
        """Test detection of while(true) loop"""
        code = """
        function process() external {
            while (true) {
                doSomething();
            }
        }
        """
        results = self.detector.analyze_looping_issues(code)
        infinite_vulns = [v for v in results if v.vulnerability_type == 'infinite_loop_risk']
        self.assertGreater(len(infinite_vulns), 0)
    
    def test_infinite_for_loop(self):
        """Test detection of infinite for loop"""
        code = """
        function process() external {
            for (;;) {
                doSomething();
            }
        }
        """
        results = self.detector.analyze_looping_issues(code)
        infinite_vulns = [v for v in results if v.vulnerability_type == 'infinite_loop_risk']
        self.assertGreater(len(infinite_vulns), 0)


class TestTerminationConditions(unittest.TestCase):
    """Test loop termination condition detection"""
    
    def setUp(self):
        self.detector = LoopingDetector()
    
    def test_while_loop_variable_not_decremented(self):
        """Test detection of while loop variable never decremented"""
        code = """
        function process() external {
            uint256 count = 10;
            while (count > 0) {
                // count never decremented - infinite loop
                doSomething();
            }
        }
        """
        results = self.detector.analyze_looping_issues(code)
        termination_vulns = [v for v in results if v.vulnerability_type == 'termination_condition_error']
        self.assertGreater(len(termination_vulns), 0)


class TestUnboundedLoops(unittest.TestCase):
    """Test unbounded loop detection"""
    
    def setUp(self):
        self.detector = LoopingDetector()
    
    def test_unbounded_array_loop(self):
        """Test detection of unbounded array loop"""
        code = """
        function processUsers(address[] memory users) external {
            for (uint i = 0; i < users.length; i++) {
                // No length cap - gas risk
                process(users[i]);
            }
        }
        """
        results = self.detector.analyze_looping_issues(code)
        unbounded_vulns = [v for v in results if v.vulnerability_type == 'unbounded_loop']
        self.assertGreater(len(unbounded_vulns), 0)


class TestNestedLoops(unittest.TestCase):
    """Test nested unbounded loop detection"""
    
    def setUp(self):
        self.detector = LoopingDetector()
    
    def test_nested_unbounded_loops(self):
        """Test detection of nested unbounded loops"""
        code = """
        function processAll(uint256[] memory items1, uint256[] memory items2) external {
            for (uint i = 0; i < items1.length; i++) {
                for (uint j = 0; j < items2.length; j++) {
                    // Nested unbounded - high gas risk
                    process(items1[i], items2[j]);
                }
            }
        }
        """
        results = self.detector.analyze_looping_issues(code)
        nested_vulns = [v for v in results if v.vulnerability_type == 'nested_unbounded_loops']
        self.assertGreater(len(nested_vulns), 0)


class TestLoopingSummary(unittest.TestCase):
    """Test looping summary"""
    
    def setUp(self):
        self.detector = LoopingDetector()
    
    def test_summary_generation(self):
        """Test summary generation"""
        code = """
        function test() external {
            while (true) { break; }
        }
        """
        summary = self.detector.get_looping_summary(code)
        self.assertIn('total_vulnerabilities', summary)
        self.assertIn('by_type', summary)
        self.assertIn('by_severity', summary)


if __name__ == '__main__':
    unittest.main()

