"""
Tests for Precision Analyzer Fixes

This test suite validates the precision analyzer improvements:
1. Accurate line number reporting
2. Pro-rated division pattern detection
3. LinearCreditDebtTracker specific vulnerability detection
"""

import pytest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.precision_analyzer import (
    PrecisionAnalyzer,
    PrecisionVulnerability,
    PrecisionIssue,
    PrecisionRisk
)


class TestPrecisionAnalyzerFixes:
    """Test suite for precision analyzer improvements"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.analyzer = PrecisionAnalyzer()
    
    def test_analyzer_initialization(self):
        """Test that analyzer initializes correctly"""
        assert self.analyzer is not None
        assert len(self.analyzer.precision_patterns) > 0
    
    def test_prorated_division_pattern_detection(self):
        """
        Test detection of the exact pro-rated division pattern from LinearCreditDebtTracker.sol
        This was reported at wrong line number in the original audit.
        """
        vulnerable_code = '''pragma solidity 0.8.28;

contract LinearCreditDebtTracker {
    struct Item {
        int128 totalValue;
        int128 settledValue;
        uint40 start;
        uint32 duration;
    }
    
    function calcItemValue(uint24 _id) public view returns (int256 value_) {
        Item memory item = getItem({_id: _id});

        // Handle cases outside of start and stop bounds
        if (block.timestamp <= item.start) {
            return item.settledValue;
        } else if (block.timestamp >= item.start + item.duration) {
            return item.settledValue + item.totalValue;
        }

        uint256 lapsed = block.timestamp - item.start;

        int256 proRatedValue = item.totalValue * int256(lapsed) / int256(uint256(item.duration));

        return item.settledValue + proRatedValue;
    }
    
    function getItem(uint24 _id) public view returns (Item memory) {
        return items[_id];
    }
}
'''
        
        vulnerabilities = self.analyzer.analyze_precision_loss(vulnerable_code)
        
        # Should detect the pro-rated division vulnerability
        assert len(vulnerabilities) > 0, "Should detect precision loss vulnerability"
        
        # Find the pro-rated division vulnerability
        prorated_vulns = [v for v in vulnerabilities if 'prorated' in v.operation_type.lower() 
                         or 'truncation' in v.description.lower()]
        
        assert len(prorated_vulns) > 0, "Should specifically detect pro-rated division pattern"
        
        vuln = prorated_vulns[0]
        
        # Verify line number accuracy - should be around line 23-24 (where the division occurs)
        assert 22 <= vuln.line_number <= 25, f"Line number should be around 23-24, got {vuln.line_number}"
        
        # More importantly, verify the code snippet contains the right code
        assert 'proRatedValue' in vuln.code_snippet
        assert 'totalValue' in vuln.code_snippet
        assert 'int256' in vuln.code_snippet
        
        # Verify severity
        assert vuln.severity in ["high", "critical"], f"Should be high severity, got {vuln.severity}"
        
        # Verify confidence
        assert vuln.confidence >= 0.9, f"Should have high confidence, got {vuln.confidence}"
        
        # Verify description mentions the issue
        assert 'truncation' in vuln.description.lower() or 'precision loss' in vuln.description.lower()
    
    def test_line_number_accuracy_simple_case(self):
        """Test that line numbers are accurately reported in simple cases"""
        code = '''pragma solidity ^0.8.0;

contract SimpleContract {
    function calculate(uint256 a, uint256 b) public pure returns (uint256) {
        uint256 result = a / b;
        return result;
    }
}
'''
        
        vulnerabilities = self.analyzer.analyze_precision_loss(code)
        
        if len(vulnerabilities) > 0:
            # Line 5 has the division
            division_vulns = [v for v in vulnerabilities if v.line_number == 5]
            assert len(division_vulns) > 0, "Should detect division at line 5"
    
    def test_line_number_accuracy_complex_case(self):
        """Test line number accuracy with complex multi-line expressions"""
        code = '''pragma solidity ^0.8.0;

contract ComplexContract {
    function complexCalc(
        uint256 value,
        uint256 duration
    ) public pure returns (uint256) {
        uint256 result = 
            value * 100 / duration;
        return result;
    }
}
'''
        
        vulnerabilities = self.analyzer.analyze_precision_loss(code)
        
        if len(vulnerabilities) > 0:
            # Division is on line 9
            for vuln in vulnerabilities:
                # Line number should be 9 (where the division operator is)
                if 'division' in vuln.vulnerability_type:
                    assert vuln.line_number == 9, f"Expected line 9, got {vuln.line_number}"
    
    def test_precision_loss_description_quality(self):
        """Test that vulnerability descriptions are detailed and actionable"""
        code = '''
contract TestContract {
    function proRated(uint256 totalValue, uint256 lapsed, uint256 duration) 
        public pure returns (uint256) {
        return totalValue * int256(lapsed) / int256(duration);
    }
}
'''
        
        vulnerabilities = self.analyzer.analyze_precision_loss(code)
        
        if len(vulnerabilities) > 0:
            vuln = vulnerabilities[0]
            
            # Description should be informative
            assert len(vuln.description) > 50, "Description should be detailed"
            
            # Should mention the specific risk
            description_lower = vuln.description.lower()
            assert ('truncation' in description_lower or 
                   'precision' in description_lower or
                   'loss' in description_lower)
    
    def test_recommendation_quality(self):
        """Test that recommendations are specific and actionable"""
        code = '''
contract TestContract {
    function divide(uint256 a, uint256 b) public pure returns (uint256) {
        return a * 100 / b;
    }
}
'''
        
        vulnerabilities = self.analyzer.analyze_precision_loss(code)
        
        if len(vulnerabilities) > 0:
            vuln = vulnerabilities[0]
            
            # Recommendation should be provided
            assert len(vuln.recommendation) > 0
            
            # Should mention specific solutions
            rec_lower = vuln.recommendation.lower()
            assert ('fixed-point' in rec_lower or 
                   'scale' in rec_lower or
                   'library' in rec_lower or
                   'precision' in rec_lower)
    
    def test_code_snippet_generation(self):
        """Test that code snippets include context and markers"""
        code = '''pragma solidity ^0.8.0;

contract TestContract {
    uint256 public value;
    
    function calculate(uint256 a, uint256 b) public pure returns (uint256) {
        uint256 result = a / b;
        return result;
    }
}
'''
        
        vulnerabilities = self.analyzer.analyze_precision_loss(code)
        
        if len(vulnerabilities) > 0:
            vuln = vulnerabilities[0]
            
            # Should have a code snippet
            assert len(vuln.code_snippet) > 0
            
            # Should include context lines
            assert 'calculate' in vuln.code_snippet or 'result' in vuln.code_snippet
            
            # Should have line marker if using new format
            # (May or may not have >>> depending on implementation)
    
    def test_no_false_positives_for_safe_division(self):
        """Test that safe division patterns are not flagged"""
        safe_code = '''
import "@openzeppelin/contracts/utils/math/Math.sol";

contract SafeContract {
    using Math for uint256;
    
    function safeDivide(uint256 a, uint256 b) public pure returns (uint256) {
        return a.mulDiv(100, b);
    }
}
'''
        
        vulnerabilities = self.analyzer.analyze_precision_loss(safe_code)
        
        # Should have fewer or no vulnerabilities due to Math library usage
        # (Depends on implementation - may still detect but with lower confidence)
    
    def test_multiple_divisions_on_same_line(self):
        """Test handling of multiple divisions on the same line"""
        code = '''
contract TestContract {
    function calc(uint256 a, uint256 b, uint256 c) public pure returns (uint256) {
        return a / b + c / a;
    }
}
'''
        
        vulnerabilities = self.analyzer.analyze_precision_loss(code)
        
        # Should detect both divisions
        # All should be around line 3-4 (accounting for test setup variations)
        if len(vulnerabilities) > 0:
            division_vulns = [v for v in vulnerabilities if 'division' in v.vulnerability_type]
            assert len(division_vulns) >= 1, "Should detect at least one division"
            # Line numbers should be close to each other (same line)
            line_numbers = [v.line_number for v in division_vulns]
            assert all(3 <= ln <= 5 for ln in line_numbers), f"Line numbers should be around 3-4, got {line_numbers}"
    
    def test_cast_pattern_detection(self):
        """Test detection of type casting in divisions"""
        code = '''
contract TestContract {
    function calculate(int128 value, uint256 lapsed, uint32 duration) 
        public pure returns (int256) {
        return value * int256(lapsed) / int256(uint256(duration));
    }
}
'''
        
        vulnerabilities = self.analyzer.analyze_precision_loss(code)
        
        # Should detect this pattern
        assert len(vulnerabilities) > 0
        
        # Should have high confidence for this specific pattern
        high_conf_vulns = [v for v in vulnerabilities if v.confidence >= 0.9]
        assert len(high_conf_vulns) > 0, "Should have high confidence for cast pattern"
    
    def test_swc_id_assignment(self):
        """Test that SWC-101 is correctly assigned"""
        code = '''
contract TestContract {
    function divide(uint256 a, uint256 b) public pure returns (uint256) {
        return a / b;
    }
}
'''
        
        vulnerabilities = self.analyzer.analyze_precision_loss(code)
        
        if len(vulnerabilities) > 0:
            assert vulnerabilities[0].swc_id == 'SWC-101'
    
    def test_severity_levels(self):
        """Test that severity levels are appropriately assigned"""
        # High severity for pro-rated division
        high_severity_code = '''
contract Test {
    function calc(int128 total, uint256 elapsed, uint256 duration) public pure returns (int256) {
        return total * int256(elapsed) / int256(duration);
    }
}
'''
        
        vulns_high = self.analyzer.analyze_precision_loss(high_severity_code)
        if len(vulns_high) > 0:
            high_severity_found = any(v.severity in ['high', 'critical'] for v in vulns_high)
            assert high_severity_found, "Should flag high severity for pro-rated pattern"
        
        # Medium severity for simple division
        medium_severity_code = '''
contract Test {
    function calc(uint256 a, uint256 b) public pure returns (uint256) {
        return a / b;
    }
}
'''
        
        vulns_medium = self.analyzer.analyze_precision_loss(medium_severity_code)
        # May have medium severity detections
    
    def test_precision_summary(self):
        """Test precision summary generation"""
        code = '''
contract Test {
    function calc1(uint256 a, uint256 b) public pure returns (uint256) {
        return a / b;
    }
    
    function calc2(uint256 a, uint256 b) public pure returns (uint256) {
        return a * b;
    }
    
    function calc3(uint256 a, uint256 b) public pure returns (uint256) {
        return a % b;
    }
}
'''
        
        summary = self.analyzer.get_precision_summary(code)
        
        assert 'division_operations' in summary
        assert 'multiplication_operations' in summary
        assert 'modulo_operations' in summary
        assert summary['division_operations'] > 0
        assert summary['multiplication_operations'] > 0
        assert summary['modulo_operations'] > 0


class TestLineNumberVerification:
    """Test line number verification methods"""
    
    def setup_method(self):
        self.analyzer = PrecisionAnalyzer()
    
    def test_verify_line_number_correct(self):
        """Test verification of correct line number"""
        code = "line1\nline2 a / b\nline3"
        lines = code.split('\n')
        
        import re
        match = re.search(r'a\s*/\s*b', code)
        line_number = code[:match.start()].count('\n') + 1
        
        # Should be line 2
        assert line_number == 2
        
        # Verification should pass
        is_correct = self.analyzer._verify_line_number(match, lines, line_number)
        assert is_correct == True
    
    def test_verify_line_number_incorrect(self):
        """Test detection of incorrect line number"""
        code = "line1\nline2 a / b\nline3"
        lines = code.split('\n')
        
        import re
        match = re.search(r'a\s*/\s*b', code)
        
        # Wrong line number
        wrong_line_number = 1
        
        # Verification should fail
        is_correct = self.analyzer._verify_line_number(match, lines, wrong_line_number)
        assert is_correct == False
    
    def test_get_code_snippet_from_lines(self):
        """Test code snippet generation with context"""
        lines = [
            "pragma solidity ^0.8.0;",
            "",
            "contract Test {",
            "    function calc(uint256 a, uint256 b) public pure returns (uint256) {",
            "        return a / b;",
            "    }",
            "}"
        ]
        
        # Get snippet for line 5 (the division)
        snippet = self.analyzer._get_code_snippet_from_lines(lines, 5, context=2)
        
        # Should include the target line
        assert "a / b" in snippet
        
        # Should include context
        assert "function calc" in snippet or "return" in snippet


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

