"""
Tests for IntentionalDesignDetector

Tests the ability to detect functions that are intentionally designed
without certain checks, reducing false positives.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.intentional_design_detector import (
    IntentionalDesignDetector,
    IntentionalPatternType,
    IntentionalPattern,
    IntentionalDesignResult
)


# Sample contract from Kaia - the chargeWithoutEvent false positive
KAIA_BRIDGE_TRANSFER_CONTRACT = """
pragma solidity 0.5.6;

contract BridgeTransferKLAY is BridgeTransfer, ReentrancyGuard {
    bool public isLockedKLAY;

    // chargeWithoutEvent sends KLAY to this contract without event for increasing
    // the withdrawal limit.
    function chargeWithoutEvent() external payable {}

    // () requests transfer KLAY to msg.sender address on relative chain.
    function () external payable {
        _requestKLAYTransfer(msg.sender, feeOfKLAY, new bytes(0));
    }
    
    function notify() external {
        // Sync state - anyone can call
        _syncState();
    }
    
    function poke() external {
        // Update state - permissionless
        _update();
    }
}
"""


class TestIntentionalPatternDetection:
    """Test detection of intentional design patterns."""
    
    def test_charge_without_event_detected(self):
        """Should detect chargeWithoutEvent as intentional design."""
        detector = IntentionalDesignDetector()
        
        function_code = "function chargeWithoutEvent() external payable {}"
        result = detector.analyze_function(function_code, "chargeWithoutEvent")
        
        assert result.is_intentional is True
        assert result.confidence >= 0.80
    
    def test_notify_function_detected(self):
        """Should detect notify() as permissionless sync function."""
        detector = IntentionalDesignDetector()
        
        function_code = "function notify() external { _syncState(); }"
        result = detector.analyze_function(function_code, "notify")
        
        assert result.is_intentional is True
        assert IntentionalPatternType.STATE_SYNC in [p.pattern_type for p in result.matched_patterns]
    
    def test_poke_function_detected(self):
        """Should detect poke() as permissionless sync function."""
        detector = IntentionalDesignDetector()
        
        function_code = "function poke() external { _update(); }"
        result = detector.analyze_function(function_code, "poke")
        
        assert result.is_intentional is True
    
    def test_sync_function_detected(self):
        """Should detect sync() as permissionless function."""
        detector = IntentionalDesignDetector()
        
        function_code = "function sync() external { _syncReserves(); }"
        result = detector.analyze_function(function_code, "sync")
        
        assert result.is_intentional is True
    
    def test_receive_function_detected(self):
        """Should detect receive() as intentionally permissionless."""
        detector = IntentionalDesignDetector()
        
        function_code = "receive() external payable { }"
        result = detector.analyze_function(function_code, "receive")
        
        assert result.is_intentional is True
        assert result.confidence >= 0.90
    
    def test_fallback_function_detected(self):
        """Should detect fallback() as intentionally permissionless."""
        detector = IntentionalDesignDetector()
        
        function_code = "fallback() external payable { _handleFallback(); }"
        result = detector.analyze_function(function_code, "fallback")
        
        assert result.is_intentional is True


class TestCommentBasedDetection:
    """Test detection through comment analysis."""
    
    def test_comment_indicates_intentional(self):
        """Should boost confidence when comment indicates intent."""
        detector = IntentionalDesignDetector()
        
        function_code = "function charge() external payable {}"
        comment = "// Anyone can call this to add liquidity"
        
        result = detector.analyze_function(function_code, "charge", comment)
        
        # Comment should help identify as intentional
        assert result.confidence > 0
    
    def test_permissionless_comment(self):
        """Should detect 'permissionless' in comments."""
        detector = IntentionalDesignDetector()
        
        function_code = "function update() external {}"
        comment = "// Permissionless function for keepers"
        
        result = detector.analyze_function(function_code, "update", comment)
        
        assert result.is_intentional is True or result.confidence > 0.5
    
    def test_by_design_comment(self):
        """Should detect 'by design' in comments."""
        detector = IntentionalDesignDetector()
        
        function_code = "function foo() external {}"
        comment = "// This is intentionally public by design"
        
        result = detector.analyze_function(function_code, "foo", comment)
        
        assert result.confidence > 0.5
    
    def test_withdrawal_limit_comment(self):
        """Should detect 'for increasing the withdrawal limit' pattern."""
        detector = IntentionalDesignDetector()
        
        function_code = "function chargeWithoutEvent() external payable {}"
        comment = "// chargeWithoutEvent sends KLAY to this contract without event for increasing the withdrawal limit."
        
        result = detector.analyze_function(function_code, "chargeWithoutEvent", comment)
        
        assert result.is_intentional is True


class TestMissingCheckAnalysis:
    """Test analysis of specific missing checks."""
    
    def test_is_missing_access_control_intentional(self):
        """Should identify when missing access control is intentional."""
        detector = IntentionalDesignDetector()
        
        function_code = "function chargeWithoutEvent() external payable {}"
        
        is_intentional, confidence, reason = detector.is_missing_check_intentional(
            function_code, 
            'access_control',
            surrounding_comments=""
        )
        
        assert is_intentional is True
        assert 'access_control' in detector.patterns[1].typically_missing  # charge pattern
    
    def test_is_missing_event_intentional(self):
        """Should identify when missing event is intentional."""
        detector = IntentionalDesignDetector()
        
        function_code = "function chargeWithoutEvent() external payable {}"
        
        is_intentional, confidence, reason = detector.is_missing_check_intentional(
            function_code,
            'event_emission',
            surrounding_comments=""
        )
        
        # The "WithoutEvent" name pattern indicates intentional
        assert is_intentional is True


class TestShouldSuppressFinding:
    """Test finding suppression logic."""
    
    def test_suppress_missing_access_control_on_charge(self):
        """Should suppress missing access control on charge functions."""
        detector = IntentionalDesignDetector()
        
        function_code = "function chargeWithoutEvent() external payable {}"
        
        should_suppress, reason = detector.should_suppress_finding(
            'missing_access_control',
            function_code,
            surrounding_comments=""
        )
        
        assert should_suppress is True
        # Reason should indicate this is expected/intentional behavior
        assert 'expected' in reason.lower() or 'pattern' in reason.lower() or 'intentional' in reason.lower()
    
    def test_suppress_permissionless_on_notify(self):
        """Should suppress 'anyone can call' on notify functions."""
        detector = IntentionalDesignDetector()
        
        function_code = "function notify() external { _sync(); }"
        
        should_suppress, reason = detector.should_suppress_finding(
            'anyone_can_call',
            function_code,
            surrounding_comments=""
        )
        
        assert should_suppress is True
    
    def test_no_suppress_on_regular_function(self):
        """Should NOT suppress findings on regular functions."""
        detector = IntentionalDesignDetector()
        
        function_code = "function transfer(address to, uint256 amount) external { }"
        
        should_suppress, reason = detector.should_suppress_finding(
            'missing_access_control',
            function_code,
            surrounding_comments=""
        )
        
        assert should_suppress is False


class TestGetFunctionIntentContext:
    """Test extraction of comment context."""
    
    def test_extract_preceding_comments(self):
        """Should extract comments before function."""
        detector = IntentionalDesignDetector()
        
        contract = """
        // This is a helper comment
        // chargeWithoutEvent sends KLAY without event
        // for increasing the withdrawal limit.
        function chargeWithoutEvent() external payable {}
        """
        
        # Line 4 is approximately where the function starts
        context = detector.get_function_intent_context(contract, 4)
        
        assert 'chargeWithoutEvent' in context or 'withdrawal' in context.lower()
    
    def test_extract_inline_comments(self):
        """Should extract inline comments in function."""
        detector = IntentionalDesignDetector()
        
        contract = """
        function charge() external payable {
            // This is intentionally permissionless
            balance += msg.value;
        }
        """
        
        context = detector.get_function_intent_context(contract, 1)
        
        assert 'intentionally' in context.lower() or 'permissionless' in context.lower()


class TestKaiaFalsePositiveScenarios:
    """
    Test the specific false positive scenarios from Kaia audit.
    """
    
    def test_charge_without_event_not_vulnerability(self):
        """
        The audit reported: "chargeWithoutEvent lacks access control"
        Reality: It's intentionally permissionless for adding bridge liquidity
        """
        detector = IntentionalDesignDetector()
        
        function_code = "function chargeWithoutEvent() external payable {}"
        comment = "// chargeWithoutEvent sends KLAY to this contract without event for increasing the withdrawal limit."
        
        result = detector.analyze_function(function_code, "chargeWithoutEvent", comment)
        
        assert result.is_intentional is True, "Should recognize chargeWithoutEvent as intentional"
        
        # Should suppress the finding
        should_suppress, reason = detector.should_suppress_finding(
            'missing_access_control',
            function_code,
            comment
        )
        
        assert should_suppress is True, "Should suppress 'missing access control' finding"


class TestEdgeCases:
    """Test edge cases and error handling."""
    
    def test_empty_function(self):
        """Should handle empty function gracefully."""
        detector = IntentionalDesignDetector()
        result = detector.analyze_function("", "")
        
        assert result.is_intentional is False
    
    def test_no_patterns_matched(self):
        """Should return false for functions without intentional patterns."""
        detector = IntentionalDesignDetector()
        
        function_code = "function regularFunction() external { doSomething(); }"
        result = detector.analyze_function(function_code, "regularFunction")
        
        assert result.is_intentional is False
        assert len(result.matched_patterns) == 0
    
    def test_getter_function(self):
        """Should detect getter functions as intentionally simple."""
        detector = IntentionalDesignDetector()
        
        function_code = "function getBalance() external view returns (uint256) { return balance; }"
        result = detector.analyze_function(function_code, "getBalance")
        
        assert result.is_intentional is True
        assert IntentionalPatternType.SIMPLE_GETTER in [p.pattern_type for p in result.matched_patterns]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

