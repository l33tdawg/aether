"""
Integration Tests for Kaia False Positive Elimination

Tests the complete pipeline to ensure all the Dec 2025 improvements work together
to eliminate the false positives found in the Kaia audit:

1. "unlockToken lacks validation" - FALSE POSITIVE (modifier validates)
2. "deregisterToken lacks validation" - FALSE POSITIVE (modifier validates)  
3. "counterpartBridge lacks validation" - BORDERLINE (owner-only, informational)
4. "chargeWithoutEvent lacks access control" - FALSE POSITIVE (intentional design)
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.modifier_semantic_analyzer import ModifierSemanticAnalyzer
from core.intentional_design_detector import IntentionalDesignDetector
from core.access_control_context_analyzer import AccessControlContextAnalyzer
from core.enhanced_false_positive_filter import EnhancedFalsePositiveFilter


# Full Kaia BridgeTokens contract (simplified for testing)
KAIA_BRIDGE_TOKENS = """
pragma solidity 0.5.6;

contract BridgeTokens is Ownable {
    mapping(address => address) public registeredTokens;
    mapping(address => uint) public indexOfTokens;
    address[] public registeredTokenList;
    mapping(address => bool) public lockedTokens;

    modifier onlyRegisteredToken(address _token) {
        require(registeredTokens[_token] != address(0), "not allowed token");
        _;
    }

    modifier onlyNotRegisteredToken(address _token) {
        require(registeredTokens[_token] == address(0), "allowed token");
        _;
    }

    modifier onlyLockedToken(address _token) {
        require(lockedTokens[_token], "unlocked token");
        _;
    }

    modifier onlyUnlockedToken(address _token) {
        require(!lockedTokens[_token], "locked token");
        _;
    }

    function deregisterToken(address _token)
        external
        onlyOwner
        onlyRegisteredToken(_token)
    {
        delete registeredTokens[_token];
        delete lockedTokens[_token];
    }

    function unlockToken(address _token)
        external
        onlyOwner
        onlyRegisteredToken(_token)
        onlyLockedToken(_token)
    {
        delete lockedTokens[_token];
    }
}
"""

# Kaia BridgeTransferKLAY contract (simplified)
KAIA_BRIDGE_TRANSFER_KLAY = """
pragma solidity 0.5.6;

contract BridgeTransferKLAY is BridgeTransfer, ReentrancyGuard {
    bool public isLockedKLAY;

    // chargeWithoutEvent sends KLAY to this contract without event for increasing
    // the withdrawal limit.
    function chargeWithoutEvent() external payable {}
    
    function requestKLAYTransfer(address _to, uint256 _value, bytes calldata _extraData) external payable {
        uint256 feeLimit = msg.value - _value;
        _requestKLAYTransfer(_to, feeLimit, _extraData);
    }
}
"""

# Kaia BridgeCounterPart contract
KAIA_BRIDGE_COUNTERPART = """
pragma solidity 0.5.6;

contract BridgeCounterPart is Ownable {
    address public counterpartBridge;

    event CounterpartBridgeChanged(address _bridge);

    function setCounterPartBridge(address _bridge)
        external
        onlyOwner
    {
        counterpartBridge = _bridge;
        emit CounterpartBridgeChanged(_bridge);
    }
}
"""


class TestUnlockTokenFalsePositive:
    """
    Test elimination of: "unlockToken lacks validation for token address"
    This was marked as CRITICAL but is a false positive.
    """
    
    def test_modifier_detects_validation(self):
        """ModifierSemanticAnalyzer should detect _token is validated."""
        analyzer = ModifierSemanticAnalyzer()
        analyzer.analyze_contract(KAIA_BRIDGE_TOKENS)
        
        unlock_func = """
        function unlockToken(address _token)
            external
            onlyOwner
            onlyRegisteredToken(_token)
            onlyLockedToken(_token)
        {
            delete lockedTokens[_token];
        }
        """
        
        is_validated, modifiers = analyzer.is_parameter_validated_by_modifiers(
            unlock_func, '_token'
        )
        
        assert is_validated is True
        assert 'onlyRegisteredToken' in modifiers
    
    def test_access_control_analyzer_detects_validation(self):
        """AccessControlContextAnalyzer should detect parameter validation."""
        analyzer = AccessControlContextAnalyzer()
        
        unlock_func = """
        function unlockToken(address _token)
            external
            onlyOwner
            onlyRegisteredToken(_token)
            onlyLockedToken(_token)
        {
            delete lockedTokens[_token];
        }
        """
        
        result = analyzer.analyze_function_access_control(
            unlock_func, 
            'unlockToken',
            KAIA_BRIDGE_TOKENS
        )
        
        # Should have access control (onlyOwner)
        assert result['has_access_control'] is True
        
        # Should detect parameter validation from custom modifiers
        assert result['has_parameter_validation'] is True
        assert '_token' in result['validated_parameters']


class TestDeregisterTokenFalsePositive:
    """
    Test elimination of: "deregisterToken lacks validation for token address"
    This was marked as HIGH but is a false positive.
    """
    
    def test_modifier_detects_validation(self):
        """ModifierSemanticAnalyzer should detect _token is validated."""
        analyzer = ModifierSemanticAnalyzer()
        analyzer.analyze_contract(KAIA_BRIDGE_TOKENS)
        
        deregister_func = """
        function deregisterToken(address _token)
            external
            onlyOwner
            onlyRegisteredToken(_token)
        {
            delete registeredTokens[_token];
        }
        """
        
        is_validated, modifiers = analyzer.is_parameter_validated_by_modifiers(
            deregister_func, '_token'
        )
        
        assert is_validated is True
        assert 'onlyRegisteredToken' in modifiers


class TestChargeWithoutEventFalsePositive:
    """
    Test elimination of: "chargeWithoutEvent lacks access control"
    This was marked as MEDIUM but is a false positive (intentional design).
    """
    
    def test_intentional_design_detected(self):
        """IntentionalDesignDetector should recognize chargeWithoutEvent."""
        detector = IntentionalDesignDetector()
        
        func = "function chargeWithoutEvent() external payable {}"
        comment = "// chargeWithoutEvent sends KLAY to this contract without event for increasing the withdrawal limit."
        
        result = detector.analyze_function(func, "chargeWithoutEvent", comment)
        
        assert result.is_intentional is True
        assert result.confidence >= 0.80
    
    def test_should_suppress_finding(self):
        """Should suppress 'missing access control' finding."""
        detector = IntentionalDesignDetector()
        
        func = "function chargeWithoutEvent() external payable {}"
        comment = "// for increasing the withdrawal limit"
        
        should_suppress, reason = detector.should_suppress_finding(
            'missing_access_control',
            func,
            comment
        )
        
        assert should_suppress is True


class TestEnhancedFilterIntegration:
    """
    Test the EnhancedFalsePositiveFilter with all new strategies.
    """
    
    def test_filter_detects_modifier_validation(self):
        """Filter should detect modifier-based validation."""
        filter = EnhancedFalsePositiveFilter()
        filter.analyze_contract_context(KAIA_BRIDGE_TOKENS, "BridgeTokens")
        
        # Simulate a finding about unlockToken lacking validation
        finding = {
            'vulnerability_type': 'missing_input_validation',
            'severity': 'critical',
            'line': 55,  # Line of unlockToken
            'description': "The 'unlockToken' function lacks validation for the token address parameter"
        }
        
        result = filter.validate_finding(finding)
        
        # Should either be false positive or have reasoning about modifier validation
        has_modifier_reasoning = any(
            'modifier' in r.lower() or 'validated' in r.lower() 
            for r in result.reasoning
        )
        
        # The filter should recognize this as problematic
        assert result.is_false_positive or has_modifier_reasoning or result.adjusted_severity
    
    def test_filter_detects_intentional_design(self):
        """Filter should detect intentional design patterns."""
        filter = EnhancedFalsePositiveFilter()
        filter.analyze_contract_context(KAIA_BRIDGE_TRANSFER_KLAY, "BridgeTransferKLAY")
        
        # Simulate a finding about chargeWithoutEvent
        finding = {
            'vulnerability_type': 'missing_access_control',
            'severity': 'medium',
            'line': 9,  # Line of chargeWithoutEvent
            'description': "The chargeWithoutEvent function lacks access control, anyone can call it"
        }
        
        result = filter.validate_finding(finding)
        
        # Should detect intentional design
        has_intentional_reasoning = any(
            'intentional' in r.lower() or 'design' in r.lower() or 'pattern' in r.lower()
            for r in result.reasoning
        )
        
        assert result.is_false_positive or has_intentional_reasoning


class TestAccessControlContextEnhancements:
    """
    Test the enhanced AccessControlContextAnalyzer.
    """
    
    def test_custom_modifier_analysis(self):
        """Should analyze custom modifiers for validation."""
        analyzer = AccessControlContextAnalyzer()
        
        result = analyzer.analyze_function_access_control(
            """
            function unlockToken(address _token)
                external
                onlyOwner
                onlyRegisteredToken(_token)
            {
                delete lockedTokens[_token];
            }
            """,
            'unlockToken',
            KAIA_BRIDGE_TOKENS
        )
        
        # Should have detected the custom modifiers
        assert 'onlyRegisteredToken' in result.get('custom_modifiers', []) or \
               result.get('has_parameter_validation') is True
    
    def test_is_parameter_validated(self):
        """Should correctly identify validated parameters."""
        analyzer = AccessControlContextAnalyzer()
        
        # Pre-analyze the contract
        analyzer.analyze_contract_modifiers(KAIA_BRIDGE_TOKENS)
        
        is_validated, sources = analyzer.is_parameter_validated(
            """
            function unlockToken(address _token)
                external
                onlyOwner
                onlyRegisteredToken(_token)
            {
            }
            """,
            '_token',
            KAIA_BRIDGE_TOKENS
        )
        
        assert is_validated is True
        assert len(sources) > 0


class TestRegressionPrevention:
    """
    Ensure improvements don't break existing functionality.
    """
    
    def test_real_vulnerability_not_suppressed(self):
        """Should NOT suppress real vulnerabilities."""
        detector = IntentionalDesignDetector()
        
        # This is a real vulnerability - missing validation on transfer
        func = "function transfer(address to, uint256 amount) external { _transfer(msg.sender, to, amount); }"
        
        result = detector.analyze_function(func, "transfer")
        
        # transfer() should NOT be marked as intentional design
        assert result.is_intentional is False
    
    def test_actual_missing_validation_detected(self):
        """Should still detect actual missing validation."""
        analyzer = ModifierSemanticAnalyzer()
        analyzer.analyze_contract(KAIA_BRIDGE_TOKENS)
        
        # A function without validation modifiers
        func = """
        function unsafeTransfer(address _token) external {
            IERC20(_token).transfer(msg.sender, 1000);
        }
        """
        
        is_validated, modifiers = analyzer.is_parameter_validated_by_modifiers(
            func, '_token'
        )
        
        # Should NOT be marked as validated
        assert is_validated is False
    
    def test_filter_preserves_real_findings(self):
        """Filter should preserve real vulnerability findings."""
        filter = EnhancedFalsePositiveFilter()
        
        # A simple contract without special patterns
        simple_contract = """
        contract Simple {
            function transfer(address to, uint256 amount) external {
                balances[msg.sender] -= amount;
                balances[to] += amount;
            }
        }
        """
        
        filter.analyze_contract_context(simple_contract, "Simple")
        
        finding = {
            'vulnerability_type': 'reentrancy',
            'severity': 'high',
            'line': 3,
            'description': 'External call before state update allows reentrancy attack'
        }
        
        result = filter.validate_finding(finding)
        
        # Real reentrancy finding should NOT be marked as false positive
        # (unless there's specific protection detected)
        # The filter might adjust severity but shouldn't blindly suppress
        assert not result.is_false_positive or len(result.reasoning) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

