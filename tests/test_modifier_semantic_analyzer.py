"""
Tests for ModifierSemanticAnalyzer

Tests the ability to parse modifier bodies and understand their validation semantics,
which helps reduce false positives for "missing validation" findings.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.modifier_semantic_analyzer import (
    ModifierSemanticAnalyzer,
    ModifierDefinition,
    ModifierValidation,
    ValidationKind,
    FunctionModifierUsage
)


# Sample contract from Kaia bridge - the source of our false positives
KAIA_BRIDGE_TOKENS_CONTRACT = """
pragma solidity 0.5.6;

import "../../libs/openzeppelin-contracts-v2/contracts/ownership/Ownable.sol";

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

    function unlockToken(address _token)
        external
        onlyOwner
        onlyRegisteredToken(_token)
        onlyLockedToken(_token)
    {
        delete lockedTokens[_token];
    }

    function deregisterToken(address _token)
        external
        onlyOwner
        onlyRegisteredToken(_token)
    {
        delete registeredTokens[_token];
        delete lockedTokens[_token];
    }
    
    function lockToken(address _token)
        external
        onlyOwner
        onlyRegisteredToken(_token)
        onlyUnlockedToken(_token)
    {
        lockedTokens[_token] = true;
    }
}
"""


class TestModifierExtraction:
    """Test modifier definition extraction."""
    
    def test_extract_all_modifiers(self):
        """Should extract all modifier definitions from contract."""
        analyzer = ModifierSemanticAnalyzer()
        modifiers = analyzer.analyze_contract(KAIA_BRIDGE_TOKENS_CONTRACT)
        
        assert len(modifiers) == 4
        assert 'onlyRegisteredToken' in modifiers
        assert 'onlyNotRegisteredToken' in modifiers
        assert 'onlyLockedToken' in modifiers
        assert 'onlyUnlockedToken' in modifiers
    
    def test_modifier_parameters(self):
        """Should correctly parse modifier parameters."""
        analyzer = ModifierSemanticAnalyzer()
        modifiers = analyzer.analyze_contract(KAIA_BRIDGE_TOKENS_CONTRACT)
        
        mod = modifiers['onlyRegisteredToken']
        assert '_token' in mod.parameters
        assert mod.parameter_types.get('_token') == 'address'
    
    def test_modifier_validations_extracted(self):
        """Should extract validations from modifier body."""
        analyzer = ModifierSemanticAnalyzer()
        modifiers = analyzer.analyze_contract(KAIA_BRIDGE_TOKENS_CONTRACT)
        
        mod = modifiers['onlyRegisteredToken']
        assert len(mod.validations) > 0
        
        # Should have found the require statement
        validation = mod.validations[0]
        assert 'registeredTokens[_token]' in validation.condition or '_token' in validation.condition


class TestParameterValidationDetection:
    """Test detection of parameter validation through modifiers."""
    
    def test_validated_params_detected(self):
        """Should detect that _token is validated by onlyRegisteredToken."""
        analyzer = ModifierSemanticAnalyzer()
        modifiers = analyzer.analyze_contract(KAIA_BRIDGE_TOKENS_CONTRACT)
        
        mod = modifiers['onlyRegisteredToken']
        assert '_token' in mod.validated_params
    
    def test_function_modifier_usage_extraction(self):
        """Should extract modifier usages from function signature."""
        analyzer = ModifierSemanticAnalyzer()
        analyzer.analyze_contract(KAIA_BRIDGE_TOKENS_CONTRACT)
        
        function_code = """
        function unlockToken(address _token)
            external
            onlyOwner
            onlyRegisteredToken(_token)
            onlyLockedToken(_token)
        {
            delete lockedTokens[_token];
        }
        """
        
        usages = analyzer.get_function_modifier_usages(function_code)
        
        # Should find at least the custom modifiers
        modifier_names = [u.modifier_name for u in usages]
        assert 'onlyRegisteredToken' in modifier_names
        assert 'onlyLockedToken' in modifier_names
    
    def test_is_parameter_validated_by_modifiers(self):
        """Should correctly identify parameter validated by modifiers."""
        analyzer = ModifierSemanticAnalyzer()
        analyzer.analyze_contract(KAIA_BRIDGE_TOKENS_CONTRACT)
        
        function_code = """
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
            function_code, '_token'
        )
        
        assert is_validated is True
        assert 'onlyRegisteredToken' in modifiers


class TestAccessControlDetection:
    """Test detection of access control modifiers."""
    
    def test_owner_check_detected(self):
        """Should detect access control patterns in modifiers."""
        contract = """
        modifier onlyOwner() {
            require(msg.sender == owner, "not owner");
            _;
        }
        
        modifier onlyAdmin() {
            require(msg.sender == admin, "not admin");
            _;
        }
        """
        
        analyzer = ModifierSemanticAnalyzer()
        modifiers = analyzer.analyze_contract(contract)
        
        assert modifiers['onlyOwner'].is_access_control is True
        assert modifiers['onlyAdmin'].is_access_control is True
    
    def test_get_function_access_control_modifiers(self):
        """Should return list of access control modifiers on function."""
        contract = """
        modifier onlyOwner() {
            require(msg.sender == owner, "not owner");
            _;
        }
        
        modifier onlyRegisteredToken(address _token) {
            require(registeredTokens[_token] != address(0), "not allowed");
            _;
        }
        """
        
        analyzer = ModifierSemanticAnalyzer()
        analyzer.analyze_contract(contract)
        
        function_code = """
        function test() external onlyOwner onlyRegisteredToken(token) {
        }
        """
        
        ac_modifiers = analyzer.get_function_access_control_modifiers(function_code)
        assert 'onlyOwner' in ac_modifiers


class TestReentrancyGuardDetection:
    """Test detection of reentrancy guard modifiers."""
    
    def test_reentrancy_guard_detected(self):
        """Should detect reentrancy guard patterns."""
        contract = """
        modifier nonReentrant() {
            require(_status != _ENTERED, "ReentrancyGuard: reentrant call");
            _status = _ENTERED;
            _;
            _status = _NOT_ENTERED;
        }
        """
        
        analyzer = ModifierSemanticAnalyzer()
        modifiers = analyzer.analyze_contract(contract)
        
        assert modifiers['nonReentrant'].is_reentrancy_guard is True
    
    def test_has_reentrancy_protection(self):
        """Should detect if function has reentrancy protection."""
        contract = """
        modifier nonReentrant() {
            require(_status != _ENTERED, "reentrant");
            _;
        }
        """
        
        analyzer = ModifierSemanticAnalyzer()
        analyzer.analyze_contract(contract)
        
        function_code = "function withdraw() external nonReentrant { }"
        assert analyzer.has_reentrancy_protection(function_code) is True
        
        function_code2 = "function deposit() external { }"
        assert analyzer.has_reentrancy_protection(function_code2) is False


class TestKaiaFalsePositiveScenarios:
    """
    Test the specific false positive scenarios from Kaia audit.
    These tests validate that our improvements would catch those FPs.
    """
    
    def test_unlock_token_not_missing_validation(self):
        """
        The audit reported: "unlockToken lacks validation for token address"
        Reality: onlyRegisteredToken modifier validates it
        """
        analyzer = ModifierSemanticAnalyzer()
        analyzer.analyze_contract(KAIA_BRIDGE_TOKENS_CONTRACT)
        
        unlock_function = """
        function unlockToken(address _token)
            external
            onlyOwner
            onlyRegisteredToken(_token)
            onlyLockedToken(_token)
        {
            delete lockedTokens[_token];
        }
        """
        
        # This should detect that _token IS validated
        is_validated, validating_modifiers = analyzer.is_parameter_validated_by_modifiers(
            unlock_function, '_token'
        )
        
        assert is_validated is True, "Should detect _token is validated by onlyRegisteredToken"
        assert 'onlyRegisteredToken' in validating_modifiers
    
    def test_deregister_token_not_missing_validation(self):
        """
        The audit reported: "deregisterToken lacks validation for token address"
        Reality: onlyRegisteredToken modifier validates it
        """
        analyzer = ModifierSemanticAnalyzer()
        analyzer.analyze_contract(KAIA_BRIDGE_TOKENS_CONTRACT)
        
        deregister_function = """
        function deregisterToken(address _token)
            external
            onlyOwner
            onlyRegisteredToken(_token)
        {
            delete registeredTokens[_token];
        }
        """
        
        is_validated, validating_modifiers = analyzer.is_parameter_validated_by_modifiers(
            deregister_function, '_token'
        )
        
        assert is_validated is True, "Should detect _token is validated by onlyRegisteredToken"
        assert 'onlyRegisteredToken' in validating_modifiers


class TestEdgeCases:
    """Test edge cases and error handling."""
    
    def test_empty_contract(self):
        """Should handle empty contract gracefully."""
        analyzer = ModifierSemanticAnalyzer()
        modifiers = analyzer.analyze_contract("")
        assert modifiers == {}
    
    def test_contract_without_modifiers(self):
        """Should handle contract without modifiers."""
        contract = """
        contract Simple {
            function foo() public {}
        }
        """
        
        analyzer = ModifierSemanticAnalyzer()
        modifiers = analyzer.analyze_contract(contract)
        assert modifiers == {}
    
    def test_modifier_without_parameters(self):
        """Should handle modifiers without parameters."""
        contract = """
        modifier whenNotPaused() {
            require(!paused, "paused");
            _;
        }
        """
        
        analyzer = ModifierSemanticAnalyzer()
        modifiers = analyzer.analyze_contract(contract)
        
        assert 'whenNotPaused' in modifiers
        assert modifiers['whenNotPaused'].parameters == []
    
    def test_complex_modifier_body(self):
        """Should handle complex modifier bodies."""
        contract = """
        modifier complexCheck(address _addr, uint256 _amount) {
            require(_addr != address(0), "zero address");
            require(_amount > 0, "zero amount");
            require(balances[_addr] >= _amount, "insufficient");
            _;
        }
        """
        
        analyzer = ModifierSemanticAnalyzer()
        modifiers = analyzer.analyze_contract(contract)
        
        mod = modifiers['complexCheck']
        assert '_addr' in mod.parameters
        assert '_amount' in mod.parameters
        assert len(mod.validations) >= 2  # At least 2 require statements


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

