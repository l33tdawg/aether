#!/usr/bin/env python3
"""
Tests for Governance Detector Module

Tests governance protection detection to prevent false positives.
"""

import pytest
from core.governance_detector import GovernanceDetector, ValidationDetector


class TestGovernanceDetector:
    """Test cases for GovernanceDetector."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.detector = GovernanceDetector()
    
    def test_initialization(self):
        """Test GovernanceDetector initialization."""
        assert len(self.detector.setter_patterns) > 0
        assert len(self.detector.access_modifiers) > 0
        assert 'onlyOwner' in self.detector.access_modifiers
        assert 'onlyGovernor' in self.detector.access_modifiers
    
    def test_detects_onlyowner_protection(self):
        """Test detection of onlyOwner protection."""
        contract_code = """
        contract Protocol {
            function setFees(uint64[] memory xFee, int64[] memory yFee) external onlyOwner {
                require(xFee.length == yFee.length, "Length mismatch");
                xFeeMint = xFee;
                yFeeMint = yFee;
            }
        }
        """
        
        setter_info = self.detector.find_setter_for_param('Fees', contract_code)
        
        assert setter_info is not None
        assert setter_info['is_protected'] is True
        assert 'onlyOwner' in setter_info['protected_by']
    
    def test_detects_validation_in_setter(self):
        """Test detection of require validation in setter."""
        contract_code = """
        contract Protocol {
            function setFees(uint64[] memory xFee, int64[] memory yFee) external {
                require(msg.sender == governance, "Only governance");
                require(yFee[i] >= yFee[i-1], "Must be monotonic");
                xFeeMint = xFee;
            }
        }
        """
        
        setter_info = self.detector.find_setter_for_param('Fees', contract_code)
        
        assert setter_info is not None
        assert setter_info['has_validation'] is True
        assert setter_info['is_protected'] is True
    
    def test_detects_multiple_modifiers(self):
        """Test detection of multiple access control modifiers."""
        contract_code = """
        contract Protocol {
            function setOracle(address oracle) external onlyGovernor onlyAuthorized {
                oracleAddress = oracle;
            }
        }
        """
        
        setter_info = self.detector.find_setter_for_param('Oracle', contract_code)
        
        assert setter_info is not None
        assert setter_info['is_protected'] is True
        assert 'onlyGovernor' in setter_info['protected_by']
        assert 'onlyAuthorized' in setter_info['protected_by']
    
    def test_no_setter_found(self):
        """Test when no setter function exists."""
        contract_code = """
        contract Protocol {
            uint256 public value;
            
            function getValue() external view returns (uint256) {
                return value;
            }
        }
        """
        
        setter_info = self.detector.find_setter_for_param('Value', contract_code)
        
        assert setter_info is None
    
    def test_unprotected_setter(self):
        """Test detection of unprotected setter."""
        contract_code = """
        contract Protocol {
            function setFees(uint256 fee) external {
                // No access control or validation!
                protocolFee = fee;
            }
        }
        """
        
        setter_info = self.detector.find_setter_for_param('Fees', contract_code)
        
        assert setter_info is not None
        assert setter_info['is_protected'] is False
        assert len(setter_info['protected_by']) == 0
        assert setter_info['has_validation'] is False


class TestCheckValidationInSetter:
    """Test check_validation_in_setter method."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.detector = GovernanceDetector()
    
    def test_governed_parameter(self):
        """Test detecting governed parameter."""
        contract_code = """
        contract GNSTradingCallbacksV6_4 {
            function setFees(uint64[] memory xFee, int64[] memory yFee) external onlyGov {
                require(xFee.length == yFee.length, "LENGTH_MISMATCH");
                for (uint256 i = 1; i < yFee.length; i++) {
                    require(yFee[i] >= yFee[i-1], "FEES_NOT_MONOTONIC");
                }
                xFeeMint = xFee;
                yFeeMint = yFee;
            }
        }
        """
        
        result = self.detector.check_validation_in_setter('Fee', contract_code)
        
        assert result['governed'] is True
        assert 'onlyGov' in result['reason']
        assert result['confidence'] >= 0.8
    
    def test_non_governed_parameter(self):
        """Test detecting non-governed parameter."""
        contract_code = """
        contract Protocol {
            uint256 public fee;
            
            function updateFee(uint256 newFee) external {
                fee = newFee;  // No protection!
            }
        }
        """
        
        result = self.detector.check_validation_in_setter('Fee', contract_code)
        
        # Setter exists but not protected
        assert result['governed'] is False
        assert 'not protected' in result['reason'] or 'No setter found' in result['reason']
    
    def test_no_setter_exists(self):
        """Test when no setter exists."""
        contract_code = """
        contract Protocol {
            uint256 public constant FEE = 100;
        }
        """
        
        result = self.detector.check_validation_in_setter('Fee', contract_code)
        
        assert result['governed'] is False
        assert 'No setter found' in result['reason']


class TestAccessControlDetection:
    """Test access control detection."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.detector = GovernanceDetector()
    
    def test_has_access_control_with_modifier(self):
        """Test detection of access control via modifier."""
        function_code = """
        function withdrawFunds(uint256 amount) external onlyOwner {
            payable(msg.sender).transfer(amount);
        }
        """
        
        result = self.detector.has_access_control(function_code)
        
        assert result['has_access_control'] is True
        assert 'onlyOwner' in result['modifiers']
        assert result['confidence'] >= 0.8
    
    def test_has_access_control_inline(self):
        """Test detection of inline access control."""
        function_code = """
        function withdrawFunds(uint256 amount) external {
            require(msg.sender == owner, "Only owner");
            payable(msg.sender).transfer(amount);
        }
        """
        
        result = self.detector.has_access_control(function_code)
        
        assert result['has_access_control'] is True
        assert result['inline_checks'] > 0
    
    def test_no_access_control(self):
        """Test detection of missing access control."""
        function_code = """
        function withdrawFunds(uint256 amount) external {
            payable(msg.sender).transfer(amount);  // No access control!
        }
        """
        
        result = self.detector.has_access_control(function_code)
        
        assert result['has_access_control'] is False
        assert len(result['modifiers']) == 0
        assert result['inline_checks'] == 0


class TestGovernanceFunctionDetection:
    """Test governance function detection."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.detector = GovernanceDetector()
    
    def test_is_governance_function(self):
        """Test identifying governance functions."""
        contract_code = """
        contract Protocol {
            function setParameter(uint256 value) external onlyGovernor {
                parameter = value;
            }
            
            function publicFunction() external {
                // Anyone can call
            }
        }
        """
        
        assert self.detector.is_governance_function('setParameter', contract_code) is True
        assert self.detector.is_governance_function('publicFunction', contract_code) is False
    
    def test_nonexistent_function(self):
        """Test with nonexistent function."""
        contract_code = "contract Test {}"
        
        assert self.detector.is_governance_function('nonExistent', contract_code) is False


class TestGovernanceSummary:
    """Test governance summary generation."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.detector = GovernanceDetector()
    
    def test_governance_summary(self):
        """Test getting governance summary."""
        contract_code = """
        contract Protocol {
            function setFees(uint256 fee) external onlyOwner {
                protocolFee = fee;
            }
            
            function setOracle(address oracle) external onlyGovernor {
                oracleAddress = oracle;
            }
            
            function publicFunction() external {
                // Public access
            }
        }
        """
        
        summary = self.detector.get_governance_summary(contract_code)
        
        assert 'total_setters' in summary
        assert 'protected_functions' in summary
        assert 'has_governance' in summary
        assert summary['total_setters'] >= 2
        assert summary['protected_functions'] >= 2
        assert summary['has_governance'] is True
    
    def test_no_governance_summary(self):
        """Test summary for contract without governance."""
        contract_code = """
        contract SimpleContract {
            uint256 public value;
            
            function getValue() external view returns (uint256) {
                return value;
            }
        }
        """
        
        summary = self.detector.get_governance_summary(contract_code)
        
        assert summary['has_governance'] is False
        assert summary['protected_functions'] == 0


class TestValidationDetector:
    """Test cases for ValidationDetector."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.detector = ValidationDetector()
    
    def test_check_if_validated(self):
        """Test checking if location has validation."""
        contract_code = """
        pragma solidity 0.7.6;
        
        contract Token {
            function transfer(address to, uint256 amount) external {
                require(to != address(0), "Invalid address");
                require(amount > 0, "Invalid amount");
                require(balance >= amount, "Insufficient balance");
                
                balance = balance - amount;  // Line 10
            }
        }
        """
        
        # Line 10 has validation before it
        assert self.detector.check_if_validated(10, contract_code) is True
    
    def test_no_validation(self):
        """Test when no validation exists."""
        contract_code = """
        pragma solidity 0.7.6;
        
        contract Vulnerable {
            function transfer(uint256 amount) external {
                balance = balance - amount;  // Line 6, no validation
            }
        }
        """
        
        assert self.detector.check_if_validated(6, contract_code) is False
    
    def test_get_validation_context(self):
        """Test getting detailed validation context."""
        contract_code = """
        contract Token {
            function transfer(uint256 amount) external {
                require(amount > 0);
                require(balance >= amount);
                
                balance = balance - amount;  // Line 7
            }
        }
        """
        
        context = self.detector.get_validation_context(7, contract_code)
        
        assert context['has_validation'] is True
        assert len(context['validations']) > 0
        assert context['context_lines'] > 0


class TestRealWorldCases:
    """Test real-world governance scenarios."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.detector = GovernanceDetector()
    
    def test_gains_network_fee_setter(self):
        """Test Gains Network fee setter detection."""
        contract_code = """
        pragma solidity 0.8.28;
        
        contract GNSTradingCallbacksV6_4 {
            uint64[] public xFeeMint;
            int64[] public yFeeMint;
            
            function setFees(uint64[] memory xFee, int64[] memory yFee) external onlyGov {
                require(xFee.length == yFee.length, "LENGTH_MISMATCH");
                
                for (uint256 i = 1; i < yFee.length; i++) {
                    require(yFee[i] >= yFee[i-1], "FEES_NOT_MONOTONIC");
                }
                
                xFeeMint = xFee;
                yFeeMint = yFee;
            }
        }
        """
        
        result = self.detector.check_validation_in_setter('Fee', contract_code)
        
        assert result['governed'] is True
        assert 'onlyGov' in result['reason']
        assert result['confidence'] >= 0.9
    
    def test_rocket_pool_network_contract_access(self):
        """Test RocketPool network contract access control."""
        contract_code = """
        pragma solidity 0.7.6;
        
        contract RocketVault {
            modifier onlyLatestNetworkContract(string memory _contractName) {
                require(msg.sender == rocketStorage.getAddress(
                    keccak256(abi.encodePacked("contract.address", _contractName))
                ));
                _;
            }
            
            function withdrawEther(uint256 _amount) external onlyLatestNetworkContract("rocketVault") {
                payable(msg.sender).transfer(_amount);
            }
        }
        """
        
        # Check if withdrawEther is governance-protected
        assert self.detector.is_governance_function('withdrawEther', contract_code) is True


class TestFunctionBraceMatching:
    """Test function brace matching logic."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.detector = GovernanceDetector()
    
    def test_simple_function_end(self):
        """Test finding end of simple function."""
        contract_code = """
        function test() external {
            value = 1;
        }
        """
        
        start_pos = contract_code.find('{') + 1
        end_pos = self.detector._find_function_end(start_pos, contract_code)
        
        # Should find the closing brace
        assert end_pos > start_pos
        assert contract_code[end_pos - 1] == '}'
    
    def test_nested_braces_function(self):
        """Test finding end of function with nested braces."""
        contract_code = """
        function complex() external {
            if (condition) {
                for (uint i = 0; i < 10; i++) {
                    value = i;
                }
            }
        }
        """
        
        start_pos = contract_code.find('{') + 1
        end_pos = self.detector._find_function_end(start_pos, contract_code)
        
        # Should find the outermost closing brace
        assert end_pos > start_pos
        # Should have extracted the function body correctly
        # The extracted section should end after the final closing brace
        assert contract_code[end_pos - 1] == '}'


class TestValidationDetector:
    """Test cases for ValidationDetector."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.detector = ValidationDetector()
    
    def test_require_detection(self):
        """Test detection of require statements."""
        contract_code = """
        contract Token {
            function transfer(uint256 amount) external {
                require(amount > 0);
                require(balance >= amount);
                balance = balance - amount;  // Line 6
            }
        }
        """
        
        assert self.detector.check_if_validated(6, contract_code, vuln_type='arithmetic') is True
    
    def test_revert_detection(self):
        """Test detection of revert statements."""
        contract_code = """
        contract Token {
            function transfer(uint256 amount) external {
                if (amount == 0) revert("Invalid");
                if (balance < amount) revert("Insufficient");
                balance = balance - amount;  // Line 6
            }
        }
        """
        
        assert self.detector.check_if_validated(6, contract_code, vuln_type='arithmetic') is True
    
    def test_safemath_detection(self):
        """Test detection of SafeMath usage."""
        contract_code = """
        contract Token {
            using SafeMath for uint256;
            
            function transfer(uint256 amount) external {
                balance = balance.sub(amount);  // Line 6
            }
        }
        """
        
        # SafeMath should be detected in context
        assert self.detector.check_if_validated(6, contract_code, vuln_type='arithmetic') is True
    
    def test_modifier_protection_detection(self):
        """Test detection of modifier with require."""
        contract_code = """
        contract Token {
            modifier validAmount(uint256 amount) {
                require(amount > 0);
                require(amount <= maxAmount);
                _;
            }
            
            function transfer(uint256 amount) external validAmount(amount) {
                balance = balance - amount;  // Line 10
            }
        }
        """
        
        # Modifier pattern should be detected (for arithmetic)
        assert self.detector.check_if_validated(10, contract_code, vuln_type='arithmetic') is True


class TestGovernancePatterns:
    """Test various governance patterns."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.detector = GovernanceDetector()
    
    def test_timelock_pattern(self):
        """Test detection of timelock governance."""
        contract_code = """
        contract Protocol {
            function setParameter(uint256 value) external onlyGovernor {
                require(msg.sender == timelock, "Only timelock");
                parameter = value;
            }
        }
        """
        
        result = self.detector.check_validation_in_setter('Parameter', contract_code)
        
        assert result['governed'] is True
    
    def test_multisig_pattern(self):
        """Test detection of multisig governance."""
        contract_code = """
        contract Protocol {
            function setConfig(bytes memory config) external onlyController {
                configuration = config;
            }
        }
        """
        
        result = self.detector.check_validation_in_setter('Config', contract_code)
        
        assert result['governed'] is True
        assert 'onlyController' in result['reason']
    
    def test_role_based_access(self):
        """Test detection of role-based access control."""
        contract_code = """
        contract Protocol {
            function setFee(uint256 fee) external onlyRole(ADMIN_ROLE) {
                protocolFee = fee;
            }
        }
        """
        
        result = self.detector.check_validation_in_setter('Fee', contract_code)
        
        assert result['governed'] is True
        assert 'onlyRole' in result['reason']


class TestEdgeCases:
    """Test edge cases and error handling."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.detector = GovernanceDetector()
    
    def test_empty_contract(self):
        """Test with empty contract."""
        contract_code = ""
        
        result = self.detector.check_validation_in_setter('Fee', contract_code)
        
        assert result['governed'] is False
    
    def test_malformed_function(self):
        """Test with malformed function."""
        contract_code = """
        contract Test {
            function setFee  // Missing everything
        }
        """
        
        result = self.detector.check_validation_in_setter('Fee', contract_code)
        
        # Should handle gracefully
        assert isinstance(result, dict)
        assert 'governed' in result
    
    def test_case_insensitive_matching(self):
        """Test case-insensitive parameter matching."""
        contract_code = """
        contract Protocol {
            function setfees(uint256 fee) external onlyOwner {
                protocolFee = fee;
            }
        }
        """
        
        # Should match 'fees' even with different capitalization
        setter_info = self.detector.find_setter_for_param('Fee', contract_code)
        
        assert setter_info is not None
        assert setter_info['is_protected'] is True


class TestComplexContracts:
    """Test with complex real-world contracts."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.detector = GovernanceDetector()
    
    def test_multiple_setters(self):
        """Test contract with multiple setter functions."""
        contract_code = """
        contract Protocol {
            function setFees(uint256 fee) external onlyOwner {
                protocolFee = fee;
            }
            
            function setOracle(address oracle) external onlyGovernor {
                oracleAddress = oracle;
            }
            
            function setParameter(bytes memory param) external onlyAdmin {
                configuration = param;
            }
        }
        """
        
        summary = self.detector.get_governance_summary(contract_code)
        
        assert summary['total_setters'] >= 3
        assert summary['protected_functions'] >= 3
        assert summary['has_governance'] is True
    
    def test_inherited_access_control(self):
        """Test detection of inherited access control."""
        contract_code = """
        import "@openzeppelin/contracts/access/Ownable.sol";
        
        contract Protocol is Ownable {
            function setFees(uint256 fee) external onlyOwner {
                protocolFee = fee;
            }
        }
        """
        
        result = self.detector.check_validation_in_setter('Fee', contract_code)
        
        # Should detect onlyOwner even from inherited contract
        assert result['governed'] is True


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

