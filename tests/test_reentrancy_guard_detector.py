#!/usr/bin/env python3
"""
Tests for Reentrancy Guard Detector Module

Tests detection of existing reentrancy protection mechanisms.
"""

import pytest
from core.reentrancy_guard_detector import ReentrancyGuardDetector, ReentrancyProtection


class TestReentrancyGuardDetector:
    """Test cases for ReentrancyGuardDetector."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.detector = ReentrancyGuardDetector()
    
    def test_initialization(self):
        """Test detector initialization."""
        assert len(self.detector.REENTRANCY_MODIFIERS) > 0
        assert 'nonReentrant' in self.detector.REENTRANCY_MODIFIERS
        assert len(self.detector.REENTRANCY_GUARD_LIBRARIES) > 0


class TestModifierDetection:
    """Test detection of reentrancy modifiers."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.detector = ReentrancyGuardDetector()
    
    def test_detects_nonreentrant_modifier(self):
        """Test detection of nonReentrant modifier."""
        contract_code = """
        pragma solidity 0.8.28;
        
        contract RewardHandler {
            function sellRewards(uint256 minAmountOut, bytes memory payload) 
                external 
                nonReentrant 
                returns (uint256 amountOut) 
            {
                ODOS_ROUTER.call(payload);
            }
        }
        """
        
        protections = self.detector.detect_protections(contract_code, 'RewardHandler')
        
        assert len(protections) > 0
        assert any(p.mechanism == 'nonReentrant' for p in protections)
        
        nonreentrant_protection = next(p for p in protections if p.mechanism == 'nonReentrant')
        assert nonreentrant_protection.function_name == 'sellRewards'
        assert nonreentrant_protection.protection_type == 'modifier'
    
    def test_detects_reentrancyguard_modifier(self):
        """Test detection of reentrancyGuard modifier."""
        contract_code = """
        contract Test {
            function withdraw() external reentrancyGuard {
                msg.sender.call{value: balance}("");
            }
        }
        """
        
        protections = self.detector.detect_protections(contract_code, 'Test')
        
        assert len(protections) > 0
        assert any(p.mechanism == 'reentrancyGuard' for p in protections)
    
    def test_detects_lock_modifier(self):
        """Test detection of lock/mutex modifier."""
        contract_code = """
        contract Test {
            function withdraw() external lock {
                msg.sender.call{value: balance}("");
            }
        }
        """
        
        protections = self.detector.detect_protections(contract_code, 'Test')
        
        assert len(protections) > 0
        assert any(p.mechanism == 'lock' for p in protections)


class TestLibraryInheritanceDetection:
    """Test detection of reentrancy guard libraries."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.detector = ReentrancyGuardDetector()
    
    def test_detects_reentrancyguard_inheritance(self):
        """Test detection of ReentrancyGuard inheritance."""
        contract_code = """
        pragma solidity ^0.8.0;
        
        import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
        
        contract Vault is ReentrancyGuard {
            function withdraw() external {
                // Protected by inherited guard
            }
        }
        """
        
        protections = self.detector.detect_protections(contract_code, 'Vault')
        
        assert len(protections) > 0
        library_protections = [p for p in protections if p.protection_type == 'library']
        assert len(library_protections) > 0
        assert any('ReentrancyGuard' in p.mechanism for p in library_protections)
    
    def test_detects_upgradeable_reentrancyguard(self):
        """Test detection of ReentrancyGuardUpgradeable."""
        contract_code = """
        import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
        
        contract Vault is ReentrancyGuardUpgradeable {
            function withdraw() external {
                // Protected
            }
        }
        """
        
        protections = self.detector.detect_protections(contract_code, 'Vault')
        
        assert len(protections) > 0
        assert any('ReentrancyGuard' in p.mechanism for p in protections)


class TestCustomMutexDetection:
    """Test detection of custom mutex patterns."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.detector = ReentrancyGuardDetector()
    
    def test_detects_locked_variable(self):
        """Test detection of locked variable pattern."""
        contract_code = """
        contract Vault {
            uint256 private locked;
            
            function withdraw() external {
                require(locked == 0, "Reentrant call");
                locked = 1;
                msg.sender.call{value: balance}("");
                locked = 0;
            }
        }
        """
        
        protections = self.detector.detect_protections(contract_code, 'Vault')
        
        assert len(protections) > 0
        assert any(p.protection_type == 'pattern' for p in protections)
    
    def test_detects_entered_flag(self):
        """Test detection of _entered flag pattern."""
        contract_code = """
        contract Vault {
            bool private _entered;
            
            function withdraw() external {
                require(!_entered, "Reentrant");
                _entered = true;
                msg.sender.call{value: balance}("");
                _entered = false;
            }
        }
        """
        
        protections = self.detector.detect_protections(contract_code, 'Vault')
        
        assert len(protections) > 0
        assert any(p.protection_type == 'pattern' for p in protections)


class TestFunctionProtectionCheck:
    """Test checking if specific functions are protected."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.detector = ReentrancyGuardDetector()
    
    def test_function_is_protected(self):
        """Test that protected function is detected."""
        contract_code = """
        contract Test {
            function withdraw() external nonReentrant {
                msg.sender.call{value: balance}("");
            }
        }
        """
        
        protections = self.detector.detect_protections(contract_code, 'Test')
        
        is_protected = self.detector.is_function_protected(
            'withdraw', 10, protections
        )
        
        assert is_protected is True
    
    def test_function_not_protected(self):
        """Test that unprotected function is detected."""
        contract_code = """
        contract Test {
            function withdraw() external {
                msg.sender.call{value: balance}("");
            }
        }
        """
        
        protections = self.detector.detect_protections(contract_code, 'Test')
        
        is_protected = self.detector.is_function_protected(
            'withdraw', 10, protections
        )
        
        assert is_protected is False
    
    def test_global_protection_covers_all_functions(self):
        """Test that library inheritance protects all functions."""
        contract_code = """
        import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
        
        contract Test is ReentrancyGuard {
            function withdraw() external {
                // Implicitly protected
            }
        }
        """
        
        protections = self.detector.detect_protections(contract_code, 'Test')
        
        # Global protection (library) should protect all functions
        is_protected = self.detector.is_function_protected(
            'withdraw', 10, protections
        )
        
        assert is_protected is True


class TestVulnerabilityFiltering:
    """Test vulnerability filtering with reentrancy guards."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.detector = ReentrancyGuardDetector()
    
    def test_filters_protected_function(self):
        """Test filtering reentrancy vulnerability in protected function."""
        contract_code = """
        contract RewardHandler {
            function sellRewards() external nonReentrant {
                ODOS_ROUTER.call(payload);
            }
        }
        """
        
        vulnerability = {
            'type': 'reentrancy',
            'function': 'sellRewards',
            'line': 34
        }
        
        should_filter, reason = self.detector.should_filter_reentrancy_vuln(
            vulnerability, contract_code, 'RewardHandler'
        )
        
        assert should_filter is True
        assert 'nonReentrant' in reason
    
    def test_does_not_filter_unprotected_function(self):
        """Test that unprotected functions are not filtered."""
        contract_code = """
        contract Vulnerable {
            function withdraw() external {
                msg.sender.call{value: balance}("");
            }
        }
        """
        
        vulnerability = {
            'type': 'reentrancy',
            'function': 'withdraw',
            'line': 10
        }
        
        should_filter, reason = self.detector.should_filter_reentrancy_vuln(
            vulnerability, contract_code, 'Vulnerable'
        )
        
        assert should_filter is False
        assert reason == ""


class TestCEIPatternCheck:
    """Test Checks-Effects-Interactions pattern detection."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.detector = ReentrancyGuardDetector()
    
    def test_detects_cei_compliance(self):
        """Test detection of CEI pattern compliance."""
        function_code = """
        function withdraw(uint256 amount) external {
            require(balances[msg.sender] >= amount);  // Check
            balances[msg.sender] -= amount;           // Effect
            msg.sender.call{value: amount}("");       // Interaction
        }
        """
        
        result = self.detector.check_cei_pattern(function_code)
        
        assert result['follows_cei'] is True
        assert result['checks_count'] > 0
        assert result['effects_count'] > 0
        assert result['interactions_count'] > 0
    
    def test_detects_cei_violation(self):
        """Test detection of CEI pattern violation."""
        function_code = """
        function withdraw(uint256 amount) external {
            require(balances[msg.sender] >= amount);  // Check
            msg.sender.call{value: amount}("");       // Interaction
            balances[msg.sender] -= amount;           # Effect AFTER interaction (violation)
        }
        """
        
        result = self.detector.check_cei_pattern(function_code)
        
        assert result['follows_cei'] is False
        assert len(result['violations']) > 0


class TestParallelProtocolFinding3:
    """Regression test for Parallel Protocol Finding #3."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.detector = ReentrancyGuardDetector()
    
    def test_rewardhandler_nonreentrant_detected(self):
        """Test that RewardHandler nonReentrant modifier is detected."""
        contract_code = """
        pragma solidity 0.8.28;
        
        contract RewardHandler {
            function sellRewards(uint256 minAmountOut, bytes memory payload) 
                external 
                nonReentrant 
                returns (uint256 amountOut) 
            {
                (bool success, bytes memory result) = ODOS_ROUTER.call(payload);
                if (!success) _revertBytes(result);
                
                for (uint256 i; i < listLength; ++i) {
                    uint256 newBalance = IERC20(list[i]).balanceOf(address(this));
                    if (newBalance < balances[i]) {
                        revert InvalidSwap();
                    }
                }
            }
        }
        """
        
        vulnerability = {
            'type': 'insufficient_balance_invariance_check',
            'function': 'sellRewards',
            'line': 65,
            'description': 'Balance checks can be bypassed with tokens with hooks'
        }
        
        should_filter, reason = self.detector.should_filter_reentrancy_vuln(
            vulnerability, contract_code, 'RewardHandler'
        )
        
        assert should_filter is True
        assert 'nonReentrant' in reason


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

