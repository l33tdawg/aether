#!/usr/bin/env python3
"""
Tests for Design Assumption Detector Module

Tests detection of documented design assumptions to prevent false positives.
"""

import pytest
from core.design_assumption_detector import DesignAssumptionDetector, DesignAssumption


class TestDesignAssumptionDetector:
    """Test cases for DesignAssumptionDetector."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.detector = DesignAssumptionDetector()
    
    def test_initialization(self):
        """Test detector initialization."""
        assert len(self.detector.ASSUMPTION_PATTERNS) > 0
        assert 'trusted_token' in self.detector.ASSUMPTION_PATTERNS
        assert 'trusted_oracle' in self.detector.ASSUMPTION_PATTERNS
        assert len(self.detector.compiled_patterns) > 0
    
    def test_detects_trusted_token_assumption(self):
        """Test detection of trusted token assumption."""
        contract_code = """
        pragma solidity 0.8.28;
        
        /// @dev Implementations assume that asset is safe to interact with,
        /// on which there cannot be reentrancy attacks
        contract BaseSavings {
            function _accrue() internal {
                ITokenP(asset()).mint(address(this), earned);
            }
        }
        """
        
        assumptions = self.detector.detect_assumptions(contract_code, 'BaseSavings')
        
        assert len(assumptions) > 0
        assert any(a.assumption_type == 'trusted_token' for a in assumptions)
        
        trusted_token_assumption = next(a for a in assumptions if a.assumption_type == 'trusted_token')
        assert 'asset is safe' in trusted_token_assumption.trust_requirement.lower()
    
    def test_detects_authorized_fork_pattern(self):
        """Test detection of authorized fork pattern."""
        contract_code = """
        pragma solidity 0.8.28;
        
        /// @title Savings
        /// @author Cooper Labs
        /// @dev This contract is an authorized fork of Angle's Savings contract:
        /// https://github.com/AngleProtocol/angle-transmuter
        contract Savings is BaseSavings {
            // Contract code
        }
        """
        
        assumptions = self.detector.detect_assumptions(contract_code, 'Savings')
        
        assert len(assumptions) > 0
        assert any(a.assumption_type == 'inherited_security' for a in assumptions)
    
    def test_detects_known_limitation(self):
        """Test detection of known limitation comments."""
        contract_code = """
        pragma solidity 0.8.0;
        
        /// @notice Known limitation: does not support ERC777 tokens
        /// @dev By design, this contract only works with standard ERC20
        contract Vault {
            function deposit(IERC20 token, uint256 amount) external {
                token.transferFrom(msg.sender, address(this), amount);
            }
        }
        """
        
        assumptions = self.detector.detect_assumptions(contract_code, 'Vault')
        
        assert len(assumptions) > 0
        known_limitation = any(a.assumption_type == 'known_limitation' for a in assumptions)
        assert known_limitation


class TestVulnerabilityAssumptionMapping:
    """Test vulnerability to assumption mapping."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.detector = DesignAssumptionDetector()
    
    def test_reentrancy_maps_to_trusted_token(self):
        """Test that reentrancy vulnerabilities map to trusted_token assumptions."""
        contract_code = """
        /// @dev Assumes that asset is safe to interact with
        contract Test {}
        """
        
        assumptions = self.detector.detect_assumptions(contract_code, 'Test')
        
        vulnerability = {
            'type': 'reentrancy',
            'line': 10,
            'function': 'withdraw'
        }
        
        is_safe = self.detector.is_vulnerability_assumed_safe(vulnerability, assumptions)
        
        assert is_safe is True
    
    def test_oracle_vulnerability_maps_to_trusted_oracle(self):
        """Test that oracle vulnerabilities map to trusted_oracle assumptions."""
        contract_code = """
        /// @dev Assumes oracle is trusted and provides accurate data
        contract PriceFeed {}
        """
        
        assumptions = self.detector.detect_assumptions(contract_code, 'PriceFeed')
        
        vulnerability = {
            'type': 'oracle_manipulation',
            'line': 10
        }
        
        is_safe = self.detector.is_vulnerability_assumed_safe(vulnerability, assumptions)
        
        assert is_safe is True
    
    def test_no_matching_assumption_returns_false(self):
        """Test that vulnerabilities without matching assumptions return False."""
        contract_code = """
        pragma solidity 0.8.0;
        
        contract Test {
            function test() external {}
        }
        """
        
        assumptions = self.detector.detect_assumptions(contract_code, 'Test')
        
        vulnerability = {
            'type': 'reentrancy',
            'line': 10
        }
        
        is_safe = self.detector.is_vulnerability_assumed_safe(vulnerability, assumptions)
        
        # No assumptions, should not be considered safe
        assert is_safe is False


class TestParallelProtocolRegressionCases:
    """Regression tests for Parallel Protocol false positives."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.detector = DesignAssumptionDetector()
    
    def test_basesavings_trusted_asset_assumption(self):
        """Test BaseSavings trusted asset assumption (Finding #1)."""
        contract_code = """
        pragma solidity 0.8.28;
        
        /// @title BaseSavings
        /// @dev Implementations assume that `asset` is safe to interact with,
        /// on which there cannot be reentrancy attacks
        /// @dev This contract is an authorized fork of Angle's Savings contract
        abstract contract BaseSavings {
            function _accrue() internal {
                ITokenP(asset()).mint(address(this), earned);
            }
        }
        """
        
        assumptions = self.detector.detect_assumptions(contract_code, 'BaseSavings')
        
        # Should detect trusted token assumption
        assert len(assumptions) >= 2  # trusted_token + inherited_security
        
        vulnerability = {
            'type': 'reentrancy_in_accrue_path_via_asset_token',
            'line': 10,
            'description': 'External call to asset token without nonReentrant guard'
        }
        
        is_safe = self.detector.is_vulnerability_assumed_safe(vulnerability, assumptions)
        assert is_safe is True
    
    def test_rewardhandler_balance_check_assumption(self):
        """Test RewardHandler balance check assumption (Finding #3)."""
        contract_code = """
        pragma solidity 0.8.28;
        
        /// @title RewardHandler
        /// @dev This contract is an authorized fork of Angle's RewardHandler
        /// @dev Assumes collateral tokens are well-behaved standard ERC20
        contract RewardHandler {
            function sellRewards() external nonReentrant {
                // Balance checks
            }
        }
        """
        
        assumptions = self.detector.detect_assumptions(contract_code, 'RewardHandler')
        
        vulnerability = {
            'type': 'insufficient_balance_invariance_check',
            'line': 65,
            'description': 'Tokens with transfer hooks can manipulate balance'
        }
        
        is_safe = self.detector.is_vulnerability_assumed_safe(vulnerability, assumptions)
        assert is_safe is True


class TestInheritedSecurityDetection:
    """Test detection of inherited security models."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.detector = DesignAssumptionDetector()
    
    def test_detects_openzeppelin_inheritance(self):
        """Test detection of OpenZeppelin imports."""
        contract_code = """
        pragma solidity ^0.8.0;
        
        import "@openzeppelin/contracts/access/Ownable.sol";
        import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
        
        contract MyContract is Ownable, ReentrancyGuard {
            // Contract code
        }
        """
        
        inherited = self.detector.detect_inherited_security(contract_code)
        
        assert inherited is not None
        assert inherited['source'] == 'openzeppelin'
        assert 'audited' in inherited['audit_status'].lower()
    
    def test_detects_angle_fork(self):
        """Test detection of Angle Protocol fork."""
        contract_code = """
        /// @dev This contract is an authorized fork of Angle's Transmuter
        /// https://github.com/AngleProtocol/angle-transmuter
        contract Parallelizer {
            // Contract code
        }
        """
        
        inherited = self.detector.detect_inherited_security(contract_code)
        
        assert inherited is not None
        assert inherited['source'] == 'angle'
        assert 'Code4rena' in inherited['audit_status']
    
    def test_detects_aave_fork(self):
        """Test detection of Aave fork."""
        contract_code = """
        /// @notice Based on Aave V3 pool logic
        contract LendingPool {
            // Contract code
        }
        """
        
        inherited = self.detector.detect_inherited_security(contract_code)
        
        assert inherited is not None
        assert inherited['source'] == 'aave'


class TestFilterReasonGeneration:
    """Test filter reason generation."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.detector = DesignAssumptionDetector()
    
    def test_generate_filter_reason(self):
        """Test generating filter reason."""
        assumption = DesignAssumption(
            assumption_type='trusted_token',
            description='Assumes asset is safe to interact with',
            location='BaseSavings:L25',
            trust_requirement='asset is safe',
            patterns=['assume.*asset.*safe']
        )
        
        vulnerability = {
            'type': 'reentrancy',
            'line': 108
        }
        
        reason = self.detector.generate_filter_reason(vulnerability, assumption)
        
        assert 'Design assumption' in reason
        assert 'BaseSavings:L25' in reason
        assert 'asset is safe' in reason
        assert 'documented limitation' in reason.lower()


class TestEdgeCases:
    """Test edge cases and error handling."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.detector = DesignAssumptionDetector()
    
    def test_empty_contract(self):
        """Test with empty contract."""
        assumptions = self.detector.detect_assumptions('', 'Empty')
        assert len(assumptions) == 0
    
    def test_contract_without_comments(self):
        """Test contract without any comments."""
        contract_code = """
        pragma solidity ^0.8.0;
        contract NoComments {
            uint256 public value;
            function setValue(uint256 v) external { value = v; }
        }
        """
        
        assumptions = self.detector.detect_assumptions(contract_code, 'NoComments')
        assert len(assumptions) == 0
    
    def test_multiline_comment_detection(self):
        """Test detection in multiline comments."""
        contract_code = """
        /**
         * @title Test Contract
         * @dev This contract assumes that all tokens are safe
         * and cannot be used for reentrancy attacks
         */
        contract Test {}
        """
        
        assumptions = self.detector.detect_assumptions(contract_code, 'Test')
        
        assert len(assumptions) > 0
        assert any('safe' in a.description.lower() for a in assumptions)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

