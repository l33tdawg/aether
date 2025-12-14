#!/usr/bin/env python3
"""
Tests for Design Pattern Detector

Tests the detection of intentional design patterns that might appear
as vulnerabilities but are actually safe by design.
"""

import pytest
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.design_pattern_detector import (
    DesignPatternDetector,
    SafePatternType,
    PatternMatchResult
)


class TestDesignPatternDetector:
    """Test cases for DesignPatternDetector."""
    
    @pytest.fixture
    def detector(self):
        """Create detector instance."""
        return DesignPatternDetector()
    
    def test_migration_helper_detection(self, detector):
        """Test detection of migration helper pattern."""
        function_name = "transferFundsFromSharedBridge"
        function_code = """
        function transferFundsFromSharedBridge(address _token) external {
            ensureTokenIsRegistered(_token);
            L1_NULLIFIER.transferTokenToNTV(_token);
            if (balanceAfter <= balanceBefore) {
                revert NoFundsTransferred();
            }
        }
        """
        contract_code = function_code
        
        result = detector.detect_safe_pattern(function_name, function_code, contract_code)
        
        assert result.is_safe_pattern is True
        assert result.pattern_type == SafePatternType.MIGRATION_HELPER
        assert result.confidence >= 0.7
    
    def test_update_chain_balances_detection(self, detector):
        """Test detection of updateChainBalances pattern."""
        function_name = "updateChainBalancesFromSharedBridge"
        function_code = """
        function updateChainBalancesFromSharedBridge(address _token, uint256 _targetChainId) external {
            uint256 nullifierChainBalance = L1_NULLIFIER.chainBalance(_targetChainId, _token);
            chainBalance[_targetChainId][assetId] = chainBalance[_targetChainId][assetId] + nullifierChainBalance;
        }
        """
        contract_code = function_code
        
        result = detector.detect_safe_pattern(function_name, function_code, contract_code)
        
        assert result.is_safe_pattern is True
        assert result.pattern_type == SafePatternType.MIGRATION_HELPER
    
    def test_pull_payment_detection(self, detector):
        """Test detection of pull payment pattern."""
        function_name = "claimRewards"
        function_code = """
        function claimRewards() external {
            uint256 amount = balances[msg.sender];
            balances[msg.sender] = 0;
            token.safeTransfer(msg.sender, amount);
        }
        """
        contract_code = function_code
        
        result = detector.detect_safe_pattern(function_name, function_code, contract_code)
        
        assert result.is_safe_pattern is True
        assert result.pattern_type == SafePatternType.PULL_PAYMENT
    
    def test_withdraw_pattern_detection(self, detector):
        """Test detection of withdraw pattern."""
        function_name = "withdrawFunds"
        function_code = """
        function withdrawFunds(uint256 amount) external {
            require(balances[msg.sender] >= amount, "Insufficient balance");
            balances[msg.sender] -= amount;
            token.safeTransfer(msg.sender, amount);
        }
        """
        contract_code = function_code
        
        result = detector.detect_safe_pattern(function_name, function_code, contract_code)
        
        assert result.is_safe_pattern is True
        assert result.pattern_type == SafePatternType.PULL_PAYMENT
    
    def test_factory_deploy_detection(self, detector):
        """Test detection of factory deploy pattern."""
        function_name = "createPool"
        function_code = """
        function createPool(address tokenA, address tokenB) external returns (address) {
            address pool = address(new Pool(tokenA, tokenB));
            pools[tokenA][tokenB] = pool;
            return pool;
        }
        """
        contract_code = function_code
        
        result = detector.detect_safe_pattern(function_name, function_code, contract_code)
        
        assert result.is_safe_pattern is True
        assert result.pattern_type == SafePatternType.FACTORY_DEPLOY
    
    def test_clone_factory_detection(self, detector):
        """Test detection of clone factory pattern."""
        function_name = "deployClone"
        function_code = """
        function deployClone(bytes32 salt) external returns (address) {
            address clone = Clones.cloneDeterministic(implementation, salt);
            emit CloneDeployed(clone);
            return clone;
        }
        """
        contract_code = function_code
        
        result = detector.detect_safe_pattern(function_name, function_code, contract_code)
        
        assert result.is_safe_pattern is True
        assert result.pattern_type == SafePatternType.FACTORY_DEPLOY
    
    def test_sync_operation_detection(self, detector):
        """Test detection of sync operation pattern."""
        function_name = "sync"
        function_code = """
        function sync() external {
            reserve0 = IERC20(token0).balanceOf(address(this));
            reserve1 = IERC20(token1).balanceOf(address(this));
        }
        """
        contract_code = function_code
        
        result = detector.detect_safe_pattern(function_name, function_code, contract_code)
        
        assert result.is_safe_pattern is True
        assert result.pattern_type == SafePatternType.SYNC_OPERATION
    
    def test_bridge_relay_detection(self, detector):
        """Test detection of bridge relay pattern."""
        function_name = "relayMessage"
        function_code = """
        function relayMessage(bytes calldata message, bytes32[] calldata merkleProof) external {
            bytes32 messageHash = keccak256(message);
            require(verifyProof(messageHash, merkleProof), "Invalid proof");
            _executeMessage(message);
        }
        """
        contract_code = function_code
        
        result = detector.detect_safe_pattern(function_name, function_code, contract_code)
        
        assert result.is_safe_pattern is True
        assert result.pattern_type == SafePatternType.BRIDGE_RELAY
    
    def test_no_pattern_matched(self, detector):
        """Test when no safe pattern is matched."""
        function_name = "dangerousFunction"
        function_code = """
        function dangerousFunction(address target, uint256 amount) external {
            token.transfer(target, amount);
        }
        """
        contract_code = function_code
        
        result = detector.detect_safe_pattern(function_name, function_code, contract_code)
        
        assert result.is_safe_pattern is False
        assert result.pattern_type is None


class TestIntentionallyPermissionless:
    """Test intentionally permissionless detection."""
    
    @pytest.fixture
    def detector(self):
        return DesignPatternDetector()
    
    def test_documented_permissionless(self, detector):
        """Test detection of documented permissionless functions."""
        contract_code = """
        /**
         * @notice This function is intentionally permissionless.
         * Anyone can call to trigger the migration.
         */
        function transferFundsFromSharedBridge(address _token) external {
            L1_NULLIFIER.transferTokenToNTV(_token);
        }
        """
        
        function_code = """
        function transferFundsFromSharedBridge(address _token) external {
            L1_NULLIFIER.transferTokenToNTV(_token);
        }
        """
        
        finding = {
            'vulnerability_type': 'missing_access_control',
            'description': 'Function lacks access control'
        }
        
        is_intentional, reasoning, confidence = detector.is_intentionally_permissionless(
            'transferFundsFromSharedBridge',
            function_code,
            contract_code,
            finding
        )
        
        # Should detect either the safe pattern or the documentation
        assert is_intentional is True or confidence >= 0.7
    
    def test_internal_only_update(self, detector):
        """Test detection of internal-only update functions."""
        function_code = """
        function updateAccountingState() external {
            totalSupply = token.balanceOf(address(this));
            lastUpdate = block.timestamp;
        }
        """
        
        is_internal = detector._is_internal_only_update(function_code)
        
        assert is_internal is True
    
    def test_external_transfer_not_internal_only(self, detector):
        """Test that external transfers are not internal-only."""
        function_code = """
        function withdraw(address recipient, uint256 amount) external {
            token.transfer(recipient, amount);
        }
        """
        
        is_internal = detector._is_internal_only_update(function_code)
        
        # Has external transfer, so NOT internal-only
        assert is_internal is False


class TestAccessControlFindingFilter:
    """Test filtering of access control findings."""
    
    @pytest.fixture
    def detector(self):
        return DesignPatternDetector()
    
    def test_filter_migration_helper_finding(self, detector):
        """Test filtering access control finding for migration helper."""
        finding = {
            'vulnerability_type': 'missing_access_control',
            'description': 'The transferFundsFromSharedBridge function lacks access control'
        }
        
        function_code = """
        function transferFundsFromSharedBridge(address _token) external {
            L1_NULLIFIER.transferTokenToNTV(_token);
        }
        """
        
        contract_code = function_code
        
        should_filter, reasoning = detector.should_filter_access_control_finding(
            finding,
            'transferFundsFromSharedBridge',
            function_code,
            contract_code
        )
        
        assert should_filter is True
        assert 'migration' in reasoning.lower() or 'permissionless' in reasoning.lower()
    
    def test_dont_filter_real_vulnerability(self, detector):
        """Test that real vulnerabilities are not filtered."""
        finding = {
            'vulnerability_type': 'missing_access_control',
            'description': 'The drainFunds function lacks access control'
        }
        
        # Use a function that transfers funds to an arbitrary address - definitely a vulnerability
        function_code = """
        function drainFunds(address recipient, uint256 amount) external {
            token.transfer(recipient, amount);
            emit FundsDrained(recipient, amount);
        }
        """
        
        contract_code = function_code
        
        should_filter, reasoning = detector.should_filter_access_control_finding(
            finding,
            'drainFunds',
            function_code,
            contract_code
        )
        
        # Should NOT filter - this is a real vulnerability (transfers to arbitrary recipient)
        assert should_filter is False
    
    def test_non_access_control_finding_not_processed(self, detector):
        """Test that non-access-control findings are not processed."""
        finding = {
            'vulnerability_type': 'reentrancy',
            'description': 'Potential reentrancy vulnerability'
        }
        
        function_code = """
        function withdraw() external {
            // some code
        }
        """
        
        should_filter, reasoning = detector.should_filter_access_control_finding(
            finding,
            'withdraw',
            function_code,
            ""
        )
        
        assert should_filter is False
        assert 'Not an access control finding' in reasoning


class TestPatternMatchResult:
    """Test PatternMatchResult dataclass."""
    
    def test_result_creation(self):
        """Test creating pattern match results."""
        result = PatternMatchResult(
            is_safe_pattern=True,
            pattern_type=SafePatternType.MIGRATION_HELPER,
            confidence=0.85,
            reasoning='Migration helper pattern detected',
            matches_found=['transferTokenToNTV', 'chainBalance']
        )
        
        assert result.is_safe_pattern is True
        assert result.pattern_type == SafePatternType.MIGRATION_HELPER
        assert result.confidence == 0.85
        assert len(result.matches_found) == 2


class TestPatternDescriptions:
    """Test pattern description retrieval."""
    
    @pytest.fixture
    def detector(self):
        return DesignPatternDetector()
    
    def test_get_pattern_description(self, detector):
        """Test getting pattern descriptions."""
        for pattern_type in SafePatternType:
            description = detector.get_pattern_description(pattern_type)
            assert isinstance(description, str)
            assert len(description) > 20


class TestEdgeCases:
    """Test edge cases and error handling."""
    
    @pytest.fixture
    def detector(self):
        return DesignPatternDetector()
    
    def test_empty_function_code(self, detector):
        """Test with empty function code."""
        result = detector.detect_safe_pattern('test', '', '')
        
        assert result.is_safe_pattern is False
    
    def test_function_name_case_insensitive(self, detector):
        """Test that function name matching is case-insensitive."""
        function_name = "TRANSFERFUNDSFROMSHAREDBRIDGE"  # All caps
        function_code = """
        function TRANSFERFUNDSFROMSHAREDBRIDGE(address _token) external {
            L1_NULLIFIER.transferTokenToNTV(_token);
        }
        """
        
        result = detector.detect_safe_pattern(function_name, function_code, function_code)
        
        # Should still detect migration pattern
        assert result.is_safe_pattern is True
    
    def test_partial_function_name_match(self, detector):
        """Test partial function name matching."""
        function_name = "migrateTokensToNewVault"
        function_code = """
        function migrateTokensToNewVault(address[] calldata tokens) external {
            for (uint i = 0; i < tokens.length; i++) {
                IERC20(tokens[i]).safeTransfer(address(this), balance);
            }
        }
        """
        
        result = detector.detect_safe_pattern(function_name, function_code, function_code)
        
        # Should detect migration pattern from function name
        assert result.is_safe_pattern is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
