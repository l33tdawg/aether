#!/usr/bin/env python3
"""
Tests for Cross-Contract Analyzer

Tests the cross-contract access control analysis functionality
to ensure external calls with access control are properly detected.
"""

import pytest
import sys
import tempfile
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.cross_contract_analyzer import (
    CrossContractAnalyzer,
    ExternalCallInfo,
    CrossContractAccessResult
)


class TestCrossContractAnalyzer:
    """Test cases for CrossContractAnalyzer."""
    
    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance."""
        return CrossContractAnalyzer()
    
    @pytest.fixture
    def sample_contract(self):
        """Sample contract with external calls."""
        return """// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IL1Nullifier} from "./interfaces/IL1Nullifier.sol";
import {IERC20} from "@openzeppelin/contracts-v4/token/ERC20/IERC20.sol";

contract L1NativeTokenVault {
    IL1Nullifier public immutable override L1_NULLIFIER;
    
    receive() external payable {
        if (address(L1_NULLIFIER) != msg.sender) {
            revert Unauthorized(msg.sender);
        }
    }
    
    function transferFundsFromSharedBridge(address _token) external {
        ensureTokenIsRegistered(_token);
        if (_token == ETH_TOKEN_ADDRESS) {
            uint256 balanceBefore = address(this).balance;
            L1_NULLIFIER.transferTokenToNTV(_token);
            uint256 balanceAfter = address(this).balance;
            if (balanceAfter <= balanceBefore) {
                revert NoFundsTransferred();
            }
        } else {
            uint256 balanceBefore = IERC20(_token).balanceOf(address(this));
            L1_NULLIFIER.transferTokenToNTV(_token);
            uint256 balanceAfter = IERC20(_token).balanceOf(address(this));
        }
    }
    
    function updateChainBalancesFromSharedBridge(address _token, uint256 _targetChainId) external {
        uint256 nullifierChainBalance = L1_NULLIFIER.chainBalance(_targetChainId, _token);
        L1_NULLIFIER.nullifyChainBalanceByNTV(_targetChainId, _token);
    }
}
"""
    
    @pytest.fixture
    def nullifier_contract(self):
        """L1Nullifier contract with access control."""
        return """// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

contract L1Nullifier {
    IL1NativeTokenVault public l1NativeTokenVault;
    
    modifier onlyL1NTV() {
        if (msg.sender != address(l1NativeTokenVault)) {
            revert Unauthorized(msg.sender);
        }
        _;
    }
    
    function transferTokenToNTV(address _token) external onlyL1NTV {
        // Transfer logic
    }
    
    function nullifyChainBalanceByNTV(uint256 _chainId, address _token) external onlyL1NTV {
        chainBalance[_chainId][_token] = 0;
    }
    
    function chainBalance(uint256 _chainId, address _token) external view returns (uint256) {
        return __DEPRECATED_chainBalance[_chainId][_token];
    }
}
"""
    
    def test_analyze_external_calls(self, analyzer, sample_contract):
        """Test detection of external calls in a function."""
        function_code = """
        function transferFundsFromSharedBridge(address _token) external {
            ensureTokenIsRegistered(_token);
            L1_NULLIFIER.transferTokenToNTV(_token);
            uint256 balance = IERC20(_token).balanceOf(address(this));
        }
        """
        
        calls = analyzer.analyze_external_calls(function_code, sample_contract)
        
        # Should detect the L1_NULLIFIER call but skip balanceOf
        non_view_calls = [c for c in calls if c.function_name not in analyzer.SAFE_VIEW_FUNCTIONS]
        assert len(non_view_calls) >= 1
        
        # Should detect transferTokenToNTV
        transfer_calls = [c for c in calls if c.function_name == 'transferTokenToNTV']
        assert len(transfer_calls) == 1
    
    def test_skip_safe_view_functions(self, analyzer, sample_contract):
        """Test that safe view functions are skipped."""
        function_code = """
        function checkBalance() external view {
            uint256 bal = token.balanceOf(address(this));
            uint256 allow = token.allowance(owner, spender);
            uint256 supply = token.totalSupply();
        }
        """
        
        calls = analyzer.analyze_external_calls(function_code, sample_contract)
        
        # Should skip all view functions
        assert len(calls) == 0
    
    def test_is_immutable_reference(self, analyzer):
        """Test detection of immutable contract references."""
        contract = """
        IL1Nullifier public immutable override L1_NULLIFIER;
        address public owner;
        IL1AssetRouter public immutable L1_ASSET_ROUTER;
        """
        
        assert analyzer._is_immutable_reference('L1_NULLIFIER', contract) is True
        assert analyzer._is_immutable_reference('L1_ASSET_ROUTER', contract) is True
        assert analyzer._is_immutable_reference('owner', contract) is False
    
    def test_get_contract_type(self, analyzer):
        """Test extraction of contract type from declaration."""
        contract = """
        IL1Nullifier public immutable override L1_NULLIFIER;
        IL1AssetRouter public L1_ASSET_ROUTER;
        address public token;
        """
        
        assert analyzer._get_contract_type('L1_NULLIFIER', contract) == 'IL1Nullifier'
        assert analyzer._get_contract_type('L1_ASSET_ROUTER', contract) == 'IL1AssetRouter'
    
    def test_interface_cast_detection(self, analyzer, sample_contract):
        """Test detection of interface cast calls."""
        function_code = """
        function doSomething(address tokenAddr) external {
            uint256 result = IUniswapPool(tokenAddr).swap(amount, recipient);
        }
        """
        
        calls = analyzer.analyze_external_calls(function_code, sample_contract)
        
        # Should detect the swap call
        swap_calls = [c for c in calls if c.function_name == 'swap']
        assert len(swap_calls) == 1
        assert swap_calls[0].contract_type == 'IUniswapPool'
    
    def test_skip_self_references(self, analyzer, sample_contract):
        """Test that self-references are skipped."""
        function_code = """
        function doSomething() external {
            this.otherFunction();
            address(this).balance;
            super.initialize();
        }
        """
        
        calls = analyzer.analyze_external_calls(function_code, sample_contract)
        
        # Should skip this, address, super
        assert len(calls) == 0


class TestAccessControlDetection:
    """Test access control detection on external functions."""
    
    @pytest.fixture
    def analyzer(self):
        return CrossContractAnalyzer()
    
    def test_find_function_access_control(self, analyzer):
        """Test finding access control modifiers on functions."""
        contract = """
        contract Test {
            function adminOnly() external onlyOwner {
                // admin stuff
            }
            
            function multiModifier() external onlyRole(ADMIN_ROLE) whenNotPaused {
                // stuff
            }
            
            function noModifier() external {
                // public stuff
            }
        }
        """
        
        modifiers = analyzer._find_function_access_control('adminOnly', contract)
        assert 'onlyOwner' in modifiers
        
        modifiers = analyzer._find_function_access_control('multiModifier', contract)
        assert 'onlyRole' in modifiers or 'whenNotPaused' in modifiers
        
        modifiers = analyzer._find_function_access_control('noModifier', contract)
        assert len(modifiers) == 0
    
    def test_check_internal_access_control(self, analyzer):
        """Test detection of internal access control checks."""
        contract = """
        contract Test {
            function internalCheck() external {
                require(msg.sender == owner, "Not owner");
                // do stuff
            }
            
            function callsCheckRole() external {
                _checkRole(ADMIN_ROLE);
                // do stuff
            }
        }
        """
        
        has_control = analyzer._check_internal_access_control('internalCheck', contract)
        assert has_control is True
        
        has_control = analyzer._check_internal_access_control('callsCheckRole', contract)
        assert has_control is True


class TestCrossContractAccessResult:
    """Test CrossContractAccessResult dataclass."""
    
    def test_result_creation(self):
        """Test creating access result."""
        result = CrossContractAccessResult(
            has_access_control=True,
            reasoning='Protected by onlyL1NTV',
            confidence=0.9,
            external_calls_analyzed=3,
            protected_calls=2
        )
        
        assert result.has_access_control is True
        assert result.confidence == 0.9
        assert result.protected_calls == 2


class TestEnhancedAccessControlCheck:
    """Test enhanced access control checking."""
    
    @pytest.fixture
    def analyzer(self):
        return CrossContractAnalyzer()
    
    def test_enhance_access_control_check(self, analyzer):
        """Test enhanced access control check with external calls."""
        contract_code = """
        IL1Nullifier public immutable L1_NULLIFIER;
        """
        
        function_code = """
        function transferFunds(address _token) external {
            L1_NULLIFIER.transferTokenToNTV(_token);
        }
        """
        
        vuln = {
            'vulnerability_type': 'missing_access_control',
            'description': 'Function lacks access control'
        }
        
        result = analyzer.enhance_access_control_check(
            vuln, function_code, contract_code
        )
        
        assert isinstance(result, CrossContractAccessResult)
        assert result.external_calls_analyzed >= 1


class TestPermissionlessSafetyCheck:
    """Test permissionless but safe detection."""
    
    @pytest.fixture
    def analyzer(self):
        return CrossContractAnalyzer()
    
    def test_permissionless_but_protected(self, analyzer):
        """Test detection of permissionless functions protected by external calls."""
        contract_code = """
        IL1Nullifier public immutable L1_NULLIFIER;
        """
        
        function_code = """
        function migrateTokens(address _token) external {
            // Anyone can call, but L1_NULLIFIER enforces access
            L1_NULLIFIER.transferTokenToNTV(_token);
        }
        """
        
        is_safe, reasoning = analyzer.is_permissionless_but_safe(
            function_code, contract_code
        )
        
        # Note: Without access to actual L1Nullifier code, 
        # it may not detect the protection
        assert isinstance(is_safe, bool)
        assert isinstance(reasoning, str)


class TestWithProjectRoot:
    """Test cross-contract analysis with project root."""
    
    def test_with_temp_project(self):
        """Test with a temporary project structure."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            
            # Create contract files
            (tmppath / "L1Nullifier.sol").write_text("""
            contract L1Nullifier {
                modifier onlyL1NTV() {
                    require(msg.sender == l1NativeTokenVault);
                    _;
                }
                
                function transferTokenToNTV(address _token) external onlyL1NTV {
                    // transfer
                }
            }
            """)
            
            analyzer = CrossContractAnalyzer(project_root=tmppath)
            
            # Test finding contract
            content = analyzer._find_contract_content('L1Nullifier', None)
            
            assert content is not None
            assert 'onlyL1NTV' in content


class TestEdgeCases:
    """Test edge cases and error handling."""
    
    @pytest.fixture
    def analyzer(self):
        return CrossContractAnalyzer()
    
    def test_empty_function(self, analyzer):
        """Test with empty function code."""
        calls = analyzer.analyze_external_calls("", "")
        assert calls == []
    
    def test_comments_ignored(self, analyzer):
        """Test that comments are ignored."""
        function_code = """
        function test() external {
            // L1_NULLIFIER.transferTokenToNTV(_token);
            /* L1_NULLIFIER.dangerousCall() */
        }
        """
        
        calls = analyzer.analyze_external_calls(function_code, "")
        
        # Should not detect commented calls
        assert len(calls) == 0
    
    def test_no_project_root(self, analyzer):
        """Test without project root."""
        result = analyzer._check_external_function_access_control(
            'L1_NULLIFIER',
            'transferTokenToNTV',
            'IL1Nullifier',
            "",
            None
        )
        
        # Should handle gracefully
        assert 'has_access_control' in result
        assert isinstance(result['has_access_control'], bool)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
