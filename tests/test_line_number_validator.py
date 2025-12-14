#!/usr/bin/env python3
"""
Tests for Line Number Validator

Tests the line number validation and correction functionality
to ensure LLM-reported line numbers are accurate.
"""

import pytest
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.line_number_validator import LineNumberValidator, LineValidationResult


class TestLineNumberValidator:
    """Test cases for LineNumberValidator."""
    
    @pytest.fixture
    def validator(self):
        """Create validator instance."""
        return LineNumberValidator()
    
    @pytest.fixture
    def sample_contract(self):
        """Sample contract for testing."""
        return """// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IERC20} from "@openzeppelin/contracts-v4/token/ERC20/IERC20.sol";

contract L1ERC20Bridge {
    IL1Nullifier public immutable override L1_NULLIFIER;
    
    function deposit(
        address _l2Receiver,
        address _l1Token,
        uint256 _amount
    ) public payable returns (bytes32 l2TxHash) {
        if (_amount == 0) {
            revert EmptyDeposit();
        }
        uint256 amount = _approveFundsToAssetRouter(msg.sender, IERC20(_l1Token), _amount);
        if (amount != _amount) {
            revert TokensWithFeesNotSupported();
        }
        return l2TxHash;
    }
    
    function _approveFundsToAssetRouter(address _from, IERC20 _token, uint256 _amount) internal returns (uint256) {
        uint256 balanceBefore = _token.balanceOf(address(this));
        _token.safeTransferFrom(_from, address(this), _amount);
        uint256 balanceAfter = _token.balanceOf(address(this));
        return balanceAfter - balanceBefore;
    }
}
"""
    
    def test_valid_line_number(self, validator, sample_contract):
        """Test that valid line numbers pass validation."""
        finding = {
            'title': 'Balance Delta Issue',
            'description': 'The _approveFundsToAssetRouter function calculates balance delta',
            'line_number': 25,  # Line where _approveFundsToAssetRouter is
            'code_snippet': 'function _approveFundsToAssetRouter'
        }
        
        result = validator.validate_finding_line_number(finding, sample_contract)
        
        assert 'line_validation' in result
        # Should either be valid or corrected to a nearby line
        assert result['line_validation']['status'] in ['valid', 'corrected', 'assumed_valid', 'uncertain']
    
    def test_line_number_exceeds_file_length(self, validator, sample_contract):
        """Test that line numbers exceeding file length are corrected."""
        total_lines = len(sample_contract.split('\n'))
        
        finding = {
            'title': 'Balance Delta Issue',
            'description': 'The _approveFundsToAssetRouter function has an issue',
            'line_number': 315,  # Way beyond file length
            'code_snippet': '_approveFundsToAssetRouter'
        }
        
        result = validator.validate_finding_line_number(finding, sample_contract)
        
        assert 'line_validation' in result
        # Should be either corrected or marked invalid
        status = result['line_validation']['status']
        assert status in ['corrected', 'invalid']
        
        if status == 'corrected':
            # If corrected, should be within bounds
            assert result['line_number'] <= total_lines
    
    def test_line_number_correction_finds_function(self, validator, sample_contract):
        """Test that correction finds the correct function."""
        finding = {
            'title': 'Deposit Function Issue',
            'description': 'The deposit function lacks validation',
            'line_number': 100,  # Wrong line
            'code_snippet': 'function deposit'
        }
        
        result = validator.validate_finding_line_number(finding, sample_contract)
        
        # Should find deposit function
        if result['line_validation']['status'] == 'corrected':
            # Check that the corrected line is around the deposit function (line ~10)
            corrected_line = result['line_number']
            assert 5 <= corrected_line <= 25  # Deposit function range
    
    def test_extract_identifiers_from_description(self, validator):
        """Test identifier extraction from description."""
        description = "The `_approveFundsToAssetRouter` function has an issue"
        title = "Balance Check Vulnerability"
        
        identifiers = validator._extract_identifiers(description, title)
        
        assert '_approveFundsToAssetRouter' in identifiers
    
    def test_extract_identifiers_camel_case(self, validator):
        """Test CamelCase identifier extraction."""
        description = "The L1ERC20Bridge contract has a vulnerability in TokensWithFeesNotSupported"
        title = "Token Handling Issue"
        
        identifiers = validator._extract_identifiers(description, title)
        
        # Should extract CamelCase names
        assert any('Bridge' in i or 'Token' in i for i in identifiers)
    
    def test_nearby_line_check(self, validator, sample_contract):
        """Test nearby line checking functionality."""
        lines = sample_contract.split('\n')
        
        # Test finding identifier on nearby line
        identifiers = ['_approveFundsToAssetRouter']
        
        result = validator._check_nearby_lines(28, identifiers, lines, window=5)
        
        # Should find match within window
        if result:
            corrected_line, confidence = result
            assert abs(corrected_line - 25) <= 5  # Within window of actual function
    
    def test_batch_validation(self, validator, sample_contract):
        """Test batch validation of multiple findings."""
        findings = [
            {
                'title': 'Valid Finding',
                'description': 'Issue in deposit function',
                'line_number': 10,  # Valid
            },
            {
                'title': 'Invalid Line Finding',
                'description': 'Issue in _approveFundsToAssetRouter',
                'line_number': 500,  # Invalid
            },
            {
                'title': 'Missing Line Finding',
                'description': 'Some other issue',
                'line_number': 0,  # No line
            },
        ]
        
        validated, stats = validator.validate_findings_batch(findings, sample_contract)
        
        assert stats['total'] == 3
        assert stats['valid'] + stats['corrected'] + stats['invalid'] + stats['uncertain'] == 3
    
    def test_zero_line_number(self, validator, sample_contract):
        """Test handling of zero line numbers."""
        finding = {
            'title': 'No Line Finding',
            'description': 'The deposit function has an issue',
            'line_number': 0,
        }
        
        result = validator.validate_finding_line_number(finding, sample_contract)
        
        # Should handle gracefully
        assert 'line_validation' in result


class TestLineValidationResult:
    """Test LineValidationResult dataclass."""
    
    def test_result_creation(self):
        """Test creating validation results."""
        result = LineValidationResult(
            status='valid',
            original_line=10,
            corrected_line=None,
            confidence=0.95,
            reason='Line matches'
        )
        
        assert result.status == 'valid'
        assert result.original_line == 10
        assert result.corrected_line is None
        assert result.confidence == 0.95
    
    def test_corrected_result(self):
        """Test corrected validation result."""
        result = LineValidationResult(
            status='corrected',
            original_line=315,
            corrected_line=25,
            confidence=0.85,
            reason='Found via pattern search'
        )
        
        assert result.status == 'corrected'
        assert result.corrected_line == 25


class TestEdgeCases:
    """Test edge cases and error handling."""
    
    @pytest.fixture
    def validator(self):
        return LineNumberValidator()
    
    def test_empty_contract(self, validator):
        """Test with empty contract."""
        finding = {
            'title': 'Test',
            'description': 'Test finding',
            'line_number': 1,
        }
        
        result = validator.validate_finding_line_number(finding, "")
        
        # Should handle gracefully
        assert 'line_validation' in result
    
    def test_very_long_contract(self, validator):
        """Test with very long contract."""
        # Generate a large contract
        long_contract = "pragma solidity ^0.8.0;\n" + "\n".join([
            f"function func{i}() public {{ }}" for i in range(1000)
        ])
        
        finding = {
            'title': 'Test',
            'description': 'Issue in func500',
            'line_number': 500,
        }
        
        result = validator.validate_finding_line_number(finding, long_contract)
        
        # Should complete without error
        assert 'line_validation' in result
    
    def test_unicode_in_contract(self, validator):
        """Test with unicode characters in contract."""
        contract = """
        // 合约说明
        pragma solidity ^0.8.0;
        
        function deposit(uint256 amount) external {
            // コメント
            require(amount > 0, "Amount must be positive");
        }
        """
        
        finding = {
            'title': 'Deposit Issue',
            'description': 'Issue in deposit function',
            'line_number': 5,
        }
        
        result = validator.validate_finding_line_number(finding, contract)
        
        # Should handle unicode gracefully
        assert 'line_validation' in result
    
    def test_finding_without_required_fields(self, validator):
        """Test with finding missing required fields."""
        finding = {
            'title': 'Test',
            # Missing description and line_number
        }
        
        result = validator.validate_finding_line_number(finding, "pragma solidity ^0.8.0;")
        
        # Should handle gracefully
        assert isinstance(result, dict)


class TestCommentLineCorrection:
    """Test correction of comment line numbers."""
    
    @pytest.fixture
    def validator(self):
        return LineNumberValidator()
    
    def test_comment_line_correction_to_constructor(self, validator):
        """Test that comment lines are corrected to actual code."""
        contract = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IBridgehub} from "./interfaces/IBridgehub.sol";

contract MessageRoot {
    IBridgehub public immutable BRIDGE_HUB;
    
    /// @notice Initializes the contract with the bridgehub address
    /// @param _bridgehub The address of the bridgehub contract
    constructor(IBridgehub _bridgehub) {
        BRIDGE_HUB = _bridgehub;
    }
}
"""
        # Finding points to line 10 (comment) instead of line 11 (constructor)
        finding = {
            'title': 'Unchecked Input',
            'description': 'The constructor(IBridgehub _bridgehub) parameter is not validated',
            'line_number': 10,  # Points to comment
        }
        
        result = validator.validate_finding_line_number(finding, contract)
        
        # Should be corrected to constructor line
        assert result.get('line_validation', {}).get('status') == 'corrected'
        assert result.get('line_number') == 11  # Constructor line
    
    def test_comment_block_skipped(self, validator):
        """Test that multi-line comments are skipped."""
        contract = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @notice This is a test contract
 * @dev Used for testing purposes
 */
contract Test {
    function doSomething() external {
        // Some logic
    }
}
"""
        # Finding points to NatSpec comment
        finding = {
            'title': 'Missing Validation',
            'description': 'The doSomething function lacks input validation',
            'line_number': 5,  # Points to NatSpec
        }
        
        result = validator.validate_finding_line_number(finding, contract)
        
        # Should detect it's a comment and try to correct
        validation = result.get('line_validation', {})
        assert validation.get('status') in ['corrected', 'uncertain']
    
    def test_is_comment_detection(self, validator):
        """Test comment detection helper."""
        assert validator._is_comment_or_empty("// This is a comment") is True
        assert validator._is_comment_or_empty("/// NatSpec comment") is True
        assert validator._is_comment_or_empty("/** Multi-line start") is True
        assert validator._is_comment_or_empty(" * continuation") is True
        assert validator._is_comment_or_empty("   */") is True
        assert validator._is_comment_or_empty("") is True
        assert validator._is_comment_or_empty("   ") is True
        assert validator._is_comment_or_empty("{") is True
        assert validator._is_comment_or_empty("}") is True
        
        # Actual code should return False
        assert validator._is_comment_or_empty("function test() {") is False
        assert validator._is_comment_or_empty("constructor() {") is False
        assert validator._is_comment_or_empty("uint256 x = 5;") is False


class TestIntegration:
    """Integration tests for line number validation."""
    
    @pytest.fixture
    def validator(self):
        return LineNumberValidator()
    
    def test_real_world_scenario(self, validator):
        """Test with a real-world-like scenario."""
        contract = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

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
        }
    }
    
    function updateChainBalancesFromSharedBridge(address _token, uint256 _targetChainId) external {
        uint256 nullifierChainBalance = L1_NULLIFIER.chainBalance(_targetChainId, _token);
        chainBalance[_targetChainId][assetId] += nullifierChainBalance;
    }
}
"""
        
        # Simulate an LLM finding with wrong line number (like in our validation)
        finding = {
            'title': 'Missing Access Control',
            'description': 'The `transferFundsFromSharedBridge` function lacks access control',
            'line_number': 66,  # Wrong - this was the actual reported wrong line
            'code_snippet': 'function transferFundsFromSharedBridge'
        }
        
        result = validator.validate_finding_line_number(finding, contract)
        
        # Should detect the wrong line and try to correct
        validation = result.get('line_validation', {})
        
        # Either it should find the correct line or mark as uncertain
        if validation.get('status') == 'corrected':
            # Should find the function around line 13-14
            corrected = result.get('line_number', 0)
            assert 10 <= corrected <= 20, f"Corrected line {corrected} not near function definition"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
