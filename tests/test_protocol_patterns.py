"""
Tests for Protocol Pattern Library

Ensures protocol-specific patterns are correctly identified.
"""

import pytest
from core.protocol_patterns import ProtocolPatternLibrary, ProtocolPattern


class TestProtocolPatternLibrary:
    """Test protocol pattern library functionality."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.library = ProtocolPatternLibrary()
    
    def test_initialization(self):
        """Test that library initializes with all patterns."""
        assert 'uniswap_v3' in self.library.patterns
        assert 'compound' in self.library.patterns
        assert 'aave' in self.library.patterns
        assert 'general_defi' in self.library.patterns
    
    def test_uniswap_v3_uint128_overflow_pattern(self):
        """Test Uniswap V3 uint128 overflow pattern detection."""
        contract_code = """
        pragma solidity =0.7.6;
        
        // In Position.sol:
        // overflow is acceptable because the user must withdraw
        // before they hit type(uint128).max fees
        
        library Position {
            struct Info {
                uint128 tokensOwed0;
                uint128 tokensOwed1;
            }
        }
        
        contract UniswapV3Pool {
            function burn() external {
                position.tokensOwed0 = tokensOwed0 + uint128(amount0);
                position.tokensOwed1 = tokensOwed1 + uint128(amount1);
            }
        }
        """
        
        context = {
            'file_path': '/contracts/UniswapV3Pool.sol',
            'code_snippet': 'position.tokensOwed0 = tokensOwed0 + uint128(amount0);',
            'surrounding_context': contract_code,
            'function_context': 'function burn() external {}'
        }
        
        pattern = self.library.check_pattern_match('integer_overflow', contract_code, context)
        
        assert pattern is not None
        assert pattern.pattern_type == 'integer_overflow'
        assert pattern.acceptable_behavior is True
        assert 'Users must withdraw before uint128.max' in pattern.reason
    
    def test_uniswap_v3_ownership_renunciation(self):
        """Test Uniswap V3 ownership renunciation pattern."""
        contract_code = """
        pragma solidity =0.7.6;
        
        contract UniswapV3Factory {
            address public owner;
            
            /// @notice Transfers ownership - can be set to zero to renounce
            function setOwner(address _owner) external {
                require(msg.sender == owner);
                owner = _owner;
            }
        }
        """
        
        context = {
            'file_path': '/contracts/UniswapV3Factory.sol',
            'code_snippet': 'function setOwner(address _owner) external',
            'surrounding_context': contract_code,
            'function_context': 'function setOwner(address _owner) external { require(msg.sender == owner); owner = _owner; }'
        }
        
        pattern = self.library.check_pattern_match('access_control', contract_code, context)
        
        assert pattern is not None
        assert pattern.pattern_type == 'access_control'
        assert pattern.acceptable_behavior is True
        assert 'Decentralization' in pattern.reason
    
    def test_uniswap_v3_fixed_point_math(self):
        """Test Uniswap V3 fixed-point math pattern."""
        contract_code = """
        pragma solidity =0.7.6;
        
        /// @title Square root price math
        /// @notice Uses fixed point Q64.96 arithmetic
        library SqrtPriceMath {
            function getNextSqrtPriceFromAmount0RoundingUp(
                uint160 sqrtPX96,
                uint128 liquidity,
                uint256 amount
            ) internal pure returns (uint160) {
                // Fixed point division - precision loss acceptable
                return uint160(UnsafeMath.divRoundingUp(numerator1, sqrtPX96));
            }
        }
        """
        
        context = {
            'file_path': '/contracts/libraries/SqrtPriceMath.sol',
            'code_snippet': 'return uint160(UnsafeMath.divRoundingUp(numerator1, sqrtPX96));',
            'surrounding_context': contract_code,
            'function_context': contract_code
        }
        
        pattern = self.library.check_pattern_match('precision_loss', contract_code, context)
        
        assert pattern is not None
        assert pattern.pattern_type == 'precision_loss'
        assert pattern.acceptable_behavior is True
        assert 'Fixed-point arithmetic' in pattern.reason
    
    def test_general_safecast_pattern(self):
        """Test general SafeCast pattern detection."""
        contract_code = """
        pragma solidity ^0.8.0;
        
        import "@openzeppelin/contracts/utils/math/SafeCast.sol";
        
        contract VotingToken {
            function delegate(address delegatee, uint256 amount) external {
                // SafeCast reverts on overflow - this is intentional safe type narrowing
                uint96 amount96 = SafeCast.toUint96(amount);
                _delegate(delegatee, amount96);
            }
        }
        """
        
        context = {
            'file_path': '/contracts/VotingToken.sol',
            'code_snippet': 'uint96 amount96 = SafeCast.toUint96(amount);',
            'surrounding_context': contract_code,
            'function_context': 'function delegate(address delegatee, uint256 amount) external {}'
        }
        
        pattern = self.library.check_pattern_match('integer_overflow', contract_code, context)
        
        assert pattern is not None
        assert pattern.pattern_type == 'integer_overflow'
        assert pattern.acceptable_behavior is True
        assert 'SafeCast library reverts on overflow' in pattern.reason
    
    def test_chainlink_oracle_flash_loan_immunity(self):
        """Test Chainlink oracle flash loan immunity pattern."""
        contract_code = """
        pragma solidity ^0.8.0;
        
        import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";
        
        contract PriceFeed {
            AggregatorV3Interface public priceFeed;
            
            function getLatestPrice() public view returns (int) {
                (
                    uint80 roundID,
                    int price,
                    uint startedAt,
                    uint timeStamp,
                    uint80 answeredInRound
                ) = priceFeed.latestRoundData();
                return price;
            }
        }
        """
        
        context = {
            'file_path': '/contracts/PriceFeed.sol',
            'code_snippet': 'priceFeed.latestRoundData();',
            'surrounding_context': contract_code,
            'function_context': 'function getLatestPrice() public view returns (int) {}'
        }
        
        pattern = self.library.check_pattern_match('oracle_manipulation', contract_code, context)
        
        assert pattern is not None
        assert pattern.pattern_type == 'oracle_manipulation'
        assert pattern.acceptable_behavior is True
        assert 'immune to flash loan manipulation' in pattern.reason
    
    def test_solidity_version_extraction(self):
        """Test Solidity version extraction."""
        test_cases = [
            ('pragma solidity =0.7.6;', '0.7.6'),
            ('pragma solidity ^0.8.0;', '0.8.0'),
            ('pragma solidity >=0.7.6 <0.9.0;', '0.7.6'),
            ('pragma solidity 0.8.19;', '0.8.19'),
        ]
        
        for code, expected_version in test_cases:
            version = self.library.extract_solidity_version(code)
            assert version == expected_version, f"Expected {expected_version}, got {version}"
    
    def test_version_comparison(self):
        """Test version comparison logic."""
        assert self.library._compare_versions('0.7.6', '0.8.0') < 0
        assert self.library._compare_versions('0.8.0', '0.7.6') > 0
        assert self.library._compare_versions('0.8.0', '0.8.0') == 0
        assert self.library._compare_versions('0.8.19', '0.8.2') > 0
    
    def test_version_compatibility_check(self):
        """Test Solidity version compatibility checking."""
        pattern = ProtocolPattern(
            pattern_type='integer_overflow',
            comment_markers=[],
            file_markers=[],
            code_markers=[],
            reason='Test',
            acceptable_behavior=True,
            solidity_version_specific='<0.8.0'
        )
        
        # Should match for Solidity 0.7.6 (before 0.8.0)
        assert self.library.check_solidity_version_compatibility(pattern, '0.7.6') is True
        
        # Should NOT match for Solidity 0.8.0 (>= 0.8.0)
        assert self.library.check_solidity_version_compatibility(pattern, '0.8.0') is False
        
        # Should NOT match for Solidity 0.8.19
        assert self.library.check_solidity_version_compatibility(pattern, '0.8.19') is False
    
    def test_safemath_vs_safecast_version_specificity(self):
        """Test that SafeMath and SafeCast patterns respect Solidity versions."""
        safemath_code = """
        pragma solidity 0.6.12;
        
        import "@openzeppelin/contracts/math/SafeMath.sol";
        
        contract Token {
            using SafeMath for uint256;
            
            function transfer(address to, uint256 amount) external {
                balance = balance.sub(amount);
            }
        }
        """
        
        context_safemath = {
            'file_path': '/contracts/Token.sol',
            'code_snippet': 'balance.sub(amount);',
            'surrounding_context': safemath_code,
            'function_context': 'function transfer(address to, uint256 amount) external {}'
        }
        
        # SafeMath should match for Solidity <0.8.0
        pattern_safemath = self.library.check_pattern_match('integer_overflow', safemath_code, context_safemath)
        assert pattern_safemath is not None
        assert pattern_safemath.solidity_version_specific == '<0.8.0'
        assert pattern_safemath.acceptable_behavior is True
        
        # Verify version compatibility check works
        safemath_version = self.library.extract_solidity_version(safemath_code)
        assert safemath_version == '0.6.12'
        assert self.library.check_solidity_version_compatibility(pattern_safemath, safemath_version) is True
        
        # SafeMath should NOT be compatible with Solidity 0.8.0+
        assert self.library.check_solidity_version_compatibility(pattern_safemath, '0.8.0') is False
    
    def test_no_match_for_actual_vulnerability(self):
        """Test that actual vulnerabilities don't match false positive patterns."""
        vulnerable_code = """
        pragma solidity 0.7.6;
        
        contract VulnerableToken {
            mapping(address => uint256) public balances;
            
            function unsafeTransfer(address to, uint256 amount) external {
                // ACTUAL VULNERABILITY: No SafeMath, no overflow protection
                balances[msg.sender] = balances[msg.sender] - amount;
                balances[to] = balances[to] + amount;
            }
        }
        """
        
        context = {
            'file_path': '/contracts/VulnerableToken.sol',
            'code_snippet': 'balances[msg.sender] - amount',
            'surrounding_context': vulnerable_code,
            'function_context': 'function unsafeTransfer(address to, uint256 amount) external {}'
        }
        
        pattern = self.library.check_pattern_match('integer_overflow', vulnerable_code, context)
        
        # Should NOT match any false positive pattern
        assert pattern is None
    
    def test_get_patterns_for_protocol(self):
        """Test retrieving patterns for a specific protocol."""
        uniswap_patterns = self.library.get_patterns_for_protocol('uniswap_v3')
        
        assert 'acceptable_uint128_overflow' in uniswap_patterns
        assert 'ownership_renunciation' in uniswap_patterns
        assert 'fixed_point_precision' in uniswap_patterns
    
    def test_get_all_patterns(self):
        """Test retrieving all patterns."""
        all_patterns = self.library.get_all_patterns()
        
        assert len(all_patterns) >= 4  # At least 4 protocols
        assert all(isinstance(patterns, dict) for patterns in all_patterns.values())


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

