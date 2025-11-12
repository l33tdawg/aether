#!/usr/bin/env python3
"""
Unit tests for Cross-Protocol Pattern Recognizer
"""

import unittest
from core.cross_protocol_pattern_recognizer import (
    CrossProtocolPatternRecognizer,
    ProtocolType,
    ProtocolDetection,
    ProtocolPattern,
    PatternCategory
)


class TestCrossProtocolPatternRecognizer(unittest.TestCase):
    """Test cases for cross-protocol pattern recognition."""

    def setUp(self):
        """Set up test fixtures."""
        self.recognizer = CrossProtocolPatternRecognizer()

    def test_empty_contract(self):
        """Test analysis of empty contract."""
        detections = self.recognizer.analyze_contract("")
        self.assertEqual(len(detections), 0)

    def test_uniswap_v3_detection(self):
        """Test Uniswap V3 pattern detection."""
        uniswap_v3_contract = """
pragma solidity ^0.8.0;

contract UniswapV3Pool {
    int24 public tickSpacing;
    uint160 public sqrtPriceX96;
    uint128 public liquidity;

    function mint(
        address recipient,
        int24 tickLower,
        int24 tickUpper,
        uint128 amount,
        bytes calldata data
    ) external returns (uint256 amount0, uint256 amount1) {
        // Mint liquidity position
        return (amount0, amount1);
    }

    function burn(
        int24 tickLower,
        int24 tickUpper,
        uint128 amount
    ) external returns (uint256 amount0, uint256 amount1) {
        // Burn liquidity position
        return (amount0, amount1);
    }

    function swap(
        address recipient,
        bool zeroForOne,
        int256 amountSpecified,
        uint160 sqrtPriceLimitX96,
        bytes calldata data
    ) external returns (int256 amount0, int256 amount1) {
        // Swap implementation
        return (amount0, amount1);
    }
}
"""
        detections = self.recognizer.analyze_contract(uniswap_v3_contract)

        # Should detect Uniswap V3
        uniswap_detections = [d for d in detections if d.protocol == ProtocolType.UNISWAP_V3]
        self.assertTrue(len(uniswap_detections) > 0, "Should detect Uniswap V3 patterns")

        detection = uniswap_detections[0]
        self.assertGreater(detection.confidence, 0.3, "Should have reasonable confidence for Uniswap V3")
        self.assertIn("concentrated_liquidity", detection.detected_patterns)

    def test_aave_v3_detection(self):
        """Test Aave V3 pattern detection."""
        aave_v3_contract = """
pragma solidity ^0.8.0;

contract AaveV3Pool {
    uint256 public constant HEALTH_FACTOR_LIQUIDATION_THRESHOLD = 1e18;

    function liquidationCall(
        address collateralAsset,
        address debtAsset,
        address user,
        uint256 debtToCover,
        bool receiveAToken
    ) external {
        // Liquidation logic
    }

    function getUserAccountData(address user) external view
        returns (
            uint256 totalCollateralBase,
            uint256 totalDebtBase,
            uint256 availableBorrowsBase,
            uint256 currentLiquidationThreshold,
            uint256 ltv,
            uint256 healthFactor
        ) {
        return (totalCollateralBase, totalDebtBase, availableBorrowsBase,
                currentLiquidationThreshold, ltv, healthFactor);
    }

    function flashLoan(
        address receiverAddress,
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] modes,
        address onBehalfOf,
        bytes calldata params,
        uint16 referralCode
    ) external {
        // Flash loan logic
    }
}
"""
        detections = self.recognizer.analyze_contract(aave_v3_contract)

        # Should detect Aave V3
        aave_detections = [d for d in detections if d.protocol == ProtocolType.AAVE_V3]
        self.assertTrue(len(aave_detections) > 0, "Should detect Aave V3 patterns")

        detection = aave_detections[0]
        self.assertGreater(detection.confidence, 0.3, "Should have reasonable confidence for Aave V3")

    def test_compound_v3_detection(self):
        """Test Compound V3 pattern detection."""
        compound_v3_contract = """
pragma solidity ^0.8.0;

contract CompoundV3Comet {
    uint256 public utilizationRate;
    uint256 public supplyRate;
    uint256 public borrowRate;

    function getSupplyRate(uint256 utilization) external view returns (uint64) {
        return 0;
    }

    function getBorrowRate(uint256 utilization) external view returns (uint64) {
        return 0;
    }

    function accrueInterest() external {
        // Accrue interest logic
    }

    function getUtilization() external view returns (uint256) {
        return utilizationRate;
    }
}
"""
        detections = self.recognizer.analyze_contract(compound_v3_contract)

        # Should detect Compound V3
        compound_detections = [d for d in detections if d.protocol == ProtocolType.COMPOUND_V3]
        self.assertTrue(len(compound_detections) > 0, "Should detect Compound V3 patterns")

    def test_makerdao_detection(self):
        """Test MakerDAO pattern detection."""
        makerdao_contract = """
pragma solidity ^0.8.0;

contract MakerDAO {
    uint256 public liquidationRatio;
    uint256 public stabilityFee;

    function open(bytes32 ilk, address usr) external returns (uint256) {
        // Open CDP
        return 0;
    }

    function join(uint256 wad) external {
        // Join collateral
    }

    function draw(uint256 wad) external {
        // Draw DAI
    }

    function wipe(uint256 wad) external {
        // Wipe debt
    }

    function shut() external {
        // Close CDP
    }
}
"""
        detections = self.recognizer.analyze_contract(makerdao_contract)

        # Should detect MakerDAO
        maker_detections = [d for d in detections if d.protocol == ProtocolType.MAKERDAO]
        self.assertTrue(len(maker_detections) > 0, "Should detect MakerDAO patterns")

    def test_curve_detection(self):
        """Test Curve Finance pattern detection."""
        curve_contract = """
pragma solidity ^0.8.0;

contract CurvePool {
    uint256 public A; // Amplification coefficient
    uint256 public fee;
    uint256[2] public balances;

    function exchange(
        int128 i,
        int128 j,
        uint256 dx,
        uint256 min_dy
    ) external returns (uint256) {
        // Exchange logic
        return 0;
    }

    function add_liquidity(uint256[2] calldata amounts, uint256 min_mint_amount) external {
        // Add liquidity logic
    }

    function remove_liquidity(uint256 amount, uint256[2] calldata min_amounts) external {
        // Remove liquidity logic
    }

    function get_dy(int128 i, int128 j, uint256 dx) external view returns (uint256) {
        // Get exchange rate
        return 0;
    }
}
"""
        detections = self.recognizer.analyze_contract(curve_contract)

        # Should detect Curve
        curve_detections = [d for d in detections if d.protocol == ProtocolType.CURVE]
        self.assertTrue(len(curve_detections) > 0, "Should detect Curve patterns")

    def test_generic_amm_detection(self):
        """Test generic AMM pattern detection."""
        generic_amm = """
pragma solidity ^0.8.0;

contract GenericAMM {
    uint256 public reserve0;
    uint256 public reserve1;
    uint256 public totalSupply;

    function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external {
        // Swap logic
    }

    function addLiquidity(uint256 amount0, uint256 amount1) external {
        // Add liquidity logic
    }

    function removeLiquidity(uint256 liquidity) external {
        // Remove liquidity logic
    }

    function getReserves() external view returns (uint256, uint256) {
        return (reserve0, reserve1);
    }
}
"""
        detections = self.recognizer.analyze_contract(generic_amm)

        # Should detect generic AMM
        amm_detections = [d for d in detections if d.protocol == ProtocolType.GENERIC_AMM]
        self.assertTrue(len(amm_detections) > 0, "Should detect generic AMM patterns")

    def test_severity_adjustments(self):
        """Test protocol-specific severity adjustments."""
        # Test Uniswap V3 adjustments
        should_adjust, reason, multiplier = self.recognizer.should_adjust_severity(
            'flash_loan_attack', ProtocolType.UNISWAP_V3
        )
        self.assertTrue(should_adjust, "Uniswap V3 flash loans should be adjusted")
        self.assertLess(multiplier, 1.0, "Flash loan attacks should be less severe on Uniswap V3")

        # Test Aave V3 adjustments
        should_adjust, reason, multiplier = self.recognizer.should_adjust_severity(
            'health_factor_manipulation', ProtocolType.AAVE_V3
        )
        self.assertTrue(should_adjust, "Aave health factor manipulation should be adjusted")
        self.assertGreater(multiplier, 1.0, "Health factor manipulation should be more severe on Aave")

        # Test no adjustment for unknown combination
        should_adjust, reason, multiplier = self.recognizer.should_adjust_severity(
            'unknown_vulnerability', ProtocolType.UNISWAP_V3
        )
        self.assertFalse(should_adjust, "Unknown vulnerability should not be adjusted")

    def test_protocol_specific_checks(self):
        """Test protocol-specific security check recommendations."""
        uniswap_checks = self.recognizer.get_protocol_specific_checks(ProtocolType.UNISWAP_V3)
        self.assertGreater(len(uniswap_checks), 0, "Uniswap V3 should have specific checks")
        self.assertIn("tick", uniswap_checks[0].lower(), "Should mention tick calculations")

        aave_checks = self.recognizer.get_protocol_specific_checks(ProtocolType.AAVE_V3)
        self.assertGreater(len(aave_checks), 0, "Aave V3 should have specific checks")
        self.assertTrue(any("health" in check.lower() for check in aave_checks),
                       "Should mention health factor checks")

        compound_checks = self.recognizer.get_protocol_specific_checks(ProtocolType.COMPOUND_V3)
        self.assertGreater(len(compound_checks), 0, "Compound V3 should have specific checks")

    def test_multiple_protocols(self):
        """Test detection when contract implements multiple protocol patterns."""
        multi_protocol_contract = """
pragma solidity ^0.8.0;

// Mix of Uniswap V3 and Aave patterns
contract MultiProtocol {
    // Uniswap V3 patterns
    int24 public tickLower;
    int24 public tickUpper;
    uint160 public sqrtPriceX96;

    function mint(address recipient, int24 tickLower, int24 tickUpper, uint128 amount) external {
        // Uniswap mint
    }

    // Aave patterns
    uint256 public healthFactor;
    uint256 public liquidationThreshold;

    function liquidationCall(address collateral, address debt, address user, uint256 debtToCover) external {
        // Aave liquidation
    }

    function getUserAccountData(address user) external view returns (uint256, uint256, uint256, uint256, uint256, uint256) {
        // Aave account data
        return (0, 0, 0, 0, 0, 0);
    }
}
"""
        detections = self.recognizer.analyze_contract(multi_protocol_contract)

        # Should detect both protocols
        protocols_detected = {d.protocol for d in detections}
        self.assertIn(ProtocolType.UNISWAP_V3, protocols_detected)
        self.assertIn(ProtocolType.AAVE_V3, protocols_detected)

    def test_confidence_ordering(self):
        """Test that detections are ordered by confidence."""
        mixed_contract = """
pragma solidity ^0.8.0;

contract MixedProtocol {
    // Strong Uniswap V3 indicators
    int24 public tickSpacing = 60;
    uint160 public sqrtPriceX96;
    uint24 public fee = 3000;

    function mint(address r, int24 tl, int24 tu, uint128 a, bytes calldata d) external returns (uint256, uint256) {
        return (0, 0);
    }

    // Weaker Aave indicators
    uint256 public healthFactor;

    function getUserAccountData(address) external view returns (uint256, uint256, uint256, uint256, uint256, uint256) {
        return (0, 0, 0, 0, 0, 0);
    }
}
"""
        detections = self.recognizer.analyze_contract(mixed_contract)

        # Uniswap V3 should be detected with higher confidence than Aave
        uniswap_detection = next((d for d in detections if d.protocol == ProtocolType.UNISWAP_V3), None)
        aave_detection = next((d for d in detections if d.protocol == ProtocolType.AAVE_V3), None)

        if uniswap_detection and aave_detection:
            self.assertGreater(uniswap_detection.confidence, aave_detection.confidence,
                             "Uniswap V3 should have higher confidence than Aave in this case")

    def test_summary_generation(self):
        """Test summary generation for detected protocols."""
        test_contract = """
pragma solidity ^0.8.0;

contract UniswapV3Pool {
    int24 public tickSpacing;
    uint160 public sqrtPriceX96;

    function mint(address r, int24 tl, int24 tu, uint128 a) external returns (uint256, uint256) {
        return (0, 0);
    }
}
"""
        detections = self.recognizer.analyze_contract(test_contract)
        summary = self.recognizer.get_summary()

        self.assertGreater(summary['protocols_detected'], 0)
        self.assertGreater(summary['average_confidence'], 0)
        self.assertIsNotNone(summary['primary_protocol'])
        self.assertIn('uniswap_v3', summary['all_protocols'])

    def test_no_false_detection(self):
        """Test that regular contracts don't trigger protocol detection."""
        regular_contract = """
pragma solidity ^0.8.0;

contract RegularToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply;

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }
}
"""
        detections = self.recognizer.analyze_contract(regular_contract)

        # Should not detect any specific protocols with high confidence
        high_confidence = [d for d in detections if d.confidence > 0.7]
        self.assertEqual(len(high_confidence), 0, "Regular token contract should not trigger high-confidence protocol detection")


if __name__ == '__main__':
    unittest.main()
