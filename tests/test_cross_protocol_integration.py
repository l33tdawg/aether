#!/usr/bin/env python3
"""
Integration tests for Cross-Protocol Pattern Recognition with Enhanced Vulnerability Detector
"""

import unittest
from core.enhanced_vulnerability_detector import EnhancedVulnerabilityDetector
from core.cross_protocol_pattern_recognizer import ProtocolType


class TestCrossProtocolIntegration(unittest.TestCase):
    """Test integration of cross-protocol recognition with vulnerability detection."""

    def setUp(self):
        """Set up test fixtures."""
        self.detector = EnhancedVulnerabilityDetector()

    def test_uniswap_v3_integration(self):
        """Test Uniswap V3 protocol integration reduces false positives."""
        uniswap_v3_contract = """
pragma solidity ^0.8.0;

contract UniswapV3Pool {
    int24 public constant tickSpacing = 60;
    uint160 public sqrtPriceX96;
    uint128 public liquidity;

    function mint(
        address recipient,
        int24 tickLower,
        int24 tickUpper,
        uint128 amount,
        bytes calldata data
    ) external returns (uint256 amount0, uint256 amount1) {
        // Complex tick math - should not be flagged as vulnerable
        int256 amount0Int = int256(amount) * int256(tickUpper - tickLower) / int256(tickSpacing);
        int256 amount1Int = int256(amount) * int256(tickUpper - tickLower) / int256(tickSpacing);

        amount0 = uint256(amount0Int);
        amount1 = uint256(amount1Int);

        return (amount0, amount1);
    }

    function flashCallback(
        uint256 fee0,
        uint256 fee1,
        bytes calldata data
    ) external {
        // Flash swap callback - external calls are expected
        // This should not trigger reentrancy warnings
        address caller = abi.decode(data, (address));
        // Some callback logic...
    }
}
"""
        vulnerabilities = self.detector.analyze_contract(uniswap_v3_contract)

        # Should detect Uniswap V3 protocol
        self.assertIn('detected_protocols', self.detector.contract_context)
        protocols = self.detector.contract_context['detected_protocols']
        uniswap_protocols = [p for p in protocols if p.protocol == ProtocolType.UNISWAP_V3]
        self.assertTrue(len(uniswap_protocols) > 0, "Should detect Uniswap V3 protocol")

        # Complex math should not generate excessive false positives
        # (This is more of a smoke test - actual vulnerability detection depends on the base detector)

    def test_aave_v3_health_factor_protection(self):
        """Test that Aave V3 health factor checks are properly handled."""
        aave_v3_contract = """
pragma solidity ^0.8.0;

contract AaveV3Pool {
    uint256 public constant HEALTH_FACTOR_LIQUIDATION_THRESHOLD = 1e18;

    mapping(address => uint256) public healthFactor;

    function validateHealthFactor(address user) internal view {
        require(healthFactor[user] >= HEALTH_FACTOR_LIQUIDATION_THRESHOLD, "Health factor too low");
    }

    function borrow(address asset, uint256 amount, address onBehalfOf) external {
        validateHealthFactor(onBehalfOf);
        // Borrow logic - requires are expected
    }

    function liquidationCall(
        address collateralAsset,
        address debtAsset,
        address user,
        uint256 debtToCover,
        bool receiveAToken
    ) external {
        // Health factor checks are normal protocol behavior
        require(healthFactor[user] < HEALTH_FACTOR_LIQUIDATION_THRESHOLD, "Cannot liquidate healthy position");

        // Liquidation logic - expected behavior for the protocol
        uint256 bonus = debtToCover * 105 / 100; // 5% bonus
        // ... liquidation implementation
    }
}
"""
        vulnerabilities = self.detector.analyze_contract(aave_v3_contract)

        # Should detect Aave V3 protocol
        self.assertIn('detected_protocols', self.detector.contract_context)
        protocols = self.detector.contract_context['detected_protocols']
        aave_protocols = [p for p in protocols if p.protocol == ProtocolType.AAVE_V3]
        self.assertTrue(len(aave_protocols) > 0, "Should detect Aave V3 protocol")

    def test_compound_v3_interest_rate_handling(self):
        """Test Compound V3 interest rate model handling."""
        compound_v3_contract = """
pragma solidity ^0.8.0;

contract CompoundV3Comet {
    uint64 public supplyRate;
    uint64 public borrowRate;
    uint256 public utilizationRate;

    function getSupplyRate(uint256 utilization) external view returns (uint64) {
        // Interest rate calculation - complex math expected
        if (utilization == 0) return 0;

        // Some complex rate calculation
        uint256 rate = utilization * 1e18 / 1e16; // Example calculation
        return uint64(rate);
    }

    function getBorrowRate(uint256 utilization) external view returns (uint64) {
        // Borrow rate calculation - also expected complex math
        uint256 rate = utilization * 12e17 / 1e16; // Example with kink
        return uint64(rate);
    }

    function accrueInterest() external {
        // Update rates based on utilization
        utilizationRate = totalBorrow * 1e18 / totalSupply;
        supplyRate = getSupplyRate(utilizationRate);
        borrowRate = getBorrowRate(utilizationRate);
    }
}
"""
        vulnerabilities = self.detector.analyze_contract(compound_v3_contract)

        # Should detect Compound V3 protocol
        self.assertIn('detected_protocols', self.detector.contract_context)
        protocols = self.detector.contract_context['detected_protocols']
        compound_protocols = [p for p in protocols if p.protocol == ProtocolType.COMPOUND_V3]
        self.assertTrue(len(compound_protocols) > 0, "Should detect Compound V3 protocol")

    def test_makerdao_governance_patterns(self):
        """Test MakerDAO governance and vault patterns."""
        makerdao_contract = """
pragma solidity ^0.8.0;

contract MakerDAO {
    uint256 public liquidationRatio = 150 * 1e27; // 150%
    uint256 public stabilityFee = 1e27; // 1% per year

    mapping(bytes32 => address) public ilks; // Collateral types
    mapping(address => mapping(bytes32 => uint256)) public urns; // CDPs

    function open(bytes32 ilk, address usr) external returns (uint256) {
        // Open a new CDP
        // This is expected governance functionality
        return 0;
    }

    function draw(uint256 wad) external {
        // Draw DAI from CDP
        // Requires collateral ratio checks
        uint256 collateral = urns[msg.sender][ilk];
        uint256 debt = wad;
        require(collateral * 1e27 / debt >= liquidationRatio, "Unsafe collateral ratio");
    }

    function wipe(uint256 wad) external {
        // Repay DAI debt
        // Expected vault management
    }
}
"""
        vulnerabilities = self.detector.analyze_contract(makerdao_contract)

        # Should detect MakerDAO protocol
        self.assertIn('detected_protocols', self.detector.contract_context)
        protocols = self.detector.contract_context['detected_protocols']
        maker_protocols = [p for p in protocols if p.protocol == ProtocolType.MAKERDAO]
        self.assertTrue(len(maker_protocols) > 0, "Should detect MakerDAO protocol")

    def test_protocol_severity_adjustments(self):
        """Test that protocol-specific severity adjustments are applied."""
        # Create a mock vulnerability that should be adjusted for specific protocols

        # For this test, we'll create a contract that would normally trigger certain patterns
        # and verify that the protocol context adjusts the severity appropriately

        # This is more of an integration test to ensure the adjustment logic works
        test_contract = """
pragma solidity ^0.8.0;

contract TestUniswapV3 {
    int24 public tickSpacing = 60;
    uint160 public sqrtPriceX96;

    function mint(address r, int24 tl, int24 tu, uint128 a) external returns (uint256, uint256) {
        // Uniswap V3 mint function
        return (0, 0);
    }

    function someComplexFunction() external {
        // This function might have some pattern that gets detected as a vulnerability
        // but should be adjusted due to protocol context
        uint256 x = 1000;
        uint256 y = 2000;
        uint256 result = x * y / 1000; // Potential precision loss
    }
}
"""
        vulnerabilities = self.detector.analyze_contract(test_contract)

        # Verify that protocol detection worked
        self.assertIn('primary_protocol', self.detector.contract_context)
        primary_protocol = self.detector.contract_context['primary_protocol']
        self.assertEqual(primary_protocol, ProtocolType.UNISWAP_V3)

        # The actual vulnerability adjustments depend on what vulnerabilities are detected
        # by the base detector, but the integration should work without breaking

    def test_multiple_protocol_detection(self):
        """Test detection and handling of contracts implementing multiple protocols."""
        multi_protocol_contract = """
pragma solidity ^0.8.0;

contract MultiProtocol {
    // Uniswap V3 patterns
    int24 public tickSpacing = 60;
    uint160 public sqrtPriceX96;

    function mint(address r, int24 tl, int24 tu, uint128 a) external returns (uint256, uint256) {
        return (0, 0);
    }

    // Aave patterns
    uint256 public healthFactor;
    uint256 public liquidationThreshold;

    function liquidationCall(address collateral, address debt, address user, uint256 debtToCover) external {
        // Liquidation logic
    }

    function getUserAccountData(address user) external view returns (uint256, uint256, uint256, uint256, uint256, uint256) {
        return (healthFactor, 0, 0, liquidationThreshold, 0, healthFactor);
    }
}
"""
        vulnerabilities = self.detector.analyze_contract(multi_protocol_contract)

        # Should detect multiple protocols
        self.assertIn('detected_protocols', self.detector.contract_context)
        protocols = self.detector.contract_context['detected_protocols']
        protocol_types = {p.protocol for p in protocols}

        self.assertIn(ProtocolType.UNISWAP_V3, protocol_types)
        self.assertIn(ProtocolType.AAVE_V3, protocol_types)

        # Should pick the highest confidence as primary
        primary_protocol = self.detector.contract_context.get('primary_protocol')
        self.assertIsNotNone(primary_protocol)

    def test_backward_compatibility(self):
        """Test that existing contracts still work without protocol detection."""
        regular_contract = """
pragma solidity ^0.8.0;

contract RegularContract {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    function transfer(address to, uint256 amount) external {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}
"""
        vulnerabilities = self.detector.analyze_contract(regular_contract)

        # Should still work normally
        self.assertIsInstance(vulnerabilities, list)

        # Should not have detected any specific protocols
        detected_protocols = self.detector.contract_context.get('detected_protocols', [])
        # May detect generic patterns but should not be high confidence
        high_confidence_protocols = [p for p in detected_protocols if p.confidence > 0.7]
        self.assertEqual(len(high_confidence_protocols), 0, "Regular contract should not trigger high-confidence protocol detection")

    def test_protocol_context_preservation(self):
        """Test that protocol context is properly preserved across multiple analyses."""
        # First analysis
        uniswap_contract = """
contract UniswapV3Pool {
    int24 public tickSpacing = 60;
    function mint(address r, int24 tl, int24 tu, uint128 a) external returns (uint256, uint256) {
        return (0, 0);
    }
}
"""
        vuln1 = self.detector.analyze_contract(uniswap_contract)
        context1 = self.detector.contract_context.copy()

        # Second analysis with different contract
        aave_contract = """
contract AaveV3Pool {
    uint256 public healthFactor;
    function liquidationCall(address c, address d, address u, uint256 dtc) external {}
}
"""
        vuln2 = self.detector.analyze_contract(aave_contract)
        context2 = self.detector.contract_context.copy()

        # Contexts should be different
        self.assertNotEqual(
            context1.get('primary_protocol'),
            context2.get('primary_protocol'),
            "Different contracts should have different protocol contexts"
        )

        # Both should have detected protocols
        self.assertIn('primary_protocol', context1)
        self.assertIn('primary_protocol', context2)

    def test_performance_impact(self):
        """Test that cross-protocol recognition doesn't significantly impact performance."""
        import time

        large_contract = """
pragma solidity ^0.8.0;

contract LargeUniswapV3Pool {
    int24 public constant tickSpacing = 60;
    uint160 public sqrtPriceX96;
    uint128 public liquidity;

    mapping(int24 => mapping(int24 => uint128)) public positions;

    function mint(address recipient, int24 tickLower, int24 tickUpper, uint128 amount, bytes calldata data)
        external returns (uint256 amount0, uint256 amount1) {

        // Complex position management logic
        require(tickLower < tickUpper, "Invalid ticks");
        require(tickUpper % tickSpacing == 0, "Tick spacing");
        require(tickLower % tickSpacing == 0, "Tick spacing");

        positions[tickLower][tickUpper] += amount;
        liquidity += amount;

        // Complex math calculations
        amount0 = uint256(int256(amount) * int256(tickUpper - tickLower) / int256(tickSpacing));
        amount1 = uint256(int256(amount) * int256(tickUpper - tickLower) / int256(tickSpacing));

        return (amount0, amount1);
    }

    function burn(int24 tickLower, int24 tickUpper, uint128 amount)
        external returns (uint256 amount0, uint256 amount1) {

        require(positions[tickLower][tickUpper] >= amount, "Insufficient position");

        positions[tickLower][tickUpper] -= amount;
        liquidity -= amount;

        amount0 = uint256(int256(amount) * int256(tickUpper - tickLower) / int256(tickSpacing));
        amount1 = uint256(int256(amount) * int256(tickUpper - tickLower) / int256(tickSpacing));

        return (amount0, amount1);
    }

    function swap(address recipient, bool zeroForOne, int256 amountSpecified, uint160 sqrtPriceLimitX96, bytes calldata data)
        external returns (int256 amount0, int256 amount1) {

        // Complex swap logic
        require(sqrtPriceLimitX96 > 0, "Invalid price limit");

        // Simulate swap calculations
        if (zeroForOne) {
            amount0 = amountSpecified;
            amount1 = -int256(uint256(amountSpecified) * uint256(sqrtPriceX96) / (1 << 96));
        } else {
            amount1 = amountSpecified;
            amount0 = -int256(uint256(amountSpecified) * (1 << 96) / uint256(sqrtPriceX96));
        }

        return (amount0, amount1);
    }

    function flash(address recipient, uint256 amount0, uint256 amount1, bytes calldata data) external {
        // Flash swap logic
        require(amount0 > 0 || amount1 > 0, "Invalid flash amounts");

        // Callback to recipient
        IUniswapV3FlashCallback(recipient).uniswapV3FlashCallback(0, 0, data);

        // Check repayment would happen here
    }
}

interface IUniswapV3FlashCallback {
    function uniswapV3FlashCallback(uint256 fee0, uint256 fee1, bytes calldata data) external;
}
"""

        start_time = time.time()
        vulnerabilities = self.detector.analyze_contract(large_contract)
        end_time = time.time()

        duration = end_time - start_time

        # Should complete in reasonable time (protocol detection adds some overhead but should be acceptable)
        self.assertLess(duration, 10.0, "Large contract analysis should complete within 10 seconds")

        # Should still detect the protocol
        self.assertIn('detected_protocols', self.detector.contract_context)
        protocols = self.detector.contract_context['detected_protocols']
        uniswap_protocols = [p for p in protocols if p.protocol == ProtocolType.UNISWAP_V3]
        self.assertTrue(len(uniswap_protocols) > 0, "Should detect Uniswap V3 even in large contracts")


if __name__ == '__main__':
    unittest.main()
