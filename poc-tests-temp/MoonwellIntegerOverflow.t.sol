// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import "@forge-std/Test.sol";
import {ChainlinkCompositeOracle} from "@protocol/oracles/ChainlinkCompositeOracle.sol";
import {AggregatorV3Interface} from "@protocol/oracles/AggregatorV3Interface.sol";

/**
 * @title Moonwell Integer Overflow PoC
 * @notice Proof-of-concept demonstrating potential integer overflow in ChainlinkCompositeOracle
 * @dev This test attempts to trigger overflow in getDerivedPriceThreeOracles
 * 
 * EXPLOITABILITY ASSESSMENT:
 * - Realistic: LOW - Requires extremely large prices
 * - Difficulty: MEDIUM - Need to find assets with very large prices
 * - Impact: MEDIUM - Could cause DoS if triggered
 * 
 * ATTACK SCENARIO:
 * 1. Find three Chainlink feeds with very large prices
 * 2. Multiply them together: firstPrice * secondPrice * thirdPrice
 * 3. If result exceeds int256 max (~9.2e76), overflow occurs
 * 4. Solidity 0.8+ will revert, causing DoS
 */
contract MoonwellIntegerOverflowTest is Test {
    ChainlinkCompositeOracle public compositeOracle;
    MockChainlinkAggregator public oracleA;
    MockChainlinkAggregator public oracleB;
    MockChainlinkAggregator public oracleC;
    
    function setUp() public {
        // Deploy mock oracles
        oracleA = new MockChainlinkAggregator(1e18, 18); // 1e18 price
        oracleB = new MockChainlinkAggregator(1e18, 18); // 1e18 price
        oracleC = new MockChainlinkAggregator(1e18, 18); // 1e18 price
        
        // Deploy composite oracle
        compositeOracle = new ChainlinkCompositeOracle(
            address(oracleA),
            address(oracleB),
            address(oracleC)
        );
    }
    
    /**
     * @notice Test: Calculate maximum safe prices before overflow
     * @dev Determines the maximum price values that won't cause overflow
     */
    function testCalculateMaxSafePrices() public {
        // int256 max is approximately 9.2e76
        // For three prices: firstPrice * secondPrice * thirdPrice / scalingFactor
        // scalingFactor = 10^(expectedDecimals * 2) = 10^36 for 18 decimals
        
        // Maximum safe price per oracle:
        // sqrt(9.2e76 * 1e36) ≈ 3.03e56 per price
        
        int256 maxInt256 = type(int256).max; // ~9.2e76
        int256 scalingFactor = 1e36; // For 18 decimals * 2
        
        // Calculate max safe price
        // price^3 / 1e36 <= 9.2e76
        // price^3 <= 9.2e112
        // price <= cube_root(9.2e112) ≈ 4.5e37
        
        int256 maxSafePrice = 4.5e37; // Approximately
        
        console.log("=== MAXIMUM SAFE PRICES ===");
        console.log("int256 max:", maxInt256);
        console.log("Scaling factor:", scalingFactor);
        console.log("Max safe price per oracle:", maxSafePrice);
        console.log("This is extremely large - unlikely in practice");
    }
    
    /**
     * @notice Test: Attempt to trigger overflow with extreme prices
     * @dev Tries to cause overflow (should revert in Solidity 0.8+)
     */
    function testOverflowAttempt() public {
        // Set extremely large prices
        // Note: These values are theoretical - real Chainlink prices are much smaller
        int256 extremePrice = 1e30; // Extremely large price
        
        oracleA.setPrice(extremePrice);
        oracleB.setPrice(extremePrice);
        oracleC.setPrice(extremePrice);
        
        // This should revert due to overflow protection in Solidity 0.8+
        // The function will revert rather than silently overflow
        vm.expectRevert();
        compositeOracle.getDerivedPriceThreeOracles(
            address(oracleA),
            address(oracleB),
            address(oracleC),
            18
        );
        
        console.log("=== OVERFLOW PROTECTION ===");
        console.log("Solidity 0.8+ reverts on overflow");
        console.log("This prevents silent bugs but causes DoS");
        console.log("Risk: MEDIUM (DoS if triggered)");
    }
    
    /**
     * @notice Test: Real-world price scenario
     * @dev Checks if real-world prices could cause overflow
     */
    function testRealWorldPrices() public {
        // Real-world example: BTC/USD, ETH/USD, etc.
        // BTC/USD: ~$60,000 = 6e4 (scaled to 18 decimals = 6e22)
        // ETH/USD: ~$3,000 = 3e3 (scaled to 18 decimals = 3e21)
        
        int256 btcPrice = 6e22; // BTC/USD scaled to 18 decimals
        int256 ethPrice = 3e21; // ETH/USD scaled to 18 decimals
        int256 stEthPrice = 3e21; // stETH/ETH scaled to 18 decimals
        
        oracleA.setPrice(btcPrice);
        oracleB.setPrice(ethPrice);
        oracleC.setPrice(stEthPrice);
        
        // Calculate: 6e22 * 3e21 * 3e21 = 5.4e64
        // This is well below int256 max (9.2e76)
        // So real-world prices are safe
        
        uint256 result = compositeOracle.getDerivedPriceThreeOracles(
            address(oracleA),
            address(oracleB),
            address(oracleC),
            18
        );
        
        console.log("=== REAL-WORLD PRICES ===");
        console.log("BTC/USD:", btcPrice);
        console.log("ETH/USD:", ethPrice);
        console.log("stETH/ETH:", stEthPrice);
        console.log("Result:", result);
        console.log("Safe: YES (well below overflow threshold)");
        
        assertTrue(result > 0, "Real-world prices work correctly");
    }
    
    /**
     * @notice Test: Edge case - very large but valid prices
     * @dev Tests prices near but below overflow threshold
     */
    function testNearOverflowThreshold() public {
        // Set prices near but below overflow threshold
        // Each price: ~1e25 (well below 4.5e37 max)
        int256 nearMaxPrice = 1e25;
        
        oracleA.setPrice(nearMaxPrice);
        oracleB.setPrice(nearMaxPrice);
        oracleC.setPrice(nearMaxPrice);
        
        // Should work: 1e25 * 1e25 * 1e25 / 1e36 = 1e39 (still safe)
        uint256 result = compositeOracle.getDerivedPriceThreeOracles(
            address(oracleA),
            address(oracleB),
            address(oracleC),
            18
        );
        
        console.log("=== NEAR OVERFLOW THRESHOLD ===");
        console.log("Price per oracle:", nearMaxPrice);
        console.log("Result:", result);
        console.log("Status: SAFE");
        
        assertTrue(result > 0, "Near-threshold prices work correctly");
    }
}

/**
 * @title Mock Chainlink Aggregator (Simplified)
 */
contract MockChainlinkAggregator is AggregatorV3Interface {
    int256 public price;
    uint8 public decimals_;
    
    constructor(int256 _price, uint8 _decimals) {
        price = _price;
        decimals_ = _decimals;
    }
    
    function setPrice(int256 _price) external {
        price = _price;
    }
    
    function latestRoundData()
        external
        view
        override
        returns (
            uint80,
            int256,
            uint256,
            uint256,
            uint80
        )
    {
        return (1, price, block.timestamp, block.timestamp, 1);
    }
    
    function decimals() external view override returns (uint8) {
        return decimals_;
    }
    
    function description() external pure override returns (string memory) {
        return "Mock Chainlink Aggregator";
    }
    
    function version() external pure override returns (uint256) {
        return 1;
    }
    
    function getRoundData(uint80) external pure override returns (uint80, int256, uint256, uint256, uint80) {
        revert("Not implemented");
    }
}

