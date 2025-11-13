// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function approve(address, uint256) external returns (bool);
}

interface IStakedCap {
    function initialize(address _accessControl, address _asset, uint256 _lockDuration) external;
    function notify() external;
    function deposit(uint256 assets, address receiver) external returns (uint256);
    function withdraw(uint256 assets, address receiver, address owner) external returns (uint256);
    function totalAssets() external view returns (uint256);
    function totalLocked() external view returns (uint256);
    function lockedProfit() external view returns (uint256);
    function lastNotify() external view returns (uint256);
    function lockDuration() external view returns (uint256);
    function asset() external view returns (address);
    function balanceOf(address) external view returns (uint256);
}

/// @title Cap Contracts Validation Test
/// @notice Tests to validate findings from the audit report
contract CapContractsValidation is Test {
    // Mainnet addresses - we'll use USDC as the asset
    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address constant WHALE = 0x4B16c5dE96EB2117bBE5fd171E4d203624B014aa; // USDC whale
    
    IStakedCap stakedCap;
    address accessControl;
    address user1;
    address user2;
    
    uint256 constant LOCK_DURATION = 7 days;
    uint256 constant INITIAL_DEPOSIT = 1000e6; // 1000 USDC
    
    function setUp() public {
        // Fork Ethereum mainnet
        vm.createSelectFork("https://eth.llamarpc.com", 21170000); // Recent block
        
        user1 = makeAddr("user1");
        user2 = makeAddr("user2");
        accessControl = makeAddr("accessControl");
        
        // Deploy mock AccessControl (for testing)
        MockAccessControl mockAC = new MockAccessControl();
        accessControl = address(mockAC);
        
        // Deploy StakedCap implementation
        // Note: We'd need the actual deployment bytecode or compile the contract
        // For now, this is a test template showing the methodology
        
        console.log("Setup complete");
    }
    
    /// @notice Test Finding #2: totalLocked Overwrite Vulnerability
    /// @dev This tests whether calling notify() prematurely can unlock vesting yield
    function test_Finding2_TotalLockedOverwrite_VALIDATION() public {
        vm.skip(true); // Skip until we deploy actual contracts
        
        console.log("\n=== Testing Finding #2: totalLocked Overwrite ===");
        
        // Fund the whale account
        vm.startPrank(WHALE);
        IERC20(USDC).transfer(user1, INITIAL_DEPOSIT);
        vm.stopPrank();
        
        // User1 deposits initial funds
        vm.startPrank(user1);
        IERC20(USDC).approve(address(stakedCap), type(uint256).max);
        stakedCap.deposit(INITIAL_DEPOSIT, user1);
        vm.stopPrank();
        
        // === SCENARIO 1: First yield notification ===
        uint256 firstYield = 100e6; // 100 USDC yield
        vm.prank(WHALE);
        IERC20(USDC).transfer(address(stakedCap), firstYield);
        
        stakedCap.notify();
        uint256 totalLockedAfterFirst = stakedCap.totalLocked();
        uint256 lastNotifyFirst = stakedCap.lastNotify();
        
        console.log("First notification:");
        console.log("  Total Locked:", totalLockedAfterFirst);
        console.log("  Last Notify:", lastNotifyFirst);
        
        assertEq(totalLockedAfterFirst, firstYield, "First notification should lock full yield");
        
        // === SCENARIO 2: Try to call notify() BEFORE lock duration passes ===
        vm.warp(block.timestamp + LOCK_DURATION / 2); // Move to halfway point
        
        uint256 secondYield = 50e6; // 50 USDC more yield
        vm.prank(WHALE);
        IERC20(USDC).transfer(address(stakedCap), secondYield);
        
        // This SHOULD REVERT because we're still in the vesting period
        vm.expectRevert(); // Expecting "StillVesting()" error
        stakedCap.notify();
        
        console.log("\nAttempt to notify during vesting period:");
        console.log("  Result: REVERTED as expected");
        console.log("  This proves you CANNOT prematurely unlock by calling notify()");
        
        // === SCENARIO 3: Verify locked profit decreases over time ===
        uint256 lockedProfitAtHalf = stakedCap.lockedProfit();
        console.log("\nAt 50% of lock duration:");
        console.log("  Locked Profit:", lockedProfitAtHalf);
        console.log("  Expected: ~50e6");
        
        // Should be approximately half locked
        assertApproxEqRel(lockedProfitAtHalf, firstYield / 2, 0.01e18, "Half should be locked");
        
        // === SCENARIO 4: Call notify() AFTER lock duration completes ===
        vm.warp(block.timestamp + LOCK_DURATION / 2 + 1); // Complete the lock duration
        
        uint256 lockedProfitAfterVesting = stakedCap.lockedProfit();
        console.log("\nAfter full lock duration:");
        console.log("  Locked Profit:", lockedProfitAfterVesting);
        
        // Should be fully unlocked (0 or very close to 0)
        assertLe(lockedProfitAfterVesting, 1e6, "Should be fully unlocked");
        
        // Now we CAN call notify() with new yield
        stakedCap.notify();
        uint256 totalLockedAfterSecond = stakedCap.totalLocked();
        
        console.log("\nSecond notification (after vesting complete):");
        console.log("  Total Locked:", totalLockedAfterSecond);
        console.log("  Previous locked profit was: 0 (fully vested)");
        console.log("  New yield:", secondYield);
        
        assertEq(totalLockedAfterSecond, secondYield, "Should lock only new yield");
        
        console.log("\n=== CONCLUSION ===");
        console.log("The 'overwrite' is INTENTIONAL and CORRECT behavior");
        console.log("Reason: notify() can only be called after full vesting");
        console.log("At that point, previous totalLocked has fully vested (lockedProfit = 0)");
        console.log("Finding #2 appears to be INVALID");
    }
    
    /// @notice Test edge case: What if notify() is called exactly at lock duration boundary
    function test_Finding2_EdgeCase_ExactBoundary() public {
        vm.skip(true);
        
        console.log("\n=== Testing Edge Case: Exact Boundary ===");
        
        // Setup
        vm.startPrank(WHALE);
        IERC20(USDC).transfer(user1, INITIAL_DEPOSIT);
        IERC20(USDC).transfer(address(stakedCap), 100e6);
        vm.stopPrank();
        
        vm.prank(user1);
        IERC20(USDC).approve(address(stakedCap), type(uint256).max);
        stakedCap.deposit(INITIAL_DEPOSIT, user1);
        
        stakedCap.notify();
        uint256 lastNotify = stakedCap.lastNotify();
        
        // Warp to EXACTLY lastNotify + lockDuration
        vm.warp(lastNotify + LOCK_DURATION);
        
        uint256 lockedProfit = stakedCap.lockedProfit();
        console.log("Locked Profit at exact boundary:", lockedProfit);
        console.log("Check condition: lastNotify + lockDuration > block.timestamp");
        console.log("  ", lastNotify + LOCK_DURATION, ">", block.timestamp);
        
        // At exact boundary, the condition is: lastNotify + lockDuration > block.timestamp
        // If they're equal, the condition is false, so notify() should succeed
        
        vm.prank(WHALE);
        IERC20(USDC).transfer(address(stakedCap), 50e6);
        
        // This should NOT revert
        stakedCap.notify();
        console.log("Notify at exact boundary: SUCCESS");
    }
    
    /// @notice Test the actual vulnerability scenario the audit claims
    function test_Finding2_AuditClaimValidation() public {
        vm.skip(true);
        
        console.log("\n=== Testing Audit's Claim ===");
        console.log("Audit claims: 'attacker can prematurely unlock by calling notify() again'");
        console.log("Let's test if this is possible...\n");
        
        // Setup
        vm.startPrank(WHALE);
        IERC20(USDC).transfer(user1, INITIAL_DEPOSIT);
        IERC20(USDC).transfer(address(stakedCap), 100e6);
        vm.stopPrank();
        
        vm.prank(user1);
        IERC20(USDC).approve(address(stakedCap), type(uint256).max);
        stakedCap.deposit(INITIAL_DEPOSIT, user1);
        
        // First notify
        stakedCap.notify();
        uint256 totalAssetsAfterNotify = stakedCap.totalAssets();
        console.log("After first notify, totalAssets:", totalAssetsAfterNotify);
        
        // Move forward 1 day (still vesting)
        vm.warp(block.timestamp + 1 days);
        uint256 totalAssetsDuring = stakedCap.totalAssets();
        console.log("After 1 day, totalAssets:", totalAssetsDuring);
        
        // Attacker tries to manipulate by calling notify with minimal yield
        vm.prank(WHALE);
        IERC20(USDC).transfer(address(stakedCap), 1e6); // 1 USDC
        
        console.log("\nAttacker attempts to call notify() to 'prematurely unlock'...");
        try stakedCap.notify() {
            console.log("  Result: SUCCESS (vulnerability exists!)");
            uint256 totalAssetsAfterAttack = stakedCap.totalAssets();
            console.log("  Total assets after attack:", totalAssetsAfterAttack);
            
            if (totalAssetsAfterAttack > totalAssetsDuring) {
                console.log("  VULNERABILITY CONFIRMED: Assets were unlocked prematurely!");
            }
        } catch {
            console.log("  Result: REVERTED");
            console.log("  The attack is PREVENTED by the StillVesting() check");
            console.log("  Finding #2 is INVALID");
        }
    }
}

/// @notice Mock AccessControl for testing
contract MockAccessControl {
    function checkAccess(bytes4, address, address) external pure returns (bool) {
        return true; // Allow all access for testing
    }
}

