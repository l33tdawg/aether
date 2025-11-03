#!/usr/bin/env python3
"""
Demo: Move Vulnerability Database Integration

This script demonstrates the new Move-inspired detectors in action.
"""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.business_logic_detector import BusinessLogicDetector
from core.state_management_detector import StateManagementDetector
from core.data_inconsistency_detector import DataInconsistencyDetector
from core.centralization_detector import CentralizationDetector
from core.looping_detector import LoopingDetector
from core.enhanced_vulnerability_detector import EnhancedVulnerabilityDetector


# Example vulnerable contract with Move-inspired issues
VULNERABLE_CONTRACT = """
pragma solidity ^0.8.0;

contract VulnerableExample {
    mapping(address => bool) public authorized;
    mapping(address => uint256) public balances;
    mapping(address => bool) public claimed;
    uint256 public totalSupply;
    uint256 public rewardIndex = 1000;
    mapping(address => uint256) public lastRewardIndex;
    
    address public owner;
    
    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }
    
    // Issue 1: Backwards validation logic (Move-inspired)
    function addToWhitelist(address user) external {
        require(!authorized[user], "Already authorized");  // Logic backwards!
        authorized[user] = true;
    }
    
    // Issue 2: Self-comparison bug (Move-inspired)
    function validateVersion(uint256 version) external pure returns (bool) {
        require(version == version, "Invalid version");  // Always true!
        return true;
    }
    
    // Issue 3: Missing state update (Move-inspired)
    function claimRewards() external {
        uint256 reward = calculateReward();
        // Missing: claimed[msg.sender] = true
        payable(msg.sender).transfer(reward);
    }
    
    // Issue 4: New user claiming all rewards (Move-inspired)
    function calculateReward() public view returns (uint256) {
        return rewardIndex - 0;  // New users get full history!
    }
    
    // Issue 5: Loop variable not updated (Move-inspired)
    function withdrawAll(uint256 requestedAmount) external {
        for (uint i = 0; i < 10; i++) {
            // requestedAmount never decremented - will over-withdraw!
            withdraw(requestedAmount);
        }
    }
    
    // Issue 6: Unlimited minting (Move-inspired)
    function mint(address to, uint256 amount) external onlyOwner {
        balances[to] += amount;
        // Missing: totalSupply cap check
        // Missing: totalSupply update
    }
    
    // Issue 7: Missing token validation (Move-inspired)
    function swapToken(address tokenA, address tokenB) external {
        // Missing: require(tokenA != address(0))
        // Missing: require(tokenB != address(0))
        IERC20(tokenA).transfer(msg.sender, 100);
    }
    
    // Issue 8: Infinite loop risk
    function processAll() external {
        uint256 count = 10;
        while (count > 0) {
            // count never decremented - infinite loop!
            doSomething();
        }
    }
    
    function withdraw(uint256 amount) internal {}
    function doSomething() internal {}
}

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}
"""


def demo_business_logic_detection():
    """Demonstrate business logic vulnerability detection"""
    print("\n" + "="*80)
    print("🔍 BUSINESS LOGIC DETECTOR (Move-Inspired)")
    print("="*80)
    
    detector = BusinessLogicDetector()
    vulnerabilities = detector.analyze_business_logic(VULNERABLE_CONTRACT)
    
    print(f"\n✅ Found {len(vulnerabilities)} business logic vulnerabilities:\n")
    
    for vuln in vulnerabilities[:5]:  # Show first 5
        print(f"  [{vuln.severity.upper()}] {vuln.description}")
        print(f"  Line {vuln.line_number}: {vuln.code_snippet[:60]}...")
        print(f"  💡 {vuln.recommendation}\n")


def demo_state_management_detection():
    """Demonstrate state management vulnerability detection"""
    print("\n" + "="*80)
    print("🔍 STATE MANAGEMENT DETECTOR (Move-Inspired)")
    print("="*80)
    
    detector = StateManagementDetector()
    vulnerabilities = detector.analyze_state_management(VULNERABLE_CONTRACT)
    
    print(f"\n✅ Found {len(vulnerabilities)} state management vulnerabilities:\n")
    
    for vuln in vulnerabilities[:5]:  # Show first 5
        print(f"  [{vuln.severity.upper()}] {vuln.description}")
        print(f"  Line {vuln.line_number}: {vuln.code_snippet[:60]}...")
        print(f"  💡 {vuln.recommendation}\n")


def demo_centralization_detection():
    """Demonstrate centralization risk detection"""
    print("\n" + "="*80)
    print("🔍 CENTRALIZATION DETECTOR (Move-Inspired)")
    print("="*80)
    
    detector = CentralizationDetector()
    vulnerabilities = detector.analyze_centralization_risks(VULNERABLE_CONTRACT)
    
    print(f"\n✅ Found {len(vulnerabilities)} centralization risks:\n")
    
    for vuln in vulnerabilities[:5]:  # Show first 5
        print(f"  [{vuln.severity.upper()}] {vuln.description}")
        print(f"  Line {vuln.line_number}: {vuln.code_snippet[:60]}...")
        print(f"  💡 {vuln.recommendation}\n")


def demo_full_integration():
    """Demonstrate full integration with enhanced detector"""
    print("\n" + "="*80)
    print("🔍 FULL INTEGRATION - ENHANCED VULNERABILITY DETECTOR")
    print("="*80)
    
    detector = EnhancedVulnerabilityDetector()
    vulnerabilities = detector.analyze_contract(VULNERABLE_CONTRACT)
    
    print(f"\n✅ Total vulnerabilities detected: {len(vulnerabilities)}\n")
    
    # Group by category
    by_category = {}
    for vuln in vulnerabilities:
        category = vuln.category or 'other'
        by_category[category] = by_category.get(category, 0) + 1
    
    print("📊 Breakdown by category:")
    for category, count in sorted(by_category.items(), key=lambda x: x[1], reverse=True):
        print(f"   {category}: {count}")
    
    # Group by severity
    by_severity = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    for vuln in vulnerabilities:
        severity = vuln.severity.lower()
        if severity in by_severity:
            by_severity[severity] += 1
    
    print("\n📊 Breakdown by severity:")
    for severity, count in by_severity.items():
        if count > 0:
            print(f"   {severity.upper()}: {count}")


def main():
    """Run all demos"""
    print("\n" + "="*80)
    print("🚀 MOVE VULNERABILITY DATABASE INTEGRATION DEMO")
    print("="*80)
    print("\nDemonstrating Aether's new Move-inspired vulnerability detectors")
    print("Adapted from 128 Critical/High findings across 77 Move audit reports\n")
    
    demo_business_logic_detection()
    demo_state_management_detection()
    demo_centralization_detection()
    demo_full_integration()
    
    print("\n" + "="*80)
    print("✅ DEMO COMPLETE")
    print("="*80)
    print("\nFor more information, see:")
    print("  - MOVE_INTEGRATION.md - Detailed integration guide")
    print("  - INTEGRATION_SUMMARY.md - Executive summary")
    print("  - https://github.com/MoveMaverick/move-vulnerability-database")
    print("")


if __name__ == '__main__':
    main()

