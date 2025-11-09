"""
Test for delegatecall target detection to prevent false positives.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.improved_vulnerability_detector import ImprovedVulnerabilityDetector


def test_agent_executor_no_false_positive():
    """Test that AgentExecutor is correctly identified as delegatecall target."""
    
    agent_executor_code = """
// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

/// @title Code which will run within an `Agent` using `delegatecall`.
/// @dev This is a singleton contract, meaning that all agents will execute the same code.
contract AgentExecutor {
    // Transfer ether to `recipient`.
    function transferEther(address payable recipient, uint256 amount) external {
        recipient.safeNativeTransfer(amount);
    }

    // Transfer ERC20 to `recipient`.
    function transferToken(address token, address recipient, uint128 amount) external {
        IERC20(token).safeTransfer(recipient, amount);
    }

    // Call contract with Ether value
    function callContract(address target, bytes memory data, uint256 value) external {
        bool success = Call.safeCall(target, data, value);
        if (!success) {
            revert();
        }
    }

    function deposit() external payable {}
}
"""

    detector = ImprovedVulnerabilityDetector()
    vulnerabilities = detector.analyze_contract("AgentExecutor.sol", agent_executor_code)
    
    # Filter for access control vulnerabilities
    access_control_vulns = [v for v in vulnerabilities if 'access_control' in v.vulnerability_type]
    
    print(f"\\n=== AgentExecutor Analysis ===")
    print(f"Is delegatecall target: {detector.is_delegatecall_target}")
    print(f"Total vulnerabilities: {len(vulnerabilities)}")
    print(f"Access control vulnerabilities: {len(access_control_vulns)}")
    
    if access_control_vulns:
        print("\\n[FAIL] False positives detected:")
        for vuln in access_control_vulns:
            print(f"  Line {vuln.line_number}: {vuln.description}")
        return False
    else:
        print("\\n[PASS] No false positives! AgentExecutor correctly identified as delegatecall target.")
        return True


def test_normal_contract_still_flagged():
    """Test that normal contracts without access control are still flagged."""
    
    normal_contract_code = """
// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract VulnerableContract {
    address public owner;
    
    // This SHOULD be flagged - no access control
    function withdraw() external {
        payable(msg.sender).transfer(address(this).balance);
    }
    
    // This should also be flagged
    function changeOwner(address newOwner) external {
        owner = newOwner;
    }
}
"""

    detector = ImprovedVulnerabilityDetector()
    vulnerabilities = detector.analyze_contract("VulnerableContract.sol", normal_contract_code)
    
    # Filter for access control vulnerabilities
    access_control_vulns = [v for v in vulnerabilities if 'access_control' in v.vulnerability_type]
    
    print(f"\\n=== VulnerableContract Analysis ===")
    print(f"Is delegatecall target: {detector.is_delegatecall_target}")
    print(f"Total vulnerabilities: {len(vulnerabilities)}")
    print(f"Access control vulnerabilities: {len(access_control_vulns)}")
    
    if access_control_vulns:
        print(f"\\n[PASS] Correctly flagged {len(access_control_vulns)} access control issues:")
        for vuln in access_control_vulns:
            print(f"  Line {vuln.line_number}: {vuln.description}")
        return True
    else:
        print("\\n[FAIL] Should have flagged access control issues but didn't!")
        return False


def test_library_contract():
    """Test that library contracts are recognized as delegatecall targets."""
    
    library_code = """
// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

library MathLibrary {
    function add(uint256 a, uint256 b) external pure returns (uint256) {
        return a + b;
    }
    
    function multiply(uint256 a, uint256 b) external pure returns (uint256) {
        return a * b;
    }
}
"""

    detector = ImprovedVulnerabilityDetector()
    vulnerabilities = detector.analyze_contract("MathLibrary.sol", library_code)
    
    # Filter for access control vulnerabilities
    access_control_vulns = [v for v in vulnerabilities if 'access_control' in v.vulnerability_type]
    
    print(f"\\n=== MathLibrary Analysis ===")
    print(f"Is delegatecall target: {detector.is_delegatecall_target}")
    print(f"Total vulnerabilities: {len(vulnerabilities)}")
    print(f"Access control vulnerabilities: {len(access_control_vulns)}")
    
    if access_control_vulns:
        print("\\n[FAIL] Libraries should not be flagged for missing access control!")
        return False
    else:
        print("\\n[PASS] Library correctly identified as delegatecall target.")
        return True


if __name__ == "__main__":
    print("=" * 70)
    print("Testing Delegatecall Target Detection")
    print("=" * 70)
    
    results = []
    
    # Test 1: AgentExecutor should NOT be flagged
    results.append(("AgentExecutor (no false positive)", test_agent_executor_no_false_positive()))
    
    # Test 2: Normal contract SHOULD be flagged
    results.append(("VulnerableContract (still detects issues)", test_normal_contract_still_flagged()))
    
    # Test 3: Library should NOT be flagged
    results.append(("Library (no false positive)", test_library_contract()))
    
    # Summary
    print("\\n" + "=" * 70)
    print("Test Summary")
    print("=" * 70)
    
    for test_name, passed in results:
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"{status} - {test_name}")
    
    total = len(results)
    passed = sum(1 for _, p in results if p)
    
    print(f"\\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\\n🎉 All tests passed! Delegatecall detection working correctly.")
        sys.exit(0)
    else:
        print(f"\\n❌ {total - passed} test(s) failed.")
        sys.exit(1)

