#!/usr/bin/env python3
"""
Test validation of risc0-ethereum false positives fix
"""

import unittest
from core.enhanced_vulnerability_detector import EnhancedVulnerabilityDetector


class TestRisc0EthereumValidation(unittest.TestCase):
    """Test that our improvements correctly handle the risc0-ethereum false positives."""

    def setUp(self):
        """Set up test fixtures."""
        self.detector = EnhancedVulnerabilityDetector()

    def test_manage_s_sol_false_positives(self):
        """Test that Manage.s.sol false positives are filtered."""
        # Simulate the Manage.s.sol patterns that caused false positives

        # Pattern 1: Variable comparison (this was actually correct code)
        comparison_code = """
function verifierEstop() internal returns (RiscZeroVerifierEmergencyStop) {
    bytes4 selector = bytes4(vm.envBytes("VERIFIER_SELECTOR"));
    for (uint256 i = 0; i < deployment.verifiers.length; i++) {
        if (deployment.verifiers[i].selector == selector) {  // This line was flagged
            _verifierEstop = RiscZeroVerifierEmergencyStop(deployment.verifiers[i].estop);
            break;
        }
    }
    return _verifierEstop;
}
"""
        vulnerabilities = self.detector.analyze_contract(comparison_code, "contracts/script/Manage.s.sol")

        # Should not flag struct field comparison as "variable compared to itself"
        comparison_vulns = [v for v in vulnerabilities if 'compare' in v.vulnerability_type.lower() or 'self' in str(v.description).lower()]
        self.assertEqual(len(comparison_vulns), 0, "Struct field comparison should not be flagged")

    def test_simulate_function_reentrancy_false_positive(self):
        """Test that the simulate() function reentrancy false positive is filtered."""
        simulate_code = """
function simulate(address dest, bytes memory data) internal {
    console2.log("Simulating call to", dest);
    console2.logBytes(data);
    uint256 snapshot = vm.snapshot();
    vm.prank(address(timelockController()));
    (bool success,) = dest.call(data);
    require(success, "simulation of transaction to schedule failed");
    vm.revertTo(snapshot);
    console2.log("Simulation successful");
}
"""
        vulnerabilities = self.detector.analyze_contract(simulate_code, "contracts/script/Manage.s.sol")

        # Should not flag reentrancy because vm.revertTo() prevents state persistence
        reentrancy_vulns = [v for v in vulnerabilities if 'reentrancy' in v.vulnerability_type.lower()]
        self.assertEqual(len(reentrancy_vulns), 0, "Foundry snapshot/revert pattern should filter reentrancy")

    def test_emergency_stop_security_pattern(self):
        """Test that the emergency stop circuit breaker is recognized as legitimate."""
        estop_code = """
contract RiscZeroVerifierEmergencyStop is IRiscZeroVerifier, Ownable2Step, Pausable {
    IRiscZeroVerifier public immutable verifier;

    error InvalidProofOfExploit();

    constructor(IRiscZeroVerifier _verifier, address guardian) Ownable(guardian) {
        verifier = _verifier;
    }

    function estop() external onlyOwner {
        _pause();
    }

    function estop(Receipt calldata receipt) external {
        if (receipt.claimDigest != bytes32(0)) {
            revert InvalidProofOfExploit();
        }
        // Check that the proof of exploit receipt really does verify.
        verifyIntegrity(receipt);
        _pause();
    }

    function verify(bytes calldata seal, bytes32 imageId, bytes32 journalDigest) external view whenNotPaused {
        // Forward the call on to the wrapped contract.
        verifier.verify(seal, imageId, journalDigest);
    }

    function verifyIntegrity(Receipt calldata receipt) public view whenNotPaused {
        // Forward the call on to the wrapped contract.
        verifier.verifyIntegrity(receipt);
    }
}
"""
        vulnerabilities = self.detector.analyze_contract(estop_code, "contracts/src/RiscZeroVerifierEmergencyStop.sol")

        # Should not flag access control issues for the circuit breaker
        access_vulns = [v for v in vulnerabilities if 'access' in v.vulnerability_type.lower() and 'control' in v.vulnerability_type.lower()]
        validation_vulns = [v for v in vulnerabilities if 'validation' in v.vulnerability_type.lower()]

        # Should be significantly reduced due to security pattern recognition
        print(f"Found {len(access_vulns)} access control vulns and {len(validation_vulns)} validation vulns")
        print("Vulnerabilities found:", [v.vulnerability_type for v in vulnerabilities])

        # The circuit breaker should not be flagged as having insufficient validation
        insufficient_validation = [v for v in vulnerabilities if 'insufficient' in str(v.description).lower() and 'validation' in str(v.description).lower()]
        self.assertEqual(len(insufficient_validation), 0, "Circuit breaker should not be flagged for insufficient validation")

    def test_overall_vulnerability_reduction(self):
        """Test that overall false positives are reduced for risc0-ethereum."""
        # Load and analyze a representative sample of risc0-ethereum code
        # This simulates the original analysis that found 3 high-severity issues

        risc0_combined = """
// Simulate key parts of risc0-ethereum that caused false positives

// From Manage.s.sol
function simulate(address dest, bytes memory data) internal {
    uint256 snapshot = vm.snapshot();
    vm.prank(address(timelockController()));
    (bool success,) = dest.call(data);
    vm.revertTo(snapshot);
}

function verifierEstop() internal returns (RiscZeroVerifierEmergencyStop) {
    bytes4 selector = bytes4(vm.envBytes("VERIFIER_SELECTOR"));
    for (uint256 i = 0; i < deployment.verifiers.length; i++) {
        if (deployment.verifiers[i].selector == selector) {
            _verifierEstop = RiscZeroVerifierEmergencyStop(deployment.verifiers[i].estop);
            break;
        }
    }
}

// From RiscZeroVerifierEmergencyStop.sol
contract RiscZeroVerifierEmergencyStop is IRiscZeroVerifier, Ownable2Step, Pausable {
    function estop(Receipt calldata receipt) external {
        if (receipt.claimDigest != bytes32(0)) {
            revert InvalidProofOfExploit();
        }
        verifyIntegrity(receipt);
        _pause();
    }
}
"""
        vulnerabilities = self.detector.analyze_contract(risc0_combined)

        # Count high-severity vulnerabilities
        high_severity = [v for v in vulnerabilities if hasattr(v, 'severity') and v.severity == 'high']

        print(f"Found {len(high_severity)} high-severity vulnerabilities")
        print("High-severity issues:", [(v.vulnerability_type, v.line_number) for v in high_severity])

        # The original report found 3 high-severity issues
        # With our improvements, this should be significantly reduced
        # We expect 0 high-severity issues from the patterns that were false positives
        self.assertEqual(len(high_severity), 0, "Should eliminate the original 3 false positive high-severity findings")

    def test_legitimate_vulnerabilities_still_detected(self):
        """Ensure that legitimate vulnerabilities in similar code are still detected."""
        # Add a real vulnerability to risc0-like code
        vulnerable_risc0 = """
contract RiscZeroVerifierEmergencyStop is IRiscZeroVerifier, Ownable2Step, Pausable {
    function estop(Receipt calldata receipt) external {
        if (receipt.claimDigest != bytes32(0)) {
            revert InvalidProofOfExploit();
        }
        verifyIntegrity(receipt);
        _pause();
    }

    // LEGITIMATE VULNERABILITY: Reentrancy in unprotected function
    function vulnerableWithdraw() external {
        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;  // State change
        (bool success,) = msg.sender.call{value: amount}("");  // External call after state change
        if (!success) {
            balances[msg.sender] = amount;  // Attempted rollback
        }
    }
}
"""
        vulnerabilities = self.detector.analyze_contract(vulnerable_risc0)

        # Should still detect the legitimate reentrancy
        reentrancy_vulns = [v for v in vulnerabilities if 'reentrancy' in v.vulnerability_type.lower()]
        self.assertGreater(len(reentrancy_vulns), 0, "Should still detect legitimate reentrancy vulnerabilities")

        # Should not flag the circuit breaker
        access_vulns = [v for v in vulnerabilities if 'access' in v.vulnerability_type.lower() and 'estop' in str(v.description).lower()]
        self.assertEqual(len(access_vulns), 0, "Should not flag circuit breaker as access control issue")


if __name__ == '__main__':
    unittest.main()
