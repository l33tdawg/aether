#!/usr/bin/env python3
"""
Unit tests for Foundry Code Recognizer
"""

import unittest
from core.foundry_code_recognizer import FoundryCodeRecognizer, FoundryPattern


class TestFoundryCodeRecognizer(unittest.TestCase):
    """Test cases for Foundry code recognition."""

    def setUp(self):
        """Set up test fixtures."""
        self.recognizer = FoundryCodeRecognizer()

    def test_empty_contract(self):
        """Test analysis of empty contract."""
        patterns = self.recognizer.analyze_contract("")
        self.assertEqual(len(patterns), 0)

    def test_snapshot_revert_pattern(self):
        """Test detection of snapshot/revert testing patterns."""
        contract_code = """
pragma solidity ^0.8.0;

contract TestContract {
    function testSomething() public {
        uint256 snapshot = vm.snapshot();
        // Do something
        vm.prank(address(0x123));
        (bool success,) = target.call(data);
        require(success);
        vm.revertTo(snapshot);
    }
}
"""
        patterns = self.recognizer.analyze_contract(contract_code)

        # Should detect snapshot_revert pattern
        pattern_types = [p.pattern_type for p in patterns]
        self.assertIn('snapshot_revert', pattern_types)

        # Should detect prank_impersonation pattern
        self.assertIn('prank_impersonation', pattern_types)

    def test_foundry_cheats_detection(self):
        """Test detection of Foundry cheat codes."""
        contract_code = """
pragma solidity ^0.8.0;

contract TestContract {
    function setUp() public {
        vm.warp(block.timestamp + 1 days);
        vm.deal(address(this), 100 ether);
        vm.etch(address(0x123), hex"1234");
    }
}
"""
        patterns = self.recognizer.analyze_contract(contract_code)

        # Should detect foundry_cheats pattern
        pattern_types = [p.pattern_type for p in patterns]
        self.assertIn('foundry_cheats', pattern_types)

    def test_script_contract_detection(self):
        """Test detection of Foundry script contracts."""
        contract_code = """
pragma solidity ^0.8.0;

import {Script} from "forge-std/Script.sol";

contract DeployScript is Script {
    function run() external {
        vm.broadcast();
        new MyContract();
    }
}
"""
        patterns = self.recognizer.analyze_contract(contract_code)

        # Should detect script_contract pattern
        pattern_types = [p.pattern_type for p in patterns]
        self.assertIn('script_contract', pattern_types)

    def test_test_contract_detection(self):
        """Test detection of Foundry test contracts."""
        contract_code = """
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";

contract MyContractTest is Test {
    function setUp() public {}

    function testSomething() public {
        // test code
    }
}
"""
        patterns = self.recognizer.analyze_contract(contract_code)

        # Should detect test_contract pattern
        pattern_types = [p.pattern_type for p in patterns]
        self.assertIn('test_contract', pattern_types)

    def test_file_path_recognition(self):
        """Test file path-based pattern recognition."""
        # Test script file detection
        patterns = self.recognizer.analyze_contract("contract C {}", "contracts/script/Deploy.s.sol")
        pattern_types = [p.pattern_type for p in patterns]
        self.assertIn('script_file', pattern_types)

        # Test regular contract file
        patterns = self.recognizer.analyze_contract("contract C {}", "contracts/MyContract.sol")
        pattern_types = [p.pattern_type for p in patterns]
        self.assertNotIn('script_file', pattern_types)

    def test_filtering_logic(self):
        """Test vulnerability filtering logic."""
        # Set up recognizer with patterns
        contract_code = """
pragma solidity ^0.8.0;

import {Script} from "forge-std/Script.sol";

contract DeployScript is Script {
    function run() external {
        uint256 snapshot = vm.snapshot();
        vm.prank(deployer);
        (bool success,) = target.call(data);
        vm.revertTo(snapshot);
    }
}
"""
        self.recognizer.analyze_contract(contract_code)

        # Test filtering reentrancy in script context
        should_filter, reason = self.recognizer.should_filter_finding({
            'vulnerability_type': 'reentrancy',
            'line_number': 10  # Line with external call
        })
        self.assertTrue(should_filter)
        self.assertIn('Foundry testing context', reason)

        # Test filtering access control in script context
        should_filter, reason = self.recognizer.should_filter_finding({
            'vulnerability_type': 'access_control',
            'line_number': 8  # Line with vm.prank
        })
        self.assertTrue(should_filter)

    def test_snapshot_revert_pattern_detection(self):
        """Test specific snapshot/revert pattern detection."""
        contract_code = """
function testSomething() public {
    uint256 snapshot = vm.snapshot();
    // Some test code
    address target = address(0x123);
    bytes memory data = abi.encodeCall(target.doSomething, ());
    (bool success,) = target.call(data);
    vm.revertTo(snapshot);
}
"""
        is_snapshot_pattern = self.recognizer.is_snapshot_revert_pattern(contract_code, 5)
        self.assertTrue(is_snapshot_pattern)

        # Test non-snapshot line
        is_snapshot_pattern = self.recognizer.is_snapshot_revert_pattern(contract_code, 1)
        self.assertFalse(is_snapshot_pattern)

    def test_context_summary(self):
        """Test context summary generation."""
        contract_code = """
pragma solidity ^0.8.0;

import {Script} from "forge-std/Script.sol";

contract DeployScript is Script {
    function run() external {
        uint256 snapshot = vm.snapshot();
        vm.prank(address(0x123));
        vm.revertTo(snapshot);
    }
}
"""
        self.recognizer.analyze_contract(contract_code)

        summary = self.recognizer.get_context_summary()
        self.assertGreaterEqual(summary['total_patterns'], 3)  # At least script_contract, snapshot_revert, prank_impersonation
        self.assertTrue(summary['is_script_contract'])
        self.assertTrue(summary['has_testing_utilities'])
        self.assertFalse(summary['is_test_contract'])

        # Verify expected pattern types are present
        expected_patterns = ['script_contract', 'snapshot_revert', 'prank_impersonation']
        for pattern in expected_patterns:
            self.assertIn(pattern, summary['pattern_types'])
            self.assertGreater(summary['pattern_types'][pattern], 0)

    def test_no_false_patterns(self):
        """Test that legitimate production code doesn't trigger patterns."""
        production_code = """
pragma solidity ^0.8.0;

contract ProductionContract {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function transferOwnership(address newOwner) public {
        require(msg.sender == owner, "Not owner");
        owner = newOwner;
    }

    function doSomething() public {
        require(msg.sender == owner);
        // Some business logic
    }
}
"""
        patterns = self.recognizer.analyze_contract(production_code)

        # Should not detect any Foundry patterns in production code
        foundry_patterns = [p for p in patterns if p.pattern_type in [
            'snapshot_revert', 'prank_impersonation', 'foundry_cheats',
            'script_contract', 'test_contract', 'script_file'
        ]]
        self.assertEqual(len(foundry_patterns), 0)


if __name__ == '__main__':
    unittest.main()
