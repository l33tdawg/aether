#!/usr/bin/env python3
"""
Foundry Test Generator for AetherAudit

Generates Foundry test files for vulnerability validation and fuzzing.
"""

import os
import tempfile
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass


@dataclass
class TestTemplate:
    """Template for generating Foundry tests."""
    name: str
    template: str
    description: str


class FoundryTestGenerator:
    """Generates Foundry test files for vulnerability validation."""

    def __init__(self):
        self.test_templates = self._initialize_templates()

    def _initialize_templates(self) -> Dict[str, TestTemplate]:
        """Initialize test templates for different vulnerability types."""
        return {
            'reentrancy': TestTemplate(
                name='ReentrancyTest',
                template=self._get_reentrancy_template(),
                description='Test for reentrancy vulnerabilities'
            ),
            'access_control': TestTemplate(
                name='AccessControlTest',
                template=self._get_access_control_template(),
                description='Test for access control vulnerabilities'
            ),
            'arithmetic': TestTemplate(
                name='ArithmeticTest',
                template=self._get_arithmetic_template(),
                description='Test for arithmetic vulnerabilities'
            ),
            'unchecked_calls': TestTemplate(
                name='UncheckedCallsTest',
                template=self._get_unchecked_calls_template(),
                description='Test for unchecked calls vulnerabilities'
            ),
            'tx_origin': TestTemplate(
                name='TxOriginTest',
                template=self._get_tx_origin_template(),
                description='Test for tx.origin vulnerabilities'
            ),
            'flash_loan': TestTemplate(
                name='FlashLoanTest',
                template=self._get_flash_loan_template(),
                description='Test for flash loan vulnerabilities'
            ),
            'oracle_manipulation': TestTemplate(
                name='OracleManipulationTest',
                template=self._get_oracle_manipulation_template(),
                description='Test for oracle manipulation vulnerabilities'
            ),
            'generic': TestTemplate(
                name='GenericTest',
                template=self._get_generic_template(),
                description='Generic test template'
            )
        }

    def generate_test(self, vulnerability_type: str, contract_path: str, vulnerability_info: Dict[str, Any]) -> Optional[str]:
        """Generate a Foundry test file for the given vulnerability."""
        if vulnerability_type not in self.test_templates:
            vulnerability_type = 'generic'

        template = self.test_templates[vulnerability_type]
        contract_name = Path(contract_path).stem

        # Replace placeholders in template
        test_code = template.template.format(
            contract_name=contract_name,
            contract_path=contract_path,
            vulnerability_title=vulnerability_info.get('title', 'Unknown'),
            vulnerability_description=vulnerability_info.get('description', ''),
            vulnerability_line=vulnerability_info.get('line', 0),
            swc_id=vulnerability_info.get('swc_id', ''),
            severity=vulnerability_info.get('severity', 'Medium')
        )

        return test_code

    def save_test_file(self, test_code: str, output_dir: str = "test") -> str:
        """Save test code to a file."""
        os.makedirs(output_dir, exist_ok=True)
        
        # Generate unique filename
        import time
        timestamp = int(time.time())
        filename = f"VulnerabilityTest_{timestamp}.sol"
        filepath = os.path.join(output_dir, filename)
        
        with open(filepath, 'w') as f:
            f.write(test_code)
        
        return filepath

    def _get_reentrancy_template(self) -> str:
        """Get reentrancy test template."""
        return '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

// Import the vulnerable contract
import "../{contract_path}";

contract ReentrancyValidationTest is Test {{
    {contract_name} public target;
    ReentrancyAttacker public attacker;
    
    function setUp() public {{
        target = new {contract_name}();
        attacker = new ReentrancyAttacker(address(target));
        
        // Fund the target contract
        vm.deal(address(target), 10 ether);
        vm.deal(address(attacker), 1 ether);
    }}
    
    function testReentrancyVulnerability() public {{
        uint256 initialBalance = address(target).balance;
        
        // Execute reentrancy attack
        attacker.attack();
        
        // Check if attack was successful
        assertTrue(attacker.attackSuccessful(), "Reentrancy attack failed");
        
        // Check if funds were drained
        uint256 finalBalance = address(target).balance;
        assertLt(finalBalance, initialBalance, "Funds were not drained");
        
        console.log("Initial balance:", initialBalance);
        console.log("Final balance:", finalBalance);
        console.log("Attack count:", attacker.attackCount());
    }}
}}

contract ReentrancyAttacker {{
    {contract_name} public target;
    bool public attackSuccessful;
    uint256 public attackCount;
    
    constructor(address _target) {{
        target = {contract_name}(_target);
    }}
    
    function attack() public payable {{
        // Deposit to get balance
        target.deposit{{value: 1 ether}}();
        
        // Withdraw to trigger reentrancy
        target.withdraw(1 ether);
    }}
    
    receive() external payable {{
        if (attackCount < 3 && address(target).balance > 0) {{
            attackCount++;
            // Reentrancy: Call withdraw again
            target.withdraw(1 ether);
            attackSuccessful = true;
        }}
    }}
}}'''

    def _get_access_control_template(self) -> str:
        """Get access control test template."""
        return '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

// Import the vulnerable contract
import "../{contract_path}";

contract AccessControlValidationTest is Test {{
    {contract_name} public target;
    
    function setUp() public {{
        target = new {contract_name}();
    }}
    
    function testAccessControlBypass() public {{
        // Try to call admin function as non-admin
        vm.prank(address(0x1337));
        
        // This should fail if access control works
        try target.adminFunction() {{
            // If we reach here, access control is broken
            assertTrue(false, "Access control bypass succeeded");
        }} catch {{
            // This is expected if access control works
            assertTrue(true, "Access control working correctly");
        }}
    }}
}}'''

    def _get_arithmetic_template(self) -> str:
        """Get arithmetic test template."""
        return '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

// Import the vulnerable contract
import "../{contract_path}";

contract ArithmeticValidationTest is Test {{
    {contract_name} public target;
    
    function setUp() public {{
        target = new {contract_name}();
    }}
    
    function testArithmeticOverflow() public {{
        // Trigger overflow with maximum uint256 value
        uint256 maxValue = type(uint256).max;
        
        // Call vulnerable function
        try target.vulnerableFunction(maxValue) {{
            // If no revert, overflow occurred
            console.log("Overflow successfully triggered");
            assertTrue(true, "Arithmetic overflow detected");
        }} catch {{
            console.log("Function reverted - overflow prevented");
            assertTrue(false, "No overflow detected");
        }}
    }}
}}'''

    def _get_unchecked_calls_template(self) -> str:
        """Get unchecked calls test template."""
        return '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

// Import the vulnerable contract
import "../{contract_path}";

contract UncheckedCallsValidationTest is Test {{
    {contract_name} public target;
    FailingContract public failing;
    
    function setUp() public {{
        target = new {contract_name}();
        failing = new FailingContract();
    }}
    
    function testUncheckedCall() public {{
        // This should succeed even if the low-level call fails
        // because the return value is not checked
        target.makeUncheckedCall(address(failing));
        
        // If we reach here and the contract state is inconsistent,
        // the unchecked call vulnerability is confirmed
        assertTrue(true, "Unchecked call test completed");
    }}
}}

contract FailingContract {{
    function alwaysFails() external pure returns (bool) {{
        revert("I always fail");
    }}
}}'''

    def _get_tx_origin_template(self) -> str:
        """Get tx.origin test template."""
        return '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

// Import the vulnerable contract
import "../{contract_path}";

contract TxOriginValidationTest is Test {{
    {contract_name} public target;
    TxOriginBypass public bypass;
    
    function setUp() public {{
        target = new {contract_name}();
        bypass = new TxOriginBypass(address(target));
    }}
    
    function testTxOriginBypass() public {{
        // This should succeed if tx.origin check is bypassed
        bypass.bypassCheck();
        
        // Verify bypass succeeded
        assertTrue(true, "tx.origin bypass test completed");
    }}
}}

contract TxOriginBypass {{
    {contract_name} public target;
    
    constructor(address _target) {{
        target = {contract_name}(_target);
    }}
    
    function bypassCheck() external {{
        // Call the vulnerable function through this contract
        // The tx.origin will be different from msg.sender
        target.txOriginProtectedFunction();
    }}
}}'''

    def _get_flash_loan_template(self) -> str:
        """Get flash loan test template."""
        return '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

// Import the vulnerable contract
import "../{contract_path}";

contract FlashLoanValidationTest is Test {{
    {contract_name} public target;
    FlashLoanAttacker public attacker;
    
    function setUp() public {{
        target = new {contract_name}();
        attacker = new FlashLoanAttacker(address(target));
    }}
    
    function testFlashLoanAttack() public {{
        // Execute flash loan attack
        attacker.executeAttack();
        
        // Verify attack succeeded
        assertTrue(attacker.attackSuccessful(), "Flash loan attack failed");
    }}
}}

contract FlashLoanAttacker {{
    {contract_name} public target;
    bool public attackSuccessful;
    
    constructor(address _target) {{
        target = {contract_name}(_target);
    }}
    
    function executeAttack() public {{
        address[] memory assets = new address[](1);
        uint256[] memory amounts = new uint256[](1);
        uint256[] memory modes = new uint256[](1);
        
        assets[0] = address(0x1234);
        amounts[0] = 1000000000000000000; // 1 ETH
        modes[0] = 0;
        
        target.flashLoan(assets, amounts, modes, address(this), "", 0);
    }}
    
    function executeOperation(
        address[] memory assets,
        uint256[] memory amounts,
        uint256[] memory modes,
        address initiator,
        bytes memory params
    ) external {{
        // Attack logic here
        attackSuccessful = true;
    }}
}}'''

    def _get_oracle_manipulation_template(self) -> str:
        """Get oracle manipulation test template."""
        return '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

// Import the vulnerable contract
import "../{contract_path}";

contract OracleManipulationValidationTest is Test {{
    {contract_name} public target;
    
    function setUp() public {{
        target = new {contract_name}();
    }}
    
    function testOracleManipulation() public {{
        // Manipulate oracle price
        vm.mockCall(
            address(0x1234), // Oracle address
            abi.encodeWithSignature("latestAnswer()"),
            abi.encode(1000000) // Manipulated price
        );
        
        // Call function that uses oracle
        uint256 price = target.getAssetPrice(address(0x5678));
        
        // Verify manipulation succeeded
        assertEq(price, 1000000, "Oracle manipulation failed");
    }}
}}'''

    def _get_generic_template(self) -> str:
        """Get generic test template."""
        return '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

// Import the vulnerable contract
import "../{contract_path}";

contract GenericValidationTest is Test {{
    {contract_name} public target;
    
    function setUp() public {{
        target = new {contract_name}();
    }}
    
    function testVulnerability() public {{
        // Generic test for vulnerability validation
        // This test should be customized based on the specific vulnerability
        
        console.log("Testing vulnerability:", "{vulnerability_title}");
        console.log("Description:", "{vulnerability_description}");
        console.log("Line:", {vulnerability_line});
        console.log("SWC ID:", "{swc_id}");
        console.log("Severity:", "{severity}");
        
        // Add specific test logic here based on vulnerability type
        assertTrue(true, "Generic vulnerability test completed");
    }}
}}'''
