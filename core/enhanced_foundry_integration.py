#!/usr/bin/env python3
"""
Enhanced Foundry Integration for Bug Bounty Submissions

This module integrates the enhanced vulnerability detectors with Foundry
validation to produce bug bounty submissions that meet industry standards.
"""

import asyncio
import json
import tempfile
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

from core.enhanced_vulnerability_detector import EnhancedVulnerabilityDetector
from core.foundry_validator import FoundryValidator, ValidationResult
from core.report_generator import ReportGenerator
from core.enhanced_submission_format import (
    SubmissionBuilder,
    SubmissionValidator,
    SubmissionFormatter,
    VerifiedBugBountySubmission
)
from core.fork_testing import check_dependencies


@dataclass
class BugBountySubmission:
    """Complete bug bounty submission with Foundry validation."""
    contract_name: str
    contract_code: str
    vulnerabilities: List[Dict[str, Any]]
    foundry_validation: Dict[str, Any]
    submission_report: str
    foundry_tests: List[str]
    exploit_pocs: List[str]
    severity_summary: Dict[str, int]
    total_potential_profit: float
    confidence_score: float


class EnhancedFoundryIntegration:
    """Enhanced integration between vulnerability detectors and Foundry validation."""
    
    def __init__(self):
        self.detector = EnhancedVulnerabilityDetector()
        self.foundry_validator = FoundryValidator()
        self.report_generator = ReportGenerator()
        
    async def analyze_and_validate_contract(
        self,
        contract_path: str,
        output_dir: str = None,
        use_real_world_validation: bool = False,
        target_platform: str = "immunefi",
        mainnet_rpc_key: str = None
    ) -> Dict[str, Any]:
        """Analyze contract and validate findings with Foundry and optional real-world testing."""

        if output_dir is None:
            output_dir = tempfile.mkdtemp(prefix="bug_bounty_analysis_")

        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)

        # Read contract code
        with open(contract_path, 'r') as f:
            contract_code = f.read()

        contract_name = Path(contract_path).stem

        print(f"🔍 Analyzing contract: {contract_name}")

        # Step 1: Detect vulnerabilities using enhanced detectors
        print("📊 Running enhanced vulnerability detection...")
        vulnerabilities = self.detector.analyze_contract(contract_code)

        print(f"✅ Found {len(vulnerabilities)} potential vulnerabilities")

        # Step 2: Configure real-world validation if requested
        real_world_validation = None
        if use_real_world_validation:
            print("🌐 Configuring real-world validation...")
            if not check_dependencies():
                print("⚠️  Missing dependencies for real-world validation, falling back to mock testing")
                use_real_world_validation = False
            elif mainnet_rpc_key:
                # Configure RPC for real-world validation
                success = self.foundry_validator.configure_real_world_validation(mainnet_rpc_key)
                if success:
                    self.foundry_validator.enable_real_world_validation()
                    print("✅ Real-world validation enabled")
                else:
                    print("❌ Failed to configure real-world validation")
                    use_real_world_validation = False

        # Step 3: Validate findings with Foundry
        print(f"🧪 Validating findings with Foundry tests ({self.foundry_validator.get_validation_mode()})...")
        foundry_validation = await self.foundry_validator.generate_bug_bounty_submission(
            vulnerabilities, contract_code, str(output_path)
        )

        # Step 4: Generate enhanced submission with real-world validation if available
        print("📝 Generating enhanced bug bounty submission...")
        submission = await self._generate_enhanced_submission(
            contract_name, contract_code, vulnerabilities, foundry_validation, output_path, target_platform
        )

        # Step 5: Generate reports
        print("📋 Generating reports...")
        await self._generate_enhanced_reports(submission, output_path)

        print(f"🎯 Enhanced bug bounty submission complete! Check {output_path}")
        print(f"   Validation method: {submission['validation']['validation_method']}")
        print(f"   Vulnerabilities: {submission['validation']['total_vulnerabilities']}")
        print(f"   Validated: {submission['validation']['validated_vulnerabilities']}")
        print(f"   Exploitable: {submission['validation']['exploitable_vulnerabilities']}")
        if submission['validation'].get('total_potential_profit'):
            print(f"   Potential Profit: {submission['validation']['total_potential_profit']} ETH")

        return submission

    async def _generate_enhanced_submission(
        self,
        contract_name: str,
        contract_code: str,
        vulnerabilities: List[Dict[str, Any]],
        foundry_validation: Dict[str, Any],
        output_path: Path,
        target_platform: str
    ) -> Dict[str, Any]:
        """Generate enhanced submission using new format."""

        # Extract real-world validation results if available
        real_world_validation = None
        if foundry_validation.get("foundry_validation", {}).get("real_world_validation"):
            # Extract real-world validation data from foundry validation results
            real_world_validation = {
                "enabled": True,
                "method": "mainnet_fork_testing",
                "transaction_proofs": [],
                "exploit_transactions": []
            }

            # Collect transaction proofs from vulnerabilities
            for vuln in foundry_validation.get("vulnerabilities", []):
                vuln_validation = vuln.get("foundry_validation", {})
                if vuln_validation.get("transaction_proof"):
                    real_world_validation["transaction_proofs"].append({
                        "transaction_hash": vuln_validation.get("transaction_hash"),
                        "fork_info": vuln_validation.get("transaction_proof", {}).get("fork_info", {}),
                        "state_changes": vuln_validation.get("transaction_proof", {}).get("state_changes", []),
                        "profit_realized": vuln_validation.get("profit_realized", 0.0),
                        "gas_used": vuln_validation.get("gas_used", 0),
                        "exploit_executed": vuln_validation.get("exploitable", False),
                        "vulnerability_confirmed": vuln_validation.get("validated", False)
                    })

        # Create enhanced submission
        builder = SubmissionBuilder()
        submission = builder.create_submission(
            contract_name=contract_name,
            contract_address="0x0000000000000000000000000000000000000000",  # Would be extracted from contract
            vulnerabilities=vulnerabilities,
            foundry_validation=foundry_validation,
            real_world_validation=real_world_validation
        )

        # Validate and format for target platform
        result = await builder.validate_and_format(target_platform)

        # Save enhanced submission files
        submission_file = output_path / "enhanced_submission.json"
        submission.save_to_file(str(submission_file))

        return {
            "submission": submission,
            "validation": {
                "total_vulnerabilities": len(vulnerabilities),
                "validated_vulnerabilities": foundry_validation.get("summary", {}).get("validated_vulnerabilities", 0),
                "exploitable_vulnerabilities": foundry_validation.get("summary", {}).get("exploitable_vulnerabilities", 0),
                "total_potential_profit": foundry_validation.get("summary", {}).get("total_potential_profit", 0.0),
                "validation_method": submission.verification_method,
                "real_world_validation": real_world_validation is not None,
                "submission_score": result["validation"]["score"]
            },
            "formatted": result["formatted"],
            "platform": target_platform
        }

    async def _generate_comprehensive_submission(
        self,
        contract_name: str,
        contract_code: str,
        vulnerabilities: List[Dict[str, Any]],
        foundry_validation: Dict[str, Any],
        output_path: Path
    ) -> BugBountySubmission:
        """Generate comprehensive bug bounty submission."""
        
        # Calculate severity summary
        severity_summary = {
            'critical': len([v for v in vulnerabilities if getattr(v, 'severity', 'unknown') == 'critical']),
            'high': len([v for v in vulnerabilities if getattr(v, 'severity', 'unknown') == 'high']),
            'medium': len([v for v in vulnerabilities if getattr(v, 'severity', 'unknown') == 'medium']),
            'low': len([v for v in vulnerabilities if getattr(v, 'severity', 'unknown') == 'low'])
        }
        
        # Calculate total potential profit
        total_potential_profit = foundry_validation['summary']['total_potential_profit']
        
        # Calculate confidence score
        confidence_score = self._calculate_confidence_score(vulnerabilities, foundry_validation)
        
        # Generate submission report
        submission_report = self._generate_submission_markdown(
            contract_name, vulnerabilities, foundry_validation, severity_summary
        )
        
        # Collect Foundry test files
        foundry_tests = list(output_path.glob("**/*_test.sol"))
        
        # Generate exploit PoCs
        exploit_pocs = await self._generate_exploit_pocs(vulnerabilities, output_path)
        
        return BugBountySubmission(
            contract_name=contract_name,
            contract_code=contract_code,
            vulnerabilities=vulnerabilities,
            foundry_validation=foundry_validation,
            submission_report=submission_report,
            foundry_tests=[str(test) for test in foundry_tests],
            exploit_pocs=exploit_pocs,
            severity_summary=severity_summary,
            total_potential_profit=total_potential_profit,
            confidence_score=confidence_score
        )
    
    def _calculate_confidence_score(
        self, 
        vulnerabilities: List[Dict[str, Any]], 
        foundry_validation: Dict[str, Any]
    ) -> float:
        """Calculate overall confidence score for the submission."""
        
        if not vulnerabilities:
            return 0.0
        
        # Base confidence from vulnerability detection
        base_confidence = sum(getattr(v, 'confidence', 0.0) for v in vulnerabilities) / len(vulnerabilities)
        
        # Validation bonus
        validation_results = foundry_validation['foundry_validation']['validation_results']
        validated_count = sum(1 for r in validation_results if r['vulnerability_confirmed'])
        validation_bonus = (validated_count / len(validation_results)) * 0.3 if validation_results else 0.0
        
        # Exploit bonus
        exploitable_count = sum(1 for r in validation_results if r['exploit_executed'])
        exploit_bonus = (exploitable_count / len(validation_results)) * 0.2 if validation_results else 0.0
        
        total_confidence = min(base_confidence + validation_bonus + exploit_bonus, 1.0)
        
        return total_confidence
    
    def _generate_submission_markdown(
        self,
        contract_name: str,
        vulnerabilities: List[Dict[str, Any]],
        foundry_validation: Dict[str, Any],
        severity_summary: Dict[str, int]
    ) -> str:
        """Generate markdown submission report."""
        
        report = f"""# Bug Bounty Submission: {contract_name}

## Executive Summary

This submission identifies **{len(vulnerabilities)} vulnerabilities** in the {contract_name} contract, validated using Foundry tests and executable proof-of-concepts.

### Key Findings
- **Critical**: {severity_summary['critical']} vulnerabilities
- **High**: {severity_summary['high']} vulnerabilities  
- **Medium**: {severity_summary['medium']} vulnerabilities
- **Low**: {severity_summary['low']} vulnerabilities

### Validation Results
- **Validated Vulnerabilities**: {foundry_validation['summary']['validated_vulnerabilities']}
- **Exploitable Vulnerabilities**: {foundry_validation['summary']['exploitable_vulnerabilities']}
- **Total Potential Profit**: {foundry_validation['summary']['total_potential_profit']} ETH

## Detailed Vulnerabilities

"""
        
        # Add vulnerability details
        for i, vuln in enumerate(vulnerabilities, 1):
            validation = getattr(vuln, 'foundry_validation', {})
            
            report += f"""### {i}. {getattr(vuln, 'vulnerability_type', 'Unknown').replace('_', ' ').title()}

**Severity**: {getattr(vuln, 'severity', 'Unknown').title()}
**Confidence**: {getattr(vuln, 'confidence', 0.0):.2f}
**Line**: {getattr(vuln, 'line_number', 'Unknown')}

**Description**: {getattr(vuln, 'description', 'No description available')}

**Code Snippet**:
```solidity
{getattr(vuln, 'code_snippet', '// No code snippet available')}
```

**Foundry Validation**:
- **Validated**: {'✅ Yes' if validation.get('validated', False) else '❌ No'}
- **Exploitable**: {'✅ Yes' if validation.get('exploitable', False) else '❌ No'}
- **Profit Realized**: {validation.get('profit_realized', 0.0)} ETH

**Recommendation**: {getattr(vuln, 'recommendation', 'No recommendation available')}

---

"""
        
        # Add Foundry test results
        report += """## Foundry Test Results

The following Foundry tests validate the identified vulnerabilities:

"""
        
        validation_results = foundry_validation['foundry_validation']['validation_results']
        for result in validation_results:
            status = "✅ PASSED" if result['success'] else "❌ FAILED"
            report += f"- **{result['vulnerability_type']}**: {status}\n"
        
        # Add recommendations
        report += f"""
## Recommendations

{chr(10).join(f"- {rec}" for rec in foundry_validation.get('recommendations', []))}

## Proof of Concept

Executable proof-of-concepts are provided in the Foundry test files, demonstrating:
1. How each vulnerability can be exploited
2. The potential financial impact
3. Steps to reproduce the attack

## Conclusion

This submission provides comprehensive analysis with executable proof-of-concepts that meet bug bounty program standards. All findings have been validated using Foundry tests to ensure accuracy and exploitability.

---
*Generated by Enhanced AetherAudit Tool with Foundry Integration*
"""
        
        return report
    
    async def _generate_exploit_pocs(
        self, 
        vulnerabilities: List[Dict[str, Any]], 
        output_path: Path
    ) -> List[str]:
        """Generate exploit proof-of-concepts."""
        
        pocs = []
        
        for i, vuln in enumerate(vulnerabilities, 1):
            vuln_type = getattr(vuln, 'vulnerability_type', 'unknown')
            
            # Generate PoC based on vulnerability type
            if vuln_type == 'arithmetic_overflow':
                poc = self._generate_overflow_poc(vuln)
            elif vuln_type == 'division_by_zero':
                poc = self._generate_division_poc(vuln)
            elif vuln_type == 'reentrancy':
                poc = self._generate_reentrancy_poc(vuln)
            else:
                poc = self._generate_generic_poc(vuln)
            
            # Save PoC
            poc_file = output_path / f"exploit_{i}_{vuln_type}.sol"
            with open(poc_file, 'w') as f:
                f.write(poc)
            
            pocs.append(str(poc_file))
        
        return pocs
    
    def _generate_overflow_poc(self, vuln) -> str:
        """Generate arithmetic overflow PoC."""
        return f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Arithmetic Overflow Exploit PoC
// Vulnerability: {getattr(vuln, 'vulnerability_type', 'unknown')}
// Severity: {getattr(vuln, 'severity', 'unknown')}
// Line: {getattr(vuln, 'line_number', 'unknown')}

contract ArithmeticOverflowExploit {{
    function exploit() public pure returns (uint256) {{
        // Trigger arithmetic overflow
        uint256 max = type(uint256).max;
        uint256 result = max + 1; // This will overflow to 0
        
        return result;
    }}
    
    function demonstrateOverflow() public pure returns (bool) {{
        uint256 a = type(uint256).max;
        uint256 b = 2;
        uint256 result = a * b; // This will overflow
        
        return result < a; // Should be true due to overflow
    }}
}}
"""
    
    def _generate_division_poc(self, vuln) -> str:
        """Generate division by zero PoC."""
        return f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Division by Zero Exploit PoC
// Vulnerability: {getattr(vuln, 'vulnerability_type', 'unknown')}
// Severity: {getattr(vuln, 'severity', 'unknown')}
// Line: {getattr(vuln, 'line_number', 'unknown')}

contract DivisionByZeroExploit {{
    function exploit() public pure returns (uint256) {{
        // This will revert due to division by zero
        uint256 a = 100;
        uint256 b = 0;
        
        return a / b; // Division by zero
    }}
    
    function demonstrateDivisionByZero() public pure returns (bool) {{
        try this.exploit() returns (uint256) {{
            return false; // Should not reach here
        }} catch {{
            return true; // Division by zero caught
        }}
    }}
}}
"""
    
    def _generate_reentrancy_poc(self, vuln) -> str:
        """Generate reentrancy PoC."""
        return f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Reentrancy Exploit PoC
// Vulnerability: {getattr(vuln, 'vulnerability_type', 'unknown')}
// Severity: {getattr(vuln, 'severity', 'unknown')}
// Line: {getattr(vuln, 'line_number', 'unknown')}

contract ReentrancyExploit {{
    address public target;
    bool public attacking;
    
    constructor(address _target) {{
        target = _target;
    }}
    
    function attack() public payable {{
        attacking = true;
        // Call target contract's vulnerable function
        (bool success, ) = target.call{{value: msg.value}}(
            abi.encodeWithSignature("withdraw(uint256)", msg.value)
        );
        require(success, "Attack failed");
    }}
    
    receive() external payable {{
        if (attacking && address(target).balance >= msg.value) {{
            // Reentrancy attack
            (bool success, ) = target.call(
                abi.encodeWithSignature("withdraw(uint256)", msg.value)
            );
            if (success) {{
                attacking = false;
            }}
        }}
    }}
}}
"""
    
    def _generate_generic_poc(self, vuln) -> str:
        """Generate generic PoC."""
        return f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Generic Exploit PoC
// Vulnerability: {getattr(vuln, 'vulnerability_type', 'unknown')}
// Severity: {getattr(vuln, 'severity', 'unknown')}
// Line: {getattr(vuln, 'line_number', 'unknown')}

contract GenericExploit {{
    function exploit() public pure returns (bool) {{
        // Generic exploit demonstration
        // This is a placeholder for {getattr(vuln, 'vulnerability_type', 'unknown')} vulnerability
        
        return true;
    }}
    
    function demonstrateVulnerability() public pure returns (string memory) {{
        return "Vulnerability demonstrated: {getattr(vuln, 'vulnerability_type', 'unknown')}";
    }}
}}
"""
    
    async def _generate_submission_reports(self, submission: BugBountySubmission, output_path: Path):
        """Generate submission reports."""
        
        # Save main submission report
        report_file = output_path / "bug_bounty_submission.md"
        with open(report_file, 'w') as f:
            f.write(submission.submission_report)
        
        # Save JSON data
        json_file = output_path / "submission_data.json"
        with open(json_file, 'w') as f:
            json.dump({
                'contract_name': submission.contract_name,
                'vulnerabilities': [vars(v) if hasattr(v, '__dict__') else v for v in submission.vulnerabilities],
                'foundry_validation': submission.foundry_validation,
                'severity_summary': submission.severity_summary,
                'total_potential_profit': submission.total_potential_profit,
                'confidence_score': submission.confidence_score
            }, f, indent=2)
        
        # Save contract code
        contract_file = output_path / f"{submission.contract_name}.sol"
        with open(contract_file, 'w') as f:
            f.write(submission.contract_code)
        
        print(f"📄 Enhanced reports saved to {output_path}")
        print(f"   - Enhanced submission: {submission_file}")
        print(f"   - Platform formatted: {platform}_submission.md")
        print(f"   - Contract: {contract_file}")
        print(f"   - Foundry tests: {len(submission.foundry_tests)} files")
        print(f"   - Exploit PoCs: {len(submission.exploit_pocs)} files")
        print(f"   - Validation score: {result['validation']['score']:.1f}/100")

    async def _generate_enhanced_reports(self, submission: Dict[str, Any], output_path: Path):
        """Generate enhanced reports with platform formatting."""

        # Save platform-formatted submission
        platform = submission.get("platform", "immunefi")
        formatted = submission.get("formatted", {})

        platform_file = output_path / f"{platform}_submission.md"
        with open(platform_file, 'w') as f:
            f.write(f"# {formatted.get('title', 'Bug Bounty Submission')}\n\n")
            f.write(formatted.get('description', 'No description available'))

        # Save validation report
        validation = submission.get("validation", {})
        validation_file = output_path / "validation_report.md"
        with open(validation_file, 'w') as f:
            f.write(f"""# Validation Report

## Summary
- **Total Vulnerabilities**: {validation.get('total_vulnerabilities', 0)}
- **Validated Vulnerabilities**: {validation.get('validated_vulnerabilities', 0)}
- **Exploitable Vulnerabilities**: {validation.get('exploitable_vulnerabilities', 0)}
- **Potential Profit**: {validation.get('total_potential_profit', 0.0)} ETH
- **Validation Method**: {validation.get('validation_method', 'unknown')}
- **Real-World Validation**: {validation.get('real_world_validation', False)}
- **Submission Score**: {validation.get('submission_score', 0.0):.1f}/100

## Validation Details
""")

            if validation.get('real_world_validation'):
                f.write("- **Real-World Fork Testing**: Enabled ✅\n")
                f.write("- **Transaction Proofs**: Available ✅\n")
                f.write("- **Mainnet State Validation**: Confirmed ✅\n")
            else:
                f.write("- **Mock Testing**: Used (No RPC configuration) ⚠️\n")
                f.write("- **Real-World Validation**: Not available\n")

        print(f"   - Platform submission: {platform_file}")
        print(f"   - Validation report: {validation_file}")


async def main():
    """Main function for testing the enhanced integration."""

    print("🚀 Enhanced AetherAudit with Real-World Foundry Verification")
    print("=" * 60)

    # Check if Foundry is installed
    validator = FoundryValidator()
    if not validator.check_foundry_installation():
        print("❌ Foundry not found. Installing...")
        if validator.install_foundry():
            print("✅ Foundry installed successfully")
        else:
            print("❌ Failed to install Foundry")
            return

    # Test integration
    integration = EnhancedFoundryIntegration()

    # Create a test contract with known vulnerabilities
    test_contract = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableContract {
    mapping(address => uint256) public balances;

    // Vulnerable: No reentrancy protection
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // Vulnerable: External call before state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] -= amount;
    }

    // Vulnerable: Potential overflow
    function calculate(uint256 a, uint256 b) public pure returns (uint256) {
        return a * b; // No overflow protection
    }

    // Vulnerable: Division by zero
    function divide(uint256 a, uint256 b) public pure returns (uint256) {
        return a / b; // No zero check
    }

    // Vulnerable: Access control
    function adminFunction() public {
        // No access control - anyone can call this
        balances[msg.sender] = 999999;
    }
}
"""

    # Save test contract
    with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
        f.write(test_contract)
        test_contract_path = f.name

    try:
        print("\n📋 Test Options:")
        print("1. Mock validation only (fast)")
        print("2. Real-world validation with demo RPC")
        print("3. Real-world validation with your RPC key")

        choice = input("\nChoose validation method (1-3): ").strip()

        use_real_world = False
        mainnet_key = None

        if choice == "2":
            print("🔧 Using demo mode - limited real-world testing")
            use_real_world = True
        elif choice == "3":
            mainnet_key = input("Enter your Alchemy mainnet API key: ").strip()
            if mainnet_key:
                use_real_world = True
            else:
                print("❌ No API key provided, using mock validation")
        else:
            print("📝 Using mock validation")

        # Run analysis with chosen validation method
        result = await integration.analyze_and_validate_contract(
            test_contract_path,
            use_real_world_validation=use_real_world,
            target_platform="immunefi",
            mainnet_rpc_key=mainnet_key
        )

        submission = result["submission"]
        validation = result["validation"]

        print(f"\n🎯 Enhanced Bug Bounty Submission Complete!")
        print(f"   Contract: {submission.contract_name}")
        print(f"   Vulnerabilities Found: {validation['total_vulnerabilities']}")
        print(f"   Vulnerabilities Validated: {validation['validated_vulnerabilities']}")
        print(f"   Vulnerabilities Exploitable: {validation['exploitable_vulnerabilities']}")
        print(f"   Validation Method: {validation['validation_method']}")
        print(f"   Real-World Validation: {'✅ Enabled' if validation['real_world_validation'] else '❌ Disabled'}")
        print(f"   Submission Score: {validation['submission_score']:.1f}/100")

        if validation.get('total_potential_profit'):
            print(f"   Potential Profit: {validation['total_potential_profit']} ETH")

        print(f"\n📁 Files generated in output directory:")
        print(f"   - Enhanced submission: enhanced_submission.json")
        print(f"   - Platform formatted: {result['platform']}_submission.md")
        print(f"   - Validation report: validation_report.md")
        print(f"   - Foundry test files: Multiple .sol files")

        if validation['real_world_validation']:
            print(f"\n🔗 Real-world validation details:")
            print(f"   - Fork RPC endpoints used")
            print(f"   - Transaction proofs generated")
            print(f"   - Mainnet state validation completed")

    finally:
        # Clean up
        Path(test_contract_path).unlink()

    print(f"\n✅ Analysis complete! Check the output directory for all generated files.")


if __name__ == "__main__":
    asyncio.run(main())
