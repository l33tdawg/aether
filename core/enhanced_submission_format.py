#!/usr/bin/env python3
"""
Enhanced Bug Bounty Submission Format for Real-World Foundry Verification

This module implements the verified bug bounty submission format outlined in the
real-world Foundry verification plan, providing comprehensive submission structure
with transaction proofs and real-world validation results.
"""

import json
import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from pathlib import Path
import yaml

@dataclass
class VerifiedBugBountySubmission:
    """Complete verified bug bounty submission with real-world validation."""

    # Metadata
    submission_id: str
    timestamp: str
    verification_status: str
    verification_method: str
    submitter_info: Dict[str, str]

    # Vulnerability Information
    contract_name: str
    contract_address: str
    contract_chain: str
    vulnerabilities: List[Dict[str, Any]]

    # Validation Results
    foundry_validation: Dict[str, Any]
    real_world_validation: Dict[str, Any]
    transaction_proofs: List[Dict[str, Any]]

    # Impact Assessment
    financial_impact: float
    security_impact: str
    exploitability_confirmed: bool
    reproducibility_score: float

    # Proof of Concept
    exploit_contracts: List[str]
    exploit_transactions: List[str]
    test_results: List[Dict[str, Any]]

    # Recommendations
    recommended_fixes: List[str]
    testing_required: bool
    additional_notes: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def save_to_file(self, filepath: str) -> None:
        """Save submission to file."""
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)

class SubmissionValidator:
    """Validator for verified bug bounty submissions."""

    def __init__(self):
        self.validation_rules = self._initialize_validation_rules()

    def _initialize_validation_rules(self) -> Dict[str, Any]:
        """Initialize validation rules for submissions."""
        return {
            "required_fields": [
                "submission_id", "contract_name", "vulnerabilities",
                "foundry_validation", "real_world_validation"
            ],
            "vulnerability_requirements": {
                "min_confidence": 0.7,
                "min_severity": "medium",
                "requires_proof": True,
                "requires_impact": True
            },
            "proof_requirements": {
                "requires_transaction_hash": True,
                "requires_profit_calculation": True,
                "requires_state_changes": True,
                "requires_fork_info": True
            },
            "format_requirements": {
                "max_description_length": 2000,
                "requires_code_snippet": True,
                "requires_line_numbers": True
            }
        }

    async def validate_submission(self, submission: VerifiedBugBountySubmission) -> Dict[str, Any]:
        """Validate submission against bug bounty standards."""

        validation_result = {
            "valid": True,
            "errors": [],
            "warnings": [],
            "score": 0.0
        }

        # Check required fields
        for field in self.validation_rules["required_fields"]:
            if not hasattr(submission, field) or getattr(submission, field) is None:
                validation_result["errors"].append(f"Missing required field: {field}")
                validation_result["valid"] = False

        # Validate vulnerabilities
        vuln_validation = self._validate_vulnerabilities(submission.vulnerabilities)
        validation_result["errors"].extend(vuln_validation["errors"])
        validation_result["warnings"].extend(vuln_validation["warnings"])

        # Validate proofs
        proof_validation = self._validate_proofs(submission.transaction_proofs)
        validation_result["errors"].extend(proof_validation["errors"])
        validation_result["warnings"].extend(proof_validation["warnings"])

        # Validate format
        format_validation = self._validate_format(submission)
        validation_result["errors"].extend(format_validation["errors"])
        validation_result["warnings"].extend(format_validation["warnings"])

        # Calculate score
        if validation_result["valid"]:
            validation_result["score"] = self._calculate_submission_score(submission)

        return validation_result

    def _validate_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """Validate vulnerability information."""
        errors = []
        warnings = []

        if not vulnerabilities:
            errors.append("No vulnerabilities provided")
            return {"errors": errors, "warnings": warnings}

        for i, vuln in enumerate(vulnerabilities):
            vuln_errors, vuln_warnings = self._validate_single_vulnerability(vuln, i)
            errors.extend(vuln_errors)
            warnings.extend(vuln_warnings)

        return {"errors": errors, "warnings": warnings}

    def _validate_single_vulnerability(self, vuln: Dict[str, Any], index: int) -> tuple:
        """Validate single vulnerability."""
        errors = []
        warnings = []

        # Check required vulnerability fields
        required_fields = ["vulnerability_type", "severity", "description", "line_number"]
        for field in required_fields:
            value = getattr(vuln, field, None)
            if not value:
                errors.append(f"Vulnerability {index+1}: Missing required field '{field}'")

        # Check confidence threshold
        confidence = getattr(vuln, "confidence", 0)
        if confidence < self.validation_rules["vulnerability_requirements"]["min_confidence"]:
            warnings.append(f"Vulnerability {index+1}: Low confidence score ({confidence})")

        # Check severity
        severity = getattr(vuln, "severity", "").lower()
        valid_severities = ["low", "medium", "high", "critical"]
        if severity not in valid_severities:
            errors.append(f"Vulnerability {index+1}: Invalid severity '{severity}'")

        # Check if proof exists
        if self.validation_rules["vulnerability_requirements"]["requires_proof"]:
            foundry_validation = getattr(vuln, "foundry_validation", {})
            if not foundry_validation or not foundry_validation.get("validated"):
                errors.append(f"Vulnerability {index+1}: No validation proof provided")

        return errors, warnings

    def _validate_proofs(self, proofs: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """Validate transaction proofs."""
        errors = []
        warnings = []

        if not proofs:
            errors.append("No transaction proofs provided")
            return {"errors": errors, "warnings": warnings}

        for i, proof in enumerate(proofs):
            proof_errors, proof_warnings = self._validate_single_proof(proof, i)
            errors.extend(proof_errors)
            warnings.extend(proof_warnings)

        return {"errors": errors, "warnings": warnings}

    def _validate_single_proof(self, proof: Dict[str, Any], index: int) -> tuple:
        """Validate single proof."""
        errors = []
        warnings = []

        # Check required proof fields
        required_fields = ["transaction_hash", "fork_info", "state_changes"]
        for field in required_fields:
            if field not in proof or not proof[field]:
                errors.append(f"Proof {index+1}: Missing required field '{field}'")

        # Validate transaction hash format
        tx_hash = proof.get("transaction_hash", "")
        if tx_hash and not self._is_valid_transaction_hash(tx_hash):
            errors.append(f"Proof {index+1}: Invalid transaction hash format")

        # Validate fork info
        fork_info = proof.get("fork_info", {})
        if not fork_info.get("rpc_url") or not fork_info.get("block_number"):
            errors.append(f"Proof {index+1}: Incomplete fork information")

        return errors, warnings

    def _validate_format(self, submission: VerifiedBugBountySubmission) -> Dict[str, List[str]]:
        """Validate submission format."""
        errors = []
        warnings = []

        # Check description length
        for vuln in submission.vulnerabilities:
            desc = getattr(vuln, "description", "")
            if len(desc) > self.validation_rules["format_requirements"]["max_description_length"]:
                warnings.append(f"Vulnerability description too long ({len(desc)} chars)")

        return {"errors": errors, "warnings": warnings}

    def _is_valid_transaction_hash(self, tx_hash: str) -> bool:
        """Validate transaction hash format."""
        if not tx_hash.startswith("0x"):
            return False
        if len(tx_hash) != 66:  # 0x + 64 hex chars
            return False
        try:
            int(tx_hash, 16)
            return True
        except ValueError:
            return False

    def _calculate_submission_score(self, submission: VerifiedBugBountySubmission) -> float:
        """Calculate overall submission quality score."""
        score = 0.0

        # Base score from vulnerabilities
        vuln_count = len(submission.vulnerabilities)
        if vuln_count > 0:
            avg_confidence = sum(getattr(v, "confidence", 0) for v in submission.vulnerabilities) / vuln_count
            score += avg_confidence * 30  # 30% from confidence

        # Validation score
        validation_rate = submission.foundry_validation.get("validated_vulnerabilities", 0) / max(vuln_count, 1)
        score += validation_rate * 25  # 25% from validation

        # Exploitability score
        exploit_rate = submission.foundry_validation.get("exploitable_vulnerabilities", 0) / max(vuln_count, 1)
        score += exploit_rate * 20  # 20% from exploitability

        # Real-world validation bonus
        if submission.real_world_validation.get("enabled", False):
            score += 15  # 15% bonus for real-world validation

        # Impact score
        if submission.financial_impact > 0:
            impact_score = min(submission.financial_impact / 1000000, 10)  # Cap at 10 points for $1M+
            score += impact_score

        return min(score, 100.0)  # Cap at 100

class SubmissionFormatter:
    """Format submissions for different bug bounty platforms."""

    def __init__(self):
        self.platform_configs = self._initialize_platform_configs()

    def _initialize_platform_configs(self) -> Dict[str, Dict[str, Any]]:
        """Initialize platform-specific formatting configurations."""
        return {
            "immunefi": {
                "title_format": "{contract_name} - {vulnerability_types}",
                "description_template": """
## Summary
{summary}

## Impact
{impact}

## Proof of Concept
{proof_of_concept}

## Tools Used
- Foundry for exploit validation
- Mainnet fork testing
- Real-world transaction verification

## Recommendations
{recommendations}
""",
                "max_title_length": 100,
                "requires_attachments": True
            },
            "hackerone": {
                "title_format": "[{severity}] {contract_name} - {primary_vulnerability}",
                "description_template": """
# Vulnerability Report

## Executive Summary
{summary}

## Technical Details
{technical_details}

## Exploitation
{exploitation_details}

## Impact Assessment
{impact}

## Remediation
{recommendations}

## Attachments
- Foundry test files
- Transaction proofs
- Exploit contracts
""",
                "severity_mapping": {
                    "critical": "critical",
                    "high": "high",
                    "medium": "medium",
                    "low": "low"
                }
            },
            "bugcrowd": {
                "title_format": "{contract_name}: {vulnerability_summary}",
                "description_template": """
## Description
{description}

## Severity
{severity}

## Reproduction Steps
{reproduction}

## Evidence
{evidence}

## Fix Recommendation
{fix_recommendation}
""",
                "requires_cwe": False
            }
        }

    def format_for_platform(self, submission: VerifiedBugBountySubmission, platform: str) -> Dict[str, Any]:
        """Format submission for specific platform."""
        if platform not in self.platform_configs:
            raise ValueError(f"Unsupported platform: {platform}")

        config = self.platform_configs[platform]

        # Generate title
        title = self._generate_title(submission, config["title_format"])

        # Generate description
        description = self._generate_description(submission, config["description_template"])

        # Generate attachments
        attachments = self._generate_attachments(submission)

        return {
            "title": title,
            "description": description,
            "severity": self._get_primary_severity(submission),
            "attachments": attachments,
            "metadata": {
                "platform": platform,
                "submission_id": submission.submission_id,
                "validation_method": submission.verification_method,
                "real_world_validated": submission.real_world_validation.get("enabled", False)
            }
        }

    def _generate_title(self, submission: VerifiedBugBountySubmission, title_format: str) -> str:
        """Generate submission title."""
        # Get primary vulnerability type
        primary_vuln = submission.vulnerabilities[0] if submission.vulnerabilities else None

        # Get unique vulnerability types
        vuln_types = list(set(getattr(v, "vulnerability_type", "Unknown") for v in submission.vulnerabilities))
        vuln_summary = ", ".join(vuln_types[:3])  # Limit to 3 types

        # Format title
        title = title_format.format(
            contract_name=submission.contract_name,
            vulnerability_types=vuln_summary,
            severity=self._get_primary_severity(submission),
            primary_vulnerability=getattr(primary_vuln, "vulnerability_type", "Unknown") if primary_vuln else "Unknown"
        )

        return title[:100]  # Truncate if too long

    def _generate_description(self, submission: VerifiedBugBountySubmission, template: str) -> str:
        """Generate submission description."""

        # Generate summary
        vuln_count = len(submission.vulnerabilities)
        validated_count = submission.foundry_validation.get("validated_vulnerabilities", 0)
        profit = submission.financial_impact

        summary = f"Found {vuln_count} vulnerabilities in {submission.contract_name}, "
        summary += f"with {validated_count} confirmed exploitable using real-world fork testing. "
        summary += f"Potential financial impact: {profit} ETH."

        # Generate impact description
        impact = f"Financial Impact: {profit} ETH\n"
        impact += f"Security Impact: {submission.security_impact}\n"
        impact += f"Exploitability: {'Confirmed' if submission.exploitability_confirmed else 'Theoretical'}"

        # Generate proof of concept section
        poc = ""
        if submission.transaction_proofs:
            poc += f"## Real-World Validation Results\n"
            poc += f"- Fork RPC: {submission.transaction_proofs[0].get('fork_info', {}).get('rpc_url', 'N/A')}\n"
            poc += f"- Transaction Hash: {submission.transaction_proofs[0].get('transaction_hash', 'N/A')}\n"
            poc += f"- Profit Realized: {submission.transaction_proofs[0].get('profit_realized', 0)} ETH\n"
            poc += f"- Gas Used: {submission.transaction_proofs[0].get('gas_used', 0)}\n"

        poc += f"\n## Foundry Test Results\n"
        for vuln in submission.vulnerabilities[:3]:  # Show first 3
            validation = getattr(vuln, "foundry_validation", {})
            poc += f"- {getattr(vuln, 'vulnerability_type', 'Unknown')}: {'✅ Validated' if validation.get('validated') else '❌ Failed'}\n"

        # Generate recommendations
        recommendations = "\n".join(f"- {rec}" for rec in submission.recommended_fixes)

        # Technical details
        technical_details = ""
        for vuln in submission.vulnerabilities:
            technical_details += f"### {getattr(vuln, 'vulnerability_type', 'Unknown')}\n"
            technical_details += f"**Line:** {getattr(vuln, 'line_number', 'N/A')}\n"
            technical_details += f"**Description:** {getattr(vuln, 'description', 'N/A')}\n\n"

        # Exploitation details
        exploitation_details = ""
        for proof in submission.transaction_proofs:
            exploitation_details += f"**Transaction:** {proof.get('transaction_hash', 'N/A')}\n"
            exploitation_details += f"**Profit:** {proof.get('profit_realized', 0)} ETH\n"
            exploitation_details += f"**State Changes:** {len(proof.get('state_changes', []))} modifications\n\n"

        # Format template
        description = template.format(
            summary=summary,
            impact=impact,
            proof_of_concept=poc,
            recommendations=recommendations,
            technical_details=technical_details,
            exploitation_details=exploitation_details,
            description=getattr(submission.vulnerabilities[0], 'description', '') if submission.vulnerabilities else '',
            severity=self._get_primary_severity(submission),
            reproduction="See Foundry test files",
            evidence="Transaction proofs and Foundry validation results",
            fix_recommendation="\n".join(submission.recommended_fixes)
        )

        return description

    def _generate_attachments(self, submission: VerifiedBugBountySubmission) -> List[Dict[str, str]]:
        """Generate list of attachments."""
        attachments = []

        # Add main submission file
        attachments.append({
            "name": "verified_submission.json",
            "type": "application/json",
            "description": "Complete submission with validation results"
        })

        # Add transaction proofs
        if submission.transaction_proofs:
            attachments.append({
                "name": "transaction_proofs.json",
                "type": "application/json",
                "description": "Real-world transaction proofs"
            })

        # Add Foundry test files
        for i, test_file in enumerate(submission.test_results[:5]):  # Limit to 5
            attachments.append({
                "name": f"foundry_test_{i+1}.sol",
                "type": "text/plain",
                "description": f"Foundry test file {i+1}"
            })

        # Add exploit contracts
        for i, exploit_file in enumerate(submission.exploit_contracts[:3]):  # Limit to 3
            attachments.append({
                "name": f"exploit_contract_{i+1}.sol",
                "type": "text/plain",
                "description": f"Exploit contract {i+1}"
            })

        return attachments

    def _get_primary_severity(self, submission: VerifiedBugBountySubmission) -> str:
        """Get primary severity from vulnerabilities."""
        if not submission.vulnerabilities:
            return "medium"

        # Count severities
        severities = {}
        for vuln in submission.vulnerabilities:
            severity = getattr(vuln, "severity", "medium").lower()
            severities[severity] = severities.get(severity, 0) + 1

        # Return most common highest severity
        priority = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        return max(severities.keys(), key=lambda x: priority.get(x, 0))

class SubmissionBuilder:
    """Builder for creating verified bug bounty submissions."""

    def __init__(self):
        self.submission = None
        self.validator = SubmissionValidator()
        self.formatter = SubmissionFormatter()

    def create_submission(
        self,
        contract_name: str,
        contract_address: str,
        vulnerabilities: List[Dict[str, Any]],
        foundry_validation: Dict[str, Any],
        real_world_validation: Dict[str, Any] = None
    ) -> VerifiedBugBountySubmission:
        """Create a new verified submission."""

        # Generate submission ID
        submission_id = str(uuid.uuid4())

        # Calculate financial impact
        financial_impact = self._calculate_financial_impact(foundry_validation, real_world_validation)

        # Generate recommendations
        recommended_fixes = self._generate_recommendations(vulnerabilities)

        # Create submission
        submission = VerifiedBugBountySubmission(
            submission_id=submission_id,
            timestamp=datetime.now().isoformat(),
            verification_status="verified" if real_world_validation else "validated",
            verification_method=real_world_validation.get("method", "foundry_testing") if real_world_validation else "foundry_testing",
            submitter_info={
                "tool": "Enhanced AetherAudit with Real-World Foundry Verification",
                "version": "1.0.0",
                "timestamp": datetime.now().isoformat()
            },
            contract_name=contract_name,
            contract_address=contract_address,
            contract_chain="ethereum",
            vulnerabilities=vulnerabilities,
            foundry_validation=foundry_validation,
            real_world_validation=real_world_validation or {"enabled": False},
            transaction_proofs=real_world_validation.get("transaction_proofs", []) if real_world_validation else [],
            financial_impact=financial_impact,
            security_impact=self._assess_security_impact(vulnerabilities),
            exploitability_confirmed=self._check_exploitability(foundry_validation, real_world_validation),
            reproducibility_score=self._calculate_reproducibility_score(foundry_validation, real_world_validation),
            exploit_contracts=[],  # Would be populated with actual file paths
            exploit_transactions=real_world_validation.get("exploit_transactions", []) if real_world_validation else [],
            test_results=foundry_validation.get("test_results", []),
            recommended_fixes=recommended_fixes,
            testing_required=True,
            additional_notes="This submission includes real-world validation using mainnet forks and transaction proofs."
        )

        self.submission = submission
        return submission

    def _calculate_financial_impact(self, foundry_validation: Dict[str, Any], real_world_validation: Dict[str, Any] = None) -> float:
        """Calculate total financial impact."""
        foundry_profit = foundry_validation.get("total_potential_profit", 0.0)

        if real_world_validation and real_world_validation.get("enabled"):
            real_world_profit = sum(
                proof.get("profit_realized", 0.0)
                for proof in real_world_validation.get("transaction_proofs", [])
            )
            return max(foundry_profit, real_world_profit)  # Use higher estimate

        return foundry_profit

    def _generate_recommendations(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Generate fix recommendations."""
        recommendations = []

        vuln_types = set(getattr(v, "vulnerability_type", "unknown") for v in vulnerabilities)

        if "reentrancy" in vuln_types:
            recommendations.append("Implement ReentrancyGuard or use checks-effects-interactions pattern")
        if "arithmetic_overflow" in vuln_types:
            recommendations.append("Use SafeMath library or Solidity 0.8+ built-in overflow protection")
        if "access_control" in vuln_types:
            recommendations.append("Implement proper access control modifiers and role-based permissions")
        if "oracle_manipulation" in vuln_types:
            recommendations.append("Use decentralized oracles with time-weighted average prices (TWAP)")

        if not recommendations:
            recommendations.append("Conduct thorough security audit and implement defensive programming practices")

        return recommendations

    def _assess_security_impact(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Assess overall security impact."""
        high_severity = sum(1 for v in vulnerabilities if getattr(v, "severity", "").lower() in ["high", "critical"])

        if high_severity >= 2:
            return "Critical - Multiple high-severity vulnerabilities that could lead to complete protocol compromise"
        elif high_severity == 1:
            return "High - Single high-severity vulnerability with significant impact potential"
        else:
            return "Medium - Multiple medium-severity issues that could be chained for exploitation"

    def _check_exploitability(self, foundry_validation: Dict[str, Any], real_world_validation: Dict[str, Any] = None) -> bool:
        """Check if vulnerabilities are confirmed exploitable."""
        exploitable_count = foundry_validation.get("exploitable_vulnerabilities", 0)

        if real_world_validation and real_world_validation.get("enabled"):
            real_world_exploits = sum(
                1 for proof in real_world_validation.get("transaction_proofs", [])
                if proof.get("exploit_executed", False)
            )
            return real_world_exploits > 0

        return exploitable_count > 0

    def _calculate_reproducibility_score(self, foundry_validation: Dict[str, Any], real_world_validation: Dict[str, Any] = None) -> float:
        """Calculate reproducibility score (0-1)."""
        validated_count = foundry_validation.get("validated_vulnerabilities", 0)
        total_count = foundry_validation.get("total_vulnerabilities", 1)

        base_score = validated_count / total_count if total_count > 0 else 0.0

        # Bonus for real-world validation
        if real_world_validation and real_world_validation.get("enabled"):
            real_world_success_rate = sum(
                1 for proof in real_world_validation.get("transaction_proofs", [])
                if proof.get("vulnerability_confirmed", False)
            ) / max(len(real_world_validation.get("transaction_proofs", [])), 1)
            base_score = (base_score + real_world_success_rate) / 2

        return min(base_score, 1.0)

    async def validate_and_format(self, platform: str = "immunefi") -> Dict[str, Any]:
        """Validate submission and format for platform."""
        if not self.submission:
            raise ValueError("No submission created yet")

        # Validate submission
        validation_result = await self.validator.validate_submission(self.submission)

        if not validation_result["valid"]:
            raise ValueError(f"Submission validation failed: {validation_result['errors']}")

        # Format for platform
        formatted_submission = self.formatter.format_for_platform(self.submission, platform)

        return {
            "submission": self.submission,
            "validation": validation_result,
            "formatted": formatted_submission,
            "platform": platform
        }

# Utility functions
def create_enhanced_submission(
    contract_name: str,
    contract_address: str,
    vulnerabilities: List[Dict[str, Any]],
    foundry_validation: Dict[str, Any],
    real_world_validation: Dict[str, Any] = None,
    platform: str = "immunefi"
) -> Dict[str, Any]:
    """Create and validate an enhanced submission."""
    builder = SubmissionBuilder()

    # Create submission
    submission = builder.create_submission(
        contract_name, contract_address, vulnerabilities,
        foundry_validation, real_world_validation
    )

    # Validate and format
    return asyncio.run(builder.validate_and_format(platform))

def load_submission_from_file(filepath: str) -> VerifiedBugBountySubmission:
    """Load submission from JSON file."""
    with open(filepath, 'r') as f:
        data = json.load(f)

    return VerifiedBugBountySubmission(**data)

def save_submission_to_file(submission: VerifiedBugBountySubmission, filepath: str) -> None:
    """Save submission to JSON file."""
    submission.save_to_file(filepath)
