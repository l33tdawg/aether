#!/usr/bin/env python3
"""
Immunefi Integration for AetherAudit

Provides integration with Immunefi bug bounty programs including:
- Program discovery and analysis
- Bounty estimation
- Submission preparation
- Program-specific vulnerability patterns
- Historical bounty data
"""

import asyncio
import json
import aiohttp
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import re


class ProgramStatus(Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    ENDED = "ended"
    UPCOMING = "upcoming"


class VulnerabilitySeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class ImmunefiProgram:
    """Immunefi program information."""
    name: str
    protocol: str
    status: ProgramStatus
    max_bounty: float
    min_bounty: float
    total_budget: float
    website: str
    description: str
    scope: List[str] = field(default_factory=list)
    out_of_scope: List[str] = field(default_factory=list)
    vulnerability_types: List[str] = field(default_factory=list)
    submission_guidelines: str = ""
    last_updated: datetime = field(default_factory=datetime.now)


@dataclass
class BountyEstimate:
    """Bounty estimate for vulnerability."""
    vulnerability_type: str
    severity: VulnerabilitySeverity
    min_estimate: float
    max_estimate: float
    confidence: float
    program: str
    factors: List[str] = field(default_factory=list)


class ImmunefiIntegration:
    """Immunefi integration for bug bounty programs."""

    def __init__(self):
        self.programs = self._load_immunefi_programs()
        self.historical_bounties = self._load_historical_bounties()
        self.vulnerability_patterns = self._load_vulnerability_patterns()
        
    def _load_immunefi_programs(self) -> Dict[str, ImmunefiProgram]:
        """Load Immunefi program data."""
        return {
            "aave": ImmunefiProgram(
                name="Aave Protocol",
                protocol="Aave",
                status=ProgramStatus.ACTIVE,
                max_bounty=1000000.0,
                min_bounty=10000.0,
                total_budget=5000000.0,
                website="https://immunefi.com/bounty/aave/",
                description="Aave is a decentralized non-custodial liquidity protocol",
                scope=[
                    "Aave V2 and V3 contracts",
                    "AToken, StableDebtToken, VariableDebtToken contracts",
                    "LendingPool, LendingPoolAddressesProvider",
                    "PriceOracle, InterestRateStrategy contracts"
                ],
                out_of_scope=[
                    "Third-party integrations",
                    "Frontend applications",
                    "Mobile applications"
                ],
                vulnerability_types=[
                    "Flash loan attacks",
                    "Oracle manipulation",
                    "Liquidation manipulation",
                    "Interest rate manipulation",
                    "Access control bypass",
                    "Reentrancy attacks"
                ],
                submission_guidelines="Submit detailed PoC with impact assessment"
            ),
            
            "compound": ImmunefiProgram(
                name="Compound Protocol",
                protocol="Compound",
                status=ProgramStatus.ACTIVE,
                max_bounty=500000.0,
                min_bounty=5000.0,
                total_budget=2000000.0,
                website="https://immunefi.com/bounty/compound/",
                description="Compound is an algorithmic money market protocol",
                scope=[
                    "Compound V2 contracts",
                    "CToken contracts",
                    "Comptroller contract",
                    "InterestRateModel contracts",
                    "PriceOracle contracts"
                ],
                out_of_scope=[
                    "Third-party integrations",
                    "Frontend applications",
                    "Mobile applications"
                ],
                vulnerability_types=[
                    "Interest rate manipulation",
                    "Liquidation manipulation",
                    "Oracle manipulation",
                    "Access control bypass",
                    "Reentrancy attacks"
                ],
                submission_guidelines="Submit detailed PoC with impact assessment"
            ),
            
            "uniswap": ImmunefiProgram(
                name="Uniswap Protocol",
                protocol="Uniswap",
                status=ProgramStatus.ACTIVE,
                max_bounty=250000.0,
                min_bounty=10000.0,
                total_budget=1000000.0,
                website="https://immunefi.com/bounty/uniswap/",
                description="Uniswap is a decentralized exchange protocol",
                scope=[
                    "Uniswap V2 contracts",
                    "Uniswap V3 contracts",
                    "Router contracts",
                    "Factory contracts",
                    "Pair contracts"
                ],
                out_of_scope=[
                    "Third-party integrations",
                    "Frontend applications",
                    "Mobile applications"
                ],
                vulnerability_types=[
                    "Price manipulation",
                    "Flash swap attacks",
                    "Liquidity manipulation",
                    "MEV extraction",
                    "Access control bypass"
                ],
                submission_guidelines="Submit detailed PoC with impact assessment"
            ),
            
            "curve": ImmunefiProgram(
                name="Curve Finance",
                protocol="Curve",
                status=ProgramStatus.ACTIVE,
                max_bounty=500000.0,
                min_bounty=10000.0,
                total_budget=2000000.0,
                website="https://immunefi.com/bounty/curve/",
                description="Curve is an automated market maker for stablecoins",
                scope=[
                    "Curve V1 contracts",
                    "Curve V2 contracts",
                    "Pool contracts",
                    "Gauge contracts",
                    "Voting contracts"
                ],
                out_of_scope=[
                    "Third-party integrations",
                    "Frontend applications",
                    "Mobile applications"
                ],
                vulnerability_types=[
                    "Amplification manipulation",
                    "Exchange manipulation",
                    "Liquidity manipulation",
                    "Governance attacks",
                    "Access control bypass"
                ],
                submission_guidelines="Submit detailed PoC with impact assessment"
            ),
            
            "balancer": ImmunefiProgram(
                name="Balancer Protocol",
                protocol="Balancer",
                status=ProgramStatus.ACTIVE,
                max_bounty=250000.0,
                min_bounty=10000.0,
                total_budget=1000000.0,
                website="https://immunefi.com/bounty/balancer/",
                description="Balancer is an automated market maker protocol",
                scope=[
                    "Balancer V1 contracts",
                    "Balancer V2 contracts",
                    "Pool contracts",
                    "Vault contracts",
                    "WeightedPool contracts"
                ],
                out_of_scope=[
                    "Third-party integrations",
                    "Frontend applications",
                    "Mobile applications"
                ],
                vulnerability_types=[
                    "Pool manipulation",
                    "Weight manipulation",
                    "Swap manipulation",
                    "Liquidity manipulation",
                    "Access control bypass"
                ],
                submission_guidelines="Submit detailed PoC with impact assessment"
            ),
            
            "yearn": ImmunefiProgram(
                name="Yearn Finance",
                protocol="Yearn",
                status=ProgramStatus.ACTIVE,
                max_bounty=200000.0,
                min_bounty=5000.0,
                total_budget=500000.0,
                website="https://immunefi.com/bounty/yearn/",
                description="Yearn is a yield farming protocol",
                scope=[
                    "Yearn V2 contracts",
                    "Vault contracts",
                    "Strategy contracts",
                    "Controller contracts",
                    "Governance contracts"
                ],
                out_of_scope=[
                    "Third-party integrations",
                    "Frontend applications",
                    "Mobile applications"
                ],
                vulnerability_types=[
                    "Vault manipulation",
                    "Strategy manipulation",
                    "Harvest manipulation",
                    "Governance attacks",
                    "Access control bypass"
                ],
                submission_guidelines="Submit detailed PoC with impact assessment"
            ),
            
            "makerdao": ImmunefiProgram(
                name="MakerDAO",
                protocol="MakerDAO",
                status=ProgramStatus.ACTIVE,
                max_bounty=1000000.0,
                min_bounty=10000.0,
                total_budget=5000000.0,
                website="https://immunefi.com/bounty/makerdao/",
                description="MakerDAO is a decentralized credit platform",
                scope=[
                    "MakerDAO V2 contracts",
                    "Vault contracts",
                    "Collateral contracts",
                    "Governance contracts",
                    "Oracle contracts"
                ],
                out_of_scope=[
                    "Third-party integrations",
                    "Frontend applications",
                    "Mobile applications"
                ],
                vulnerability_types=[
                    "Governance manipulation",
                    "Collateral manipulation",
                    "Oracle manipulation",
                    "Vault manipulation",
                    "Access control bypass"
                ],
                submission_guidelines="Submit detailed PoC with impact assessment"
            ),
            
            "synthetix": ImmunefiProgram(
                name="Synthetix Protocol",
                protocol="Synthetix",
                status=ProgramStatus.ACTIVE,
                max_bounty=500000.0,
                min_bounty=10000.0,
                total_budget=2000000.0,
                website="https://immunefi.com/bounty/synthetix/",
                description="Synthetix is a synthetic asset protocol",
                scope=[
                    "Synthetix contracts",
                    "Synth contracts",
                    "Exchange contracts",
                    "Oracle contracts",
                    "Governance contracts"
                ],
                out_of_scope=[
                    "Third-party integrations",
                    "Frontend applications",
                    "Mobile applications"
                ],
                vulnerability_types=[
                    "Synthetic asset manipulation",
                    "Exchange manipulation",
                    "Oracle manipulation",
                    "Governance attacks",
                    "Access control bypass"
                ],
                submission_guidelines="Submit detailed PoC with impact assessment"
            )
        }

    def _load_historical_bounties(self) -> Dict[str, List[Dict[str, Any]]]:
        """Load historical bounty data."""
        return {
            "aave": [
                {"vulnerability_type": "Flash loan attack", "severity": "critical", "bounty": 500000, "date": "2023-01-15"},
                {"vulnerability_type": "Oracle manipulation", "severity": "high", "bounty": 100000, "date": "2023-02-20"},
                {"vulnerability_type": "Liquidation manipulation", "severity": "high", "bounty": 75000, "date": "2023-03-10"}
            ],
            "compound": [
                {"vulnerability_type": "Interest rate manipulation", "severity": "high", "bounty": 150000, "date": "2023-01-20"},
                {"vulnerability_type": "Liquidation manipulation", "severity": "medium", "bounty": 50000, "date": "2023-02-15"},
                {"vulnerability_type": "Oracle manipulation", "severity": "high", "bounty": 100000, "date": "2023-03-05"}
            ],
            "uniswap": [
                {"vulnerability_type": "Price manipulation", "severity": "high", "bounty": 200000, "date": "2023-01-25"},
                {"vulnerability_type": "Flash swap attack", "severity": "critical", "bounty": 250000, "date": "2023-02-10"},
                {"vulnerability_type": "Liquidity manipulation", "severity": "medium", "bounty": 75000, "date": "2023-03-15"}
            ],
            "curve": [
                {"vulnerability_type": "Amplification manipulation", "severity": "high", "bounty": 300000, "date": "2023-01-30"},
                {"vulnerability_type": "Exchange manipulation", "severity": "medium", "bounty": 100000, "date": "2023-02-25"},
                {"vulnerability_type": "Governance attack", "severity": "critical", "bounty": 500000, "date": "2023-03-20"}
            ]
        }

    def _load_vulnerability_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Load vulnerability patterns for each program."""
        return {
            "aave": {
                "flash_loan_attack": {
                    "severity": "critical",
                    "min_bounty": 100000,
                    "max_bounty": 1000000,
                    "avg_bounty": 500000,
                    "success_rate": 0.8
                },
                "oracle_manipulation": {
                    "severity": "high",
                    "min_bounty": 50000,
                    "max_bounty": 500000,
                    "avg_bounty": 200000,
                    "success_rate": 0.7
                },
                "liquidation_manipulation": {
                    "severity": "high",
                    "min_bounty": 25000,
                    "max_bounty": 250000,
                    "avg_bounty": 100000,
                    "success_rate": 0.6
                }
            },
            "compound": {
                "interest_rate_manipulation": {
                    "severity": "high",
                    "min_bounty": 50000,
                    "max_bounty": 500000,
                    "avg_bounty": 200000,
                    "success_rate": 0.7
                },
                "liquidation_manipulation": {
                    "severity": "medium",
                    "min_bounty": 25000,
                    "max_bounty": 250000,
                    "avg_bounty": 100000,
                    "success_rate": 0.6
                },
                "oracle_manipulation": {
                    "severity": "high",
                    "min_bounty": 50000,
                    "max_bounty": 500000,
                    "avg_bounty": 200000,
                    "success_rate": 0.7
                }
            },
            "uniswap": {
                "price_manipulation": {
                    "severity": "high",
                    "min_bounty": 50000,
                    "max_bounty": 250000,
                    "avg_bounty": 150000,
                    "success_rate": 0.6
                },
                "flash_swap_attack": {
                    "severity": "critical",
                    "min_bounty": 100000,
                    "max_bounty": 250000,
                    "avg_bounty": 200000,
                    "success_rate": 0.8
                },
                "liquidity_manipulation": {
                    "severity": "medium",
                    "min_bounty": 25000,
                    "max_bounty": 100000,
                    "avg_bounty": 75000,
                    "success_rate": 0.5
                }
            }
        }

    def get_program(self, protocol: str) -> Optional[ImmunefiProgram]:
        """Get Immunefi program by protocol name."""
        return self.programs.get(protocol.lower())

    def get_all_programs(self) -> List[ImmunefiProgram]:
        """Get all Immunefi programs."""
        return list(self.programs.values())

    def get_active_programs(self) -> List[ImmunefiProgram]:
        """Get all active Immunefi programs."""
        return [program for program in self.programs.values() if program.status == ProgramStatus.ACTIVE]

    def estimate_bounty(self, vulnerability_type: str, severity: str, protocol: str) -> BountyEstimate:
        """Estimate bounty for vulnerability."""
        
        # Get program
        program = self.get_program(protocol)
        if not program:
            return BountyEstimate(
                vulnerability_type=vulnerability_type,
                severity=VulnerabilitySeverity(severity),
                min_estimate=0,
                max_estimate=0,
                confidence=0,
                program="Unknown"
            )
        
        # Get vulnerability patterns
        patterns = self.vulnerability_patterns.get(protocol.lower(), {})
        vuln_pattern = patterns.get(vulnerability_type, {})
        
        if not vuln_pattern:
            # Use generic estimation
            return self._estimate_generic_bounty(vulnerability_type, severity, program)
        
        # Calculate estimate based on pattern
        min_estimate = vuln_pattern.get("min_bounty", 0)
        max_estimate = vuln_pattern.get("max_bounty", 0)
        avg_bounty = vuln_pattern.get("avg_bounty", 0)
        success_rate = vuln_pattern.get("success_rate", 0.5)
        
        # Adjust based on severity
        if severity == "critical":
            min_estimate *= 1.5
            max_estimate *= 1.5
        elif severity == "high":
            min_estimate *= 1.2
            max_estimate *= 1.2
        elif severity == "low":
            min_estimate *= 0.5
            max_estimate *= 0.5
        
        # Calculate confidence
        confidence = success_rate * 0.8  # Base confidence on success rate
        
        return BountyEstimate(
            vulnerability_type=vulnerability_type,
            severity=VulnerabilitySeverity(severity),
            min_estimate=min_estimate,
            max_estimate=max_estimate,
            confidence=confidence,
            program=program.name,
            factors=[
                f"Historical success rate: {success_rate:.1%}",
                f"Average bounty: ${avg_bounty:,.0f}",
                f"Program status: {program.status.value}",
                f"Total budget: ${program.total_budget:,.0f}"
            ]
        )

    def _estimate_generic_bounty(self, vulnerability_type: str, severity: str, program: ImmunefiProgram) -> BountyEstimate:
        """Estimate generic bounty for unknown vulnerability type."""
        
        # Base estimates by severity
        base_estimates = {
            "critical": {"min": 100000, "max": 1000000},
            "high": {"min": 25000, "max": 500000},
            "medium": {"min": 5000, "max": 100000},
            "low": {"min": 1000, "max": 25000}
        }
        
        base = base_estimates.get(severity, {"min": 1000, "max": 10000})
        
        # Adjust based on program
        min_estimate = base["min"] * (program.max_bounty / 1000000)  # Scale by program size
        max_estimate = base["max"] * (program.max_bounty / 1000000)
        
        # Cap by program limits
        min_estimate = min(min_estimate, program.min_bounty)
        max_estimate = min(max_estimate, program.max_bounty)
        
        return BountyEstimate(
            vulnerability_type=vulnerability_type,
            severity=VulnerabilitySeverity(severity),
            min_estimate=min_estimate,
            max_estimate=max_estimate,
            confidence=0.5,  # Lower confidence for generic estimates
            program=program.name,
            factors=[
                "Generic estimation (no specific pattern)",
                f"Program max bounty: ${program.max_bounty:,.0f}",
                f"Program status: {program.status.value}"
            ]
        )

    def get_historical_bounties(self, protocol: str) -> List[Dict[str, Any]]:
        """Get historical bounties for protocol."""
        return self.historical_bounties.get(protocol.lower(), [])

    def analyze_vulnerability_for_program(self, vulnerability: Dict[str, Any], protocol: str) -> Dict[str, Any]:
        """Analyze vulnerability for specific Immunefi program."""
        
        program = self.get_program(protocol)
        if not program:
            return {"error": f"Program not found for protocol: {protocol}"}
        
        vuln_type = vulnerability.get("vulnerability_type", "unknown")
        severity = vulnerability.get("severity", "medium")
        
        # Check if vulnerability type is in scope
        in_scope = vuln_type in program.vulnerability_types
        
        # Estimate bounty
        bounty_estimate = self.estimate_bounty(vuln_type, severity, protocol)
        
        # Get historical data
        historical_bounties = self.get_historical_bounties(protocol)
        
        # Calculate success probability
        success_probability = self._calculate_success_probability(vuln_type, severity, protocol)
        
        return {
            "program": {
                "name": program.name,
                "protocol": program.protocol,
                "status": program.status.value,
                "max_bounty": program.max_bounty,
                "min_bounty": program.min_bounty,
                "total_budget": program.total_budget,
                "website": program.website
            },
            "vulnerability_analysis": {
                "type": vuln_type,
                "severity": severity,
                "in_scope": in_scope,
                "success_probability": success_probability
            },
            "bounty_estimate": {
                "min_estimate": bounty_estimate.min_estimate,
                "max_estimate": bounty_estimate.max_estimate,
                "confidence": bounty_estimate.confidence,
                "factors": bounty_estimate.factors
            },
            "historical_data": {
                "total_bounties": len(historical_bounties),
                "avg_bounty": sum(b["bounty"] for b in historical_bounties) / len(historical_bounties) if historical_bounties else 0,
                "max_bounty": max(b["bounty"] for b in historical_bounties) if historical_bounties else 0,
                "recent_bounties": historical_bounties[-5:] if historical_bounties else []
            },
            "recommendations": [
                "Submit detailed PoC with impact assessment",
                "Include gas analysis and attack simulation",
                "Provide clear reproduction steps",
                "Estimate potential financial impact"
            ]
        }

    def _calculate_success_probability(self, vulnerability_type: str, severity: str, protocol: str) -> float:
        """Calculate success probability for vulnerability submission."""
        
        # Base probability by severity
        base_probabilities = {
            "critical": 0.8,
            "high": 0.6,
            "medium": 0.4,
            "low": 0.2
        }
        
        base_prob = base_probabilities.get(severity, 0.3)
        
        # Adjust based on vulnerability type
        patterns = self.vulnerability_patterns.get(protocol.lower(), {})
        vuln_pattern = patterns.get(vulnerability_type, {})
        
        if vuln_pattern:
            success_rate = vuln_pattern.get("success_rate", 0.5)
            return min(0.95, base_prob * success_rate)
        
        return base_prob

    def generate_submission_template(self, vulnerability: Dict[str, Any], protocol: str) -> str:
        """Generate submission template for Immunefi."""
        
        program = self.get_program(protocol)
        if not program:
            return "Program not found"
        
        vuln_type = vulnerability.get("vulnerability_type", "unknown")
        severity = vulnerability.get("severity", "medium")
        description = vulnerability.get("description", "")
        
        template = f"""
# Immunefi Submission Template

## Program Information
- **Program**: {program.name}
- **Protocol**: {program.protocol}
- **Status**: {program.status.value}
- **Max Bounty**: ${program.max_bounty:,.0f}
- **Website**: {program.website}

## Vulnerability Details
- **Type**: {vuln_type}
- **Severity**: {severity}
- **Description**: {description}

## Impact Assessment
- **Financial Impact**: [Estimate potential financial impact]
- **Affected Users**: [Number of users affected]
- **Affected Funds**: [Amount of funds at risk]

## Proof of Concept
- **Attack Vector**: [Detailed attack vector]
- **Exploit Steps**: [Step-by-step exploit process]
- **Code**: [Exploit code]
- **Test Results**: [Test execution results]

## Reproduction Steps
1. [Step 1]
2. [Step 2]
3. [Step 3]

## Recommended Fix
- **Fix Description**: [Detailed fix description]
- **Code Changes**: [Specific code changes needed]
- **Testing**: [Testing recommendations]

## Additional Information
- **Gas Analysis**: [Gas usage analysis]
- **Attack Simulation**: [Foundry test results]
- **Historical Context**: [Similar attacks in the past]

## Contact Information
- **Researcher**: [Your name]
- **Email**: [Your email]
- **Telegram**: [Your telegram handle]
- **Twitter**: [Your twitter handle]
"""
        
        return template

    def get_program_statistics(self) -> Dict[str, Any]:
        """Get statistics for all programs."""
        
        total_programs = len(self.programs)
        active_programs = len(self.get_active_programs())
        total_budget = sum(program.total_budget for program in self.programs.values())
        avg_max_bounty = sum(program.max_bounty for program in self.programs.values()) / total_programs
        
        # Count by protocol
        protocol_counts = {}
        for program in self.programs.values():
            protocol = program.protocol
            protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
        
        # Count by status
        status_counts = {}
        for program in self.programs.values():
            status = program.status.value
            status_counts[status] = status_counts.get(status, 0) + 1
        
        return {
            "total_programs": total_programs,
            "active_programs": active_programs,
            "total_budget": total_budget,
            "avg_max_bounty": avg_max_bounty,
            "protocol_distribution": protocol_counts,
            "status_distribution": status_counts,
            "top_programs": sorted(
                self.programs.values(),
                key=lambda p: p.max_bounty,
                reverse=True
            )[:5]
        }
