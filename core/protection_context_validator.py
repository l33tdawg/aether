#!/usr/bin/env python3
"""
Protection Context Validator

Validates findings against protocol-level protections to determine if
vulnerabilities are actually exploitable.
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum

try:
    from core.protocol_architecture_analyzer import ProtocolArchitecture, SecurityBoundary
    from core.off_chain_component_finder import ObserverComponent, ObserverMapping
    from core.legacy_contract_detector import LegacyStatus
except ImportError:
    # Fallback for missing dependencies
    ProtocolArchitecture = None
    SecurityBoundary = None
    ObserverComponent = None
    ObserverMapping = None
    LegacyStatus = None


class MitigationType(Enum):
    """Types of mitigations."""
    OFF_CHAIN_VALIDATION = "off_chain_validation"
    LEGACY_CONTRACT = "legacy_contract"
    MULTI_COMPONENT_BOUNDARY = "multi_component_boundary"
    USER_ERROR_ONLY = "user_error_only"


@dataclass
class Mitigation:
    """Represents a mitigation that affects vulnerability severity."""
    mitigation_type: MitigationType
    prevents_exploit: bool
    prevents_user_error: bool
    adjusted_severity: Optional[str] = None
    adjusted_confidence: Optional[float] = None
    reasoning: str = ""
    confidence: float = 0.8


@dataclass
class ExploitabilityAssessment:
    """Assessment of whether vulnerability is exploitable."""
    exploitable_as_security_vulnerability: bool
    exploitable_as_user_error: bool
    reasoning: str
    severity_adjustment: Optional[str] = None
    bounty_eligible: bool = True


@dataclass
class ProtectionValidationResult:
    """Result of protection validation."""
    is_mitigated: bool
    mitigation_type: Optional[MitigationType] = None
    adjusted_severity: Optional[str] = None
    adjusted_confidence: Optional[float] = None
    reasoning: str = ""
    confidence: float = 0.0
    mitigations: List[Mitigation] = field(default_factory=list)
    exploitability: Optional[ExploitabilityAssessment] = None


class ProtectionContextValidator:
    """Validates findings against protocol-level protections."""
    
    def validate_finding(
        self,
        vulnerability: Dict[str, Any],
        architecture: Optional[ProtocolArchitecture],
        observers: List[ObserverComponent],
        legacy_status: Optional[LegacyStatus]
    ) -> ProtectionValidationResult:
        """
        Validate if vulnerability is mitigated by protocol protections.
        
        Args:
            vulnerability: Vulnerability finding dictionary
            architecture: Protocol architecture analysis
            observers: List of observer components
            legacy_status: Legacy contract status
            
        Returns:
            ProtectionValidationResult with validation outcome
        """
        mitigations = []
        
        # Check off-chain mitigation
        off_chain_mitigation = self.check_off_chain_mitigation(vulnerability, observers)
        if off_chain_mitigation:
            mitigations.append(off_chain_mitigation)
        
        # Check legacy mitigation
        legacy_mitigation = self.check_legacy_mitigation(vulnerability, legacy_status)
        if legacy_mitigation:
            mitigations.append(legacy_mitigation)
        
        # Check multi-component boundary
        boundary_mitigation = self.check_boundary_mitigation(vulnerability, architecture)
        if boundary_mitigation:
            mitigations.append(boundary_mitigation)
        
        # Assess exploitability
        exploitability = self.assess_exploitability(vulnerability, mitigations)
        
        # Determine if mitigated
        is_mitigated = any(m.prevents_exploit for m in mitigations)
        
        # Determine adjusted severity
        adjusted_severity = self._determine_adjusted_severity(
            vulnerability.get('severity', 'medium'),
            mitigations
        )
        
        # Build reasoning
        reasoning = self._build_reasoning(mitigations, exploitability)
        
        return ProtectionValidationResult(
            is_mitigated=is_mitigated,
            mitigation_type=mitigations[0].mitigation_type if mitigations else None,
            adjusted_severity=adjusted_severity,
            adjusted_confidence=self._calculate_adjusted_confidence(
                vulnerability.get('confidence', 0.5),
                mitigations
            ),
            reasoning=reasoning,
            confidence=max([m.confidence for m in mitigations], default=0.0),
            mitigations=mitigations,
            exploitability=exploitability
        )
    
    def check_off_chain_mitigation(
        self,
        vulnerability: Dict[str, Any],
        observers: List[ObserverComponent]
    ) -> Optional[Mitigation]:
        """
        Check if off-chain observer prevents exploitation.
        
        Args:
            vulnerability: Vulnerability finding
            observers: List of observer components
            
        Returns:
            Mitigation if found, None otherwise
        """
        vuln_type = vulnerability.get('vulnerability_type', '').lower()
        description = vulnerability.get('description', '').lower()
        
        # Check if this is an input validation issue
        input_validation_keywords = [
            'missing input validation', 'missing validation', 'no validation',
            'destinationchainid', 'destinationaddress', 'destinationgaslimit',
            'invalid input', 'unvalidated input'
        ]
        
        if not any(keyword in vuln_type or keyword in description for keyword in input_validation_keywords):
            return None
        
        # Check observers for validation
        for observer in observers:
            # Check if observer validates relevant parameters
            validated_params = observer.validates_parameters
            
            # Common parameters that might be validated
            relevant_params = [
                'destinationChainId', 'chainId', 'destinationChain',
                'destinationAddress', 'destination', 'address',
                'destinationGasLimit', 'gasLimit', 'gas'
            ]
            
            if any(param in validated_params for param in relevant_params):
                # Check if observer has validation functions
                if observer.validation_functions:
                    return Mitigation(
                        mitigation_type=MitigationType.OFF_CHAIN_VALIDATION,
                        prevents_exploit=True,
                        prevents_user_error=False,  # User can still make mistakes
                        adjusted_severity='medium',  # Downgrade from high
                        reasoning=f"Off-chain observer {observer.name} validates parameters before processing. Prevents systemic exploit but user errors still possible.",
                        confidence=0.8
                    )
        
        return None
    
    def check_legacy_mitigation(
        self,
        vulnerability: Dict[str, Any],
        legacy_status: LegacyStatus
    ) -> Optional[Mitigation]:
        """
        Check if vulnerability is in legacy contract.
        
        Args:
            vulnerability: Vulnerability finding
            legacy_status: Legacy contract status
            
        Returns:
            Mitigation if legacy, None otherwise
        """
        if not legacy_status.is_legacy:
            return None
        
        # Legacy contracts are still exploitable, but lower priority
        original_severity = vulnerability.get('severity', 'medium').lower()
        
        # Severity adjustment mapping
        severity_map = {
            'critical': 'high',
            'high': 'medium',
            'medium': 'low',
            'low': 'low'
        }
        
        adjusted_severity = severity_map.get(original_severity, original_severity)
        
        reasoning_parts = ["Contract is marked as legacy/deprecated"]
        if legacy_status.replacement_contracts:
            reasoning_parts.append(f"Replacement: {', '.join(legacy_status.replacement_contracts)}")
        if legacy_status.deprecation_notices:
            reasoning_parts.append(f"Deprecation notices found: {len(legacy_status.deprecation_notices)}")
        
        return Mitigation(
            mitigation_type=MitigationType.LEGACY_CONTRACT,
            prevents_exploit=False,  # Still exploitable
            prevents_user_error=False,
            adjusted_severity=adjusted_severity,
            reasoning="; ".join(reasoning_parts),
            confidence=legacy_status.confidence
        )
    
    def check_boundary_mitigation(
        self,
        vulnerability: Dict[str, Any],
        architecture: ProtocolArchitecture
    ) -> Optional[Mitigation]:
        """
        Check if vulnerability is mitigated by multi-component boundary.
        
        Args:
            vulnerability: Vulnerability finding
            architecture: Protocol architecture
            
        Returns:
            Mitigation if boundary protection found, None otherwise
        """
        # Check if there are security boundaries that might protect this
        for boundary in architecture.security_boundaries:
            if boundary.validation_type == 'input_validation':
                # Check if boundary components include the vulnerable contract
                vuln_contract = vulnerability.get('contract_name', '')
                if vuln_contract in boundary.components:
                    return Mitigation(
                        mitigation_type=MitigationType.MULTI_COMPONENT_BOUNDARY,
                        prevents_exploit=True,  # If boundary is secure
                        prevents_user_error=False,
                        adjusted_severity='medium',
                        reasoning=f"Security boundary at {boundary.boundary_name} validates inputs before processing",
                        confidence=0.7
                    )
        
        return None
    
    def assess_exploitability(
        self,
        vulnerability: Dict[str, Any],
        mitigations: List[Mitigation]
    ) -> ExploitabilityAssessment:
        """
        Assess if vulnerability is actually exploitable.
        
        Args:
            vulnerability: Vulnerability finding
            mitigations: List of mitigations
            
        Returns:
            ExploitabilityAssessment
        """
        # Check if any mitigation prevents exploit
        prevents_exploit = any(m.prevents_exploit for m in mitigations)
        prevents_user_error = any(m.prevents_user_error for m in mitigations)
        
        # Determine severity adjustment
        severity_adjustment = None
        if mitigations:
            adjusted_severities = [m.adjusted_severity for m in mitigations if m.adjusted_severity]
            if adjusted_severities:
                severity_adjustment = adjusted_severities[0]
        
        # Build reasoning
        if prevents_exploit and not prevents_user_error:
            reasoning = "Protocol-level protection prevents systemic exploit, but user errors still possible. This is a user error risk, not a security exploit."
            bounty_eligible = False
        elif prevents_exploit and prevents_user_error:
            reasoning = "Protocol-level protection prevents both exploits and user errors."
            bounty_eligible = False
        elif not prevents_exploit:
            reasoning = "No protocol-level protection found. Vulnerability is exploitable."
            bounty_eligible = True
        else:
            reasoning = "Mitigation status unclear."
            bounty_eligible = True
        
        return ExploitabilityAssessment(
            exploitable_as_security_vulnerability=not prevents_exploit,
            exploitable_as_user_error=not prevents_user_error,
            reasoning=reasoning,
            severity_adjustment=severity_adjustment,
            bounty_eligible=bounty_eligible
        )
    
    def _determine_adjusted_severity(
        self,
        original_severity: str,
        mitigations: List[Mitigation]
    ) -> Optional[str]:
        """Determine adjusted severity based on mitigations."""
        if not mitigations:
            return None
        
        # Get all adjusted severities
        adjusted_severities = [m.adjusted_severity for m in mitigations if m.adjusted_severity]
        
        if not adjusted_severities:
            return None
        
        # Use the most conservative (lowest) severity
        severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        
        original_level = severity_order.get(original_severity.lower(), 2)
        adjusted_levels = [severity_order.get(s.lower(), 2) for s in adjusted_severities]
        
        if adjusted_levels:
            min_adjusted = min(adjusted_levels)
            if min_adjusted < original_level:
                # Find severity name for this level
                reverse_map = {v: k for k, v in severity_order.items()}
                return reverse_map.get(min_adjusted, original_severity)
        
        return None
    
    def _calculate_adjusted_confidence(
        self,
        original_confidence: float,
        mitigations: List[Mitigation]
    ) -> float:
        """Calculate adjusted confidence based on mitigations."""
        if not mitigations:
            return original_confidence
        
        # Average mitigation confidences
        mitigation_confidences = [m.confidence for m in mitigations]
        avg_mitigation_confidence = sum(mitigation_confidences) / len(mitigation_confidences)
        
        # Blend original and mitigation confidence
        return (original_confidence + avg_mitigation_confidence) / 2
    
    def _build_reasoning(
        self,
        mitigations: List[Mitigation],
        exploitability: Optional[ExploitabilityAssessment]
    ) -> str:
        """Build reasoning string from mitigations and exploitability."""
        parts = []
        
        if mitigations:
            parts.append(f"Found {len(mitigations)} mitigation(s):")
            for i, mitigation in enumerate(mitigations, 1):
                parts.append(f"{i}. {mitigation.reasoning}")
        
        if exploitability:
            parts.append(f"Exploitability: {exploitability.reasoning}")
        
        return "\n".join(parts) if parts else "No protocol-level protections detected."

