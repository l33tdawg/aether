#!/usr/bin/env python3
"""
Protocol Protection Detector

Main orchestrator for protocol-level protection detection.
Integrates architecture analysis, off-chain component finding, legacy detection,
and protection validation.
"""

from typing import Dict, List, Optional, Any
from pathlib import Path

from core.protocol_architecture_analyzer import ProtocolArchitectureAnalyzer, ProtocolArchitecture
from core.off_chain_component_finder import OffChainComponentFinder, ObserverComponent
from core.legacy_contract_detector import LegacyContractDetector, LegacyStatus
from core.protection_context_validator import ProtectionContextValidator, ProtectionValidationResult


class ProtocolProtectionDetector:
    """Main orchestrator for protocol-level protection detection."""
    
    def __init__(self, enabled: bool = True):
        """
        Initialize protocol protection detector.
        
        Args:
            enabled: Whether protocol protection detection is enabled
        """
        self.enabled = enabled
        
        if enabled:
            self.architecture_analyzer = ProtocolArchitectureAnalyzer()
            self.off_chain_finder = OffChainComponentFinder()
            self.legacy_detector = LegacyContractDetector()
            self.protection_validator = ProtectionContextValidator()
        else:
            self.architecture_analyzer = None
            self.off_chain_finder = None
            self.legacy_detector = None
            self.protection_validator = None
    
    def analyze_architecture(
        self,
        contract_code: str,
        contract_path: Optional[Path] = None,
        project_root: Optional[Path] = None,
        github_url: Optional[str] = None
    ) -> Optional[ProtocolArchitecture]:
        """
        Analyze protocol architecture.
        
        Args:
            contract_code: Contract source code
            contract_path: Path to contract file
            project_root: Root directory of project
            github_url: Optional GitHub URL
            
        Returns:
            ProtocolArchitecture or None if disabled
        """
        if not self.enabled or not self.architecture_analyzer:
            return None
        
        try:
            return self.architecture_analyzer.analyze_architecture(
                contract_code=contract_code,
                contract_path=contract_path,
                project_root=project_root,
                github_url=github_url
            )
        except Exception:
            # Fail silently to not break existing functionality
            return None
    
    def find_observers(
        self,
        project_root: Optional[Path]
    ) -> List[ObserverComponent]:
        """
        Find off-chain observer components.
        
        Args:
            project_root: Root directory of project
            
        Returns:
            List of ObserverComponent objects
        """
        if not self.enabled or not self.off_chain_finder or not project_root:
            return []
        
        try:
            return self.off_chain_finder.find_observers(project_root)
        except Exception:
            return []
    
    def detect_legacy_status(
        self,
        contract_code: str,
        contract_path: Optional[Path] = None,
        project_root: Optional[Path] = None
    ) -> Optional[LegacyStatus]:
        """
        Detect legacy contract status.
        
        Args:
            contract_code: Contract source code
            contract_path: Path to contract file
            project_root: Root directory of project
            
        Returns:
            LegacyStatus or None if disabled
        """
        if not self.enabled or not self.legacy_detector:
            return None
        
        try:
            return self.legacy_detector.detect_legacy_status(
                contract_code=contract_code,
                contract_path=contract_path,
                project_root=project_root
            )
        except Exception:
            return None
    
    def validate_finding(
        self,
        vulnerability: Dict[str, Any],
        contract_code: str,
        contract_path: Optional[Path] = None,
        project_root: Optional[Path] = None
    ) -> Optional[ProtectionValidationResult]:
        """
        Validate a vulnerability finding against protocol protections.
        
        Args:
            vulnerability: Vulnerability finding dictionary
            contract_code: Contract source code
            contract_path: Path to contract file
            project_root: Root directory of project
            
        Returns:
            ProtectionValidationResult or None if disabled/error
        """
        if not self.enabled:
            return None
        
        try:
            # Analyze architecture
            architecture = self.analyze_architecture(
                contract_code=contract_code,
                contract_path=contract_path,
                project_root=project_root
            )
            
            if not architecture:
                architecture = ProtocolArchitecture()
            
            # Find observers
            observers = self.find_observers(project_root)
            
            # Detect legacy status
            legacy_status = self.detect_legacy_status(
                contract_code=contract_code,
                contract_path=contract_path,
                project_root=project_root
            )
            
            if not legacy_status:
                legacy_status = LegacyStatus(is_legacy=False, confidence=0.0)
            
            # Validate finding
            return self.protection_validator.validate_finding(
                vulnerability=vulnerability,
                architecture=architecture,
                observers=observers,
                legacy_status=legacy_status
            )
        
        except Exception:
            # Fail silently to not break existing functionality
            return None
    
    def filter_vulnerabilities(
        self,
        vulnerabilities: List[Dict[str, Any]],
        contract_code: str,
        contract_path: Optional[Path] = None,
        project_root: Optional[Path] = None
    ) -> List[Dict[str, Any]]:
        """
        Filter vulnerabilities based on protocol protections.
        
        Args:
            vulnerabilities: List of vulnerability findings
            contract_code: Contract source code
            contract_path: Path to contract file
            project_root: Root directory of project
            
        Returns:
            Filtered list of vulnerabilities with adjusted severities
        """
        if not self.enabled:
            return vulnerabilities
        
        filtered = []
        
        for vuln in vulnerabilities:
            # Validate against protocol protections
            validation_result = self.validate_finding(
                vulnerability=vuln,
                contract_code=contract_code,
                contract_path=contract_path,
                project_root=project_root
            )
            
            if validation_result:
                # Adjust vulnerability based on validation
                adjusted_vuln = vuln.copy()
                
                # Update severity if adjusted
                if validation_result.adjusted_severity:
                    adjusted_vuln['original_severity'] = vuln.get('severity', 'medium')
                    adjusted_vuln['severity'] = validation_result.adjusted_severity
                    adjusted_vuln['severity_adjustment_reason'] = validation_result.reasoning
                
                # Update confidence if adjusted
                if validation_result.adjusted_confidence:
                    adjusted_vuln['confidence'] = validation_result.adjusted_confidence
                
                # Add protocol protection context
                adjusted_vuln['protocol_protection'] = {
                    'is_mitigated': validation_result.is_mitigated,
                    'mitigation_type': validation_result.mitigation_type.value if validation_result.mitigation_type else None,
                    'reasoning': validation_result.reasoning,
                    'exploitability': {
                        'security_vulnerability': validation_result.exploitability.exploitable_as_security_vulnerability if validation_result.exploitability else None,
                        'user_error': validation_result.exploitability.exploitable_as_user_error if validation_result.exploitability else None,
                        'bounty_eligible': validation_result.exploitability.bounty_eligible if validation_result.exploitability else None,
                    } if validation_result.exploitability else None
                }
                
                filtered.append(adjusted_vuln)
            else:
                # No protocol protection found, keep original
                filtered.append(vuln)
        
        return filtered

