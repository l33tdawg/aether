"""
Centralization Risk Detector

This module detects centralization risks in smart contracts, inspired by Move vulnerability patterns:
- Single admin with excessive permissions
- Unlimited minting/burning capabilities
- No multisig requirement for privileged operations
- Lack of timelock for critical parameter changes
"""

import re
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum


class CentralizationRiskType(Enum):
    """Types of centralization risks"""
    EXCESSIVE_ADMIN_PERMISSIONS = "excessive_admin_permissions"
    UNLIMITED_MINTING = "unlimited_minting"
    UNLIMITED_BURNING = "unlimited_burning"
    NO_MULTISIG = "no_multisig"
    NO_TIMELOCK = "no_timelock"
    SINGLE_POINT_OF_FAILURE = "single_point_of_failure"
    PRIVILEGED_WITHDRAWAL = "privileged_withdrawal"


@dataclass
class CentralizationVulnerability:
    """Represents a centralization risk"""
    vulnerability_type: str
    severity: str
    description: str
    line_number: int
    code_snippet: str
    confidence: float
    swc_id: str
    recommendation: str
    context: Dict[str, Any]


class CentralizationDetector:
    """Detects centralization risks in smart contracts"""
    
    def __init__(self):
        self.admin_patterns = self._initialize_admin_patterns()
        self.minting_patterns = self._initialize_minting_patterns()
        self.burning_patterns = self._initialize_burning_patterns()
        self.multisig_patterns = self._initialize_multisig_patterns()
        self.privileged_functions = set()
    
    def _initialize_admin_patterns(self) -> List[Dict[str, Any]]:
        """Initialize patterns for excessive admin permissions"""
        return [
            {
                'pattern': r'modifier\s+onlyOwner\s*\(\s*\).*?_;',
                'description': 'onlyOwner modifier used - check for excessive permissions',
                'severity': 'medium',
                'recommendation': 'Consider multi-signature or timelock for critical operations'
            },
            {
                'pattern': r'function\s+(\w+)\s*\([^)]*\).*?onlyOwner',
                'description': 'Owner-only function - review if appropriate',
                'severity': 'low',
                'recommendation': 'Ensure owner permissions are necessary and well-documented'
            },
            {
                'pattern': r'(owner|admin)\s*=\s*msg\.sender',
                'description': 'Single address assigned as owner/admin',
                'severity': 'medium',
                'recommendation': 'Consider using multi-signature wallet for admin role'
            }
        ]
    
    def _initialize_minting_patterns(self) -> List[Dict[str, Any]]:
        """Initialize patterns for unlimited minting"""
        return [
            {
                'pattern': r'function\s+mint\s*\([^)]*\).*?onlyOwner(?!.*?require\([^)]*amount\s*<=)',
                'description': 'Unlimited minting capability',
                'severity': 'high',
                'recommendation': 'Add minting cap or rate limiting'
            },
            {
                'pattern': r'_mint\s*\([^)]*\)(?!.*?totalSupply.*?maxSupply)',
                'description': 'Minting without supply cap check',
                'severity': 'high',
                'recommendation': 'Enforce maximum supply limit'
            },
            {
                'pattern': r'function\s+mint\w*\s*\([^)]*uint256\s+amount[^)]*\)(?!.*?mintingLimit)',
                'description': 'Arbitrary amount minting without limit',
                'severity': 'high',
                'recommendation': 'Implement minting limit per transaction or time period'
            }
        ]
    
    def _initialize_burning_patterns(self) -> List[Dict[str, Any]]:
        """Initialize patterns for unlimited burning"""
        return [
            {
                'pattern': r'function\s+burn\w*\s*\([^)]*address\s+from[^)]*\).*?onlyOwner',
                'description': 'Admin can burn tokens from any address',
                'severity': 'critical',
                'recommendation': 'Remove ability to burn from arbitrary addresses or require approval'
            },
            {
                'pattern': r'_burn\s*\(\s*(\w+)\s*,(?!.*?require\([^)]*balanceOf)',
                'description': 'Burning without balance check',
                'severity': 'medium',
                'recommendation': 'Verify balance before burning'
            }
        ]
    
    def _initialize_multisig_patterns(self) -> List[Dict[str, Any]]:
        """Initialize patterns for missing multisig"""
        return [
            {
                'pattern': r'function\s+(pause|unpause|setFee|setRate|upgradeProxy)\s*\([^)]*\).*?onlyOwner',
                'description': 'Critical function without multisig requirement',
                'severity': 'high',
                'recommendation': 'Require multiple signatures for critical operations'
            },
            {
                'pattern': r'function\s+transferOwnership\s*\([^)]*\)',
                'description': 'Ownership transfer without timelock',
                'severity': 'medium',
                'recommendation': 'Add timelock to ownership transfers'
            }
        ]
    
    def analyze_centralization_risks(self, contract_content: str) -> List[CentralizationVulnerability]:
        """Analyze contract for centralization risks"""
        vulnerabilities = []
        lines = contract_content.split('\n')
        
        # Identify privileged functions
        self._identify_privileged_functions(contract_content)
        
        # Detect admin permission risks
        vulnerabilities.extend(self._detect_admin_risks(contract_content, lines))
        
        # Detect unlimited minting
        vulnerabilities.extend(self._detect_minting_risks(contract_content, lines))
        
        # Detect unlimited burning
        vulnerabilities.extend(self._detect_burning_risks(contract_content, lines))
        
        # Detect missing multisig
        vulnerabilities.extend(self._detect_multisig_risks(contract_content, lines))
        
        # Detect single point of failure
        vulnerabilities.extend(self._detect_single_point_failure(contract_content, lines))
        
        return vulnerabilities
    
    def _identify_privileged_functions(self, contract_content: str):
        """Identify functions with privileged access modifiers"""
        privilege_modifiers = ['onlyOwner', 'onlyAdmin', 'onlyGovernance', 'onlyRole']
        
        for modifier in privilege_modifiers:
            pattern = f'function\\s+(\\w+)\\s*\\([^)]*\\).*?{modifier}'
            matches = re.finditer(pattern, contract_content, re.MULTILINE | re.DOTALL)
            for match in matches:
                func_name = match.group(1)
                self.privileged_functions.add(func_name)
    
    def _detect_admin_risks(self, contract_content: str, lines: List[str]) -> List[CentralizationVulnerability]:
        """Detect excessive admin permissions"""
        vulnerabilities = []
        
        for pattern_info in self.admin_patterns:
            pattern = pattern_info['pattern']
            matches = re.finditer(pattern, contract_content, re.MULTILINE | re.DOTALL)
            
            for match in matches:
                line_number = self._get_line_number(match.start(), contract_content)
                code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""
                
                vulnerability = CentralizationVulnerability(
                    vulnerability_type='excessive_admin_permissions',
                    severity=pattern_info['severity'],
                    description=pattern_info['description'],
                    line_number=line_number,
                    code_snippet=code_snippet,
                    confidence=0.7,
                    swc_id='SWC-105',
                    recommendation=pattern_info['recommendation'],
                    context={'function': match.group(1) if len(match.groups()) > 0 else 'unknown'}
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _detect_minting_risks(self, contract_content: str, lines: List[str]) -> List[CentralizationVulnerability]:
        """Detect unlimited minting capabilities"""
        vulnerabilities = []
        
        for pattern_info in self.minting_patterns:
            pattern = pattern_info['pattern']
            matches = re.finditer(pattern, contract_content, re.MULTILINE | re.DOTALL)
            
            for match in matches:
                line_number = self._get_line_number(match.start(), contract_content)
                code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""
                
                vulnerability = CentralizationVulnerability(
                    vulnerability_type='unlimited_minting',
                    severity=pattern_info['severity'],
                    description=pattern_info['description'],
                    line_number=line_number,
                    code_snippet=code_snippet,
                    confidence=0.75,
                    swc_id='SWC-105',
                    recommendation=pattern_info['recommendation'],
                    context={'match': match.group(0)[:100]}
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _detect_burning_risks(self, contract_content: str, lines: List[str]) -> List[CentralizationVulnerability]:
        """Detect unlimited burning capabilities"""
        vulnerabilities = []
        
        for pattern_info in self.burning_patterns:
            pattern = pattern_info['pattern']
            matches = re.finditer(pattern, contract_content, re.MULTILINE | re.DOTALL)
            
            for match in matches:
                line_number = self._get_line_number(match.start(), contract_content)
                code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""
                
                vulnerability = CentralizationVulnerability(
                    vulnerability_type='unlimited_burning',
                    severity=pattern_info['severity'],
                    description=pattern_info['description'],
                    line_number=line_number,
                    code_snippet=code_snippet,
                    confidence=0.8,
                    swc_id='SWC-105',
                    recommendation=pattern_info['recommendation'],
                    context={'match': match.group(0)[:100]}
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _detect_multisig_risks(self, contract_content: str, lines: List[str]) -> List[CentralizationVulnerability]:
        """Detect missing multisig requirements"""
        vulnerabilities = []
        
        for pattern_info in self.multisig_patterns:
            pattern = pattern_info['pattern']
            matches = re.finditer(pattern, contract_content, re.MULTILINE | re.DOTALL)
            
            for match in matches:
                line_number = self._get_line_number(match.start(), contract_content)
                code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""
                
                vulnerability = CentralizationVulnerability(
                    vulnerability_type='no_multisig',
                    severity=pattern_info['severity'],
                    description=pattern_info['description'],
                    line_number=line_number,
                    code_snippet=code_snippet,
                    confidence=0.7,
                    swc_id='SWC-105',
                    recommendation=pattern_info['recommendation'],
                    context={'function': match.group(1) if len(match.groups()) > 0 else 'unknown'}
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _detect_single_point_failure(self, contract_content: str, lines: List[str]) -> List[CentralizationVulnerability]:
        """Detect single points of failure"""
        vulnerabilities = []
        
        # Count privileged functions
        if len(self.privileged_functions) > 5:
            # Many privileged functions suggests centralization risk
            vulnerability = CentralizationVulnerability(
                vulnerability_type='single_point_of_failure',
                severity='high',
                description=f'Contract has {len(self.privileged_functions)} privileged functions - high centralization risk',
                line_number=1,
                code_snippet='Multiple privileged functions detected',
                confidence=0.8,
                swc_id='SWC-105',
                recommendation='Consider decentralizing critical functions or using multi-signature',
                context={'privileged_function_count': len(self.privileged_functions), 'functions': list(self.privileged_functions)}
            )
            vulnerabilities.append(vulnerability)
        
        # Check for withdrawal functions with owner access
        withdrawal_pattern = r'function\s+(withdraw\w*|extractFees|claimFees)\s*\([^)]*\).*?onlyOwner'
        matches = re.finditer(withdrawal_pattern, contract_content, re.MULTILINE | re.DOTALL)
        
        for match in matches:
            line_number = self._get_line_number(match.start(), contract_content)
            code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""
            
            vulnerability = CentralizationVulnerability(
                vulnerability_type='privileged_withdrawal',
                severity='high',
                description='Owner can withdraw funds - centralization risk',
                line_number=line_number,
                code_snippet=code_snippet,
                confidence=0.85,
                swc_id='SWC-105',
                recommendation='Implement multi-signature or DAO governance for fund withdrawal',
                context={'function': match.group(1)}
            )
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _get_line_number(self, position: int, content: str) -> int:
        """Get line number from character position"""
        return content[:position].count('\n') + 1
    
    def get_centralization_summary(self, contract_content: str) -> Dict[str, Any]:
        """Get summary of centralization risks"""
        vulnerabilities = self.analyze_centralization_risks(contract_content)
        
        summary = {
            'total_vulnerabilities': len(vulnerabilities),
            'privileged_functions_count': len(self.privileged_functions),
            'privileged_functions': list(self.privileged_functions),
            'by_type': {},
            'by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        }
        
        for vuln in vulnerabilities:
            # Count by type
            vuln_type = vuln.vulnerability_type
            summary['by_type'][vuln_type] = summary['by_type'].get(vuln_type, 0) + 1
            
            # Count by severity
            severity = vuln.severity.lower()
            if severity in summary['by_severity']:
                summary['by_severity'][severity] += 1
        
        return summary

