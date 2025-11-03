"""
State Management Vulnerability Detector

This module detects state management issues in smart contracts, inspired by Move vulnerability patterns:
- Missing state updates after operations
- Inconsistent state tracking (variables not updated in loops)
- Missing state validation checks
- State desynchronization between related data structures
"""

import re
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum


class StateManagementVulnerabilityType(Enum):
    """Types of state management vulnerabilities"""
    MISSING_STATE_UPDATE = "missing_state_update"
    INCONSISTENT_STATE_TRACKING = "inconsistent_state_tracking"
    MISSING_STATE_VALIDATION = "missing_state_validation"
    STATE_DESYNCHRONIZATION = "state_desynchronization"
    UNRESET_STATE = "unreset_state"
    STATE_MUTATION_MISSING = "state_mutation_missing"


@dataclass
class StateManagementVulnerability:
    """Represents a state management vulnerability"""
    vulnerability_type: str
    severity: str
    description: str
    line_number: int
    code_snippet: str
    confidence: float
    swc_id: str
    recommendation: str
    context: Dict[str, Any]


class StateManagementDetector:
    """Detects state management vulnerabilities in smart contracts"""
    
    def __init__(self):
        self.state_update_patterns = self._initialize_state_update_patterns()
        self.state_validation_patterns = self._initialize_state_validation_patterns()
        self.state_sync_patterns = self._initialize_state_sync_patterns()
        self.tracked_state_vars = set()
    
    def _initialize_state_update_patterns(self) -> List[Dict[str, Any]]:
        """Initialize patterns for missing state updates"""
        return [
            {
                'pattern': r'function\s+(\w+)\s*\([^)]*\).*?\{[^}]*transfer\([^}]*\}(?!.*?(\w+\.balance|balances\[))',
                'description': 'Transfer without updating balance state',
                'severity': 'critical',
                'recommendation': 'Update balance state after transfer'
            },
            {
                'pattern': r'delete\s+(\w+\[\w+\])(?!.*?\1\s*=)',
                'description': 'Mapping entry deleted but not reset',
                'severity': 'high',
                'recommendation': 'Reset related state variables after delete'
            },
            {
                'pattern': r'function\s+claim\w*\s*\([^)]*\).*?\{(?!.*?(claimed|hasClaimed)\s*=\s*true)',
                'description': 'Claim function without marking as claimed',
                'severity': 'critical',
                'recommendation': 'Set claimed status to prevent double claiming'
            }
        ]
    
    def _initialize_state_validation_patterns(self) -> List[Dict[str, Any]]:
        """Initialize patterns for missing state validation"""
        return [
            {
                'pattern': r'function\s+\w+\s*\([^)]*\).*?external.*?\{(?!.*?require)',
                'description': 'External function without state validation',
                'severity': 'medium',
                'recommendation': 'Add require statements to validate state'
            },
            {
                'pattern': r'(\w+)\s*=\s*\w+\[(\w+)\](?!.*?require\([^)]*\2)',
                'description': 'Mapping access without existence check',
                'severity': 'high',
                'recommendation': 'Validate mapping entry exists before access'
            },
            {
                'pattern': r'function\s+(withdraw|unstake|redeem)\s*\([^)]*\).*?\{(?!.*?require\([^)]*balance)',
                'description': 'Withdrawal function without balance validation',
                'severity': 'high',
                'recommendation': 'Validate sufficient balance before withdrawal'
            }
        ]
    
    def _initialize_state_sync_patterns(self) -> List[Dict[str, Any]]:
        """Initialize patterns for state desynchronization"""
        return [
            {
                'pattern': r'(\w+)\s*\+=.*?(?!.*?\1Total\s*\+=)',
                'description': 'Individual state updated but total not synced',
                'severity': 'high',
                'recommendation': 'Update total when updating individual values'
            },
            {
                'pattern': r'balanceOf\[(\w+)\]\s*[+\-]=.*?(?!.*?totalSupply\s*[+\-]=)',
                'description': 'Balance updated without updating total supply',
                'severity': 'critical',
                'recommendation': 'Synchronize totalSupply with balance changes'
            }
        ]
    
    def analyze_state_management(self, contract_content: str) -> List[StateManagementVulnerability]:
        """Analyze contract for state management vulnerabilities"""
        vulnerabilities = []
        lines = contract_content.split('\n')
        
        # Identify state variables
        self._identify_state_variables(contract_content)
        
        # Detect missing state updates
        vulnerabilities.extend(self._detect_missing_state_updates(contract_content, lines))
        
        # Detect missing state validation
        vulnerabilities.extend(self._detect_missing_state_validation(contract_content, lines))
        
        # Detect state desynchronization
        vulnerabilities.extend(self._detect_state_desynchronization(contract_content, lines))
        
        # Detect unreset state in loops
        vulnerabilities.extend(self._detect_unreset_loop_state(contract_content, lines))
        
        return vulnerabilities
    
    def _identify_state_variables(self, contract_content: str):
        """Identify state variables in the contract"""
        # Match state variable declarations
        state_var_pattern = r'^\s*(mapping|uint256|address|bool|uint|int|bytes32|string)\s+(public\s+|private\s+|internal\s+)?(\w+)\s*;'
        matches = re.finditer(state_var_pattern, contract_content, re.MULTILINE)
        
        for match in matches:
            var_name = match.group(3)
            self.tracked_state_vars.add(var_name)
    
    def _detect_missing_state_updates(self, contract_content: str, lines: List[str]) -> List[StateManagementVulnerability]:
        """Detect missing state updates"""
        vulnerabilities = []
        
        for pattern_info in self.state_update_patterns:
            pattern = pattern_info['pattern']
            matches = re.finditer(pattern, contract_content, re.MULTILINE | re.DOTALL)
            
            for match in matches:
                line_number = self._get_line_number(match.start(), contract_content)
                code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""
                
                vulnerability = StateManagementVulnerability(
                    vulnerability_type='missing_state_update',
                    severity=pattern_info['severity'],
                    description=pattern_info['description'],
                    line_number=line_number,
                    code_snippet=code_snippet,
                    confidence=0.75,
                    swc_id='SWC-107',
                    recommendation=pattern_info['recommendation'],
                    context={'pattern': pattern, 'function': match.group(1) if len(match.groups()) > 0 else 'unknown'}
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _detect_missing_state_validation(self, contract_content: str, lines: List[str]) -> List[StateManagementVulnerability]:
        """Detect missing state validation"""
        vulnerabilities = []
        
        for pattern_info in self.state_validation_patterns:
            pattern = pattern_info['pattern']
            matches = re.finditer(pattern, contract_content, re.MULTILINE | re.DOTALL)
            
            for match in matches:
                line_number = self._get_line_number(match.start(), contract_content)
                code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""
                
                # Skip view/pure functions for some checks
                if 'view' in code_snippet or 'pure' in code_snippet:
                    continue
                
                vulnerability = StateManagementVulnerability(
                    vulnerability_type='missing_state_validation',
                    severity=pattern_info['severity'],
                    description=pattern_info['description'],
                    line_number=line_number,
                    code_snippet=code_snippet,
                    confidence=0.65,
                    swc_id='SWC-123',
                    recommendation=pattern_info['recommendation'],
                    context={'match': match.group(0)[:100]}
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _detect_state_desynchronization(self, contract_content: str, lines: List[str]) -> List[StateManagementVulnerability]:
        """Detect state desynchronization between related variables"""
        vulnerabilities = []
        
        for pattern_info in self.state_sync_patterns:
            pattern = pattern_info['pattern']
            matches = re.finditer(pattern, contract_content, re.MULTILINE)
            
            for match in matches:
                line_number = self._get_line_number(match.start(), contract_content)
                code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""
                
                vulnerability = StateManagementVulnerability(
                    vulnerability_type='state_desynchronization',
                    severity=pattern_info['severity'],
                    description=pattern_info['description'],
                    line_number=line_number,
                    code_snippet=code_snippet,
                    confidence=0.7,
                    swc_id='SWC-123',
                    recommendation=pattern_info['recommendation'],
                    context={'variable': match.group(1) if len(match.groups()) > 0 else 'unknown'}
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _detect_unreset_loop_state(self, contract_content: str, lines: List[str]) -> List[StateManagementVulnerability]:
        """Detect state variables not reset in loops (Move-inspired)"""
        vulnerabilities = []
        
        # Pattern: for loop with state variable that should be updated
        loop_pattern = r'for\s*\([^)]+\)\s*\{([^}]+)\}'
        matches = re.finditer(loop_pattern, contract_content, re.MULTILINE | re.DOTALL)
        
        for match in matches:
            loop_body = match.group(1)
            line_number = self._get_line_number(match.start(), contract_content)
            
            # Look for variables that are read but never written in loop
            read_vars = set(re.findall(r'\b(\w+)\b(?!\s*[=+\-*/])', loop_body))
            written_vars = set(re.findall(r'\b(\w+)\s*[+\-*/]?=', loop_body))
            
            # Check for accumulation variables that should be updated
            accumulation_keywords = ['amount', 'total', 'sum', 'count', 'requested']
            for var in read_vars:
                if any(keyword in var.lower() for keyword in accumulation_keywords):
                    if var not in written_vars and var in self.tracked_state_vars:
                        code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""
                        
                        vulnerability = StateManagementVulnerability(
                            vulnerability_type='inconsistent_state_tracking',
                            severity='high',
                            description=f'Variable "{var}" read but not updated in loop',
                            line_number=line_number,
                            code_snippet=code_snippet,
                            confidence=0.6,
                            swc_id='SWC-123',
                            recommendation=f'Update {var} in loop to track cumulative changes',
                            context={'variable': var, 'loop_body': loop_body[:100]}
                        )
                        vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _get_line_number(self, position: int, content: str) -> int:
        """Get line number from character position"""
        return content[:position].count('\n') + 1
    
    def get_state_management_summary(self, contract_content: str) -> Dict[str, Any]:
        """Get summary of state management vulnerabilities"""
        vulnerabilities = self.analyze_state_management(contract_content)
        
        summary = {
            'total_vulnerabilities': len(vulnerabilities),
            'state_variables_tracked': len(self.tracked_state_vars),
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

