"""
Data Inconsistency Vulnerability Detector

This module detects data inconsistency issues in smart contracts, inspired by Move vulnerability patterns:
- Loop variables not updated (e.g., requested_amount not decremented)
- Inconsistent variable tracking in iterations
- Missing data synchronization between structures
- Sorting/ordering requirement violations
"""

import re
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum


class DataInconsistencyVulnerabilityType(Enum):
    """Types of data inconsistency vulnerabilities"""
    LOOP_VARIABLE_NOT_UPDATED = "loop_variable_not_updated"
    INCONSISTENT_ITERATION_TRACKING = "inconsistent_iteration_tracking"
    MISSING_DATA_SYNC = "missing_data_sync"
    SORTING_VIOLATION = "sorting_violation"
    ARRAY_LENGTH_MISMATCH = "array_length_mismatch"
    ACCUMULATOR_NOT_UPDATED = "accumulator_not_updated"


@dataclass
class DataInconsistencyVulnerability:
    """Represents a data inconsistency vulnerability"""
    vulnerability_type: str
    severity: str
    description: str
    line_number: int
    code_snippet: str
    confidence: float
    swc_id: str
    recommendation: str
    context: Dict[str, Any]


class DataInconsistencyDetector:
    """Detects data inconsistency vulnerabilities in smart contracts"""
    
    def __init__(self):
        self.loop_variable_patterns = self._initialize_loop_variable_patterns()
        self.sync_patterns = self._initialize_sync_patterns()
        self.sorting_patterns = self._initialize_sorting_patterns()
    
    def _initialize_loop_variable_patterns(self) -> List[Dict[str, Any]]:
        """Initialize patterns for loop variable issues"""
        return [
            {
                'pattern': r'for\s*\([^)]+\)\s*\{[^}]*(\w*amount\w*)[^}]*\}(?!.*?\1\s*[-+]=)',
                'description': 'Amount variable in loop never updated',
                'severity': 'high',
                'recommendation': 'Update amount variable in loop to track remaining'
            },
            {
                'pattern': r'while\s*\([^)]*(\w+)\s*>\s*0[^)]*\)[^}]*\{(?!.*?\1\s*[-]=)',
                'description': 'While loop condition variable never decremented',
                'severity': 'critical',
                'recommendation': 'Decrement loop variable to prevent infinite loop'
            },
            {
                'pattern': r'for\s*\([^)]+\)\s*\{[^}]*withdraw[^}]*\}(?!.*?remaining\s*[-]=)',
                'description': 'Withdrawal loop without tracking remaining amount',
                'severity': 'high',
                'recommendation': 'Track remaining amount to prevent over-withdrawal'
            }
        ]
    
    def _initialize_sync_patterns(self) -> List[Dict[str, Any]]:
        """Initialize patterns for data synchronization issues"""
        return [
            {
                'pattern': r'(\w+)\[(\w+)\]\s*=.*?(?!.*?\1Total\s*[+\-]=)',
                'description': 'Array/mapping updated without syncing total',
                'severity': 'high',
                'recommendation': 'Synchronize total when updating individual elements'
            },
            {
                'pattern': r'push\s*\([^)]+\)(?!.*?\.length)',
                'description': 'Array push without tracking length separately',
                'severity': 'medium',
                'recommendation': 'Track array length if used for calculations'
            },
            {
                'pattern': r'delete\s+(\w+)\[(?!.*?count\s*-=)',
                'description': 'Delete from array/mapping without updating count',
                'severity': 'medium',
                'recommendation': 'Update count when deleting elements'
            }
        ]
    
    def _initialize_sorting_patterns(self) -> List[Dict[str, Any]]:
        """Initialize patterns for sorting/ordering violations"""
        return [
            {
                'pattern': r'function\s+sort\w*\s*\([^)]*\).*?\{(?!.*?(if|require)\s*\([^)]*<[^)]*\))',
                'description': 'Sort function without comparison logic',
                'severity': 'high',
                'recommendation': 'Implement proper comparison in sort function'
            },
            {
                'pattern': r'(\w+)\s*=\s*(\w+)\s*<\s*\2',
                'description': 'Comparison uses same variable on both sides',
                'severity': 'critical',
                'recommendation': 'Fix comparison - using same variable on both sides'
            }
        ]
    
    def analyze_data_inconsistency(self, contract_content: str) -> List[DataInconsistencyVulnerability]:
        """Analyze contract for data inconsistency vulnerabilities"""
        vulnerabilities = []
        lines = contract_content.split('\n')
        
        # Detect loop variable issues
        vulnerabilities.extend(self._detect_loop_variable_issues(contract_content, lines))
        
        # Detect data synchronization issues
        vulnerabilities.extend(self._detect_sync_issues(contract_content, lines))
        
        # Detect sorting violations
        vulnerabilities.extend(self._detect_sorting_violations(contract_content, lines))
        
        # Detect accumulator issues
        vulnerabilities.extend(self._detect_accumulator_issues(contract_content, lines))
        
        # Detect array length mismatches
        vulnerabilities.extend(self._detect_array_length_mismatches(contract_content, lines))
        
        return vulnerabilities
    
    def _detect_loop_variable_issues(self, contract_content: str, lines: List[str]) -> List[DataInconsistencyVulnerability]:
        """Detect loop variables that are not updated"""
        vulnerabilities = []
        
        for pattern_info in self.loop_variable_patterns:
            pattern = pattern_info['pattern']
            matches = re.finditer(pattern, contract_content, re.MULTILINE | re.DOTALL)
            
            for match in matches:
                line_number = self._get_line_number(match.start(), contract_content)
                code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""
                
                vulnerability = DataInconsistencyVulnerability(
                    vulnerability_type='loop_variable_not_updated',
                    severity=pattern_info['severity'],
                    description=pattern_info['description'],
                    line_number=line_number,
                    code_snippet=code_snippet,
                    confidence=0.75,
                    swc_id='SWC-123',
                    recommendation=pattern_info['recommendation'],
                    context={'variable': match.group(1) if len(match.groups()) > 0 else 'unknown'}
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _detect_sync_issues(self, contract_content: str, lines: List[str]) -> List[DataInconsistencyVulnerability]:
        """Detect data synchronization issues"""
        vulnerabilities = []
        
        for pattern_info in self.sync_patterns:
            pattern = pattern_info['pattern']
            matches = re.finditer(pattern, contract_content, re.MULTILINE | re.DOTALL)
            
            for match in matches:
                line_number = self._get_line_number(match.start(), contract_content)
                code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""
                
                vulnerability = DataInconsistencyVulnerability(
                    vulnerability_type='missing_data_sync',
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
    
    def _detect_sorting_violations(self, contract_content: str, lines: List[str]) -> List[DataInconsistencyVulnerability]:
        """Detect sorting/ordering requirement violations"""
        vulnerabilities = []
        
        for pattern_info in self.sorting_patterns:
            pattern = pattern_info['pattern']
            matches = re.finditer(pattern, contract_content, re.MULTILINE | re.DOTALL)
            
            for match in matches:
                line_number = self._get_line_number(match.start(), contract_content)
                code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""
                
                vulnerability = DataInconsistencyVulnerability(
                    vulnerability_type='sorting_violation',
                    severity=pattern_info['severity'],
                    description=pattern_info['description'],
                    line_number=line_number,
                    code_snippet=code_snippet,
                    confidence=0.8,
                    swc_id='SWC-123',
                    recommendation=pattern_info['recommendation'],
                    context={'match': match.group(0)[:100]}
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _detect_accumulator_issues(self, contract_content: str, lines: List[str]) -> List[DataInconsistencyVulnerability]:
        """Detect accumulator variables not properly updated"""
        vulnerabilities = []
        
        # Pattern: loop with accumulator-like variable that's never updated
        loop_pattern = r'for\s*\([^)]+\)\s*\{([^}]+)\}'
        matches = re.finditer(loop_pattern, contract_content, re.MULTILINE | re.DOTALL)
        
        accumulator_keywords = ['total', 'sum', 'count', 'accumulated', 'collected']
        
        for match in matches:
            loop_body = match.group(1)
            line_number = self._get_line_number(match.start(), contract_content)
            
            # Find potential accumulator variables (mentioned but not updated)
            for keyword in accumulator_keywords:
                # Check if keyword appears in loop body
                if keyword in loop_body.lower():
                    # Check if it's being updated (+=, -=, =)
                    update_pattern = f'{keyword}\\s*[+\\-*\\/]?='
                    if not re.search(update_pattern, loop_body, re.IGNORECASE):
                        code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""
                        
                        vulnerability = DataInconsistencyVulnerability(
                            vulnerability_type='accumulator_not_updated',
                            severity='medium',
                            description=f'Accumulator variable "{keyword}" mentioned but not updated in loop',
                            line_number=line_number,
                            code_snippet=code_snippet,
                            confidence=0.6,
                            swc_id='SWC-123',
                            recommendation=f'Update {keyword} in loop if it should track cumulative value',
                            context={'keyword': keyword, 'loop_body': loop_body[:100]}
                        )
                        vulnerabilities.append(vulnerability)
                        break  # Only report once per loop
        
        return vulnerabilities
    
    def _detect_array_length_mismatches(self, contract_content: str, lines: List[str]) -> List[DataInconsistencyVulnerability]:
        """Detect array length mismatches in multi-array operations"""
        vulnerabilities = []
        
        # Pattern: function taking multiple arrays without length checks
        multi_array_pattern = r'function\s+\w+\s*\(([^)]*\[\][^)]*\[\][^)]*)\)(?!.*?require\([^)]*\.length\s*==)'
        matches = re.finditer(multi_array_pattern, contract_content, re.MULTILINE)
        
        for match in matches:
            line_number = self._get_line_number(match.start(), contract_content)
            code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""
            
            # Count how many array parameters
            array_count = match.group(1).count('[]')
            if array_count >= 2:
                vulnerability = DataInconsistencyVulnerability(
                    vulnerability_type='array_length_mismatch',
                    severity='medium',
                    description=f'Function with {array_count} arrays without length validation',
                    line_number=line_number,
                    code_snippet=code_snippet,
                    confidence=0.7,
                    swc_id='SWC-120',
                    recommendation='Add require statement to ensure array lengths match',
                    context={'array_count': array_count}
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _get_line_number(self, position: int, content: str) -> int:
        """Get line number from character position"""
        return content[:position].count('\n') + 1
    
    def get_data_inconsistency_summary(self, contract_content: str) -> Dict[str, Any]:
        """Get summary of data inconsistency vulnerabilities"""
        vulnerabilities = self.analyze_data_inconsistency(contract_content)
        
        summary = {
            'total_vulnerabilities': len(vulnerabilities),
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

