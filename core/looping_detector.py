"""
Looping Issues Detector

This module detects looping issues in smart contracts, inspired by Move vulnerability patterns:
- Infinite loop risks (e.g., zero seed causing infinite loops)
- Loop variable update issues
- Loop termination problems
- Unbounded loop gas consumption
"""

import re
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum


class LoopingVulnerabilityType(Enum):
    """Types of looping vulnerabilities"""
    INFINITE_LOOP_RISK = "infinite_loop_risk"
    LOOP_VARIABLE_NOT_UPDATED = "loop_variable_not_updated"
    TERMINATION_CONDITION_ERROR = "termination_condition_error"
    UNBOUNDED_LOOP = "unbounded_loop"
    ZERO_SEED_LOOP = "zero_seed_loop"
    NESTED_UNBOUNDED_LOOPS = "nested_unbounded_loops"


@dataclass
class LoopingVulnerability:
    """Represents a looping vulnerability"""
    vulnerability_type: str
    severity: str
    description: str
    line_number: int
    code_snippet: str
    confidence: float
    swc_id: str
    recommendation: str
    context: Dict[str, Any]


class LoopingDetector:
    """Detects looping vulnerabilities in smart contracts"""
    
    def __init__(self):
        self.infinite_loop_patterns = self._initialize_infinite_loop_patterns()
        self.termination_patterns = self._initialize_termination_patterns()
        self.unbounded_patterns = self._initialize_unbounded_patterns()
    
    def _initialize_infinite_loop_patterns(self) -> List[Dict[str, Any]]:
        """Initialize patterns for infinite loop risks"""
        return [
            {
                'pattern': r'while\s*\(\s*true\s*\)',
                'description': 'Infinite while loop without break condition',
                'severity': 'critical',
                'recommendation': 'Add proper termination condition or break statement'
            },
            {
                'pattern': r'while\s*\([^)]*\)\s*\{(?!.*?break)',
                'description': 'While loop without break statement',
                'severity': 'medium',
                'recommendation': 'Add break condition to prevent infinite loop'
            },
            {
                'pattern': r'for\s*\(\s*;\s*;\s*\)',
                'description': 'Infinite for loop without conditions',
                'severity': 'critical',
                'recommendation': 'Add proper loop conditions'
            }
        ]
    
    def _initialize_termination_patterns(self) -> List[Dict[str, Any]]:
        """Initialize patterns for loop termination issues"""
        return [
            {
                'pattern': r'while\s*\(\s*(\w+)\s*>\s*0\s*\)[^}]*\{(?!.*?\1\s*[-]=)',
                'description': 'While loop condition variable never decremented',
                'severity': 'critical',
                'recommendation': 'Decrement loop variable to ensure termination'
            },
            {
                'pattern': r'while\s*\(\s*(\w+)\s*<\s*\w+\s*\)[^}]*\{(?!.*?\1\s*[+]=)',
                'description': 'While loop condition variable never incremented',
                'severity': 'critical',
                'recommendation': 'Increment loop variable to ensure termination'
            },
            {
                'pattern': r'for\s*\([^;]*;[^;]*;[^)]*\)\s*\{[^}]*continue[^}]*\}(?!.*?i\+\+)',
                'description': 'For loop with continue but no increment',
                'severity': 'high',
                'recommendation': 'Ensure loop variable increments even with continue'
            }
        ]
    
    def _initialize_unbounded_patterns(self) -> List[Dict[str, Any]]:
        """Initialize patterns for unbounded loops"""
        return [
            {
                'pattern': r'for\s*\([^)]*\.length[^)]*\)(?!.*?require\([^)]*length\s*<=)',
                'description': 'Unbounded loop over array without length check',
                'severity': 'medium',
                'recommendation': 'Add maximum length check to prevent gas exhaustion'
            },
            {
                'pattern': r'while\s*\([^)]*\.length[^)]*\)',
                'description': 'While loop based on array length',
                'severity': 'medium',
                'recommendation': 'Use for loop with bounded length'
            }
        ]
    
    def analyze_looping_issues(self, contract_content: str) -> List[LoopingVulnerability]:
        """Analyze contract for looping vulnerabilities"""
        vulnerabilities = []
        lines = contract_content.split('\n')
        
        # Detect infinite loop risks
        vulnerabilities.extend(self._detect_infinite_loops(contract_content, lines))
        
        # Detect termination condition errors
        vulnerabilities.extend(self._detect_termination_errors(contract_content, lines))
        
        # Detect unbounded loops
        vulnerabilities.extend(self._detect_unbounded_loops(contract_content, lines))
        
        # Detect zero seed loops (Move-inspired)
        vulnerabilities.extend(self._detect_zero_seed_loops(contract_content, lines))
        
        # Detect nested unbounded loops
        vulnerabilities.extend(self._detect_nested_unbounded_loops(contract_content, lines))
        
        return vulnerabilities
    
    def _detect_infinite_loops(self, contract_content: str, lines: List[str]) -> List[LoopingVulnerability]:
        """Detect infinite loop risks"""
        vulnerabilities = []
        
        for pattern_info in self.infinite_loop_patterns:
            pattern = pattern_info['pattern']
            matches = re.finditer(pattern, contract_content, re.MULTILINE | re.DOTALL)
            
            for match in matches:
                line_number = self._get_line_number(match.start(), contract_content)
                code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""
                
                vulnerability = LoopingVulnerability(
                    vulnerability_type='infinite_loop_risk',
                    severity=pattern_info['severity'],
                    description=pattern_info['description'],
                    line_number=line_number,
                    code_snippet=code_snippet,
                    confidence=0.85,
                    swc_id='SWC-128',
                    recommendation=pattern_info['recommendation'],
                    context={'match': match.group(0)[:100]}
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _detect_termination_errors(self, contract_content: str, lines: List[str]) -> List[LoopingVulnerability]:
        """Detect loop termination condition errors"""
        vulnerabilities = []
        
        for pattern_info in self.termination_patterns:
            pattern = pattern_info['pattern']
            matches = re.finditer(pattern, contract_content, re.MULTILINE | re.DOTALL)
            
            for match in matches:
                line_number = self._get_line_number(match.start(), contract_content)
                code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""
                
                vulnerability = LoopingVulnerability(
                    vulnerability_type='termination_condition_error',
                    severity=pattern_info['severity'],
                    description=pattern_info['description'],
                    line_number=line_number,
                    code_snippet=code_snippet,
                    confidence=0.8,
                    swc_id='SWC-128',
                    recommendation=pattern_info['recommendation'],
                    context={'variable': match.group(1) if len(match.groups()) > 0 else 'unknown'}
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _detect_unbounded_loops(self, contract_content: str, lines: List[str]) -> List[LoopingVulnerability]:
        """Detect unbounded loops that could cause gas exhaustion"""
        vulnerabilities = []
        
        for pattern_info in self.unbounded_patterns:
            pattern = pattern_info['pattern']
            matches = re.finditer(pattern, contract_content, re.MULTILINE | re.DOTALL)
            
            for match in matches:
                line_number = self._get_line_number(match.start(), contract_content)
                code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""
                
                vulnerability = LoopingVulnerability(
                    vulnerability_type='unbounded_loop',
                    severity=pattern_info['severity'],
                    description=pattern_info['description'],
                    line_number=line_number,
                    code_snippet=code_snippet,
                    confidence=0.7,
                    swc_id='SWC-128',
                    recommendation=pattern_info['recommendation'],
                    context={'match': match.group(0)[:100]}
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _detect_zero_seed_loops(self, contract_content: str, lines: List[str]) -> List[LoopingVulnerability]:
        """Detect zero seed causing infinite loops (Move-inspired)"""
        vulnerabilities = []
        
        # Pattern: random/seed function with potential zero value causing infinite loop
        zero_seed_pattern = r'(\w+)\s*=\s*(\w*[Rr]andom\w*)\s*\([^)]*0[^)]*\)'
        matches = re.finditer(zero_seed_pattern, contract_content, re.MULTILINE)
        
        for match in matches:
            # Check if this seed is used in a loop
            seed_var = match.group(1)
            line_number = self._get_line_number(match.start(), contract_content)
            
            # Look for usage in subsequent loops
            loop_pattern = f'(while|for)\\s*\\([^)]*{seed_var}[^)]*\\)'
            if re.search(loop_pattern, contract_content[match.end():]):
                code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""
                
                vulnerability = LoopingVulnerability(
                    vulnerability_type='zero_seed_loop',
                    severity='high',
                    description=f'Zero seed for random function may cause infinite loop',
                    line_number=line_number,
                    code_snippet=code_snippet,
                    confidence=0.75,
                    swc_id='SWC-128',
                    recommendation='Add check to prevent zero seed in random functions',
                    context={'seed_variable': seed_var}
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _detect_nested_unbounded_loops(self, contract_content: str, lines: List[str]) -> List[LoopingVulnerability]:
        """Detect nested unbounded loops (high gas risk)"""
        vulnerabilities = []
        
        # Pattern: nested for loops over arrays
        nested_loop_pattern = r'for\s*\([^)]*\.length[^)]*\)\s*\{[^}]*for\s*\([^)]*\.length'
        matches = re.finditer(nested_loop_pattern, contract_content, re.MULTILINE | re.DOTALL)
        
        for match in matches:
            line_number = self._get_line_number(match.start(), contract_content)
            code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""
            
            # Check if there's a length bound
            has_bound = bool(re.search(r'require\([^)]*length\s*<=\s*\d+', contract_content[:match.start()]))
            
            if not has_bound:
                vulnerability = LoopingVulnerability(
                    vulnerability_type='nested_unbounded_loops',
                    severity='high',
                    description='Nested unbounded loops - high gas consumption risk',
                    line_number=line_number,
                    code_snippet=code_snippet,
                    confidence=0.85,
                    swc_id='SWC-128',
                    recommendation='Add maximum array length checks or avoid nested unbounded loops',
                    context={'match': match.group(0)[:100]}
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _get_line_number(self, position: int, content: str) -> int:
        """Get line number from character position"""
        return content[:position].count('\n') + 1
    
    def get_looping_summary(self, contract_content: str) -> Dict[str, Any]:
        """Get summary of looping vulnerabilities"""
        vulnerabilities = self.analyze_looping_issues(contract_content)
        
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

