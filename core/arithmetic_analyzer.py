"""
Arithmetic Analysis Engine for Smart Contract Vulnerability Detection

This module provides comprehensive arithmetic vulnerability detection including:
- Integer overflow/underflow detection
- Division by zero detection
- Complex arithmetic expression analysis
- Variable dependency tracking
"""

import re
from typing import List, Dict, Any, Tuple, Optional
from dataclasses import dataclass
from enum import Enum


class VulnerabilityType(Enum):
    """Types of arithmetic vulnerabilities"""
    INTEGER_OVERFLOW = "integer_overflow"
    INTEGER_UNDERFLOW = "integer_underflow"
    DIVISION_BY_ZERO = "division_by_zero"
    ARITHMETIC_OVERFLOW = "arithmetic_overflow"
    ARITHMETIC_UNDERFLOW = "arithmetic_underflow"


@dataclass
class VulnerabilityMatch:
    """Represents a detected vulnerability"""
    vulnerability_type: VulnerabilityType
    severity: str
    description: str
    line_number: int
    code_snippet: str
    confidence: float
    swc_id: str
    recommendation: str


class ArithmeticAnalyzer:
    """Analyzes arithmetic operations for vulnerabilities"""
    
    def __init__(self):
        self.overflow_patterns = self._initialize_overflow_patterns()
        self.underflow_patterns = self._initialize_underflow_patterns()
        self.division_patterns = self._initialize_division_patterns()
        self.arithmetic_operations = ['+', '-', '*', '/', '%', '**']
        
    def _initialize_overflow_patterns(self) -> List[Dict[str, Any]]:
        """Initialize patterns for overflow detection"""
        return [
            {
                'pattern': r'(\w+)\s*\*\s*(\w+)',
                'description': 'Multiplication operation that could overflow',
                'severity': 'high',
                'swc_id': 'SWC-101'
            },
            {
                'pattern': r'(\w+)\s*\+\s*(\w+)',
                'description': 'Addition operation that could overflow',
                'severity': 'medium',
                'swc_id': 'SWC-101'
            },
            {
                'pattern': r'(\w+)\s*\*\*\s*(\w+)',
                'description': 'Exponentiation operation that could overflow',
                'severity': 'high',
                'swc_id': 'SWC-101'
            },
            {
                'pattern': r'(\w+)\s*<<\s*(\w+)',
                'description': 'Left shift operation that could overflow',
                'severity': 'medium',
                'swc_id': 'SWC-101'
            }
        ]
    
    def _initialize_underflow_patterns(self) -> List[Dict[str, Any]]:
        """Initialize patterns for underflow detection"""
        return [
            {
                'pattern': r'(\w+)\s*-\s*(\w+)',
                'description': 'Subtraction operation that could underflow',
                'severity': 'high',
                'swc_id': 'SWC-101'
            },
            {
                'pattern': r'(\w+)\s*>>\s*(\w+)',
                'description': 'Right shift operation that could underflow',
                'severity': 'medium',
                'swc_id': 'SWC-101'
            }
        ]
    
    def _initialize_division_patterns(self) -> List[Dict[str, Any]]:
        """Initialize patterns for division by zero detection"""
        return [
            {
                'pattern': r'(\w+)\s*/\s*(\w+)',
                'description': 'Division operation that could divide by zero',
                'severity': 'high',
                'swc_id': 'SWC-101'
            },
            {
                'pattern': r'(\w+)\s*%\s*(\w+)',
                'description': 'Modulo operation that could divide by zero',
                'severity': 'high',
                'swc_id': 'SWC-101'
            }
        ]
    
    def analyze_arithmetic_operations(self, contract_content: str) -> List[VulnerabilityMatch]:
        """Analyze all arithmetic operations for vulnerabilities"""
        vulnerabilities = []
        
        # Split content into lines for line number tracking
        lines = contract_content.split('\n')
        
        # Detect overflow patterns
        vulnerabilities.extend(self._detect_overflow_vulnerabilities(contract_content, lines))
        
        # Detect underflow patterns  
        vulnerabilities.extend(self._detect_underflow_vulnerabilities(contract_content, lines))
        
        # Detect division by zero
        vulnerabilities.extend(self._detect_division_by_zero(contract_content, lines))
        
        # Detect complex arithmetic expressions
        vulnerabilities.extend(self._detect_complex_arithmetic_expressions(contract_content, lines))
        
        return vulnerabilities
    
    def _detect_overflow_vulnerabilities(self, contract_content: str, lines: List[str]) -> List[VulnerabilityMatch]:
        """Detect overflow vulnerabilities"""
        vulnerabilities = []
        
        for pattern_info in self.overflow_patterns:
            pattern = pattern_info['pattern']
            matches = re.finditer(pattern, contract_content, re.MULTILINE)
            
            for match in matches:
                line_number = self._get_line_number(match.start(), contract_content)
                code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""
                
                # Check if this is a false positive
                if self._is_false_positive_overflow(match, code_snippet):
                    continue
                
                vulnerability = VulnerabilityMatch(
                    vulnerability_type=VulnerabilityType.INTEGER_OVERFLOW,
                    severity=pattern_info['severity'],
                    description=pattern_info['description'],
                    line_number=line_number,
                    code_snippet=code_snippet,
                    confidence=self._calculate_overflow_confidence(match, code_snippet),
                    swc_id=pattern_info['swc_id'],
                    recommendation=self._get_overflow_recommendation()
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _detect_underflow_vulnerabilities(self, contract_content: str, lines: List[str]) -> List[VulnerabilityMatch]:
        """Detect underflow vulnerabilities"""
        vulnerabilities = []
        
        for pattern_info in self.underflow_patterns:
            pattern = pattern_info['pattern']
            matches = re.finditer(pattern, contract_content, re.MULTILINE)
            
            for match in matches:
                line_number = self._get_line_number(match.start(), contract_content)
                code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""
                
                # Check if this is a false positive
                if self._is_false_positive_underflow(match, code_snippet):
                    continue
                
                vulnerability = VulnerabilityMatch(
                    vulnerability_type=VulnerabilityType.INTEGER_UNDERFLOW,
                    severity=pattern_info['severity'],
                    description=pattern_info['description'],
                    line_number=line_number,
                    code_snippet=code_snippet,
                    confidence=self._calculate_underflow_confidence(match, code_snippet),
                    swc_id=pattern_info['swc_id'],
                    recommendation=self._get_underflow_recommendation()
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _detect_division_by_zero(self, contract_content: str, lines: List[str]) -> List[VulnerabilityMatch]:
        """Detect division by zero vulnerabilities"""
        vulnerabilities = []
        
        for pattern_info in self.division_patterns:
            pattern = pattern_info['pattern']
            matches = re.finditer(pattern, contract_content, re.MULTILINE)
            
            for match in matches:
                line_number = self._get_line_number(match.start(), contract_content)
                code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""
                
                # Check if this is a false positive
                if self._is_false_positive_division(match, code_snippet):
                    continue
                
                vulnerability = VulnerabilityMatch(
                    vulnerability_type=VulnerabilityType.DIVISION_BY_ZERO,
                    severity=pattern_info['severity'],
                    description=pattern_info['description'],
                    line_number=line_number,
                    code_snippet=code_snippet,
                    confidence=self._calculate_division_confidence(match, code_snippet),
                    swc_id=pattern_info['swc_id'],
                    recommendation=self._get_division_recommendation()
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _detect_complex_arithmetic_expressions(self, contract_content: str, lines: List[str]) -> List[VulnerabilityMatch]:
        """Detect complex arithmetic expressions that could be vulnerable"""
        vulnerabilities = []
        
        # Pattern for complex expressions like (a - b) * c / d
        complex_pattern = r'\([^)]+\)\s*[\+\-\*\/\%]\s*\([^)]+\)'
        matches = re.finditer(complex_pattern, contract_content, re.MULTILINE)
        
        for match in matches:
            line_number = self._get_line_number(match.start(), contract_content)
            code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""
            
            vulnerability = VulnerabilityMatch(
                vulnerability_type=VulnerabilityType.ARITHMETIC_OVERFLOW,
                severity='medium',
                description='Complex arithmetic expression that could overflow or underflow',
                line_number=line_number,
                code_snippet=code_snippet,
                confidence=0.6,
                swc_id='SWC-101',
                recommendation='Consider using SafeMath library or add explicit bounds checking'
            )
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _get_line_number(self, position: int, content: str) -> int:
        """Get line number from character position"""
        return content[:position].count('\n') + 1
    
    def _is_false_positive_overflow(self, match: re.Match, code_snippet: str) -> bool:
        """Check if overflow detection is a false positive"""
        # Skip if using SafeMath or similar libraries
        if 'SafeMath' in code_snippet or 'safe' in code_snippet.lower():
            return True
        
        # Skip if there are explicit bounds checks
        if 'require(' in code_snippet and ('max' in code_snippet or 'limit' in code_snippet):
            return True
        
        # Skip if using fixed-point arithmetic libraries
        if 'FixedPoint' in code_snippet or 'PRBMath' in code_snippet:
            return True
        
        return False
    
    def _is_false_positive_underflow(self, match: re.Match, code_snippet: str) -> bool:
        """Check if underflow detection is a false positive"""
        # Skip if using SafeMath or similar libraries
        if 'SafeMath' in code_snippet or 'safe' in code_snippet.lower():
            return True
        
        # Skip if there are explicit bounds checks
        if 'require(' in code_snippet and ('min' in code_snippet or 'limit' in code_snippet):
            return True
        
        # Skip if using fixed-point arithmetic libraries
        if 'FixedPoint' in code_snippet or 'PRBMath' in code_snippet:
            return True
        
        return False
    
    def _is_false_positive_division(self, match: re.Match, code_snippet: str) -> bool:
        """Check if division by zero detection is a false positive"""
        # Skip if there's explicit zero check
        if 'require(' in code_snippet and ('!= 0' in code_snippet or '> 0' in code_snippet):
            return True
        
        # Skip if using SafeMath or similar libraries
        if 'SafeMath' in code_snippet or 'safe' in code_snippet.lower():
            return True
        
        # Skip if denominator is a constant non-zero value
        if re.search(r'/\s*\d+', code_snippet) and not re.search(r'/\s*0', code_snippet):
            return True
        
        return False
    
    def _calculate_overflow_confidence(self, match: re.Match, code_snippet: str) -> float:
        """Calculate confidence score for overflow detection"""
        confidence = 0.5  # Base confidence
        
        # Increase confidence if no safety checks
        if 'require(' not in code_snippet and 'assert(' not in code_snippet:
            confidence += 0.2
        
        # Increase confidence if using user input
        if 'msg.sender' in code_snippet or 'tx.origin' in code_snippet:
            confidence += 0.2
        
        # Increase confidence if in external/public function
        if 'external' in code_snippet or 'public' in code_snippet:
            confidence += 0.1
        
        return min(confidence, 1.0)
    
    def _calculate_underflow_confidence(self, match: re.Match, code_snippet: str) -> float:
        """Calculate confidence score for underflow detection"""
        confidence = 0.5  # Base confidence
        
        # Increase confidence if no safety checks
        if 'require(' not in code_snippet and 'assert(' not in code_snippet:
            confidence += 0.2
        
        # Increase confidence if using user input
        if 'msg.sender' in code_snippet or 'tx.origin' in code_snippet:
            confidence += 0.2
        
        # Increase confidence if in external/public function
        if 'external' in code_snippet or 'public' in code_snippet:
            confidence += 0.1
        
        return min(confidence, 1.0)
    
    def _calculate_division_confidence(self, match: re.Match, code_snippet: str) -> float:
        """Calculate confidence score for division by zero detection"""
        confidence = 0.6  # Base confidence
        
        # Increase confidence if no zero checks
        if '!= 0' not in code_snippet and '> 0' not in code_snippet:
            confidence += 0.3
        
        # Increase confidence if using user input
        if 'msg.sender' in code_snippet or 'tx.origin' in code_snippet:
            confidence += 0.1
        
        return min(confidence, 1.0)
    
    def _get_overflow_recommendation(self) -> str:
        """Get recommendation for overflow vulnerabilities"""
        return "Use SafeMath library or add explicit bounds checking before arithmetic operations"
    
    def _get_underflow_recommendation(self) -> str:
        """Get recommendation for underflow vulnerabilities"""
        return "Use SafeMath library or add explicit bounds checking before arithmetic operations"
    
    def _get_division_recommendation(self) -> str:
        """Get recommendation for division by zero vulnerabilities"""
        return "Add explicit zero check before division operations: require(denominator != 0)"
