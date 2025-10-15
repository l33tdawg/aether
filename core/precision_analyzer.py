"""
Precision Analyzer for Smart Contract Security

This module detects precision loss in mathematical operations, analyzes rounding
errors and their impact, and identifies incorrect precision handling.
"""

import re
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum


class PrecisionIssue(Enum):
    """Types of precision issues"""
    PRECISION_LOSS = "precision_loss"
    ROUNDING_ERROR = "rounding_error"
    INCORRECT_PRECISION = "incorrect_precision"
    DIVISION_PRECISION = "division_precision"
    MULTIPLICATION_PRECISION = "multiplication_precision"


class PrecisionRisk(Enum):
    """Risk levels for precision issues"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class PrecisionOperation:
    """Represents a precision-sensitive operation"""
    operation_type: str
    line_number: int
    code_snippet: str
    operands: List[str]
    result_type: str
    has_precision_handling: bool
    precision_constant: Optional[str]
    risk_level: PrecisionRisk
    confidence: float


@dataclass
class PrecisionVulnerability:
    """Represents a precision-related vulnerability"""
    vulnerability_type: str
    severity: str
    description: str
    line_number: int
    code_snippet: str
    confidence: float
    swc_id: str
    recommendation: str
    operation_type: str
    precision_impact: str


class PrecisionAnalyzer:
    """Analyzes precision loss in mathematical operations"""
    
    def __init__(self):
        self.precision_patterns = self._initialize_precision_patterns()
        self.rounding_patterns = self._initialize_rounding_patterns()
        self.division_patterns = self._initialize_division_patterns()
        self.precision_constants = self._initialize_precision_constants()
        self.risky_operations = self._initialize_risky_operations()
        
    def _initialize_precision_patterns(self) -> List[Dict[str, Any]]:
        """Initialize patterns for precision analysis"""
        return [
            {
                'pattern': r'(\w+)\s*/\s*(\w+)',
                'description': 'Division operation that could cause precision loss',
                'type': PrecisionIssue.DIVISION_PRECISION,
                'risk_level': PrecisionRisk.MEDIUM
            },
            {
                'pattern': r'(\w+)\s*\*\s*(\w+)\s*/\s*(\w+)',
                'description': 'Multiplication followed by division - potential precision loss',
                'type': PrecisionIssue.MULTIPLICATION_PRECISION,
                'risk_level': PrecisionRisk.HIGH
            },
            {
                'pattern': r'(\w+)\s*%\s*(\w+)',
                'description': 'Modulo operation that could cause precision issues',
                'type': PrecisionIssue.PRECISION_LOSS,
                'risk_level': PrecisionRisk.MEDIUM
            },
            {
                'pattern': r'(\w+)\s*\*\s*(\d+)\s*/\s*(\d+)',
                'description': 'Fixed-point arithmetic with potential precision loss',
                'type': PrecisionIssue.INCORRECT_PRECISION,
                'risk_level': PrecisionRisk.HIGH
            }
        ]
    
    def _initialize_rounding_patterns(self) -> List[Dict[str, Any]]:
        """Initialize patterns for rounding analysis"""
        return [
            {
                'pattern': r'(\w+)\s*/\s*(\w+)\s*\*\s*(\w+)',
                'description': 'Division followed by multiplication - potential rounding error',
                'type': PrecisionIssue.ROUNDING_ERROR,
                'risk_level': PrecisionRisk.MEDIUM
            },
            {
                'pattern': r'(\w+)\s*\+\s*(\w+)\s*/\s*(\w+)',
                'description': 'Addition with division - potential rounding error',
                'type': PrecisionIssue.ROUNDING_ERROR,
                'risk_level': PrecisionRisk.MEDIUM
            },
            {
                'pattern': r'(\w+)\s*-\s*(\w+)\s*/\s*(\w+)',
                'description': 'Subtraction with division - potential rounding error',
                'type': PrecisionIssue.ROUNDING_ERROR,
                'risk_level': PrecisionRisk.MEDIUM
            }
        ]
    
    def _initialize_division_patterns(self) -> List[Dict[str, Any]]:
        """Initialize patterns for division analysis"""
        return [
            {
                'pattern': r'(\w+)\s*/\s*(\w+)\s*\+\s*(\w+)\s*/\s*(\w+)',
                'description': 'Multiple divisions that could cause precision loss',
                'type': PrecisionIssue.DIVISION_PRECISION,
                'risk_level': PrecisionRisk.HIGH
            },
            {
                'pattern': r'(\w+)\s*/\s*(\w+)\s*-\s*(\w+)\s*/\s*(\w+)',
                'description': 'Multiple divisions with subtraction - potential precision loss',
                'type': PrecisionIssue.DIVISION_PRECISION,
                'risk_level': PrecisionRisk.HIGH
            },
            {
                'pattern': r'(\w+)\s*/\s*(\w+)\s*\*\s*(\w+)\s*/\s*(\w+)',
                'description': 'Complex division chain - high precision loss risk',
                'type': PrecisionIssue.DIVISION_PRECISION,
                'risk_level': PrecisionRisk.CRITICAL
            }
        ]
    
    def _initialize_precision_constants(self) -> Set[str]:
        """Initialize list of precision constants"""
        return {
            '1e18', '1e6', '1e8', '1000000000000000000', '1000000', '100000000',
            'WAD', 'RAY', 'DECIMALS', 'PRECISION', 'SCALE', 'MULTIPLIER'
        }
    
    def _initialize_risky_operations(self) -> Set[str]:
        """Initialize list of risky operations for precision"""
        return {
            'division', 'modulo', 'multiplication', 'exponentiation',
            'sqrt', 'pow', 'log', 'exp'
        }
    
    def analyze_precision_loss(self, contract_content: str) -> List[PrecisionVulnerability]:
        """Analyze precision loss in mathematical operations"""
        vulnerabilities = []
        
        # Split content into lines for line number tracking
        lines = contract_content.split('\n')
        
        # Detect precision loss in divisions
        vulnerabilities.extend(self._detect_precision_loss_divisions(contract_content, lines))
        
        # Detect rounding errors
        vulnerabilities.extend(self._detect_rounding_errors(contract_content, lines))
        
        # Detect incorrect precision handling
        vulnerabilities.extend(self._detect_incorrect_precision_handling(contract_content, lines))
        
        # Detect complex arithmetic expressions
        vulnerabilities.extend(self._detect_complex_arithmetic_precision(contract_content, lines))
        
        return vulnerabilities
    
    def _detect_precision_loss_divisions(self, contract_content: str, lines: List[str]) -> List[PrecisionVulnerability]:
        """Detect precision loss in division operations"""
        vulnerabilities = []
        
        # Simple division pattern for testing
        simple_division_pattern = r'(\w+)\s*/\s*(\w+)'
        matches = re.finditer(simple_division_pattern, contract_content, re.MULTILINE)
        
        for match in matches:
            line_number = self._get_line_number(match.start(), contract_content)
            code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""
            
            # Check if this is a false positive
            if self._is_false_positive_precision(match, code_snippet):
                continue
            
            # Check if there's precision handling
            has_precision_handling = self._has_precision_handling(contract_content, line_number)
            
            if not has_precision_handling:
                vulnerability = PrecisionVulnerability(
                    vulnerability_type='precision_loss_division',
                    severity='medium',
                    description='Division operation that could cause precision loss',
                    line_number=line_number,
                    code_snippet=code_snippet,
                    confidence=self._calculate_precision_confidence(match, code_snippet),
                    swc_id='SWC-101',
                    recommendation='Use fixed-point arithmetic or add precision handling',
                    operation_type='division',
                    precision_impact='high'
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _detect_rounding_errors(self, contract_content: str, lines: List[str]) -> List[PrecisionVulnerability]:
        """Detect rounding errors in mathematical operations"""
        vulnerabilities = []
        
        # Simple rounding pattern for testing
        simple_rounding_pattern = r'(\w+)\s*/\s*(\w+)\s*\*\s*(\w+)'
        matches = re.finditer(simple_rounding_pattern, contract_content, re.MULTILINE)
        
        for match in matches:
            line_number = self._get_line_number(match.start(), contract_content)
            code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""
            
            # Check if this is a false positive
            if self._is_false_positive_rounding(match, code_snippet):
                continue
            
            # Check if there's rounding handling
            has_rounding_handling = self._has_rounding_handling(contract_content, line_number)
            
            if not has_rounding_handling:
                vulnerability = PrecisionVulnerability(
                    vulnerability_type='rounding_error',
                    severity='medium',
                    description='Division followed by multiplication - potential rounding error',
                    line_number=line_number,
                    code_snippet=code_snippet,
                    confidence=self._calculate_rounding_confidence(match, code_snippet),
                    swc_id='SWC-101',
                    recommendation='Add proper rounding handling or use fixed-point arithmetic',
                    operation_type='rounding',
                    precision_impact='medium'
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _detect_incorrect_precision_handling(self, contract_content: str, lines: List[str]) -> List[PrecisionVulnerability]:
        """Detect incorrect precision handling"""
        vulnerabilities = []
        
        for pattern_info in self.precision_patterns:
            pattern = pattern_info['pattern']
            matches = re.finditer(pattern, contract_content, re.MULTILINE)
            
            for match in matches:
                line_number = self._get_line_number(match.start(), contract_content)
                code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""
                
                # Check if this is a false positive
                if self._is_false_positive_incorrect(match, code_snippet):
                    continue
                
                # Check if precision constants are used incorrectly
                if self._has_incorrect_precision_constant(code_snippet):
                    vulnerability = PrecisionVulnerability(
                        vulnerability_type='incorrect_precision_handling',
                        severity=pattern_info['risk_level'].value,
                        description='Incorrect precision constant usage',
                        line_number=line_number,
                        code_snippet=code_snippet,
                        confidence=0.8,
                        swc_id='SWC-101',
                        recommendation='Use correct precision constants or fixed-point arithmetic',
                        operation_type='precision_constant',
                        precision_impact='high'
                    )
                    vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _detect_complex_arithmetic_precision(self, contract_content: str, lines: List[str]) -> List[PrecisionVulnerability]:
        """Detect precision issues in complex arithmetic expressions"""
        vulnerabilities = []
        
        # Pattern for complex expressions with multiple operations
        complex_pattern = r'\([^)]+\)\s*[\+\-\*\/\%]\s*\([^)]+\)'
        matches = re.finditer(complex_pattern, contract_content, re.MULTILINE)
        
        for match in matches:
            line_number = self._get_line_number(match.start(), contract_content)
            code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""
            
            # Check if expression contains precision-sensitive operations
            if self._contains_precision_sensitive_operations(code_snippet):
                vulnerability = PrecisionVulnerability(
                    vulnerability_type='complex_arithmetic_precision',
                    severity='medium',
                    description='Complex arithmetic expression with potential precision loss',
                    line_number=line_number,
                    code_snippet=code_snippet,
                    confidence=0.6,
                    swc_id='SWC-101',
                    recommendation='Break down complex expressions and add precision handling',
                    operation_type='complex_arithmetic',
                    precision_impact='medium'
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _is_false_positive_precision(self, match: re.Match, code_snippet: str) -> bool:
        """Check if precision detection is a false positive"""
        # Skip if using fixed-point arithmetic libraries
        if any(lib in code_snippet for lib in ['FixedPoint', 'PRBMath', 'ABDKMath', 'SafeMath']):
            return True
        
        # Skip if there's explicit precision handling
        if any(constant in code_snippet for constant in self.precision_constants):
            return True
        
        # Skip if using WAD or RAY constants
        if 'WAD' in code_snippet or 'RAY' in code_snippet:
            return True
        
        return False
    
    def _is_false_positive_rounding(self, match: re.Match, code_snippet: str) -> bool:
        """Check if rounding detection is a false positive"""
        # Skip if using fixed-point arithmetic libraries
        if any(lib in code_snippet for lib in ['FixedPoint', 'PRBMath', 'ABDKMath', 'SafeMath']):
            return True
        
        # Skip if there's explicit rounding handling (but not in type names)
        if ('round(' in code_snippet.lower() or 'ceil(' in code_snippet.lower() or 'floor(' in code_snippet.lower()):
            return True
        
        return False
    
    def _is_false_positive_incorrect(self, match: re.Match, code_snippet: str) -> bool:
        """Check if incorrect precision detection is a false positive"""
        # Skip if using fixed-point arithmetic libraries
        if any(lib in code_snippet for lib in ['FixedPoint', 'PRBMath', 'ABDKMath', 'SafeMath']):
            return True
        
        # Skip if precision constants are used correctly
        if self._has_correct_precision_constant(code_snippet):
            return True
        
        return False
    
    def _has_precision_handling(self, contract_content: str, line_number: int) -> bool:
        """Check if there's precision handling nearby"""
        lines = contract_content.split('\n')
        
        # Check lines before and after
        start_line = max(0, line_number - 5)
        end_line = min(len(lines), line_number + 5)
        
        for i in range(start_line, end_line):
            if i < len(lines):
                line = lines[i]
                # Check for precision handling patterns
                if any(constant in line for constant in self.precision_constants):
                    return True
                if any(lib in line for lib in ['FixedPoint', 'PRBMath', 'ABDKMath']):
                    return True
        
        return False
    
    def _has_rounding_handling(self, contract_content: str, line_number: int) -> bool:
        """Check if there's rounding handling nearby"""
        lines = contract_content.split('\n')
        
        # Check lines before and after
        start_line = max(0, line_number - 5)
        end_line = min(len(lines), line_number + 5)
        
        for i in range(start_line, end_line):
            if i < len(lines):
                line = lines[i]
                # Check for rounding handling patterns (function calls only)
                if any(func in line.lower() for func in ['round(', 'ceil(', 'floor(', 'truncate(']):
                    return True
        
        return False
    
    def _has_incorrect_precision_constant(self, code_snippet: str) -> bool:
        """Check if precision constants are used incorrectly"""
        # Check for common precision mistakes
        incorrect_patterns = [
            r'1e18\s*/\s*1e6',  # Mixing different precision scales
            r'1e6\s*\*\s*1e18',  # Incorrect precision multiplication
            r'WAD\s*/\s*RAY',     # Mixing WAD and RAY
            r'RAY\s*\*\s*WAD'    # Mixing RAY and WAD
        ]
        
        for pattern in incorrect_patterns:
            if re.search(pattern, code_snippet):
                return True
        
        return False
    
    def _has_correct_precision_constant(self, code_snippet: str) -> bool:
        """Check if precision constants are used correctly"""
        # Check for correct precision usage
        correct_patterns = [
            r'1e18\s*\*\s*(\w+)\s*/\s*1e18',  # Correct WAD usage
            r'1e6\s*\*\s*(\w+)\s*/\s*1e6',    # Correct 6-decimal usage
            r'WAD\s*\*\s*(\w+)\s*/\s*WAD',   # Correct WAD usage
            r'RAY\s*\*\s*(\w+)\s*/\s*RAY'    # Correct RAY usage
        ]
        
        for pattern in correct_patterns:
            if re.search(pattern, code_snippet):
                return True
        
        return False
    
    def _contains_precision_sensitive_operations(self, code_snippet: str) -> bool:
        """Check if code snippet contains precision-sensitive operations"""
        precision_sensitive = ['/', '%', '*', '**', 'pow', 'sqrt']
        return any(op in code_snippet for op in precision_sensitive)
    
    def _calculate_precision_confidence(self, match: re.Match, code_snippet: str) -> float:
        """Calculate confidence score for precision detection"""
        confidence = 0.5  # Base confidence
        
        # Increase confidence if no precision handling
        if not self._has_precision_handling(code_snippet, 0):
            confidence += 0.3
        
        # Increase confidence for division operations
        if '/' in code_snippet:
            confidence += 0.2
        
        # Increase confidence for complex expressions
        if code_snippet.count('(') > 1:
            confidence += 0.1
        
        return min(confidence, 1.0)
    
    def _calculate_rounding_confidence(self, match: re.Match, code_snippet: str) -> float:
        """Calculate confidence score for rounding detection"""
        confidence = 0.4  # Base confidence
        
        # Increase confidence if no rounding handling
        if not self._has_rounding_handling(code_snippet, 0):
            confidence += 0.3
        
        # Increase confidence for multiple operations
        operation_count = sum(1 for op in ['+', '-', '*', '/'] if op in code_snippet)
        confidence += min(operation_count * 0.1, 0.3)
        
        return min(confidence, 1.0)
    
    def _get_line_number(self, position: int, content: str) -> int:
        """Get line number from character position"""
        return content[:position].count('\n') + 1
    
    def get_precision_summary(self, contract_content: str) -> Dict[str, Any]:
        """Get summary of precision operations in contract"""
        summary = {
            'total_precision_operations': 0,
            'division_operations': 0,
            'multiplication_operations': 0,
            'modulo_operations': 0,
            'complex_expressions': 0,
            'precision_constants_used': 0,
            'fixed_point_libraries': 0,
            'precision_issues': 0
        }
        
        # Count different types of operations
        summary['division_operations'] = len(re.findall(r'(\w+)\s*/\s*(\w+)', contract_content))
        summary['multiplication_operations'] = len(re.findall(r'(\w+)\s*\*\s*(\w+)', contract_content))
        summary['modulo_operations'] = len(re.findall(r'(\w+)\s*%\s*(\w+)', contract_content))
        summary['complex_expressions'] = len(re.findall(r'\([^)]+\)\s*[\+\-\*\/\%]\s*\([^)]+\)', contract_content))
        
        # Count precision constants
        for constant in self.precision_constants:
            if constant in contract_content:
                summary['precision_constants_used'] += 1
        
        # Count fixed-point libraries
        fixed_point_libs = ['FixedPoint', 'PRBMath', 'ABDKMath', 'SafeMath']
        for lib in fixed_point_libs:
            if lib in contract_content:
                summary['fixed_point_libraries'] += 1
        
        # Calculate total precision operations
        summary['total_precision_operations'] = (
            summary['division_operations'] + 
            summary['multiplication_operations'] + 
            summary['modulo_operations'] + 
            summary['complex_expressions']
        )
        
        return summary
    
    def analyze_precision_impact(self, contract_content: str) -> Dict[str, Any]:
        """Analyze the impact of precision issues"""
        impact_analysis = {
            'high_impact_operations': 0,
            'medium_impact_operations': 0,
            'low_impact_operations': 0,
            'total_impact_score': 0,
            'precision_risk_level': 'low'
        }
        
        # Find all precision-sensitive operations
        precision_operations = self._find_precision_operations(contract_content)
        
        for operation in precision_operations:
            if operation.risk_level == PrecisionRisk.CRITICAL:
                impact_analysis['high_impact_operations'] += 1
                impact_analysis['total_impact_score'] += 4
            elif operation.risk_level == PrecisionRisk.HIGH:
                impact_analysis['high_impact_operations'] += 1
                impact_analysis['total_impact_score'] += 3
            elif operation.risk_level == PrecisionRisk.MEDIUM:
                impact_analysis['medium_impact_operations'] += 1
                impact_analysis['total_impact_score'] += 2
            else:
                impact_analysis['low_impact_operations'] += 1
                impact_analysis['total_impact_score'] += 1
        
        # Determine overall risk level
        if impact_analysis['total_impact_score'] >= 10:
            impact_analysis['precision_risk_level'] = 'critical'
        elif impact_analysis['total_impact_score'] >= 6:
            impact_analysis['precision_risk_level'] = 'high'
        elif impact_analysis['total_impact_score'] >= 3:
            impact_analysis['precision_risk_level'] = 'medium'
        else:
            impact_analysis['precision_risk_level'] = 'low'
        
        return impact_analysis
    
    def _find_precision_operations(self, contract_content: str) -> List[PrecisionOperation]:
        """Find all precision-sensitive operations in contract"""
        operations = []
        
        # Combine all patterns
        all_patterns = self.precision_patterns + self.rounding_patterns + self.division_patterns
        
        for pattern_info in all_patterns:
            pattern = pattern_info['pattern']
            matches = re.finditer(pattern, contract_content, re.MULTILINE)
            
            for match in matches:
                line_number = self._get_line_number(match.start(), contract_content)
                code_snippet = match.group(0)
                
                operation = PrecisionOperation(
                    operation_type=pattern_info['type'].value,
                    line_number=line_number,
                    code_snippet=code_snippet,
                    operands=list(match.groups()),
                    result_type='unknown',
                    has_precision_handling=self._has_precision_handling(contract_content, line_number),
                    precision_constant=None,
                    risk_level=pattern_info['risk_level'],
                    confidence=self._calculate_precision_confidence(match, code_snippet)
                )
                
                operations.append(operation)
        
        return operations
