"""
Arithmetic Analysis Engine for Smart Contract Vulnerability Detection

This module provides comprehensive arithmetic vulnerability detection including:
- Integer overflow/underflow detection with comment-aware false positive filtering
- Division by zero detection
- Complex arithmetic expression analysis
- Variable dependency tracking
- Protocol-specific pattern recognition
- Solidity version-aware analysis
"""

import re
from typing import List, Dict, Any, Tuple, Optional
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


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
    """Analyzes arithmetic operations for vulnerabilities with protocol-aware filtering."""
    
    def __init__(self):
        self.overflow_patterns = self._initialize_overflow_patterns()
        self.underflow_patterns = self._initialize_underflow_patterns()
        self.division_patterns = self._initialize_division_patterns()
        self.arithmetic_operations = ['+', '-', '*', '/', '%', '**']
        
        # Initialize protocol pattern library for smart false positive filtering
        try:
            from core.protocol_patterns import ProtocolPatternLibrary
            self.protocol_patterns = ProtocolPatternLibrary()
        except ImportError:
            self.protocol_patterns = None
        
        # Cache for Solidity version per contract
        self.contract_version_cache = {}
        # Cache for file path context
        self.current_file_path = None
        
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
        """Detect overflow vulnerabilities with enhanced false positive filtering"""
        vulnerabilities = []
        
        for pattern_info in self.overflow_patterns:
            pattern = pattern_info['pattern']
            matches = re.finditer(pattern, contract_content, re.MULTILINE)
            
            for match in matches:
                line_number = self._get_line_number(match.start(), contract_content)
                code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""
                
                # Check if this is a false positive (enhanced with comment-aware and protocol pattern checking)
                if self._is_false_positive_overflow(match, code_snippet, contract_content, line_number):
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
    
    def _is_false_positive_overflow(self, match: re.Match, code_snippet: str, contract_content: str = "", line_number: int = 0) -> bool:
        """
        Check if overflow detection is a false positive using multiple strategies:
        1. Comment-aware analysis (checks for "overflow is acceptable" patterns)
        2. Protocol-specific patterns (Uniswap V3, etc.)
        3. Library usage (SafeMath, SafeCast, etc.)
        4. Solidity version awareness (<0.8.0 vs >=0.8.0)
        """
        # Strategy 1: Check for documented overflow acceptance in comments
        if self._has_acceptable_overflow_comment(contract_content, line_number):
            return True
        
        # Strategy 2: Check protocol-specific patterns
        if self.protocol_patterns:
            context = self._build_context_for_pattern_check(
                code_snippet, contract_content, line_number
            )
            pattern = self.protocol_patterns.check_pattern_match(
                'integer_overflow', contract_content, context
            )
            if pattern and pattern.acceptable_behavior:
                # Additional check: Verify Solidity version compatibility if specified
                if pattern.solidity_version_specific:
                    version = self._extract_solidity_version(contract_content)
                    if version and self.protocol_patterns.check_solidity_version_compatibility(pattern, version):
                        return True
                else:
                    return True
        
        # Strategy 3: Traditional library checks
        # Skip if using SafeMath or similar libraries
        if 'SafeMath' in code_snippet or 'safe' in code_snippet.lower():
            return True
        
        # Skip if using SafeCast (intentional type narrowing with revert-on-overflow)
        if 'SafeCast' in code_snippet or '.toUint' in code_snippet:
            return True
        
        # Skip if there are explicit bounds checks
        if 'require(' in code_snippet and ('max' in code_snippet or 'limit' in code_snippet):
            return True
        
        # Skip if using fixed-point arithmetic libraries
        if 'FixedPoint' in code_snippet or 'PRBMath' in code_snippet:
            return True
        
        # Strategy 4: Solidity version-specific analysis
        # In Solidity >=0.8.0, overflow checks are automatic (unless in unchecked block)
        version = self._extract_solidity_version(contract_content)
        if version and self._compare_versions(version, '0.8.0') >= 0:
            # Check if NOT in unchecked block
            if 'unchecked' not in code_snippet:
                return True  # Automatic overflow protection
        
        # Check for uint128 casts in Solidity <0.8 with documented bounds
        if 'uint128(' in code_snippet and version and self._compare_versions(version, '0.8.0') < 0:
            # Look for documentation about type(uint128).max limits
            if re.search(r'type\s*\(\s*uint128\s*\)\s*\.\s*max', contract_content, re.IGNORECASE):
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
    
    def _has_acceptable_overflow_comment(self, contract_content: str, line_number: int) -> bool:
        """
        Check if there are comments indicating overflow is acceptable.
        Searches within 30 lines before and 10 lines after the flagged line.
        """
        lines = contract_content.split('\n')
        search_start = max(0, line_number - 30)
        search_end = min(len(lines), line_number + 10)
        
        # Patterns that indicate intentional overflow
        acceptable_overflow_patterns = [
            r'overflow\s+is\s+acceptable',
            r'overflow\s+is\s+not\s+possible',
            r'overflow\s+acceptable',
            r'have\s+to\s+withdraw\s+before',
            r'type\s*\(\s*uint\d+\s*\)\s*\.\s*max',
            r'max\s+value\s+of\s+uint\d+',
            r'cannot\s+overflow',
            r'will\s+not\s+overflow',
            r'safe\s+from\s+overflow',
        ]
        
        # Search in comments around the flagged line
        for i in range(search_start, search_end):
            if i >= len(lines):
                break
            line = lines[i]
            
            # Check single-line comments
            if '//' in line:
                comment = line[line.index('//'):]
                for pattern in acceptable_overflow_patterns:
                    if re.search(pattern, comment, re.IGNORECASE):
                        return True
            
            # Check multi-line comments
            if '/*' in line or '*' in line.strip()[:1]:
                for pattern in acceptable_overflow_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        return True
        
        return False
    
    def _build_context_for_pattern_check(
        self, 
        code_snippet: str, 
        contract_content: str, 
        line_number: int
    ) -> Dict[str, Any]:
        """Build context dictionary for protocol pattern matching."""
        # Extract surrounding context (20 lines before and after)
        lines = contract_content.split('\n')
        start_line = max(0, line_number - 20)
        end_line = min(len(lines), line_number + 20)
        surrounding_context = '\n'.join(lines[start_line:end_line])
        
        # Try to extract function context
        function_context = self._extract_function_context(contract_content, line_number)
        
        return {
            'file_path': self.current_file_path or '',
            'code_snippet': code_snippet,
            'surrounding_context': surrounding_context,
            'function_context': function_context,
            'line_number': line_number,
        }
    
    def _extract_function_context(self, contract_content: str, line_number: int) -> str:
        """Extract the function containing the specified line."""
        lines = contract_content.split('\n')
        
        # Search backwards for function declaration
        function_start = -1
        for i in range(line_number - 1, -1, -1):
            if i >= len(lines):
                continue
            if re.match(r'\s*function\s+\w+', lines[i]):
                function_start = i
                break
        
        if function_start == -1:
            return ""
        
        # Search forward for function end (closing brace at same or lower indentation)
        function_end = len(lines)
        brace_count = 0
        for i in range(function_start, len(lines)):
            line = lines[i]
            brace_count += line.count('{') - line.count('}')
            if brace_count == 0 and '{' in lines[function_start:i+1]:
                function_end = i + 1
                break
        
        return '\n'.join(lines[function_start:function_end])
    
    def _extract_solidity_version(self, contract_content: str) -> Optional[str]:
        """Extract Solidity version from pragma statement."""
        # Try to get from cache first
        cache_key = hash(contract_content[:500])  # Use first 500 chars as key
        if cache_key in self.contract_version_cache:
            return self.contract_version_cache[cache_key]
        
        pragma_match = re.search(r'pragma\s+solidity\s+([^;]+);', contract_content)
        if pragma_match:
            version_spec = pragma_match.group(1).strip()
            # Extract actual version number (e.g., "^0.8.0" -> "0.8.0")
            version_match = re.search(r'(\d+\.\d+\.\d+)', version_spec)
            if version_match:
                version = version_match.group(1)
                self.contract_version_cache[cache_key] = version
                return version
            # Handle range specs like ">=0.7.6 <0.9.0"
            version_match = re.search(r'(\d+\.\d+)', version_spec)
            if version_match:
                version = version_match.group(1) + ".0"
                self.contract_version_cache[cache_key] = version
                return version
        
        return None
    
    def _compare_versions(self, v1: str, v2: str) -> int:
        """
        Compare two semantic version strings.
        Returns: -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
        """
        def normalize_version(v: str) -> List[int]:
            return [int(x) for x in v.split('.')]
        
        v1_parts = normalize_version(v1)
        v2_parts = normalize_version(v2)
        
        # Pad with zeros if needed
        max_len = max(len(v1_parts), len(v2_parts))
        v1_parts.extend([0] * (max_len - len(v1_parts)))
        v2_parts.extend([0] * (max_len - len(v2_parts)))
        
        for p1, p2 in zip(v1_parts, v2_parts):
            if p1 < p2:
                return -1
            elif p1 > p2:
                return 1
        
        return 0
    
    def set_file_context(self, file_path: str):
        """Set the current file path for context in pattern matching."""
        self.current_file_path = file_path
