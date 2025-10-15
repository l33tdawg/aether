"""
Gas Analyzer for Smart Contract Security

This module analyzes gas consumption patterns, detects potential gas limit issues,
and identifies gas optimization opportunities.
"""

import re
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum


class GasIssue(Enum):
    """Types of gas issues"""
    GAS_LIMIT_EXCEEDED = "gas_limit_exceeded"
    INEFFICIENT_OPERATION = "inefficient_operation"
    UNLIMITED_GAS_CALL = "unlimited_gas_call"
    LOOP_GAS_CONSUMPTION = "loop_gas_consumption"
    STORAGE_GAS_CONSUMPTION = "storage_gas_consumption"
    EXTERNAL_CALL_GAS = "external_call_gas"


class GasRisk(Enum):
    """Risk levels for gas issues"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class GasOperation:
    """Represents a gas-consuming operation"""
    operation_type: str
    line_number: int
    code_snippet: str
    gas_estimate: int
    has_gas_limit: bool
    gas_limit: Optional[int]
    is_optimizable: bool
    risk_level: GasRisk
    confidence: float


@dataclass
class GasVulnerability:
    """Represents a gas-related vulnerability"""
    vulnerability_type: str
    severity: str
    description: str
    line_number: int
    code_snippet: str
    confidence: float
    swc_id: str
    recommendation: str
    operation_type: str
    gas_impact: str


class GasAnalyzer:
    """Analyzes gas consumption patterns"""
    
    def __init__(self):
        self.gas_patterns = self._initialize_gas_patterns()
        self.loop_patterns = self._initialize_loop_patterns()
        self.storage_patterns = self._initialize_storage_patterns()
        self.external_call_patterns = self._initialize_external_call_patterns()
        self.gas_limits = self._initialize_gas_limits()
        
    def _initialize_gas_patterns(self) -> List[Dict[str, Any]]:
        """Initialize patterns for gas analysis"""
        return [
            {
                'pattern': r'(\w+)\.call\s*\(\s*[^)]*\)',
                'description': 'External call without gas limit',
                'type': GasIssue.UNLIMITED_GAS_CALL,
                'risk_level': GasRisk.HIGH
            },
            {
                'pattern': r'(\w+)\.delegatecall\s*\(\s*[^)]*\)',
                'description': 'Delegate call without gas limit',
                'type': GasIssue.UNLIMITED_GAS_CALL,
                'risk_level': GasRisk.CRITICAL
            },
            {
                'pattern': r'(\w+)\.staticcall\s*\(\s*[^)]*\)',
                'description': 'Static call without gas limit',
                'type': GasIssue.UNLIMITED_GAS_CALL,
                'risk_level': GasRisk.MEDIUM
            },
            {
                'pattern': r'(\w+)\.transfer\s*\(\s*[^)]*\)',
                'description': 'Transfer operation',
                'type': GasIssue.EXTERNAL_CALL_GAS,
                'risk_level': GasRisk.MEDIUM
            },
            {
                'pattern': r'(\w+)\.send\s*\(\s*[^)]*\)',
                'description': 'Send operation',
                'type': GasIssue.EXTERNAL_CALL_GAS,
                'risk_level': GasRisk.MEDIUM
            }
        ]
    
    def _initialize_loop_patterns(self) -> List[Dict[str, Any]]:
        """Initialize patterns for loop analysis"""
        return [
            {
                'pattern': r'for\s*\(\s*(\w+)\s*=\s*0\s*;\s*\1\s*<\s*(\w+)\.length\s*;\s*\1\+\+\s*\)',
                'description': 'Array iteration loop',
                'type': GasIssue.LOOP_GAS_CONSUMPTION,
                'risk_level': GasRisk.MEDIUM
            },
            {
                'pattern': r'while\s*\(\s*[^)]+\s*\)\s*\{',
                'description': 'While loop',
                'type': GasIssue.LOOP_GAS_CONSUMPTION,
                'risk_level': GasRisk.HIGH
            },
            {
                'pattern': r'do\s*\{[^}]*\}\s*while\s*\(\s*[^)]+\s*\)',
                'description': 'Do-while loop',
                'type': GasIssue.LOOP_GAS_CONSUMPTION,
                'risk_level': GasRisk.HIGH
            }
        ]
    
    def _initialize_storage_patterns(self) -> List[Dict[str, Any]]:
        """Initialize patterns for storage analysis"""
        return [
            {
                'pattern': r'(\w+)\s*=\s*[^;]+;',
                'description': 'Storage variable assignment',
                'type': GasIssue.STORAGE_GAS_CONSUMPTION,
                'risk_level': GasRisk.MEDIUM
            },
            {
                'pattern': r'(\w+)\[(\w+)\]\s*=\s*[^;]+;',
                'description': 'Storage array assignment',
                'type': GasIssue.STORAGE_GAS_CONSUMPTION,
                'risk_level': GasRisk.HIGH
            },
            {
                'pattern': r'(\w+)\.(\w+)\s*=\s*[^;]+;',
                'description': 'Storage struct assignment',
                'type': GasIssue.STORAGE_GAS_CONSUMPTION,
                'risk_level': GasRisk.MEDIUM
            }
        ]
    
    def _initialize_external_call_patterns(self) -> List[Dict[str, Any]]:
        """Initialize patterns for external call analysis"""
        return [
            {
                'pattern': r'(\w+)\.call\s*\(\s*[^)]*gas\s*:\s*(\w+)[^)]*\)',
                'description': 'External call with gas limit',
                'type': GasIssue.EXTERNAL_CALL_GAS,
                'risk_level': GasRisk.LOW
            },
            {
                'pattern': r'(\w+)\.delegatecall\s*\(\s*[^)]*gas\s*:\s*(\w+)[^)]*\)',
                'description': 'Delegate call with gas limit',
                'type': GasIssue.EXTERNAL_CALL_GAS,
                'risk_level': GasRisk.LOW
            },
            {
                'pattern': r'(\w+)\.staticcall\s*\(\s*[^)]*gas\s*:\s*(\w+)[^)]*\)',
                'description': 'Static call with gas limit',
                'type': GasIssue.EXTERNAL_CALL_GAS,
                'risk_level': GasRisk.LOW
            }
        ]
    
    def _initialize_gas_limits(self) -> Dict[str, int]:
        """Initialize gas limits for different operations"""
        return {
            'block_gas_limit': 30000000,
            'transaction_gas_limit': 21000,
            'call_gas_limit': 2300,
            'transfer_gas_limit': 21000,
            'storage_slot_gas': 20000,
            'storage_word_gas': 5000,
            'sload_gas': 800,
            'sstore_gas': 20000
        }
    
    def analyze_gas_consumption(self, contract_content: str) -> List[GasVulnerability]:
        """Analyze gas consumption patterns"""
        vulnerabilities = []
        
        # Split content into lines for line number tracking
        lines = contract_content.split('\n')
        
        # Detect potential gas limit issues
        vulnerabilities.extend(self._detect_gas_limit_issues(contract_content, lines))
        
        # Detect gas-inefficient patterns
        vulnerabilities.extend(self._detect_gas_inefficient_patterns(contract_content, lines))
        
        # Detect external calls without gas limits
        vulnerabilities.extend(self._detect_unlimited_gas_calls(contract_content, lines))
        
        # Detect loop gas consumption issues
        vulnerabilities.extend(self._detect_loop_gas_issues(contract_content, lines))
        
        # Detect storage gas consumption issues
        vulnerabilities.extend(self._detect_storage_gas_issues(contract_content, lines))
        
        return vulnerabilities
    
    def _detect_gas_limit_issues(self, contract_content: str, lines: List[str]) -> List[GasVulnerability]:
        """Detect potential gas limit issues"""
        vulnerabilities = []
        
        # Find all function declarations
        functions = self._find_function_declarations(contract_content)
        
        for function in functions:
            # Estimate gas consumption for function
            gas_estimate = self._estimate_function_gas(function, contract_content)
            
            if gas_estimate > self.gas_limits['block_gas_limit'] * 0.8:  # 80% of block gas limit
                vulnerability = GasVulnerability(
                    vulnerability_type='gas_limit_issue',
                    severity='high',
                    description=f'Function {function["name"]} may exceed gas limit (estimated: {gas_estimate})',
                    line_number=function['line_number'],
                    code_snippet=function['code_snippet'],
                    confidence=0.7,
                    swc_id='SWC-128',
                    recommendation='Optimize function or split into smaller functions',
                    operation_type='function',
                    gas_impact='high'
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _detect_gas_inefficient_patterns(self, contract_content: str, lines: List[str]) -> List[GasVulnerability]:
        """Detect gas-inefficient patterns"""
        vulnerabilities = []
        
        # Pattern for inefficient storage operations
        inefficient_patterns = [
            {
                'pattern': r'(\w+)\s*=\s*(\w+)\s*\+\s*1;',
                'description': 'Inefficient increment operation',
                'recommendation': 'Use ++ operator instead'
            },
            {
                'pattern': r'(\w+)\s*=\s*(\w+)\s*-\s*1;',
                'description': 'Inefficient decrement operation',
                'recommendation': 'Use -- operator instead'
            },
            {
                'pattern': r'(\w+)\s*=\s*(\w+)\s*\*\s*2;',
                'description': 'Inefficient multiplication by 2',
                'recommendation': 'Use bit shift left (<< 1) instead'
            },
            {
                'pattern': r'(\w+)\s*=\s*(\w+)\s*/\s*2;',
                'description': 'Inefficient division by 2',
                'recommendation': 'Use bit shift right (>> 1) instead'
            }
        ]
        
        for pattern_info in inefficient_patterns:
            pattern = pattern_info['pattern']
            matches = re.finditer(pattern, contract_content, re.MULTILINE)
            
            for match in matches:
                line_number = self._get_line_number(match.start(), contract_content)
                code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""
                
                vulnerability = GasVulnerability(
                    vulnerability_type='gas_inefficient_pattern',
                    severity='low',
                    description=pattern_info['description'],
                    line_number=line_number,
                    code_snippet=code_snippet,
                    confidence=0.8,
                    swc_id='SWC-128',
                    recommendation=pattern_info['recommendation'],
                    operation_type='arithmetic',
                    gas_impact='low'
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _detect_unlimited_gas_calls(self, contract_content: str, lines: List[str]) -> List[GasVulnerability]:
        """Detect external calls without gas limits"""
        vulnerabilities = []
        
        # Simple call pattern for testing
        simple_call_pattern = r'(\w+)\.call\s*\(\s*[^)]*\)'
        matches = re.finditer(simple_call_pattern, contract_content, re.MULTILINE)
        
        for match in matches:
            line_number = self._get_line_number(match.start(), contract_content)
            code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""
            
            # Check if this is a false positive
            if self._is_false_positive_gas_call(match, code_snippet):
                continue
            
            # Check if there's a gas limit
            has_gas_limit = self._has_gas_limit(match, code_snippet)
            
            if not has_gas_limit:
                vulnerability = GasVulnerability(
                    vulnerability_type='unlimited_gas_call',
                    severity='high',
                    description='External call without gas limit',
                    line_number=line_number,
                    code_snippet=code_snippet,
                    confidence=self._calculate_gas_call_confidence(match, code_snippet),
                    swc_id='SWC-128',
                    recommendation='Add gas limit to external call',
                    operation_type='external_call',
                    gas_impact='high'
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _detect_loop_gas_issues(self, contract_content: str, lines: List[str]) -> List[GasVulnerability]:
        """Detect loop gas consumption issues"""
        vulnerabilities = []
        
        # Simple loop pattern for testing - matches loops iterating over array length
        simple_loop_pattern = r'for\s*\([^;]*;\s*\w+\s*<\s*\w+\.length\s*;[^)]*\)'
        matches = re.finditer(simple_loop_pattern, contract_content, re.MULTILINE)
        
        for match in matches:
            line_number = self._get_line_number(match.start(), contract_content)
            code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""
            
            # Check if this is a false positive
            if self._is_false_positive_loop(match, code_snippet):
                continue
            
            # Estimate loop gas consumption
            loop_gas_estimate = self._estimate_loop_gas(match, code_snippet, contract_content)
            
            if loop_gas_estimate > 1000:  # Lower threshold for testing
                vulnerability = GasVulnerability(
                    vulnerability_type='loop_gas_issue',
                    severity='medium',
                    description=f'Loop may consume excessive gas (estimated: {loop_gas_estimate})',
                    line_number=line_number,
                    code_snippet=code_snippet,
                    confidence=self._calculate_loop_confidence(match, code_snippet),
                    swc_id='SWC-128',
                    recommendation='Add loop bounds checking or optimize loop',
                    operation_type='loop',
                    gas_impact='medium'
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _detect_storage_gas_issues(self, contract_content: str, lines: List[str]) -> List[GasVulnerability]:
        """Detect storage gas consumption issues"""
        vulnerabilities = []
        
        for pattern_info in self.storage_patterns:
            pattern = pattern_info['pattern']
            matches = re.finditer(pattern, contract_content, re.MULTILINE)
            
            for match in matches:
                line_number = self._get_line_number(match.start(), contract_content)
                code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""
                
                # Check if this is a false positive
                if self._is_false_positive_storage(match, code_snippet):
                    continue
                
                # Estimate storage gas consumption
                storage_gas_estimate = self._estimate_storage_gas(match, code_snippet)
                
                if storage_gas_estimate > self.gas_limits['storage_slot_gas']:
                    vulnerability = GasVulnerability(
                        vulnerability_type='storage_gas_issue',
                        severity=pattern_info['risk_level'].value,
                        description=f'Storage operation may consume excessive gas (estimated: {storage_gas_estimate})',
                        line_number=line_number,
                        code_snippet=code_snippet,
                        confidence=self._calculate_storage_confidence(match, code_snippet),
                        swc_id='SWC-128',
                        recommendation='Optimize storage operations or use events for logging',
                        operation_type='storage',
                        gas_impact='medium'
                    )
                    vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _find_function_declarations(self, contract_content: str) -> List[Dict[str, Any]]:
        """Find all function declarations in contract"""
        functions = []
        
        # Pattern for function declarations
        function_pattern = r'function\s+(\w+)\s*\([^)]*\)\s*(?:external|public|internal|private)?\s*(?:payable|view|pure)?'
        matches = re.finditer(function_pattern, contract_content, re.MULTILINE)
        
        for match in matches:
            function_name = match.group(1)
            line_number = self._get_line_number(match.start(), contract_content)
            code_snippet = match.group(0)
            
            functions.append({
                'name': function_name,
                'line_number': line_number,
                'code_snippet': code_snippet
            })
        
        return functions
    
    def _estimate_function_gas(self, function: Dict[str, Any], contract_content: str) -> int:
        """Estimate gas consumption for a function"""
        # This is a simplified estimation
        # In practice, you would need more sophisticated analysis
        
        gas_estimate = 21000  # Base transaction cost
        
        # Find function content
        function_content = self._get_function_content(contract_content, function['line_number'])
        
        if function_content:
            # Count different operations
            external_calls = len(re.findall(r'\.call\s*\(|\.delegatecall\s*\(|\.staticcall\s*\(|\.transfer\s*\(|\.send\s*\(', function_content))
            storage_ops = len(re.findall(r'\w+\s*=\s*[^;]+;', function_content))
            loops = len(re.findall(r'for\s*\(|while\s*\(|do\s*\{', function_content))
            
            # Estimate gas based on operations
            gas_estimate += external_calls * 2300  # External call cost
            gas_estimate += storage_ops * 20000   # Storage operation cost
            gas_estimate += loops * 10000         # Loop overhead
        
        return gas_estimate
    
    def _get_function_content(self, contract_content: str, line_number: int) -> Optional[str]:
        """Get function content"""
        lines = contract_content.split('\n')
        
        if line_number > len(lines):
            return None
        
        # Find function start
        start_line = line_number - 1
        brace_count = 0
        in_function = False
        
        for i in range(start_line, len(lines)):
            line = lines[i]
            
            if '{' in line:
                brace_count += line.count('{')
                in_function = True
            elif '}' in line:
                brace_count -= line.count('}')
                
                if in_function and brace_count == 0:
                    return '\n'.join(lines[start_line:i+1])
        
        return None
    
    def _estimate_loop_gas(self, match: re.Match, code_snippet: str, contract_content: str) -> int:
        """Estimate gas consumption for a loop"""
        # This is a simplified estimation
        gas_estimate = 0
        
        # Base loop overhead
        gas_estimate += 1000
        
        # Estimate based on loop type
        if 'for' in code_snippet:
            gas_estimate += 500  # For loop overhead
        elif 'while' in code_snippet:
            gas_estimate += 1000  # While loop overhead
        elif 'do' in code_snippet:
            gas_estimate += 1000  # Do-while loop overhead
        
        # Find loop body and estimate operations
        loop_body = self._get_loop_body(contract_content, match.start())
        if loop_body:
            # Count operations in loop body
            operations = len(re.findall(r'\w+\s*=\s*[^;]+;', loop_body))
            gas_estimate += operations * 1000
        
        return gas_estimate
    
    def _get_loop_body(self, contract_content: str, position: int) -> Optional[str]:
        """Get loop body content"""
        lines = contract_content.split('\n')
        line_number = self._get_line_number(position, contract_content)
        
        if line_number > len(lines):
            return None
        
        # Find loop start
        start_line = line_number - 1
        brace_count = 0
        in_loop = False
        
        for i in range(start_line, len(lines)):
            line = lines[i]
            
            if '{' in line:
                brace_count += line.count('{')
                in_loop = True
            elif '}' in line:
                brace_count -= line.count('}')
                
                if in_loop and brace_count == 0:
                    return '\n'.join(lines[start_line:i+1])
        
        return None
    
    def _estimate_storage_gas(self, match: re.Match, code_snippet: str) -> int:
        """Estimate gas consumption for storage operations"""
        gas_estimate = 0
        
        # Base storage operation cost
        if '[' in code_snippet and ']' in code_snippet:
            gas_estimate += self.gas_limits['storage_slot_gas']  # Array/storage slot
        else:
            gas_estimate += self.gas_limits['storage_word_gas']  # Single word
        
        return gas_estimate
    
    def _is_false_positive_gas_call(self, match: re.Match, code_snippet: str) -> bool:
        """Check if gas call detection is a false positive"""
        # Skip if there's a gas limit (but not in comments)
        if ('gas:' in code_snippet or 'gas ' in code_snippet) and '//' not in code_snippet:
            return True
        
        # Skip if using gasleft() for gas estimation
        if 'gasleft()' in code_snippet:
            return True
        
        return False
    
    def _is_false_positive_loop(self, match: re.Match, code_snippet: str) -> bool:
        """Check if loop detection is a false positive"""
        # Skip if there's bounds checking
        if 'require(' in code_snippet and ('length' in code_snippet or '<' in code_snippet or '>' in code_snippet):
            return True
        
        # Skip if loop has a fixed upper bound
        if re.search(r'<\s*\d+', code_snippet):
            return True
        
        return False
    
    def _is_false_positive_storage(self, match: re.Match, code_snippet: str) -> bool:
        """Check if storage detection is a false positive"""
        # Skip if it's a memory variable
        if 'memory' in code_snippet or 'calldata' in code_snippet:
            return True
        
        # Skip if it's a local variable
        if 'uint' in code_snippet and '=' in code_snippet:
            return True
        
        return False
    
    def _has_gas_limit(self, match: re.Match, code_snippet: str) -> bool:
        """Check if there's a gas limit"""
        # Check for gas limit in the actual call, not in comments
        call_part = code_snippet.split('//')[0] if '//' in code_snippet else code_snippet
        return 'gas:' in call_part or 'gas ' in call_part
    
    def _calculate_gas_call_confidence(self, match: re.Match, code_snippet: str) -> float:
        """Calculate confidence score for gas call detection"""
        confidence = 0.6  # Base confidence
        
        # Increase confidence if no gas limit
        if not self._has_gas_limit(match, code_snippet):
            confidence += 0.3
        
        # Increase confidence for delegate calls
        if 'delegatecall' in code_snippet:
            confidence += 0.1
        
        return min(confidence, 1.0)
    
    def _calculate_loop_confidence(self, match: re.Match, code_snippet: str) -> float:
        """Calculate confidence score for loop detection"""
        confidence = 0.5  # Base confidence
        
        # Increase confidence if no bounds checking
        if 'require(' not in code_snippet or 'length' not in code_snippet:
            confidence += 0.3
        
        # Increase confidence for while loops
        if 'while' in code_snippet:
            confidence += 0.2
        
        return min(confidence, 1.0)
    
    def _calculate_storage_confidence(self, match: re.Match, code_snippet: str) -> float:
        """Calculate confidence score for storage detection"""
        confidence = 0.4  # Base confidence
        
        # Increase confidence for array operations
        if '[' in code_snippet and ']' in code_snippet:
            confidence += 0.3
        
        # Increase confidence for struct operations
        if '.' in code_snippet:
            confidence += 0.2
        
        return min(confidence, 1.0)
    
    def _get_line_number(self, position: int, content: str) -> int:
        """Get line number from character position"""
        return content[:position].count('\n') + 1
    
    def get_gas_summary(self, contract_content: str) -> Dict[str, Any]:
        """Get summary of gas operations in contract"""
        summary = {
            'total_functions': 0,
            'external_calls': 0,
            'storage_operations': 0,
            'loops': 0,
            'estimated_total_gas': 0,
            'gas_optimization_opportunities': 0,
            'high_gas_functions': 0
        }
        
        # Count different types of operations
        summary['external_calls'] = len(re.findall(r'\.call\s*\(|\.delegatecall\s*\(|\.staticcall\s*\(|\.transfer\s*\(|\.send\s*\(', contract_content))
        summary['storage_operations'] = len(re.findall(r'\w+\s*=\s*[^;]+;', contract_content))
        summary['loops'] = len(re.findall(r'for\s*\(|while\s*\(|do\s*\{', contract_content))
        
        # Count functions
        functions = self._find_function_declarations(contract_content)
        summary['total_functions'] = len(functions)
        
        # Estimate total gas and find high gas functions
        for function in functions:
            gas_estimate = self._estimate_function_gas(function, contract_content)
            summary['estimated_total_gas'] += gas_estimate
            
            if gas_estimate > self.gas_limits['block_gas_limit'] * 0.5:
                summary['high_gas_functions'] += 1
        
        # Count gas optimization opportunities
        summary['gas_optimization_opportunities'] = len(re.findall(r'\w+\s*=\s*\w+\s*[\+\-]\s*1;', contract_content))
        
        return summary
    
    def analyze_gas_optimization(self, contract_content: str) -> List[Dict[str, Any]]:
        """Analyze gas optimization opportunities"""
        optimizations = []
        
        # Find inefficient patterns
        inefficient_patterns = [
            {
                'pattern': r'(\w+)\s*=\s*(\w+)\s*\+\s*1;',
                'optimization': r'\1 = \2++;',
                'description': 'Use increment operator',
                'gas_savings': 100
            },
            {
                'pattern': r'(\w+)\s*=\s*(\w+)\s*-\s*1;',
                'optimization': r'\1 = \2--;',
                'description': 'Use decrement operator',
                'gas_savings': 100
            },
            {
                'pattern': r'(\w+)\s*=\s*(\w+)\s*\*\s*2;',
                'optimization': r'\1 = \2 << 1;',
                'description': 'Use bit shift for multiplication by 2',
                'gas_savings': 50
            },
            {
                'pattern': r'(\w+)\s*=\s*(\w+)\s*/\s*2;',
                'optimization': r'\1 = \2 >> 1;',
                'description': 'Use bit shift for division by 2',
                'gas_savings': 50
            }
        ]
        
        for pattern_info in inefficient_patterns:
            pattern = pattern_info['pattern']
            matches = re.finditer(pattern, contract_content, re.MULTILINE)
            
            for match in matches:
                line_number = self._get_line_number(match.start(), contract_content)
                code_snippet = match.group(0)
                
                optimization = {
                    'line_number': line_number,
                    'current_code': code_snippet,
                    'optimized_code': re.sub(pattern, pattern_info['optimization'], code_snippet),
                    'description': pattern_info['description'],
                    'gas_savings': pattern_info['gas_savings'],
                    'confidence': 0.9
                }
                
                optimizations.append(optimization)
        
        return optimizations
