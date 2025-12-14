"""
Data Decoding Analyzer for Smart Contract Security

This module analyzes abi.decode() usage for vulnerabilities, detects malformed input
handling, and identifies potential decoding errors.
"""

import re
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum


class DecodingType(Enum):
    """Types of data decoding operations"""
    ABI_DECODE = "abi_decode"
    ABI_ENCODE = "abi_encode"
    MSG_DATA = "msg_data"
    CALLDATA = "calldata"
    BYTES_SLICE = "bytes_slice"
    BYTES_CONVERSION = "bytes_conversion"


class DecodingRisk(Enum):
    """Risk levels for decoding operations"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class DecodingOperation:
    """Represents a data decoding operation"""
    operation_type: DecodingType
    line_number: int
    code_snippet: str
    data_source: str
    target_types: List[str]
    has_validation: bool
    has_error_handling: bool
    risk_level: DecodingRisk
    confidence: float


@dataclass
class DecodingVulnerability:
    """Represents a decoding-related vulnerability"""
    vulnerability_type: str
    severity: str
    description: str
    line_number: int
    code_snippet: str
    confidence: float
    swc_id: str
    recommendation: str
    operation_type: str
    data_source: str


class DataDecodingAnalyzer:
    """Analyzes data decoding operations for vulnerabilities"""
    
    def __init__(self):
        self.decoding_patterns = self._initialize_decoding_patterns()
        self.malformed_patterns = self._initialize_malformed_patterns()
        self.error_handling_patterns = self._initialize_error_handling_patterns()
        self.risky_types = self._initialize_risky_types()
        
    def _initialize_decoding_patterns(self) -> List[Dict[str, Any]]:
        """Initialize patterns for decoding analysis"""
        return [
            {
                'pattern': r'abi\.decode\s*\(\s*([^,]+),\s*\(([^)]+)\)\s*\)',
                'description': 'ABI decode operation',
                'type': DecodingType.ABI_DECODE,
                'risk_level': DecodingRisk.HIGH
            },
            {
                'pattern': r'abi\.encode\s*\(\s*([^)]+)\s*\)',
                'description': 'ABI encode operation',
                'type': DecodingType.ABI_ENCODE,
                'risk_level': DecodingRisk.MEDIUM
            },
            {
                'pattern': r'bytes\s+(\w+)\s*=\s*msg\.data',
                'description': 'Direct msg.data assignment',
                'type': DecodingType.MSG_DATA,
                'risk_level': DecodingRisk.CRITICAL
            },
            {
                'pattern': r'(\w+)\s*=\s*abi\.decode\s*\(\s*msg\.data\s*\[4:\],\s*\(([^)]+)\)\s*\)',
                'description': 'Direct msg.data decoding',
                'type': DecodingType.MSG_DATA,
                'risk_level': DecodingRisk.CRITICAL
            },
            {
                'pattern': r'(\w+)\s*=\s*abi\.decode\s*\(\s*calldata\s*\[4:\],\s*\(([^)]+)\)\s*\)',
                'description': 'Direct calldata decoding',
                'type': DecodingType.CALLDATA,
                'risk_level': DecodingRisk.HIGH
            },
            {
                'pattern': r'(\w+)\s*=\s*(\w+)\s*\[(\w+):(\w+)\]',
                'description': 'Bytes slicing operation',
                'type': DecodingType.BYTES_SLICE,
                'risk_level': DecodingRisk.MEDIUM
            }
        ]
    
    def _initialize_malformed_patterns(self) -> List[Dict[str, Any]]:
        """Initialize patterns for malformed input detection"""
        return [
            {
                'pattern': r'abi\.decode\s*\(\s*([^,]+),\s*\([^)]+\)\s*\)',
                'description': 'ABI decode without length validation',
                'risk_level': DecodingRisk.HIGH
            },
            {
                'pattern': r'msg\.data\s*\[4:\]',
                'description': 'Direct msg.data slicing without validation',
                'risk_level': DecodingRisk.CRITICAL
            },
            {
                'pattern': r'calldata\s*\[4:\]',
                'description': 'Direct calldata slicing without validation',
                'risk_level': DecodingRisk.HIGH
            },
            {
                'pattern': r'(\w+)\s*\[(\w+):(\w+)\]',
                'description': 'Bytes slicing without bounds checking',
                'risk_level': DecodingRisk.MEDIUM
            }
        ]
    
    def _initialize_error_handling_patterns(self) -> List[str]:
        """Initialize patterns for error handling detection"""
        return [
            r'try\s*\{',
            r'catch\s*\([^)]*\)\s*\{',
            r'require\s*\([^)]*\)',
            r'assert\s*\([^)]*\)',
            r'revert\s*\([^)]*\)',
            r'if\s*\([^)]*\)\s*\{'
        ]
    
    def _initialize_risky_types(self) -> Set[str]:
        """Initialize list of risky data types for decoding"""
        return {
            'bytes', 'bytes32', 'bytes4', 'bytes8', 'bytes16',
            'string', 'address', 'uint256', 'int256', 'bool'
        }
    
    def analyze_decoding_operations(self, contract_content: str) -> List[DecodingVulnerability]:
        """Analyze data decoding operations for vulnerabilities"""
        vulnerabilities = []
        
        # Split content into lines for line number tracking
        lines = contract_content.split('\n')
        
        # Detect malformed input handling
        vulnerabilities.extend(self._detect_malformed_input_handling(contract_content, lines))
        
        # Detect unsafe decoding operations
        vulnerabilities.extend(self._detect_unsafe_decoding_operations(contract_content, lines))
        
        # Detect missing error handling
        vulnerabilities.extend(self._detect_missing_error_handling(contract_content, lines))
        
        # Detect bounds checking issues
        vulnerabilities.extend(self._detect_decoding_bounds_issues(contract_content, lines))
        
        return vulnerabilities
    
    def _detect_malformed_input_handling(self, contract_content: str, lines: List[str]) -> List[DecodingVulnerability]:
        """Detect malformed input handling vulnerabilities"""
        vulnerabilities = []
        
        for pattern_info in self.malformed_patterns:
            pattern = pattern_info['pattern']
            matches = re.finditer(pattern, contract_content, re.MULTILINE)
            
            for match in matches:
                line_number = self._get_line_number(match.start(), contract_content)
                code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""
                
                # Check if this is a false positive
                if self._is_false_positive_malformed(match, code_snippet, contract_content, line_number):
                    continue
                
                # Check if there's validation nearby
                has_validation = self._has_validation_nearby(contract_content, line_number)
                
                if not has_validation:
                    vulnerability = DecodingVulnerability(
                        vulnerability_type='malformed_input_handling',
                        severity=pattern_info['risk_level'].value,
                        description=pattern_info['description'],
                        line_number=line_number,
                        code_snippet=code_snippet,
                        confidence=self._calculate_malformed_confidence(match, code_snippet),
                        swc_id='SWC-120',
                        recommendation='Add input validation before decoding operations',
                        operation_type='decoding',
                        data_source=self._extract_data_source(match, code_snippet)
                    )
                    vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _detect_unsafe_decoding_operations(self, contract_content: str, lines: List[str]) -> List[DecodingVulnerability]:
        """Detect unsafe decoding operations"""
        vulnerabilities = []
        
        for pattern_info in self.decoding_patterns:
            pattern = pattern_info['pattern']
            matches = re.finditer(pattern, contract_content, re.MULTILINE)
            
            for match in matches:
                line_number = self._get_line_number(match.start(), contract_content)
                code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""
                
                # Check if this is a false positive
                if self._is_false_positive_unsafe(match, code_snippet, contract_content, line_number):
                    continue
                
                # Analyze the operation
                operation = self._analyze_decoding_operation(match, code_snippet, line_number)
                
                if operation.risk_level in [DecodingRisk.HIGH, DecodingRisk.CRITICAL]:
                    vulnerability = DecodingVulnerability(
                        vulnerability_type='unvalidated_decoding',
                        severity=operation.risk_level.value,
                        description=f'Unsafe {operation.operation_type.value} operation',
                        line_number=line_number,
                        code_snippet=code_snippet,
                        confidence=operation.confidence,
                        swc_id='SWC-120',
                        recommendation=self._get_decoding_recommendation(operation),
                        operation_type=operation.operation_type.value,
                        data_source=operation.data_source
                    )
                    vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _detect_missing_error_handling(self, contract_content: str, lines: List[str]) -> List[DecodingVulnerability]:
        """Detect missing error handling in decoding operations"""
        vulnerabilities = []
        
        # Find all decoding operations
        decoding_operations = self._find_decoding_operations(contract_content)
        
        for operation in decoding_operations:
            if not operation.has_error_handling:
                # Skip false positives
                # Skip if in view/pure function
                if self._is_in_view_function(contract_content, operation.line_number):
                    continue
                
                # Skip CCIP-Read patterns
                if any(pattern in operation.code_snippet for pattern in ['extraData', 'response', 'resolveCallback', 'returnData']):
                    continue
                
                # Skip callbacks
                if 'callback' in operation.code_snippet.lower():
                    continue
                
                # Skip if in callback function
                function_context = self._get_function_context(contract_content, operation.line_number)
                if 'callback' in function_context.lower():
                    continue
                
                vulnerability = DecodingVulnerability(
                    vulnerability_type='missing_error_handling',
                    severity='medium',
                    description=f'Decoding operation without error handling',
                    line_number=operation.line_number,
                    code_snippet=operation.code_snippet,
                    confidence=0.7,
                    swc_id='SWC-120',
                    recommendation='Add try-catch blocks or error handling for decoding operations',
                    operation_type=operation.operation_type.value,
                    data_source=operation.data_source
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _detect_decoding_bounds_issues(self, contract_content: str, lines: List[str]) -> List[DecodingVulnerability]:
        """Detect bounds checking issues in decoding operations"""
        vulnerabilities = []
        
        # Pattern for bytes slicing operations
        slice_pattern = r'(\w+)\s*\[(\w+):(\w+)\]'
        matches = re.finditer(slice_pattern, contract_content, re.MULTILINE)
        
        for match in matches:
            line_number = self._get_line_number(match.start(), contract_content)
            code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""
            
            # Check if this is a false positive
            if self._is_false_positive_bounds(match, code_snippet):
                continue
            
            # Check if there's bounds checking
            has_bounds_checking = self._has_bounds_checking(contract_content, line_number, match)
            
            if not has_bounds_checking:
                vulnerability = DecodingVulnerability(
                    vulnerability_type='decoding_bounds_issue',
                    severity='medium',
                    description='Bytes slicing without bounds checking',
                    line_number=line_number,
                    code_snippet=code_snippet,
                    confidence=0.6,
                    swc_id='SWC-120',
                    recommendation='Add bounds checking before bytes slicing',
                    operation_type='bytes_slice',
                    data_source=match.group(1)
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _find_decoding_operations(self, contract_content: str) -> List[DecodingOperation]:
        """Find all decoding operations in contract"""
        operations = []
        
        for pattern_info in self.decoding_patterns:
            pattern = pattern_info['pattern']
            matches = re.finditer(pattern, contract_content, re.MULTILINE)
            
            for match in matches:
                line_number = self._get_line_number(match.start(), contract_content)
                code_snippet = match.group(0)
                
                operation = DecodingOperation(
                    operation_type=pattern_info['type'],
                    line_number=line_number,
                    code_snippet=code_snippet,
                    data_source=self._extract_data_source(match, code_snippet),
                    target_types=self._extract_target_types(match, code_snippet),
                    has_validation=self._has_validation_nearby(contract_content, line_number),
                    has_error_handling=self._has_error_handling_nearby(contract_content, line_number),
                    risk_level=pattern_info['risk_level'],
                    confidence=self._calculate_operation_confidence(match, code_snippet)
                )
                
                operations.append(operation)
        
        return operations
    
    def _analyze_decoding_operation(self, match: re.Match, code_snippet: str, line_number: int) -> DecodingOperation:
        """Analyze a specific decoding operation"""
        # Extract data source
        data_source = self._extract_data_source(match, code_snippet)
        
        # Extract target types
        target_types = self._extract_target_types(match, code_snippet)
        
        # Determine risk level
        risk_level = self._determine_risk_level(data_source, target_types)
        
        # Calculate confidence
        confidence = self._calculate_operation_confidence(match, code_snippet)
        
        return DecodingOperation(
            operation_type=DecodingType.ABI_DECODE,  # Default type
            line_number=line_number,
            code_snippet=code_snippet,
            data_source=data_source,
            target_types=target_types,
            has_validation=self._has_validation_nearby(code_snippet, line_number),
            has_error_handling=self._has_error_handling_nearby(code_snippet, line_number),
            risk_level=risk_level,
            confidence=confidence
        )
    
    def _extract_data_source(self, match: re.Match, code_snippet: str) -> str:
        """Extract data source from match"""
        if 'msg.data' in code_snippet:
            return 'msg.data'
        elif 'calldata' in code_snippet:
            return 'calldata'
        elif len(match.groups()) > 0:
            return match.group(1)
        else:
            return 'unknown'
    
    def _extract_target_types(self, match: re.Match, code_snippet: str) -> List[str]:
        """Extract target types from match"""
        types = []
        
        # Look for type patterns in the code snippet
        type_patterns = [
            r'uint\d*',
            r'int\d*',
            r'bytes\d*',
            r'address',
            r'bool',
            r'string'
        ]
        
        for pattern in type_patterns:
            matches = re.findall(pattern, code_snippet)
            types.extend(matches)
        
        return list(set(types))  # Remove duplicates
    
    def _determine_risk_level(self, data_source: str, target_types: List[str]) -> DecodingRisk:
        """Determine risk level for decoding operation"""
        risk_score = 0
        
        # Risk based on data source
        if data_source == 'msg.data':
            risk_score += 3
        elif data_source == 'calldata':
            risk_score += 2
        else:
            risk_score += 1
        
        # Risk based on target types
        for target_type in target_types:
            if target_type in self.risky_types:
                risk_score += 1
        
        # Determine risk level
        if risk_score >= 5:
            return DecodingRisk.CRITICAL
        elif risk_score >= 3:
            return DecodingRisk.HIGH
        elif risk_score >= 2:
            return DecodingRisk.MEDIUM
        else:
            return DecodingRisk.LOW
    
    def _calculate_operation_confidence(self, match: re.Match, code_snippet: str) -> float:
        """Calculate confidence score for operation"""
        confidence = 0.5  # Base confidence
        
        # Increase confidence if no validation
        if 'require(' not in code_snippet and 'assert(' not in code_snippet:
            confidence += 0.2
        
        # Increase confidence if using risky data sources
        if 'msg.data' in code_snippet:
            confidence += 0.2
        elif 'calldata' in code_snippet:
            confidence += 0.1
        
        # Increase confidence if no error handling
        if 'try' not in code_snippet and 'catch' not in code_snippet:
            confidence += 0.1
        
        return min(confidence, 1.0)
    
    def _is_false_positive_malformed(self, match: re.Match, code_snippet: str, contract_content: str = "", line_number: int = 0) -> bool:
        """Check if malformed detection is a false positive"""
        # Skip if there's explicit validation
        if 'require(' in code_snippet or 'assert(' in code_snippet:
            return True
        
        # Skip if using SafeMath or similar libraries
        if 'SafeMath' in code_snippet or 'safe' in code_snippet.lower():
            return True
        
        # Skip if in a try-catch block
        if 'try' in code_snippet and 'catch' in code_snippet:
            return True
        
        # Skip if governance/admin controlled (config, managerData, etc.)
        if contract_content and line_number:
            if self._is_governance_controlled(code_snippet, contract_content, line_number):
                return True
        
        # NEW: Skip if in a view/pure function (can't modify state, low impact)
        if contract_content and line_number:
            if self._is_in_view_function(contract_content, line_number):
                return True
        
        # NEW: Skip if decoding external call results (expected to revert on bad data)
        if 'abi.decode(' in code_snippet and any(pattern in code_snippet for pattern in ['returnData', 'response', 'result', 'data']):
            if any(call in code_snippet for call in ['.call(', '.staticcall(', '.delegatecall(']):
                return True
        
        # NEW: Skip CCIP-Read / EIP-3668 patterns (off-chain data decoding is expected)
        if any(pattern in code_snippet for pattern in ['extraData', 'OffchainLookup', 'resolveCallback', 'response']):
            return True
        
        # NEW: Skip if decoding callback data (EIP-3668, CCIP-Read, etc.)
        if 'callback' in code_snippet.lower():
            return True
        
        # NEW: Skip if in a callback function
        if contract_content and line_number:
            function_context = self._get_function_context(contract_content, line_number)
            if 'callback' in function_context.lower():
                return True
        
        return False
    
    def _is_false_positive_unsafe(self, match: re.Match, code_snippet: str, contract_content: str = "", line_number: int = 0) -> bool:
        """Check if unsafe detection is a false positive"""
        # Skip if there's explicit validation
        if 'require(' in code_snippet or 'assert(' in code_snippet:
            return True
        
        # Skip if using SafeMath or similar libraries
        if 'SafeMath' in code_snippet or 'safe' in code_snippet.lower():
            return True
        
        # Skip if in a try-catch block
        if 'try' in code_snippet and 'catch' in code_snippet:
            return True
        
        # NEW: Skip if in a view/pure function
        if contract_content and line_number:
            if self._is_in_view_function(contract_content, line_number):
                return True
        
        # NEW: Skip if decoding external call results (but NOT msg.data which is a vulnerability)
        # Be specific to avoid filtering msg.data which we want to detect
        external_result_patterns = ['returnData', 'responseData', 'resultData', 'callResult', 'callData']
        if 'abi.decode(' in code_snippet and 'msg.data' not in code_snippet:
            if any(pattern in code_snippet for pattern in external_result_patterns):
                return True
        
        # NEW: Skip CCIP-Read patterns
        if any(pattern in code_snippet for pattern in ['extraData', 'OffchainLookup', 'resolveCallback', 'response']):
            return True
        
        # NEW: Skip callback patterns
        if 'callback' in code_snippet.lower():
            return True
        
        # NEW: Skip if in a callback function
        if contract_content and line_number:
            function_context = self._get_function_context(contract_content, line_number)
            if 'callback' in function_context.lower():
                return True
        
        return False
    
    def _is_false_positive_bounds(self, match: re.Match, code_snippet: str) -> bool:
        """Check if bounds detection is a false positive"""
        # Skip if there's explicit bounds checking
        if 'require(' in code_snippet and ('length' in code_snippet or '<' in code_snippet or '>' in code_snippet):
            return True
        
        # Skip if using SafeMath or similar libraries
        if 'SafeMath' in code_snippet or 'safe' in code_snippet.lower():
            return True
        
        return False
    
    def _has_validation_nearby(self, contract_content: str, line_number: int) -> bool:
        """Check if there's validation nearby"""
        lines = contract_content.split('\n')
        
        # Check lines before and after
        start_line = max(0, line_number - 5)
        end_line = min(len(lines), line_number + 5)
        
        for i in range(start_line, end_line):
            if i < len(lines):
                line = lines[i]
                if 'require(' in line or 'assert(' in line:
                    return True
        
        return False
    
    def _has_error_handling_nearby(self, contract_content: str, line_number: int) -> bool:
        """Check if there's error handling nearby"""
        lines = contract_content.split('\n')
        
        # Check lines before and after
        start_line = max(0, line_number - 10)
        end_line = min(len(lines), line_number + 10)
        
        for i in range(start_line, end_line):
            if i < len(lines):
                line = lines[i]
                for pattern in self.error_handling_patterns:
                    if re.search(pattern, line):
                        return True
        
        return False
    
    def _has_bounds_checking(self, contract_content: str, line_number: int, match: re.Match) -> bool:
        """Check if there's bounds checking"""
        lines = contract_content.split('\n')
        
        # Check lines before the operation
        start_line = max(0, line_number - 10)
        end_line = line_number
        
        for i in range(start_line, end_line):
            if i < len(lines):
                line = lines[i]
                # Check for bounds checking patterns
                if 'require(' in line and ('length' in line or '<' in line or '>' in line):
                    return True
        
        return False
    
    def _calculate_malformed_confidence(self, match: re.Match, code_snippet: str) -> float:
        """Calculate confidence score for malformed detection"""
        confidence = 0.6  # Base confidence
        
        # Increase confidence if no validation
        if 'require(' not in code_snippet and 'assert(' not in code_snippet:
            confidence += 0.3
        
        # Increase confidence if using msg.data
        if 'msg.data' in code_snippet:
            confidence += 0.1
        
        return min(confidence, 1.0)
    
    def _get_decoding_recommendation(self, operation: DecodingOperation) -> str:
        """Get recommendation for decoding operation"""
        if operation.operation_type == DecodingType.MSG_DATA:
            return 'Add validation for msg.data before decoding'
        elif operation.operation_type == DecodingType.CALLDATA:
            return 'Add validation for calldata before decoding'
        elif operation.operation_type == DecodingType.ABI_DECODE:
            return 'Add input validation before ABI decoding'
        else:
            return 'Add proper validation and error handling for decoding operations'
    
    def _get_line_number(self, position: int, content: str) -> int:
        """Get line number from character position"""
        return content[:position].count('\n') + 1
    
    def _is_in_view_function(self, contract_content: str, line_number: int) -> bool:
        """Check if code is inside a view or pure function (read-only, can't steal funds)"""
        function_context = self._get_function_context(contract_content, line_number)
        
        # Check for view or pure modifiers
        if any(modifier in function_context for modifier in ['view', 'pure']):
            return True
        
        # Check for external/public view functions
        if re.search(r'function\s+\w+\s*\([^)]*\)\s+(external|public)\s+view', function_context):
            return True
        if re.search(r'function\s+\w+\s*\([^)]*\)\s+view\s+(external|public)', function_context):
            return True
        
        return False
    
    def _is_governance_controlled(self, code_snippet: str, contract_content: str, line_number: int) -> bool:
        """Check if the decoded data comes from governance/trusted source"""
        # Common governance patterns
        governance_patterns = [
            r'config',
            r'managerData',
            r'oracleConfig',
            r'oracleData',
            r'whitelistData',
        ]
        
        for pattern in governance_patterns:
            if pattern in code_snippet:
                # Check if this is set by governance
                function_context = self._get_function_context(contract_content, line_number)
                if any(modifier in function_context for modifier in ['onlyOwner', 'onlyGovernor', 'onlyAdmin', 'onlyGuardian', 'restricted']):
                    return True
        
        # Check if in a library (libraries often have trusted callers)
        if self._is_library_context(contract_content, line_number):
            return True
        
        return False
    
    def _get_function_context(self, contract_content: str, line_number: int) -> str:
        """Extract the function containing the specified line"""
        lines = contract_content.split('\n')
        
        function_start = -1
        for i in range(line_number - 1, -1, -1):
            if i >= len(lines):
                continue
            if re.match(r'\s*function\s+\w+', lines[i]):
                function_start = i
                break
        
        if function_start == -1:
            return ""
        
        function_end = len(lines)
        brace_count = 0
        for i in range(function_start, len(lines)):
            line = lines[i]
            brace_count += line.count('{') - line.count('}')
            if brace_count == 0 and '{' in '\n'.join(lines[function_start:i+1]):
                function_end = i + 1
                break
        
        return '\n'.join(lines[function_start:function_end])
    
    def _is_library_context(self, contract_content: str, line_number: int) -> bool:
        """Check if code is in a library"""
        lines = contract_content.split('\n')
        
        for i in range(line_number - 1, max(0, line_number - 100), -1):
            if i < len(lines):
                line = lines[i]
                if re.search(r'^\s*library\s+\w+', line):
                    return True
                if re.search(r'^\s*contract\s+\w+', line):
                    return False
        
        return False
    
    def get_decoding_summary(self, contract_content: str) -> Dict[str, Any]:
        """Get summary of decoding operations in contract"""
        operations = self._find_decoding_operations(contract_content)
        
        summary = {
            'total_operations': len(operations),
            'operations_by_type': {},
            'operations_by_risk': {},
            'operations_with_validation': len([op for op in operations if op.has_validation]),
            'operations_with_error_handling': len([op for op in operations if op.has_error_handling]),
            'high_risk_operations': len([op for op in operations if op.risk_level in [DecodingRisk.HIGH, DecodingRisk.CRITICAL]]),
            'average_confidence': sum(op.confidence for op in operations) / len(operations) if operations else 0
        }
        
        # Group operations by type
        for operation in operations:
            op_type = operation.operation_type.value
            summary['operations_by_type'][op_type] = summary['operations_by_type'].get(op_type, 0) + 1
        
        # Group operations by risk level
        for operation in operations:
            risk_level = operation.risk_level.value
            summary['operations_by_risk'][risk_level] = summary['operations_by_risk'].get(risk_level, 0) + 1
        
        return summary
