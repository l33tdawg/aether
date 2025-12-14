"""
Input Validation Detector for Smart Contract Security

This module detects missing input validation in functions, analyzes arbitrary data
decoding functions, and identifies bounds checking issues.
"""

import re
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum


class ValidationType(Enum):
    """Types of input validation"""
    MISSING_VALIDATION = "missing_validation"
    BOUNDS_CHECKING = "bounds_checking"
    NULL_CHECKING = "null_checking"
    FORMAT_VALIDATION = "format_validation"
    RANGE_VALIDATION = "range_validation"


class ParameterType(Enum):
    """Types of function parameters"""
    ADDRESS = "address"
    UINT = "uint"
    INT = "int"
    BYTES = "bytes"
    STRING = "string"
    ARRAY = "array"
    MAPPING = "mapping"
    STRUCT = "struct"
    ENUM = "enum"


@dataclass
class FunctionParameter:
    """Represents a function parameter"""
    name: str
    param_type: ParameterType
    data_type: str
    is_indexed: bool
    is_payable: bool
    has_validation: bool
    validation_type: Optional[ValidationType]
    line_number: int


@dataclass
class FunctionInfo:
    """Represents function information"""
    name: str
    parameters: List[FunctionParameter]
    visibility: str
    state_mutability: str
    is_external: bool
    is_public: bool
    is_payable: bool
    line_number: int
    has_input_validation: bool
    validation_score: float


@dataclass
class InputValidationVulnerability:
    """Represents an input validation vulnerability"""
    vulnerability_type: str
    severity: str
    description: str
    line_number: int
    code_snippet: str
    confidence: float
    swc_id: str
    recommendation: str
    parameter_name: str
    parameter_type: str


class InputValidationDetector:
    """Detects missing input validation in functions"""
    
    def __init__(self):
        self.validation_patterns = self._initialize_validation_patterns()
        self.decoding_patterns = self._initialize_decoding_patterns()
        self.bounds_patterns = self._initialize_bounds_patterns()
        self.sensitive_parameters = self._initialize_sensitive_parameters()
        # Move-inspired patterns
        self.token_validation_patterns = self._initialize_token_validation_patterns()
        self.identifier_validation_patterns = self._initialize_identifier_validation_patterns()
        self.signature_validation_patterns = self._initialize_signature_validation_patterns()
        self.zero_value_patterns = self._initialize_zero_value_patterns()
        
    def _initialize_validation_patterns(self) -> List[Dict[str, Any]]:
        """Initialize patterns for validation detection"""
        return [
            {
                'pattern': r'require\s*\(\s*(\w+)\s*!=\s*address\s*\(\s*0\s*\)\s*\)',
                'description': 'Address zero validation',
                'type': ValidationType.NULL_CHECKING
            },
            {
                'pattern': r'require\s*\(\s*(\w+)\s*!=\s*0\s*\)',
                'description': 'Zero value validation',
                'type': ValidationType.NULL_CHECKING
            },
            {
                'pattern': r'require\s*\(\s*(\w+)\s*>\s*0\s*\)',
                'description': 'Positive value validation',
                'type': ValidationType.RANGE_VALIDATION
            },
            {
                'pattern': r'require\s*\(\s*(\w+)\s*<=\s*(\w+)\s*\)',
                'description': 'Upper bound validation',
                'type': ValidationType.BOUNDS_CHECKING
            },
            {
                'pattern': r'require\s*\(\s*(\w+)\s*>=\s*(\w+)\s*\)',
                'description': 'Lower bound validation',
                'type': ValidationType.BOUNDS_CHECKING
            },
            {
                'pattern': r'require\s*\(\s*(\w+)\.length\s*>\s*0\s*\)',
                'description': 'Array length validation',
                'type': ValidationType.BOUNDS_CHECKING
            },
            {
                'pattern': r'require\s*\(\s*(\w+)\.length\s*<=\s*(\w+)\s*\)',
                'description': 'Array length upper bound validation',
                'type': ValidationType.BOUNDS_CHECKING
            }
        ]
    
    def _initialize_decoding_patterns(self) -> List[Dict[str, Any]]:
        """Initialize patterns for data decoding detection"""
        return [
            {
                'pattern': r'abi\.decode\s*\(\s*([^,]+),\s*\([^)]+\)\s*\)',
                'description': 'ABI decode operation',
                'risk_level': 'high'
            },
            {
                'pattern': r'abi\.encode\s*\(\s*([^)]+)\s*\)',
                'description': 'ABI encode operation',
                'risk_level': 'medium'
            },
            {
                'pattern': r'bytes\s+(\w+)\s*=\s*msg\.data',
                'description': 'Direct msg.data assignment',
                'risk_level': 'high'
            },
            {
                'pattern': r'(\w+)\s*=\s*abi\.decode\s*\(\s*msg\.data\s*\[4:\],\s*\([^)]+\)\s*\)',
                'description': 'Direct msg.data decoding',
                'risk_level': 'critical'
            }
        ]
    
    def _initialize_bounds_patterns(self) -> List[Dict[str, Any]]:
        """Initialize patterns for bounds checking detection"""
        return [
            {
                'pattern': r'(\w+)\[(\w+)\]',
                'description': 'Array access without bounds checking',
                'risk_level': 'high'
            },
            {
                'pattern': r'(\w+)\.length',
                'description': 'Array length access',
                'risk_level': 'medium'
            },
            {
                'pattern': r'for\s*\(\s*(\w+)\s*=\s*0\s*;\s*\1\s*<\s*(\w+)\.length\s*;\s*\1\+\+\s*\)',
                'description': 'Array iteration without bounds checking',
                'risk_level': 'medium'
            }
        ]
    
    def _initialize_sensitive_parameters(self) -> Set[str]:
        """Initialize list of sensitive parameter names"""
        return {
            'amount', 'value', 'balance', 'price', 'rate', 'fee', 'cost', 'total',
            'sender', 'recipient', 'to', 'from', 'owner', 'admin', 'user', 'account',
            'token', 'contract', 'address', 'id', 'index', 'key', 'data', 'input',
            # Move-inspired additions
            'tokenA', 'tokenB', 'coinType', 'assetType', 'poolId', 'vaultId',
            'orderId', 'positionId', 'signature', 'nonce', 'deadline'
        }
    
    def _initialize_token_validation_patterns(self) -> List[Dict[str, Any]]:
        """Initialize patterns for token address validation (Move-inspired)"""
        return [
            {
                'pattern': r'function\s+\w+\s*\([^)]*address\s+(\w*[Tt]oken\w*)[^)]*\)',
                'description': 'Token address parameter without validation',
                'risk_level': 'critical',
                'recommendation': 'Validate token address is not zero and matches expected token type'
            },
            {
                'pattern': r'function\s+\w+\s*\([^)]*address\s+(\w*[Aa]sset\w*)[^)]*\)',
                'description': 'Asset address parameter without validation',
                'risk_level': 'critical',
                'recommendation': 'Validate asset address matches pool configuration'
            },
            {
                'pattern': r'IERC20\s*\(\s*(\w+)\s*\)',
                'description': 'Token contract cast without validation',
                'risk_level': 'high',
                'recommendation': 'Validate token address before casting to IERC20'
            }
        ]
    
    def _initialize_identifier_validation_patterns(self) -> List[Dict[str, Any]]:
        """Initialize patterns for identifier validation (Move UID-inspired)"""
        return [
            {
                'pattern': r'function\s+\w+\s*\([^)]*uint256\s+(\w*[Ii]d\w*)[^)]*\)',
                'description': 'ID parameter without validation',
                'risk_level': 'high',
                'recommendation': 'Validate ID matches expected resource/entity'
            },
            {
                'pattern': r'mapping\s*\([^)]+\)\s+public\s+\w+;\s*.*?function\s+\w+\([^)]*uint256\s+id[^)]*\)',
                'description': 'Function uses ID to access mapping without existence check',
                'risk_level': 'high',
                'recommendation': 'Add require(mapping[id] exists) before access'
            }
        ]
    
    def _initialize_signature_validation_patterns(self) -> List[Dict[str, Any]]:
        """Initialize patterns for signature validation (Move-inspired)"""
        return [
            {
                'pattern': r'function\s+\w+\s*\([^)]*bytes\s+(memory\s+)?signature[^)]*\)',
                'description': 'Signature parameter without length validation',
                'risk_level': 'high',
                'recommendation': 'Validate signature.length == 65 for ECDSA signatures'
            },
            {
                'pattern': r'ecrecover\s*\([^)]*signature',
                'description': 'ecrecover usage without signature length check',
                'risk_level': 'high',
                'recommendation': 'Validate signature length before ecrecover to prevent malleability'
            }
        ]
    
    def _initialize_zero_value_patterns(self) -> List[Dict[str, Any]]:
        """Initialize patterns for zero value checks in critical operations"""
        return [
            {
                'pattern': r'function\s+(mint|deposit|stake|lock)\s*\([^)]*uint256\s+amount[^)]*\)',
                'description': 'Critical deposit/mint function without zero amount check',
                'risk_level': 'medium',
                'recommendation': 'Add require(amount > 0) to prevent zero-value operations'
            },
            {
                'pattern': r'\.transfer\s*\(\s*\w+\s*,\s*(\w+)\s*\)',
                'description': 'Token transfer without zero amount validation',
                'risk_level': 'medium',
                'recommendation': 'Validate transfer amount > 0 to prevent wasted gas'
            }
        ]
    
    def analyze_input_validation(self, contract_content: str) -> List[InputValidationVulnerability]:
        """Analyze input validation patterns"""
        vulnerabilities = []
        
        # Split content into lines for line number tracking
        lines = contract_content.split('\n')
        
        # Detect missing input validation
        vulnerabilities.extend(self._detect_missing_input_validation(contract_content, lines))
        
        # Detect arbitrary data decoding without validation
        vulnerabilities.extend(self._detect_unvalidated_decoding(contract_content, lines))
        
        # Detect bounds checking issues
        vulnerabilities.extend(self._detect_bounds_checking_issues(contract_content, lines))
        
        # Detect parameter validation issues
        vulnerabilities.extend(self._detect_parameter_validation_issues(contract_content, lines))
        
        # Move-inspired detections
        vulnerabilities.extend(self._detect_token_validation_issues(contract_content, lines))
        vulnerabilities.extend(self._detect_identifier_validation_issues(contract_content, lines))
        vulnerabilities.extend(self._detect_signature_validation_issues(contract_content, lines))
        vulnerabilities.extend(self._detect_zero_value_issues(contract_content, lines))
        
        # NEW: Detect missing zero-address validation in admin setter functions
        vulnerabilities.extend(self._detect_admin_setter_zero_address_issues(contract_content, lines))
        
        return vulnerabilities
    
    def _detect_admin_setter_zero_address_issues(self, contract_content: str, lines: List[str]) -> List[InputValidationVulnerability]:
        """
        Detect admin setter functions that set address parameters without zero-address validation.
        
        This addresses the issue found in ADI-Stack-Contracts Bridgehub.sol setAddresses() 
        where critical addresses were set without checking for address(0).
        """
        vulnerabilities = []
        
        # Pattern for setter functions that set addresses with admin modifiers
        # Matches: function setX(...address _param...) external onlyOwner/onlyAdmin
        setter_pattern = r'function\s+(set\w+|update\w+|change\w+|configure\w+)\s*\(([^)]*)\)\s*([^{]*)\{'
        
        # Admin modifier patterns
        admin_modifiers = [
            'onlyOwner', 'onlyAdmin', 'onlyRole', 'onlyGovernance',
            'onlyOwnerOrAdmin', 'onlyOperator', 'onlyManager', 'authorized'
        ]
        
        for match in re.finditer(setter_pattern, contract_content, re.IGNORECASE | re.DOTALL):
            func_name = match.group(1)
            params_str = match.group(2)
            modifiers_str = match.group(3)
            func_start = match.start()
            line_number = self._get_line_number(func_start, contract_content)
            
            # Check if this function has admin modifiers
            has_admin_modifier = any(mod in modifiers_str for mod in admin_modifiers)
            
            # Check if function is external or public
            is_external = 'external' in modifiers_str or 'public' in modifiers_str
            
            if not is_external:
                continue
            
            # Extract address parameters from the function signature
            address_params = re.findall(r'(?:address|I\w+)\s+(\w+)', params_str)
            
            if not address_params:
                continue
            
            # Get function body to check for zero-address validation
            func_body = self._get_function_content(contract_content, line_number)
            if not func_body:
                continue
            
            # Check each address parameter for zero-address validation
            for param in address_params:
                has_zero_check = self._has_zero_address_check(func_body, param)
                
                if not has_zero_check:
                    # Determine severity based on admin modifier presence
                    severity = 'low' if has_admin_modifier else 'medium'
                    
                    # Determine confidence based on context
                    confidence = 0.85 if has_admin_modifier else 0.75
                    
                    # Extract code snippet
                    snippet_end = min(func_start + 200, len(contract_content))
                    code_snippet = contract_content[func_start:snippet_end].strip()
                    
                    vulnerability = InputValidationVulnerability(
                        vulnerability_type='missing_zero_address_check',
                        severity=severity,
                        description=f'Admin function {func_name}() sets address parameter "{param}" without zero-address validation. '
                                    f'If called with address(0), it could brick the contract functionality.',
                        line_number=line_number,
                        code_snippet=code_snippet[:150] + '...' if len(code_snippet) > 150 else code_snippet,
                        confidence=confidence,
                        swc_id='SWC-123',
                        recommendation=f'Add validation: require({param} != address(0), "{func_name}: zero address");',
                        parameter_name=param,
                        parameter_type='address'
                    )
                    vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _has_zero_address_check(self, func_body: str, param_name: str) -> bool:
        """
        Check if a function body contains zero-address validation for a parameter.
        
        Looks for patterns like:
        - require(param != address(0))
        - if (param == address(0)) revert
        - revert ZeroAddress() style custom errors
        """
        if not func_body:
            return False
        
        # Normalize whitespace for matching
        func_body_normalized = ' '.join(func_body.split())
        
        # Check for various zero-address validation patterns
        zero_check_patterns = [
            # require(param != address(0))
            rf'require\s*\(\s*{re.escape(param_name)}\s*!=\s*address\s*\(\s*0\s*\)',
            rf'require\s*\(\s*address\s*\(\s*{re.escape(param_name)}\s*\)\s*!=\s*address\s*\(\s*0\s*\)',
            # if (param == address(0)) revert
            rf'if\s*\(\s*{re.escape(param_name)}\s*==\s*address\s*\(\s*0\s*\)',
            rf'if\s*\(\s*address\s*\(\s*{re.escape(param_name)}\s*\)\s*==\s*address\s*\(\s*0\s*\)',
            # Custom error reverts with ZeroAddress
            rf'{re.escape(param_name)}.*ZeroAddress',
            rf'ZeroAddress.*{re.escape(param_name)}',
            # General zero address check on the parameter
            rf'require\s*\([^)]*{re.escape(param_name)}[^)]*!=\s*address\s*\(\s*0\s*\)',
            # != address(0x0) variant
            rf'{re.escape(param_name)}\s*!=\s*address\s*\(\s*0x0\s*\)',
        ]
        
        for pattern in zero_check_patterns:
            if re.search(pattern, func_body_normalized, re.IGNORECASE):
                return True
        
        return False
    
    def _detect_missing_input_validation(self, contract_content: str, lines: List[str]) -> List[InputValidationVulnerability]:
        """Detect missing input validation in functions"""
        vulnerabilities = []
        
        # Find all function declarations
        functions = self._find_function_declarations(contract_content)
        
        for function in functions:
            # Analyze function parameters
            for parameter in function.parameters:
                if not parameter.has_validation and self._is_sensitive_parameter(parameter):
                    vulnerability = InputValidationVulnerability(
                        vulnerability_type='missing_input_validation',
                        severity=self._get_validation_severity(parameter),
                        description=f'Missing input validation for parameter {parameter.name} in function {function.name}',
                        line_number=parameter.line_number,
                        code_snippet=self._get_function_snippet(contract_content, function.line_number),
                        confidence=self._calculate_validation_confidence(parameter, function),
                        swc_id='SWC-120',
                        recommendation=self._get_validation_recommendation(parameter),
                        parameter_name=parameter.name,
                        parameter_type=parameter.data_type
                    )
                    vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _detect_unvalidated_decoding(self, contract_content: str, lines: List[str]) -> List[InputValidationVulnerability]:
        """Detect arbitrary data decoding without validation"""
        vulnerabilities = []
        
        for pattern_info in self.decoding_patterns:
            pattern = pattern_info['pattern']
            matches = re.finditer(pattern, contract_content, re.MULTILINE)
            
            for match in matches:
                line_number = self._get_line_number(match.start(), contract_content)
                code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""
                
                # Check if this is a false positive
                if self._is_false_positive_decoding(match, code_snippet):
                    continue
                
                # Check if there's validation nearby
                has_validation = self._has_validation_nearby(contract_content, line_number)
                
                if not has_validation:
                    vulnerability = InputValidationVulnerability(
                        vulnerability_type='unvalidated_decoding',
                        severity=pattern_info['risk_level'],
                        description=pattern_info['description'],
                        line_number=line_number,
                        code_snippet=code_snippet,
                        confidence=self._calculate_decoding_confidence(match, code_snippet),
                        swc_id='SWC-120',
                        recommendation='Add input validation before decoding operations',
                        parameter_name='data',
                        parameter_type='bytes'
                    )
                    vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _detect_bounds_checking_issues(self, contract_content: str, lines: List[str]) -> List[InputValidationVulnerability]:
        """Detect bounds checking issues"""
        vulnerabilities = []
        
        for pattern_info in self.bounds_patterns:
            pattern = pattern_info['pattern']
            matches = re.finditer(pattern, contract_content, re.MULTILINE)
            
            for match in matches:
                line_number = self._get_line_number(match.start(), contract_content)
                code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""
                
                # Check if this is a false positive
                if self._is_false_positive_bounds(match, code_snippet):
                    continue
                
                # Check if there's bounds checking
                has_bounds_checking = self._has_bounds_checking(contract_content, line_number, match)
                
                if not has_bounds_checking:
                    vulnerability = InputValidationVulnerability(
                        vulnerability_type='bounds_checking_issue',
                        severity=pattern_info['risk_level'],
                        description=pattern_info['description'],
                        line_number=line_number,
                        code_snippet=code_snippet,
                        confidence=self._calculate_bounds_confidence(match, code_snippet),
                        swc_id='SWC-120',
                        recommendation='Add bounds checking before array access',
                        parameter_name=match.group(1) if len(match.groups()) > 0 else 'array',
                        parameter_type='array'
                    )
                    vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _detect_parameter_validation_issues(self, contract_content: str, lines: List[str]) -> List[InputValidationVulnerability]:
        """Detect parameter validation issues"""
        vulnerabilities = []
        
        # Find all function declarations
        functions = self._find_function_declarations(contract_content)
        
        for function in functions:
            # Check if function is external/public and has sensitive parameters
            if (function.is_external or function.is_public) and function.parameters:
                for parameter in function.parameters:
                    if self._is_sensitive_parameter(parameter) and not parameter.has_validation:
                        # Check if parameter is used in critical operations
                        if self._is_parameter_used_critically(contract_content, function, parameter):
                            vulnerability = InputValidationVulnerability(
                                vulnerability_type='parameter_validation_issue',
                                severity='high',
                                description=f'Sensitive parameter {parameter.name} in {function.visibility} function {function.name} without validation',
                                line_number=parameter.line_number,
                                code_snippet=self._get_function_snippet(contract_content, function.line_number),
                                confidence=0.8,
                                swc_id='SWC-120',
                                recommendation=f'Add validation for parameter {parameter.name}',
                                parameter_name=parameter.name,
                                parameter_type=parameter.data_type
                            )
                            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _find_function_declarations(self, contract_content: str) -> List[FunctionInfo]:
        """Find all function declarations in contract"""
        functions = []
        
        # Pattern for function declarations
        function_pattern = r'function\s+(\w+)\s*\(([^)]*)\)\s*(?:external|public|internal|private)?\s*(?:payable|view|pure)?'
        matches = re.finditer(function_pattern, contract_content, re.MULTILINE)
        
        for match in matches:
            function_name = match.group(1)
            parameters_str = match.group(2)
            line_number = self._get_line_number(match.start(), contract_content)
            
            # Parse parameters
            parameters = self._parse_function_parameters(parameters_str, line_number)
            
            # Determine function properties
            is_external = 'external' in match.group(0)
            is_public = 'public' in match.group(0)
            is_payable = 'payable' in match.group(0)
            
            # Check for input validation
            has_input_validation = self._has_input_validation_in_function(contract_content, line_number)
            validation_score = self._calculate_validation_score(parameters, has_input_validation)
            
            function_info = FunctionInfo(
                name=function_name,
                parameters=parameters,
                visibility='external' if is_external else 'public' if is_public else 'internal',
                state_mutability='payable' if is_payable else 'nonpayable',
                is_external=is_external,
                is_public=is_public,
                is_payable=is_payable,
                line_number=line_number,
                has_input_validation=has_input_validation,
                validation_score=validation_score
            )
            
            functions.append(function_info)
        
        return functions
    
    def _parse_function_parameters(self, parameters_str: str, line_number: int) -> List[FunctionParameter]:
        """Parse function parameters"""
        parameters = []
        
        if not parameters_str.strip():
            return parameters
        
        # Split parameters by comma
        param_parts = [part.strip() for part in parameters_str.split(',')]
        
        for param_part in param_parts:
            if param_part:
                # Parse parameter type and name
                param_match = re.match(r'(\w+)\s+(\w+)', param_part)
                if param_match:
                    data_type = param_match.group(1)
                    param_name = param_match.group(2)
                    
                    # Determine parameter type
                    param_type = self._get_parameter_type(data_type)
                    
                    # Check if parameter has validation
                    has_validation = self._parameter_has_validation(param_name, data_type)
                    validation_type = self._get_validation_type(param_name, data_type) if has_validation else None
                    
                    parameter = FunctionParameter(
                        name=param_name,
                        param_type=param_type,
                        data_type=data_type,
                        is_indexed=False,
                        is_payable=False,
                        has_validation=has_validation,
                        validation_type=validation_type,
                        line_number=line_number
                    )
                    
                    parameters.append(parameter)
        
        return parameters
    
    def _get_parameter_type(self, data_type: str) -> ParameterType:
        """Get parameter type from data type"""
        if data_type.startswith('address'):
            return ParameterType.ADDRESS
        elif data_type.startswith('uint'):
            return ParameterType.UINT
        elif data_type.startswith('int'):
            return ParameterType.INT
        elif data_type.startswith('bytes'):
            return ParameterType.BYTES
        elif data_type == 'string':
            return ParameterType.STRING
        elif '[]' in data_type:
            return ParameterType.ARRAY
        elif data_type.startswith('mapping'):
            return ParameterType.MAPPING
        else:
            return ParameterType.STRUCT
    
    def _parameter_has_validation(self, param_name: str, data_type: str) -> bool:
        """Check if parameter has validation"""
        # This would need to be implemented based on the contract content
        # For now, return False as a placeholder
        return False
    
    def _get_validation_type(self, param_name: str, data_type: str) -> Optional[ValidationType]:
        """Get validation type for parameter"""
        # This would need to be implemented based on the contract content
        # For now, return None as a placeholder
        return None
    
    def _is_sensitive_parameter(self, parameter: FunctionParameter) -> bool:
        """Check if parameter is sensitive"""
        return (parameter.name.lower() in self.sensitive_parameters or
                parameter.param_type in [ParameterType.ADDRESS, ParameterType.UINT, ParameterType.BYTES])
    
    def _is_parameter_used_critically(self, contract_content: str, function: FunctionInfo, parameter: FunctionParameter) -> bool:
        """Check if parameter is used in critical operations"""
        # Find function content
        function_content = self._get_function_content(contract_content, function.line_number)
        
        if function_content:
            # Check for critical operations
            critical_patterns = [
                r'\.transfer\s*\(',
                r'\.send\s*\(',
                r'\.call\s*\(',
                r'\.delegatecall\s*\(',
                r'\.staticcall\s*\(',
                r'=\s*[^;]+;',  # Assignment
                r'require\s*\(',
                r'assert\s*\('
            ]
            
            for pattern in critical_patterns:
                if re.search(pattern, function_content):
                    return True
        
        return False
    
    def _has_input_validation_in_function(self, contract_content: str, line_number: int) -> bool:
        """Check if function has input validation"""
        # Find function content
        function_content = self._get_function_content(contract_content, line_number)
        
        if function_content:
            # Check for validation patterns
            for pattern_info in self.validation_patterns:
                if re.search(pattern_info['pattern'], function_content):
                    return True
        
        return False
    
    def _calculate_validation_score(self, parameters: List[FunctionParameter], has_input_validation: bool) -> float:
        """Calculate validation score for function"""
        if not parameters:
            return 1.0
        
        validated_params = sum(1 for param in parameters if param.has_validation)
        score = validated_params / len(parameters)
        
        if has_input_validation:
            score += 0.2
        
        return min(score, 1.0)
    
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
    
    def _get_function_snippet(self, contract_content: str, line_number: int) -> str:
        """Get function snippet"""
        lines = contract_content.split('\n')
        
        if line_number <= len(lines):
            return lines[line_number - 1].strip()
        
        return ""
    
    def _is_false_positive_decoding(self, match: re.Match, code_snippet: str) -> bool:
        """Check if decoding detection is a false positive"""
        # Skip if there's explicit validation
        if 'require(' in code_snippet or 'assert(' in code_snippet:
            return True
        
        # Skip if using SafeMath or similar libraries
        if 'SafeMath' in code_snippet or 'safe' in code_snippet.lower():
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
    
    def _has_bounds_checking(self, contract_content: str, line_number: int, match: re.Match) -> bool:
        """Check if there's bounds checking"""
        lines = contract_content.split('\n')
        
        # Check lines before the access
        start_line = max(0, line_number - 10)
        end_line = line_number
        
        for i in range(start_line, end_line):
            if i < len(lines):
                line = lines[i]
                # Check for bounds checking patterns
                if 'require(' in line and ('length' in line or '<' in line or '>' in line):
                    return True
        
        return False
    
    def _calculate_validation_confidence(self, parameter: FunctionParameter, function: FunctionInfo) -> float:
        """Calculate confidence score for validation detection"""
        confidence = 0.5  # Base confidence
        
        # Increase confidence for sensitive parameters
        if self._is_sensitive_parameter(parameter):
            confidence += 0.2
        
        # Increase confidence for external/public functions
        if function.is_external or function.is_public:
            confidence += 0.2
        
        # Increase confidence for payable functions
        if function.is_payable:
            confidence += 0.1
        
        return min(confidence, 1.0)
    
    def _calculate_decoding_confidence(self, match: re.Match, code_snippet: str) -> float:
        """Calculate confidence score for decoding detection"""
        confidence = 0.6  # Base confidence
        
        # Increase confidence if no validation
        if 'require(' not in code_snippet and 'assert(' not in code_snippet:
            confidence += 0.3
        
        # Increase confidence if using msg.data
        if 'msg.data' in code_snippet:
            confidence += 0.1
        
        return min(confidence, 1.0)
    
    def _calculate_bounds_confidence(self, match: re.Match, code_snippet: str) -> float:
        """Calculate confidence score for bounds detection"""
        confidence = 0.5  # Base confidence
        
        # Increase confidence if no bounds checking
        if 'require(' not in code_snippet or 'length' not in code_snippet:
            confidence += 0.3
        
        # Increase confidence for array access
        if '[' in code_snippet and ']' in code_snippet:
            confidence += 0.2
        
        return min(confidence, 1.0)
    
    def _get_validation_severity(self, parameter: FunctionParameter) -> str:
        """Get validation severity for parameter"""
        if parameter.param_type in [ParameterType.ADDRESS, ParameterType.BYTES]:
            return 'high'
        elif parameter.param_type in [ParameterType.UINT, ParameterType.INT]:
            return 'medium'
        else:
            return 'low'
    
    def _get_validation_recommendation(self, parameter: FunctionParameter) -> str:
        """Get validation recommendation for parameter"""
        if parameter.param_type == ParameterType.ADDRESS:
            return f'Add address validation: require({parameter.name} != address(0))'
        elif parameter.param_type in [ParameterType.UINT, ParameterType.INT]:
            return f'Add range validation: require({parameter.name} > 0)'
        elif parameter.param_type == ParameterType.BYTES:
            return f'Add length validation: require({parameter.name}.length > 0)'
        else:
            return f'Add validation for parameter {parameter.name}'
    
    def _detect_token_validation_issues(self, contract_content: str, lines: List[str]) -> List[InputValidationVulnerability]:
        """Detect missing token address validation (Move-inspired)"""
        vulnerabilities = []
        
        for pattern_info in self.token_validation_patterns:
            pattern = pattern_info['pattern']
            matches = re.finditer(pattern, contract_content, re.MULTILINE)
            
            for match in matches:
                line_number = self._get_line_number(match.start(), contract_content)
                code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""
                
                # Get function content to check for validation
                function_content = self._get_function_content(contract_content, line_number)
                if not function_content:
                    continue
                
                # Check if token validation exists
                has_validation = (
                    'require(' in function_content and 
                    ('!= address(0)' in function_content or 'token' in function_content.lower())
                )
                
                if not has_validation:
                    vulnerability = InputValidationVulnerability(
                        vulnerability_type='missing_token_validation',
                        severity=pattern_info['risk_level'],
                        description=pattern_info['description'],
                        line_number=line_number,
                        code_snippet=code_snippet,
                        confidence=0.75,
                        swc_id='SWC-120',
                        recommendation=pattern_info['recommendation'],
                        parameter_name=match.group(1) if len(match.groups()) > 0 else 'token',
                        parameter_type='address'
                    )
                    vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _detect_identifier_validation_issues(self, contract_content: str, lines: List[str]) -> List[InputValidationVulnerability]:
        """Detect missing identifier/ID validation (Move UID-inspired)"""
        vulnerabilities = []
        
        for pattern_info in self.identifier_validation_patterns:
            pattern = pattern_info['pattern']
            matches = re.finditer(pattern, contract_content, re.MULTILINE)
            
            for match in matches:
                line_number = self._get_line_number(match.start(), contract_content)
                code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""
                
                # Get function content to check for validation
                function_content = self._get_function_content(contract_content, line_number)
                if not function_content:
                    continue
                
                # Check if ID validation exists (e.g., require(id < maxId) or require(exists[id]))
                has_validation = (
                    'require(' in function_content and 
                    ('id' in function_content.lower() or 'exists' in function_content.lower())
                )
                
                if not has_validation:
                    vulnerability = InputValidationVulnerability(
                        vulnerability_type='missing_identifier_validation',
                        severity=pattern_info['risk_level'],
                        description=pattern_info['description'],
                        line_number=line_number,
                        code_snippet=code_snippet,
                        confidence=0.7,
                        swc_id='SWC-120',
                        recommendation=pattern_info['recommendation'],
                        parameter_name=match.group(1) if len(match.groups()) > 0 else 'id',
                        parameter_type='uint256'
                    )
                    vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _detect_signature_validation_issues(self, contract_content: str, lines: List[str]) -> List[InputValidationVulnerability]:
        """Detect missing signature validation (Move-inspired)"""
        vulnerabilities = []
        
        for pattern_info in self.signature_validation_patterns:
            pattern = pattern_info['pattern']
            matches = re.finditer(pattern, contract_content, re.MULTILINE)
            
            for match in matches:
                line_number = self._get_line_number(match.start(), contract_content)
                code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""
                
                # Get function content to check for signature length validation
                function_content = self._get_function_content(contract_content, line_number)
                if not function_content:
                    continue
                
                # Check if signature length validation exists
                has_validation = (
                    'require(' in function_content and 
                    ('signature.length' in function_content or '.length == 65' in function_content)
                )
                
                if not has_validation:
                    vulnerability = InputValidationVulnerability(
                        vulnerability_type='missing_signature_validation',
                        severity=pattern_info['risk_level'],
                        description=pattern_info['description'],
                        line_number=line_number,
                        code_snippet=code_snippet,
                        confidence=0.8,
                        swc_id='SWC-117',
                        recommendation=pattern_info['recommendation'],
                        parameter_name='signature',
                        parameter_type='bytes'
                    )
                    vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _detect_zero_value_issues(self, contract_content: str, lines: List[str]) -> List[InputValidationVulnerability]:
        """Detect missing zero value checks for critical operations"""
        vulnerabilities = []
        
        for pattern_info in self.zero_value_patterns:
            pattern = pattern_info['pattern']
            matches = re.finditer(pattern, contract_content, re.MULTILINE)
            
            for match in matches:
                line_number = self._get_line_number(match.start(), contract_content)
                code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""
                
                # Get function content to check for zero value validation
                function_content = self._get_function_content(contract_content, line_number)
                if not function_content:
                    continue
                
                # Check if zero value check exists
                has_validation = (
                    'require(' in function_content and 
                    ('> 0' in function_content or '!= 0' in function_content or 'amount' in function_content)
                )
                
                if not has_validation:
                    vulnerability = InputValidationVulnerability(
                        vulnerability_type='missing_zero_value_check',
                        severity=pattern_info['risk_level'],
                        description=pattern_info['description'],
                        line_number=line_number,
                        code_snippet=code_snippet,
                        confidence=0.65,
                        swc_id='SWC-120',
                        recommendation=pattern_info['recommendation'],
                        parameter_name='amount',
                        parameter_type='uint256'
                    )
                    vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _get_line_number(self, position: int, content: str) -> int:
        """Get line number from character position"""
        return content[:position].count('\n') + 1
    
    def get_input_validation_summary(self, contract_content: str) -> Dict[str, Any]:
        """Get summary of input validation in contract"""
        functions = self._find_function_declarations(contract_content)
        
        summary = {
            'total_functions': len(functions),
            'functions_with_validation': len([f for f in functions if f.has_input_validation]),
            'external_functions': len([f for f in functions if f.is_external]),
            'public_functions': len([f for f in functions if f.is_public]),
            'payable_functions': len([f for f in functions if f.is_payable]),
            'average_validation_score': sum(f.validation_score for f in functions) / len(functions) if functions else 0,
            'sensitive_parameters': sum(len([p for p in f.parameters if self._is_sensitive_parameter(p)]) for f in functions),
            'unvalidated_sensitive_parameters': sum(len([p for p in f.parameters if self._is_sensitive_parameter(p) and not p.has_validation]) for f in functions)
        }
        
        return summary
