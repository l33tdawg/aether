"""
Contract Interface Validator for Smart Contract Security

This module validates external contract interfaces, detects interface mismatches,
and analyzes external contract call safety.
"""

import re
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum


class InterfaceType(Enum):
    """Types of contract interfaces"""
    ERC20 = "ERC20"
    ERC721 = "ERC721"
    ERC1155 = "ERC1155"
    CUSTOM = "custom"
    UNKNOWN = "unknown"


class ValidationResult(Enum):
    """Validation results"""
    VALID = "valid"
    INVALID = "invalid"
    WARNING = "warning"
    ERROR = "error"


@dataclass
class InterfaceFunction:
    """Represents a function in an interface"""
    name: str
    parameters: List[str]
    return_types: List[str]
    visibility: str
    state_mutability: str
    is_payable: bool
    is_view: bool
    is_pure: bool


@dataclass
class InterfaceValidation:
    """Represents interface validation result"""
    interface_type: InterfaceType
    validation_result: ValidationResult
    issues: List[str]
    warnings: List[str]
    recommendations: List[str]
    confidence: float


@dataclass
class InterfaceMismatch:
    """Represents an interface mismatch"""
    mismatch_type: str
    severity: str
    description: str
    line_number: int
    code_snippet: str
    confidence: float
    swc_id: str
    recommendation: str
    expected_interface: str
    actual_interface: str


class ContractInterfaceValidator:
    """Validates external contract interfaces and detects mismatches"""
    
    def __init__(self):
        self.interface_patterns = self._initialize_interface_patterns()
        self.erc20_interface = self._initialize_erc20_interface()
        self.erc721_interface = self._initialize_erc721_interface()
        self.erc1155_interface = self._initialize_erc1155_interface()
        self.known_interfaces = self._initialize_known_interfaces()
        
    def _initialize_interface_patterns(self) -> List[Dict[str, Any]]:
        """Initialize patterns for interface analysis"""
        return [
            {
                'pattern': r'interface\s+(\w+)\s*\{',
                'description': 'Interface declaration',
                'type': 'interface_declaration'
            },
            {
                'pattern': r'(\w+)\s*=\s*I(\w+)\([^)]*\)',
                'description': 'Interface instantiation',
                'type': 'interface_instantiation'
            },
            {
                'pattern': r'(\w+)\.(\w+)\s*\([^)]*\)',
                'description': 'Interface function call',
                'type': 'interface_call'
            }
        ]
    
    def _initialize_erc20_interface(self) -> Dict[str, InterfaceFunction]:
        """Initialize ERC20 interface functions"""
        return {
            'totalSupply': InterfaceFunction(
                name='totalSupply',
                parameters=[],
                return_types=['uint256'],
                visibility='external',
                state_mutability='view',
                is_payable=False,
                is_view=True,
                is_pure=False
            ),
            'balanceOf': InterfaceFunction(
                name='balanceOf',
                parameters=['address'],
                return_types=['uint256'],
                visibility='external',
                state_mutability='view',
                is_payable=False,
                is_view=True,
                is_pure=False
            ),
            'transfer': InterfaceFunction(
                name='transfer',
                parameters=['address', 'uint256'],
                return_types=['bool'],
                visibility='external',
                state_mutability='nonpayable',
                is_payable=False,
                is_view=False,
                is_pure=False
            ),
            'transferFrom': InterfaceFunction(
                name='transferFrom',
                parameters=['address', 'address', 'uint256'],
                return_types=['bool'],
                visibility='external',
                state_mutability='nonpayable',
                is_payable=False,
                is_view=False,
                is_pure=False
            ),
            'approve': InterfaceFunction(
                name='approve',
                parameters=['address', 'uint256'],
                return_types=['bool'],
                visibility='external',
                state_mutability='nonpayable',
                is_payable=False,
                is_view=False,
                is_pure=False
            ),
            'allowance': InterfaceFunction(
                name='allowance',
                parameters=['address', 'address'],
                return_types=['uint256'],
                visibility='external',
                state_mutability='view',
                is_payable=False,
                is_view=True,
                is_pure=False
            )
        }
    
    def _initialize_erc721_interface(self) -> Dict[str, InterfaceFunction]:
        """Initialize ERC721 interface functions"""
        return {
            'balanceOf': InterfaceFunction(
                name='balanceOf',
                parameters=['address'],
                return_types=['uint256'],
                visibility='external',
                state_mutability='view',
                is_payable=False,
                is_view=True,
                is_pure=False
            ),
            'ownerOf': InterfaceFunction(
                name='ownerOf',
                parameters=['uint256'],
                return_types=['address'],
                visibility='external',
                state_mutability='view',
                is_payable=False,
                is_view=True,
                is_pure=False
            ),
            'safeTransferFrom': InterfaceFunction(
                name='safeTransferFrom',
                parameters=['address', 'address', 'uint256'],
                return_types=[],
                visibility='external',
                state_mutability='nonpayable',
                is_payable=False,
                is_view=False,
                is_pure=False
            ),
            'transferFrom': InterfaceFunction(
                name='transferFrom',
                parameters=['address', 'address', 'uint256'],
                return_types=[],
                visibility='external',
                state_mutability='nonpayable',
                is_payable=False,
                is_view=False,
                is_pure=False
            ),
            'approve': InterfaceFunction(
                name='approve',
                parameters=['address', 'uint256'],
                return_types=[],
                visibility='external',
                state_mutability='nonpayable',
                is_payable=False,
                is_view=False,
                is_pure=False
            ),
            'setApprovalForAll': InterfaceFunction(
                name='setApprovalForAll',
                parameters=['address', 'bool'],
                return_types=[],
                visibility='external',
                state_mutability='nonpayable',
                is_payable=False,
                is_view=False,
                is_pure=False
            ),
            'getApproved': InterfaceFunction(
                name='getApproved',
                parameters=['uint256'],
                return_types=['address'],
                visibility='external',
                state_mutability='view',
                is_payable=False,
                is_view=True,
                is_pure=False
            ),
            'isApprovedForAll': InterfaceFunction(
                name='isApprovedForAll',
                parameters=['address', 'address'],
                return_types=['bool'],
                visibility='external',
                state_mutability='view',
                is_payable=False,
                is_view=True,
                is_pure=False
            )
        }
    
    def _initialize_erc1155_interface(self) -> Dict[str, InterfaceFunction]:
        """Initialize ERC1155 interface functions"""
        return {
            'balanceOf': InterfaceFunction(
                name='balanceOf',
                parameters=['address', 'uint256'],
                return_types=['uint256'],
                visibility='external',
                state_mutability='view',
                is_payable=False,
                is_view=True,
                is_pure=False
            ),
            'balanceOfBatch': InterfaceFunction(
                name='balanceOfBatch',
                parameters=['address[]', 'uint256[]'],
                return_types=['uint256[]'],
                visibility='external',
                state_mutability='view',
                is_payable=False,
                is_view=True,
                is_pure=False
            ),
            'setApprovalForAll': InterfaceFunction(
                name='setApprovalForAll',
                parameters=['address', 'bool'],
                return_types=[],
                visibility='external',
                state_mutability='nonpayable',
                is_payable=False,
                is_view=False,
                is_pure=False
            ),
            'isApprovedForAll': InterfaceFunction(
                name='isApprovedForAll',
                parameters=['address', 'address'],
                return_types=['bool'],
                visibility='external',
                state_mutability='view',
                is_payable=False,
                is_view=True,
                is_pure=False
            ),
            'safeTransferFrom': InterfaceFunction(
                name='safeTransferFrom',
                parameters=['address', 'address', 'uint256', 'uint256', 'bytes'],
                return_types=[],
                visibility='external',
                state_mutability='nonpayable',
                is_payable=False,
                is_view=False,
                is_pure=False
            ),
            'safeBatchTransferFrom': InterfaceFunction(
                name='safeBatchTransferFrom',
                parameters=['address', 'address', 'uint256[]', 'uint256[]', 'bytes'],
                return_types=[],
                visibility='external',
                state_mutability='nonpayable',
                is_payable=False,
                is_view=False,
                is_pure=False
            )
        }
    
    def _initialize_known_interfaces(self) -> Dict[str, InterfaceType]:
        """Initialize known interface types"""
        return {
            'IERC20': InterfaceType.ERC20,
            'ERC20': InterfaceType.ERC20,
            'IERC721': InterfaceType.ERC721,
            'ERC721': InterfaceType.ERC721,
            'IERC1155': InterfaceType.ERC1155,
            'ERC1155': InterfaceType.ERC1155
        }
    
    def validate_external_interfaces(self, contract_content: str) -> List[InterfaceValidation]:
        """Validate external contract interfaces"""
        validations = []
        
        # Find interface declarations
        interface_declarations = self._find_interface_declarations(contract_content)
        
        # Find interface instantiations
        interface_instantiations = self._find_interface_instantiations(contract_content)
        
        # Find interface calls
        interface_calls = self._find_interface_calls(contract_content)
        
        # Validate each interface
        for interface_name, interface_type in interface_declarations.items():
            validation = self._validate_interface(interface_name, interface_type, contract_content)
            validations.append(validation)
        
        # Validate interface instantiations
        for instantiation in interface_instantiations:
            validation = self._validate_interface_instantiation(instantiation, contract_content)
            validations.append(validation)
        
        # Validate interface calls
        for call in interface_calls:
            validation = self._validate_interface_call(call, contract_content)
            validations.append(validation)
        
        return validations
    
    def _find_interface_declarations(self, contract_content: str) -> Dict[str, InterfaceType]:
        """Find interface declarations in contract"""
        interfaces = {}
        
        # Pattern for interface declarations
        interface_pattern = r'interface\s+(\w+)\s*\{'
        matches = re.finditer(interface_pattern, contract_content, re.MULTILINE)
        
        for match in matches:
            interface_name = match.group(1)
            interface_type = self.known_interfaces.get(interface_name, InterfaceType.CUSTOM)
            interfaces[interface_name] = interface_type
        
        return interfaces
    
    def _find_interface_instantiations(self, contract_content: str) -> List[Dict[str, Any]]:
        """Find interface instantiations in contract"""
        instantiations = []
        
        # Pattern for interface instantiations
        instantiation_pattern = r'(\w+)\s*=\s*I(\w+)\([^)]*\)'
        matches = re.finditer(instantiation_pattern, contract_content, re.MULTILINE)
        
        for match in matches:
            variable_name = match.group(1)
            interface_name = match.group(2)
            line_number = self._get_line_number(match.start(), contract_content)
            
            instantiations.append({
                'variable_name': variable_name,
                'interface_name': interface_name,
                'line_number': line_number,
                'code_snippet': match.group(0)
            })
        
        return instantiations
    
    def _find_interface_calls(self, contract_content: str) -> List[Dict[str, Any]]:
        """Find interface calls in contract"""
        calls = []
        
        # Pattern for interface calls
        call_pattern = r'(\w+)\.(\w+)\s*\([^)]*\)'
        matches = re.finditer(call_pattern, contract_content, re.MULTILINE)
        
        for match in matches:
            contract_name = match.group(1)
            function_name = match.group(2)
            line_number = self._get_line_number(match.start(), contract_content)
            
            calls.append({
                'contract_name': contract_name,
                'function_name': function_name,
                'line_number': line_number,
                'code_snippet': match.group(0)
            })
        
        return calls
    
    def _validate_interface(self, interface_name: str, interface_type: InterfaceType, contract_content: str) -> InterfaceValidation:
        """Validate a specific interface"""
        issues = []
        warnings = []
        recommendations = []
        
        # Extract interface content
        interface_content = self._extract_interface_content(contract_content, interface_name)
        
        if not interface_content:
            issues.append(f"Interface {interface_name} not found")
            return InterfaceValidation(
                interface_type=interface_type,
                validation_result=ValidationResult.ERROR,
                issues=issues,
                warnings=warnings,
                recommendations=recommendations,
                confidence=1.0
            )
        
        # Validate based on interface type
        if interface_type == InterfaceType.ERC20:
            issues.extend(self._validate_erc20_interface(interface_content))
        elif interface_type == InterfaceType.ERC721:
            issues.extend(self._validate_erc721_interface(interface_content))
        elif interface_type == InterfaceType.ERC1155:
            issues.extend(self._validate_erc1155_interface(interface_content))
        else:
            issues.extend(self._validate_custom_interface(interface_content))
        
        # Determine validation result
        if issues:
            validation_result = ValidationResult.ERROR
        elif warnings:
            validation_result = ValidationResult.WARNING
        else:
            validation_result = ValidationResult.VALID
        
        # Generate recommendations
        if issues:
            recommendations.append("Fix interface implementation issues")
        if warnings:
            recommendations.append("Review interface warnings")
        
        return InterfaceValidation(
            interface_type=interface_type,
            validation_result=validation_result,
            issues=issues,
            warnings=warnings,
            recommendations=recommendations,
            confidence=0.8
        )
    
    def _validate_interface_instantiation(self, instantiation: Dict[str, Any], contract_content: str) -> InterfaceValidation:
        """Validate interface instantiation"""
        issues = []
        warnings = []
        recommendations = []
        
        interface_name = instantiation['interface_name']
        variable_name = instantiation['variable_name']
        
        # Check if interface exists
        if interface_name not in self.known_interfaces:
            warnings.append(f"Unknown interface: {interface_name}")
        
        # Check if variable is properly typed
        variable_declaration = self._find_variable_declaration(contract_content, variable_name)
        if not variable_declaration:
            issues.append(f"Variable {variable_name} not properly declared")
        
        # Check for proper initialization
        if 'address(0)' in instantiation['code_snippet']:
            warnings.append(f"Interface {interface_name} initialized with zero address")
        
        validation_result = ValidationResult.WARNING if warnings else ValidationResult.VALID
        
        return InterfaceValidation(
            interface_type=InterfaceType.CUSTOM,
            validation_result=validation_result,
            issues=issues,
            warnings=warnings,
            recommendations=recommendations,
            confidence=0.7
        )
    
    def _validate_interface_call(self, call: Dict[str, Any], contract_content: str) -> InterfaceValidation:
        """Validate interface call"""
        issues = []
        warnings = []
        recommendations = []
        
        contract_name = call['contract_name']
        function_name = call['function_name']
        
        # Check if contract is properly declared
        contract_declaration = self._find_variable_declaration(contract_content, contract_name)
        if not contract_declaration:
            issues.append(f"Contract {contract_name} not properly declared")
        
        # Check if function exists in interface
        interface_type = self._get_contract_interface_type(contract_content, contract_name)
        if interface_type != InterfaceType.UNKNOWN:
            if not self._function_exists_in_interface(function_name, interface_type):
                issues.append(f"Function {function_name} not found in {interface_type.value} interface")
        
        # Check for proper error handling
        if not self._has_error_handling(contract_content, call['line_number']):
            warnings.append(f"Interface call without error handling")
        
        validation_result = ValidationResult.ERROR if issues else ValidationResult.WARNING if warnings else ValidationResult.VALID
        
        return InterfaceValidation(
            interface_type=interface_type,
            validation_result=validation_result,
            issues=issues,
            warnings=warnings,
            recommendations=recommendations,
            confidence=0.6
        )
    
    def _extract_interface_content(self, contract_content: str, interface_name: str) -> Optional[str]:
        """Extract interface content from contract"""
        # Pattern to find interface content
        interface_pattern = rf'interface\s+{interface_name}\s*\{{(.*?)\}}'
        match = re.search(interface_pattern, contract_content, re.DOTALL)
        
        if match:
            return match.group(1)
        return None
    
    def _validate_erc20_interface(self, interface_content: str) -> List[str]:
        """Validate ERC20 interface implementation"""
        issues = []
        
        # Check for required functions
        required_functions = ['totalSupply', 'balanceOf', 'transfer', 'transferFrom', 'approve', 'allowance']
        
        for func_name in required_functions:
            if func_name not in interface_content:
                issues.append(f"Missing required ERC20 function: {func_name}")
        
        # Check for events
        required_events = ['Transfer', 'Approval']
        for event_name in required_events:
            if event_name not in interface_content:
                issues.append(f"Missing required ERC20 event: {event_name}")
        
        return issues
    
    def _validate_erc721_interface(self, interface_content: str) -> List[str]:
        """Validate ERC721 interface implementation"""
        issues = []
        
        # Check for required functions
        required_functions = ['balanceOf', 'ownerOf', 'safeTransferFrom', 'transferFrom', 'approve', 'setApprovalForAll', 'getApproved', 'isApprovedForAll']
        
        for func_name in required_functions:
            if func_name not in interface_content:
                issues.append(f"Missing required ERC721 function: {func_name}")
        
        # Check for events
        required_events = ['Transfer', 'Approval', 'ApprovalForAll']
        for event_name in required_events:
            if event_name not in interface_content:
                issues.append(f"Missing required ERC721 event: {event_name}")
        
        return issues
    
    def _validate_erc1155_interface(self, interface_content: str) -> List[str]:
        """Validate ERC1155 interface implementation"""
        issues = []
        
        # Check for required functions
        required_functions = ['balanceOf', 'balanceOfBatch', 'setApprovalForAll', 'isApprovedForAll', 'safeTransferFrom', 'safeBatchTransferFrom']
        
        for func_name in required_functions:
            if func_name not in interface_content:
                issues.append(f"Missing required ERC1155 function: {func_name}")
        
        # Check for events
        required_events = ['TransferSingle', 'TransferBatch', 'ApprovalForAll', 'URI']
        for event_name in required_events:
            if event_name not in interface_content:
                issues.append(f"Missing required ERC1155 event: {event_name}")
        
        return issues
    
    def _validate_custom_interface(self, interface_content: str) -> List[str]:
        """Validate custom interface implementation"""
        issues = []
        
        # Check for basic interface structure
        if not interface_content.strip():
            issues.append("Empty interface")
        
        # Check for function declarations
        function_count = len(re.findall(r'function\s+\w+', interface_content))
        if function_count == 0:
            issues.append("Interface has no functions")
        
        return issues
    
    def _find_variable_declaration(self, contract_content: str, variable_name: str) -> Optional[str]:
        """Find variable declaration"""
        # Pattern for variable declarations
        declaration_pattern = rf'(\w+)\s+{variable_name}\s*[;=]'
        match = re.search(declaration_pattern, contract_content)
        
        if match:
            return match.group(0)
        return None
    
    def _get_contract_interface_type(self, contract_content: str, contract_name: str) -> InterfaceType:
        """Get interface type for a contract"""
        # Find variable declaration
        declaration = self._find_variable_declaration(contract_content, contract_name)
        
        if declaration:
            # Check if it's an interface type
            for interface_name, interface_type in self.known_interfaces.items():
                if interface_name in declaration:
                    return interface_type
        
        return InterfaceType.UNKNOWN
    
    def _function_exists_in_interface(self, function_name: str, interface_type: InterfaceType) -> bool:
        """Check if function exists in interface"""
        if interface_type == InterfaceType.ERC20:
            return function_name in self.erc20_interface
        elif interface_type == InterfaceType.ERC721:
            return function_name in self.erc721_interface
        elif interface_type == InterfaceType.ERC1155:
            return function_name in self.erc1155_interface
        
        return False
    
    def _has_error_handling(self, contract_content: str, line_number: int) -> bool:
        """Check if there's error handling around the line"""
        lines = contract_content.split('\n')
        
        # Check lines before and after
        start_line = max(0, line_number - 5)
        end_line = min(len(lines), line_number + 5)
        
        for i in range(start_line, end_line):
            if i < len(lines):
                line = lines[i]
                if 'require(' in line or 'assert(' in line or 'revert' in line:
                    return True
        
        return False
    
    def _get_line_number(self, position: int, content: str) -> int:
        """Get line number from character position"""
        return content[:position].count('\n') + 1
    
    def detect_interface_mismatches(self, contract_content: str) -> List[InterfaceMismatch]:
        """Detect interface mismatches with external contracts"""
        mismatches = []
        
        # Find interface calls
        interface_calls = self._find_interface_calls(contract_content)
        
        for call in interface_calls:
            contract_name = call['contract_name']
            function_name = call['function_name']
            
            # Get expected interface type
            interface_type = self._get_contract_interface_type(contract_content, contract_name)
            
            if interface_type != InterfaceType.UNKNOWN:
                # Check if function exists in expected interface
                if not self._function_exists_in_interface(function_name, interface_type):
                    mismatch = InterfaceMismatch(
                        mismatch_type='function_not_found',
                        severity='high',
                        description=f'Function {function_name} not found in {interface_type.value} interface',
                        line_number=call['line_number'],
                        code_snippet=call['code_snippet'],
                        confidence=0.8,
                        swc_id='SWC-107',
                        recommendation=f'Implement {function_name} function or use correct interface',
                        expected_interface=interface_type.value,
                        actual_interface='unknown'
                    )
                    mismatches.append(mismatch)
        
        return mismatches
    
    def get_interface_summary(self, contract_content: str) -> Dict[str, Any]:
        """Get summary of interfaces used in contract"""
        summary = {
            'total_interfaces': 0,
            'interface_types': {},
            'interface_calls': 0,
            'validation_issues': 0,
            'warnings': 0
        }
        
        # Count interface declarations
        interface_declarations = self._find_interface_declarations(contract_content)
        summary['total_interfaces'] = len(interface_declarations)
        
        # Count interface types
        for interface_name, interface_type in interface_declarations.items():
            interface_type_str = interface_type.value
            summary['interface_types'][interface_type_str] = summary['interface_types'].get(interface_type_str, 0) + 1
        
        # Count interface calls
        interface_calls = self._find_interface_calls(contract_content)
        summary['interface_calls'] = len(interface_calls)
        
        # Count validation issues
        validations = self.validate_external_interfaces(contract_content)
        for validation in validations:
            summary['validation_issues'] += len(validation.issues)
            summary['warnings'] += len(validation.warnings)
        
        return summary
