"""
Modifier Semantic Analyzer

Analyzes Solidity modifier bodies to understand their validation semantics.
This helps detect when parameters are validated through modifiers rather than
inline require() statements, reducing false positives for "missing validation" findings.

Key improvements:
1. Extract all modifier definitions from contracts
2. Parse what each modifier validates (parameters, state, access control)
3. Map modifier arguments to function parameters
4. Understand custom validation modifiers like onlyRegisteredToken
"""

import re
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum


class ValidationKind(Enum):
    """Types of validation a modifier can perform."""
    PARAMETER_CHECK = "parameter_check"  # Validates a parameter value
    ACCESS_CONTROL = "access_control"    # Restricts who can call
    STATE_CHECK = "state_check"          # Checks contract state
    TIMING_CHECK = "timing_check"        # Checks time/block constraints
    REENTRANCY_GUARD = "reentrancy_guard"  # Prevents reentrancy


@dataclass
class ModifierValidation:
    """Represents a single validation performed by a modifier."""
    kind: ValidationKind
    parameter: Optional[str]  # Parameter being validated (if any)
    condition: str            # The condition being checked
    error_message: Optional[str]  # Error message if available
    line_in_modifier: int     # Line number within modifier body


@dataclass
class ModifierDefinition:
    """Represents a parsed modifier definition."""
    name: str
    parameters: List[str]
    parameter_types: Dict[str, str]  # param_name -> type
    body: str
    validations: List[ModifierValidation] = field(default_factory=list)
    validated_params: Set[str] = field(default_factory=set)
    is_access_control: bool = False
    is_reentrancy_guard: bool = False
    start_line: int = 0


@dataclass
class FunctionModifierUsage:
    """Represents how a modifier is used on a function."""
    modifier_name: str
    arguments: List[str]  # Arguments passed to modifier
    arg_to_param_mapping: Dict[str, str]  # modifier_param -> function_param


class ModifierSemanticAnalyzer:
    """Analyzes modifier bodies to understand their validation semantics."""
    
    def __init__(self):
        self.modifier_definitions: Dict[str, ModifierDefinition] = {}
        self._contract_content: str = ""
        
        # Patterns for identifying validation types
        self.access_control_patterns = [
            r'msg\.sender\s*==',
            r'msg\.sender\s*!=',
            r'hasRole\s*\(',
            r'_hasRole\s*\(',
            r'owner\s*==',
            r'owner\s*!=',
            r'isAuthorized',
            r'onlyOwner',
        ]
        
        self.reentrancy_patterns = [
            r'_status\s*==\s*_NOT_ENTERED',
            r'_status\s*!=\s*_ENTERED', 
            r'locked\s*==\s*false',
            r'!locked',
            r'ReentrancyGuard',
            r'nonReentrant',
        ]
        
        self.timing_patterns = [
            r'block\.timestamp',
            r'block\.number',
            r'now\s*[<>]',  # deprecated but still used
        ]
    
    def analyze_contract(self, contract_content: str) -> Dict[str, ModifierDefinition]:
        """Extract and analyze all modifiers from a contract."""
        self._contract_content = contract_content
        self.modifier_definitions = {}
        
        # Find all modifier definitions
        # Pattern handles multi-line modifiers with various formatting
        modifier_pattern = r'modifier\s+(\w+)\s*\(([^)]*)\)\s*\{([\s\S]*?)\n\s*\}'
        
        for match in re.finditer(modifier_pattern, contract_content):
            name = match.group(1)
            params_str = match.group(2).strip()
            body = match.group(3)
            
            # Calculate start line
            start_pos = match.start()
            start_line = contract_content[:start_pos].count('\n') + 1
            
            # Parse parameters
            params, param_types = self._parse_modifier_params(params_str)
            
            # Create modifier definition
            mod_def = ModifierDefinition(
                name=name,
                parameters=params,
                parameter_types=param_types,
                body=body,
                start_line=start_line
            )
            
            # Analyze the modifier body
            mod_def.validations = self._extract_validations(body, params)
            mod_def.validated_params = self._get_validated_params(mod_def.validations, params)
            mod_def.is_access_control = self._is_access_control_modifier(body)
            mod_def.is_reentrancy_guard = self._is_reentrancy_guard(body)
            
            self.modifier_definitions[name] = mod_def
        
        return self.modifier_definitions
    
    def _parse_modifier_params(self, params_str: str) -> Tuple[List[str], Dict[str, str]]:
        """Parse modifier parameter string into names and types."""
        params = []
        param_types = {}
        
        if not params_str.strip():
            return params, param_types
        
        # Split by comma, handling complex types
        parts = [p.strip() for p in params_str.split(',')]
        
        for part in parts:
            if not part:
                continue
            
            # Pattern: type [memory|storage|calldata] name
            match = re.match(r'(\w+(?:\[\])?)\s*(?:memory|storage|calldata)?\s*(\w+)', part)
            if match:
                param_type = match.group(1)
                param_name = match.group(2)
                params.append(param_name)
                param_types[param_name] = param_type
        
        return params, param_types
    
    def _extract_validations(self, body: str, params: List[str]) -> List[ModifierValidation]:
        """Extract all validations from a modifier body."""
        validations = []
        lines = body.split('\n')
        
        for i, line in enumerate(lines):
            line = line.strip()
            
            # Check for require statements
            require_match = re.search(r'require\s*\((.+?)(?:,\s*["\']([^"\']+)["\'])?\s*\)', line)
            if require_match:
                condition = require_match.group(1).strip()
                error_msg = require_match.group(2) if require_match.lastindex >= 2 else None
                
                validation = self._classify_validation(condition, error_msg, params, i)
                if validation:
                    validations.append(validation)
            
            # Check for revert statements (including custom errors)
            if 'revert' in line:
                # Look for condition in previous line or same line
                if i > 0 and 'if' in lines[i-1]:
                    cond_match = re.search(r'if\s*\((.+?)\)', lines[i-1])
                    if cond_match:
                        condition = cond_match.group(1).strip()
                        # Negate condition since revert means condition triggers failure
                        validation = self._classify_validation(f"!({condition})", None, params, i)
                        if validation:
                            validations.append(validation)
                elif 'if' in line:
                    cond_match = re.search(r'if\s*\((.+?)\)\s*revert', line)
                    if cond_match:
                        condition = cond_match.group(1).strip()
                        validation = self._classify_validation(f"!({condition})", None, params, i)
                        if validation:
                            validations.append(validation)
        
        return validations
    
    def _classify_validation(
        self, 
        condition: str, 
        error_msg: Optional[str],
        params: List[str],
        line_num: int
    ) -> Optional[ModifierValidation]:
        """Classify a validation condition."""
        
        # Check if it validates a parameter
        validated_param = None
        for param in params:
            if param in condition:
                validated_param = param
                break
        
        # Determine validation kind
        kind = ValidationKind.STATE_CHECK  # default
        
        # Check for access control patterns
        for pattern in self.access_control_patterns:
            if re.search(pattern, condition, re.IGNORECASE):
                kind = ValidationKind.ACCESS_CONTROL
                break
        
        # Check for timing patterns
        for pattern in self.timing_patterns:
            if re.search(pattern, condition):
                kind = ValidationKind.TIMING_CHECK
                break
        
        # If a parameter is involved and not access control, it's parameter check
        if validated_param and kind == ValidationKind.STATE_CHECK:
            kind = ValidationKind.PARAMETER_CHECK
        
        return ModifierValidation(
            kind=kind,
            parameter=validated_param,
            condition=condition,
            error_message=error_msg,
            line_in_modifier=line_num
        )
    
    def _get_validated_params(
        self, 
        validations: List[ModifierValidation],
        params: List[str]
    ) -> Set[str]:
        """Get the set of parameters that are validated by the modifier."""
        validated = set()
        
        for validation in validations:
            if validation.parameter:
                validated.add(validation.parameter)
        
        return validated
    
    def _is_access_control_modifier(self, body: str) -> bool:
        """Check if modifier is primarily for access control."""
        for pattern in self.access_control_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                return True
        return False
    
    def _is_reentrancy_guard(self, body: str) -> bool:
        """Check if modifier is a reentrancy guard."""
        for pattern in self.reentrancy_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                return True
        return False
    
    def get_function_modifier_usages(self, function_code: str) -> List[FunctionModifierUsage]:
        """Extract modifier usages from a function signature."""
        usages = []
        
        # Find modifiers in function signature
        # Pattern: function name(...) visibility modifier1(args) modifier2 ...
        # We need to find text after the function params and visibility
        
        # First, find the function body start
        body_start = function_code.find('{')
        if body_start == -1:
            signature = function_code
        else:
            signature = function_code[:body_start]
        
        # Extract modifiers - they appear after visibility keywords
        visibility_keywords = ['external', 'public', 'internal', 'private', 'view', 'pure', 'payable']
        
        # Find all potential modifier usages
        # Pattern: identifier or identifier(args)
        modifier_pattern = r'\b(\w+)\s*(?:\(([^)]*)\))?'
        
        for match in re.finditer(modifier_pattern, signature):
            name = match.group(1)
            args_str = match.group(2) if match.group(2) else ""
            
            # Skip if it's a keyword, function name, or common Solidity keywords
            skip_words = visibility_keywords + [
                'function', 'returns', 'return', 'memory', 'storage', 'calldata',
                'uint', 'uint256', 'uint128', 'uint64', 'uint32', 'uint8',
                'int', 'int256', 'address', 'bool', 'bytes', 'string',
                'override', 'virtual'
            ]
            
            if name.lower() in skip_words or name.startswith('uint') or name.startswith('int'):
                continue
            
            # Check if this is a known modifier
            if name in self.modifier_definitions:
                args = [a.strip() for a in args_str.split(',') if a.strip()]
                mod_def = self.modifier_definitions[name]
                
                # Map arguments to modifier parameters
                arg_mapping = {}
                for i, (arg, param) in enumerate(zip(args, mod_def.parameters)):
                    arg_mapping[param] = arg
                
                usages.append(FunctionModifierUsage(
                    modifier_name=name,
                    arguments=args,
                    arg_to_param_mapping=arg_mapping
                ))
        
        return usages
    
    def get_function_validated_params(
        self, 
        function_code: str,
        function_params: List[str]
    ) -> Dict[str, List[str]]:
        """
        Get which function parameters are validated by modifiers.
        
        Returns:
            Dict mapping function parameter names to list of modifier names that validate them
        """
        validated = {param: [] for param in function_params}
        
        usages = self.get_function_modifier_usages(function_code)
        
        for usage in usages:
            if usage.modifier_name not in self.modifier_definitions:
                continue
            
            mod_def = self.modifier_definitions[usage.modifier_name]
            
            # For each parameter the modifier validates, find the corresponding function param
            for mod_param in mod_def.validated_params:
                if mod_param in usage.arg_to_param_mapping:
                    func_param = usage.arg_to_param_mapping[mod_param]
                    # The func_param might be an expression or variable
                    # Try to match it to function params
                    for fp in function_params:
                        if fp in func_param or func_param == fp:
                            validated[fp].append(usage.modifier_name)
        
        return validated
    
    def is_parameter_validated_by_modifiers(
        self,
        function_code: str,
        param_name: str
    ) -> Tuple[bool, List[str]]:
        """
        Check if a specific parameter is validated by modifiers.
        
        Returns:
            (is_validated, list_of_validating_modifiers)
        """
        usages = self.get_function_modifier_usages(function_code)
        validating_modifiers = []
        
        for usage in usages:
            if usage.modifier_name not in self.modifier_definitions:
                continue
            
            mod_def = self.modifier_definitions[usage.modifier_name]
            
            # Check if param_name is passed to this modifier and validated
            for mod_param, func_arg in usage.arg_to_param_mapping.items():
                if param_name in func_arg or func_arg == param_name:
                    if mod_param in mod_def.validated_params:
                        validating_modifiers.append(usage.modifier_name)
        
        return len(validating_modifiers) > 0, validating_modifiers
    
    def get_function_access_control_modifiers(self, function_code: str) -> List[str]:
        """Get list of access control modifiers on a function."""
        usages = self.get_function_modifier_usages(function_code)
        access_control_mods = []
        
        for usage in usages:
            if usage.modifier_name in self.modifier_definitions:
                mod_def = self.modifier_definitions[usage.modifier_name]
                if mod_def.is_access_control:
                    access_control_mods.append(usage.modifier_name)
        
        return access_control_mods
    
    def has_reentrancy_protection(self, function_code: str) -> bool:
        """Check if function has reentrancy protection via modifiers."""
        usages = self.get_function_modifier_usages(function_code)
        
        for usage in usages:
            if usage.modifier_name in self.modifier_definitions:
                mod_def = self.modifier_definitions[usage.modifier_name]
                if mod_def.is_reentrancy_guard:
                    return True
            # Also check for common reentrancy modifier names
            if usage.modifier_name.lower() in ['nonreentrant', 'noreentrant', 'reentrancyguard']:
                return True
        
        return False

