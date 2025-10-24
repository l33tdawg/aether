#!/usr/bin/env python3
"""
Governance and Access Control Detector

Identifies governance controls that prevent vulnerabilities.
Prevents false positives from flagging governance-controlled parameters.
"""

import re
from typing import Dict, List, Optional, Tuple


class GovernanceDetector:
    """Detects governance controls that prevent vulnerabilities."""
    
    def __init__(self):
        self.setter_patterns = {
            'fee_setters': r'function\s+(set|update)(Fee|Fees)\s*\([^)]*\)\s+external',
            'oracle_setters': r'function\s+(set|update)(Oracle|Price)\s*\([^)]*\)\s+external',
            'param_setters': r'function\s+(set|update)\w+\s*\([^)]*\)\s+external',
        }
        
        self.access_modifiers = [
            'onlyOwner', 'onlyGovernor', 'onlyGuardian', 'onlyGov',
            'onlyRole', 'restricted', 'onlyAdmin', 'onlyController',
            'onlyGovernance', 'onlyAuthorized', 'onlyLatestNetworkContract'
        ]
    
    def find_setter_for_param(self, param_name: str, contract_code: str) -> Optional[Dict]:
        """
        Find setter function for a parameter and its protections.
        
        Args:
            param_name: Parameter name (e.g., "Fee", "Oracle")
            contract_code: Full contract source code
            
        Returns:
            Dict with setter info and protection details, or None if not found
        """
        
        # Look for function that sets this parameter (set* or update*)
        setter_pattern = rf'function\s+(set|update){param_name}s?\s*\([^)]*\)([^{{]*)\{{'
        match = re.search(setter_pattern, contract_code, re.IGNORECASE)
        
        if not match:
            return None
        
        # Check for access control modifiers
        modifiers_section = match.group(2)  # Group 2 is now the modifiers section
        protected_by = []
        
        for modifier in self.access_modifiers:
            if modifier in modifiers_section:
                protected_by.append(modifier)
        
        # Also check for require() statements inside function
        function_end = self._find_function_end(match.end(), contract_code)
        function_body = contract_code[match.end():function_end]
        
        has_validation = bool(re.search(r'require\s*\(', function_body))
        
        return {
            'setter_found': True,
            'protected_by': protected_by,
            'has_validation': has_validation,
            'is_protected': len(protected_by) > 0 or has_validation,
            'function_body': function_body[:200]  # First 200 chars for debugging
        }
    
    def _find_function_end(self, start: int, code: str) -> int:
        """Find end of function by matching braces."""
        brace_count = 1
        i = start
        while i < len(code) and brace_count > 0:
            if code[i] == '{':
                brace_count += 1
            elif code[i] == '}':
                brace_count -= 1
            i += 1
        return i
    
    def check_validation_in_setter(self, param_name: str, contract_code: str) -> Dict:
        """
        Check if parameter has validated setter.
        
        Args:
            param_name: Parameter name to check
            contract_code: Full contract source code
        
        Returns:
            Dict with 'governed' (bool), 'reason' (str), 'confidence' (float)
        """
        setter_info = self.find_setter_for_param(param_name, contract_code)
        
        if not setter_info:
            return {
                'governed': False, 
                'reason': 'No setter found',
                'confidence': 0.3
            }
        
        if setter_info['is_protected']:
            return {
                'governed': True,
                'reason': f"Protected by: {', '.join(setter_info['protected_by'])}" if setter_info['protected_by'] else "Has validation",
                'confidence': 0.9
            }
        
        return {
            'governed': False,
            'reason': 'Setter exists but not protected',
            'confidence': 0.5
        }
    
    def has_access_control(self, function_code: str) -> Dict:
        """
        Check if a function has access control.
        
        Args:
            function_code: Function source code (including signature and body)
            
        Returns:
            Dict with 'has_access_control' (bool), 'modifiers' (list), 'confidence' (float)
        """
        found_modifiers = []
        
        # Check for access control modifiers
        for modifier in self.access_modifiers:
            if modifier in function_code:
                found_modifiers.append(modifier)
        
        # Check for inline access control (require with msg.sender check)
        inline_checks = re.findall(
            r'require\s*\(\s*msg\.sender\s*==\s*\w+', 
            function_code
        )
        
        has_inline_control = len(inline_checks) > 0
        
        if found_modifiers or has_inline_control:
            return {
                'has_access_control': True,
                'modifiers': found_modifiers,
                'inline_checks': len(inline_checks),
                'confidence': 0.9 if found_modifiers else 0.7
            }
        
        return {
            'has_access_control': False,
            'modifiers': [],
            'inline_checks': 0,
            'confidence': 0.8
        }
    
    def is_governance_function(self, function_name: str, contract_code: str) -> bool:
        """
        Check if a function is governance-related.
        
        Args:
            function_name: Name of the function
            contract_code: Full contract source code
            
        Returns:
            True if function appears to be governance-controlled
        """
        # Extract function definition
        pattern = rf'function\s+{function_name}\s*\([^)]*\)([^{{]*)\{{'
        match = re.search(pattern, contract_code)
        
        if not match:
            return False
        
        # Check for access control modifiers
        modifiers = match.group(1)
        for modifier in self.access_modifiers:
            if modifier in modifiers:
                return True
        
        return False
    
    def get_governance_summary(self, contract_code: str) -> Dict:
        """
        Get summary of governance controls in contract.
        
        Args:
            contract_code: Full contract source code
            
        Returns:
            Dict with governance information
        """
        # Find all setter functions
        setters = []
        for pattern_name, pattern in self.setter_patterns.items():
            matches = re.finditer(pattern, contract_code)
            for match in matches:
                setters.append({
                    'type': pattern_name,
                    'code': match.group(0)
                })
        
        # Find all functions with access control
        protected_functions = []
        function_pattern = r'function\s+(\w+)\s*\([^)]*\)([^{]*)\{'
        for match in re.finditer(function_pattern, contract_code):
            function_name = match.group(1)
            modifiers = match.group(2)
            
            # Check for access control
            has_control = any(mod in modifiers for mod in self.access_modifiers)
            if has_control:
                protected_functions.append({
                    'name': function_name,
                    'modifiers': [mod for mod in self.access_modifiers if mod in modifiers]
                })
        
        return {
            'total_setters': len(setters),
            'protected_functions': len(protected_functions),
            'setter_functions': setters,
            'access_controlled_functions': protected_functions,
            'has_governance': len(protected_functions) > 0
        }


class ValidationDetector:
    """Detects protective validation functions for arithmetic operations."""
    
    VALIDATION_PATTERNS = {
        'bounds_checks': r'require\s*\([^)]*[<>]=?[^)]*\)',  # Arithmetic bounds
        'safe_functions': r'(SafeMath|SafeCast|Math\.)',  # Safe math libraries
        'max_checks': r'require\s*\([^)]*<=\s*(MAX|max)',  # Max value checks
        'min_checks': r'require\s*\([^)]*>=\s*(MIN|min)',  # Min value checks
        'revert_bounds': r'if\s*\([^)]*[<>]=?[^)]*\)\s*revert',  # Revert on bounds
    }
    
    def check_if_validated(self, vuln_line: int, contract_code: str, vuln_type: str = 'arithmetic') -> bool:
        """
        Check if vulnerability location has relevant validation.
        
        Args:
            vuln_line: Line number of vulnerability
            contract_code: Full contract source code
            vuln_type: Type of vulnerability (default: 'arithmetic')
            
        Returns:
            True if validation found before vulnerability
        """
        lines = contract_code.split('\n')
        
        # Check 20 lines before vuln
        context_start = max(0, vuln_line - 20)
        context = '\n'.join(lines[context_start:vuln_line])
        
        # For arithmetic vulnerabilities, look for bounds checks
        if 'arithmetic' in vuln_type.lower() or 'overflow' in vuln_type.lower() or 'underflow' in vuln_type.lower():
            # Look for validation patterns
            for pattern_name, pattern in self.VALIDATION_PATTERNS.items():
                if re.search(pattern, context):
                    return True
        
        return False
    
    def get_validation_context(self, vuln_line: int, contract_code: str) -> Dict:
        """
        Get detailed validation context around vulnerability.
        
        Args:
            vuln_line: Line number of vulnerability
            contract_code: Full contract source code
            
        Returns:
            Dict with validation details
        """
        lines = contract_code.split('\n')
        context_start = max(0, vuln_line - 20)
        context = '\n'.join(lines[context_start:vuln_line])
        
        validations_found = []
        for pattern_name, pattern in self.VALIDATION_PATTERNS.items():
            matches = re.findall(pattern, context)
            if matches:
                validations_found.append({
                    'type': pattern_name,
                    'count': len(matches)
                })
        
        return {
            'has_validation': len(validations_found) > 0,
            'validations': validations_found,
            'context_lines': vuln_line - context_start
        }

