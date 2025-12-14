#!/usr/bin/env python3
"""
Variable Shadowing Detector

Detects local variables that shadow state variables or function parameters,
which can lead to confusing code and potential bugs.

This detector addresses the issue found in ADI-Stack-Contracts Bridgehub.sol
where `bytes32 baseTokenAssetId = baseTokenAssetId[_chainId]` shadows the
state mapping of the same name.
"""

import re
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass


@dataclass
class ShadowingVulnerability:
    """Represents a variable shadowing issue."""
    vulnerability_type: str
    severity: str
    confidence: float
    line_number: int
    description: str
    code_snippet: str
    swc_id: str = "SWC-119"
    category: str = "code_quality"
    context: Dict[str, Any] = None
    validation_status: str = "validated"
    
    def __post_init__(self):
        if self.context is None:
            self.context = {}


class VariableShadowingDetector:
    """
    Detects variable shadowing issues in Solidity contracts.
    
    Types of shadowing detected:
    1. Local variables shadowing state variables
    2. Function parameters shadowing state variables
    3. Local variables shadowing inherited state variables
    4. Constructor parameters shadowing state variables
    """
    
    def __init__(self):
        self.state_variables: Dict[str, Dict[str, Any]] = {}
        self.contract_inheritance: Dict[str, List[str]] = {}
    
    def analyze_contract(self, contract_content: str, file_path: str = "") -> List[ShadowingVulnerability]:
        """
        Analyze a Solidity contract for variable shadowing issues.
        
        Args:
            contract_content: The Solidity source code
            file_path: Optional file path for context
            
        Returns:
            List of detected shadowing vulnerabilities
        """
        vulnerabilities = []
        lines = contract_content.split('\n')
        
        # Step 1: Extract all state variables from all contracts in the file
        self._extract_state_variables(contract_content)
        
        # Step 2: Extract inheritance relationships
        self._extract_inheritance(contract_content)
        
        # Step 3: Find functions and check for shadowing
        vulnerabilities.extend(self._check_function_shadowing(contract_content, lines))
        
        # Step 4: Check constructor parameter shadowing
        vulnerabilities.extend(self._check_constructor_shadowing(contract_content, lines))
        
        return vulnerabilities
    
    def _extract_state_variables(self, contract_content: str) -> None:
        """Extract all state variable declarations from contracts."""
        self.state_variables = {}
        
        # Find all contract definitions
        contract_pattern = r'contract\s+(\w+)[^{]*\{'
        
        for contract_match in re.finditer(contract_pattern, contract_content):
            contract_name = contract_match.group(1)
            contract_start = contract_match.start()
            contract_body_start = contract_match.end()
            
            # Find contract body end
            brace_count = 1
            contract_body_end = contract_body_start
            for i in range(contract_body_start, len(contract_content)):
                if contract_content[i] == '{':
                    brace_count += 1
                elif contract_content[i] == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        contract_body_end = i
                        break
            
            contract_body = contract_content[contract_body_start:contract_body_end]
            
            if contract_name not in self.state_variables:
                self.state_variables[contract_name] = {}
            
            # Find state variable declarations (not inside functions)
            # State variables are declared at contract level, before functions
            
            # Pattern for state variable declarations
            # Matches: type [visibility] [modifier] name [= value];
            state_var_patterns = [
                # mapping(type => type) [visibility] name; (new Solidity 0.8.x syntax)
                r'^\s*(mapping\s*\([^)]+\))\s*(?:public|private|internal)?\s*(\w+)\s*;',
                # mapping(type chainId => type) public name; (named key syntax)
                r'^\s*(mapping\s*\(\s*\w+\s+\w+\s*=>\s*\w+\s*\))\s*(?:public|private|internal)?\s*(\w+)\s*;',
                # type[] [visibility] name;
                r'^\s*(\w+(?:\[\])?)\s+(?:public|private|internal|immutable|constant)?\s*(\w+)\s*(?:=|;)',
                # address/uint/bytes etc.
                r'^\s*(address|uint\d*|int\d*|bytes\d*|bool|string)\s+(?:public|private|internal|immutable|constant)?\s*(\w+)\s*(?:=|;)',
                # Interface types like IMessageRoot, ICTMDeploymentTracker
                r'^\s*(I\w+)\s+(?:public|private|internal|immutable|constant)?\s*(\w+)\s*;',
            ]
            
            # Track function boundaries to exclude function-local declarations
            func_boundaries = self._get_function_boundaries(contract_body)
            
            for line_idx, line in enumerate(contract_body.split('\n')):
                line_num_in_contract = line_idx
                
                # Check if this line is inside a function
                is_inside_function = any(
                    start <= line_num_in_contract <= end 
                    for start, end in func_boundaries
                )
                
                if is_inside_function:
                    continue
                
                # Skip comments
                stripped = line.strip()
                if stripped.startswith('//') or stripped.startswith('*') or stripped.startswith('/*'):
                    continue
                
                # Skip function, event, modifier, error declarations
                if any(keyword in stripped for keyword in ['function ', 'event ', 'modifier ', 'error ', 'constructor']):
                    continue
                
                # Try to match state variable patterns
                for pattern in state_var_patterns:
                    match = re.search(pattern, line)
                    if match:
                        var_type = match.group(1)
                        var_name = match.group(2)
                        
                        # Skip function names, events, modifiers
                        if var_name in ['function', 'event', 'modifier', 'constructor', 'error']:
                            continue
                        
                        # Calculate actual line number in the full file
                        full_line_num = contract_content[:contract_body_start].count('\n') + line_idx + 1
                        
                        self.state_variables[contract_name][var_name] = {
                            'type': var_type,
                            'line': full_line_num,
                            'contract': contract_name
                        }
                        break
    
    def _get_function_boundaries(self, contract_body: str) -> List[Tuple[int, int]]:
        """Get line number boundaries of all functions in contract body."""
        boundaries = []
        lines = contract_body.split('\n')
        
        func_start = None
        brace_count = 0
        in_function = False
        
        for i, line in enumerate(lines):
            # Check for function start
            if re.search(r'function\s+\w+\s*\(', line) or re.search(r'constructor\s*\(', line):
                func_start = i
                in_function = True
                brace_count = 0
            
            if in_function:
                brace_count += line.count('{')
                brace_count -= line.count('}')
                
                if brace_count == 0 and '{' in contract_body[:sum(len(l)+1 for l in lines[:i+1])]:
                    if func_start is not None:
                        boundaries.append((func_start, i))
                    in_function = False
                    func_start = None
        
        return boundaries
    
    def _extract_inheritance(self, contract_content: str) -> None:
        """Extract contract inheritance relationships."""
        self.contract_inheritance = {}
        
        # Pattern: contract Name is Parent1, Parent2, ...
        inheritance_pattern = r'contract\s+(\w+)\s+is\s+([^{]+)\{'
        
        for match in re.finditer(inheritance_pattern, contract_content):
            contract_name = match.group(1)
            parents_str = match.group(2)
            
            # Parse parent contracts (handling constructor args like Parent(arg))
            parents = []
            for parent in parents_str.split(','):
                parent = parent.strip()
                # Extract just the contract name, not constructor args
                parent_name = re.match(r'(\w+)', parent)
                if parent_name:
                    parents.append(parent_name.group(1))
            
            self.contract_inheritance[contract_name] = parents
    
    def _get_all_state_vars_for_contract(self, contract_name: str) -> Dict[str, Dict[str, Any]]:
        """Get all state variables including inherited ones."""
        all_vars = {}
        
        # Get variables from parent contracts first
        if contract_name in self.contract_inheritance:
            for parent in self.contract_inheritance[contract_name]:
                if parent in self.state_variables:
                    all_vars.update(self.state_variables[parent])
        
        # Then add this contract's variables (they override parents)
        if contract_name in self.state_variables:
            all_vars.update(self.state_variables[contract_name])
        
        return all_vars
    
    def _check_function_shadowing(self, contract_content: str, lines: List[str]) -> List[ShadowingVulnerability]:
        """Check for local variables shadowing state variables in functions."""
        vulnerabilities = []
        
        # Find all contracts
        contract_pattern = r'contract\s+(\w+)[^{]*\{'
        
        for contract_match in re.finditer(contract_pattern, contract_content):
            contract_name = contract_match.group(1)
            contract_start = contract_match.start()
            
            # Get all state variables for this contract (including inherited)
            state_vars = self._get_all_state_vars_for_contract(contract_name)
            
            if not state_vars:
                continue
            
            # Find functions in this contract
            # Use a more robust approach to find function bodies
            func_pattern = r'function\s+(\w+)\s*\(([^)]*)\)[^{]*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}'
            
            # Get contract body
            contract_body_start = contract_match.end()
            brace_count = 1
            contract_body_end = contract_body_start
            
            for i in range(contract_body_start, len(contract_content)):
                if contract_content[i] == '{':
                    brace_count += 1
                elif contract_content[i] == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        contract_body_end = i
                        break
            
            contract_body = contract_content[contract_body_start:contract_body_end]
            
            for func_match in re.finditer(func_pattern, contract_body, re.DOTALL):
                func_name = func_match.group(1)
                func_params = func_match.group(2)
                func_body = func_match.group(3)
                func_start_offset = func_match.start()
                
                # Check function parameters for shadowing
                param_names = self._extract_parameter_names(func_params)
                for param_name in param_names:
                    if param_name in state_vars:
                        line_num = contract_content[:contract_body_start + func_start_offset].count('\n') + 1
                        vulnerabilities.append(ShadowingVulnerability(
                            vulnerability_type='variable_shadowing',
                            severity='low',
                            confidence=0.90,
                            line_number=line_num,
                            description=f'Function parameter "{param_name}" in {func_name}() shadows state variable "{param_name}" declared in {state_vars[param_name]["contract"]}',
                            code_snippet=f'function {func_name}({func_params[:100]}...)',
                            context={
                                'shadowed_var': param_name,
                                'var_type': state_vars[param_name]['type'],
                                'function': func_name,
                                'contract': contract_name
                            }
                        ))
                
                # Check local variable declarations for shadowing
                local_var_vulns = self._check_local_vars_in_function(
                    func_body, func_name, state_vars, contract_name,
                    contract_content[:contract_body_start + func_start_offset].count('\n') + 1
                )
                vulnerabilities.extend(local_var_vulns)
        
        return vulnerabilities
    
    def _extract_parameter_names(self, params_str: str) -> List[str]:
        """Extract parameter names from function signature."""
        names = []
        
        if not params_str.strip():
            return names
        
        # Split by comma and extract names
        # Format: type [memory|storage|calldata] name
        for param in params_str.split(','):
            param = param.strip()
            if not param:
                continue
            
            # Get the last word as the parameter name
            parts = param.split()
            if parts:
                name = parts[-1].strip()
                # Remove any trailing characters like )
                name = re.sub(r'[^a-zA-Z0-9_]', '', name)
                if name and name not in ['memory', 'storage', 'calldata']:
                    names.append(name)
        
        return names
    
    def _check_local_vars_in_function(
        self, 
        func_body: str, 
        func_name: str, 
        state_vars: Dict[str, Dict[str, Any]],
        contract_name: str,
        func_start_line: int
    ) -> List[ShadowingVulnerability]:
        """Check for local variable declarations that shadow state variables."""
        vulnerabilities = []
        
        lines = func_body.split('\n')
        
        # Patterns for local variable declarations - more comprehensive matching
        local_var_patterns = [
            # type name = ... (basic assignment)
            r'(?:^|\s)(\w+(?:\d+)?(?:\[\])?)\s+(\w+)\s*=',
            # type memory/storage name = ...
            r'(?:^|\s)(\w+(?:\d+)?(?:\[\])?)\s+(?:memory|storage|calldata)\s+(\w+)\s*=',
            # type name; (declaration without assignment)
            r'(?:^|\s)(\w+(?:\d+)?(?:\[\])?)\s+(\w+)\s*;',
            # type memory/storage name; (declaration without assignment)
            r'(?:^|\s)(\w+(?:\d+)?(?:\[\])?)\s+(?:memory|storage|calldata)\s+(\w+)\s*;',
        ]
        
        # Common types to match
        solidity_types = {
            'address', 'bool', 'string', 'bytes', 
            'uint', 'uint8', 'uint16', 'uint32', 'uint64', 'uint128', 'uint256',
            'int', 'int8', 'int16', 'int32', 'int64', 'int128', 'int256',
            'bytes1', 'bytes2', 'bytes4', 'bytes8', 'bytes16', 'bytes32',
        }
        
        for line_idx, line in enumerate(lines):
            # Skip comments
            stripped = line.strip()
            if stripped.startswith('//') or not stripped:
                continue
            
            # Skip control flow statements
            if any(stripped.startswith(kw) for kw in ['if', 'for', 'while', 'return', 'require', 'assert', 'revert', 'emit']):
                continue
            
            for pattern in local_var_patterns:
                matches = re.finditer(pattern, line)
                for match in matches:
                    var_type = match.group(1)
                    var_name = match.group(2)
                    
                    # Skip if it looks like a function call or control structure
                    if var_type.lower() in ['if', 'for', 'while', 'return', 'require', 'assert', 'revert', 'function', 'emit']:
                        continue
                    
                    # Only match valid Solidity types or mapping-like types
                    is_valid_type = (
                        var_type.lower() in solidity_types or
                        var_type.lower().startswith('uint') or
                        var_type.lower().startswith('int') or
                        var_type.lower().startswith('bytes') or
                        var_type.startswith('I') or  # Interface types
                        var_type[0].isupper()  # Custom types start with uppercase
                    )
                    
                    if not is_valid_type:
                        continue
                    
                    # Check if this variable name matches a state variable
                    if var_name in state_vars:
                        actual_line = func_start_line + line_idx
                        
                        # Determine severity based on same-name same-type (higher risk)
                        severity = 'low'
                        confidence = 0.95
                        
                        vulnerabilities.append(ShadowingVulnerability(
                            vulnerability_type='variable_shadowing',
                            severity=severity,
                            confidence=confidence,
                            line_number=actual_line,
                            description=f'Local variable "{var_name}" in {func_name}() shadows state variable "{var_name}" (type: {state_vars[var_name]["type"]}) from {state_vars[var_name]["contract"]}',
                            code_snippet=line.strip()[:150],
                            context={
                                'shadowed_var': var_name,
                                'var_type': state_vars[var_name]['type'],
                                'function': func_name,
                                'contract': contract_name,
                                'original_line': state_vars[var_name]['line']
                            }
                        ))
        
        return vulnerabilities
    
    def _check_constructor_shadowing(self, contract_content: str, lines: List[str]) -> List[ShadowingVulnerability]:
        """Check for constructor parameter shadowing."""
        vulnerabilities = []
        
        # Find constructors
        constructor_pattern = r'constructor\s*\(([^)]*)\)[^{]*\{'
        
        for match in re.finditer(constructor_pattern, contract_content):
            params_str = match.group(1)
            line_num = contract_content[:match.start()].count('\n') + 1
            
            # Find which contract this constructor belongs to
            contract_name = None
            for contract_match in re.finditer(r'contract\s+(\w+)[^{]*\{', contract_content):
                if contract_match.end() < match.start():
                    contract_name = contract_match.group(1)
            
            if not contract_name:
                continue
            
            state_vars = self._get_all_state_vars_for_contract(contract_name)
            param_names = self._extract_parameter_names(params_str)
            
            for param_name in param_names:
                if param_name in state_vars:
                    vulnerabilities.append(ShadowingVulnerability(
                        vulnerability_type='variable_shadowing',
                        severity='low',
                        confidence=0.85,
                        line_number=line_num,
                        description=f'Constructor parameter "{param_name}" shadows state variable "{param_name}" in {contract_name}',
                        code_snippet=f'constructor({params_str[:100]}...)',
                        context={
                            'shadowed_var': param_name,
                            'var_type': state_vars[param_name]['type'],
                            'function': 'constructor',
                            'contract': contract_name
                        }
                    ))
        
        return vulnerabilities
    
    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of the analysis."""
        return {
            'contracts_analyzed': len(self.state_variables),
            'state_variables_found': sum(len(v) for v in self.state_variables.values()),
            'inheritance_relationships': len(self.contract_inheritance)
        }
