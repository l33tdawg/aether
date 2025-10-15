"""
Variable Dependency Tracker for Smart Contract Analysis

This module tracks variable assignments and dependencies to analyze potential
vulnerabilities in variable usage and value ranges.
"""

import re
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum
from collections import defaultdict, deque


class VariableType(Enum):
    """Types of variables"""
    STATE_VARIABLE = "state_variable"
    LOCAL_VARIABLE = "local_variable"
    PARAMETER = "parameter"
    RETURN_VALUE = "return_value"
    FUNCTION_CALL = "function_call"


class DependencyType(Enum):
    """Types of variable dependencies"""
    ASSIGNMENT = "assignment"
    READ = "read"
    MODIFICATION = "modification"
    CONDITIONAL = "conditional"


@dataclass
class VariableInfo:
    """Information about a variable"""
    name: str
    var_type: VariableType
    data_type: str
    declaration_line: int
    scope: str
    is_public: bool
    is_private: bool
    is_internal: bool
    is_external: bool
    is_constant: bool
    is_immutable: bool
    initial_value: Optional[str]
    dependencies: List[str]
    dependents: List[str]


@dataclass
class VariableUsage:
    """Represents a variable usage"""
    variable_name: str
    usage_type: DependencyType
    line_number: int
    context: str
    value_range: Optional[Tuple[Any, Any]]
    is_user_input: bool
    is_external_call: bool


@dataclass
class DependencyGraph:
    """Represents the dependency graph"""
    variables: Dict[str, VariableInfo]
    dependencies: Dict[str, List[str]]
    usages: List[VariableUsage]
    cycles: List[List[str]]


class VariableDependencyTracker:
    """Tracks variable dependencies and analyzes potential vulnerabilities"""
    
    def __init__(self):
        self.variable_map = {}
        self.dependency_graph = {}
        self.usage_history = []
        self.function_scopes = {}
        
    def track_variable_dependencies(self, contract_content: str) -> DependencyGraph:
        """Track all variable dependencies in contract"""
        lines = contract_content.split('\n')
        
        # Initialize tracking structures
        variables = {}
        dependencies = defaultdict(list)
        usages = []
        
        # Track function scopes
        current_function = None
        current_scope = "contract"
        
        for i, line in enumerate(lines, 1):
            line = line.strip()
            
            # Track function declarations
            function_match = re.search(r'function\s+(\w+)\s*\(', line)
            if function_match:
                current_function = function_match.group(1)
                current_scope = f"function_{current_function}"
            
            # Track variable declarations
            self._track_variable_declarations(line, i, variables, current_scope)
            
            # Track variable assignments
            self._track_variable_assignments(line, i, variables, dependencies, usages, current_function)
            
            # Track variable usages
            self._track_variable_usages(line, i, variables, usages, current_function)
            
            # Track function calls
            self._track_function_calls(line, i, variables, usages, current_function)
        
        # Detect dependency cycles
        cycles = self._detect_dependency_cycles(dependencies)
        
        return DependencyGraph(
            variables=variables,
            dependencies=dict(dependencies),
            usages=usages,
            cycles=cycles
        )
    
    def _track_variable_declarations(self, line: str, line_number: int, 
                                   variables: Dict[str, VariableInfo], scope: str):
        """Track variable declarations"""
        # State variable declarations
        state_var_pattern = r'(public|private|internal|external)?\s*(constant|immutable)?\s*(\w+)\s+(\w+)(?:\s*=\s*([^;]+))?;'
        state_matches = re.finditer(state_var_pattern, line)
        
        for match in state_matches:
            visibility = match.group(1) or 'internal'
            mutability = match.group(2) or ''
            data_type = match.group(3)
            var_name = match.group(4)
            initial_value = match.group(5)
            
            variables[var_name] = VariableInfo(
                name=var_name,
                var_type=VariableType.STATE_VARIABLE,
                data_type=data_type,
                declaration_line=line_number,
                scope=scope,
                is_public=visibility == 'public',
                is_private=visibility == 'private',
                is_internal=visibility == 'internal',
                is_external=visibility == 'external',
                is_constant='constant' in mutability,
                is_immutable='immutable' in mutability,
                initial_value=initial_value,
                dependencies=[],
                dependents=[]
            )
        
        # Local variable declarations
        local_var_pattern = r'(\w+)\s+(\w+)(?:\s*=\s*([^;]+))?;'
        local_matches = re.finditer(local_var_pattern, line)
        
        for match in local_matches:
            data_type = match.group(1)
            var_name = match.group(2)
            initial_value = match.group(3)
            
            # Skip if it's a function declaration
            if data_type in ['function', 'modifier', 'event', 'struct', 'enum']:
                continue
            
            variables[var_name] = VariableInfo(
                name=var_name,
                var_type=VariableType.LOCAL_VARIABLE,
                data_type=data_type,
                declaration_line=line_number,
                scope=scope,
                is_public=False,
                is_private=False,
                is_internal=False,
                is_external=False,
                is_constant=False,
                is_immutable=False,
                initial_value=initial_value,
                dependencies=[],
                dependents=[]
            )
    
    def _track_variable_assignments(self, line: str, line_number: int,
                                 variables: Dict[str, VariableInfo],
                                 dependencies: Dict[str, List[str]],
                                 usages: List[VariableUsage],
                                 current_function: Optional[str]):
        """Track variable assignments"""
        # Assignment pattern: variable = expression
        assignment_pattern = r'(\w+)\s*=\s*([^;]+);'
        matches = re.finditer(assignment_pattern, line)
        
        for match in matches:
            var_name = match.group(1)
            expression = match.group(2)
            
            if var_name in variables:
                # Track assignment usage
                usages.append(VariableUsage(
                    variable_name=var_name,
                    usage_type=DependencyType.ASSIGNMENT,
                    line_number=line_number,
                    context=expression,
                    value_range=None,
                    is_user_input=self._is_user_input(expression),
                    is_external_call=self._is_external_call(expression)
                ))
                
                # Extract dependencies from expression
                expr_vars = self._extract_variables_from_expression(expression)
                for expr_var in expr_vars:
                    if expr_var in variables:
                        dependencies[var_name].append(expr_var)
                        variables[expr_var].dependents.append(var_name)
    
    def _track_variable_usages(self, line: str, line_number: int,
                             variables: Dict[str, VariableInfo],
                             usages: List[VariableUsage],
                             current_function: Optional[str]):
        """Track variable usages"""
        # Find all variable references
        var_pattern = r'\b(\w+)\b'
        matches = re.finditer(var_pattern, line)
        
        for match in matches:
            var_name = match.group(1)
            
            if var_name in variables:
                # Determine usage type
                usage_type = DependencyType.READ
                if 'require(' in line or 'assert(' in line or 'if (' in line:
                    usage_type = DependencyType.CONDITIONAL
                elif '=' in line and var_name in line.split('=')[0]:
                    usage_type = DependencyType.MODIFICATION
                
                usages.append(VariableUsage(
                    variable_name=var_name,
                    usage_type=usage_type,
                    line_number=line_number,
                    context=line,
                    value_range=None,
                    is_user_input=self._is_user_input(line),
                    is_external_call=self._is_external_call(line)
                ))
    
    def _track_function_calls(self, line: str, line_number: int,
                           variables: Dict[str, VariableInfo],
                           usages: List[VariableUsage],
                           current_function: Optional[str]):
        """Track function calls"""
        # Function call pattern
        func_call_pattern = r'(\w+)\s*\([^)]*\)'
        matches = re.finditer(func_call_pattern, line)
        
        for match in matches:
            func_name = match.group(1)
            
            # Check if it's a variable being called as function
            if func_name in variables:
                usages.append(VariableUsage(
                    variable_name=func_name,
                    usage_type=DependencyType.FUNCTION_CALL,
                    line_number=line_number,
                    context=line,
                    value_range=None,
                    is_user_input=False,
                    is_external_call=True
                ))
    
    def _extract_variables_from_expression(self, expression: str) -> List[str]:
        """Extract variable names from expression"""
        # Remove function calls and keep only variable references
        cleaned_expr = re.sub(r'\w+\s*\([^)]*\)', '', expression)
        
        # Extract variable names
        var_pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b'
        matches = re.findall(var_pattern, cleaned_expr)
        
        # Filter out keywords and numbers
        keywords = {'uint', 'int', 'bool', 'address', 'string', 'bytes', 'mapping', 'struct', 'enum', 'function', 'return', 'if', 'else', 'for', 'while', 'do', 'break', 'continue', 'true', 'false', 'this', 'super', 'msg', 'tx', 'block', 'now', 'gasleft', 'revert', 'require', 'assert', 'modifier', 'event', 'emit', 'payable', 'view', 'pure', 'external', 'public', 'internal', 'private', 'memory', 'storage', 'calldata'}
        
        variables = []
        for match in matches:
            if match not in keywords and not match.isdigit():
                variables.append(match)
        
        return variables
    
    def _is_user_input(self, expression: str) -> bool:
        """Check if expression contains user input"""
        user_input_patterns = ['msg.sender', 'msg.value', 'tx.origin', 'msg.data', 'calldata']
        return any(pattern in expression for pattern in user_input_patterns)
    
    def _is_external_call(self, expression: str) -> bool:
        """Check if expression contains external calls"""
        external_patterns = ['.call(', '.delegatecall(', '.staticcall(', '.transfer(', '.send(']
        return any(pattern in expression for pattern in external_patterns)
    
    def _detect_dependency_cycles(self, dependencies: Dict[str, List[str]]) -> List[List[str]]:
        """Detect cycles in dependency graph using DFS"""
        cycles = []
        visited = set()
        rec_stack = set()
        path = []
        
        def dfs(node):
            visited.add(node)
            rec_stack.add(node)
            path.append(node)
            
            for neighbor in dependencies.get(node, []):
                if neighbor not in visited:
                    if dfs(neighbor):
                        return True
                elif neighbor in rec_stack:
                    # Found a cycle
                    cycle_start = path.index(neighbor)
                    cycle = path[cycle_start:] + [neighbor]
                    cycles.append(cycle)
                    return True
            
            rec_stack.remove(node)
            path.pop()
            return False
        
        for node in dependencies:
            if node not in visited:
                dfs(node)
        
        return cycles
    
    def analyze_variable_vulnerabilities(self, var_name: str, graph: DependencyGraph) -> List[Dict[str, Any]]:
        """Analyze specific variable for vulnerabilities"""
        vulnerabilities = []
        
        if var_name not in graph.variables:
            return vulnerabilities
        
        var_info = graph.variables[var_name]
        
        # Analyze for uninitialized variable usage
        vulnerabilities.extend(self._analyze_uninitialized_usage(var_name, graph))
        
        # Analyze for dependency cycles
        vulnerabilities.extend(self._analyze_dependency_cycles(var_name, graph))
        
        # Analyze for user input validation
        vulnerabilities.extend(self._analyze_user_input_validation(var_name, graph))
        
        # Analyze for external call dependencies
        vulnerabilities.extend(self._analyze_external_call_dependencies(var_name, graph))
        
        # Analyze for state variable exposure
        vulnerabilities.extend(self._analyze_state_variable_exposure(var_name, graph))
        
        return vulnerabilities
    
    def _analyze_uninitialized_usage(self, var_name: str, graph: DependencyGraph) -> List[Dict[str, Any]]:
        """Analyze for uninitialized variable usage"""
        vulnerabilities = []
        
        if var_name not in graph.variables:
            return vulnerabilities
        
        var_info = graph.variables[var_name]
        
        # Check if variable is used before initialization
        if not var_info.initial_value and var_info.var_type == VariableType.LOCAL_VARIABLE:
            # Find first usage
            first_usage = None
            for usage in graph.usages:
                if usage.variable_name == var_name:
                    first_usage = usage
                    break
            
            if first_usage and first_usage.line_number < var_info.declaration_line:
                vulnerabilities.append({
                    'type': 'uninitialized_variable',
                    'severity': 'medium',
                    'description': f'Variable {var_name} used before initialization',
                    'line_number': first_usage.line_number,
                    'confidence': 0.8
                })
        
        return vulnerabilities
    
    def _analyze_dependency_cycles(self, var_name: str, graph: DependencyGraph) -> List[Dict[str, Any]]:
        """Analyze for dependency cycles involving the variable"""
        vulnerabilities = []
        
        for cycle in graph.cycles:
            if var_name in cycle:
                vulnerabilities.append({
                    'type': 'dependency_cycle',
                    'severity': 'high',
                    'description': f'Variable {var_name} involved in dependency cycle: {" -> ".join(cycle)}',
                    'line_number': graph.variables[var_name].declaration_line,
                    'confidence': 0.9
                })
        
        return vulnerabilities
    
    def _analyze_user_input_validation(self, var_name: str, graph: DependencyGraph) -> List[Dict[str, Any]]:
        """Analyze user input validation for the variable"""
        vulnerabilities = []
        
        # Check if variable depends on user input without validation
        user_input_usages = [usage for usage in graph.usages 
                           if usage.variable_name == var_name and usage.is_user_input]
        
        if user_input_usages:
            # Check if there's validation
            validation_found = False
            for usage in graph.usages:
                if (usage.variable_name == var_name and 
                    ('require(' in usage.context or 'assert(' in usage.context)):
                    validation_found = True
                    break
            
            if not validation_found:
                vulnerabilities.append({
                    'type': 'missing_input_validation',
                    'severity': 'high',
                    'description': f'Variable {var_name} depends on user input without validation',
                    'line_number': user_input_usages[0].line_number,
                    'confidence': 0.7
                })
        
        return vulnerabilities
    
    def _analyze_external_call_dependencies(self, var_name: str, graph: DependencyGraph) -> List[Dict[str, Any]]:
        """Analyze external call dependencies for the variable"""
        vulnerabilities = []
        
        # Check if variable depends on external calls
        external_call_usages = [usage for usage in graph.usages 
                              if usage.variable_name == var_name and usage.is_external_call]
        
        if external_call_usages:
            vulnerabilities.append({
                'type': 'external_call_dependency',
                'severity': 'medium',
                'description': f'Variable {var_name} depends on external calls - potential reentrancy risk',
                'line_number': external_call_usages[0].line_number,
                'confidence': 0.6
            })
        
        return vulnerabilities
    
    def _analyze_state_variable_exposure(self, var_name: str, graph: DependencyGraph) -> List[Dict[str, Any]]:
        """Analyze state variable exposure"""
        vulnerabilities = []
        
        if var_name not in graph.variables:
            return vulnerabilities
        
        var_info = graph.variables[var_name]
        
        if var_info.var_type == VariableType.STATE_VARIABLE:
            # Check if sensitive state variable is public
            if var_info.is_public and self._is_sensitive_variable(var_name):
                vulnerabilities.append({
                    'type': 'sensitive_state_exposure',
                    'severity': 'medium',
                    'description': f'Sensitive state variable {var_name} is public',
                    'line_number': var_info.declaration_line,
                    'confidence': 0.7
                })
        
        return vulnerabilities
    
    def _is_sensitive_variable(self, var_name: str) -> bool:
        """Check if variable name suggests sensitive data"""
        sensitive_patterns = ['password', 'secret', 'key', 'private', 'admin', 'owner', 'balance', 'amount']
        return any(pattern in var_name.lower() for pattern in sensitive_patterns)
    
    def get_variable_dependency_chain(self, var_name: str, graph: DependencyGraph) -> List[str]:
        """Get the dependency chain for a variable"""
        if var_name not in graph.variables:
            return []
        
        visited = set()
        chain = []
        
        def build_chain(node):
            if node in visited:
                return
            visited.add(node)
            chain.append(node)
            
            for dep in graph.dependencies.get(node, []):
                build_chain(dep)
        
        build_chain(var_name)
        return chain
    
    def get_variable_impact_analysis(self, var_name: str, graph: DependencyGraph) -> Dict[str, Any]:
        """Get impact analysis for a variable"""
        if var_name not in graph.variables:
            return {}
        
        var_info = graph.variables[var_name]
        
        # Count dependents
        dependent_count = len(var_info.dependents)
        
        # Count usages
        usage_count = len([usage for usage in graph.usages if usage.variable_name == var_name])
        
        # Check if variable is used in external functions
        external_usage = any(usage.is_external_call for usage in graph.usages 
                           if usage.variable_name == var_name)
        
        # Check if variable depends on user input
        user_input_dependency = any(usage.is_user_input for usage in graph.usages 
                                  if usage.variable_name == var_name)
        
        return {
            'variable_name': var_name,
            'dependent_count': dependent_count,
            'usage_count': usage_count,
            'external_usage': external_usage,
            'user_input_dependency': user_input_dependency,
            'impact_score': dependent_count + usage_count + (2 if external_usage else 0) + (1 if user_input_dependency else 0)
        }
