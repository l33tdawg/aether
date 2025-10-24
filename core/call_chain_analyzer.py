#!/usr/bin/env python3
"""
Call Chain Analyzer - Tracks function call paths and access control propagation.

This module analyzes complete call chains to determine if functions are actually
protected by access control, even if the protection is in a calling function rather
than the function itself.

Solves false positives like:
- Library functions flagged as unprotected when only called from protected facets
- Internal functions flagged when all entry points have access control
- Constructor-only functions flagged as runtime vulnerabilities
"""

from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict, deque
import re


@dataclass
class FunctionInfo:
    """Information about a function."""
    name: str
    contract: str
    visibility: str  # public, external, internal, private
    modifiers: List[str] = field(default_factory=list)
    is_constructor: bool = False
    is_fallback: bool = False
    line_number: int = 0
    body: str = ""
    calls: List[str] = field(default_factory=list)  # Functions this function calls


@dataclass
class CallPath:
    """Represents a call path to a function."""
    entry_point: str  # e.g., "DiamondCut.diamondCut"
    call_chain: List[str]  # ["DiamondCut.diamondCut", "LibDiamond.diamondCut", "_initializeDiamondCut"]
    has_access_control: bool
    access_modifiers: List[str] = field(default_factory=list)
    is_constructor_only: bool = False
    confidence: float = 0.8


class CallChainAnalyzer:
    """Analyzes complete call chains to determine if functions are actually protected."""
    
    # Known access control modifiers (can be extended)
    ACCESS_MODIFIERS = [
        'onlyOwner', 'onlyGovernor', 'onlyGuardian', 'onlyGov',
        'onlyRole', 'restricted', 'onlyAdmin', 'onlyController',
        'onlyGovernance', 'onlyAuthorized', 'onlyLatestNetworkContract',
        'onlyMinter', 'onlyBurner', 'whenNotPaused', 'requiresAuth'
    ]
    
    def __init__(self):
        self.functions: Dict[str, FunctionInfo] = {}  # "Contract.function" -> FunctionInfo
        self.call_graph: Dict[str, Set[str]] = defaultdict(set)  # caller -> set of callees
        self.reverse_call_graph: Dict[str, Set[str]] = defaultdict(set)  # callee -> set of callers
        self.entry_points: Set[str] = set()  # public/external functions
        
    def build_call_graph(self, contract_files: List[Dict]) -> Dict:
        """
        Build complete call graph across all contracts.
        
        Args:
            contract_files: List of dicts with 'content', 'name', 'path'
            
        Returns:
            Dict with call graph information
        """
        print("🔍 Building call graph...")
        
        # Step 1: Extract all function definitions
        for contract_file in contract_files:
            self._extract_functions(contract_file)
        
        # Step 2: Build call relationships
        for func_key, func_info in self.functions.items():
            self._extract_function_calls(func_info)
        
        # Step 3: Identify entry points
        self._identify_entry_points()
        
        print(f"   Found {len(self.functions)} functions, {len(self.entry_points)} entry points")
        
        return {
            'functions': len(self.functions),
            'entry_points': len(self.entry_points),
            'call_edges': sum(len(v) for v in self.call_graph.values())
        }
    
    def _extract_functions(self, contract_file: Dict):
        """Extract all function definitions from a contract file."""
        content = contract_file['content']
        contract_name = self._extract_contract_name(content)
        
        if not contract_name:
            # Try to get from filename
            contract_name = contract_file['name'].replace('.sol', '')
        
        # Pattern to match function definitions (improved to handle modifiers)
        # Matches: function name(params) visibility [modifiers] returns
        func_pattern = r'function\s+(\w+)\s*\([^)]*\)\s*(public|external|internal|private)?([^{]*?)\{'
        
        for match in re.finditer(func_pattern, content):
            func_name = match.group(1)
            visibility = match.group(2) or 'public'  # Default to public if not specified
            modifiers_section = match.group(3) or ''
            
            # Extract modifiers from the section between visibility and {
            modifiers = []
            for modifier in self.ACCESS_MODIFIERS:
                if modifier in modifiers_section:
                    modifiers.append(modifier)
            
            # Also check for custom modifiers (simple pattern)
            custom_modifier_pattern = r'\b([a-z][a-zA-Z0-9]*)\s*(?:\([^)]*\))?\s*(?=\{|returns?|public|external|internal|private)'
            for custom_match in re.finditer(custom_modifier_pattern, modifiers_section):
                potential_modifier = custom_match.group(1)
                if potential_modifier not in ['returns', 'return', 'view', 'pure', 'payable', 'virtual', 'override']:
                    if potential_modifier not in modifiers:
                        modifiers.append(potential_modifier)
            
            # Extract function body
            body_start = match.end()
            body = self._extract_function_body(content, body_start - 1)
            
            # Line number
            line_num = content[:match.start()].count('\n') + 1
            
            func_key = f"{contract_name}.{func_name}"
            
            self.functions[func_key] = FunctionInfo(
                name=func_name,
                contract=contract_name,
                visibility=visibility,
                modifiers=modifiers,
                is_constructor=(func_name == 'constructor'),
                line_number=line_num,
                body=body
            )
        
        # Also check for constructor
        constructor_pattern = r'constructor\s*\([^)]*\)([^{]*?)\{'
        for match in re.finditer(constructor_pattern, content):
            modifiers_section = match.group(1) or ''
            modifiers = []
            for modifier in self.ACCESS_MODIFIERS:
                if modifier in modifiers_section:
                    modifiers.append(modifier)
            
            body_start = match.end()
            body = self._extract_function_body(content, body_start - 1)
            line_num = content[:match.start()].count('\n') + 1
            
            func_key = f"{contract_name}.constructor"
            
            self.functions[func_key] = FunctionInfo(
                name='constructor',
                contract=contract_name,
                visibility='public',
                modifiers=modifiers,
                is_constructor=True,
                line_number=line_num,
                body=body
            )
    
    def _extract_contract_name(self, content: str) -> Optional[str]:
        """Extract contract/library name from source."""
        # Try contract
        match = re.search(r'contract\s+(\w+)', content)
        if match:
            return match.group(1)
        
        # Try library
        match = re.search(r'library\s+(\w+)', content)
        if match:
            return match.group(1)
        
        return None
    
    def _extract_function_body(self, content: str, start_pos: int) -> str:
        """Extract function body by matching braces."""
        brace_count = 0
        i = start_pos
        body_start = start_pos
        
        while i < len(content):
            if content[i] == '{':
                if brace_count == 0:
                    body_start = i + 1
                brace_count += 1
            elif content[i] == '}':
                brace_count -= 1
                if brace_count == 0:
                    return content[body_start:i]
            i += 1
        
        return ""
    
    def _extract_function_calls(self, func_info: FunctionInfo):
        """Extract function calls made within a function."""
        body = func_info.body
        
        # Keywords to exclude from function calls
        keywords = {'if', 'for', 'while', 'require', 'assert', 'revert', 'emit', 'return'}
        
        caller_key = f"{func_info.contract}.{func_info.name}"
        
        # First, find all qualified calls (LibName.function or ContractName.function)
        qualified_call_pattern = r'\b([A-Z][a-zA-Z0-9_]*)\.([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
        
        found_calls = set()  # Track what we've already found
        
        for match in re.finditer(qualified_call_pattern, body):
            lib_or_contract = match.group(1)
            called_func = match.group(2)
            
            if called_func in keywords:
                continue
            
            # Try to find this function
            qualified_key = f"{lib_or_contract}.{called_func}"
            if qualified_key in self.functions:
                self.call_graph[caller_key].add(qualified_key)
                self.reverse_call_graph[qualified_key].add(caller_key)
                found_calls.add(called_func)
        
        # Then find unqualified calls (same contract/library)
        unqualified_call_pattern = r'\b([a-z_][a-zA-Z0-9_]*)\s*\('
        
        for match in re.finditer(unqualified_call_pattern, body):
            called_func = match.group(1)
            
            if called_func in keywords or called_func in found_calls:
                continue
            
            # Check if it's in the same contract/library
            same_contract_key = f"{func_info.contract}.{called_func}"
            if same_contract_key in self.functions:
                self.call_graph[caller_key].add(same_contract_key)
                self.reverse_call_graph[same_contract_key].add(caller_key)
                found_calls.add(called_func)
    
    def _identify_entry_points(self):
        """Identify entry points (public/external functions, constructors)."""
        for func_key, func_info in self.functions.items():
            if func_info.visibility in ['public', 'external'] or func_info.is_constructor:
                self.entry_points.add(func_key)
    
    def find_all_paths_to_function(self, function_name: str, contract_name: str = None) -> List[CallPath]:
        """
        Find all possible call paths that can reach this function.
        
        Args:
            function_name: Name of the function
            contract_name: Optional contract name to disambiguate
            
        Returns:
            List of CallPath objects showing all ways to reach this function
        """
        # Find the function key
        target_keys = []
        if contract_name:
            target_key = f"{contract_name}.{function_name}"
            if target_key in self.functions:
                target_keys.append(target_key)
        else:
            # Search all contracts for this function name
            for func_key in self.functions:
                if func_key.endswith(f".{function_name}"):
                    target_keys.append(func_key)
        
        if not target_keys:
            return []
        
        all_paths = []
        for target_key in target_keys:
            paths = self._find_paths_bfs(target_key)
            all_paths.extend(paths)
        
        return all_paths
    
    def _find_paths_bfs(self, target_key: str) -> List[CallPath]:
        """Find all paths from entry points to target using BFS."""
        paths = []
        
        # BFS from each entry point
        for entry_point in self.entry_points:
            # Use BFS to find all paths
            queue = deque([(entry_point, [entry_point])])
            visited_paths = set()
            
            while queue:
                current, path = queue.popleft()
                
                # Avoid infinite loops
                path_tuple = tuple(path)
                if path_tuple in visited_paths:
                    continue
                visited_paths.add(path_tuple)
                
                # Check if we reached the target
                if current == target_key:
                    # Create CallPath object
                    entry_func = self.functions[entry_point]
                    
                    # Check if this path has access control
                    has_ac = len(entry_func.modifiers) > 0
                    ac_modifiers = entry_func.modifiers if has_ac else []
                    is_constructor = entry_func.is_constructor
                    
                    call_path = CallPath(
                        entry_point=entry_point,
                        call_chain=path,
                        has_access_control=has_ac,
                        access_modifiers=ac_modifiers,
                        is_constructor_only=is_constructor
                    )
                    paths.append(call_path)
                    continue
                
                # Explore neighbors
                if current in self.call_graph:
                    for next_func in self.call_graph[current]:
                        # Avoid cycles (but allow path exploration)
                        if len(path) < 10:  # Limit path length to prevent infinite loops
                            queue.append((next_func, path + [next_func]))
        
        return paths
    
    def is_function_protected(self, function_name: str, contract_name: str = None) -> Dict:
        """
        Determine if a function is actually protected by checking ALL call paths.
        
        Returns: {
            'protected': bool,
            'reasoning': str,
            'unprotected_paths': List[CallPath],
            'protected_paths': List[CallPath],
            'constructor_only_paths': List[CallPath],
            'confidence': float
        }
        """
        all_paths = self.find_all_paths_to_function(function_name, contract_name)
        
        if not all_paths:
            # Function not found or unreachable
            return {
                'protected': False,
                'reasoning': f"Function {function_name} not found in call graph or unreachable",
                'unprotected_paths': [],
                'protected_paths': [],
                'constructor_only_paths': [],
                'confidence': 0.3
            }
        
        # Categorize paths
        protected_paths = []
        unprotected_paths = []
        constructor_only_paths = []
        
        for path in all_paths:
            if path.is_constructor_only:
                constructor_only_paths.append(path)
            elif path.has_access_control:
                protected_paths.append(path)
            else:
                unprotected_paths.append(path)
        
        # Determine protection status
        if unprotected_paths:
            # There are unprotected runtime paths - vulnerable
            return {
                'protected': False,
                'reasoning': f"Found {len(unprotected_paths)} unprotected runtime path(s) to {function_name}",
                'unprotected_paths': unprotected_paths,
                'protected_paths': protected_paths,
                'constructor_only_paths': constructor_only_paths,
                'confidence': 0.9
            }
        elif protected_paths:
            # All runtime paths are protected
            modifiers = set()
            for path in protected_paths:
                modifiers.update(path.access_modifiers)
            
            return {
                'protected': True,
                'reasoning': f"All {len(protected_paths)} runtime path(s) to {function_name} are protected by: {', '.join(modifiers)}",
                'unprotected_paths': [],
                'protected_paths': protected_paths,
                'constructor_only_paths': constructor_only_paths,
                'confidence': 0.95
            }
        elif constructor_only_paths:
            # Only reachable from constructor - deployment-time only
            return {
                'protected': True,
                'reasoning': f"{function_name} is only reachable from constructor (deployment-time only, not runtime exploitable)",
                'unprotected_paths': [],
                'protected_paths': [],
                'constructor_only_paths': constructor_only_paths,
                'confidence': 0.9
            }
        else:
            # No paths found (shouldn't happen if we got here)
            return {
                'protected': False,
                'reasoning': "Unexpected state: paths found but none categorized",
                'unprotected_paths': [],
                'protected_paths': [],
                'constructor_only_paths': [],
                'confidence': 0.1
            }
    
    def get_function_info(self, function_name: str, contract_name: str = None) -> Optional[FunctionInfo]:
        """Get information about a specific function."""
        if contract_name:
            func_key = f"{contract_name}.{function_name}"
            return self.functions.get(func_key)
        else:
            # Search for function
            for func_key, func_info in self.functions.items():
                if func_key.endswith(f".{function_name}"):
                    return func_info
        return None
    
    def visualize_paths(self, paths: List[CallPath]) -> str:
        """Create a text visualization of call paths."""
        if not paths:
            return "No paths found"
        
        output = []
        for i, path in enumerate(paths, 1):
            protection = "✅ PROTECTED" if path.has_access_control else "❌ UNPROTECTED"
            if path.is_constructor_only:
                protection = "🔨 CONSTRUCTOR-ONLY"
            
            output.append(f"\nPath {i}: {protection}")
            for j, func_key in enumerate(path.call_chain):
                indent = "  " * j
                func_info = self.functions.get(func_key)
                if func_info:
                    modifiers = f" [{', '.join(func_info.modifiers)}]" if func_info.modifiers else ""
                    output.append(f"{indent}→ {func_key} ({func_info.visibility}){modifiers}")
                else:
                    output.append(f"{indent}→ {func_key}")
        
        return "\n".join(output)

