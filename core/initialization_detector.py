"""
Initialization Vulnerability Detector for Smart Contract Security

This module detects initialization vulnerabilities including:
- Front-running risks in unprotected initialization functions
- Missing access control on init/initialize functions
- Improper initialization patterns
- Reinitialization vulnerabilities
"""

import re
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum


class InitializationType(Enum):
    """Types of initialization vulnerabilities"""
    UNPROTECTED_INIT = "unprotected_initialization"
    FRONTRUN_RISK = "initialization_frontrun_risk"
    MISSING_INITIALIZER_MODIFIER = "missing_initializer_modifier"
    WEAK_INIT_CHECK = "weak_initialization_check"
    REINITIALIZATION_RISK = "reinitialization_risk"
    STATE_MODIFICATION_WITHOUT_ACCESS_CONTROL = "state_modification_without_access_control"


@dataclass
class InitializationVulnerability:
    """Represents an initialization vulnerability"""
    vulnerability_type: str
    severity: str
    description: str
    line_number: int
    code_snippet: str
    confidence: float
    swc_id: str
    recommendation: str
    function_name: str
    has_access_control: bool
    has_initializer_modifier: bool
    has_internal_check_only: bool
    state_variables_modified: List[str]
    context: Dict[str, Any]


class InitializationDetector:
    """Detects initialization vulnerabilities in smart contracts"""
    
    def __init__(self):
        self.init_patterns = self._initialize_init_patterns()
        self.access_control_modifiers = self._initialize_access_control_modifiers()
        self.initializer_modifiers = self._initialize_initializer_modifiers()
        self.internal_check_patterns = self._initialize_internal_check_patterns()
        self.state_modification_patterns = self._initialize_state_modification_patterns()
        
    def _initialize_init_patterns(self) -> List[Dict[str, Any]]:
        """Initialize patterns for initialization function detection"""
        return [
            {
                'pattern': r'function\s+(init|initialize)\s*\([^)]*\)\s+(external|public)',
                'description': 'Initialization function',
                'type': 'init_function'
            },
            {
                'pattern': r'function\s+__init\w*\s*\([^)]*\)',
                'description': 'Internal initialization function',
                'type': 'internal_init'
            },
            {
                'pattern': r'function\s+\w*[Ii]nit\w*\s*\([^)]*\)\s+(external|public)',
                'description': 'Init-like function',
                'type': 'init_like'
            }
        ]
    
    def _initialize_access_control_modifiers(self) -> Set[str]:
        """Initialize access control modifiers"""
        return {
            'onlyOwner', 'onlyAdmin', 'onlyAdminOrOwner', 'onlyGovernance',
            'onlyController', 'onlyManager', 'onlyRole', 'onlyAuthorized',
            'restricted', 'authorized', 'onlyProxy', 'onlyDelegateCall'
        }
    
    def _initialize_initializer_modifiers(self) -> Set[str]:
        """Initialize OpenZeppelin-style initializer modifiers"""
        return {
            'initializer', 'reinitializer', 'onlyInitializing'
        }
    
    def _initialize_internal_check_patterns(self) -> List[str]:
        """Initialize patterns for internal initialization checks"""
        return [
            r'require\s*\(\s*!.*__isInitialized',
            r'require\s*\(\s*!.*initialized',
            r'require\s*\(\s*!.*_initialized',
            r'if\s*\(\s*.*initialized.*\)\s*revert',
            r'if\s*\(\s*__isInitialized\(\)\s*\)\s*revert',
            r'require\s*\(\s*!\s*initialized',  # Simple check
            r'require\s*\(\s*!\s*__isInitialized\(\)',  # With function call
        ]
    
    def _initialize_state_modification_patterns(self) -> List[str]:
        """Initialize patterns for state modifications"""
        return [
            r'(\w+)\s*=\s*([^;]+);',  # Assignment
            r'\.push\s*\(',
            r'\.pop\s*\(',
            r'delete\s+\w+',
            r'mapping\s*\([^)]+\)\s*=',
        ]
    
    def analyze_initialization(self, contract_content: str, contract_name: str = "") -> List[InitializationVulnerability]:
        """Analyze initialization patterns for vulnerabilities"""
        vulnerabilities = []
        
        # Split content into lines for line number tracking
        lines = contract_content.split('\n')
        
        # Detect unprotected initialization functions
        vulnerabilities.extend(self._detect_unprotected_init(contract_content, lines, contract_name))
        
        # Detect weak internal-only checks (front-running risk)
        vulnerabilities.extend(self._detect_weak_init_checks(contract_content, lines, contract_name))
        
        # Detect missing initializer modifiers (OpenZeppelin pattern)
        vulnerabilities.extend(self._detect_missing_initializer_modifier(contract_content, lines, contract_name))
        
        # Detect potential reinitialization vulnerabilities
        vulnerabilities.extend(self._detect_reinitialization_risk(contract_content, lines, contract_name))
        
        return vulnerabilities
    
    def _detect_unprotected_init(self, contract_content: str, lines: List[str], contract_name: str) -> List[InitializationVulnerability]:
        """Detect initialization functions without proper access control"""
        vulnerabilities = []
        
        # Pattern for init functions
        init_pattern = r'function\s+(init|initialize|__init\w*)\s*\(([^)]*)\)\s+(external|public)([^{]*)\{'
        matches = re.finditer(init_pattern, contract_content, re.MULTILINE | re.IGNORECASE)
        
        for match in matches:
            function_name = match.group(1)
            params = match.group(2)
            visibility = match.group(3)
            modifiers_section = match.group(4)
            
            line_number = self._get_line_number(match.start(), contract_content)
            
            # Check for access control modifiers
            has_access_control = any(modifier in modifiers_section for modifier in self.access_control_modifiers)
            has_initializer_modifier = any(modifier in modifiers_section for modifier in self.initializer_modifiers)
            
            # Get function body
            function_body = self._get_function_body(contract_content, match.start())
            
            # Check if relies only on internal checks
            has_internal_check_only = any(
                re.search(pattern, function_body, re.MULTILINE | re.DOTALL) 
                for pattern in self.internal_check_patterns
            )
            
            # Find state variables being modified
            state_vars = self._find_modified_state_variables(function_body)
            
            # Determine if this is vulnerable
            is_vulnerable = False
            vuln_type = None
            severity = "medium"
            confidence = 0.7
            description = ""
            recommendation = ""
            
            if visibility in ['external', 'public'] and not has_access_control:
                if has_internal_check_only and state_vars:
                    # This is the critical pattern from AccountERC20Tracker
                    is_vulnerable = True
                    vuln_type = InitializationType.FRONTRUN_RISK
                    severity = "high"
                    confidence = 0.88
                    description = (
                        f"The `{function_name}` function is {visibility} and lacks access control modifiers. "
                        f"While it includes a check like `require(!__isInitialized())`, this only prevents "
                        f"double initialization but does NOT restrict WHO can call it. An attacker can "
                        f"front-run the legitimate initialization and set critical state variables "
                        f"(e.g., {', '.join(state_vars[:3]) if state_vars else 'account'}) to malicious values, "
                        f"permanently compromising the contract before the intended owner initializes it."
                    )
                    recommendation = (
                        f"Add an access control modifier like `onlyOwner` or use OpenZeppelin's "
                        f"`initializer` modifier. For proxy patterns, consider using `onlyProxy` or "
                        f"`onlyDelegateCall` to ensure initialization happens in the correct context."
                    )
                elif not has_internal_check_only:
                    # No protection at all
                    is_vulnerable = True
                    vuln_type = InitializationType.UNPROTECTED_INIT
                    severity = "critical"
                    confidence = 0.95
                    description = (
                        f"The `{function_name}` function is {visibility} with no access control "
                        f"and no initialization state check. Anyone can call this function and "
                        f"potentially set critical state variables, leading to complete contract compromise."
                    )
                    recommendation = (
                        f"Add both access control (e.g., `onlyOwner`) and initialization checks "
                        f"(e.g., `initializer` modifier from OpenZeppelin)."
                    )
            
            if is_vulnerable:
                # Get code snippet with context
                code_snippet = self._get_code_snippet(lines, line_number, context_lines=5)
                
                vulnerability = InitializationVulnerability(
                    vulnerability_type=vuln_type.value,
                    severity=severity,
                    description=description,
                    line_number=line_number,
                    code_snippet=code_snippet,
                    confidence=confidence,
                    swc_id='SWC-105',  # Unprotected Ether Withdrawal / Access Control
                    recommendation=recommendation,
                    function_name=function_name,
                    has_access_control=has_access_control,
                    has_initializer_modifier=has_initializer_modifier,
                    has_internal_check_only=has_internal_check_only,
                    state_variables_modified=state_vars,
                    context={
                        'contract_name': contract_name,
                        'visibility': visibility,
                        'parameters': params,
                        'modifiers': modifiers_section.strip(),
                        'uses_openzeppelin_pattern': has_initializer_modifier
                    }
                )
                
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _detect_weak_init_checks(self, contract_content: str, lines: List[str], contract_name: str) -> List[InitializationVulnerability]:
        """Detect initialization functions with weak internal-only checks"""
        vulnerabilities = []
        
        # This is already covered in _detect_unprotected_init but can be separated for clarity
        # For now, we'll skip to avoid duplication
        
        return vulnerabilities
    
    def _detect_missing_initializer_modifier(self, contract_content: str, lines: List[str], contract_name: str) -> List[InitializationVulnerability]:
        """Detect init functions missing OpenZeppelin initializer modifier"""
        vulnerabilities = []
        
        # Check if contract uses OpenZeppelin upgradeable pattern
        uses_upgradeable = 'Initializable' in contract_content or 'Upgradeable' in contract_content
        
        if not uses_upgradeable:
            # Not using upgradeable pattern, so this check doesn't apply
            return vulnerabilities
        
        # Find init functions without initializer modifier
        init_pattern = r'function\s+(init|initialize)\s*\(([^)]*)\)\s+(external|public)([^{]*)\{'
        matches = re.finditer(init_pattern, contract_content, re.MULTILINE)
        
        for match in matches:
            function_name = match.group(1)
            modifiers_section = match.group(4)
            
            has_initializer = any(mod in modifiers_section for mod in self.initializer_modifiers)
            
            if not has_initializer:
                line_number = self._get_line_number(match.start(), contract_content)
                code_snippet = self._get_code_snippet(lines, line_number, context_lines=3)
                
                vulnerability = InitializationVulnerability(
                    vulnerability_type=InitializationType.MISSING_INITIALIZER_MODIFIER.value,
                    severity="medium",
                    description=(
                        f"The `{function_name}` function in an Upgradeable contract "
                        f"is missing the `initializer` modifier. This can lead to "
                        f"reinitialization vulnerabilities or improper initialization state tracking."
                    ),
                    line_number=line_number,
                    code_snippet=code_snippet,
                    confidence=0.85,
                    swc_id='SWC-105',
                    recommendation=(
                        f"Add the `initializer` or `reinitializer(uint64 version)` modifier "
                        f"from OpenZeppelin's Initializable contract."
                    ),
                    function_name=function_name,
                    has_access_control=False,
                    has_initializer_modifier=False,
                    has_internal_check_only=True,
                    state_variables_modified=[],
                    context={
                        'contract_name': contract_name,
                        'uses_upgradeable_pattern': True
                    }
                )
                
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _detect_reinitialization_risk(self, contract_content: str, lines: List[str], contract_name: str) -> List[InitializationVulnerability]:
        """Detect potential reinitialization vulnerabilities"""
        vulnerabilities = []
        
        # Look for init functions that might be called multiple times
        # This is a complex analysis - for now, we'll do basic pattern matching
        
        return vulnerabilities
    
    def _get_function_body(self, contract_content: str, start_pos: int) -> str:
        """Extract function body starting from position (can be function start or anywhere)"""
        brace_count = 0
        in_function = False
        body_start = None
        
        # Find the opening brace
        for i in range(start_pos, len(contract_content)):
            char = contract_content[i]
            
            if char == '{':
                if not in_function:
                    in_function = True
                    body_start = i + 1  # Start after the opening brace
                brace_count += 1
            elif char == '}':
                brace_count -= 1
                if in_function and brace_count == 0:
                    # Return the function body (content between braces)
                    return contract_content[body_start:i]
        
        return ""
    
    def _find_modified_state_variables(self, function_body: str) -> List[str]:
        """Find state variables being modified in function"""
        modified_vars = []
        
        # Look for ERC7201 pattern first ($.varname = ...)
        erc7201_pattern = r'\$\.(\w+)\s*='
        matches = re.finditer(erc7201_pattern, function_body)
        for match in matches:
            modified_vars.append(match.group(1))
        
        # Look for direct assignments (varname = ...)
        # But be careful to extract the left-hand side only
        assignment_pattern = r'^\s*(\w+)\s*=\s*[^;=]+;'
        for line in function_body.split('\n'):
            match = re.search(assignment_pattern, line)
            if match:
                var_name = match.group(1)
                # Filter out obvious local variables and parameters
                if (not var_name.startswith('_') and 
                    var_name not in ['i', 'j', 'k', 'index', 'count', 'result', 'temp']):
                    modified_vars.append(var_name)
        
        # Look for member assignments (storage.field = ...)
        member_pattern = r'(\w+)\.(\w+)\s*='
        matches = re.finditer(member_pattern, function_body)
        for match in matches:
            struct_name = match.group(1)
            field_name = match.group(2)
            # If it looks like storage access, add the field
            if '$' in struct_name or 'storage' in struct_name.lower():
                modified_vars.append(field_name)
        
        return list(set(modified_vars))  # Remove duplicates
    
    def _get_line_number(self, position: int, content: str) -> int:
        """Get line number from character position"""
        return content[:position].count('\n') + 1
    
    def _get_code_snippet(self, lines: List[str], line_number: int, context_lines: int = 3) -> str:
        """Get code snippet with context"""
        start_line = max(0, line_number - context_lines - 1)
        end_line = min(len(lines), line_number + context_lines)
        
        snippet_lines = []
        for i in range(start_line, end_line):
            if i < len(lines):
                prefix = ">>> " if i == line_number - 1 else "    "
                snippet_lines.append(f"{prefix}{lines[i]}")
        
        return '\n'.join(snippet_lines)
    
    def get_initialization_summary(self, contract_content: str) -> Dict[str, Any]:
        """Get summary of initialization patterns in contract"""
        summary = {
            'has_init_function': False,
            'uses_upgradeable_pattern': False,
            'uses_openzeppelin_initializer': False,
            'init_functions': [],
            'total_vulnerabilities': 0,
            'critical_vulnerabilities': 0,
            'high_vulnerabilities': 0
        }
        
        # Check for init functions
        init_pattern = r'function\s+(init|initialize)\s*\('
        if re.search(init_pattern, contract_content, re.IGNORECASE):
            summary['has_init_function'] = True
        
        # Check for upgradeable pattern
        if 'Initializable' in contract_content or 'Upgradeable' in contract_content:
            summary['uses_upgradeable_pattern'] = True
        
        # Check for OpenZeppelin initializer
        if 'initializer' in contract_content:
            summary['uses_openzeppelin_initializer'] = True
        
        # Find all init functions
        matches = re.finditer(init_pattern, contract_content, re.IGNORECASE)
        for match in matches:
            summary['init_functions'].append(match.group(1))
        
        # Run analysis to get vulnerability counts
        vulnerabilities = self.analyze_initialization(contract_content)
        summary['total_vulnerabilities'] = len(vulnerabilities)
        summary['critical_vulnerabilities'] = len([v for v in vulnerabilities if v.severity == 'critical'])
        summary['high_vulnerabilities'] = len([v for v in vulnerabilities if v.severity == 'high'])
        
        return summary

