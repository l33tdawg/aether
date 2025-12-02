"""
Reentrancy Guard Detector

Detects existing reentrancy protection mechanisms to prevent false positives
when flagging potential reentrancy vulnerabilities.
"""

import re
from typing import List, Dict, Any, Set, Optional
from dataclasses import dataclass


@dataclass
class ReentrancyProtection:
    """Represents detected reentrancy protection."""
    protection_type: str  # 'modifier', 'library', 'pattern'
    function_name: str
    line_number: int
    mechanism: str  # e.g., 'nonReentrant', 'ReentrancyGuard', 'mutex'


class ReentrancyGuardDetector:
    """
    Detects reentrancy protection mechanisms in Solidity contracts.
    
    Checks for:
    - nonReentrant modifier
    - ReentrancyGuard inheritance
    - Custom mutex patterns
    - CEI (Checks-Effects-Interactions) pattern compliance
    """
    
    REENTRANCY_MODIFIERS = [
        'nonReentrant',
        'noReentrancy',
        'nonreentrant',
        'reentrancyGuard',
        'lock',
        'mutex',
    ]
    
    REENTRANCY_GUARD_LIBRARIES = [
        'ReentrancyGuard',
        'ReentrancyGuardUpgradeable',
        'nonReentrant',
    ]
    
    def __init__(self):
        pass
    
    def detect_protections(
        self,
        contract_code: str,
        contract_name: str
    ) -> List[ReentrancyProtection]:
        """
        Detect all reentrancy protections in the contract.
        
        Args:
            contract_code: The Solidity source code
            contract_name: Name of the contract
            
        Returns:
            List of detected reentrancy protections
        """
        protections = []
        
        # Check for inherited guards
        inherited = self._check_inheritance(contract_code)
        if inherited:
            protections.extend(inherited)
        
        # Check for modifiers on functions
        function_protections = self._check_function_modifiers(contract_code)
        protections.extend(function_protections)
        
        # Check for custom mutex patterns
        custom_mutex = self._check_custom_mutex(contract_code)
        protections.extend(custom_mutex)
        
        return protections
    
    def _check_inheritance(self, contract_code: str) -> List[ReentrancyProtection]:
        """Check if contract inherits from a reentrancy guard."""
        protections = []
        
        # Look for inheritance
        inheritance_pattern = r'contract\s+\w+\s+is\s+([^{]+)\{'
        match = re.search(inheritance_pattern, contract_code)
        
        if match:
            inherited_contracts = match.group(1)
            for guard_lib in self.REENTRANCY_GUARD_LIBRARIES:
                if guard_lib in inherited_contracts:
                    protections.append(ReentrancyProtection(
                        protection_type='library',
                        function_name='*',  # Applies to all
                        line_number=0,
                        mechanism=guard_lib
                    ))
        
        # Look for imports
        import_pattern = r'import.*ReentrancyGuard'
        if re.search(import_pattern, contract_code):
            protections.append(ReentrancyProtection(
                protection_type='library',
                function_name='*',
                line_number=0,
                mechanism='ReentrancyGuard (imported)'
            ))
        
        return protections
    
    def _check_function_modifiers(
        self,
        contract_code: str
    ) -> List[ReentrancyProtection]:
        """Check for reentrancy modifiers on functions."""
        protections = []
        lines = contract_code.split('\n')
        
        # Track if we're in a function definition (multiline)
        in_function = False
        current_function = None
        current_function_line = 0
        
        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            
            # Check if this line starts a function
            if 'function' in stripped and '(' in stripped:
                current_function = self._extract_function_name(stripped)
                current_function_line = line_num
                in_function = True
            
            # Check for modifiers in function signature (can be multiline)
            if in_function:
                for modifier in self.REENTRANCY_MODIFIERS:
                    if modifier in stripped:
                        protections.append(ReentrancyProtection(
                            protection_type='modifier',
                            function_name=current_function or 'unknown',
                            line_number=current_function_line,
                            mechanism=modifier
                        ))
                
                # End of function signature when we hit {
                if '{' in stripped:
                    in_function = False
        
        return protections
    
    def _extract_function_name(self, line: str) -> Optional[str]:
        """Extract function name from a function definition line."""
        match = re.search(r'function\s+(\w+)\s*\(', line)
        return match.group(1) if match else None
    
    def _check_custom_mutex(self, contract_code: str) -> List[ReentrancyProtection]:
        """Check for custom mutex/lock patterns."""
        protections = []
        
        # Look for common mutex patterns
        mutex_patterns = [
            (r'uint256.*locked', 'locked variable'),
            (r'bool.*_entered', 'entered flag'),
            (r'require\s*\(.*locked.*==\s*0', 'lock check'),
            (r'locked\s*=\s*1', 'manual lock'),
        ]
        
        for pattern, mechanism in mutex_patterns:
            if re.search(pattern, contract_code, re.IGNORECASE):
                protections.append(ReentrancyProtection(
                    protection_type='pattern',
                    function_name='*',
                    line_number=0,
                    mechanism=mechanism
                ))
        
        return protections
    
    def is_function_protected(
        self,
        function_name: str,
        function_line: int,
        protections: List[ReentrancyProtection],
        tolerance: int = 50
    ) -> bool:
        """
        Check if a specific function is protected against reentrancy.
        
        Args:
            function_name: Name of the function
            function_line: Line number of the function
            protections: List of detected protections
            tolerance: Line number tolerance for matching
            
        Returns:
            True if the function has reentrancy protection
        """
        for protection in protections:
            # Global protection (library inheritance)
            if protection.function_name == '*':
                return True
            
            # Direct function match
            if protection.function_name == function_name:
                return True
            
            # Proximity match (within tolerance lines)
            if abs(protection.line_number - function_line) <= tolerance:
                return True
        
        return False
    
    def check_cei_pattern(
        self,
        function_code: str
    ) -> Dict[str, Any]:
        """
        Check if function follows Checks-Effects-Interactions pattern.
        
        Returns:
            Dict with compliance info
        """
        lines = [l.strip() for l in function_code.split('\n') if l.strip()]
        
        # Identify different types of statements
        checks = []
        effects = []
        interactions = []
        
        # More precise patterns for external calls to avoid false positives
        # e.g., '.send' should not match 'msg.sender'
        interaction_patterns = [
            r'\.call\s*[({]',      # .call( or .call{
            r'\.transfer\s*\(',    # .transfer(
            r'\.send\s*\(',        # .send( - not .sender
            r'\.delegatecall\s*[({]',
            r'\.staticcall\s*[({]',
        ]
        
        for i, line in enumerate(lines):
            if 'require' in line or 'assert' in line:
                checks.append((i, line))
            elif any(re.search(pattern, line) for pattern in interaction_patterns):
                interactions.append((i, line))
            elif ('=' in line or '-=' in line or '+=' in line) and \
                 any(keyword in line.lower() for keyword in ['balance', 'amount', 'total', 'supply']):
                effects.append((i, line))
        
        # Check order: Checks -> Effects -> Interactions
        violations = []
        
        # If we have interactions and effects, check order
        if interactions and effects:
            last_interaction_line = interactions[-1][0]
            
            # Check if any effects come after interactions
            for effect_line, effect in effects:
                if effect_line > last_interaction_line:
                    violations.append(
                        f"Effect after interaction: {effect} (line {effect_line})"
                    )
        
        return {
            'follows_cei': len(violations) == 0,
            'violations': violations,
            'checks_count': len(checks),
            'effects_count': len(effects),
            'interactions_count': len(interactions),
        }
    
    def should_filter_reentrancy_vuln(
        self,
        vulnerability: Dict[str, Any],
        contract_code: str,
        contract_name: str
    ) -> tuple[bool, str]:
        """
        Determine if a reentrancy vulnerability should be filtered.
        
        Args:
            vulnerability: The vulnerability dict
            contract_code: Full contract source code
            contract_name: Name of the contract
            
        Returns:
            Tuple of (should_filter, reason)
        """
        protections = self.detect_protections(contract_code, contract_name)
        
        if not protections:
            return False, ""
        
        vuln_line = vulnerability.get('line', 0)
        vuln_function = vulnerability.get('function', '')
        
        # Check if this specific function is protected
        if self.is_function_protected(vuln_function, vuln_line, protections):
            mechanisms = [p.mechanism for p in protections]
            reason = (
                f"Function '{vuln_function}' has reentrancy protection:\n"
                f"Mechanisms: {', '.join(set(mechanisms))}"
            )
            return True, reason
        
        return False, ""

