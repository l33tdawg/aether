"""
Access Control Context Analyzer

This module analyzes access control patterns to determine if reported vulnerabilities
are actually exploitable by external attackers or require admin privileges.

Key improvements from ZetaChain validation:
1. Detect admin-only functions and downgrade severity appropriately
2. Identify trusted role requirements (onlyFungibleModule, onlyRole, etc.)
3. Distinguish between user-facing and admin functions
4. Reduce false positives for configuration functions
"""

import re
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum


class AccessLevel(Enum):
    """Access levels for functions"""
    PUBLIC = "public"  # Anyone can call
    RESTRICTED = "restricted"  # Requires specific role
    OWNER_ONLY = "owner_only"  # Only owner/admin
    INTERNAL = "internal"  # Internal/private
    MODULE_ONLY = "module_only"  # Specific trusted module


@dataclass
class AccessControlPattern:
    """Represents an access control pattern"""
    pattern: str
    access_level: AccessLevel
    role_name: Optional[str]
    confidence: float
    severity_multiplier: float  # How much to reduce severity


class AccessControlContextAnalyzer:
    """Analyzes access control context to adjust vulnerability severity"""
    
    def __init__(self):
        self.access_patterns = self._initialize_access_patterns()
        self.modifier_patterns = self._initialize_modifier_patterns()
        self.admin_function_keywords = self._initialize_admin_keywords()
        
    def _initialize_access_patterns(self) -> List[AccessControlPattern]:
        """Initialize access control detection patterns"""
        return [
            # OpenZeppelin AccessControl
            AccessControlPattern(
                pattern=r'require\s*\(\s*hasRole\s*\(',
                access_level=AccessLevel.RESTRICTED,
                role_name="hasRole",
                confidence=0.95,
                severity_multiplier=0.3  # Reduce severity by 70%
            ),
            AccessControlPattern(
                pattern=r'require\s*\(\s*_hasRole\s*\(',
                access_level=AccessLevel.RESTRICTED,
                role_name="_hasRole",
                confidence=0.95,
                severity_multiplier=0.3
            ),
            # Owner patterns
            AccessControlPattern(
                pattern=r'require\s*\(\s*msg\.sender\s*==\s*owner',
                access_level=AccessLevel.OWNER_ONLY,
                role_name="owner",
                confidence=0.95,
                severity_multiplier=0.2
            ),
            AccessControlPattern(
                pattern=r'require\s*\(\s*_msgSender\s*\(\s*\)\s*==\s*owner',
                access_level=AccessLevel.OWNER_ONLY,
                role_name="owner",
                confidence=0.95,
                severity_multiplier=0.2
            ),
            # Module-specific (like FUNGIBLE_MODULE_ADDRESS)
            AccessControlPattern(
                pattern=r'require\s*\(\s*msg\.sender\s*==\s*FUNGIBLE_MODULE_ADDRESS',
                access_level=AccessLevel.MODULE_ONLY,
                role_name="FUNGIBLE_MODULE_ADDRESS",
                confidence=0.98,
                severity_multiplier=0.1  # Reduce by 90% - highly trusted
            ),
            AccessControlPattern(
                pattern=r'if\s*\(\s*msg\.sender\s*!=\s*FUNGIBLE_MODULE_ADDRESS\s*\)\s*revert',
                access_level=AccessLevel.MODULE_ONLY,
                role_name="FUNGIBLE_MODULE_ADDRESS",
                confidence=0.98,
                severity_multiplier=0.1
            ),
            # Admin/Governance patterns
            AccessControlPattern(
                pattern=r'require\s*\(\s*msg\.sender\s*==\s*admin',
                access_level=AccessLevel.OWNER_ONLY,
                role_name="admin",
                confidence=0.95,
                severity_multiplier=0.2
            ),
            AccessControlPattern(
                pattern=r'require\s*\(\s*isGovernance\s*\(',
                access_level=AccessLevel.OWNER_ONLY,
                role_name="governance",
                confidence=0.9,
                severity_multiplier=0.2
            ),
        ]
    
    def _initialize_modifier_patterns(self) -> Dict[str, AccessControlPattern]:
        """Initialize function modifier patterns"""
        return {
            'onlyOwner': AccessControlPattern(
                pattern='onlyOwner',
                access_level=AccessLevel.OWNER_ONLY,
                role_name='owner',
                confidence=0.98,
                severity_multiplier=0.2
            ),
            'onlyRole': AccessControlPattern(
                pattern='onlyRole',
                access_level=AccessLevel.RESTRICTED,
                role_name='role',
                confidence=0.95,
                severity_multiplier=0.3
            ),
            'onlyGovernance': AccessControlPattern(
                pattern='onlyGovernance',
                access_level=AccessLevel.OWNER_ONLY,
                role_name='governance',
                confidence=0.95,
                severity_multiplier=0.2
            ),
            'onlyAdmin': AccessControlPattern(
                pattern='onlyAdmin',
                access_level=AccessLevel.OWNER_ONLY,
                role_name='admin',
                confidence=0.95,
                severity_multiplier=0.2
            ),
            'onlyFungibleModule': AccessControlPattern(
                pattern='onlyFungibleModule',
                access_level=AccessLevel.MODULE_ONLY,
                role_name='fungibleModule',
                confidence=0.98,
                severity_multiplier=0.1
            ),
            'onlyManager': AccessControlPattern(
                pattern='onlyManager',
                access_level=AccessLevel.RESTRICTED,
                role_name='manager',
                confidence=0.9,
                severity_multiplier=0.3
            ),
        }
    
    def _initialize_admin_keywords(self) -> Set[str]:
        """Initialize keywords that indicate admin/configuration functions"""
        return {
            'set', 'update', 'configure', 'initialize', 'setup',
            'change', 'modify', 'admin', 'owner', 'governance',
            'registry', 'manager', 'pause', 'unpause', 'upgrade'
        }
    
    def analyze_function_access_control(
        self,
        function_code: str,
        function_name: str,
        contract_content: str
    ) -> Dict[str, Any]:
        """
        Analyze access control for a specific function
        
        Returns:
            Dict with:
            - access_level: AccessLevel enum
            - has_access_control: bool
            - access_control_type: str
            - severity_adjustment: float (multiplier)
            - is_admin_function: bool
            - role_name: Optional[str]
        """
        result = {
            'access_level': AccessLevel.PUBLIC,
            'has_access_control': False,
            'access_control_type': None,
            'severity_adjustment': 1.0,  # No adjustment by default
            'is_admin_function': False,
            'role_name': None,
            'confidence': 0.0
        }
        
        # Check for modifiers in function signature
        for modifier_name, pattern in self.modifier_patterns.items():
            if modifier_name in function_code:
                result['has_access_control'] = True
                result['access_level'] = pattern.access_level
                result['access_control_type'] = modifier_name
                result['severity_adjustment'] = pattern.severity_multiplier
                result['role_name'] = pattern.role_name
                result['confidence'] = pattern.confidence
                break
        
        # Check for inline access control patterns
        if not result['has_access_control']:
            for pattern_obj in self.access_patterns:
                if re.search(pattern_obj.pattern, function_code, re.IGNORECASE):
                    result['has_access_control'] = True
                    result['access_level'] = pattern_obj.access_level
                    result['access_control_type'] = 'inline_check'
                    result['severity_adjustment'] = pattern_obj.severity_multiplier
                    result['role_name'] = pattern_obj.role_name
                    result['confidence'] = pattern_obj.confidence
                    break
        
        # Check if it's an admin/configuration function based on name
        function_name_lower = function_name.lower()
        is_admin = any(keyword in function_name_lower for keyword in self.admin_function_keywords)
        result['is_admin_function'] = is_admin
        
        # If it's an admin function with access control, further reduce severity
        if is_admin and result['has_access_control']:
            result['severity_adjustment'] *= 0.5  # Additional 50% reduction
        
        return result
    
    def adjust_vulnerability_severity(
        self,
        vulnerability: Dict[str, Any],
        access_control_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Adjust vulnerability severity based on access control context
        
        Args:
            vulnerability: The vulnerability dict
            access_control_info: Access control analysis result
        
        Returns:
            Updated vulnerability dict with adjusted severity
        """
        adjusted = vulnerability.copy()
        
        # Skip if no access control
        if not access_control_info['has_access_control']:
            return adjusted
        
        # Apply severity adjustment
        original_severity = adjusted.get('severity', 'medium')
        multiplier = access_control_info['severity_adjustment']
        
        # Map severity to numeric values
        severity_map = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
        reverse_map = {4: 'critical', 3: 'high', 2: 'medium', 1: 'low', 0: 'info'}
        
        current_level = severity_map.get(original_severity.lower(), 2)
        adjusted_level = int(current_level * multiplier)
        adjusted_level = max(0, min(4, adjusted_level))  # Clamp to valid range
        
        new_severity = reverse_map[adjusted_level]
        
        # Update vulnerability
        adjusted['original_severity'] = original_severity
        adjusted['severity'] = new_severity
        adjusted['access_control'] = {
            'protected': True,
            'access_level': access_control_info['access_level'].value,
            'role': access_control_info['role_name'],
            'confidence': access_control_info['confidence']
        }
        
        # Add explanation to description
        if access_control_info['access_level'] in [AccessLevel.OWNER_ONLY, AccessLevel.MODULE_ONLY]:
            adjusted['description'] += f" [NOTE: Requires {access_control_info['role_name']} privileges - NOT exploitable by external attackers. Original severity: {original_severity}, Adjusted: {new_severity}]"
        elif access_control_info['access_level'] == AccessLevel.RESTRICTED:
            adjusted['description'] += f" [NOTE: Requires specific role ({access_control_info['role_name']}) - Limited exploitability. Original severity: {original_severity}, Adjusted: {new_severity}]"
        
        # Reduce confidence slightly for admin-only issues
        if 'confidence' in adjusted:
            if access_control_info['access_level'] in [AccessLevel.OWNER_ONLY, AccessLevel.MODULE_ONLY]:
                adjusted['confidence'] = adjusted['confidence'] * 0.8
        
        return adjusted
    
    def extract_function_code(self, contract_content: str, function_name: str, line_number: int) -> str:
        """Extract the full function code including modifiers"""
        lines = contract_content.split('\n')
        
        # Start from the line number and go backwards to find function declaration
        start_line = max(0, line_number - 10)
        end_line = min(len(lines), line_number + 100)
        
        function_code = '\n'.join(lines[start_line:end_line])
        return function_code
    
    def is_configuration_function(self, function_name: str) -> bool:
        """Check if function is a configuration/admin function"""
        function_name_lower = function_name.lower()
        return any(keyword in function_name_lower for keyword in self.admin_function_keywords)

