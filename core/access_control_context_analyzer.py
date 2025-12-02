"""
Access Control Context Analyzer

This module analyzes access control patterns to determine if reported vulnerabilities
are actually exploitable by external attackers or require admin privileges.

Key improvements from ZetaChain validation:
1. Detect admin-only functions and downgrade severity appropriately
2. Identify trusted role requirements (onlyFungibleModule, onlyRole, etc.)
3. Distinguish between user-facing and admin functions
4. Reduce false positives for configuration functions

Enhanced in Dec 2025:
5. Analyze custom modifier bodies to understand their validation semantics
6. Detect parameter validation through modifiers (e.g., onlyRegisteredToken)
7. Recognize intentional design patterns (e.g., chargeWithoutEvent)
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
    VALIDATED = "validated"  # Has parameter validation via modifiers


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
        
        # New components for enhanced analysis
        self._modifier_analyzer = None
        self._intentional_design_detector = None
        self._contract_analyzed = False
    
    def _get_modifier_analyzer(self):
        """Lazy load modifier analyzer."""
        if self._modifier_analyzer is None:
            from .modifier_semantic_analyzer import ModifierSemanticAnalyzer
            self._modifier_analyzer = ModifierSemanticAnalyzer()
        return self._modifier_analyzer
    
    def _get_intentional_design_detector(self):
        """Lazy load intentional design detector."""
        if self._intentional_design_detector is None:
            from .intentional_design_detector import IntentionalDesignDetector
            self._intentional_design_detector = IntentionalDesignDetector()
        return self._intentional_design_detector
    
    def analyze_contract_modifiers(self, contract_content: str):
        """Pre-analyze all modifiers in the contract for faster function analysis."""
        modifier_analyzer = self._get_modifier_analyzer()
        modifier_analyzer.analyze_contract(contract_content)
        self._contract_analyzed = True
        
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
            - has_parameter_validation: bool (NEW)
            - validated_parameters: List[str] (NEW)
            - is_intentional_design: bool (NEW)
            - custom_modifiers: List[str] (NEW)
        """
        result = {
            'access_level': AccessLevel.PUBLIC,
            'has_access_control': False,
            'access_control_type': None,
            'severity_adjustment': 1.0,  # No adjustment by default
            'is_admin_function': False,
            'role_name': None,
            'confidence': 0.0,
            # New fields for enhanced analysis
            'has_parameter_validation': False,
            'validated_parameters': [],
            'is_intentional_design': False,
            'intentional_design_reason': None,
            'custom_modifiers': [],
            'all_modifiers_analyzed': False,
        }
        
        # Pre-analyze contract modifiers if not done yet
        if not self._contract_analyzed and contract_content:
            self.analyze_contract_modifiers(contract_content)
        
        # Check for known modifiers in function signature
        for modifier_name, pattern in self.modifier_patterns.items():
            if modifier_name in function_code:
                result['has_access_control'] = True
                result['access_level'] = pattern.access_level
                result['access_control_type'] = modifier_name
                result['severity_adjustment'] = pattern.severity_multiplier
                result['role_name'] = pattern.role_name
                result['confidence'] = pattern.confidence
                break
        
        # NEW: Check for custom modifiers that provide validation
        custom_modifier_result = self._analyze_custom_modifiers(function_code, contract_content)
        if custom_modifier_result:
            result['custom_modifiers'] = custom_modifier_result.get('modifiers', [])
            result['all_modifiers_analyzed'] = True
            
            # Check for access control from custom modifiers
            if custom_modifier_result.get('has_access_control') and not result['has_access_control']:
                result['has_access_control'] = True
                result['access_level'] = AccessLevel.RESTRICTED
                result['access_control_type'] = 'custom_modifier'
                result['severity_adjustment'] = 0.3
                result['confidence'] = 0.85
            
            # Check for parameter validation from custom modifiers
            if custom_modifier_result.get('validated_params'):
                result['has_parameter_validation'] = True
                result['validated_parameters'] = list(custom_modifier_result['validated_params'])
                # Adjust severity if parameters are validated
                if not result['has_access_control']:
                    result['access_level'] = AccessLevel.VALIDATED
                    result['severity_adjustment'] = min(result['severity_adjustment'], 0.4)
        
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
        
        # NEW: Check for intentional design patterns
        intentional_result = self._check_intentional_design(function_code, function_name, contract_content)
        if intentional_result.get('is_intentional'):
            result['is_intentional_design'] = True
            result['intentional_design_reason'] = intentional_result.get('reason')
            # Significantly reduce severity for intentional design
            result['severity_adjustment'] = min(result['severity_adjustment'], 0.2)
        
        return result
    
    def _analyze_custom_modifiers(
        self, 
        function_code: str, 
        contract_content: str
    ) -> Optional[Dict[str, Any]]:
        """Analyze custom modifiers on a function to understand their semantics."""
        try:
            modifier_analyzer = self._get_modifier_analyzer()
            
            # Make sure contract is analyzed
            if not modifier_analyzer.modifier_definitions and contract_content:
                modifier_analyzer.analyze_contract(contract_content)
            
            # Get modifier usages on this function
            usages = modifier_analyzer.get_function_modifier_usages(function_code)
            
            if not usages:
                return None
            
            result = {
                'modifiers': [],
                'has_access_control': False,
                'validated_params': set(),
            }
            
            for usage in usages:
                result['modifiers'].append(usage.modifier_name)
                
                if usage.modifier_name in modifier_analyzer.modifier_definitions:
                    mod_def = modifier_analyzer.modifier_definitions[usage.modifier_name]
                    
                    # Check for access control
                    if mod_def.is_access_control:
                        result['has_access_control'] = True
                    
                    # Check for parameter validation
                    for mod_param in mod_def.validated_params:
                        if mod_param in usage.arg_to_param_mapping:
                            func_param = usage.arg_to_param_mapping[mod_param]
                            result['validated_params'].add(func_param)
            
            return result
            
        except Exception:
            # Fail gracefully if modifier analysis fails
            return None
    
    def _check_intentional_design(
        self, 
        function_code: str, 
        function_name: str,
        contract_content: str
    ) -> Dict[str, Any]:
        """Check if the function follows intentional design patterns."""
        try:
            detector = self._get_intentional_design_detector()
            
            # Get surrounding comments if we have contract content
            surrounding_comments = ""
            if contract_content and function_code:
                # Find function position and extract comments
                func_pos = contract_content.find(function_code[:50])  # First 50 chars
                if func_pos > 0:
                    func_line = contract_content[:func_pos].count('\n')
                    surrounding_comments = detector.get_function_intent_context(
                        contract_content, func_line
                    )
            
            result = detector.analyze_function(
                function_code, 
                function_name, 
                surrounding_comments
            )
            
            return {
                'is_intentional': result.is_intentional,
                'reason': result.reasoning if result.is_intentional else None,
                'confidence': result.confidence,
            }
            
        except Exception:
            return {'is_intentional': False, 'reason': None}
    
    def is_parameter_validated(
        self,
        function_code: str,
        param_name: str,
        contract_content: str = ""
    ) -> Tuple[bool, List[str]]:
        """
        Check if a specific parameter is validated (by modifiers or inline checks).
        
        Returns:
            (is_validated, list_of_validation_sources)
        """
        validation_sources = []
        
        # Check inline validation
        inline_patterns = [
            rf'require\s*\(\s*{re.escape(param_name)}\s*!=',
            rf'require\s*\(\s*{re.escape(param_name)}\s*>',
            rf'require\s*\(\s*{re.escape(param_name)}\s*<',
            rf'if\s*\(\s*{re.escape(param_name)}\s*==.*revert',
        ]
        
        for pattern in inline_patterns:
            if re.search(pattern, function_code):
                validation_sources.append('inline_require')
                break
        
        # Check modifier validation
        try:
            modifier_analyzer = self._get_modifier_analyzer()
            if contract_content and not modifier_analyzer.modifier_definitions:
                modifier_analyzer.analyze_contract(contract_content)
            
            is_validated, modifiers = modifier_analyzer.is_parameter_validated_by_modifiers(
                function_code, param_name
            )
            
            if is_validated:
                validation_sources.extend([f'modifier:{m}' for m in modifiers])
                
        except Exception:
            pass
        
        return len(validation_sources) > 0, validation_sources
    
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

