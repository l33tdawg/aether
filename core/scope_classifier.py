"""
Scope Classifier for Bug Bounties

Classifies vulnerabilities as in-scope or out-of-scope based on
common bug bounty program rules (Immunefi, HackerOne, etc.).
"""

import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum


class ScopeStatus(Enum):
    """Vulnerability scope status."""
    IN_SCOPE = "in_scope"
    OUT_OF_SCOPE = "out_of_scope"
    EDGE_CASE = "edge_case"


@dataclass
class ScopeClassification:
    """Result of scope classification."""
    status: ScopeStatus
    reason: str
    confidence: float
    category: str


class ScopeClassifier:
    """
    Classifies vulnerabilities according to bug bounty scope rules.
    
    Common out-of-scope items:
    - Admin/governance-only issues
    - DoS on admin functions
    - Known issues/design limitations
    - Hypothetical vulnerabilities with no impact
    - Issues requiring privileged access
    """
    
    OUT_OF_SCOPE_CATEGORIES = {
        'admin_only_dos': {
            'description': 'DoS on admin/governance functions',
            'reason': 'Admin functions can be upgraded/fixed by governance',
            'keywords': ['admin', 'governance', 'owner', 'guardian', 'restricted'],
            'vuln_types': ['dos', 'gas', 'unbounded', 'array'],
        },
        'governance_misconfiguration': {
            'description': 'Governance parameter misconfiguration risks',
            'reason': 'Governance is trusted; misconfiguration is out of scope',
            'keywords': ['governance', 'onlyOwner', 'onlyGov', 'restricted'],
            'vuln_types': ['parameter', 'validation', 'bounds', 'config', 'unvalidated_external'],
        },
        'known_limitations': {
            'description': 'Documented known limitations or design assumptions',
            'reason': 'Explicitly documented as known issue',
            'keywords': ['known issue', 'known limitation', 'by design', 'assumes'],
            'vuln_types': ['*'],  # All types
        },
        'hypothetical': {
            'description': 'Hypothetical vulnerabilities with no realistic impact',
            'reason': 'No practical exploit path or requires unrealistic conditions',
            'keywords': ['theoretical', 'hypothetical', 'unlikely', 'unrealistic'],
            'vuln_types': ['*'],
        },
        'display_only': {
            'description': 'Display/UI issues with no fund impact',
            'reason': 'No user funds or protocol funds at risk',
            'keywords': ['display', 'ui', 'view', 'getter', 'cosmetic'],
            'vuln_types': ['*'],
        },
        'informational': {
            'description': 'Best practice violations, code quality, informational',
            'reason': 'No security impact, no funds at risk',
            'keywords': ['best practice', 'code quality', 'informational', 'gas optimization'],
            'vuln_types': ['best_practice', 'code_quality', 'informational', 'gas'],
        },
    }
    
    # Access control modifiers that indicate admin-only functions
    ADMIN_MODIFIERS = [
        'onlyOwner', 'onlyGovernor', 'onlyGuardian', 'onlyGov',
        'onlyRole', 'restricted', 'onlyAdmin', 'onlyController',
        'onlyGovernance', 'onlyAuthorized', 'requiresAuth',
        'onlyLatestNetworkContract',  # RocketPool pattern
    ]
    
    def __init__(self):
        pass
    
    def classify_vulnerability(
        self,
        vulnerability: Dict[str, Any],
        contract_code: str,
        contract_name: str
    ) -> ScopeClassification:
        """
        Classify if a vulnerability is in or out of scope.
        
        Args:
            vulnerability: Vulnerability dict with 'type', 'severity', etc.
            contract_code: Full contract source code
            contract_name: Name of the contract
            
        Returns:
            ScopeClassification with status and reasoning
        """
        vuln_type = vulnerability.get('type', '').lower()
        vuln_function = vulnerability.get('function', '')
        vuln_description = vulnerability.get('description', '').lower()
        
        # Check each out-of-scope category
        
        # 1. Admin-only DoS
        if self._is_admin_only_dos(vulnerability, contract_code):
            return ScopeClassification(
                status=ScopeStatus.OUT_OF_SCOPE,
                reason="DoS on admin-only function. Admin functions are trusted and can be upgraded.",
                confidence=0.9,
                category='admin_only_dos'
            )
        
        # 2. Governance misconfiguration
        if self._is_governance_misconfiguration(vulnerability, contract_code):
            return ScopeClassification(
                status=ScopeStatus.OUT_OF_SCOPE,
                reason="Governance parameter misconfiguration. Governance is trusted per protocol assumptions.",
                confidence=0.85,
                category='governance_misconfiguration'
            )
        
        # 3. Known limitations (check comments/documentation)
        if self._is_known_limitation(vulnerability, contract_code):
            return ScopeClassification(
                status=ScopeStatus.OUT_OF_SCOPE,
                reason="Documented known limitation or design assumption.",
                confidence=0.8,
                category='known_limitations'
            )
        
        # 4. Hypothetical/unrealistic
        if self._is_hypothetical(vulnerability):
            return ScopeClassification(
                status=ScopeStatus.OUT_OF_SCOPE,
                reason="Hypothetical vulnerability with no realistic exploit path.",
                confidence=0.7,
                category='hypothetical'
            )
        
        # 5. Display-only issues
        if self._is_display_only(vulnerability, contract_code):
            return ScopeClassification(
                status=ScopeStatus.OUT_OF_SCOPE,
                reason="Display/view function issue with no fund impact.",
                confidence=0.75,
                category='display_only'
            )
        
        # 6. Informational / Best practice issues
        if self._is_informational(vulnerability):
            return ScopeClassification(
                status=ScopeStatus.OUT_OF_SCOPE,
                reason="Informational or best practice violation with no security impact.",
                confidence=0.8,
                category='informational'
            )
        
        # Default: IN SCOPE
        return ScopeClassification(
            status=ScopeStatus.IN_SCOPE,
            reason="Vulnerability affects user or protocol funds without privileged access.",
            confidence=0.8,
            category='standard_vulnerability'
        )
    
    def _is_admin_only_dos(
        self,
        vulnerability: Dict[str, Any],
        contract_code: str
    ) -> bool:
        """Check if this is a DoS on an admin-only function."""
        vuln_type = vulnerability.get('type', '').lower()
        vuln_function = vulnerability.get('function', '')
        
        # Check if it's a DoS-type vulnerability
        dos_keywords = ['dos', 'denial', 'gas', 'unbounded', 'loop', 'array']
        is_dos = any(keyword in vuln_type for keyword in dos_keywords)
        
        if not is_dos:
            return False
        
        # Check if function has admin access control
        if vuln_function:
            function_pattern = rf'function\s+{re.escape(vuln_function)}\s*\([^)]*\)([^{{]*)\{{'
            match = re.search(function_pattern, contract_code)
            
            if match:
                modifiers = match.group(1)
                has_admin_modifier = any(
                    modifier in modifiers for modifier in self.ADMIN_MODIFIERS
                )
                if has_admin_modifier:
                    return True
        
        return False
    
    def _is_governance_misconfiguration(
        self,
        vulnerability: Dict[str, Any],
        contract_code: str
    ) -> bool:
        """Check if this is a governance parameter misconfiguration risk."""
        vuln_type = vulnerability.get('type', '').lower()
        vuln_function = vulnerability.get('function', '')
        vuln_description = vulnerability.get('description', '').lower()
        
        # Keywords that suggest parameter validation or configuration
        param_keywords = ['parameter', 'validation', 'bounds', 'config', 'setter', 'unvalidated']
        is_param_issue = any(keyword in vuln_type for keyword in param_keywords)
        
        # Also check if description mentions governance/config control
        is_config_issue = any(keyword in vuln_description for keyword in ['config', 'governance', 'arbitrary bytes'])
        
        if not (is_param_issue or is_config_issue):
            return False
        
        # Check if function is governance-controlled
        if vuln_function:
            function_pattern = rf'function\s+{re.escape(vuln_function)}\s*\([^)]*\)([^{{]*)\{{'
            match = re.search(function_pattern, contract_code)
            
            if match:
                modifiers = match.group(1)
                has_admin_modifier = any(
                    modifier in modifiers for modifier in self.ADMIN_MODIFIERS
                )
                if has_admin_modifier:
                    return True
        
        # Check if contract itself is a Governor/Setter contract (by name)
        if 'SettersGovernor' in contract_code or 'governance' in contract_code[:500].lower():
            if 'restricted' in contract_code or 'onlyGovernor' in contract_code:
                return True
        
        return False
    
    def _is_known_limitation(
        self,
        vulnerability: Dict[str, Any],
        contract_code: str
    ) -> bool:
        """Check if this is a documented known limitation."""
        vuln_description = vulnerability.get('description', '').lower()
        
        # Check for "known issue" or "by design" in comments near vulnerability
        vuln_line = vulnerability.get('line', 0)
        if vuln_line:
            lines = contract_code.split('\n')
            # Check 10 lines before and after
            context_start = max(0, vuln_line - 10)
            context_end = min(len(lines), vuln_line + 10)
            context = '\n'.join(lines[context_start:context_end])
            
            known_patterns = [
                r'known\s+(?:issue|limitation)',
                r'by\s+design',
                r'intentional(?:ly)?',
                r'assumes?\s+.*(?:safe|trusted)',
            ]
            
            for pattern in known_patterns:
                if re.search(pattern, context, re.IGNORECASE):
                    return True
        
        return False
    
    def _is_hypothetical(self, vulnerability: Dict[str, Any]) -> bool:
        """Check if this is a hypothetical vulnerability."""
        vuln_description = vulnerability.get('description', '').lower()
        
        hypothetical_keywords = [
            'could potentially',
            'might be possible',
            'theoretical',
            'hypothetical',
            'in theory',
            'if a malicious',
            'assumes attacker',
        ]
        
        # Check if description has 2+ hypothetical markers
        hypothetical_count = sum(
            1 for keyword in hypothetical_keywords
            if keyword in vuln_description
        )
        
        return hypothetical_count >= 2
    
    def _is_display_only(
        self,
        vulnerability: Dict[str, Any],
        contract_code: str
    ) -> bool:
        """Check if this is a display/view function issue."""
        vuln_function = vulnerability.get('function', '')
        
        if not vuln_function:
            return False
        
        # Check if function is a view/pure function
        function_pattern = rf'function\s+{re.escape(vuln_function)}\s*\([^)]*\)\s+[^{{]*\b(view|pure)\b'
        if re.search(function_pattern, contract_code):
            # View/pure functions can't modify state, so impact is limited
            return True
        
        return False
    
    def _is_informational(self, vulnerability: Dict[str, Any]) -> bool:
        """Check if this is an informational/best practice issue."""
        vuln_type = vulnerability.get('type', '').lower()
        severity = vulnerability.get('severity', '').lower()
        
        # Informational keywords
        informational_types = [
            'best_practice', 
            'code_quality', 
            'informational',
            'gas_optimization',
            'style',
            'naming',
        ]
        
        # Check if type indicates informational
        if any(info_type in vuln_type for info_type in informational_types):
            return True
        
        # Check if severity is informational/low and type is non-critical
        if severity in ['informational', 'info', 'note']:
            return True
        
        return False
    
    def get_bounty_eligibility(
        self,
        vulnerability: Dict[str, Any],
        contract_code: str,
        contract_name: str
    ) -> Dict[str, Any]:
        """
        Get detailed bounty eligibility assessment.
        
        Returns:
            Dict with eligibility info and recommendations
        """
        classification = self.classify_vulnerability(
            vulnerability, contract_code, contract_name
        )
        
        severity = vulnerability.get('severity', 'unknown').lower()
        
        # Estimate bounty potential
        bounty_estimate = None
        if classification.status == ScopeStatus.IN_SCOPE:
            # Rough Immunefi estimates
            bounty_ranges = {
                'critical': (50000, 250000),
                'high': (10000, 50000),
                'medium': (2000, 10000),
                'low': (0, 2000),
            }
            bounty_estimate = bounty_ranges.get(severity, (0, 0))
        
        return {
            'eligible': classification.status == ScopeStatus.IN_SCOPE,
            'status': classification.status.value,
            'reason': classification.reason,
            'confidence': classification.confidence,
            'category': classification.category,
            'bounty_estimate': bounty_estimate,
            'recommendation': self._get_recommendation(classification),
        }
    
    def _get_recommendation(self, classification: ScopeClassification) -> str:
        """Get recommendation based on classification."""
        if classification.status == ScopeStatus.IN_SCOPE:
            return "✅ Submit to bug bounty program with proof of concept"
        elif classification.status == ScopeStatus.OUT_OF_SCOPE:
            return f"❌ Do not submit - {classification.reason}"
        else:
            return "⚠️  Edge case - review with program team before submitting"

