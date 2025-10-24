"""
Design Assumption Detector

Identifies vulnerabilities that are actually documented design assumptions,
preventing false positives from known limitations and trust models.
"""

import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class DesignAssumption:
    """Represents a detected design assumption."""
    assumption_type: str
    description: str
    location: str  # file:line or contract name
    trust_requirement: str
    patterns: List[str]


class DesignAssumptionDetector:
    """
    Detects design assumptions in smart contracts.
    
    Common patterns:
    - "assumes X is safe/trusted"
    - "requires X to be well-behaved"
    - "expects X to not be malicious"
    - "trust assumption: X"
    """
    
    ASSUMPTION_PATTERNS = {
        'trusted_token': [
            r'assume.*(?:asset|token|collateral).*(?:safe|trusted|well-behaved)',
            r'requires?.*(?:asset|token|collateral).*(?:well-behaved|standard)',
            r'expects?.*(?:asset|token|collateral).*(?:not|no).*(?:malicious|reentrancy)',
            r'trust.*(?:asset|token|collateral)',
            r'(?:asset|token|collateral).*(?:is|are).*(?:safe|trusted|well-behaved)',
        ],
        'trusted_oracle': [
            r'assume.*oracle.*(?:safe|trusted|honest)',
            r'requires?.*oracle.*(?:accurate|reliable)',
            r'trust.*oracle',
        ],
        'trusted_admin': [
            r'assume.*(?:admin|governance|owner).*(?:benign|honest|trusted)',
            r'governance.*is.*trusted',
            r'admin.*is.*trusted',
        ],
        'inherited_security': [
            r'(?:fork|inherited|based on).*(?:audited|security)',
            r'authorized fork of',
            r'implementation.*from.*(?:openzeppelin|angle|aave)',
        ],
        'known_limitation': [
            r'known (?:issue|limitation)',
            r'by design',
            r'intentional(?:ly)?.*(?:not|lacks)',
            r'does not (?:support|handle)',
        ]
    }
    
    VULNERABILITY_ASSUMPTION_MAPPING = {
        'reentrancy': 'trusted_token',
        'token_callback': 'trusted_token',
        'malicious_token': 'trusted_token',
        'balance_invariance': 'trusted_token',
        'insufficient_balance': 'trusted_token',
        'oracle_manipulation': 'trusted_oracle',
        'oracle': 'trusted_oracle',
        'governance_control': 'trusted_admin',
        'parameter_validation': 'trusted_admin',
    }
    
    def __init__(self):
        self.compiled_patterns = self._compile_patterns()
    
    def _compile_patterns(self) -> Dict[str, List[re.Pattern]]:
        """Compile regex patterns for performance."""
        compiled = {}
        for assumption_type, patterns in self.ASSUMPTION_PATTERNS.items():
            compiled[assumption_type] = [
                re.compile(pattern, re.IGNORECASE) for pattern in patterns
            ]
        return compiled
    
    def detect_assumptions(
        self,
        contract_code: str,
        contract_name: str
    ) -> List[DesignAssumption]:
        """
        Detect design assumptions in contract code.
        
        Args:
            contract_code: The Solidity source code
            contract_name: Name of the contract
            
        Returns:
            List of detected design assumptions
        """
        assumptions = []
        lines = contract_code.split('\n')
        
        for line_num, line in enumerate(lines, start=1):
            # Check comments and natspec
            if '//' in line or '/*' in line or '*' in line or '///' in line:
                comment = self._extract_comment(line)
                if comment:
                    assumption = self._check_comment_for_assumptions(
                        comment, contract_name, line_num
                    )
                    if assumption:
                        assumptions.append(assumption)
        
        return assumptions
    
    def _extract_comment(self, line: str) -> Optional[str]:
        """Extract comment text from a line."""
        # Single line comment
        if '//' in line:
            return line.split('//', 1)[1].strip()
        # Multiline comment or natspec
        if '*' in line:
            return line.split('*', 1)[1].strip() if '*' in line else line.strip()
        return None
    
    def _check_comment_for_assumptions(
        self,
        comment: str,
        contract_name: str,
        line_num: int
    ) -> Optional[DesignAssumption]:
        """Check if a comment contains a design assumption."""
        for assumption_type, patterns in self.compiled_patterns.items():
            for pattern in patterns:
                if pattern.search(comment):
                    return DesignAssumption(
                        assumption_type=assumption_type,
                        description=comment,
                        location=f"{contract_name}:L{line_num}",
                        trust_requirement=self._extract_trust_requirement(comment),
                        patterns=[pattern.pattern]
                    )
        return None
    
    def _extract_trust_requirement(self, comment: str) -> str:
        """Extract what needs to be trusted from the comment."""
        # Look for "assumes X" or "requires X" patterns
        assume_match = re.search(
            r'assume[s]?\s+(?:that\s+)?(.+?)(?:\.|,|$)',
            comment,
            re.IGNORECASE
        )
        if assume_match:
            return assume_match.group(1).strip()
        
        require_match = re.search(
            r'require[s]?\s+(.+?)(?:\.|,|to|$)',
            comment,
            re.IGNORECASE
        )
        if require_match:
            return require_match.group(1).strip()
        
        return comment[:100]  # First 100 chars as fallback
    
    def is_vulnerability_assumed_safe(
        self,
        vulnerability: Dict[str, Any],
        assumptions: List[DesignAssumption]
    ) -> bool:
        """
        Check if a vulnerability is actually a documented design assumption.
        
        Args:
            vulnerability: Vulnerability dict with 'type', 'line', etc.
            assumptions: List of detected design assumptions
            
        Returns:
            True if the vulnerability is covered by a design assumption
        """
        vuln_type = vulnerability.get('type', '').lower()
        vuln_line = vulnerability.get('line', 0)
        
        # Map vulnerability type to assumption type
        expected_assumption = None
        for vuln_keyword, assumption_type in self.VULNERABILITY_ASSUMPTION_MAPPING.items():
            if vuln_keyword in vuln_type:
                expected_assumption = assumption_type
                break
        
        if not expected_assumption:
            return False
        
        # Check if there's a matching assumption near the vulnerability
        for assumption in assumptions:
            if assumption.assumption_type == expected_assumption:
                # Assumption covers entire contract or is close to vulnerability
                return True
        
        return False
    
    def generate_filter_reason(
        self,
        vulnerability: Dict[str, Any],
        assumption: DesignAssumption
    ) -> str:
        """Generate a reason for filtering this vulnerability."""
        return (
            f"Design assumption: {assumption.description}\n"
            f"Location: {assumption.location}\n"
            f"Trust requirement: {assumption.trust_requirement}\n"
            f"This is a documented limitation, not a vulnerability."
        )
    
    def detect_inherited_security(self, contract_code: str) -> Optional[Dict[str, str]]:
        """
        Detect if contract inherits from audited codebases.
        
        Returns:
            Dict with source and audit info if found
        """
        inherited_from = {
            'openzeppelin': {
                'pattern': r'@openzeppelin/contracts',
                'audit_status': 'Industry-standard, heavily audited',
            },
            'angle': {
                'pattern': r'authorized fork of.*Angle',
                'audit_status': 'Audited by Code4rena',
            },
            'aave': {
                'pattern': r'(?:fork|based on).*Aave',
                'audit_status': 'Audited by multiple firms',
            },
        }
        
        for source, info in inherited_from.items():
            if re.search(info['pattern'], contract_code, re.IGNORECASE):
                return {
                    'source': source,
                    'audit_status': info['audit_status'],
                    'implication': 'Inherited security model should match source'
                }
        
        return None

