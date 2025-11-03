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
        ],
        'personal_deployment': [  # NEW: Personal bot/tool patterns
            r'(?:each person|every user|individuals?).*deploy.*own',
            r'recommended.*(?:deploy|use).*own.*(?:instance|copy)',
            r'personal.*(?:liquidator|bot|arbitrage)',
            r'(?:to|should).*avoid.*(?:flashbot|mev|steal)',
            r'ownable.*(?:liquidator|bot|arbitrage|challenger)',
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
        'centralization': 'personal_deployment',  # NEW
        'privileged_functions': 'personal_deployment',  # NEW
        'access_control': 'personal_deployment',  # NEW (context-dependent)
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
    
    def detect_personal_deployment_pattern(self, contract_code: str, contract_name: str) -> Optional[Dict[str, Any]]:
        """
        Detect contracts designed for personal deployment (not protocol contracts).
        
        Personal deployment contracts (like liquidator bots, arbitrage bots) are
        intentionally Ownable without timelocks or governance. This is BY DESIGN,
        not a centralization vulnerability.
        
        Indicators:
        - Comment says "each person should deploy their own"
        - Contract is a bot/liquidator/challenger/arbitrage tool
        - Ownable pattern with no governance/timelock (intentional for personal use)
        - Comments mention avoiding MEV/flashbots stealing profits
        
        Args:
            contract_code: Solidity source code
            contract_name: Name of the contract
            
        Returns:
            Dict with pattern detection info or None
        """
        # Check for personal deployment patterns in comments
        personal_deployment_indicators = {
            'explicit_comment': False,
            'bot_naming': False,
            'mev_protection_mention': False,
            'ownable_without_governance': False,
            'personal_profit_mention': False
        }
        
        # Pattern 1: Explicit comments about personal deployment
        explicit_patterns = [
            r'(?:each person|every user|individuals?).*deploy.*(?:own|their)',
            r'recommended.*(?:deploy|use).*(?:own|personal).*(?:instance|copy|contract)',
            r'(?:to|should).*deploy.*own.*(?:ownable|liquidator|bot)',
        ]
        
        for pattern in explicit_patterns:
            if re.search(pattern, contract_code, re.IGNORECASE):
                personal_deployment_indicators['explicit_comment'] = True
                break
        
        # Pattern 2: Bot/tool naming conventions
        bot_patterns = [
            'liquidator', 'challenger', 'arbitrage', 'bot', 'keeper',
            'executor', 'flashloan', 'mev', 'searcher'
        ]
        
        contract_lower = contract_name.lower()
        if any(bot_name in contract_lower for bot_name in bot_patterns):
            personal_deployment_indicators['bot_naming'] = True
        
        # Pattern 3: MEV/profit protection mentions
        mev_protection_patterns = [
            r'avoid.*(?:flash.*bot|mev).*steal.*profit',
            r'prevent.*(?:frontrun|sandwich).*attack',
            r'personal.*profit.*protection',
        ]
        
        for pattern in mev_protection_patterns:
            if re.search(pattern, contract_code, re.IGNORECASE):
                personal_deployment_indicators['mev_protection_mention'] = True
                break
        
        # Pattern 4: Ownable without governance infrastructure
        has_ownable = re.search(r'\bOwnable\b', contract_code)
        has_governance = re.search(r'\b(?:timelock|governance|multisig|dao)\b', contract_code, re.IGNORECASE)
        
        if has_ownable and not has_governance:
            personal_deployment_indicators['ownable_without_governance'] = True
        
        # Pattern 5: Personal profit mentions (vs protocol fees)
        if re.search(r'(?:owner|deployer|user).*(?:profit|reward|fee)', contract_code, re.IGNORECASE):
            personal_deployment_indicators['personal_profit_mention'] = True
        
        # Calculate confidence score
        indicator_score = sum(personal_deployment_indicators.values())
        
        # Require at least 2 indicators for high confidence
        if indicator_score >= 2:
            return {
                'is_personal_deployment': True,
                'confidence': min(0.9, 0.5 + (indicator_score * 0.15)),  # 0.65-0.9 confidence
                'indicators': personal_deployment_indicators,
                'indicator_count': indicator_score,
                'reasoning': self._generate_personal_deployment_reasoning(personal_deployment_indicators, contract_name),
                'implication': 'Centralization/access control is BY DESIGN for personal tools',
                'severity_override': 'INFORMATIONAL',  # Not a vulnerability
            }
        
        return None
    
    def _generate_personal_deployment_reasoning(self, indicators: Dict[str, bool], contract_name: str) -> str:
        """Generate reasoning for personal deployment classification."""
        active_indicators = [key for key, value in indicators.items() if value]
        
        reasoning = f"Contract '{contract_name}' is a PERSONAL DEPLOYMENT tool, not a protocol contract.\n\n"
        reasoning += "Evidence:\n"
        
        if indicators['explicit_comment']:
            reasoning += "- Explicit documentation recommending personal deployment\n"
        if indicators['bot_naming']:
            reasoning += f"- Bot/tool naming convention ('{contract_name}')\n"
        if indicators['mev_protection_mention']:
            reasoning += "- Comments about protecting personal profits from MEV\n"
        if indicators['ownable_without_governance']:
            reasoning += "- Ownable pattern without governance (intentional for personal control)\n"
        if indicators['personal_profit_mention']:
            reasoning += "- References to individual owner profits (not protocol fees)\n"
        
        reasoning += "\nIMPLICATION:\n"
        reasoning += "Centralization/privileged functions are BY DESIGN.\n"
        reasoning += "Each user deploys their own instance and controls it directly.\n"
        reasoning += "This is NOT a protocol vulnerability - it's intended architecture.\n"
        
        return reasoning

