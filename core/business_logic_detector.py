"""
Business Logic Vulnerability Detector

This module detects business logic errors in smart contracts, inspired by Move vulnerability patterns:
- Backwards validation logic (checking for wrong condition)
- Self-comparison bugs (comparing variable to itself)
- Incorrect parameter order in function calls
- Cooldown/timestamp comparison errors
- Reward calculation issues
- Authentication logic errors
"""

import re
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum


class BusinessLogicVulnerabilityType(Enum):
    """Types of business logic vulnerabilities"""
    BACKWARDS_VALIDATION = "backwards_validation"
    SELF_COMPARISON = "self_comparison"
    INCORRECT_PARAMETER_ORDER = "incorrect_parameter_order"
    COOLDOWN_BYPASS = "cooldown_bypass"
    REWARD_CALCULATION_ERROR = "reward_calculation_error"
    AUTHENTICATION_ERROR = "authentication_error"
    INCORRECT_SORTING = "incorrect_sorting"
    VERSION_CHECK_ERROR = "version_check_error"


@dataclass
class BusinessLogicVulnerability:
    """Represents a business logic vulnerability"""
    vulnerability_type: str
    severity: str
    description: str
    line_number: int
    code_snippet: str
    confidence: float
    swc_id: str
    recommendation: str
    context: Dict[str, Any]


class BusinessLogicDetector:
    """Detects business logic vulnerabilities in smart contracts"""
    
    def __init__(self):
        self.backwards_validation_patterns = self._initialize_backwards_validation_patterns()
        self.self_comparison_patterns = self._initialize_self_comparison_patterns()
        self.parameter_order_patterns = self._initialize_parameter_order_patterns()
        self.cooldown_patterns = self._initialize_cooldown_patterns()
        self.reward_calculation_patterns = self._initialize_reward_calculation_patterns()
        self.authentication_patterns = self._initialize_authentication_patterns()
    
    def _initialize_backwards_validation_patterns(self) -> List[Dict[str, Any]]:
        """Initialize patterns for backwards validation logic"""
        return [
            {
                'pattern': r'require\s*\(\s*!\s*(\w+)\s*\)',
                'description': 'Negated condition in require - verify logic is not backwards',
                'severity': 'medium',
                'confidence': 0.6,
                'recommendation': 'Review logic - ensure condition is not inverted'
            },
            {
                'pattern': r'if\s*\(\s*!\s*exists\[',
                'description': 'Checking for non-existence when should check existence',
                'severity': 'high',
                'confidence': 0.7,
                'recommendation': 'Verify logic - typically should check if(exists[...])'
            },
            {
                'pattern': r'require\s*\(\s*!\s*authorized\[',
                'description': 'Checking for unauthorized when should check authorized',
                'severity': 'critical',
                'confidence': 0.8,
                'recommendation': 'Logic appears backwards - should check require(authorized[...])'
            }
        ]
    
    def _initialize_self_comparison_patterns(self) -> List[Dict[str, Any]]:
        """Initialize patterns for self-comparison bugs"""
        return [
            {
                'pattern': r'(\w+(?:\.\w+)?)\s*[=!<>]=\s*\1(?!\w)',
                'description': 'Variable compared to itself - likely copy-paste error',
                'severity': 'high',
                'confidence': 0.85,
                'recommendation': 'Variable compared to itself - check for typo or logic error'
            },
            {
                'pattern': r'assert\s*\(\s*(\w+)\s*[!<>=]=\s*\1\s*\)',
                'description': 'Assert compares variable to itself',
                'severity': 'high',
                'confidence': 0.85,
                'recommendation': 'Self-comparison in assert - always true or always false'
            }
        ]
    
    def _initialize_parameter_order_patterns(self) -> List[Dict[str, Any]]:
        """Initialize patterns for incorrect parameter order"""
        return [
            {
                'pattern': r'function\s+(\w+)\s*\([^)]*uint256\s+price[^)]*uint256\s+amount[^)]*\).*?function\s+\1\s*\([^)]*amount[^)]*price',
                'description': 'Function parameters may be in wrong order',
                'severity': 'high',
                'confidence': 0.65,
                'recommendation': 'Verify parameter order matches expected convention'
            },
            {
                'pattern': r'swap\s*\(\s*(\w+)\s*,\s*(\w+)\s*\).*?\/\/.*?should be \2.*?\1',
                'description': 'Comment indicates parameters in wrong order',
                'severity': 'critical',
                'confidence': 0.95,
                'recommendation': 'Fix parameter order as indicated in comment'
            }
        ]
    
    def _initialize_cooldown_patterns(self) -> List[Dict[str, Any]]:
        """Initialize patterns for cooldown/timestamp errors"""
        return [
            {
                'pattern': r'require\s*\(\s*block\.timestamp\s*>=\s*(\w+\.cooldown)',
                'description': 'Cooldown check uses >= instead of > (allows bypass at exact time)',
                'severity': 'medium',
                'confidence': 0.7,
                'recommendation': 'Use strict inequality (>) for cooldown checks'
            },
            {
                'pattern': r'block\.timestamp\s*<=\s*(\w+\.deadline)',
                'description': 'Deadline check may allow action at exact expiry time',
                'severity': 'low',
                'confidence': 0.6,
                'recommendation': 'Consider using strict inequality (<) for deadlines'
            },
            {
                'pattern': r'require\s*\(\s*currentTime\s*>=\s*cooldown\.cooldownEnd\s*\|\|',
                'description': 'Cooldown logic with OR may allow bypass',
                'severity': 'high',
                'confidence': 0.75,
                'recommendation': 'Review cooldown logic - OR condition may create bypass'
            }
        ]
    
    def _initialize_reward_calculation_patterns(self) -> List[Dict[str, Any]]:
        """Initialize patterns for reward calculation errors"""
        return [
            {
                'pattern': r'rewardIndex\s*-\s*0(?!\w)',
                'description': 'Reward calculation uses 0 as baseline (may allow new users to claim all rewards)',
                'severity': 'critical',
                'confidence': 0.8,
                'recommendation': 'Use user.lastRewardIndex instead of 0 for new users'
            },
            {
                'pattern': r'reward\s*=.*?totalRewardIndex(?!.*?user\.lastRewardIndex)',
                'description': 'Reward calculated from total without user baseline',
                'severity': 'high',
                'confidence': 0.75,
                'recommendation': 'Subtract user.lastRewardIndex to prevent claiming full history'
            },
            {
                'pattern': r'userReward\s*=.*?poolReward\s*\*\s*userShare',
                'description': 'Reward calculation may have precision loss',
                'severity': 'medium',
                'confidence': 0.65,
                'recommendation': 'Review for precision loss - multiply before divide'
            }
        ]
    
    def _initialize_authentication_patterns(self) -> List[Dict[str, Any]]:
        """Initialize patterns for authentication logic errors"""
        return [
            {
                'pattern': r'require\s*\(\s*!\s*isAuthorized\s*\)',
                'description': 'Authentication check appears backwards',
                'severity': 'critical',
                'confidence': 0.85,
                'recommendation': 'Remove negation - should be require(isAuthorized)'
            },
            {
                'pattern': r'if\s*\(\s*!\s*whitelist\[.*?\]\s*\).*?revert',
                'description': 'Whitelist check logic may be inverted',
                'severity': 'high',
                'confidence': 0.75,
                'recommendation': 'Verify logic - typically revert if NOT in whitelist'
            }
        ]
    
    def analyze_business_logic(self, contract_content: str) -> List[BusinessLogicVulnerability]:
        """Analyze contract for business logic vulnerabilities"""
        vulnerabilities = []
        lines = contract_content.split('\n')
        
        # Detect backwards validation logic
        vulnerabilities.extend(self._detect_backwards_validation(contract_content, lines))
        
        # Detect self-comparison bugs
        vulnerabilities.extend(self._detect_self_comparison(contract_content, lines))
        
        # Detect parameter order issues
        vulnerabilities.extend(self._detect_parameter_order_issues(contract_content, lines))
        
        # Detect cooldown/timestamp errors
        vulnerabilities.extend(self._detect_cooldown_errors(contract_content, lines))
        
        # Detect reward calculation issues
        vulnerabilities.extend(self._detect_reward_calculation_errors(contract_content, lines))
        
        # Detect authentication errors
        vulnerabilities.extend(self._detect_authentication_errors(contract_content, lines))
        
        return vulnerabilities
    
    def _detect_backwards_validation(self, contract_content: str, lines: List[str]) -> List[BusinessLogicVulnerability]:
        """Detect backwards validation logic"""
        vulnerabilities = []
        
        for pattern_info in self.backwards_validation_patterns:
            pattern = pattern_info['pattern']
            matches = re.finditer(pattern, contract_content, re.MULTILINE)
            
            for match in matches:
                line_number = self._get_line_number(match.start(), contract_content)
                code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""
                
                # Skip if this is intentional (e.g., reverting on condition)
                if self._is_intentional_negation(code_snippet, contract_content, line_number):
                    continue
                
                vulnerability = BusinessLogicVulnerability(
                    vulnerability_type='backwards_validation',
                    severity=pattern_info['severity'],
                    description=pattern_info['description'],
                    line_number=line_number,
                    code_snippet=code_snippet,
                    confidence=pattern_info['confidence'],
                    swc_id='SWC-123',
                    recommendation=pattern_info['recommendation'],
                    context={'pattern': pattern, 'match': match.group(0)}
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _detect_self_comparison(self, contract_content: str, lines: List[str]) -> List[BusinessLogicVulnerability]:
        """Detect self-comparison bugs"""
        vulnerabilities = []
        
        for pattern_info in self.self_comparison_patterns:
            pattern = pattern_info['pattern']
            matches = re.finditer(pattern, contract_content, re.MULTILINE)
            
            for match in matches:
                line_number = self._get_line_number(match.start(), contract_content)
                code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""
                
                # Skip if match is inside a comment (check the actual match position)
                match_start = match.start()
                line_start = contract_content.rfind('\n', 0, match_start) + 1
                before_match = contract_content[line_start:match_start]
                if '//' in before_match:
                    continue
                
                # Skip if the comparison itself is in a string literal (very unlikely)
                if code_snippet.startswith('//') or code_snippet.startswith('/*'):
                    continue
                
                # Skip if intentional (e.g., while (x == x) for infinite loop)
                if 'while' in code_snippet or 'for' in code_snippet:
                    continue
                
                vulnerability = BusinessLogicVulnerability(
                    vulnerability_type='self_comparison',
                    severity=pattern_info['severity'],
                    description=pattern_info['description'],
                    line_number=line_number,
                    code_snippet=code_snippet,
                    confidence=pattern_info['confidence'],
                    swc_id='SWC-123',
                    recommendation=pattern_info['recommendation'],
                    context={'variable': match.group(1) if len(match.groups()) > 0 else 'unknown'}
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _detect_parameter_order_issues(self, contract_content: str, lines: List[str]) -> List[BusinessLogicVulnerability]:
        """Detect incorrect parameter order"""
        vulnerabilities = []
        
        for pattern_info in self.parameter_order_patterns:
            pattern = pattern_info['pattern']
            matches = re.finditer(pattern, contract_content, re.MULTILINE | re.DOTALL)
            
            for match in matches:
                line_number = self._get_line_number(match.start(), contract_content)
                code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""
                
                vulnerability = BusinessLogicVulnerability(
                    vulnerability_type='incorrect_parameter_order',
                    severity=pattern_info['severity'],
                    description=pattern_info['description'],
                    line_number=line_number,
                    code_snippet=code_snippet,
                    confidence=pattern_info['confidence'],
                    swc_id='SWC-123',
                    recommendation=pattern_info['recommendation'],
                    context={'match': match.group(0)[:100]}
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _detect_cooldown_errors(self, contract_content: str, lines: List[str]) -> List[BusinessLogicVulnerability]:
        """Detect cooldown/timestamp comparison errors"""
        vulnerabilities = []
        
        for pattern_info in self.cooldown_patterns:
            pattern = pattern_info['pattern']
            matches = re.finditer(pattern, contract_content, re.MULTILINE)
            
            for match in matches:
                line_number = self._get_line_number(match.start(), contract_content)
                code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""
                
                vulnerability = BusinessLogicVulnerability(
                    vulnerability_type='cooldown_bypass',
                    severity=pattern_info['severity'],
                    description=pattern_info['description'],
                    line_number=line_number,
                    code_snippet=code_snippet,
                    confidence=pattern_info['confidence'],
                    swc_id='SWC-116',
                    recommendation=pattern_info['recommendation'],
                    context={'match': match.group(0)}
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _detect_reward_calculation_errors(self, contract_content: str, lines: List[str]) -> List[BusinessLogicVulnerability]:
        """Detect reward calculation errors"""
        vulnerabilities = []
        
        for pattern_info in self.reward_calculation_patterns:
            pattern = pattern_info['pattern']
            matches = re.finditer(pattern, contract_content, re.MULTILINE)
            
            for match in matches:
                line_number = self._get_line_number(match.start(), contract_content)
                code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""
                
                vulnerability = BusinessLogicVulnerability(
                    vulnerability_type='reward_calculation_error',
                    severity=pattern_info['severity'],
                    description=pattern_info['description'],
                    line_number=line_number,
                    code_snippet=code_snippet,
                    confidence=pattern_info['confidence'],
                    swc_id='SWC-101',
                    recommendation=pattern_info['recommendation'],
                    context={'match': match.group(0)}
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _detect_authentication_errors(self, contract_content: str, lines: List[str]) -> List[BusinessLogicVulnerability]:
        """Detect authentication logic errors"""
        vulnerabilities = []
        
        for pattern_info in self.authentication_patterns:
            pattern = pattern_info['pattern']
            matches = re.finditer(pattern, contract_content, re.MULTILINE)
            
            for match in matches:
                line_number = self._get_line_number(match.start(), contract_content)
                code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""
                
                vulnerability = BusinessLogicVulnerability(
                    vulnerability_type='authentication_error',
                    severity=pattern_info['severity'],
                    description=pattern_info['description'],
                    line_number=line_number,
                    code_snippet=code_snippet,
                    confidence=pattern_info['confidence'],
                    swc_id='SWC-105',
                    recommendation=pattern_info['recommendation'],
                    context={'match': match.group(0)}
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _is_intentional_negation(self, code_snippet: str, contract_content: str, line_number: int) -> bool:
        """Check if negation is intentional (e.g., reverting on false condition)"""
        # Check for revert pattern
        if 'revert' in code_snippet.lower():
            return True
        
        # Check if followed by revert
        lines = contract_content.split('\n')
        if line_number < len(lines):
            next_line = lines[line_number].strip() if line_number < len(lines) else ""
            if 'revert' in next_line.lower():
                return True
        
        return False
    
    def _get_line_number(self, position: int, content: str) -> int:
        """Get line number from character position"""
        return content[:position].count('\n') + 1
    
    def get_business_logic_summary(self, contract_content: str) -> Dict[str, Any]:
        """Get summary of business logic vulnerabilities"""
        vulnerabilities = self.analyze_business_logic(contract_content)
        
        summary = {
            'total_vulnerabilities': len(vulnerabilities),
            'by_type': {},
            'by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        }
        
        for vuln in vulnerabilities:
            # Count by type
            vuln_type = vuln.vulnerability_type
            summary['by_type'][vuln_type] = summary['by_type'].get(vuln_type, 0) + 1
            
            # Count by severity
            severity = vuln.severity.lower()
            if severity in summary['by_severity']:
                summary['by_severity'][severity] += 1
        
        return summary

