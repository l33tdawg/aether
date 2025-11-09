"""
External Trust Analyzer for Smart Contract Security

This module analyzes external contract calls for trust issues, missing validation,
and potential manipulation vulnerabilities.
"""

import re
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum
from collections import defaultdict


class TrustLevel(Enum):
    """Trust levels for external contracts"""
    UNTRUSTED = "untrusted"
    PARTIALLY_TRUSTED = "partially_trusted"
    TRUSTED = "trusted"
    UNKNOWN = "unknown"


class CallType(Enum):
    """Types of external calls"""
    STATIC_CALL = "static_call"
    DELEGATE_CALL = "delegate_call"
    CALL = "call"
    TRANSFER = "transfer"
    SEND = "send"
    FUNCTION_CALL = "function_call"


@dataclass
class ExternalCall:
    """Represents an external contract call"""
    call_type: CallType
    target_contract: str
    function_name: Optional[str]
    line_number: int
    code_snippet: str
    has_validation: bool
    has_gas_limit: bool
    has_return_value_check: bool
    trust_level: TrustLevel
    risk_score: float


@dataclass
class TrustVulnerability:
    """Represents a trust-related vulnerability"""
    vulnerability_type: str
    severity: str
    description: str
    line_number: int
    code_snippet: str
    confidence: float
    swc_id: str
    recommendation: str
    affected_contract: str


class ExternalTrustAnalyzer:
    """Analyzes external contract dependencies for trust issues"""
    
    def __init__(self):
        self.trust_patterns = self._initialize_trust_patterns()
        self.validation_patterns = self._initialize_validation_patterns()
        self.known_trusted_contracts = self._initialize_trusted_contracts()
        self.known_untrusted_patterns = self._initialize_untrusted_patterns()
        
    def _initialize_trust_patterns(self) -> List[Dict[str, Any]]:
        """Initialize patterns for trust analysis"""
        return [
            {
                'pattern': r'(\w+)\.call\s*\([^)]*\)',
                'description': 'Low-level call without validation',
                'severity': 'high',
                'swc_id': 'SWC-107'
            },
            {
                'pattern': r'(\w+)\.delegatecall\s*\([^)]*\)',
                'description': 'Delegate call without validation',
                'severity': 'critical',
                'swc_id': 'SWC-112'
            },
            {
                'pattern': r'(\w+)\.staticcall\s*\([^)]*\)',
                'description': 'Static call without validation',
                'severity': 'medium',
                'swc_id': 'SWC-107'
            },
            {
                'pattern': r'(\w+)\.transfer\s*\([^)]*\)',
                'description': 'Transfer without validation',
                'severity': 'medium',
                'swc_id': 'SWC-107'
            },
            {
                'pattern': r'(\w+)\.send\s*\([^)]*\)',
                'description': 'Send without validation',
                'severity': 'medium',
                'swc_id': 'SWC-107'
            }
        ]
    
    def _initialize_validation_patterns(self) -> List[str]:
        """Initialize patterns for validation detection"""
        return [
            r'require\s*\(\s*\w+\s*!=\s*address\s*\(\s*0\s*\)\s*\)',
            r'require\s*\(\s*\w+\s*!=\s*0\s*\)',
            r'assert\s*\(\s*\w+\s*!=\s*address\s*\(\s*0\s*\)\s*\)',
            r'assert\s*\(\s*\w+\s*!=\s*0\s*\)',
            r'if\s*\(\s*\w+\s*!=\s*address\s*\(\s*0\s*\)\s*\)',
            r'if\s*\(\s*\w+\s*!=\s*0\s*\)'
        ]
    
    def _initialize_trusted_contracts(self) -> Set[str]:
        """Initialize list of known trusted contracts"""
        return {
            'WETH', 'USDC', 'USDT', 'DAI', 'WBTC', 'UNI', 'LINK', 'AAVE', 'COMP', 'MKR',
            'OpenZeppelin', 'SafeMath', 'ERC20', 'ERC721', 'ERC1155', 'Ownable', 'Pausable'
        }
    
    def _initialize_untrusted_patterns(self) -> List[str]:
        """Initialize patterns for untrusted contracts"""
        return [
            r'msg\.sender',
            r'tx\.origin',
            r'address\s*\(\s*0\s*\)',
            r'address\s*\(\s*1\s*\)'
        ]
    
    def analyze_external_dependencies(self, contract_content: str) -> List[TrustVulnerability]:
        """Analyze external contract dependencies for trust issues"""
        vulnerabilities = []
        
        # Split content into lines for line number tracking
        lines = contract_content.split('\n')
        
        # Detect external calls without validation
        vulnerabilities.extend(self._detect_unvalidated_external_calls(contract_content, lines))
        
        # Detect missing contract existence checks
        vulnerabilities.extend(self._detect_missing_existence_checks(contract_content, lines))
        
        # Detect potential external manipulation
        vulnerabilities.extend(self._detect_external_manipulation(contract_content, lines))
        
        # Detect delegate call vulnerabilities
        vulnerabilities.extend(self._detect_delegate_call_vulnerabilities(contract_content, lines))
        
        # Detect reentrancy vulnerabilities
        vulnerabilities.extend(self._detect_reentrancy_vulnerabilities(contract_content, lines))
        
        return vulnerabilities
    
    def _detect_unvalidated_external_calls(self, contract_content: str, lines: List[str]) -> List[TrustVulnerability]:
        """Detect external calls without validation"""
        vulnerabilities = []
        
        for pattern_info in self.trust_patterns:
            pattern = pattern_info['pattern']
            matches = re.finditer(pattern, contract_content, re.MULTILINE)
            
            for match in matches:
                line_number = self._get_line_number(match.start(), contract_content)
                code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""
                target_contract = match.group(1)
                
                # Skip language-reserved dispatch (internal base call) like super.<fn>()
                # This is not an external call and does not require existence checks/validation
                if target_contract == 'super':
                    continue
                
                # Check if this is a false positive
                if self._is_false_positive_external_call(match, code_snippet, target_contract):
                    continue
                
                # Check if there's validation nearby
                has_validation = self._has_validation_nearby(contract_content, line_number, target_contract)
                
                if not has_validation:
                    vulnerability = TrustVulnerability(
                        vulnerability_type='unvalidated_external_call',
                        severity=pattern_info['severity'],
                        description=pattern_info['description'],
                        line_number=line_number,
                        code_snippet=code_snippet,
                        confidence=self._calculate_external_call_confidence(match, code_snippet, target_contract),
                        swc_id=pattern_info['swc_id'],
                        recommendation=self._get_external_call_recommendation(target_contract),
                        affected_contract=target_contract
                    )
                    vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _detect_missing_existence_checks(self, contract_content: str, lines: List[str]) -> List[TrustVulnerability]:
        """Detect missing contract existence checks"""
        vulnerabilities = []
        
        # Pattern for external calls
        external_call_pattern = r'(\w+)\.(call|delegatecall|staticcall|transfer|send)\s*\([^)]*\)'
        matches = re.finditer(external_call_pattern, contract_content, re.MULTILINE)
        
        for match in matches:
            line_number = self._get_line_number(match.start(), contract_content)
            code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""
            target_contract = match.group(1)
            
            # Skip language-reserved dispatch (internal base call) like super.<fn>()
            # This is not an external call and does not require existence checks
            if target_contract == 'super':
                continue
            
            # Check if there's an existence check
            has_existence_check = self._has_existence_check(contract_content, line_number, target_contract)
            
            if not has_existence_check:
                vulnerability = TrustVulnerability(
                    vulnerability_type='missing_existence_check',
                    severity='medium',
                    description=f'External call to {target_contract} without existence check',
                    line_number=line_number,
                    code_snippet=code_snippet,
                    confidence=0.7,
                    swc_id='SWC-107',
                    recommendation=f'Add existence check: require({target_contract} != address(0))',
                    affected_contract=target_contract
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _detect_external_manipulation(self, contract_content: str, lines: List[str]) -> List[TrustVulnerability]:
        """Detect potential external manipulation"""
        vulnerabilities = []
        
        # Pattern for external calls in critical functions
        critical_function_pattern = r'function\s+(\w+)\s*\([^)]*\)\s*(?:external|public)'
        function_matches = re.finditer(critical_function_pattern, contract_content, re.MULTILINE)
        
        for func_match in function_matches:
            function_name = func_match.group(1)
            func_line = self._get_line_number(func_match.start(), contract_content)
            
            # Find external calls within this function
            func_end_line = self._find_function_end(contract_content, func_line)
            
            if func_end_line:
                func_content = '\n'.join(lines[func_line - 1:func_end_line])
                
                # Check for external calls
                external_calls = re.findall(r'(\w+)\.(call|delegatecall|staticcall|transfer|send)', func_content)
                
                for target_contract, call_type in external_calls:
                    # Skip internal base calls via super
                    if target_contract == 'super':
                        continue
                    # Check if this is a user-controlled contract
                    if self._is_user_controlled_contract(target_contract, func_content):
                        vulnerability = TrustVulnerability(
                            vulnerability_type='external_manipulation',
                            severity='high',
                            description=f'External call to user-controlled contract {target_contract} in function {function_name}',
                            line_number=func_line,
                            code_snippet=func_content.split('\n')[0],
                            confidence=0.8,
                            swc_id='SWC-107',
                            recommendation='Add access control and validation for external calls',
                            affected_contract=target_contract
                        )
                        vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _detect_delegate_call_vulnerabilities(self, contract_content: str, lines: List[str]) -> List[TrustVulnerability]:
        """Detect delegate call vulnerabilities"""
        vulnerabilities = []
        
        # Pattern for delegate calls
        delegate_call_pattern = r'(\w+)\.delegatecall\s*\([^)]*\)'
        matches = re.finditer(delegate_call_pattern, contract_content, re.MULTILINE)
        
        for match in matches:
            line_number = self._get_line_number(match.start(), contract_content)
            code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""
            target_contract = match.group(1)
            
            vulnerability = TrustVulnerability(
                vulnerability_type='delegate_call_vulnerability',
                severity='critical',
                description=f'Delegate call to {target_contract} - high risk of code injection',
                line_number=line_number,
                code_snippet=code_snippet,
                confidence=0.9,
                swc_id='SWC-112',
                recommendation='Avoid delegate calls or implement strict validation',
                affected_contract=target_contract
            )
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _detect_reentrancy_vulnerabilities(self, contract_content: str, lines: List[str]) -> List[TrustVulnerability]:
        """Detect reentrancy vulnerabilities"""
        vulnerabilities = []
        
        # Pattern for external calls followed by state changes
        # Updated to handle .call{value: amount}("") syntax
        external_call_pattern = r'(\w+)\.(call|delegatecall|staticcall|transfer|send)(\{[^}]*\})?\s*\('
        matches = re.finditer(external_call_pattern, contract_content, re.MULTILINE)
        
        for match in matches:
            line_number = self._get_line_number(match.start(), contract_content)
            code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""
            target_contract = match.group(1)
            
            # Check for reentrancy guards (nonReentrant modifier, etc.)
            if self._has_reentrancy_guard(contract_content, line_number):
                continue
            
            # FIX 3: Check if function has access control protection (onlyOwner, etc.)
            # Reentrancy in access-controlled functions is less critical (requires privileged access)
            if self._has_access_control_protection(contract_content, line_number):
                # Only flag if it's a critical issue or can be exploited via front-running
                # Otherwise, skip since it requires privileged access
                if not self._is_critical_reentrancy_context(contract_content, line_number, code_snippet):
                    continue
            
            # Check if there are state changes after this call
            has_state_changes_after = self._has_state_changes_after(contract_content, line_number)
            
            if has_state_changes_after:
                vulnerability = TrustVulnerability(
                    vulnerability_type='reentrancy_vulnerability',
                    severity='high',
                    description=f'Potential reentrancy vulnerability: external call to {target_contract} followed by state changes',
                    line_number=line_number,
                    code_snippet=code_snippet,
                    confidence=0.7,
                    swc_id='SWC-107',
                    recommendation='Use checks-effects-interactions pattern or reentrancy guards',
                    affected_contract=target_contract
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _get_line_number(self, position: int, content: str) -> int:
        """Get line number from character position"""
        return content[:position].count('\n') + 1
    
    def _is_false_positive_external_call(self, match: re.Match, code_snippet: str, target_contract: str) -> bool:
        """Check if external call detection is a false positive"""
        # Skip if target is a known trusted contract
        if target_contract in self.known_trusted_contracts:
            return True
        
        # Skip if there's explicit validation
        if any(pattern in code_snippet for pattern in ['require(', 'assert(', 'if (']):
            return True
        
        # Skip if using OpenZeppelin or other trusted libraries
        if 'OpenZeppelin' in code_snippet or 'SafeMath' in code_snippet:
            return True
        
        # FIX 1: Skip read-only ERC20 functions (balanceOf, allowance, totalSupply, etc.)
        # These are view functions that cannot manipulate state or cause trust issues
        read_only_erc20_functions = [
            'balanceOf', 'allowance', 'totalSupply', 'name', 'symbol', 
            'decimals', 'balance', 'nonce', 'DOMAIN_SEPARATOR', 'PERMIT_TYPEHASH'
        ]
        if any(func in code_snippet for func in read_only_erc20_functions):
            return True  # These are view functions, not trust issues
        
        # FIX 2: Skip if this is an IERC20 interface cast (view-only operations)
        if re.search(r'IERC20\s*\([^)]+\)\.(balanceOf|allowance|totalSupply|name|symbol|decimals)', code_snippet):
            return True
        
        return False
    
    def _has_validation_nearby(self, contract_content: str, line_number: int, target_contract: str) -> bool:
        """Check if there's validation nearby the external call"""
        lines = contract_content.split('\n')
        
        # Check lines before and after the call
        start_line = max(0, line_number - 5)
        end_line = min(len(lines), line_number + 5)
        
        for i in range(start_line, end_line):
            if i < len(lines):
                line = lines[i]
                # Check for validation patterns
                for pattern in self.validation_patterns:
                    if re.search(pattern, line):
                        return True
        
        return False
    
    def _has_existence_check(self, contract_content: str, line_number: int, target_contract: str) -> bool:
        """Check if there's an existence check for the target contract"""
        lines = contract_content.split('\n')
        
        # Check lines before the call
        start_line = max(0, line_number - 10)
        end_line = line_number
        
        for i in range(start_line, end_line):
            if i < len(lines):
                line = lines[i]
                # Check for existence check patterns
                if (f'{target_contract} != address(0)' in line or 
                    f'{target_contract} != 0' in line or
                    f'require({target_contract}' in line):
                    return True
        
        return False
    
    def _is_user_controlled_contract(self, target_contract: str, func_content: str) -> bool:
        """Check if the target contract is user-controlled"""
        # Check if target is msg.sender or tx.origin
        if target_contract in ['msg.sender', 'tx.origin']:
            return True
        
        # Check if target is a parameter
        if f'{target_contract}' in func_content and 'function' in func_content:
            return True
        
        return False
    
    def _has_state_changes_after(self, contract_content: str, line_number: int) -> bool:
        """Check if there are state changes after the external call"""
        lines = contract_content.split('\n')
        
        # Check lines after the call
        start_line = line_number
        end_line = min(len(lines), line_number + 20)
        
        for i in range(start_line, end_line):
            if i < len(lines):
                line = lines[i]
                # Check for state change patterns
                if re.search(r'\w+\s*=\s*[^;]+;', line) or re.search(r'\w+\s*\+\+|--', line):
                    return True
        
        return False
    
    def _find_function_end(self, contract_content: str, start_line: int) -> Optional[int]:
        """Find the end of a function"""
        lines = contract_content.split('\n')
        brace_count = 0
        in_function = False
        
        for i in range(start_line - 1, len(lines)):
            line = lines[i]
            
            if '{' in line:
                brace_count += line.count('{')
                in_function = True
            elif '}' in line:
                brace_count -= line.count('}')
                
                if in_function and brace_count == 0:
                    return i + 1
        
        return None
    
    def _has_reentrancy_guard(self, contract_content: str, line_number: int) -> bool:
        """Check if the function has a reentrancy guard"""
        function_context = self._get_function_context_for_line(contract_content, line_number)
        
        if not function_context:
            return False
        
        # Check for nonReentrant modifier
        if 'nonReentrant' in function_context:
            return True
        
        # Check for custom guards
        guard_patterns = [
            r'require\s*\(\s*!locked',
            r'require\s*\(\s*_status\s*!=',
            r'require\s*\(\s*statusReentrant',
            r'_ENTERED',
            r'_NOT_ENTERED',
        ]
        
        for pattern in guard_patterns:
            if re.search(pattern, function_context):
                return True
        
        return False
    
    def _get_function_context_for_line(self, contract_content: str, line_number: int) -> str:
        """Extract the function containing the specified line"""
        lines = contract_content.split('\n')
        
        function_start = -1
        for i in range(line_number - 1, -1, -1):
            if i >= len(lines):
                continue
            if re.match(r'\s*function\s+\w+', lines[i]):
                function_start = i
                break
        
        if function_start == -1:
            return ""
        
        function_end = len(lines)
        brace_count = 0
        for i in range(function_start, len(lines)):
            line = lines[i]
            brace_count += line.count('{') - line.count('}')
            if brace_count == 0 and '{' in '\n'.join(lines[function_start:i+1]):
                function_end = i + 1
                break
        
        return '\n'.join(lines[function_start:function_end])
    
    def _has_access_control_protection(self, contract_content: str, line_number: int) -> bool:
        """Check if function has access control (onlyOwner, onlyRole, etc.)"""
        function_context = self._get_function_context_for_line(contract_content, line_number)
        
        if not function_context:
            return False
        
        # Check for access control modifiers
        access_modifiers = [
            'onlyOwner', 'onlyRole', 'onlyAdmin', 'onlyGovernance', 
            'onlyAuthorized', 'onlyManager', 'onlyKeeper', 'onlyOperator'
        ]
        
        # Check modifiers on function declaration
        for modifier in access_modifiers:
            if re.search(rf'\b{modifier}\b', function_context):
                return True
        
        # Check for internal authorization calls
        auth_patterns = [
            r'_authorizeUpgrade\s*\(',
            r'_checkRole\s*\(',
            r'_onlyOwner\s*\(',
            r'require\s*\(\s*msg\.sender\s*==\s*\w+\.owner\s*\(\s*\)',
            r'require\s*\(\s*owner\s*==\s*msg\.sender',
        ]
        
        for pattern in auth_patterns:
            if re.search(pattern, function_context):
                return True
        
        return False
    
    def _is_critical_reentrancy_context(self, contract_content: str, line_number: int, code_snippet: str) -> bool:
        """Check if reentrancy is in a critical context that should still be flagged even with access control"""
        function_context = self._get_function_context_for_line(contract_content, line_number)
        
        if not function_context:
            return True  # Default to flagging if we can't determine context
        
        # Critical contexts that should still be flagged:
        # 1. Flash loan operations
        critical_keywords = ['flashLoan', 'flashBorrow', 'onFlashLoan', 'arbitrage']
        if any(keyword in function_context.lower() or keyword in code_snippet.lower() for keyword in critical_keywords):
            return True
        
        # 2. Functions that handle user funds
        fund_keywords = ['withdraw', 'transfer', 'liquidation', 'liquidate']
        if any(keyword in function_context.lower() for keyword in fund_keywords):
            return True
        
        # 3. Functions that modify critical state
        critical_state = ['balance', 'totalSupply', 'reserves', 'collateral']
        if any(keyword in function_context.lower() for keyword in critical_state):
            return True
        
        return False
    
    def _calculate_external_call_confidence(self, match: re.Match, code_snippet: str, target_contract: str) -> float:
        """Calculate confidence score for external call detection"""
        confidence = 0.5  # Base confidence
        
        # Increase confidence if no validation
        if 'require(' not in code_snippet and 'assert(' not in code_snippet:
            confidence += 0.2
        
        # Increase confidence if target is user-controlled
        if target_contract in ['msg.sender', 'tx.origin']:
            confidence += 0.3
        
        # Increase confidence if in external/public function
        if 'external' in code_snippet or 'public' in code_snippet:
            confidence += 0.1
        
        return min(confidence, 1.0)
    
    def _get_external_call_recommendation(self, target_contract: str) -> str:
        """Get recommendation for external call vulnerabilities"""
        return f"Add validation for {target_contract}: require({target_contract} != address(0))"
    
    def analyze_contract_trust_level(self, contract_content: str) -> TrustLevel:
        """Analyze the overall trust level of the contract"""
        # Count external calls
        external_calls = len(re.findall(r'\w+\.(call|delegatecall|staticcall|transfer|send)', contract_content))
        
        # Count validation patterns
        validations = len(re.findall(r'require\s*\([^)]*\)|assert\s*\([^)]*\)', contract_content))
        
        # Count access control patterns
        access_controls = len(re.findall(r'onlyOwner|onlyAdmin|modifier', contract_content))
        
        # Calculate trust score
        trust_score = (validations + access_controls) / max(external_calls, 1)
        
        if trust_score >= 2.0:
            return TrustLevel.TRUSTED
        elif trust_score >= 1.0:
            return TrustLevel.PARTIALLY_TRUSTED
        elif trust_score >= 0.5:
            return TrustLevel.UNTRUSTED
        else:
            return TrustLevel.UNKNOWN
    
    def get_external_call_summary(self, contract_content: str) -> Dict[str, Any]:
        """Get summary of external calls in the contract"""
        external_calls = []
        
        # Find all external calls
        call_pattern = r'(\w+)\.(call|delegatecall|staticcall|transfer|send)\s*\([^)]*\)'
        matches = re.finditer(call_pattern, contract_content, re.MULTILINE)
        
        for match in matches:
            line_number = self._get_line_number(match.start(), contract_content)
            target_contract = match.group(1)
            call_type = CallType(match.group(2))
            
            external_calls.append(ExternalCall(
                call_type=call_type,
                target_contract=target_contract,
                function_name=None,
                line_number=line_number,
                code_snippet=match.group(0),
                has_validation=self._has_validation_nearby(contract_content, line_number, target_contract),
                has_gas_limit='gas' in match.group(0),
                has_return_value_check=False,  # Would need more complex analysis
                trust_level=self._get_contract_trust_level(target_contract),
                risk_score=self._calculate_call_risk_score(call_type, target_contract)
            ))
        
        return {
            'total_calls': len(external_calls),
            'calls_by_type': self._group_calls_by_type(external_calls),
            'calls_by_trust_level': self._group_calls_by_trust_level(external_calls),
            'high_risk_calls': [call for call in external_calls if call.risk_score > 0.7],
            'unvalidated_calls': [call for call in external_calls if not call.has_validation]
        }
    
    def _get_contract_trust_level(self, contract_name: str) -> TrustLevel:
        """Get trust level for a specific contract"""
        if contract_name in self.known_trusted_contracts:
            return TrustLevel.TRUSTED
        elif contract_name in ['msg.sender', 'tx.origin']:
            return TrustLevel.UNTRUSTED
        else:
            return TrustLevel.UNKNOWN
    
    def _calculate_call_risk_score(self, call_type: CallType, target_contract: str) -> float:
        """Calculate risk score for an external call"""
        risk_score = 0.0
        
        # Base risk by call type
        if call_type == CallType.DELEGATE_CALL:
            risk_score += 0.8
        elif call_type == CallType.CALL:
            risk_score += 0.6
        elif call_type == CallType.STATIC_CALL:
            risk_score += 0.3
        elif call_type in [CallType.TRANSFER, CallType.SEND]:
            risk_score += 0.4
        
        # Risk by target contract
        if target_contract in ['msg.sender', 'tx.origin']:
            risk_score += 0.3
        elif target_contract in self.known_trusted_contracts:
            risk_score -= 0.2
        
        return max(0.0, min(1.0, risk_score))
    
    def _group_calls_by_type(self, external_calls: List[ExternalCall]) -> Dict[str, int]:
        """Group external calls by type"""
        groups = defaultdict(int)
        for call in external_calls:
            groups[call.call_type.value] += 1
        return dict(groups)
    
    def _group_calls_by_trust_level(self, external_calls: List[ExternalCall]) -> Dict[str, int]:
        """Group external calls by trust level"""
        groups = defaultdict(int)
        for call in external_calls:
            groups[call.trust_level.value] += 1
        return dict(groups)
