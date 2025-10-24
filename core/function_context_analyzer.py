"""
Function Context Analyzer - Protocol-agnostic function classification.

This module analyzes functions to determine their context (getter, setter, action),
state impact (read-only, state-changing, critical), and risk level. This enables
better severity calibration and false positive filtering without protocol-specific rules.
"""

import re
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class StateImpact(Enum):
    """Level of state impact a function has."""
    READ_ONLY = "read-only"
    STATE_CHANGING = "state-changing"
    CRITICAL = "critical"


class DataFlow(Enum):
    """Type of data flow in the function."""
    GETTER = "getter"
    SETTER = "setter"
    ACTION = "action"
    VIEW = "view"
    UNKNOWN = "unknown"


class RiskLevel(Enum):
    """Risk level of the function."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class FunctionContext:
    """Context information about a function."""
    state_impact: StateImpact
    data_flow: DataFlow
    risk_level: RiskLevel
    is_view: bool
    is_pure: bool
    is_payable: bool
    is_external: bool
    is_public: bool
    has_storage_write: bool
    has_external_call: bool
    has_token_transfer: bool
    has_delegatecall: bool
    has_selfdestruct: bool
    modifies_balance: bool
    confidence: float
    reasoning: str


class FunctionContextAnalyzer:
    """Analyzes function context to determine risk and appropriate validation rules."""
    
    def __init__(self):
        # Common getter prefixes across protocols
        self.getter_prefixes = (
            'get', 'is', 'has', 'can', 'total', 'balance', 
            'query', 'fetch', 'read', 'check', 'view', 'show'
        )
        
        # Common setter prefixes across protocols
        self.setter_prefixes = (
            'set', 'update', 'configure', 'initialize', 'init',
            'change', 'modify', 'adjust', 'toggle', 'enable', 'disable'
        )
        
        # Common action verbs in DeFi
        self.action_verbs = (
            'swap', 'mint', 'burn', 'deposit', 'withdraw', 'transfer',
            'approve', 'redeem', 'claim', 'stake', 'unstake', 'borrow',
            'repay', 'liquidate', 'execute', 'process', 'submit', 'add',
            'remove', 'create', 'destroy', 'lock', 'unlock'
        )
    
    def analyze_function(self, 
                        function_code: str, 
                        function_name: str,
                        contract_code: Optional[str] = None) -> FunctionContext:
        """
        Analyze a function to determine its context.
        
        Args:
            function_code: The function's source code
            function_name: Name of the function
            contract_code: Full contract code for additional context (optional)
        
        Returns:
            FunctionContext with all analyzed properties
        """
        
        # 1. Extract visibility and mutability
        is_view = bool(re.search(r'\bview\b', function_code))
        is_pure = bool(re.search(r'\bpure\b', function_code))
        is_payable = bool(re.search(r'\bpayable\b', function_code))
        is_external = bool(re.search(r'\bexternal\b', function_code))
        is_public = bool(re.search(r'\bpublic\b', function_code))
        
        # 2. Detect state mutations (generic patterns)
        has_storage_write = self._detect_storage_writes(function_code)
        has_external_call = self._detect_external_calls(function_code)
        has_token_transfer = self._detect_token_transfers(function_code)
        has_delegatecall = self._detect_delegatecall(function_code)
        has_selfdestruct = self._detect_selfdestruct(function_code)
        modifies_balance = self._detect_balance_modification(function_code)
        
        # 3. Determine data flow from function name
        data_flow = self._classify_data_flow(function_name)
        
        # 4. Calculate state impact
        state_impact = self._calculate_state_impact(
            is_view, is_pure, has_storage_write, has_external_call,
            has_token_transfer, has_delegatecall, has_selfdestruct
        )
        
        # 5. Determine risk level
        risk_level, reasoning = self._calculate_risk_level(
            state_impact, is_payable, has_external_call, 
            has_token_transfer, has_delegatecall, has_selfdestruct,
            modifies_balance, data_flow
        )
        
        # 6. Calculate confidence
        confidence = self._calculate_confidence(
            is_view, is_pure, data_flow, function_name
        )
        
        return FunctionContext(
            state_impact=state_impact,
            data_flow=data_flow,
            risk_level=risk_level,
            is_view=is_view,
            is_pure=is_pure,
            is_payable=is_payable,
            is_external=is_external,
            is_public=is_public,
            has_storage_write=has_storage_write,
            has_external_call=has_external_call,
            has_token_transfer=has_token_transfer,
            has_delegatecall=has_delegatecall,
            has_selfdestruct=has_selfdestruct,
            modifies_balance=modifies_balance,
            confidence=confidence,
            reasoning=reasoning
        )
    
    def _detect_storage_writes(self, code: str) -> bool:
        """Detect if function writes to storage."""
        patterns = [
            r'\w+\s*=\s*[^=]',  # Assignment (not ==)
            r'\.push\s*\(',      # Array push
            r'\.pop\s*\(',       # Array pop
            r'delete\s+\w+',     # Delete statement
            r'\+\+',             # Increment
            r'--',               # Decrement
        ]
        
        for pattern in patterns:
            if re.search(pattern, code):
                return True
        return False
    
    def _detect_external_calls(self, code: str) -> bool:
        """Detect external contract calls."""
        patterns = [
            r'\.\s*call\s*[\(\{]',
            r'\.delegatecall\s*\(',
            r'\.staticcall\s*\(',
            r'\.\w+\s*\(',  # General external call pattern
        ]
        
        # Exclude common internal calls
        exclude = [
            r'require\(',
            r'revert\(',
            r'assert\(',
            r'keccak256\(',
            r'ecrecover\(',
        ]
        
        for pattern in patterns:
            if re.search(pattern, code):
                # Check it's not an excluded pattern
                for excl in exclude:
                    if re.search(excl, code):
                        continue
                return True
        return False
    
    def _detect_token_transfers(self, code: str) -> bool:
        """Detect token transfer operations."""
        patterns = [
            r'\btransfer\s*\(',
            r'\btransferFrom\s*\(',
            r'\bsafeTransfer\s*\(',
            r'\bsafeTransferFrom\s*\(',
            r'\bmint\s*\(',
            r'\bburn\s*\(',
            r'\bsend\s*\(',
        ]
        
        return any(re.search(pattern, code) for pattern in patterns)
    
    def _detect_delegatecall(self, code: str) -> bool:
        """Detect delegatecall usage."""
        return bool(re.search(r'\bdelegatecall\s*\(', code))
    
    def _detect_selfdestruct(self, code: str) -> bool:
        """Detect selfdestruct usage."""
        return bool(re.search(r'\bselfdestruct\s*\(', code))
    
    def _detect_balance_modification(self, code: str) -> bool:
        """Detect balance modifications."""
        patterns = [
            r'balance\s*[+\-]=',
            r'balance\s*=\s*[^=]',
            r'msg\.value',
            r'\.transfer\s*\(',
            r'\.send\s*\(',
        ]
        
        return any(re.search(pattern, code, re.IGNORECASE) for pattern in patterns)
    
    def _classify_data_flow(self, function_name: str) -> DataFlow:
        """Classify function based on naming patterns."""
        func_lower = function_name.lower()
        
        if func_lower.startswith(self.getter_prefixes):
            return DataFlow.GETTER
        elif func_lower.startswith(self.setter_prefixes):
            return DataFlow.SETTER
        elif any(verb in func_lower for verb in self.action_verbs):
            return DataFlow.ACTION
        else:
            return DataFlow.UNKNOWN
    
    def _calculate_state_impact(self,
                               is_view: bool,
                               is_pure: bool,
                               has_storage_write: bool,
                               has_external_call: bool,
                               has_token_transfer: bool,
                               has_delegatecall: bool,
                               has_selfdestruct: bool) -> StateImpact:
        """Calculate the state impact level."""
        
        # Pure/view functions with no external calls are read-only
        if (is_view or is_pure) and not has_external_call:
            return StateImpact.READ_ONLY
        
        # Critical operations
        if any([has_token_transfer, has_delegatecall, has_selfdestruct]):
            return StateImpact.CRITICAL
        
        # External calls are critical (potential reentrancy, etc.)
        if has_external_call:
            return StateImpact.CRITICAL
        
        # Storage writes are state-changing
        if has_storage_write:
            return StateImpact.STATE_CHANGING
        
        # Default to read-only
        return StateImpact.READ_ONLY
    
    def _calculate_risk_level(self,
                             state_impact: StateImpact,
                             is_payable: bool,
                             has_external_call: bool,
                             has_token_transfer: bool,
                             has_delegatecall: bool,
                             has_selfdestruct: bool,
                             modifies_balance: bool,
                             data_flow: DataFlow) -> Tuple[RiskLevel, str]:
        """Calculate risk level with reasoning."""
        
        reasons = []
        
        # Critical risk factors
        if has_selfdestruct:
            reasons.append("uses selfdestruct")
            return RiskLevel.CRITICAL, "; ".join(reasons)
        
        if has_delegatecall:
            reasons.append("uses delegatecall")
            return RiskLevel.CRITICAL, "; ".join(reasons)
        
        # High risk factors
        if has_token_transfer:
            reasons.append("transfers tokens")
        
        if is_payable:
            reasons.append("accepts ether")
        
        if modifies_balance:
            reasons.append("modifies balances")
        
        if has_external_call:
            reasons.append("makes external calls")
        
        if reasons:
            return RiskLevel.HIGH, "; ".join(reasons)
        
        # Medium risk - state changes
        if state_impact == StateImpact.STATE_CHANGING:
            reasons.append("modifies state")
            return RiskLevel.MEDIUM, "; ".join(reasons)
        
        # Low risk - read-only
        if state_impact == StateImpact.READ_ONLY:
            reasons.append("read-only function")
            return RiskLevel.LOW, "; ".join(reasons)
        
        return RiskLevel.MEDIUM, "default risk assessment"
    
    def _calculate_confidence(self,
                             is_view: bool,
                             is_pure: bool,
                             data_flow: DataFlow,
                             function_name: str) -> float:
        """Calculate confidence in the analysis."""
        
        confidence = 0.7  # Base confidence
        
        # High confidence for view/pure
        if is_view or is_pure:
            confidence += 0.2
        
        # Higher confidence if name matches pattern
        if data_flow != DataFlow.UNKNOWN:
            confidence += 0.1
        
        # Slightly lower confidence for edge cases
        if not function_name.strip():
            confidence -= 0.2
        
        return min(1.0, max(0.0, confidence))
    
    def should_validate_parameters(self, context: FunctionContext) -> bool:
        """
        Determine if parameter validation is critical for this function.
        
        Getters don't need strict validation (returning empty data is ok).
        State-changing functions need strict validation.
        """
        
        # Read-only getters don't need strict validation
        if context.state_impact == StateImpact.READ_ONLY and context.data_flow == DataFlow.GETTER:
            return False
        
        # Critical/state-changing functions need validation
        if context.state_impact in [StateImpact.CRITICAL, StateImpact.STATE_CHANGING]:
            return True
        
        # Actions need validation
        if context.data_flow in [DataFlow.ACTION, DataFlow.SETTER]:
            return True
        
        return False
    
    def adjust_finding_severity(self, 
                               finding_type: str,
                               original_severity: str,
                               context: FunctionContext) -> Tuple[str, Optional[str]]:
        """
        Adjust finding severity based on function context.
        
        Returns:
            (adjusted_severity, reason_for_adjustment or None)
        """
        
        # Parameter validation issues in read-only getters are low severity
        if 'parameter_validation' in finding_type.lower():
            if context.state_impact == StateImpact.READ_ONLY:
                if original_severity in ['high', 'critical']:
                    return ('low', 'Read-only function - returning default values is acceptable behavior')
            elif context.state_impact == StateImpact.CRITICAL:
                if original_severity == 'low':
                    return ('high', 'Critical function - parameter validation is essential')
        
        # Reentrancy only matters for state-changing functions
        if 'reentrancy' in finding_type.lower():
            if context.state_impact == StateImpact.READ_ONLY:
                return ('info', 'Read-only function - reentrancy has no exploitable impact')
            elif not context.has_external_call:
                return ('low', 'No external calls detected - reentrancy risk is theoretical')
        
        # Access control is critical for state-changing functions
        if 'access' in finding_type.lower() and 'control' in finding_type.lower():
            if context.state_impact == StateImpact.CRITICAL:
                if original_severity in ['low', 'medium']:
                    return ('high', 'Critical function without access control')
            elif context.state_impact == StateImpact.READ_ONLY:
                if original_severity == 'high':
                    return ('low', 'Read-only function - access control less critical')
        
        # No adjustment needed
        return (original_severity, None)
    
    def is_false_positive(self,
                         finding_type: str,
                         finding_description: str,
                         context: FunctionContext) -> Tuple[bool, str]:
        """
        Determine if a finding is a false positive based on context.
        
        Returns:
            (is_false_positive, reason)
        """
        
        # Claims about state/fund impact on read-only functions
        if context.state_impact == StateImpact.READ_ONLY:
            state_impact_keywords = [
                'transfer', 'balance', 'token', 'ether', 'payment',
                'withdrawal', 'deposit', 'steal', 'drain', 'loss'
            ]
            if any(kw in finding_description.lower() for kw in state_impact_keywords):
                return (True, f"Finding claims fund/state impact but function is {context.state_impact.value}")
        
        # Reentrancy claims on functions without external calls
        if 'reentrancy' in finding_type.lower():
            if not context.has_external_call:
                return (True, "Reentrancy finding but function makes no external calls")
            if context.is_view or context.is_pure:
                return (True, "Reentrancy finding on view/pure function (no state impact)")
        
        # Access control on internal/private functions (would be in function_code check)
        
        return (False, "")


if __name__ == "__main__":
    # Example usage
    analyzer = FunctionContextAnalyzer()
    
    # Test case 1: Getter function
    getter_code = """
    function getCollateralMintFees(address collateral)
        external
        view
        returns (uint64[] memory xFeeMint, int64[] memory yFeeMint)
    {
        Collateral storage collatInfo = s.transmuterStorage().collaterals[collateral];
        return (collatInfo.xFeeMint, collatInfo.yFeeMint);
    }
    """
    
    context = analyzer.analyze_function(getter_code, "getCollateralMintFees")
    print(f"Getter Context: {context.data_flow.value}, Impact: {context.state_impact.value}, Risk: {context.risk_level.value}")
    print(f"Should validate params: {analyzer.should_validate_parameters(context)}")
    print()
    
    # Test case 2: Transfer function
    transfer_code = """
    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }
    """
    
    context = analyzer.analyze_function(transfer_code, "transfer")
    print(f"Transfer Context: {context.data_flow.value}, Impact: {context.state_impact.value}, Risk: {context.risk_level.value}")
    print(f"Should validate params: {analyzer.should_validate_parameters(context)}")
    print(f"Reasoning: {context.reasoning}")

