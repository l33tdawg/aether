"""
Impact Analyzer - Calculate actual security impact of findings.

This module determines if a finding has real security impact by cross-referencing
the vulnerability description with the function's actual capabilities. Prevents
reporting issues that claim fund loss on read-only functions, etc.
"""

import re
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

from core.function_context_analyzer import FunctionContext, StateImpact, RiskLevel

logger = logging.getLogger(__name__)


class ImpactType(Enum):
    """Types of security impact."""
    FUNDS = "funds"  # Loss or theft of funds
    ACCESS = "access"  # Unauthorized access/privilege escalation
    DOS = "dos"  # Denial of service
    STATE_CORRUPTION = "state_corruption"  # Invalid state
    INFO_LEAK = "info_leak"  # Information disclosure
    GOVERNANCE = "governance"  # Governance manipulation
    NONE = "none"  # No real impact


class FinancialImpactType(Enum):
    """Specific types of financial impact for accurate severity assessment."""
    FUND_DRAIN = "fund_drain"  # Complete or partial fund loss (CRITICAL/HIGH)
    PROFIT_REDUCTION = "profit_reduction"  # MEV/slippage reduces expected profits (MEDIUM)
    UNFAVORABLE_RATE = "unfavorable_rate"  # Bad exchange rate but not complete loss (MEDIUM)
    GAS_WASTE = "gas_waste"  # Failed transactions waste gas (LOW)
    DOS_FINANCIAL = "dos_financial"  # DoS prevents earning (LOW-MEDIUM)
    NONE = "none"  # No financial impact


@dataclass
class ImpactAnalysis:
    """Result of impact analysis."""
    has_impact: bool
    impact_type: ImpactType
    severity_adjustment: int  # -2 to +2
    should_report: bool
    confidence: float
    reasoning: str
    attack_scenario_plausible: bool


class ImpactAnalyzer:
    """Analyzes actual security impact of findings."""
    
    def __init__(self):
        # Keywords indicating different impact types
        self.impact_keywords = {
            ImpactType.FUNDS: [
                'transfer', 'balance', 'token', 'ether', 'eth', 'payment',
                'withdrawal', 'deposit', 'steal', 'drain', 'loss', 'fund',
                'mint', 'burn', 'value', 'amount', 'price', 'asset'
            ],
            ImpactType.ACCESS: [
                'authorization', 'permission', 'role', 'owner', 'admin',
                'access', 'privilege', 'control', 'unauthorized', 'bypass',
                'escalation', 'restricted', 'protected', 'only'
            ],
            ImpactType.DOS: [
                'denial', 'dos', 'block', 'lock', 'stuck', 'freeze',
                'unavailable', 'prevent', 'stop', 'halt', 'gas', 'revert'
            ],
            ImpactType.STATE_CORRUPTION: [
                'state', 'corrupt', 'invalid', 'inconsistent', 'broken',
                'incorrect', 'wrong', 'manipulate', 'overflow', 'underflow'
            ],
            ImpactType.INFO_LEAK: [
                'information', 'leak', 'disclosure', 'reveal', 'expose',
                'private', 'sensitive', 'confidential'
            ],
            ImpactType.GOVERNANCE: [
                'governance', 'vote', 'proposal', 'quorum', 'delegat',
                'timelock', 'upgrade', 'parameter'
            ]
        }
    
    def calculate_impact(self,
                        finding: Dict,
                        function_context: FunctionContext) -> ImpactAnalysis:
        """
        Calculate the actual security impact of a finding.
        
        Args:
            finding: Vulnerability finding dictionary
            function_context: Context of the function where finding was detected
        
        Returns:
            ImpactAnalysis with detailed impact assessment
        """
        
        description = finding.get('description', '').lower()
        vuln_type = finding.get('vulnerability_type', '').lower()
        severity = finding.get('severity', 'medium').lower()
        
        # Detect what the finding claims to affect
        claimed_impacts = self._detect_claimed_impacts(description + ' ' + vuln_type)
        
        # Cross-reference with function capabilities
        actual_impact = self._cross_reference_capabilities(
            claimed_impacts, function_context
        )
        
        # Check if attack scenario is plausible
        attack_scenario_plausible = self._verify_attack_scenario(
            finding, function_context
        )
        
        # Calculate severity adjustment
        severity_adjustment = self._calculate_severity_adjustment(
            actual_impact, claimed_impacts, function_context, severity
        )
        
        # Determine if should report
        should_report = self._should_report_finding(
            actual_impact, function_context, attack_scenario_plausible
        )
        
        # Build reasoning
        reasoning = self._build_reasoning(
            actual_impact, claimed_impacts, function_context, 
            attack_scenario_plausible
        )
        
        # Calculate confidence
        confidence = self._calculate_confidence(
            actual_impact, function_context, attack_scenario_plausible
        )
        
        return ImpactAnalysis(
            has_impact=actual_impact != ImpactType.NONE,
            impact_type=actual_impact,
            severity_adjustment=severity_adjustment,
            should_report=should_report,
            confidence=confidence,
            reasoning=reasoning,
            attack_scenario_plausible=attack_scenario_plausible
        )
    
    def classify_financial_impact(self, vuln: Dict) -> Tuple[FinancialImpactType, float]:
        """
        Classify specific type of financial impact for accurate severity assessment.
        
        Distinguishes between:
        - FUND_DRAIN: Direct loss/theft of user/protocol funds (CRITICAL/HIGH)
        - PROFIT_REDUCTION: MEV/slippage reduces expected profits (MEDIUM)
        - UNFAVORABLE_RATE: Bad exchange rate but not complete loss (MEDIUM)
        - GAS_WASTE: Failed transactions waste gas fees (LOW)
        - DOS_FINANCIAL: DoS prevents earning but no direct loss (LOW-MEDIUM)
        
        Args:
            vuln: Vulnerability dictionary
            
        Returns:
            (FinancialImpactType, severity_multiplier)
        """
        desc = vuln.get('description', '').lower()
        vuln_type = vuln.get('vulnerability_type', '').lower()
        combined_text = desc + ' ' + vuln_type
        
        # Pattern 1: FUND_DRAIN (most severe)
        fund_drain_patterns = [
            r'(?:drain|steal|theft).*(?:fund|token|balance)',
            r'unauthorized.*(?:withdraw|transfer)',
            r'(?:complete|total).*loss',
            r'attacker.*(?:steal|drain|extract).*fund',
            r'(?:victim|user|protocol).*lose.*(?:all|entire|complete)',
        ]
        
        for pattern in fund_drain_patterns:
            if re.search(pattern, combined_text):
                return (FinancialImpactType.FUND_DRAIN, 1.0)  # No adjustment (critical)
        
        # Pattern 2: PROFIT_REDUCTION (medium severity)
        profit_reduction_patterns = [
            r'(?:reduce|decrease|lower).*profit',
            r'(?:unfavorable|bad|poor).*(?:rate|price|swap)',
            r'mev.*(?:extract|profit|steal)',
            r'(?:sandwich|frontrun).*attack',
            r'profit.*(?:loss|reduced)',
            r'accept.*unfavorable',
            r'slippage.*manipulation',
        ]
        
        for pattern in profit_reduction_patterns:
            if re.search(pattern, combined_text):
                return (FinancialImpactType.PROFIT_REDUCTION, 0.6)  # Downgrade to MEDIUM
        
        # Pattern 3: UNFAVORABLE_RATE (medium severity)
        unfavorable_rate_patterns = [
            r'manipulat.*(?:price|rate|exchange)',
            r'(?:incorrect|wrong).*(?:price|valuation)',
            r'price.*(?:manipulation|distortion)',
            r'exchange.*rate.*(?:manipulation|exploit)',
        ]
        
        for pattern in unfavorable_rate_patterns:
            if re.search(pattern, combined_text):
                # Check if it's actual drain or just rate issue
                if not re.search(r'(?:complete|total|all).*loss', combined_text):
                    return (FinancialImpactType.UNFAVORABLE_RATE, 0.65)  # MEDIUM
        
        # Pattern 4: GAS_WASTE (low severity)
        gas_waste_patterns = [
            r'(?:wast|spend).*gas',
            r'failed.*(?:liquidation|arbitrage|transaction)',
            r'gas.*fee.*(?:loss|wasted)',
            r'revert.*(?:cost|expense)',
        ]
        
        for pattern in gas_waste_patterns:
            if re.search(pattern, combined_text):
                # Check if there's actual fund loss beyond gas
                if not re.search(r'(?:fund|token|balance).*(?:loss|stolen)', combined_text):
                    return (FinancialImpactType.GAS_WASTE, 0.3)  # LOW
        
        # Pattern 5: DOS_FINANCIAL (low-medium severity)
        dos_financial_patterns = [
            r'dos.*(?:prevent|block).*(?:earn|profit|liquidat)',
            r'(?:lock|freeze|stuck).*fund',
            r'unavailable.*(?:withdraw|claim)',
        ]
        
        for pattern in dos_financial_patterns:
            if re.search(pattern, combined_text):
                return (FinancialImpactType.DOS_FINANCIAL, 0.4)  # LOW-MEDIUM
        
        # Default: check if there's any financial impact mentioned
        if 'fund' in combined_text or 'loss' in combined_text or 'token' in combined_text:
            return (FinancialImpactType.FUND_DRAIN, 0.8)  # Conservative assumption
        
        return (FinancialImpactType.NONE, 0.0)
    
    def _detect_claimed_impacts(self, text: str) -> List[ImpactType]:
        """Detect what impacts the finding claims to have."""
        claimed = []
        
        for impact_type, keywords in self.impact_keywords.items():
            if any(keyword in text for keyword in keywords):
                claimed.append(impact_type)
        
        if not claimed:
            claimed.append(ImpactType.NONE)
        
        return claimed
    
    def _cross_reference_capabilities(self,
                                     claimed_impacts: List[ImpactType],
                                     context: FunctionContext) -> ImpactType:
        """
        Cross-reference claimed impacts with actual function capabilities.
        
        Returns the highest-priority actual impact.
        """
        
        # Read-only functions can't affect funds or state directly
        if context.state_impact == StateImpact.READ_ONLY:
            # Can only have info leak impact
            if ImpactType.INFO_LEAK in claimed_impacts:
                return ImpactType.INFO_LEAK
            # Claims of fund/state impact are false
            if any(imp in claimed_impacts for imp in [ImpactType.FUNDS, ImpactType.STATE_CORRUPTION]):
                return ImpactType.NONE  # Mismatch = no real impact
            return ImpactType.INFO_LEAK  # Default for view functions
        
        # Functions that transfer tokens/eth have fund impact
        if context.has_token_transfer or context.modifies_balance:
            if ImpactType.FUNDS in claimed_impacts:
                return ImpactType.FUNDS
        
        # Functions with external calls could have various impacts
        if context.has_external_call:
            # Prioritize fund impact if claimed
            if ImpactType.FUNDS in claimed_impacts and context.modifies_balance:
                return ImpactType.FUNDS
            if ImpactType.ACCESS in claimed_impacts:
                return ImpactType.ACCESS
            if ImpactType.DOS in claimed_impacts:
                return ImpactType.DOS
        
        # Delegatecall is always critical
        if context.has_delegatecall:
            if ImpactType.FUNDS in claimed_impacts or ImpactType.ACCESS in claimed_impacts:
                return ImpactType.FUNDS  # Delegatecall can do anything
        
        # State-changing functions
        if context.state_impact == StateImpact.STATE_CHANGING:
            if ImpactType.STATE_CORRUPTION in claimed_impacts:
                return ImpactType.STATE_CORRUPTION
            if ImpactType.DOS in claimed_impacts:
                return ImpactType.DOS
            # Could be governance impact
            if ImpactType.GOVERNANCE in claimed_impacts:
                return ImpactType.GOVERNANCE
        
        # Default to first claimed impact if plausible
        if claimed_impacts and claimed_impacts[0] != ImpactType.NONE:
            return claimed_impacts[0]
        
        return ImpactType.NONE
    
    def _verify_attack_scenario(self,
                                finding: Dict,
                                context: FunctionContext) -> bool:
        """
        Verify if the attack scenario described is plausible.
        
        A good attack scenario should:
        1. Have clear steps
        2. Lead to the claimed impact
        3. Be executable given function capabilities
        """
        
        attack_scenario = finding.get('attack_scenario', '')
        if not attack_scenario:
            return False
        
        # Check if scenario has multiple steps
        has_steps = bool(re.search(r'(1\.|2\.|step|first|then|finally)', 
                                  attack_scenario.lower()))
        
        # Check if scenario describes an outcome
        has_outcome = any(word in attack_scenario.lower() 
                         for word in ['result', 'lead', 'cause', 'impact', 'loss'])
        
        # Check if scenario is long enough to be detailed
        is_detailed = len(attack_scenario) > 100
        
        # Check if scenario matches function capabilities
        matches_capabilities = True
        if context.state_impact == StateImpact.READ_ONLY:
            # Scenario shouldn't claim state changes
            if any(word in attack_scenario.lower() 
                   for word in ['modify', 'change', 'update', 'steal', 'drain']):
                matches_capabilities = False
        
        return has_steps and has_outcome and is_detailed and matches_capabilities
    
    def _calculate_severity_adjustment(self,
                                      actual_impact: ImpactType,
                                      claimed_impacts: List[ImpactType],
                                      context: FunctionContext,
                                      original_severity: str) -> int:
        """
        Calculate how much to adjust severity (-2 to +2).
        
        Returns:
            Negative = downgrade, Positive = upgrade, 0 = no change
        """
        
        # Mismatch between claimed and actual impact
        if actual_impact == ImpactType.NONE and claimed_impacts != [ImpactType.NONE]:
            return -2  # Major downgrade
        
        # Fund impact on critical function - upgrade
        if actual_impact == ImpactType.FUNDS and context.risk_level == RiskLevel.HIGH:
            if original_severity == 'medium':
                return +1
            elif original_severity == 'low':
                return +2
        
        # Info leak claims as high severity - downgrade
        if actual_impact == ImpactType.INFO_LEAK and original_severity == 'high':
            return -1
        
        # Read-only function with high severity claim - downgrade
        if context.state_impact == StateImpact.READ_ONLY and original_severity == 'high':
            return -2
        
        # Access control on critical functions - upgrade
        if actual_impact == ImpactType.ACCESS and context.state_impact == StateImpact.CRITICAL:
            if original_severity == 'low':
                return +2
            elif original_severity == 'medium':
                return +1
        
        return 0
    
    def _should_report_finding(self,
                              actual_impact: ImpactType,
                              context: FunctionContext,
                              attack_scenario_plausible: bool) -> bool:
        """Determine if finding should be reported."""
        
        # No actual impact = don't report
        if actual_impact == ImpactType.NONE:
            return False
        
        # Info leaks on read-only functions - only report if high risk
        if actual_impact == ImpactType.INFO_LEAK:
            if context.risk_level in [RiskLevel.LOW, RiskLevel.MEDIUM]:
                return False
        
        # No plausible attack scenario for critical findings - don't report
        if actual_impact in [ImpactType.FUNDS, ImpactType.ACCESS]:
            if not attack_scenario_plausible:
                return False
        
        # Report all other cases
        return True
    
    def _build_reasoning(self,
                        actual_impact: ImpactType,
                        claimed_impacts: List[ImpactType],
                        context: FunctionContext,
                        attack_plausible: bool) -> str:
        """Build human-readable reasoning."""
        
        parts = []
        
        # Function context
        parts.append(f"Function is {context.state_impact.value}")
        parts.append(f"risk level: {context.risk_level.value}")
        
        # Claimed vs actual
        claimed_str = ', '.join(imp.value for imp in claimed_impacts)
        parts.append(f"Finding claims: {claimed_str}")
        parts.append(f"Actual impact: {actual_impact.value}")
        
        # Capabilities
        capabilities = []
        if context.has_token_transfer:
            capabilities.append("transfers tokens")
        if context.has_external_call:
            capabilities.append("external calls")
        if context.has_storage_write:
            capabilities.append("writes storage")
        if context.is_view:
            capabilities.append("view-only")
        
        if capabilities:
            parts.append(f"Function capabilities: {', '.join(capabilities)}")
        
        # Attack scenario
        if attack_plausible:
            parts.append("Attack scenario is plausible")
        else:
            parts.append("Attack scenario missing or implausible")
        
        return "; ".join(parts)
    
    def _calculate_confidence(self,
                             actual_impact: ImpactType,
                             context: FunctionContext,
                             attack_plausible: bool) -> float:
        """Calculate confidence in the impact analysis."""
        
        confidence = 0.7  # Base
        
        # High confidence for clear mismatches
        if actual_impact == ImpactType.NONE:
            confidence = 0.95
        
        # High confidence for clear matches
        if actual_impact == ImpactType.FUNDS and context.has_token_transfer:
            confidence = 0.95
        
        # Lower confidence if attack not plausible
        if not attack_plausible:
            confidence -= 0.2
        
        # Higher confidence for view functions
        if context.is_view:
            confidence += 0.1
        
        return min(1.0, max(0.0, confidence))
    
    def get_severity_from_impact(self, impact_type: ImpactType, risk_level: RiskLevel) -> str:
        """Map impact type and risk level to severity."""
        
        severity_matrix = {
            ImpactType.FUNDS: {
                RiskLevel.CRITICAL: 'critical',
                RiskLevel.HIGH: 'high',
                RiskLevel.MEDIUM: 'medium',
                RiskLevel.LOW: 'low'
            },
            ImpactType.ACCESS: {
                RiskLevel.CRITICAL: 'critical',
                RiskLevel.HIGH: 'high',
                RiskLevel.MEDIUM: 'medium',
                RiskLevel.LOW: 'low'
            },
            ImpactType.DOS: {
                RiskLevel.CRITICAL: 'high',
                RiskLevel.HIGH: 'medium',
                RiskLevel.MEDIUM: 'medium',
                RiskLevel.LOW: 'low'
            },
            ImpactType.STATE_CORRUPTION: {
                RiskLevel.CRITICAL: 'high',
                RiskLevel.HIGH: 'high',
                RiskLevel.MEDIUM: 'medium',
                RiskLevel.LOW: 'low'
            },
            ImpactType.INFO_LEAK: {
                RiskLevel.CRITICAL: 'medium',
                RiskLevel.HIGH: 'low',
                RiskLevel.MEDIUM: 'low',
                RiskLevel.LOW: 'info'
            },
            ImpactType.GOVERNANCE: {
                RiskLevel.CRITICAL: 'high',
                RiskLevel.HIGH: 'medium',
                RiskLevel.MEDIUM: 'medium',
                RiskLevel.LOW: 'low'
            },
            ImpactType.NONE: {
                RiskLevel.CRITICAL: 'info',
                RiskLevel.HIGH: 'info',
                RiskLevel.MEDIUM: 'info',
                RiskLevel.LOW: 'info'
            }
        }
        
        return severity_matrix.get(impact_type, {}).get(risk_level, 'medium')


if __name__ == "__main__":
    # Example usage
    from core.function_context_analyzer import FunctionContextAnalyzer
    
    analyzer = FunctionContextAnalyzer()
    impact_analyzer = ImpactAnalyzer()
    
    # Test case: Parameter validation on getter
    getter_code = """
    function getCollateralMintFees(address collateral)
        external
        view
        returns (uint64[] memory xFeeMint, int64[] memory yFeeMint)
    {
        return (collatInfo.xFeeMint, collatInfo.yFeeMint);
    }
    """
    
    context = analyzer.analyze_function(getter_code, "getCollateralMintFees")
    
    finding = {
        'vulnerability_type': 'parameter_validation_issue',
        'severity': 'high',
        'description': 'Function does not validate collateral address, could lead to incorrect data',
        'attack_scenario': ''
    }
    
    impact = impact_analyzer.calculate_impact(finding, context)
    print(f"Impact Analysis:")
    print(f"  Has Impact: {impact.has_impact}")
    print(f"  Impact Type: {impact.impact_type.value}")
    print(f"  Should Report: {impact.should_report}")
    print(f"  Severity Adjustment: {impact.severity_adjustment}")
    print(f"  Reasoning: {impact.reasoning}")

