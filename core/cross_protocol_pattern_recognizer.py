#!/usr/bin/env python3
"""
Cross-Protocol Pattern Recognizer

Enhanced DeFi protocol-specific pattern recognition for comprehensive auditing.
Extends the basic DeFi pattern recognizer with detailed protocol implementations.

Supports: Uniswap V3, Aave V3, Compound V3, MakerDAO, Curve, Balancer, etc.
"""

import re
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from decimal import Decimal


class ProtocolType(Enum):
    """Supported DeFi protocols."""
    UNISWAP_V3 = "uniswap_v3"
    AAVE_V3 = "aave_v3"
    COMPOUND_V3 = "compound_v3"
    MAKERDAO = "makerdao"
    CURVE = "curve"
    BALANCER = "balancer"
    YEARN = "yearn"
    CONVEX = "convex"
    SUSHISWAP = "sushiswap"
    PANCAKESWAP = "pancakeswap"
    GENERIC_AMM = "generic_amm"
    GENERIC_LENDING = "generic_lending"


class PatternCategory(Enum):
    """Categories of protocol patterns."""
    LIQUIDITY_MANAGEMENT = "liquidity_management"
    PRICE_ORACLE = "price_oracle"
    INTEREST_RATE = "interest_rate"
    LIQUIDATION = "liquidation"
    FLASH_LOAN = "flash_loan"
    STAKING = "staking"
    VOTING = "voting"
    VAULT_MANAGEMENT = "vault_management"


@dataclass
class ProtocolPattern:
    """A protocol-specific pattern with detailed characteristics."""
    protocol: ProtocolType
    category: PatternCategory
    pattern_name: str
    confidence: float
    description: str

    # Pattern detection
    code_patterns: List[str]  # Regex patterns to match
    function_signatures: List[str]  # Expected function signatures
    variable_patterns: Dict[str, str]  # Variable name patterns

    # Security implications
    security_notes: List[str]
    common_vulnerabilities: List[str]
    false_positive_indicators: List[str]

    # Validation rules
    invariant_checks: List[str]  # Things that should always be true
    risk_patterns: Dict[str, str]  # Pattern -> Risk level


@dataclass
class ProtocolDetection:
    """Result of protocol pattern detection."""
    protocol: ProtocolType
    confidence: float
    detected_patterns: List[str]
    security_implications: List[str]
    recommended_checks: List[str]


class CrossProtocolPatternRecognizer:
    """
    Advanced cross-protocol pattern recognition for DeFi auditing.

    Provides detailed, protocol-specific analysis to:
    - Reduce false positives by understanding expected behavior
    - Identify protocol-specific vulnerabilities
    - Provide context-aware severity adjustments
    - Suggest protocol-appropriate validation checks
    """

    def __init__(self):
        self.protocol_patterns = self._initialize_protocol_patterns()
        self.detected_protocols: List[ProtocolDetection] = []

    def _initialize_protocol_patterns(self) -> Dict[ProtocolType, List[ProtocolPattern]]:
        """Initialize comprehensive protocol pattern library."""
        return {
            ProtocolType.UNISWAP_V3: self._get_uniswap_v3_patterns(),
            ProtocolType.AAVE_V3: self._get_aave_v3_patterns(),
            ProtocolType.COMPOUND_V3: self._get_compound_v3_patterns(),
            ProtocolType.MAKERDAO: self._get_makerdao_patterns(),
            ProtocolType.CURVE: self._get_curve_patterns(),
            ProtocolType.GENERIC_AMM: self._get_generic_amm_patterns(),
            ProtocolType.GENERIC_LENDING: self._get_generic_lending_patterns(),
        }

    def analyze_contract(self, contract_code: str) -> List[ProtocolDetection]:
        """
        Analyze contract for protocol-specific patterns.

        Returns list of detected protocols with confidence scores and implications.
        """
        self.detected_protocols = []

        for protocol, patterns in self.protocol_patterns.items():
            detection = self._analyze_protocol(contract_code, protocol, patterns)
            if detection.confidence > 0.2:  # Only include reasonably confident detections
                self.detected_protocols.append(detection)

        # Sort by confidence
        self.detected_protocols.sort(key=lambda x: x.confidence, reverse=True)

        return self.detected_protocols

    def _analyze_protocol(self, contract_code: str, protocol: ProtocolType,
                         patterns: List[ProtocolPattern]) -> ProtocolDetection:
        """Analyze contract for a specific protocol's patterns."""

        detected_patterns = []
        total_confidence = 0.0
        security_implications = []
        recommended_checks = []

        for pattern in patterns:
            confidence = self._match_pattern(contract_code, pattern)
            if confidence > 0.3:  # Pattern detected (more lenient)
                detected_patterns.append(pattern.pattern_name)
                total_confidence += confidence
                security_implications.extend(pattern.security_notes)
                recommended_checks.extend(pattern.invariant_checks)

        # Calculate overall protocol confidence
        if detected_patterns:
            avg_confidence = total_confidence / len(detected_patterns)
            # Boost confidence if multiple patterns detected
            protocol_confidence = min(avg_confidence * (1 + len(detected_patterns) * 0.1), 0.95)
        else:
            protocol_confidence = 0.0

        return ProtocolDetection(
            protocol=protocol,
            confidence=protocol_confidence,
            detected_patterns=detected_patterns,
            security_implications=list(set(security_implications)),
            recommended_checks=list(set(recommended_checks))
        )

    def _match_pattern(self, contract_code: str, pattern: ProtocolPattern) -> float:
        """Match a specific pattern against contract code."""

        confidence = 0.0
        matches_found = 0

        # Check code patterns (regex)
        for regex_pattern in pattern.code_patterns:
            if re.search(regex_pattern, contract_code, re.IGNORECASE | re.MULTILINE):
                confidence += 0.3
                matches_found += 1

        # Check function signatures (look for function names)
        for func_sig in pattern.function_signatures:
            func_name = func_sig.split('(')[0]
            # Look for function declaration with this name
            func_pattern = rf'\bfunction\s+{re.escape(func_name)}\s*\('
            if re.search(func_pattern, contract_code, re.IGNORECASE | re.MULTILINE):
                confidence += 0.4
                matches_found += 1

        # Check variable patterns
        for var_pattern, expected_type in pattern.variable_patterns.items():
            # Look for variable declarations (type can come before or after name)
            var_regex1 = rf'\b{re.escape(expected_type)}\b.*?\b{re.escape(var_pattern)}\b'
            var_regex2 = rf'\b{re.escape(var_pattern)}\b.*?\b{re.escape(expected_type)}\b'
            if re.search(var_regex1, contract_code, re.IGNORECASE) or re.search(var_regex2, contract_code, re.IGNORECASE):
                confidence += 0.3
                matches_found += 1

        # Normalize confidence based on matches found
        if matches_found > 0:
            confidence = min(confidence / matches_found, 1.0)
        else:
            confidence = 0.0

        return confidence

    def should_adjust_severity(self, vulnerability_type: str, protocol: ProtocolType) -> Tuple[bool, str, float]:
        """
        Check if vulnerability severity should be adjusted for a specific protocol.

        Returns: (should_adjust, reason, confidence_multiplier)
        """
        adjustments = {
            ProtocolType.UNISWAP_V3: {
                'oracle_manipulation': (True, 'Uniswap V3 uses TWAP oracles - manipulation harder', 0.7),
                'flash_loan_attack': (True, 'Flash loans are core to Uniswap V3 design', 0.3),
                'reentrancy': (False, 'Standard reentrancy concerns apply', 1.0),
            },
            ProtocolType.AAVE_V3: {
                'liquidation_arbitrage': (True, 'Liquidations are expected protocol behavior', 0.5),
                'health_factor_manipulation': (True, 'Health factor manipulation is critical', 1.2),
                'flash_loan_attack': (True, 'Aave flash loans are designed to be safe', 0.6),
            },
            ProtocolType.COMPOUND_V3: {
                'interest_arbitrage': (True, 'Interest rate arbitrage is expected', 0.4),
                'oracle_failure': (True, 'Compound relies heavily on price oracles', 1.1),
                'liquidation': (True, 'Liquidations are core protocol mechanism', 0.5),
            },
            ProtocolType.MAKERDAO: {
                'governance_attack': (True, 'MakerDAO has complex governance', 1.0),
                'vault_liquidation': (True, 'CDP liquidations are expected', 0.6),
                'oracle_attack': (True, 'MakerDAO uses multiple oracles', 1.1),
            }
        }

        protocol_adjustments = adjustments.get(protocol, {})
        if vulnerability_type in protocol_adjustments:
            should_adjust, reason, multiplier = protocol_adjustments[vulnerability_type]
            return should_adjust, reason, multiplier

        return False, "", 1.0

    def get_protocol_specific_checks(self, protocol: ProtocolType) -> List[str]:
        """Get protocol-specific security checks that should be performed."""
        checks = {
            ProtocolType.UNISWAP_V3: [
                "Check tick spacing and fee tier calculations",
                "Verify TWAP oracle manipulation resistance",
                "Validate concentrated liquidity math",
                "Check flash swap callback security",
                "Verify position NFT minting/burning logic"
            ],
            ProtocolType.AAVE_V3: [
                "Verify health factor calculations",
                "Check liquidation bonus parameters",
                "Validate interest rate model",
                "Verify flash loan fee calculations",
                "Check reserve factor updates"
            ],
            ProtocolType.COMPOUND_V3: [
                "Verify utilization rate calculations",
                "Check interest rate model parameters",
                "Validate exchange rate calculations",
                "Verify liquidation incentive math",
                "Check comptroller permission checks"
            ],
            ProtocolType.MAKERDAO: [
                "Verify vault stability fee calculations",
                "Check liquidation ratio parameters",
                "Validate oracle price feeds",
                "Verify governance proposal execution",
                "Check emergency shutdown procedures"
            ]
        }

        return checks.get(protocol, [])

    # Protocol-specific pattern definitions

    def _get_uniswap_v3_patterns(self) -> List[ProtocolPattern]:
        """Uniswap V3 specific patterns."""
        return [
            ProtocolPattern(
                protocol=ProtocolType.UNISWAP_V3,
                category=PatternCategory.LIQUIDITY_MANAGEMENT,
                pattern_name="concentrated_liquidity",
                confidence=0.8,
                description="Uniswap V3 concentrated liquidity positions",
                code_patterns=[
                    r'tickLower|tickUpper',
                    r'sqrtPriceX96',
                    r'liquidityDelta',
                    r'mint.*position',
                    r'burn.*position'
                ],
                function_signatures=[
                    'mint(address,int24,int24,uint128)',
                    'burn(int24,int24,uint128)',
                    'collect(address,int24,int24)',
                    'swap(address,bool,int256,uint160)'
                ],
                variable_patterns={
                    'tickSpacing': 'int24',
                    'fee': 'uint24',
                    'sqrtPriceX96': 'uint160'
                },
                security_notes=[
                    "Tick math must prevent overflow/underflow",
                    "Liquidity calculations are complex and error-prone",
                    "Position NFT ownership must be validated"
                ],
                common_vulnerabilities=[
                    "Tick manipulation attacks",
                    "Liquidity calculation errors",
                    "Position ownership bypass"
                ],
                false_positive_indicators=[
                    "Complex math operations are expected",
                    "Tick boundary checks are normal"
                ],
                invariant_checks=[
                    "Total liquidity should balance after operations",
                    "Tick positions should be within valid ranges",
                    "Fees should accumulate correctly"
                ],
                risk_patterns={
                    "tick.*manipulation": "high",
                    "liquidity.*overflow": "critical",
                    "position.*ownership": "high"
                }
            ),
            ProtocolPattern(
                protocol=ProtocolType.UNISWAP_V3,
                category=PatternCategory.FLASH_LOAN,
                pattern_name="flash_swap",
                confidence=0.9,
                description="Uniswap V3 flash swap mechanism",
                code_patterns=[
                    r'flash.*callback',
                    r'uniswapV3FlashCallback',
                    r'amount0Out|amount1Out',
                    r'pay.*flash.*loan'
                ],
                function_signatures=[
                    'flash(address,uint256,uint256,bytes)',
                    'uniswapV3FlashCallback(uint256,uint256,bytes)'
                ],
                variable_patterns={},
                security_notes=[
                    "Flash swap callbacks must be implemented securely",
                    "Loan repayment must be enforced",
                    "Callback functions must validate caller"
                ],
                common_vulnerabilities=[
                    "Callback reentrancy",
                    "Insufficient loan repayment",
                    "Unauthorized callback execution"
                ],
                false_positive_indicators=[
                    "External calls in callbacks are expected",
                    "Complex payment logic is normal"
                ],
                invariant_checks=[
                    "Flash loan amounts must be repaid plus fees",
                    "Callback must be called by Uniswap pool",
                    "Payment must succeed"
                ],
                risk_patterns={
                    "callback.*reentrancy": "critical",
                    "insufficient.*repayment": "critical",
                    "unauthorized.*callback": "high"
                }
            )
        ]

    def _get_aave_v3_patterns(self) -> List[ProtocolPattern]:
        """Aave V3 specific patterns."""
        return [
            ProtocolPattern(
                protocol=ProtocolType.AAVE_V3,
                category=PatternCategory.LIQUIDATION,
                pattern_name="health_factor_calculation",
                confidence=0.9,
                description="Aave V3 health factor and liquidation logic",
                code_patterns=[
                    r'healthFactor|liquidationThreshold',
                    r'totalCollateralBase|totalDebtBase',
                    r'liquidationBonus|closeFactor',
                    r'calculateHealthFactor',
                    r'validateHealthFactor'
                ],
                function_signatures=[
                    'liquidationCall(address,address,address,uint256,bool)',
                    'calculateHealthFactor(uint256,uint256,uint256)',
                    'getUserAccountData(address)'
                ],
                variable_patterns={
                    'healthFactor': 'uint256',
                    'liquidationThreshold': 'uint256',
                    'liquidationBonus': 'uint256'
                },
                security_notes=[
                    "Health factor must never be manipulated",
                    "Liquidation thresholds must be validated",
                    "Liquidation bonuses must be reasonable"
                ],
                common_vulnerabilities=[
                    "Health factor manipulation",
                    "Incorrect liquidation math",
                    "Bad debt accumulation"
                ],
                false_positive_indicators=[
                    "Health factor checks are expected",
                    "Liquidation logic is normal protocol behavior"
                ],
                invariant_checks=[
                    "Health factor must be > 1 for solvent positions",
                    "Liquidation bonus must be < 100%",
                    "Total debt should not exceed total collateral value"
                ],
                risk_patterns={
                    "health.*factor.*manipulation": "critical",
                    "liquidation.*math.*error": "critical",
                    "bad.*debt": "high"
                }
            ),
            ProtocolPattern(
                protocol=ProtocolType.AAVE_V3,
                category=PatternCategory.FLASH_LOAN,
                pattern_name="aave_flash_loan",
                confidence=0.8,
                description="Aave V3 flash loan implementation",
                code_patterns=[
                    r'flashLoan|flashLoanSimple',
                    r'executeOperation',
                    r'flashLoanReceiver',
                    r'premium|fee'
                ],
                function_signatures=[
                    'flashLoan(address[],uint256[],uint256[],address,bytes,uint16)',
                    'flashLoanSimple(address,address,uint256,bytes,uint16)',
                    'executeOperation(address[],uint256[],uint256[],address,bytes)'
                ],
                variable_patterns={
                    'FLASHLOAN_PREMIUM_TOTAL': 'uint128',
                    'MAX_NUMBER_RESERVES': 'uint16'
                },
                security_notes=[
                    "Flash loan receiver must implement executeOperation",
                    "Premium fees must be paid",
                    "Flash loan amounts must be validated"
                ],
                common_vulnerabilities=[
                    "Flash loan fee evasion",
                    "Callback reentrancy",
                    "Insufficient premium payment"
                ],
                false_positive_indicators=[
                    "External calls in executeOperation are expected",
                    "Premium calculations are normal"
                ],
                invariant_checks=[
                    "Premium must be paid to pool",
                    "Flash loan amount must be returned",
                    "executeOperation must succeed"
                ],
                risk_patterns={
                    "fee.*evasion": "high",
                    "callback.*reentrancy": "critical",
                    "insufficient.*premium": "high"
                }
            )
        ]

    def _get_compound_v3_patterns(self) -> List[ProtocolPattern]:
        """Compound V3 specific patterns."""
        return [
            ProtocolPattern(
                protocol=ProtocolType.COMPOUND_V3,
                category=PatternCategory.INTEREST_RATE,
                pattern_name="interest_rate_model",
                confidence=0.8,
                description="Compound V3 interest rate calculations",
                code_patterns=[
                    r'utilizationRate|supplyRate|borrowRate',
                    r'getSupplyRate|getBorrowRate',
                    r'updateInterestRates',
                    r'accrueInterest'
                ],
                function_signatures=[
                    'getSupplyRate(uint256,uint256,uint256,uint256)',
                    'getBorrowRate(uint256,uint256,uint256,uint256)',
                    'accrueInterest()'
                ],
                variable_patterns={
                    'borrowRate': 'uint256',
                    'supplyRate': 'uint256',
                    'utilizationRate': 'uint256'
                },
                security_notes=[
                    "Interest rate calculations must be monotonic",
                    "Utilization rate must be bounded [0, 1]",
                    "Interest accrual must be time-weighted"
                ],
                common_vulnerabilities=[
                    "Interest rate manipulation",
                    "Incorrect utilization calculation",
                    "Time-based calculation errors"
                ],
                false_positive_indicators=[
                    "Complex rate calculations are expected",
                    "Time-based math is normal"
                ],
                invariant_checks=[
                    "Supply rate >= borrow rate",
                    "Utilization rate ∈ [0, 1]",
                    "Interest accrues monotonically"
                ],
                risk_patterns={
                    "rate.*manipulation": "high",
                    "utilization.*error": "critical",
                    "time.*calculation": "medium"
                }
            )
        ]

    def _get_makerdao_patterns(self) -> List[ProtocolPattern]:
        """MakerDAO specific patterns."""
        return [
            ProtocolPattern(
                protocol=ProtocolType.MAKERDAO,
                category=PatternCategory.VAULT_MANAGEMENT,
                pattern_name="cdp_management",
                confidence=0.8,
                description="MakerDAO CDP (Collateralized Debt Position) management",
                code_patterns=[
                    r'collateral.*ratio|liquidation.*ratio',
                    r'stability.*fee|stabilityFee',
                    r'vault.*liquidation|cdp.*liquidation',
                    r'draw.*dai|wipe.*dai'
                ],
                function_signatures=[
                    'open(address,bytes32)',
                    'join(uint256)',
                    'draw(uint256)',
                    'wipe(uint256)',
                    'shut()'
                ],
                variable_patterns={
                    'liquidationRatio': 'uint256',
                    'stabilityFee': 'uint256',
                    'debtCeiling': 'uint256'
                },
                security_notes=[
                    "Collateral ratio must exceed liquidation ratio",
                    "Stability fees must accrue correctly",
                    "Liquidation penalties must be applied"
                ],
                common_vulnerabilities=[
                    "Collateral price manipulation",
                    "Stability fee calculation errors",
                    "Liquidation ratio bypass"
                ],
                false_positive_indicators=[
                    "Liquidation logic is expected protocol behavior",
                    "Fee calculations are normal"
                ],
                invariant_checks=[
                    "Collateral value > debt * liquidation ratio",
                    "Stability fees accrue over time",
                    "Liquidation penalty <= 100%"
                ],
                risk_patterns={
                    "collateral.*manipulation": "critical",
                    "fee.*calculation": "high",
                    "liquidation.*bypass": "critical"
                }
            )
        ]

    def _get_curve_patterns(self) -> List[ProtocolPattern]:
        """Curve Finance specific patterns."""
        return [
            ProtocolPattern(
                protocol=ProtocolType.CURVE,
                category=PatternCategory.LIQUIDITY_MANAGEMENT,
                pattern_name="stable_swap",
                confidence=0.8,
                description="Curve stable swap AMM",
                code_patterns=[
                    r'exchange.*dy|exchange_underlying',
                    r'add_liquidity|remove_liquidity',
                    r'get_dy|get_dx',
                    r'amplification|amplification_coeff'
                ],
                function_signatures=[
                    'exchange(int128,int128,uint256,uint256)',
                    'add_liquidity(uint256[],uint256)',
                    'remove_liquidity(uint256,uint256[])',
                    'get_dy(int128,int128,uint256)'
                ],
                variable_patterns={
                    'A': 'uint256',  # Amplification coefficient
                    'fee': 'uint256',
                    'balances': 'uint256[]'
                },
                security_notes=[
                    "Slippage calculations must be accurate",
                    "Invariant must be maintained",
                    "Fee calculations must be correct"
                ],
                common_vulnerabilities=[
                    "Slippage manipulation",
                    "Invariant calculation errors",
                    "Fee precision loss"
                ],
                false_positive_indicators=[
                    "Complex math operations are expected",
                    "Slippage checks are normal"
                ],
                invariant_checks=[
                    "Pool invariant must be maintained",
                    "Exchange rates must be reasonable",
                    "Fees must be collected correctly"
                ],
                risk_patterns={
                    "slippage.*manipulation": "high",
                    "invariant.*error": "critical",
                    "precision.*loss": "medium"
                }
            )
        ]

    def _get_generic_amm_patterns(self) -> List[ProtocolPattern]:
        """Generic AMM patterns."""
        return [
            ProtocolPattern(
                protocol=ProtocolType.GENERIC_AMM,
                category=PatternCategory.LIQUIDITY_MANAGEMENT,
                pattern_name="constant_product",
                confidence=0.6,
                description="Generic constant product AMM (x*y=k)",
                code_patterns=[
                    r'reserve0|reserve1',
                    r'sqrt.*price|getPrice',
                    r'swap.*amount|swapExactTokens',
                    r'addLiquidity|removeLiquidity'
                ],
                function_signatures=[
                    'swap(uint256,uint256,address,bytes)',
                    'addLiquidity(uint256,uint256)',
                    'removeLiquidity(uint256)'
                ],
                variable_patterns={
                    'reserve0': 'uint256',
                    'reserve1': 'uint256',
                    'totalSupply': 'uint256'
                },
                security_notes=[
                    "Reserves must be updated atomically",
                    "Slippage must be calculated correctly",
                    "Liquidity tokens must be minted/burned proportionally"
                ],
                common_vulnerabilities=[
                    "Reserve manipulation",
                    "Slippage bypass",
                    "Liquidity calculation errors"
                ],
                false_positive_indicators=[
                    "Reserve updates are expected",
                    "Price calculations are normal"
                ],
                invariant_checks=[
                    "k = reserve0 * reserve1 must hold",
                    "Total supply must match liquidity",
                    "Fees must be collected correctly"
                ],
                risk_patterns={
                    "reserve.*manipulation": "critical",
                    "slippage.*bypass": "high",
                    "liquidity.*error": "medium"
                }
            )
        ]

    def _get_generic_lending_patterns(self) -> List[ProtocolPattern]:
        """Generic lending protocol patterns."""
        return [
            ProtocolPattern(
                protocol=ProtocolType.GENERIC_LENDING,
                category=PatternCategory.LIQUIDATION,
                pattern_name="lending_liquidation",
                confidence=0.6,
                description="Generic lending protocol liquidation",
                code_patterns=[
                    r'liquidate|liquidation',
                    r'collateral.*ratio|health.*factor',
                    r'seize.*collateral|repay.*debt',
                    r'liquidation.*bonus|bonus'
                ],
                function_signatures=[
                    'liquidate(address,address,uint256)',
                    'calculateHealthFactor(address)',
                    'seizeCollateral(address,uint256)'
                ],
                variable_patterns={
                    'collateralFactor': 'uint256',
                    'liquidationThreshold': 'uint256',
                    'liquidationBonus': 'uint256'
                },
                security_notes=[
                    "Health factors must be calculated correctly",
                    "Liquidation bonuses must be reasonable",
                    "Collateral seizure must be proportional"
                ],
                common_vulnerabilities=[
                    "Health factor manipulation",
                    "Bad debt accumulation",
                    "Incorrect liquidation math"
                ],
                false_positive_indicators=[
                    "Liquidation logic is expected",
                    "Health factor checks are normal"
                ],
                invariant_checks=[
                    "Health factor must be > 1 for solvent positions",
                    "Liquidation bonus must be < 100%",
                    "Seized collateral must not exceed debt"
                ],
                risk_patterns={
                    "health.*factor.*manipulation": "critical",
                    "bad.*debt": "high",
                    "liquidation.*math": "critical"
                }
            )
        ]

    def get_summary(self) -> Dict[str, Any]:
        """Get summary of detected protocols and implications."""
        if not self.detected_protocols:
            return {"protocols_detected": 0, "total_confidence": 0.0}

        total_confidence = sum(p.confidence for p in self.detected_protocols)
        avg_confidence = total_confidence / len(self.detected_protocols)

        return {
            "protocols_detected": len(self.detected_protocols),
            "total_confidence": total_confidence,
            "average_confidence": avg_confidence,
            "primary_protocol": self.detected_protocols[0].protocol.value if self.detected_protocols else None,
            "all_protocols": [p.protocol.value for p in self.detected_protocols],
            "security_checks_needed": len(set().union(*[p.recommended_checks for p in self.detected_protocols]))
        }
