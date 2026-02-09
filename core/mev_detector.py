#!/usr/bin/env python3
"""
MEV-Specific Vulnerability Detector

Advanced detector for MEV (Maximal Extractable Value) vulnerabilities including:
- Sandwich attacks
- Arbitrage opportunities
- Liquidation front-running
- Governance front-running
- MEV extraction patterns
- Flashbot protection bypass
"""

import re
import json
import asyncio
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime


class MEVVulnerabilityType(Enum):
    SANDWICH_ATTACK = "sandwich_attack"
    ARBITRAGE_OPPORTUNITY = "arbitrage_opportunity"
    LIQUIDATION_FRONT_RUN = "liquidation_front_run"
    GOVERNANCE_FRONT_RUN = "governance_front_run"
    MEV_EXTRACTION = "mev_extraction"
    FLASHBOT_BYPASS = "flashbot_bypass"
    PRIVATE_MEMPOOL_BYPASS = "private_mempool_bypass"
    GAS_PRICE_MANIPULATION = "gas_price_manipulation"
    TOCTOU_PRICE_MANIPULATION = "toctou_price_manipulation"  # NEW
    MEMPOOL_TIMING_ATTACK = "mempool_timing_attack"  # NEW


@dataclass
class MEVVulnerability:
    """MEV-specific vulnerability representation."""
    vuln_type: MEVVulnerabilityType
    severity: str
    confidence: float
    line_number: int
    description: str
    code_snippet: str
    attack_vector: str
    financial_impact: str
    exploit_complexity: str
    mev_potential: str
    poc_suggestion: str
    fix_suggestion: str
    context: Dict[str, Any] = field(default_factory=dict)
    
    # MEV-specific fields
    mev_category: str = ""
    extraction_method: str = ""
    target_protocol: str = ""
    attack_prerequisites: List[str] = field(default_factory=list)
    mitigation_strategies: List[str] = field(default_factory=list)
    historical_examples: List[str] = field(default_factory=list)
    gas_optimization: str = ""
    mempool_monitoring: str = ""


class MEVDetector:
    """Advanced MEV vulnerability detector with specialized patterns."""

    def __init__(self):
        self.mev_patterns = self._initialize_mev_patterns()
        self.sandwich_patterns = self._initialize_sandwich_patterns()
        self.arbitrage_patterns = self._initialize_arbitrage_patterns()
        self.front_run_patterns = self._initialize_front_run_patterns()
        self.extraction_patterns = self._initialize_extraction_patterns()
        
        # MEV-specific data
        self.mev_data = self._load_mev_data()
        self.historical_mev_attacks = self._load_historical_mev_attacks()

    def _initialize_mev_patterns(self) -> Dict[str, List[Dict[str, Any]]]:
        """Initialize MEV-specific vulnerability patterns."""
        return {
            "sandwich_attack": [
                {
                    "pattern": r"(swap|exchange|trade)\s*\([^)]*amountIn[^)]*amountOutMin[^)]*\)",
                    "severity": "medium",
                    "confidence": 0.5,
                    "description": "Trading function - checking for adequate sandwich attack protections",
                    "attack_vector": "MEV sandwich attack via insufficient slippage controls",
                    "financial_impact": "Medium - MEV extraction from users",
                    "exploit_complexity": "High",
                    "mev_potential": "$1,000-$50,000 per attack",
                    "poc_suggestion": "Demonstrate sandwich attack with front-running",
                    "fix_suggestion": "Add MEV protection: enforce nonzero minAmountOut, add deadline check",
                    "mev_category": "Sandwich Attack",
                    "extraction_method": "Front-run + Back-run",
                    "target_protocol": "DEX",
                    "attack_prerequisites": ["Public mempool", "MEV bot access", "Slippage tolerance"],
                    "mitigation_strategies": ["Private mempools", "Slippage protection", "MEV protection"],
                    "historical_examples": ["Uniswap Sandwich Attacks", "SushiSwap MEV Extraction"],
                    "gas_optimization": "High gas price for front-running",
                    "mempool_monitoring": "Monitor for large trades",
                    "required_protections": [
                        r"amountOutMin\s*>\s*0|minAmountOut\s*>\s*0|require\s*\([^)]*amountOutMin",
                        r"deadline|block\.timestamp\s*<=|expiry",
                    ],
                    "protection_reduces_confidence": [
                        r"slippage|priceImpact|minAmountOut|amountOutMin",
                    ],
                },
            ],

            "arbitrage_opportunity": [
                {
                    "pattern": r"(getAmountOut|getAmountIn|getReserves)\s*\([^)]*\)",
                    "severity": "low",
                    "confidence": 0.4,
                    "description": "Price calculation function - normal DeFi primitive, not a vulnerability by itself",
                    "attack_vector": "Cross-protocol arbitrage (informational only)",
                    "financial_impact": "Low - Arbitrage is a normal market mechanism",
                    "exploit_complexity": "High",
                    "mev_potential": "$1,000-$100,000 per opportunity",
                    "poc_suggestion": "N/A - arbitrage opportunities are market features",
                    "fix_suggestion": "Consider TWAP pricing for critical operations",
                    "mev_category": "Arbitrage",
                    "extraction_method": "Price difference exploitation",
                    "target_protocol": "DEX",
                    "attack_prerequisites": ["Multiple protocol access", "Price discrepancies"],
                    "mitigation_strategies": ["Cross-protocol validation", "TWAP pricing"],
                    "required_protections": [],
                    "protection_reduces_confidence": [
                        r"twap|timeWeighted|observe\(|consult\(",
                    ],
                },
            ],

            "liquidation_front_run": [
                {
                    "pattern": r"(liquidate|liquidationCall)\s*\([^)]*collateral[^)]*debt[^)]*\)",
                    "severity": "medium",
                    "confidence": 0.5,
                    "description": "Liquidation function - checking for front-running protections",
                    "attack_vector": "Liquidation front-running",
                    "financial_impact": "Medium - Unfair liquidation extraction",
                    "exploit_complexity": "Medium",
                    "mev_potential": "$10,000-$250,000 per liquidation",
                    "poc_suggestion": "Demonstrate liquidation front-running",
                    "fix_suggestion": "Add liquidation delay, batch liquidations, or private mempool submission",
                    "mev_category": "Liquidation Front-run",
                    "extraction_method": "Front-running liquidation",
                    "target_protocol": "Lending Protocol",
                    "attack_prerequisites": ["Liquidation opportunity", "Front-running capability"],
                    "mitigation_strategies": ["Liquidation protection", "Batch liquidation", "Gas auction"],
                    "required_protections": [
                        r"liquidationDelay|batchLiquidat|liquidationQueue",
                    ],
                    "protection_reduces_confidence": [
                        r"onlyKeeper|onlyLiquidator|whitelist",
                    ],
                },
            ],

            "governance_front_run": [
                {
                    "pattern": r"(propose|execute)\s*\([^)]*proposalId[^)]*\)",
                    "severity": "medium",
                    "confidence": 0.5,
                    "description": "Governance function - checking for timelock and front-running protections",
                    "attack_vector": "Governance front-running or flash-loan voting",
                    "financial_impact": "High - Governance manipulation",
                    "exploit_complexity": "High",
                    "mev_potential": "$10,000-$500,000 per attack",
                    "poc_suggestion": "Demonstrate governance front-running",
                    "fix_suggestion": "Add timelock, voting delay, and snapshot-based voting power",
                    "mev_category": "Governance Front-run",
                    "extraction_method": "Front-running governance",
                    "target_protocol": "Governance Protocol",
                    "attack_prerequisites": ["Governance access", "Front-running capability"],
                    "mitigation_strategies": ["Timelock", "Voting delay", "Snapshot voting"],
                    "required_protections": [
                        r"timelock|TimelockController|delay|votingDelay",
                    ],
                    "protection_reduces_confidence": [
                        r"snapshot|getVotes\(.*blockNumber|getPastVotes",
                    ],
                },
            ],

            "mev_extraction": [
                {
                    "pattern": r"(swap|exchange|trade).*(swap|exchange|trade)",
                    "severity": "low",
                    "confidence": 0.4,
                    "description": "Multiple trading operations - check for atomic MEV protections",
                    "attack_vector": "Multi-step MEV extraction",
                    "financial_impact": "Low-Medium - MEV extraction",
                    "exploit_complexity": "High",
                    "mev_potential": "$1,000-$100,000 per extraction",
                    "poc_suggestion": "Demonstrate multi-step MEV extraction",
                    "fix_suggestion": "Add MEV protection and private transaction submission",
                    "mev_category": "MEV Extraction",
                    "extraction_method": "Multi-transaction MEV",
                    "target_protocol": "DEX",
                    "attack_prerequisites": ["Multiple transaction access", "MEV opportunity"],
                    "mitigation_strategies": ["MEV protection", "Private mempool", "Flashbots"],
                    "required_protections": [],
                    "protection_reduces_confidence": [
                        r"private|flashbots|mev.protect|commit.*reveal",
                    ],
                },
            ],

            "flashbot_bypass": [
                {
                    "pattern": r"(block\.coinbase|tx\.gasprice\s*[><=])",
                    "severity": "low",
                    "confidence": 0.4,
                    "description": "Block-level MEV indicator - informational",
                    "attack_vector": "Miner/validator MEV extraction",
                    "financial_impact": "Low - Validator MEV",
                    "exploit_complexity": "High",
                    "mev_potential": "$100-$5,000 per bypass",
                    "poc_suggestion": "Show validator MEV extraction",
                    "fix_suggestion": "Use commit-reveal or private transaction submission",
                    "mev_category": "Validator MEV",
                    "extraction_method": "Block-level MEV",
                    "target_protocol": "Universal",
                    "attack_prerequisites": ["Validator access"],
                    "mitigation_strategies": ["Commit-reveal", "Private mempool"],
                    "required_protections": [],
                    "protection_reduces_confidence": [],
                }
            ]
        }

    def _initialize_sandwich_patterns(self) -> Dict[str, List[str]]:
        """Initialize sandwich attack patterns."""
        return {
            "swap_functions": [
                r"swapExactTokensForTokens",
                r"swapExactETHForTokens",
                r"swapTokensForExactTokens",
                r"swapETHForExactTokens"
            ],
            "slippage_protection": [
                r"amountOutMin|minAmountOut",
                r"slippage|priceImpact",
                r"deadline|timeLimit"
            ],
            "price_impact": [
                r"getAmountsOut|getAmountsIn",
                r"getReserves|getPrice",
                r"calculateSwap|calculateTrade"
            ]
        }

    def _initialize_arbitrage_patterns(self) -> Dict[str, List[str]]:
        """Initialize arbitrage patterns."""
        return {
            "price_calculation": [
                r"getAmountOut|getAmountIn",
                r"getPrice|getRate",
                r"getExchangeRate|getReserves"
            ],
            "cross_protocol": [
                r"getPrice.*getRate",
                r"getAmountOut.*getAmountIn",
                r"getReserves.*getPrice"
            ],
            "arbitrage_opportunity": [
                r"price.*difference|rate.*difference",
                r"arbitrage|profit.*opportunity",
                r"cross.*protocol.*price"
            ]
        }

    def _initialize_front_run_patterns(self) -> Dict[str, List[str]]:
        """Initialize front-running patterns."""
        return {
            "liquidation": [
                r"liquidate|liquidationCall",
                r"healthFactor|collateralRatio",
                r"liquidation.*threshold"
            ],
            "governance": [
                r"propose|execute|vote",
                r"quorum|majority|threshold",
                r"votingPower|governance"
            ],
            "trading": [
                r"swap|exchange|trade",
                r"buy|sell|purchase",
                r"order|transaction"
            ]
        }

    def _initialize_extraction_patterns(self) -> Dict[str, List[str]]:
        """Initialize MEV extraction patterns."""
        return {
            "multi_transaction": [
                r"swap.*swap|exchange.*exchange",
                r"trade.*trade|buy.*sell",
                r"transaction.*transaction"
            ],
            "price_manipulation": [
                r"price.*manipulation|rate.*manipulation",
                r"oracle.*manipulation|feed.*manipulation",
                r"price.*impact|rate.*impact"
            ],
            "gas_optimization": [
                r"gas.*optimization|gas.*price",
                r"gas.*limit|gas.*estimation",
                r"gas.*efficient|gas.*saving"
            ]
        }

    def _load_mev_data(self) -> Dict[str, Any]:
        """Load MEV-specific data."""
        return {
            "sandwich_attack": {
                "min_profit": 1000,
                "max_profit": 50000,
                "avg_profit": 10000,
                "success_rate": 0.7,
                "gas_cost": 50000
            },
            "arbitrage_opportunity": {
                "min_profit": 1000,
                "max_profit": 100000,
                "avg_profit": 25000,
                "success_rate": 0.8,
                "gas_cost": 80000
            },
            "liquidation_front_run": {
                "min_profit": 10000,
                "max_profit": 250000,
                "avg_profit": 50000,
                "success_rate": 0.6,
                "gas_cost": 100000
            },
            "governance_front_run": {
                "min_profit": 10000,
                "max_profit": 500000,
                "avg_profit": 100000,
                "success_rate": 0.5,
                "gas_cost": 150000
            }
        }

    def _load_historical_mev_attacks(self) -> Dict[str, List[str]]:
        """Load historical MEV attack examples."""
        return {
            "sandwich_attack": [
                "Uniswap Sandwich Attacks (Ongoing)",
                "SushiSwap MEV Extraction (Ongoing)",
                "PancakeSwap MEV Attacks (Ongoing)",
                "1inch MEV Extraction (Ongoing)"
            ],
            "arbitrage_opportunity": [
                "Uniswap-Arbitrum Arbitrage",
                "SushiSwap-Polygon Arbitrage",
                "PancakeSwap-BSC Arbitrage",
                "Curve-Arbitrum Arbitrage"
            ],
            "liquidation_front_run": [
                "Compound Liquidation Front-running",
                "Aave Liquidation Front-running",
                "MakerDAO Liquidation Front-running",
                "Venus Liquidation Front-running"
            ],
            "governance_front_run": [
                "Compound Governance Front-running",
                "MakerDAO Governance Front-running",
                "Uniswap Governance Front-running",
                "Aave Governance Front-running"
            ]
        }

    async def analyze_contract(self, contract_path: str, content: str) -> List[MEVVulnerability]:
        """Analyze contract for MEV vulnerabilities."""
        vulnerabilities = []
        lines = content.split('\n')
        
        # Analyze each MEV vulnerability type
        for vuln_type, patterns in self.mev_patterns.items():
            for pattern_info in patterns:
                pattern = pattern_info["pattern"]
                regex = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                
                for match in regex.finditer(content):
                    line_number = content[:match.start()].count('\n') + 1
                    
                    # Extract code snippet with context
                    start_line = max(0, line_number - 3)
                    end_line = min(len(lines), line_number + 3)
                    code_snippet = '\n'.join(lines[start_line:end_line])
                    
                    vulnerability = MEVVulnerability(
                        vuln_type=MEVVulnerabilityType(vuln_type),
                        severity=pattern_info["severity"],
                        confidence=pattern_info["confidence"],
                        line_number=line_number,
                        description=pattern_info["description"],
                        code_snippet=code_snippet,
                        attack_vector=pattern_info["attack_vector"],
                        financial_impact=pattern_info["financial_impact"],
                        exploit_complexity=pattern_info["exploit_complexity"],
                        mev_potential=pattern_info["mev_potential"],
                        poc_suggestion=pattern_info["poc_suggestion"],
                        fix_suggestion=pattern_info["fix_suggestion"],
                        context={
                            "pattern_match": match.group(),
                            "contract_path": contract_path,
                            "vulnerability_type": vuln_type
                        },
                        mev_category=pattern_info.get("mev_category", ""),
                        extraction_method=pattern_info.get("extraction_method", ""),
                        target_protocol=pattern_info.get("target_protocol", ""),
                        attack_prerequisites=pattern_info.get("attack_prerequisites", []),
                        mitigation_strategies=pattern_info.get("mitigation_strategies", []),
                        historical_examples=pattern_info.get("historical_examples", []),
                        gas_optimization=pattern_info.get("gas_optimization", ""),
                        mempool_monitoring=pattern_info.get("mempool_monitoring", "")
                    )
                    
                    # Apply additional validation
                    if await self._validate_mev_vulnerability(vulnerability, content):
                        vulnerabilities.append(vulnerability)
        
        # Add cross-protocol MEV analysis
        vulnerabilities.extend(await self._analyze_cross_protocol_mev(content, contract_path))
        
        # Add protocol-specific MEV analysis
        vulnerabilities.extend(await self._analyze_protocol_specific_mev(content, contract_path))
        
        return vulnerabilities

    async def _validate_mev_vulnerability(self, vulnerability: MEVVulnerability, content: str) -> bool:
        """Validate MEV vulnerability with additional context checks."""

        # Check if the pattern has protection indicators that reduce confidence
        # (These are defined per-pattern in the mev_patterns dict)
        vuln_type_str = vulnerability.vuln_type.value
        for pattern_group in self.mev_patterns.get(vuln_type_str, []):
            for reduce_pattern in pattern_group.get("protection_reduces_confidence", []):
                if re.search(reduce_pattern, content, re.IGNORECASE):
                    vulnerability.confidence *= 0.4
                    vulnerability.context["protection_indicator_found"] = reduce_pattern

        # Check for MEV protection patterns
        protection_patterns = {
            "sandwich_attack": [
                r"mev.*protection|antiMEV",
                r"slippage.*protection|priceImpact.*limit",
                r"private.*mempool|flashbots",
                r"twap.*pricing|time.*weighted"
            ],
            "arbitrage_opportunity": [
                r"arbitrage.*protection|antiArbitrage",
                r"price.*synchronization|rate.*synchronization",
                r"cross.*protocol.*validation",
                r"arbitrage.*limit|profit.*limit"
            ],
            "liquidation_front_run": [
                r"liquidation.*protection|antiLiquidation",
                r"front.*run.*protection|antiFrontRun",
                r"gas.*optimization|gas.*efficient",
                r"liquidation.*delay|front.*run.*delay"
            ],
            "governance_front_run": [
                r"governance.*protection|antiGovernance",
                r"front.*run.*protection|antiFrontRun",
                r"voting.*delay|proposal.*delay",
                r"governance.*timelock|execution.*delay"
            ]
        }
        
        vuln_type = vulnerability.vuln_type.value
        if vuln_type in protection_patterns:
            for pattern in protection_patterns[vuln_type]:
                if re.search(pattern, content, re.IGNORECASE):
                    # Protection found, reduce confidence
                    vulnerability.confidence *= 0.5
                    vulnerability.context["protection_found"] = pattern
        
        # Only report vulnerabilities with sufficient confidence
        return vulnerability.confidence > 0.5

    async def _analyze_cross_protocol_mev(self, content: str, contract_path: str) -> List[MEVVulnerability]:
        """Analyze cross-protocol MEV patterns."""
        vulnerabilities = []
        
        # Look for cross-protocol MEV interaction patterns
        cross_protocol_patterns = [
            {
                "pattern": r"(getPrice|getRate|getExchangeRate).*(getPrice|getRate|getExchangeRate)",
                "vuln_type": "arbitrage_opportunity",
                "severity": "medium",
                "confidence": 0.6,
                "description": "Multiple price sources detected - potential for cross-protocol MEV",
                "attack_vector": "Cross-protocol MEV arbitrage",
                "financial_impact": "Medium - Cross-protocol MEV",
                "exploit_complexity": "High",
                "mev_potential": "$1,000-$100,000 per opportunity"
            }
        ]
        
        for pattern_info in cross_protocol_patterns:
            pattern = pattern_info["pattern"]
            regex = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            
            for match in regex.finditer(content):
                line_number = content[:match.start()].count('\n') + 1
                
                vulnerability = MEVVulnerability(
                    vuln_type=MEVVulnerabilityType(pattern_info["vuln_type"]),
                    severity=pattern_info["severity"],
                    confidence=pattern_info["confidence"],
                    line_number=line_number,
                    description=pattern_info["description"],
                    code_snippet=match.group(),
                    attack_vector=pattern_info["attack_vector"],
                    financial_impact=pattern_info["financial_impact"],
                    exploit_complexity=pattern_info["exploit_complexity"],
                    mev_potential=pattern_info["mev_potential"],
                    poc_suggestion="Demonstrate cross-protocol MEV arbitrage",
                    fix_suggestion="Add cross-protocol MEV protection",
                    context={"pattern_match": match.group(), "contract_path": contract_path},
                    mev_category="Cross-Protocol MEV",
                    extraction_method="Cross-protocol arbitrage",
                    target_protocol="Universal"
                )
                
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities

    async def _analyze_protocol_specific_mev(self, content: str, contract_path: str) -> List[MEVVulnerability]:
        """Analyze protocol-specific MEV patterns."""
        vulnerabilities = []
        
        # Detect protocol type
        protocol_type = self._detect_protocol_type(content)
        
        # Protocol-specific MEV patterns
        protocol_mev_patterns = {
            "uniswap_v2": {
                "sandwich_attack": [
                    r"getReserves.*getAmountOut",
                    r"swap.*amount0Out.*amount1Out",
                    r"mint.*liquidity.*totalSupply"
                ],
                "arbitrage_opportunity": [
                    r"getAmountOut.*getAmountIn",
                    r"getReserves.*getPrice",
                    r"calculateSwap.*calculateTrade"
                ]
            },
            "uniswap_v3": {
                "sandwich_attack": [
                    r"getAmount0Delta.*getAmount1Delta",
                    r"swap.*amount0.*amount1.*sqrtPriceX96",
                    r"mint.*tickLower.*tickUpper"
                ],
                "arbitrage_opportunity": [
                    r"getAmount0Delta.*getAmount1Delta",
                    r"getSqrtPriceX96.*getTick",
                    r"calculateSwap.*calculateTrade"
                ]
            },
            "compound": {
                "liquidation_front_run": [
                    r"liquidateBorrow.*borrower.*repayAmount.*cTokenCollateral",
                    r"getAccountLiquidity.*sumCollateral.*sumBorrowPlusEffects"
                ],
                "arbitrage_opportunity": [
                    r"getBorrowRate.*getSupplyRate",
                    r"accrueInterest.*borrowIndex",
                    r"calculateInterestRates.*utilizationRate"
                ]
            },
            "aave": {
                "liquidation_front_run": [
                    r"liquidationCall.*collateralAsset.*debtAsset.*user.*debtToCover.*receiveAToken",
                    r"calculateHealthFactor.*totalCollateralETH.*totalDebtETH.*liquidationThreshold"
                ],
                "arbitrage_opportunity": [
                    r"getReserveData.*getReserveNormalizedIncome.*getReserveNormalizedDebt",
                    r"calculateInterestRates.*utilizationRate.*stableBorrowRate.*variableBorrowRate"
                ]
            }
        }
        
        if protocol_type in protocol_mev_patterns:
            patterns = protocol_mev_patterns[protocol_type]
            
            for pattern_category, pattern_list in patterns.items():
                for pattern in pattern_list:
                    regex = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                    
                    for match in regex.finditer(content):
                        line_number = content[:match.start()].count('\n') + 1
                        
                        vulnerability = MEVVulnerability(
                            vuln_type=MEVVulnerabilityType(pattern_category),
                            severity="medium",
                            confidence=0.7,
                            line_number=line_number,
                            description=f"{protocol_type} {pattern_category} MEV pattern detected",
                            code_snippet=match.group(),
                            attack_vector=f"{protocol_type} {pattern_category} MEV",
                            financial_impact="Medium - Protocol-specific MEV",
                            exploit_complexity="High",
                            mev_potential="$1,000-$100,000 per opportunity",
                            poc_suggestion=f"Demonstrate {protocol_type} {pattern_category} MEV attack",
                            fix_suggestion=f"Add {protocol_type} {pattern_category} MEV protection",
                            context={"pattern_match": match.group(), "contract_path": contract_path},
                            mev_category=f"{protocol_type} {pattern_category}",
                            extraction_method=f"{protocol_type} {pattern_category}",
                            target_protocol=protocol_type
                        )
                        
                        vulnerabilities.append(vulnerability)
        
        return vulnerabilities

    def _detect_protocol_type(self, content: str) -> str:
        """Detect the protocol type from contract content."""
        protocol_indicators = {
            "uniswap_v2": ["UniswapV2", "IUniswapV2", "V2Router", "V2Factory"],
            "uniswap_v3": ["UniswapV3", "IUniswapV3", "V3Router", "V3Factory"],
            "compound": ["Compound", "CToken", "Comptroller", "InterestRateModel"],
            "aave": ["Aave", "LendingPool", "AToken", "StableDebtToken"],
            "curve": ["Curve", "ICurve", "StableSwap", "MetaPool"]
        }
        
        for protocol, indicators in protocol_indicators.items():
            if any(indicator in content for indicator in indicators):
                return protocol
        
        return "unknown"

    def generate_mev_poc_suggestion(self, vulnerability: MEVVulnerability) -> str:
        """Generate MEV-specific proof-of-concept suggestion."""
        
        poc_templates = {
            "sandwich_attack": """
// MEV Sandwich Attack PoC
contract MEVSandwichAttack {{
    function exploitSandwich() external {{
        // 1. Monitor mempool for large trades
        // 2. Front-run with buy order
        // 3. Let victim trade execute (price impact)
        // 4. Back-run with sell order
        // 5. Profit from price difference
        
        // MEV Category: Sandwich Attack
        // Extraction Method: Front-run + Back-run
        // Target Protocol: DEX
        // MEV Potential: $1,000-$50,000 per attack
    }}
}}
            """,
            "arbitrage_opportunity": """
// MEV Arbitrage Opportunity PoC
contract MEVArbitrage {{
    function exploitArbitrage() external {{
        // 1. Monitor price differences across protocols
        // 2. Execute arbitrage trades
        // 3. Profit from price differences
        // 4. Optimize gas for maximum profit
        
        // MEV Category: Arbitrage
        // Extraction Method: Price difference exploitation
        // Target Protocol: DEX
        // MEV Potential: $1,000-$100,000 per opportunity
    }}
}}
            """,
            "liquidation_front_run": """
// MEV Liquidation Front-run PoC
contract MEVLiquidationFrontRun {{
    function exploitLiquidationFrontRun() external {{
        // 1. Monitor liquidation opportunities
        // 2. Front-run liquidation transaction
        // 3. Execute liquidation with higher gas
        // 4. Profit from liquidation bonus
        
        // MEV Category: Liquidation Front-run
        // Extraction Method: Front-running liquidation
        // Target Protocol: Lending Protocol
        // MEV Potential: $10,000-$250,000 per liquidation
    }}
}}
            """,
            "governance_front_run": """
// MEV Governance Front-run PoC
contract MEVGovernanceFrontRun {{
    function exploitGovernanceFrontRun() external {{
        // 1. Monitor governance proposals
        // 2. Front-run governance execution
        // 3. Execute governance action with higher gas
        // 4. Profit from governance manipulation
        
        // MEV Category: Governance Front-run
        // Extraction Method: Front-running governance
        // Target Protocol: Governance Protocol
        // MEV Potential: $10,000-$500,000 per attack
    }}
}}
            """
        }
        
        vuln_type = vulnerability.vuln_type.value
        return poc_templates.get(vuln_type, "// MEV PoC template not available")

    def get_mev_potential_estimate(self, vulnerability: MEVVulnerability) -> str:
        """Get MEV potential estimate for vulnerability."""
        
        vuln_type = vulnerability.vuln_type.value
        if vuln_type in self.mev_data:
            mev_info = self.mev_data[vuln_type]
            min_profit = mev_info["min_profit"]
            max_profit = mev_info["max_profit"]
            
            # Apply severity multiplier
            if vulnerability.severity == "high":
                min_profit *= 2
                max_profit *= 2
            elif vulnerability.severity == "low":
                min_profit *= 0.5
                max_profit *= 0.5
            
            return f"${min_profit:,} - ${max_profit:,}"
        
        return "Unknown"

    def generate_comprehensive_mev_report(self, vulnerabilities: List[MEVVulnerability]) -> Dict[str, Any]:
        """Generate comprehensive MEV vulnerability report."""
        
        report = {
            "summary": {
                "total_vulnerabilities": len(vulnerabilities),
                "critical_count": len([v for v in vulnerabilities if v.severity == "critical"]),
                "high_count": len([v for v in vulnerabilities if v.severity == "high"]),
                "medium_count": len([v for v in vulnerabilities if v.severity == "medium"]),
                "low_count": len([v for v in vulnerabilities if v.severity == "low"])
            },
            "vulnerabilities": [],
            "recommendations": [],
            "mev_potential": {
                "estimated_total": "$0",
                "breakdown": {}
            },
            "mev_categories": {},
            "protocol_analysis": {}
        }
        
        # Process vulnerabilities
        for vuln in vulnerabilities:
            vuln_data = {
                "type": vuln.vuln_type.value,
                "severity": vuln.severity,
                "confidence": vuln.confidence,
                "line_number": vuln.line_number,
                "description": vuln.description,
                "attack_vector": vuln.attack_vector,
                "financial_impact": vuln.financial_impact,
                "exploit_complexity": vuln.exploit_complexity,
                "mev_potential": vuln.mev_potential,
                "poc_suggestion": vuln.poc_suggestion,
                "fix_suggestion": vuln.fix_suggestion,
                "code_snippet": vuln.code_snippet,
                "mev_category": vuln.mev_category,
                "extraction_method": vuln.extraction_method,
                "target_protocol": vuln.target_protocol,
                "attack_prerequisites": vuln.attack_prerequisites,
                "mitigation_strategies": vuln.mitigation_strategies,
                "historical_examples": vuln.historical_examples,
                "gas_optimization": vuln.gas_optimization,
                "mempool_monitoring": vuln.mempool_monitoring
            }
            report["vulnerabilities"].append(vuln_data)
        
        # Generate recommendations
        unique_fixes = set(v.fix_suggestion for v in vulnerabilities)
        report["recommendations"] = list(unique_fixes)
        
        # Calculate MEV potential
        mev_total = 0
        for vuln in vulnerabilities:
            mev_range = vuln.mev_potential
            # Extract minimum MEV value
            min_mev = re.search(r'\$([0-9,]+)', mev_range)
            if min_mev:
                min_value = int(min_mev.group(1).replace(',', ''))
                mev_total += min_value
        
        report["mev_potential"]["estimated_total"] = f"${mev_total:,}"
        
        # Analyze MEV categories
        mev_categories = {}
        for vuln in vulnerabilities:
            category = vuln.mev_category
            if category not in mev_categories:
                mev_categories[category] = {
                    "count": 0,
                    "severity_distribution": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                    "protocols_affected": set()
                }
            mev_categories[category]["count"] += 1
            mev_categories[category]["severity_distribution"][vuln.severity] += 1
            mev_categories[category]["protocols_affected"].add(vuln.target_protocol)
        
        # Convert sets to lists for JSON serialization
        for category_info in mev_categories.values():
            category_info["protocols_affected"] = list(category_info["protocols_affected"])
        
        report["mev_categories"] = mev_categories
        
        # Analyze protocol distribution
        protocol_analysis = {}
        for vuln in vulnerabilities:
            protocol = vuln.target_protocol
            if protocol not in protocol_analysis:
                protocol_analysis[protocol] = {
                    "vulnerability_count": 0,
                    "severity_distribution": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                    "mev_categories": set()
                }
            protocol_analysis[protocol]["vulnerability_count"] += 1
            protocol_analysis[protocol]["severity_distribution"][vuln.severity] += 1
            protocol_analysis[protocol]["mev_categories"].add(vuln.mev_category)
        
        # Convert sets to lists for JSON serialization
        for protocol_info in protocol_analysis.values():
            protocol_info["mev_categories"] = list(protocol_info["mev_categories"])
        
        report["protocol_analysis"] = protocol_analysis
        
        return report
    
    def detect_toctou_pattern(self, contract_code: str, vuln: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Detect Time-Of-Check-Time-Of-Use vulnerabilities in price/reserve calculations.
        
        This identifies the pattern where:
        1. View/pure function calculates prices off-chain (Time-of-Check)
        2. State-changing function uses those prices on-chain (Time-of-Use)
        3. Gap allows MEV/front-running attacks
        
        Example: Liquidator bot calls maxSlippageToMinPrices() off-chain, then submits
                 runArbitrage() with those params - attacker can front-run between calls.
        
        Returns:
            Dict with TOCTOU classification or None if not TOCTOU
        """
        vuln_desc = vuln.get('description', '').lower()
        vuln_type = vuln.get('vulnerability_type', '').lower()
        code_snippet = vuln.get('code_snippet', '') or vuln.get('code', '')
        
        # Check if this is mislabeled as "flash loan" but is actually TOCTOU
        if 'flash loan' in vuln_type or 'flash loan' in vuln_desc:
            # Look for TOCTOU indicators
            toctou_indicators = {
                'off_chain_calculation': False,
                'on_chain_usage': False,
                'view_function': False,
                'public_mempool': False,
                'reserves_based': False
            }
            
            # Check for view/pure functions (off-chain calculation)
            if re.search(r'\b(view|pure)\s+returns.*\b(price|reserves|min|max)', contract_code, re.IGNORECASE):
                toctou_indicators['off_chain_calculation'] = True
                toctou_indicators['view_function'] = True
            
            # Check for getReserves pattern (spot price vulnerability)
            if re.search(r'getReserves\s*\(', code_snippet, re.IGNORECASE) or 'getReserves' in vuln_desc:
                toctou_indicators['reserves_based'] = True
                toctou_indicators['on_chain_usage'] = True
            
            # Check for state-changing execution functions
            if re.search(r'\b(run|execute|perform).*\b(arbitrage|swap|liquidate)', contract_code, re.IGNORECASE):
                toctou_indicators['on_chain_usage'] = True
            
            # Check for mempool exposure (external/public functions)
            if re.search(r'\b(external|public)\s+(virtual\s+)?returns', code_snippet):
                toctou_indicators['public_mempool'] = True
            
            # Check description for TOCTOU keywords
            toctou_keywords = [
                'same block', 'manipulate.*block', 'mempool', 'front-run',
                'spot.*reserve', 'current.*reserve', 'reads.*manipulated'
            ]
            for keyword in toctou_keywords:
                if re.search(keyword, vuln_desc, re.IGNORECASE):
                    toctou_indicators['public_mempool'] = True
                    break
            
            # If multiple TOCTOU indicators present, it's likely TOCTOU not atomic flash loan
            toctou_score = sum(toctou_indicators.values())
            
            if toctou_score >= 3:
                return {
                    'is_toctou': True,
                    'attack_type': 'TOCTOU/MEV Price Manipulation',
                    'severity_adjustment': 'MEDIUM',  # Downgrade from HIGH
                    'description_update': self._generate_toctou_description(vuln, toctou_indicators),
                    'toctou_indicators': toctou_indicators,
                    'confidence': 0.8,
                    'reasoning': f"""This is a Time-Of-Check-Time-Of-Use (TOCTOU) vulnerability, NOT a pure flash loan attack.
                    
TOCTOU Pattern Detected:
- Off-chain calculation: {toctou_indicators['off_chain_calculation']}
- On-chain usage: {toctou_indicators['on_chain_usage']}
- View function: {toctou_indicators['view_function']}  
- Public mempool: {toctou_indicators['public_mempool']}
- Reserves-based: {toctou_indicators['reserves_based']}

Attack Vector: Front-running (not atomic flash loan)
- Bot calls view function off-chain at Time T0
- Bot submits transaction with T0 parameters
- Attacker sees pending tx in mempool
- Attacker front-runs with DEX manipulation
- Bot's tx executes with stale params at Time T1
- Attacker back-runs to profit

Impact: MEDIUM (profit reduction, not fund drain)
Exploitability: Requires public mempool + MEV infrastructure"""
                }
        
        return None
    
    def _generate_toctou_description(self, vuln: Dict, indicators: Dict[str, bool]) -> str:
        """Generate accurate TOCTOU vulnerability description."""
        base_desc = vuln.get('description', '')
        
        toctou_addendum = """

CLASSIFICATION: TOCTOU/MEV Price Manipulation (NOT atomic flash loan attack)

ATTACK MECHANISM:
1. Victim calls view function off-chain to calculate parameters (Time T0)
2. Victim submits transaction to public mempool with T0 parameters  
3. Attacker monitors mempool and sees pending transaction
4. Attacker front-runs with large DEX swap to manipulate reserves
5. Victim's transaction executes using T0 params but T1 reserves (stale data)
6. Victim accepts unfavorable trade due to parameter-reserve mismatch
7. Attacker back-runs to reverse manipulation and capture profit

KEY DIFFERENCES FROM FLASH LOAN:
- NOT atomic (requires 3 separate transactions: front-run, victim, back-run)
- Requires mempool visibility (not possible with private mempools)
- Requires MEV infrastructure (limited on some networks)
- Impact is profit reduction, not complete fund drain

REALISTIC IMPACT: Medium severity
- Reduces victim profits by 10-30%
- Requires specific network conditions
- Mitigated by private mempool/flashbots
"""
        
        return base_desc + toctou_addendum
    
    def classify_price_manipulation_type(self, vuln: Dict[str, Any], contract_code: str) -> str:
        """
        Classify price manipulation as either:
        - ATOMIC_FLASH_LOAN: Single transaction flash loan attack
        - TOCTOU_MEV: Time-gap attack via mempool observation
        - ORACLE_MANIPULATION: Persistent oracle price manipulation
        
        Returns classification string.
        """
        desc = vuln.get('description', '').lower()
        code = vuln.get('code_snippet', '') or vuln.get('code', '')
        
        # Check for atomic flash loan indicators
        atomic_indicators = [
            'onFlashLoan' in contract_code,
            'flashLoan(' in contract_code,
            'executeOperation' in contract_code,
            'within.*same.*transaction' in desc,
            'atomic' in desc
        ]
        
        # Check for TOCTOU indicators
        toctou_indicators = [
            'mempool' in desc,
            'front.*run' in desc or 'front-run' in desc,
            'pending.*transaction' in desc,
            'time.*gap' in desc or 'time gap' in desc,
            re.search(r'\b(view|pure)\s+.*returns', contract_code),
            'getReserves' in code and not 'flashLoan' in contract_code,
            'same block' in desc and not 'same transaction' in desc
        ]
        
        # Check for oracle manipulation indicators  
        oracle_indicators = [
            'oracle' in desc,
            'chainlink' in desc.lower(),
            'price.*feed' in desc,
            'external.*price' in desc
        ]
        
        atomic_score = sum(1 for ind in atomic_indicators if ind)
        toctou_score = sum(1 for ind in toctou_indicators if ind)
        oracle_score = sum(1 for ind in oracle_indicators if ind)
        
        # Classify based on highest score
        scores = {
            'ATOMIC_FLASH_LOAN': atomic_score,
            'TOCTOU_MEV': toctou_score,
            'ORACLE_MANIPULATION': oracle_score
        }
        
        classification = max(scores, key=scores.get)
        
        # Require minimum score threshold
        if scores[classification] < 2:
            return 'UNCERTAIN'
        
        return classification
