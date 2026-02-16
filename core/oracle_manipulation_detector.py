#!/usr/bin/env python3
"""
Oracle Manipulation Detector

Advanced detector for oracle manipulation vulnerabilities including:
- Chainlink oracle attacks
- Band Protocol manipulation
- Tellor oracle exploits
- Pyth oracle manipulation
- Stale price attacks
- Price feed manipulation
- Oracle aggregation attacks
- Cross-oracle arbitrage
"""

import re
import json
import asyncio
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime


class OracleType(Enum):
    CHAINLINK = "chainlink"
    BAND = "band"
    TELLOR = "tellor"
    PYTH = "pyth"
    UNISWAP_V2 = "uniswap_v2"
    UNISWAP_V3 = "uniswap_v3"
    CUSTOM = "custom"
    AGGREGATED = "aggregated"


class OracleManipulationType(Enum):
    PRICE_MANIPULATION = "price_manipulation"
    STALE_PRICE_ATTACK = "stale_price_attack"
    ROUND_ID_MANIPULATION = "round_id_manipulation"
    TIMESTAMP_MANIPULATION = "timestamp_manipulation"
    AGGREGATION_ATTACK = "aggregation_attack"
    CROSS_ORACLE_ARBITRAGE = "cross_oracle_arbitrage"
    FLASH_LOAN_ORACLE_ATTACK = "flash_loan_oracle_attack"
    ORACLE_FRONT_RUNNING = "oracle_front_running"


@dataclass
class OracleVulnerability:
    """Oracle-specific vulnerability representation."""
    vuln_type: OracleManipulationType
    oracle_type: OracleType
    severity: str
    confidence: float
    line_number: int
    description: str
    code_snippet: str
    attack_vector: str
    financial_impact: str
    exploit_complexity: str
    immunefi_bounty_potential: str
    poc_suggestion: str
    fix_suggestion: str
    context: Dict[str, Any] = field(default_factory=dict)
    
    # Oracle-specific fields
    oracle_address: str = ""
    price_feed: str = ""
    manipulation_method: str = ""
    attack_prerequisites: List[str] = field(default_factory=list)
    mitigation_strategies: List[str] = field(default_factory=list)
    historical_examples: List[str] = field(default_factory=list)
    price_deviation_threshold: float = 0.0
    staleness_threshold: int = 0


class OracleManipulationDetector:
    """Advanced oracle manipulation vulnerability detector."""

    def __init__(self):
        self.oracle_patterns = self._initialize_oracle_patterns()
        self.manipulation_patterns = self._initialize_manipulation_patterns()
        self.validation_patterns = self._initialize_validation_patterns()
        self.historical_attacks = self._load_historical_attacks()
        self.oracle_addresses = self._load_oracle_addresses()

    def _initialize_oracle_patterns(self) -> Dict[OracleType, List[str]]:
        """Initialize oracle-specific patterns."""
        return {
            OracleType.CHAINLINK: [
                r"Chainlink|PriceFeed|AggregatorV3",
                r"latestRoundData|getRoundData",
                r"decimals\(\)|description\(\)",
                r"roundId|startedAt|updatedAt",
                r"answeredInRound|phaseId"
            ],
            OracleType.BAND: [
                r"BandProtocol|StdReference",
                r"getReferenceData|getReferenceDataBulk",
                r"rate|resolve|lastUpdatedBase",
                r"lastUpdatedQuote|base|quote"
            ],
            OracleType.TELLOR: [
                r"Tellor|UsingTellor",
                r"getCurrentValue|getDataBefore",
                r"queryId|timestamp|value",
                r"getIndexForDataBefore|getNewValueCountbyQueryId"
            ],
            OracleType.PYTH: [
                r"Pyth|IPyth",
                r"getPrice|getPriceUnsafe",
                r"priceFeed|priceId",
                r"getEmaPrice|getEmaPriceUnsafe"
            ],
            OracleType.UNISWAP_V2: [
                r"UniswapV2|IUniswapV2",
                r"getReserves|getAmountOut",
                r"pair|factory|router",
                r"token0|token1"
            ],
            OracleType.UNISWAP_V3: [
                r"UniswapV3|IUniswapV3",
                r"getAmount0Delta|getAmount1Delta",
                r"sqrtPriceX96|tick|liquidity",
                r"pool|position|manager"
            ]
        }

    def _initialize_manipulation_patterns(self) -> Dict[OracleManipulationType, List[Dict[str, Any]]]:
        """Initialize oracle manipulation patterns.

        Key design: patterns flag oracle USAGE and then check if required
        validations are MISSING. Validation code (e.g. roundId > 0, updatedAt > 0)
        is a PROTECTION, not a vulnerability. We only report when protections
        are absent.
        """
        return {
            OracleManipulationType.PRICE_MANIPULATION: [
                {
                    "pattern": r"latestRoundData\s*\(\s*\)",
                    "severity": "high",
                    "confidence": 0.6,
                    "description": "Chainlink oracle usage without complete return value validation",
                    "attack_vector": "Stale/invalid price exploitation due to incomplete validation",
                    "financial_impact": "High - Incorrect pricing leads to fund loss",
                    "exploit_complexity": "Medium",
                    "immunefi_bounty_potential": "$10,000-$500,000",
                    "poc_suggestion": "Demonstrate exploitation with stale or zero price",
                    "fix_suggestion": "Validate all return values: require(answer > 0), require(updatedAt > 0), require(answeredInRound >= roundId), check staleness",
                    "manipulation_method": "Incomplete oracle validation",
                    "attack_prerequisites": ["Oracle returns stale/zero data", "Price-sensitive operations"],
                    "mitigation_strategies": ["Complete return value validation", "Staleness checks", "Circuit breakers"],
                    "historical_examples": ["Harvest Finance Oracle Attack ($34M)", "Mango Markets ($116M)"],
                    "required_validations": [
                        r"answer\s*>\s*0|price\s*>\s*0|require\s*\([^)]*answer[^)]*>[^)]*0",
                        r"updatedAt\s*>|block\.timestamp\s*-\s*updatedAt|staleness|maxAge|freshness",
                        r"answeredInRound\s*>=\s*roundId",
                    ],
                    "min_validations_required": 2,
                }
            ],

            OracleManipulationType.STALE_PRICE_ATTACK: [
                {
                    "pattern": r"latestRoundData\s*\(\s*\)",
                    "severity": "medium",
                    "confidence": 0.5,
                    "description": "Oracle price feed without staleness check",
                    "attack_vector": "Stale price exploitation - oracle data may be hours/days old",
                    "financial_impact": "Medium - Stale price enables arbitrage",
                    "exploit_complexity": "Low",
                    "immunefi_bounty_potential": "$1,000-$50,000",
                    "poc_suggestion": "Show exploitation when oracle heartbeat is missed",
                    "fix_suggestion": "Add: require(block.timestamp - updatedAt < MAX_STALENESS)",
                    "manipulation_method": "Stale price exploitation",
                    "attack_prerequisites": ["Oracle heartbeat delay", "Price-sensitive operations"],
                    "mitigation_strategies": ["Staleness threshold check", "Fallback oracle", "Emergency pause"],
                    "required_validations": [
                        r"block\.timestamp\s*-\s*updatedAt|updatedAt\s*\+|maxAge|staleness|heartbeat|STALENESS",
                    ],
                    "min_validations_required": 1,
                }
            ],

            OracleManipulationType.ROUND_ID_MANIPULATION: [
                {
                    "pattern": r"latestRoundData\s*\(\s*\)",
                    "severity": "medium",
                    "confidence": 0.5,
                    "description": "Oracle usage without round completeness validation",
                    "attack_vector": "Incomplete round data exploitation",
                    "financial_impact": "Medium - Using data from incomplete rounds",
                    "exploit_complexity": "High",
                    "immunefi_bounty_potential": "$1,000-$50,000",
                    "poc_suggestion": "Demonstrate incomplete round exploitation",
                    "fix_suggestion": "Add: require(answeredInRound >= roundId)",
                    "manipulation_method": "Incomplete round exploitation",
                    "attack_prerequisites": ["Oracle round incomplete", "Price-sensitive operations"],
                    "mitigation_strategies": ["Round completeness check", "answeredInRound validation"],
                    "required_validations": [
                        r"answeredInRound\s*>=\s*roundId|answeredInRound\s*==\s*roundId",
                    ],
                    "min_validations_required": 1,
                }
            ],

            OracleManipulationType.FLASH_LOAN_ORACLE_ATTACK: [
                {
                    "pattern": r"balanceOf\s*\([^)]*\)\s*/\s*totalSupply|getReserves\s*\(\s*\)\s*[^;]*price",
                    "severity": "critical",
                    "confidence": 0.8,
                    "description": "On-chain spot price used as oracle - vulnerable to flash loan manipulation",
                    "attack_vector": "Flash loan price manipulation via spot price dependency",
                    "financial_impact": "Critical - Protocol drain via single-block price manipulation",
                    "exploit_complexity": "Medium",
                    "immunefi_bounty_potential": "$50,000-$2,000,000",
                    "poc_suggestion": "Demonstrate flash loan attack manipulating spot reserves",
                    "fix_suggestion": "Use off-chain oracle (Chainlink) or TWAP instead of spot price",
                    "manipulation_method": "Flash loan spot price manipulation",
                    "attack_prerequisites": ["Flash loan access", "Spot price dependency"],
                    "mitigation_strategies": ["Use Chainlink/off-chain oracle", "Use TWAP", "Add manipulation resistance"],
                    "historical_examples": ["Harvest Finance ($34M)", "Value DeFi ($6M)", "Cream Finance ($18M)"],
                    "required_validations": [
                        r"twap|timeWeighted|observe\(|consult\(|TWAP",
                        r"Chainlink|AggregatorV3|priceFeed",
                    ],
                    "min_validations_required": 1,
                }
            ],

            OracleManipulationType.ORACLE_FRONT_RUNNING: [
                {
                    "pattern": r"oracle.*update|updatePrice|setPrice|submitValue",
                    "severity": "medium",
                    "confidence": 0.5,
                    "description": "Oracle update mechanism - check for front-running protections",
                    "attack_vector": "Oracle update front-running",
                    "financial_impact": "Medium - Oracle front-running profits",
                    "exploit_complexity": "Medium",
                    "immunefi_bounty_potential": "$1,000-$50,000",
                    "poc_suggestion": "Show oracle update front-running",
                    "fix_suggestion": "Add commit-reveal or private submission for oracle updates",
                    "manipulation_method": "Oracle front-running",
                    "attack_prerequisites": ["Oracle update visibility", "Front-running capability"],
                    "mitigation_strategies": ["Commit-reveal", "Private mempool", "Time delay"],
                    "required_validations": [
                        r"commit.*reveal|commitHash|onlyOracle|onlyReporter|whitelistReporter",
                    ],
                    "min_validations_required": 1,
                }
            ],
        }

    def _initialize_validation_patterns(self) -> Dict[str, List[str]]:
        """Initialize oracle validation patterns."""
        return {
            "price_validation": [
                r"require\s*\(\s*.*price.*>.*0\s*\)",
                r"require\s*\(\s*.*price.*<.*maxPrice\s*\)",
                r"require\s*\(\s*.*price.*>.*minPrice\s*\)"
            ],
            "timestamp_validation": [
                r"require\s*\(\s*.*timestamp.*>.*0\s*\)",
                r"require\s*\(\s*.*updatedAt.*>.*0\s*\)",
                r"require\s*\(\s*.*startedAt.*>.*0\s*\)"
            ],
            "round_validation": [
                r"require\s*\(\s*.*roundId.*>.*0\s*\)",
                r"require\s*\(\s*.*answeredInRound.*>.*0\s*\)",
                r"require\s*\(\s*.*phaseId.*>.*0\s*\)"
            ],
            "freshness_validation": [
                r"require\s*\(\s*.*block\.timestamp.*-.*updatedAt.*<.*maxAge\s*\)",
                r"require\s*\(\s*.*now.*-.*timestamp.*<.*maxAge\s*\)"
            ],
            "deviation_validation": [
                r"require\s*\(\s*.*price.*-.*previousPrice.*<.*maxDeviation\s*\)",
                r"require\s*\(\s*.*abs.*price.*-.*previousPrice.*<.*maxDeviation\s*\)"
            ]
        }

    def _load_historical_attacks(self) -> Dict[OracleManipulationType, List[str]]:
        """Load historical oracle attack examples."""
        return {
            OracleManipulationType.PRICE_MANIPULATION: [
                "Harvest Finance Oracle Attack ($34M)",
                "Value DeFi Oracle Manipulation ($6M)",
                "Cream Finance Oracle Attack ($18M)",
                "bZx Flash Loan Oracle Attack ($1M)"
            ],
            OracleManipulationType.STALE_PRICE_ATTACK: [
                "Alpha Homora Stale Price Attack",
                "Value DeFi Stale Price Attack",
                "Cream Finance Stale Price Attack"
            ],
            OracleManipulationType.FLASH_LOAN_ORACLE_ATTACK: [
                "Harvest Finance Flash Loan Oracle Attack ($34M)",
                "Value DeFi Flash Loan Oracle Attack ($6M)",
                "Cream Finance Flash Loan Oracle Attack ($18M)"
            ],
            OracleManipulationType.AGGREGATION_ATTACK: [
                "Alpha Homora Aggregation Attack",
                "Value DeFi Aggregation Attack"
            ]
        }

    def _load_oracle_addresses(self) -> Dict[str, List[str]]:
        """Load known oracle addresses."""
        return {
            "chainlink": [
                "0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419",  # ETH/USD
                "0x8A753747A1Fa494EC906cE90E9f37563A8AF630e",  # LINK/USD
                "0x2c1d072e956AFFC0d435Cb7AC38EF18d24d9127c"   # BTC/USD
            ],
            "band": [
                "0xDA7a001b254CD22e46d3eAB04d937489c93174C3",  # Band Protocol
                "0x568B8fd03992F56BF240958d22F5a6Fcf7B85086"   # Band Standard Reference
            ],
            "tellor": [
                "0x88dF592F8eb5D7Bd38bFeF7dEb0fBc02cf3778a0",   # Tellor Oracle
                "0xACC2d274Fc6D8C5C5d6C5C5d6C5C5d6C5C5d6C5C"   # Tellor Playground
            ],
            "pyth": [
                "0x4305FB66699C3B2702D4d05CF1c307c6d76561a1",  # Pyth Oracle
                "0x7f5c764cbc14f9669b88837ca1490cca17c31607"   # Pyth USDC
            ]
        }

    def detect_oracle_type(self, content: str) -> List[OracleType]:
        """Detect oracle types from contract content."""
        detected_types = []
        
        for oracle_type, patterns in self.oracle_patterns.items():
            if any(re.search(pattern, content, re.IGNORECASE) for pattern in patterns):
                detected_types.append(oracle_type)
        
        return detected_types

    async def analyze_contract(self, contract_path: str, content: str) -> List[OracleVulnerability]:
        """Analyze contract for oracle manipulation vulnerabilities."""
        vulnerabilities = []
        
        # Detect oracle types
        oracle_types = self.detect_oracle_type(content)
        if not oracle_types:
            return vulnerabilities
        
        lines = content.split('\n')
        
        # Analyze each manipulation type
        for vuln_type, patterns in self.manipulation_patterns.items():
            for pattern_info in patterns:
                pattern = pattern_info["pattern"]
                regex = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                
                for match in regex.finditer(content):
                    line_number = content[:match.start()].count('\n') + 1

                    # Check if required validations exist in contract
                    required_validations = pattern_info.get("required_validations", [])
                    min_required = pattern_info.get("min_validations_required", 1)

                    validations_found = 0
                    validations_present = []
                    for validation_pattern in required_validations:
                        if re.search(validation_pattern, content, re.IGNORECASE):
                            validations_found += 1
                            validations_present.append(validation_pattern)

                    # Skip if sufficient validations are present
                    if validations_found >= min_required:
                        continue

                    # Extract code snippet with context
                    start_line = max(0, line_number - 3)
                    end_line = min(len(lines), line_number + 3)
                    code_snippet = '\n'.join(lines[start_line:end_line])
                    
                    # Determine oracle type
                    oracle_type = self._determine_oracle_type_from_match(match.group(), oracle_types)
                    
                    vulnerability = OracleVulnerability(
                        vuln_type=vuln_type,
                        oracle_type=oracle_type,
                        severity=pattern_info["severity"],
                        confidence=pattern_info["confidence"],
                        line_number=line_number,
                        description=pattern_info["description"],
                        code_snippet=code_snippet,
                        attack_vector=pattern_info["attack_vector"],
                        financial_impact=pattern_info["financial_impact"],
                        exploit_complexity=pattern_info["exploit_complexity"],
                        immunefi_bounty_potential=pattern_info["immunefi_bounty_potential"],
                        poc_suggestion=pattern_info["poc_suggestion"],
                        fix_suggestion=pattern_info["fix_suggestion"],
                        context={
                            "pattern_match": match.group(),
                            "contract_path": contract_path,
                            "vulnerability_type": vuln_type.value,
                            "oracle_type": oracle_type.value
                        },
                        manipulation_method=pattern_info.get("manipulation_method", ""),
                        attack_prerequisites=pattern_info.get("attack_prerequisites", []),
                        mitigation_strategies=pattern_info.get("mitigation_strategies", []),
                        historical_examples=pattern_info.get("historical_examples", [])
                    )
                    
                    # Apply additional validation
                    if await self._validate_oracle_vulnerability(vulnerability, content):
                        vulnerabilities.append(vulnerability)
        
        # Add oracle-specific analysis
        vulnerabilities.extend(await self._analyze_oracle_specific_patterns(content, contract_path, oracle_types))
        
        return vulnerabilities

    def _determine_oracle_type_from_match(self, match_text: str, oracle_types: List[OracleType]) -> OracleType:
        """Determine oracle type from match text."""
        match_lower = match_text.lower()
        
        for oracle_type in oracle_types:
            if oracle_type.value.replace("_", "") in match_lower:
                return oracle_type
        
        return oracle_types[0] if oracle_types else OracleType.CUSTOM

    async def _validate_oracle_vulnerability(self, vulnerability: OracleVulnerability, content: str) -> bool:
        """Validate oracle vulnerability with additional context checks."""
        
        # Check for oracle protection patterns
        protection_patterns = {
            OracleManipulationType.PRICE_MANIPULATION: [
                r"price.*validation|price.*check",
                r"circuitBreaker|emergencyStop",
                r"multiple.*oracle|oracle.*aggregation"
            ],
            OracleManipulationType.STALE_PRICE_ATTACK: [
                r"timestamp.*validation|freshness.*check",
                r"updatedAt.*validation|startedAt.*validation",
                r"maxAge|staleness.*check"
            ],
            OracleManipulationType.ROUND_ID_MANIPULATION: [
                r"roundId.*validation|answeredInRound.*validation",
                r"phaseId.*validation|comprehensive.*validation",
                r"round.*check|phase.*check"
            ],
            OracleManipulationType.TIMESTAMP_MANIPULATION: [
                r"timestamp.*validation|time.*validation",
                r"freshness.*check|age.*check",
                r"maxAge|staleness.*threshold"
            ],
            OracleManipulationType.AGGREGATION_ATTACK: [
                r"aggregation.*validation|outlier.*detection",
                r"median.*pricing|price.*aggregation",
                r"multiple.*source.*validation"
            ],
            OracleManipulationType.FLASH_LOAN_ORACLE_ATTACK: [
                r"flash.*loan.*protection|anti.*flash.*loan",
                r"oracle.*validation|price.*validation",
                r"circuitBreaker|emergencyStop"
            ]
        }
        
        vuln_type = vulnerability.vuln_type
        if vuln_type in protection_patterns:
            for pattern in protection_patterns[vuln_type]:
                if re.search(pattern, content, re.IGNORECASE):
                    # Protection found, reduce confidence
                    vulnerability.confidence *= 0.5
                    vulnerability.context["protection_found"] = pattern
        
        # Only report vulnerabilities with sufficient confidence
        return vulnerability.confidence > 0.5

    def _check_l2_sequencer_feed(self, content: str) -> bool:
        """Check if contract handles L2 sequencer uptime feed (Arbitrum/Optimism)."""
        l2_patterns = [
            r"sequencerUptimeFeed|SEQUENCER_UPTIME_FEED",
            r"isSequencerUp|sequencerUp",
            r"gracePeriod|GRACE_PERIOD_TIME",
        ]
        return any(re.search(p, content, re.IGNORECASE) for p in l2_patterns)

    def _check_l2_sequencer_missing(self, content: str, contract_path: str) -> List[OracleVulnerability]:
        """Detect Chainlink usage on L2 without sequencer uptime feed check."""
        vulnerabilities = []

        # Detect L2 indicators in the contract
        l2_indicators = [
            r"Arbitrum|arbitrum|ARBITRUM",
            r"Optimism|optimism|OPTIMISM",
            r"L2|layer2|layerTwo",
            r"arbSys|ArbSys",
            r"iOVM|OVM_|optimismPortal",
        ]
        is_l2 = any(re.search(p, content) for p in l2_indicators)
        if not is_l2:
            return vulnerabilities

        # Contract uses Chainlink on L2 — check for sequencer feed
        if self._check_l2_sequencer_feed(content):
            return vulnerabilities

        # Find first latestRoundData call for the line number
        match = re.search(r"latestRoundData\s*\(\s*\)", content)
        if not match:
            return vulnerabilities

        line_number = content[:match.start()].count('\n') + 1
        lines = content.split('\n')
        start_line = max(0, line_number - 3)
        end_line = min(len(lines), line_number + 3)
        code_snippet = '\n'.join(lines[start_line:end_line])

        vulnerabilities.append(OracleVulnerability(
            vuln_type=OracleManipulationType.PRICE_MANIPULATION,
            oracle_type=OracleType.CHAINLINK,
            severity="high",
            confidence=0.75,
            line_number=line_number,
            description="Chainlink oracle on L2 without sequencer uptime feed check — prices may be stale during sequencer downtime",
            code_snippet=code_snippet,
            attack_vector="L2 sequencer downtime allows stale Chainlink prices to be used for critical operations",
            financial_impact="High - Stale prices during L2 sequencer outage enable arbitrage and liquidation exploits",
            exploit_complexity="Low",
            immunefi_bounty_potential="$10,000-$100,000",
            poc_suggestion="Demonstrate stale price exploitation during simulated sequencer downtime on Arbitrum/Optimism",
            fix_suggestion="Add sequencer uptime feed check: query sequencerUptimeFeed, require sequencer is up, enforce grace period after restart",
            context={"contract_path": contract_path, "check_type": "l2_sequencer_missing"},
            manipulation_method="L2 sequencer downtime stale price exploitation",
            attack_prerequisites=["L2 deployment (Arbitrum/Optimism)", "Sequencer downtime event"],
            mitigation_strategies=["Check sequencerUptimeFeed", "Enforce grace period after sequencer restart", "Pause protocol during downtime"],
            historical_examples=["Arbitrum sequencer downtime events", "Optimism sequencer outage incidents"],
        ))

        return vulnerabilities

    def _check_cross_oracle_arbitrage(self, content: str, contract_path: str, oracle_types: List[OracleType]) -> List[OracleVulnerability]:
        """Detect contracts using 2+ oracle sources without price deviation check."""
        vulnerabilities = []

        # Collect all price-fetching call sites
        price_call_patterns = [
            (r"latestRoundData\s*\(\s*\)", "Chainlink"),
            (r"getReferenceData\s*\([^)]*\)", "Band"),
            (r"getCurrentValue\s*\([^)]*\)", "Tellor"),
            (r"getPrice\s*\([^)]*\)|getPriceUnsafe\s*\([^)]*\)", "Pyth"),
            (r"getReserves\s*\(\s*\)", "UniswapV2"),
        ]

        found_sources: List[Tuple[str, int]] = []
        for pattern, source_name in price_call_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_number = content[:match.start()].count('\n') + 1
                found_sources.append((source_name, line_number))

        # Need 2+ distinct oracle source types to flag cross-oracle arbitrage
        distinct_sources = set(s[0] for s in found_sources)
        if len(distinct_sources) < 2:
            return vulnerabilities

        # Check if a deviation/comparison check exists between prices
        deviation_patterns = [
            r"abs\s*\([^)]*price[^)]*-[^)]*price[^)]*\)",
            r"price.*-.*price.*<.*threshold|price.*-.*price.*<.*deviation",
            r"maxDeviation|priceDeviation|priceDiff|priceSpread",
            r"require\s*\([^)]*price[^)]*-[^)]*price",
            r"deviation.*check|spread.*check",
        ]
        has_deviation_check = any(
            re.search(p, content, re.IGNORECASE) for p in deviation_patterns
        )
        if has_deviation_check:
            return vulnerabilities

        # Report at the first oracle call site
        first_line = min(s[1] for s in found_sources)
        lines = content.split('\n')
        start_line = max(0, first_line - 3)
        end_line = min(len(lines), first_line + 3)
        code_snippet = '\n'.join(lines[start_line:end_line])

        source_list = ", ".join(sorted(distinct_sources))
        vulnerabilities.append(OracleVulnerability(
            vuln_type=OracleManipulationType.CROSS_ORACLE_ARBITRAGE,
            oracle_type=OracleType.AGGREGATED,
            severity="high",
            confidence=0.7,
            line_number=first_line,
            description=f"Contract uses multiple oracle sources ({source_list}) without cross-price deviation check — arbitrage between feeds possible",
            code_snippet=code_snippet,
            attack_vector="Attacker exploits price divergence between oracle feeds when no deviation threshold enforced",
            financial_impact="High - Cross-oracle price discrepancy enables risk-free arbitrage or unfair liquidations",
            exploit_complexity="Medium",
            immunefi_bounty_potential="$10,000-$250,000",
            poc_suggestion="Show that when oracle feeds diverge beyond a threshold, attacker can profit by choosing the favorable price path",
            fix_suggestion="Add cross-price deviation check: require(abs(priceA - priceB) * 10000 / priceA < maxDeviationBps)",
            context={"contract_path": contract_path, "oracle_sources": sorted(distinct_sources)},
            manipulation_method="Cross-oracle price divergence arbitrage",
            attack_prerequisites=["Multiple oracle sources", "No deviation check between feeds"],
            mitigation_strategies=["Cross-price deviation threshold", "Use single canonical oracle", "Median-of-three pricing"],
            historical_examples=["Mango Markets cross-oracle exploit ($116M)"],
        ))

        return vulnerabilities

    def _check_twap_manipulation(self, content: str, contract_path: str) -> List[OracleVulnerability]:
        """Detect short TWAP observation windows vulnerable to manipulation."""
        vulnerabilities = []

        # Detect TWAP usage patterns
        twap_patterns = [
            r"observe\s*\(",
            r"consult\s*\(",
            r"twap|TWAP|timeWeightedAverage",
            r"getTimeWeightedTick",
            r"OracleLibrary\.consult",
        ]
        has_twap = any(re.search(p, content) for p in twap_patterns)
        if not has_twap:
            return vulnerabilities

        lines = content.split('\n')

        # Look for short period constants or inline period values
        # Match numeric literals that could be TWAP periods (in seconds)
        short_period_patterns = [
            # observe([secondsAgo, 0]) or similar with small values
            (r"observe\s*\(\s*\[?\s*(\d+)", "observe"),
            # consult(pool, period) with small period
            (r"consult\s*\([^,]*,\s*(\d+)", "consult"),
            # secondsAgo = N or period = N with small N
            (r"(?:secondsAgo|period|twapPeriod|twapInterval|window)\s*=\s*(\d+)", "assignment"),
            # uint32 constant declarations for TWAP period
            (r"(?:TWAP_PERIOD|PERIOD|WINDOW|INTERVAL|SECONDS_AGO)\s*=\s*(\d+)", "constant"),
        ]

        for pattern, match_type in short_period_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                period_value = int(match.group(1))
                # Flag periods under 1800 seconds (30 minutes)
                if period_value > 0 and period_value < 1800:
                    line_number = content[:match.start()].count('\n') + 1
                    start_line = max(0, line_number - 3)
                    end_line = min(len(lines), line_number + 3)
                    code_snippet = '\n'.join(lines[start_line:end_line])

                    vulnerabilities.append(OracleVulnerability(
                        vuln_type=OracleManipulationType.PRICE_MANIPULATION,
                        oracle_type=OracleType.UNISWAP_V3,
                        severity="high",
                        confidence=0.75,
                        line_number=line_number,
                        description=f"TWAP oracle uses short observation window ({period_value}s) — vulnerable to single-block or multi-block manipulation",
                        code_snippet=code_snippet,
                        attack_vector="Attacker manipulates pool price for short duration to skew TWAP; shorter windows are easier and cheaper to attack",
                        financial_impact="High - Short TWAP window can be manipulated within a few blocks for protocol drain",
                        exploit_complexity="Medium",
                        immunefi_bounty_potential="$10,000-$500,000",
                        poc_suggestion="Demonstrate TWAP manipulation over the short window using flash loan or multi-block MEV",
                        fix_suggestion=f"Increase TWAP window to at least 1800 seconds (30 minutes); current value is {period_value}s",
                        context={"contract_path": contract_path, "twap_period": period_value, "match_type": match_type},
                        manipulation_method="Short TWAP window manipulation",
                        attack_prerequisites=["Short TWAP observation period", "Sufficient liquidity to move price"],
                        mitigation_strategies=["Use TWAP window >= 30 minutes", "Add manipulation-resistant bounds", "Use Chainlink as primary oracle"],
                        historical_examples=["Euler Finance TWAP manipulation", "Rari Fuse pool TWAP attacks"],
                    ))
                    break  # One finding per pattern type is sufficient

        return vulnerabilities

    def _check_pyth_confidence_interval(self, content: str, contract_path: str) -> List[OracleVulnerability]:
        """Detect Pyth oracle usage without confidence interval validation."""
        vulnerabilities = []

        # Find Pyth price retrieval calls
        pyth_price_patterns = [
            r"getPrice\s*\([^)]*\)",
            r"getPriceUnsafe\s*\([^)]*\)",
            r"getPriceNoOlderThan\s*\([^)]*\)",
            r"getEmaPrice\s*\([^)]*\)",
            r"getEmaPriceUnsafe\s*\([^)]*\)",
        ]

        has_pyth_price = False
        first_match = None
        for pattern in pyth_price_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                has_pyth_price = True
                if first_match is None or match.start() < first_match.start():
                    first_match = match

        if not has_pyth_price or first_match is None:
            return vulnerabilities

        # Check if confidence field is validated
        confidence_patterns = [
            r"\.conf\b",
            r"confidence",
            r"require\s*\([^)]*conf[^)]*<",
            r"conf\s*[<>]=?\s*\d",
            r"price\.conf",
            r"maxConfWidth|confidenceRatio|confRatio",
        ]
        has_confidence_check = any(
            re.search(p, content, re.IGNORECASE) for p in confidence_patterns
        )
        if has_confidence_check:
            return vulnerabilities

        line_number = content[:first_match.start()].count('\n') + 1
        lines = content.split('\n')
        start_line = max(0, line_number - 3)
        end_line = min(len(lines), line_number + 3)
        code_snippet = '\n'.join(lines[start_line:end_line])

        vulnerabilities.append(OracleVulnerability(
            vuln_type=OracleManipulationType.PRICE_MANIPULATION,
            oracle_type=OracleType.PYTH,
            severity="medium",
            confidence=0.7,
            line_number=line_number,
            description="Pyth oracle price used without checking confidence interval — wide confidence means unreliable price",
            code_snippet=code_snippet,
            attack_vector="Attacker exploits periods of high price uncertainty when Pyth confidence interval is wide but contract trusts the price blindly",
            financial_impact="Medium - Unreliable price during high volatility leads to unfavorable trades or liquidations",
            exploit_complexity="Low",
            immunefi_bounty_potential="$5,000-$50,000",
            poc_suggestion="Show that during a period of wide Pyth confidence, the price can deviate significantly from true market price",
            fix_suggestion="Validate Pyth confidence: require(price.conf * MAX_CONF_WIDTH < price.price) to reject wide-spread prices",
            context={"contract_path": contract_path, "check_type": "pyth_confidence_missing"},
            manipulation_method="Pyth wide confidence interval exploitation",
            attack_prerequisites=["Pyth oracle usage", "Period of high price uncertainty"],
            mitigation_strategies=["Check price.conf relative to price.price", "Set maxConfWidth threshold", "Pause on excessive confidence spread"],
            historical_examples=["Pyth confidence interval issues on Solana DeFi protocols"],
        ))

        return vulnerabilities

    async def _analyze_oracle_specific_patterns(self, content: str, contract_path: str, oracle_types: List[OracleType]) -> List[OracleVulnerability]:
        """Analyze oracle-specific patterns."""
        vulnerabilities = []

        for oracle_type in oracle_types:
            if oracle_type == OracleType.CHAINLINK:
                vulnerabilities.extend(await self._analyze_chainlink_patterns(content, contract_path))
                # Check for missing L2 sequencer feed on L2-targeted Chainlink usage
                vulnerabilities.extend(self._check_l2_sequencer_missing(content, contract_path))
            elif oracle_type == OracleType.BAND:
                vulnerabilities.extend(await self._analyze_band_patterns(content, contract_path))
            elif oracle_type == OracleType.TELLOR:
                vulnerabilities.extend(await self._analyze_tellor_patterns(content, contract_path))
            elif oracle_type == OracleType.PYTH:
                vulnerabilities.extend(await self._analyze_pyth_patterns(content, contract_path))
                # Check for missing Pyth confidence interval validation
                vulnerabilities.extend(self._check_pyth_confidence_interval(content, contract_path))
            elif oracle_type == OracleType.UNISWAP_V2:
                vulnerabilities.extend(await self._analyze_uniswap_v2_patterns(content, contract_path))
            elif oracle_type == OracleType.UNISWAP_V3:
                vulnerabilities.extend(await self._analyze_uniswap_v3_patterns(content, contract_path))

        # Cross-oracle checks (need 2+ oracle sources)
        if len(oracle_types) >= 2:
            vulnerabilities.extend(self._check_cross_oracle_arbitrage(content, contract_path, oracle_types))

        # TWAP manipulation check for Uniswap oracles
        if OracleType.UNISWAP_V3 in oracle_types or OracleType.UNISWAP_V2 in oracle_types:
            vulnerabilities.extend(self._check_twap_manipulation(content, contract_path))

        return vulnerabilities

    async def _analyze_chainlink_patterns(self, content: str, contract_path: str) -> List[OracleVulnerability]:
        """Analyze Chainlink-specific patterns."""
        vulnerabilities = []
        
        # Check for Chainlink-specific vulnerabilities
        chainlink_patterns = [
            {
                "pattern": r"latestRoundData\(\)",
                "vuln_type": OracleManipulationType.PRICE_MANIPULATION,
                "severity": "high",
                "confidence": 0.8,
                "description": "Chainlink latestRoundData without validation",
                "attack_vector": "Chainlink price manipulation",
                "financial_impact": "High - Chainlink price manipulation",
                "exploit_complexity": "Medium",
                "immunefi_bounty_potential": "$10,000-$250,000"
            },
            {
                "pattern": r"getRoundData\([^)]*\)",
                "vuln_type": OracleManipulationType.ROUND_ID_MANIPULATION,
                "severity": "medium",
                "confidence": 0.6,
                "description": "Chainlink getRoundData without validation",
                "attack_vector": "Chainlink round manipulation",
                "financial_impact": "Medium - Chainlink round manipulation",
                "exploit_complexity": "Medium",
                "immunefi_bounty_potential": "$5,000-$50,000"
            }
        ]
        
        for pattern_info in chainlink_patterns:
            pattern = pattern_info["pattern"]
            regex = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            
            for match in regex.finditer(content):
                line_number = content[:match.start()].count('\n') + 1
                
                vulnerability = OracleVulnerability(
                    vuln_type=pattern_info["vuln_type"],
                    oracle_type=OracleType.CHAINLINK,
                    severity=pattern_info["severity"],
                    confidence=pattern_info["confidence"],
                    line_number=line_number,
                    description=pattern_info["description"],
                    code_snippet=match.group(),
                    attack_vector=pattern_info["attack_vector"],
                    financial_impact=pattern_info["financial_impact"],
                    exploit_complexity=pattern_info["exploit_complexity"],
                    immunefi_bounty_potential=pattern_info["immunefi_bounty_potential"],
                    poc_suggestion="Demonstrate Chainlink-specific attack",
                    fix_suggestion="Add Chainlink-specific validation",
                    context={"pattern_match": match.group(), "contract_path": contract_path},
                    oracle_address="Chainlink",
                    price_feed="Chainlink Price Feed"
                )
                
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities

    async def _analyze_band_patterns(self, content: str, contract_path: str) -> List[OracleVulnerability]:
        """Analyze Band Protocol-specific patterns."""
        vulnerabilities = []
        
        # Check for Band-specific vulnerabilities
        band_patterns = [
            {
                "pattern": r"getReferenceData\([^)]*\)",
                "vuln_type": OracleManipulationType.PRICE_MANIPULATION,
                "severity": "high",
                "confidence": 0.8,
                "description": "Band getReferenceData without validation",
                "attack_vector": "Band price manipulation",
                "financial_impact": "High - Band price manipulation",
                "exploit_complexity": "Medium",
                "immunefi_bounty_potential": "$10,000-$250,000"
            }
        ]
        
        for pattern_info in band_patterns:
            pattern = pattern_info["pattern"]
            regex = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            
            for match in regex.finditer(content):
                line_number = content[:match.start()].count('\n') + 1
                
                vulnerability = OracleVulnerability(
                    vuln_type=pattern_info["vuln_type"],
                    oracle_type=OracleType.BAND,
                    severity=pattern_info["severity"],
                    confidence=pattern_info["confidence"],
                    line_number=line_number,
                    description=pattern_info["description"],
                    code_snippet=match.group(),
                    attack_vector=pattern_info["attack_vector"],
                    financial_impact=pattern_info["financial_impact"],
                    exploit_complexity=pattern_info["exploit_complexity"],
                    immunefi_bounty_potential=pattern_info["immunefi_bounty_potential"],
                    poc_suggestion="Demonstrate Band-specific attack",
                    fix_suggestion="Add Band-specific validation",
                    context={"pattern_match": match.group(), "contract_path": contract_path},
                    oracle_address="Band Protocol",
                    price_feed="Band Reference Data"
                )
                
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities

    async def _analyze_tellor_patterns(self, content: str, contract_path: str) -> List[OracleVulnerability]:
        """Analyze Tellor-specific patterns."""
        vulnerabilities = []
        
        # Check for Tellor-specific vulnerabilities
        tellor_patterns = [
            {
                "pattern": r"getCurrentValue\([^)]*\)",
                "vuln_type": OracleManipulationType.PRICE_MANIPULATION,
                "severity": "high",
                "confidence": 0.8,
                "description": "Tellor getCurrentValue without validation",
                "attack_vector": "Tellor price manipulation",
                "financial_impact": "High - Tellor price manipulation",
                "exploit_complexity": "Medium",
                "immunefi_bounty_potential": "$10,000-$250,000"
            }
        ]
        
        for pattern_info in tellor_patterns:
            pattern = pattern_info["pattern"]
            regex = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            
            for match in regex.finditer(content):
                line_number = content[:match.start()].count('\n') + 1
                
                vulnerability = OracleVulnerability(
                    vuln_type=pattern_info["vuln_type"],
                    oracle_type=OracleType.TELLOR,
                    severity=pattern_info["severity"],
                    confidence=pattern_info["confidence"],
                    line_number=line_number,
                    description=pattern_info["description"],
                    code_snippet=match.group(),
                    attack_vector=pattern_info["attack_vector"],
                    financial_impact=pattern_info["financial_impact"],
                    exploit_complexity=pattern_info["exploit_complexity"],
                    immunefi_bounty_potential=pattern_info["immunefi_bounty_potential"],
                    poc_suggestion="Demonstrate Tellor-specific attack",
                    fix_suggestion="Add Tellor-specific validation",
                    context={"pattern_match": match.group(), "contract_path": contract_path},
                    oracle_address="Tellor Oracle",
                    price_feed="Tellor Price Feed"
                )
                
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities

    async def _analyze_pyth_patterns(self, content: str, contract_path: str) -> List[OracleVulnerability]:
        """Analyze Pyth-specific patterns."""
        vulnerabilities = []
        
        # Check for Pyth-specific vulnerabilities
        pyth_patterns = [
            {
                "pattern": r"getPrice\([^)]*\)",
                "vuln_type": OracleManipulationType.PRICE_MANIPULATION,
                "severity": "high",
                "confidence": 0.8,
                "description": "Pyth getPrice without validation",
                "attack_vector": "Pyth price manipulation",
                "financial_impact": "High - Pyth price manipulation",
                "exploit_complexity": "Medium",
                "immunefi_bounty_potential": "$10,000-$250,000"
            }
        ]
        
        for pattern_info in pyth_patterns:
            pattern = pattern_info["pattern"]
            regex = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            
            for match in regex.finditer(content):
                line_number = content[:match.start()].count('\n') + 1
                
                vulnerability = OracleVulnerability(
                    vuln_type=pattern_info["vuln_type"],
                    oracle_type=OracleType.PYTH,
                    severity=pattern_info["severity"],
                    confidence=pattern_info["confidence"],
                    line_number=line_number,
                    description=pattern_info["description"],
                    code_snippet=match.group(),
                    attack_vector=pattern_info["attack_vector"],
                    financial_impact=pattern_info["financial_impact"],
                    exploit_complexity=pattern_info["exploit_complexity"],
                    immunefi_bounty_potential=pattern_info["immunefi_bounty_potential"],
                    poc_suggestion="Demonstrate Pyth-specific attack",
                    fix_suggestion="Add Pyth-specific validation",
                    context={"pattern_match": match.group(), "contract_path": contract_path},
                    oracle_address="Pyth Oracle",
                    price_feed="Pyth Price Feed"
                )
                
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities

    async def _analyze_uniswap_v2_patterns(self, content: str, contract_path: str) -> List[OracleVulnerability]:
        """Analyze Uniswap V2-specific patterns."""
        vulnerabilities = []
        
        # Check for Uniswap V2-specific vulnerabilities
        uniswap_v2_patterns = [
            {
                "pattern": r"getReserves\(\)",
                "vuln_type": OracleManipulationType.PRICE_MANIPULATION,
                "severity": "high",
                "confidence": 0.8,
                "description": "Uniswap V2 getReserves without validation",
                "attack_vector": "Uniswap V2 price manipulation",
                "financial_impact": "High - Uniswap V2 price manipulation",
                "exploit_complexity": "Medium",
                "immunefi_bounty_potential": "$10,000-$250,000"
            }
        ]
        
        for pattern_info in uniswap_v2_patterns:
            pattern = pattern_info["pattern"]
            regex = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            
            for match in regex.finditer(content):
                line_number = content[:match.start()].count('\n') + 1
                
                vulnerability = OracleVulnerability(
                    vuln_type=pattern_info["vuln_type"],
                    oracle_type=OracleType.UNISWAP_V2,
                    severity=pattern_info["severity"],
                    confidence=pattern_info["confidence"],
                    line_number=line_number,
                    description=pattern_info["description"],
                    code_snippet=match.group(),
                    attack_vector=pattern_info["attack_vector"],
                    financial_impact=pattern_info["financial_impact"],
                    exploit_complexity=pattern_info["exploit_complexity"],
                    immunefi_bounty_potential=pattern_info["immunefi_bounty_potential"],
                    poc_suggestion="Demonstrate Uniswap V2-specific attack",
                    fix_suggestion="Add Uniswap V2-specific validation",
                    context={"pattern_match": match.group(), "contract_path": contract_path},
                    oracle_address="Uniswap V2 Pair",
                    price_feed="Uniswap V2 Reserves"
                )
                
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities

    async def _analyze_uniswap_v3_patterns(self, content: str, contract_path: str) -> List[OracleVulnerability]:
        """Analyze Uniswap V3-specific patterns."""
        vulnerabilities = []
        
        # Check for Uniswap V3-specific vulnerabilities
        uniswap_v3_patterns = [
            {
                "pattern": r"getAmount0Delta\([^)]*\)|getAmount1Delta\([^)]*\)",
                "vuln_type": OracleManipulationType.PRICE_MANIPULATION,
                "severity": "high",
                "confidence": 0.8,
                "description": "Uniswap V3 getAmount0Delta/getAmount1Delta without validation",
                "attack_vector": "Uniswap V3 price manipulation",
                "financial_impact": "High - Uniswap V3 price manipulation",
                "exploit_complexity": "High",
                "immunefi_bounty_potential": "$10,000-$250,000"
            }
        ]
        
        for pattern_info in uniswap_v3_patterns:
            pattern = pattern_info["pattern"]
            regex = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            
            for match in regex.finditer(content):
                line_number = content[:match.start()].count('\n') + 1
                
                vulnerability = OracleVulnerability(
                    vuln_type=pattern_info["vuln_type"],
                    oracle_type=OracleType.UNISWAP_V3,
                    severity=pattern_info["severity"],
                    confidence=pattern_info["confidence"],
                    line_number=line_number,
                    description=pattern_info["description"],
                    code_snippet=match.group(),
                    attack_vector=pattern_info["attack_vector"],
                    financial_impact=pattern_info["financial_impact"],
                    exploit_complexity=pattern_info["exploit_complexity"],
                    immunefi_bounty_potential=pattern_info["immunefi_bounty_potential"],
                    poc_suggestion="Demonstrate Uniswap V3-specific attack",
                    fix_suggestion="Add Uniswap V3-specific validation",
                    context={"pattern_match": match.group(), "contract_path": contract_path},
                    oracle_address="Uniswap V3 Pool",
                    price_feed="Uniswap V3 Price"
                )
                
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities

    def generate_oracle_poc_suggestion(self, vulnerability: OracleVulnerability) -> str:
        """Generate oracle-specific proof-of-concept suggestion."""
        
        poc_templates = {
            OracleType.CHAINLINK: """
// Chainlink Oracle Manipulation PoC
contract ChainlinkOracleAttack {{
    function exploitChainlinkOracle() external {{
        // 1. Manipulate Chainlink price feed
        // 2. Execute trade at manipulated price
        // 3. Profit from price difference
        
        // Oracle: Chainlink
        // Vulnerability: {vuln_type}
        // Severity: {severity}
        // Bounty Potential: {bounty_potential}
    }}
}}
            """,
            OracleType.BAND: """
// Band Protocol Oracle Manipulation PoC
contract BandOracleAttack {{
    function exploitBandOracle() external {{
        // 1. Manipulate Band reference data
        // 2. Execute trade at manipulated price
        // 3. Profit from price difference
        
        // Oracle: Band Protocol
        // Vulnerability: {vuln_type}
        // Severity: {severity}
        // Bounty Potential: {bounty_potential}
    }}
}}
            """,
            OracleType.TELLOR: """
// Tellor Oracle Manipulation PoC
contract TellorOracleAttack {{
    function exploitTellorOracle() external {{
        // 1. Manipulate Tellor price feed
        // 2. Execute trade at manipulated price
        // 3. Profit from price difference
        
        // Oracle: Tellor
        // Vulnerability: {vuln_type}
        // Severity: {severity}
        // Bounty Potential: {bounty_potential}
    }}
}}
            """,
            OracleType.PYTH: """
// Pyth Oracle Manipulation PoC
contract PythOracleAttack {{
    function exploitPythOracle() external {{
        // 1. Manipulate Pyth price feed
        // 2. Execute trade at manipulated price
        // 3. Profit from price difference
        
        // Oracle: Pyth
        // Vulnerability: {vuln_type}
        // Severity: {severity}
        // Bounty Potential: {bounty_potential}
    }}
}}
            """,
            OracleType.UNISWAP_V2: """
// Uniswap V2 Oracle Manipulation PoC
contract UniswapV2OracleAttack {{
    function exploitUniswapV2Oracle() external {{
        // 1. Manipulate Uniswap V2 reserves
        // 2. Execute trade at manipulated price
        // 3. Profit from price difference
        
        // Oracle: Uniswap V2
        // Vulnerability: {vuln_type}
        // Severity: {severity}
        // Bounty Potential: {bounty_potential}
    }}
}}
            """,
            OracleType.UNISWAP_V3: """
// Uniswap V3 Oracle Manipulation PoC
contract UniswapV3OracleAttack {{
    function exploitUniswapV3Oracle() external {{
        // 1. Manipulate Uniswap V3 price
        // 2. Execute trade at manipulated price
        // 3. Profit from price difference
        
        // Oracle: Uniswap V3
        // Vulnerability: {vuln_type}
        // Severity: {severity}
        // Bounty Potential: {bounty_potential}
    }}
}}
            """
        }
        
        template = poc_templates.get(vulnerability.oracle_type, "// Oracle PoC template not available")
        return template.format(
            vuln_type=vulnerability.vuln_type.value,
            severity=vulnerability.severity,
            bounty_potential=vulnerability.immunefi_bounty_potential
        )

    def generate_comprehensive_oracle_report(self, vulnerabilities: List[OracleVulnerability]) -> Dict[str, Any]:
        """Generate comprehensive oracle vulnerability report."""
        
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
            "bounty_potential": {
                "estimated_total": "$0",
                "breakdown": {}
            },
            "oracle_analysis": {},
            "manipulation_analysis": {}
        }
        
        # Process vulnerabilities
        for vuln in vulnerabilities:
            vuln_data = {
                "type": vuln.vuln_type.value,
                "oracle_type": vuln.oracle_type.value,
                "severity": vuln.severity,
                "confidence": vuln.confidence,
                "line_number": vuln.line_number,
                "description": vuln.description,
                "attack_vector": vuln.attack_vector,
                "financial_impact": vuln.financial_impact,
                "exploit_complexity": vuln.exploit_complexity,
                "immunefi_bounty_potential": vuln.immunefi_bounty_potential,
                "poc_suggestion": vuln.poc_suggestion,
                "fix_suggestion": vuln.fix_suggestion,
                "code_snippet": vuln.code_snippet,
                "oracle_address": vuln.oracle_address,
                "price_feed": vuln.price_feed,
                "manipulation_method": vuln.manipulation_method,
                "attack_prerequisites": vuln.attack_prerequisites,
                "mitigation_strategies": vuln.mitigation_strategies,
                "historical_examples": vuln.historical_examples,
                "price_deviation_threshold": vuln.price_deviation_threshold,
                "staleness_threshold": vuln.staleness_threshold
            }
            report["vulnerabilities"].append(vuln_data)
        
        # Generate recommendations
        unique_fixes = set(v.fix_suggestion for v in vulnerabilities)
        report["recommendations"] = list(unique_fixes)
        
        # Calculate bounty potential
        bounty_total = 0
        for vuln in vulnerabilities:
            bounty_range = vuln.immunefi_bounty_potential
            # Extract minimum bounty value
            min_bounty = re.search(r'\$([0-9,]+)', bounty_range)
            if min_bounty:
                min_value = int(min_bounty.group(1).replace(',', ''))
                bounty_total += min_value
        
        report["bounty_potential"]["estimated_total"] = f"${bounty_total:,}"
        
        # Analyze oracle distribution
        oracle_analysis = {}
        for vuln in vulnerabilities:
            oracle_type = vuln.oracle_type.value
            if oracle_type not in oracle_analysis:
                oracle_analysis[oracle_type] = {
                    "vulnerability_count": 0,
                    "severity_distribution": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                    "vulnerability_types": set(),
                    "manipulation_methods": set()
                }
            oracle_analysis[oracle_type]["vulnerability_count"] += 1
            oracle_analysis[oracle_type]["severity_distribution"][vuln.severity] += 1
            oracle_analysis[oracle_type]["vulnerability_types"].add(vuln.vuln_type.value)
            oracle_analysis[oracle_type]["manipulation_methods"].add(vuln.manipulation_method)
        
        # Convert sets to lists for JSON serialization
        for oracle_info in oracle_analysis.values():
            oracle_info["vulnerability_types"] = list(oracle_info["vulnerability_types"])
            oracle_info["manipulation_methods"] = list(oracle_info["manipulation_methods"])
        
        report["oracle_analysis"] = oracle_analysis
        
        # Analyze manipulation distribution
        manipulation_analysis = {}
        for vuln in vulnerabilities:
            manipulation_type = vuln.vuln_type.value
            if manipulation_type not in manipulation_analysis:
                manipulation_analysis[manipulation_type] = {
                    "vulnerability_count": 0,
                    "severity_distribution": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                    "oracle_types": set(),
                    "manipulation_methods": set()
                }
            manipulation_analysis[manipulation_type]["vulnerability_count"] += 1
            manipulation_analysis[manipulation_type]["severity_distribution"][vuln.severity] += 1
            manipulation_analysis[manipulation_type]["oracle_types"].add(vuln.oracle_type.value)
            manipulation_analysis[manipulation_type]["manipulation_methods"].add(vuln.manipulation_method)
        
        # Convert sets to lists for JSON serialization
        for manipulation_info in manipulation_analysis.values():
            manipulation_info["oracle_types"] = list(manipulation_info["oracle_types"])
            manipulation_info["manipulation_methods"] = list(manipulation_info["manipulation_methods"])
        
        report["manipulation_analysis"] = manipulation_analysis
        
        return report
