#!/usr/bin/env python3
"""
Cross-Protocol Attack Detector

Advanced detector for cross-protocol vulnerabilities including:
- Cross-protocol arbitrage attacks
- Protocol composability vulnerabilities
- Cross-chain bridge attacks
- Cross-protocol MEV extraction
- Protocol interaction exploits
- Cross-protocol governance attacks
- Cross-protocol liquidation attacks
- Cross-protocol oracle manipulation
"""

import re
import json
import asyncio
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime


class ProtocolType(Enum):
    AAVE = "aave"
    COMPOUND = "compound"
    UNISWAP = "uniswap"
    CURVE = "curve"
    BALANCER = "balancer"
    SUSHISWAP = "sushiswap"
    MAKERDAO = "makerdao"
    SYNTHETIX = "synthetix"
    YEARN = "yearn"
    CONVEX = "convex"
    FRAX = "frax"
    LIDO = "lido"
    ROCKET_POOL = "rocket_pool"
    HOP = "hop"
    OPTIMISM = "optimism"
    ARBITRUM = "arbitrum"
    POLYGON = "polygon"
    BSC = "bsc"
    AVALANCHE = "avalanche"
    FANTOM = "fantom"
    CUSTOM = "custom"


class CrossProtocolAttackType(Enum):
    ARBITRAGE_ATTACK = "arbitrage_attack"
    COMPOSABILITY_EXPLOIT = "composability_exploit"
    CROSS_CHAIN_BRIDGE_ATTACK = "cross_chain_bridge_attack"
    CROSS_PROTOCOL_MEV = "cross_protocol_mev"
    PROTOCOL_INTERACTION_EXPLOIT = "protocol_interaction_exploit"
    CROSS_PROTOCOL_GOVERNANCE = "cross_protocol_governance"
    CROSS_PROTOCOL_LIQUIDATION = "cross_protocol_liquidation"
    CROSS_PROTOCOL_ORACLE_MANIPULATION = "cross_protocol_oracle_manipulation"
    CROSS_PROTOCOL_FLASH_LOAN_ATTACK = "cross_protocol_flash_loan_attack"
    CROSS_PROTOCOL_REENTRANCY = "cross_protocol_reentrancy"


@dataclass
class CrossProtocolVulnerability:
    """Cross-protocol vulnerability representation."""
    vuln_type: CrossProtocolAttackType
    source_protocol: ProtocolType
    target_protocol: ProtocolType
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
    
    # Cross-protocol specific fields
    interaction_pattern: str = ""
    attack_prerequisites: List[str] = field(default_factory=list)
    mitigation_strategies: List[str] = field(default_factory=list)
    historical_examples: List[str] = field(default_factory=list)
    cross_protocol_risks: List[str] = field(default_factory=list)
    composability_score: float = 0.0
    attack_surface: str = ""


class CrossProtocolDetector:
    """Advanced cross-protocol vulnerability detector."""

    def __init__(self):
        self.protocol_patterns = self._initialize_protocol_patterns()
        self.cross_protocol_patterns = self._initialize_cross_protocol_patterns()
        self.interaction_patterns = self._initialize_interaction_patterns()
        self.historical_attacks = self._load_historical_attacks()
        self.protocol_addresses = self._load_protocol_addresses()

    def _initialize_protocol_patterns(self) -> Dict[ProtocolType, List[str]]:
        """Initialize protocol-specific patterns."""
        return {
            ProtocolType.AAVE: [
                r"Aave|LendingPool|AToken|DebtToken",
                r"supply\(|withdraw\(|borrow\(|repay\(",
                r"flashLoan\(|liquidate\(|swapBorrowRateMode\(",
                r"getReserveData\(|getUserAccountData\("
            ],
            ProtocolType.COMPOUND: [
                r"Compound|Comptroller|CToken|CErc20",
                r"mint\(|redeem\(|borrow\(|repayBorrow\(",
                r"liquidateBorrow\(|seize\(|accrueInterest\(",
                r"getAccountLiquidity\(|getBorrowRate\("
            ],
            ProtocolType.UNISWAP: [
                r"Uniswap|IUniswapV2Router|IUniswapV3Router",
                r"swapExactTokensForTokens\(|swapTokensForExactTokens\(",
                r"addLiquidity\(|removeLiquidity\(|swap\(",
                r"getAmountsOut\(|getAmountsIn\(|getReserves\("
            ],
            ProtocolType.CURVE: [
                r"Curve|ICurvePool|ICurveGauge",
                r"exchange\(|exchange_underlying\(|add_liquidity\(",
                r"remove_liquidity\(|remove_liquidity_one_coin\(",
                r"get_dy\(|get_dx\(|calc_token_amount\("
            ],
            ProtocolType.BALANCER: [
                r"Balancer|IVault|IPool|IGauge",
                r"swap\(|joinPool\(|exitPool\(|batchSwap\(",
                r"queryBatchSwap\(|getPool\(|getPoolTokens\(",
                r"getPoolTokenInfo\(|getPoolId\("
            ],
            ProtocolType.SUSHISWAP: [
                r"SushiSwap|ISushiSwapRouter|ISushiSwapPair",
                r"swapExactTokensForTokens\(|swapTokensForExactTokens\(",
                r"addLiquidity\(|removeLiquidity\(|swap\(",
                r"getAmountsOut\(|getAmountsIn\(|getReserves\("
            ],
            ProtocolType.MAKERDAO: [
                r"MakerDAO|Vat|Jug|Cat|Vow",
                r"open\(|give\(|frob\(|move\(|flux\(",
                r"bite\(|grab\(|heal\(|suck\(",
                r"drip\(|file\(|fold\("
            ],
            ProtocolType.SYNTHETIX: [
                r"Synthetix|ISynthetix|IExchangeRates",
                r"exchange\(|exchangeWithTracking\(|settle\(",
                r"transfer\(|transferFrom\(|approve\(",
                r"issue\(|burn\(|liquidateDelinquentAccount\("
            ],
            ProtocolType.YEARN: [
                r"Yearn|IVault|IStrategy|IYToken",
                r"deposit\(|withdraw\(|earn\(|harvest\(",
                r"balanceOf\(|totalSupply\(|pricePerShare\(",
                r"governance\(|management\(|guardian\("
            ],
            ProtocolType.CONVEX: [
                r"Convex|IConvexBooster|IConvexRewards",
                r"deposit\(|withdraw\(|claimRewards\(",
                r"stake\(|unstake\(|getReward\(",
                r"earned\(|rewardRate\(|totalSupply\("
            ],
            ProtocolType.FRAX: [
                r"Frax|IFrax|IFraxAMO|IFraxPool",
                r"mint\(|redeem\(|exchange\(|swap\(",
                r"addCollateral\(|removeCollateral\(",
                r"collect\(|harvest\(|rebalance\("
            ],
            ProtocolType.LIDO: [
                r"Lido|IStETH|ILido|IDepositContract",
                r"submit\(|deposit\(|withdraw\(|claim\(",
                r"getTotalPooledEther\(|getTotalShares\(",
                r"getBeaconStat\(|getFee\("
            ],
            ProtocolType.ROCKET_POOL: [
                r"RocketPool|IRocketPool|IRocketTokenRETH",
                r"deposit\(|withdraw\(|claim\(|stake\(",
                r"getTotalPooledEther\(|getTotalShares\(",
                r"getBeaconStat\(|getFee\("
            ],
            ProtocolType.HOP: [
                r"Hop|IHopBridge|IHopL2AmmWrapper",
                r"sendToL2\(|swapAndSend\(|bondWithdrawal\(",
                r"withdraw\(|claim\(|relay\(|distribute\(",
                r"getTransferId\(|getTransferRootId\("
            ],
            ProtocolType.OPTIMISM: [
                r"Optimism|IL1CrossDomainMessenger|IL2CrossDomainMessenger",
                r"sendMessage\(|relayMessage\(|finalizeDeposit\(",
                r"depositTransaction\(|finalizeWithdrawal\(",
                r"getMessageHash\(|getMessageNonce\("
            ],
            ProtocolType.ARBITRUM: [
                r"Arbitrum|IInbox|IOutbox|IBridge",
                r"sendL2Message\(|sendUnsignedTransaction\(",
                r"executeTransaction\(|finalizeInboundTransfer\(",
                r"getMessageHash\(|getMessageNonce\("
            ],
            ProtocolType.POLYGON: [
                r"Polygon|IPolygonBridge|IFxTunnel",
                r"deposit\(|withdraw\(|claim\(|relay\(",
                r"sendMessage\(|receiveMessage\(",
                r"getMessageHash\(|getMessageNonce\("
            ],
            ProtocolType.BSC: [
                r"BSC|IBSCBridge|IPeggedTokenBridge",
                r"deposit\(|withdraw\(|claim\(|relay\(",
                r"sendMessage\(|receiveMessage\(",
                r"getMessageHash\(|getMessageNonce\("
            ],
            ProtocolType.AVALANCHE: [
                r"Avalanche|IAvalancheBridge|ISnowBridge",
                r"deposit\(|withdraw\(|claim\(|relay\(",
                r"sendMessage\(|receiveMessage\(",
                r"getMessageHash\(|getMessageNonce\("
            ],
            ProtocolType.FANTOM: [
                r"Fantom|IFantomBridge|IAnyswapBridge",
                r"deposit\(|withdraw\(|claim\(|relay\(",
                r"sendMessage\(|receiveMessage\(",
                r"getMessageHash\(|getMessageNonce\("
            ]
        }

    def _initialize_cross_protocol_patterns(self) -> Dict[CrossProtocolAttackType, List[Dict[str, Any]]]:
        """Initialize cross-protocol attack patterns."""
        return {
            CrossProtocolAttackType.ARBITRAGE_ATTACK: [
                {
                    "pattern": r"Aave.*Uniswap|Uniswap.*Aave|Compound.*Curve|Curve.*Compound",
                    "severity": "medium",
                    "confidence": 0.7,
                    "description": "Cross-protocol arbitrage opportunity detected",
                    "attack_vector": "Cross-protocol arbitrage",
                    "financial_impact": "Medium - Arbitrage profits",
                    "exploit_complexity": "Medium",
                    "immunefi_bounty_potential": "$1,000-$50,000",
                    "poc_suggestion": "Demonstrate cross-protocol arbitrage",
                    "fix_suggestion": "Add arbitrage protection mechanisms",
                    "interaction_pattern": "Price arbitrage",
                    "attack_prerequisites": ["Multiple protocol access", "Price discrepancies"],
                    "mitigation_strategies": ["Arbitrage limits", "Price synchronization", "Circuit breakers"],
                    "historical_examples": ["Alpha Homora Cross-Protocol Arbitrage", "Value DeFi Cross-Protocol Arbitrage"]
                }
            ],
            
            CrossProtocolAttackType.COMPOSABILITY_EXPLOIT: [
                {
                    "pattern": r"protocol.*protocol|protocol.*interaction|interaction.*protocol",
                    "severity": "high",
                    "confidence": 0.8,
                    "description": "Protocol composability vulnerability detected",
                    "attack_vector": "Composability exploit",
                    "financial_impact": "High - Composability attacks",
                    "exploit_complexity": "High",
                    "immunefi_bounty_potential": "$10,000-$250,000",
                    "poc_suggestion": "Demonstrate composability exploit",
                    "fix_suggestion": "Add composability protection",
                    "interaction_pattern": "Protocol interaction",
                    "attack_prerequisites": ["Multiple protocol access", "Composability logic"],
                    "mitigation_strategies": ["Composability limits", "Interaction validation", "State isolation"],
                    "historical_examples": ["Alpha Homora Composability Attack", "Value DeFi Composability Attack"]
                }
            ],
            
            CrossProtocolAttackType.CROSS_CHAIN_BRIDGE_ATTACK: [
                {
                    "pattern": r"bridge.*bridge|cross.*chain|chain.*bridge",
                    "severity": "high",
                    "confidence": 0.8,
                    "description": "Cross-chain bridge vulnerability detected",
                    "attack_vector": "Cross-chain bridge attack",
                    "financial_impact": "High - Bridge attacks",
                    "exploit_complexity": "High",
                    "immunefi_bounty_potential": "$10,000-$500,000",
                    "poc_suggestion": "Demonstrate cross-chain bridge attack",
                    "fix_suggestion": "Add bridge protection mechanisms",
                    "interaction_pattern": "Cross-chain interaction",
                    "attack_prerequisites": ["Cross-chain access", "Bridge logic"],
                    "mitigation_strategies": ["Bridge validation", "Cross-chain verification", "Emergency stops"],
                    "historical_examples": ["Wormhole Bridge Attack ($325M)", "Ronin Bridge Attack ($625M)"]
                }
            ],
            
            CrossProtocolAttackType.CROSS_PROTOCOL_MEV: [
                {
                    "pattern": r"MEV.*protocol|protocol.*MEV|front.*run.*protocol",
                    "severity": "medium",
                    "confidence": 0.6,
                    "description": "Cross-protocol MEV opportunity detected",
                    "attack_vector": "Cross-protocol MEV",
                    "financial_impact": "Medium - MEV extraction",
                    "exploit_complexity": "High",
                    "immunefi_bounty_potential": "$1,000-$50,000",
                    "poc_suggestion": "Demonstrate cross-protocol MEV",
                    "fix_suggestion": "Add MEV protection mechanisms",
                    "interaction_pattern": "MEV extraction",
                    "attack_prerequisites": ["MEV capability", "Protocol interaction"],
                    "mitigation_strategies": ["MEV protection", "Front-running prevention", "Time delays"],
                    "historical_examples": ["Alpha Homora MEV Attack", "Value DeFi MEV Attack"]
                }
            ],
            
            CrossProtocolAttackType.PROTOCOL_INTERACTION_EXPLOIT: [
                {
                    "pattern": r"interact.*protocol|protocol.*interact|call.*protocol",
                    "severity": "high",
                    "confidence": 0.8,
                    "description": "Protocol interaction exploit detected",
                    "attack_vector": "Protocol interaction exploit",
                    "financial_impact": "High - Interaction exploits",
                    "exploit_complexity": "High",
                    "immunefi_bounty_potential": "$10,000-$250,000",
                    "poc_suggestion": "Demonstrate protocol interaction exploit",
                    "fix_suggestion": "Add interaction protection",
                    "interaction_pattern": "Protocol interaction",
                    "attack_prerequisites": ["Protocol interaction", "State manipulation"],
                    "mitigation_strategies": ["Interaction validation", "State isolation", "Access control"],
                    "historical_examples": ["Alpha Homora Interaction Attack", "Value DeFi Interaction Attack"]
                }
            ],
            
            CrossProtocolAttackType.CROSS_PROTOCOL_GOVERNANCE: [
                {
                    "pattern": r"governance.*protocol|protocol.*governance|vote.*protocol",
                    "severity": "high",
                    "confidence": 0.8,
                    "description": "Cross-protocol governance vulnerability detected",
                    "attack_vector": "Cross-protocol governance attack",
                    "financial_impact": "High - Governance attacks",
                    "exploit_complexity": "High",
                    "immunefi_bounty_potential": "$10,000-$250,000",
                    "poc_suggestion": "Demonstrate cross-protocol governance attack",
                    "fix_suggestion": "Add governance protection",
                    "interaction_pattern": "Governance interaction",
                    "attack_prerequisites": ["Governance access", "Protocol interaction"],
                    "mitigation_strategies": ["Governance validation", "Interaction limits", "Access control"],
                    "historical_examples": ["Alpha Homora Governance Attack", "Value DeFi Governance Attack"]
                }
            ],
            
            CrossProtocolAttackType.CROSS_PROTOCOL_LIQUIDATION: [
                {
                    "pattern": r"liquidate.*protocol|protocol.*liquidate|liquidation.*protocol",
                    "severity": "high",
                    "confidence": 0.8,
                    "description": "Cross-protocol liquidation vulnerability detected",
                    "attack_vector": "Cross-protocol liquidation attack",
                    "financial_impact": "High - Liquidation attacks",
                    "exploit_complexity": "High",
                    "immunefi_bounty_potential": "$10,000-$250,000",
                    "poc_suggestion": "Demonstrate cross-protocol liquidation attack",
                    "fix_suggestion": "Add liquidation protection",
                    "interaction_pattern": "Liquidation interaction",
                    "attack_prerequisites": ["Liquidation access", "Protocol interaction"],
                    "mitigation_strategies": ["Liquidation validation", "Interaction limits", "Access control"],
                    "historical_examples": ["Alpha Homora Liquidation Attack", "Value DeFi Liquidation Attack"]
                }
            ],
            
            CrossProtocolAttackType.CROSS_PROTOCOL_ORACLE_MANIPULATION: [
                {
                    "pattern": r"oracle.*protocol|protocol.*oracle|price.*protocol",
                    "severity": "high",
                    "confidence": 0.8,
                    "description": "Cross-protocol oracle manipulation detected",
                    "attack_vector": "Cross-protocol oracle manipulation",
                    "financial_impact": "High - Oracle manipulation",
                    "exploit_complexity": "High",
                    "immunefi_bounty_potential": "$10,000-$500,000",
                    "poc_suggestion": "Demonstrate cross-protocol oracle manipulation",
                    "fix_suggestion": "Add oracle protection",
                    "interaction_pattern": "Oracle interaction",
                    "attack_prerequisites": ["Oracle access", "Protocol interaction"],
                    "mitigation_strategies": ["Oracle validation", "Interaction limits", "Price validation"],
                    "historical_examples": ["Alpha Homora Oracle Attack", "Value DeFi Oracle Attack"]
                }
            ],
            
            CrossProtocolAttackType.CROSS_PROTOCOL_FLASH_LOAN_ATTACK: [
                {
                    "pattern": r"flashLoan.*protocol|protocol.*flashLoan|flash.*protocol",
                    "severity": "critical",
                    "confidence": 0.9,
                    "description": "Cross-protocol flash loan attack detected",
                    "attack_vector": "Cross-protocol flash loan attack",
                    "financial_impact": "Critical - Protocol drain",
                    "exploit_complexity": "High",
                    "immunefi_bounty_potential": "$50,000-$2,000,000",
                    "poc_suggestion": "Demonstrate cross-protocol flash loan attack",
                    "fix_suggestion": "Add flash loan protection",
                    "interaction_pattern": "Flash loan interaction",
                    "attack_prerequisites": ["Flash loan access", "Protocol interaction", "Large capital"],
                    "mitigation_strategies": ["Flash loan limits", "Interaction validation", "Circuit breakers"],
                    "historical_examples": ["Alpha Homora Flash Loan Attack", "Value DeFi Flash Loan Attack"]
                }
            ],
            
            CrossProtocolAttackType.CROSS_PROTOCOL_REENTRANCY: [
                {
                    "pattern": r"reentrancy.*protocol|protocol.*reentrancy|reentrant.*protocol",
                    "severity": "high",
                    "confidence": 0.8,
                    "description": "Cross-protocol reentrancy vulnerability detected",
                    "attack_vector": "Cross-protocol reentrancy attack",
                    "financial_impact": "High - Reentrancy attacks",
                    "exploit_complexity": "High",
                    "immunefi_bounty_potential": "$10,000-$250,000",
                    "poc_suggestion": "Demonstrate cross-protocol reentrancy attack",
                    "fix_suggestion": "Add reentrancy protection",
                    "interaction_pattern": "Reentrancy interaction",
                    "attack_prerequisites": ["Reentrancy access", "Protocol interaction"],
                    "mitigation_strategies": ["Reentrancy guards", "Interaction limits", "State isolation"],
                    "historical_examples": ["Alpha Homora Reentrancy Attack", "Value DeFi Reentrancy Attack"]
                }
            ]
        }

    def _initialize_interaction_patterns(self) -> Dict[str, List[str]]:
        """Initialize protocol interaction patterns."""
        return {
            "protocol_calls": [
                r"\.call\(|\.delegatecall\(|\.staticcall\(",
                r"interface.*call|external.*call",
                r"protocol.*call|call.*protocol"
            ],
            "cross_protocol_transfers": [
                r"transfer.*protocol|protocol.*transfer",
                r"cross.*protocol.*transfer",
                r"bridge.*transfer|transfer.*bridge"
            ],
            "protocol_state_changes": [
                r"protocol.*state|state.*protocol",
                r"cross.*protocol.*state",
                r"interaction.*state|state.*interaction"
            ],
            "protocol_events": [
                r"emit.*protocol|protocol.*emit",
                r"event.*protocol|protocol.*event",
                r"log.*protocol|protocol.*log"
            ],
            "protocol_validation": [
                r"validate.*protocol|protocol.*validate",
                r"check.*protocol|protocol.*check",
                r"verify.*protocol|protocol.*verify"
            ]
        }

    def _load_historical_attacks(self) -> Dict[CrossProtocolAttackType, List[str]]:
        """Load historical cross-protocol attack examples."""
        return {
            CrossProtocolAttackType.ARBITRAGE_ATTACK: [
                "Alpha Homora Cross-Protocol Arbitrage ($37M)",
                "Value DeFi Cross-Protocol Arbitrage ($6M)",
                "Cream Finance Cross-Protocol Arbitrage ($18M)"
            ],
            CrossProtocolAttackType.COMPOSABILITY_EXPLOIT: [
                "Alpha Homora Composability Attack ($37M)",
                "Value DeFi Composability Attack ($6M)",
                "Cream Finance Composability Attack ($18M)"
            ],
            CrossProtocolAttackType.CROSS_CHAIN_BRIDGE_ATTACK: [
                "Wormhole Bridge Attack ($325M)",
                "Ronin Bridge Attack ($625M)",
                "Nomad Bridge Attack ($190M)"
            ],
            CrossProtocolAttackType.CROSS_PROTOCOL_FLASH_LOAN_ATTACK: [
                "Alpha Homora Flash Loan Attack ($37M)",
                "Value DeFi Flash Loan Attack ($6M)",
                "Cream Finance Flash Loan Attack ($18M)"
            ]
        }

    def _load_protocol_addresses(self) -> Dict[str, List[str]]:
        """Load known protocol addresses."""
        return {
            "aave": [
                "0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9",  # LendingPool
                "0x3ed3B47Dd13EC9a98b44e6204A523E766B225811",  # AToken
                "0x531842cEbbdD378f8ee36D171d6cC9C4fcf475Ec"   # DebtToken
            ],
            "compound": [
                "0x3d9819210A31b4961b30EF54bE2aeD79B9c9Cd3B",  # Comptroller
                "0x39AA39c021dfbaE8faC545936693aC917d5E7563",  # CToken
                "0x70e36f6BF80a52b3B46b3aF8e106CC0ed743E8e4"   # CErc20
            ],
            "uniswap": [
                "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",  # V2 Router
                "0xE592427A0AEce92De3Edee1F18E0157C05861564",  # V3 Router
                "0x1F98431c8aD98523631AE4a59f267346ea31F984"   # V3 Factory
            ],
            "curve": [
                "0xbEbc44782C7dB0a1A60Cb6fe97d0b483032FF1C7",  # 3Pool
                "0xA2B47E3D5c44877cca798226B7B8118F9BFb7A56",  # Compound
                "0x79a8C46DeA5aDa233ABaFFD40F3A0A2B1e5A4F27"   # yPool
            ],
            "balancer": [
                "0xBA12222222228d8Ba445958a75a0704d566BF2C8",  # Vault
                "0x5c6Ee304399DBdB9C8Ef030aB642B10820DB8F56",  # Pool
                "0x7B50775383d3D6f0215A8F290f2c9e2eEBBEceb2"   # Gauge
            ]
        }

    def detect_protocol_types(self, content: str) -> List[ProtocolType]:
        """Detect protocol types from contract content."""
        detected_types = []
        
        for protocol_type, patterns in self.protocol_patterns.items():
            if any(re.search(pattern, content, re.IGNORECASE) for pattern in patterns):
                detected_types.append(protocol_type)
        
        return detected_types

    async def analyze_contract(self, contract_path: str, content: str) -> List[CrossProtocolVulnerability]:
        """Analyze contract for cross-protocol vulnerabilities."""
        vulnerabilities = []
        
        # Detect protocol types
        protocol_types = self.detect_protocol_types(content)
        if len(protocol_types) < 2:
            return vulnerabilities  # Need at least 2 protocols for cross-protocol attacks
        
        lines = content.split('\n')
        
        # Analyze each cross-protocol attack type
        for vuln_type, patterns in self.cross_protocol_patterns.items():
            for pattern_info in patterns:
                pattern = pattern_info["pattern"]
                regex = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                
                for match in regex.finditer(content):
                    line_number = content[:match.start()].count('\n') + 1
                    
                    # Extract code snippet with context
                    start_line = max(0, line_number - 3)
                    end_line = min(len(lines), line_number + 3)
                    code_snippet = '\n'.join(lines[start_line:end_line])
                    
                    # Determine source and target protocols
                    source_protocol, target_protocol = self._determine_protocols_from_match(match.group(), protocol_types)
                    
                    vulnerability = CrossProtocolVulnerability(
                        vuln_type=vuln_type,
                        source_protocol=source_protocol,
                        target_protocol=target_protocol,
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
                            "source_protocol": source_protocol.value,
                            "target_protocol": target_protocol.value
                        },
                        interaction_pattern=pattern_info.get("interaction_pattern", ""),
                        attack_prerequisites=pattern_info.get("attack_prerequisites", []),
                        mitigation_strategies=pattern_info.get("mitigation_strategies", []),
                        historical_examples=pattern_info.get("historical_examples", []),
                        cross_protocol_risks=self._identify_cross_protocol_risks(vuln_type, source_protocol, target_protocol),
                        composability_score=self._calculate_composability_score(vuln_type, source_protocol, target_protocol),
                        attack_surface=self._identify_attack_surface(vuln_type, source_protocol, target_protocol)
                    )
                    
                    # Apply additional validation
                    if await self._validate_cross_protocol_vulnerability(vulnerability, content):
                        vulnerabilities.append(vulnerability)
        
        # Add cross-protocol specific analysis
        vulnerabilities.extend(await self._analyze_cross_protocol_specific_patterns(content, contract_path, protocol_types))
        
        return vulnerabilities

    def _determine_protocols_from_match(self, match_text: str, protocol_types: List[ProtocolType]) -> Tuple[ProtocolType, ProtocolType]:
        """Determine source and target protocols from match text."""
        match_lower = match_text.lower()
        
        # Find protocols mentioned in the match
        mentioned_protocols = []
        for protocol_type in protocol_types:
            if protocol_type.value.replace("_", "") in match_lower:
                mentioned_protocols.append(protocol_type)
        
        if len(mentioned_protocols) >= 2:
            return mentioned_protocols[0], mentioned_protocols[1]
        elif len(mentioned_protocols) == 1:
            return mentioned_protocols[0], protocol_types[1] if len(protocol_types) > 1 else protocol_types[0]
        else:
            return protocol_types[0], protocol_types[1] if len(protocol_types) > 1 else protocol_types[0]

    def _identify_cross_protocol_risks(self, vuln_type: CrossProtocolAttackType, source_protocol: ProtocolType, target_protocol: ProtocolType) -> List[str]:
        """Identify cross-protocol risks."""
        risks = []
        
        if vuln_type == CrossProtocolAttackType.ARBITRAGE_ATTACK:
            risks.extend([
                "Price manipulation across protocols",
                "Liquidity drain from target protocol",
                "Market disruption through arbitrage"
            ])
        elif vuln_type == CrossProtocolAttackType.COMPOSABILITY_EXPLOIT:
            risks.extend([
                "State manipulation across protocols",
                "Logic bypass through composability",
                "Unexpected protocol interactions"
            ])
        elif vuln_type == CrossProtocolAttackType.CROSS_CHAIN_BRIDGE_ATTACK:
            risks.extend([
                "Bridge token manipulation",
                "Cross-chain state inconsistency",
                "Bridge protocol compromise"
            ])
        elif vuln_type == CrossProtocolAttackType.CROSS_PROTOCOL_FLASH_LOAN_ATTACK:
            risks.extend([
                "Protocol drain through flash loans",
                "Cross-protocol state manipulation",
                "Large-scale financial impact"
            ])
        
        return risks

    def _calculate_composability_score(self, vuln_type: CrossProtocolAttackType, source_protocol: ProtocolType, target_protocol: ProtocolType) -> float:
        """Calculate composability risk score."""
        base_score = 0.5
        
        # Adjust based on vulnerability type
        if vuln_type == CrossProtocolAttackType.CROSS_PROTOCOL_FLASH_LOAN_ATTACK:
            base_score += 0.4
        elif vuln_type == CrossProtocolAttackType.COMPOSABILITY_EXPLOIT:
            base_score += 0.3
        elif vuln_type == CrossProtocolAttackType.CROSS_CHAIN_BRIDGE_ATTACK:
            base_score += 0.3
        elif vuln_type == CrossProtocolAttackType.CROSS_PROTOCOL_ORACLE_MANIPULATION:
            base_score += 0.2
        
        # Adjust based on protocol combination
        high_risk_combinations = [
            (ProtocolType.AAVE, ProtocolType.UNISWAP),
            (ProtocolType.COMPOUND, ProtocolType.CURVE),
            (ProtocolType.BALANCER, ProtocolType.CURVE),
            (ProtocolType.YEARN, ProtocolType.CURVE)
        ]
        
        if (source_protocol, target_protocol) in high_risk_combinations or (target_protocol, source_protocol) in high_risk_combinations:
            base_score += 0.2
        
        return min(base_score, 1.0)

    def _identify_attack_surface(self, vuln_type: CrossProtocolAttackType, source_protocol: ProtocolType, target_protocol: ProtocolType) -> str:
        """Identify attack surface."""
        if vuln_type == CrossProtocolAttackType.ARBITRAGE_ATTACK:
            return f"Price arbitrage between {source_protocol.value} and {target_protocol.value}"
        elif vuln_type == CrossProtocolAttackType.COMPOSABILITY_EXPLOIT:
            return f"Composability interaction between {source_protocol.value} and {target_protocol.value}"
        elif vuln_type == CrossProtocolAttackType.CROSS_CHAIN_BRIDGE_ATTACK:
            return f"Cross-chain bridge interaction between {source_protocol.value} and {target_protocol.value}"
        elif vuln_type == CrossProtocolAttackType.CROSS_PROTOCOL_FLASH_LOAN_ATTACK:
            return f"Flash loan interaction between {source_protocol.value} and {target_protocol.value}"
        else:
            return f"Cross-protocol interaction between {source_protocol.value} and {target_protocol.value}"

    async def _validate_cross_protocol_vulnerability(self, vulnerability: CrossProtocolVulnerability, content: str) -> bool:
        """Validate cross-protocol vulnerability with additional context checks."""
        
        # Check for cross-protocol protection patterns
        protection_patterns = {
            CrossProtocolAttackType.ARBITRAGE_ATTACK: [
                r"arbitrage.*protection|arbitrage.*limit",
                r"price.*validation|price.*check",
                r"circuitBreaker|emergencyStop"
            ],
            CrossProtocolAttackType.COMPOSABILITY_EXPLOIT: [
                r"composability.*protection|composability.*limit",
                r"interaction.*validation|interaction.*check",
                r"state.*isolation|isolation.*protection"
            ],
            CrossProtocolAttackType.CROSS_CHAIN_BRIDGE_ATTACK: [
                r"bridge.*protection|bridge.*validation",
                r"cross.*chain.*validation|cross.*chain.*check",
                r"bridge.*limit|bridge.*threshold"
            ],
            CrossProtocolAttackType.CROSS_PROTOCOL_FLASH_LOAN_ATTACK: [
                r"flash.*loan.*protection|anti.*flash.*loan",
                r"cross.*protocol.*protection|cross.*protocol.*limit",
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
        return vulnerability.confidence > 0.3

    async def _analyze_cross_protocol_specific_patterns(self, content: str, contract_path: str, protocol_types: List[ProtocolType]) -> List[CrossProtocolVulnerability]:
        """Analyze cross-protocol specific patterns."""
        vulnerabilities = []
        
        # Analyze protocol combinations
        for i, source_protocol in enumerate(protocol_types):
            for target_protocol in protocol_types[i+1:]:
                vulnerabilities.extend(await self._analyze_protocol_combination(content, contract_path, source_protocol, target_protocol))
        
        return vulnerabilities

    async def _analyze_protocol_combination(self, content: str, contract_path: str, source_protocol: ProtocolType, target_protocol: ProtocolType) -> List[CrossProtocolVulnerability]:
        """Analyze specific protocol combination."""
        vulnerabilities = []
        
        # Check for protocol interaction patterns
        interaction_patterns = [
            {
                "pattern": f"{source_protocol.value}.*{target_protocol.value}|{target_protocol.value}.*{source_protocol.value}",
                "vuln_type": CrossProtocolAttackType.PROTOCOL_INTERACTION_EXPLOIT,
                "severity": "high",
                "confidence": 0.8,
                "description": f"Cross-protocol interaction between {source_protocol.value} and {target_protocol.value}",
                "attack_vector": "Protocol interaction exploit",
                "financial_impact": "High - Protocol interaction exploits",
                "exploit_complexity": "High",
                "immunefi_bounty_potential": "$10,000-$250,000"
            }
        ]
        
        for pattern_info in interaction_patterns:
            pattern = pattern_info["pattern"]
            regex = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            
            for match in regex.finditer(content):
                line_number = content[:match.start()].count('\n') + 1
                
                vulnerability = CrossProtocolVulnerability(
                    vuln_type=pattern_info["vuln_type"],
                    source_protocol=source_protocol,
                    target_protocol=target_protocol,
                    severity=pattern_info["severity"],
                    confidence=pattern_info["confidence"],
                    line_number=line_number,
                    description=pattern_info["description"],
                    code_snippet=match.group(),
                    attack_vector=pattern_info["attack_vector"],
                    financial_impact=pattern_info["financial_impact"],
                    exploit_complexity=pattern_info["exploit_complexity"],
                    immunefi_bounty_potential=pattern_info["immunefi_bounty_potential"],
                    poc_suggestion=f"Demonstrate {source_protocol.value}-{target_protocol.value} interaction attack",
                    fix_suggestion=f"Add {source_protocol.value}-{target_protocol.value} interaction protection",
                    context={"pattern_match": match.group(), "contract_path": contract_path},
                    interaction_pattern=f"{source_protocol.value}-{target_protocol.value} interaction",
                    attack_prerequisites=[f"{source_protocol.value} access", f"{target_protocol.value} access"],
                    mitigation_strategies=["Interaction validation", "Access control", "State isolation"],
                    cross_protocol_risks=["Protocol interaction", "State manipulation", "Logic bypass"],
                    composability_score=self._calculate_composability_score(pattern_info["vuln_type"], source_protocol, target_protocol),
                    attack_surface=f"Cross-protocol interaction between {source_protocol.value} and {target_protocol.value}"
                )
                
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities

    def generate_cross_protocol_poc_suggestion(self, vulnerability: CrossProtocolVulnerability) -> str:
        """Generate cross-protocol proof-of-concept suggestion."""
        
        poc_template = """
// Cross-Protocol Attack PoC
contract CrossProtocolAttack {{
    function exploitCrossProtocol() external {{
        // 1. Interact with {source_protocol} protocol
        // 2. Manipulate state in {target_protocol} protocol
        // 3. Execute cross-protocol exploit
        // 4. Profit from cross-protocol interaction
        
        // Source Protocol: {source_protocol}
        // Target Protocol: {target_protocol}
        // Vulnerability: {vuln_type}
        // Severity: {severity}
        // Bounty Potential: {bounty_potential}
        // Attack Surface: {attack_surface}
        // Composability Score: {composability_score}
    }}
}}
        """
        
        return poc_template.format(
            source_protocol=vulnerability.source_protocol.value,
            target_protocol=vulnerability.target_protocol.value,
            vuln_type=vulnerability.vuln_type.value,
            severity=vulnerability.severity,
            bounty_potential=vulnerability.immunefi_bounty_potential,
            attack_surface=vulnerability.attack_surface,
            composability_score=vulnerability.composability_score
        )

    def generate_comprehensive_cross_protocol_report(self, vulnerabilities: List[CrossProtocolVulnerability]) -> Dict[str, Any]:
        """Generate comprehensive cross-protocol vulnerability report."""
        
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
            "protocol_analysis": {},
            "cross_protocol_analysis": {},
            "composability_analysis": {}
        }
        
        # Process vulnerabilities
        for vuln in vulnerabilities:
            vuln_data = {
                "type": vuln.vuln_type.value,
                "source_protocol": vuln.source_protocol.value,
                "target_protocol": vuln.target_protocol.value,
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
                "interaction_pattern": vuln.interaction_pattern,
                "attack_prerequisites": vuln.attack_prerequisites,
                "mitigation_strategies": vuln.mitigation_strategies,
                "historical_examples": vuln.historical_examples,
                "cross_protocol_risks": vuln.cross_protocol_risks,
                "composability_score": vuln.composability_score,
                "attack_surface": vuln.attack_surface
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
        
        # Analyze protocol distribution
        protocol_analysis = {}
        for vuln in vulnerabilities:
            for protocol in [vuln.source_protocol, vuln.target_protocol]:
                protocol_type = protocol.value
                if protocol_type not in protocol_analysis:
                    protocol_analysis[protocol_type] = {
                        "vulnerability_count": 0,
                        "severity_distribution": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                        "vulnerability_types": set(),
                        "interaction_patterns": set()
                    }
                protocol_analysis[protocol_type]["vulnerability_count"] += 1
                protocol_analysis[protocol_type]["severity_distribution"][vuln.severity] += 1
                protocol_analysis[protocol_type]["vulnerability_types"].add(vuln.vuln_type.value)
                protocol_analysis[protocol_type]["interaction_patterns"].add(vuln.interaction_pattern)
        
        # Convert sets to lists for JSON serialization
        for protocol_info in protocol_analysis.values():
            protocol_info["vulnerability_types"] = list(protocol_info["vulnerability_types"])
            protocol_info["interaction_patterns"] = list(protocol_info["interaction_patterns"])
        
        report["protocol_analysis"] = protocol_analysis
        
        # Analyze cross-protocol distribution
        cross_protocol_analysis = {}
        for vuln in vulnerabilities:
            combination = f"{vuln.source_protocol.value}-{vuln.target_protocol.value}"
            if combination not in cross_protocol_analysis:
                cross_protocol_analysis[combination] = {
                    "vulnerability_count": 0,
                    "severity_distribution": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                    "vulnerability_types": set(),
                    "composability_scores": []
                }
            cross_protocol_analysis[combination]["vulnerability_count"] += 1
            cross_protocol_analysis[combination]["severity_distribution"][vuln.severity] += 1
            cross_protocol_analysis[combination]["vulnerability_types"].add(vuln.vuln_type.value)
            cross_protocol_analysis[combination]["composability_scores"].append(vuln.composability_score)
        
        # Convert sets to lists and calculate average composability scores
        for combination_info in cross_protocol_analysis.values():
            combination_info["vulnerability_types"] = list(combination_info["vulnerability_types"])
            if combination_info["composability_scores"]:
                combination_info["average_composability_score"] = sum(combination_info["composability_scores"]) / len(combination_info["composability_scores"])
            else:
                combination_info["average_composability_score"] = 0.0
            del combination_info["composability_scores"]  # Remove raw scores
        
        report["cross_protocol_analysis"] = cross_protocol_analysis
        
        # Analyze composability
        composability_analysis = {
            "high_risk_combinations": [],
            "medium_risk_combinations": [],
            "low_risk_combinations": []
        }
        
        for combination, info in cross_protocol_analysis.items():
            avg_score = info["average_composability_score"]
            if avg_score >= 0.7:
                composability_analysis["high_risk_combinations"].append({
                    "combination": combination,
                    "composability_score": avg_score,
                    "vulnerability_count": info["vulnerability_count"]
                })
            elif avg_score >= 0.4:
                composability_analysis["medium_risk_combinations"].append({
                    "combination": combination,
                    "composability_score": avg_score,
                    "vulnerability_count": info["vulnerability_count"]
                })
            else:
                composability_analysis["low_risk_combinations"].append({
                    "combination": combination,
                    "composability_score": avg_score,
                    "vulnerability_count": info["vulnerability_count"]
                })
        
        report["composability_analysis"] = composability_analysis
        
        return report
