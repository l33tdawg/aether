#!/usr/bin/env python3
"""
Chain-Specific Vulnerability Detectors

Specialized vulnerability detection for different blockchain ecosystems.
"""

import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum


class ChainType(Enum):
    ETHEREUM = "ethereum"
    POLYGON = "polygon"
    ARBITRUM = "arbitrum"
    OPTIMISM = "optimism"
    BSC = "bsc"
    BASE = "base"
    POLYGON_ZKEVM = "polygon_zkevm"
    AVALANCHE = "avalanche"
    FANTOM = "fantom"
    SOLANA = "solana"


@dataclass
class ChainVulnerability:
    """Chain-specific vulnerability finding."""
    vulnerability_type: str
    severity: str
    description: str
    line_number: Optional[int]
    code_snippet: str
    recommendation: str
    chain_specific: bool
    confidence: float


class BaseChainDetector:
    """Base class for chain-specific detectors."""

    def __init__(self, chain_type: ChainType):
        self.chain_type = chain_type
        self.vulnerabilities: List[ChainVulnerability] = []

    def analyze_contract(self, content: str, contract_path: str) -> List[ChainVulnerability]:
        """Analyze contract for chain-specific vulnerabilities."""
        self.vulnerabilities = []

        # Handle None or empty content gracefully
        if not content:
            return self.vulnerabilities

        self.content = content
        self.contract_path = contract_path

        # Run all detection methods
        self._detect_chain_specific_patterns()
        self._detect_gas_inefficiencies()
        self._detect_bridge_vulnerabilities()
        self._detect_oracle_manipulation()

        return self.vulnerabilities

    def _detect_chain_specific_patterns(self):
        """Detect chain-specific vulnerability patterns."""
        pass

    def _detect_gas_inefficiencies(self):
        """Detect gas inefficiencies specific to the chain."""
        pass

    def _detect_bridge_vulnerabilities(self):
        """Detect bridge-related vulnerabilities."""
        pass

    def _detect_oracle_manipulation(self):
        """Detect oracle manipulation vulnerabilities."""
        pass


class PolygonDetector(BaseChainDetector):
    """Polygon-specific vulnerability detector."""

    def __init__(self):
        super().__init__(ChainType.POLYGON)

    def _detect_chain_specific_patterns(self):
        """Detect Polygon-specific patterns."""
        # Check for missing checkpoint manager interactions
        if re.search(r'checkpointManager|checkpoint', self.content, re.IGNORECASE):
            if not re.search(r'IChildToken|IRootChainManager', self.content, re.IGNORECASE):
                self.vulnerabilities.append(ChainVulnerability(
                    vulnerability_type="polygon_checkpoint_missing",
                    severity="medium",
                    description="Contract interacts with Polygon checkpoint but may be missing proper bridge manager integration",
                    line_number=None,
                    code_snippet="",
                    recommendation="Ensure proper integration with IRootChainManager or IChildToken interfaces",
                    chain_specific=True,
                    confidence=0.7
                ))

        # Check for state receiver patterns
        if re.search(r'onStateReceive|IStateReceiver', self.content, re.IGNORECASE):
            if not re.search(r'onlyStateSync', self.content, re.IGNORECASE):
                self.vulnerabilities.append(ChainVulnerability(
                    vulnerability_type="polygon_state_sync_missing",
                    severity="high",
                    description="State receiver contract missing state sync validation",
                    line_number=None,
                    code_snippet="",
                    recommendation="Implement proper state sync validation to prevent unauthorized state changes",
                    chain_specific=True,
                    confidence=0.8
                ))

    def _detect_gas_inefficiencies(self):
        """Detect Polygon-specific gas inefficiencies."""
        # Check for expensive cross-chain calls
        if re.search(r'call\(|delegatecall\(|staticcall\(', self.content):
            self.vulnerabilities.append(ChainVulnerability(
                vulnerability_type="polygon_gas_optimization",
                severity="low",
                description="Cross-chain calls can be expensive on Polygon - consider batching or optimization",
                line_number=None,
                code_snippet="",
                recommendation="Consider using Polygon-specific optimizations like batch processing for cross-chain calls",
                chain_specific=True,
                confidence=0.6
            ))


class ArbitrumDetector(BaseChainDetector):
    """Arbitrum-specific vulnerability detector."""

    def __init__(self):
        super().__init__(ChainType.ARBITRUM)

    def _detect_chain_specific_patterns(self):
        """Detect Arbitrum-specific patterns."""
        # Check for ArbOS-specific patterns
        if re.search(r'arbos|ArbOS|ArbSys', self.content, re.IGNORECASE):
            if not re.search(r'IArbSys|ArbSys', self.content, re.IGNORECASE):
                self.vulnerabilities.append(ChainVulnerability(
                    vulnerability_type="arbitrum_arbos_integration",
                    severity="medium",
                    description="Contract uses ArbOS features but may be missing proper ArbSys integration",
                    line_number=None,
                    code_snippet="",
                    recommendation="Ensure proper integration with ArbSys interface for ArbOS features",
                    chain_specific=True,
                    confidence=0.7
                ))

        # Check for retryable ticket patterns
        if re.search(r'retryable|ticket|inbox', self.content, re.IGNORECASE):
            if not re.search(r'retryableTicket|IRetryableTicket', self.content, re.IGNORECASE):
                self.vulnerabilities.append(ChainVulnerability(
                    vulnerability_type="arbitrum_retryable_validation",
                    severity="high",
                    description="Contract handles retryable tickets but may be missing proper validation",
                    line_number=None,
                    code_snippet="",
                    recommendation="Implement proper retryable ticket validation to prevent unauthorized redemptions",
                    chain_specific=True,
                    confidence=0.8
                ))


class OptimismDetector(BaseChainDetector):
    """Optimism-specific vulnerability detector."""

    def __init__(self):
        super().__init__(ChainType.OPTIMISM)

    def _detect_chain_specific_patterns(self):
        """Detect Optimism-specific patterns."""
        # Check for OVM-specific patterns
        if re.search(r'OVM_|ovm|OptimismMintableERC20', self.content, re.IGNORECASE):
            if not re.search(r'IOVM|OptimismEnvironment', self.content, re.IGNORECASE):
                self.vulnerabilities.append(ChainVulnerability(
                    vulnerability_type="optimism_ovm_integration",
                    severity="medium",
                    description="Contract uses OVM features but may be missing proper OVM integration",
                    line_number=None,
                    code_snippet="",
                    recommendation="Ensure proper integration with OVM interfaces for Optimism-specific features",
                    chain_specific=True,
                    confidence=0.7
                ))


class BSCDetector(BaseChainDetector):
    """BSC-specific vulnerability detector."""

    def __init__(self):
        super().__init__(ChainType.BSC)

    def _detect_chain_specific_patterns(self):
        """Detect BSC-specific patterns."""
        # Check for BEP patterns
        if re.search(r'BEP20|IBEP20|BEP721|IBEP721', self.content, re.IGNORECASE):
            if not re.search(r'_mint|_burn|totalSupply', self.content, re.IGNORECASE):
                self.vulnerabilities.append(ChainVulnerability(
                    vulnerability_type="bsc_bep_integration",
                    severity="medium",
                    description="Contract implements BEP standards but may be missing required functions",
                    line_number=None,
                    code_snippet="",
                    recommendation="Ensure complete BEP20/BEP721 implementation including required functions",
                    chain_specific=True,
                    confidence=0.7
                ))


class PolygonZkEVMDetector(BaseChainDetector):
    """Polygon zkEVM-specific vulnerability detector."""

    def __init__(self):
        super().__init__(ChainType.POLYGON_ZKEVM)

    def _detect_chain_specific_patterns(self):
        """Detect Polygon zkEVM-specific patterns."""
        # Check for zkEVM-specific patterns
        if re.search(r'zkEVM|PolygonZkEVM|zero.?knowledge', self.content, re.IGNORECASE):
            if not re.search(r'PolygonZkEVMBridge|IZkEVMBridge', self.content, re.IGNORECASE):
                self.vulnerabilities.append(ChainVulnerability(
                    vulnerability_type="polygon_zkevm_bridge_integration",
                    severity="medium",
                    description="Contract uses zkEVM features but may be missing proper bridge integration",
                    line_number=None,
                    code_snippet="",
                    recommendation="Ensure proper integration with PolygonZkEVMBridge for zkEVM-specific features",
                    chain_specific=True,
                    confidence=0.7
                ))


class AvalancheDetector(BaseChainDetector):
    """Avalanche-specific vulnerability detector."""

    def __init__(self):
        super().__init__(ChainType.AVALANCHE)

    def _detect_chain_specific_patterns(self):
        """Detect Avalanche-specific patterns."""
        # Check for Avalanche-specific patterns
        if re.search(r'Avalanche|AVAX|snowball', self.content, re.IGNORECASE):
            if not re.search(r'IAvalanche|Snowball', self.content, re.IGNORECASE):
                self.vulnerabilities.append(ChainVulnerability(
                    vulnerability_type="avalanche_integration",
                    severity="medium",
                    description="Contract uses Avalanche features but may be missing proper integration",
                    line_number=None,
                    code_snippet="",
                    recommendation="Ensure proper integration with Avalanche-specific interfaces",
                    chain_specific=True,
                    confidence=0.7
                ))


class FantomDetector(BaseChainDetector):
    """Fantom-specific vulnerability detector."""

    def __init__(self):
        super().__init__(ChainType.FANTOM)

    def _detect_chain_specific_patterns(self):
        """Detect Fantom-specific patterns."""
        # Check for Fantom-specific patterns
        if re.search(r'Fantom|FTM|fantom', self.content, re.IGNORECASE):
            if not re.search(r'IFantom|fantom', self.content, re.IGNORECASE):
                self.vulnerabilities.append(ChainVulnerability(
                    vulnerability_type="fantom_integration",
                    severity="medium",
                    description="Contract uses Fantom features but may be missing proper integration",
                    line_number=None,
                    code_snippet="",
                    recommendation="Ensure proper integration with Fantom-specific interfaces",
                    chain_specific=True,
                    confidence=0.7
                ))


class ChainDetectorManager:
    """Manager for all chain-specific detectors."""

    def __init__(self):
        self.detectors = {
            ChainType.POLYGON: PolygonDetector(),
            ChainType.ARBITRUM: ArbitrumDetector(),
            ChainType.OPTIMISM: OptimismDetector(),
            ChainType.BSC: BSCDetector(),
            ChainType.BASE: BaseChainDetector(ChainType.BASE),
            ChainType.POLYGON_ZKEVM: PolygonZkEVMDetector(),
            ChainType.AVALANCHE: AvalancheDetector(),
            ChainType.FANTOM: FantomDetector(),
        }

    def analyze_contract(self, content: str, contract_path: str, chain_type: Optional[ChainType] = None) -> List[ChainVulnerability]:
        """Analyze contract with appropriate chain detector."""
        all_vulnerabilities = []

        if chain_type and chain_type in self.detectors:
            # Analyze with specific chain detector
            detector = self.detectors[chain_type]
            vulnerabilities = detector.analyze_contract(content, contract_path)
            all_vulnerabilities.extend(vulnerabilities)
        else:
            # Analyze with all detectors (for multi-chain contracts or unknown chains)
            for detector in self.detectors.values():
                vulnerabilities = detector.analyze_contract(content, contract_path)
                all_vulnerabilities.extend(vulnerabilities)

        return all_vulnerabilities

    def get_supported_chains(self) -> List[ChainType]:
        """Get list of supported chain types."""
        return list(self.detectors.keys())
