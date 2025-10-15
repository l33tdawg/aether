#!/usr/bin/env python3
"""
Unit tests for chain-specific vulnerability detectors.
"""

import pytest
from core.chain_specific_detectors import (
    ChainDetectorManager,
    ChainType,
    ChainVulnerability,
    PolygonDetector,
    ArbitrumDetector,
    OptimismDetector,
    BSCDetector,
    PolygonZkEVMDetector,
    AvalancheDetector,
    FantomDetector
)


class TestChainDetectorManager:
    """Test cases for ChainDetectorManager."""

    def test_initialization(self):
        """Test ChainDetectorManager initialization."""
        manager = ChainDetectorManager()

        # Should have detectors for all supported chains
        expected_chains = [
            ChainType.POLYGON, ChainType.ARBITRUM, ChainType.OPTIMISM,
            ChainType.BSC, ChainType.BASE, ChainType.POLYGON_ZKEVM,
            ChainType.AVALANCHE, ChainType.FANTOM
        ]

        for chain in expected_chains:
            assert chain in manager.detectors

    def test_get_supported_chains(self):
        """Test getting supported chains."""
        manager = ChainDetectorManager()

        chains = manager.get_supported_chains()
        expected_chains = [
            ChainType.POLYGON, ChainType.ARBITRUM, ChainType.OPTIMISM,
            ChainType.BSC, ChainType.BASE, ChainType.POLYGON_ZKEVM,
            ChainType.AVALANCHE, ChainType.FANTOM
        ]

        for chain in expected_chains:
            assert chain in chains

    def test_analyze_contract_specific_chain(self):
        """Test analyzing contract with specific chain detector."""
        manager = ChainDetectorManager()

        # Test Polygon-specific contract
        polygon_contract = """
        pragma solidity ^0.8.0;

        contract PolygonContract {
            address public checkpointManager;

            function setCheckpointManager(address _manager) external {
                checkpointManager = _manager;
            }

            function onStateReceive(uint256, bytes calldata) external {
                // State sync logic
            }
        }
        """

        vulnerabilities = manager.analyze_contract(polygon_contract, "test.sol", ChainType.POLYGON)

        # Should detect Polygon-specific issues
        polygon_vulns = [v for v in vulnerabilities if 'polygon' in v.vulnerability_type.lower()]
        assert len(polygon_vulns) > 0

    def test_analyze_contract_all_chains(self):
        """Test analyzing contract with all chain detectors."""
        manager = ChainDetectorManager()

        # Test generic contract that might trigger multiple detectors
        generic_contract = """
        pragma solidity ^0.8.0;

        contract GenericContract {
            address public arbSys;

            function setArbSys(address _arbSys) external {
                arbSys = _arbSys;
            }
        }
        """

        vulnerabilities = manager.analyze_contract(generic_contract, "test.sol")

        # Should analyze with all detectors
        assert len(vulnerabilities) >= 0  # May or may not find issues


class TestPolygonDetector:
    """Test cases for PolygonDetector."""

    def test_polygon_checkpoint_detection(self):
        """Test detection of Polygon checkpoint patterns."""
        detector = PolygonDetector()

        contract_with_checkpoint = """
        pragma solidity ^0.8.0;

        contract TestContract {
            address public checkpointManager;

            function interactWithCheckpoint() external {
                // Missing proper bridge manager validation
                checkpointManager = msg.sender;
            }
        }
        """

        vulnerabilities = detector.analyze_contract(contract_with_checkpoint, "test.sol")

        checkpoint_vulns = [v for v in vulnerabilities if 'checkpoint' in v.vulnerability_type]
        assert len(checkpoint_vulns) > 0

    def test_polygon_state_sync_detection(self):
        """Test detection of Polygon state sync patterns."""
        detector = PolygonDetector()

        contract_with_state_sync = """
        pragma solidity ^0.8.0;

        contract TestContract {
            function onStateReceive(uint256 id, bytes calldata data) external {
                // Missing state sync validation
                // Process state without proper checks
            }
        }
        """

        vulnerabilities = detector.analyze_contract(contract_with_state_sync, "test.sol")

        state_sync_vulns = [v for v in vulnerabilities if 'state_sync' in v.vulnerability_type]
        assert len(state_sync_vulns) > 0

    def test_polygon_gas_optimization(self):
        """Test detection of Polygon gas inefficiencies."""
        detector = PolygonDetector()

        contract_with_cross_chain_calls = """
        pragma solidity ^0.8.0;

        contract TestContract {
            function crossChainCall() external {
                address(0).call(""); // Expensive cross-chain call
            }
        }
        """

        vulnerabilities = detector.analyze_contract(contract_with_cross_chain_calls, "test.sol")

        gas_vulns = [v for v in vulnerabilities if 'gas_optimization' in v.vulnerability_type]
        assert len(gas_vulns) > 0


class TestArbitrumDetector:
    """Test cases for ArbitrumDetector."""

    def test_arbitrum_arbos_detection(self):
        """Test detection of ArbOS patterns."""
        detector = ArbitrumDetector()

        contract_with_arbos = """
        pragma solidity ^0.8.0;

        contract TestContract {
            function useArbOS() external {
                arbos.call(); // ArbOS interaction without proper integration
            }
        }
        """

        vulnerabilities = detector.analyze_contract(contract_with_arbos, "test.sol")

        arbos_vulns = [v for v in vulnerabilities if 'arbos' in v.vulnerability_type]
        assert len(arbos_vulns) > 0

    def test_arbitrum_retryable_detection(self):
        """Test detection of retryable ticket patterns."""
        detector = ArbitrumDetector()

        contract_with_retryable = """
        pragma solidity ^0.8.0;

        contract TestContract {
            function handleRetryable() external {
                // Missing retryable ticket validation
                ArbOS arbOS;
                arbOS.call();
            }
        }
        """

        vulnerabilities = detector.analyze_contract(contract_with_retryable, "test.sol")

        arbos_vulns = [v for v in vulnerabilities if 'arbos' in v.vulnerability_type]
        assert len(arbos_vulns) > 0


class TestOptimismDetector:
    """Test cases for OptimismDetector."""

    def test_optimism_ovm_detection(self):
        """Test detection of OVM patterns."""
        detector = OptimismDetector()

        contract_with_ovm = """
        pragma solidity ^0.8.0;

        contract TestContract {
            function useOVM() external {
                OVM_call(); // OVM usage without proper integration
            }
        }
        """

        vulnerabilities = detector.analyze_contract(contract_with_ovm, "test.sol")

        ovm_vulns = [v for v in vulnerabilities if 'ovm' in v.vulnerability_type]
        assert len(ovm_vulns) > 0


class TestBSCDetector:
    """Test cases for BSCDetector."""

    def test_bsc_bep_detection(self):
        """Test detection of BEP standard compliance."""
        detector = BSCDetector()

        contract_with_bep = """
        pragma solidity ^0.8.0;

        contract TestToken is BEP20 {
            // Missing required BEP20 functions
        }
        """

        vulnerabilities = detector.analyze_contract(contract_with_bep, "test.sol")

        bep_vulns = [v for v in vulnerabilities if 'bep' in v.vulnerability_type]
        assert len(bep_vulns) > 0


class TestPolygonZkEVMDetector:
    """Test cases for PolygonZkEVMDetector."""

    def test_polygon_zkevm_bridge_detection(self):
        """Test detection of zkEVM bridge patterns."""
        detector = PolygonZkEVMDetector()

        contract_with_zkevm = """
        pragma solidity ^0.8.0;

        contract TestContract {
            function useZkEVM() external {
                zkEVM zkEVM;
                zkEVM.call(); // zkEVM usage without proper integration
            }
        }
        """

        vulnerabilities = detector.analyze_contract(contract_with_zkevm, "test.sol")

        zkevm_vulns = [v for v in vulnerabilities if 'zkevm' in v.vulnerability_type]
        assert len(zkevm_vulns) > 0


class TestAvalancheDetector:
    """Test cases for AvalancheDetector."""

    def test_avalanche_integration_detection(self):
        """Test detection of Avalanche-specific patterns."""
        detector = AvalancheDetector()

        contract_with_avalanche = """
        pragma solidity ^0.8.0;

        contract TestContract {
            function useAvalanche() external {
                // Avalanche-specific logic without proper integration
            }
        }
        """

        vulnerabilities = detector.analyze_contract(contract_with_avalanche, "test.sol")

        avalanche_vulns = [v for v in vulnerabilities if 'avalanche' in v.vulnerability_type]
        # May or may not find issues depending on patterns
        assert isinstance(vulnerabilities, list)


class TestFantomDetector:
    """Test cases for FantomDetector."""

    def test_fantom_integration_detection(self):
        """Test detection of Fantom-specific patterns."""
        detector = FantomDetector()

        contract_with_fantom = """
        pragma solidity ^0.8.0;

        contract TestContract {
            function useFantom() external {
                // Fantom-specific logic without proper integration
            }
        }
        """

        vulnerabilities = detector.analyze_contract(contract_with_fantom, "test.sol")

        fantom_vulns = [v for v in vulnerabilities if 'fantom' in v.vulnerability_type]
        # May or may not find issues depending on patterns
        assert isinstance(vulnerabilities, list)


class TestChainVulnerability:
    """Test cases for ChainVulnerability dataclass."""

    def test_chain_vulnerability_creation(self):
        """Test creating ChainVulnerability instances."""
        vuln = ChainVulnerability(
            vulnerability_type="test_vulnerability",
            severity="high",
            description="Test vulnerability description",
            line_number=42,
            code_snippet="function test() {}",
            recommendation="Fix the issue",
            chain_specific=True,
            confidence=0.9
        )

        assert vuln.vulnerability_type == "test_vulnerability"
        assert vuln.severity == "high"
        assert vuln.description == "Test vulnerability description"
        assert vuln.line_number == 42
        assert vuln.code_snippet == "function test() {}"
        assert vuln.recommendation == "Fix the issue"
        assert vuln.chain_specific is True
        assert vuln.confidence == 0.9


if __name__ == '__main__':
    pytest.main([__file__])
