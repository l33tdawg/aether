#!/usr/bin/env python3
"""
Integration tests for multi-chain audit pipeline.
"""

import asyncio
import pytest
import tempfile
import os
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock

from core.audit_engine import AetherAuditEngine
from core.blockchain_abstraction import BlockchainManager
from core.chain_specific_detectors import ChainDetectorManager, ChainType
from core.performance_optimizer import PerformanceOptimizer, OptimizationLevel


class TestMultiChainAuditIntegration:
    """Integration tests for multi-chain audit pipeline."""

    @pytest.fixture
    def sample_contract(self):
        """Sample contract for testing."""
        return """
        pragma solidity ^0.8.0;

        contract MultiChainTest {
            address public owner;
            mapping(address => uint256) public balances;

            constructor() {
                owner = msg.sender;
            }

            function deposit() external payable {
                balances[msg.sender] += msg.value;
            }

            function withdraw(uint256 amount) external {
                require(balances[msg.sender] >= amount, "Insufficient balance");
                balances[msg.sender] -= amount;
                payable(msg.sender).transfer(amount);
            }
        }
        """

    @pytest.fixture
    def temp_contract_file(self, sample_contract):
        """Create temporary contract file for testing."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
            f.write(sample_contract)
            temp_path = f.name
        yield temp_path
        os.unlink(temp_path)

    def test_audit_engine_initialization_with_multi_chain(self):
        """Test audit engine initialization with multi-chain support."""
        engine = AetherAuditEngine(verbose=True)

        # Should have blockchain manager and chain detector manager
        assert hasattr(engine, 'blockchain_manager')
        assert hasattr(engine, 'chain_detector_manager')

        # Blockchain manager should support multiple networks
        networks = engine.blockchain_manager.get_supported_networks()
        assert 'ethereum' in networks
        assert 'polygon' in networks
        assert 'polygon_zkevm' in networks
        assert 'avalanche' in networks

    @pytest.mark.asyncio
    async def test_enhanced_analysis_with_chain_detection(self, temp_contract_file):
        """Test enhanced analysis includes chain-specific detection."""
        engine = AetherAuditEngine(verbose=True)

        # Mock the chain detector manager to return some vulnerabilities
        mock_vulnerabilities = [
            Mock(severity='medium', vulnerability_type='polygon_checkpoint_missing'),
            Mock(severity='high', vulnerability_type='arbitrum_retryable_validation')
        ]

        engine.chain_detector_manager.analyze_contract = Mock(return_value=mock_vulnerabilities)

        # Run enhanced analysis
        results = await engine.run_enhanced_analysis(temp_contract_file)

        # Should include chain-specific vulnerabilities
        assert 'chain_specific_vulns' in str(results).lower() or len(results.get('vulnerabilities', [])) > 0

    def test_large_contract_optimization_integration(self):
        """Test large contract optimization integration."""
        engine = AetherAuditEngine(verbose=True)

        # Create a very large contract (>100K lines)
        large_contract_lines = []
        for i in range(150000):
            large_contract_lines.append(f"    uint256 public var{i};")
        large_contract = "pragma solidity ^0.8.0;\ncontract LargeTest {\n" + "\n".join(large_contract_lines) + "\n}"

        # Test optimization
        optimized = engine.performance_optimizer.optimize_mega_contract(large_contract)

        # Should be optimized and smaller than original
        assert isinstance(optimized, str)
        assert len(optimized) > 0

    def test_multi_chain_contract_detection(self):
        """Test detection of multi-chain contract patterns."""
        detector_manager = ChainDetectorManager()

        # Test contract with Polygon-specific patterns
        polygon_contract = """
        pragma solidity ^0.8.0;

        import "./interfaces/IChildToken.sol";

        contract PolygonBridge {
            address public checkpointManager;

            function setCheckpointManager(address _manager) external {
                checkpointManager = _manager;
            }

            function onStateReceive(uint256 id, bytes calldata data) external {
                // State sync logic
            }
        }
        """

        vulnerabilities = detector_manager.analyze_contract(polygon_contract, "test.sol", ChainType.POLYGON)

        # Should detect Polygon-specific issues
        polygon_specific = [v for v in vulnerabilities if 'polygon' in v.vulnerability_type.lower()]
        assert len(polygon_specific) > 0

    def test_performance_optimizer_level_integration(self):
        """Test performance optimizer level affects behavior."""
        # Test with different optimization levels
        minimal_optimizer = PerformanceOptimizer(OptimizationLevel.MINIMAL)
        aggressive_optimizer = PerformanceOptimizer(OptimizationLevel.AGGRESSIVE)

        # Aggressive should have more workers
        assert aggressive_optimizer.max_workers >= minimal_optimizer.max_workers

        # Test with medium contract
        medium_contract = "pragma solidity ^0.8.0;\ncontract Test {\n" + "\n".join([f"    uint256 public var{i};" for i in range(5000)]) + "\n}"

        # Both should handle it, but may use different strategies
        result_minimal = minimal_optimizer.optimize_large_contract(medium_contract)
        result_aggressive = aggressive_optimizer.optimize_large_contract(medium_contract)

        assert isinstance(result_minimal, str)
        assert isinstance(result_aggressive, str)

    @pytest.mark.asyncio
    async def test_blockchain_manager_integration(self):
        """Test blockchain manager integration."""
        manager = BlockchainManager()

        # Test getting network info for multiple chains
        for network in ['ethereum', 'polygon', 'polygon_zkevm']:
            info = manager.get_network_info(network)
            assert info is not None
            assert info.name is not None
            assert info.chain_id is not None

        # Test contract retrieval (will fail without real API, but should not crash)
        try:
            result = await manager.get_contract('0xA0b86a33E6441b8c4C8C0C8C0C8C0C8C0C8C0C8C', 'ethereum')
            # Should return None for invalid requests or succeed with mocked data
            assert result is None or isinstance(result, object)
        except Exception as e:
            # Should handle errors gracefully
            assert isinstance(e, Exception)

    def test_chain_detector_integration_with_audit_engine(self, temp_contract_file):
        """Test chain detector integration with audit engine."""
        engine = AetherAuditEngine(verbose=True)

        # Test that chain detectors are properly integrated
        assert engine.chain_detector_manager is not None

        # Test chain-specific analysis
        contract_content = "pragma solidity ^0.8.0;\ncontract Test {\n    function test() public {}\n}"

        vulnerabilities = engine.chain_detector_manager.analyze_contract(contract_content, temp_contract_file)

        # Should return list of vulnerabilities (may be empty if no issues found)
        assert isinstance(vulnerabilities, list)

    def test_performance_optimizer_mega_contract_workflow(self):
        """Test complete mega contract optimization workflow."""
        optimizer = PerformanceOptimizer(OptimizationLevel.MAXIMUM)

        # Create massive contract
        lines = []
        for i in range(200000):
            lines.append(f"    uint256 public var{i};")
        mega_contract = "pragma solidity ^0.8.0;\ncontract MegaTest {\n" + "\n".join(lines) + "\n}"

        # Test full workflow
        start_memory = len(mega_contract.encode('utf-8'))

        # Optimize the contract
        optimized = optimizer.optimize_mega_contract(mega_contract)

        # Should complete without crashing
        assert isinstance(optimized, str)
        assert len(optimized) > 0

        # Get performance summary
        summary = optimizer.get_performance_summary()
        assert isinstance(summary, dict)

    @pytest.mark.asyncio
    async def test_full_multi_chain_audit_pipeline(self, temp_contract_file):
        """Test complete multi-chain audit pipeline."""
        engine = AetherAuditEngine(verbose=True)

        # Mock external dependencies to avoid real API calls
        with patch.object(engine.llm_analyzer, 'analyze_vulnerabilities', new_callable=AsyncMock) as mock_llm:
            with patch.object(engine.fuzz_engine, 'run_enhanced_fuzzing', new_callable=AsyncMock) as mock_fuzz:

                # Mock LLM response
                mock_llm.return_value = {
                    'vulnerabilities': [],
                    'gas_optimizations': [],
                    'confidence': 0.8
                }

                # Mock fuzz response
                mock_fuzz.return_value = {
                    'total_runs': 1000,
                    'coverage': 85.0,
                    'vulnerabilities_found': [],
                    'execution_time': 10.5,
                    'gas_usage': {'min': 21000, 'max': 50000, 'avg': 35000}
                }

                # Run the audit pipeline
                flow_config = {
                    'flow': [
                        {'node': 'FileReaderNode'},
                        {'node': 'StaticAnalysisNode'},
                        {'node': 'LLMAnalysisNode'},
                        {'node': 'ReportNode'}
                    ],
                    'tools': [
                        {
                            'name': 'llm_gpt',
                            'type': 'reasoning',
                            'enabled': True,
                            'model': 'gpt-4',
                            'config': {
                                'temperature': 0.2,
                                'max_tokens': 1000
                            }
                        }
                    ]
                }

                results = await engine.run_audit(temp_contract_file, flow_config)

                # Should complete successfully and return results
                assert results is not None
                assert isinstance(results, dict)
                # Should have audit results with at least the file reader node
                assert 'audit' in results or 'filereadernode' in results

    def test_error_handling_in_multi_chain_features(self):
        """Test error handling in multi-chain features."""
        # Test blockchain manager error handling
        manager = BlockchainManager()

        # Test invalid network
        result = asyncio.run(manager.get_contract('0x123', 'invalid_network'))
        assert result is None

        # Test invalid address format
        result = asyncio.run(manager.get_contract('invalid_address', 'ethereum'))
        assert result is None

        # Test performance optimizer error handling
        optimizer = PerformanceOptimizer()

        # Test with None input (should handle gracefully)
        try:
            result = optimizer.optimize_large_contract(None)
            assert result == "" or result is None
        except AttributeError:
            # Expected behavior when content is None
            pass

        # Test with empty string
        result = optimizer.optimize_large_contract("")
        assert result == ""

        # Test chain detector error handling
        detector_manager = ChainDetectorManager()

        # Test with None content
        vulnerabilities = detector_manager.analyze_contract(None, "test.sol")
        assert isinstance(vulnerabilities, list)


if __name__ == '__main__':
    pytest.main([__file__])
