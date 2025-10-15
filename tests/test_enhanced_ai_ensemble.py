#!/usr/bin/env python3
"""
Unit tests for enhanced AI ensemble system.
"""

import pytest
import asyncio
import json
import time
from unittest.mock import Mock, AsyncMock, patch
from pathlib import Path

from core.ai_ensemble import (
    EnhancedAIEnsemble,
    DeFiSecurityExpert,
    GasOptimizationExpert,
    SecurityBestPracticesExpert,
    ModelResult,
    ConsensusResult
)


class TestEnhancedAIEnsemble:
    """Test cases for EnhancedAIEnsemble."""

    def test_initialization(self):
        """Test EnhancedAIEnsemble initialization."""
        ensemble = EnhancedAIEnsemble()

        # Should initialize with 3 specialized agents
        assert len(ensemble.agents) == 3
        # Check that agents exist by their roles
        agent_roles = [agent.role for agent in ensemble.agents]
        assert "DeFi Protocol Security Expert" in agent_roles
        assert "Gas Optimization Expert" in agent_roles
        assert "Security Best Practices Expert" in agent_roles

    @pytest.mark.asyncio
    async def test_analyze_contract_ensemble_success(self):
        """Test successful ensemble analysis."""
        ensemble = EnhancedAIEnsemble()

        # Mock the agents to return predictable results
        for agent in ensemble.agents:
            agent.analyze_contract = AsyncMock(return_value=ModelResult(
                model_name=agent.agent_name,
                findings=[
                    {
                        "type": "test_vulnerability",
                        "severity": "medium",
                        "confidence": 0.8,
                        "description": "Test finding",
                        "line": 10
                    }
                ],
                confidence=0.8,
                processing_time=1.0,
                metadata={"role": agent.role}
            ))

        contract_content = "pragma solidity ^0.8.0; contract Test { function test() public {} }"

        result = await ensemble.analyze_contract_ensemble(contract_content)

        # Should return consensus result
        assert isinstance(result, ConsensusResult)
        assert len(result.consensus_findings) > 0
        assert result.model_agreement > 0
        assert result.confidence_score > 0
        assert len(result.individual_results) == 3

    @pytest.mark.asyncio
    async def test_analyze_contract_ensemble_partial_failure(self):
        """Test ensemble analysis with some agents failing."""
        ensemble = EnhancedAIEnsemble()

        # Mock agents to have mixed success/failure
        success_results = [
            ModelResult("defi_expert", [{"type": "defi_vuln", "severity": "high", "confidence": 0.9, "line": 10}], 0.9, 1.0, {}),
            ModelResult("gas_expert", [{"type": "gas_optimization", "severity": "medium", "confidence": 0.8, "line": 20}], 0.8, 1.0, {})
        ]

        # Set up agents to return success or failure
        for i, agent in enumerate(ensemble.agents):
            if i < len(success_results):
                agent.analyze_contract = AsyncMock(return_value=success_results[i])
            else:
                agent.analyze_contract = AsyncMock(side_effect=Exception("API Error"))

        contract_content = "pragma solidity ^0.8.0; contract Test { function test() public {} }"

        result = await ensemble.analyze_contract_ensemble(contract_content)

        # Should still return results from successful agents
        assert isinstance(result, ConsensusResult)
        assert len(result.individual_results) >= 1  # At least some successful agents

    @pytest.mark.asyncio
    async def test_analyze_contract_ensemble_all_fail(self):
        """Test ensemble analysis when all agents fail."""
        ensemble = EnhancedAIEnsemble()

        # Mock all agents to fail
        for agent in ensemble.agents:
            agent.analyze_contract = AsyncMock(side_effect=Exception("API Error"))

        contract_content = "pragma solidity ^0.8.0; contract Test { function test() public {} }"

        result = await ensemble.analyze_contract_ensemble(contract_content)

        # Should return empty consensus result
        assert isinstance(result, ConsensusResult)
        assert len(result.consensus_findings) == 0
        assert result.model_agreement == 0.0
        assert result.confidence_score == 0.0
        assert len(result.individual_results) == 0

    def test_consensus_generation(self):
        """Test consensus generation from multiple results."""
        ensemble = EnhancedAIEnsemble()

        # Create mock results with some overlapping findings
        results = [
            ModelResult(
                model_name="agent1",
                findings=[
                    {"type": "reentrancy", "severity": "high", "confidence": 0.9, "line": 10},
                    {"type": "access_control", "severity": "medium", "confidence": 0.8, "line": 20}
                ],
                confidence=0.9,
                processing_time=1.0,
                metadata={}
            ),
            ModelResult(
                model_name="agent2",
                findings=[
                    {"type": "reentrancy", "severity": "high", "confidence": 0.85, "line": 10},
                    {"type": "gas_optimization", "severity": "low", "confidence": 0.7, "line": 30}
                ],
                confidence=0.85,
                processing_time=1.0,
                metadata={}
            ),
            ModelResult(
                model_name="agent3",
                findings=[
                    {"type": "access_control", "severity": "medium", "confidence": 0.75, "line": 20}
                ],
                confidence=0.75,
                processing_time=1.0,
                metadata={}
            )
        ]

        consensus = ensemble._generate_consensus(results)

        # Should have consensus on findings that appear in multiple results
        assert 'findings' in consensus
        assert 'agreement' in consensus
        assert 'confidence' in consensus

        # Should have at least one consensus finding (reentrancy or access_control)
        assert len(consensus['findings']) >= 1

    def test_finding_similarity_key_generation(self):
        """Test finding similarity key generation."""
        ensemble = EnhancedAIEnsemble()

        finding1 = {"type": "reentrancy", "severity": "high", "line": 10}
        finding2 = {"type": "reentrancy", "severity": "high", "line": 10}
        finding3 = {"type": "access_control", "severity": "medium", "line": 20}

        key1 = ensemble._get_finding_key(finding1)
        key2 = ensemble._get_finding_key(finding2)
        key3 = ensemble._get_finding_key(finding3)

        # Same findings should have same key
        assert key1 == key2

        # Different findings should have different keys
        assert key1 != key3

    def test_learning_patterns_integration(self):
        """Test learning patterns integration."""
        ensemble = EnhancedAIEnsemble()

        # Mock database manager
        ensemble.db_manager.get_learning_patterns = Mock(return_value=[
            {
                'pattern_type': 'defi',
                'original_classification': 'false_positive',
                'corrected_classification': 'true_positive',
                'confidence_threshold': 0.8,
                'reasoning': 'Test pattern',
                'success_rate': 0.9
            }
        ])

        patterns = ensemble.get_learning_patterns()

        assert 'total_patterns' in patterns
        assert 'high_confidence_patterns' in patterns
        assert patterns['total_patterns'] >= 0

    def test_store_learning_pattern(self):
        """Test storing learning patterns."""
        ensemble = EnhancedAIEnsemble()

        # Mock database manager
        ensemble.db_manager.store_learning_pattern = Mock()

        ensemble.store_learning_pattern(
            pattern_type="test_type",
            original_classification="false_positive",
            corrected_classification="true_positive",
            reasoning="Test reasoning",
            source_audit_id="test_audit_123"
        )

        # Should call database store method
        ensemble.db_manager.store_learning_pattern.assert_called_once()


# Legacy test classes removed - using new specialized agents only


class TestModelResult:
    """Test cases for ModelResult dataclass."""

    def test_model_result_creation(self):
        """Test creating ModelResult instances."""
        result = ModelResult(
            model_name="test_model",
            findings=[
                {"type": "vulnerability", "severity": "high", "confidence": 0.9}
            ],
            confidence=0.85,
            processing_time=1.5,
            metadata={"test": "data"}
        )

        assert result.model_name == "test_model"
        assert len(result.findings) == 1
        assert result.confidence == 0.85
        assert result.processing_time == 1.5
        assert result.metadata["test"] == "data"


class TestConsensusResult:
    """Test cases for ConsensusResult dataclass."""

    def test_consensus_result_creation(self):
        """Test creating ConsensusResult instances."""
        individual_results = [
            ModelResult("model1", [], 0.8, 1.0, {}),
            ModelResult("model2", [], 0.9, 1.2, {})
        ]

        result = ConsensusResult(
            consensus_findings=[
                {"type": "consensus_vulnerability", "severity": "high", "confidence": 0.85}
            ],
            model_agreement=0.8,
            confidence_score=0.85,
            processing_time=2.2,
            individual_results=individual_results
        )

        assert len(result.consensus_findings) == 1
        assert result.model_agreement == 0.8
        assert result.confidence_score == 0.85
        assert result.processing_time == 2.2
        assert len(result.individual_results) == 2


if __name__ == '__main__':
    pytest.main([__file__])
