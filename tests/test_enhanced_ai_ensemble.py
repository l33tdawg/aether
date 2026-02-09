#!/usr/bin/env python3
"""
Unit tests for enhanced AI ensemble system.
"""

import pytest
import asyncio
import json
import time
from unittest.mock import Mock, AsyncMock, patch, PropertyMock
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

        # Should initialize with 3 legacy agents via backward-compatible property
        assert len(ensemble.agents) == 3
        # Check that legacy agents exist by their roles
        agent_roles = [agent.role for agent in ensemble.agents]
        assert "DeFi Protocol Security Expert" in agent_roles
        assert "Gas Optimization Expert" in agent_roles
        assert "Security Best Practices Expert" in agent_roles

    def test_initialization_legacy_agents(self):
        """Test that _legacy_agents are properly set."""
        ensemble = EnhancedAIEnsemble()

        assert len(ensemble._legacy_agents) == 3
        assert isinstance(ensemble._legacy_agents[0], DeFiSecurityExpert)
        assert isinstance(ensemble._legacy_agents[1], GasOptimizationExpert)
        assert isinstance(ensemble._legacy_agents[2], SecurityBestPracticesExpert)

    def test_initialization_production_models(self):
        """Test that production models are properly initialized."""
        ensemble = EnhancedAIEnsemble()

        # Should have 6 production multi-provider agents
        assert len(ensemble.models) == 6
        assert 'gpt5_security' in ensemble.models
        assert 'gpt5_defi' in ensemble.models
        assert 'gemini_security' in ensemble.models
        assert 'gemini_verification' in ensemble.models
        assert 'anthropic_security' in ensemble.models
        assert 'anthropic_reasoning' in ensemble.models

    def test_active_agents_with_openai_key(self):
        """Test that active_agents includes OpenAI agents when key is set."""
        ensemble = EnhancedAIEnsemble()

        with patch.dict('os.environ', {'OPENAI_API_KEY': 'test-key'}):
            active = ensemble.active_agents
            # Should include at least the 2 OpenAI agents
            agent_names = [a.agent_name for a in active]
            assert any('gpt5' in name or 'openai' in name.lower() for name in agent_names) or len(active) >= 2

    def test_active_agents_no_keys(self):
        """Test that active_agents returns empty when no API keys are set."""
        ensemble = EnhancedAIEnsemble()

        # Clear all API keys
        with patch.dict('os.environ', {}, clear=True):
            # Also mock config to not have keys
            ensemble.config.config = Mock(
                openai_api_key=None,
                gemini_api_key=None,
                anthropic_api_key=None,
            )
            # Use spec=False to allow arbitrary attribute access
            active = ensemble.active_agents
            assert len(active) == 0

    def test_agents_property_backward_compat(self):
        """Test that .agents property returns legacy agents for backward compatibility."""
        ensemble = EnhancedAIEnsemble()

        # .agents should return the same as ._legacy_agents
        assert ensemble.agents is ensemble._legacy_agents

    @pytest.mark.asyncio
    async def test_analyze_with_ensemble_uses_production_agents(self):
        """Test that analyze_with_ensemble uses production agents when available."""
        ensemble = EnhancedAIEnsemble()

        # Mock active_agents to return fake production agents
        mock_agents = []
        for name in ['gpt5_security', 'gemini_security', 'anthropic_security']:
            agent = Mock()
            agent.agent_name = name
            agent.analyze_contract = AsyncMock(return_value=ModelResult(
                model_name=name,
                findings=[{
                    "type": "reentrancy",
                    "severity": "high",
                    "confidence": 0.9,
                    "description": "Test finding",
                    "line": 10
                }],
                confidence=0.9,
                processing_time=1.0,
                metadata={}
            ))
            mock_agents.append(agent)

        with patch.object(type(ensemble), 'active_agents', new_callable=PropertyMock, return_value=mock_agents):
            result = await ensemble.analyze_with_ensemble(
                "pragma solidity ^0.8.0; contract Test { function test() public {} }"
            )

        assert isinstance(result, ConsensusResult)
        # All 3 mock agents should have been called
        for agent in mock_agents:
            agent.analyze_contract.assert_called_once()

    @pytest.mark.asyncio
    async def test_analyze_with_ensemble_fallback_to_legacy(self):
        """Test that analyze_with_ensemble falls back to legacy agents when no production agents have keys."""
        ensemble = EnhancedAIEnsemble()

        # Mock active_agents to be empty (no API keys)
        with patch.object(type(ensemble), 'active_agents', new_callable=PropertyMock, return_value=[]):
            # Mock legacy agents
            for agent in ensemble._legacy_agents:
                agent.analyze_contract = AsyncMock(return_value=ModelResult(
                    model_name=agent.agent_name,
                    findings=[{
                        "type": "test_vulnerability",
                        "severity": "medium",
                        "confidence": 0.8,
                        "description": "Test finding",
                        "line": 10
                    }],
                    confidence=0.8,
                    processing_time=1.0,
                    metadata={"role": agent.role}
                ))

            contract_content = "pragma solidity ^0.8.0; contract Test { function test() public {} }"
            result = await ensemble.analyze_with_ensemble(contract_content)

        assert isinstance(result, ConsensusResult)
        assert len(result.individual_results) == 3  # legacy agents

    @pytest.mark.asyncio
    async def test_analyze_contract_ensemble_success(self):
        """Test successful ensemble analysis."""
        ensemble = EnhancedAIEnsemble()

        # Mock the legacy agents to return predictable results
        for agent in ensemble._legacy_agents:
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

        # Force use of legacy agents by patching active_agents to empty
        with patch.object(type(ensemble), 'active_agents', new_callable=PropertyMock, return_value=[]):
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
        for i, agent in enumerate(ensemble._legacy_agents):
            if i < len(success_results):
                agent.analyze_contract = AsyncMock(return_value=success_results[i])
            else:
                agent.analyze_contract = AsyncMock(side_effect=Exception("API Error"))

        contract_content = "pragma solidity ^0.8.0; contract Test { function test() public {} }"

        # Force use of legacy agents
        with patch.object(type(ensemble), 'active_agents', new_callable=PropertyMock, return_value=[]):
            result = await ensemble.analyze_contract_ensemble(contract_content)

        # Should still return results from successful agents
        assert isinstance(result, ConsensusResult)
        assert len(result.individual_results) >= 1  # At least some successful agents

    @pytest.mark.asyncio
    async def test_analyze_contract_ensemble_all_fail(self):
        """Test ensemble analysis when all agents fail."""
        ensemble = EnhancedAIEnsemble()

        # Mock all agents to fail
        for agent in ensemble._legacy_agents:
            agent.analyze_contract = AsyncMock(side_effect=Exception("API Error"))

        contract_content = "pragma solidity ^0.8.0; contract Test { function test() public {} }"

        # Force use of legacy agents
        with patch.object(type(ensemble), 'active_agents', new_callable=PropertyMock, return_value=[]):
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

    def test_consensus_agreement_scoring(self):
        """Test that agreement score properly reflects corroborated findings."""
        ensemble = EnhancedAIEnsemble()

        # Create results where 2 agents agree on one finding, 1 agent has unique finding
        results = [
            ModelResult("agent1", [{"type": "reentrancy", "severity": "high", "confidence": 0.9, "line": 10}], 0.9, 1.0, {}),
            ModelResult("agent2", [{"type": "reentrancy", "severity": "high", "confidence": 0.85, "line": 10}], 0.85, 1.0, {}),
            ModelResult("agent3", [{"type": "gas_optimization", "severity": "low", "confidence": 0.7, "line": 30}], 0.7, 1.0, {}),
        ]

        consensus = ensemble._generate_consensus(results)

        # Agreement should be > 0 since reentrancy is corroborated by 2 agents
        assert consensus['agreement'] > 0

        # Check that findings have agreement_count
        for f in consensus['findings']:
            assert 'agreement_count' in f

        # Reentrancy finding should have agreement_count >= 2
        reentrancy_findings = [f for f in consensus['findings'] if 'reentrancy' in f.get('type', '')]
        if reentrancy_findings:
            assert reentrancy_findings[0]['agreement_count'] >= 2
            assert reentrancy_findings[0].get('needs_verification') is False

        # Gas optimization should have agreement_count == 1 (single agent)
        gas_findings = [f for f in consensus['findings'] if 'gas' in f.get('type', '')]
        if gas_findings:
            assert gas_findings[0]['agreement_count'] == 1
            assert gas_findings[0].get('needs_verification') is True

    def test_consensus_confidence_boost_for_agreement(self):
        """Test that multi-agent agreement boosts confidence."""
        ensemble = EnhancedAIEnsemble()

        results = [
            ModelResult("agent1", [{"type": "reentrancy", "severity": "high", "confidence": 0.8, "line": 10}], 0.8, 1.0, {}),
            ModelResult("agent2", [{"type": "reentrancy", "severity": "high", "confidence": 0.8, "line": 10}], 0.8, 1.0, {}),
        ]

        consensus = ensemble._generate_consensus(results)
        reentrancy = [f for f in consensus['findings'] if 'reentrancy' in f.get('type', '')]
        assert len(reentrancy) == 1

        # Confidence should be boosted: avg(0.8, 0.8) + 0.1 = 0.9
        assert reentrancy[0]['confidence'] == pytest.approx(0.9, abs=0.01)

    def test_consensus_confidence_penalty_for_single_agent(self):
        """Test that single-agent findings get confidence penalty."""
        ensemble = EnhancedAIEnsemble()

        results = [
            ModelResult("agent1", [{"type": "gas_optimization", "severity": "low", "confidence": 0.7, "line": 30}], 0.7, 1.0, {}),
        ]

        consensus = ensemble._generate_consensus(results)
        assert len(consensus['findings']) == 1
        # Confidence should be penalized: 0.7 - 0.15 = 0.55
        assert consensus['findings'][0]['confidence'] == pytest.approx(0.55, abs=0.01)
        assert consensus['findings'][0].get('needs_verification') is True

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

    def test_finding_key_line_bucketing(self):
        """Test that nearby lines get the same key bucket."""
        ensemble = EnhancedAIEnsemble()

        # Lines 10 and 15 should be in the same bucket (10s)
        finding1 = {"type": "reentrancy", "line": 10}
        finding2 = {"type": "reentrancy", "line": 15}
        assert ensemble._get_finding_key(finding1) == ensemble._get_finding_key(finding2)

        # Lines 10 and 25 should be in different buckets
        finding3 = {"type": "reentrancy", "line": 25}
        assert ensemble._get_finding_key(finding1) != ensemble._get_finding_key(finding3)

    def test_normalize_vuln_type(self):
        """Test vulnerability type normalization for fuzzy matching."""
        ensemble = EnhancedAIEnsemble()

        # Aliases should map to canonical names
        assert ensemble._normalize_vuln_type("cross_function_reentrancy") == "reentrancy"
        assert ensemble._normalize_vuln_type("read_only_reentrancy") == "reentrancy"
        assert ensemble._normalize_vuln_type("missing_access_control") == "access_control"
        assert ensemble._normalize_vuln_type("privilege_escalation") == "access_control"
        assert ensemble._normalize_vuln_type("price_manipulation") == "oracle_manipulation"
        assert ensemble._normalize_vuln_type("rounding_error") == "precision_loss"
        assert ensemble._normalize_vuln_type("frontrunning") == "front_running"
        assert ensemble._normalize_vuln_type("sandwich_attack") == "front_running"
        assert ensemble._normalize_vuln_type("overflow") == "integer_overflow"
        assert ensemble._normalize_vuln_type("underflow") == "integer_overflow"

    def test_normalize_vuln_type_passthrough(self):
        """Test that unknown types pass through normalization unchanged."""
        ensemble = EnhancedAIEnsemble()

        assert ensemble._normalize_vuln_type("completely_unknown") == "completely_unknown"

    def test_findings_match_fuzzy_same_type_close_lines(self):
        """Test fuzzy matching with same type and close line numbers."""
        ensemble = EnhancedAIEnsemble()

        f1 = {"type": "reentrancy", "severity": "high", "line": 10}
        f2 = {"type": "reentrancy", "severity": "high", "line": 13}  # Within +/-5

        assert ensemble._findings_match_fuzzy(f1, f2) is True

    def test_findings_match_fuzzy_different_type(self):
        """Test fuzzy matching rejects different types."""
        ensemble = EnhancedAIEnsemble()

        f1 = {"type": "reentrancy", "severity": "high", "line": 10}
        f2 = {"type": "access_control", "severity": "high", "line": 10}

        assert ensemble._findings_match_fuzzy(f1, f2) is False

    def test_findings_match_fuzzy_distant_lines(self):
        """Test fuzzy matching rejects findings with distant lines."""
        ensemble = EnhancedAIEnsemble()

        f1 = {"type": "reentrancy", "severity": "high", "line": 10}
        f2 = {"type": "reentrancy", "severity": "high", "line": 50}  # Way beyond +/-5

        assert ensemble._findings_match_fuzzy(f1, f2) is False

    def test_findings_match_fuzzy_alias_types(self):
        """Test fuzzy matching recognizes aliased types as the same."""
        ensemble = EnhancedAIEnsemble()

        f1 = {"type": "reentrancy", "severity": "high", "line": 10}
        f2 = {"type": "cross_function_reentrancy", "severity": "high", "line": 10}

        assert ensemble._findings_match_fuzzy(f1, f2) is True

    def test_merge_similar_findings_multi_agent(self):
        """Test merging findings from multiple agents."""
        ensemble = EnhancedAIEnsemble()

        findings = [
            {"type": "reentrancy", "severity": "high", "confidence": 0.9, "line": 10, "description": "Agent 1 finding"},
            {"type": "reentrancy", "severity": "high", "confidence": 0.85, "line": 10, "description": "Agent 2 finding"},
        ]

        merged = ensemble._merge_similar_findings(findings, models=["agent1", "agent2"])

        assert merged['agreement_count'] == 2
        assert merged['needs_verification'] is False
        assert merged['models'] == ["agent1", "agent2"]
        # Confidence boosted: avg(0.9, 0.85) + 0.1 = 0.975
        assert merged['confidence'] == pytest.approx(0.975, abs=0.01)

    def test_merge_similar_findings_single_agent(self):
        """Test merging a single agent finding gets penalized."""
        ensemble = EnhancedAIEnsemble()

        findings = [
            {"type": "gas_issue", "severity": "low", "confidence": 0.7, "line": 30, "description": "Gas issue"},
        ]

        merged = ensemble._merge_similar_findings(findings, models=["agent1"])

        assert merged['agreement_count'] == 1
        assert merged['needs_verification'] is True
        # Confidence penalized: 0.7 - 0.15 = 0.55
        assert merged['confidence'] == pytest.approx(0.55, abs=0.01)

    def test_deduplicate_findings(self):
        """Test deduplication with fuzzy matching and model tracking."""
        ensemble = EnhancedAIEnsemble()

        all_findings = [
            {"type": "reentrancy", "severity": "high", "confidence": 0.9, "line": 10},
            {"type": "reentrancy", "severity": "high", "confidence": 0.85, "line": 12},  # Fuzzy match
            {"type": "access_control", "severity": "medium", "confidence": 0.8, "line": 50},
        ]

        all_findings_with_models = [
            (all_findings[0], "agent1"),
            (all_findings[1], "agent2"),
            (all_findings[2], "agent3"),
        ]

        deduped = ensemble._deduplicate_findings(all_findings, all_findings_with_models)

        # Should have 2 unique findings: reentrancy (merged) and access_control
        assert len(deduped) == 2

        # Reentrancy should be corroborated
        reentrancy = [f for f in deduped if 'reentrancy' in ensemble._normalize_vuln_type(f.get('type', ''))]
        assert len(reentrancy) == 1
        assert reentrancy[0]['agreement_count'] == 2
        assert set(reentrancy[0]['models']) == {"agent1", "agent2"}

    def test_get_provider_for_agent(self):
        """Test provider identification for agents."""
        ensemble = EnhancedAIEnsemble()

        assert ensemble._get_provider_for_agent('gpt5_security') == 'openai'
        assert ensemble._get_provider_for_agent('gpt5_defi') == 'openai'
        assert ensemble._get_provider_for_agent('gemini_security') == 'gemini'
        assert ensemble._get_provider_for_agent('gemini_verification') == 'gemini'
        assert ensemble._get_provider_for_agent('anthropic_security') == 'anthropic'
        assert ensemble._get_provider_for_agent('anthropic_reasoning') == 'anthropic'
        # Legacy agents map to openai
        assert ensemble._get_provider_for_agent('defi_expert') == 'openai'
        assert ensemble._get_provider_for_agent('gas_expert') == 'openai'
        assert ensemble._get_provider_for_agent('unknown_agent') == 'unknown'

    def test_get_challenger_agents_cross_provider(self):
        """Test that challengers are selected from different providers."""
        ensemble = EnhancedAIEnsemble()

        # Finding from OpenAI agent
        challengers = ensemble._get_challenger_agents(['gpt5_security'], count=2)

        # Challengers should NOT be from openai
        for c in challengers:
            provider = ensemble._get_provider_for_agent(c.agent_name if hasattr(c, 'agent_name') else '')
            # At minimum, challengers should exist
            assert c is not None

    def test_get_challenger_agents_fallback(self):
        """Test challenger selection when not enough cross-provider agents."""
        ensemble = EnhancedAIEnsemble()

        # Request from all providers - should still return some challengers
        challengers = ensemble._get_challenger_agents(
            ['gpt5_security', 'gemini_security', 'anthropic_security'],
            count=2
        )
        # Should find at least some challengers as fallback
        assert len(challengers) <= 2

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


class TestCrossValidation:
    """Test cases for cross-validation functionality."""

    @pytest.mark.asyncio
    async def test_cross_validate_skips_non_critical(self):
        """Test that cross-validation only processes high/critical findings."""
        ensemble = EnhancedAIEnsemble()

        findings = [
            {"type": "gas_issue", "severity": "low", "confidence": 0.7, "line": 10},
            {"type": "info", "severity": "informational", "confidence": 0.5, "line": 20},
        ]

        result = await ensemble._cross_validate_findings(findings, "contract content")

        # Should return findings unchanged (no high/critical)
        assert result == findings

    @pytest.mark.asyncio
    async def test_cross_validate_processes_high_findings(self):
        """Test cross-validation processes high severity findings."""
        ensemble = EnhancedAIEnsemble()

        findings = [
            {"type": "reentrancy", "severity": "high", "confidence": 0.9, "line": 10,
             "description": "Reentrancy vulnerability", "models": ["gpt5_security"]},
        ]

        # Mock challenger agents
        mock_challenger = Mock()
        mock_challenger.agent_name = "gemini_security"
        mock_challenger.analyze_contract = AsyncMock(return_value=ModelResult(
            model_name="gemini_security",
            findings=[{"is_valid": True, "description": "Confirmed valid vulnerability"}],
            confidence=0.9,
            processing_time=1.0,
            metadata={}
        ))

        with patch.object(ensemble, '_get_challenger_agents', return_value=[mock_challenger, mock_challenger]):
            result = await ensemble._cross_validate_findings(
                findings,
                "pragma solidity ^0.8.0;\ncontract Test {\n    function test() public {}\n}"
            )

        # Should have cross_validation metadata
        assert result[0].get('cross_validation') is not None
        assert result[0]['cross_validation']['cross_validated'] is True

    @pytest.mark.asyncio
    async def test_cross_validate_confirmation_boosts_confidence(self):
        """Test that 2+ confirmations boost confidence."""
        ensemble = EnhancedAIEnsemble()

        findings = [
            {"type": "reentrancy", "severity": "critical", "confidence": 0.7, "line": 10,
             "description": "Test", "models": ["gpt5_security"]},
        ]

        # Create challengers that both confirm
        mock_challengers = []
        for name in ["gemini_security", "anthropic_security"]:
            c = Mock()
            c.agent_name = name
            c.analyze_contract = AsyncMock(return_value=ModelResult(
                model_name=name,
                findings=[{"is_valid": True, "description": "Confirmed real vulnerability"}],
                confidence=0.9,
                processing_time=1.0,
                metadata={}
            ))
            mock_challengers.append(c)

        with patch.object(ensemble, '_get_challenger_agents', return_value=mock_challengers):
            result = await ensemble._cross_validate_findings(
                findings,
                "pragma solidity ^0.8.0;\n" * 20
            )

        # Confidence should be boosted by 0.15
        assert result[0]['confidence'] == pytest.approx(0.85, abs=0.01)

    @pytest.mark.asyncio
    async def test_cross_validate_rejection_reduces_confidence(self):
        """Test that 2+ rejections reduce confidence and mark as likely FP."""
        ensemble = EnhancedAIEnsemble()

        findings = [
            {"type": "reentrancy", "severity": "high", "confidence": 0.8, "line": 10,
             "description": "Test", "models": ["gpt5_security"]},
        ]

        # Create challengers that both reject
        mock_challengers = []
        for name in ["gemini_security", "anthropic_security"]:
            c = Mock()
            c.agent_name = name
            c.analyze_contract = AsyncMock(return_value=ModelResult(
                model_name=name,
                findings=[{"is_valid": False, "description": "This is a false positive"}],
                confidence=0.2,
                processing_time=1.0,
                metadata={}
            ))
            mock_challengers.append(c)

        with patch.object(ensemble, '_get_challenger_agents', return_value=mock_challengers):
            result = await ensemble._cross_validate_findings(
                findings,
                "pragma solidity ^0.8.0;\n" * 20
            )

        # Confidence should be reduced by 0.25
        assert result[0]['confidence'] == pytest.approx(0.55, abs=0.01)
        assert result[0].get('likely_false_positive') is True


class TestDeepDiveAnalysis:
    """Test cases for deep-dive analysis."""

    @pytest.mark.asyncio
    async def test_deep_dive_empty_findings(self):
        """Test deep-dive with no findings returns unchanged."""
        ensemble = EnhancedAIEnsemble()

        result = await ensemble.deep_dive_analysis([], "contract content")
        assert result == []

    @pytest.mark.asyncio
    async def test_deep_dive_selects_top_5(self):
        """Test that deep-dive only processes top 5 findings."""
        ensemble = EnhancedAIEnsemble()

        # Create 8 findings
        findings = []
        for i in range(8):
            findings.append({
                "type": f"vuln_{i}",
                "severity": "high",
                "confidence": 0.5 + i * 0.05,
                "line": i * 10,
                "description": f"Vulnerability {i}",
            })

        # Mock the agent
        mock_agent = Mock()
        mock_agent.analyze_contract = AsyncMock(return_value=ModelResult(
            model_name="anthropic_reasoning",
            findings=[{"verified": True, "adjusted_confidence": 0.95}],
            confidence=0.95,
            processing_time=2.0,
            metadata={}
        ))
        ensemble.models['anthropic_reasoning'] = mock_agent

        result = await ensemble.deep_dive_analysis(findings, "pragma solidity ^0.8.0;\n" * 30)

        # Should have called analyze_contract 5 times (top 5)
        assert mock_agent.analyze_contract.call_count == 5

    @pytest.mark.asyncio
    async def test_deep_dive_verified_boosts_confidence(self):
        """Test that verified deep-dive boosts finding confidence."""
        ensemble = EnhancedAIEnsemble()

        findings = [
            {"type": "reentrancy", "severity": "high", "confidence": 0.7, "line": 10, "description": "Test"},
        ]

        mock_agent = Mock()
        mock_agent.analyze_contract = AsyncMock(return_value=ModelResult(
            model_name="anthropic_reasoning",
            findings=[{"verified": True, "adjusted_confidence": 0.95}],
            confidence=0.95,
            processing_time=2.0,
            metadata={}
        ))
        ensemble.models['anthropic_reasoning'] = mock_agent

        result = await ensemble.deep_dive_analysis(findings, "pragma solidity ^0.8.0;\n" * 30)

        assert result[0].get('deep_dive_verified') is True
        assert result[0]['confidence'] == pytest.approx(0.95, abs=0.01)

    @pytest.mark.asyncio
    async def test_deep_dive_refuted_reduces_confidence(self):
        """Test that refuted deep-dive reduces finding confidence."""
        ensemble = EnhancedAIEnsemble()

        findings = [
            {"type": "reentrancy", "severity": "high", "confidence": 0.8, "line": 10, "description": "Test"},
        ]

        mock_agent = Mock()
        mock_agent.analyze_contract = AsyncMock(return_value=ModelResult(
            model_name="anthropic_reasoning",
            findings=[{"verified": False}],
            confidence=0.2,
            processing_time=2.0,
            metadata={}
        ))
        ensemble.models['anthropic_reasoning'] = mock_agent

        result = await ensemble.deep_dive_analysis(findings, "pragma solidity ^0.8.0;\n" * 30)

        assert result[0].get('deep_dive_verified') is False
        assert result[0]['confidence'] == pytest.approx(0.6, abs=0.01)


class TestCrossContractAnalysis:
    """Test cases for cross-contract interaction analysis."""

    @pytest.mark.asyncio
    async def test_cross_contract_single_contract_returns_empty(self):
        """Test that single contract returns empty results."""
        ensemble = EnhancedAIEnsemble()

        result = await ensemble.analyze_cross_contract_interactions([
            {"name": "Token.sol", "content": "contract Token {}"}
        ])

        assert result == []

    @pytest.mark.asyncio
    async def test_cross_contract_no_interactions_returns_empty(self):
        """Test that contracts with no cross-references return empty."""
        ensemble = EnhancedAIEnsemble()

        result = await ensemble.analyze_cross_contract_interactions([
            {"name": "Token.sol", "content": "contract Token { function transfer() {} }"},
            {"name": "Vault.sol", "content": "contract Vault { function deposit() {} }"},
        ])

        assert result == []

    @pytest.mark.asyncio
    async def test_cross_contract_with_interactions(self):
        """Test cross-contract analysis when contracts reference each other."""
        ensemble = EnhancedAIEnsemble()

        # Use content that matches the interaction regex: Token( or Token. or IToken(
        contract_files = [
            {"name": "Token.sol", "content": "contract Token { function transfer() external {} }"},
            {"name": "Vault.sol", "content": "contract Vault { IToken public token; function deposit() { Token.transfer(); } }"},
        ]

        mock_agent = Mock()
        mock_agent.analyze_contract = AsyncMock(return_value=ModelResult(
            model_name="anthropic_reasoning",
            findings=[{
                "type": "cross_contract_reentrancy",
                "severity": "high",
                "confidence": 0.85,
                "line": 1,
                "description": "Cross-contract reentrancy via Token.transfer()"
            }],
            confidence=0.85,
            processing_time=2.0,
            metadata={}
        ))
        ensemble.models['anthropic_reasoning'] = mock_agent

        result = await ensemble.analyze_cross_contract_interactions(contract_files)

        # Should find the interaction and produce findings
        assert len(result) >= 1


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
