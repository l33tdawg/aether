"""Tests for the deep analysis engine."""

import asyncio
import json
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from core.deep_analysis_engine import (
    DeepAnalysisEngine,
    DeepAnalysisResult,
    PassResult,
    _build_pass1_prompt,
    _build_pass2_prompt,
    _build_pass3_prompt,
    _build_pass4_prompt,
    _build_pass5_prompt,
    _build_pass6_prompt,
    _content_hash,
)
from core.protocol_archetypes import (
    ArchetypeResult,
    ProtocolArchetype,
    ProtocolArchetypeDetector,
)


SAMPLE_CONTRACT = """
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol";

contract SimpleVault is ERC4626 {
    constructor(IERC20 asset_) ERC4626(asset_) ERC20("Vault", "vTKN") {}

    function totalAssets() public view override returns (uint256) {
        return IERC20(asset()).balanceOf(address(this));
    }

    function deposit(uint256 assets, address receiver) public override returns (uint256) {
        return super.deposit(assets, receiver);
    }
}
"""


class TestDeepAnalysisEngine(unittest.TestCase):
    """Test the DeepAnalysisEngine pipeline."""

    def setUp(self):
        # Mock LLM analyzer
        self.mock_llm = MagicMock()
        self.mock_llm._call_llm = AsyncMock()
        self.engine = DeepAnalysisEngine(self.mock_llm)

    def test_content_hash(self):
        h1 = _content_hash("hello")
        h2 = _content_hash("hello")
        h3 = _content_hash("world")
        self.assertEqual(h1, h2)
        self.assertNotEqual(h1, h3)
        self.assertEqual(len(h1), 16)

    def test_archetype_detection_in_engine(self):
        """Engine should detect archetype from contract code."""
        result = self.engine.archetype_detector.detect(SAMPLE_CONTRACT)
        self.assertEqual(result.primary, ProtocolArchetype.VAULT_ERC4626)

    def test_extract_findings_valid_json(self):
        response = json.dumps({
            "findings": [
                {
                    "type": "first_depositor_inflation",
                    "severity": "critical",
                    "confidence": 0.9,
                    "title": "First Depositor Attack",
                    "description": "Vault is vulnerable to share inflation",
                    "line": 10,
                }
            ]
        })
        findings = self.engine._extract_findings(response, "test_pass")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['type'], 'first_depositor_inflation')
        self.assertEqual(findings[0]['severity'], 'critical')
        self.assertEqual(findings[0]['source'], 'deep_analysis_test_pass')

    def test_extract_findings_empty_json(self):
        findings = self.engine._extract_findings('{"findings": []}', "test")
        self.assertEqual(len(findings), 0)

    def test_extract_findings_invalid_json(self):
        findings = self.engine._extract_findings("not json at all", "test")
        self.assertEqual(len(findings), 0)

    def test_extract_findings_preserves_extra_fields(self):
        response = json.dumps({
            "findings": [{
                "type": "flash_loan_attack",
                "severity": "critical",
                "confidence": 0.85,
                "description": "Test",
                "attack_steps": ["Step 1", "Step 2"],
                "capital_required": "0",
                "profit_estimate": "1000 ETH",
                "line": 42,
            }]
        })
        findings = self.engine._extract_findings(response, "test")
        self.assertEqual(findings[0]['attack_steps'], ["Step 1", "Step 2"])
        self.assertEqual(findings[0]['capital_required'], "0")
        self.assertEqual(findings[0]['profit_estimate'], "1000 ETH")

    def test_summarize_findings_empty(self):
        summary = self.engine._summarize_findings([], "Test Section")
        self.assertIn("No findings", summary)

    def test_summarize_findings_with_data(self):
        findings = [
            {'severity': 'critical', 'title': 'Big Bug', 'description': 'Very bad'},
            {'severity': 'high', 'title': 'Medium Bug', 'description': 'Bad'},
        ]
        summary = self.engine._summarize_findings(findings, "Analysis")
        self.assertIn("2 findings", summary)
        self.assertIn("CRITICAL", summary)
        self.assertIn("Big Bug", summary)

    def test_deep_analysis_result_to_llm_format(self):
        result = DeepAnalysisResult(
            archetype=ArchetypeResult(primary=ProtocolArchetype.VAULT_ERC4626, confidence=0.9),
            all_findings=[
                {'type': 'vuln1', 'severity': 'high', 'line': 10, 'vulnerability_type': 'vuln1', 'line_number': 10},
                {'type': 'vuln2', 'severity': 'critical', 'line': 20, 'vulnerability_type': 'vuln2', 'line_number': 20},
            ],
            pass_results=[PassResult("test", "content", [])],
        )
        llm_format = result.to_llm_results_format()
        self.assertIn('analysis', llm_format)
        self.assertEqual(len(llm_format['analysis']['vulnerabilities']), 2)
        self.assertEqual(llm_format['analysis']['archetype'], 'vault_erc4626')
        self.assertTrue(llm_format['deep_analysis'])

    def test_deep_analysis_result_deduplication(self):
        result = DeepAnalysisResult(
            archetype=ArchetypeResult(primary=ProtocolArchetype.UNKNOWN, confidence=0.0),
            all_findings=[
                {'type': 'reentrancy', 'severity': 'high', 'line': 10, 'vulnerability_type': 'reentrancy', 'line_number': 10},
                {'type': 'reentrancy', 'severity': 'high', 'line': 10, 'vulnerability_type': 'reentrancy', 'line_number': 10},  # duplicate
            ],
        )
        llm_format = result.to_llm_results_format()
        self.assertEqual(len(llm_format['analysis']['vulnerabilities']), 1)

    def test_full_pipeline_with_mocked_llm(self):
        """Test the full pipeline with mocked LLM responses."""
        pass1_response = json.dumps({
            "protocol_archetype": "vault_erc4626",
            "core_purpose": "ERC-4626 vault",
            "value_flows": [],
            "invariants": [{"id": "INV-1", "description": "totalAssets >= totalSupply value", "related_state": ["totalAssets"], "critical": True}],
            "trust_assumptions": [],
            "state_variables": [],
            "external_dependencies": [],
        })
        pass2_response = json.dumps({
            "functions": [{"name": "deposit", "visibility": "public"}],
            "state_dependency_graph": [],
            "privileged_operations": [],
        })
        pass3_response = json.dumps({
            "findings": [{
                "type": "first_depositor_inflation",
                "severity": "critical",
                "confidence": 0.9,
                "title": "First Depositor Attack",
                "description": "No virtual shares protection",
                "line": 10,
            }]
        })
        pass4_response = json.dumps({"findings": []})
        pass5_response = json.dumps({
            "findings": [{
                "type": "donation_attack",
                "severity": "high",
                "confidence": 0.7,
                "title": "Share Price Manipulation",
                "description": "Direct donation inflates totalAssets",
                "line": 9,
            }]
        })
        pass6_response = json.dumps({
            "findings": [{
                "type": "division_by_zero",
                "severity": "medium",
                "confidence": 0.6,
                "title": "Empty vault division",
                "description": "Division by zero when totalSupply is 0",
                "line": 9,
            }]
        })

        self.mock_llm._call_llm.side_effect = [
            pass1_response, pass2_response, pass3_response,
            pass4_response, pass5_response, pass6_response,
        ]

        result = asyncio.run(self.engine.analyze(
            SAMPLE_CONTRACT,
            [{'content': SAMPLE_CONTRACT, 'path': 'test.sol', 'name': 'test.sol'}],
            {'vulnerabilities': []},
        ))

        self.assertIsInstance(result, DeepAnalysisResult)
        self.assertEqual(result.archetype.primary, ProtocolArchetype.VAULT_ERC4626)
        self.assertEqual(len(result.all_findings), 3)  # Pass 3 + Pass 5 + Pass 6
        self.assertGreater(result.total_duration, 0)

    def test_pipeline_handles_pass_failure(self):
        """Pipeline should continue if individual passes fail."""
        self.mock_llm._call_llm.side_effect = [
            None,  # Pass 1 fails
            None,  # Pass 2 fails
            json.dumps({"findings": [{"type": "vuln", "severity": "high", "confidence": 0.8, "description": "test", "line": 1}]}),
            json.dumps({"findings": []}),
            json.dumps({"findings": []}),
            json.dumps({"findings": []}),
        ]

        result = asyncio.run(self.engine.analyze(
            SAMPLE_CONTRACT,
            [{'content': SAMPLE_CONTRACT, 'path': 'test.sol', 'name': 'test.sol'}],
            {'vulnerabilities': []},
        ))

        self.assertIsInstance(result, DeepAnalysisResult)
        # Should still get findings from pass 3
        self.assertGreaterEqual(len(result.all_findings), 1)

    def test_caching_works(self):
        """Same content should use cached pass 1/2 results."""
        self.mock_llm._call_llm.side_effect = [
            '{"invariants": []}',  # Pass 1
            '{"functions": []}',   # Pass 2
            '{"findings": []}',    # Pass 3
            '{"findings": []}',    # Pass 4
            '{"findings": []}',    # Pass 5
            '{"findings": []}',    # Pass 6
            # Second run should use cache for passes 1 & 2
            '{"findings": []}',    # Pass 3
            '{"findings": []}',    # Pass 4
            '{"findings": []}',    # Pass 5
            '{"findings": []}',    # Pass 6
        ]

        # First run
        asyncio.run(self.engine.analyze(
            SAMPLE_CONTRACT,
            [{'content': SAMPLE_CONTRACT, 'path': 'test.sol', 'name': 'test.sol'}],
            {'vulnerabilities': []},
        ))

        # Second run (should use cache for passes 1 & 2)
        asyncio.run(self.engine.analyze(
            SAMPLE_CONTRACT,
            [{'content': SAMPLE_CONTRACT, 'path': 'test.sol', 'name': 'test.sol'}],
            {'vulnerabilities': []},
        ))

        # Should have 10 total calls (6 + 4), not 12 (6 + 6)
        self.assertEqual(self.mock_llm._call_llm.call_count, 10)


class TestPromptBuilders(unittest.TestCase):
    """Test that prompt builders produce well-formed prompts."""

    def test_pass1_prompt_contains_contract(self):
        archetype = ArchetypeResult(primary=ProtocolArchetype.VAULT_ERC4626, confidence=0.8)
        prompt = _build_pass1_prompt("contract Test {}", archetype)
        self.assertIn("contract Test", prompt)
        self.assertIn("vault_erc4626", prompt)
        self.assertIn("JSON", prompt)

    def test_pass2_prompt_includes_pass1(self):
        prompt = _build_pass2_prompt("contract Test {}", "Pass 1 result here")
        self.assertIn("Pass 1 result here", prompt)
        self.assertIn("attack surface", prompt.lower())

    def test_pass3_prompt_includes_checklist(self):
        prompt = _build_pass3_prompt("contract Test {}", "{}", "{}", "## Checklist\n- Item 1")
        self.assertIn("Checklist", prompt)
        self.assertIn("invariant", prompt.lower())

    def test_pass5_prompt_is_adversarial(self):
        prompt = _build_pass5_prompt("contract Test {}", "{}", "{}", "", "", "")
        self.assertIn("attacker", prompt.lower())
        self.assertIn("flash loan", prompt.lower())

    def test_pass6_prompt_checks_boundaries(self):
        prompt = _build_pass6_prompt("contract Test {}", "{}")
        self.assertIn("zero", prompt.lower())
        self.assertIn("maximum", prompt.lower())
        self.assertIn("edge case", prompt.lower())


if __name__ == '__main__':
    unittest.main()
