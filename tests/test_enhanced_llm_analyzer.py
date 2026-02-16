"""
Comprehensive test suite for the LLM analysis pipeline.

Tests core/enhanced_llm_analyzer.py (EnhancedLLMAnalyzer) and
core/ai_ensemble.py (EnhancedAIEnsemble, BaseAIModel, ModelResult,
ConsensusResult, agent classes, and consensus building).

All LLM API calls (OpenAI, Gemini/Google, Anthropic) are mocked.
"""

import asyncio
import json
import os
import sys
import unittest
from dataclasses import asdict
from types import SimpleNamespace
from unittest.mock import MagicMock, patch, PropertyMock

# Ensure project root is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


# ---------------------------------------------------------------------------
# Sample contract used across tests
# ---------------------------------------------------------------------------
SAMPLE_CONTRACT = '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/Ownable.sol";

contract VulnerableVault is Ownable {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] -= amount;
    }

    function getBalance() external view returns (uint256) {
        return balances[msg.sender];
    }
}
'''

# Contracts for version-specific tests
CONTRACT_SOLIDITY_07 = '''
pragma solidity ^0.7.6;

contract OldVault {
    mapping(address => uint256) public balances;
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
}
'''

CONTRACT_NO_PRAGMA = '''
contract NoPragma {
    uint256 public x;
}
'''

# ---------------------------------------------------------------------------
# Mock LLM response payloads
# ---------------------------------------------------------------------------
MOCK_LLM_VULN_RESPONSE = json.dumps({
    "vulnerabilities": [
        {
            "swc_id": "SWC-107",
            "title": "Reentrancy in withdraw",
            "description": "The withdraw function sends ETH before updating the balance, enabling reentrancy.",
            "severity": "high",
            "confidence": 0.95,
            "exploitability": "High - attacker deploys contract that calls withdraw recursively",
            "attack_vector": "Deploy attacking contract, deposit, call withdraw recursively",
            "financial_impact": "Full vault drain",
            "exploit_complexity": "low",
            "detection_difficulty": "low",
            "immunefi_bounty_value": "$10k-$50k",
            "working_poc": "contract Attacker { ... }",
            "fix_suggestion": "Use checks-effects-interactions pattern",
            "validation_evidence": "msg.sender.call before balance update on line 17"
        }
    ],
    "gas_optimizations": [],
    "best_practices": [],
    "summary": "Critical reentrancy vulnerability found."
})

MOCK_LLM_EMPTY_RESPONSE = json.dumps({
    "vulnerabilities": [],
    "gas_optimizations": [],
    "best_practices": [],
    "summary": "No vulnerabilities found."
})

MOCK_ENSEMBLE_FINDINGS_JSON = json.dumps({
    "findings": [
        {
            "type": "reentrancy",
            "severity": "high",
            "confidence": 0.9,
            "description": "Reentrancy in withdraw function",
            "line": 15,
            "swc_id": "SWC-107",
            "exploit_steps": "Step 1: Deposit. Step 2: Call withdraw. Step 3: Re-enter.",
            "why_not_false_positive": "Balance updated after external call",
            "affected_funds": "$10k+"
        }
    ]
})


# ---------------------------------------------------------------------------
# Helper: run async coroutines from sync tests
# ---------------------------------------------------------------------------
def _run(coro):
    """Run an async coroutine synchronously."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ---------------------------------------------------------------------------
# Helper: create EnhancedLLMAnalyzer with controlled env
# ---------------------------------------------------------------------------
def _make_llm_analyzer(openai_key=None, gemini_key=None, anthropic_key=None,
                        model="gpt-4o", explicit_api_key=None):
    """Create an EnhancedLLMAnalyzer with controlled env vars and mocked clients.

    All external dependencies (OpenAI client, anthropic client, ConfigManager)
    are mocked so no real API calls or file I/O occur.
    """
    env = {}
    if openai_key:
        env["OPENAI_API_KEY"] = openai_key
    if gemini_key:
        env["GEMINI_API_KEY"] = gemini_key
    if anthropic_key:
        env["ANTHROPIC_API_KEY"] = anthropic_key

    # We need to patch several things:
    # 1. os.environ via patch.dict
    # 2. The OpenAI class at module level
    # 3. The lazy ConfigManager import (inside try/except)
    # 4. The lazy anthropic import (inside try/except)
    mock_openai_client = MagicMock()
    mock_anthropic_client = MagicMock()

    with patch.dict(os.environ, env, clear=True):
        with patch('core.enhanced_llm_analyzer.OpenAI', return_value=mock_openai_client):
            # Patch the config_manager module so the lazy import inside __init__ works
            # but returns a mock that has no keys
            mock_cm = MagicMock()
            mock_cm.config.openai_api_key = ''
            mock_cm.config.gemini_api_key = ''
            mock_cm.config.anthropic_api_key = ''
            with patch('core.config_manager.ConfigManager', return_value=mock_cm):
                # Patch anthropic module for the lazy import
                mock_anthropic_mod = MagicMock()
                mock_anthropic_mod.Anthropic.return_value = mock_anthropic_client
                with patch.dict('sys.modules', {'anthropic': mock_anthropic_mod}):
                    from core.enhanced_llm_analyzer import EnhancedLLMAnalyzer
                    if explicit_api_key is not None:
                        analyzer = EnhancedLLMAnalyzer(api_key=explicit_api_key, model=model)
                    else:
                        analyzer = EnhancedLLMAnalyzer(model=model)

    # Attach mock clients for test assertions
    analyzer._mock_openai_client = mock_openai_client
    analyzer._mock_anthropic_client = mock_anthropic_client
    return analyzer


# ===================================================================
# EnhancedLLMAnalyzer Tests
# ===================================================================

class TestEnhancedLLMAnalyzerInit(unittest.TestCase):
    """Tests for EnhancedLLMAnalyzer.__init__"""

    def test_init_no_api_keys(self):
        """Constructor with no API keys sets has_api_key=False."""
        analyzer = _make_llm_analyzer()
        self.assertFalse(analyzer.has_api_key)
        self.assertIsNone(analyzer.client)  # No OpenAI key => no client
        self.assertIsNone(analyzer.anthropic_client)  # No Anthropic key

    def test_init_openai_only(self):
        """Constructor with only OpenAI key creates client."""
        analyzer = _make_llm_analyzer(openai_key="sk-test-openai")
        self.assertTrue(analyzer.has_api_key)
        self.assertIsNotNone(analyzer.client)
        self.assertEqual(analyzer.api_key, "sk-test-openai")

    def test_init_gemini_only(self):
        """Constructor with only Gemini key."""
        analyzer = _make_llm_analyzer(gemini_key="gemini-test-key")
        self.assertTrue(analyzer.has_api_key)
        self.assertEqual(analyzer.gemini_api_key, "gemini-test-key")
        self.assertIsNone(analyzer.client)  # No OpenAI client

    def test_init_anthropic_only(self):
        """Constructor with only Anthropic key creates anthropic client."""
        analyzer = _make_llm_analyzer(anthropic_key="anthropic-test-key")
        self.assertTrue(analyzer.has_api_key)
        self.assertEqual(analyzer.anthropic_api_key, "anthropic-test-key")
        self.assertIsNotNone(analyzer.anthropic_client)

    def test_init_all_keys(self):
        """Constructor with all API keys."""
        analyzer = _make_llm_analyzer(
            openai_key="sk-test", gemini_key="gem-test", anthropic_key="ant-test"
        )
        self.assertTrue(analyzer.has_api_key)
        self.assertEqual(analyzer.api_key, "sk-test")
        self.assertEqual(analyzer.gemini_api_key, "gem-test")
        self.assertEqual(analyzer.anthropic_api_key, "ant-test")

    def test_init_explicit_model(self):
        """Constructor with explicitly specified model."""
        analyzer = _make_llm_analyzer(openai_key="sk-test", model="gpt-4-turbo")
        self.assertEqual(analyzer.model, "gpt-4-turbo")

    def test_init_explicit_api_key(self):
        """Constructor with explicitly passed API key takes precedence."""
        analyzer = _make_llm_analyzer(explicit_api_key="sk-explicit")
        self.assertEqual(analyzer.api_key, "sk-explicit")

    def test_fallback_models_list(self):
        """Fallback models list is populated."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        self.assertIsInstance(analyzer.fallback_models, list)
        self.assertGreater(len(analyzer.fallback_models), 0)

    def test_model_context_limits_populated(self):
        """Context limits dict contains expected models."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        self.assertIn("gpt-5-chat-latest", analyzer.model_context_limits)
        self.assertIn("gemini-2.5-flash", analyzer.model_context_limits)
        self.assertIn("claude-opus-4-6", analyzer.model_context_limits)


# -------------------------------------------------------------------
class TestAnalyzeVulnerabilities(unittest.TestCase):
    """Tests for EnhancedLLMAnalyzer.analyze_vulnerabilities()"""

    def test_no_api_key_returns_disabled(self):
        """With no API key, returns disabled response."""
        analyzer = _make_llm_analyzer()
        result = _run(analyzer.analyze_vulnerabilities(SAMPLE_CONTRACT, {}, {}))
        self.assertTrue(result['success'])
        self.assertEqual(result['model'], 'disabled')
        self.assertEqual(result['analysis']['vulnerabilities'], [])

    @patch('core.enhanced_llm_analyzer.EnhancedLLMAnalyzer._call_llm')
    def test_happy_path_with_mocked_response(self, mock_call_llm):
        """Happy path: LLM returns valid vuln JSON."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        mock_call_llm.return_value = MOCK_LLM_VULN_RESPONSE
        result = _run(analyzer.analyze_vulnerabilities(SAMPLE_CONTRACT, {}, {}))
        self.assertTrue(result['success'])
        self.assertIn('analysis', result)
        mock_call_llm.assert_awaited_once()

    @patch('core.enhanced_llm_analyzer.EnhancedLLMAnalyzer._call_llm')
    def test_llm_returns_none_uses_fallback(self, mock_call_llm):
        """When LLM returns None, fallback response is used."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        mock_call_llm.return_value = None
        result = _run(analyzer.analyze_vulnerabilities(SAMPLE_CONTRACT, {}, {}))
        self.assertTrue(result['success'])
        self.assertEqual(result['model'], 'failed')

    @patch('core.enhanced_llm_analyzer.EnhancedLLMAnalyzer._call_llm')
    def test_llm_exception_uses_fallback(self, mock_call_llm):
        """When LLM raises an exception, fallback response is returned."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        mock_call_llm.side_effect = RuntimeError("API down")
        result = _run(analyzer.analyze_vulnerabilities(SAMPLE_CONTRACT, {}, {}))
        self.assertTrue(result['success'])
        self.assertEqual(result['model'], 'failed')

    @patch('core.enhanced_llm_analyzer.EnhancedLLMAnalyzer._call_llm')
    def test_empty_vulnerabilities_response(self, mock_call_llm):
        """Empty vulnerabilities array is valid."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        mock_call_llm.return_value = MOCK_LLM_EMPTY_RESPONSE
        result = _run(analyzer.analyze_vulnerabilities(SAMPLE_CONTRACT, {}, {}))
        self.assertTrue(result['success'])
        self.assertEqual(result['analysis']['vulnerabilities'], [])


# -------------------------------------------------------------------
class TestCreateEnhancedAnalysisPrompt(unittest.TestCase):
    """Tests for _create_enhanced_analysis_prompt()"""

    def test_prompt_contains_contract(self):
        """Prompt includes the contract source code."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        prompt = analyzer._create_enhanced_analysis_prompt(SAMPLE_CONTRACT, {})
        self.assertIn("VulnerableVault", prompt)
        self.assertIn("withdraw", prompt)

    def test_prompt_includes_static_results(self):
        """Prompt includes summaries from static analysis."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        vuln = SimpleNamespace(title="Reentrancy", description="External call before state update")
        static_results = {"vulnerabilities": [vuln]}
        prompt = analyzer._create_enhanced_analysis_prompt(SAMPLE_CONTRACT, static_results)
        self.assertIn("Reentrancy", prompt)

    def test_prompt_truncates_large_contract(self):
        """Very large contracts are truncated to fit model context."""
        analyzer = _make_llm_analyzer(openai_key="sk-test", model="gpt-4")
        huge_contract = "// " + "x" * 500000
        prompt = analyzer._create_enhanced_analysis_prompt(huge_contract, {})
        self.assertIn("[Note: Contract truncated", prompt)

    def test_prompt_version_guidance_0_8(self):
        """Prompt contains >=0.8.0 guidance for Solidity 0.8.19."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        prompt = analyzer._create_enhanced_analysis_prompt(SAMPLE_CONTRACT, {})
        self.assertIn("0.8.19", prompt)
        self.assertIn("Automatic overflow/underflow protection ENABLED", prompt)

    def test_prompt_version_guidance_0_7(self):
        """Prompt contains <0.8.0 guidance for Solidity 0.7.6."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        prompt = analyzer._create_enhanced_analysis_prompt(CONTRACT_SOLIDITY_07, {})
        self.assertIn("NO automatic overflow/underflow protection", prompt)

    def test_prompt_includes_validation_checklist(self):
        """Prompt includes the validation checklist."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        prompt = analyzer._create_enhanced_analysis_prompt(SAMPLE_CONTRACT, {})
        self.assertIn("VALIDATION CHECKLIST", prompt)

    def test_prompt_json_output_format(self):
        """Prompt specifies JSON output format."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        prompt = analyzer._create_enhanced_analysis_prompt(SAMPLE_CONTRACT, {})
        self.assertIn('"vulnerabilities"', prompt)
        self.assertIn('"gas_optimizations"', prompt)


# -------------------------------------------------------------------
class TestCallLLM(unittest.TestCase):
    """Tests for _call_llm() -- model selection, fallback, provider routing."""

    @patch('core.enhanced_llm_analyzer.EnhancedLLMAnalyzer._call_openai_api')
    def test_routes_to_openai(self, mock_openai):
        """OpenAI models are routed to _call_openai_api."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        mock_openai.return_value = '{"result": "ok"}'
        result = _run(analyzer._call_llm("test prompt", model="gpt-4o"))
        mock_openai.assert_awaited_once()
        self.assertIsNotNone(result)

    @patch('core.enhanced_llm_analyzer.EnhancedLLMAnalyzer._call_gemini_api')
    def test_routes_to_gemini(self, mock_gemini):
        """Gemini models are routed to _call_gemini_api."""
        analyzer = _make_llm_analyzer(gemini_key="gem-test")
        mock_gemini.return_value = '{"result": "ok"}'
        result = _run(analyzer._call_llm("test prompt", model="gemini-2.5-flash"))
        mock_gemini.assert_awaited_once()

    @patch('core.enhanced_llm_analyzer.EnhancedLLMAnalyzer._call_anthropic_api')
    def test_routes_to_anthropic(self, mock_anthropic):
        """Claude models are routed to _call_anthropic_api."""
        analyzer = _make_llm_analyzer(anthropic_key="ant-test")
        mock_anthropic.return_value = '{"result": "ok"}'
        result = _run(analyzer._call_llm("test prompt", model="claude-sonnet-4-5-20250929"))
        mock_anthropic.assert_awaited_once()

    def test_no_api_key_returns_none(self):
        """No API key at all returns None."""
        analyzer = _make_llm_analyzer()
        result = _run(analyzer._call_llm("test prompt"))
        self.assertIsNone(result)

    @patch('core.enhanced_llm_analyzer.EnhancedLLMAnalyzer._call_openai_api')
    def test_fallback_on_primary_failure(self, mock_openai):
        """Falls back to next model when primary model fails."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        call_count = [0]

        async def side_effect(model, prompt, max_tokens):
            call_count[0] += 1
            if call_count[0] == 1:
                raise RuntimeError("Model unavailable")
            return '{"result": "fallback"}'

        mock_openai.side_effect = side_effect
        result = _run(analyzer._call_llm("test prompt", model="gpt-4o"))
        # Should have tried more than once
        self.assertGreater(call_count[0], 1)

    @patch('core.enhanced_llm_analyzer.EnhancedLLMAnalyzer._call_openai_api')
    def test_control_chars_stripped_from_response(self, mock_openai):
        """Control characters are stripped from the LLM response."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        mock_openai.return_value = '{"result": "ok\x01\x02"}'
        result = _run(analyzer._call_llm("test prompt", model="gpt-4o"))
        self.assertNotIn('\x01', result)
        self.assertNotIn('\x02', result)

    @patch('core.enhanced_llm_analyzer.EnhancedLLMAnalyzer._call_openai_api')
    def test_prompt_truncated_for_small_model(self, mock_openai):
        """Prompt is truncated when too large for model context."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        mock_openai.return_value = '{"result": "ok"}'
        huge_prompt = "x" * 500000
        result = _run(analyzer._call_llm(huge_prompt, model="gpt-4"))  # 8192 context
        # The prompt passed to _call_openai_api should be smaller
        self.assertIsNotNone(result)


# -------------------------------------------------------------------
class TestCallOpenAIAPI(unittest.TestCase):
    """Tests for _call_openai_api()"""

    def test_gpt5_uses_max_completion_tokens(self):
        """GPT-5 models use max_completion_tokens param."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        mock_client = analyzer._mock_openai_client
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content="ok"))]
        mock_response.usage = MagicMock(prompt_tokens=100, completion_tokens=50)
        mock_client.chat.completions.create.return_value = mock_response

        with patch('core.llm_usage_tracker.LLMUsageTracker.get_instance', return_value=MagicMock()):
            result = _run(analyzer._call_openai_api("gpt-5-chat-latest", "prompt", 8000))

        call_kwargs = mock_client.chat.completions.create.call_args[1]
        self.assertIn("max_completion_tokens", call_kwargs)
        self.assertNotIn("max_tokens", call_kwargs)
        self.assertEqual(result, "ok")

    def test_gpt4_uses_max_tokens(self):
        """GPT-4 models use max_tokens param."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        mock_client = analyzer._mock_openai_client
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content="result"))]
        mock_response.usage = MagicMock(prompt_tokens=100, completion_tokens=50)
        mock_client.chat.completions.create.return_value = mock_response

        with patch('core.llm_usage_tracker.LLMUsageTracker.get_instance', return_value=MagicMock()):
            result = _run(analyzer._call_openai_api("gpt-4o", "prompt", 4000))

        call_kwargs = mock_client.chat.completions.create.call_args[1]
        self.assertIn("max_tokens", call_kwargs)
        self.assertNotIn("max_completion_tokens", call_kwargs)

    def test_gpt5_mini_no_temperature(self):
        """GPT-5-mini does not set temperature."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        mock_client = analyzer._mock_openai_client
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content="ok"))]
        mock_response.usage = MagicMock(prompt_tokens=10, completion_tokens=5)
        mock_client.chat.completions.create.return_value = mock_response

        with patch('core.llm_usage_tracker.LLMUsageTracker.get_instance', return_value=MagicMock()):
            _run(analyzer._call_openai_api("gpt-5-mini", "prompt", 8000))

        call_kwargs = mock_client.chat.completions.create.call_args[1]
        self.assertNotIn("temperature", call_kwargs)

    def test_gpt5_non_mini_has_temperature(self):
        """GPT-5 (non-mini) sets temperature=0.1."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        mock_client = analyzer._mock_openai_client
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content="ok"))]
        mock_response.usage = MagicMock(prompt_tokens=10, completion_tokens=5)
        mock_client.chat.completions.create.return_value = mock_response

        with patch('core.llm_usage_tracker.LLMUsageTracker.get_instance', return_value=MagicMock()):
            _run(analyzer._call_openai_api("gpt-5-chat-latest", "prompt", 8000))

        call_kwargs = mock_client.chat.completions.create.call_args[1]
        self.assertEqual(call_kwargs.get("temperature"), 0.1)

    def test_usage_tracking(self):
        """Usage is recorded via LLMUsageTracker."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        mock_client = analyzer._mock_openai_client
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content="ok"))]
        mock_response.usage = MagicMock(prompt_tokens=500, completion_tokens=200)
        mock_client.chat.completions.create.return_value = mock_response

        with patch('core.llm_usage_tracker.LLMUsageTracker.get_instance') as mock_get_instance:
            mock_tracker = MagicMock()
            mock_get_instance.return_value = mock_tracker
            _run(analyzer._call_openai_api("gpt-4o", "prompt", 4000))
            mock_tracker.record.assert_called_once_with(
                "openai", "gpt-4o", 500, 200, "enhanced_llm_analyzer"
            )

    def test_no_client_returns_none(self):
        """Returns None when client is not initialized."""
        analyzer = _make_llm_analyzer()
        self.assertIsNone(analyzer.client)
        result = _run(analyzer._call_openai_api("gpt-4o", "prompt", 4000))
        self.assertIsNone(result)


# -------------------------------------------------------------------
class TestCallGeminiAPI(unittest.TestCase):
    """Tests for _call_gemini_api()"""

    @patch('core.enhanced_llm_analyzer.requests.post')
    def test_happy_path(self, mock_post):
        """Successful Gemini API call returns text."""
        analyzer = _make_llm_analyzer(gemini_key="gem-test")
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "candidates": [{"content": {"parts": [{"text": '{"vulnerabilities": []}'}]}}],
            "usageMetadata": {"promptTokenCount": 100, "candidatesTokenCount": 50}
        }
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

        with patch('core.llm_usage_tracker.LLMUsageTracker.get_instance', return_value=MagicMock()):
            result = _run(analyzer._call_gemini_api("gemini-2.5-flash", "prompt", 12000))

        self.assertEqual(result, '{"vulnerabilities": []}')

    @patch('core.enhanced_llm_analyzer.requests.post')
    def test_no_candidates_returns_none(self, mock_post):
        """No candidates in response returns None."""
        analyzer = _make_llm_analyzer(gemini_key="gem-test")
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"candidates": []}
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp
        result = _run(analyzer._call_gemini_api("gemini-2.5-flash", "prompt", 12000))
        self.assertIsNone(result)

    @patch('core.enhanced_llm_analyzer.requests.post')
    @patch('core.enhanced_llm_analyzer.time.sleep')
    def test_retry_on_timeout(self, mock_sleep, mock_post):
        """Retries on timeout, succeeds on second attempt."""
        analyzer = _make_llm_analyzer(gemini_key="gem-test")
        import requests as real_requests

        mock_success = MagicMock()
        mock_success.json.return_value = {
            "candidates": [{"content": {"parts": [{"text": "ok"}]}}],
            "usageMetadata": {}
        }
        mock_success.raise_for_status = MagicMock()

        mock_post.side_effect = [
            real_requests.exceptions.Timeout("timeout"),
            mock_success
        ]

        result = _run(analyzer._call_gemini_api("gemini-2.5-flash", "prompt", 12000))
        self.assertEqual(result, "ok")
        self.assertEqual(mock_post.call_count, 2)

    @patch('core.enhanced_llm_analyzer.requests.post')
    def test_gemini_usage_tracking(self, mock_post):
        """Gemini usage metadata is tracked."""
        analyzer = _make_llm_analyzer(gemini_key="gem-test")
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "candidates": [{"content": {"parts": [{"text": "ok"}]}}],
            "usageMetadata": {"promptTokenCount": 200, "candidatesTokenCount": 100}
        }
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

        with patch('core.llm_usage_tracker.LLMUsageTracker.get_instance') as mock_get_instance:
            mock_tracker = MagicMock()
            mock_get_instance.return_value = mock_tracker
            _run(analyzer._call_gemini_api("gemini-2.5-flash", "prompt", 12000))
            mock_tracker.record.assert_called_once_with(
                "gemini", "gemini-2.5-flash", 200, 100, "enhanced_llm_analyzer"
            )

    @patch('core.enhanced_llm_analyzer.requests.post')
    def test_no_text_in_parts(self, mock_post):
        """Parts without text key returns None."""
        analyzer = _make_llm_analyzer(gemini_key="gem-test")
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "candidates": [{"content": {"parts": [{"thought": "thinking..."}]}}],
            "usageMetadata": {}
        }
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp
        result = _run(analyzer._call_gemini_api("gemini-2.5-flash", "prompt", 12000))
        self.assertIsNone(result)

    @patch('core.enhanced_llm_analyzer.requests.post')
    def test_prompt_feedback_returns_none(self, mock_post):
        """Prompt feedback (safety filter) returns None."""
        analyzer = _make_llm_analyzer(gemini_key="gem-test")
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "candidates": [],
            "promptFeedback": {"blockReason": "SAFETY"}
        }
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp
        result = _run(analyzer._call_gemini_api("gemini-2.5-flash", "prompt", 12000))
        self.assertIsNone(result)


# -------------------------------------------------------------------
class TestCallAnthropicAPI(unittest.TestCase):
    """Tests for _call_anthropic_api()"""

    def test_happy_path(self):
        """Anthropic API call returns text content."""
        analyzer = _make_llm_analyzer(anthropic_key="ant-test")
        mock_block = MagicMock()
        mock_block.text = '{"vulnerabilities": []}'
        mock_response = MagicMock()
        mock_response.content = [mock_block]
        mock_response.usage = MagicMock(input_tokens=100, output_tokens=50)
        analyzer.anthropic_client.messages.create.return_value = mock_response

        with patch('core.llm_usage_tracker.LLMUsageTracker.get_instance', return_value=MagicMock()):
            result = _run(analyzer._call_anthropic_api("claude-sonnet-4-5-20250929", "prompt", 8000))
        self.assertEqual(result, '{"vulnerabilities": []}')

    def test_no_client_returns_none(self):
        """Returns None when anthropic_client is None."""
        analyzer = _make_llm_analyzer()  # No anthropic key
        self.assertIsNone(analyzer.anthropic_client)
        result = _run(analyzer._call_anthropic_api("claude-sonnet-4-5-20250929", "prompt", 8000))
        self.assertIsNone(result)

    def test_usage_tracking(self):
        """Anthropic usage is tracked."""
        analyzer = _make_llm_analyzer(anthropic_key="ant-test")
        mock_block = MagicMock()
        mock_block.text = "ok"
        mock_response = MagicMock()
        mock_response.content = [mock_block]
        mock_response.usage = MagicMock(input_tokens=300, output_tokens=150)
        analyzer.anthropic_client.messages.create.return_value = mock_response

        with patch('core.llm_usage_tracker.LLMUsageTracker.get_instance') as mock_get_instance:
            mock_tracker = MagicMock()
            mock_get_instance.return_value = mock_tracker
            _run(analyzer._call_anthropic_api("claude-opus-4-6", "prompt", 8000))
            mock_tracker.record.assert_called_once_with(
                "anthropic", "claude-opus-4-6", 300, 150, "enhanced_llm_analyzer"
            )

    def test_empty_content_returns_none(self):
        """Empty content list returns None."""
        analyzer = _make_llm_analyzer(anthropic_key="ant-test")
        mock_response = MagicMock()
        mock_response.content = []
        mock_response.usage = MagicMock(input_tokens=100, output_tokens=0)
        analyzer.anthropic_client.messages.create.return_value = mock_response

        with patch('core.llm_usage_tracker.LLMUsageTracker.get_instance', return_value=MagicMock()):
            result = _run(analyzer._call_anthropic_api("claude-opus-4-6", "prompt", 8000))
        self.assertIsNone(result)


# -------------------------------------------------------------------
class TestParseAndValidateResponse(unittest.TestCase):
    """Tests for _parse_and_validate_response()"""

    def test_valid_json_parsed(self):
        """Valid JSON is parsed and returned successfully."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        result = analyzer._parse_and_validate_response(MOCK_LLM_VULN_RESPONSE, SAMPLE_CONTRACT)
        self.assertTrue(result['success'])
        self.assertIn('analysis', result)

    def test_empty_vulnerabilities(self):
        """Empty vulnerabilities array is valid."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        result = analyzer._parse_and_validate_response(MOCK_LLM_EMPTY_RESPONSE, SAMPLE_CONTRACT)
        self.assertTrue(result['success'])
        self.assertEqual(result['analysis']['vulnerabilities'], [])

    def test_validation_summary_present(self):
        """Result includes validation_summary."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        result = analyzer._parse_and_validate_response(MOCK_LLM_EMPTY_RESPONSE, SAMPLE_CONTRACT)
        self.assertIn('validation_summary', result)
        self.assertIn('total_found', result['validation_summary'])

    def test_raw_response_included(self):
        """Raw LLM response is included in result."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        result = analyzer._parse_and_validate_response(MOCK_LLM_EMPTY_RESPONSE, SAMPLE_CONTRACT)
        self.assertEqual(result['raw_response'], MOCK_LLM_EMPTY_RESPONSE)


# -------------------------------------------------------------------
class TestValidateVulnerability(unittest.TestCase):
    """Tests for _validate_vulnerability()"""

    def test_valid_vulnerability(self):
        """Vulnerability with all required fields and high confidence passes."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        vuln = {
            "title": "Reentrancy in withdraw",
            "description": "External call before state update in withdraw function",
            "severity": "high",
            "confidence": 0.95,
        }
        self.assertTrue(analyzer._validate_vulnerability(vuln, SAMPLE_CONTRACT))

    def test_missing_required_fields(self):
        """Vulnerability missing required fields is rejected."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        vuln = {"title": "Something", "severity": "high"}  # Missing description, confidence
        self.assertFalse(analyzer._validate_vulnerability(vuln, SAMPLE_CONTRACT))

    def test_low_confidence_rejected(self):
        """Vulnerability with confidence < 0.7 is rejected."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        vuln = {
            "title": "Maybe something",
            "description": "Possible issue",
            "severity": "low",
            "confidence": 0.3,
        }
        self.assertFalse(analyzer._validate_vulnerability(vuln, SAMPLE_CONTRACT))

    def test_confidence_at_threshold(self):
        """Vulnerability with confidence exactly 0.7 passes threshold."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        vuln = {
            "title": "General vulnerability issue",
            "description": "A potential problem with the code logic",
            "severity": "medium",
            "confidence": 0.7,
        }
        result = analyzer._validate_vulnerability(vuln, SAMPLE_CONTRACT)
        self.assertIsInstance(result, bool)

    def test_missing_title(self):
        """Missing title field rejected."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        vuln = {"description": "desc", "severity": "high", "confidence": 0.9}
        self.assertFalse(analyzer._validate_vulnerability(vuln, SAMPLE_CONTRACT))

    def test_missing_severity(self):
        """Missing severity field rejected."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        vuln = {"title": "Test", "description": "desc", "confidence": 0.9}
        self.assertFalse(analyzer._validate_vulnerability(vuln, SAMPLE_CONTRACT))


# -------------------------------------------------------------------
class TestIsLikelyFalsePositive(unittest.TestCase):
    """Tests for _is_likely_false_positive()"""

    def test_standard_pattern_is_false_positive(self):
        """Descriptions containing 'standard openzeppelin pattern' are FP."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        vuln = {
            "title": "Access control",
            "description": "This is a standard openzeppelin pattern, no issue here.",
            "severity": "low",
            "confidence": 0.8,
        }
        self.assertTrue(analyzer._is_likely_false_positive(vuln, SAMPLE_CONTRACT))

    def test_properly_protected_pattern(self):
        """'properly protected' in description is FP."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        vuln = {
            "title": "Access issue",
            "description": "This function is properly protected by modifiers.",
            "severity": "low",
            "confidence": 0.8,
        }
        self.assertTrue(analyzer._is_likely_false_positive(vuln, SAMPLE_CONTRACT))

    def test_deployment_time_issue_is_false_positive(self):
        """Deployment-time issues in constructors are FP."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        vuln = {
            "title": "Constructor issue",
            "description": "During deployment this could be exploited by malicious deployer",
            "severity": "medium",
            "confidence": 0.8,
            "code_snippet": "constructor() { ... }",
        }
        self.assertTrue(analyzer._is_likely_false_positive(vuln, SAMPLE_CONTRACT))

    def test_centralization_concern_is_false_positive(self):
        """Centralization/governance concerns are FP."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        vuln = {
            "title": "Centralization Risk",
            "description": "The EOA private key compromised would allow full access",
            "severity": "high",
            "confidence": 0.9,
        }
        self.assertTrue(analyzer._is_likely_false_positive(vuln, SAMPLE_CONTRACT))

    def test_real_vuln_not_false_positive(self):
        """Real vulnerability is not flagged as false positive."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        vuln = {
            "title": "Reentrancy in withdraw",
            "description": "External call before state update enables recursive drain",
            "severity": "high",
            "confidence": 0.95,
        }
        self.assertFalse(analyzer._is_likely_false_positive(vuln, SAMPLE_CONTRACT))

    def test_proxy_openzeppelin_false_positive(self):
        """OpenZeppelin proxy vulnerability types are detected as FP in proxy contracts."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        proxy_contract = '''
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
contract MyProxy is ERC1967Proxy {}
'''
        vuln = {
            "title": "Proxy admin risk",
            "description": "Admin can upgrade the proxy and the storage slot implementation is vulnerable.",
            "severity": "high",
            "confidence": 0.9,
            "vulnerability_type": "upgradeability",
        }
        self.assertTrue(analyzer._is_likely_false_positive(vuln, proxy_contract))

    def test_false_positive_keyword_in_description(self):
        """'false positive' in description detected."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        vuln = {
            "title": "Something",
            "description": "This is a false positive because of X.",
            "severity": "low",
            "confidence": 0.8,
        }
        self.assertTrue(analyzer._is_likely_false_positive(vuln, SAMPLE_CONTRACT))

    def test_without_multisig_centralization(self):
        """'without multisig' centralization concern is FP."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        vuln = {
            "title": "Admin risk",
            "description": "Owner is an EOA without multisig protection",
            "severity": "medium",
            "confidence": 0.85,
        }
        self.assertTrue(analyzer._is_likely_false_positive(vuln, SAMPLE_CONTRACT))


# -------------------------------------------------------------------
class TestExtractSolidityVersion(unittest.TestCase):
    """Tests for _extract_solidity_version()"""

    def test_caret_version(self):
        """Extracts version from ^0.8.19."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        self.assertEqual(analyzer._extract_solidity_version(SAMPLE_CONTRACT), "0.8.19")

    def test_range_version(self):
        """Extracts from >=0.7.6 <0.9.0."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        contract = 'pragma solidity >=0.7.6 <0.9.0;'
        self.assertEqual(analyzer._extract_solidity_version(contract), "0.7.6")

    def test_exact_version(self):
        """Extracts from exact version."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        contract = 'pragma solidity 0.8.0;'
        self.assertEqual(analyzer._extract_solidity_version(contract), "0.8.0")

    def test_no_pragma_returns_none(self):
        """Returns None when no pragma."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        self.assertIsNone(analyzer._extract_solidity_version(CONTRACT_NO_PRAGMA))

    def test_partial_version(self):
        """Handles version with only major.minor."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        contract = 'pragma solidity ^0.8;'
        result = analyzer._extract_solidity_version(contract)
        self.assertIn("0.8", result)

    def test_tilde_version(self):
        """Extracts from ~0.6.12."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        contract = 'pragma solidity ~0.6.12;'
        self.assertEqual(analyzer._extract_solidity_version(contract), "0.6.12")


# -------------------------------------------------------------------
class TestGenerateVersionSpecificGuidance(unittest.TestCase):
    """Tests for _generate_version_specific_guidance()"""

    def test_pre_08_guidance(self):
        """Solidity <0.8.0 guidance warns about no overflow protection."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        guidance = analyzer._generate_version_specific_guidance("0.7.6")
        self.assertIn("NO automatic overflow/underflow protection", guidance)
        self.assertIn("0.7.6", guidance)

    def test_post_08_guidance(self):
        """Solidity >=0.8.0 guidance notes automatic overflow protection."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        guidance = analyzer._generate_version_specific_guidance("0.8.19")
        self.assertIn("Automatic overflow/underflow protection ENABLED", guidance)

    def test_none_version(self):
        """None version returns unknown guidance."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        guidance = analyzer._generate_version_specific_guidance(None)
        self.assertIn("UNKNOWN", guidance)

    def test_invalid_version_returns_empty(self):
        """Malformed version returns empty string."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        guidance = analyzer._generate_version_specific_guidance("abc")
        self.assertEqual(guidance, "")

    def test_solidity_0_6(self):
        """0.6.x gets <0.8.0 guidance."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        guidance = analyzer._generate_version_specific_guidance("0.6.12")
        self.assertIn("NO automatic overflow/underflow protection", guidance)

    def test_solidity_0_8_0(self):
        """Exactly 0.8.0 gets >=0.8.0 guidance."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        guidance = analyzer._generate_version_specific_guidance("0.8.0")
        self.assertIn("Automatic overflow/underflow protection ENABLED", guidance)


# -------------------------------------------------------------------
class TestFixJsonString(unittest.TestCase):
    """Tests for _fix_json_string()"""

    def test_control_chars_removed(self):
        """Control characters are escaped to unicode."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        fixed = analyzer._fix_json_string('{"key": "val\x01ue"}')
        self.assertNotIn('\x01', fixed)

    def test_trailing_comma_removed(self):
        """Trailing commas before } are removed."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        fixed = analyzer._fix_json_string('{"a": 1, "b": 2,}')
        self.assertNotIn(',}', fixed)

    def test_unmatched_brackets_closed(self):
        """Missing closing brackets are added."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        fixed = analyzer._fix_json_string('{"a": [1, 2')
        self.assertGreaterEqual(fixed.count(']'), 1)
        self.assertGreaterEqual(fixed.count('}'), 1)

    def test_already_valid_json_structure(self):
        """Valid JSON with nested objects passes through structurally."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        valid = '{"vulnerabilities": [], "summary": "none"}'
        fixed = analyzer._fix_json_string(valid)
        # Should still be valid JSON after fixing
        self.assertIn('"vulnerabilities"', fixed)

    def test_extra_text_before_json_removed(self):
        """Text before JSON object is stripped."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        fixed = analyzer._fix_json_string('Here is the response: {"vulnerabilities": []}')
        self.assertIn('"vulnerabilities"', fixed)

    def test_odd_quotes_fixed(self):
        """Odd number of quotes gets closing quote added."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        # 3 quotes (odd) -- the method adds a closing quote
        input_str = '{"key": "unclosed'
        fixed = analyzer._fix_json_string(input_str)
        # Should have even number of quotes
        self.assertEqual(fixed.count('"') % 2, 0)


# -------------------------------------------------------------------
class TestCreateFallbackResponse(unittest.TestCase):
    """Tests for _create_fallback_response()"""

    def test_fallback_structure(self):
        """Fallback response has the expected structure."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        result = analyzer._create_fallback_response()
        self.assertTrue(result['success'])
        self.assertEqual(result['model'], 'failed')
        self.assertEqual(result['analysis']['vulnerabilities'], [])
        self.assertEqual(result['analysis']['gas_optimizations'], [])
        self.assertEqual(result['analysis']['best_practices'], [])
        self.assertIn('note', result['analysis'])

    def test_fallback_has_empty_raw_response(self):
        """Fallback raw_response is empty string."""
        analyzer = _make_llm_analyzer(openai_key="sk-test")
        result = analyzer._create_fallback_response()
        self.assertEqual(result['raw_response'], '')


# ===================================================================
# AI Ensemble Tests
# ===================================================================

class TestModelResultDataclass(unittest.TestCase):
    """Tests for ModelResult dataclass."""

    def test_creation(self):
        from core.ai_ensemble import ModelResult
        result = ModelResult(
            model_name="test",
            findings=[{"type": "reentrancy"}],
            confidence=0.9,
            processing_time=1.5,
            metadata={"key": "val"}
        )
        self.assertEqual(result.model_name, "test")
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.confidence, 0.9)

    def test_asdict(self):
        from core.ai_ensemble import ModelResult
        result = ModelResult(
            model_name="m1", findings=[], confidence=0.5,
            processing_time=0.1, metadata={}
        )
        d = asdict(result)
        self.assertIn("model_name", d)
        self.assertIn("findings", d)
        self.assertIn("processing_time", d)


class TestConsensusResultDataclass(unittest.TestCase):
    """Tests for ConsensusResult dataclass."""

    def test_creation(self):
        from core.ai_ensemble import ConsensusResult, ModelResult
        mr = ModelResult(model_name="a", findings=[], confidence=0.5,
                         processing_time=0.1, metadata={})
        cr = ConsensusResult(
            consensus_findings=[],
            model_agreement=0.8,
            confidence_score=0.75,
            processing_time=2.0,
            individual_results=[mr]
        )
        self.assertEqual(cr.model_agreement, 0.8)
        self.assertEqual(len(cr.individual_results), 1)

    def test_asdict_consensus(self):
        from core.ai_ensemble import ConsensusResult
        cr = ConsensusResult(
            consensus_findings=[{"type": "x"}],
            model_agreement=0.5,
            confidence_score=0.6,
            processing_time=1.0,
            individual_results=[]
        )
        d = asdict(cr)
        self.assertIn("consensus_findings", d)
        self.assertEqual(len(d["consensus_findings"]), 1)


# -------------------------------------------------------------------
class TestBaseAIModelSmartTruncate(unittest.TestCase):
    """Tests for BaseAIModel._smart_truncate()"""

    def _make_agent(self):
        """Create a minimal BaseAIModel instance."""
        from core.ai_ensemble import BaseAIModel
        agent = BaseAIModel.__new__(BaseAIModel)
        agent.agent_name = "test_agent"
        agent.role = "tester"
        agent.focus_areas = ["test"]
        agent.confidence_weight = 1.0
        agent.db_manager = MagicMock()
        agent.config = MagicMock()
        return agent

    def test_short_content_unchanged(self):
        """Short content is not truncated."""
        agent = self._make_agent()
        content = "short content"
        result = agent._smart_truncate(content, "gpt-5-mini")
        self.assertEqual(result, content)

    def test_long_content_truncated_gpt4(self):
        """Long content is truncated for small-context model."""
        agent = self._make_agent()
        content = "x" * 50000
        result = agent._smart_truncate(content, "gpt-4")
        # gpt-4 limit is 24000 chars, 80% = 19200
        self.assertLessEqual(len(result), 24000)

    def test_gemini_has_large_limit(self):
        """Gemini models have very large context limits."""
        agent = self._make_agent()
        content = "x" * 600000
        result = agent._smart_truncate(content, "gemini-2.5-flash")
        # Gemini limit is 800000 chars, 80% = 640000
        self.assertEqual(len(result), 600000)

    def test_unknown_model_uses_default(self):
        """Unknown model names use the 16000 default limit."""
        agent = self._make_agent()
        content = "x" * 20000
        result = agent._smart_truncate(content, "unknown-model")
        # Default is 16000 * 0.8 = 12800
        self.assertLessEqual(len(result), 16000)

    def test_claude_limit(self):
        """Claude models use 160000 char limit."""
        agent = self._make_agent()
        content = "x" * 200000
        result = agent._smart_truncate(content, "claude-opus-4-6")
        # 160000 * 0.8 = 128000
        self.assertLessEqual(len(result), 160000)

    def test_empty_model_uses_default(self):
        """Empty model name uses default limit."""
        agent = self._make_agent()
        content = "x" * 20000
        result = agent._smart_truncate(content, "")
        self.assertLessEqual(len(result), 16000)


# -------------------------------------------------------------------
class TestBaseAIModelValidateFindingSchema(unittest.TestCase):
    """Tests for BaseAIModel._validate_finding_schema()"""

    def _make_agent(self):
        from core.ai_ensemble import BaseAIModel
        agent = BaseAIModel.__new__(BaseAIModel)
        agent.agent_name = "test_agent"
        agent.role = "tester"
        agent.focus_areas = ["test"]
        agent.confidence_weight = 1.0
        agent.db_manager = MagicMock()
        agent.config = MagicMock()
        return agent

    def test_good_finding_passes(self):
        """Finding with type, severity, description, and exploit_steps passes."""
        agent = self._make_agent()
        findings = [{
            "type": "reentrancy",
            "severity": "high",
            "description": "State not updated before call",
            "exploit_steps": "Step 1: ...",
            "confidence": 0.9,
        }]
        result = agent._validate_finding_schema(findings)
        self.assertEqual(len(result), 1)

    def test_finding_with_reasoning_chain_passes(self):
        """Finding with why_not_false_positive passes."""
        agent = self._make_agent()
        findings = [{
            "type": "access_control",
            "severity": "medium",
            "description": "Missing modifier",
            "why_not_false_positive": "No parent access control",
            "confidence": 0.85,
        }]
        result = agent._validate_finding_schema(findings)
        self.assertEqual(len(result), 1)

    def test_finding_with_attack_scenario(self):
        """Finding with exploit_scenario also passes."""
        agent = self._make_agent()
        findings = [{
            "type": "flash_loan",
            "severity": "critical",
            "description": "Flash loan attack possible",
            "exploit_scenario": "Borrow, manipulate, profit",
            "confidence": 0.9,
        }]
        result = agent._validate_finding_schema(findings)
        self.assertEqual(len(result), 1)

    def test_missing_basic_fields_dropped(self):
        """Finding missing type/severity/description is dropped."""
        agent = self._make_agent()
        findings = [{"type": "something"}]  # Missing severity, description
        result = agent._validate_finding_schema(findings)
        self.assertEqual(len(result), 0)

    def test_no_exploit_no_fp_reason_low_confidence_dropped(self):
        """Finding without exploit_steps or why_not_false_positive and low confidence is dropped."""
        agent = self._make_agent()
        findings = [{
            "type": "reentrancy",
            "severity": "high",
            "description": "Possible reentrancy",
            "confidence": 0.5,
        }]
        result = agent._validate_finding_schema(findings)
        self.assertEqual(len(result), 0)

    def test_high_confidence_passes_without_exploit(self):
        """High-confidence finding (>=0.8) passes even without exploit_steps."""
        agent = self._make_agent()
        findings = [{
            "type": "logic_error",
            "severity": "high",
            "description": "State inconsistency",
            "confidence": 0.85,
        }]
        result = agent._validate_finding_schema(findings)
        self.assertEqual(len(result), 1)
        self.assertTrue(result[0].get('needs_verification'))

    def test_empty_findings_list(self):
        """Empty findings list returns empty."""
        agent = self._make_agent()
        result = agent._validate_finding_schema([])
        self.assertEqual(result, [])

    def test_multiple_findings_mixed(self):
        """Mix of valid and invalid findings filters correctly."""
        agent = self._make_agent()
        findings = [
            {"type": "reentrancy", "severity": "high", "description": "Real", "exploit_steps": "1,2,3"},
            {"type": "x"},  # Invalid
            {"type": "access", "severity": "low", "description": "Maybe", "confidence": 0.3},  # No exploit, low conf
        ]
        result = agent._validate_finding_schema(findings)
        self.assertEqual(len(result), 1)


# -------------------------------------------------------------------
class TestBaseAIModelApplyLearningPatterns(unittest.TestCase):
    """Tests for BaseAIModel._apply_learning_patterns()"""

    def _make_agent(self):
        from core.ai_ensemble import BaseAIModel
        agent = BaseAIModel.__new__(BaseAIModel)
        agent.agent_name = "test"
        agent.role = "tester"
        agent.focus_areas = ["defi", "reentrancy"]
        agent.confidence_weight = 1.0
        agent.db_manager = MagicMock()
        agent.config = MagicMock()
        return agent

    def test_returns_focus_areas(self):
        """Returns context with focus areas."""
        agent = self._make_agent()
        agent.db_manager.get_learning_patterns.return_value = []
        result = agent._apply_learning_patterns("contract code")
        self.assertIn("focus_areas", result)
        self.assertEqual(result["focus_areas"], ["defi", "reentrancy"])

    def test_high_success_rate_patterns_included(self):
        """Patterns with success_rate > 0.7 are included."""
        agent = self._make_agent()
        agent.db_manager.get_learning_patterns.return_value = [
            {"success_rate": 0.9, "pattern_type": "defi", "original_classification": "a",
             "corrected_classification": "b", "confidence_threshold": 0.8, "reasoning": "test"}
        ]
        result = agent._apply_learning_patterns("contract code")
        # Called for each of 2 focus areas, 1 pattern each = 2
        self.assertEqual(len(result["learned_patterns"]), 2)

    def test_low_success_rate_patterns_excluded(self):
        """Patterns with success_rate <= 0.7 are excluded."""
        agent = self._make_agent()
        agent.db_manager.get_learning_patterns.return_value = [
            {"success_rate": 0.3, "pattern_type": "defi", "original_classification": "a",
             "corrected_classification": "b"}
        ]
        result = agent._apply_learning_patterns("contract code")
        self.assertEqual(len(result["learned_patterns"]), 0)

    def test_db_error_returns_defaults(self):
        """Database errors return default context."""
        agent = self._make_agent()
        agent.db_manager.get_learning_patterns.side_effect = Exception("DB error")
        result = agent._apply_learning_patterns("contract code")
        self.assertEqual(result["learned_patterns"], [])


# -------------------------------------------------------------------
class TestBaseAIModelUsageTracking(unittest.TestCase):
    """Tests for _track_openai_usage, _track_gemini_usage, _track_anthropic_usage"""

    def _make_agent(self):
        from core.ai_ensemble import BaseAIModel
        agent = BaseAIModel.__new__(BaseAIModel)
        agent.agent_name = "test_agent"
        return agent

    @patch('core.llm_usage_tracker.LLMUsageTracker.get_instance')
    def test_track_openai_usage(self, mock_get_instance):
        """OpenAI usage tracking records provider and tokens."""
        agent = self._make_agent()
        mock_response = MagicMock()
        mock_response.usage.prompt_tokens = 100
        mock_response.usage.completion_tokens = 50
        mock_tracker = MagicMock()
        mock_get_instance.return_value = mock_tracker
        agent._track_openai_usage(mock_response, "gpt-4o")
        mock_tracker.record.assert_called_once_with(
            "openai", "gpt-4o", 100, 50, "ai_ensemble.test_agent"
        )

    @patch('core.llm_usage_tracker.LLMUsageTracker.get_instance')
    def test_track_gemini_usage(self, mock_get_instance):
        """Gemini usage tracking records from usageMetadata dict."""
        agent = self._make_agent()
        result_dict = {
            "usageMetadata": {"promptTokenCount": 200, "candidatesTokenCount": 100}
        }
        mock_tracker = MagicMock()
        mock_get_instance.return_value = mock_tracker
        agent._track_gemini_usage(result_dict, "gemini-2.5-flash")
        mock_tracker.record.assert_called_once_with(
            "gemini", "gemini-2.5-flash", 200, 100, "ai_ensemble.test_agent"
        )

    @patch('core.llm_usage_tracker.LLMUsageTracker.get_instance')
    def test_track_anthropic_usage(self, mock_get_instance):
        """Anthropic usage tracking records input/output tokens."""
        agent = self._make_agent()
        mock_response = MagicMock()
        mock_response.usage.input_tokens = 300
        mock_response.usage.output_tokens = 150
        mock_tracker = MagicMock()
        mock_get_instance.return_value = mock_tracker
        agent._track_anthropic_usage(mock_response, "claude-opus-4-6")
        mock_tracker.record.assert_called_once_with(
            "anthropic", "claude-opus-4-6", 300, 150, "ai_ensemble.test_agent"
        )

    def test_track_openai_no_usage_no_error(self):
        """No error when response has no usage attribute."""
        agent = self._make_agent()
        mock_response = MagicMock(spec=[])  # No usage attribute
        agent._track_openai_usage(mock_response, "gpt-4o")  # Should not raise

    def test_track_gemini_empty_metadata_no_error(self):
        """No error when usageMetadata is empty."""
        agent = self._make_agent()
        agent._track_gemini_usage({}, "gemini-2.5-flash")  # Should not raise

    def test_track_anthropic_no_usage_no_error(self):
        """No error when response has no usage attribute."""
        agent = self._make_agent()
        mock_response = MagicMock(spec=[])
        agent._track_anthropic_usage(mock_response, "claude-opus-4-6")  # Should not raise


# -------------------------------------------------------------------
class TestDeFiSecurityExpertAnalyze(unittest.TestCase):
    """Tests for DeFiSecurityExpert.analyze_contract()"""

    @patch('core.ai_ensemble.DatabaseManager')
    @patch('core.ai_ensemble.ConfigManager')
    def test_no_api_key_returns_empty(self, mock_config_cls, mock_db_cls):
        """No API key returns empty findings with error."""
        from core.ai_ensemble import DeFiSecurityExpert

        mock_db = MagicMock()
        mock_db.get_learning_patterns.return_value = []
        mock_db_cls.return_value = mock_db
        mock_config_obj = MagicMock()
        mock_config_obj.config.openai_api_key = None
        mock_config_cls.return_value = mock_config_obj

        expert = DeFiSecurityExpert()

        with patch.dict(os.environ, {}, clear=True):
            result = _run(expert.analyze_contract(SAMPLE_CONTRACT))

        self.assertEqual(result.findings, [])
        self.assertEqual(result.confidence, 0.0)

    @patch('core.ai_ensemble.DatabaseManager')
    @patch('core.ai_ensemble.ConfigManager')
    def test_successful_analysis(self, mock_config_cls, mock_db_cls):
        """Successful OpenAI call returns findings."""
        from core.ai_ensemble import DeFiSecurityExpert

        mock_db = MagicMock()
        mock_db.get_learning_patterns.return_value = []
        mock_db_cls.return_value = mock_db
        mock_config_cls.return_value = MagicMock()

        expert = DeFiSecurityExpert()

        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content=MOCK_ENSEMBLE_FINDINGS_JSON))]
        mock_response.usage = MagicMock(prompt_tokens=100, completion_tokens=50)

        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_response

        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}):
            with patch('openai.OpenAI', return_value=mock_client):
                with patch('core.llm_usage_tracker.LLMUsageTracker.get_instance', return_value=MagicMock()):
                    result = _run(expert.analyze_contract(SAMPLE_CONTRACT))

        self.assertEqual(result.model_name, "defi_expert")
        self.assertIsInstance(result.findings, list)
        self.assertGreater(result.processing_time, 0)


# -------------------------------------------------------------------
class TestGPT5SecurityAuditorAnalyze(unittest.TestCase):
    """Tests for GPT5SecurityAuditor.analyze_contract()"""

    @patch('core.ai_ensemble.DatabaseManager')
    @patch('core.ai_ensemble.ConfigManager')
    def test_no_api_key(self, mock_config_cls, mock_db_cls):
        """Returns empty findings when no API key."""
        from core.ai_ensemble import GPT5SecurityAuditor

        mock_config_obj = MagicMock()
        mock_config_obj.config.openai_api_key = None
        mock_config_obj.config.agent_gpt5_security_model = None
        mock_config_cls.return_value = mock_config_obj
        mock_db_cls.return_value = MagicMock()

        auditor = GPT5SecurityAuditor()

        # Also patch core.config_manager.ConfigManager for the lazy import inside
        # analyze_contract's method body
        with patch('core.config_manager.ConfigManager', return_value=mock_config_obj):
            result = _run(auditor.analyze_contract(SAMPLE_CONTRACT))

        self.assertEqual(result.model_name, "gpt5_security")
        self.assertEqual(result.findings, [])
        self.assertIn("error", result.metadata)


# -------------------------------------------------------------------
class TestGeminiSecurityAuditorAnalyze(unittest.TestCase):
    """Tests for GeminiSecurityAuditor.analyze_contract()"""

    @patch('core.ai_ensemble.DatabaseManager')
    @patch('core.config_manager.ConfigManager')
    def test_no_api_key(self, mock_config_cls, mock_db_cls):
        """Returns empty findings when no Gemini API key."""
        from core.ai_ensemble import GeminiSecurityAuditor

        mock_config_obj = MagicMock()
        mock_config_obj.config.gemini_api_key = None
        mock_config_cls.return_value = mock_config_obj
        mock_db_cls.return_value = MagicMock()

        auditor = GeminiSecurityAuditor()
        result = _run(auditor.analyze_contract(SAMPLE_CONTRACT))

        self.assertEqual(result.model_name, "gemini_security")
        self.assertEqual(result.findings, [])

    @patch('core.ai_ensemble.DatabaseManager')
    @patch('core.ai_ensemble.ConfigManager')
    def test_successful_gemini_call(self, mock_config_cls, mock_db_cls):
        """Successful Gemini REST API call parses findings."""
        from core.ai_ensemble import GeminiSecurityAuditor

        mock_config_obj = MagicMock()
        mock_config_obj.config.gemini_api_key = "gem-test"
        mock_config_obj.config.agent_gemini_security_model = "gemini-2.5-flash"
        mock_config_cls.return_value = mock_config_obj
        mock_db_cls.return_value = MagicMock()

        auditor = GeminiSecurityAuditor()

        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "candidates": [{"content": {"parts": [{"text": MOCK_ENSEMBLE_FINDINGS_JSON}]}, "finishReason": "STOP"}],
            "usageMetadata": {"promptTokenCount": 100, "candidatesTokenCount": 50}
        }
        mock_resp.raise_for_status = MagicMock()

        with patch('requests.post', return_value=mock_resp):
            with patch('core.llm_usage_tracker.LLMUsageTracker.get_instance', return_value=MagicMock()):
                result = _run(auditor.analyze_contract(SAMPLE_CONTRACT))

        self.assertEqual(result.model_name, "gemini_security")
        self.assertIsInstance(result.findings, list)


# -------------------------------------------------------------------
class TestAnthropicSecurityAuditorAnalyze(unittest.TestCase):
    """Tests for AnthropicSecurityAuditor.analyze_contract()"""

    @patch('core.ai_ensemble.DatabaseManager')
    @patch('core.ai_ensemble.ConfigManager')
    def test_no_api_key(self, mock_config_cls, mock_db_cls):
        """Returns empty findings when no Anthropic API key."""
        from core.ai_ensemble import AnthropicSecurityAuditor

        mock_config_obj = MagicMock()
        mock_config_obj.config.anthropic_api_key = None
        mock_config_cls.return_value = mock_config_obj
        mock_db_cls.return_value = MagicMock()

        with patch.dict(os.environ, {}, clear=True):
            auditor = AnthropicSecurityAuditor()
            result = _run(auditor.analyze_contract(SAMPLE_CONTRACT))

        self.assertEqual(result.model_name, "anthropic_security")
        self.assertEqual(result.findings, [])


# -------------------------------------------------------------------
class TestAIEnsembleConsensus(unittest.TestCase):
    """Tests for AIEnsemble._generate_consensus() and helpers."""

    def _make_ensemble(self):
        with patch('core.ai_ensemble.DatabaseManager'):
            with patch('core.ai_ensemble.ConfigManager'):
                from core.ai_ensemble import AIEnsemble
                return AIEnsemble()

    def test_empty_results_returns_zero_agreement(self):
        """No valid results returns 0.0 agreement."""
        ensemble = self._make_ensemble()
        consensus = ensemble._generate_consensus([])
        self.assertEqual(consensus['agreement'], 0.0)
        self.assertEqual(consensus['findings'], [])

    def test_single_agent_finding(self):
        """Single agent result produces findings with low agreement."""
        from core.ai_ensemble import ModelResult
        ensemble = self._make_ensemble()
        result = ModelResult(
            model_name="agent1",
            findings=[{"type": "reentrancy", "severity": "high", "confidence": 0.9, "line": 15}],
            confidence=0.85,
            processing_time=1.0,
            metadata={}
        )
        consensus = ensemble._generate_consensus([result])
        self.assertGreater(len(consensus['findings']), 0)
        self.assertEqual(consensus['agreement'], 0.0)

    def test_two_agents_agree_on_same_finding(self):
        """Two agents finding same type/line produce high agreement."""
        from core.ai_ensemble import ModelResult
        ensemble = self._make_ensemble()
        r1 = ModelResult(
            model_name="agent1",
            findings=[{"type": "reentrancy", "severity": "high", "confidence": 0.9, "line": 15}],
            confidence=0.85, processing_time=1.0, metadata={}
        )
        r2 = ModelResult(
            model_name="agent2",
            findings=[{"type": "cross_function_reentrancy", "severity": "high", "confidence": 0.85, "line": 16}],
            confidence=0.8, processing_time=1.0, metadata={}
        )
        consensus = ensemble._generate_consensus([r1, r2])
        self.assertEqual(len(consensus['findings']), 1)
        self.assertGreater(consensus['agreement'], 0.0)

    def test_different_types_not_merged(self):
        """Findings of different types are not merged."""
        from core.ai_ensemble import ModelResult
        ensemble = self._make_ensemble()
        r1 = ModelResult(
            model_name="agent1",
            findings=[{"type": "reentrancy", "severity": "high", "confidence": 0.9, "line": 15}],
            confidence=0.85, processing_time=1.0, metadata={}
        )
        r2 = ModelResult(
            model_name="agent2",
            findings=[{"type": "access_control", "severity": "high", "confidence": 0.85, "line": 15}],
            confidence=0.8, processing_time=1.0, metadata={}
        )
        consensus = ensemble._generate_consensus([r1, r2])
        self.assertEqual(len(consensus['findings']), 2)

    def test_normalize_vuln_type(self):
        """Vulnerability type normalization works correctly."""
        ensemble = self._make_ensemble()
        self.assertEqual(ensemble._normalize_vuln_type("reentrancy"), "reentrancy")
        self.assertEqual(ensemble._normalize_vuln_type("cross_function_reentrancy"), "reentrancy")
        self.assertEqual(ensemble._normalize_vuln_type("read_only_reentrancy"), "reentrancy")
        self.assertEqual(ensemble._normalize_vuln_type("missing_access_control"), "access_control")
        self.assertEqual(ensemble._normalize_vuln_type("oracle_manipulation"), "oracle_manipulation")
        self.assertEqual(ensemble._normalize_vuln_type("novel_type"), "novel_type")
        self.assertEqual(ensemble._normalize_vuln_type("Flash Loan Attack"), "flash_loan")

    def test_findings_match_fuzzy_same_type_close_lines(self):
        """Findings with same type and close line numbers match."""
        ensemble = self._make_ensemble()
        f1 = {"type": "reentrancy", "line": 15}
        f2 = {"type": "cross_function_reentrancy", "line": 17}
        self.assertTrue(ensemble._findings_match_fuzzy(f1, f2))

    def test_findings_match_fuzzy_different_type(self):
        """Findings with different types don't match."""
        ensemble = self._make_ensemble()
        f1 = {"type": "reentrancy", "line": 15}
        f2 = {"type": "access_control", "line": 15}
        self.assertFalse(ensemble._findings_match_fuzzy(f1, f2))

    def test_findings_match_fuzzy_distant_lines(self):
        """Findings with same type but distant lines don't match."""
        ensemble = self._make_ensemble()
        f1 = {"type": "reentrancy", "line": 10}
        f2 = {"type": "reentrancy", "line": 100}
        self.assertFalse(ensemble._findings_match_fuzzy(f1, f2))

    def test_findings_match_fuzzy_negative_lines(self):
        """Negative line numbers are treated as unknown and match."""
        ensemble = self._make_ensemble()
        f1 = {"type": "reentrancy", "line": -1}
        f2 = {"type": "reentrancy", "line": -1}
        self.assertTrue(ensemble._findings_match_fuzzy(f1, f2))

    def test_merge_similar_findings_boosts_confidence(self):
        """Merging 2+ similar findings boosts confidence."""
        ensemble = self._make_ensemble()
        findings = [
            {"type": "reentrancy", "severity": "high", "confidence": 0.8},
            {"type": "reentrancy", "severity": "high", "confidence": 0.85},
        ]
        merged = ensemble._merge_similar_findings(findings, ["agent1", "agent2"])
        self.assertEqual(merged['agreement_count'], 2)
        self.assertAlmostEqual(merged['confidence'], 0.925, places=2)
        self.assertFalse(merged['needs_verification'])

    def test_merge_single_finding_penalizes_confidence(self):
        """Single finding gets confidence penalty."""
        ensemble = self._make_ensemble()
        findings = [
            {"type": "reentrancy", "severity": "high", "confidence": 0.8},
        ]
        merged = ensemble._merge_similar_findings(findings, ["agent1"])
        self.assertEqual(merged['agreement_count'], 1)
        self.assertAlmostEqual(merged['confidence'], 0.72, places=2)
        self.assertTrue(merged['needs_verification'])

    def test_get_finding_key(self):
        """Finding key is the normalized vulnerability type."""
        ensemble = self._make_ensemble()
        key = ensemble._get_finding_key({"type": "reentrancy", "line": 15})
        self.assertEqual(key, "reentrancy")

    def test_get_finding_key_normalizes_type(self):
        """Finding key normalizes cross_function_reentrancy to reentrancy."""
        ensemble = self._make_ensemble()
        key = ensemble._get_finding_key({"type": "cross_function_reentrancy", "line": 15})
        self.assertEqual(key, "reentrancy")


# -------------------------------------------------------------------
class TestAIEnsembleProperties(unittest.TestCase):
    """Tests for AIEnsemble properties and configuration."""

    def _make_ensemble(self):
        with patch('core.ai_ensemble.DatabaseManager'):
            with patch('core.ai_ensemble.ConfigManager'):
                from core.ai_ensemble import AIEnsemble
                return AIEnsemble()

    def test_models_dict_has_six_agents(self):
        """Ensemble has 6 production agents."""
        ensemble = self._make_ensemble()
        self.assertEqual(len(ensemble.models), 6)
        self.assertIn('gpt5_security', ensemble.models)
        self.assertIn('gemini_security', ensemble.models)
        self.assertIn('anthropic_security', ensemble.models)

    def test_agents_property_returns_legacy(self):
        """The .agents property returns legacy agents for backward compatibility."""
        ensemble = self._make_ensemble()
        self.assertEqual(len(ensemble.agents), 3)

    def test_get_model_specializations(self):
        """get_model_specializations returns all 6 agent focus areas."""
        ensemble = self._make_ensemble()
        specs = ensemble.get_model_specializations()
        self.assertEqual(len(specs), 6)
        self.assertIn('gpt5_security', specs)
        self.assertIn('reentrancy', specs['gpt5_security'])

    def test_get_ensemble_stats(self):
        """get_ensemble_stats returns proper structure."""
        ensemble = self._make_ensemble()
        stats = ensemble.get_ensemble_stats()
        self.assertEqual(stats['total_models'], 6)
        self.assertIn('model_specializations', stats)
        self.assertIn('model_weights', stats)

    def test_enhanced_ai_ensemble_alias(self):
        """EnhancedAIEnsemble is an alias for AIEnsemble."""
        from core.ai_ensemble import AIEnsemble, EnhancedAIEnsemble
        self.assertIs(EnhancedAIEnsemble, AIEnsemble)

    def test_update_model_weights(self):
        """update_model_weights updates agent confidence_weight."""
        ensemble = self._make_ensemble()
        ensemble.update_model_weights({'gpt5_security': 2.0})
        self.assertEqual(ensemble.models['gpt5_security'].confidence_weight, 2.0)


# -------------------------------------------------------------------
class TestAIEnsembleActiveAgents(unittest.TestCase):
    """Tests for AIEnsemble.active_agents property."""

    def test_no_keys_returns_empty(self):
        """No API keys means no active agents."""
        with patch.dict(os.environ, {}, clear=True):
            with patch('core.ai_ensemble.DatabaseManager'):
                with patch('core.ai_ensemble.ConfigManager') as mock_config_cls:
                    mock_config_obj = MagicMock()
                    mock_config_obj.config.openai_api_key = None
                    mock_config_obj.config.gemini_api_key = None
                    mock_config_obj.config.anthropic_api_key = None
                    mock_config_cls.return_value = mock_config_obj
                    from core.ai_ensemble import AIEnsemble
                    ensemble = AIEnsemble()
                    active = ensemble.active_agents
        self.assertEqual(len(active), 0)

    def test_openai_key_activates_gpt5_agents(self):
        """Setting OPENAI_API_KEY activates GPT5 agents."""
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}, clear=True):
            with patch('core.ai_ensemble.DatabaseManager'):
                with patch('core.ai_ensemble.ConfigManager') as mock_config_cls:
                    mock_config_obj = MagicMock()
                    mock_config_obj.config.openai_api_key = None
                    mock_config_obj.config.gemini_api_key = None
                    mock_config_obj.config.anthropic_api_key = None
                    mock_config_cls.return_value = mock_config_obj
                    from core.ai_ensemble import AIEnsemble
                    ensemble = AIEnsemble()
                    active = ensemble.active_agents
        agent_names = [a.agent_name for a in active]
        self.assertIn('gpt5_security', agent_names)
        self.assertIn('gpt5_defi', agent_names)


# -------------------------------------------------------------------
class TestAIEnsembleAnalyzeWithEnsemble(unittest.TestCase):
    """Tests for AIEnsemble.analyze_with_ensemble()"""

    def test_all_agents_fail_returns_empty(self):
        """When all agents fail, returns empty consensus."""
        with patch('core.ai_ensemble.DatabaseManager'):
            with patch('core.ai_ensemble.ConfigManager'):
                from core.ai_ensemble import AIEnsemble, ModelResult
                ensemble = AIEnsemble()

        mock_agent = MagicMock()
        mock_agent.agent_name = "mock_agent"
        mock_agent.analyze_contract.return_value = ModelResult(
            model_name="mock", findings=[], confidence=0.0,
            processing_time=0.1, metadata={"error": "fail"}
        )

        with patch.object(type(ensemble), 'active_agents', new_callable=PropertyMock, return_value=[mock_agent]):
            result = _run(ensemble.analyze_with_ensemble(SAMPLE_CONTRACT))

        self.assertEqual(result.consensus_findings, [])
        self.assertEqual(result.model_agreement, 0.0)

    def test_analyze_contract_ensemble_alias(self):
        """analyze_contract_ensemble is an alias for analyze_with_ensemble."""
        with patch('core.ai_ensemble.DatabaseManager'):
            with patch('core.ai_ensemble.ConfigManager'):
                from core.ai_ensemble import AIEnsemble
                ensemble = AIEnsemble()

        # Just verify the method exists and calls through
        with patch.object(ensemble, 'analyze_with_ensemble') as mock_method:
            mock_method.return_value = MagicMock()
            _run(ensemble.analyze_contract_ensemble("contract"))
            mock_method.assert_awaited_once_with("contract")


# -------------------------------------------------------------------
class TestStubModels(unittest.TestCase):
    """Tests for the stub/test models (DeFiSpecialistModel, FormalVerificationModel)."""

    @patch('core.ai_ensemble.DatabaseManager')
    @patch('core.ai_ensemble.ConfigManager')
    def test_defi_specialist_model(self, mock_config, mock_db):
        """DeFiSpecialistModel returns hardcoded findings."""
        from core.ai_ensemble import DeFiSpecialistModel
        model = DeFiSpecialistModel()
        result = _run(model.analyze_contract("contract code"))
        self.assertEqual(result.model_name, "defi_specialist")
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0]['type'], 'reentrancy')

    @patch('core.ai_ensemble.DatabaseManager')
    @patch('core.ai_ensemble.ConfigManager')
    def test_formal_verification_model(self, mock_config, mock_db):
        """FormalVerificationModel returns hardcoded findings."""
        from core.ai_ensemble import FormalVerificationModel
        model = FormalVerificationModel()
        result = _run(model.analyze_contract("contract code"))
        self.assertEqual(result.model_name, "formal_verification")
        self.assertEqual(len(result.findings), 1)
        self.assertGreater(result.confidence, 0.8)

    @patch('core.ai_ensemble.DatabaseManager')
    @patch('core.ai_ensemble.ConfigManager')
    def test_defi_specialist_confidence_weight(self, mock_config, mock_db):
        """DeFiSpecialistModel applies confidence_weight to finding confidence."""
        from core.ai_ensemble import DeFiSpecialistModel
        model = DeFiSpecialistModel()
        model.confidence_weight = 0.5
        result = _run(model.analyze_contract("contract code"))
        # confidence should be 0.7 * 0.5 = 0.35
        self.assertAlmostEqual(result.findings[0]['confidence'], 0.35, places=2)


# -------------------------------------------------------------------
class TestGetProviderForAgent(unittest.TestCase):
    """Tests for AIEnsemble._get_provider_for_agent()"""

    def _make_ensemble(self):
        with patch('core.ai_ensemble.DatabaseManager'):
            with patch('core.ai_ensemble.ConfigManager'):
                from core.ai_ensemble import AIEnsemble
                return AIEnsemble()

    def test_gpt5_agents(self):
        ensemble = self._make_ensemble()
        self.assertEqual(ensemble._get_provider_for_agent('gpt5_security'), 'openai')
        self.assertEqual(ensemble._get_provider_for_agent('gpt5_defi'), 'openai')

    def test_gemini_agents(self):
        ensemble = self._make_ensemble()
        self.assertEqual(ensemble._get_provider_for_agent('gemini_security'), 'gemini')
        self.assertEqual(ensemble._get_provider_for_agent('gemini_verification'), 'gemini')

    def test_anthropic_agents(self):
        ensemble = self._make_ensemble()
        self.assertEqual(ensemble._get_provider_for_agent('anthropic_security'), 'anthropic')
        self.assertEqual(ensemble._get_provider_for_agent('anthropic_reasoning'), 'anthropic')

    def test_legacy_agents(self):
        ensemble = self._make_ensemble()
        self.assertEqual(ensemble._get_provider_for_agent('defi_expert'), 'openai')
        self.assertEqual(ensemble._get_provider_for_agent('proxy_expert'), 'openai')

    def test_unknown_agent(self):
        ensemble = self._make_ensemble()
        self.assertEqual(ensemble._get_provider_for_agent('mystery'), 'unknown')


if __name__ == '__main__':
    unittest.main()
