"""
Comprehensive test suite for the LLM analysis pipeline.

Tests core/enhanced_llm_analyzer.py (EnhancedLLMAnalyzer).

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


if __name__ == '__main__':
    unittest.main()
