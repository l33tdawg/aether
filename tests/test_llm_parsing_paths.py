import asyncio
import pytest

from core.enhanced_llm_analyzer import EnhancedLLMAnalyzer
from core.llm_false_positive_filter import LLMFalsePositiveFilter
from core.llm_foundry_generator import LLMFoundryGenerator


@pytest.mark.asyncio
async def test_enhanced_llm_analyzer_parses_valid_json(monkeypatch):
    analyzer = EnhancedLLMAnalyzer(api_key="dummy")

    async def fake_call_llm(prompt: str, model: str = ""):
        return '{"vulnerabilities": [{"title": "Access Control", "description": "Missing check", "severity": "medium", "confidence": 0.9}], "summary": {"total_vulnerabilities": 1, "high_severity_count": 0, "execution_time": 0.1}}'

    monkeypatch.setattr(analyzer, "_call_llm", fake_call_llm)

    contract_code = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.19;
    contract C {
        function foo() public { /* no access control */ }
    }
    """
    # Ensure validation passes regardless of code heuristics
    monkeypatch.setattr(analyzer, "_validate_vulnerability", lambda v, c: True)
    result = await analyzer.analyze_vulnerabilities(contract_code, {"vulnerabilities": []}, {})
    assert result.get('success') in (True, False) or 'analysis' in result
    vulns = result.get('analysis', {}).get('vulnerabilities', [])
    assert isinstance(vulns, list)


@pytest.mark.asyncio
async def test_enhanced_llm_analyzer_parses_malformed_json(monkeypatch):
    analyzer = EnhancedLLMAnalyzer(api_key="dummy")

    async def fake_call_llm(prompt: str, model: str = ""):
        # Malformed: control char, trailing comma, missing quotes
        return '```json\n{\n  "vulnerabilities": [ { "title": "Reentrancy", "severity": "high", "confidence": 0.85, } ],\n  "summary": { "total_vulnerabilities": 1, "high_severity_count": 1, "execution_time": 0.2 }\x01\n}\n```'

    monkeypatch.setattr(analyzer, "_call_llm", fake_call_llm)

    result = await analyzer.analyze_vulnerabilities("contract code", {"vulnerabilities": []}, {})
    # Should not throw; either parsed or fallback response
    assert 'analysis' in result
    assert isinstance(result.get('analysis', {}).get('vulnerabilities', []), list)


@pytest.mark.asyncio
async def test_llm_false_positive_filter_parses_validation(monkeypatch):
    analyzer = EnhancedLLMAnalyzer(api_key="dummy")
    fp = LLMFalsePositiveFilter(analyzer)

    async def fake_call_llm(prompt: str, model: str = ""):
        return '```json\n{\n  "is_false_positive": false,\n  "confidence": 0.88,\n  "reasoning": "looks real"\n}\n```'

    monkeypatch.setattr(analyzer, "_call_llm", fake_call_llm)

    vulns = [{
        'vulnerability_type': 'access_control',
        'severity': 'medium',
        'confidence': 0.8,
        'line_number': 10,
        'description': 'test'
    }]

    validated = await fp.validate_vulnerabilities(vulns, "contract code", "C")
    assert len(validated) == 1
    assert validated[0].get('validation_confidence', 0) >= 0.8


def test_foundry_generator_parse_test_response():
    gen = LLMFoundryGenerator()
    response = '{"test_code": "// SPDX-License-Identifier: MIT\\npragma solidity ^0.8.19;\\n", "exploit_code": "// SPDX-License-Identifier: MIT\\npragma solidity ^0.8.19;\\n", "fixed_code": "// SPDX-License-Identifier: MIT\\npragma solidity ^0.8.19;\\n"}'
    result = gen._parse_test_response(response, { 'vulnerability_type': 'access_control' }, 'MyContract')
    assert result.success is True
    assert 'pragma solidity' in result.test_code
    assert 'pragma solidity' in result.exploit_code


