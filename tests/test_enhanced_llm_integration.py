#!/usr/bin/env python3
"""
Test suite for enhanced LLM integration and analysis improvements.

Tests the integration between poc_generator and enhanced LLM analyzer,
including improved prompt engineering and response parsing.
"""

import pytest
import asyncio
import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from typing import Dict, Any

# Add parent directory to path for imports
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from core.foundry_poc_generator import FoundryPoCGenerator
    from core.enhanced_llm_analyzer import EnhancedLLMAnalyzer
except ImportError as e:
    print(f"Import error: {e}")
    sys.exit(1)


class TestEnhancedLLMAnalyzerIntegration:
    """Test integration with enhanced LLM analyzer."""

    @pytest.fixture
    def poc_generator(self):
        """Create poc_generator instance for testing."""
        return FoundryPoCGenerator({})

    @pytest.fixture
    def llm_analyzer(self):
        """Create enhanced LLM analyzer for testing."""
        return EnhancedLLMAnalyzer(api_key="test_key")

    @pytest.fixture
    def sample_contract(self):
        """Sample contract for testing."""
        return '''
pragma solidity 0.8.19;

interface IVulnerable {
    function withdraw(uint256 amount) external;
    function balanceOf(address account) external view returns (uint256);
}

contract VulnerableContract {
    mapping(address => uint256) balances;

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount); // Reentrancy vulnerability
    }

    function balanceOf(address account) external view returns (uint256) {
        return balances[account];
    }
}
'''

    @pytest.mark.asyncio
    async def test_enhanced_prompt_generation_for_llm(self, poc_generator, sample_contract):
        """Test that enhanced prompts are suitable for LLM processing."""
        context = {
            'contract_name': 'VulnerableContract',
            'vulnerability_type': 'reentrancy',
            'line_number': 15,
            'description': 'Reentrancy vulnerability in withdraw function',
            'contract_source': sample_contract,
            'solc_version': '0.8.19',
            'available_functions': ['withdraw', 'balanceOf']
        }

        prompt = poc_generator._create_poc_generation_prompt(context, {})

        # Should be well-structured for LLM understanding
        assert len(prompt) > 1000  # Substantial prompt
        assert prompt.count('\n') > 20  # Well-formatted

        # Should include clear sections
        assert 'VULNERABILITY INTEL:' in prompt
        assert 'CONTRACT ANALYSIS' in prompt
        assert 'ATTACK CHAIN' in prompt
        assert 'REQUIREMENTS' in prompt

        # Should have clear output format specification
        assert 'DELIVERABLE FORMAT:' in prompt
        assert 'Return ONLY valid JSON' in prompt

    @pytest.mark.asyncio
    async def test_llm_response_parsing_robustness(self, poc_generator):
        """Test robustness of LLM response parsing."""
        test_cases = [
            # Valid JSON response
            {
                "test_code": "pragma solidity 0.8.19; contract Test {}",
                "exploit_code": "pragma solidity 0.8.19; contract Exploit {}",
                "explanation": "Test explanation"
            },
            # JSON in markdown code block
            """```json
{
    "test_code": "pragma solidity 0.8.19; contract Test {}",
    "exploit_code": "pragma solidity 0.8.19; contract Exploit {}",
    "explanation": "Test explanation"
}
```""",
            # Mixed content with JSON
            """Here's the exploit code:

```json
{
    "test_code": "pragma solidity 0.8.19; contract Test {}",
    "exploit_code": "pragma solidity 0.8.19; contract Exploit {}",
    "explanation": "Test explanation"
}
```

Some additional explanation.""",
        ]

        for i, response in enumerate(test_cases):
            result = poc_generator._parse_llm_poc_response(str(response))

            # Should parse successfully
            assert isinstance(result, dict)
            assert 'test_code' in result
            assert 'exploit_code' in result
            assert 'explanation' in result

            # Should contain expected content
            assert 'pragma solidity 0.8.19' in result['test_code']
            assert 'contract Test' in result['test_code']
            assert 'contract Exploit' in result['exploit_code']

    @pytest.mark.asyncio
    async def test_enhanced_error_messages_for_llm(self, poc_generator):
        """Test enhanced error messages for LLM guidance."""
        compile_errors = [
            "DeclarationError: Identifier not found or not unique",
            "TypeError: Type uint256 is not implicitly convertible to address"
        ]

        contract_code = "pragma solidity 0.8.19; contract Test {}"
        prompt = poc_generator._create_compilation_fix_prompt(errors, contract_code, "Test.sol")

        # Should provide specific guidance for common errors
        assert 'Fix type mismatches' in prompt
        assert 'Add missing imports' in prompt
        assert 'Fix function signatures' in prompt
        assert 'Resolve variable scoping issues' in prompt

        # Should specify exact requirements
        assert 'Ensure the code compiles with `forge build`' in prompt
        assert 'Maintain the same functionality' in prompt

    @pytest.mark.asyncio
    async def test_attack_chain_specificity_for_llm(self, poc_generator):
        """Test that attack chains are specific enough for LLM understanding."""
        # Test different vulnerability types
        vulnerability_types = [
            'access_control',
            'reentrancy',
            'oracle_manipulation',
            'flash_loan_attack'
        ]

        for vuln_type in vulnerability_types:
            context = {
                'contract_name': 'TestContract',
                'vulnerability_type': vuln_type,
                'available_functions': ['withdraw', 'balanceOf']
            }

            attack_chain = poc_generator._analyze_attack_chain_for_prompt(
                context, "external functions", "modifiers"
            )

            # Should be specific to vulnerability type
            assert isinstance(attack_chain, str)
            assert len(attack_chain) > 100  # Substantial content
            assert vuln_type.replace('_', ' ').title() in attack_chain or vuln_type in attack_chain

            # Should include specific attack steps
            assert '1.' in attack_chain  # Numbered steps
            assert 'Attacker' in attack_chain  # Attacker actions

    @pytest.mark.asyncio
    async def test_contract_context_enhancement_for_llm(self, poc_generator, sample_contract):
        """Test that contract context is enhanced for LLM understanding."""
        context = {
            'contract_name': 'VulnerableContract',
            'vulnerability_type': 'reentrancy',
            'line_number': 15,
            'description': 'Reentrancy vulnerability'
        }

        enhanced_context = poc_generator._extract_enhanced_contract_context(sample_contract, context)

        # Should provide vulnerability-focused context
        assert '>>>   15:' in enhanced_context  # Vulnerability location marker
        assert 'REENTRANCY CONTEXT' in enhanced_context

        # Should include relevant code sections
        assert 'withdraw' in enhanced_context.lower()
        assert 'transfer' in enhanced_context.lower()

        # Should be well-structured for LLM parsing
        assert len(enhanced_context) > 200  # Substantial context
        assert enhanced_context.count('\n') > 5  # Multiple lines


class TestResponseQualityValidation:
    """Test response quality validation improvements."""

    @pytest.fixture
    def poc_generator(self):
        """Create poc_generator instance for testing."""
        return FoundryPoCGenerator({})

    def test_real_exploit_code_validation(self, poc_generator):
        """Test validation of real vs stub exploit code."""
        # Test real exploit code
        real_exploit = """
pragma solidity 0.8.19;

interface IVulnerable {
    function withdraw(uint256 amount) external;
}

contract ExploitContract {
    IVulnerable public target;
    address public attacker;

    constructor(address _target, address _attacker) {
        target = IVulnerable(_target);
        attacker = _attacker;
    }

    function exploit() external {
        require(msg.sender == attacker, "Only attacker");
        uint256 balance = address(target).balance;
        target.withdraw(balance);
        payable(attacker).transfer(address(this).balance);
    }
}
"""

        available_functions = ['withdraw', 'balanceOf']

        # Should validate as real exploit
        is_real = poc_generator._is_real_exploit_code(real_exploit, available_functions)
        assert is_real is True

    def test_stub_code_rejection(self, poc_generator):
        """Test rejection of stub exploit code."""
        # Test stub code
        stub_code = """
pragma solidity 0.8.19;

contract StubContract {
    bool public executed = false;

    function exploit() external {
        executed = true; // Just sets a boolean - not real exploit
    }
}
"""

        available_functions = ['withdraw', 'balanceOf']

        # Should reject as stub
        is_real = poc_generator._is_real_exploit_code(stub_code, available_functions)
        assert is_real is False

    def test_compilation_error_detection_in_prompts(self, poc_generator):
        """Test that compilation errors are properly detected and included in prompts."""
        errors = [
            "TypeError: Type uint256 is not implicitly convertible to address",
            "DeclarationError: Identifier not found or not unique",
            "ParserError: Expected ';' but got '}'"
        ]

        # Should categorize errors properly
        categorized = poc_generator._categorize_compile_errors(errors)

        assert isinstance(categorized, dict)
        assert 'type_errors' in categorized or 'declaration_errors' in categorized

        # Should provide actionable error information
        error_summary = poc_generator._create_compilation_fix_prompt(errors, "contract code", "Test.sol")
        assert len(error_summary) > 500  # Substantial error guidance


class TestEnhancedPromptEngineering:
    """Test enhanced prompt engineering techniques."""

    @pytest.fixture
    def poc_generator(self):
        """Create poc_generator instance for testing."""
        return FoundryPoCGenerator({})

    def test_bounty_impact_emphasis(self, poc_generator):
        """Test that prompts emphasize bounty impact."""
        context = {
            'contract_name': 'TestContract',
            'vulnerability_type': 'critical_vulnerability'
        }

        prompt = poc_generator._create_poc_generation_prompt(context, {})

        # Should emphasize high-value bounty potential
        assert '$100k+' in prompt or '$250k' in prompt or '$500k' in prompt
        assert 'bounty' in prompt.lower()
        assert 'bug bounty' in prompt.lower()

    def test_technical_accuracy_requirements(self, poc_generator):
        """Test that prompts enforce technical accuracy."""
        context = {
            'contract_name': 'TestContract',
            'solc_version': '0.8.19',
            'available_functions': ['withdraw', 'balanceOf']
        }

        prompt = poc_generator._create_poc_generation_prompt(context, {})

        # Should enforce technical accuracy
        assert 'EXACTLY "pragma solidity 0.8.19"' in prompt
        assert 'REAL FUNCTIONS ONLY' in prompt
        assert '40-character hex' in prompt
        assert 'NO PLACEHOLDERS' in prompt

    def test_attack_vector_specificity(self, poc_generator):
        """Test that attack vectors are specific to vulnerability types."""
        contexts = [
            {
                'vulnerability_type': 'access_control',
                'contract_name': 'TestContract'
            },
            {
                'vulnerability_type': 'reentrancy',
                'contract_name': 'TestContract'
            },
            {
                'vulnerability_type': 'oracle_manipulation',
                'contract_name': 'TestContract'
            }
        ]

        for context in contexts:
            attack_chain = poc_generator._analyze_attack_chain_for_prompt(
                context, "functions", "modifiers"
            )

            # Should be specific to vulnerability type
            vuln_type = context['vulnerability_type']
            if vuln_type == 'access_control':
                assert 'governance' in attack_chain.lower() or 'owner' in attack_chain.lower()
            elif vuln_type == 'reentrancy':
                assert 'external call' in attack_chain.lower() or 'state change' in attack_chain.lower()
            elif vuln_type == 'oracle_manipulation':
                assert 'price' in attack_chain.lower() or 'oracle' in attack_chain.lower()


class TestSystemIntegration:
    """Test overall system integration."""

    @pytest.fixture
    def poc_generator(self):
        """Create poc_generator instance for testing."""
        return FoundryPoCGenerator({})

    @pytest.mark.asyncio
    async def test_end_to_end_prompt_generation(self, poc_generator):
        """Test end-to-end prompt generation pipeline."""
        # Simulate real-world context
        context = {
            'contract_name': 'RocketVault',
            'vulnerability_type': 'access_control',
            'vulnerability_class': 'Access Control',
            'severity': 'critical',
            'line_number': 42,
            'entrypoint': 'withdrawEther',
            'description': 'Governance can replace network contracts allowing vault drainage',
            'contract_source': '''
pragma solidity 0.7.6;

contract RocketVault {
    modifier onlyLatestNetworkContract(string memory _contractName) {
        require(msg.sender == rocketStorage.getAddress(
            keccak256(abi.encodePacked("contract.address", _contractName))
        ));
        _;
    }

    function withdrawEther(uint256 _amount) external onlyLatestNetworkContract("rocketVault") {
        payable(msg.sender).transfer(_amount);
    }
}
''',
            'solc_version': '0.7.6',
            'available_functions': ['withdrawEther', 'balanceOf']
        }

        # Generate enhanced prompt
        prompt = poc_generator._create_poc_generation_prompt(context, {})

        # Should include all enhanced features
        assert '🎯 MISSION:' in prompt
        assert 'RocketVault' in prompt
        assert 'Access Control' in prompt
        assert 'withdrawEther' in prompt
        assert '0.7.6' in prompt

        # Should include attack chain
        attack_chain = poc_generator._analyze_attack_chain_for_prompt(context, "functions", "modifiers")
        assert 'governance' in attack_chain.lower()

        # Should include enhanced contract context
        enhanced_context = poc_generator._extract_enhanced_contract_context(
            context['contract_source'], context
        )
        assert '>>>   42:' in enhanced_context  # Vulnerability location
        assert 'ACCESS CONTROL CONTEXT' in enhanced_context

    @pytest.mark.asyncio
    async def test_compilation_feedback_integration(self, poc_generator, temp_project_dir):
        """Test integration of compilation feedback in the workflow."""
        # Create test scenario with compilation errors
        compile_errors = [
            "DeclarationError: Identifier not found or not unique",
            "TypeError: Type uint256 is not implicitly convertible to address"
        ]

        # Mock successful LLM repair
        async def mock_llm_call(prompt, model="gpt-4o-mini"):
            return '''{
                "test_code": "pragma solidity 0.8.19;\\ncontract Test {}",
                "exploit_code": "pragma solidity 0.8.19;\\ncontract Exploit {}",
                "explanation": "Fixed compilation errors"
            }'''

        poc_generator.llm_analyzer = Mock()
        poc_generator.llm_analyzer._call_llm = mock_llm_call

        test_result = Mock()
        test_result.contract_name = "TestContract"

        # Test the integration
        repair_result = await poc_generator._analyze_and_repair_errors(
            test_result, compile_errors, temp_project_dir
        )

        # Should integrate compilation feedback
        assert repair_result['repaired'] is True
        assert 'pragma solidity 0.8.19' in repair_result['test_code']


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
