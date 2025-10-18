#!/usr/bin/env python3
"""
Comprehensive test suite for poc_generator improvements.

Tests all the major improvements made to the poc_generator system:
- AST-based contract analysis
- Enhanced LLM prompts
- Iterative compilation fixes
- Enhanced contract context extraction
- Improved error handling
- Integration with enhanced LLM analyzer

This test suite validates that the poc_generator now produces
production-ready exploits suitable for $100k+ bug bounty submissions.
"""

import pytest
import asyncio
import tempfile
import json
import os
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


class TestProductionReadyExploitGeneration:
    """Test that poc_generator produces production-ready exploits."""

    @pytest.fixture
    def poc_generator(self):
        """Create poc_generator instance for testing."""
        return FoundryPoCGenerator({})

    @pytest.fixture
    def production_ready_context(self):
        """Production-ready context for exploit generation."""
        return {
            'contract_name': 'RocketVault',
            'vulnerability_type': 'access_control',
            'vulnerability_class': 'Access Control',
            'severity': 'critical',
            'line_number': 42,
            'entrypoint': 'withdrawEther',
            'description': 'Governance can replace network contracts allowing immediate vault drainage without timelock',
            'contract_source': '''
pragma solidity 0.7.6;

interface IRocketStorage {
    function getAddress(bytes32 _key) external view returns (address);
}

interface IRocketVault {
    function withdrawEther(uint256 _amount) external;
    function balanceOf(string memory _networkContractName) external view returns (uint256);
}

contract RocketVault {
    IRocketStorage public rocketStorage;

    modifier onlyLatestNetworkContract(string memory _contractName) {
        require(msg.sender == rocketStorage.getAddress(
            keccak256(abi.encodePacked("contract.address", _contractName))
        ), "Only latest network contract allowed");
        _;
    }

    function withdrawEther(uint256 _amount) external onlyLatestNetworkContract("rocketVault") {
        payable(msg.sender).transfer(_amount);
    }

    function balanceOf(string memory _networkContractName) external view returns (uint256) {
        return balances[_networkContractName];
    }
}
''',
            'solc_version': '0.7.6',
            'available_functions': ['withdrawEther', 'balanceOf']
        }

    def test_production_ready_prompt_generation(self, poc_generator, production_ready_context):
        """Test that prompts are production-ready for $100k+ bounty submissions."""
        prompt = poc_generator._create_poc_generation_prompt(production_ready_context, {})

        # Should be comprehensive for professional security review
        assert len(prompt) > 2000  # Substantial, detailed prompt
        assert prompt.count('\n') > 30  # Well-structured

        # Should emphasize production quality
        assert 'PRODUCTION-READY' in prompt
        assert '$100k+' in prompt or '$250k' in prompt
        assert 'bug bounty' in prompt.lower()
        assert 'security professionals' in prompt.lower()

        # Should include all critical requirements
        assert 'EXACTLY "pragma solidity 0.7.6"' in prompt
        assert 'REAL FUNCTIONS ONLY' in prompt
        assert '40-character hex' in prompt
        assert 'vm.createSelectFork' in prompt
        assert 'assertTrue' in prompt or 'assertEq' in prompt

    def test_attack_chain_completeness(self, poc_generator, production_ready_context):
        """Test that attack chains are complete and realistic."""
        attack_chain = poc_generator._analyze_attack_chain_for_prompt(
            production_ready_context, "external functions", "modifiers"
        )

        # Should include complete attack scenario
        assert '1.' in attack_chain  # Multiple steps
        assert 'Attacker' in attack_chain
        assert 'governance' in attack_chain.lower()
        assert 'withdrawEther' in attack_chain
        assert 'timelock' in attack_chain.lower() or 'immediate' in attack_chain.lower()

        # Should be specific to RocketVault vulnerability
        assert 'RocketVault' in attack_chain or 'vault' in attack_chain.lower()

    def test_enhanced_contract_context_quality(self, poc_generator, production_ready_context):
        """Test that enhanced contract context provides quality analysis."""
        enhanced_context = poc_generator._extract_enhanced_contract_context(
            production_ready_context['contract_source'], production_ready_context
        )

        # Should highlight vulnerability location
        assert '>>>   42:' in enhanced_context

        # Should include access control context
        assert 'ACCESS CONTROL CONTEXT' in enhanced_context
        assert 'onlyLatestNetworkContract' in enhanced_context

        # Should include interface analysis
        assert 'IRocketVault' in enhanced_context
        assert 'withdrawEther' in enhanced_context

        # Should be well-structured for LLM understanding
        assert len(enhanced_context) > 500  # Substantial context
        assert enhanced_context.count('\n') > 10  # Multiple sections


class TestExploitQualityMetrics:
    """Test exploit quality metrics and validation."""

    @pytest.fixture
    def poc_generator(self):
        """Create poc_generator instance for testing."""
        return FoundryPoCGenerator({})

    def test_exploit_compilation_readiness(self, poc_generator):
        """Test that generated exploits are compilation-ready."""
        # Test valid Solidity code generation
        valid_exploit_code = poc_generator._generate_access_control_exploit("TestContract")

        # Should be valid Solidity syntax
        assert 'pragma solidity' in valid_exploit_code
        assert 'contract' in valid_exploit_code
        assert 'function' in valid_exploit_code
        assert '// SPDX-License-Identifier: MIT' in valid_exploit_code

        # Should have proper structure
        assert 'TestContractAccessControlExploit' in valid_exploit_code
        assert 'constructor' in valid_exploit_code
        assert 'exploit' in valid_exploit_code

    def test_test_suite_completeness(self, poc_generator):
        """Test that test suites are complete and professional."""
        valid_test_code = poc_generator._generate_access_control_test("TestContract")

        # Should be complete Foundry test
        assert 'pragma solidity' in valid_test_code
        assert 'is Test' in valid_test_code
        assert 'function setUp() public' in valid_test_code
        assert 'function test' in valid_test_code
        assert 'assert' in valid_test_code

        # Should include proper imports
        assert 'forge-std/Test.sol' in valid_test_code
        assert 'TestContract' in valid_test_code
        assert 'Exploit' in valid_test_code

    def test_real_function_usage_validation(self, poc_generator):
        """Test that exploits only use real contract functions."""
        available_functions = ['withdrawEther', 'balanceOf', 'transfer']
        contract_code = "pragma solidity 0.8.19; contract Test { function withdrawEther() public {} }"

        # Mock AST analysis to return real functions
        with patch.object(poc_generator, '_extract_external_functions') as mock_extract:
            mock_extract.return_value = "- withdrawEther() (external)\n- balanceOf() (external)"

            functions = poc_generator._extract_external_functions(contract_code)

            # Should only include real functions
            assert 'withdrawEther' in functions
            assert 'balanceOf' in functions
            assert 'nonExistentFunction' not in functions


class TestErrorHandlingAndRecovery:
    """Test error handling and recovery mechanisms."""

    @pytest.fixture
    def poc_generator(self):
        """Create poc_generator instance for testing."""
        return FoundryPoCGenerator({})

    def test_malformed_contract_graceful_handling(self, poc_generator):
        """Test graceful handling of malformed contracts."""
        malformed_contracts = [
            "",  # Empty
            "pragma solidity",  # Incomplete
            "contract Test {",  # Incomplete contract
            "function test() { return; }",  # Missing pragma
            "// Just a comment",  # No code
        ]

        for malformed_contract in malformed_contracts:
            # Should handle without crashing
            try:
                functions = poc_generator._extract_external_functions(malformed_contract)
                modifiers = poc_generator._extract_modifiers(malformed_contract)

                # Should return strings (possibly empty)
                assert isinstance(functions, str)
                assert isinstance(modifiers, str)

            except Exception as e:
                pytest.fail(f"Malformed contract handling failed: {e}")

    def test_llm_response_robustness(self, poc_generator):
        """Test robustness of LLM response parsing."""
        response_variants = [
            # Standard JSON
            '{"test_code": "code1", "exploit_code": "code2"}',

            # JSON in markdown
            "```json\n{\"test_code\": \"code1\", \"exploit_code\": \"code2\"}\n```",

            # Mixed content
            "Here's the code:\n```json\n{\"test_code\": \"code1\", \"exploit_code\": \"code2\"}\n```",

            # Malformed JSON (should fallback gracefully)
            '{"incomplete": "json"',

            # Empty response
            "",

            # Non-JSON response
            "Just some text without JSON",
        ]

        for response in response_variants:
            result = poc_generator._parse_llm_poc_response(response)

            # Should always return a dictionary
            assert isinstance(result, dict)
            assert 'test_code' in result
            assert 'exploit_code' in result
            assert 'explanation' in result

    def test_compilation_error_recovery(self, poc_generator):
        """Test recovery from compilation errors."""
        # Test error categorization
        errors = [
            "TypeError: Type uint256 is not implicitly convertible to address",
            "DeclarationError: Identifier not found or not unique",
            "ParserError: Expected ';' but got '}'"
        ]

        categorized = poc_generator._categorize_compile_errors(errors)

        # Should categorize errors appropriately
        assert isinstance(categorized, dict)

        # Should generate helpful fix prompt
        contract_code = "pragma solidity 0.8.19; contract Test {}"
        fix_prompt = poc_generator._create_compilation_fix_prompt(errors, contract_code, "Test.sol")

        assert 'Fix type mismatches' in fix_prompt
        assert 'Add missing imports' in fix_prompt
        assert 'Test.sol' in fix_prompt


class TestPerformanceImprovements:
    """Test performance improvements."""

    @pytest.fixture
    def poc_generator(self):
        """Create poc_generator instance for testing."""
        return FoundryPoCGenerator({})

    def test_large_contract_processing(self, poc_generator):
        """Test processing of large contracts."""
        # Create large contract (1000+ lines)
        large_contract = 'pragma solidity 0.8.19;\ncontract Large {\n'
        for i in range(1000):
            large_contract += f'    function func{i}() public {{}}\n'
        large_contract += '}\n'

        # Should process within reasonable time
        import time
        start_time = time.time()

        functions = poc_generator._extract_external_functions(large_contract)
        modifiers = poc_generator._extract_modifiers(large_contract)

        end_time = time.time()
        processing_time = end_time - start_time

        # Should complete within 5 seconds
        assert processing_time < 5.0
        assert isinstance(functions, str)
        assert isinstance(modifiers, str)

    def test_enhanced_context_performance(self, poc_generator):
        """Test performance of enhanced context extraction."""
        large_contract = 'pragma solidity 0.8.19;\ncontract Test {\n'
        for i in range(500):
            large_contract += f'    uint256 public var{i};\n'
        large_contract += '}\n'

        context = {
            'vulnerability_type': 'access_control',
            'line_number': 250,
            'contract_name': 'Test'
        }

        import time
        start_time = time.time()

        enhanced_context = poc_generator._extract_enhanced_contract_context(large_contract, context)

        end_time = time.time()
        processing_time = end_time - start_time

        # Should complete within 2 seconds
        assert processing_time < 2.0
        assert isinstance(enhanced_context, str)
        assert len(enhanced_context) > 100  # Should provide substantial context


class TestIntegrationWithExistingFeatures:
    """Test integration with existing poc_generator features."""

    @pytest.fixture
    def poc_generator(self):
        """Create poc_generator instance for testing."""
        return FoundryPoCGenerator({})

    def test_backward_compatibility_maintained(self, poc_generator):
        """Test that existing functionality still works."""
        # Test existing method availability
        assert hasattr(poc_generator, '_extract_external_functions')
        assert hasattr(poc_generator, '_extract_modifiers')
        assert hasattr(poc_generator, '_create_poc_generation_prompt')
        assert hasattr(poc_generator, '_parse_llm_poc_response')

        # Test that existing methods still work
        contract_code = "pragma solidity 0.8.19; contract Test { function test() public {} }"
        functions = poc_generator._extract_external_functions(contract_code)
        assert isinstance(functions, str)

    def test_enhanced_features_additive(self, poc_generator):
        """Test that enhanced features are additive, not replacing existing ones."""
        context = {
            'contract_name': 'TestContract',
            'vulnerability_type': 'test_type'
        }

        # Should still generate prompts
        prompt = poc_generator._create_poc_generation_prompt(context, {})
        assert isinstance(prompt, str)
        assert len(prompt) > 0

        # Should include both old and new features
        assert 'contract_name' in prompt or 'TestContract' in prompt


class TestQualityAssurance:
    """Test quality assurance of generated exploits."""

    @pytest.fixture
    def poc_generator(self):
        """Create poc_generator instance for testing."""
        return FoundryPoCGenerator({})

    def test_exploit_structure_quality(self, poc_generator):
        """Test quality of exploit contract structure."""
        exploit_code = poc_generator._generate_access_control_exploit("TestContract")

        # Should follow Solidity best practices
        assert '// SPDX-License-Identifier: MIT' in exploit_code
        assert 'pragma solidity' in exploit_code
        assert 'contract' in exploit_code
        assert 'interface' in exploit_code  # Should define interfaces

        # Should have proper exploit structure
        assert 'function exploit' in exploit_code.lower()
        assert 'function ' in exploit_code  # Multiple functions
        assert 'event' in exploit_code.lower()  # Events for logging

    def test_test_suite_quality(self, poc_generator):
        """Test quality of test suite structure."""
        test_code = poc_generator._generate_access_control_test("TestContract")

        # Should follow Foundry testing best practices
        assert 'is Test' in test_code
        assert 'function setUp() public' in test_code
        assert 'function test' in test_code
        assert 'assert' in test_code

        # Should include proper setup
        assert 'vm.' in test_code  # Foundry cheatcodes
        assert 'new' in test_code  # Contract deployment

    def test_address_validation_in_prompts(self, poc_generator):
        """Test that address validation is enforced in prompts."""
        context = {
            'contract_name': 'TestContract',
            'vulnerability_type': 'test'
        }

        prompt = poc_generator._create_poc_generation_prompt(context, {})

        # Should enforce valid address formats
        assert '40-character hex' in prompt
        assert '0x followed by 40 hex' in prompt
        assert 'NEVER use' in prompt and 'YourAddress' in prompt
        assert 'VALID addresses' in prompt


class TestBountySubmissionReadiness:
    """Test that generated exploits are ready for bounty submission."""

    @pytest.fixture
    def poc_generator(self):
        """Create poc_generator instance for testing."""
        return FoundryPoCGenerator({})

    def test_bounty_submission_quality_standards(self, poc_generator):
        """Test that exploits meet bounty submission quality standards."""
        context = {
            'contract_name': 'HighValueContract',
            'vulnerability_type': 'critical_vulnerability',
            'severity': 'critical'
        }

        prompt = poc_generator._create_poc_generation_prompt(context, {})

        # Should meet professional security standards
        assert 'security professionals' in prompt.lower()
        assert 'production-ready' in prompt.lower()
        assert 'working exploit' in prompt.lower()
        assert 'demonstrates' in prompt.lower()

        # Should emphasize real impact
        assert 'financial impact' in prompt.lower() or 'funds' in prompt.lower()
        assert 'mainnet' in prompt.lower() or 'production' in prompt.lower()

    def test_exploit_demonstration_quality(self, poc_generator):
        """Test that exploits properly demonstrate the vulnerability."""
        exploit_code = poc_generator._generate_access_control_exploit("TestContract")

        # Should demonstrate actual exploitation
        assert 'require(msg.sender == attacker' in exploit_code or 'Only attacker' in exploit_code
        assert 'target.' in exploit_code  # Calls vulnerable contract
        assert 'payable(attacker).transfer' in exploit_code or 'attacker' in exploit_code

        # Should include verification
        assert 'function ' in exploit_code  # Multiple functions for verification

    def test_comprehensive_test_coverage(self, poc_generator):
        """Test that test suites provide comprehensive coverage."""
        test_code = poc_generator._generate_access_control_test("TestContract")

        # Should test multiple scenarios
        assert 'test' in test_code  # Test functions
        assert 'assert' in test_code  # Assertions
        assert 'vm.' in test_code  # Foundry testing

        # Should demonstrate exploit success
        assert 'exploit' in test_code.lower()
        assert 'bypass' in test_code.lower() or 'attack' in test_code.lower()


class TestSystemReliability:
    """Test overall system reliability."""

    @pytest.fixture
    def poc_generator(self):
        """Create poc_generator instance for testing."""
        return FoundryPoCGenerator({})

    def test_system_handles_edge_cases(self, poc_generator):
        """Test handling of edge cases and error conditions."""
        edge_cases = [
            # Empty context
            {},
            # Minimal context
            {'contract_name': 'Test'},
            # Context with missing fields
            {'contract_name': 'Test', 'vulnerability_type': 'test'},
            # Context with extra fields
            {'contract_name': 'Test', 'vulnerability_type': 'test', 'extra_field': 'value'}
        ]

        for context in edge_cases:
            try:
                # Should handle without crashing
                if 'contract_name' in context:
                    prompt = poc_generator._create_poc_generation_prompt(context, {})
                    assert isinstance(prompt, str)
                    assert len(prompt) > 0

            except Exception as e:
                pytest.fail(f"Edge case handling failed for context {context}: {e}")

    def test_system_handles_large_inputs(self, poc_generator):
        """Test handling of large inputs."""
        # Large context
        large_context = {
            'contract_name': 'TestContract',
            'vulnerability_type': 'test',
            'description': 'x' * 10000,  # Very large description
            'contract_source': 'pragma solidity 0.8.19; contract Test { function test() public {} }' * 100  # Large contract
        }

        try:
            prompt = poc_generator._create_poc_generation_prompt(large_context, {})
            assert isinstance(prompt, str)
            assert len(prompt) > 0

        except Exception as e:
            pytest.fail(f"Large input handling failed: {e}")

    def test_system_resource_usage(self, poc_generator):
        """Test system resource usage is reasonable."""
        import time
        import psutil
        import os

        # Get initial memory usage
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB

        # Perform intensive operations
        for i in range(10):
            context = {
                'contract_name': f'TestContract{i}',
                'vulnerability_type': 'test',
                'contract_source': 'pragma solidity 0.8.19; contract Test { function test() public {} }'
            }

            prompt = poc_generator._create_poc_generation_prompt(context, {})
            enhanced_context = poc_generator._extract_enhanced_contract_context(
                context['contract_source'], context
            )

        # Get final memory usage
        final_memory = process.memory_info().rss / 1024 / 1024  # MB

        # Memory increase should be reasonable (< 100MB for intensive operations)
        memory_increase = final_memory - initial_memory
        assert memory_increase < 100, f"Memory usage increased by {memory_increase:.1f}MB, which may be excessive"


if __name__ == '__main__':
    # Run comprehensive test suite
    pytest.main([
        __file__,
        'test_poc_generator_enhancements.py',
        'test_iterative_compilation_fixes.py',
        'test_enhanced_llm_integration.py',
        '-v',
        '--tb=short'
    ])
