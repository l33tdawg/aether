#!/usr/bin/env python3
"""
Comprehensive test suite for enhanced poc_generator features.

Tests all the new features added to the poc_generator:
- AST-based contract analysis
- Enhanced LLM prompts with attack chain analysis
- Compilation feedback loop with iterative refinement
- Enhanced contract context extraction
- Improved error handling and validation
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


class TestASTBasedContractAnalysis:
    """Test AST-based contract analysis functionality."""

    @pytest.fixture
    def poc_generator(self):
        """Create poc_generator instance for testing."""
        return FoundryPoCGenerator({})

    @pytest.fixture
    def sample_contract(self):
        """Sample contract for testing AST analysis."""
        return '''
pragma solidity 0.7.6;

interface IRocketVault {
    function withdrawEther(uint256 _amount) external;
    function balanceOf(string memory _networkContractName) external view returns (uint256);
}

contract RocketVault {
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
'''

    def test_ast_analysis_fallback_to_regex(self, poc_generator, sample_contract):
        """Test that AST analysis falls back to regex when Slither not available."""
        # Mock Slither as unavailable
        with patch('core.foundry_poc_generator.AST_ANALYSIS_AVAILABLE', False):
            functions = poc_generator._extract_external_functions(sample_contract)

            # Should still extract functions using regex fallback
            assert isinstance(functions, str)
            assert 'withdrawEther' in functions
            assert 'balanceOf' in functions

    def test_external_function_extraction(self, poc_generator, sample_contract):
        """Test external function extraction from contract."""
        functions = poc_generator._extract_external_functions(sample_contract)

        assert isinstance(functions, str)
        assert 'withdrawEther' in functions
        assert 'balanceOf' in functions
        assert 'external' in functions or 'public' in functions

    def test_modifier_extraction(self, poc_generator, sample_contract):
        """Test modifier extraction from contract."""
        modifiers = poc_generator._extract_modifiers(sample_contract)

        assert isinstance(modifiers, str)
        assert 'onlyLatestNetworkContract' in modifiers

    def test_enhanced_contract_context_extraction(self, poc_generator, sample_contract):
        """Test enhanced contract context extraction based on vulnerability type."""
        context = {
            'contract_name': 'RocketVault',
            'vulnerability_type': 'access_control',
            'line_number': 15,
            'description': 'Access control bypass in withdrawEther function'
        }

        enhanced_context = poc_generator._extract_enhanced_contract_context(sample_contract, context)

        assert isinstance(enhanced_context, str)
        assert '>>>   15:' in enhanced_context  # Vulnerability line marker
        assert 'ACCESS CONTROL CONTEXT' in enhanced_context
        assert 'IRocketVault' in enhanced_context

    def test_attack_chain_analysis_for_prompt(self, poc_generator, sample_contract):
        """Test attack chain analysis for different vulnerability types."""
        # Test access control attack chain
        context = {
            'contract_name': 'RocketVault',
            'vulnerability_type': 'access_control',
            'available_functions': ['withdrawEther', 'balanceOf']
        }

        attack_chain = poc_generator._analyze_attack_chain_for_prompt(
            context, "external functions", "modifiers"
        )

        assert isinstance(attack_chain, str)
        assert 'ATTACK CHAIN' in attack_chain
        assert 'Access Control Bypass' in attack_chain
        assert 'withdrawEther' in attack_chain


class TestEnhancedLLMPrompts:
    """Test enhanced LLM prompt generation."""

    @pytest.fixture
    def poc_generator(self):
        """Create poc_generator instance for testing."""
        return FoundryPoCGenerator({})

    @pytest.fixture
    def sample_context(self):
        """Sample context for prompt generation."""
        return {
            'contract_name': 'TestContract',
            'vulnerability_type': 'access_control',
            'vulnerability_class': 'Access Control',
            'severity': 'high',
            'line_number': 42,
            'entrypoint': 'withdrawEther',
            'description': 'Access control bypass vulnerability',
            'contract_source': 'pragma solidity 0.8.0; contract Test { function withdrawEther() public {} }',
            'solc_version': '0.8.19',
            'available_functions': ['withdrawEther', 'balanceOf']
        }

    def test_enhanced_prompt_generation(self, poc_generator, sample_context):
        """Test that enhanced prompts are generated correctly."""
        prompt = poc_generator._create_poc_generation_prompt(sample_context, {})

        # Check for enhanced prompt features
        assert '🎯 MISSION:' in prompt
        assert '$100k+ bounty' in prompt
        assert 'ATTACK CHAIN ANALYSIS' in prompt
        assert 'TARGET FUNCTIONS' in prompt
        assert 'PRODUCTION-READY' in prompt
        assert 'BOUNTY IMPACT' in prompt

        # Check for critical requirements
        assert 'SOLIDITY VERSION' in prompt
        assert 'REAL FUNCTIONS ONLY' in prompt
        assert 'VALID ADDRESSES' in prompt
        assert 'NO PLACEHOLDERS' in prompt

        # Check for quality checklist
        assert 'EXPLOIT QUALITY CHECKLIST' in prompt
        assert 'ATTACK EXECUTION PATTERN' in prompt

    def test_attack_chain_inclusion_in_prompt(self, poc_generator, sample_context):
        """Test that attack chain analysis is included in prompts."""
        prompt = poc_generator._create_poc_generation_prompt(sample_context, {})

        # Should include attack chain for access control
        assert 'Access Control Bypass' in prompt
        assert 'withdrawEther' in prompt  # Available function
        assert 'governance' in prompt.lower()  # Attack vector

    def test_compilation_fix_prompt_generation(self, poc_generator):
        """Test compilation fix prompt generation."""
        errors = [
            "DeclarationError: Identifier not found or not unique",
            "TypeError: Type uint256 is not implicitly convertible to address"
        ]

        contract_code = "pragma solidity 0.8.19; contract Test {}"
        prompt = poc_generator._create_compilation_fix_prompt(errors, contract_code, "Test.sol")

        assert 'URGENT: Fix the following Solidity compilation errors' in prompt
        assert 'DeclarationError' in prompt
        assert 'TypeError' in prompt
        assert 'Test.sol' in prompt
        assert 'ORIGINAL CODE' in prompt
        assert 'Return ONLY the corrected Solidity code' in prompt


class TestCompilationFeedbackLoop:
    """Test compilation feedback loop functionality."""

    @pytest.fixture
    def poc_generator(self):
        """Create poc_generator instance for testing."""
        return FoundryPoCGenerator({})

    @pytest.fixture
    def temp_project_dir(self):
        """Create temporary project directory for testing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create foundry.toml
            foundry_toml = Path(temp_dir) / "foundry.toml"
            foundry_toml.write_text("""
[profile.default]
src = "src"
out = "out"
libs = ["lib"]
solc_version = "0.8.19"
            """)

            # Create lib directory
            lib_dir = Path(temp_dir) / "lib"
            lib_dir.mkdir()

            yield temp_dir

    @pytest.mark.asyncio
    async def test_compilation_result_parsing(self, poc_generator, temp_project_dir):
        """Test parsing of compilation results."""
        compile_result = await poc_generator._compile_foundry_project(temp_project_dir)

        # Should return a dictionary with expected keys
        assert isinstance(compile_result, dict)
        assert 'success' in compile_result
        assert 'errors' in compile_result
        assert 'output' in compile_result
        assert 'return_code' in compile_result

    @pytest.mark.asyncio
    async def test_iterative_compilation_fix(self, poc_generator, temp_project_dir):
        """Test iterative compilation fix functionality."""
        # Create test result
        test_result = Mock()
        test_result.contract_name = "TestContract"

        # Test iterative compilation fix
        result = await poc_generator._iterative_compilation_fix(test_result, temp_project_dir, max_iterations=2)

        assert isinstance(result, dict)
        assert 'success' in result
        assert 'iterations' in result
        assert 'final_result' in result

    @pytest.mark.asyncio
    async def test_error_repair_analysis(self, poc_generator, temp_project_dir):
        """Test error repair analysis functionality."""
        test_result = Mock()
        test_result.contract_name = "TestContract"

        compile_errors = [
            "TypeError: Member 'nonExistentFunction' not found",
            "DeclarationError: Undeclared identifier 'undefinedVariable'"
        ]

        # Test error repair
        repair_result = await poc_generator._analyze_and_repair_errors(
            test_result, compile_errors, temp_project_dir
        )

        assert isinstance(repair_result, dict)
        assert 'repaired' in repair_result


class TestEnhancedContractContext:
    """Test enhanced contract context extraction."""

    @pytest.fixture
    def poc_generator(self):
        """Create poc_generator instance for testing."""
        return FoundryPoCGenerator({})

    @pytest.fixture
    def complex_contract(self):
        """Complex contract for testing context extraction."""
        return '''
pragma solidity 0.8.19;

import "@openzeppelin/contracts/access/Ownable.sol";

interface IOracle {
    function getPrice() external view returns (uint256);
    function updatePrice(uint256 price) external;
}

contract DeFiProtocol is Ownable {
    IOracle public oracle;
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    modifier onlyOracle() {
        require(msg.sender == address(oracle), "Only oracle");
        _;
    }

    function deposit(uint256 amount) external {
        balances[msg.sender] += amount;
        totalSupply += amount;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        totalSupply -= amount;
        payable(msg.sender).transfer(amount); // Potential reentrancy
    }

    function updateOraclePrice(uint256 newPrice) external onlyOracle {
        // Oracle manipulation vulnerability
        oracle.updatePrice(newPrice);
    }

    function flashLoan(uint256 amount) external {
        require(amount > 0, "Invalid amount");
        // Flash loan logic
    }
}
'''

    def test_access_control_context_extraction(self, poc_generator, complex_contract):
        """Test access control context extraction."""
        context = {
            'vulnerability_type': 'access_control',
            'line_number': 45,  # Line with onlyOracle modifier
            'contract_name': 'DeFiProtocol'
        }

        enhanced_context = poc_generator._extract_enhanced_contract_context(complex_contract, context)

        assert 'ACCESS CONTROL CONTEXT' in enhanced_context
        assert 'onlyOracle' in enhanced_context

    def test_reentrancy_context_extraction(self, poc_generator, complex_contract):
        """Test reentrancy context extraction."""
        context = {
            'vulnerability_type': 'reentrancy',
            'line_number': 35,  # Line with withdraw function
            'contract_name': 'DeFiProtocol'
        }

        enhanced_context = poc_generator._extract_enhanced_contract_context(complex_contract, context)

        assert 'REENTRANCY CONTEXT' in enhanced_context
        assert 'External call' in enhanced_context or 'transfer' in enhanced_context

    def test_oracle_context_extraction(self, poc_generator, complex_contract):
        """Test oracle context extraction."""
        context = {
            'vulnerability_type': 'oracle',
            'line_number': 40,  # Line with updateOraclePrice function
            'contract_name': 'DeFiProtocol'
        }

        enhanced_context = poc_generator._extract_enhanced_contract_context(complex_contract, context)

        assert 'ORACLE CONTEXT' in enhanced_context
        assert 'price' in enhanced_context.lower()


class TestVulnerabilitySpecificAnalysis:
    """Test vulnerability-specific analysis and prompts."""

    @pytest.fixture
    def poc_generator(self):
        """Create poc_generator instance for testing."""
        return FoundryPoCGenerator({})

    def test_access_control_attack_chain(self, poc_generator):
        """Test access control attack chain generation."""
        context = {
            'contract_name': 'TestContract',
            'vulnerability_type': 'access_control'
        }

        attack_chain = poc_generator._analyze_attack_chain_for_prompt(
            context, "functions", "modifiers"
        )

        assert 'Access Control Bypass' in attack_chain
        assert 'governance' in attack_chain.lower()
        assert 'withdrawEther' in attack_chain or 'withdraw' in attack_chain

    def test_reentrancy_attack_chain(self, poc_generator):
        """Test reentrancy attack chain generation."""
        context = {
            'contract_name': 'TestContract',
            'vulnerability_type': 'reentrancy'
        }

        attack_chain = poc_generator._analyze_attack_chain_for_prompt(
            context, "functions", "modifiers"
        )

        assert 'Reentrancy Attack' in attack_chain
        assert 'external call' in attack_chain.lower()
        assert 'state change' in attack_chain.lower()

    def test_oracle_attack_chain(self, poc_generator):
        """Test oracle attack chain generation."""
        context = {
            'contract_name': 'TestContract',
            'vulnerability_type': 'oracle'
        }

        attack_chain = poc_generator._analyze_attack_chain_for_prompt(
            context, "functions", "modifiers"
        )

        assert 'Oracle Manipulation' in attack_chain
        assert 'price' in attack_chain.lower()
        assert 'dependent' in attack_chain.lower()


class TestErrorHandlingAndValidation:
    """Test error handling and validation improvements."""

    @pytest.fixture
    def poc_generator(self):
        """Create poc_generator instance for testing."""
        return FoundryPoCGenerator({})

    def test_compile_error_parsing(self, poc_generator):
        """Test compilation error parsing."""
        compiler_output = """
error[1234]: TypeError: Type uint256 is not implicitly convertible to address
  --> Test.sol:42:10:
   |
42 |     address target = amount;
   |          ^^^^^^^

error[5678]: DeclarationError: Identifier not found or not unique
  --> Test.sol:45:5:
   |
45 |     undefinedFunction();
   |     ^^^^^^^^^^^^^^^^^^
        """

        errors = poc_generator._parse_compile_errors(compiler_output)

        assert len(errors) == 2
        assert 'TypeError' in errors[0]
        assert 'DeclarationError' in errors[1]
        assert 'uint256' in errors[0]
        assert 'undefinedFunction' in errors[1]

    def test_invalid_json_response_handling(self, poc_generator):
        """Test handling of invalid JSON responses from LLM."""
        # Test with malformed JSON
        malformed_response = '{"test_code": "pragma solidity 0.8.19", "exploit_code": }'

        result = poc_generator._parse_llm_poc_response(malformed_response)

        # Should return fallback structure
        assert isinstance(result, dict)
        assert 'test_code' in result
        assert 'exploit_code' in result

    def test_empty_response_handling(self, poc_generator):
        """Test handling of empty responses."""
        result = poc_generator._parse_llm_poc_response("")

        assert isinstance(result, dict)
        assert result['test_code'] == ""
        assert result['exploit_code'] == ""


class TestIntegrationWithEnhancedFeatures:
    """Test integration of all enhanced features."""

    @pytest.fixture
    def poc_generator(self):
        """Create poc_generator instance for testing."""
        return FoundryPoCGenerator({})

    @pytest.fixture
    def sample_contract(self):
        """Sample contract for integration testing."""
        return '''
pragma solidity 0.8.19;

interface IVulnerable {
    function withdraw(uint256 amount) external;
    function deposit(uint256 amount) external;
}

contract VulnerableContract {
    mapping(address => uint256) public balances;

    function deposit(uint256 amount) external payable {
        balances[msg.sender] += amount;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount); // Reentrancy vulnerability
    }
}
'''

    @pytest.mark.asyncio
    async def test_full_poc_generation_pipeline(self, poc_generator, sample_contract):
        """Test the complete PoC generation pipeline with all enhancements."""
        # Mock the LLM call to return valid response
        async def mock_llm_call(prompt, model="gpt-4o-mini"):
            return '''{
                "test_code": "// SPDX-License-Identifier: MIT\\npragma solidity 0.8.19;\\n\\nimport \\"forge-std/Test.sol\\";\\n\\ncontract TestContract is Test {\\n    function testExploit() public {\\n        assertTrue(true);\\n    }\\n}",
                "exploit_code": "// SPDX-License-Identifier: MIT\\npragma solidity 0.8.19;\\n\\ncontract ExploitContract {\\n    function exploit() external {\\n        // Exploit logic\\n    }\\n}",
                "explanation": "Demonstrates the vulnerability exploitation"
            }'''

        # Patch the LLM call
        poc_generator.llm_analyzer = Mock()
        poc_generator.llm_analyzer._call_llm = mock_llm_call

        # Test context for generation
        context = {
            'contract_name': 'VulnerableContract',
            'vulnerability_type': 'reentrancy',
            'line_number': 15,
            'description': 'Reentrancy vulnerability in withdraw function'
        }

        # Generate PoC (this would normally be async)
        try:
            # This is a simplified test since the full pipeline is complex
            # Just test that the enhanced prompt generation works
            prompt = poc_generator._create_poc_generation_prompt(context, {})

            # Should generate enhanced prompt
            assert '🎯 MISSION:' in prompt
            assert 'ATTACK CHAIN' in prompt
            assert '0.8.19' in prompt  # Solidity version

        except Exception as e:
            pytest.fail(f"Enhanced PoC generation pipeline failed: {e}")

    def test_enhanced_prompt_quality_metrics(self, poc_generator):
        """Test that enhanced prompts meet quality metrics."""
        context = {
            'contract_name': 'TestContract',
            'vulnerability_type': 'access_control',
            'description': 'Test vulnerability'
        }

        prompt = poc_generator._create_poc_generation_prompt(context, {})

        # Check for quality indicators
        quality_metrics = {
            'has_mission_statement': '🎯 MISSION:' in prompt,
            'has_bounty_impact': '$100k+' in prompt,
            'has_attack_chain': 'ATTACK CHAIN' in prompt,
            'has_requirements': 'REQUIREMENTS' in prompt,
            'has_quality_checklist': 'QUALITY CHECKLIST' in prompt,
            'has_address_validation': '40-character hex' in prompt,
            'has_version_specification': 'pragma solidity 0.8.19' in prompt
        }

        # All quality metrics should pass
        for metric, passed in quality_metrics.items():
            assert passed, f"Quality metric failed: {metric}"


class TestPerformanceAndReliability:
    """Test performance and reliability of enhanced features."""

    @pytest.fixture
    def poc_generator(self):
        """Create poc_generator instance for testing."""
        return FoundryPoCGenerator({})

    def test_large_contract_handling(self, poc_generator):
        """Test handling of large contracts."""
        # Create large contract
        large_contract = 'pragma solidity 0.8.19;\ncontract Large {\n'
        for i in range(1000):
            large_contract += f'    uint256 public var{i};\n'
        large_contract += '}\n'

        # Should handle without crashing
        try:
            functions = poc_generator._extract_external_functions(large_contract)
            assert isinstance(functions, str)

            modifiers = poc_generator._extract_modifiers(large_contract)
            assert isinstance(modifiers, str)

        except Exception as e:
            pytest.fail(f"Large contract handling failed: {e}")

    def test_malformed_contract_handling(self, poc_generator):
        """Test handling of malformed contracts."""
        malformed_contracts = [
            "",  # Empty
            "pragma solidity",  # Incomplete pragma
            "contract Test {",  # Incomplete contract
            "function test() {",  # Incomplete function
        ]

        for malformed_contract in malformed_contracts:
            try:
                functions = poc_generator._extract_external_functions(malformed_contract)
                modifiers = poc_generator._extract_modifiers(malformed_contract)

                # Should return strings (possibly empty) without crashing
                assert isinstance(functions, str)
                assert isinstance(modifiers, str)

            except Exception as e:
                pytest.fail(f"Malformed contract handling failed for '{malformed_contract[:50]}...': {e}")

    def test_context_extraction_performance(self, poc_generator):
        """Test performance of enhanced context extraction."""
        large_contract = 'pragma solidity 0.8.19;\ncontract Test {\n'
        for i in range(500):
            large_contract += f'    function func{i}() public {{}}\n'
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

        # Should complete within reasonable time (< 1 second for 500-line contract)
        assert processing_time < 1.0
        assert isinstance(enhanced_context, str)
        assert len(enhanced_context) > 0


class TestBackwardCompatibility:
    """Test backward compatibility of enhanced features."""

    @pytest.fixture
    def poc_generator(self):
        """Create poc_generator instance for testing."""
        return FoundryPoCGenerator({})

    def test_fallback_to_regex_when_ast_unavailable(self, poc_generator):
        """Test that regex fallback works when AST unavailable."""
        contract_code = '''
pragma solidity 0.8.19;

contract TestContract {
    function externalFunction() external {}
    function publicFunction() public {}
    function privateFunction() private {}

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }
}
'''

        # Mock AST as unavailable
        with patch('core.foundry_poc_generator.AST_ANALYSIS_AVAILABLE', False):
            functions = poc_generator._extract_external_functions(contract_code)
            modifiers = poc_generator._extract_modifiers(contract_code)

            # Should still work with regex fallback
            assert isinstance(functions, str)
            assert isinstance(modifiers, str)

            # Should find external and public functions
            assert 'externalFunction' in functions
            assert 'publicFunction' in functions
            assert 'onlyOwner' in modifiers


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
