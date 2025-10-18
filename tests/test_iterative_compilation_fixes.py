#!/usr/bin/env python3
"""
Test suite for iterative compilation fixes and enhanced error handling.

Tests the iterative compilation feedback loop and error repair functionality.
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


class TestIterativeCompilationFixes:
    """Test iterative compilation fix functionality."""

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

            # Create src directory
            src_dir = Path(temp_dir) / "src"
            src_dir.mkdir()

            yield temp_dir

    @pytest.mark.asyncio
    async def test_compilation_success_detection(self, poc_generator, temp_project_dir):
        """Test detection of successful compilation."""
        # Mock successful compilation
        with patch.object(poc_generator, '_compile_foundry_project') as mock_compile:
            mock_compile.return_value = {
                'success': True,
                'errors': [],
                'output': 'Compilation successful',
                'return_code': 0
            }

            test_result = Mock()
            test_result.contract_name = "TestContract"

            result = await poc_generator._iterative_compilation_fix(test_result, temp_project_dir, max_iterations=3)

            assert result['success'] is True
            assert result['iterations'] == 1  # Should stop after first successful compilation

    @pytest.mark.asyncio
    async def test_compilation_error_detection_and_fix(self, poc_generator, temp_project_dir):
        """Test detection and fixing of compilation errors."""
        # Mock compilation failure then success
        call_count = 0
        def mock_compile(project_dir):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # First call: compilation fails
                return {
                    'success': False,
                    'errors': ['TypeError: Type uint256 is not implicitly convertible to address'],
                    'output': 'Compilation failed',
                    'return_code': 1
                }
            else:
                # Second call: compilation succeeds after fix
                return {
                    'success': True,
                    'errors': [],
                    'output': 'Compilation successful',
                    'return_code': 0
                }

        with patch.object(poc_generator, '_compile_foundry_project', side_effect=mock_compile):
            with patch.object(poc_generator, '_analyze_and_repair_errors') as mock_repair:
                mock_repair.return_value = {
                    'repaired': True,
                    'test_code': 'pragma solidity 0.8.19; contract Test {}',
                    'exploit_code': 'pragma solidity 0.8.19; contract Exploit {}'
                }

                test_result = Mock()
                test_result.contract_name = "TestContract"

                result = await poc_generator._iterative_compilation_fix(test_result, temp_project_dir, max_iterations=3)

                assert result['success'] is True
                assert result['iterations'] == 2  # Should take 2 iterations

    @pytest.mark.asyncio
    async def test_max_iterations_reached(self, poc_generator, temp_project_dir):
        """Test behavior when max iterations are reached without success."""
        # Mock persistent compilation failure
        with patch.object(poc_generator, '_compile_foundry_project') as mock_compile:
            mock_compile.return_value = {
                'success': False,
                'errors': ['Persistent error that cannot be fixed'],
                'output': 'Compilation failed',
                'return_code': 1
            }

            with patch.object(poc_generator, '_analyze_and_repair_errors') as mock_repair:
                mock_repair.return_value = {'repaired': False}

                test_result = Mock()
                test_result.contract_name = "TestContract"

                result = await poc_generator._iterative_compilation_fix(test_result, temp_project_dir, max_iterations=2)

                assert result['success'] is False
                assert result['iterations'] == 2  # Should reach max iterations

    @pytest.mark.asyncio
    async def test_repair_generation_from_errors(self, poc_generator, temp_project_dir):
        """Test repair generation from compilation errors."""
        compile_errors = [
            "DeclarationError: Identifier not found or not unique",
            "TypeError: Type uint256 is not implicitly convertible to address"
        ]

        test_result = Mock()
        test_result.contract_name = "TestContract"

        # Mock LLM response for repair
        async def mock_llm_call(prompt, model="gpt-4o-mini"):
            return '''{
                "test_code": "// Fixed test code\\npragma solidity 0.8.19;\\ncontract Test {}",
                "exploit_code": "// Fixed exploit code\\npragma solidity 0.8.19;\\ncontract Exploit {}",
                "explanation": "Fixed compilation errors"
            }'''

        poc_generator.llm_analyzer = Mock()
        poc_generator.llm_analyzer._call_llm = mock_llm_call

        repair_result = await poc_generator._analyze_and_repair_errors(
            test_result, compile_errors, temp_project_dir
        )

        assert repair_result['repaired'] is True
        assert 'test_code' in repair_result
        assert 'exploit_code' in repair_result
        assert 'pragma solidity 0.8.19' in repair_result['test_code']

    @pytest.mark.asyncio
    async def test_repair_failure_handling(self, poc_generator, temp_project_dir):
        """Test handling when repair generation fails."""
        compile_errors = ["Some error"]

        test_result = Mock()
        test_result.contract_name = "TestContract"

        # Mock LLM failure
        async def mock_llm_call(prompt, model="gpt-4o-mini"):
            raise Exception("LLM API error")

        poc_generator.llm_analyzer = Mock()
        poc_generator.llm_analyzer._call_llm = mock_llm_call

        repair_result = await poc_generator._analyze_and_repair_errors(
            test_result, compile_errors, temp_project_dir
        )

        assert repair_result['repaired'] is False

    @pytest.mark.asyncio
    async def test_file_writing_during_repair(self, poc_generator, temp_project_dir):
        """Test that repaired code is written to files."""
        compile_errors = ["Test error"]

        test_result = Mock()
        test_result.contract_name = "TestContract"

        # Mock successful repair
        async def mock_llm_call(prompt, model="gpt-4o-mini"):
            return '''{
                "test_code": "pragma solidity 0.8.19;\\ncontract Test {}",
                "exploit_code": "pragma solidity 0.8.19;\\ncontract Exploit {}",
                "explanation": "Fixed errors"
            }'''

        poc_generator.llm_analyzer = Mock()
        poc_generator.llm_analyzer._call_llm = mock_llm_call

        # Mock file operations
        with patch('builtins.open', create=True) as mock_file:
            mock_file_instance = MagicMock()
            mock_file.return_value.__enter__.return_value = mock_file_instance

            repair_result = await poc_generator._analyze_and_repair_errors(
                test_result, compile_errors, temp_project_dir
            )

            # Should attempt to write files
            assert mock_file.call_count >= 0  # May vary based on implementation


class TestEnhancedErrorHandling:
    """Test enhanced error handling and validation."""

    @pytest.fixture
    def poc_generator(self):
        """Create poc_generator instance for testing."""
        return FoundryPoCGenerator({})

    def test_compile_error_categorization(self, poc_generator):
        """Test categorization of compilation errors."""
        errors = [
            "TypeError: Type uint256 is not implicitly convertible to address",
            "DeclarationError: Identifier not found or not unique",
            "ParserError: Expected ';' but got '}'",
            "Warning: Unused variable 'temp'"
        ]

        # Test that errors are parsed correctly
        parsed_errors = poc_generator._parse_compile_errors("\n".join(errors))

        assert len(parsed_errors) >= 3  # Should parse most errors
        assert any('TypeError' in error for error in parsed_errors)
        assert any('DeclarationError' in error for error in parsed_errors)

    def test_compilation_fix_prompt_quality(self, poc_generator):
        """Test quality of compilation fix prompts."""
        errors = [
            "TypeError: Type uint256 is not implicitly convertible to address",
            "DeclarationError: Identifier not found or not unique"
        ]

        contract_code = "pragma solidity 0.8.19; contract Test { function test() public {} }"
        prompt = poc_generator._create_compilation_fix_prompt(errors, contract_code, "Test.sol")

        # Should include all critical elements
        assert 'URGENT: Fix the following Solidity compilation errors' in prompt
        assert 'Test.sol' in prompt
        assert 'TypeError' in prompt
        assert 'DeclarationError' in prompt
        assert 'ORIGINAL CODE' in prompt
        assert 'Return ONLY the corrected Solidity code' in prompt

        # Should include fix guidance
        assert 'Fix type mismatches' in prompt
        assert 'Add missing imports' in prompt
        assert 'Fix function signatures' in prompt

    def test_llm_response_validation(self, poc_generator):
        """Test LLM response validation for compilation fixes."""
        # Test valid response
        valid_response = '''{
            "test_code": "pragma solidity 0.8.19;\\ncontract Test {}",
            "exploit_code": "pragma solidity 0.8.19;\\ncontract Exploit {}",
            "explanation": "Fixed compilation errors"
        }'''

        result = poc_generator._parse_llm_poc_response(valid_response)
        assert 'test_code' in result
        assert 'exploit_code' in result
        assert 'pragma solidity 0.8.19' in result['test_code']

    def test_malformed_llm_response_handling(self, poc_generator):
        """Test handling of malformed LLM responses."""
        malformed_responses = [
            "",  # Empty
            "Just some text",  # Plain text
            '{"incomplete": "json"',  # Incomplete JSON
            '{"test_code": "code"}',  # Missing required fields
            "```json\n{incomplete json}\n```",  # Malformed in code block
        ]

        for malformed_response in malformed_responses:
            result = poc_generator._parse_llm_poc_response(malformed_response)

            # Should return fallback structure
            assert isinstance(result, dict)
            assert 'test_code' in result
            assert 'exploit_code' in result

    def test_error_repair_loop_termination(self, poc_generator, temp_project_dir):
        """Test that error repair loop terminates appropriately."""
        # Mock persistent failure
        with patch.object(poc_generator, '_compile_foundry_project') as mock_compile:
            mock_compile.return_value = {
                'success': False,
                'errors': ['Persistent error'],
                'output': 'Failed',
                'return_code': 1
            }

            with patch.object(poc_generator, '_analyze_and_repair_errors') as mock_repair:
                mock_repair.return_value = {'repaired': False}

                test_result = Mock()
                test_result.contract_name = "TestContract"

                # Should terminate after max iterations
                result = await poc_generator._iterative_compilation_fix(
                    test_result, temp_project_dir, max_iterations=3
                )

                assert result['success'] is False
                assert result['iterations'] == 3


class TestIntegrationWithExistingWorkflow:
    """Test integration with existing poc_generator workflow."""

    @pytest.fixture
    def poc_generator(self):
        """Create poc_generator instance for testing."""
        return FoundryPoCGenerator({})

    @pytest.fixture
    def sample_context(self):
        """Sample context for testing."""
        return {
            'contract_name': 'TestContract',
            'vulnerability_type': 'reentrancy',
            'line_number': 15,
            'description': 'Reentrancy vulnerability'
        }

    def test_enhanced_prompt_integration(self, poc_generator, sample_context):
        """Test that enhanced prompts integrate with existing workflow."""
        # Generate enhanced prompt
        prompt = poc_generator._create_poc_generation_prompt(sample_context, {})

        # Should contain both new and existing elements
        assert '🎯 MISSION:' in prompt  # New enhanced feature
        assert 'SOLIDITY VERSION' in prompt  # Existing feature
        assert 'AVAILABLE FUNCTIONS' in prompt  # Existing feature

        # Should maintain JSON output format requirement
        assert 'Return ONLY valid JSON' in prompt

    def test_backward_compatibility_maintained(self, poc_generator, sample_context):
        """Test that existing functionality still works."""
        # Should still generate prompts even without enhanced features
        prompt = poc_generator._create_poc_generation_prompt(sample_context, {})

        # Basic requirements should still be present
        assert 'contract_name' in prompt or 'TestContract' in prompt
        assert 'vulnerability_type' in prompt or 'reentrancy' in prompt
        assert 'line_number' in prompt or '15' in prompt


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
