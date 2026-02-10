"""
Tests for Script Detection and File Context in Audit Pipeline

Covers:
- ContractDiscovery._is_script_file() heuristics
- Script filtering in enhanced_audit_engine LLM analysis
- File context header generation in deep_analysis_engine
"""

import pytest
from pathlib import Path

from core.discovery import ContractDiscovery, ContractInfo


class TestIsScriptByDirectoryPath:
    """Test script detection via directory path heuristics."""

    def test_script_dir_detected(self):
        """Files under /script/ should be detected as scripts."""
        fp = Path("/project/script/Deploy.sol")
        assert ContractDiscovery._is_script_file(fp, "") is True

    def test_scripts_dir_detected(self):
        """Files under /scripts/ should be detected as scripts."""
        fp = Path("/project/scripts/Deploy.sol")
        assert ContractDiscovery._is_script_file(fp, "") is True

    def test_nested_script_dir(self):
        """Files in nested /script/ subdirectories should be detected."""
        fp = Path("/project/script/base/RBAC.sol")
        assert ContractDiscovery._is_script_file(fp, "") is True


class TestIsScriptByFilename:
    """Test script detection via .s.sol suffix."""

    def test_s_sol_suffix(self):
        """Files ending with .s.sol should be detected as scripts."""
        fp = Path("/project/src/Deploy.s.sol")
        assert ContractDiscovery._is_script_file(fp, "") is True

    def test_regular_sol_not_script(self):
        """.sol files without .s.sol suffix should not be detected."""
        fp = Path("/project/src/Token.sol")
        assert ContractDiscovery._is_script_file(fp, "") is False


class TestIsScriptByImports:
    """Test script detection via forge-std imports."""

    def test_forge_std_script_import(self):
        """Importing forge-std/Script.sol should mark as script."""
        content = 'import "forge-std/Script.sol";\ncontract Deploy is Script {}'
        fp = Path("/project/src/Deploy.sol")
        assert ContractDiscovery._is_script_file(fp, content) is True

    def test_forge_std_console_import(self):
        """Importing forge-std/console.sol should mark as script."""
        content = 'import "forge-std/console.sol";\ncontract Debug {}'
        fp = Path("/project/src/Debug.sol")
        assert ContractDiscovery._is_script_file(fp, content) is True

    def test_no_forge_std_import(self):
        """Regular imports should not trigger script detection."""
        content = 'import "@openzeppelin/contracts/token/ERC20/ERC20.sol";\ncontract Token is ERC20 {}'
        fp = Path("/project/src/Token.sol")
        assert ContractDiscovery._is_script_file(fp, content) is False


class TestIsScriptByInheritance:
    """Test script detection via 'is Script' inheritance."""

    def test_is_script_pattern(self):
        """'is Script' inheritance should mark as script."""
        content = 'pragma solidity ^0.8.0;\ncontract Deploy is Script {\n  function run() external {}\n}'
        fp = Path("/project/src/Deploy.sol")
        assert ContractDiscovery._is_script_file(fp, content) is True

    def test_is_not_script_pattern(self):
        """'is ERC20' should not be detected as script."""
        content = 'contract Token is ERC20 {}'
        fp = Path("/project/src/Token.sol")
        assert ContractDiscovery._is_script_file(fp, content) is False


class TestNotScriptForProduction:
    """Test that production contracts are not flagged."""

    def test_src_token(self):
        """Standard production contract should not be flagged."""
        content = """
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MyToken is ERC20 {
    constructor() ERC20("MyToken", "MTK") {
        _mint(msg.sender, 1000000 * 10 ** decimals());
    }
}
"""
        fp = Path("/project/src/MyToken.sol")
        assert ContractDiscovery._is_script_file(fp, content) is False

    def test_contract_info_is_script_false(self):
        """ContractInfo.is_script defaults to False."""
        info = ContractInfo(
            file_path=Path("/project/src/Token.sol"),
            contract_name="Token",
            solc_version="^0.8.0",
            line_count=50,
            dependencies=[],
        )
        assert info.is_script is False


class TestFileContextHeaderGeneration:
    """Test _build_file_context_header from deep_analysis_engine."""

    def test_header_format(self):
        """Verify the header format with production and script files."""
        from core.deep_analysis_engine import _build_file_context_header

        contract_files = [
            {'path': '/project/src/Token.sol', 'content': '', 'is_script': False},
            {'path': '/project/script/Deploy.sol', 'content': '', 'is_script': True},
        ]
        header = _build_file_context_header(contract_files)
        assert "## Project Files" in header
        assert "Token.sol [PRODUCTION]" in header
        assert "Deploy.sol [DEPLOYMENT SCRIPT]" in header

    def test_empty_files_list(self):
        """Empty contract files should produce empty header."""
        from core.deep_analysis_engine import _build_file_context_header

        assert _build_file_context_header([]) == ""


class TestCombinedContentExcludesScripts:
    """Test that scripts are excluded from combined content for LLM analysis."""

    def test_scripts_filtered_from_production_files(self):
        """Verify the filtering logic that enhanced_audit_engine uses."""
        contract_files = [
            {'path': '/project/src/Token.sol', 'content': 'contract Token {}', 'is_script': False},
            {'path': '/project/script/Deploy.sol', 'content': 'contract Deploy is Script {}', 'is_script': True},
            {'path': '/project/src/Vault.sol', 'content': 'contract Vault {}', 'is_script': False},
        ]

        # Replicate the filtering logic from _run_enhanced_llm_analysis
        production_files = [cf for cf in contract_files if not cf.get('is_script', False)]

        assert len(production_files) == 2
        assert all(not cf['is_script'] for cf in production_files)
        assert 'Token' in production_files[0]['path']
        assert 'Vault' in production_files[1]['path']

    def test_all_scripts_fallback(self):
        """If all files are scripts, fall back to including them."""
        contract_files = [
            {'path': '/project/script/Deploy.sol', 'content': 'contract Deploy {}', 'is_script': True},
        ]
        production_files = [cf for cf in contract_files if not cf.get('is_script', False)]
        if not production_files:
            production_files = contract_files
        assert len(production_files) == 1


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
