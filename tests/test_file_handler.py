"""
Tests for file handling utilities.
"""

import pytest
from pathlib import Path

from utils.file_handler import FileHandler


class TestFileHandler:
    """Test cases for FileHandler."""

    def setup_method(self):
        """Set up test fixtures."""
        self.file_handler = FileHandler()

    def test_read_solidity_file(self):
        """Test reading a valid Solidity file."""
        # Create a temporary Solidity file
        test_content = '''
pragma solidity ^0.8.0;

contract TestContract {
    uint256 public value;

    constructor(uint256 _value) {
        value = _value;
    }
}
'''
        test_file = Path("test_contract.sol")
        test_file.write_text(test_content)

        try:
            files_data = self.file_handler.read_contract_files(str(test_file))

            assert len(files_data) == 1
            assert files_data[0][0] == str(test_file)
            assert test_content.strip() in files_data[0][1]

        finally:
            test_file.unlink()

    def test_read_nonexistent_file(self):
        """Test reading a nonexistent file."""
        with pytest.raises(FileNotFoundError):
            self.file_handler.read_contract_files("nonexistent.sol")

    def test_read_directory_with_solidity_files(self):
        """Test reading a directory containing Solidity files."""
        # Create temporary directory with Solidity files
        test_dir = Path("test_contracts")
        test_dir.mkdir()

        contract1_content = '''
pragma solidity ^0.8.0;
contract Contract1 {
    uint256 public value;
}
'''
        contract2_content = '''
pragma solidity ^0.8.0;
contract Contract2 {
    string public name;
}
'''

        (test_dir / "Contract1.sol").write_text(contract1_content)
        (test_dir / "Contract2.sol").write_text(contract2_content)

        try:
            files_data = self.file_handler.read_contract_files(str(test_dir))

            assert len(files_data) == 2
            # Check that both files are found (order may vary)
            file_names = [Path(f[0]).name for f in files_data]
            assert "Contract1.sol" in file_names
            assert "Contract2.sol" in file_names

        finally:
            # Clean up
            for file in test_dir.glob("*.sol"):
                file.unlink()
            test_dir.rmdir()

    def test_extract_line_metadata(self):
        """Test extracting metadata for specific lines."""
        content = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TestContract {
    uint256 public value;

    function setValue(uint256 _value) public {
        value = _value;
    }
}'''

        metadata = self.file_handler.extract_line_metadata(content, 5)  # Line with "contract TestContract"

        assert metadata['line_number'] == 5
        assert metadata['line_content'] == "contract TestContract {"
        assert not metadata['is_comment']
        assert not metadata['is_empty']

    def test_find_function_at_line(self):
        """Test finding function that contains a specific line."""
        content = '''
contract TestContract {
    function testFunction() public {
        uint256 value = 42;
        // This is line 5
        return value;
    }
}'''

        function_info = self.file_handler.find_function_at_line(content, 5)

        assert function_info['function_name'] == 'testFunction'
        assert function_info['start_line'] == 3
        assert 5 in function_info['line_range']

    def test_get_contract_imports(self):
        """Test extracting import statements."""
        content = '''
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract TestContract {
    // Contract code here
}
'''

        imports = self.file_handler.get_contract_imports(content)

        assert len(imports) == 2
        assert imports[0]['type'] == 'direct'
        assert imports[0]['from'] == '@openzeppelin/contracts/token/ERC20/ERC20.sol'
        assert imports[1]['type'] == 'named'
        assert imports[1]['symbols'] == 'Ownable'

    def test_calculate_file_metrics(self):
        """Test calculating file metrics."""
        content = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// This is a comment
contract TestContract {
    uint256 public value; // Another comment

    function test() public {
        // Function code
        value = 42;
    }
}'''

        metrics = self.file_handler.calculate_file_metrics(content)

        assert metrics['total_lines'] == 14
        assert metrics['code_lines'] >= 6  # Contract, function, assignments, etc.
        assert metrics['comment_lines'] >= 2  # Two comment lines
        assert metrics['comment_ratio'] > 0
        assert metrics['code_ratio'] > 0
