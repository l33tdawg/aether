"""
File handling utilities for smart contract analysis.
"""

import os
import re
from pathlib import Path
from typing import Dict, List, Tuple, Union


class FileHandler:
    """Handle reading and processing of smart contract files."""

    # Common Solidity file extensions
    SOLIDITY_EXTENSIONS = {'.sol'}

    def __init__(self):
        self.solidity_patterns = [
            re.compile(r'pragma\s+solidity\s+[^;]+;', re.IGNORECASE),
            re.compile(r'contract\s+\w+', re.IGNORECASE),
            re.compile(r'interface\s+\w+', re.IGNORECASE),
            re.compile(r'library\s+\w+', re.IGNORECASE),
        ]

    def read_contract_files(self, path: Union[str, Path]) -> List[Tuple[str, str]]:
        """
        Read Solidity contract files from a path (file or directory).

        Args:
            path: Path to file or directory containing Solidity files

        Returns:
            List of tuples (file_path, file_content)
        """
        target_path = Path(path)

        if not target_path.exists():
            raise FileNotFoundError(f"Path does not exist: {path}")

        files_data = []

        if target_path.is_file():
            if self._is_solidity_file(target_path):
                content = self._read_file_with_encoding(target_path)
                if self._is_valid_solidity(content):
                    files_data.append((str(target_path), content))
                else:
                    print(f"⚠️  Warning: {target_path} doesn't appear to be a valid Solidity file")
            else:
                raise ValueError(f"File is not a Solidity file: {path}")

        elif target_path.is_dir():
            # Recursively find all Solidity files
            for sol_file in target_path.rglob("*.sol"):
                if sol_file.is_file():
                    content = self._read_file_with_encoding(sol_file)
                    if self._is_valid_solidity(content):
                        files_data.append((str(sol_file), content))
                    else:
                        print(f"⚠️  Warning: {sol_file} doesn't appear to be a valid Solidity file")

        if not files_data:
            raise FileNotFoundError(f"No valid Solidity files found in: {path}")

        return files_data

    def _is_solidity_file(self, file_path: Path) -> bool:
        """Check if file has Solidity extension."""
        return file_path.suffix.lower() in self.SOLIDITY_EXTENSIONS

    def _read_file_with_encoding(self, file_path: Path) -> str:
        """Read file with multiple encoding attempts."""
        encodings = ['utf-8', 'utf-8-sig', 'latin-1', 'cp1252']

        for encoding in encodings:
            try:
                with open(file_path, 'r', encoding=encoding) as f:
                    return f.read()
            except UnicodeDecodeError:
                continue
            except Exception as e:
                raise IOError(f"Error reading file {file_path}: {e}")

        raise UnicodeDecodeError("utf-8", b"", 0, 0, "Unable to decode file with any supported encoding")

    def _is_valid_solidity(self, content: str) -> bool:
        """Check if file content appears to be valid Solidity."""
        # Check for Solidity pragma or contract declarations
        content_lower = content.lower()

        # Must have at least one Solidity indicator
        has_solidity_indicators = any(
            pattern.search(content) for pattern in self.solidity_patterns
        )

        # Should not be empty or too short
        is_not_empty = bool(content.strip())
        is_not_too_short = len(content.strip()) > 50

        return has_solidity_indicators and is_not_empty and is_not_too_short

    def extract_line_metadata(self, content: str, line_number: int) -> Dict[str, Union[str, int]]:
        """Extract metadata for a specific line in the contract."""
        lines = content.split('\n')

        if 1 <= line_number <= len(lines):
            target_line = lines[line_number - 1]  # Convert to 0-based index

            return {
                'line_number': line_number,
                'line_content': target_line.strip(),
                'line_length': len(target_line),
                'indentation_level': len(target_line) - len(target_line.lstrip()),
                'is_comment': target_line.strip().startswith('//') or '/*' in target_line[:10],
                'is_empty': not target_line.strip(),
            }
        else:
            return {
                'line_number': line_number,
                'error': 'Line number out of range'
            }

    def find_function_at_line(self, content: str, line_number: int) -> Dict[str, Union[str, int, List[int]]]:
        """Find function definition that contains the given line."""
        lines = content.split('\n')

        if not (1 <= line_number <= len(lines)):
            return {'error': 'Line number out of range'}

        # Look backwards for function definition
        current_line = line_number - 1  # Convert to 0-based

        # Find the function this line belongs to
        function_start = None
        brace_count = 0
        in_function = False

        for i in range(current_line, -1, -1):
            line = lines[i].strip()

            # Count braces to track function boundaries
            brace_count += line.count('{') - line.count('}')

            # Check if this line starts a function
            if re.search(r'\bfunction\s+\w+\s*\(', line):
                if brace_count >= 0:  # We're not inside another function's braces
                    function_start = i + 1  # Convert back to 1-based
                    in_function = True
                    break

        if function_start:
            # Find function end (next closing brace at same level)
            function_end = None
            for i in range(current_line, len(lines)):
                line = lines[i]
                brace_count += line.count('{') - line.count('}')

                if brace_count < 0 and i > current_line:
                    function_end = i + 1  # Convert back to 1-based
                    break

            # Extract function signature
            function_lines = lines[function_start - 1:i] if function_end else lines[function_start - 1:]
            function_content = '\n'.join(function_lines)

            # Extract function name and signature
            func_match = re.search(r'function\s+(\w+)\s*\(([^)]*)\)', function_content)
            if func_match:
                func_name = func_match.group(1)
                func_params = func_match.group(2)
            else:
                func_name = 'unknown'
                func_params = ''

            return {
                'function_name': func_name,
                'function_signature': f'function {func_name}({func_params})',
                'start_line': function_start,
                'end_line': function_end,
                'line_range': list(range(function_start, function_end or len(lines) + 1))
            }
        else:
            return {'error': 'No function found at line'}

    def get_contract_imports(self, content: str) -> List[Dict[str, str]]:
        """Extract import statements from Solidity contract."""
        imports = []

        # Match import statements
        import_patterns = [
            re.compile(r'import\s+["\']([^"\']+)["\'];', re.IGNORECASE),
            re.compile(r'import\s+\{([^}]+)\}\s+from\s+["\']([^"\']+)["\'];', re.IGNORECASE),
            re.compile(r'import\s+["\']([^"\']+)["\'];', re.IGNORECASE),
        ]

        for pattern in import_patterns:
            matches = pattern.findall(content)
            for match in matches:
                if len(match) == 2:  # Named import
                    imports.append({
                        'type': 'named',
                        'symbols': match[0].strip(),
                        'from': match[1]
                    })
                else:  # Direct import
                    imports.append({
                        'type': 'direct',
                        'from': match[0]
                    })

        return imports

    def get_contract_structure(self, content: str) -> Dict[str, List[Dict[str, Union[str, int]]]]:
        """Extract high-level contract structure."""
        structure = {
            'contracts': [],
            'interfaces': [],
            'libraries': [],
            'structs': [],
            'enums': []
        }

        lines = content.split('\n')

        for i, line in enumerate(lines, 1):
            line_stripped = line.strip()

            # Find contract definitions
            contract_match = re.search(r'contract\s+(\w+)', line_stripped)
            if contract_match:
                structure['contracts'].append({
                    'name': contract_match.group(1),
                    'line': i,
                    'type': 'contract'
                })

            # Find interface definitions
            interface_match = re.search(r'interface\s+(\w+)', line_stripped)
            if interface_match:
                structure['interfaces'].append({
                    'name': interface_match.group(1),
                    'line': i,
                    'type': 'interface'
                })

            # Find library definitions
            library_match = re.search(r'library\s+(\w+)', line_stripped)
            if library_match:
                structure['libraries'].append({
                    'name': library_match.group(1),
                    'line': i,
                    'type': 'library'
                })

            # Find struct definitions
            struct_match = re.search(r'struct\s+(\w+)', line_stripped)
            if struct_match:
                structure['structs'].append({
                    'name': struct_match.group(1),
                    'line': i,
                    'type': 'struct'
                })

            # Find enum definitions
            enum_match = re.search(r'enum\s+(\w+)', line_stripped)
            if enum_match:
                structure['enums'].append({
                    'name': enum_match.group(1),
                    'line': i,
                    'type': 'enum'
                })

        return structure

    def calculate_file_metrics(self, content: str) -> Dict[str, Union[int, float]]:
        """Calculate basic metrics for a Solidity file."""
        lines = content.split('\n')
        total_lines = len(lines)

        # Count different types of lines
        code_lines = 0
        comment_lines = 0
        empty_lines = 0
        contract_lines = 0

        in_multiline_comment = False

        for line in lines:
            stripped = line.strip()

            # Handle multiline comments
            if '/*' in line and '*/' not in line:
                in_multiline_comment = True
            if '*/' in line:
                in_multiline_comment = False
                if '/*' in line:  # Single line comment
                    comment_lines += 1
                else:
                    comment_lines += 1
                    continue

            if in_multiline_comment:
                comment_lines += 1
                continue

            # Count line types
            if not stripped:
                empty_lines += 1
            elif stripped.startswith('//') or stripped.startswith('/*'):
                comment_lines += 1
            else:
                code_lines += 1
                if any(keyword in stripped.lower() for keyword in ['contract', 'interface', 'library']):
                    contract_lines += 1

        return {
            'total_lines': total_lines,
            'code_lines': code_lines,
            'comment_lines': comment_lines,
            'empty_lines': empty_lines,
            'contract_lines': contract_lines,
            'comment_ratio': comment_lines / total_lines if total_lines > 0 else 0,
            'code_ratio': code_lines / total_lines if total_lines > 0 else 0
        }
