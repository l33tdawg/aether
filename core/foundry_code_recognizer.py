#!/usr/bin/env python3
"""
Foundry Code Recognizer

Recognizes Foundry-specific patterns that are commonly misidentified as vulnerabilities:
- vm.revertTo() snapshot restoration
- vm.prank() address impersonation
- Testing utilities and patterns
- Script vs production contract detection
"""

import re
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass


@dataclass
class FoundryPattern:
    """Represents a detected Foundry testing pattern."""
    pattern_type: str
    line_number: int
    description: str
    context: Dict[str, Any]


class FoundryCodeRecognizer:
    """
    Recognizes Foundry-specific code patterns to prevent false positives.

    Key patterns that cause false positives:
    1. vm.revertTo() - State restoration, not reentrancy
    2. vm.prank() - Address impersonation for testing
    3. vm.snapshot() - State snapshots for testing
    4. Script contracts (deploy/test scripts)
    """

    def __init__(self):
        self.foundry_patterns = self._initialize_patterns()
        self.detected_patterns: List[FoundryPattern] = []

    def _initialize_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Initialize Foundry-specific pattern recognition."""
        return {
            'snapshot_revert': {
                'patterns': [
                    r'vm\.revertTo\s*\([^)]+\)',
                    r'uint256\s+\w+\s*=\s*vm\.snapshot\s*\(\s*\)',
                    r'vm\.snapshot\s*\(\s*\)'
                ],
                'description': 'Foundry snapshot/revert mechanism for testing',
                'false_positive_types': ['reentrancy', 'state_change_after_external_call']
            },
            'prank_impersonation': {
                'patterns': [
                    r'vm\.prank\s*\([^)]+\)',
                    r'vm\.startPrank\s*\([^)]+\)',
                    r'vm\.stopPrank\s*\(\s*\)'
                ],
                'description': 'Foundry address impersonation for testing',
                'false_positive_types': ['access_control', 'unauthorized_access']
            },
            'foundry_cheats': {
                'patterns': [
                    r'vm\.warp\s*\(',
                    r'vm\.roll\s*\(',
                    r'vm\.deal\s*\(',
                    r'vm\.etch\s*\(',
                    r'vm\.expectRevert\s*\(',
                    r'vm\.expectEmit\s*\('
                ],
                'description': 'Foundry cheat codes for test environment manipulation',
                'false_positive_types': ['state_manipulation', 'unauthorized_state_change']
            },
            'script_contract': {
                'patterns': [
                    r'contract\s+\w+Script\s+is\s+Script',
                    r'import\s+.*Script\.sol',
                    r'function\s+run\s*\(\s*\)\s+external',
                    r'vm\.broadcast\s*\('
                ],
                'description': 'Foundry script contract for deployment/testing',
                'false_positive_types': ['production_vulnerability']
            },
            'test_contract': {
                'patterns': [
                    r'contract\s+\w+Test\s+is\s+Test',
                    r'import\s+.*Test\.sol',
                    r'function\s+test\w*\s*\(',
                    r'function\s+setUp\s*\(\s*\)'
                ],
                'description': 'Foundry test contract',
                'false_positive_types': ['production_vulnerability']
            }
        }

    def analyze_contract(self, contract_code: str, file_path: str = "") -> List[FoundryPattern]:
        """
        Analyze contract code for Foundry-specific patterns.

        Args:
            contract_code: The Solidity contract code
            file_path: Optional file path for additional context

        Returns:
            List of detected Foundry patterns
        """
        self.detected_patterns = []
        lines = contract_code.split('\n')

        # Check file path for Foundry indicators
        if file_path:
            if 'script/' in file_path or file_path.endswith('.s.sol'):
                self.detected_patterns.append(FoundryPattern(
                    pattern_type='script_file',
                    line_number=1,
                    description='Foundry script file (.s.sol or in script/ directory)',
                    context={'file_path': file_path}
                ))

        # Analyze each line for patterns
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith('//'):
                continue

            for pattern_name, pattern_config in self.foundry_patterns.items():
                for regex_pattern in pattern_config['patterns']:
                    if re.search(regex_pattern, stripped):
                        self.detected_patterns.append(FoundryPattern(
                            pattern_type=pattern_name,
                            line_number=line_num,
                            description=pattern_config['description'],
                            context={
                                'matched_pattern': regex_pattern,
                                'line_content': stripped,
                                'false_positive_types': pattern_config['false_positive_types']
                            }
                        ))
                        break  # Only record one match per line per pattern type

        return self.detected_patterns

    def is_foundry_test_context(self, line_number: int) -> bool:
        """
        Check if a line number is within Foundry testing context.

        Args:
            line_number: Line number to check

        Returns:
            True if line is in Foundry testing context
        """
        for pattern in self.detected_patterns:
            # Check if line is within a reasonable proximity to Foundry patterns
            if abs(pattern.line_number - line_number) <= 10:  # Within 10 lines
                if pattern.pattern_type in ['snapshot_revert', 'prank_impersonation', 'foundry_cheats']:
                    return True

        return False

    def should_filter_finding(self, finding: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Determine if a finding should be filtered due to Foundry context.

        Args:
            finding: Vulnerability finding dictionary

        Returns:
            Tuple of (should_filter, reason)
        """
        vuln_type = finding.get('vulnerability_type', '').lower()
        line_number = finding.get('line_number', 0)

        # Check if we're in Foundry testing context
        if self.is_foundry_test_context(line_number):
            return True, f"Line {line_number} is in Foundry testing context (snapshot/prank/cheat codes detected)"

        # Check specific pattern matches
        for pattern in self.detected_patterns:
            if pattern.pattern_type == 'script_contract' or pattern.pattern_type == 'script_file':
                if vuln_type in ['reentrancy', 'access_control', 'state_manipulation']:
                    return True, f"Contract is a Foundry script, not production code"

            if pattern.pattern_type == 'test_contract':
                return True, f"Contract is a Foundry test, not production code"

            # Check false positive types for this pattern
            false_positive_types = pattern.context.get('false_positive_types', [])
            if vuln_type in false_positive_types:
                # Check if the finding is near this pattern
                if abs(pattern.line_number - line_number) <= 5:  # Very close proximity
                    return True, f"Finding near Foundry {pattern.pattern_type} pattern: {pattern.description}"

        return False, ""

    def is_snapshot_revert_pattern(self, contract_code: str, line_number: int) -> bool:
        """
        Specifically check if a line is part of snapshot/revert testing pattern.

        This is critical for filtering false reentrancy positives.
        """
        lines = contract_code.split('\n')
        if line_number < 1 or line_number > len(lines):
            return False

        # Look for snapshot -> call -> revert pattern within a small window
        start_line = max(1, line_number - 5)
        end_line = min(len(lines), line_number + 5)

        has_snapshot = False
        has_revert = False
        has_external_call = False

        for i in range(start_line - 1, end_line):
            line = lines[i].strip()

            if 'vm.snapshot()' in line or 'vm.revertTo(' in line:
                has_snapshot = True
            if 'vm.revertTo(' in line:
                has_revert = True
            if '.call(' in line or '.call{' in line:
                has_external_call = True

        return has_snapshot and has_revert and has_external_call

    def get_context_summary(self) -> Dict[str, Any]:
        """Get summary of detected Foundry patterns for reporting."""
        pattern_counts = {}
        for pattern in self.detected_patterns:
            pattern_counts[pattern.pattern_type] = pattern_counts.get(pattern.pattern_type, 0) + 1

        return {
            'total_patterns': len(self.detected_patterns),
            'pattern_types': pattern_counts,
            'is_script_contract': any(p.pattern_type in ['script_contract', 'script_file']
                                    for p in self.detected_patterns),
            'is_test_contract': any(p.pattern_type == 'test_contract'
                                  for p in self.detected_patterns),
            'has_testing_utilities': any(p.pattern_type in ['snapshot_revert', 'prank_impersonation', 'foundry_cheats']
                                       for p in self.detected_patterns)
        }
