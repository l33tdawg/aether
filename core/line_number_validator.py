#!/usr/bin/env python3
"""
Line Number Validator

Validates and corrects LLM-reported line numbers against actual code.
Addresses the issue of LLM hallucinating line numbers that don't match the actual code.
"""

import re
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass


@dataclass
class LineValidationResult:
    """Result of line number validation."""
    status: str  # 'valid', 'corrected', 'invalid'
    original_line: int
    corrected_line: Optional[int]
    confidence: float
    reason: str


class LineNumberValidator:
    """Validates and corrects LLM-reported line numbers against actual code."""

    def __init__(self):
        # Common function/code patterns to search for
        self.identifier_patterns = [
            r'function\s+(\w+)',  # Function names
            r'modifier\s+(\w+)',  # Modifier names
            r'event\s+(\w+)',     # Event names
            r'error\s+(\w+)',     # Custom error names
            r'mapping\s*\([^)]+\)\s+(?:public\s+)?(\w+)',  # Mapping names
            r'`(\w+)\s*\(',       # Backticked function calls
            r'`(\w+)`',           # Backticked identifiers
        ]

    def validate_finding_line_number(
        self,
        finding: Dict[str, Any],
        contract_content: str
    ) -> Dict[str, Any]:
        """
        Verify reported line number matches the finding description.
        If mismatched, attempt to locate the correct line.
        
        Args:
            finding: Vulnerability finding dict with 'line' or 'line_number'
            contract_content: Full contract source code
            
        Returns:
            Finding dict with validated/corrected line number and validation metadata
        """
        reported_line = finding.get('line', finding.get('line_number', 0))
        description = finding.get('description', '')
        title = finding.get('title', '')
        code_snippet = finding.get('code_snippet', '')

        lines = contract_content.split('\n')
        total_lines = len(lines)

        # Initialize validation result
        validation_result = LineValidationResult(
            status='valid',
            original_line=reported_line,
            corrected_line=None,
            confidence=1.0,
            reason='Line number within bounds'
        )

        # Check 1: Line number within bounds
        if reported_line > total_lines or reported_line < 1:
            validation_result.status = 'invalid'
            validation_result.reason = f'Reported line {reported_line} exceeds file length ({total_lines} lines)'
            validation_result.confidence = 0.0

            # Attempt to find actual location
            corrected_line = self._find_actual_line(finding, contract_content)
            if corrected_line:
                validation_result.status = 'corrected'
                validation_result.corrected_line = corrected_line
                validation_result.confidence = 0.85
                validation_result.reason = f'Corrected from {reported_line} to {corrected_line} via pattern search'
                finding['line_number'] = corrected_line
                finding['line'] = corrected_line

            finding['line_validation'] = {
                'status': validation_result.status,
                'original_line': validation_result.original_line,
                'corrected_to': validation_result.corrected_line,
                'confidence': validation_result.confidence,
                'reason': validation_result.reason
            }
            return finding

        # Check 2: Line is a comment or empty - find actual code line
        line_content = lines[reported_line - 1]
        
        if self._is_comment_or_empty(line_content):
            # Line is a comment, find the actual code
            corrected_line = self._find_nearest_code_line(reported_line, lines, finding)
            if corrected_line and corrected_line != reported_line:
                finding['line_number'] = corrected_line
                finding['line'] = corrected_line
                finding['line_validation'] = {
                    'status': 'corrected',
                    'original_line': reported_line,
                    'corrected_to': corrected_line,
                    'confidence': 0.90,
                    'reason': f'Line {reported_line} is a comment, corrected to code at line {corrected_line}'
                }
                return finding

        # Check 3: Line content matches description
        # Extract key identifiers from description
        key_identifiers = self._extract_identifiers(description, title, code_snippet)

        if not key_identifiers:
            # Can't validate without identifiers, assume valid
            finding['line_validation'] = {
                'status': 'assumed_valid',
                'original_line': reported_line,
                'confidence': 0.7,
                'reason': 'No identifiers to validate against'
            }
            return finding

        # Check if any identifiers appear on the reported line
        matches_on_line = sum(1 for ident in key_identifiers if ident.lower() in line_content.lower())

        if matches_on_line > 0:
            # Line content matches description
            finding['line_validation'] = {
                'status': 'valid',
                'original_line': reported_line,
                'confidence': 0.95,
                'reason': f'Found {matches_on_line} matching identifier(s) on line'
            }
            return finding

        # Check nearby lines (±10)
        nearby_match = self._check_nearby_lines(
            reported_line, key_identifiers, lines, window=10
        )

        if nearby_match:
            corrected_line, confidence = nearby_match
            validation_result.status = 'corrected'
            validation_result.corrected_line = corrected_line
            validation_result.confidence = confidence
            validation_result.reason = f'Found matching identifier at line {corrected_line} (was {reported_line})'

            finding['line_number'] = corrected_line
            finding['line'] = corrected_line
            finding['line_validation'] = {
                'status': 'corrected',
                'original_line': reported_line,
                'corrected_to': corrected_line,
                'confidence': confidence,
                'reason': validation_result.reason
            }
            return finding

        # Try broader search via function/pattern matching
        corrected_line = self._find_actual_line(finding, contract_content)
        if corrected_line and corrected_line != reported_line:
            finding['line_number'] = corrected_line
            finding['line'] = corrected_line
            finding['line_validation'] = {
                'status': 'corrected',
                'original_line': reported_line,
                'corrected_to': corrected_line,
                'confidence': 0.75,
                'reason': 'Found via pattern search'
            }
            return finding

        # Could not validate - mark as uncertain
        finding['line_validation'] = {
            'status': 'uncertain',
            'original_line': reported_line,
            'confidence': 0.5,
            'reason': 'Could not find matching identifiers near reported line'
        }
        return finding

    def _is_comment_or_empty(self, line: str) -> bool:
        """Check if a line is a comment or empty."""
        stripped = line.strip()
        
        # Empty line
        if not stripped:
            return True
        
        # Single-line comment
        if stripped.startswith('//'):
            return True
        
        # Multi-line comment start/end or content
        if stripped.startswith('/*') or stripped.startswith('*') or stripped.endswith('*/'):
            return True
        
        # NatSpec comments
        if stripped.startswith('///') or stripped.startswith('/**'):
            return True
        
        # Just opening/closing braces
        if stripped in ['{', '}', '};']:
            return True
        
        return False

    def _find_nearest_code_line(
        self,
        reported_line: int,
        lines: List[str],
        finding: Dict[str, Any]
    ) -> Optional[int]:
        """
        Find the nearest actual code line from a comment line.
        
        Searches forward first (comments usually precede code),
        then backward if no code found forward.
        """
        description = finding.get('description', '').lower()
        title = finding.get('title', '').lower()
        
        # Keywords to look for based on the finding
        keywords = []
        if 'constructor' in description or 'constructor' in title:
            keywords.append('constructor')
        if 'function' in description:
            # Extract function name
            import re
            func_match = re.search(r'`?(\w+)`?\s+function|function\s+`?(\w+)`?', description)
            if func_match:
                keywords.append(func_match.group(1) or func_match.group(2))
        
        # Search forward first (up to 10 lines)
        for offset in range(1, 11):
            check_idx = reported_line - 1 + offset
            if check_idx >= len(lines):
                break
            
            line_content = lines[check_idx]
            if not self._is_comment_or_empty(line_content):
                # Found code line, check if it matches keywords
                if keywords:
                    if any(kw.lower() in line_content.lower() for kw in keywords):
                        return check_idx + 1  # 1-indexed
                else:
                    # No specific keywords, return first code line
                    return check_idx + 1
        
        # Search backward if forward search didn't find matching keywords
        for offset in range(1, 11):
            check_idx = reported_line - 1 - offset
            if check_idx < 0:
                break
            
            line_content = lines[check_idx]
            if not self._is_comment_or_empty(line_content):
                if keywords:
                    if any(kw.lower() in line_content.lower() for kw in keywords):
                        return check_idx + 1
                # Don't return non-keyword matches going backward
        
        # Return first code line found forward
        for offset in range(1, 11):
            check_idx = reported_line - 1 + offset
            if check_idx >= len(lines):
                break
            if not self._is_comment_or_empty(lines[check_idx]):
                return check_idx + 1
        
        return None

    def _extract_identifiers(self, description: str, title: str, code_snippet: str = "") -> List[str]:
        """Extract function/variable names from finding description and title."""
        identifiers = set()
        combined_text = f"{description} {title} {code_snippet}"

        for pattern in self.identifier_patterns:
            matches = re.findall(pattern, combined_text)
            for match in matches:
                if len(match) > 2:  # Filter out noise
                    identifiers.add(match)

        # Also extract CamelCase words that look like function/contract names
        camel_pattern = r'\b([A-Z][a-z]+(?:[A-Z][a-z]+)+)\b'
        camel_matches = re.findall(camel_pattern, combined_text)
        for match in camel_matches:
            if len(match) > 4:
                identifiers.add(match)

        # Extract _underscored names (common in Solidity)
        underscore_pattern = r'\b(_\w{3,})\b'
        underscore_matches = re.findall(underscore_pattern, combined_text)
        identifiers.update(underscore_matches)

        return list(identifiers)

    def _check_nearby_lines(
        self,
        reported_line: int,
        identifiers: List[str],
        lines: List[str],
        window: int = 10
    ) -> Optional[Tuple[int, float]]:
        """
        Check nearby lines for matching identifiers.
        
        Returns:
            Tuple of (corrected_line, confidence) or None
        """
        best_match_line = None
        best_match_count = 0

        for offset in range(-window, window + 1):
            if offset == 0:
                continue  # Skip the reported line (already checked)

            check_line_idx = reported_line + offset - 1
            if 0 <= check_line_idx < len(lines):
                line_content = lines[check_line_idx].lower()
                match_count = sum(1 for ident in identifiers if ident.lower() in line_content)

                if match_count > best_match_count:
                    best_match_count = match_count
                    best_match_line = check_line_idx + 1  # Convert back to 1-indexed

        if best_match_line and best_match_count > 0:
            # Confidence decreases with distance from reported line
            distance = abs(best_match_line - reported_line)
            confidence = max(0.6, 0.95 - (distance * 0.03))
            return (best_match_line, confidence)

        return None

    def _find_actual_line(self, finding: Dict, contract_content: str) -> Optional[int]:
        """Attempt to locate the actual line number via pattern matching."""
        description = finding.get('description', '')
        title = finding.get('title', '')
        code_snippet = finding.get('code_snippet', '')

        lines = contract_content.split('\n')

        # Strategy 1: Find function definition mentioned in description
        func_patterns = [
            r'`(\w+)\s*\(',  # Function in backticks
            r'function\s+`?(\w+)`?',  # "function X"
            r'(\w+)\s+function',  # "X function"
            r'the\s+`?(\w+)`?\s+function',  # "the X function"
        ]

        for pattern in func_patterns:
            match = re.search(pattern, description + ' ' + title, re.IGNORECASE)
            if match:
                func_name = match.group(1)
                # Find this function in code
                for i, line in enumerate(lines, 1):
                    if f'function {func_name}' in line:
                        return i

        # Strategy 2: Look for code snippets mentioned in description
        code_patterns = re.findall(r'`([^`]+)`', description)
        for code_pattern in code_patterns:
            if len(code_pattern) > 5:  # Meaningful code snippet
                # Clean up the pattern for search
                search_pattern = code_pattern.strip()
                for i, line in enumerate(lines, 1):
                    if search_pattern in line:
                        return i

        # Strategy 3: If code_snippet is provided, find it in the contract
        if code_snippet and len(code_snippet) > 10:
            # Get first non-empty line of snippet
            snippet_lines = [l.strip() for l in code_snippet.split('\n') if l.strip()]
            if snippet_lines:
                first_snippet_line = snippet_lines[0]
                for i, line in enumerate(lines, 1):
                    if first_snippet_line in line.strip():
                        return i

        return None

    def validate_findings_batch(
        self,
        findings: List[Dict[str, Any]],
        contract_content: str
    ) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
        """
        Validate a batch of findings and return statistics.
        
        Args:
            findings: List of vulnerability findings
            contract_content: Contract source code
            
        Returns:
            Tuple of (validated_findings, stats_dict)
        """
        validated = []
        stats = {
            'total': len(findings),
            'valid': 0,
            'corrected': 0,
            'invalid': 0,
            'uncertain': 0
        }

        for finding in findings:
            validated_finding = self.validate_finding_line_number(finding, contract_content)
            validation_status = validated_finding.get('line_validation', {}).get('status', 'unknown')

            if validation_status in ['valid', 'assumed_valid']:
                stats['valid'] += 1
                validated.append(validated_finding)
            elif validation_status == 'corrected':
                stats['corrected'] += 1
                validated.append(validated_finding)
            elif validation_status == 'invalid':
                stats['invalid'] += 1
                # Don't include invalid findings (couldn't be corrected)
            else:  # uncertain
                stats['uncertain'] += 1
                validated.append(validated_finding)

        return validated, stats
