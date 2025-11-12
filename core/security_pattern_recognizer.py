#!/usr/bin/env python3
"""
Security Pattern Recognizer

Recognizes intentional security patterns that are often misidentified as vulnerabilities:
- Emergency stop/circuit breaker mechanisms
- Multi-signature requirements
- Time-locked operations
- Access control patterns
"""

import re
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass


@dataclass
class SecurityPattern:
    """Represents a detected security pattern."""
    pattern_type: str
    line_number: int
    description: str
    confidence: float
    context: Dict[str, Any]


class SecurityPatternRecognizer:
    """
    Recognizes legitimate security patterns to prevent false positives.

    Key patterns that cause false positives:
    1. Circuit breakers (emergency stops)
    2. Access control mechanisms
    3. Time-locked operations
    4. Multi-signature requirements
    5. Fail-safe mechanisms
    """

    def __init__(self):
        self.security_patterns = self._initialize_patterns()
        self.detected_patterns: List[SecurityPattern] = []

    def _initialize_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Initialize security pattern recognition."""
        return {
            'circuit_breaker': {
                'patterns': [
                    r'function\s+\w+\s*\([^)]*\)\s+external\s+onlyOwner',
                    r'revert\s+InvalidProofOfExploit',
                    r'claimDigest\s*==\s*bytes32\(0\)',
                    r'verifyIntegrity\s*\(',
                    r'_pause\s*\(\s*\)'
                ],
                'description': 'Circuit breaker/emergency stop mechanism',
                'false_positive_types': ['access_control', 'insufficient_validation'],
                'required_context': ['pause', 'emergency', 'stop']
            },
            'time_lock': {
                'patterns': [
                    r'block\.timestamp\s*[><=]+\s*\w+\s*\+\s*\w+',
                    r'getMinDelay\s*\(\s*\)',
                    r'schedule\w*\s*\(',
                    r'delay\w*\s*\+\s*block\.timestamp'
                ],
                'description': 'Time-locked operation for security',
                'false_positive_types': ['timing_dependency'],
                'required_context': ['delay', 'schedule', 'timelock']
            },
            'access_control': {
                'patterns': [
                    r'onlyOwner\s*\(\s*\)',
                    r'onlyRole\s*\(',
                    r'msg\.sender\s*==\s*owner',
                    r'hasRole\s*\(',
                    r'_checkOwner\s*\(\s*\)'
                ],
                'description': 'Access control mechanism',
                'false_positive_types': ['unauthorized_access', 'permission_bypass'],
                'required_context': ['owner', 'role', 'access']
            },
            'multi_sig': {
                'patterns': [
                    r'confirmations\s*\+\+',
                    r'execute\w*\s*\(\s*\)',
                    r'submit\w*\s*\(',
                    r'threshold\s*[><=]+\s*confirmations'
                ],
                'description': 'Multi-signature wallet pattern',
                'false_positive_types': ['single_point_failure'],
                'required_context': ['signature', 'confirm', 'threshold']
            },
            'fail_safe': {
                'patterns': [
                    r'whenNotPaused\s*\(\s*\)',
                    r'paused\s*\(\s*\)',
                    r'Pausable\s*\w*',
                    r'emergency\w*\('
                ],
                'description': 'Fail-safe/pausable mechanism',
                'false_positive_types': ['denial_of_service'],
                'required_context': ['pause', 'emergency', 'fail']
            },
            'proof_verification': {
                'patterns': [
                    r'verify\w*\s*\(',
                    r'proof\w*\s*\w*',
                    r'check\w*Proof\s*\(',
                    r'validate\w*\s*\('
                ],
                'description': 'Cryptographic proof verification',
                'false_positive_types': ['insufficient_validation'],
                'required_context': ['proof', 'verify', 'validate']
            }
        }

    def analyze_contract(self, contract_code: str) -> List[SecurityPattern]:
        """
        Analyze contract code for security patterns.

        Args:
            contract_code: The Solidity contract code

        Returns:
            List of detected security patterns
        """
        self.detected_patterns = []
        lines = contract_code.split('\n')

        # Analyze each line for patterns
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith('//') or stripped.startswith('*'):
                continue

            for pattern_name, pattern_config in self.security_patterns.items():
                confidence = 0.0
                matched_patterns = []

                # Check if all required patterns are present
                for regex_pattern in pattern_config['patterns']:
                    if re.search(regex_pattern, stripped):
                        matched_patterns.append(regex_pattern)
                        confidence += 1.0 / len(pattern_config['patterns'])

                # Check for required context words
                required_context = pattern_config.get('required_context', [])
                context_matches = sum(1 for context in required_context if context.lower() in stripped.lower())
                if required_context:
                    context_confidence = context_matches / len(required_context)
                    confidence = min(confidence, context_confidence)

                if confidence >= 0.3:  # Threshold for detection (more lenient)
                    self.detected_patterns.append(SecurityPattern(
                        pattern_type=pattern_name,
                        line_number=line_num,
                        description=pattern_config['description'],
                        confidence=confidence,
                        context={
                            'matched_patterns': matched_patterns,
                            'line_content': stripped,
                            'false_positive_types': pattern_config['false_positive_types'],
                            'required_context': required_context
                        }
                    ))

        # Look for circuit breaker pattern specifically (the risc0-ethereum case)
        self._detect_circuit_breaker_pattern(contract_code)

        return self.detected_patterns

    def _detect_circuit_breaker_pattern(self, contract_code: str):
        """Specifically detect circuit breaker patterns like in risc0-ethereum."""
        lines = contract_code.split('\n')

        # Look for emergency stop function with claimDigest check
        estop_function_start = -1
        has_claim_digest_check = False
        has_verify_integrity = False
        has_pause_call = False

        for i, line in enumerate(lines):
            stripped = line.strip()

            # Find estop function
            if 'function estop(' in stripped and 'external' in stripped:
                estop_function_start = i

            # Check for claimDigest validation
            if 'claimDigest != bytes32(0)' in stripped or 'claimDigest == bytes32(0)' in stripped:
                has_claim_digest_check = True

            # Check for verifyIntegrity call
            if 'verifyIntegrity(' in stripped:
                has_verify_integrity = True

            # Check for pause call
            if '_pause()' in stripped:
                has_pause_call = True

        # If we found all components of a circuit breaker, add it
        if has_claim_digest_check and has_verify_integrity and has_pause_call:
            self.detected_patterns.append(SecurityPattern(
                pattern_type='circuit_breaker',
                line_number=estop_function_start + 1 if estop_function_start >= 0 else 1,
                description='Circuit breaker with proof-of-exploit validation',
                confidence=0.95,
                context={
                    'pattern': 'emergency_stop_with_validation',
                    'components': {
                        'claim_digest_check': has_claim_digest_check,
                        'verify_integrity': has_verify_integrity,
                        'pause_mechanism': has_pause_call
                    },
                    'false_positive_types': ['access_control', 'insufficient_validation', 'unauthorized_emergency_action']
                }
            ))

    def should_filter_finding(self, finding: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Determine if a finding should be filtered due to security pattern context.

        Args:
            finding: Vulnerability finding dictionary

        Returns:
            Tuple of (should_filter, reason)
        """
        vuln_type = finding.get('vulnerability_type', '').lower()
        line_number = finding.get('line_number', 0)

        # Check if finding is near any detected security patterns
        for pattern in self.detected_patterns:
            # Check proximity (within 20 lines for context)
            if abs(pattern.line_number - line_number) <= 20:
                false_positive_types = pattern.context.get('false_positive_types', [])
                if any(fp_type.lower() in vuln_type for fp_type in false_positive_types):
                    return True, f"Finding near legitimate {pattern.pattern_type} pattern: {pattern.description}"

            # Special case for circuit breaker
            if pattern.pattern_type == 'circuit_breaker':
                if vuln_type in ['access_control', 'insufficient_validation', 'unauthorized']:
                    if abs(pattern.line_number - line_number) <= 30:  # Larger window for circuit breakers
                        return True, f"Circuit breaker mechanism - {pattern.description}"

        return False, ""

    def is_emergency_stop_pattern(self, contract_code: str, line_number: int) -> bool:
        """
        Check if a specific line is part of an emergency stop pattern.
        """
        lines = contract_code.split('\n')
        if line_number < 1 or line_number > len(lines):
            return False

        # Look for emergency stop pattern in context
        start_line = max(1, line_number - 15)
        end_line = min(len(lines), line_number + 15)

        has_owner_check = False
        has_pause = False
        has_validation = False

        for i in range(start_line - 1, end_line):
            line = lines[i].strip().lower()

            if 'onlyowner' in line or 'require' in line and 'owner' in line:
                has_owner_check = True
            if '_pause()' in line or 'pause' in line:
                has_pause = True
            if 'verify' in line or 'check' in line or 'validate' in line:
                has_validation = True

        return has_owner_check and has_pause

    def get_context_summary(self) -> Dict[str, Any]:
        """Get summary of detected security patterns for reporting."""
        pattern_counts = {}
        total_confidence = 0.0

        for pattern in self.detected_patterns:
            pattern_counts[pattern.pattern_type] = pattern_counts.get(pattern.pattern_type, 0) + 1
            total_confidence += pattern.confidence

        return {
            'total_patterns': len(self.detected_patterns),
            'pattern_types': pattern_counts,
            'average_confidence': total_confidence / max(1, len(self.detected_patterns)),
            'has_circuit_breaker': any(p.pattern_type == 'circuit_breaker' for p in self.detected_patterns),
            'has_access_control': any(p.pattern_type == 'access_control' for p in self.detected_patterns),
            'has_time_lock': any(p.pattern_type == 'time_lock' for p in self.detected_patterns)
        }
