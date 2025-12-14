#!/usr/bin/env python3
"""
Design Pattern Detector

Detects intentional design patterns that might appear as vulnerabilities but are safe.
Examples: migration helpers, pull payments, factory deployments, etc.
"""

import re
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum


class SafePatternType(Enum):
    """Types of safe permissionless patterns."""
    MIGRATION_HELPER = "migration_helper"
    PULL_PAYMENT = "pull_payment"
    FACTORY_DEPLOY = "factory_deploy"
    SYNC_OPERATION = "sync_operation"
    RESCUE_FUNCTION = "rescue_function"
    BRIDGE_RELAY = "bridge_relay"


@dataclass
class PatternMatchResult:
    """Result of pattern detection."""
    is_safe_pattern: bool
    pattern_type: Optional[SafePatternType]
    confidence: float
    reasoning: str
    matches_found: List[str]


class DesignPatternDetector:
    """Detects intentional design patterns that might appear as vulnerabilities."""

    # Safe permissionless patterns with their characteristics
    SAFE_PATTERNS = {
        SafePatternType.MIGRATION_HELPER: {
            'function_patterns': [
                r'transferFundsFrom\w+',
                r'migrate\w*',
                r'updateChainBalances\w*',
                r'sync\w*Balance',
                r'migrateTo\w*',
                r'transferTo\w+Vault',
            ],
            'characteristic_code': [
                # Funds move TO the contract, not away
                r'\.transfer\(\s*address\s*\(\s*this\s*\)',
                r'\.safeTransfer\(\s*address\s*\(\s*this\s*\)',
                # Reads from authorized source
                r'\w+\.chainBalance\(',
                r'\w+\.transferTokenToNTV\(',
                r'\w+\.nullifyChainBalance',
                # Updates internal accounting
                r'chainBalance\[\w+\]\[\w+\]\s*[+\-]=',
            ],
            'reasoning': 'Migration helper pattern: permissionless by design, funds only move within protocol contracts',
            'min_matches': 1
        },
        SafePatternType.PULL_PAYMENT: {
            'function_patterns': [
                r'claim\w*',
                r'withdraw\w*',
                r'redeem\w*',
                r'collect\w*',
            ],
            'characteristic_code': [
                # Must have ownership/balance check
                r'balances\[msg\.sender\]',
                r'pendingWithdrawals\[',
                r'_balances\[msg\.sender\]',
                r'claimable\[msg\.sender\]',
                # SafeTransfer to msg.sender (pull pattern)
                r'\.safeTransfer\(\s*msg\.sender',
                r'\.transfer\(\s*msg\.sender',
            ],
            'reasoning': 'Pull payment pattern: users can only claim their own funds, not others',
            'min_matches': 2
        },
        SafePatternType.FACTORY_DEPLOY: {
            'function_patterns': [
                r'create\w*',
                r'deploy\w*',
                r'clone\w*',
                r'spawn\w*',
            ],
            'characteristic_code': [
                r'CREATE2',
                r'new\s+\w+\(',
                r'Clones\.clone\(',
                r'Clones\.cloneDeterministic\(',
                r'CREATE\s',
            ],
            'reasoning': 'Factory pattern: permissionless deployment of new instances with deterministic addresses',
            'min_matches': 1
        },
        SafePatternType.SYNC_OPERATION: {
            'function_patterns': [
                r'sync\w*',
                r'update\w*Balance',
                r'refresh\w*',
                r'poke\w*',
            ],
            'characteristic_code': [
                # Updates state from external source
                r'\.balanceOf\(\s*address\s*\(\s*this\s*\)\s*\)',
                r'reserve\d?\s*=',
                r'lastBalance\s*=',
                # No external transfers
            ],
            'negative_patterns': [
                # Should NOT have outgoing transfers
                r'\.transfer\([^)]*[^t][^h][^i][^s]',
            ],
            'reasoning': 'Sync operation pattern: permissionless state sync, does not move funds',
            'min_matches': 1
        },
        SafePatternType.RESCUE_FUNCTION: {
            'function_patterns': [
                r'rescue\w*',
                r'recover\w*Token',
                r'sweep\w*',
                r'emergencyWithdraw',
            ],
            'characteristic_code': [
                # Restricted by admin/owner
                r'onlyOwner',
                r'onlyAdmin',
                r'onlyGuardian',
                r'require\([^)]*owner',
            ],
            'reasoning': 'Rescue function pattern: admin-only emergency fund recovery',
            'min_matches': 1
        },
        SafePatternType.BRIDGE_RELAY: {
            'function_patterns': [
                r'relay\w*',
                r'finalize\w*',
                r'process\w*Message',
                r'receiveMessage',
            ],
            'characteristic_code': [
                # Merkle proof verification
                r'merkleProof',
                r'verifyProof',
                r'proveL\d',
                # Message hash verification
                r'messageHash',
                r'keccak256\([^)]*message',
            ],
            'reasoning': 'Bridge relay pattern: cryptographically verified cross-chain message execution',
            'min_matches': 1
        }
    }

    def detect_safe_pattern(
        self,
        function_name: str,
        function_code: str,
        contract_code: str
    ) -> PatternMatchResult:
        """
        Detect if a function follows a known safe permissionless pattern.
        
        Args:
            function_name: Name of the function
            function_code: Function body code
            contract_code: Full contract code
            
        Returns:
            PatternMatchResult with detection details
        """
        for pattern_type, config in self.SAFE_PATTERNS.items():
            # Check if function name matches pattern
            name_matches = any(
                re.search(p, function_name, re.IGNORECASE)
                for p in config['function_patterns']
            )

            if not name_matches:
                continue

            # Count characteristic code matches
            combined_code = f"{function_code}\n{contract_code}"
            matches_found = []

            for code_pattern in config['characteristic_code']:
                if re.search(code_pattern, combined_code):
                    matches_found.append(code_pattern)

            # Check negative patterns (patterns that should NOT be present)
            negative_patterns = config.get('negative_patterns', [])
            has_negative = any(
                re.search(p, function_code)
                for p in negative_patterns
            )

            if has_negative:
                continue

            min_matches = config.get('min_matches', 1)
            if len(matches_found) >= min_matches:
                confidence = min(0.95, 0.7 + (0.05 * len(matches_found)))
                return PatternMatchResult(
                    is_safe_pattern=True,
                    pattern_type=pattern_type,
                    confidence=confidence,
                    reasoning=config['reasoning'],
                    matches_found=matches_found
                )

        # No safe pattern detected
        return PatternMatchResult(
            is_safe_pattern=False,
            pattern_type=None,
            confidence=0.0,
            reasoning='No known safe pattern detected',
            matches_found=[]
        )

    def is_intentionally_permissionless(
        self,
        function_name: str,
        function_code: str,
        contract_code: str,
        finding: Dict[str, Any]
    ) -> tuple[bool, str, float]:
        """
        Check if a function is intentionally permissionless by design.
        
        This is used to filter false positives where lack of access control
        is actually the intended behavior.
        
        Args:
            function_name: Name of the function
            function_code: Function body code
            contract_code: Full contract code
            finding: The vulnerability finding dict
            
        Returns:
            Tuple of (is_intentional, reasoning, confidence)
        """
        # Check for known safe patterns
        pattern_result = self.detect_safe_pattern(
            function_name, function_code, contract_code
        )

        if pattern_result.is_safe_pattern:
            return (
                True,
                pattern_result.reasoning,
                pattern_result.confidence
            )

        # Check for explicit "permissionless" documentation
        doc_patterns = [
            r'/\*\*[^*]*permissionless[^*]*\*/',
            r'//.*permissionless',
            r'/\*\*[^*]*anyone can call[^*]*\*/',
            r'//.*anyone can call',
            r'/\*\*[^*]*public function[^*]*\*/',
        ]

        # Check function and surrounding context for documentation
        function_start = contract_code.find(f'function {function_name}')
        if function_start > 0:
            # Get preceding comments (up to 500 chars before)
            context_start = max(0, function_start - 500)
            context = contract_code[context_start:function_start]

            for pattern in doc_patterns:
                if re.search(pattern, context, re.IGNORECASE | re.DOTALL):
                    return (
                        True,
                        'Function is documented as intentionally permissionless',
                        0.85
                    )

        # Check if function only updates internal state without external effects
        if self._is_internal_only_update(function_code):
            return (
                True,
                'Function only updates internal accounting without external transfers',
                0.75
            )

        return (False, 'No intentional permissionless pattern detected', 0.0)

    def _is_internal_only_update(self, function_code: str) -> bool:
        """
        Check if function only performs internal state updates.
        
        Internal-only functions that don't transfer value to arbitrary addresses
        are typically safe to be permissionless.
        """
        # Patterns that indicate external value transfer (NOT internal-only)
        external_transfer_patterns = [
            r'\.transfer\(',
            r'\.send\(',
            r'\.call\{[^}]*value',
            r'safeTransfer\([^,]+,',  # Transfer to non-this address
        ]

        # Check for external transfers
        has_external_transfer = any(
            re.search(p, function_code)
            for p in external_transfer_patterns
        )

        if has_external_transfer:
            # Check if transfer is to address(this) - that's internal
            safe_transfer_patterns = [
                r'\.transfer\(\s*address\s*\(\s*this\s*\)',
                r'safeTransfer\(\s*address\s*\(\s*this\s*\)',
            ]

            only_internal = all(
                re.search(p, function_code)
                for p in external_transfer_patterns
                if re.search(p, function_code)
            ) and any(
                re.search(p, function_code)
                for p in safe_transfer_patterns
            )

            return only_internal

        # No external transfers = internal only
        return True

    def get_pattern_description(self, pattern_type: SafePatternType) -> str:
        """Get a human-readable description of a pattern type."""
        descriptions = {
            SafePatternType.MIGRATION_HELPER: (
                "Migration helper functions are intentionally permissionless to allow "
                "anyone to trigger the migration of funds between protocol contracts. "
                "This is safe because funds only move within the protocol's own contracts."
            ),
            SafePatternType.PULL_PAYMENT: (
                "Pull payment pattern allows users to withdraw their own funds. "
                "This is safe because users can only claim funds allocated to them."
            ),
            SafePatternType.FACTORY_DEPLOY: (
                "Factory pattern allows permissionless deployment of new contract instances. "
                "This is safe because deployed contracts are from approved templates."
            ),
            SafePatternType.SYNC_OPERATION: (
                "Sync operations update internal state to match external state. "
                "This is safe because they don't transfer funds, only update accounting."
            ),
            SafePatternType.RESCUE_FUNCTION: (
                "Rescue functions allow emergency fund recovery by admins. "
                "These are typically restricted but may appear permissionless in analysis."
            ),
            SafePatternType.BRIDGE_RELAY: (
                "Bridge relay functions execute cross-chain messages. "
                "They are permissionless but protected by cryptographic proof verification."
            ),
        }
        return descriptions.get(pattern_type, "Unknown pattern type")

    def should_filter_access_control_finding(
        self,
        finding: Dict[str, Any],
        function_name: str,
        function_code: str,
        contract_code: str
    ) -> tuple[bool, str]:
        """
        Determine if an access control finding should be filtered.
        
        Args:
            finding: The vulnerability finding
            function_name: Name of the function
            function_code: Function body code
            contract_code: Full contract code
            
        Returns:
            Tuple of (should_filter, reasoning)
        """
        vuln_type = finding.get('vulnerability_type', '').lower()
        description = finding.get('description', '').lower()

        # Only process access control related findings
        if not any(kw in vuln_type or kw in description 
                   for kw in ['access control', 'permission', 'authorization', 'missing modifier']):
            return (False, 'Not an access control finding')

        # Check for intentionally permissionless pattern
        is_intentional, reasoning, confidence = self.is_intentionally_permissionless(
            function_name, function_code, contract_code, finding
        )

        if is_intentional and confidence >= 0.7:
            return (True, reasoning)

        return (False, 'No safe permissionless pattern detected')
