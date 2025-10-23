"""
Protocol-Specific Pattern Library

This module contains protocol-specific patterns for identifying false positives and
understanding documented design decisions in DeFi protocols.

Based on DEEP_ANALYSIS_FALSE_POSITIVES.md recommendations.
"""

import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass


@dataclass
class ProtocolPattern:
    """Represents a protocol-specific pattern that indicates a false positive."""
    pattern_type: str
    comment_markers: List[str]
    file_markers: List[str]
    code_markers: List[str]
    reason: str
    acceptable_behavior: bool
    solidity_version_specific: Optional[str] = None  # e.g., "<0.8.0" or ">=0.8.0"


class ProtocolPatternLibrary:
    """Library of protocol-specific patterns for false positive detection."""
    
    def __init__(self):
        self.patterns = self._initialize_patterns()
    
    def _initialize_patterns(self) -> Dict[str, Dict[str, ProtocolPattern]]:
        """Initialize all protocol-specific patterns."""
        return {
            'uniswap_v3': self._uniswap_v3_patterns(),
            'compound': self._compound_patterns(),
            'aave': self._aave_patterns(),
            'general_defi': self._general_defi_patterns(),
        }
    
    def _uniswap_v3_patterns(self) -> Dict[str, ProtocolPattern]:
        """Uniswap V3 specific patterns."""
        return {
            'acceptable_uint128_overflow': ProtocolPattern(
                pattern_type='integer_overflow',
                comment_markers=[
                    'overflow is acceptable',
                    'overflow is not possible',
                    'have to withdraw before',
                    'type(uint128).max',
                    'max value of uint128',
                    'tokensOwed can never be',
                ],
                file_markers=[],  # Generic - look for comment markers not filenames
                code_markers=[
                    'uint128',
                    '+=',
                ],
                reason='Documented design: Users must withdraw before uint128.max fees accumulate. Overflow is intentional and bounded.',
                acceptable_behavior=True,
                solidity_version_specific='<0.8.0'
            ),
            'audited_math_library': ProtocolPattern(
                pattern_type='integer_overflow',
                comment_markers=[
                    'Credit to',
                    'MIT license',
                    'Remco Bloemen',
                    'xn--2-umb.com',
                ],
                file_markers=[],
                code_markers=[
                    'mulDiv',
                    'library',
                    'internal pure',
                    'assembly',
                ],
                reason='Well-audited mathematical library (Remco Bloemen mulDiv). Extensively tested and verified.',
                acceptable_behavior=True
            ),
            'ownership_renunciation': ProtocolPattern(
                pattern_type='access_control',
                comment_markers=[
                    'can be set to zero',
                    'allow zero address',
                    'ownership transfer',
                    'renounce ownership',
                    'transfer ownership',
                    'can be changed by',
                    'decentralization',
                    'immutable',
                ],
                file_markers=[],  # Don't restrict by filename - look for patterns in any file
                code_markers=[
                    'function setOwner',
                    'function transferOwnership',
                    'owner =',
                    'msg.sender == owner',
                ],
                reason='Decentralization feature - allowing ownership renunciation to address(0) is intentional in DeFi protocols.',
                acceptable_behavior=True
            ),
            'fixed_point_precision': ProtocolPattern(
                pattern_type='precision_loss',
                comment_markers=[
                    'fixed point',
                    'Q64.96',
                    'UQ112x112',
                    'precision loss acceptable',
                    'within <1 wei',
                    'lossless version',
                    'rounding',
                    'round up',
                    'round down',
                ],
                file_markers=[],  # Don't restrict by filename - look for patterns
                code_markers=[
                    'mulDiv',
                    'divRoundingUp',
                    'mulDivRoundingUp',
                    'FixedPoint',
                    'fixed-point',
                ],
                reason='Fixed-point arithmetic - precision loss is part of the mathematical model and is bounded.',
                acceptable_behavior=True
            ),
            'sqrt_price_math': ProtocolPattern(
                pattern_type='arithmetic_complexity',
                comment_markers=[
                    'square root price',
                    'tick math',
                    'price calculation',
                ],
                file_markers=['SqrtPriceMath.sol', 'TickMath.sol'],
                code_markers=[
                    'sqrtPX96',
                    'getSqrtRatioAtTick',
                    'getTickAtSqrtRatio',
                ],
                reason='Complex mathematical operations for AMM pricing - precision and overflow behavior is carefully designed.',
                acceptable_behavior=True
            ),
        }
    
    def _compound_patterns(self) -> Dict[str, ProtocolPattern]:
        """Compound protocol specific patterns."""
        return {
            'interest_rate_model': ProtocolPattern(
                pattern_type='arithmetic_precision',
                comment_markers=[
                    'interest rate',
                    'exponential',
                    'mantissa',
                ],
                file_markers=['InterestRateModel.sol', 'Exponential.sol'],
                code_markers=[
                    'mantissa',
                    'expScale',
                    'getBorrowRate',
                    'getSupplyRate',
                ],
                reason='Interest rate calculations use high-precision mantissa arithmetic - precision loss is expected and bounded.',
                acceptable_behavior=True
            ),
            'comptroller_markets': ProtocolPattern(
                pattern_type='state_management',
                comment_markers=[
                    'market listed',
                    'markets',
                    'cToken',
                ],
                file_markers=['Comptroller.sol', 'CToken.sol'],
                code_markers=[
                    'markets',
                    'allMarkets',
                    'marketGroupId',
                ],
                reason='Market state management - administrative functions are intentionally centralized for governance.',
                acceptable_behavior=True
            ),
        }
    
    def _aave_patterns(self) -> Dict[str, ProtocolPattern]:
        """Aave protocol specific patterns."""
        return {
            'ray_math': ProtocolPattern(
                pattern_type='precision_loss',
                comment_markers=[
                    'ray',
                    '1e27',
                    'rayMul',
                    'rayDiv',
                ],
                file_markers=['WadRayMath.sol', 'MathUtils.sol'],
                code_markers=[
                    'RAY',
                    'rayMul',
                    'rayDiv',
                    'wadMul',
                    'wadDiv',
                ],
                reason='Ray math (1e27 precision) - high precision arithmetic with accepted rounding behavior.',
                acceptable_behavior=True
            ),
            'pool_configurator': ProtocolPattern(
                pattern_type='access_control',
                comment_markers=[
                    'pool admin',
                    'configurator',
                    'emergency admin',
                ],
                file_markers=['PoolConfigurator.sol', 'ACLManager.sol'],
                code_markers=[
                    'onlyPoolAdmin',
                    'onlyEmergencyAdmin',
                    'onlyRiskOrPoolAdmins',
                ],
                reason='Administrative functions are protected by ACL system - centralized control is by design for governance.',
                acceptable_behavior=True
            ),
        }
    
    def _general_defi_patterns(self) -> Dict[str, ProtocolPattern]:
        """General DeFi patterns applicable across protocols."""
        return {
            'safecast_type_narrowing': ProtocolPattern(
                pattern_type='integer_overflow',
                comment_markers=[
                    'SafeCast',
                    'safe casting',
                    'type narrowing',
                    'revert on overflow',
                ],
                file_markers=['SafeCast.sol'],
                code_markers=[
                    'SafeCast.toUint96',
                    'SafeCast.toUint128',
                    'SafeCast.toUint160',
                    'SafeCast.toInt',
                ],
                reason='SafeCast library reverts on overflow - this is intentional safe type narrowing, not a vulnerability.',
                acceptable_behavior=True,
                solidity_version_specific='>=0.8.0'
            ),
            'safemath_protection': ProtocolPattern(
                pattern_type='integer_overflow',
                comment_markers=[
                    'SafeMath',
                    'checked arithmetic',
                ],
                file_markers=['SafeMath.sol'],
                code_markers=[
                    'using SafeMath',
                    'SafeMath.add',
                    'SafeMath.sub',
                    'SafeMath.mul',
                    'SafeMath.div',
                    '.add(',
                    '.sub(',
                    '.mul(',
                    '.div(',
                ],
                reason='SafeMath library provides overflow protection - operations revert on overflow.',
                acceptable_behavior=True,
                solidity_version_specific='<0.8.0'
            ),
            'openzeppelin_access_control': ProtocolPattern(
                pattern_type='access_control',
                comment_markers=[
                    'AccessControl',
                    'role-based',
                    'RBAC',
                ],
                file_markers=['AccessControl.sol', 'Ownable.sol'],
                code_markers=[
                    'onlyRole',
                    'onlyOwner',
                    'hasRole',
                    '_checkRole',
                ],
                reason='OpenZeppelin AccessControl provides role-based access - widely audited and battle-tested.',
                acceptable_behavior=True
            ),
            'chainlink_oracle_flash_loan_immunity': ProtocolPattern(
                pattern_type='oracle_manipulation',
                comment_markers=[
                    'Chainlink',
                    'price feed',
                    'AggregatorV3',
                ],
                file_markers=['AggregatorV3Interface.sol'],
                code_markers=[
                    'AggregatorV3Interface',
                    'latestRoundData',
                    'ChainlinkClient',
                    'aggregatorV3',
                ],
                reason='Chainlink oracles are off-chain aggregators - immune to flash loan manipulation.',
                acceptable_behavior=True
            ),
            'reentrancy_guard': ProtocolPattern(
                pattern_type='reentrancy',
                comment_markers=[
                    'ReentrancyGuard',
                    'nonReentrant',
                ],
                file_markers=['ReentrancyGuard.sol'],
                code_markers=[
                    'nonReentrant',
                    '_nonReentrantBefore',
                    '_nonReentrantAfter',
                ],
                reason='OpenZeppelin ReentrancyGuard provides protection against reentrancy attacks.',
                acceptable_behavior=True
            ),
            'pausable_by_design': ProtocolPattern(
                pattern_type='access_control',
                comment_markers=[
                    'Pausable',
                    'emergency stop',
                    'circuit breaker',
                ],
                file_markers=['Pausable.sol'],
                code_markers=[
                    'whenNotPaused',
                    'whenPaused',
                    'pause()',
                    'unpause()',
                ],
                reason='Pausable pattern is an intentional emergency stop mechanism - administrative control is by design.',
                acceptable_behavior=True
            ),
        }
    
    def _normalize_vulnerability_type(self, vuln_type: str) -> str:
        """
        Normalize vulnerability type names to match protocol patterns.
        Maps specific detector types to general pattern categories.
        """
        vuln_type_lower = vuln_type.lower().strip()
        
        # Precision loss variations
        if 'precision' in vuln_type_lower or 'division' in vuln_type_lower:
            return 'precision_loss'
        
        # Access control / parameter validation
        if 'parameter_validation' in vuln_type_lower or 'validation' in vuln_type_lower:
            # Could be access control (ownership) or input validation
            # Return list to check both
            return 'access_control'
        
        # Integer overflow variations  
        if 'overflow' in vuln_type_lower or 'underflow' in vuln_type_lower:
            return 'integer_overflow'
        
        # Return as-is if no normalization needed
        return vuln_type_lower
    
    def check_pattern_match(
        self, 
        vulnerability_type: str, 
        contract_code: str, 
        context: Dict[str, Any]
    ) -> Optional[ProtocolPattern]:
        """
        Check if a vulnerability matches any protocol-specific pattern.
        
        Args:
            vulnerability_type: Type of vulnerability being checked
            contract_code: Full contract source code
            context: Additional context including file path, comments, etc.
        
        Returns:
            ProtocolPattern if a match is found, None otherwise
        """
        import logging
        logger = logging.getLogger(__name__)
        
        # Normalize the vulnerability type for better matching
        normalized_type = self._normalize_vulnerability_type(vulnerability_type)
        logger.debug(f"    Original type: '{vulnerability_type}' -> Normalized: '{normalized_type}'")
        
        # Check all protocols
        for protocol_name, protocol_patterns in self.patterns.items():
            for pattern_name, pattern in protocol_patterns.items():
                # Check both original and normalized types
                if pattern.pattern_type == vulnerability_type or pattern.pattern_type == normalized_type:
                    logger.debug(f"    Checking pattern '{pattern_name}' ({pattern.pattern_type})")
                    if self._matches_pattern(pattern, contract_code, context):
                        logger.info(f"    ✓ MATCHED: {pattern_name} - {pattern.reason}")
                        return pattern
                    else:
                        logger.debug(f"    ✗ No match for {pattern_name}")
        
        return None
    
    def _matches_pattern(
        self, 
        pattern: ProtocolPattern, 
        contract_code: str, 
        context: Dict[str, Any]
    ) -> bool:
        """Check if a pattern matches the given code and context."""
        
        # Extract context information
        file_path = context.get('file_path', '')
        code_snippet = context.get('code_snippet', '')
        surrounding_context = context.get('surrounding_context', '')
        function_context = context.get('function_context', '')
        
        # Combine all relevant code for searching
        searchable_code = f"{contract_code}\n{code_snippet}\n{surrounding_context}\n{function_context}"
        
        # Check file markers
        file_match = any(marker in file_path for marker in pattern.file_markers) if pattern.file_markers else False
        
        # Check code markers
        code_match = any(marker in searchable_code for marker in pattern.code_markers) if pattern.code_markers else False
        
        # Check comment markers
        comment_match = False
        if pattern.comment_markers:
            comment_match = any(
                re.search(rf'//.*{re.escape(marker)}', searchable_code, re.IGNORECASE) or
                re.search(rf'/\*.*{re.escape(marker)}.*\*/', searchable_code, re.IGNORECASE | re.DOTALL)
                for marker in pattern.comment_markers
            )
        
        # Special handling for import-based patterns (like Chainlink)
        # Check if any code marker appears in an import statement
        import_match = False
        if pattern.code_markers:
            import_match = any(
                re.search(rf'import\s+.*{re.escape(marker)}', searchable_code, re.IGNORECASE)
                for marker in pattern.code_markers
            )
        
        # Improved matching logic - more flexible and generic:
        # 1. If pattern has comment markers and they match + code markers match -> TRUE (strong signal)
        # 2. If pattern has no file markers (generic pattern) and code markers match -> TRUE
        # 3. If pattern has file markers and they match + code markers -> TRUE (specific file pattern)
        # 4. Import-based patterns (like Chainlink oracles) -> TRUE
        
        # Strong signal: Comment markers are explicit documentation
        if comment_match and code_match:
            return True
        
        # Generic patterns (no file restrictions) with code match
        if not pattern.file_markers and code_match:
            return True
        
        # File-specific patterns
        if file_match and code_match:
            return True
        
        # Import-based patterns
        if import_match:
            return True
        
        # Multiple code markers (stronger signal for generic patterns)
        if pattern.code_markers:
            matching_markers = sum(1 for marker in pattern.code_markers if marker in searchable_code)
            if matching_markers >= 3:  # At least 3 code markers = strong signal
                return True
        
        return False
    
    def extract_solidity_version(self, contract_code: str) -> Optional[str]:
        """Extract Solidity version from pragma statement."""
        pragma_match = re.search(r'pragma\s+solidity\s+([^;]+);', contract_code)
        if pragma_match:
            version_spec = pragma_match.group(1).strip()
            # Extract actual version number (e.g., "^0.8.0" -> "0.8.0")
            version_match = re.search(r'(\d+\.\d+\.\d+)', version_spec)
            if version_match:
                return version_match.group(1)
            # Handle range specs like ">=0.7.6 <0.9.0"
            version_match = re.search(r'(\d+\.\d+)', version_spec)
            if version_match:
                return version_match.group(1) + ".0"
        return None
    
    def check_solidity_version_compatibility(
        self, 
        pattern: ProtocolPattern, 
        contract_version: Optional[str]
    ) -> bool:
        """
        Check if a pattern is compatible with the contract's Solidity version.
        
        Args:
            pattern: The protocol pattern to check
            contract_version: The Solidity version of the contract (e.g., "0.7.6")
        
        Returns:
            True if pattern is compatible or version check doesn't apply, False otherwise
        """
        if not pattern.solidity_version_specific or not contract_version:
            return True
        
        # Parse version spec (e.g., "<0.8.0", ">=0.8.0")
        version_spec = pattern.solidity_version_specific
        
        if version_spec.startswith('>='):
            min_version = version_spec[2:]
            return self._compare_versions(contract_version, min_version) >= 0
        elif version_spec.startswith('<='):
            max_version = version_spec[2:]
            return self._compare_versions(contract_version, max_version) <= 0
        elif version_spec.startswith('<'):
            max_version = version_spec[1:]
            return self._compare_versions(contract_version, max_version) < 0
        elif version_spec.startswith('>'):
            min_version = version_spec[1:]
            return self._compare_versions(contract_version, min_version) > 0
        
        return True
    
    def _compare_versions(self, v1: str, v2: str) -> int:
        """
        Compare two semantic version strings.
        
        Returns:
            -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
        """
        def normalize_version(v: str) -> List[int]:
            return [int(x) for x in v.split('.')]
        
        v1_parts = normalize_version(v1)
        v2_parts = normalize_version(v2)
        
        # Pad with zeros if needed
        max_len = max(len(v1_parts), len(v2_parts))
        v1_parts.extend([0] * (max_len - len(v1_parts)))
        v2_parts.extend([0] * (max_len - len(v2_parts)))
        
        for p1, p2 in zip(v1_parts, v2_parts):
            if p1 < p2:
                return -1
            elif p1 > p2:
                return 1
        
        return 0
    
    def get_patterns_for_protocol(self, protocol_name: str) -> Dict[str, ProtocolPattern]:
        """Get all patterns for a specific protocol."""
        return self.patterns.get(protocol_name, {})
    
    def get_all_patterns(self) -> Dict[str, Dict[str, ProtocolPattern]]:
        """Get all patterns from all protocols."""
        return self.patterns

