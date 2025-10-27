#!/usr/bin/env python3
"""
Architectural Pattern Detection - Recognizes common DeFi/Solidity patterns.

This module detects and validates architectural patterns in smart contracts
to avoid false positives from pattern-specific access control mechanisms.

Solves false positives like:
- Diamond proxy libraries flagged for missing direct access control
- UUPS proxies flagged for delegatecall usage
- Transparent proxies flagged for admin-only functions
"""

from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
import re


@dataclass
class ArchitecturalPattern:
    """Detected architectural pattern."""
    pattern_type: str  # "EIP2535_Diamond", "UUPS_Proxy", "Transparent_Proxy", etc.
    components: Dict[str, List[str]] = field(default_factory=dict)  # Component type -> file list
    access_control_layer: str = "contract"  # Where to check for AC
    validation_rules: Dict[str, any] = field(default_factory=dict)
    confidence: float = 0.8
    indicators_found: Set[str] = field(default_factory=set)


class ArchitecturalPatternDetector:
    """Detects and validates architectural patterns in smart contracts."""
    
    def __init__(self):
        self.patterns = {
            'EIP2535_Diamond': {
                'description': 'EIP-2535 Diamond Proxy Pattern',
                'indicators': [
                    'DiamondProxy',
                    'LibDiamond',
                    'Facet',
                    'diamondCut',
                    'FacetCut',
                    'delegatecall',
                    'facetAddress',
                    'selectorInfo',
                    'FacetCutAction'
                ],
                'min_indicators': 4,  # Need at least 4 indicators to confidently identify
                'access_control_layer': 'facet',
                'validation_rules': {
                    'facets_must_have_modifiers': True,
                    'libraries_can_skip_modifiers': True,
                    'constructor_init_allowed': True,
                    'internal_functions_skip_ac': True,
                },
                'file_patterns': {
                    'proxy': r'DiamondProxy',
                    'library': r'Lib\w+',
                    'facet': r'\w+Facet',
                }
            },
            'UUPS_Proxy': {
                'description': 'Universal Upgradeable Proxy Standard (UUPS)',
                'indicators': [
                    'UUPSUpgradeable',
                    '_authorizeUpgrade',
                    'upgradeToAndCall',
                    'upgradeTo',
                    'ERC1967Upgrade',
                    'proxiableUUID',
                ],
                'min_indicators': 3,
                'access_control_layer': 'implementation',
                'validation_rules': {
                    'upgrade_must_be_protected': True,
                    'delegatecall_in_upgrade': True,
                },
                'file_patterns': {
                    'implementation': r'(?:Implementation|Upgradeable)',
                }
            },
            'Transparent_Proxy': {
                'description': 'Transparent Upgradeable Proxy',
                'indicators': [
                    'TransparentUpgradeableProxy',
                    'ProxyAdmin',
                    '_admin',
                    'changeAdmin',
                    'ERC1967Proxy',
                ],
                'min_indicators': 3,
                'access_control_layer': 'proxy_admin',
                'validation_rules': {
                    'admin_only_upgrade': True,
                    'implementation_separate': True,
                }
            },
            'Beacon_Proxy': {
                'description': 'Beacon Proxy Pattern',
                'indicators': [
                    'BeaconProxy',
                    'UpgradeableBeacon',
                    '_beacon',
                    '_implementation',
                    'IBeacon',
                ],
                'min_indicators': 3,
                'access_control_layer': 'beacon',
                'validation_rules': {
                    'beacon_owns_implementation': True,
                }
            },
            'Minimal_Proxy': {
                'description': 'Minimal Proxy (EIP-1167 Clone)',
                'indicators': [
                    'Clones',
                    'clone',
                    'cloneDeterministic',
                    'EIP1167',
                    'minimal proxy',
                ],
                'min_indicators': 2,
                'access_control_layer': 'implementation',
                'validation_rules': {
                    'immutable_implementation': True,
                }
            }
        }
    
    def detect_pattern(self, contract_files: List[Dict]) -> Optional[ArchitecturalPattern]:
        """
        Detect which architectural pattern (if any) is being used.
        
        Args:
            contract_files: List of dicts with 'content', 'name', 'path'
            
        Returns:
            ArchitecturalPattern if detected, None otherwise
        """
        # Combine all content for pattern matching
        all_content = '\n'.join([f['content'] for f in contract_files])
        all_filenames = [f['name'] for f in contract_files]
        
        best_match = None
        best_score = 0
        
        for pattern_name, pattern_def in self.patterns.items():
            indicators_found = set()
            
            # Check for indicators in code
            for indicator in pattern_def['indicators']:
                if indicator in all_content:
                    indicators_found.add(indicator)
            
            # Calculate match score
            match_score = len(indicators_found)
            min_required = pattern_def['min_indicators']
            
            # If we have enough indicators, this is a potential match
            if match_score >= min_required:
                # Calculate confidence based on how many indicators we found
                confidence = min(0.95, 0.5 + (match_score / len(pattern_def['indicators'])) * 0.5)
                
                if match_score > best_score:
                    best_score = match_score
                    
                    # Extract components
                    components = self._extract_components(
                        contract_files, 
                        pattern_def.get('file_patterns', {})
                    )
                    
                    best_match = ArchitecturalPattern(
                        pattern_type=pattern_name,
                        components=components,
                        access_control_layer=pattern_def['access_control_layer'],
                        validation_rules=pattern_def['validation_rules'],
                        confidence=confidence,
                        indicators_found=indicators_found
                    )
        
        return best_match
    
    def _extract_components(self, contract_files: List[Dict], file_patterns: Dict[str, str]) -> Dict[str, List[str]]:
        """Extract component files based on patterns."""
        components = {}
        
        for component_type, pattern in file_patterns.items():
            matching_files = []
            
            for file in contract_files:
                if re.search(pattern, file['name']):
                    matching_files.append(file['name'])
            
            if matching_files:
                components[component_type] = matching_files
        
        return components
    
    def adjust_finding_for_pattern(self, finding: Dict, pattern: ArchitecturalPattern) -> Dict:
        """
        Adjust finding severity/validity based on architectural pattern.
        
        Args:
            finding: Vulnerability finding dict
            pattern: Detected architectural pattern
            
        Returns:
            Modified finding dict with adjusted severity/false_positive status
        """
        if pattern.pattern_type == 'EIP2535_Diamond':
            return self._adjust_for_diamond_pattern(finding, pattern)
        elif pattern.pattern_type == 'UUPS_Proxy':
            return self._adjust_for_uups_pattern(finding, pattern)
        elif pattern.pattern_type == 'Transparent_Proxy':
            return self._adjust_for_transparent_proxy(finding, pattern)
        
        return finding
    
    def _adjust_for_diamond_pattern(self, finding: Dict, pattern: ArchitecturalPattern) -> Dict:
        """Adjust findings for Diamond proxy pattern."""
        vuln_type = finding.get('vulnerability_type', '')
        contract_name = finding.get('contract_name', '')
        
        # Check if finding is in a library
        is_library = 'Lib' in contract_name or any('Lib' in comp for comp in pattern.components.get('library', []))
        
        # Check if finding is about access control
        is_access_control = vuln_type in ['access_control', 'authorization', 'upgrade_authorization']
        
        if is_library and is_access_control:
            # Libraries in Diamond pattern don't need direct access control
            # Access control is enforced at the facet level
            finding['is_false_positive'] = True
            finding['false_positive_reason'] = (
                f"Diamond Pattern (EIP-2535): Libraries don't require direct access control. "
                f"Access control enforced at facet level ({pattern.access_control_layer}). "
                f"Library functions are only callable through protected facets."
            )
            finding['architectural_pattern'] = pattern.pattern_type
            finding['confidence'] = max(0.1, finding.get('confidence', 0.8) - 0.5)  # Reduce confidence
            
            if self.verbose_mode():
                print(f"   🏗️  Adjusted: {contract_name} is part of Diamond pattern - library access control check skipped")
        
        # Check for constructor issues in Diamond proxy
        if 'constructor' in finding.get('description', '').lower():
            if 'DiamondProxy' in contract_name:
                finding['is_false_positive'] = True
                finding['false_positive_reason'] = (
                    "Diamond Pattern: Constructor initialization is standard deployment pattern. "
                    "Proxy is initialized with facets during deployment by deployer."
                )
        
        # Check for delegatecall in libraries (expected in Diamond pattern)
        if 'delegatecall' in finding.get('code_snippet', '').lower() and is_library:
            finding['severity'] = 'info'
            finding['context'] = finding.get('context', {})
            finding['context']['architectural_note'] = (
                "delegatecall is expected in Diamond pattern libraries for initialization"
            )
        
        return finding
    
    def _adjust_for_uups_pattern(self, finding: Dict, pattern: ArchitecturalPattern) -> Dict:
        """Adjust findings for UUPS proxy pattern (enhanced for delegation)."""
        vuln_type = finding.get('vulnerability_type', '').lower()
        contract_name = finding.get('contract_name', '')
        file_path = finding.get('file_path', '')
        
        # Check for upgrade authorization
        if vuln_type == 'upgrade_authorization':
            # Check if _authorizeUpgrade is protected
            code_snippet = finding.get('code_snippet', '')
            if '_authorizeUpgrade' in code_snippet:
                # This is expected - don't flag as vulnerability if it has modifiers
                if any(modifier in code_snippet for modifier in ['onlyOwner', 'onlyRole', 'onlyAdmin']):
                    finding['is_false_positive'] = True
                    finding['false_positive_reason'] = (
                        "UUPS Pattern: _authorizeUpgrade is properly protected with access control modifier"
                    )
        
        # NEW: Check if this is an implementation/module contract
        is_implementation = self._is_implementation_contract(contract_name, file_path, pattern)
        
        # NEW: Access control findings in implementation contracts
        if is_implementation and any(keyword in vuln_type for keyword in ['access', 'authorization', 'unprotected']):
            # Note: This is a basic check. The DelegationFlowAnalyzer will do a more thorough job
            # We mark it as potentially false positive for manual review
            finding['context'] = finding.get('context', {})
            finding['context']['architectural_note'] = (
                "UUPS Pattern: This appears to be an implementation contract. "
                "Access control may be enforced at the proxy level via delegation. "
                "Verify proxy contract for protection."
            )
            
            if self.verbose_mode():
                print(f"   🏗️  Note: {contract_name} appears to be UUPS implementation - check proxy for access control")
        
        # NEW: Constructor warnings in proxy contracts
        if 'constructor' in finding.get('description', '').lower():
            code_snippet = finding.get('code_snippet', '')
            if 'disableInitializers' in code_snippet or '_disableInitializers' in code_snippet:
                finding['is_false_positive'] = True
                finding['false_positive_reason'] = (
                    "UUPS Pattern: _disableInitializers() in constructor is correct pattern "
                    "to prevent initialization of implementation contract"
                )
        
        return finding
    
    def _is_implementation_contract(self, contract_name: str, file_path: str, 
                                   pattern: ArchitecturalPattern) -> bool:
        """Check if contract is an implementation/module contract in UUPS pattern."""
        # Check for implementation in components
        impl_components = pattern.components.get('implementation', [])
        if any(impl in contract_name or contract_name in impl for impl in impl_components):
            return True
        
        # Check for common implementation path patterns
        impl_indicators = ['/implementations/', '/modules/', '/contracts/']
        if file_path and any(indicator in file_path for indicator in impl_indicators):
            # But not if it's the main proxy file
            if 'proxy' not in contract_name.lower() and 'network' in contract_name.lower():
                return False
            if 'proxy' not in file_path.lower():
                return True
        
        return False
    
    def _adjust_for_transparent_proxy(self, finding: Dict, pattern: ArchitecturalPattern) -> Dict:
        """Adjust findings for Transparent proxy pattern."""
        # In transparent proxies, admin functions are expected to be separate
        # This is a placeholder for future enhancements
        return finding
    
    def verbose_mode(self) -> bool:
        """Check if verbose mode is enabled (from environment or config)."""
        import os
        return os.getenv('AETHER_VERBOSE', '').lower() in ['1', 'true', 'yes']
    
    def get_pattern_description(self, pattern: ArchitecturalPattern) -> str:
        """Get human-readable description of detected pattern."""
        pattern_def = self.patterns.get(pattern.pattern_type, {})
        description = pattern_def.get('description', pattern.pattern_type)
        
        output = [f"📐 Detected Pattern: {description}"]
        output.append(f"   Confidence: {pattern.confidence:.0%}")
        output.append(f"   Indicators Found: {', '.join(sorted(pattern.indicators_found))}")
        
        if pattern.components:
            output.append(f"   Components:")
            for comp_type, files in pattern.components.items():
                output.append(f"      - {comp_type}: {', '.join(files)}")
        
        output.append(f"   Access Control Layer: {pattern.access_control_layer}")
        
        return '\n'.join(output)

