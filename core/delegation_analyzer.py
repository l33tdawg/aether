#!/usr/bin/env python3
"""
Delegation Flow Analyzer - Detects and analyzes proxy delegation patterns.

This module analyzes how functions are called through proxy delegation patterns
to prevent false positives when access control is enforced at the proxy level
but not in the delegated module/implementation contracts.

Solves false positives like:
- Module functions flagged for missing access control when proxy has protection
- UUPS implementation functions flagged when proxy enforces access control
- Diamond facet functions flagged when proxy has protection
"""

import re
from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum


class ProxyType(Enum):
    """Types of proxy patterns."""
    UUPS = "UUPS"  # Universal Upgradeable Proxy Standard
    TRANSPARENT = "Transparent"  # Transparent Proxy
    DIAMOND = "Diamond"  # EIP-2535 Diamond
    BEACON = "Beacon"  # Beacon Proxy
    MINIMAL = "Minimal"  # EIP-1167 Clone
    CUSTOM = "Custom"  # Custom delegation pattern
    NOT_PROXY = "NotProxy"


@dataclass
class DelegationMapping:
    """Maps a function from proxy to its delegated module."""
    function_name: str
    proxy_contract: str
    module_contract: str
    module_enum: Optional[str]  # e.g., "SSV_DAO", "SSV_OPERATORS"
    has_access_control: bool
    access_modifiers: List[str] = field(default_factory=list)  # onlyOwner, etc.
    line_number: int = 0


@dataclass
class ProxyContract:
    """Information about a detected proxy contract."""
    name: str
    file_path: str
    proxy_type: ProxyType
    protected_functions: Set[str] = field(default_factory=set)
    delegations: List[DelegationMapping] = field(default_factory=list)
    module_mappings: Dict[str, str] = field(default_factory=dict)  # module_enum -> contract_name


@dataclass
class ModuleContract:
    """Information about a detected module/implementation contract."""
    name: str
    file_path: str
    is_library: bool
    exposed_functions: Set[str] = field(default_factory=set)
    protected_by_proxy: Set[str] = field(default_factory=set)  # Functions protected at proxy level


@dataclass
class DelegationFlow:
    """Complete delegation flow analysis result."""
    has_proxy_pattern: bool
    proxy_contracts: List[ProxyContract] = field(default_factory=list)
    module_contracts: List[ModuleContract] = field(default_factory=list)
    protected_at_proxy: Set[str] = field(default_factory=set)  # All functions with proxy protection
    confidence: float = 0.0


class DelegationFlowAnalyzer:
    """Analyzes how functions are called through proxy delegation."""
    
    def __init__(self):
        # Proxy indicators
        self.proxy_indicators = {
            ProxyType.UUPS: [
                r'UUPSUpgradeable',
                r'_authorizeUpgrade',
                r'upgradeToAndCall',
                r'ERC1967Upgrade',
            ],
            ProxyType.TRANSPARENT: [
                r'TransparentUpgradeableProxy',
                r'ProxyAdmin',
                r'_admin',
            ],
            ProxyType.DIAMOND: [
                r'DiamondProxy',
                r'LibDiamond',
                r'Facet',
                r'diamondCut',
            ],
            ProxyType.BEACON: [
                r'BeaconProxy',
                r'UpgradeableBeacon',
                r'IBeacon',
            ],
            ProxyType.MINIMAL: [
                r'Clones',
                r'clone\(',
                r'cloneDeterministic',
            ],
        }
        
        # Access control modifiers
        self.access_modifiers = [
            'onlyOwner',
            'onlyRole',
            'onlyAdmin',
            'onlyGovernance',
            'onlyGuardian',
            'auth',
            'authorized',
            'requiresAuth',
        ]
        
        # Delegation patterns
        self.delegation_patterns = [
            r'_delegate\s*\(',  # Custom delegation
            r'delegatecall',    # Low-level delegation
            r'\.functionDelegateCall',  # OpenZeppelin pattern
        ]
    
    def analyze_delegation_flow(self, contract_files: List[Dict[str, Any]]) -> DelegationFlow:
        """
        Analyze delegation flow across all contracts.
        
        Args:
            contract_files: List of dicts with 'content', 'name', 'path' keys
            
        Returns:
            DelegationFlow with complete analysis
        """
        flow = DelegationFlow(has_proxy_pattern=False)
        
        # Step 1: Detect proxy contracts
        for file in contract_files:
            proxy_type = self._detect_proxy_type(file['content'])
            
            if proxy_type != ProxyType.NOT_PROXY:
                proxy = self._analyze_proxy_contract(file, proxy_type)
                flow.proxy_contracts.append(proxy)
                flow.has_proxy_pattern = True
                
                # Add to global protected functions set
                flow.protected_at_proxy.update(proxy.protected_functions)
        
        # Step 2: Detect module/implementation contracts
        if flow.has_proxy_pattern:
            for file in contract_files:
                # Skip proxy contracts themselves
                if any(p.name == file.get('name', '') for p in flow.proxy_contracts):
                    continue
                
                module = self._analyze_module_contract(file, flow.proxy_contracts)
                if module.exposed_functions:  # Only add if it has public functions
                    flow.module_contracts.append(module)
        
        # Step 3: Map which module functions are protected at proxy level
        for proxy in flow.proxy_contracts:
            for delegation in proxy.delegations:
                # Find the corresponding module
                for module in flow.module_contracts:
                    if delegation.module_contract in module.name or module.name in delegation.module_contract:
                        if delegation.has_access_control:
                            module.protected_by_proxy.add(delegation.function_name)
        
        # Step 4: Calculate confidence
        flow.confidence = self._calculate_confidence(flow)
        
        return flow
    
    def _detect_proxy_type(self, content: str) -> ProxyType:
        """Detect the type of proxy pattern used."""
        
        # Check for custom delegation first (most specific)
        if re.search(r'_delegate\s*\(', content):
            # Check if it's also UUPS
            if re.search(r'UUPSUpgradeable', content):
                return ProxyType.UUPS
            return ProxyType.CUSTOM
        
        # Check known patterns
        for proxy_type, indicators in self.proxy_indicators.items():
            match_count = sum(1 for ind in indicators if re.search(ind, content))
            if match_count >= 2:  # Need at least 2 indicators
                return proxy_type
        
        return ProxyType.NOT_PROXY
    
    def _analyze_proxy_contract(self, file: Dict[str, Any], proxy_type: ProxyType) -> ProxyContract:
        """Analyze a proxy contract to extract delegation information."""
        content = file['content']
        name = file.get('name', 'Unknown')
        path = file.get('path', '')
        
        proxy = ProxyContract(
            name=name,
            file_path=path,
            proxy_type=proxy_type
        )
        
        # Extract protected functions
        proxy.protected_functions = self._extract_protected_functions(content)
        
        # Extract delegation mappings
        proxy.delegations = self._extract_delegations(content, name)
        
        # Build module mappings
        for delegation in proxy.delegations:
            if delegation.module_enum:
                proxy.module_mappings[delegation.module_enum] = delegation.module_contract
        
        return proxy
    
    def _extract_protected_functions(self, content: str) -> Set[str]:
        """Extract function names that have access control modifiers."""
        protected = set()
        
        # Pattern: function functionName(...) external/public [modifiers] {
        # Need to handle multiline function signatures
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            # Look for function declarations
            func_match = re.search(r'function\s+(\w+)\s*\(', line)
            if func_match:
                func_name = func_match.group(1)
                
                # Collect all lines until we find the opening brace (for multiline signatures)
                func_lines = []
                for j in range(i, min(i + 15, len(lines))):  # Increased from 5 to 15 lines
                    func_lines.append(lines[j])
                    if '{' in lines[j]:  # Found opening brace
                        break
                
                check_lines = '\n'.join(func_lines)
                
                # Check for access control modifiers
                for modifier in self.access_modifiers:
                    if re.search(r'\b' + modifier + r'\b', check_lines):
                        protected.add(func_name)
                        break
        
        return protected
    
    def _extract_delegations(self, content: str, proxy_name: str) -> List[DelegationMapping]:
        """
        Extract which functions delegate to which modules.
        
        Handles patterns like:
        - function updateNetworkFee(...) external onlyOwner {
              _delegate(SSVStorage.load().ssvContracts[SSVModules.SSV_DAO]);
          }
        """
        delegations = []
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            # Look for function declarations
            func_match = re.search(r'function\s+(\w+)\s*\(', line)
            if func_match:
                func_name = func_match.group(1)
                
                # Get function signature and body (next ~10 lines)
                func_block = '\n'.join(lines[i:min(i+10, len(lines))])
                
                # Check for delegation - look for _delegate and module pattern in same block
                # Patterns to match:
                # - _delegate(SSVStorage.load().ssvContracts[SSVModules.SSV_DAO])
                # - _delegate(modules.MODULE_A)
                # - _delegate(module) - simple pattern
                # - _delegate(storage[SSVModules.DAO])
                if '_delegate' in func_block:
                    # Try to find the module enum reference
                    module_match = re.search(r'(?:SSVModules|modules)\.(\w+)', func_block)
                    if module_match:
                        delegate_match = module_match
                        module_enum = module_match.group(1)
                    else:
                        # Simple pattern: _delegate(variableName)
                        simple_match = re.search(r'_delegate\s*\(\s*(\w+)', func_block)
                        if simple_match:
                            delegate_match = simple_match
                            module_enum = simple_match.group(1)
                        else:
                            delegate_match = None
                            module_enum = None
                else:
                    delegate_match = None
                    module_enum = None
                    
                if delegate_match and module_enum:
                    # Check for access control
                    has_ac = False
                    modifiers = []
                    for modifier in self.access_modifiers:
                        if re.search(r'\b' + modifier + r'\b', func_block):
                            has_ac = True
                            modifiers.append(modifier)
                    
                    delegations.append(DelegationMapping(
                        function_name=func_name,
                        proxy_contract=proxy_name,
                        module_contract=module_enum,
                        module_enum=module_enum,
                        has_access_control=has_ac,
                        access_modifiers=modifiers,
                        line_number=i + 1
                    ))
        
        return delegations
    
    def _analyze_module_contract(self, file: Dict[str, Any], 
                                 proxy_contracts: List[ProxyContract]) -> ModuleContract:
        """Analyze a potential module/implementation contract."""
        content = file['content']
        name = file.get('name', 'Unknown')
        path = file.get('path', '')
        
        # Check if it's a library
        is_library = bool(re.search(r'\blibrary\s+\w+', content))
        
        # Extract external/public functions
        exposed_functions = self._extract_exposed_functions(content)
        
        module = ModuleContract(
            name=name,
            file_path=path,
            is_library=is_library,
            exposed_functions=exposed_functions
        )
        
        return module
    
    def _extract_exposed_functions(self, content: str) -> Set[str]:
        """Extract external and public function names."""
        exposed = set()
        
        # Pattern: function name(...) (external|public)
        pattern = r'function\s+(\w+)\s*\([^)]*\)\s+(?:external|public)'
        
        for match in re.finditer(pattern, content):
            func_name = match.group(1)
            exposed.add(func_name)
        
        return exposed
    
    def _calculate_confidence(self, flow: DelegationFlow) -> float:
        """Calculate confidence in the delegation flow analysis."""
        if not flow.has_proxy_pattern:
            return 1.0  # High confidence there's no proxy
        
        confidence = 0.5  # Base confidence
        
        # Higher confidence if we found delegations
        if any(p.delegations for p in flow.proxy_contracts):
            confidence += 0.3
        
        # Higher confidence if we identified modules
        if flow.module_contracts:
            confidence += 0.2
        
        return min(1.0, confidence)
    
    def is_function_protected_at_proxy(self, function_name: str, 
                                       contract_name: str,
                                       flow: DelegationFlow) -> Tuple[bool, Optional[str]]:
        """
        Check if a function in a module contract is protected at the proxy level.
        
        Returns:
            (is_protected, reason)
        """
        if not flow.has_proxy_pattern:
            return (False, None)
        
        # Check if function is in the protected set
        if function_name in flow.protected_at_proxy:
            # Find which proxy protects it
            for proxy in flow.proxy_contracts:
                for delegation in proxy.delegations:
                    if delegation.function_name == function_name and delegation.has_access_control:
                        modifiers = ', '.join(delegation.access_modifiers)
                        return (True, f"Protected by {proxy.name} with {modifiers}")
        
        # Check if this module's functions are protected
        for module in flow.module_contracts:
            if contract_name in module.name or module.name in contract_name:
                if function_name in module.protected_by_proxy:
                    return (True, f"Protected at proxy level for {module.name}")
        
        return (False, None)
    
    def get_summary(self, flow: DelegationFlow) -> str:
        """Get human-readable summary of delegation flow analysis."""
        if not flow.has_proxy_pattern:
            return "No proxy pattern detected"
        
        lines = [
            f"🔗 Proxy Pattern Detected (confidence: {flow.confidence:.0%})",
            f"   Proxy Contracts: {len(flow.proxy_contracts)}",
        ]
        
        for proxy in flow.proxy_contracts:
            lines.append(f"      • {proxy.name} ({proxy.proxy_type.value})")
            lines.append(f"        - Protected functions: {len(proxy.protected_functions)}")
            lines.append(f"        - Delegations: {len(proxy.delegations)}")
        
        lines.append(f"   Module Contracts: {len(flow.module_contracts)}")
        for module in flow.module_contracts:
            lines.append(f"      • {module.name}")
            lines.append(f"        - Exposed functions: {len(module.exposed_functions)}")
            lines.append(f"        - Protected at proxy: {len(module.protected_by_proxy)}")
        
        lines.append(f"   Total functions protected at proxy level: {len(flow.protected_at_proxy)}")
        
        return '\n'.join(lines)


if __name__ == "__main__":
    # Quick test
    analyzer = DelegationFlowAnalyzer()
    
    # Test with SSV Network pattern
    test_contracts = [
        {
            'name': 'SSVNetwork.sol',
            'path': 'contracts/SSVNetwork.sol',
            'content': '''
                contract SSVNetwork is UUPSUpgradeable, Ownable2StepUpgradeable {
                    function updateNetworkFee(uint256 fee) external override onlyOwner {
                        _delegate(SSVStorage.load().ssvContracts[SSVModules.SSV_DAO]);
                    }
                    
                    function withdrawNetworkEarnings(uint256 amount) external override onlyOwner {
                        _delegate(SSVStorage.load().ssvContracts[SSVModules.SSV_DAO]);
                    }
                }
            '''
        },
        {
            'name': 'SSVDAO.sol',
            'path': 'contracts/modules/SSVDAO.sol',
            'content': '''
                contract SSVDAO is ISSVDAO {
                    function updateNetworkFee(uint256 fee) external override {
                        StorageProtocol storage sp = SSVStorageProtocol.load();
                        sp.updateNetworkFee(fee);
                    }
                    
                    function withdrawNetworkEarnings(uint256 amount) external override {
                        CoreLib.transferBalance(msg.sender, amount);
                    }
                }
            '''
        }
    ]
    
    flow = analyzer.analyze_delegation_flow(test_contracts)
    print(analyzer.get_summary(flow))
    
    # Test protection check
    is_protected, reason = analyzer.is_function_protected_at_proxy(
        'updateNetworkFee', 
        'SSVDAO.sol',
        flow
    )
    print(f"\nIs updateNetworkFee protected? {is_protected}")
    if reason:
        print(f"Reason: {reason}")

