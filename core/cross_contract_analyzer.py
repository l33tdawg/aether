#!/usr/bin/env python3
"""
Cross-Contract Analyzer

Analyzes access control across contract boundaries by following external contract calls.
Addresses the issue of missing cross-contract access control analysis.
"""

import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field


@dataclass
class ExternalCallInfo:
    """Information about an external contract call."""
    contract_reference: str  # e.g., "L1_NULLIFIER"
    function_name: str       # e.g., "transferTokenToNTV"
    line_number: int
    has_access_control: bool
    access_control_details: str
    contract_type: str = ""  # e.g., "IL1Nullifier"
    is_immutable: bool = False


@dataclass
class CrossContractAccessResult:
    """Result of cross-contract access control analysis."""
    has_access_control: bool
    reasoning: str
    confidence: float
    external_calls_analyzed: int
    protected_calls: int
    call_details: List[ExternalCallInfo] = field(default_factory=list)


class CrossContractAnalyzer:
    """Analyzes access control across contract boundaries."""

    # Known access control modifiers
    ACCESS_CONTROL_MODIFIERS = [
        'onlyOwner', 'onlyRole', 'onlyAdmin', 'onlyGuardian',
        'onlyL1NTV', 'onlyAssetRouter', 'onlyLegacyBridge',
        'restricted', 'requiresAuth', 'onlyAuthorized',
        'onlyTrusted', 'onlyTrustedOrRestricted', 'onlyGovernance',
        'onlyGovernor', 'onlyManager', 'onlyOwnerOrGuardian',
        'whenNotPaused', 'nonReentrant'
    ]

    # Safe view functions that don't need access control analysis
    SAFE_VIEW_FUNCTIONS = [
        'balanceOf', 'allowance', 'totalSupply', 'name', 'symbol',
        'decimals', 'owner', 'getReserves', 'slot0', 'positions',
        'liquidity', 'fee', 'tickSpacing', 'token0', 'token1'
    ]

    def __init__(self, project_root: Optional[Path] = None):
        self.project_root = project_root
        self.contract_cache: Dict[str, str] = {}  # contract_name -> content
        self.interface_cache: Dict[str, str] = {}  # interface_name -> content

    def analyze_external_calls(
        self,
        function_code: str,
        current_contract_code: str,
        current_contract_path: Optional[Path] = None
    ) -> List[ExternalCallInfo]:
        """
        Identify and analyze external contract calls in a function.
        
        Args:
            function_code: The function body to analyze
            current_contract_code: Full contract source code
            current_contract_path: Path to current contract file
            
        Returns:
            List of ExternalCallInfo for each external call found
        """
        external_calls = []
        lines = function_code.split('\n')

        for i, line in enumerate(lines, 1):
            # Skip comments
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*'):
                continue

            # Pattern 1: Immutable reference call: L1_NULLIFIER.transferTokenToNTV(...)
            immutable_pattern = r'(\w+)\.(\w+)\s*\('
            matches = re.finditer(immutable_pattern, line)

            for match in matches:
                contract_ref = match.group(1)
                func_name = match.group(2)

                # Skip self-references and keywords
                if contract_ref in ['this', 'super', 'address', 'msg', 'block', 'tx', 'abi', 'type']:
                    continue

                # Skip safe view functions
                if func_name in self.SAFE_VIEW_FUNCTIONS:
                    continue

                # Check if this is an immutable/state variable reference
                is_immutable = self._is_immutable_reference(contract_ref, current_contract_code)
                contract_type = self._get_contract_type(contract_ref, current_contract_code)

                # Check access control on the called function
                access_info = self._check_external_function_access_control(
                    contract_ref,
                    func_name,
                    contract_type,
                    current_contract_code,
                    current_contract_path
                )

                external_calls.append(ExternalCallInfo(
                    contract_reference=contract_ref,
                    function_name=func_name,
                    line_number=i,
                    has_access_control=access_info['has_access_control'],
                    access_control_details=access_info['details'],
                    contract_type=contract_type,
                    is_immutable=is_immutable
                ))

            # Pattern 2: Interface cast call: IContract(addr).function(...)
            cast_pattern = r'(I\w+)\s*\(\s*(\w+)\s*\)\s*\.(\w+)\s*\('
            cast_matches = re.finditer(cast_pattern, line)

            for match in cast_matches:
                interface_type = match.group(1)
                address_var = match.group(2)
                func_name = match.group(3)

                # Skip safe view functions
                if func_name in self.SAFE_VIEW_FUNCTIONS:
                    continue

                # Check access control
                access_info = self._check_external_function_access_control(
                    address_var,
                    func_name,
                    interface_type,
                    current_contract_code,
                    current_contract_path
                )

                external_calls.append(ExternalCallInfo(
                    contract_reference=address_var,
                    function_name=func_name,
                    line_number=i,
                    has_access_control=access_info['has_access_control'],
                    access_control_details=access_info['details'],
                    contract_type=interface_type,
                    is_immutable=False
                ))

        return external_calls

    def _is_immutable_reference(self, var_name: str, contract_code: str) -> bool:
        """Check if variable is an immutable contract reference."""
        # Pattern: address immutable L1_NULLIFIER or IL1Nullifier immutable L1_NULLIFIER
        patterns = [
            rf'(?:address|I\w+)\s+(?:public\s+)?immutable\s+(?:override\s+)?{re.escape(var_name)}',
            rf'immutable\s+(?:public\s+)?(?:address|I\w+)\s+(?:override\s+)?{re.escape(var_name)}',
        ]
        return any(re.search(p, contract_code) for p in patterns)

    def _get_contract_type(self, var_name: str, contract_code: str) -> str:
        """Get the contract/interface type for a variable."""
        patterns = [
            rf'(I\w+)\s+(?:public\s+)?(?:immutable\s+)?(?:override\s+)?{re.escape(var_name)}',
            rf'(I\w+)\s+{re.escape(var_name)}',
            rf'address\s+(?:public\s+)?(?:immutable\s+)?{re.escape(var_name)}',
        ]

        for pattern in patterns:
            match = re.search(pattern, contract_code)
            if match:
                if match.lastindex and match.lastindex >= 1:
                    return match.group(1)
                return 'address'

        return ""

    def _check_external_function_access_control(
        self,
        contract_ref: str,
        func_name: str,
        contract_type: str,
        current_contract_code: str,
        current_contract_path: Optional[Path]
    ) -> Dict:
        """
        Check if the called function in external contract has access control.
        
        Strategy:
        1. Find the contract/interface type
        2. Locate the actual contract implementation
        3. Check for access control on the target function
        """
        result = {
            'has_access_control': False,
            'details': '',
            'modifiers_found': []
        }

        if not contract_type:
            result['details'] = f"Could not determine type for {contract_ref}"
            return result

        # Try to find the actual contract implementation
        if self.project_root and contract_type.startswith('I'):
            # Interface name like IL1Nullifier -> look for L1Nullifier.sol
            impl_name = contract_type[1:]  # Remove 'I' prefix

            contract_content = self._find_contract_content(
                impl_name,
                current_contract_path
            )

            if contract_content:
                # Check access control on target function
                modifiers = self._find_function_access_control(func_name, contract_content)

                if modifiers:
                    result['has_access_control'] = True
                    result['modifiers_found'] = modifiers
                    result['details'] = f"{contract_ref}.{func_name}() is protected by: {', '.join(modifiers)}"
                else:
                    # Check if function has internal access checks
                    has_internal_checks = self._check_internal_access_control(
                        func_name, contract_content
                    )
                    if has_internal_checks:
                        result['has_access_control'] = True
                        result['details'] = f"{contract_ref}.{func_name}() has internal access control checks"
                    else:
                        result['details'] = f"{contract_ref}.{func_name}() - no access control found"
            else:
                result['details'] = f"Could not locate implementation for {contract_type}"
        else:
            result['details'] = f"Cannot analyze non-interface type or no project root: {contract_type}"

        return result

    def _find_contract_content(
        self,
        contract_name: str,
        current_path: Optional[Path]
    ) -> Optional[str]:
        """Find and load contract content by name."""
        if contract_name in self.contract_cache:
            return self.contract_cache[contract_name]

        if not self.project_root:
            return None

        # Search strategies
        search_names = [
            f"{contract_name}.sol",
            f"I{contract_name}.sol",  # Interface might have implementation
        ]

        # Check relative to current contract first
        if current_path:
            parent_dir = current_path.parent
            for name in search_names:
                candidate = parent_dir / name
                if candidate.exists():
                    try:
                        content = candidate.read_text(encoding='utf-8', errors='ignore')
                        if f'contract {contract_name}' in content:
                            self.contract_cache[contract_name] = content
                            return content
                    except Exception:
                        continue

        # Search project-wide
        try:
            for sol_file in self.project_root.rglob("*.sol"):
                try:
                    content = sol_file.read_text(encoding='utf-8', errors='ignore')
                    if f'contract {contract_name}' in content or f'contract {contract_name} ' in content:
                        self.contract_cache[contract_name] = content
                        return content
                except Exception:
                    continue
        except Exception:
            pass

        return None

    def _find_function_access_control(
        self,
        func_name: str,
        contract_content: str
    ) -> List[str]:
        """Find access control modifiers on a function."""
        # Pattern to find function with modifiers
        pattern = rf'function\s+{re.escape(func_name)}\s*\([^)]*\)\s+([^{{]+)\{{'
        match = re.search(pattern, contract_content, re.DOTALL)

        if not match:
            return []

        modifiers_section = match.group(1)

        found_modifiers = []
        for modifier in self.ACCESS_CONTROL_MODIFIERS:
            if modifier in modifiers_section:
                found_modifiers.append(modifier)

        # Also check for custom modifiers with "only" prefix
        custom_only_modifiers = re.findall(r'\b(only\w+)\b', modifiers_section)
        for mod in custom_only_modifiers:
            if mod not in found_modifiers:
                found_modifiers.append(mod)

        return found_modifiers

    def _check_internal_access_control(
        self,
        func_name: str,
        contract_content: str
    ) -> bool:
        """Check if function has internal access control (require/if statements)."""
        # Find function body
        pattern = rf'function\s+{re.escape(func_name)}\s*\([^)]*\)\s*[^{{]*\{{'
        match = re.search(pattern, contract_content)

        if not match:
            return False

        # Extract function body
        start = match.end()
        brace_count = 1
        end = start

        while end < len(contract_content) and brace_count > 0:
            if contract_content[end] == '{':
                brace_count += 1
            elif contract_content[end] == '}':
                brace_count -= 1
            end += 1

        func_body = contract_content[start:end]

        # Check for access control patterns
        access_patterns = [
            r'require\s*\([^)]*msg\.sender',
            r'if\s*\([^)]*msg\.sender[^)]*\)\s*revert',
            r'_checkCanCall\(',
            r'_checkRole\(',
            r'_checkOwner\(',
            r'onlyOwner',
        ]

        return any(re.search(p, func_body) for p in access_patterns)

    def enhance_access_control_check(
        self,
        vuln: Dict,
        function_code: str,
        contract_code: str,
        contract_path: Optional[Path] = None
    ) -> CrossContractAccessResult:
        """
        Enhanced access control check that includes cross-contract analysis.
        
        Args:
            vuln: Vulnerability dict
            function_code: The vulnerable function's code
            contract_code: Full contract source code
            contract_path: Path to the contract file
            
        Returns:
            CrossContractAccessResult with analysis details
        """
        # Analyze external calls
        external_calls = self.analyze_external_calls(
            function_code,
            contract_code,
            contract_path
        )

        # Filter to protected calls
        protected_calls = [c for c in external_calls if c.has_access_control]

        if protected_calls:
            details = "; ".join([c.access_control_details for c in protected_calls])
            return CrossContractAccessResult(
                has_access_control=True,
                reasoning=f"Protected via external call access control: {details}",
                confidence=0.90,
                external_calls_analyzed=len(external_calls),
                protected_calls=len(protected_calls),
                call_details=external_calls
            )

        return CrossContractAccessResult(
            has_access_control=False,
            reasoning='No access control found in function or external calls',
            confidence=0.70,
            external_calls_analyzed=len(external_calls),
            protected_calls=0,
            call_details=external_calls
        )

    def is_permissionless_but_safe(
        self,
        function_code: str,
        contract_code: str,
        contract_path: Optional[Path] = None
    ) -> Tuple[bool, str]:
        """
        Check if a permissionless function is safe because external calls enforce access.
        
        Example: transferFundsFromSharedBridge() is permissionless but calls
        L1_NULLIFIER.transferTokenToNTV() which requires onlyL1NTV.
        
        Returns:
            Tuple of (is_safe, reasoning)
        """
        external_calls = self.analyze_external_calls(
            function_code,
            contract_code,
            contract_path
        )

        # Check if any critical external call has access control
        # that effectively protects the function
        for call in external_calls:
            if call.has_access_control and call.is_immutable:
                return (
                    True,
                    f"Function is permissionless but protected by {call.contract_reference}.{call.function_name}() "
                    f"which requires {call.access_control_details}"
                )

        return (False, "No protective external access control found")
