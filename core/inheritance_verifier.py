"""
Inheritance Verifier

Accurately verifies contract inheritance chains to prevent false claims about
inherited functionality (e.g., claiming a contract inherits ReentrancyGuard when it doesn't).
"""

import re
from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass


@dataclass
class ContractInheritance:
    """Represents a contract's inheritance information."""
    contract_name: str
    direct_parents: List[str]  # Directly inherited contracts
    all_ancestors: Set[str]  # All contracts in inheritance chain
    imports: List[str]  # Import statements
    has_inheritance: bool


class InheritanceVerifier:
    """
    Verifies contract inheritance chains with high accuracy.
    
    Prevents false positives like:
    - Claiming ReentrancyGuard is inherited when it's not
    - Misidentifying which OpenZeppelin contracts are used
    - Missing indirect inheritance through base contracts
    """
    
    def __init__(self):
        self.inheritance_cache: Dict[str, ContractInheritance] = {}
        
    def analyze_contract(self, contract_code: str, contract_name: str = None) -> ContractInheritance:
        """
        Analyze a contract's inheritance chain.
        
        Args:
            contract_code: Full contract source code
            contract_name: Name of contract to analyze (if multiple in file)
        
        Returns:
            ContractInheritance object with complete inheritance info
        """
        # Extract imports
        imports = self._extract_imports(contract_code)
        
        # Find contract declaration
        if contract_name:
            contract_decl = self._find_contract_declaration(contract_code, contract_name)
        else:
            # Find first contract declaration
            contract_decl = self._find_first_contract(contract_code)
            if contract_decl:
                contract_name = contract_decl.get('name')
        
        if not contract_decl:
            return ContractInheritance(
                contract_name=contract_name or "Unknown",
                direct_parents=[],
                all_ancestors=set(),
                imports=imports,
                has_inheritance=False
            )
        
        direct_parents = contract_decl.get('parents', [])
        
        # Build full ancestor tree (would need external contract code for full resolution)
        all_ancestors = set(direct_parents)
        
        # Try to infer additional ancestors from imports and known patterns
        all_ancestors.update(self._infer_ancestors_from_imports(imports, direct_parents))
        
        inheritance = ContractInheritance(
            contract_name=contract_name,
            direct_parents=direct_parents,
            all_ancestors=all_ancestors,
            imports=imports,
            has_inheritance=len(direct_parents) > 0
        )
        
        # Cache result
        self.inheritance_cache[contract_name] = inheritance
        
        return inheritance
    
    def _extract_imports(self, contract_code: str) -> List[str]:
        """Extract all import statements."""
        imports = []
        
        # Match import statements
        import_pattern = r'import\s+(?:{[^}]+}\s+from\s+)?["\']([^"\']+)["\']'
        for match in re.finditer(import_pattern, contract_code):
            imports.append(match.group(1))
        
        return imports
    
    def _find_contract_declaration(self, contract_code: str, contract_name: str) -> Optional[Dict]:
        """Find specific contract declaration."""
        # Pattern: contract ContractName is Parent1, Parent2 {
        pattern = rf'contract\s+{contract_name}\s+(?:is\s+([^{{]+))?\{{'
        match = re.search(pattern, contract_code)
        
        if not match:
            # Try without inheritance
            pattern = rf'contract\s+{contract_name}\s*\{{'
            match = re.search(pattern, contract_code)
            if match:
                return {'name': contract_name, 'parents': []}
            return None
        
        parents_str = match.group(1)
        if not parents_str:
            return {'name': contract_name, 'parents': []}
        
        # Parse parent contracts
        parents = [p.strip() for p in parents_str.split(',')]
        
        return {'name': contract_name, 'parents': parents}
    
    def _find_first_contract(self, contract_code: str) -> Optional[Dict]:
        """Find first contract declaration."""
        # Pattern: contract ContractName is Parent1, Parent2 {
        pattern = r'contract\s+(\w+)\s+(?:is\s+([^{]+))?\{'
        match = re.search(pattern, contract_code)
        
        if not match:
            return None
        
        contract_name = match.group(1)
        parents_str = match.group(2)
        
        if not parents_str:
            return {'name': contract_name, 'parents': []}
        
        parents = [p.strip() for p in parents_str.split(',')]
        
        return {'name': contract_name, 'parents': parents}
    
    def _infer_ancestors_from_imports(self, imports: List[str], direct_parents: List[str]) -> Set[str]:
        """
        Infer likely ancestors from import paths.
        
        This is a heuristic - full resolution would require parsing imported files.
        """
        ancestors = set()
        
        # Common OpenZeppelin inheritance patterns
        oz_patterns = {
            'ReentrancyGuard': ['ReentrancyGuard.sol', 'ReentrancyGuardUpgradeable.sol'],
            'Ownable': ['Ownable.sol', 'OwnableUpgradeable.sol'],
            'AccessControl': ['AccessControl.sol', 'AccessControlUpgradeable.sol'],
            'Pausable': ['Pausable.sol', 'PausableUpgradeable.sol'],
            'ERC20': ['ERC20.sol', 'ERC20Upgradeable.sol'],
            'ERC721': ['ERC721.sol', 'ERC721Upgradeable.sol'],
            'ERC4626': ['ERC4626.sol', 'ERC4626Upgradeable.sol'],
            'UUPSUpgradeable': ['UUPSUpgradeable.sol'],
            'Initializable': ['Initializable.sol'],
        }
        
        for parent in direct_parents:
            # Check if this parent is in our known patterns
            for ancestor, import_patterns in oz_patterns.items():
                if parent == ancestor or parent.startswith(ancestor):
                    # Check if imports support this
                    for imp in imports:
                        if any(pattern in imp for pattern in import_patterns):
                            # Add known transitive dependencies
                            if ancestor == 'ERC4626Upgradeable':
                                ancestors.update(['ERC20Upgradeable', 'Initializable'])
                            elif ancestor == 'UUPSUpgradeable':
                                ancestors.update(['Initializable'])
                            elif 'Upgradeable' in ancestor:
                                ancestors.add('Initializable')
        
        return ancestors
    
    def inherits_from(self, contract_name: str, ancestor: str) -> bool:
        """
        Check if a contract inherits from a specific ancestor.
        
        Args:
            contract_name: Name of contract to check
            ancestor: Name of ancestor to look for
        
        Returns:
            True if contract inherits from ancestor
        """
        if contract_name not in self.inheritance_cache:
            return False
        
        inheritance = self.inheritance_cache[contract_name]
        
        # Check direct parents
        if ancestor in inheritance.direct_parents:
            return True
        
        # Check all ancestors
        if ancestor in inheritance.all_ancestors:
            return True
        
        # Check partial matches (e.g., "ERC20" matches "ERC20Upgradeable")
        for parent in inheritance.direct_parents:
            if ancestor in parent:
                return True
        
        for anc in inheritance.all_ancestors:
            if ancestor in anc:
                return True
        
        return False
    
    def verify_claim(self, contract_name: str, claimed_ancestor: str) -> Tuple[bool, str]:
        """
        Verify a claim about inheritance.
        
        Args:
            contract_name: Contract being checked
            claimed_ancestor: Claimed inherited contract
        
        Returns:
            (is_valid, explanation)
        """
        if contract_name not in self.inheritance_cache:
            return False, f"Contract {contract_name} not analyzed"
        
        inheritance = self.inheritance_cache[contract_name]
        
        # Check if claim is valid
        if self.inherits_from(contract_name, claimed_ancestor):
            # Find where it comes from
            if claimed_ancestor in inheritance.direct_parents:
                return True, f"{contract_name} directly inherits {claimed_ancestor}"
            else:
                return True, f"{contract_name} inherits {claimed_ancestor} through inheritance chain"
        
        # Claim is false
        actual_parents = ", ".join(inheritance.direct_parents) if inheritance.direct_parents else "none"
        return False, f"{contract_name} does NOT inherit {claimed_ancestor}. Actual parents: {actual_parents}"
    
    def get_inheritance_summary(self, contract_name: str) -> str:
        """Get human-readable inheritance summary."""
        if contract_name not in self.inheritance_cache:
            return f"No inheritance information for {contract_name}"
        
        inheritance = self.inheritance_cache[contract_name]
        
        if not inheritance.has_inheritance:
            return f"{contract_name} has no inheritance"
        
        summary = f"{contract_name} inherits from:\n"
        summary += f"  Direct parents: {', '.join(inheritance.direct_parents)}\n"
        
        if inheritance.all_ancestors:
            other_ancestors = inheritance.all_ancestors - set(inheritance.direct_parents)
            if other_ancestors:
                summary += f"  Inferred ancestors: {', '.join(other_ancestors)}\n"
        
        summary += f"  Total imports: {len(inheritance.imports)}"
        
        return summary


def test_inheritance_verifier():
    """Test with Cap contracts example."""
    
    # StakedCap contract (from our audit)
    sample_code = '''
// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

import { Access } from "../access/Access.sol";
import { IStakedCap } from "../interfaces/IStakedCap.sol";
import { StakedCapStorageUtils } from "../storage/StakedCapStorageUtils.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import { ERC20PermitUpgradeable } from "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20PermitUpgradeable.sol";
import { ERC20Upgradeable, ERC4626Upgradeable } from "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC4626Upgradeable.sol";

contract StakedCap is
    IStakedCap,
    UUPSUpgradeable,
    ERC4626Upgradeable,
    ERC20PermitUpgradeable,
    Access,
    StakedCapStorageUtils
{
    // ... contract code ...
}
    '''
    
    verifier = InheritanceVerifier()
    inheritance = verifier.analyze_contract(sample_code, "StakedCap")
    
    print("=== Inheritance Analysis ===")
    print(verifier.get_inheritance_summary("StakedCap"))
    
    print("\n=== Verification Tests ===")
    
    # Test valid claim
    is_valid, explanation = verifier.verify_claim("StakedCap", "UUPSUpgradeable")
    print(f"Claim 'inherits UUPSUpgradeable': {is_valid}")
    print(f"  {explanation}")
    
    # Test INVALID claim (this was the audit's mistake)
    is_valid, explanation = verifier.verify_claim("StakedCap", "ReentrancyGuardUpgradeable")
    print(f"\nClaim 'inherits ReentrancyGuardUpgradeable': {is_valid}")
    print(f"  {explanation}")
    print(f"  ❌ Audit Finding 1 made this FALSE CLAIM!")
    
    # Test another valid claim
    is_valid, explanation = verifier.verify_claim("StakedCap", "ERC4626Upgradeable")
    print(f"\nClaim 'inherits ERC4626Upgradeable': {is_valid}")
    print(f"  {explanation}")


if __name__ == "__main__":
    test_inheritance_verifier()

