#!/usr/bin/env python3
"""
Cross-Contract Analyzer

Provides two analysis capabilities:
1. Inter-contract relationship analysis for the deep analysis pipeline (v3.8+)
   - ContractRelationship, CrossContractContext, InterContractAnalyzer
2. Access control analysis across contract boundaries (v3.5 legacy)
   - ExternalCallInfo, CrossContractAccessResult, CrossContractAnalyzer
"""

import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Inter-Contract Relationship Analysis (v3.8)
# ---------------------------------------------------------------------------

@dataclass
class ContractRelationship:
    """A detected relationship between two contracts."""
    caller: str          # contract name that makes the call
    callee: str          # contract/interface being called
    call_type: str       # "direct_call", "interface_call", "delegatecall", "staticcall", "inheritance"
    functions: List[str]  # specific functions called
    context: str         # relevant code snippet


@dataclass
class CrossContractContext:
    """Full inter-contract analysis result."""
    relationships: List[ContractRelationship]
    contract_groups: List[List[str]]         # groups of related contracts
    external_dependencies: List[str]         # interfaces with no implementation in project
    trust_boundaries: List[Dict[str, Any]]   # where trust assumptions change


class InterContractAnalyzer:
    """Analyzes inter-contract relationships from a list of contract files.

    Used by the deep analysis engine to build cross-contract context for
    Pass 3.5 (Cross-Contract Vulnerability Analysis).
    """

    def analyze_relationships(self, contract_files: List[Dict[str, Any]]) -> CrossContractContext:
        """Analyze inter-contract relationships from a list of contract files.

        Each contract_file dict has: 'path', 'content', 'name'
        """
        # Step A: Extract contract/interface definitions
        definitions = self._extract_definitions(contract_files)

        # Step B: Detect inter-contract calls
        relationships = self._detect_relationships(contract_files, definitions)

        # Step C: Build contract groups (transitive closure)
        contract_groups = self._build_groups(definitions, relationships)

        # Step D: Identify external dependencies
        external_deps = self._find_external_dependencies(definitions, relationships)

        # Step E: Identify trust boundaries
        trust_boundaries = self._identify_trust_boundaries(
            contract_files, definitions, relationships
        )

        return CrossContractContext(
            relationships=relationships,
            contract_groups=contract_groups,
            external_dependencies=external_deps,
            trust_boundaries=trust_boundaries,
        )

    def format_for_llm(self, context: CrossContractContext) -> str:
        """Format cross-contract relationships as text for LLM prompts."""
        if not context.relationships and not context.external_dependencies:
            return ""

        lines = ["## Cross-Contract Relationship Map", ""]

        # Relationships
        if context.relationships:
            lines.append("### Inter-Contract Interactions")
            for rel in context.relationships:
                funcs = ", ".join(rel.functions[:5])
                if len(rel.functions) > 5:
                    funcs += f" (+{len(rel.functions) - 5} more)"
                lines.append(
                    f"- **{rel.caller}** -> **{rel.callee}** "
                    f"[{rel.call_type}]: {funcs}"
                )
            lines.append("")

        # Contract groups
        if context.contract_groups:
            lines.append("### Contract Groups (interact with each other)")
            for i, group in enumerate(context.contract_groups, 1):
                lines.append(f"- Group {i}: {', '.join(group)}")
            lines.append("")

        # External dependencies
        if context.external_dependencies:
            lines.append("### External Dependencies (no implementation in project)")
            for dep in context.external_dependencies:
                lines.append(f"- {dep}")
            lines.append("")

        # Trust boundaries
        if context.trust_boundaries:
            lines.append("### Trust Boundaries")
            for tb in context.trust_boundaries:
                lines.append(
                    f"- **{tb.get('from_contract', '?')}** calls "
                    f"**{tb.get('to_contract', '?')}** "
                    f"({tb.get('trust_type', 'unknown')}): {tb.get('description', '')}"
                )
            lines.append("")

        return "\n".join(lines)

    # ----- internal helpers -----

    def _extract_definitions(
        self, contract_files: List[Dict[str, Any]]
    ) -> Dict[str, Dict[str, Any]]:
        """Extract contract/interface/library/abstract definitions from files.

        Returns a dict mapping definition name -> metadata dict.
        """
        defs: Dict[str, Dict[str, Any]] = {}
        # Matches: contract X, interface X, abstract contract X, library X
        pattern = re.compile(
            r'\b(contract|interface|abstract\s+contract|library)\s+'
            r'(\w+)',
            re.MULTILINE,
        )
        for cf in contract_files:
            content = cf.get('content', '')
            path = cf.get('path', '')
            name = cf.get('name', os.path.basename(path))
            for m in pattern.finditer(content):
                kind = m.group(1).strip()
                def_name = m.group(2)
                defs[def_name] = {
                    'kind': kind,
                    'file_path': path,
                    'file_name': name,
                }
        return defs

    def _detect_relationships(
        self,
        contract_files: List[Dict[str, Any]],
        definitions: Dict[str, Dict[str, Any]],
    ) -> List[ContractRelationship]:
        """Detect all inter-contract relationships."""
        relationships: List[ContractRelationship] = []
        all_def_names = set(definitions.keys())

        # Build a map: file_path -> list of contract names defined in that file
        file_to_contracts: Dict[str, List[str]] = {}
        for def_name, meta in definitions.items():
            fp = meta['file_path']
            file_to_contracts.setdefault(fp, []).append(def_name)

        for cf in contract_files:
            content = cf.get('content', '')
            path = cf.get('path', '')

            # Find all contracts defined in this file
            contracts_in_file = file_to_contracts.get(path, [])
            if not contracts_in_file:
                continue

            for contract_name in contracts_in_file:
                # Extract the body of this contract
                contract_body = self._extract_contract_body(content, contract_name)
                if not contract_body:
                    continue

                # 1. Inheritance
                inheritance_rels = self._detect_inheritance(
                    content, contract_name, all_def_names
                )
                relationships.extend(inheritance_rels)

                # 2. Interface calls: IFoo(addr).bar()
                iface_rels = self._detect_interface_calls(
                    contract_body, contract_name, all_def_names
                )
                relationships.extend(iface_rels)

                # 3. Direct contract calls: Foo(addr).bar() or foo.bar()
                direct_rels = self._detect_direct_calls(
                    contract_body, contract_name, all_def_names, definitions
                )
                relationships.extend(direct_rels)

                # 4. Low-level calls: delegatecall / staticcall / call
                lowlevel_rels = self._detect_lowlevel_calls(
                    contract_body, contract_name
                )
                relationships.extend(lowlevel_rels)

                # 5. State variables typed as contracts/interfaces
                statevar_rels = self._detect_typed_state_vars(
                    contract_body, contract_name, all_def_names
                )
                relationships.extend(statevar_rels)

        # Deduplicate relationships
        return self._deduplicate_relationships(relationships)

    def _extract_contract_body(self, content: str, contract_name: str) -> str:
        """Extract the body of a contract definition (between outermost braces)."""
        pattern = re.compile(
            r'\b(?:contract|interface|abstract\s+contract|library)\s+'
            + re.escape(contract_name)
            + r'\b[^{]*\{',
            re.MULTILINE,
        )
        m = pattern.search(content)
        if not m:
            return ""

        start = m.end()
        brace_count = 1
        pos = start
        while pos < len(content) and brace_count > 0:
            if content[pos] == '{':
                brace_count += 1
            elif content[pos] == '}':
                brace_count -= 1
            pos += 1

        return content[m.start():pos]

    def _detect_inheritance(
        self, content: str, contract_name: str, known_names: Set[str]
    ) -> List[ContractRelationship]:
        """Detect inheritance: contract A is B, C, D."""
        rels: List[ContractRelationship] = []
        pattern = re.compile(
            r'\b(?:contract|abstract\s+contract)\s+'
            + re.escape(contract_name)
            + r'\s+is\s+([^{]+)\{',
            re.MULTILINE,
        )
        m = pattern.search(content)
        if not m:
            return rels

        parents_str = m.group(1)
        # Split on commas, strip whitespace and optional constructor args
        parents = [
            re.sub(r'\(.*\)', '', p).strip()
            for p in parents_str.split(',')
        ]

        for parent in parents:
            if parent and parent != contract_name:
                rels.append(ContractRelationship(
                    caller=contract_name,
                    callee=parent,
                    call_type="inheritance",
                    functions=[],
                    context=f"{contract_name} is {parent}",
                ))
        return rels

    def _detect_interface_calls(
        self, contract_body: str, contract_name: str, known_names: Set[str]
    ) -> List[ContractRelationship]:
        """Detect interface cast calls: IFoo(addr).bar()."""
        rels_map: Dict[str, ContractRelationship] = {}
        # Allow one level of nested parens in constructor arg: IFoo(address(x)).bar()
        pattern = re.compile(r'(I\w+)\s*\((?:[^()]*|\([^()]*\))*\)\s*\.(\w+)\s*\(')
        for m in pattern.finditer(contract_body):
            iface = m.group(1)
            func = m.group(2)
            if iface == contract_name:
                continue
            key = (contract_name, iface)
            if key not in rels_map:
                snippet = contract_body[max(0, m.start() - 20):m.end() + 20]
                rels_map[key] = ContractRelationship(
                    caller=contract_name,
                    callee=iface,
                    call_type="interface_call",
                    functions=[],
                    context=snippet.strip(),
                )
            if func not in rels_map[key].functions:
                rels_map[key].functions.append(func)

        return list(rels_map.values())

    def _detect_direct_calls(
        self,
        contract_body: str,
        contract_name: str,
        known_names: Set[str],
        definitions: Dict[str, Dict[str, Any]],
    ) -> List[ContractRelationship]:
        """Detect direct contract calls: Foo(addr).bar() or stateVar.bar()."""
        rels_map: Dict[str, ContractRelationship] = {}

        # Pattern 1: ContractName(addr).func() -- allow nested parens
        p1 = re.compile(r'(\b[A-Z]\w+)\s*\((?:[^()]*|\([^()]*\))*\)\s*\.(\w+)\s*\(')
        for m in p1.finditer(contract_body):
            target = m.group(1)
            func = m.group(2)
            # Skip if it looks like an interface (starts with I + uppercase)
            if target.startswith('I') and len(target) > 1 and target[1].isupper():
                continue
            if target == contract_name:
                continue
            if target not in known_names:
                continue
            # Skip if it's a type cast to a primitive
            if target in ('uint256', 'uint128', 'int256', 'bytes32', 'address', 'bool'):
                continue
            kind = definitions.get(target, {}).get('kind', '')
            if 'interface' in kind:
                continue  # handled by interface_calls

            key = (contract_name, target)
            if key not in rels_map:
                snippet = contract_body[max(0, m.start() - 20):m.end() + 20]
                rels_map[key] = ContractRelationship(
                    caller=contract_name,
                    callee=target,
                    call_type="direct_call",
                    functions=[],
                    context=snippet.strip(),
                )
            if func not in rels_map[key].functions:
                rels_map[key].functions.append(func)

        # Pattern 2: stateVariable.func() where stateVariable is typed as a known contract
        # Find state variable declarations (e.g. "B public b;" or "IERC20 token;")
        state_var_pattern = re.compile(
            r'(\b[A-Z]\w*)\s+(?:public\s+|private\s+|internal\s+)?'
            r'(?:immutable\s+)?(?:override\s+)?(\w+)\s*[;=]'
        )
        var_type_map: Dict[str, str] = {}
        for m in state_var_pattern.finditer(contract_body):
            var_type = m.group(1)
            var_name = m.group(2)
            if var_type in known_names and var_type != contract_name:
                var_type_map[var_name] = var_type

        # Now look for var.func() calls
        var_call_pattern = re.compile(r'(\w+)\.(\w+)\s*\(')
        skip_refs = {
            'this', 'super', 'address', 'msg', 'block', 'tx',
            'abi', 'type', 'bytes', 'string',
        }
        for m in var_call_pattern.finditer(contract_body):
            var = m.group(1)
            func = m.group(2)
            if var in skip_refs:
                continue
            if var in var_type_map:
                target = var_type_map[var]
                key = (contract_name, target)
                if key not in rels_map:
                    snippet = contract_body[max(0, m.start() - 20):m.end() + 20]
                    rels_map[key] = ContractRelationship(
                        caller=contract_name,
                        callee=target,
                        call_type="direct_call",
                        functions=[],
                        context=snippet.strip(),
                    )
                if func not in rels_map[key].functions:
                    rels_map[key].functions.append(func)

        return list(rels_map.values())

    def _detect_lowlevel_calls(
        self, contract_body: str, contract_name: str
    ) -> List[ContractRelationship]:
        """Detect low-level calls: delegatecall, staticcall, call."""
        rels: List[ContractRelationship] = []

        # delegatecall
        dc_pattern = re.compile(
            r'(?:address\s*\(\s*)?(\w+)\s*\)?\.delegatecall\s*\('
        )
        for m in dc_pattern.finditer(contract_body):
            target = m.group(1)
            if target in ('this', 'address'):
                continue
            snippet = contract_body[max(0, m.start() - 30):m.end() + 30]
            rels.append(ContractRelationship(
                caller=contract_name,
                callee=target,
                call_type="delegatecall",
                functions=["delegatecall"],
                context=snippet.strip(),
            ))

        # staticcall
        sc_pattern = re.compile(
            r'(?:address\s*\(\s*)?(\w+)\s*\)?\.staticcall\s*\('
        )
        for m in sc_pattern.finditer(contract_body):
            target = m.group(1)
            if target in ('this', 'address'):
                continue
            snippet = contract_body[max(0, m.start() - 30):m.end() + 30]
            rels.append(ContractRelationship(
                caller=contract_name,
                callee=target,
                call_type="staticcall",
                functions=["staticcall"],
                context=snippet.strip(),
            ))

        return rels

    def _detect_typed_state_vars(
        self, contract_body: str, contract_name: str, known_names: Set[str]
    ) -> List[ContractRelationship]:
        """Detect state variables typed as contracts/interfaces (dependency, not call)."""
        # This is already partially handled by _detect_direct_calls; this method
        # captures references where the variable is declared but never called
        # (pure dependency awareness for trust boundary analysis).
        # We return empty here since the direct_calls handler covers the usage.
        return []

    def _build_groups(
        self,
        definitions: Dict[str, Dict[str, Any]],
        relationships: List[ContractRelationship],
    ) -> List[List[str]]:
        """Build groups of related contracts using transitive closure (union-find)."""
        parent: Dict[str, str] = {}

        def find(x: str) -> str:
            while parent.get(x, x) != x:
                parent[x] = parent.get(parent[x], parent[x])
                x = parent[x]
            return x

        def union(a: str, b: str) -> None:
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[ra] = rb

        # Initialize all known definitions
        all_names: Set[str] = set()
        for rel in relationships:
            all_names.add(rel.caller)
            all_names.add(rel.callee)
        for name in definitions:
            all_names.add(name)

        for name in all_names:
            parent.setdefault(name, name)

        # Union connected contracts
        for rel in relationships:
            union(rel.caller, rel.callee)

        # Build groups
        groups_map: Dict[str, List[str]] = {}
        for name in all_names:
            root = find(name)
            groups_map.setdefault(root, []).append(name)

        # Only return groups with 2+ members, sorted for determinism
        groups = [
            sorted(members)
            for members in groups_map.values()
            if len(members) >= 2
        ]
        return sorted(groups, key=lambda g: g[0])

    def _find_external_dependencies(
        self,
        definitions: Dict[str, Dict[str, Any]],
        relationships: List[ContractRelationship],
    ) -> List[str]:
        """Find interfaces/contracts referenced but not defined in the project."""
        known = set(definitions.keys())
        referenced: Set[str] = set()

        for rel in relationships:
            referenced.add(rel.callee)

        external = sorted(referenced - known)
        return external

    def _identify_trust_boundaries(
        self,
        contract_files: List[Dict[str, Any]],
        definitions: Dict[str, Dict[str, Any]],
        relationships: List[ContractRelationship],
    ) -> List[Dict[str, Any]]:
        """Identify where trust assumptions change between contracts."""
        known = set(definitions.keys())
        boundaries: List[Dict[str, Any]] = []

        for rel in relationships:
            if rel.call_type == "inheritance":
                continue  # inheritance is same-trust

            is_external = rel.callee not in known
            is_delegatecall = rel.call_type == "delegatecall"

            # Delegatecall is the highest-risk boundary -- check first
            if is_delegatecall:
                boundaries.append({
                    'from_contract': rel.caller,
                    'to_contract': rel.callee,
                    'trust_type': 'delegatecall_full_trust',
                    'description': (
                        f"{rel.caller} delegatecalls to {rel.callee}. "
                        f"Callee can modify caller's storage. "
                        f"Full trust required."
                    ),
                })
            elif is_external:
                boundaries.append({
                    'from_contract': rel.caller,
                    'to_contract': rel.callee,
                    'trust_type': 'external_dependency',
                    'description': (
                        f"{rel.caller} calls external {rel.callee} "
                        f"(not in project) via {', '.join(rel.functions[:3])}. "
                        f"Caller trusts callee's behavior."
                    ),
                })
            else:
                # Same-project external call -- trust boundary exists
                # but it's within the project
                if rel.call_type in ("interface_call", "direct_call", "staticcall"):
                    boundaries.append({
                        'from_contract': rel.caller,
                        'to_contract': rel.callee,
                        'trust_type': 'internal_cross_contract',
                        'description': (
                            f"{rel.caller} calls {rel.callee} "
                            f"via {', '.join(rel.functions[:3])}. "
                            f"State consistency depends on both contracts."
                        ),
                    })

        return boundaries

    def _deduplicate_relationships(
        self, relationships: List[ContractRelationship]
    ) -> List[ContractRelationship]:
        """Merge relationships with same caller+callee+call_type."""
        merged: Dict[Tuple[str, str, str], ContractRelationship] = {}
        for rel in relationships:
            key = (rel.caller, rel.callee, rel.call_type)
            if key in merged:
                existing = merged[key]
                for func in rel.functions:
                    if func not in existing.functions:
                        existing.functions.append(func)
            else:
                merged[key] = ContractRelationship(
                    caller=rel.caller,
                    callee=rel.callee,
                    call_type=rel.call_type,
                    functions=list(rel.functions),
                    context=rel.context,
                )
        return list(merged.values())


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
