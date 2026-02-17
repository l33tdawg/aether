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


# ---------------------------------------------------------------------------
# Related Contract Source Resolver (v4.5)
# ---------------------------------------------------------------------------

# Well-known standard library path prefixes
STANDARD_LIBRARY_PREFIXES = (
    '@openzeppelin/', 'openzeppelin-contracts/', 'openzeppelin/',
    'solmate/', 'solady/', 'forge-std/',
    '@rari-capital/', '@transmissions11/',
    'lib/openzeppelin', 'lib/solmate', 'lib/solady', 'lib/forge-std',
    'node_modules/@openzeppelin', 'node_modules/solmate', 'node_modules/solady',
)


@dataclass
class RelatedContractSource:
    """Source code of a contract related to the analysis target."""
    name: str
    file_path: str
    content: str
    relationship: str   # "parent", "interface", "library", "dependency", "sibling"
    priority: int       # 1=direct parents/interfaces, 2=libraries/typed vars, 3=transitive/group
    char_count: int = 0

    def __post_init__(self):
        if not self.char_count:
            self.char_count = len(self.content)


class RelatedContractResolver:
    """Resolves and collects source code of contracts related to analysis targets.

    Two modes:
      - **Project mode** (multi-file audit): uses InterContractAnalyzer._extract_definitions()
        to map names to files, then selects related sources based on detected relationships.
      - **Single-file mode**: parses import statements and resolves against disk using
        relative paths, Foundry remappings, node_modules, lib/, and same-directory scan.
    """

    def __init__(self):
        self._seen: Set[str] = set()  # Prevent circular resolution

    def resolve_related_sources(
        self,
        target_files: List[Dict[str, Any]],
        all_files: List[Dict[str, Any]],
        project_root: Optional[str] = None,
    ) -> List[RelatedContractSource]:
        """Resolve related contract sources.

        Args:
            target_files: Files being analyzed (subset of all_files or same)
            all_files: All available contract files in the project
            project_root: Root directory of the project (for import resolution)

        Returns:
            List of RelatedContractSource, sorted by priority (1 first).
        """
        self._seen.clear()
        related: List[RelatedContractSource] = []

        # Collect target contract names
        target_names: Set[str] = set()
        target_paths: Set[str] = set()
        for tf in target_files:
            content = tf.get('content', '')
            path = tf.get('path', '')
            target_paths.add(path)
            for m in re.finditer(
                r'\b(?:contract|interface|abstract\s+contract|library)\s+(\w+)', content
            ):
                target_names.add(m.group(1))

        if len(all_files) >= 2:
            related = self._resolve_project_mode(
                target_names, target_paths, all_files
            )
        else:
            # Single-file mode: parse imports and resolve from disk
            if target_files:
                related = self._resolve_single_file_mode(
                    target_files[0], project_root
                )

        # Sort by priority, then name for determinism
        related.sort(key=lambda r: (r.priority, r.name))
        return related

    # --- Project mode ---

    def _resolve_project_mode(
        self,
        target_names: Set[str],
        target_paths: Set[str],
        all_files: List[Dict[str, Any]],
    ) -> List[RelatedContractSource]:
        """Resolve related sources from project-level file list."""
        analyzer = InterContractAnalyzer()
        definitions = analyzer._extract_definitions(all_files)

        # Build name -> file content lookup
        path_to_file: Dict[str, Dict[str, Any]] = {}
        for cf in all_files:
            path_to_file[cf.get('path', '')] = cf

        # Detect relationships for target contracts
        relationships = analyzer._detect_relationships(all_files, definitions)

        # Build groups for transitive resolution
        groups = analyzer._build_groups(definitions, relationships)

        related: List[RelatedContractSource] = []
        added_paths: Set[str] = set()

        for rel in relationships:
            # We care about relationships where the target is the caller
            if rel.caller not in target_names:
                continue

            callee = rel.callee
            if callee in target_names:
                continue  # Skip self-references

            callee_def = definitions.get(callee)
            if not callee_def:
                continue

            callee_path = callee_def.get('file_path', '')
            if callee_path in target_paths or callee_path in added_paths:
                continue

            cf = path_to_file.get(callee_path)
            if not cf:
                continue

            content = cf.get('content', '')
            if not content:
                continue

            # Determine relationship type and priority
            if rel.call_type == 'inheritance':
                relationship = 'parent'
                priority = 1
            elif callee_def.get('kind') == 'interface':
                relationship = 'interface'
                priority = 1
            elif callee_def.get('kind') == 'library':
                relationship = 'library'
                priority = 2
            else:
                relationship = 'dependency'
                priority = 2

            # Check if standard library → summarize
            if self.is_standard_library(callee_path):
                content = self.extract_interface_summary(content)

            related.append(RelatedContractSource(
                name=callee,
                file_path=callee_path,
                content=content,
                relationship=relationship,
                priority=priority,
            ))
            added_paths.add(callee_path)

        # Also detect `using X for Y` library references not caught by
        # InterContractAnalyzer._detect_relationships()
        using_pattern = re.compile(r'\busing\s+(\w+)\s+for\s+', re.MULTILINE)
        for tf_path in target_paths:
            cf = path_to_file.get(tf_path)
            if not cf:
                continue
            for m in using_pattern.finditer(cf.get('content', '')):
                lib_name = m.group(1)
                if lib_name in target_names or lib_name in added_paths:
                    continue
                lib_def = definitions.get(lib_name)
                if not lib_def:
                    continue
                lib_path = lib_def.get('file_path', '')
                if lib_path in target_paths or lib_path in added_paths:
                    continue
                lib_cf = path_to_file.get(lib_path)
                if not lib_cf:
                    continue
                content = lib_cf.get('content', '')
                if not content:
                    continue
                if self.is_standard_library(lib_path):
                    content = self.extract_interface_summary(content)
                related.append(RelatedContractSource(
                    name=lib_name,
                    file_path=lib_path,
                    content=content,
                    relationship='library',
                    priority=2,
                ))
                added_paths.add(lib_path)

        # Add group members as priority 3 (transitive/sibling)
        for group in groups:
            for member in group:
                if member in target_names:
                    continue
                member_def = definitions.get(member)
                if not member_def:
                    continue
                member_path = member_def.get('file_path', '')
                if member_path in target_paths or member_path in added_paths:
                    continue
                cf = path_to_file.get(member_path)
                if not cf:
                    continue
                content = cf.get('content', '')
                if not content:
                    continue

                if self.is_standard_library(member_path):
                    content = self.extract_interface_summary(content)

                related.append(RelatedContractSource(
                    name=member,
                    file_path=member_path,
                    content=content,
                    relationship='sibling',
                    priority=3,
                ))
                added_paths.add(member_path)

        return related

    # --- Single-file mode ---

    def _resolve_single_file_mode(
        self,
        target_file: Dict[str, Any],
        project_root: Optional[str],
    ) -> List[RelatedContractSource]:
        """Resolve related sources by parsing import statements."""
        content = target_file.get('content', '')
        file_path = target_file.get('path', '')
        file_dir = os.path.dirname(file_path)

        if not project_root:
            project_root = self._detect_project_root(file_path)

        related: List[RelatedContractSource] = []
        remappings = self._load_remappings(project_root) if project_root else {}

        # Parse import statements
        import_pattern = re.compile(
            r'import\s+(?:{[^}]*}\s+from\s+)?["\']([^"\']+)["\']',
            re.MULTILINE,
        )

        for m in import_pattern.finditer(content):
            import_path = m.group(1)
            if import_path in self._seen:
                continue
            self._seen.add(import_path)

            resolved_path = self._resolve_import(
                import_path, file_dir, project_root, remappings
            )
            if not resolved_path or not os.path.isfile(resolved_path):
                continue

            try:
                with open(resolved_path, 'r', encoding='utf-8', errors='ignore') as f:
                    dep_content = f.read()
            except Exception:
                continue

            if not dep_content.strip():
                continue

            dep_name = os.path.splitext(os.path.basename(resolved_path))[0]
            is_stdlib = self.is_standard_library(import_path) or self.is_standard_library(resolved_path)

            # Determine relationship from content
            relationship, priority = self._classify_import(
                dep_content, content, dep_name, is_stdlib
            )

            if is_stdlib:
                dep_content = self.extract_interface_summary(dep_content)

            related.append(RelatedContractSource(
                name=dep_name,
                file_path=resolved_path,
                content=dep_content,
                relationship=relationship,
                priority=priority,
            ))

        return related

    def _classify_import(
        self, dep_content: str, target_content: str, dep_name: str, is_stdlib: bool
    ) -> Tuple[str, int]:
        """Classify a dependency's relationship and priority."""
        # Check if the target inherits from this dependency
        inherit_pattern = re.compile(
            r'\b(?:contract|abstract\s+contract)\s+\w+\s+is\s+[^{]*\b'
            + re.escape(dep_name) + r'\b'
        )
        if inherit_pattern.search(target_content):
            return ('parent', 1)

        # Check if it's an interface
        if re.search(r'\binterface\s+' + re.escape(dep_name) + r'\b', dep_content):
            return ('interface', 1)

        # Check if it's a library
        if re.search(r'\blibrary\s+' + re.escape(dep_name) + r'\b', dep_content):
            return ('library', 2)

        # Default: dependency
        return ('dependency', 2 if not is_stdlib else 3)

    def _resolve_import(
        self,
        import_path: str,
        file_dir: str,
        project_root: Optional[str],
        remappings: Dict[str, str],
    ) -> Optional[str]:
        """Resolve an import path to an absolute file path."""
        # 1. Relative path
        if import_path.startswith('.'):
            candidate = os.path.normpath(os.path.join(file_dir, import_path))
            if os.path.isfile(candidate):
                return candidate

        if not project_root:
            return None

        # 2. Foundry remappings
        for prefix, target in remappings.items():
            if import_path.startswith(prefix):
                remapped = import_path.replace(prefix, target, 1)
                candidate = os.path.normpath(os.path.join(project_root, remapped))
                if os.path.isfile(candidate):
                    return candidate

        # 3. node_modules
        candidate = os.path.join(project_root, 'node_modules', import_path)
        if os.path.isfile(candidate):
            return candidate

        # 4. lib/ directory (Foundry convention)
        candidate = os.path.join(project_root, 'lib', import_path)
        if os.path.isfile(candidate):
            return candidate

        # 5. Direct from project root
        candidate = os.path.join(project_root, import_path)
        if os.path.isfile(candidate):
            return candidate

        # 6. Same directory scan
        basename = os.path.basename(import_path)
        candidate = os.path.join(file_dir, basename)
        if os.path.isfile(candidate):
            return candidate

        return None

    def _load_remappings(self, project_root: str) -> Dict[str, str]:
        """Load Foundry remappings from remappings.txt or foundry.toml."""
        remappings: Dict[str, str] = {}

        # Try remappings.txt
        remap_file = os.path.join(project_root, 'remappings.txt')
        if os.path.isfile(remap_file):
            try:
                with open(remap_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if '=' in line and not line.startswith('#'):
                            prefix, target = line.split('=', 1)
                            remappings[prefix.strip()] = target.strip()
            except Exception:
                pass

        # Try foundry.toml
        if not remappings:
            toml_file = os.path.join(project_root, 'foundry.toml')
            if os.path.isfile(toml_file):
                try:
                    with open(toml_file, 'r') as f:
                        content = f.read()
                    # Simple regex extraction for remappings array
                    remap_match = re.search(
                        r'remappings\s*=\s*\[([^\]]*)\]', content, re.DOTALL
                    )
                    if remap_match:
                        for entry in re.findall(r'"([^"]*)"', remap_match.group(1)):
                            if '=' in entry:
                                prefix, target = entry.split('=', 1)
                                remappings[prefix.strip()] = target.strip()
                except Exception:
                    pass

        return remappings

    @staticmethod
    def _detect_project_root(file_path: str) -> Optional[str]:
        """Walk up from file_path to find project root."""
        markers = ('foundry.toml', 'hardhat.config.js', 'hardhat.config.ts',
                   'package.json', 'remappings.txt')
        current = os.path.dirname(os.path.abspath(file_path))
        for _ in range(5):  # Max 5 levels up
            for marker in markers:
                if os.path.exists(os.path.join(current, marker)):
                    return current
            parent = os.path.dirname(current)
            if parent == current:
                break
            current = parent
        return None

    @staticmethod
    def is_standard_library(path: str) -> bool:
        """Check if a path belongs to a well-known standard library."""
        normalized = path.replace('\\', '/')
        return any(prefix in normalized for prefix in STANDARD_LIBRARY_PREFIXES)

    @staticmethod
    def extract_interface_summary(content: str) -> str:
        """Extract only function/event/error signatures from contract source.

        Used for standard libraries to save context budget while preserving
        the information the LLM needs for interface compliance checks.
        """
        lines = []
        # Extract pragma
        pragma = re.search(r'pragma\s+solidity\s+[^;]+;', content)
        if pragma:
            lines.append(pragma.group(0))

        # Extract contract/interface/library declarations with inheritance
        decl_pattern = re.compile(
            r'\b(contract|interface|abstract\s+contract|library)\s+(\w+)(?:\s+is\s+[^{]+)?',
            re.MULTILINE,
        )
        for m in decl_pattern.finditer(content):
            lines.append(m.group(0).strip() + ' {')

        # Extract function signatures (without bodies)
        func_pattern = re.compile(
            r'function\s+\w+\s*\([^)]*\)\s*(?:external|public|internal|private)?'
            r'(?:\s+(?:view|pure|payable|virtual|override|returns\s*\([^)]*\)))*\s*;?',
            re.MULTILINE,
        )
        for m in func_pattern.finditer(content):
            sig = m.group(0).strip()
            if not sig.endswith(';'):
                sig += ';'
            lines.append(f'    {sig}')

        # Extract event and error signatures
        for pattern in (r'event\s+\w+\s*\([^)]*\)\s*;', r'error\s+\w+\s*\([^)]*\)\s*;'):
            for m in re.finditer(pattern, content):
                lines.append(f'    {m.group(0).strip()}')

        lines.append('}')
        lines.append('// [Standard library — interface summary only]')

        return '\n'.join(lines)

    @staticmethod
    def select_within_budget(
        related: List['RelatedContractSource'],
        budget_chars: int,
    ) -> List['RelatedContractSource']:
        """Select related sources by priority order until budget is exhausted.

        Lower priority numbers are selected first. If a contract doesn't fit,
        try to include an interface-only summary instead.
        """
        if budget_chars <= 0:
            return []

        selected: List[RelatedContractSource] = []
        used = 0

        # Already sorted by priority
        for src in related:
            if used + src.char_count <= budget_chars:
                selected.append(src)
                used += src.char_count
            elif src.priority <= 2:
                # Try interface-only summary for important contracts
                summary = RelatedContractResolver.extract_interface_summary(src.content)
                summary_len = len(summary)
                if used + summary_len <= budget_chars:
                    selected.append(RelatedContractSource(
                        name=src.name,
                        file_path=src.file_path,
                        content=summary,
                        relationship=src.relationship,
                        priority=src.priority,
                    ))
                    used += summary_len

        return selected


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
