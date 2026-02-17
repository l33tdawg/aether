"""
Solidity AST Parser — compiles Solidity contracts via py-solc-x and extracts
structured analysis data from the AST JSON.

Falls back to regex-based parsing when compilation fails (missing imports,
wrong compiler version, etc.), so callers always get useful results.
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

class Visibility(Enum):
    PUBLIC = "public"
    EXTERNAL = "external"
    INTERNAL = "internal"
    PRIVATE = "private"


class Mutability(Enum):
    PURE = "pure"
    VIEW = "view"
    NONPAYABLE = "nonpayable"
    PAYABLE = "payable"


@dataclass
class StateVariable:
    name: str
    type_name: str
    visibility: Visibility
    constant: bool = False
    immutable: bool = False
    slot: Optional[int] = None  # storage slot number
    offset: int = 0             # byte offset within slot


@dataclass
class FunctionParam:
    name: str
    type_name: str
    storage_location: str = ""  # memory, storage, calldata


@dataclass
class FunctionDef:
    name: str
    visibility: Visibility
    mutability: Mutability
    params: List[FunctionParam] = field(default_factory=list)
    returns: List[FunctionParam] = field(default_factory=list)
    modifiers: List[str] = field(default_factory=list)
    is_constructor: bool = False
    is_fallback: bool = False
    is_receive: bool = False
    body_source: str = ""
    start_line: int = 0
    end_line: int = 0
    state_reads: Set[str] = field(default_factory=set)
    state_writes: Set[str] = field(default_factory=set)
    external_calls: List[Dict] = field(default_factory=list)
    internal_calls: List[str] = field(default_factory=list)


@dataclass
class ModifierDef:
    name: str
    params: List[FunctionParam] = field(default_factory=list)
    body_source: str = ""


@dataclass
class ContractDef:
    name: str
    kind: str  # "contract", "interface", "library", "abstract"
    base_contracts: List[str] = field(default_factory=list)
    functions: List[FunctionDef] = field(default_factory=list)
    state_variables: List[StateVariable] = field(default_factory=list)
    modifiers: List[ModifierDef] = field(default_factory=list)
    events: List[Dict] = field(default_factory=list)
    using_directives: List[Dict] = field(default_factory=list)
    source_path: str = ""
    start_line: int = 0
    end_line: int = 0


@dataclass
class SolidityAST:
    """Complete parsed AST for a Solidity project."""
    contracts: List[ContractDef] = field(default_factory=list)
    inheritance_graph: Dict[str, List[str]] = field(default_factory=dict)
    storage_layout: Dict[str, List[StateVariable]] = field(default_factory=dict)
    import_map: Dict[str, str] = field(default_factory=dict)
    compiler_version: str = ""
    source_files: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class SolidityASTParser:
    """Parse Solidity source into structured AST data using solc.

    When py-solc-x is available and the source compiles successfully the parser
    walks the real AST JSON produced by solc.  When compilation fails (missing
    imports, wrong compiler version, etc.) or py-solc-x is not installed, a
    regex-based fallback extracts as much information as possible.
    """

    def __init__(self, solc_version: str = "0.8.30"):
        self.solc_version = solc_version
        self._ast_available = False
        self._solcx = None
        try:
            import solcx
            self._solcx = solcx
            self._ast_available = True
        except ImportError:
            self._ast_available = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def ast_available(self) -> bool:
        """Whether real AST parsing is available (solc installed)."""
        return self._ast_available

    def parse(self, contract_files: List[Dict[str, Any]]) -> SolidityAST:
        """Parse contract files and return structured AST.

        Args:
            contract_files: List of dicts with 'path', 'content', 'name' keys.

        Returns:
            SolidityAST with all extracted data.  Falls back to regex parsing
            if compilation fails.
        """
        sources: Dict[str, str] = {}
        for cf in contract_files:
            key = cf.get("name", cf.get("path", "Unknown.sol"))
            sources[key] = cf["content"]

        ast_result = SolidityAST(
            compiler_version=self.solc_version,
            source_files=list(sources.keys()),
        )

        compiled = False
        output: Optional[Dict] = None
        if self._ast_available:
            try:
                output = self._compile_to_ast(sources)
                compiled = True
            except Exception as exc:
                ast_result.errors.append(f"Compilation failed: {exc}")

        if compiled and output is not None:
            ast_result = self._process_compiler_output(output, ast_result)
        else:
            # Regex fallback for every source file
            for name, content in sources.items():
                fb = self._regex_fallback(content, name)
                ast_result.contracts.extend(fb.contracts)
                ast_result.inheritance_graph.update(fb.inheritance_graph)
                ast_result.import_map.update(fb.import_map)
                ast_result.errors.extend(fb.errors)

        return ast_result

    def parse_single(self, content: str, filename: str = "Contract.sol") -> SolidityAST:
        """Parse a single contract string."""
        return self.parse([{"path": filename, "content": content, "name": filename}])

    # ------------------------------------------------------------------
    # Compilation
    # ------------------------------------------------------------------

    def _compile_to_ast(self, sources: Dict[str, str]) -> Dict:
        """Compile sources and get AST + storage layout JSON."""
        solcx = self._solcx
        solcx.set_solc_version(self.solc_version)

        input_json: Dict[str, Any] = {
            "language": "Solidity",
            "sources": {name: {"content": content} for name, content in sources.items()},
            "settings": {
                "outputSelection": {
                    "*": {
                        "": ["ast"],
                        "*": ["storageLayout"],
                    }
                }
            },
        }

        output = solcx.compile_standard(input_json, allow_empty=True)
        return output

    # ------------------------------------------------------------------
    # AST-based extraction (from real solc output)
    # ------------------------------------------------------------------

    def _process_compiler_output(self, output: Dict, ast_result: SolidityAST) -> SolidityAST:
        """Process full compiler output — AST trees + storage layouts."""

        # Collect compilation errors/warnings
        for err in output.get("errors", []):
            msg = err.get("formattedMessage", err.get("message", ""))
            ast_result.errors.append(msg)

        # Walk source ASTs
        source_asts = output.get("sources", {})
        for source_name, source_data in source_asts.items():
            ast_node = source_data.get("ast")
            if ast_node is None:
                continue
            # Collect imports
            self._collect_imports(ast_node, ast_result.import_map)
            # Walk contract definitions
            contracts = self._walk_ast(ast_node, source_name)
            ast_result.contracts.extend(contracts)

        # Build inheritance graph
        for cdef in ast_result.contracts:
            ast_result.inheritance_graph[cdef.name] = list(cdef.base_contracts)

        # Extract storage layouts
        contracts_section = output.get("contracts", {})
        for source_name, source_contracts in contracts_section.items():
            for contract_name, contract_data in source_contracts.items():
                layout = contract_data.get("storageLayout")
                if layout:
                    ast_result.storage_layout[contract_name] = self._parse_storage_layout(layout)

        return ast_result

    def _collect_imports(self, ast_node: Dict, import_map: Dict[str, str]):
        """Collect import statements from the source unit."""
        for node in ast_node.get("nodes", []):
            if node.get("nodeType") == "ImportDirective":
                file_path = node.get("file", "")
                absolute_path = node.get("absolutePath", file_path)
                if file_path:
                    import_map[file_path] = absolute_path

    def _walk_ast(self, ast_node: Dict, source_name: str) -> List[ContractDef]:
        """Walk AST JSON and extract contract definitions."""
        contracts: List[ContractDef] = []
        for node in ast_node.get("nodes", []):
            if node.get("nodeType") == "ContractDefinition":
                cdef = self._parse_contract_node(node, source_name)
                contracts.append(cdef)
        return contracts

    def _parse_contract_node(self, node: Dict, source_name: str) -> ContractDef:
        """Parse a ContractDefinition AST node."""
        kind = node.get("contractKind", "contract")
        is_abstract = node.get("abstract", False)
        if is_abstract and kind == "contract":
            kind = "abstract"

        base_contracts: List[str] = []
        for base in node.get("baseContracts", []):
            base_name_node = base.get("baseName", {})
            bname = base_name_node.get("name", "")
            if not bname:
                bname = base_name_node.get("namePath", "")
            if bname:
                base_contracts.append(bname)

        # Collect state variable names first (needed for read/write analysis)
        state_var_names: Set[str] = set()
        state_variables: List[StateVariable] = []
        for sub in node.get("nodes", []):
            if sub.get("nodeType") == "VariableDeclaration" and sub.get("stateVariable", False):
                sv = self._parse_state_variable(sub)
                state_variables.append(sv)
                state_var_names.add(sv.name)

        functions: List[FunctionDef] = []
        modifiers: List[ModifierDef] = []
        events: List[Dict] = []
        using_directives: List[Dict] = []

        for sub in node.get("nodes", []):
            nt = sub.get("nodeType", "")
            if nt == "FunctionDefinition":
                fdef = self._parse_function_node(sub, state_var_names)
                functions.append(fdef)
            elif nt == "ModifierDefinition":
                mdef = self._parse_modifier_node(sub)
                modifiers.append(mdef)
            elif nt == "EventDefinition":
                events.append(self._parse_event_node(sub))
            elif nt == "UsingForDirective":
                using_directives.append(self._parse_using_directive(sub))

        src = node.get("src", "")
        start_line, end_line = self._src_to_lines(src)

        return ContractDef(
            name=node.get("name", ""),
            kind=kind,
            base_contracts=base_contracts,
            functions=functions,
            state_variables=state_variables,
            modifiers=modifiers,
            events=events,
            using_directives=using_directives,
            source_path=source_name,
            start_line=start_line,
            end_line=end_line,
        )

    def _parse_state_variable(self, node: Dict) -> StateVariable:
        """Parse a state VariableDeclaration node."""
        type_name = self._resolve_type_name(node.get("typeName", {}))
        vis_str = node.get("visibility", "internal")
        vis = self._to_visibility(vis_str)
        return StateVariable(
            name=node.get("name", ""),
            type_name=type_name,
            visibility=vis,
            constant=node.get("constant", False),
            immutable=node.get("mutability", "") == "immutable",
        )

    def _parse_function_node(self, node: Dict, state_var_names: Set[str]) -> FunctionDef:
        """Parse a FunctionDefinition node."""
        kind = node.get("kind", "function")
        is_constructor = kind == "constructor"
        is_fallback = kind == "fallback"
        is_receive = kind == "receive"

        name = node.get("name", "")
        if is_constructor:
            name = "constructor"
        elif is_fallback:
            name = "fallback"
        elif is_receive:
            name = "receive"

        vis_str = node.get("visibility", "public")
        vis = self._to_visibility(vis_str)

        mut_str = node.get("stateMutability", "nonpayable")
        mut = self._to_mutability(mut_str)

        # Parameters
        params = self._parse_param_list(node.get("parameters", {}))
        returns = self._parse_param_list(node.get("returnParameters", {}))

        # Modifiers
        modifier_names: List[str] = []
        for mod in node.get("modifiers", []):
            mod_name_node = mod.get("modifierName", {})
            mname = mod_name_node.get("name", "")
            if not mname:
                mname = mod_name_node.get("namePath", "")
            if mname:
                modifier_names.append(mname)

        # Body analysis
        body_node = node.get("body")
        state_reads: Set[str] = set()
        state_writes: Set[str] = set()
        external_calls: List[Dict] = []
        internal_calls: List[str] = []

        if body_node:
            self._analyze_function_body(
                body_node, state_var_names,
                state_reads, state_writes, external_calls, internal_calls,
            )

        src = node.get("src", "")
        start_line, end_line = self._src_to_lines(src)

        return FunctionDef(
            name=name,
            visibility=vis,
            mutability=mut,
            params=params,
            returns=returns,
            modifiers=modifier_names,
            is_constructor=is_constructor,
            is_fallback=is_fallback,
            is_receive=is_receive,
            start_line=start_line,
            end_line=end_line,
            state_reads=state_reads,
            state_writes=state_writes,
            external_calls=external_calls,
            internal_calls=internal_calls,
        )

    def _parse_param_list(self, params_node: Dict) -> List[FunctionParam]:
        """Parse a ParameterList AST node."""
        params: List[FunctionParam] = []
        for p in params_node.get("parameters", []):
            type_name = self._resolve_type_name(p.get("typeName", {}))
            storage = p.get("storageLocation", "")
            params.append(FunctionParam(
                name=p.get("name", ""),
                type_name=type_name,
                storage_location=storage if storage != "default" else "",
            ))
        return params

    def _parse_modifier_node(self, node: Dict) -> ModifierDef:
        """Parse a ModifierDefinition node."""
        params = self._parse_param_list(node.get("parameters", {}))
        return ModifierDef(
            name=node.get("name", ""),
            params=params,
        )

    def _parse_event_node(self, node: Dict) -> Dict:
        """Parse an EventDefinition node."""
        params: List[Dict[str, str]] = []
        for p in node.get("parameters", {}).get("parameters", []):
            params.append({
                "name": p.get("name", ""),
                "type": self._resolve_type_name(p.get("typeName", {})),
                "indexed": p.get("indexed", False),
            })
        return {"name": node.get("name", ""), "params": params}

    def _parse_using_directive(self, node: Dict) -> Dict:
        """Parse a UsingForDirective node."""
        lib_name = ""
        lib_node = node.get("libraryName", {})
        if lib_node:
            lib_name = lib_node.get("name", "") or lib_node.get("namePath", "")

        type_name = ""
        type_node = node.get("typeName")
        if type_node:
            type_name = self._resolve_type_name(type_node)

        return {"library": lib_name, "type": type_name}

    # ------------------------------------------------------------------
    # Function body analysis (AST-based)
    # ------------------------------------------------------------------

    def _analyze_function_body(
        self,
        node: Dict,
        state_var_names: Set[str],
        state_reads: Set[str],
        state_writes: Set[str],
        external_calls: List[Dict],
        internal_calls: List[str],
    ):
        """Recursively walk a function body to find reads, writes, and calls."""
        if not isinstance(node, dict):
            return

        nt = node.get("nodeType", "")

        # Assignment: LHS writes
        if nt == "Assignment":
            self._collect_writes(node.get("leftHandSide", {}), state_var_names, state_writes)
            self._collect_reads(node.get("rightHandSide", {}), state_var_names, state_reads)

        # Unary operations that mutate (++, --, delete)
        elif nt == "UnaryOperation":
            op = node.get("operator", "")
            if op in ("++", "--", "delete"):
                self._collect_writes(node.get("subExpression", {}), state_var_names, state_writes)
            else:
                self._collect_reads(node.get("subExpression", {}), state_var_names, state_reads)

        # Function calls
        elif nt == "FunctionCall":
            expr = node.get("expression", {})
            expr_nt = expr.get("nodeType", "")

            if expr_nt == "MemberAccess":
                member = expr.get("memberName", "")
                sub_expr = expr.get("expression", {})
                # External call heuristic: <expr>.memberName(...)
                # If the sub-expression references a state variable or has a
                # typeDescriptions with a "contract" reference, treat as external.
                type_str = (sub_expr.get("typeDescriptions") or {}).get("typeString", "")
                if "contract " in type_str or "interface " in type_str:
                    target_name = sub_expr.get("name", "")
                    external_calls.append({
                        "target": target_name,
                        "function": member,
                        "type": type_str,
                    })
                else:
                    # Could be a library call or address.call — still record
                    if member in ("call", "delegatecall", "staticcall", "transfer", "send"):
                        target_name = sub_expr.get("name", "")
                        external_calls.append({
                            "target": target_name,
                            "function": member,
                            "type": "low_level",
                        })
                    else:
                        internal_calls.append(member)
            elif expr_nt == "Identifier":
                func_name = expr.get("name", "")
                # Builtins like require, assert, etc.
                builtins = {
                    "require", "assert", "revert", "keccak256", "sha256",
                    "abi", "ecrecover", "addmod", "mulmod",
                }
                if func_name and func_name not in builtins:
                    internal_calls.append(func_name)

        # Identifier reads (general)
        elif nt == "Identifier":
            vname = node.get("name", "")
            if vname in state_var_names:
                state_reads.add(vname)

        # MemberAccess reads (e.g. someStruct.field)
        elif nt == "MemberAccess":
            sub = node.get("expression", {})
            if sub.get("nodeType") == "Identifier":
                vname = sub.get("name", "")
                if vname in state_var_names:
                    state_reads.add(vname)

        # Recurse into child nodes
        for key, value in node.items():
            if key in ("nodeType", "src", "typeDescriptions", "id"):
                continue
            if isinstance(value, dict):
                self._analyze_function_body(
                    value, state_var_names,
                    state_reads, state_writes, external_calls, internal_calls,
                )
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        self._analyze_function_body(
                            item, state_var_names,
                            state_reads, state_writes, external_calls, internal_calls,
                        )

    def _collect_writes(self, node: Dict, state_var_names: Set[str], state_writes: Set[str]):
        """Collect state variable writes from an LHS expression."""
        if not isinstance(node, dict):
            return
        nt = node.get("nodeType", "")
        if nt == "Identifier":
            vname = node.get("name", "")
            if vname in state_var_names:
                state_writes.add(vname)
        elif nt == "IndexAccess":
            # mapping[key] = val  ->  the mapping itself is written
            base = node.get("baseExpression", {})
            self._collect_writes(base, state_var_names, state_writes)
        elif nt == "MemberAccess":
            sub = node.get("expression", {})
            self._collect_writes(sub, state_var_names, state_writes)
        elif nt == "TupleExpression":
            for comp in node.get("components", []):
                if comp:
                    self._collect_writes(comp, state_var_names, state_writes)

    def _collect_reads(self, node: Dict, state_var_names: Set[str], state_reads: Set[str]):
        """Collect state variable reads from an expression."""
        if not isinstance(node, dict):
            return
        nt = node.get("nodeType", "")
        if nt == "Identifier":
            vname = node.get("name", "")
            if vname in state_var_names:
                state_reads.add(vname)
        # Recurse
        for key, value in node.items():
            if key in ("nodeType", "src", "typeDescriptions", "id"):
                continue
            if isinstance(value, dict):
                self._collect_reads(value, state_var_names, state_reads)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        self._collect_reads(item, state_var_names, state_reads)

    # ------------------------------------------------------------------
    # Storage layout
    # ------------------------------------------------------------------

    def _parse_storage_layout(self, layout: Dict) -> List[StateVariable]:
        """Parse solc storageLayout JSON into StateVariable list."""
        result: List[StateVariable] = []
        for entry in layout.get("storage", []):
            label = entry.get("label", "")
            slot_str = entry.get("slot", "0")
            offset = entry.get("offset", 0)
            type_key = entry.get("type", "")
            # Resolve type label from types section
            types = layout.get("types", {})
            type_info = types.get(type_key, {})
            type_label = type_info.get("label", type_key)

            result.append(StateVariable(
                name=label,
                type_name=type_label,
                visibility=Visibility.INTERNAL,  # storage layout doesn't include visibility
                slot=int(slot_str),
                offset=offset,
            ))
        return result

    # ------------------------------------------------------------------
    # Regex fallback
    # ------------------------------------------------------------------

    def _regex_fallback(self, content: str, filename: str) -> SolidityAST:
        """Extract what we can using regex when compilation fails."""
        ast_result = SolidityAST(
            source_files=[filename],
            errors=["Using regex fallback (compilation unavailable)"],
        )

        # Extract imports
        for m in re.finditer(r'import\s+(?:{[^}]*}\s+from\s+)?["\']([^"\']+)["\']', content):
            ast_result.import_map[m.group(1)] = m.group(1)

        # Split into lines for line-number tracking
        lines = content.split("\n")

        # Extract contract/interface/library definitions
        contract_pattern = re.compile(
            r'(abstract\s+)?(?:contract|interface|library)\s+(\w+)'
            r'(?:\s+is\s+([^{]+))?'
            r'\s*\{',
            re.MULTILINE,
        )

        for m in contract_pattern.finditer(content):
            is_abstract = bool(m.group(1))
            name = m.group(2)
            bases_str = m.group(3)

            # Determine kind
            prefix = content[m.start():m.start() + 50]
            if "interface " in prefix:
                kind = "interface"
            elif "library " in prefix:
                kind = "library"
            elif is_abstract:
                kind = "abstract"
            else:
                kind = "contract"

            # Base contracts
            base_contracts: List[str] = []
            if bases_str:
                for base_token in bases_str.split(","):
                    base_name = base_token.strip().split("(")[0].strip()
                    if base_name:
                        base_contracts.append(base_name)

            start_line = content[:m.start()].count("\n") + 1

            # Find the contract body using brace matching
            body_start = m.end() - 1  # points to '{'
            body = self._extract_brace_block(content, body_start)
            end_line = start_line + body.count("\n") if body else start_line

            # Parse contract body
            functions = self._regex_extract_functions(body or "", start_line)
            state_variables = self._regex_extract_state_vars(body or "")
            modifiers = self._regex_extract_modifiers(body or "")
            events = self._regex_extract_events(body or "")

            cdef = ContractDef(
                name=name,
                kind=kind,
                base_contracts=base_contracts,
                functions=functions,
                state_variables=state_variables,
                modifiers=modifiers,
                events=events,
                source_path=filename,
                start_line=start_line,
                end_line=end_line,
            )
            ast_result.contracts.append(cdef)
            ast_result.inheritance_graph[name] = list(base_contracts)

        return ast_result

    def _regex_extract_functions(self, body: str, body_start_line: int = 0) -> List[FunctionDef]:
        """Extract functions from a contract body using regex."""
        functions: List[FunctionDef] = []

        # Match: function name(params) vis mut modifiers returns (ret) { ... }
        # Also match constructor, fallback, receive
        func_pattern = re.compile(
            r'(function\s+(\w+)|constructor|fallback|receive)\s*'
            r'\(([^)]*)\)\s*'
            r'([^{;]*?)'
            r'(?:\{|;)',
            re.MULTILINE,
        )

        for m in func_pattern.finditer(body):
            full_match = m.group(0)
            if m.group(2):
                name = m.group(2)
                is_constructor = False
                is_fallback = False
                is_receive = False
            elif "constructor" in m.group(1):
                name = "constructor"
                is_constructor = True
                is_fallback = False
                is_receive = False
            elif "fallback" in m.group(1):
                name = "fallback"
                is_constructor = False
                is_fallback = True
                is_receive = False
            else:
                name = "receive"
                is_constructor = False
                is_fallback = False
                is_receive = True

            params_str = m.group(3) or ""
            attrs_str = m.group(4) or ""

            # Extract visibility
            vis = Visibility.PUBLIC
            for v in ("external", "public", "internal", "private"):
                if re.search(r'\b' + v + r'\b', attrs_str):
                    vis = Visibility(v)
                    break

            # Extract mutability
            mut = Mutability.NONPAYABLE
            for mt in ("pure", "view", "payable"):
                if re.search(r'\b' + mt + r'\b', attrs_str):
                    mut = Mutability(mt)
                    break

            # Extract return types
            returns: List[FunctionParam] = []
            returns_match = re.search(r'returns\s*\(([^)]*)\)', attrs_str)
            if returns_match:
                returns = self._parse_param_string(returns_match.group(1))

            # Extract modifiers (anything in attrs that isn't a keyword)
            keywords = {
                "public", "external", "internal", "private",
                "pure", "view", "payable", "virtual", "override",
                "returns",
            }
            modifier_names: List[str] = []
            for token in re.findall(r'\b(\w+)\b', attrs_str):
                if token not in keywords:
                    modifier_names.append(token)

            params = self._parse_param_string(params_str)

            line_in_body = body[:m.start()].count("\n")
            start_line = body_start_line + line_in_body

            functions.append(FunctionDef(
                name=name,
                visibility=vis,
                mutability=mut,
                params=params,
                returns=returns,
                modifiers=modifier_names,
                is_constructor=is_constructor,
                is_fallback=is_fallback,
                is_receive=is_receive,
                start_line=start_line,
            ))

        return functions

    def _regex_extract_state_vars(self, body: str) -> List[StateVariable]:
        """Extract state variable declarations from a contract body."""
        variables: List[StateVariable] = []
        # Match state variable declarations that end with ;
        # Exclude function-level locals by only matching at contract body level
        # We look for: type [visibility] [constant] [immutable] name [= ...];
        var_pattern = re.compile(
            r'^\s+'
            r'((?:mapping\s*\([^)]*\)|[\w\[\]]+))'  # type
            r'(?:\s+(public|internal|private|external))?'  # visibility
            r'(?:\s+(constant|immutable))?'
            r'(?:\s+(constant|immutable))?'
            r'\s+(\w+)'  # name
            r'\s*(?:=[^;]*)?;',
            re.MULTILINE,
        )

        for m in var_pattern.finditer(body):
            type_name = m.group(1).strip()
            vis_str = m.group(2) or "internal"
            mod1 = m.group(3) or ""
            mod2 = m.group(4) or ""
            name = m.group(5)

            # Skip if this looks like it's inside a function body
            # (heuristic: check if we're after an opening brace of a function)
            # Simple check: if the name is a keyword, skip
            if name in ("returns", "memory", "storage", "calldata", "override", "virtual"):
                continue

            vis = self._to_visibility(vis_str)
            is_constant = "constant" in (mod1, mod2)
            is_immutable = "immutable" in (mod1, mod2)

            variables.append(StateVariable(
                name=name,
                type_name=type_name,
                visibility=vis,
                constant=is_constant,
                immutable=is_immutable,
            ))

        return variables

    def _regex_extract_modifiers(self, body: str) -> List[ModifierDef]:
        """Extract modifier definitions from a contract body."""
        modifiers: List[ModifierDef] = []
        mod_pattern = re.compile(r'modifier\s+(\w+)\s*\(([^)]*)\)', re.MULTILINE)
        for m in mod_pattern.finditer(body):
            name = m.group(1)
            params = self._parse_param_string(m.group(2) or "")
            modifiers.append(ModifierDef(name=name, params=params))
        return modifiers

    def _regex_extract_events(self, body: str) -> List[Dict]:
        """Extract event definitions from a contract body."""
        events: List[Dict] = []
        event_pattern = re.compile(r'event\s+(\w+)\s*\(([^)]*)\)', re.MULTILINE)
        for m in event_pattern.finditer(body):
            name = m.group(1)
            params_str = m.group(2) or ""
            params: List[Dict[str, Any]] = []
            for p in params_str.split(","):
                p = p.strip()
                if not p:
                    continue
                indexed = "indexed" in p
                p = p.replace("indexed", "").strip()
                parts = p.split()
                if len(parts) >= 2:
                    params.append({"type": parts[0], "name": parts[-1], "indexed": indexed})
                elif len(parts) == 1:
                    params.append({"type": parts[0], "name": "", "indexed": indexed})
            events.append({"name": name, "params": params})
        return events

    def _parse_param_string(self, params_str: str) -> List[FunctionParam]:
        """Parse a comma-separated parameter string into FunctionParam list."""
        params: List[FunctionParam] = []
        if not params_str.strip():
            return params
        for p in params_str.split(","):
            p = p.strip()
            if not p:
                continue
            # Split into tokens
            tokens = p.split()
            if not tokens:
                continue
            type_name = tokens[0]
            storage = ""
            name = ""
            for t in tokens[1:]:
                if t in ("memory", "storage", "calldata"):
                    storage = t
                elif t in ("indexed",):
                    continue
                else:
                    name = t
            params.append(FunctionParam(name=name, type_name=type_name, storage_location=storage))
        return params

    # ------------------------------------------------------------------
    # Helper methods for consumers
    # ------------------------------------------------------------------

    def get_external_functions(self, ast: SolidityAST, contract_name: str) -> List[FunctionDef]:
        """Get all external/public functions for a contract (including inherited)."""
        result: List[FunctionDef] = []
        seen_names: Set[str] = set()

        # Direct functions
        for cdef in ast.contracts:
            if cdef.name == contract_name:
                for func in cdef.functions:
                    if func.visibility in (Visibility.PUBLIC, Visibility.EXTERNAL):
                        result.append(func)
                        seen_names.add(func.name)
                break

        # Inherited functions
        bases = self._resolve_all_bases(ast, contract_name)
        for base_name in bases:
            for cdef in ast.contracts:
                if cdef.name == base_name:
                    for func in cdef.functions:
                        if func.visibility in (Visibility.PUBLIC, Visibility.EXTERNAL):
                            if func.name not in seen_names:
                                result.append(func)
                                seen_names.add(func.name)

        return result

    def get_state_variable_writers(
        self, ast: SolidityAST, contract_name: str, var_name: str
    ) -> List[FunctionDef]:
        """Get all functions that write to a specific state variable."""
        writers: List[FunctionDef] = []
        for cdef in ast.contracts:
            if cdef.name == contract_name:
                for func in cdef.functions:
                    if var_name in func.state_writes:
                        writers.append(func)
                break
        return writers

    def get_modifier_chain(
        self, ast: SolidityAST, contract_name: str, function_name: str
    ) -> List[str]:
        """Get complete modifier chain for a function (including inherited modifiers)."""
        # Find the function
        for cdef in ast.contracts:
            if cdef.name == contract_name:
                for func in cdef.functions:
                    if func.name == function_name:
                        return list(func.modifiers)
        return []

    def get_storage_layout(self, ast: SolidityAST, contract_name: str) -> List[StateVariable]:
        """Get ordered storage layout for a contract."""
        return ast.storage_layout.get(contract_name, [])

    def format_for_llm(self, ast: SolidityAST) -> str:
        """Format AST summary as text for LLM prompt context."""
        parts: List[str] = ["## Contract Structure (from AST)"]

        for cdef in ast.contracts:
            # Header
            bases = f" (is {', '.join(cdef.base_contracts)})" if cdef.base_contracts else ""
            kind_label = cdef.kind.capitalize() if cdef.kind != "contract" else ""
            kind_prefix = f"{kind_label} " if kind_label else ""
            parts.append(f"### {kind_prefix}{cdef.name}{bases}")

            # State variables
            if cdef.state_variables:
                sv_parts: List[str] = []
                for sv in cdef.state_variables:
                    extras: List[str] = []
                    if sv.constant:
                        extras.append("constant")
                    if sv.immutable:
                        extras.append("immutable")
                    if sv.slot is not None:
                        extras.append(f"slot {sv.slot}")
                    extra_str = f" [{', '.join(extras)}]" if extras else ""
                    sv_parts.append(f"{sv.name}({sv.type_name}{extra_str})")
                parts.append(f"State: {', '.join(sv_parts)}")

            # Separate admin vs external functions
            admin_funcs: List[FunctionDef] = []
            external_funcs: List[FunctionDef] = []
            other_funcs: List[FunctionDef] = []

            admin_mods = {
                "onlyOwner", "onlyAdmin", "onlyGovernor", "onlyGovernance",
                "onlyRole", "restricted", "onlyAuthorized", "requiresAuth",
                "onlyGuardian", "onlyController",
            }

            for func in cdef.functions:
                if func.visibility in (Visibility.PUBLIC, Visibility.EXTERNAL):
                    if any(m in admin_mods for m in func.modifiers):
                        admin_funcs.append(func)
                    else:
                        external_funcs.append(func)
                else:
                    other_funcs.append(func)

            if external_funcs:
                parts.append("External Functions:")
                for func in external_funcs:
                    parts.append(self._format_func_summary(func))

            if admin_funcs:
                parts.append("Admin Functions:")
                for func in admin_funcs:
                    parts.append(self._format_func_summary(func))

            if other_funcs:
                parts.append("Internal Functions:")
                for func in other_funcs:
                    parts.append(self._format_func_summary(func))

            parts.append("")

        return "\n".join(parts)

    def _format_func_summary(self, func: FunctionDef) -> str:
        """Format a single function for LLM summary."""
        params_str = ", ".join(
            f"{p.type_name} {p.name}".strip() for p in func.params
        )
        returns_str = ""
        if func.returns:
            ret_types = ", ".join(
                f"{r.type_name} {r.name}".strip() for r in func.returns
            )
            returns_str = f" -> {ret_types}"

        mods_str = ""
        if func.modifiers:
            mods_str = f" [{', '.join(func.modifiers)}]"

        mut_str = ""
        if func.mutability in (Mutability.VIEW, Mutability.PURE):
            mut_str = f" {func.mutability.value}"

        access_info: List[str] = []
        if func.state_writes:
            access_info.append(f"writes: {', '.join(sorted(func.state_writes))}")
        if func.state_reads:
            access_info.append(f"reads: {', '.join(sorted(func.state_reads))}")
        access_str = f" {' '.join(access_info)}" if access_info else ""

        return f"  - {func.name}({params_str}){mut_str}{returns_str}{mods_str}{access_str}"

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def _resolve_type_name(self, type_node: Dict) -> str:
        """Resolve a typeName AST node to a human-readable string."""
        if not type_node:
            return ""
        nt = type_node.get("nodeType", "")

        if nt == "ElementaryTypeName":
            return type_node.get("name", "")
        elif nt == "UserDefinedTypeName":
            # Different solc versions use different keys
            return (
                type_node.get("name", "")
                or type_node.get("namePath", "")
                or (type_node.get("pathNode", {}) or {}).get("name", "")
            )
        elif nt == "Mapping":
            key = self._resolve_type_name(type_node.get("keyType", {}))
            val = self._resolve_type_name(type_node.get("valueType", {}))
            return f"mapping({key} => {val})"
        elif nt == "ArrayTypeName":
            base = self._resolve_type_name(type_node.get("baseType", {}))
            length = type_node.get("length")
            if length:
                return f"{base}[{length}]"
            return f"{base}[]"
        elif nt == "FunctionTypeName":
            return "function"

        # Fallback: try typeDescriptions
        td = type_node.get("typeDescriptions", {})
        return td.get("typeString", "unknown")

    def _to_visibility(self, vis_str: str) -> Visibility:
        """Convert a visibility string to Visibility enum."""
        try:
            return Visibility(vis_str)
        except ValueError:
            return Visibility.INTERNAL

    def _to_mutability(self, mut_str: str) -> Mutability:
        """Convert a mutability string to Mutability enum."""
        try:
            return Mutability(mut_str)
        except ValueError:
            return Mutability.NONPAYABLE

    def _src_to_lines(self, src_str: str) -> tuple:
        """Convert solc src string 'offset:length:fileIndex' to (start_line, end_line).

        NOTE: Without the original source we cannot resolve byte offsets to
        line numbers accurately, so we store the raw offset as a placeholder.
        Callers that need accurate lines should use the regex fallback data
        or post-process with the original source text.
        """
        if not src_str:
            return (0, 0)
        parts = src_str.split(":")
        if len(parts) >= 2:
            try:
                start = int(parts[0])
                length = int(parts[1])
                return (start, start + length)
            except ValueError:
                pass
        return (0, 0)

    def _extract_brace_block(self, content: str, start: int) -> Optional[str]:
        """Extract a brace-delimited block from content starting at the { at position start."""
        if start >= len(content) or content[start] != "{":
            return None
        depth = 0
        i = start
        in_string = False
        string_char = ""
        in_line_comment = False
        in_block_comment = False

        while i < len(content):
            ch = content[i]

            if in_line_comment:
                if ch == "\n":
                    in_line_comment = False
                i += 1
                continue

            if in_block_comment:
                if ch == "*" and i + 1 < len(content) and content[i + 1] == "/":
                    in_block_comment = False
                    i += 2
                    continue
                i += 1
                continue

            if in_string:
                if ch == "\\" and i + 1 < len(content):
                    i += 2
                    continue
                if ch == string_char:
                    in_string = False
                i += 1
                continue

            if ch in ('"', "'"):
                in_string = True
                string_char = ch
                i += 1
                continue

            if ch == "/" and i + 1 < len(content):
                next_ch = content[i + 1]
                if next_ch == "/":
                    in_line_comment = True
                    i += 2
                    continue
                elif next_ch == "*":
                    in_block_comment = True
                    i += 2
                    continue

            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return content[start:i + 1]

            i += 1

        return None

    def _resolve_all_bases(self, ast: SolidityAST, contract_name: str) -> List[str]:
        """Resolve full transitive inheritance chain for a contract."""
        visited: Set[str] = set()
        result: List[str] = []
        queue = list(ast.inheritance_graph.get(contract_name, []))

        while queue:
            base = queue.pop(0)
            if base in visited:
                continue
            visited.add(base)
            result.append(base)
            queue.extend(ast.inheritance_graph.get(base, []))

        return result
