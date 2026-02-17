"""
Taint Analysis Engine -- Data flow tracking for Solidity smart contracts.

Tracks user-controlled ("tainted") data from entry points through a contract
to identify dangerous data flows.  When tainted data reaches a dangerous sink
(external call, delegatecall, selfdestruct, etc.) without proper sanitization,
the engine reports the flow with severity, path, and missing protections.

Supports two modes:
  1. Regex-based analysis (default) -- works on raw Solidity source
  2. AST-augmented analysis -- when optional ast_data is provided for more
     precise tracking (accepts an opaque AST object)

Design goals:
  - Fast heuristic propagation (no exhaustive path enumeration)
  - Self-contained regex patterns (no external parser dependencies)
  - Compatible with the existing detection + validation pipeline
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class TaintSource(Enum):
    """Where tainted data originates."""
    FUNCTION_PARAM = "function_parameter"
    MSG_SENDER = "msg.sender"
    MSG_VALUE = "msg.value"
    CALLDATA = "calldata"
    EXTERNAL_CALL_RETURN = "external_call_return"
    BLOCK_TIMESTAMP = "block.timestamp"
    BLOCK_NUMBER = "block.number"
    TX_ORIGIN = "tx.origin"


class TaintSink(Enum):
    """Dangerous destinations for tainted data."""
    EXTERNAL_CALL = "external_call"
    EXTERNAL_CALL_VALUE = "external_value"
    DELEGATECALL = "delegatecall"
    SELFDESTRUCT = "selfdestruct"
    STORAGE_WRITE = "storage_write"
    ARRAY_INDEX = "array_index"
    DIVISION = "division"
    ETH_TRANSFER = "eth_transfer"
    COMPARISON = "comparison"
    EVENT_EMIT = "event_emit"
    CREATE = "create"
    ASSEMBLY_MSTORE = "assembly_mstore"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class TaintedVariable:
    """A variable that carries tainted data."""
    name: str
    source: TaintSource
    source_function: str
    source_param: str
    taint_path: List[str] = field(default_factory=list)
    sanitized: bool = False
    sanitizer: str = ""


@dataclass
class TaintFlow:
    """A complete taint flow from source to sink."""
    source: TaintSource
    source_function: str
    source_param: str
    sink: TaintSink
    sink_function: str
    sink_expression: str
    sink_line: int
    taint_path: List[str]
    is_sanitized: bool
    sanitizers: List[str]
    severity: str
    description: str


@dataclass
class TaintReport:
    """Complete taint analysis report for a contract."""
    contract_name: str
    taint_sources: List[Dict] = field(default_factory=list)
    taint_flows: List[TaintFlow] = field(default_factory=list)
    dangerous_flows: List[TaintFlow] = field(default_factory=list)
    sanitized_flows: List[TaintFlow] = field(default_factory=list)
    summary: Dict[str, int] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Regex helpers
# ---------------------------------------------------------------------------

# Match external/public function declarations and capture params + body
_FUNC_RE = re.compile(
    r'function\s+(\w+)\s*\(([^)]*)\)\s*'            # name + params
    r'((?:external|public|internal|private|'          # visibility / modifiers
    r'payable|view|pure|virtual|override|'
    r'returns\s*\([^)]*\)|'
    r'\w+\s*(?:\([^)]*\))?'                           # custom modifiers
    r'[\s,])*)'                                        # end of modifier group
    r'\s*\{',                                          # opening brace
    re.DOTALL
)

_VISIBILITY_RE = re.compile(r'\b(external|public|internal|private)\b')

# Match a mapping/array storage write: state[key] = val  or  state = val
_STORAGE_WRITE_RE = re.compile(
    r'(\w+)\s*\[([^\]]+)\]\s*=[^=]|'
    r'(\w+)\s*\.\w+\s*=[^=]|'
    r'(\w+)\s*=[^=]'
)

# Match function parameters: "type name" pairs
# Handles: address to, uint256 amount, address payable recipient,
#           bytes calldata data, uint256[] memory ids
_PARAM_RE = re.compile(
    r'(?:(?:address|uint\d*|int\d*|bytes\d*|bool|string|'
    r'mapping\s*\([^)]*\)|'
    r'\w+(?:\[\d*\])*)'              # base type
    r'(?:\s+payable)?'               # optional payable (address payable)
    r'(?:\s+(?:memory|storage|calldata))?'  # data location
    r')\s+(\w+)'                     # parameter name
)

# Match modifiers like onlyOwner, onlyRole, etc.
_MODIFIER_RE = re.compile(
    r'\b(onlyOwner|onlyAdmin|onlyRole|onlyGovernor|onlyGovernance|'
    r'onlyMinter|onlyOperator|onlyAuthorized|onlyWhitelisted|'
    r'onlyKeeper|whenNotPaused|nonReentrant)\b'
)


# ---------------------------------------------------------------------------
# Main analyzer class
# ---------------------------------------------------------------------------

class TaintAnalyzer:
    """Analyze taint propagation through Solidity contracts."""

    def __init__(self):
        self._use_ast = False

        # Implicit taint sources (global variables)
        self._implicit_sources = {
            'msg.sender': TaintSource.MSG_SENDER,
            'msg.value': TaintSource.MSG_VALUE,
            'tx.origin': TaintSource.TX_ORIGIN,
            'block.timestamp': TaintSource.BLOCK_TIMESTAMP,
            'block.number': TaintSource.BLOCK_NUMBER,
        }

        # Sink severity map (sink -> default severity when unsanitized)
        self._sink_severity: Dict[TaintSink, str] = {
            TaintSink.DELEGATECALL: "critical",
            TaintSink.SELFDESTRUCT: "critical",
            TaintSink.ETH_TRANSFER: "critical",
            TaintSink.EXTERNAL_CALL_VALUE: "high",
            TaintSink.EXTERNAL_CALL: "high",
            TaintSink.STORAGE_WRITE: "medium",
            TaintSink.ARRAY_INDEX: "medium",
            TaintSink.DIVISION: "medium",
            TaintSink.CREATE: "medium",
            TaintSink.ASSEMBLY_MSTORE: "medium",
            TaintSink.COMPARISON: "low",
            TaintSink.EVENT_EMIT: "low",
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(
        self,
        contract_content: str,
        contract_name: str = "",
        ast_data: Optional[Any] = None,
    ) -> TaintReport:
        """Run taint analysis on a contract.

        Args:
            contract_content: Solidity source code
            contract_name: Name of contract to analyze
            ast_data: Optional AST data for more precise analysis
        """
        self._use_ast = ast_data is not None

        if not contract_name:
            contract_name = self._detect_contract_name(contract_content)

        report = TaintReport(contract_name=contract_name)

        # Step 1: identify all taint sources
        sources = self._identify_sources(contract_content, ast_data)
        report.taint_sources = sources

        # Step 2: extract functions
        functions = self._extract_functions(contract_content, ast_data)

        # Step 3: extract state variable names for cross-function taint
        state_vars = self._extract_state_variables(contract_content)

        # Step 4: for each function with taint sources, propagate + detect sinks
        # Track which state vars become tainted and from which source
        tainted_state: Dict[str, TaintedVariable] = {}

        for func in functions:
            func_name = func['name']
            func_body = func['body']
            func_params = func['params']
            func_line_offset = func['line_offset']
            visibility = func['visibility']

            # Build initial taint set for this function
            initial_taint: List[TaintedVariable] = []

            # Params of external/public functions are tainted
            if visibility in ('external', 'public'):
                for pname in func_params:
                    tv = TaintedVariable(
                        name=pname,
                        source=TaintSource.FUNCTION_PARAM,
                        source_function=func_name,
                        source_param=pname,
                        taint_path=[pname],
                    )
                    initial_taint.append(tv)

            # Implicit sources present in function body
            for src_expr, src_type in self._implicit_sources.items():
                if src_expr in func_body:
                    # Create a pseudo-variable for implicit source
                    safe_name = src_expr.replace('.', '_')
                    tv = TaintedVariable(
                        name=safe_name,
                        source=src_type,
                        source_function=func_name,
                        source_param=src_expr,
                        taint_path=[src_expr],
                    )
                    initial_taint.append(tv)

            # External call return values in function body
            ext_returns = self._find_external_call_returns(func_body)
            for vname in ext_returns:
                tv = TaintedVariable(
                    name=vname,
                    source=TaintSource.EXTERNAL_CALL_RETURN,
                    source_function=func_name,
                    source_param=vname,
                    taint_path=[f"ext_call()->{vname}"],
                )
                initial_taint.append(tv)

            # Include tainted state vars from other functions
            for svar, stv in tainted_state.items():
                if re.search(r'\b' + re.escape(svar) + r'\b', func_body):
                    tv = TaintedVariable(
                        name=svar,
                        source=stv.source,
                        source_function=stv.source_function,
                        source_param=stv.source_param,
                        taint_path=stv.taint_path + [f"state:{svar}"],
                        sanitized=stv.sanitized,
                        sanitizer=stv.sanitizer,
                    )
                    initial_taint.append(tv)

            if not initial_taint:
                continue

            # Propagate taint through function body
            # Try CFG-based propagation first for branch-aware analysis
            propagated = None
            if ast_data is not None:
                try:
                    from core.solidity_ast import SolidityASTParser
                    cfg_parser = SolidityASTParser()
                    cfg = cfg_parser.build_cfg(func_body, func_name)
                    if cfg and cfg.blocks and len(cfg.blocks) > 1:
                        propagated = self._propagate_with_cfg(
                            cfg, initial_taint
                        )
                except Exception:
                    propagated = None

            if propagated is None:
                propagated = self._propagate_taint(
                    contract_content, func_body, initial_taint
                )

            # Track state variable tainting (for cross-function flows)
            for tv in propagated:
                if tv.name in state_vars and not tv.sanitized:
                    tainted_state[tv.name] = tv

            # Detect sanitizers
            tainted_set = {tv.name for tv in propagated}
            func_modifiers = func.get('modifiers', '')

            for tv in propagated:
                sanitizers = self._detect_sanitizers(
                    func_body, tv.name, func_modifiers
                )
                if sanitizers:
                    tv.sanitized = True
                    tv.sanitizer = '; '.join(sanitizers)

            # Detect sinks
            sinks = self._detect_sinks(
                contract_content, func_body, tainted_set, func_line_offset
            )

            # Build flows
            for sink_info in sinks:
                sink_type = sink_info['sink']
                sink_expr = sink_info['expression']
                sink_line = sink_info['line']
                sink_var = sink_info['tainted_var']

                # Find the matching tainted variable
                matching_tv = None
                for tv in propagated:
                    if tv.name == sink_var:
                        matching_tv = tv
                        break

                if matching_tv is None:
                    continue

                # Collect sanitizers for this variable
                sanitizers = self._detect_sanitizers(
                    func_body, sink_var, func_modifiers
                )
                is_sanitized = len(sanitizers) > 0

                severity = self._calculate_severity(
                    sink_type, is_sanitized, matching_tv.source
                )

                description = self._build_flow_description(
                    matching_tv, sink_type, sink_expr, is_sanitized, sanitizers
                )

                flow = TaintFlow(
                    source=matching_tv.source,
                    source_function=matching_tv.source_function,
                    source_param=matching_tv.source_param,
                    sink=sink_type,
                    sink_function=func_name,
                    sink_expression=sink_expr,
                    sink_line=sink_line,
                    taint_path=matching_tv.taint_path,
                    is_sanitized=is_sanitized,
                    sanitizers=sanitizers,
                    severity=severity,
                    description=description,
                )

                report.taint_flows.append(flow)
                if is_sanitized:
                    report.sanitized_flows.append(flow)
                else:
                    report.dangerous_flows.append(flow)

        # Build summary
        report.summary = self._build_summary(report)

        return report

    def analyze_multiple(
        self,
        contract_files: List[Dict[str, Any]],
        ast_data: Optional[Any] = None,
    ) -> List[TaintReport]:
        """Analyze multiple contracts, tracking cross-contract taint.

        Each dict in contract_files should have at minimum:
          - 'content': str  (Solidity source)
          - 'name': str     (contract/file name)
        """
        reports: List[TaintReport] = []

        # First pass: analyze each contract individually
        for cf in contract_files:
            content = cf.get('content', '')
            name = cf.get('name', '')
            report = self.analyze(content, name, ast_data)
            reports.append(report)

        # Second pass: detect cross-contract taint
        cross_flows = self._detect_cross_contract_taint(contract_files, reports)
        if cross_flows:
            # Attach cross-contract flows to the caller's report
            for flow, caller_idx in cross_flows:
                if 0 <= caller_idx < len(reports):
                    reports[caller_idx].taint_flows.append(flow)
                    if flow.is_sanitized:
                        reports[caller_idx].sanitized_flows.append(flow)
                    else:
                        reports[caller_idx].dangerous_flows.append(flow)
                    reports[caller_idx].summary = self._build_summary(
                        reports[caller_idx]
                    )

        return reports

    def format_for_llm(self, report: TaintReport) -> str:
        """Format taint report as text for LLM prompt context."""
        lines: List[str] = []
        lines.append("## Taint Analysis Results")
        lines.append("")

        if report.dangerous_flows:
            lines.append(
                f"### Dangerous Unsanitized Flows ({len(report.dangerous_flows)} found)"
            )
            for i, flow in enumerate(report.dangerous_flows, 1):
                sev = flow.severity.upper()
                lines.append(
                    f"{i}. [{sev}] {flow.source_function}({flow.source_param}) "
                    f"-> {flow.sink_expression} at line {flow.sink_line}"
                )
                path_str = " -> ".join(flow.taint_path)
                lines.append(f"   Path: {path_str}")
                lines.append(f"   Missing: {flow.description}")
                lines.append("")
        else:
            lines.append("### No Dangerous Unsanitized Flows Found")
            lines.append("")

        if report.sanitized_flows:
            lines.append(
                f"### Sanitized Flows ({len(report.sanitized_flows)} found)"
            )
            for i, flow in enumerate(report.sanitized_flows, 1):
                sanitizer_str = ', '.join(flow.sanitizers) if flow.sanitizers else 'unknown'
                lines.append(
                    f"{i}. {flow.source_function}({flow.source_param}) "
                    f"-> sanitized by {sanitizer_str}"
                )
            lines.append("")

        if report.summary:
            lines.append("### Summary")
            for key, val in report.summary.items():
                lines.append(f"- {key}: {val}")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # A. Source identification
    # ------------------------------------------------------------------

    def _identify_sources(
        self, content: str, ast_data: Optional[Any] = None
    ) -> List[Dict]:
        """Find all taint sources in the contract."""
        sources: List[Dict] = []

        # If AST data is available, use it for precise source identification
        if ast_data is not None:
            ast_sources = self._identify_sources_ast(content, ast_data)
            if ast_sources:
                return ast_sources

        # Regex-based source identification
        functions = self._extract_functions(content)

        for func in functions:
            if func['visibility'] not in ('external', 'public'):
                continue

            for pname in func['params']:
                sources.append({
                    'type': TaintSource.FUNCTION_PARAM.value,
                    'function': func['name'],
                    'parameter': pname,
                    'visibility': func['visibility'],
                })

        # Implicit sources (always present)
        for src_expr, src_type in self._implicit_sources.items():
            if src_expr in content:
                sources.append({
                    'type': src_type.value,
                    'expression': src_expr,
                })

        # External call returns
        ext_call_re = re.compile(
            r'(\w+)\s*(?:,\s*\w+)*\s*=\s*\w+\.\w+\s*\('
        )
        for m in ext_call_re.finditer(content):
            sources.append({
                'type': TaintSource.EXTERNAL_CALL_RETURN.value,
                'variable': m.group(1),
            })

        return sources

    def _identify_sources_ast(
        self, content: str, ast_data: Any
    ) -> List[Dict]:
        """Use AST data for more precise source identification."""
        sources: List[Dict] = []
        try:
            # Try to use ast_data if it has an expected interface
            if hasattr(ast_data, 'get_functions'):
                for func in ast_data.get_functions():
                    vis = getattr(func, 'visibility', 'internal')
                    if vis in ('external', 'public'):
                        params = getattr(func, 'parameters', [])
                        for p in params:
                            pname = getattr(p, 'name', str(p))
                            sources.append({
                                'type': TaintSource.FUNCTION_PARAM.value,
                                'function': getattr(func, 'name', ''),
                                'parameter': pname,
                                'visibility': vis,
                            })
            elif isinstance(ast_data, dict):
                # Handle dict-style AST
                for node in ast_data.get('nodes', []):
                    if node.get('nodeType') == 'FunctionDefinition':
                        vis = node.get('visibility', 'internal')
                        if vis in ('external', 'public'):
                            params = node.get('parameters', {}).get(
                                'parameters', []
                            )
                            for p in params:
                                pname = p.get('name', '')
                                sources.append({
                                    'type': TaintSource.FUNCTION_PARAM.value,
                                    'function': node.get('name', ''),
                                    'parameter': pname,
                                    'visibility': vis,
                                })
        except Exception:
            pass  # Fall back to regex
        return sources

    # ------------------------------------------------------------------
    # B. Taint propagation
    # ------------------------------------------------------------------

    def _propagate_taint(
        self,
        content: str,
        function_body: str,
        sources: List[TaintedVariable],
    ) -> List[TaintedVariable]:
        """Track how tainted data flows through a function body."""
        tainted: Dict[str, TaintedVariable] = {}
        for src in sources:
            tainted[src.name] = src

        # Process the function body line by line to track assignments
        lines = function_body.split('\n')
        changed = True
        iterations = 0
        max_iterations = 5  # limit fixed-point iterations for speed

        while changed and iterations < max_iterations:
            changed = False
            iterations += 1

            for line in lines:
                stripped = line.strip()
                if not stripped or stripped.startswith('//'):
                    continue

                new_tainted = self._propagate_line(stripped, tainted)
                for name, tv in new_tainted.items():
                    if name not in tainted:
                        tainted[name] = tv
                        changed = True

        return list(tainted.values())

    def _propagate_with_cfg(
        self,
        cfg: Any,
        sources: List[TaintedVariable],
    ) -> List[TaintedVariable]:
        """Branch-aware taint propagation using a ControlFlowGraph.

        Processes blocks in topological order (with loop fixed-point).
        Falls back to line-by-line propagation if CFG is empty or
        unusable.

        Args:
            cfg: A ControlFlowGraph object from solidity_ast.py
            sources: Initial taint sources for the function
        """
        from collections import deque as _deque

        blocks = getattr(cfg, 'blocks', None)
        entry = getattr(cfg, 'entry', None)
        if not blocks or entry is None:
            # Unusable CFG — caller should fall back
            return list(sources)

        # Per-block taint state: block_id -> {var_name: TaintedVariable}
        block_taint: Dict[int, Dict[str, TaintedVariable]] = {}
        for bid in blocks:
            block_taint[bid] = {}

        # Seed entry block with initial sources
        for src in sources:
            block_taint[entry][src.name] = src

        # Topological-ish traversal using a worklist
        worklist: _deque = _deque()
        worklist.append(entry)
        visit_count: Dict[int, int] = {bid: 0 for bid in blocks}
        max_visits = 5  # Bound iterations for loops

        while worklist:
            bid = worklist.popleft()
            if visit_count[bid] >= max_visits:
                continue
            visit_count[bid] += 1

            block = blocks[bid]

            # Merge taint from all predecessors into this block's input
            merged: Dict[str, TaintedVariable] = {}
            for pred_id in block.predecessors:
                for name, tv in block_taint.get(pred_id, {}).items():
                    if name not in merged:
                        merged[name] = tv

            # Also include any taint already computed for this block (from seeding)
            for name, tv in block_taint[bid].items():
                if name not in merged:
                    merged[name] = tv

            # Propagate through each statement in the block
            current = dict(merged)
            for stmt in block.statements:
                stripped = stmt.strip()
                if not stripped or stripped.startswith('//'):
                    continue
                # Reuse existing line-level propagation
                new_tainted = self._propagate_line(stripped, current)
                current.update(new_tainted)

            # Check if block taint changed
            old_taint = block_taint[bid]
            if set(current.keys()) != set(old_taint.keys()):
                block_taint[bid] = current
                # Add successors to worklist
                for succ_id in block.successors:
                    worklist.append(succ_id)
            else:
                # Even if keys match, values might differ (longer paths)
                changed = False
                for name in current:
                    if name not in old_taint:
                        changed = True
                        break
                if changed:
                    block_taint[bid] = current
                    for succ_id in block.successors:
                        worklist.append(succ_id)

        # Collect all tainted variables across all blocks
        all_tainted: Dict[str, TaintedVariable] = {}
        for bid in blocks:
            for name, tv in block_taint[bid].items():
                if name not in all_tainted:
                    all_tainted[name] = tv

        return list(all_tainted.values())

    def _propagate_line(
        self, line: str, current_taint: Dict[str, TaintedVariable]
    ) -> Dict[str, TaintedVariable]:
        """Propagate taint through a single line of code."""
        new_taint: Dict[str, TaintedVariable] = {}

        # Direct assignment: type varName = expr; or varName = expr;
        assign_match = re.match(
            r'(?:(?:uint\d*|int\d*|address|bytes\d*|bool|string|'
            r'\w+(?:\[\d*\])*)'
            r'(?:\s+(?:memory|storage|calldata))?'
            r'\s+)?'
            r'(\w+)\s*=[^=](.+?)(?:;|$)',
            line,
        )

        if assign_match:
            lhs = assign_match.group(1)
            rhs = assign_match.group(2)
            self._check_rhs_taint(lhs, rhs, current_taint, new_taint)

        # Compound assignments: x += tainted, x -= tainted, etc.
        compound_match = re.match(
            r'(\w+)\s*(?:\+=|-=|\*=|/=|%=|&=|\|=|\^=)\s*(.+?)(?:;|$)',
            line,
        )
        if compound_match:
            lhs = compound_match.group(1)
            rhs = compound_match.group(2)
            self._check_rhs_taint(lhs, rhs, current_taint, new_taint)
            # Also: if lhs was already tainted, it remains tainted
            if lhs in current_taint:
                new_taint[lhs] = current_taint[lhs]

        # Mapping/array write: mapping[key] = rhs
        mapping_match = re.match(
            r'(\w+)\s*\[([^\]]+)\]\s*=[^=]\s*(.+?)(?:;|$)', line
        )
        if mapping_match:
            mapping_name = mapping_match.group(1)
            key_expr = mapping_match.group(2)
            rhs = mapping_match.group(3)
            # If key or value is tainted, the mapping entry is tainted
            for tname in current_taint:
                if re.search(r'\b' + re.escape(tname) + r'\b', key_expr + ' ' + rhs):
                    entry_name = f"{mapping_name}[{key_expr.strip()}]"
                    tv = current_taint[tname]
                    new_taint[entry_name] = TaintedVariable(
                        name=entry_name,
                        source=tv.source,
                        source_function=tv.source_function,
                        source_param=tv.source_param,
                        taint_path=tv.taint_path + [entry_name],
                    )
                    # Also mark the mapping name itself as tainted (for sink detection)
                    new_taint[mapping_name] = TaintedVariable(
                        name=mapping_name,
                        source=tv.source,
                        source_function=tv.source_function,
                        source_param=tv.source_param,
                        taint_path=tv.taint_path + [mapping_name],
                    )
                    break

        # Ternary: z = cond ? taintedA : safeB
        ternary_match = re.match(
            r'(?:\w+\s+)?(\w+)\s*=\s*.+\?\s*(.+?)\s*:\s*(.+?)(?:;|$)', line
        )
        if ternary_match:
            lhs = ternary_match.group(1)
            branch_a = ternary_match.group(2)
            branch_b = ternary_match.group(3)
            for tname, tv in current_taint.items():
                if (re.search(r'\b' + re.escape(tname) + r'\b', branch_a) or
                        re.search(r'\b' + re.escape(tname) + r'\b', branch_b)):
                    if lhs not in new_taint:
                        new_taint[lhs] = TaintedVariable(
                            name=lhs,
                            source=tv.source,
                            source_function=tv.source_function,
                            source_param=tv.source_param,
                            taint_path=tv.taint_path + [lhs],
                        )
                    break

        return new_taint

    def _check_rhs_taint(
        self,
        lhs: str,
        rhs: str,
        current_taint: Dict[str, TaintedVariable],
        new_taint: Dict[str, TaintedVariable],
    ) -> None:
        """Check if RHS expression contains any tainted variable and propagate to LHS."""
        for tname, tv in current_taint.items():
            if re.search(r'\b' + re.escape(tname) + r'\b', rhs):
                new_taint[lhs] = TaintedVariable(
                    name=lhs,
                    source=tv.source,
                    source_function=tv.source_function,
                    source_param=tv.source_param,
                    taint_path=tv.taint_path + [lhs],
                )
                break

    # ------------------------------------------------------------------
    # C. Sanitizer detection
    # ------------------------------------------------------------------

    def _detect_sanitizers(
        self, function_body: str, tainted_var: str, modifiers: str = ""
    ) -> List[str]:
        """Check for validation between source and sink."""
        sanitizers: List[str] = []
        escaped_var = re.escape(tainted_var)

        # require() checks involving the tainted variable
        require_re = re.compile(
            r'require\s*\([^;]*\b' + escaped_var + r'\b[^;]*\)',
            re.DOTALL,
        )
        for m in require_re.finditer(function_body):
            sanitizers.append(f"require: {m.group(0).strip()[:80]}")

        # Conditional revert: if (...tainted...) revert
        if_revert_re = re.compile(
            r'if\s*\([^)]*\b' + escaped_var + r'\b[^)]*\)\s*(?:revert\b|{[^}]*revert\b)',
            re.DOTALL,
        )
        for m in if_revert_re.finditer(function_body):
            sanitizers.append(f"conditional_revert: {m.group(0).strip()[:80]}")

        # assert() checks
        assert_re = re.compile(
            r'assert\s*\([^;]*\b' + escaped_var + r'\b[^;]*\)',
            re.DOTALL,
        )
        for m in assert_re.finditer(function_body):
            sanitizers.append(f"assert: {m.group(0).strip()[:80]}")

        # Math.min / Math.max clamping
        clamp_re = re.compile(
            r'(?:Math\.min|Math\.max|FixedPointMathLib\.min|'
            r'FixedPointMathLib\.max|SignedMath\.min|SignedMath\.max)'
            r'\s*\([^)]*\b' + escaped_var + r'\b',
        )
        if clamp_re.search(function_body):
            sanitizers.append("clamping: Math.min/max")

        # SafeCast
        safecast_re = re.compile(
            r'SafeCast\.\w+\s*\(\s*' + escaped_var + r'\b',
        )
        if safecast_re.search(function_body):
            sanitizers.append("safe_cast: SafeCast")

        # Access control modifiers
        if modifiers:
            mod_match = _MODIFIER_RE.search(modifiers)
            if mod_match:
                # Access control is a sanitizer for msg.sender-sourced taint
                sanitizers.append(f"access_control: {mod_match.group(1)}")

        # Simple if-guard: if (tainted == 0) revert or return
        if_guard_re = re.compile(
            r'if\s*\(\s*' + escaped_var + r'\s*==\s*(?:0|address\(0\))\s*\)\s*(?:revert|return)',
        )
        if if_guard_re.search(function_body):
            sanitizers.append("zero_check")

        # Zero address check in require
        zero_addr_re = re.compile(
            r'require\s*\([^;]*\b' + escaped_var +
            r'\b\s*!=\s*address\s*\(\s*0\s*\)',
            re.DOTALL,
        )
        if zero_addr_re.search(function_body):
            sanitizers.append("zero_address_check")

        return sanitizers

    # ------------------------------------------------------------------
    # D. Sink detection
    # ------------------------------------------------------------------

    def _detect_sinks(
        self,
        content: str,
        function_body: str,
        tainted_vars: Set[str],
        line_offset: int = 0,
    ) -> List[Dict]:
        """Find where tainted data is used dangerously."""
        sinks: List[Dict] = []
        lines = function_body.split('\n')

        for line_idx, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith('//'):
                continue

            abs_line = line_offset + line_idx + 1

            for tvar in tainted_vars:
                if not re.search(r'\b' + re.escape(tvar) + r'\b', stripped):
                    continue

                # .call{value: tainted}
                if re.search(
                    r'\.call\s*\{[^}]*value\s*:\s*[^}]*\b' + re.escape(tvar) + r'\b',
                    stripped,
                ):
                    sinks.append({
                        'sink': TaintSink.EXTERNAL_CALL_VALUE,
                        'expression': stripped[:120],
                        'line': abs_line,
                        'tainted_var': tvar,
                    })
                    continue

                # .delegatecall(tainted)
                if re.search(
                    r'\.delegatecall\s*\([^)]*\b' + re.escape(tvar) + r'\b',
                    stripped,
                ):
                    sinks.append({
                        'sink': TaintSink.DELEGATECALL,
                        'expression': stripped[:120],
                        'line': abs_line,
                        'tainted_var': tvar,
                    })
                    continue

                # selfdestruct(tainted)
                if re.search(
                    r'selfdestruct\s*\(\s*' + re.escape(tvar) + r'\b',
                    stripped,
                ):
                    sinks.append({
                        'sink': TaintSink.SELFDESTRUCT,
                        'expression': stripped[:120],
                        'line': abs_line,
                        'tainted_var': tvar,
                    })
                    continue

                # payable(tainted).transfer() or payable(tainted).send()
                if re.search(
                    r'payable\s*\(\s*' + re.escape(tvar) + r'\s*\)\s*\.\s*(?:transfer|send)\s*\(',
                    stripped,
                ):
                    sinks.append({
                        'sink': TaintSink.ETH_TRANSFER,
                        'expression': stripped[:120],
                        'line': abs_line,
                        'tainted_var': tvar,
                    })
                    continue

                # .transfer(tainted, ...) or .transfer(..., tainted) — ETH/token transfer
                if re.search(
                    r'\.transfer\s*\([^)]*\b' + re.escape(tvar) + r'\b',
                    stripped,
                ):
                    sinks.append({
                        'sink': TaintSink.ETH_TRANSFER,
                        'expression': stripped[:120],
                        'line': abs_line,
                        'tainted_var': tvar,
                    })
                    continue

                # .call(abi.encode...(tainted)) — external call with tainted data
                if re.search(
                    r'\.call\s*\([^)]*\b' + re.escape(tvar) + r'\b',
                    stripped,
                ):
                    sinks.append({
                        'sink': TaintSink.EXTERNAL_CALL,
                        'expression': stripped[:120],
                        'line': abs_line,
                        'tainted_var': tvar,
                    })
                    continue

                # General external method call with tainted args:
                # instance.method(...tainted...) — but not .call/.delegatecall/.transfer/.send
                if re.search(
                    r'\w+\.\w+\s*\([^)]*\b' + re.escape(tvar) + r'\b[^)]*\)',
                    stripped,
                ) and not re.search(
                    r'\.\s*(?:call|delegatecall|staticcall|transfer|send)\s*[\({]',
                    stripped,
                ):
                    sinks.append({
                        'sink': TaintSink.EXTERNAL_CALL,
                        'expression': stripped[:120],
                        'line': abs_line,
                        'tainted_var': tvar,
                    })
                    continue

                # x / tainted — division by potentially zero
                if re.search(
                    r'[/]\s*' + re.escape(tvar) + r'\b', stripped
                ):
                    sinks.append({
                        'sink': TaintSink.DIVISION,
                        'expression': stripped[:120],
                        'line': abs_line,
                        'tainted_var': tvar,
                    })
                    continue

                # array[tainted] — array index
                if re.search(
                    r'\w+\s*\[\s*' + re.escape(tvar) + r'\s*\]', stripped
                ):
                    sinks.append({
                        'sink': TaintSink.ARRAY_INDEX,
                        'expression': stripped[:120],
                        'line': abs_line,
                        'tainted_var': tvar,
                    })
                    continue

                # new Contract(tainted)
                if re.search(
                    r'\bnew\s+\w+\s*\([^)]*\b' + re.escape(tvar) + r'\b',
                    stripped,
                ):
                    sinks.append({
                        'sink': TaintSink.CREATE,
                        'expression': stripped[:120],
                        'line': abs_line,
                        'tainted_var': tvar,
                    })
                    continue

                # mstore(tainted, ...) — assembly
                if re.search(
                    r'\bmstore\s*\(\s*' + re.escape(tvar) + r'\b', stripped
                ):
                    sinks.append({
                        'sink': TaintSink.ASSEMBLY_MSTORE,
                        'expression': stripped[:120],
                        'line': abs_line,
                        'tainted_var': tvar,
                    })
                    continue

                # emit Event(tainted)
                if re.search(
                    r'\bemit\s+\w+\s*\([^)]*\b' + re.escape(tvar) + r'\b',
                    stripped,
                ):
                    sinks.append({
                        'sink': TaintSink.EVENT_EMIT,
                        'expression': stripped[:120],
                        'line': abs_line,
                        'tainted_var': tvar,
                    })
                    continue

                # Storage write via compound assignment: state += tainted, state[k] += tainted
                compound_store_match = re.match(
                    r'(\w+(?:\s*\[[^\]]*\])?)\s*(?:\+=|-=|\*=|/=|%=|&=|\|=|\^=)\s*'
                    r'.*\b' + re.escape(tvar) + r'\b',
                    stripped,
                )
                if compound_store_match:
                    sinks.append({
                        'sink': TaintSink.STORAGE_WRITE,
                        'expression': stripped[:120],
                        'line': abs_line,
                        'tainted_var': tvar,
                    })
                    continue

                # Storage write: stateVar = tainted (only for state variables)
                # This is a broader pattern - check if LHS looks like state write
                storage_write_match = re.match(
                    r'(\w+)\s*=[^=]\s*.*\b' + re.escape(tvar) + r'\b',
                    stripped,
                )
                if storage_write_match:
                    lhs = storage_write_match.group(1)
                    # Only flag if LHS looks like a state variable (not a local declaration)
                    if not re.match(
                        r'(?:uint\d*|int\d*|address|bytes\d*|bool|string)\s',
                        stripped,
                    ):
                        sinks.append({
                            'sink': TaintSink.STORAGE_WRITE,
                            'expression': stripped[:120],
                            'line': abs_line,
                            'tainted_var': tvar,
                        })
                        continue

        return sinks

    # ------------------------------------------------------------------
    # E. Severity calculation
    # ------------------------------------------------------------------

    def _calculate_severity(
        self, sink: TaintSink, is_sanitized: bool, source: TaintSource
    ) -> str:
        """Calculate severity based on sink type, sanitization, and source."""
        base_severity = self._sink_severity.get(sink, "medium")

        if is_sanitized:
            # Downgrade by one level
            severity_order = ["critical", "high", "medium", "low"]
            idx = severity_order.index(base_severity) if base_severity in severity_order else 1
            return severity_order[min(idx + 1, len(severity_order) - 1)]

        # Block timestamp/number sources are less critical
        if source in (TaintSource.BLOCK_TIMESTAMP, TaintSource.BLOCK_NUMBER):
            if base_severity == "critical":
                return "high"
            elif base_severity == "high":
                return "medium"

        return base_severity

    # ------------------------------------------------------------------
    # F. Description + format helpers
    # ------------------------------------------------------------------

    def _build_flow_description(
        self,
        tv: TaintedVariable,
        sink: TaintSink,
        sink_expr: str,
        is_sanitized: bool,
        sanitizers: List[str],
    ) -> str:
        """Build a human-readable description of a taint flow."""
        source_desc = f"{tv.source_param} ({tv.source.value})"
        sink_desc = f"{sink.value}: {sink_expr[:60]}"

        if is_sanitized:
            san_str = ', '.join(sanitizers)
            return (
                f"Tainted data from {source_desc} reaches {sink_desc} "
                f"but is sanitized by: {san_str}"
            )
        else:
            return (
                f"Tainted data from {source_desc} reaches {sink_desc} "
                f"without sanitization"
            )

    def _build_summary(self, report: TaintReport) -> Dict[str, int]:
        """Build summary counts for a report."""
        summary: Dict[str, int] = {
            'total_flows': len(report.taint_flows),
            'dangerous_flows': len(report.dangerous_flows),
            'sanitized_flows': len(report.sanitized_flows),
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
        }
        for flow in report.dangerous_flows:
            sev = flow.severity
            if sev in summary:
                summary[sev] += 1
        return summary

    # ------------------------------------------------------------------
    # G. Cross-contract taint tracking
    # ------------------------------------------------------------------

    def _detect_cross_contract_taint(
        self,
        contract_files: List[Dict[str, Any]],
        reports: List[TaintReport],
    ) -> List[Tuple[TaintFlow, int]]:
        """Detect taint flows that cross contract boundaries.

        Returns list of (TaintFlow, caller_index) tuples.
        """
        cross_flows: List[Tuple[TaintFlow, int]] = []

        # Build a map: contract_name -> index
        name_to_idx: Dict[str, int] = {}
        for i, cf in enumerate(contract_files):
            name = cf.get('name', '')
            if name:
                # Strip .sol extension and path
                clean = name.rsplit('/', 1)[-1].replace('.sol', '')
                name_to_idx[clean] = i
                name_to_idx[name] = i

        # For each contract, look for external calls carrying tainted params
        for caller_idx, cf in enumerate(contract_files):
            content = cf.get('content', '')
            caller_name = cf.get('name', '')
            caller_report = reports[caller_idx]

            # Find tainted variables in this contract's dangerous flows
            tainted_params: Set[str] = set()
            for flow in caller_report.taint_flows:
                tainted_params.add(flow.source_param)
                for path_var in flow.taint_path:
                    # Extract just the variable name (not state: prefix etc.)
                    clean_var = path_var.split(':')[-1].strip()
                    tainted_params.add(clean_var)

            if not tainted_params:
                continue

            # Find external calls: instance.method(args)
            ext_call_re = re.compile(
                r'(\w+)\s*\.\s*(\w+)\s*\(([^)]*)\)'
            )

            for m in ext_call_re.finditer(content):
                target_instance = m.group(1)
                method_name = m.group(2)
                args = m.group(3)

                # Check if any arg is tainted
                call_tainted_args = []
                for tvar in tainted_params:
                    if re.search(r'\b' + re.escape(tvar) + r'\b', args):
                        call_tainted_args.append(tvar)

                if not call_tainted_args:
                    continue

                # Try to identify the target contract type
                type_re = re.compile(
                    r'(?:' + re.escape(target_instance)
                    + r'\s*=\s*(\w+)\s*\(|'
                    + r'(\w+)\s+(?:public\s+|private\s+|internal\s+)?'
                    + re.escape(target_instance) + r'\b)'
                )
                type_match = type_re.search(content)
                target_type = ''
                if type_match:
                    target_type = type_match.group(1) or type_match.group(2) or ''

                # Determine target line
                line_num = content[:m.start()].count('\n') + 1

                for targ in call_tainted_args:
                    flow = TaintFlow(
                        source=TaintSource.FUNCTION_PARAM,
                        source_function=caller_name,
                        source_param=targ,
                        sink=TaintSink.EXTERNAL_CALL,
                        sink_function=f"{target_instance}.{method_name}",
                        sink_expression=m.group(0)[:120],
                        sink_line=line_num,
                        taint_path=[targ, f"cross:{target_instance}.{method_name}"],
                        is_sanitized=False,
                        sanitizers=[],
                        severity="high",
                        description=(
                            f"Tainted parameter '{targ}' flows across contract "
                            f"boundary to {target_instance}.{method_name}()"
                        ),
                    )
                    cross_flows.append((flow, caller_idx))

        return cross_flows

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------

    def _detect_contract_name(self, content: str) -> str:
        """Extract the primary contract name from source code."""
        m = re.search(r'\bcontract\s+(\w+)', content)
        return m.group(1) if m else "Unknown"

    def _extract_functions(
        self, content: str, ast_data: Optional[Any] = None
    ) -> List[Dict]:
        """Extract function information from contract source."""
        functions: List[Dict] = []

        # Remove single-line comments to avoid false matches
        clean = re.sub(r'//[^\n]*', '', content)
        # Remove multi-line comments
        clean = re.sub(r'/\*.*?\*/', '', clean, flags=re.DOTALL)

        for m in _FUNC_RE.finditer(clean):
            name = m.group(1)
            raw_params = m.group(2)
            modifier_str = m.group(3) or ''

            # Determine visibility
            vis_match = _VISIBILITY_RE.search(modifier_str)
            visibility = vis_match.group(1) if vis_match else 'internal'

            # Parse parameter names
            params = [pm.group(1) for pm in _PARAM_RE.finditer(raw_params)]

            # Extract function body (brace-counting)
            body_start = m.end()  # right after opening brace
            body = self._extract_brace_block(clean, body_start - 1)

            # Line offset of function in the original content
            line_offset = content[:m.start()].count('\n')

            functions.append({
                'name': name,
                'params': params,
                'visibility': visibility,
                'body': body,
                'modifiers': modifier_str,
                'line_offset': line_offset,
            })

        return functions

    def _extract_brace_block(self, content: str, open_brace_pos: int) -> str:
        """Extract content between matching braces starting at open_brace_pos."""
        if open_brace_pos >= len(content) or content[open_brace_pos] != '{':
            return ""

        depth = 0
        start = open_brace_pos + 1
        for i in range(open_brace_pos, len(content)):
            ch = content[i]
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    return content[start:i]
        return content[start:]

    def _extract_state_variables(self, content: str) -> Set[str]:
        """Extract state variable names from contract source."""
        state_vars: Set[str] = set()

        # Remove comments
        clean = re.sub(r'//[^\n]*', '', content)
        clean = re.sub(r'/\*.*?\*/', '', clean, flags=re.DOTALL)

        # Find contract bodies
        contract_re = re.compile(
            r'\bcontract\s+\w+[^{]*\{', re.DOTALL
        )

        for cm in contract_re.finditer(clean):
            body = self._extract_brace_block(clean, cm.end() - 1)
            # State variables are declared at the top level of the contract body
            # (not inside functions)
            # Remove function bodies to get only top-level declarations
            func_free = re.sub(
                r'function\s+\w+\s*\([^)]*\)[^{]*\{[^}]*(?:\{[^}]*\}[^}]*)*\}',
                '',
                body,
                flags=re.DOTALL,
            )

            # Match state variable declarations
            var_re = re.compile(
                r'(?:uint\d*|int\d*|address|bytes\d*|bool|string|'
                r'mapping\s*\([^)]*\)|'
                r'\w+(?:\[\d*\])*)'
                r'(?:\s+(?:public|private|internal|constant|immutable))*'
                r'\s+(\w+)\s*[;=]'
            )
            for vm in var_re.finditer(func_free):
                state_vars.add(vm.group(1))

        return state_vars

    def _find_external_call_returns(self, function_body: str) -> List[str]:
        """Find variables that receive return values from external calls."""
        results: List[str] = []

        # Pattern: (bool success, bytes memory data) = target.call(...)
        call_ret_re = re.compile(
            r'\(?\s*(?:\w+\s+)?(\w+)\s*(?:,\s*(?:\w+\s+)?\w+)*\s*\)?\s*='
            r'\s*\w+\.\w+\s*[\({]',
        )
        for m in call_ret_re.finditer(function_body):
            results.append(m.group(1))

        # Pattern: uint256 result = IContract(addr).method(...)
        single_ret_re = re.compile(
            r'(?:uint\d*|int\d*|address|bytes\d*|bool)\s+(\w+)\s*=\s*'
            r'(?:I\w+\s*\([^)]*\)\s*\.\s*\w+|'   # IContract(addr).method
            r'\w+\s*\.\s*\w+)\s*\(',               # instance.method
        )
        for m in single_ret_re.finditer(function_body):
            results.append(m.group(1))

        return results
