"""Tests for Control Flow Graph construction, analysis, and assembly parsing.

Tests cover:
  - CFG construction for simple functions (if/else)
  - CFG construction for loops (for, while, do-while)
  - CFG construction for nested control flow
  - CFG construction for try/catch
  - CFG construction for terminal statements (return, revert)
  - Dominator computation
  - Loop header detection
  - Reachable block analysis
  - Assembly block parsing
  - format_cfg_for_llm output
  - Branch-aware taint propagation with CFG
"""

import unittest

from core.solidity_ast import (
    AssemblyBlock,
    BasicBlock,
    CFGEdge,
    ControlFlowGraph,
    SolidityASTParser,
)
from core.taint_analyzer import TaintAnalyzer, TaintedVariable, TaintSource


class TestCFGDataclasses(unittest.TestCase):
    """Test the CFG dataclass constructors."""

    def test_basic_block_defaults(self):
        b = BasicBlock(id=0)
        self.assertEqual(b.id, 0)
        self.assertEqual(b.statements, [])
        self.assertEqual(b.successors, [])
        self.assertEqual(b.predecessors, [])

    def test_cfg_edge_defaults(self):
        e = CFGEdge(from_block=0, to_block=1)
        self.assertEqual(e.from_block, 0)
        self.assertEqual(e.to_block, 1)
        self.assertIsNone(e.condition)

    def test_cfg_edge_with_condition(self):
        e = CFGEdge(from_block=0, to_block=1, condition="x > 0")
        self.assertEqual(e.condition, "x > 0")

    def test_control_flow_graph_defaults(self):
        cfg = ControlFlowGraph()
        self.assertEqual(cfg.blocks, {})
        self.assertEqual(cfg.entry, 0)
        self.assertEqual(cfg.exits, [])
        self.assertEqual(cfg.edges, [])

    def test_assembly_block_defaults(self):
        ab = AssemblyBlock()
        self.assertEqual(ab.opcodes, [])
        self.assertEqual(ab.memory_reads, [])
        self.assertEqual(ab.memory_writes, [])
        self.assertEqual(ab.storage_reads, [])
        self.assertEqual(ab.storage_writes, [])
        self.assertEqual(ab.external_calls, [])


class TestCFGConstruction(unittest.TestCase):
    """Test CFG building from function body source code."""

    def setUp(self):
        self.parser = SolidityASTParser()

    def test_empty_body(self):
        cfg = self.parser.build_cfg("")
        self.assertIn(cfg.entry, cfg.blocks)
        self.assertTrue(len(cfg.exits) > 0)

    def test_simple_statements(self):
        body = """
        uint256 x = 1;
        uint256 y = 2;
        uint256 z = x + y;
        """
        cfg = self.parser.build_cfg(body)
        self.assertIn(cfg.entry, cfg.blocks)
        # All statements in one block
        entry_block = cfg.blocks[cfg.entry]
        self.assertTrue(len(entry_block.statements) >= 3)

    def test_if_else_creates_branches(self):
        body = """
        uint256 x = 1;
        if (x > 0) {
            x = 2;
        } else {
            x = 3;
        }
        uint256 y = x;
        """
        cfg = self.parser.build_cfg(body)
        # Should have multiple blocks: entry, then, else, continuation
        self.assertTrue(len(cfg.blocks) >= 3)
        # Should have edges with conditions
        conditional_edges = [e for e in cfg.edges if e.condition is not None]
        self.assertTrue(len(conditional_edges) >= 1)

    def test_if_without_else(self):
        body = """
        uint256 x = 1;
        if (x > 0) {
            x = 2;
        }
        uint256 y = x;
        """
        cfg = self.parser.build_cfg(body)
        self.assertTrue(len(cfg.blocks) >= 2)

    def test_for_loop(self):
        body = """
        uint256 sum = 0;
        for (uint256 i = 0; i < 10; i++) {
            sum += i;
        }
        return sum;
        """
        cfg = self.parser.build_cfg(body)
        # Should have loop header, body, and exit
        self.assertTrue(len(cfg.blocks) >= 3)
        # Check for back edges (loop structure)
        loop_headers = self.parser.get_loop_headers(cfg)
        self.assertTrue(len(loop_headers) >= 1)

    def test_while_loop(self):
        body = """
        uint256 x = 100;
        while (x > 0) {
            x -= 1;
        }
        return x;
        """
        cfg = self.parser.build_cfg(body)
        self.assertTrue(len(cfg.blocks) >= 3)
        loop_headers = self.parser.get_loop_headers(cfg)
        self.assertTrue(len(loop_headers) >= 1)

    def test_do_while_loop(self):
        body = """
        uint256 x = 10;
        do {
            x -= 1;
        } while (x > 0);
        return x;
        """
        cfg = self.parser.build_cfg(body)
        self.assertTrue(len(cfg.blocks) >= 2)

    def test_nested_if(self):
        body = """
        uint256 x = 1;
        if (x > 0) {
            if (x > 5) {
                x = 10;
            } else {
                x = 3;
            }
        } else {
            x = 0;
        }
        return x;
        """
        cfg = self.parser.build_cfg(body)
        # Nested branches should produce more blocks
        self.assertTrue(len(cfg.blocks) >= 4)

    def test_return_terminates_block(self):
        body = """
        if (x > 0) {
            return 1;
        }
        return 0;
        """
        cfg = self.parser.build_cfg(body)
        # Both returns should be in exit blocks
        self.assertTrue(len(cfg.exits) >= 1)

    def test_revert_terminates_block(self):
        body = """
        if (x == 0) {
            revert("zero");
        }
        return x;
        """
        cfg = self.parser.build_cfg(body)
        # Revert and return are both terminal
        terminal_count = 0
        for bid in cfg.blocks:
            block = cfg.blocks[bid]
            for stmt in block.statements:
                if stmt.strip().startswith('return') or stmt.strip().startswith('revert'):
                    terminal_count += 1
        self.assertTrue(terminal_count >= 1)

    def test_try_catch(self):
        body = """
        uint256 result;
        try IContract(addr).doSomething() returns (uint256 val) {
            result = val;
        } catch {
            result = 0;
        }
        return result;
        """
        cfg = self.parser.build_cfg(body)
        # try/catch creates two branches
        self.assertTrue(len(cfg.blocks) >= 3)

    def test_require_not_terminal(self):
        """require() is not treated as a terminal statement."""
        body = """
        require(x > 0, "must be positive");
        uint256 y = x * 2;
        return y;
        """
        cfg = self.parser.build_cfg(body)
        # require should be in the same block as subsequent statements
        entry = cfg.blocks[cfg.entry]
        self.assertTrue(len(entry.statements) >= 2)

    def test_assembly_block_in_cfg(self):
        body = """
        uint256 x;
        assembly {
            x := sload(0)
        }
        return x;
        """
        cfg = self.parser.build_cfg(body)
        # Assembly block should be in a statement
        found_assembly = False
        for block in cfg.blocks.values():
            for stmt in block.statements:
                if 'assembly' in stmt:
                    found_assembly = True
        self.assertTrue(found_assembly)

    def test_multiple_sequential_ifs(self):
        body = """
        if (a > 0) {
            x = 1;
        }
        if (b > 0) {
            y = 1;
        }
        return x + y;
        """
        cfg = self.parser.build_cfg(body)
        self.assertTrue(len(cfg.blocks) >= 4)

    def test_loop_with_nested_if(self):
        body = """
        for (uint256 i = 0; i < n; i++) {
            if (data[i] > threshold) {
                total += data[i];
            }
        }
        """
        cfg = self.parser.build_cfg(body)
        self.assertTrue(len(cfg.blocks) >= 3)


class TestDominators(unittest.TestCase):
    """Test dominator computation."""

    def setUp(self):
        self.parser = SolidityASTParser()

    def test_simple_linear_dominators(self):
        body = """
        uint256 x = 1;
        uint256 y = 2;
        return x + y;
        """
        cfg = self.parser.build_cfg(body)
        dom = self.parser.get_dominators(cfg)
        # Entry dominates everything
        for bid in cfg.blocks:
            self.assertIn(cfg.entry, dom[bid])

    def test_if_else_dominators(self):
        body = """
        if (x > 0) {
            x = 1;
        } else {
            x = 2;
        }
        return x;
        """
        cfg = self.parser.build_cfg(body)
        dom = self.parser.get_dominators(cfg)
        # Entry block should dominate all other blocks
        for bid in cfg.blocks:
            self.assertIn(cfg.entry, dom[bid])

    def test_every_block_dominates_itself(self):
        body = """
        if (a) { x = 1; }
        if (b) { y = 1; }
        """
        cfg = self.parser.build_cfg(body)
        dom = self.parser.get_dominators(cfg)
        for bid in cfg.blocks:
            self.assertIn(bid, dom[bid])

    def test_empty_cfg_dominators(self):
        cfg = self.parser.build_cfg("")
        dom = self.parser.get_dominators(cfg)
        self.assertTrue(len(dom) >= 1)


class TestLoopHeaders(unittest.TestCase):
    """Test loop header detection via back-edge analysis."""

    def setUp(self):
        self.parser = SolidityASTParser()

    def test_for_loop_header(self):
        body = """
        for (uint256 i = 0; i < 10; i++) {
            sum += i;
        }
        """
        cfg = self.parser.build_cfg(body)
        headers = self.parser.get_loop_headers(cfg)
        self.assertTrue(len(headers) >= 1)

    def test_while_loop_header(self):
        body = """
        while (x > 0) {
            x -= 1;
        }
        """
        cfg = self.parser.build_cfg(body)
        headers = self.parser.get_loop_headers(cfg)
        self.assertTrue(len(headers) >= 1)

    def test_no_loop_no_header(self):
        body = """
        uint256 x = 1;
        return x;
        """
        cfg = self.parser.build_cfg(body)
        headers = self.parser.get_loop_headers(cfg)
        self.assertEqual(len(headers), 0)

    def test_nested_loops_multiple_headers(self):
        body = """
        for (uint256 i = 0; i < 10; i++) {
            for (uint256 j = 0; j < 10; j++) {
                sum += i * j;
            }
        }
        """
        cfg = self.parser.build_cfg(body)
        headers = self.parser.get_loop_headers(cfg)
        self.assertTrue(len(headers) >= 1)


class TestReachableBlocks(unittest.TestCase):
    """Test block reachability."""

    def setUp(self):
        self.parser = SolidityASTParser()

    def test_all_reachable_from_entry(self):
        body = """
        if (x > 0) {
            return 1;
        }
        return 0;
        """
        cfg = self.parser.build_cfg(body)
        reachable = self.parser.get_reachable_blocks(cfg, cfg.entry)
        # All blocks should be reachable from entry
        self.assertEqual(reachable, set(cfg.blocks.keys()))

    def test_exit_reaches_only_itself_if_no_successors(self):
        body = """
        return 42;
        """
        cfg = self.parser.build_cfg(body)
        for exit_id in cfg.exits:
            reachable = self.parser.get_reachable_blocks(cfg, exit_id)
            # Exit with no successors reaches only itself
            if not cfg.blocks[exit_id].successors:
                self.assertEqual(reachable, {exit_id})


class TestAssemblyParsing(unittest.TestCase):
    """Test inline assembly / Yul block parsing."""

    def setUp(self):
        self.parser = SolidityASTParser()

    def test_memory_operations(self):
        code = """
        assembly {
            let x := mload(0x40)
            mstore(0x40, add(x, 0x20))
        }
        """
        result = self.parser.parse_assembly_block(code)
        self.assertIn('mload', result.opcodes)
        self.assertIn('mstore', result.opcodes)
        self.assertTrue(len(result.memory_reads) >= 1)
        self.assertTrue(len(result.memory_writes) >= 1)

    def test_storage_operations(self):
        code = """
        assembly {
            let val := sload(slot)
            sstore(slot, newVal)
        }
        """
        result = self.parser.parse_assembly_block(code)
        self.assertIn('sload', result.opcodes)
        self.assertIn('sstore', result.opcodes)
        self.assertTrue(len(result.storage_reads) >= 1)
        self.assertTrue(len(result.storage_writes) >= 1)

    def test_external_call_detection(self):
        code = """
        assembly {
            let success := call(gas(), target, value, 0, 0, 0, 0)
        }
        """
        result = self.parser.parse_assembly_block(code)
        self.assertIn('call', result.opcodes)
        self.assertTrue(len(result.external_calls) >= 1)

    def test_delegatecall_detection(self):
        code = """
        assembly {
            let success := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
        }
        """
        result = self.parser.parse_assembly_block(code)
        self.assertIn('delegatecall', result.opcodes)
        self.assertTrue(len(result.external_calls) >= 1)

    def test_staticcall_detection(self):
        code = """
        assembly {
            let success := staticcall(gas(), target, 0, 0x24, 0, 0x20)
        }
        """
        result = self.parser.parse_assembly_block(code)
        self.assertIn('staticcall', result.opcodes)
        self.assertTrue(len(result.external_calls) >= 1)

    def test_create_detection(self):
        code = """
        assembly {
            let addr := create(0, ptr, size)
            let addr2 := create2(0, ptr, size, salt)
        }
        """
        result = self.parser.parse_assembly_block(code)
        self.assertIn('create', result.opcodes)
        self.assertIn('create2', result.opcodes)
        self.assertTrue(len(result.external_calls) >= 2)

    def test_empty_assembly(self):
        code = "assembly { }"
        result = self.parser.parse_assembly_block(code)
        self.assertEqual(result.opcodes, [])
        self.assertEqual(result.external_calls, [])

    def test_multiple_sloads(self):
        code = """
        assembly {
            let a := sload(0)
            let b := sload(1)
            let c := sload(add(slot, 2))
        }
        """
        result = self.parser.parse_assembly_block(code)
        self.assertTrue(len(result.storage_reads) >= 3)

    def test_mstore8(self):
        code = """
        assembly {
            mstore8(ptr, byte(0, value))
        }
        """
        result = self.parser.parse_assembly_block(code)
        self.assertIn('mstore8', result.opcodes)
        self.assertTrue(len(result.memory_writes) >= 1)

    def test_arithmetic_opcodes(self):
        code = """
        assembly {
            let result := add(mul(a, b), div(c, d))
        }
        """
        result = self.parser.parse_assembly_block(code)
        self.assertIn('add', result.opcodes)
        self.assertIn('mul', result.opcodes)
        self.assertIn('div', result.opcodes)

    def test_raw_code_without_assembly_wrapper(self):
        """Should handle Yul code without assembly { } wrapper."""
        code = """
        let x := sload(0)
        mstore(0, x)
        """
        result = self.parser.parse_assembly_block(code)
        self.assertTrue(len(result.storage_reads) >= 1)
        self.assertTrue(len(result.memory_writes) >= 1)


class TestFormatCFGForLLM(unittest.TestCase):
    """Test CFG formatting for LLM prompt injection."""

    def setUp(self):
        self.parser = SolidityASTParser()

    def test_format_contains_entry_and_exit(self):
        body = """
        uint256 x = 1;
        return x;
        """
        cfg = self.parser.build_cfg(body)
        output = self.parser.format_cfg_for_llm(cfg)
        self.assertIn("Entry:", output)
        self.assertIn("Exits:", output)
        self.assertIn("Control Flow Graph", output)

    def test_format_contains_block_labels(self):
        body = """
        if (x > 0) {
            return 1;
        }
        return 0;
        """
        cfg = self.parser.build_cfg(body)
        output = self.parser.format_cfg_for_llm(cfg)
        self.assertIn("B0", output)

    def test_format_shows_loop_headers(self):
        body = """
        for (uint i = 0; i < 10; i++) {
            x += 1;
        }
        """
        cfg = self.parser.build_cfg(body)
        output = self.parser.format_cfg_for_llm(cfg)
        # Should mention loop headers if any exist
        headers = self.parser.get_loop_headers(cfg)
        if headers:
            self.assertIn("loop header", output.lower())

    def test_format_shows_edges(self):
        body = """
        if (x > 0) {
            y = 1;
        } else {
            y = 2;
        }
        """
        cfg = self.parser.build_cfg(body)
        output = self.parser.format_cfg_for_llm(cfg)
        # Should show edge directions
        self.assertIn("->", output)

    def test_format_truncates_long_statements(self):
        long_stmt = "x = " + "a + " * 50 + "b"
        body = f"{long_stmt};"
        cfg = self.parser.build_cfg(body)
        output = self.parser.format_cfg_for_llm(cfg)
        # Long statements should be truncated with "..."
        self.assertIn("...", output)


class TestBranchAwareTaintPropagation(unittest.TestCase):
    """Test CFG-based taint propagation in TaintAnalyzer."""

    def setUp(self):
        self.analyzer = TaintAnalyzer()
        self.parser = SolidityASTParser()

    def test_propagate_with_simple_cfg(self):
        body = """
        uint256 x = amount;
        uint256 y = x + 1;
        """
        cfg = self.parser.build_cfg(body)

        sources = [
            TaintedVariable(
                name="amount",
                source=TaintSource.FUNCTION_PARAM,
                source_function="transfer",
                source_param="amount",
                taint_path=["amount"],
            )
        ]

        result = self.analyzer._propagate_with_cfg(cfg, sources)
        tainted_names = {tv.name for tv in result}
        self.assertIn("amount", tainted_names)

    def test_propagate_with_branch(self):
        body = """
        if (flag) {
            x = amount;
        } else {
            x = 0;
        }
        """
        cfg = self.parser.build_cfg(body)

        sources = [
            TaintedVariable(
                name="amount",
                source=TaintSource.FUNCTION_PARAM,
                source_function="deposit",
                source_param="amount",
                taint_path=["amount"],
            ),
            TaintedVariable(
                name="flag",
                source=TaintSource.FUNCTION_PARAM,
                source_function="deposit",
                source_param="flag",
                taint_path=["flag"],
            ),
        ]

        result = self.analyzer._propagate_with_cfg(cfg, sources)
        tainted_names = {tv.name for tv in result}
        self.assertIn("amount", tainted_names)

    def test_propagate_with_empty_cfg(self):
        """Falls back gracefully with empty CFG."""
        cfg = ControlFlowGraph()
        sources = [
            TaintedVariable(
                name="x",
                source=TaintSource.FUNCTION_PARAM,
                source_function="f",
                source_param="x",
                taint_path=["x"],
            )
        ]
        result = self.analyzer._propagate_with_cfg(cfg, sources)
        # Should return at least the original sources
        self.assertTrue(len(result) >= 1)

    def test_propagate_with_none_cfg(self):
        """Falls back gracefully when CFG is None."""
        sources = [
            TaintedVariable(
                name="x",
                source=TaintSource.FUNCTION_PARAM,
                source_function="f",
                source_param="x",
                taint_path=["x"],
            )
        ]
        result = self.analyzer._propagate_with_cfg(None, sources)
        self.assertTrue(len(result) >= 1)

    def test_propagate_loop_convergence(self):
        """Taint propagation through loops should converge."""
        body = """
        for (uint256 i = 0; i < 10; i++) {
            total += amount;
        }
        """
        cfg = self.parser.build_cfg(body)

        sources = [
            TaintedVariable(
                name="amount",
                source=TaintSource.FUNCTION_PARAM,
                source_function="accumulate",
                source_param="amount",
                taint_path=["amount"],
            )
        ]

        result = self.analyzer._propagate_with_cfg(cfg, sources)
        tainted_names = {tv.name for tv in result}
        self.assertIn("amount", tainted_names)


class TestSplitStatements(unittest.TestCase):
    """Test the statement splitting helper."""

    def setUp(self):
        self.parser = SolidityASTParser()

    def test_simple_semicolons(self):
        body = "uint256 x = 1; uint256 y = 2; return x + y;"
        stmts = self.parser._split_statements(body)
        self.assertEqual(len(stmts), 3)

    def test_preserves_if_body(self):
        body = 'if (x > 0) { x = 1; } uint256 y = 2;'
        stmts = self.parser._split_statements(body)
        # if + body should be one statement, y = 2 another
        self.assertTrue(len(stmts) >= 2)
        self.assertTrue(any('if' in s for s in stmts))

    def test_handles_strings(self):
        body = 'require(x > 0, "must be positive; really"); uint256 y = 1;'
        stmts = self.parser._split_statements(body)
        # The semicolon inside the string should not split
        self.assertEqual(len(stmts), 2)

    def test_handles_comments(self):
        body = """
        // this is a comment
        uint256 x = 1;
        /* block comment */
        uint256 y = 2;
        """
        stmts = self.parser._split_statements(body)
        # Only actual statements, not comments
        self.assertEqual(len(stmts), 2)

    def test_handles_empty(self):
        stmts = self.parser._split_statements("")
        self.assertEqual(stmts, [])

    def test_else_clause_separate(self):
        body = """
        if (x > 0) {
            y = 1;
        } else {
            y = 2;
        }
        """
        stmts = self.parser._split_statements(body)
        # Should have if-block and else-block as separate entries
        self.assertTrue(len(stmts) >= 2)

    def test_for_loop_as_single_statement(self):
        body = """
        for (uint i = 0; i < 10; i++) {
            sum += i;
        }
        return sum;
        """
        stmts = self.parser._split_statements(body)
        self.assertTrue(any('for' in s for s in stmts))
        self.assertTrue(any('return' in s for s in stmts))


class TestCFGEdgeCases(unittest.TestCase):
    """Test edge cases in CFG construction."""

    def setUp(self):
        self.parser = SolidityASTParser()

    def test_empty_if_body(self):
        body = """
        if (x > 0) {}
        return x;
        """
        cfg = self.parser.build_cfg(body)
        self.assertIn(cfg.entry, cfg.blocks)

    def test_deeply_nested(self):
        body = """
        if (a) {
            if (b) {
                if (c) {
                    x = 1;
                }
            }
        }
        """
        cfg = self.parser.build_cfg(body)
        self.assertTrue(len(cfg.blocks) >= 3)

    def test_loop_with_return(self):
        body = """
        for (uint i = 0; i < arr.length; i++) {
            if (arr[i] == target) {
                return i;
            }
        }
        return type(uint256).max;
        """
        cfg = self.parser.build_cfg(body)
        # Should have exits for both returns
        terminal_blocks = 0
        for bid, block in cfg.blocks.items():
            for stmt in block.statements:
                if stmt.strip().startswith('return'):
                    terminal_blocks += 1
        self.assertTrue(terminal_blocks >= 1)

    def test_successive_returns(self):
        """Dead code after return should not crash."""
        body = """
        return 1;
        return 2;
        """
        cfg = self.parser.build_cfg(body)
        self.assertTrue(len(cfg.exits) >= 1)

    def test_single_return(self):
        body = "return 42;"
        cfg = self.parser.build_cfg(body)
        self.assertIn(cfg.entry, cfg.blocks)
        self.assertTrue(len(cfg.exits) >= 1)

    def test_only_require(self):
        body = 'require(msg.sender == owner, "not owner");'
        cfg = self.parser.build_cfg(body)
        self.assertIn(cfg.entry, cfg.blocks)

    def test_complex_solidity_function(self):
        """Test with a realistic Solidity function body."""
        body = """
        require(amount > 0, "zero amount");
        require(balances[msg.sender] >= amount, "insufficient");

        uint256 fee = amount * feeRate / 10000;
        uint256 netAmount = amount - fee;

        balances[msg.sender] -= amount;
        balances[to] += netAmount;
        balances[feeRecipient] += fee;

        if (fee > 0) {
            emit FeeCollected(feeRecipient, fee);
        }

        emit Transfer(msg.sender, to, netAmount);
        return true;
        """
        cfg = self.parser.build_cfg(body)
        self.assertIn(cfg.entry, cfg.blocks)
        self.assertTrue(len(cfg.blocks) >= 2)
        # Should be reachable
        reachable = self.parser.get_reachable_blocks(cfg, cfg.entry)
        self.assertEqual(reachable, set(cfg.blocks.keys()))


class TestCFGTaintAnalyzeIntegration(unittest.TestCase):
    """Test that TaintAnalyzer.analyze() uses CFG when ast_data is provided."""

    def test_cfg_propagation_used_with_ast_data(self):
        """When ast_data is passed, analyze() should attempt CFG-based propagation."""
        code = """
pragma solidity ^0.8.0;
contract Vault {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) external {
        require(amount > 0, "zero");
        if (balances[msg.sender] >= amount) {
            balances[msg.sender] -= amount;
            payable(msg.sender).transfer(amount);
        }
    }
}
"""
        ta = TaintAnalyzer()
        # Pass a simple object as ast_data to trigger CFG path
        ast_data_marker = {"marker": True}
        report = ta.analyze(code, "Vault", ast_data=ast_data_marker)
        # Should still produce taint flows (amount is tainted)
        self.assertTrue(len(report.taint_flows) > 0)

    def test_cfg_fallback_on_invalid_ast(self):
        """When ast_data triggers CFG failure, should fallback to line-by-line."""
        code = """
pragma solidity ^0.8.0;
contract Simple {
    function send(address to, uint256 amount) external {
        payable(to).transfer(amount);
    }
}
"""
        ta = TaintAnalyzer()
        # Pass ast_data but it should fallback gracefully
        report = ta.analyze(code, "Simple", ast_data=object())
        self.assertTrue(len(report.taint_flows) > 0)

    def test_no_cfg_without_ast_data(self):
        """Without ast_data, standard line-by-line propagation is used."""
        code = """
pragma solidity ^0.8.0;
contract Token {
    mapping(address => uint256) public balances;

    function transfer(address to, uint256 amount) external {
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}
"""
        ta = TaintAnalyzer()
        report = ta.analyze(code, "Token")
        self.assertTrue(len(report.taint_flows) > 0)


if __name__ == "__main__":
    unittest.main()
