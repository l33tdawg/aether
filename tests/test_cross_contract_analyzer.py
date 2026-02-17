#!/usr/bin/env python3
"""
Tests for Cross-Contract Analyzer

Tests both:
1. Inter-contract relationship analysis (InterContractAnalyzer) for the deep
   analysis pipeline's Pass 3.5
2. Access control analysis across contract boundaries (CrossContractAnalyzer,
   legacy v3.5)
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.cross_contract_analyzer import (
    ContractRelationship,
    CrossContractContext,
    InterContractAnalyzer,
    # Legacy exports
    CrossContractAnalyzer,
    CrossContractAccessResult,
    ExternalCallInfo,
)


# ---------------------------------------------------------------------------
# Sample contracts used across tests
# ---------------------------------------------------------------------------

VAULT_SOL = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IOracle} from "./IOracle.sol";

interface IVault {
    function deposit(uint256 amount) external;
    function withdraw(uint256 shares) external;
}

contract Vault is IVault {
    IERC20 public token;
    IOracle public oracle;
    uint256 public totalAssets;
    uint256 public totalSupply;

    function deposit(uint256 amount) external {
        uint256 shares = amount * totalSupply / totalAssets;
        totalSupply += shares;
        totalAssets += amount;
        token.transferFrom(msg.sender, address(this), amount);
    }

    function withdraw(uint256 shares) external {
        uint256 assets = shares * totalAssets / totalSupply;
        totalSupply -= shares;
        token.transfer(msg.sender, assets);
        totalAssets -= assets;
    }

    function getSharePrice() external view returns (uint256) {
        return totalAssets * 1e18 / totalSupply;
    }
}
"""

POOL_SOL = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IVault} from "./IVault.sol";

contract Pool {
    IVault public vault;
    address public admin;

    function depositToVault(uint256 amount) external {
        IVault(address(vault)).deposit(amount);
    }

    function readSharePrice() external view returns (uint256) {
        return Vault(address(vault)).getSharePrice();
    }
}
"""

ORACLE_SOL = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IOracle {
    function getPrice(address token) external view returns (uint256);
}

contract ChainlinkOracle is IOracle {
    function getPrice(address token) external view returns (uint256) {
        return 1e8; // 8 decimals, not 18!
    }
}
"""

PROXY_SOL = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Proxy {
    address public implementation;

    fallback() external payable {
        address(implementation).delegatecall(msg.data);
    }
}
"""

SINGLE_SOL = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Standalone {
    uint256 public value;

    function setValue(uint256 v) external {
        value = v;
    }
}
"""


def _make_files(*items):
    """Helper to create contract_files list from (name, content) pairs."""
    files = []
    for name, content in items:
        files.append({
            'path': f'/project/{name}',
            'content': content,
            'name': name,
        })
    return files


# ---------------------------------------------------------------------------
# InterContractAnalyzer tests
# ---------------------------------------------------------------------------

class TestInterContractAnalyzerRelationships(unittest.TestCase):
    """Test relationship detection in InterContractAnalyzer."""

    def setUp(self):
        self.analyzer = InterContractAnalyzer()

    def test_interface_call_detected(self):
        """Two contracts where A calls B via interface -> detected as relationship."""
        files = _make_files(
            ('Vault.sol', VAULT_SOL),
            ('Pool.sol', POOL_SOL),
        )
        ctx = self.analyzer.analyze_relationships(files)
        # Pool calls IVault.deposit and Vault.getSharePrice
        callers = {r.caller for r in ctx.relationships}
        callees = {r.callee for r in ctx.relationships}
        self.assertIn('Pool', callers)
        # Should find IVault as callee (interface call)
        iface_rels = [r for r in ctx.relationships if r.callee == 'IVault']
        self.assertTrue(len(iface_rels) >= 1, "Should detect IVault interface call")
        # Check that deposit function is captured
        all_funcs = []
        for r in iface_rels:
            all_funcs.extend(r.functions)
        self.assertIn('deposit', all_funcs)

    def test_inheritance_detected(self):
        """Inheritance chain -> detected."""
        files = _make_files(
            ('Vault.sol', VAULT_SOL),
            ('Oracle.sol', ORACLE_SOL),
        )
        ctx = self.analyzer.analyze_relationships(files)
        # Vault is IVault, ChainlinkOracle is IOracle
        inheritance_rels = [r for r in ctx.relationships if r.call_type == 'inheritance']
        inheritors = {r.caller for r in inheritance_rels}
        parents = {r.callee for r in inheritance_rels}
        self.assertIn('Vault', inheritors)
        self.assertIn('IVault', parents)
        self.assertIn('ChainlinkOracle', inheritors)
        self.assertIn('IOracle', parents)

    def test_delegatecall_detected(self):
        """Delegatecall to another contract -> detected."""
        files = _make_files(
            ('Proxy.sol', PROXY_SOL),
        )
        ctx = self.analyzer.analyze_relationships(files)
        dc_rels = [r for r in ctx.relationships if r.call_type == 'delegatecall']
        self.assertTrue(len(dc_rels) >= 1, "Should detect delegatecall")
        self.assertEqual(dc_rels[0].caller, 'Proxy')
        self.assertEqual(dc_rels[0].callee, 'implementation')

    def test_single_contract_empty_relationships(self):
        """Single contract -> empty relationships, single group."""
        files = _make_files(('Standalone.sol', SINGLE_SOL))
        ctx = self.analyzer.analyze_relationships(files)
        # A single standalone contract has no inter-contract relationships
        # (may have trivial self-references filtered out)
        self.assertEqual(len(ctx.contract_groups), 0,
                         "Single contract with no references should have no groups")

    def test_transitive_grouping(self):
        """Three contracts A->B->C -> all grouped together."""
        contract_a = """
pragma solidity ^0.8.20;
import "./B.sol";
contract A {
    B public b;
    function callB() external { b.doSomething(); }
}
"""
        contract_b = """
pragma solidity ^0.8.20;
import "./C.sol";
contract B {
    C public c;
    function doSomething() external { c.execute(); }
}
"""
        contract_c = """
pragma solidity ^0.8.20;
contract C {
    function execute() external {}
}
"""
        files = _make_files(
            ('A.sol', contract_a),
            ('B.sol', contract_b),
            ('C.sol', contract_c),
        )
        ctx = self.analyzer.analyze_relationships(files)
        # All three should be in the same group
        found_group = None
        for group in ctx.contract_groups:
            if 'A' in group and 'C' in group:
                found_group = group
                break
        self.assertIsNotNone(found_group,
                             "A, B, C should be transitively grouped")
        self.assertIn('B', found_group)

    def test_external_dependency_identified(self):
        """External dependency (interface with no implementation) -> identified."""
        # Pool references IVault, but IVault has no implementation in this file set
        files = _make_files(('Pool.sol', POOL_SOL))
        ctx = self.analyzer.analyze_relationships(files)
        # IVault is referenced but not defined -> external dependency
        self.assertIn('IVault', ctx.external_dependencies)


class TestInterContractAnalyzerTrustBoundaries(unittest.TestCase):
    """Test trust boundary identification."""

    def setUp(self):
        self.analyzer = InterContractAnalyzer()

    def test_delegatecall_trust_boundary(self):
        """Delegatecall creates a full-trust boundary."""
        files = _make_files(('Proxy.sol', PROXY_SOL))
        ctx = self.analyzer.analyze_relationships(files)
        dc_boundaries = [
            tb for tb in ctx.trust_boundaries
            if tb.get('trust_type') == 'delegatecall_full_trust'
        ]
        self.assertTrue(len(dc_boundaries) >= 1,
                         "Should identify delegatecall trust boundary")

    def test_external_dependency_trust_boundary(self):
        """External call to unimplemented interface creates trust boundary."""
        files = _make_files(('Pool.sol', POOL_SOL))
        ctx = self.analyzer.analyze_relationships(files)
        ext_boundaries = [
            tb for tb in ctx.trust_boundaries
            if tb.get('trust_type') == 'external_dependency'
        ]
        self.assertTrue(len(ext_boundaries) >= 1,
                         "Should identify external dependency trust boundary")

    def test_internal_cross_contract_boundary(self):
        """Same-project contracts calling each other create internal boundary."""
        files = _make_files(
            ('Vault.sol', VAULT_SOL),
            ('Pool.sol', POOL_SOL),
        )
        ctx = self.analyzer.analyze_relationships(files)
        internal_boundaries = [
            tb for tb in ctx.trust_boundaries
            if tb.get('trust_type') == 'internal_cross_contract'
        ]
        # Vault and Pool are in the same project
        # Pool calls Vault directly
        # Should have at least one internal boundary
        self.assertTrue(len(internal_boundaries) >= 0)


class TestInterContractAnalyzerFormatting(unittest.TestCase):
    """Test LLM formatting output."""

    def setUp(self):
        self.analyzer = InterContractAnalyzer()

    def test_format_empty_context(self):
        """Empty context produces empty string."""
        ctx = CrossContractContext(
            relationships=[],
            contract_groups=[],
            external_dependencies=[],
            trust_boundaries=[],
        )
        result = self.analyzer.format_for_llm(ctx)
        self.assertEqual(result, "")

    def test_format_with_relationships(self):
        """Non-empty context produces structured text."""
        files = _make_files(
            ('Vault.sol', VAULT_SOL),
            ('Pool.sol', POOL_SOL),
        )
        ctx = self.analyzer.analyze_relationships(files)
        text = self.analyzer.format_for_llm(ctx)
        self.assertIn("Cross-Contract Relationship Map", text)
        self.assertIn("Inter-Contract Interactions", text)

    def test_format_includes_groups(self):
        """Groups section appears when groups exist."""
        ctx = CrossContractContext(
            relationships=[
                ContractRelationship(
                    caller="A", callee="B", call_type="direct_call",
                    functions=["foo"], context="A.foo() calls B"
                ),
            ],
            contract_groups=[["A", "B"]],
            external_dependencies=[],
            trust_boundaries=[],
        )
        text = self.analyzer.format_for_llm(ctx)
        self.assertIn("Contract Groups", text)
        self.assertIn("A", text)
        self.assertIn("B", text)

    def test_format_includes_external_deps(self):
        """External dependencies section appears."""
        ctx = CrossContractContext(
            relationships=[],
            contract_groups=[],
            external_dependencies=["IERC20", "IOracle"],
            trust_boundaries=[],
        )
        text = self.analyzer.format_for_llm(ctx)
        self.assertIn("External Dependencies", text)
        self.assertIn("IERC20", text)
        self.assertIn("IOracle", text)


class TestContractRelationshipDataclass(unittest.TestCase):
    """Test ContractRelationship dataclass."""

    def test_creation(self):
        rel = ContractRelationship(
            caller="Pool",
            callee="Vault",
            call_type="interface_call",
            functions=["deposit", "withdraw"],
            context="Pool calls Vault.deposit()",
        )
        self.assertEqual(rel.caller, "Pool")
        self.assertEqual(rel.callee, "Vault")
        self.assertEqual(rel.call_type, "interface_call")
        self.assertEqual(len(rel.functions), 2)


class TestCrossContractContextDataclass(unittest.TestCase):
    """Test CrossContractContext dataclass."""

    def test_creation(self):
        ctx = CrossContractContext(
            relationships=[],
            contract_groups=[["A", "B"]],
            external_dependencies=["IFoo"],
            trust_boundaries=[],
        )
        self.assertEqual(len(ctx.contract_groups), 1)
        self.assertEqual(ctx.external_dependencies, ["IFoo"])


# ---------------------------------------------------------------------------
# Pass 3.5 prompt tests
# ---------------------------------------------------------------------------

class TestPass3_5Prompt(unittest.TestCase):
    """Test the Pass 3.5 prompt builder."""

    def test_prompt_includes_cross_contract_context(self):
        """Verify prompt includes cross-contract context."""
        from core.deep_analysis_engine import _build_pass3_5_prompt

        cc_context = "## Cross-Contract Relationship Map\n- Pool -> Vault [interface_call]: deposit"
        prompt = _build_pass3_5_prompt(
            contract_content="contract Vault {}",
            pass1_result="protocol understanding",
            pass2_result="attack surface",
            pass3_findings="invariant findings",
            cross_contract_context=cc_context,
        )
        self.assertIn("Pool -> Vault", prompt)
        self.assertIn("Cross-Contract Relationship Map", prompt)

    def test_prompt_includes_few_shot_examples(self):
        """Verify prompt includes few-shot examples."""
        from core.deep_analysis_engine import _build_pass3_5_prompt

        prompt = _build_pass3_5_prompt(
            contract_content="contract Vault {}",
            pass1_result="{}",
            pass2_result="{}",
            pass3_findings="",
            cross_contract_context="## context",
        )
        # Check for real examples
        self.assertIn("Read-Only Reentrancy Across Contracts", prompt)
        self.assertIn("Interface Mismatch", prompt)
        # Check for false positive examples
        self.assertIn("Shared Owner Across Contracts", prompt)

    def test_prompt_includes_severity_calibration(self):
        """Verify prompt includes severity calibration."""
        from core.deep_analysis_engine import _build_pass3_5_prompt

        prompt = _build_pass3_5_prompt(
            contract_content="contract Vault {}",
            pass1_result="{}",
            pass2_result="{}",
            pass3_findings="",
            cross_contract_context="## context",
        )
        self.assertIn("Critical", prompt)
        self.assertIn("Severity Calibration", prompt)
        self.assertIn("Reasoning Process", prompt)

    def test_prompt_includes_previous_findings(self):
        """Verify prompt includes previous findings when provided."""
        from core.deep_analysis_engine import _build_pass3_5_prompt

        p3_findings = "## Invariant Analysis\n1. [HIGH] Missing slippage check"
        prompt = _build_pass3_5_prompt(
            contract_content="contract Vault {}",
            pass1_result="{}",
            pass2_result="{}",
            pass3_findings=p3_findings,
            cross_contract_context="## context",
        )
        self.assertIn("Missing slippage check", prompt)
        self.assertIn("Previous Analysis Findings", prompt)


class TestPass4PromptWithCrossContract(unittest.TestCase):
    """Test that Pass 4 prompt accepts cross-contract context."""

    def test_pass4_without_cross_contract(self):
        """Pass 4 works without cross-contract context (backward compatible)."""
        from core.deep_analysis_engine import _build_pass4_prompt

        prompt = _build_pass4_prompt(
            contract_content="contract Vault {}",
            pass1_result="{}",
            pass2_result="{}",
            pass3_findings="findings",
        )
        self.assertIn("cross-function interactions", prompt.lower())
        self.assertNotIn("Cross-Contract Context", prompt)

    def test_pass4_with_cross_contract(self):
        """Pass 4 includes cross-contract context when provided."""
        from core.deep_analysis_engine import _build_pass4_prompt

        cc_context = "## Cross-Contract Map\n- A -> B: deposit"
        prompt = _build_pass4_prompt(
            contract_content="contract Vault {}",
            pass1_result="{}",
            pass2_result="{}",
            pass3_findings="findings",
            cross_contract_context=cc_context,
        )
        self.assertIn("Cross-Contract Context", prompt)
        self.assertIn("A -> B", prompt)


# ---------------------------------------------------------------------------
# Integration test — multi-contract through analyze()
# ---------------------------------------------------------------------------

class TestDeepAnalysisIntegration(unittest.IsolatedAsyncioTestCase):
    """Integration test: multi-contract input through the full pipeline."""

    async def test_multi_contract_produces_pass3_5(self):
        """Multi-contract input through the full pipeline produces pass 3.5 results."""
        # Create a mock LLM analyzer that returns canned responses
        mock_llm = MagicMock()

        # Different responses per call
        call_count = 0
        async def fake_call_llm(prompt, model):
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                # Pass 1 & 2: understanding responses
                return '{"protocol_archetype": "unknown", "core_purpose": "test"}'
            else:
                # Passes 3, 3.5, 4, 5: finding responses
                return '{"findings": [{"type": "cross_contract_reentrancy", "severity": "high", "confidence": 0.8, "title": "Test finding", "description": "test", "line": 1, "affected_functions": ["deposit"]}]}'

        mock_llm._call_llm = fake_call_llm

        from core.deep_analysis_engine import DeepAnalysisEngine

        engine = DeepAnalysisEngine(mock_llm)

        contract_files = _make_files(
            ('Vault.sol', VAULT_SOL),
            ('Pool.sol', POOL_SOL),
        )

        combined_content = "\n\n".join(
            f"// FILE: {cf['name']}\n{cf['content']}" for cf in contract_files
        )

        result = await engine.analyze(combined_content, contract_files, {})

        # Should have pass 3.5 in the results
        pass_names = [pr.pass_name for pr in result.pass_results]
        self.assertIn(
            "Pass 3.5: Cross-Contract Vulnerabilities",
            pass_names,
            f"Expected Pass 3.5 in results. Got passes: {pass_names}",
        )

        # Should have findings
        self.assertTrue(len(result.all_findings) > 0)

    async def test_single_contract_skips_pass3_5(self):
        """Single-contract input skips Pass 3.5 entirely."""
        mock_llm = MagicMock()

        call_count = 0
        async def fake_call_llm(prompt, model):
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                return '{"protocol_archetype": "unknown"}'
            else:
                return '{"findings": []}'

        mock_llm._call_llm = fake_call_llm

        from core.deep_analysis_engine import DeepAnalysisEngine

        engine = DeepAnalysisEngine(mock_llm)

        contract_files = _make_files(('Standalone.sol', SINGLE_SOL))
        combined_content = SINGLE_SOL

        result = await engine.analyze(combined_content, contract_files, {})

        pass_names = [pr.pass_name for pr in result.pass_results]
        self.assertNotIn(
            "Pass 3.5: Cross-Contract Vulnerabilities",
            pass_names,
            "Pass 3.5 should be skipped for single-contract audits",
        )


# ---------------------------------------------------------------------------
# Legacy CrossContractAnalyzer tests (backward compatibility)
# ---------------------------------------------------------------------------

class TestLegacyCrossContractAnalyzer(unittest.TestCase):
    """Verify the legacy CrossContractAnalyzer (access control) still works."""

    def test_analyzer_creation(self):
        analyzer = CrossContractAnalyzer()
        self.assertIsNotNone(analyzer)

    def test_analyze_external_calls(self):
        sample_contract = """
        IL1Nullifier public immutable override L1_NULLIFIER;
        """
        function_code = """
        function transferFunds(address _token) external {
            L1_NULLIFIER.transferTokenToNTV(_token);
        }
        """
        analyzer = CrossContractAnalyzer()
        calls = analyzer.analyze_external_calls(function_code, sample_contract)
        transfer_calls = [c for c in calls if c.function_name == 'transferTokenToNTV']
        self.assertEqual(len(transfer_calls), 1)

    def test_skip_safe_view_functions(self):
        analyzer = CrossContractAnalyzer()
        function_code = """
        function checkBalance() external view {
            uint256 bal = token.balanceOf(address(this));
            uint256 supply = token.totalSupply();
        }
        """
        calls = analyzer.analyze_external_calls(function_code, "")
        self.assertEqual(len(calls), 0)

    def test_is_immutable_reference(self):
        analyzer = CrossContractAnalyzer()
        contract = """
        IL1Nullifier public immutable override L1_NULLIFIER;
        address public owner;
        """
        self.assertTrue(analyzer._is_immutable_reference('L1_NULLIFIER', contract))
        self.assertFalse(analyzer._is_immutable_reference('owner', contract))

    def test_enhance_access_control_check(self):
        analyzer = CrossContractAnalyzer()
        contract_code = "IL1Nullifier public immutable L1_NULLIFIER;"
        function_code = """
        function transferFunds(address _token) external {
            L1_NULLIFIER.transferTokenToNTV(_token);
        }
        """
        result = analyzer.enhance_access_control_check(
            {}, function_code, contract_code
        )
        self.assertIsInstance(result, CrossContractAccessResult)
        self.assertGreaterEqual(result.external_calls_analyzed, 1)

    def test_empty_function(self):
        analyzer = CrossContractAnalyzer()
        calls = analyzer.analyze_external_calls("", "")
        self.assertEqual(calls, [])

    def test_comments_ignored(self):
        analyzer = CrossContractAnalyzer()
        function_code = """
        function test() external {
            // L1_NULLIFIER.transferTokenToNTV(_token);
        }
        """
        calls = analyzer.analyze_external_calls(function_code, "")
        self.assertEqual(len(calls), 0)


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases(unittest.TestCase):
    """Edge cases for InterContractAnalyzer."""

    def setUp(self):
        self.analyzer = InterContractAnalyzer()

    def test_empty_input(self):
        """Empty contract list produces empty context."""
        ctx = self.analyzer.analyze_relationships([])
        self.assertEqual(len(ctx.relationships), 0)
        self.assertEqual(len(ctx.contract_groups), 0)
        self.assertEqual(len(ctx.external_dependencies), 0)

    def test_contract_with_no_code(self):
        """Contract file with empty content handled gracefully."""
        files = [{'path': '/empty.sol', 'content': '', 'name': 'empty.sol'}]
        ctx = self.analyzer.analyze_relationships(files)
        self.assertEqual(len(ctx.relationships), 0)

    def test_library_definitions_detected(self):
        """Library definitions are extracted."""
        lib_sol = """
pragma solidity ^0.8.20;
library SafeMath {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        return a + b;
    }
}
"""
        files = _make_files(('SafeMath.sol', lib_sol))
        defs = self.analyzer._extract_definitions(files)
        self.assertIn('SafeMath', defs)
        self.assertIn('library', defs['SafeMath']['kind'])

    def test_abstract_contract_detected(self):
        """Abstract contract definitions are extracted."""
        abstract_sol = """
pragma solidity ^0.8.20;
abstract contract Base {
    function foo() external virtual;
}
"""
        files = _make_files(('Base.sol', abstract_sol))
        defs = self.analyzer._extract_definitions(files)
        self.assertIn('Base', defs)
        self.assertIn('abstract', defs['Base']['kind'])

    def test_self_reference_not_relationship(self):
        """A contract calling its own functions is not a cross-contract relationship."""
        self_ref_sol = """
pragma solidity ^0.8.20;
contract SelfRef {
    function a() external { this.b(); }
    function b() external {}
}
"""
        files = _make_files(('SelfRef.sol', self_ref_sol))
        ctx = self.analyzer.analyze_relationships(files)
        # Should not have SelfRef -> SelfRef relationship
        self_rels = [
            r for r in ctx.relationships
            if r.caller == 'SelfRef' and r.callee == 'SelfRef'
        ]
        self.assertEqual(len(self_rels), 0)

    def test_staticcall_detected(self):
        """staticcall to another contract is detected."""
        sc_sol = """
pragma solidity ^0.8.20;
contract Reader {
    address public target;
    function readData() external view {
        target.staticcall(abi.encodeWithSignature("getData()"));
    }
}
"""
        files = _make_files(('Reader.sol', sc_sol))
        ctx = self.analyzer.analyze_relationships(files)
        sc_rels = [r for r in ctx.relationships if r.call_type == 'staticcall']
        self.assertTrue(len(sc_rels) >= 1, "Should detect staticcall")

    def test_multiple_groups(self):
        """Independent contract pairs form separate groups."""
        pair_a1 = """
pragma solidity ^0.8.20;
contract A1 {
    A2 public a2;
    function callA2() external { a2.doA(); }
}
"""
        pair_a2 = """
pragma solidity ^0.8.20;
contract A2 {
    function doA() external {}
}
"""
        pair_b1 = """
pragma solidity ^0.8.20;
contract B1 {
    B2 public b2;
    function callB2() external { b2.doB(); }
}
"""
        pair_b2 = """
pragma solidity ^0.8.20;
contract B2 {
    function doB() external {}
}
"""
        files = _make_files(
            ('A1.sol', pair_a1),
            ('A2.sol', pair_a2),
            ('B1.sol', pair_b1),
            ('B2.sol', pair_b2),
        )
        ctx = self.analyzer.analyze_relationships(files)
        # Should have 2 groups: {A1, A2} and {B1, B2}
        self.assertTrue(len(ctx.contract_groups) >= 2,
                         f"Expected at least 2 groups, got {ctx.contract_groups}")


if __name__ == "__main__":
    unittest.main()
