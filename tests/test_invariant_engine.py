"""Tests for the invariant extraction and Foundry test generation engine."""

import json
import unittest

from core.invariant_engine import (
    Invariant,
    InvariantEngine,
    InvariantTestSuite,
)


SAMPLE_VAULT_CODE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol";

/// @invariant totalAssets >= sum of all deposits
/// @invariant shares are non-decreasing when deposits increase
contract SimpleVault is ERC4626 {
    uint256 public totalDeposits;

    function totalAssets() public view override returns (uint256) {
        return IERC20(asset()).balanceOf(address(this));
    }

    function deposit(uint256 assets, address receiver) public override returns (uint256) {
        totalDeposits += assets;
        return super.deposit(assets, receiver);
    }
}
"""

SAMPLE_AMM_CODE = """
pragma solidity ^0.8.20;

contract SimplePair {
    uint256 public reserve0;
    uint256 public reserve1;

    function getReserves() external view returns (uint256, uint256) {
        return (reserve0, reserve1);
    }

    function swap(uint256 amount0Out, uint256 amount1Out) external {
        // k invariant check
        uint256 balance0 = reserve0 - amount0Out;
        uint256 balance1 = reserve1 - amount1Out;
        require(balance0 * balance1 >= reserve0 * reserve1);
        reserve0 = balance0;
        reserve1 = balance1;
    }

    function addLiquidity(uint256 a, uint256 b) external {
        reserve0 += a;
        reserve1 += b;
        _mint(msg.sender, sqrt(a * b));
    }

    function removeLiquidity(uint256 lp) external {}
    function _mint(address, uint256) internal {}
    function sqrt(uint256 x) internal pure returns (uint256) { return x; }
}
"""

SAMPLE_LENDING_CODE = """
pragma solidity ^0.8.20;

contract SimpleLending {
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public borrowed;
    uint256 public interestRate;

    function borrow(uint256 amount) external {
        require(collateral[msg.sender] * 75 / 100 >= borrowed[msg.sender] + amount);
        borrowed[msg.sender] += amount;
    }

    function repay(uint256 amount) external {
        borrowed[msg.sender] -= amount;
    }

    function liquidate(address user) external {
        uint256 healthFactor = collateral[user] * 100 / borrowed[user];
        require(healthFactor < 100);
    }
}
"""


class TestInvariantExtraction(unittest.TestCase):
    """Test invariant extraction from various sources."""

    def setUp(self):
        self.engine = InvariantEngine()

    def test_extract_natspec_invariants(self):
        invariants = self.engine._extract_natspec_invariants(SAMPLE_VAULT_CODE)
        self.assertEqual(len(invariants), 2)
        self.assertEqual(invariants[0].source, "natspec")
        self.assertIn("totalAssets", invariants[0].description)

    def test_extract_natspec_empty(self):
        invariants = self.engine._extract_natspec_invariants("contract Empty {}")
        self.assertEqual(len(invariants), 0)

    def test_extract_pattern_invariants_vault(self):
        invariants = self.engine._extract_pattern_invariants(SAMPLE_VAULT_CODE)
        ids = [inv.id for inv in invariants]
        self.assertIn("PAT-BALANCE-CONSERVATION", ids)
        for inv in invariants:
            self.assertEqual(inv.source, "pattern")

    def test_extract_pattern_invariants_amm(self):
        invariants = self.engine._extract_pattern_invariants(SAMPLE_AMM_CODE)
        ids = [inv.id for inv in invariants]
        self.assertIn("PAT-AMM-K", ids)

    def test_extract_pattern_invariants_lending(self):
        invariants = self.engine._extract_pattern_invariants(SAMPLE_LENDING_CODE)
        ids = [inv.id for inv in invariants]
        self.assertIn("PAT-LENDING-COLLATERAL", ids)

    def test_extract_llm_invariants(self):
        pass1_json = json.dumps({
            "invariants": [
                {"id": "INV-1", "description": "Total assets conservation", "related_state": ["totalAssets"], "critical": True},
                {"id": "INV-2", "description": "Share price monotonicity", "related_state": ["sharePrice"], "critical": False},
            ]
        })
        invariants = self.engine._extract_llm_invariants(pass1_json)
        self.assertEqual(len(invariants), 2)
        self.assertEqual(invariants[0].id, "INV-1")
        self.assertEqual(invariants[0].source, "llm")
        self.assertTrue(invariants[0].critical)

    def test_extract_llm_invariants_empty(self):
        invariants = self.engine._extract_llm_invariants("{}")
        self.assertEqual(len(invariants), 0)

    def test_extract_llm_invariants_invalid_json(self):
        invariants = self.engine._extract_llm_invariants("not json")
        self.assertEqual(len(invariants), 0)

    def test_extract_invariants_combined(self):
        """Full extraction combines all sources and deduplicates."""
        pass1_json = json.dumps({
            "invariants": [
                {"id": "LLM-1", "description": "Custom invariant from LLM", "related_state": [], "critical": True},
            ]
        })
        invariants = self.engine.extract_invariants(SAMPLE_VAULT_CODE, pass1_json)
        # Should have natspec + LLM + pattern invariants
        sources = {inv.source for inv in invariants}
        self.assertIn("natspec", sources)
        self.assertIn("llm", sources)
        self.assertIn("pattern", sources)

    def test_extract_invariants_no_duplicates(self):
        """Invariants with same ID should not duplicate."""
        pass1_json = json.dumps({
            "invariants": [
                {"id": "NATSPEC-1", "description": "duplicate of natspec", "related_state": [], "critical": True},
            ]
        })
        invariants = self.engine.extract_invariants(SAMPLE_VAULT_CODE, pass1_json)
        ids = [inv.id for inv in invariants]
        self.assertEqual(len(ids), len(set(ids)))


class TestFoundryTestGeneration(unittest.TestCase):
    """Test Foundry invariant test generation."""

    def setUp(self):
        self.engine = InvariantEngine()

    def test_generate_test_suite(self):
        invariants = [
            Invariant(
                id="INV-1",
                description="Total assets >= total supply",
                related_state=["totalAssets", "totalSupply"],
                solidity_expression="vault.totalAssets() >= vault.totalSupply()",
                source="llm",
            ),
        ]
        suite = self.engine.generate_foundry_invariant_tests(invariants, "SimpleVault")
        self.assertIsNotNone(suite)
        self.assertEqual(suite.contract_name, "SimpleVault")
        self.assertEqual(suite.test_contract_name, "SimpleVaultInvariantTest")
        self.assertEqual(suite.invariant_count, 1)
        self.assertIn("invariant_", suite.solidity_code)
        self.assertIn("assertTrue", suite.solidity_code)
        self.assertIn("vault.totalAssets() >= vault.totalSupply()", suite.solidity_code)

    def test_generate_test_suite_empty(self):
        suite = self.engine.generate_foundry_invariant_tests([], "Test")
        self.assertIsNone(suite)

    def test_generate_test_suite_no_expression(self):
        """Invariants without Solidity expressions should generate stubs."""
        invariants = [
            Invariant(
                id="INV-1",
                description="Complex invariant without expression",
                related_state=["x"],
                source="llm",
            ),
        ]
        suite = self.engine.generate_foundry_invariant_tests(invariants, "Test")
        self.assertIsNotNone(suite)
        self.assertIn("TODO", suite.solidity_code)
        self.assertIn("stub", suite.solidity_code)

    def test_generate_test_suite_multiple_invariants(self):
        invariants = [
            Invariant(id="INV-1", description="Invariant 1", related_state=[], solidity_expression="x > 0"),
            Invariant(id="INV-2", description="Invariant 2", related_state=[], solidity_expression="y > 0"),
            Invariant(id="INV-3", description="Invariant 3", related_state=[], solidity_expression="z > 0"),
        ]
        suite = self.engine.generate_foundry_invariant_tests(invariants, "Multi")
        self.assertEqual(suite.invariant_count, 3)
        # Should have 3 test functions
        self.assertEqual(suite.solidity_code.count("function invariant_"), 3)

    def test_generated_code_compiles_syntactically(self):
        """Generated Solidity should at least be syntactically reasonable."""
        invariants = [
            Invariant(
                id="INV-1",
                description="Balance conservation",
                related_state=["balance"],
                solidity_expression="token.balanceOf(address(this)) >= totalDeposited",
            ),
        ]
        suite = self.engine.generate_foundry_invariant_tests(invariants, "Vault", "src/Vault.sol")
        code = suite.solidity_code
        # Check Solidity boilerplate
        self.assertIn("SPDX-License-Identifier", code)
        self.assertIn("pragma solidity", code)
        self.assertIn("import", code)
        self.assertIn("contract VaultInvariantTest is Test", code)
        self.assertIn("function setUp()", code)

    def test_invariant_to_func_name(self):
        inv = Invariant(id="PAT-VAULT-CONSERVATION", description="test", related_state=[])
        name = self.engine._invariant_to_func_name(inv)
        self.assertEqual(name, "invariant_pat_vault_conservation")

    def test_custom_import_path(self):
        invariants = [Invariant(id="I1", description="test", related_state=[], solidity_expression="true")]
        suite = self.engine.generate_foundry_invariant_tests(invariants, "MyContract", "contracts/MyContract.sol")
        self.assertIn("contracts/MyContract.sol", suite.solidity_code)


class TestInvariantDataclass(unittest.TestCase):
    """Test Invariant dataclass."""

    def test_default_values(self):
        inv = Invariant(id="test", description="desc", related_state=["x"])
        self.assertEqual(inv.solidity_expression, "")
        self.assertEqual(inv.source, "llm")
        self.assertTrue(inv.critical)


if __name__ == '__main__':
    unittest.main()
