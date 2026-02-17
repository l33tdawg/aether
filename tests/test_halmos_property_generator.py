"""
Tests for core/halmos_property_generator.py — property generation from
findings and invariants.
"""

import unittest
from dataclasses import dataclass
from typing import List

from core.halmos_property_generator import (
    HalmosProperty,
    HalmosPropertyGenerator,
    HalmosTestSuite,
)


# Minimal Invariant stand-in for testing without importing invariant_engine
@dataclass
class _MockInvariant:
    id: str
    description: str
    related_state: List[str]
    solidity_expression: str = ""
    source: str = "test"
    critical: bool = True


class TestHalmosProperty(unittest.TestCase):
    """Test the HalmosProperty dataclass."""

    def test_defaults(self):
        p = HalmosProperty(
            function_name="check_foo",
            function_body="function check_foo(uint256 x) public { assert(true); }",
            description="test property",
        )
        self.assertIsNone(p.related_finding_id)
        self.assertEqual(p.property_type, "safety")

    def test_custom_type(self):
        p = HalmosProperty(
            function_name="check_inv",
            function_body="...",
            description="invariant",
            property_type="invariant",
        )
        self.assertEqual(p.property_type, "invariant")


class TestHalmosTestSuite(unittest.TestCase):
    """Test the HalmosTestSuite dataclass and to_solidity()."""

    def test_empty_suite(self):
        suite = HalmosTestSuite(
            contract_name="VaultHalmosTest",
            target_contract="Vault",
            target_import_path="src/Vault.sol",
        )
        sol = suite.to_solidity()
        self.assertIn("pragma solidity ^0.8.0;", sol)
        self.assertIn("contract VaultHalmosTest is Test", sol)
        self.assertIn('import "src/Vault.sol"', sol)
        self.assertIn("Vault public target", sol)

    def test_suite_with_properties(self):
        suite = HalmosTestSuite(
            contract_name="VaultHalmosTest",
            target_contract="Vault",
            target_import_path="src/Vault.sol",
            properties=[
                HalmosProperty(
                    function_name="check_noInflation",
                    function_body="function check_noInflation(uint256 x) public { assert(true); }",
                    description="No share inflation",
                ),
            ],
        )
        sol = suite.to_solidity()
        self.assertIn("check_noInflation", sol)
        self.assertIn("No share inflation", sol)

    def test_extra_imports(self):
        suite = HalmosTestSuite(
            contract_name="Test",
            target_contract="X",
            target_import_path="src/X.sol",
            extra_imports=["src/Token.sol"],
        )
        sol = suite.to_solidity()
        self.assertIn('import "src/Token.sol"', sol)


class TestHalmosPropertyGeneratorFromFindings(unittest.TestCase):
    """Test generate_from_findings()."""

    def setUp(self):
        self.gen = HalmosPropertyGenerator()

    def test_empty_findings(self):
        result = self.gen.generate_from_findings([], "Vault")
        self.assertIsNone(result)

    def test_single_reentrancy_finding(self):
        findings = [{
            "vulnerability_type": "reentrancy",
            "title": "Reentrancy in withdraw()",
            "id": "V-1",
            "function": "withdraw",
        }]
        suite = self.gen.generate_from_findings(findings, "Vault")
        self.assertIsNotNone(suite)
        self.assertEqual(suite.contract_name, "VaultHalmosTest")
        self.assertEqual(suite.target_contract, "Vault")
        self.assertEqual(len(suite.properties), 1)
        self.assertIn("noReentrancy", suite.properties[0].function_name)
        self.assertEqual(suite.properties[0].related_finding_id, "V-1")

    def test_multiple_findings(self):
        findings = [
            {"vulnerability_type": "reentrancy", "title": "Re1", "id": "V-1", "function": "f1"},
            {"vulnerability_type": "integer_overflow", "title": "OV1", "id": "V-2", "function": "f2"},
            {"vulnerability_type": "share_inflation", "title": "SI1", "id": "V-3", "function": "f3"},
        ]
        suite = self.gen.generate_from_findings(findings, "Pool")
        self.assertIsNotNone(suite)
        self.assertEqual(len(suite.properties), 3)
        types = {p.function_name.split("_")[1] for p in suite.properties}
        self.assertIn("noReentrancy", types)
        self.assertIn("noOverflow", types)
        self.assertIn("noShareInflation", types)

    def test_unknown_vuln_type_uses_default(self):
        findings = [{
            "vulnerability_type": "exotic_new_vuln",
            "title": "Some exotic bug",
            "id": "V-99",
        }]
        suite = self.gen.generate_from_findings(findings, "Token")
        self.assertIsNotNone(suite)
        self.assertEqual(len(suite.properties), 1)
        self.assertIn("check_property", suite.properties[0].function_name)

    def test_custom_contract_path(self):
        findings = [{"vulnerability_type": "flash_loan", "title": "FL", "id": "V-1"}]
        suite = self.gen.generate_from_findings(
            findings, "Vault", contract_path="contracts/Vault.sol"
        )
        self.assertEqual(suite.target_import_path, "contracts/Vault.sol")

    def test_solidity_output_compiles_pattern(self):
        findings = [
            {"vulnerability_type": "access_control", "title": "AC", "id": "V-1"},
        ]
        suite = self.gen.generate_from_findings(findings, "Gov")
        sol = suite.to_solidity()
        self.assertIn("pragma solidity", sol)
        self.assertIn("contract GovHalmosTest", sol)
        self.assertIn("check_accessControl", sol)


class TestHalmosPropertyGeneratorFromInvariants(unittest.TestCase):
    """Test generate_from_invariants()."""

    def setUp(self):
        self.gen = HalmosPropertyGenerator()

    def test_empty_invariants(self):
        result = self.gen.generate_from_invariants([], "Vault")
        self.assertIsNone(result)

    def test_invariant_with_expression(self):
        inv = _MockInvariant(
            id="PAT-VAULT-CONSERVATION",
            description="Total assets >= total shares value",
            related_state=["totalAssets", "totalSupply"],
            solidity_expression="vault.totalAssets() >= vault.convertToAssets(vault.totalSupply())",
        )
        suite = self.gen.generate_from_invariants([inv], "Vault")
        self.assertIsNotNone(suite)
        self.assertEqual(len(suite.properties), 1)
        prop = suite.properties[0]
        self.assertIn("pat_vault_conservation", prop.function_name)
        self.assertIn("assert(vault.totalAssets()", prop.function_body)
        self.assertEqual(prop.property_type, "invariant")

    def test_invariant_without_expression(self):
        inv = _MockInvariant(
            id="NATSPEC-1",
            description="Something must hold",
            related_state=[],
        )
        suite = self.gen.generate_from_invariants([inv], "Token")
        self.assertIsNotNone(suite)
        prop = suite.properties[0]
        self.assertIn("TODO", prop.function_body)
        self.assertIn("assert(true)", prop.function_body)

    def test_multiple_invariants(self):
        invs = [
            _MockInvariant(id="INV-A", description="A", related_state=[], solidity_expression="a > 0"),
            _MockInvariant(id="INV-B", description="B", related_state=[], solidity_expression="b > 0"),
            _MockInvariant(id="INV-C", description="C", related_state=[]),
        ]
        suite = self.gen.generate_from_invariants(invs, "Pool")
        self.assertIsNotNone(suite)
        self.assertEqual(len(suite.properties), 3)


class TestVulnTypeNormalization(unittest.TestCase):
    """Test _normalize_vuln_type."""

    def setUp(self):
        self.normalize = HalmosPropertyGenerator._normalize_vuln_type

    def test_exact_match(self):
        self.assertEqual(self.normalize("reentrancy"), "reentrancy")
        self.assertEqual(self.normalize("flash_loan"), "flash_loan")

    def test_case_insensitive(self):
        self.assertEqual(self.normalize("REENTRANCY"), "reentrancy")
        self.assertEqual(self.normalize("Integer_Overflow"), "integer_overflow")

    def test_hyphen_to_underscore(self):
        self.assertEqual(self.normalize("re-entrancy"), "reentrancy")
        self.assertEqual(self.normalize("flash-loan-attack"), "flash_loan")

    def test_space_to_underscore(self):
        self.assertEqual(self.normalize("integer overflow"), "integer_overflow")
        self.assertEqual(self.normalize("share inflation"), "share_inflation")

    def test_alias_mapping(self):
        self.assertEqual(self.normalize("reentrant"), "reentrancy")
        self.assertEqual(self.normalize("overflow"), "integer_overflow")
        self.assertEqual(self.normalize("underflow"), "integer_overflow")
        self.assertEqual(self.normalize("oracle_manipulation"), "price_manipulation")
        self.assertEqual(self.normalize("first_deposit"), "share_inflation")
        self.assertEqual(self.normalize("donation_attack"), "share_inflation")
        self.assertEqual(self.normalize("missing_access_control"), "access_control")
        self.assertEqual(self.normalize("flashloan"), "flash_loan")
        self.assertEqual(self.normalize("precision_loss"), "rounding_error")
        self.assertEqual(self.normalize("truncation"), "rounding_error")

    def test_unknown_type_passthrough(self):
        self.assertEqual(self.normalize("exotic_new_vuln"), "exotic_new_vuln")
        self.assertEqual(self.normalize("Something Weird"), "something_weird")


class TestFindingToProperty(unittest.TestCase):
    """Test _finding_to_property internal method."""

    def setUp(self):
        self.gen = HalmosPropertyGenerator()

    def test_reentrancy_template(self):
        finding = {
            "vulnerability_type": "reentrancy",
            "title": "Re-entrancy in withdraw",
            "id": "F-0",
            "function": "withdraw",
        }
        prop = self.gen._finding_to_property(finding, 0)
        self.assertIsNotNone(prop)
        self.assertEqual(prop.function_name, "check_noReentrancy_0")
        self.assertIn("withdraw", prop.function_body)
        self.assertEqual(prop.related_finding_id, "F-0")
        self.assertEqual(prop.property_type, "safety")

    def test_share_inflation_template(self):
        finding = {
            "vulnerability_type": "share_inflation",
            "title": "Vault inflation attack",
            "id": "F-1",
        }
        prop = self.gen._finding_to_property(finding, 1)
        self.assertIn("check_noShareInflation", prop.function_name)
        self.assertIn("convertToShares", prop.function_body)

    def test_missing_function_uses_default(self):
        finding = {
            "vulnerability_type": "reentrancy",
            "title": "Reentrancy",
            "id": "F-2",
        }
        prop = self.gen._finding_to_property(finding, 2)
        self.assertIn("unknownFunction", prop.function_body)

    def test_missing_id_generates_fallback(self):
        finding = {
            "vulnerability_type": "access_control",
            "title": "AC issue",
        }
        prop = self.gen._finding_to_property(finding, 5)
        self.assertEqual(prop.related_finding_id, "F-5")


class TestInvariantToProperty(unittest.TestCase):
    """Test _invariant_to_property internal method."""

    def setUp(self):
        self.gen = HalmosPropertyGenerator()

    def test_with_expression(self):
        inv = _MockInvariant(
            id="PAT-AMM-K",
            description="Constant product invariant",
            related_state=[],
            solidity_expression="reserve0 * reserve1 >= k_previous",
        )
        prop = self.gen._invariant_to_property(inv, 0)
        self.assertIsNotNone(prop)
        self.assertIn("check_pat_amm_k", prop.function_name)
        self.assertIn("assert(reserve0 * reserve1 >= k_previous)", prop.function_body)
        self.assertEqual(prop.property_type, "invariant")

    def test_without_expression(self):
        inv = _MockInvariant(
            id="LLM-1",
            description="Some invariant from LLM",
            related_state=[],
        )
        prop = self.gen._invariant_to_property(inv, 0)
        self.assertIn("TODO", prop.function_body)
        self.assertIn("assert(true)", prop.function_body)

    def test_special_chars_in_id(self):
        inv = _MockInvariant(
            id="NATSPEC-@weird#3",
            description="Weird chars",
            related_state=[],
            solidity_expression="x > 0",
        )
        prop = self.gen._invariant_to_property(inv, 0)
        # Function name should only contain alphanumeric + underscore
        self.assertTrue(
            all(c.isalnum() or c == '_' for c in prop.function_name),
            f"Invalid function name: {prop.function_name}",
        )


class TestPropertyTemplates(unittest.TestCase):
    """Verify all known vulnerability types produce valid properties."""

    def setUp(self):
        self.gen = HalmosPropertyGenerator()
        self.known_types = [
            "reentrancy",
            "integer_overflow",
            "share_inflation",
            "price_manipulation",
            "access_control",
            "flash_loan",
            "rounding_error",
        ]

    def test_all_known_types_generate_properties(self):
        for vuln_type in self.known_types:
            findings = [{
                "vulnerability_type": vuln_type,
                "title": f"Test {vuln_type}",
                "id": f"V-{vuln_type}",
                "function": "testFunc",
            }]
            suite = self.gen.generate_from_findings(findings, "TestContract")
            self.assertIsNotNone(
                suite,
                f"Failed to generate suite for {vuln_type}",
            )
            self.assertEqual(len(suite.properties), 1)
            sol = suite.to_solidity()
            self.assertIn("function check_", sol)
            self.assertIn("pragma solidity", sol)


class TestEndToEndSolidityGeneration(unittest.TestCase):
    """Integration test: findings -> Solidity code."""

    def test_full_pipeline(self):
        gen = HalmosPropertyGenerator()
        findings = [
            {"vulnerability_type": "reentrancy", "title": "R1", "id": "V-1", "function": "withdraw"},
            {"vulnerability_type": "share_inflation", "title": "SI", "id": "V-2"},
            {"vulnerability_type": "oracle", "title": "OM", "id": "V-3"},
        ]
        suite = gen.generate_from_findings(findings, "Vault", "src/Vault.sol")
        self.assertIsNotNone(suite)
        sol = suite.to_solidity()

        # Verify structure
        self.assertIn("SPDX-License-Identifier: MIT", sol)
        self.assertIn("pragma solidity ^0.8.0;", sol)
        self.assertIn('import "forge-std/Test.sol";', sol)
        self.assertIn('import "src/Vault.sol";', sol)
        self.assertIn("contract VaultHalmosTest is Test", sol)
        self.assertIn("Vault public target", sol)
        self.assertIn("function setUp()", sol)
        # All 3 properties present
        self.assertIn("check_noReentrancy_0", sol)
        self.assertIn("check_noShareInflation_1", sol)
        self.assertIn("check_noPriceManipulation_2", sol)


if __name__ == "__main__":
    unittest.main()
