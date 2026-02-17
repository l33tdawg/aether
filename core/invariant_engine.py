"""
Invariant Extraction & Foundry Test Generation Engine.

Takes invariants discovered by the deep analysis engine (Pass 1) and
automatically generates Foundry invariant tests (function invariant_*()).
Failing tests serve as formal-verification-lite proofs that bugs are real.
"""

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from core.json_utils import parse_llm_json

logger = logging.getLogger(__name__)


@dataclass
class Invariant:
    """A protocol invariant that should always hold."""
    id: str
    description: str
    related_state: List[str]
    solidity_expression: str = ""  # e.g. "totalAssets() >= totalSupply()"
    source: str = "llm"  # llm | natspec | pattern
    critical: bool = True


@dataclass
class InvariantTestSuite:
    """Generated Foundry invariant test suite."""
    contract_name: str
    test_contract_name: str
    solidity_code: str
    invariant_count: int
    imports: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Common invariant patterns (auto-detected from code)
# ---------------------------------------------------------------------------

_COMMON_INVARIANT_PATTERNS = [
    {
        'pattern': r'totalAssets\s*\(\)',
        'check': r'ERC4626|totalSupply',
        'id': 'PAT-VAULT-CONSERVATION',
        'description': 'Total assets should be >= total shares value (vault conservation)',
        'expression': 'vault.totalAssets() >= vault.convertToAssets(vault.totalSupply())',
        'critical': True,
    },
    {
        'pattern': r'balanceOf\s*\(\s*address\s*\(\s*this\s*\)',
        'check': r'totalDeposits|totalStaked|totalLocked',
        'id': 'PAT-BALANCE-CONSERVATION',
        'description': 'Contract token balance should match internal accounting',
        'expression': 'token.balanceOf(address(protocol)) >= protocol.totalDeposited()',
        'critical': True,
    },
    {
        'pattern': r'totalSupply\s*\(\)',
        'check': r'_mint|_burn',
        'id': 'PAT-SUPPLY-CONSERVATION',
        'description': 'Total supply should equal sum of all balances',
        'expression': 'token.totalSupply() == sum(balances)',
        'critical': True,
    },
    {
        'pattern': r'reserve[01]|getReserves',
        'check': r'swap|addLiquidity|removeLiquidity',
        'id': 'PAT-AMM-K',
        'description': 'AMM constant product invariant: k should not decrease except for fees',
        'expression': 'reserve0 * reserve1 >= k_previous',
        'critical': True,
    },
    {
        'pattern': r'healthFactor|collateral.*borrow|LTV',
        'check': r'borrow|liquidat',
        'id': 'PAT-LENDING-COLLATERAL',
        'description': 'Borrower collateral should always exceed borrowed amount (health factor > 1)',
        'expression': 'collateralValue >= borrowedValue * liquidationThreshold',
        'critical': True,
    },
    {
        'pattern': r'rewardPerToken|rewardRate',
        'check': r'stake|unstake|claimReward',
        'id': 'PAT-STAKING-REWARD',
        'description': 'Total distributed rewards should not exceed total reward budget',
        'expression': 'totalDistributed <= totalRewardBudget',
        'critical': False,
    },
]


class InvariantEngine:
    """Extracts invariants and generates Foundry invariant tests."""

    def extract_invariants(
        self,
        contract_content: str,
        pass1_result: Optional[str] = None,
    ) -> List[Invariant]:
        """Extract invariants from multiple sources.

        Sources (in priority order):
        1. NatSpec @invariant tags in the contract
        2. LLM-discovered invariants from deep analysis Pass 1
        3. Pattern-detected common invariants

        Args:
            contract_content: Full Solidity source code
            pass1_result: Raw JSON string from deep analysis Pass 1

        Returns:
            List of Invariant objects
        """
        invariants: List[Invariant] = []
        seen_ids: set = set()

        # Source 1: NatSpec @invariant tags
        natspec_invariants = self._extract_natspec_invariants(contract_content)
        for inv in natspec_invariants:
            if inv.id not in seen_ids:
                invariants.append(inv)
                seen_ids.add(inv.id)

        # Source 2: LLM-discovered invariants from Pass 1
        if pass1_result:
            llm_invariants = self._extract_llm_invariants(pass1_result)
            for inv in llm_invariants:
                if inv.id not in seen_ids:
                    invariants.append(inv)
                    seen_ids.add(inv.id)

        # Source 3: Pattern-detected common invariants
        pattern_invariants = self._extract_pattern_invariants(contract_content)
        for inv in pattern_invariants:
            if inv.id not in seen_ids:
                invariants.append(inv)
                seen_ids.add(inv.id)

        return invariants

    def generate_foundry_invariant_tests(
        self,
        invariants: List[Invariant],
        contract_name: str,
        contract_path: str = "",
    ) -> Optional[InvariantTestSuite]:
        """Generate a Foundry invariant test suite from extracted invariants.

        Args:
            invariants: List of invariants to test
            contract_name: Name of the contract under test
            contract_path: Import path for the contract

        Returns:
            InvariantTestSuite or None if no testable invariants
        """
        if not invariants:
            return None

        testable = [inv for inv in invariants if inv.solidity_expression]
        if not testable:
            # Generate stubs for invariants without expressions
            testable = invariants

        test_contract_name = f"{contract_name}InvariantTest"
        import_path = contract_path or f"src/{contract_name}.sol"

        test_functions = []
        for inv in testable:
            func_name = self._invariant_to_func_name(inv)
            if inv.solidity_expression:
                body = f'        assertTrue({inv.solidity_expression}, "{inv.description}");'
            else:
                body = f'        // TODO: Implement invariant check\n        // {inv.description}\n        assertTrue(true, "stub");'

            test_functions.append(
                f"    /// @dev Invariant: {inv.description}\n"
                f"    function {func_name}() public view {{\n"
                f"{body}\n"
                f"    }}"
            )

        functions_text = "\n\n".join(test_functions)

        solidity_code = f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "{import_path}";

/// @title Invariant Tests for {contract_name}
/// @notice Auto-generated by Aether's InvariantEngine
contract {test_contract_name} is Test {{
    {contract_name} public target;

    function setUp() public {{
        // TODO: Deploy and initialize the contract
        // target = new {contract_name}(...);
    }}

{functions_text}
}}
"""

        return InvariantTestSuite(
            contract_name=contract_name,
            test_contract_name=test_contract_name,
            solidity_code=solidity_code,
            invariant_count=len(testable),
            imports=[import_path],
        )

    # ------------------------------------------------------------------
    # Private extraction methods
    # ------------------------------------------------------------------

    def _extract_natspec_invariants(self, content: str) -> List[Invariant]:
        """Extract @invariant tags from NatSpec comments."""
        invariants = []
        # Match @invariant in /// or /** */ comments
        pattern = r'(?:///|/\*\*|\*)\s*@invariant\s+(.+?)(?:\n|\*/)'
        matches = re.finditer(pattern, content)
        for i, m in enumerate(matches):
            desc = m.group(1).strip()
            invariants.append(Invariant(
                id=f"NATSPEC-{i+1}",
                description=desc,
                related_state=[],
                source="natspec",
            ))
        return invariants

    def _extract_llm_invariants(self, pass1_result: str) -> List[Invariant]:
        """Extract invariants from deep analysis Pass 1 JSON output."""
        parsed = parse_llm_json(pass1_result)
        if not parsed or not isinstance(parsed, dict):
            return []

        raw_invariants = parsed.get('invariants', [])
        invariants = []
        for item in raw_invariants:
            if isinstance(item, dict):
                inv_id = item.get('id', f"LLM-{len(invariants)+1}")
                invariants.append(Invariant(
                    id=inv_id,
                    description=item.get('description', ''),
                    related_state=item.get('related_state', []),
                    solidity_expression=item.get('solidity_expression', ''),
                    source="llm",
                    critical=item.get('critical', True),
                ))
        return invariants

    def _extract_pattern_invariants(self, content: str) -> List[Invariant]:
        """Extract common invariants by pattern matching."""
        invariants = []
        for pat in _COMMON_INVARIANT_PATTERNS:
            if re.search(pat['pattern'], content) and re.search(pat['check'], content):
                invariants.append(Invariant(
                    id=pat['id'],
                    description=pat['description'],
                    related_state=[],
                    solidity_expression=pat.get('expression', ''),
                    source="pattern",
                    critical=pat.get('critical', True),
                ))
        return invariants

    def generate_halmos_properties(
        self,
        invariants: List[Invariant],
        contract_name: str,
        contract_path: str = "",
    ) -> Optional[str]:
        """Generate Halmos symbolic test properties from invariants.

        Unlike Foundry invariant tests (which fuzz), Halmos symbolically
        explores *all* inputs for bounded model checking.

        Args:
            invariants: Extracted invariants.
            contract_name: Name of the contract under test.
            contract_path: Import path for the contract.

        Returns:
            Solidity source code string, or None if no testable invariants.
        """
        try:
            from core.halmos_property_generator import HalmosPropertyGenerator
            generator = HalmosPropertyGenerator()
            suite = generator.generate_from_invariants(
                invariants=invariants,
                contract_name=contract_name,
                contract_path=contract_path,
            )
            return suite.to_solidity() if suite else None
        except ImportError:
            logger.warning("HalmosPropertyGenerator not available")
            return None

    def _invariant_to_func_name(self, inv: Invariant) -> str:
        """Convert an invariant to a Foundry invariant_ function name."""
        # Convert description to snake_case function name
        name = inv.id.lower().replace('-', '_')
        name = re.sub(r'[^a-z0-9_]', '', name)
        return f"invariant_{name}"
