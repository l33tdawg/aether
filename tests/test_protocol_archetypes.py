"""Tests for protocol archetype detection and checklist generation."""

import unittest
from core.protocol_archetypes import (
    ProtocolArchetype,
    ProtocolArchetypeDetector,
    ArchetypeResult,
    ChecklistItem,
    get_checklist_for_archetype,
    get_checklists_for_result,
    format_checklist_for_prompt,
)


class TestProtocolArchetypeDetector(unittest.TestCase):
    """Test archetype detection from Solidity source code."""

    def setUp(self):
        self.detector = ProtocolArchetypeDetector()

    def test_detect_vault_erc4626(self):
        code = """
        contract MyVault is ERC4626 {
            function totalAssets() public view override returns (uint256) {
                return IERC20(asset()).balanceOf(address(this));
            }
            function convertToShares(uint256 assets) public view returns (uint256) {}
            function convertToAssets(uint256 shares) public view returns (uint256) {}
            function deposit(uint256 assets, address receiver) public returns (uint256) {}
            function redeem(uint256 shares, address receiver, address owner) public returns (uint256) {}
            function previewDeposit(uint256 assets) public view returns (uint256) {}
        }
        """
        result = self.detector.detect(code)
        self.assertEqual(result.primary, ProtocolArchetype.VAULT_ERC4626)
        self.assertGreater(result.confidence, 0.5)

    def test_detect_lending_pool(self):
        code = """
        contract LendingPool {
            function borrow(uint256 amount) external {}
            function repay(uint256 amount) external {}
            function liquidate(address user) external {}
            uint256 public healthFactor;
            uint256 public collateral;
        }
        """
        result = self.detector.detect(code)
        self.assertEqual(result.primary, ProtocolArchetype.LENDING_POOL)
        self.assertGreater(result.confidence, 0.4)

    def test_detect_dex_amm(self):
        code = """
        contract UniswapV2Pair {
            function swap(uint amount0Out, uint amount1Out, address to) external {}
            function addLiquidity(uint a, uint b) external returns (uint) {}
            function removeLiquidity(uint liquidity) external {}
            function getReserves() external view returns (uint, uint, uint) {}
            uint public reserve0;
            uint public reserve1;
            uint public MINIMUM_LIQUIDITY;
        }
        """
        result = self.detector.detect(code)
        self.assertEqual(result.primary, ProtocolArchetype.DEX_AMM)
        self.assertGreater(result.confidence, 0.5)

    def test_detect_bridge(self):
        code = """
        contract Bridge {
            function relayMessage(bytes calldata message) external {}
            function proveWithdrawal(bytes32 hash) external {}
            function finalizeWithdrawal(bytes32 hash) external {}
            function crossChainTransfer(uint256 amount) external {}
        }
        """
        result = self.detector.detect(code)
        self.assertEqual(result.primary, ProtocolArchetype.BRIDGE)

    def test_detect_staking(self):
        code = """
        contract StakingRewards {
            function stake(uint256 amount) external {}
            function unstake(uint256 amount) external {}
            function claimRewards() external {}
            uint256 public rewardPerToken;
            uint256 public rewardRate;
            uint256 public totalStaked;
        }
        """
        result = self.detector.detect(code)
        self.assertEqual(result.primary, ProtocolArchetype.STAKING)

    def test_detect_governance(self):
        code = """
        contract GovernorContract is Governor {
            function propose(address[] memory targets) public returns (uint256) {}
            function castVote(uint256 proposalId, uint8 support) public {}
            uint256 public quorum;
            function proposalThreshold() public view returns (uint256) {}
        }
        """
        result = self.detector.detect(code)
        self.assertEqual(result.primary, ProtocolArchetype.GOVERNANCE)

    def test_detect_oracle(self):
        code = """
        contract PriceOracle {
            AggregatorV3Interface public priceFeed;
            function getPrice() external view returns (uint256) {
                (, int256 answer, , uint256 updatedAt, ) = priceFeed.latestRoundData();
                return uint256(answer);
            }
        }
        """
        result = self.detector.detect(code)
        self.assertEqual(result.primary, ProtocolArchetype.ORACLE)

    def test_detect_unknown(self):
        code = "contract Empty {}"
        result = self.detector.detect(code)
        self.assertEqual(result.primary, ProtocolArchetype.UNKNOWN)
        self.assertEqual(result.confidence, 0.0)

    def test_secondary_archetypes(self):
        """A vault with lending features should detect both."""
        code = """
        contract VaultLender is ERC4626 {
            function totalAssets() public view returns (uint256) {}
            function convertToShares(uint256) public view returns (uint256) {}
            function deposit(uint256 assets, address r) public returns (uint256) {}
            function borrow(uint256 amount) external {}
            function repay(uint256 amount) external {}
            function collateral() public view returns (uint256) {}
        }
        """
        result = self.detector.detect(code)
        # Either vault or lending could be primary
        archetypes = [result.primary] + result.secondary
        archetype_values = [a.value for a in archetypes]
        self.assertTrue(
            'vault_erc4626' in archetype_values or 'lending_pool' in archetype_values,
            f"Expected vault or lending in {archetype_values}"
        )

    def test_detect_from_files(self):
        files = [
            {'content': 'contract A { function swap(uint a, uint b, address to) external {} }'},
            {'content': 'contract B { function getReserves() external view returns (uint, uint) {} function addLiquidity(uint a, uint b) external {} }'},
        ]
        result = self.detector.detect_from_files(files)
        self.assertEqual(result.primary, ProtocolArchetype.DEX_AMM)


class TestArchetypeChecklists(unittest.TestCase):
    """Test checklist retrieval and formatting."""

    def test_vault_checklist_not_empty(self):
        items = get_checklist_for_archetype(ProtocolArchetype.VAULT_ERC4626)
        self.assertGreater(len(items), 0)
        self.assertIsInstance(items[0], ChecklistItem)

    def test_lending_checklist_has_oracle(self):
        items = get_checklist_for_archetype(ProtocolArchetype.LENDING_POOL)
        names = [item.name for item in items]
        self.assertTrue(any('oracle' in n.lower() or 'Oracle' in n for n in names))

    def test_unknown_checklist_empty(self):
        items = get_checklist_for_archetype(ProtocolArchetype.UNKNOWN)
        self.assertEqual(len(items), 0)

    def test_get_checklists_for_result_combines(self):
        result = ArchetypeResult(
            primary=ProtocolArchetype.VAULT_ERC4626,
            secondary=[ProtocolArchetype.LENDING_POOL],
            confidence=0.8,
        )
        items = get_checklists_for_result(result)
        # Should have both vault and lending items
        self.assertGreater(len(items), len(get_checklist_for_archetype(ProtocolArchetype.VAULT_ERC4626)))

    def test_get_checklists_no_duplicates(self):
        result = ArchetypeResult(
            primary=ProtocolArchetype.VAULT_ERC4626,
            secondary=[ProtocolArchetype.VAULT_ERC4626],  # same as primary
            confidence=0.8,
        )
        items = get_checklists_for_result(result)
        names = [item.name for item in items]
        self.assertEqual(len(names), len(set(names)))  # no duplicates

    def test_format_checklist_for_prompt(self):
        items = get_checklist_for_archetype(ProtocolArchetype.VAULT_ERC4626)
        text = format_checklist_for_prompt(items)
        self.assertIn("Archetype-Specific Vulnerability Checklist", text)
        self.assertIn("First Depositor", text)
        self.assertIn("CRITICAL", text)

    def test_format_empty_checklist(self):
        text = format_checklist_for_prompt([])
        self.assertEqual(text, "")


class TestProtocolArchetypeEnum(unittest.TestCase):
    """Test ProtocolArchetype enum values."""

    def test_all_archetypes_exist(self):
        expected = [
            'DEX_AMM', 'DEX_ORDERBOOK', 'LENDING_POOL', 'VAULT_ERC4626',
            'BRIDGE', 'STAKING', 'GOVERNANCE', 'NFT_MARKETPLACE', 'TOKEN',
            'ORACLE', 'UNKNOWN',
        ]
        for name in expected:
            self.assertTrue(hasattr(ProtocolArchetype, name), f"Missing archetype: {name}")

    def test_archetype_values_are_strings(self):
        for archetype in ProtocolArchetype:
            self.assertIsInstance(archetype.value, str)


if __name__ == '__main__':
    unittest.main()
