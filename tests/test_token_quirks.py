"""
Comprehensive test suite for the Token Quirks Database and Detector.

Tests all 12 token quirk categories with vulnerable and protected code snippets,
plus integration with the EnhancedVulnerabilityDetector.
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.token_quirks import (
    TokenQuirk,
    TOKEN_QUIRKS,
    check_token_quirks,
    get_quirk,
    get_quirks_for_archetype,
    _has_token_interaction,
)


class TestTokenQuirkDatabase(unittest.TestCase):
    """Tests for the TOKEN_QUIRKS database structure."""

    def test_database_has_12_categories(self):
        """Verify all 12 quirk categories are present."""
        self.assertEqual(len(TOKEN_QUIRKS), 12)

    def test_all_quirk_names_unique(self):
        """Each quirk should have a unique name."""
        names = [q.name for q in TOKEN_QUIRKS]
        self.assertEqual(len(names), len(set(names)))

    def test_expected_names_present(self):
        """Check the expected 12 quirk names are in the database."""
        expected = {
            "fee_on_transfer",
            "rebasing_tokens",
            "erc777_callbacks",
            "non_standard_return",
            "blocklist_tokens",
            "approval_race",
            "pausable_tokens",
            "multiple_entry_points",
            "upgradeable_tokens",
            "low_decimal_tokens",
            "transfer_hooks",
            "flash_mintable_tokens",
        }
        actual = {q.name for q in TOKEN_QUIRKS}
        self.assertEqual(expected, actual)

    def test_quirk_fields_populated(self):
        """Every quirk must have non-empty fields."""
        for quirk in TOKEN_QUIRKS:
            with self.subTest(quirk=quirk.name):
                self.assertTrue(len(quirk.description) > 0)
                self.assertTrue(len(quirk.known_tokens) > 0)
                self.assertTrue(len(quirk.detection_signals) > 0)
                self.assertTrue(len(quirk.protection_patterns) > 0)
                self.assertTrue(len(quirk.missing_protection) > 0)
                self.assertTrue(len(quirk.exploit_scenario) > 0)
                self.assertIn(quirk.severity, ("high", "medium", "low"))
                self.assertTrue(len(quirk.archetype_relevance) > 0)

    def test_get_quirk_by_name(self):
        """get_quirk() returns correct quirk or None."""
        q = get_quirk("fee_on_transfer")
        self.assertIsNotNone(q)
        self.assertEqual(q.name, "fee_on_transfer")

        self.assertIsNone(get_quirk("nonexistent_quirk"))

    def test_get_quirks_for_archetype(self):
        """get_quirks_for_archetype() returns relevant quirks."""
        dex_quirks = get_quirks_for_archetype("DEX_AMM")
        self.assertTrue(len(dex_quirks) > 0)
        for q in dex_quirks:
            self.assertIn("DEX_AMM", q.archetype_relevance)


class TestNoTokenInteraction(unittest.TestCase):
    """Test that contracts without token interaction return no findings."""

    def test_pure_math_contract(self):
        """Contract with no token calls should return empty list."""
        contract = """
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.0;

        contract MathLib {
            function add(uint256 a, uint256 b) external pure returns (uint256) {
                return a + b;
            }
            function multiply(uint256 a, uint256 b) external pure returns (uint256) {
                return a * b;
            }
        }
        """
        findings = check_token_quirks(contract)
        self.assertEqual(len(findings), 0)

    def test_empty_contract(self):
        """Empty contract string should return empty list."""
        findings = check_token_quirks("")
        self.assertEqual(len(findings), 0)

    def test_ether_only_contract(self):
        """Contract that only handles ETH should return empty list."""
        contract = """
        pragma solidity ^0.8.0;

        contract EtherVault {
            mapping(address => uint256) public balances;

            function deposit() external payable {
                balances[msg.sender] += msg.value;
            }

            function withdraw(uint256 amount) external {
                require(balances[msg.sender] >= amount);
                balances[msg.sender] -= amount;
                (bool ok,) = msg.sender.call{value: amount}("");
                require(ok);
            }
        }
        """
        findings = check_token_quirks(contract)
        self.assertEqual(len(findings), 0)


class TestHasTokenInteraction(unittest.TestCase):
    """Tests for the _has_token_interaction helper."""

    def test_detects_transfer(self):
        self.assertTrue(_has_token_interaction("token.transfer(to, amount);"))

    def test_detects_transferFrom(self):
        self.assertTrue(_has_token_interaction("token.transferFrom(from, to, amount);"))

    def test_detects_IERC20(self):
        self.assertTrue(_has_token_interaction("IERC20(token).balanceOf(user)"))

    def test_no_token_keywords(self):
        self.assertFalse(_has_token_interaction("uint256 x = a + b;"))


# ---------------------------------------------------------------------------
# Per-quirk detection tests
# ---------------------------------------------------------------------------


class TestFeeOnTransfer(unittest.TestCase):
    """Test fee_on_transfer quirk detection."""

    def test_vulnerable_deposit(self):
        """Detects when transferFrom amount is credited directly without balance check."""
        contract = """
        pragma solidity ^0.8.0;
        import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

        contract VulnerableVault {
            mapping(address => uint256) public balances;

            function deposit(address token, uint256 amount) external {
                IERC20(token).transferFrom(msg.sender, address(this), amount);
                balances[msg.sender] += amount;
            }
        }
        """
        findings = check_token_quirks(contract)
        fee_findings = [f for f in findings if "fee_on_transfer" in f['vulnerability_type']]
        self.assertGreater(len(fee_findings), 0, "Should detect fee-on-transfer vulnerability")
        self.assertEqual(fee_findings[0]['severity'], "high")

    def test_protected_with_balance_delta(self):
        """Should NOT detect when balance delta pattern is used."""
        contract = """
        pragma solidity ^0.8.0;
        import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

        contract SafeVault {
            mapping(address => uint256) public balances;

            function deposit(address token, uint256 amount) external {
                uint256 balanceBefore = IERC20(token).balanceOf(address(this));
                IERC20(token).transferFrom(msg.sender, address(this), amount);
                uint256 received = IERC20(token).balanceOf(address(this)) - balanceBefore;
                balances[msg.sender] += received;
            }
        }
        """
        findings = check_token_quirks(contract)
        fee_findings = [f for f in findings if "fee_on_transfer" in f['vulnerability_type']]
        self.assertEqual(len(fee_findings), 0, "Should NOT flag protected contract")


class TestRebasingTokens(unittest.TestCase):
    """Test rebasing_tokens quirk detection."""

    def test_vulnerable_cached_balance(self):
        """Detects when balanceOf is cached in a mapping and used later."""
        contract = """
        pragma solidity ^0.8.0;
        import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

        contract StakingPool {
            mapping(address => uint256) public deposits;
            IERC20 public stakingToken;

            function stake(uint256 amount) external {
                stakingToken.transferFrom(msg.sender, address(this), amount);
                deposits[msg.sender] = stakingToken.balanceOf(address(this));
            }

            function withdraw() external {
                uint256 amount = deposits[msg.sender];
                deposits[msg.sender] = 0;
                stakingToken.transfer(msg.sender, amount);
            }
        }
        """
        findings = check_token_quirks(contract)
        rebasing_findings = [f for f in findings if "rebasing" in f['vulnerability_type']]
        self.assertGreater(len(rebasing_findings), 0, "Should detect rebasing token vulnerability")

    def test_protected_share_accounting(self):
        """Should NOT detect when share-based accounting is used."""
        contract = """
        pragma solidity ^0.8.0;
        import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

        contract SafeStaking {
            mapping(address => uint256) public _shares;
            IERC20 public stakingToken;

            function stake(uint256 amount) external {
                stakingToken.transferFrom(msg.sender, address(this), amount);
                _shares[msg.sender] += amount;
            }
        }
        """
        findings = check_token_quirks(contract)
        rebasing_findings = [f for f in findings if "rebasing" in f['vulnerability_type']]
        self.assertEqual(len(rebasing_findings), 0, "Share-based accounting should not flag")


class TestERC777Callbacks(unittest.TestCase):
    """Test erc777_callbacks quirk detection."""

    def test_vulnerable_transfer_then_state(self):
        """Detects state update after transfer (reentrancy via ERC-777)."""
        contract = """
        pragma solidity ^0.8.0;
        import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

        contract VulnerablePool {
            mapping(address => uint256) public balances;

            function withdraw(uint256 amount) external {
                IERC20(token).transfer(msg.sender, amount);
                balances[msg.sender] -= amount;
            }
        }
        """
        findings = check_token_quirks(contract)
        erc777_findings = [f for f in findings if "erc777" in f['vulnerability_type']]
        self.assertGreater(len(erc777_findings), 0, "Should detect ERC-777 reentrancy risk")

    def test_protected_with_nonreentrant(self):
        """Should NOT detect when nonReentrant modifier is present."""
        contract = """
        pragma solidity ^0.8.0;
        import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
        import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

        contract SafePool is ReentrancyGuard {
            mapping(address => uint256) public balances;

            function withdraw(uint256 amount) external nonReentrant {
                IERC20(token).transfer(msg.sender, amount);
                balances[msg.sender] -= amount;
            }
        }
        """
        findings = check_token_quirks(contract)
        erc777_findings = [f for f in findings if "erc777" in f['vulnerability_type']]
        self.assertEqual(len(erc777_findings), 0, "nonReentrant should prevent flag")


class TestNonStandardReturn(unittest.TestCase):
    """Test non_standard_return quirk detection."""

    def test_vulnerable_direct_bool_check(self):
        """Detects require(token.transfer(...)) without SafeERC20."""
        contract = """
        pragma solidity ^0.8.0;

        contract VulnerableTransfer {
            function send(address token, address to, uint256 amount) external {
                require(IERC20(token).transfer(to, amount), "transfer failed");
            }
        }
        """
        findings = check_token_quirks(contract)
        nsr_findings = [f for f in findings if "non_standard_return" in f['vulnerability_type']]
        self.assertGreater(len(nsr_findings), 0, "Should detect non-standard return vulnerability")

    def test_protected_with_safe_erc20(self):
        """Should NOT detect when SafeERC20 is used."""
        contract = """
        pragma solidity ^0.8.0;
        import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

        contract SafeTransfer {
            using SafeERC20 for IERC20;

            function send(address token, address to, uint256 amount) external {
                IERC20(token).safeTransfer(to, amount);
            }
        }
        """
        findings = check_token_quirks(contract)
        nsr_findings = [f for f in findings if "non_standard_return" in f['vulnerability_type']]
        self.assertEqual(len(nsr_findings), 0, "SafeERC20 should prevent flag")


class TestBlocklistTokens(unittest.TestCase):
    """Test blocklist_tokens quirk detection."""

    def test_vulnerable_push_transfer(self):
        """Detects push-based transfers that can fail for blocklisted addresses."""
        contract = """
        pragma solidity ^0.8.0;
        import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

        contract RewardDistributor {
            IERC20 public token;
            address[] public users;

            function distribute(uint256 amount) external {
                for (uint256 i = 0; i < users.length; i++) {
                    token.safeTransfer(users[i], amount);
                }
            }
        }
        """
        findings = check_token_quirks(contract)
        bl_findings = [f for f in findings if "blocklist" in f['vulnerability_type']]
        self.assertGreater(len(bl_findings), 0, "Should detect blocklist DoS risk")

    def test_protected_with_pull_pattern(self):
        """Should NOT detect when pull-based withdrawal is used."""
        contract = """
        pragma solidity ^0.8.0;
        import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

        contract SafeDistributor {
            IERC20 public token;
            mapping(address => uint256) public pendingWithdraw;

            function claim() external {
                uint256 amount = pendingWithdraw[msg.sender];
                pendingWithdraw[msg.sender] = 0;
                token.transfer(msg.sender, amount);
            }
        }
        """
        findings = check_token_quirks(contract)
        bl_findings = [f for f in findings if "blocklist" in f['vulnerability_type']]
        self.assertEqual(len(bl_findings), 0, "Pull pattern should prevent flag")


class TestApprovalRace(unittest.TestCase):
    """Test approval_race quirk detection."""

    def test_vulnerable_direct_approve(self):
        """Detects direct approve(spender, amount) without zeroing first."""
        contract = """
        pragma solidity ^0.8.0;
        import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

        contract Approver {
            function setAllowance(address token, address spender, uint256 amount) external {
                IERC20(token).approve(spender, amount);
            }
        }
        """
        findings = check_token_quirks(contract)
        ar_findings = [f for f in findings if "approval_race" in f['vulnerability_type']]
        self.assertGreater(len(ar_findings), 0, "Should detect approval race condition")

    def test_protected_with_safe_increase(self):
        """Should NOT detect when safeIncreaseAllowance is used."""
        contract = """
        pragma solidity ^0.8.0;
        import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

        contract SafeApprover {
            using SafeERC20 for IERC20;

            function setAllowance(address token, address spender, uint256 amount) external {
                IERC20(token).safeIncreaseAllowance(spender, amount);
            }
        }
        """
        findings = check_token_quirks(contract)
        ar_findings = [f for f in findings if "approval_race" in f['vulnerability_type']]
        self.assertEqual(len(ar_findings), 0, "safeIncreaseAllowance should prevent flag")


class TestPausableTokens(unittest.TestCase):
    """Test pausable_tokens quirk detection."""

    def test_vulnerable_critical_transfer(self):
        """Detects token transfer in liquidation/withdrawal without failure handling."""
        contract = """
        pragma solidity ^0.8.0;
        import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

        contract LendingPool {
            IERC20 public token;

            function liquidate(address user, uint256 amount) external {
                // critical path - if token is paused, liquidation fails
                token.safeTransfer(msg.sender, amount);
            }
        }
        """
        findings = check_token_quirks(contract)
        pause_findings = [f for f in findings if "pausable" in f['vulnerability_type']]
        self.assertGreater(len(pause_findings), 0, "Should detect pausable token risk in critical path")

    def test_protected_with_try_catch(self):
        """Should NOT detect when try-catch is used around transfers."""
        contract = """
        pragma solidity ^0.8.0;
        import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

        contract SafeLending {
            IERC20 public token;

            function liquidate(address user, uint256 amount) external {
                try token.safeTransfer(msg.sender, amount) {
                    // success
                } catch {
                    // fallback handling
                }
            }
        }
        """
        findings = check_token_quirks(contract)
        pause_findings = [f for f in findings if "pausable" in f['vulnerability_type']]
        self.assertEqual(len(pause_findings), 0, "try-catch should prevent flag")


class TestMultipleEntryPoints(unittest.TestCase):
    """Test multiple_entry_points quirk detection."""

    def test_vulnerable_address_comparison(self):
        """Detects direct token address comparison without canonicalization."""
        contract = """
        pragma solidity ^0.8.0;
        import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

        contract PairFactory {
            function createPair(address tokenA, address tokenB) external {
                require(tokenA != tokenB, "same token");
                // Create pair...
                IERC20(tokenA).approve(address(this), type(uint256).max);
            }
        }
        """
        findings = check_token_quirks(contract)
        me_findings = [f for f in findings if "multiple_entry" in f['vulnerability_type']]
        self.assertGreater(len(me_findings), 0, "Should detect multiple entry point risk")

    def test_protected_with_canonical_resolution(self):
        """Should NOT detect when canonical address resolution is used."""
        contract = """
        pragma solidity ^0.8.0;
        import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

        contract SafePairFactory {
            function getCanonical(address token) internal view returns (address) {
                return token;
            }

            function createPair(address tokenA, address tokenB) external {
                tokenA = getCanonical(tokenA);
                tokenB = getCanonical(tokenB);
                require(tokenA != tokenB, "same token");
                IERC20(tokenA).approve(address(this), type(uint256).max);
            }
        }
        """
        findings = check_token_quirks(contract)
        me_findings = [f for f in findings if "multiple_entry" in f['vulnerability_type']]
        self.assertEqual(len(me_findings), 0, "Canonical resolution should prevent flag")


class TestUpgradeableTokens(unittest.TestCase):
    """Test upgradeable_tokens quirk detection."""

    def test_vulnerable_hardcoded_decimals(self):
        """Detects hardcoded decimal assumptions."""
        contract = """
        pragma solidity ^0.8.0;
        import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

        contract PriceCalculator {
            uint256 constant DECIMALS = 18;

            function getPrice(address token, uint256 amount) external view returns (uint256) {
                return amount * 1e18 / IERC20(token).balanceOf(address(this));
            }
        }
        """
        findings = check_token_quirks(contract)
        up_findings = [f for f in findings if "upgradeable" in f['vulnerability_type']]
        self.assertGreater(len(up_findings), 0, "Should detect hardcoded decimal assumptions")

    def test_protected_with_dynamic_decimals(self):
        """Should NOT detect when decimals are read dynamically."""
        contract = """
        pragma solidity ^0.8.0;
        import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";

        contract SafePriceCalculator {
            function getPrice(address token, uint256 amount) external view returns (uint256) {
                uint8 d = IERC20Metadata(token).decimals();
                return amount * (10 ** d) / IERC20(token).balanceOf(address(this));
            }
        }
        """
        findings = check_token_quirks(contract)
        up_findings = [f for f in findings if "upgradeable" in f['vulnerability_type']]
        self.assertEqual(len(up_findings), 0, "IERC20Metadata should prevent flag")


class TestLowDecimalTokens(unittest.TestCase):
    """Test low_decimal_tokens quirk detection."""

    def test_vulnerable_hardcoded_1e18(self):
        """Detects hardcoded 1e18 in token math."""
        contract = """
        pragma solidity ^0.8.0;
        import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

        contract VulnerableVault {
            function convertToShares(uint256 amount, address token) public view returns (uint256) {
                uint256 totalAssets = IERC20(token).balanceOf(address(this));
                return amount * 1e18 / totalAssets;
            }
        }
        """
        findings = check_token_quirks(contract)
        ld_findings = [f for f in findings if "low_decimal" in f['vulnerability_type']]
        self.assertGreater(len(ld_findings), 0, "Should detect hardcoded 1e18 precision issue")

    def test_protected_with_dynamic_decimals(self):
        """Should NOT detect when dynamic decimal scaling is used."""
        contract = """
        pragma solidity ^0.8.0;
        import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

        contract SafeVault {
            function convertToShares(uint256 amount, address token) public view returns (uint256) {
                uint8 d = IERC20(token).decimals();
                uint256 scaleFactor = 10 ** d;
                uint256 totalAssets = IERC20(token).balanceOf(address(this));
                return amount * scaleFactor / totalAssets;
            }
        }
        """
        findings = check_token_quirks(contract)
        ld_findings = [f for f in findings if "low_decimal" in f['vulnerability_type']]
        self.assertEqual(len(ld_findings), 0, "Dynamic decimals should prevent flag")


class TestTransferHooks(unittest.TestCase):
    """Test transfer_hooks quirk detection."""

    def test_vulnerable_transfer_then_update(self):
        """Detects state update after transfer (ERC-1363/677 reentrancy)."""
        contract = """
        pragma solidity ^0.8.0;
        import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

        contract RewardPool {
            mapping(address => uint256) public rewards;
            IERC20 public rewardToken;

            function claimReward() external {
                uint256 amount = rewards[msg.sender];
                rewardToken.transfer(msg.sender, amount);
                rewards[msg.sender] -= amount;
            }
        }
        """
        findings = check_token_quirks(contract)
        th_findings = [f for f in findings if "transfer_hooks" in f['vulnerability_type']]
        self.assertGreater(len(th_findings), 0, "Should detect transfer hook reentrancy risk")

    def test_protected_with_nonreentrant(self):
        """Should NOT detect when nonReentrant is present."""
        contract = """
        pragma solidity ^0.8.0;
        import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

        contract SafeRewardPool is ReentrancyGuard {
            mapping(address => uint256) public rewards;
            IERC20 public rewardToken;

            function claimReward() external nonReentrant {
                uint256 amount = rewards[msg.sender];
                rewardToken.transfer(msg.sender, amount);
                rewards[msg.sender] -= amount;
            }
        }
        """
        findings = check_token_quirks(contract)
        th_findings = [f for f in findings if "transfer_hooks" in f['vulnerability_type']]
        self.assertEqual(len(th_findings), 0, "nonReentrant should prevent flag")


class TestFlashMintableTokens(unittest.TestCase):
    """Test flash_mintable_tokens quirk detection."""

    def test_vulnerable_supply_based_pricing(self):
        """Detects totalSupply used in pricing logic."""
        contract = """
        pragma solidity ^0.8.0;
        import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

        contract VulnerablePricing {
            function getTokenPrice(address token) external view returns (uint256) {
                uint256 reserves = address(this).balance;
                uint256 supply = IERC20(token).totalSupply();
                uint256 price = reserves * 1e18 / supply;
                return price;
            }
        }
        """
        findings = check_token_quirks(contract)
        fm_findings = [f for f in findings if "flash_mintable" in f['vulnerability_type']]
        self.assertGreater(len(fm_findings), 0, "Should detect flash-mint supply manipulation risk")

    def test_vulnerable_balance_based_governance(self):
        """Detects balanceOf used for voting weight."""
        contract = """
        pragma solidity ^0.8.0;
        import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

        contract VulnerableGovernance {
            IERC20 public govToken;

            function getVotingPower(address user) external view returns (uint256) {
                return govToken.balanceOf(user);
                // This is the voting weight for proposals
            }

            function castVote(uint256 proposalId, bool support) external {
                uint256 weight = govToken.balanceOf(msg.sender);
                // vote with weight
            }
        }
        """
        findings = check_token_quirks(contract)
        fm_findings = [f for f in findings if "flash_mintable" in f['vulnerability_type']]
        self.assertGreater(len(fm_findings), 0, "Should detect balance-based governance risk")

    def test_protected_with_snapshot_voting(self):
        """Should NOT detect when snapshot-based voting is used."""
        contract = """
        pragma solidity ^0.8.0;
        import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Votes.sol";

        contract SafeGovernance {
            ERC20Votes public govToken;

            function getVotingPower(address user, uint256 blockNumber) external view returns (uint256) {
                return govToken.getPastVotes(user, blockNumber);
            }
        }
        """
        findings = check_token_quirks(contract)
        fm_findings = [f for f in findings if "flash_mintable" in f['vulnerability_type']]
        self.assertEqual(len(fm_findings), 0, "Snapshot voting should prevent flag")


# ---------------------------------------------------------------------------
# Finding format tests
# ---------------------------------------------------------------------------


class TestFindingFormat(unittest.TestCase):
    """Test that findings have all required fields in the standard format."""

    def test_finding_has_all_fields(self):
        """Each finding must have the standard vulnerability dict keys."""
        contract = """
        pragma solidity ^0.8.0;
        import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

        contract Vulnerable {
            mapping(address => uint256) public balances;

            function deposit(address token, uint256 amount) external {
                IERC20(token).transferFrom(msg.sender, address(this), amount);
                balances[msg.sender] += amount;
            }
        }
        """
        findings = check_token_quirks(contract)
        self.assertTrue(len(findings) > 0, "Should have at least one finding for test")

        required_keys = {
            'vulnerability_type', 'severity', 'confidence',
            'line_number', 'description', 'code_snippet', 'mitigation',
        }
        for finding in findings:
            for key in required_keys:
                self.assertIn(key, finding, f"Finding missing required key: {key}")

    def test_vulnerability_type_prefix(self):
        """All vulnerability types should be prefixed with 'token_quirk_'."""
        contract = """
        pragma solidity ^0.8.0;
        import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

        contract Vulnerable {
            mapping(address => uint256) public balances;

            function deposit(address token, uint256 amount) external {
                IERC20(token).transferFrom(msg.sender, address(this), amount);
                balances[msg.sender] += amount;
            }
        }
        """
        findings = check_token_quirks(contract)
        for finding in findings:
            self.assertTrue(
                finding['vulnerability_type'].startswith("token_quirk_"),
                f"Type should start with 'token_quirk_': {finding['vulnerability_type']}",
            )

    def test_severity_values_valid(self):
        """Severity should be high, medium, or low."""
        contract = """
        pragma solidity ^0.8.0;
        import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

        contract Vulnerable {
            mapping(address => uint256) public balances;

            function deposit(address token, uint256 amount) external {
                IERC20(token).transferFrom(msg.sender, address(this), amount);
                balances[msg.sender] += amount;
            }
        }
        """
        findings = check_token_quirks(contract)
        for finding in findings:
            self.assertIn(finding['severity'], ("high", "medium", "low"))

    def test_confidence_in_range(self):
        """Confidence should be between 0 and 1."""
        contract = """
        pragma solidity ^0.8.0;
        import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

        contract Vulnerable {
            mapping(address => uint256) public balances;

            function deposit(address token, uint256 amount) external {
                IERC20(token).transferFrom(msg.sender, address(this), amount);
                balances[msg.sender] += amount;
            }
        }
        """
        findings = check_token_quirks(contract)
        for finding in findings:
            self.assertGreaterEqual(finding['confidence'], 0.0)
            self.assertLessEqual(finding['confidence'], 1.0)

    def test_line_number_positive(self):
        """Line numbers should be positive integers."""
        contract = """
        pragma solidity ^0.8.0;
        import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

        contract Vulnerable {
            mapping(address => uint256) public balances;

            function deposit(address token, uint256 amount) external {
                IERC20(token).transferFrom(msg.sender, address(this), amount);
                balances[msg.sender] += amount;
            }
        }
        """
        findings = check_token_quirks(contract)
        for finding in findings:
            self.assertGreater(finding['line_number'], 0)


# ---------------------------------------------------------------------------
# Integration test
# ---------------------------------------------------------------------------


class TestEnhancedDetectorIntegration(unittest.TestCase):
    """Test that token quirk findings flow through EnhancedVulnerabilityDetector."""

    def test_token_quirks_in_analyze_contract(self):
        """EnhancedVulnerabilityDetector.analyze_contract should include token quirk findings."""
        from core.enhanced_vulnerability_detector import EnhancedVulnerabilityDetector

        contract = """
        pragma solidity ^0.8.0;
        import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

        contract VulnerableVault {
            mapping(address => uint256) public balances;

            function deposit(address token, uint256 amount) external {
                IERC20(token).transferFrom(msg.sender, address(this), amount);
                balances[msg.sender] += amount;
            }

            function withdraw(address token, uint256 amount) external {
                require(balances[msg.sender] >= amount);
                balances[msg.sender] -= amount;
                IERC20(token).transfer(msg.sender, amount);
            }
        }
        """
        detector = EnhancedVulnerabilityDetector()
        vulnerabilities = detector.analyze_contract(contract)

        # Check that at least one token_quirk finding is present
        token_quirk_vulns = [v for v in vulnerabilities if v.category == 'token_quirks']
        self.assertGreater(
            len(token_quirk_vulns), 0,
            "EnhancedVulnerabilityDetector should include token quirk findings",
        )

    def test_no_token_quirks_for_clean_contract(self):
        """Clean contracts should not have token quirk findings from the detector."""
        from core.enhanced_vulnerability_detector import EnhancedVulnerabilityDetector

        contract = """
        pragma solidity ^0.8.0;

        contract PureMath {
            function add(uint256 a, uint256 b) external pure returns (uint256) {
                return a + b;
            }
        }
        """
        detector = EnhancedVulnerabilityDetector()
        vulnerabilities = detector.analyze_contract(contract)

        token_quirk_vulns = [v for v in vulnerabilities if v.category == 'token_quirks']
        self.assertEqual(
            len(token_quirk_vulns), 0,
            "Pure math contract should have no token quirk findings",
        )


# ---------------------------------------------------------------------------
# Combined vulnerability contract test
# ---------------------------------------------------------------------------


class TestMultipleQuirksDetection(unittest.TestCase):
    """Test detection of multiple quirks in a single contract."""

    def test_detects_multiple_issues(self):
        """Contract with multiple token quirk vulnerabilities should find several."""
        contract = """
        pragma solidity ^0.8.0;

        contract MultiVulnerable {
            mapping(address => uint256) public balances;
            uint256 constant DECIMALS = 18;

            function deposit(address token, uint256 amount) external {
                IERC20(token).transferFrom(msg.sender, address(this), amount);
                balances[msg.sender] += amount;
            }

            function setApproval(address token, address spender, uint256 amt) external {
                IERC20(token).approve(spender, amt);
            }

            function withdraw(address token, uint256 amount) external {
                balances[msg.sender] -= amount;
                IERC20(token).transfer(msg.sender, amount);
            }
        }
        """
        findings = check_token_quirks(contract)
        # Should detect at least fee_on_transfer + approval_race
        types = {f['vulnerability_type'] for f in findings}
        self.assertGreater(len(types), 1, f"Should detect multiple quirk types, found: {types}")


if __name__ == '__main__':
    unittest.main()
