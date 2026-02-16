"""Tests for the ContractScanner — classification, scoring, and directory scanning."""

import tempfile
import unittest
from pathlib import Path

from core.contract_scanner import (
    ContractClassification,
    ContractScanner,
    DiscoveryReport,
    PriorityTier,
    ScanResult,
    _score_to_priority,
)


# ── Sample contract snippets ──────────────────────────────────────────

INTERFACE_ONLY = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}
"""

LIBRARY_ONLY = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

library SafeMath {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        return a + b;
    }
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        return a - b;
    }
}
"""

ABSTRACT_ONLY = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

abstract contract ReentrancyGuard {
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;
    uint256 private _status;

    modifier nonReentrant() {
        require(_status != _ENTERED, "ReentrancyGuard: reentrant call");
        _status = _ENTERED;
        _;
        _status = _NOT_ENTERED;
    }
}
"""

SIMPLE_TOKEN = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract SimpleToken is ERC20 {
    constructor() ERC20("Simple", "SIM") {
        _mint(msg.sender, 1000000 * 10**18);
    }
}
"""

HIGH_VALUE_VAULT = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract HighValueVault is ERC4626 {
    using SafeERC20 for IERC20;

    mapping(address => uint256) public deposits;
    mapping(address => mapping(address => uint256)) public delegations;
    uint256 public totalDeposited;
    uint256 private _status;

    function deposit(uint256 assets, address receiver) public override returns (uint256) {
        uint256 shares = super.deposit(assets, receiver);
        deposits[receiver] += assets;
        totalDeposited += assets;
        return shares;
    }

    function withdraw(uint256 assets, address receiver, address owner) public override returns (uint256) {
        uint256 shares = super.withdraw(assets, receiver, owner);
        deposits[owner] -= assets;
        totalDeposited -= assets;
        return shares;
    }

    function totalAssets() public view override returns (uint256) {
        return IERC20(asset()).balanceOf(address(this));
    }

    function convertToShares(uint256 assets) public view override returns (uint256) {
        return super.convertToShares(assets);
    }

    function convertToAssets(uint256 shares) public view override returns (uint256) {
        return super.convertToAssets(shares);
    }

    function emergencyWithdraw() external {
        uint256 bal = deposits[msg.sender];
        deposits[msg.sender] = 0;
        IERC20(asset()).safeTransfer(msg.sender, bal);
    }
}
"""

DEFI_LENDING = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./interfaces/ILendingPool.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract LendingPool {
    using SafeERC20 for IERC20;

    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;
    mapping(address => mapping(address => uint256)) public userCollateral;

    uint256 public interestRate;
    uint256 public healthFactor;

    function borrow(uint256 amount) external {
        require(collateral[msg.sender] > 0, "No collateral");
        debt[msg.sender] += amount;
        IERC20(borrowToken).safeTransfer(msg.sender, amount);
    }

    function repay(uint256 amount) external payable {
        debt[msg.sender] -= amount;
        IERC20(borrowToken).safeTransferFrom(msg.sender, address(this), amount);
    }

    function liquidate(address user) external {
        require(_getHealthFactor(user) < 1e18, "Healthy");
        uint256 debtAmount = debt[user];
        debt[user] = 0;
        collateral[user] = 0;
        (bool success, ) = msg.sender.call{value: debtAmount}("");
        require(success, "Transfer failed");
    }

    function _getHealthFactor(address user) internal view returns (uint256) {
        return collateral[user] * 1e18 / debt[user];
    }
}
"""

FORGE_TEST = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/Vault.sol";

contract VaultTest is Test {
    Vault vault;

    function setUp() public {
        vault = new Vault();
    }

    function testDeposit() public {
        vault.deposit{value: 1 ether}();
    }
}
"""

FORGE_SCRIPT = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "../src/Vault.sol";

contract DeployScript is Script {
    function run() public {
        vm.startBroadcast();
        new Vault();
        vm.stopBroadcast();
    }
}
"""

MOCK_CONTRACT = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract MockERC20 {
    mapping(address => uint256) public balanceOf;
    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }
}
"""

UPGRADEABLE_CONTRACT = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

contract VaultV2 is UUPSUpgradeable {
    mapping(address => uint256) public deposits;
    mapping(address => uint256) public shares;

    function initialize() public initializer {
        __UUPSUpgradeable_init();
    }

    function deposit() external payable {
        deposits[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount);
        deposits[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
    }

    function _authorizeUpgrade(address) internal override {}
}
"""

COMPLEX_WITH_ASSEMBLY = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ComplexRouter {
    mapping(address => mapping(address => uint256)) public allowances;
    mapping(address => uint256) public balances;

    function swap(address tokenIn, address tokenOut, uint256 amountIn) external returns (uint256) {
        IERC20(tokenIn).safeTransferFrom(msg.sender, address(this), amountIn);
        uint256 amountOut;
        assembly {
            // custom math
            amountOut := div(mul(amountIn, 997), 1000)
        }
        unchecked {
            balances[tokenOut] -= amountOut;
        }
        IERC20(tokenOut).safeTransfer(msg.sender, amountOut);
        return amountOut;
    }

    function addLiquidity(address token, uint256 amount) external {
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        balances[token] += amount;
    }

    function removeLiquidity(address token, uint256 amount) external {
        balances[token] -= amount;
        IERC20(token).safeTransfer(msg.sender, amount);
    }

    function getReserves() external view returns (uint256, uint256) {
        return (balances[address(0)], balances[address(1)]);
    }
}
"""


class TestContractClassification(unittest.TestCase):
    """Test file classification heuristics."""

    def setUp(self):
        self.scanner = ContractScanner()

    def _classify(self, content: str, filename: str = "Contract.sol") -> ContractClassification:
        with tempfile.NamedTemporaryFile(suffix=filename, mode="w", delete=False) as f:
            f.write(content)
            f.flush()
            result = self.scanner.scan_file(Path(f.name))
            return result.classification

    def test_interface_only(self):
        cls = self._classify(INTERFACE_ONLY)
        self.assertEqual(cls, ContractClassification.INTERFACE)

    def test_library_only(self):
        cls = self._classify(LIBRARY_ONLY)
        self.assertEqual(cls, ContractClassification.LIBRARY)

    def test_abstract_only(self):
        cls = self._classify(ABSTRACT_ONLY)
        self.assertEqual(cls, ContractClassification.ABSTRACT)

    def test_core_protocol(self):
        cls = self._classify(SIMPLE_TOKEN)
        self.assertEqual(cls, ContractClassification.CORE_PROTOCOL)

    def test_test_by_extension(self):
        with tempfile.NamedTemporaryFile(suffix=".t.sol", mode="w", delete=False) as f:
            f.write(FORGE_TEST)
            f.flush()
            result = self.scanner.scan_file(Path(f.name))
            self.assertEqual(result.classification, ContractClassification.TEST)

    def test_script_by_extension(self):
        with tempfile.NamedTemporaryFile(suffix=".s.sol", mode="w", delete=False) as f:
            f.write(FORGE_SCRIPT)
            f.flush()
            result = self.scanner.scan_file(Path(f.name))
            self.assertEqual(result.classification, ContractClassification.SCRIPT)

    def test_mock_by_name(self):
        with tempfile.NamedTemporaryFile(
            suffix=".sol", prefix="MockERC20", mode="w", delete=False
        ) as f:
            f.write(MOCK_CONTRACT)
            f.flush()
            result = self.scanner.scan_file(Path(f.name))
            self.assertEqual(result.classification, ContractClassification.MOCK)

    def test_test_by_content(self):
        cls = self._classify(FORGE_TEST)
        self.assertEqual(cls, ContractClassification.TEST)

    def test_script_by_content(self):
        cls = self._classify(FORGE_SCRIPT)
        self.assertEqual(cls, ContractClassification.SCRIPT)

    def test_vault_is_core(self):
        cls = self._classify(HIGH_VALUE_VAULT)
        self.assertEqual(cls, ContractClassification.CORE_PROTOCOL)

    def test_lending_is_core(self):
        cls = self._classify(DEFI_LENDING)
        self.assertEqual(cls, ContractClassification.CORE_PROTOCOL)


class TestContractScoring(unittest.TestCase):
    """Test that scoring ranks contracts correctly."""

    def setUp(self):
        self.scanner = ContractScanner()

    def _score(self, content: str, filename: str = "Contract.sol") -> ScanResult:
        with tempfile.NamedTemporaryFile(suffix=filename, mode="w", delete=False) as f:
            f.write(content)
            f.flush()
            return self.scanner.scan_file(Path(f.name))

    def test_high_value_vault_scores_medium_or_above(self):
        result = self._score(HIGH_VALUE_VAULT)
        self.assertGreaterEqual(result.score, 30, "Vault should score MEDIUM or above")
        self.assertIn(result.priority, (PriorityTier.CRITICAL, PriorityTier.HIGH, PriorityTier.MEDIUM))

    def test_defi_lending_scores_high(self):
        result = self._score(DEFI_LENDING)
        self.assertGreaterEqual(result.score, 45, "Lending pool should score HIGH or near HIGH")

    def test_simple_token_scores_medium_or_below(self):
        result = self._score(SIMPLE_TOKEN)
        self.assertLess(result.score, 50, "Simple token should score below HIGH")

    def test_interface_scores_zero(self):
        result = self._score(INTERFACE_ONLY)
        self.assertEqual(result.score, 0, "Interface should score 0")
        self.assertEqual(result.priority, PriorityTier.SKIP)

    def test_library_scores_zero(self):
        result = self._score(LIBRARY_ONLY)
        self.assertEqual(result.score, 0)

    def test_test_scores_zero(self):
        result = self._score(FORGE_TEST)
        self.assertEqual(result.score, 0)

    def test_upgradeable_gets_upgrade_points(self):
        result = self._score(UPGRADEABLE_CONTRACT)
        self.assertGreater(
            result.score_breakdown.get("upgrade_proxy", 0), 0,
            "Upgradeable contract should get upgrade/proxy points",
        )

    def test_assembly_gets_complexity_points(self):
        result = self._score(COMPLEX_WITH_ASSEMBLY)
        self.assertGreater(
            result.score_breakdown.get("code_complexity", 0), 0,
            "Assembly should add complexity points",
        )

    def test_defi_archetype_bonus(self):
        result = self._score(HIGH_VALUE_VAULT)
        self.assertGreater(
            result.score_breakdown.get("defi_signals", 0), 0,
            "Vault should get DeFi archetype bonus",
        )

    def test_value_handling_signals(self):
        result = self._score(DEFI_LENDING)
        self.assertGreater(
            result.score_breakdown.get("value_handling", 0), 0,
            "Lending pool should score on value handling",
        )

    def test_external_interactions_signals(self):
        result = self._score(DEFI_LENDING)
        self.assertGreater(
            result.score_breakdown.get("external_interactions", 0), 0,
            "Lending pool with call{value} should score on external interactions",
        )

    def test_state_complexity_signals(self):
        result = self._score(HIGH_VALUE_VAULT)
        self.assertGreater(
            result.score_breakdown.get("state_complexity", 0), 0,
            "Vault with mappings should score on state complexity",
        )

    def test_signals_populated(self):
        result = self._score(HIGH_VALUE_VAULT)
        self.assertTrue(len(result.signals) > 0, "High-value vault should have signals")

    def test_complex_router_high_score(self):
        """Router with assembly + DeFi signals should score well."""
        result = self._score(COMPLEX_WITH_ASSEMBLY)
        self.assertGreaterEqual(result.score, 30)


class TestPriorityTiers(unittest.TestCase):
    """Test that score thresholds map to correct tiers."""

    def test_critical_threshold(self):
        self.assertEqual(_score_to_priority(70, ContractClassification.CORE_PROTOCOL), PriorityTier.CRITICAL)
        self.assertEqual(_score_to_priority(100, ContractClassification.CORE_PROTOCOL), PriorityTier.CRITICAL)

    def test_high_threshold(self):
        self.assertEqual(_score_to_priority(50, ContractClassification.CORE_PROTOCOL), PriorityTier.HIGH)
        self.assertEqual(_score_to_priority(69, ContractClassification.CORE_PROTOCOL), PriorityTier.HIGH)

    def test_medium_threshold(self):
        self.assertEqual(_score_to_priority(25, ContractClassification.CORE_PROTOCOL), PriorityTier.MEDIUM)
        self.assertEqual(_score_to_priority(49, ContractClassification.CORE_PROTOCOL), PriorityTier.MEDIUM)

    def test_low_threshold(self):
        self.assertEqual(_score_to_priority(12, ContractClassification.CORE_PROTOCOL), PriorityTier.LOW)
        self.assertEqual(_score_to_priority(24, ContractClassification.CORE_PROTOCOL), PriorityTier.LOW)

    def test_skip_threshold(self):
        self.assertEqual(_score_to_priority(11, ContractClassification.CORE_PROTOCOL), PriorityTier.SKIP)
        self.assertEqual(_score_to_priority(0, ContractClassification.CORE_PROTOCOL), PriorityTier.SKIP)

    def test_abstract_also_scored(self):
        """Abstracts should get scored (not auto-SKIP) — they contain real logic."""
        self.assertEqual(_score_to_priority(50, ContractClassification.ABSTRACT), PriorityTier.HIGH)
        self.assertEqual(_score_to_priority(25, ContractClassification.ABSTRACT), PriorityTier.MEDIUM)

    def test_non_core_non_abstract_always_skip(self):
        skip_classes = {
            ContractClassification.INTERFACE,
            ContractClassification.LIBRARY,
            ContractClassification.TEST,
            ContractClassification.MOCK,
            ContractClassification.SCRIPT,
        }
        for cls in skip_classes:
            self.assertEqual(
                _score_to_priority(100, cls), PriorityTier.SKIP,
                f"{cls} with score 100 should still be SKIP",
            )


class TestScanDirectory(unittest.TestCase):
    """Test directory scanning with mixed contract types."""

    def setUp(self):
        self.scanner = ContractScanner()

    def test_scan_mixed_directory(self):
        """Create a temp dir with mixed files and verify scan behavior."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)

            # Core contracts
            (root / "src").mkdir()
            (root / "src" / "Vault.sol").write_text(HIGH_VALUE_VAULT)
            (root / "src" / "Token.sol").write_text(SIMPLE_TOKEN)

            # Interface
            (root / "src" / "interfaces").mkdir()
            (root / "src" / "interfaces" / "IERC20.sol").write_text(INTERFACE_ONLY)

            # Library
            (root / "src" / "lib").mkdir()
            # Note: 'lib' is in SKIP_DIRS, so this should be skipped

            # Test file
            (root / "test").mkdir()
            (root / "test" / "Vault.t.sol").write_text(FORGE_TEST)

            # Node modules (should be skipped)
            (root / "node_modules").mkdir()
            (root / "node_modules" / "Dep.sol").write_text(SIMPLE_TOKEN)

            report = self.scanner.scan_directory(root)

            self.assertIsInstance(report, DiscoveryReport)
            self.assertEqual(report.root_path, root.resolve())
            self.assertGreater(report.scanned, 0)
            self.assertGreater(report.scan_time_ms, -1)

            # Results should be sorted by score descending
            scores = [r.score for r in report.results]
            self.assertEqual(scores, sorted(scores, reverse=True))

            # Vault should be first (highest score)
            names = [r.contract_name for r in report.results]
            if "Vault" in names:
                vault_idx = names.index("Vault")
                self.assertEqual(vault_idx, 0, "Vault should be first (highest score)")

    def test_skip_dirs(self):
        """Verify skip directories are actually skipped."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)

            (root / "src").mkdir()
            (root / "src" / "Core.sol").write_text(SIMPLE_TOKEN)

            # These should all be skipped
            for skip_dir in ["node_modules", "forge-std", "lib"]:
                d = root / skip_dir
                d.mkdir()
                (d / "Skipped.sol").write_text(SIMPLE_TOKEN)

            report = self.scanner.scan_directory(root)
            found_names = {r.contract_name for r in report.results}
            self.assertIn("Core", found_names)
            self.assertNotIn("Skipped", found_names)

    def test_recommended_property(self):
        """Verify the recommended property returns only CRITICAL+HIGH+MEDIUM."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "Vault.sol").write_text(HIGH_VALUE_VAULT)
            (root / "IERC20.sol").write_text(INTERFACE_ONLY)

            report = self.scanner.scan_directory(root)
            for r in report.recommended:
                self.assertIn(
                    r.priority,
                    (PriorityTier.CRITICAL, PriorityTier.HIGH, PriorityTier.MEDIUM),
                )

    def test_empty_directory(self):
        """Empty directory should return an empty report."""
        with tempfile.TemporaryDirectory() as tmpdir:
            report = self.scanner.scan_directory(Path(tmpdir))
            self.assertEqual(report.scanned, 0)
            self.assertEqual(len(report.results), 0)

    def test_single_file(self):
        """Directory with a single file should work."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "Single.sol").write_text(HIGH_VALUE_VAULT)
            report = self.scanner.scan_directory(root)
            self.assertEqual(report.scanned, 1)
            self.assertEqual(report.results[0].contract_name, "Single")


class TestScanFile(unittest.TestCase):
    """Test single-file scanning."""

    def setUp(self):
        self.scanner = ContractScanner()

    def test_scan_single_file(self):
        with tempfile.NamedTemporaryFile(suffix=".sol", mode="w", delete=False) as f:
            f.write(HIGH_VALUE_VAULT)
            f.flush()
            result = self.scanner.scan_file(Path(f.name))

            self.assertIsInstance(result, ScanResult)
            self.assertEqual(result.classification, ContractClassification.CORE_PROTOCOL)
            self.assertGreater(result.score, 0)
            self.assertGreater(result.line_count, 0)
            self.assertIsInstance(result.score_breakdown, dict)
            self.assertIsInstance(result.signals, list)


if __name__ == "__main__":
    unittest.main()
