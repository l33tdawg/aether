"""
Tests for Enhanced Precision Analyzer Detection Capabilities

This test suite validates the new precision/rounding vulnerability detections:
1. Share Inflation / First Depositor Attack Detection
2. Rounding Direction Error Detection
3. Division Truncation Amplification Detection
4. Dust Amount Exploitation Detection
5. Accumulator Overflow Detection
"""

import unittest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.precision_analyzer import (
    PrecisionAnalyzer,
    PrecisionVulnerability,
    PrecisionIssue,
    PrecisionRisk
)


class TestShareInflationDetection(unittest.TestCase):
    """Test share inflation / first depositor attack detection."""

    def setUp(self):
        self.analyzer = PrecisionAnalyzer()

    def test_vulnerable_vault_detected(self):
        """Should detect share inflation in a basic vulnerable vault."""
        vulnerable_vault = """
contract Vault {
    uint256 public totalAssets;
    uint256 public totalSupply;
    function deposit(uint256 assets) external returns (uint256 shares) {
        shares = totalSupply == 0 ? assets : assets * totalSupply / totalAssets;
        totalSupply += shares;
        totalAssets += assets;
    }
}
"""
        vulns = self.analyzer.analyze_precision_loss(vulnerable_vault)
        share_inflation_vulns = [v for v in vulns if v.vulnerability_type == 'share_inflation']
        self.assertGreater(len(share_inflation_vulns), 0,
                           "Should detect share inflation in vulnerable vault")
        vuln = share_inflation_vulns[0]
        self.assertEqual(vuln.severity, 'high')
        self.assertIn('first depositor', vuln.description.lower())
        self.assertGreaterEqual(vuln.confidence, 0.70)

    def test_safe_vault_with_virtual_offset_not_detected(self):
        """Should NOT detect share inflation when virtual offset is used."""
        safe_vault = """
contract SafeVault {
    uint256 public totalAssets;
    uint256 public totalSupply;
    uint256 constant OFFSET = 1e3;
    function deposit(uint256 assets) external returns (uint256 shares) {
        shares = (assets * (totalSupply + OFFSET)) / (totalAssets + 1);
        totalSupply += shares;
        totalAssets += assets;
    }
}
"""
        vulns = self.analyzer.analyze_precision_loss(safe_vault)
        share_inflation_vulns = [v for v in vulns if v.vulnerability_type == 'share_inflation']
        self.assertEqual(len(share_inflation_vulns), 0,
                         "Should NOT detect share inflation when virtual offset is present")

    def test_safe_vault_with_decimals_offset_not_detected(self):
        """Should NOT detect share inflation when _decimalsOffset is used."""
        safe_vault = """
contract SafeERC4626Vault {
    uint256 public totalAssets;
    uint256 public totalSupply;
    function _decimalsOffset() internal pure returns (uint8) {
        return 3;
    }
    function convertToShares(uint256 assets) public view returns (uint256) {
        return assets * totalSupply / totalAssets;
    }
    function deposit(uint256 assets) external returns (uint256 shares) {
        shares = convertToShares(assets);
        totalSupply += shares;
        totalAssets += assets;
    }
}
"""
        vulns = self.analyzer.analyze_precision_loss(safe_vault)
        share_inflation_vulns = [v for v in vulns if v.vulnerability_type == 'share_inflation']
        self.assertEqual(len(share_inflation_vulns), 0,
                         "Should NOT detect share inflation when _decimalsOffset is present")

    def test_safe_vault_with_constructor_mint_not_detected(self):
        """Should NOT detect share inflation when constructor mints initial shares."""
        safe_vault = """
contract SafeVault {
    uint256 public totalAssets;
    uint256 public totalSupply;
    constructor() {
        _mint(address(0), 1000);
        totalSupply = 1000;
        totalAssets = 1000;
    }
    function deposit(uint256 assets) external returns (uint256 shares) {
        shares = assets * totalSupply / totalAssets;
        totalSupply += shares;
        totalAssets += assets;
    }
}
"""
        vulns = self.analyzer.analyze_precision_loss(safe_vault)
        share_inflation_vulns = [v for v in vulns if v.vulnerability_type == 'share_inflation']
        self.assertEqual(len(share_inflation_vulns), 0,
                         "Should NOT detect share inflation when constructor mints dead shares")

    def test_no_vault_contract_not_detected(self):
        """Should NOT detect share inflation in non-vault contracts."""
        non_vault = """
contract SimpleToken {
    mapping(address => uint256) public balanceOf;
    function transfer(address to, uint256 amount) external {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
    }
}
"""
        vulns = self.analyzer.analyze_precision_loss(non_vault)
        share_inflation_vulns = [v for v in vulns if v.vulnerability_type == 'share_inflation']
        self.assertEqual(len(share_inflation_vulns), 0,
                         "Should NOT detect share inflation in non-vault contracts")

    def test_erc4626_without_protection_detected(self):
        """Should detect share inflation in ERC4626 vault without protection."""
        vulnerable_erc4626 = """
import "@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol";

contract MyVault is ERC4626 {
    function totalAssets() public view override returns (uint256) {
        return IERC20(asset()).balanceOf(address(this));
    }
    function previewDeposit(uint256 assets) public view override returns (uint256) {
        uint256 supply = totalSupply();
        return supply == 0 ? assets : assets * supply / totalAssets();
    }
}
"""
        vulns = self.analyzer.analyze_precision_loss(vulnerable_erc4626)
        share_inflation_vulns = [v for v in vulns if v.vulnerability_type == 'share_inflation']
        self.assertGreater(len(share_inflation_vulns), 0,
                           "Should detect share inflation in ERC4626 vault without protection")


class TestRoundingDirectionDetection(unittest.TestCase):
    """Test rounding direction error detection in deposit/withdraw paths."""

    def setUp(self):
        self.analyzer = PrecisionAnalyzer()

    def test_withdraw_rounds_down_detected(self):
        """Should detect withdraw that rounds DOWN (wrong direction, favors withdrawer)."""
        vulnerable_withdraw = """
contract Vault {
    uint256 public totalAssets;
    uint256 public totalSupply;
    IERC20 token;
    function withdraw(uint256 shares) external returns (uint256 assets) {
        assets = shares * totalAssets / totalSupply;
        totalSupply -= shares;
        totalAssets -= assets;
        token.transfer(msg.sender, assets);
    }
}
"""
        vulns = self.analyzer.analyze_precision_loss(vulnerable_withdraw)
        rounding_vulns = [v for v in vulns if v.vulnerability_type == 'rounding_direction_error']
        self.assertGreater(len(rounding_vulns), 0,
                           "Should detect rounding direction error in withdraw")
        vuln = rounding_vulns[0]
        self.assertEqual(vuln.severity, 'medium')
        self.assertIn('withdraw', vuln.description.lower())

    def test_withdraw_with_round_up_not_detected(self):
        """Should NOT detect when withdraw properly rounds UP."""
        safe_withdraw = """
contract SafeVault {
    uint256 public totalAssets;
    uint256 public totalSupply;
    IERC20 token;
    function withdraw(uint256 shares) external returns (uint256 assets) {
        assets = Math.mulDiv(shares, totalAssets, totalSupply, Math.Rounding.Up);
        totalSupply -= shares;
        totalAssets -= assets;
        token.transfer(msg.sender, assets);
    }
}
"""
        vulns = self.analyzer.analyze_precision_loss(safe_withdraw)
        rounding_vulns = [v for v in vulns if v.vulnerability_type == 'rounding_direction_error']
        self.assertEqual(len(rounding_vulns), 0,
                         "Should NOT detect rounding direction error when Math.Rounding.Up is used")

    def test_withdraw_with_ceil_div_not_detected(self):
        """Should NOT detect when withdraw uses ceilDiv."""
        safe_withdraw = """
contract SafeVault {
    uint256 public totalAssets;
    uint256 public totalSupply;
    IERC20 token;
    function withdraw(uint256 shares) external returns (uint256 assets) {
        assets = ceilDiv(shares * totalAssets, totalSupply);
        totalSupply -= shares;
        totalAssets -= assets;
        token.transfer(msg.sender, assets);
    }
}
"""
        vulns = self.analyzer.analyze_precision_loss(safe_withdraw)
        rounding_vulns = [v for v in vulns if v.vulnerability_type == 'rounding_direction_error']
        self.assertEqual(len(rounding_vulns), 0,
                         "Should NOT detect rounding direction error when ceilDiv is used")

    def test_withdraw_with_manual_round_up_not_detected(self):
        """Should NOT detect when withdraw uses + (denominator - 1) rounding."""
        safe_withdraw = """
contract SafeVault {
    uint256 public totalAssets;
    uint256 public totalSupply;
    IERC20 token;
    function redeem(uint256 shares) external returns (uint256 assets) {
        assets = (shares * totalAssets + (totalSupply - 1)) / totalSupply;
        totalSupply -= shares;
        totalAssets -= assets;
        token.transfer(msg.sender, assets);
    }
}
"""
        vulns = self.analyzer.analyze_precision_loss(safe_withdraw)
        rounding_vulns = [v for v in vulns if v.vulnerability_type == 'rounding_direction_error']
        self.assertEqual(len(rounding_vulns), 0,
                         "Should NOT detect rounding direction error when manual round-up is used")

    def test_redeem_rounds_down_detected(self):
        """Should detect redeem that rounds DOWN (wrong direction)."""
        vulnerable_redeem = """
contract Vault {
    uint256 public totalAssets;
    uint256 public totalSupply;
    IERC20 token;
    function redeem(uint256 shares) external returns (uint256 assets) {
        assets = shares * totalAssets / totalSupply;
        totalSupply -= shares;
        totalAssets -= assets;
        token.transfer(msg.sender, assets);
    }
}
"""
        vulns = self.analyzer.analyze_precision_loss(vulnerable_redeem)
        rounding_vulns = [v for v in vulns if v.vulnerability_type == 'rounding_direction_error']
        self.assertGreater(len(rounding_vulns), 0,
                           "Should detect rounding direction error in redeem function")


class TestDivisionTruncationAmplification(unittest.TestCase):
    """Test division truncation amplification detection."""

    def setUp(self):
        self.analyzer = PrecisionAnalyzer()

    def test_rate_truncation_amplified_detected(self):
        """Should detect rate calculated via division then multiplied later."""
        vulnerable_code = """
contract StakingPool {
    uint256 public totalStaked;
    uint256 public totalRewards;
    mapping(address => uint256) public userStake;

    function updateRewardRate() internal {
        uint256 rewardRate = totalRewards / totalStaked;
        // ... later used as:
        uint256 reward = userStake[msg.sender] * rewardRate;
    }
}
"""
        vulns = self.analyzer.analyze_precision_loss(vulnerable_code)
        trunc_vulns = [v for v in vulns if v.vulnerability_type == 'division_truncation_amplification']
        self.assertGreater(len(trunc_vulns), 0,
                           "Should detect division truncation amplification")
        vuln = trunc_vulns[0]
        self.assertEqual(vuln.severity, 'medium')
        self.assertIn('rewardRate', vuln.description)

    def test_rate_with_precision_multiplier_not_detected(self):
        """Should NOT detect when PRECISION multiplier is used."""
        safe_code = """
contract StakingPool {
    uint256 public totalStaked;
    uint256 public totalRewards;
    uint256 constant PRECISION = 1e18;
    mapping(address => uint256) public userStake;

    function updateRewardRate() internal {
        uint256 rewardRate = totalRewards * PRECISION / totalStaked;
        uint256 reward = userStake[msg.sender] * rewardRate / PRECISION;
    }
}
"""
        vulns = self.analyzer.analyze_precision_loss(safe_code)
        trunc_vulns = [v for v in vulns if v.vulnerability_type == 'division_truncation_amplification']
        self.assertEqual(len(trunc_vulns), 0,
                         "Should NOT detect truncation amplification when PRECISION multiplier is used")

    def test_rate_with_wad_not_detected(self):
        """Should NOT detect when WAD is used as precision multiplier."""
        safe_code = """
contract StakingPool {
    uint256 public totalStaked;
    uint256 public totalRewards;
    uint256 constant WAD = 1e18;

    function updateRewardRate() internal {
        uint256 rewardRate = totalRewards * WAD / totalStaked;
        uint256 reward = userStake * rewardRate;
    }
}
"""
        vulns = self.analyzer.analyze_precision_loss(safe_code)
        trunc_vulns = [v for v in vulns if v.vulnerability_type == 'division_truncation_amplification']
        self.assertEqual(len(trunc_vulns), 0,
                         "Should NOT detect truncation amplification when WAD multiplier is used")

    def test_ratio_truncation_detected(self):
        """Should detect ratio stored via division then multiplied."""
        vulnerable_code = """
contract PriceOracle {
    uint256 public lastPrice;

    function updateRatio(uint256 numerator, uint256 denominator) internal {
        uint256 exchangeRatio = numerator / denominator;
        uint256 adjustedValue = amount * exchangeRatio;
    }
}
"""
        vulns = self.analyzer.analyze_precision_loss(vulnerable_code)
        trunc_vulns = [v for v in vulns if v.vulnerability_type == 'division_truncation_amplification']
        self.assertGreater(len(trunc_vulns), 0,
                           "Should detect ratio truncation amplification")


class TestDustExploitation(unittest.TestCase):
    """Test dust amount exploitation detection."""

    def setUp(self):
        self.analyzer = PrecisionAnalyzer()

    def test_deposit_without_zero_check_detected(self):
        """Should detect deposit where shares can round to 0 without check."""
        vulnerable_code = """
contract Vault {
    uint256 public totalAssets;
    uint256 public totalSupply;
    function deposit(uint256 assets) external returns (uint256 shares) {
        shares = assets * totalSupply / totalAssets;
        totalSupply += shares;
        totalAssets += assets;
    }
}
"""
        vulns = self.analyzer.analyze_precision_loss(vulnerable_code)
        dust_vulns = [v for v in vulns if v.vulnerability_type == 'dust_exploitation']
        self.assertGreater(len(dust_vulns), 0,
                           "Should detect dust exploitation in deposit without zero check")
        vuln = dust_vulns[0]
        self.assertEqual(vuln.severity, 'medium')

    def test_deposit_with_zero_check_not_detected(self):
        """Should NOT detect when require(shares > 0) is present."""
        safe_code = """
contract SafeVault {
    uint256 public totalAssets;
    uint256 public totalSupply;
    function deposit(uint256 assets) external returns (uint256 shares) {
        require(assets > 0, "zero amount");
        shares = assets * totalSupply / totalAssets;
        require(shares > 0, "zero shares");
        totalSupply += shares;
        totalAssets += assets;
    }
}
"""
        vulns = self.analyzer.analyze_precision_loss(safe_code)
        dust_vulns = [v for v in vulns if v.vulnerability_type == 'dust_exploitation']
        self.assertEqual(len(dust_vulns), 0,
                         "Should NOT detect dust exploitation when zero check is present")

    def test_withdraw_without_zero_check_detected(self):
        """Should detect withdraw where assets can round to 0 without check."""
        vulnerable_code = """
contract Vault {
    uint256 public totalAssets;
    uint256 public totalSupply;
    IERC20 token;
    function withdraw(uint256 shares) external returns (uint256 assets) {
        assets = shares * totalAssets / totalSupply;
        totalSupply -= shares;
        totalAssets -= assets;
        token.transfer(msg.sender, assets);
    }
}
"""
        vulns = self.analyzer.analyze_precision_loss(vulnerable_code)
        dust_vulns = [v for v in vulns if v.vulnerability_type == 'dust_exploitation']
        self.assertGreater(len(dust_vulns), 0,
                           "Should detect dust exploitation in withdraw without zero check")

    def test_mint_with_revert_on_zero_not_detected(self):
        """Should NOT detect when if (shares == 0) revert pattern is used."""
        safe_code = """
contract SafeVault {
    uint256 public totalAssets;
    uint256 public totalSupply;
    function mint(uint256 assets) external returns (uint256 shares) {
        shares = assets * totalSupply / totalAssets;
        if (shares == 0) revert ZeroShares();
        totalSupply += shares;
        totalAssets += assets;
    }
}
"""
        vulns = self.analyzer.analyze_precision_loss(safe_code)
        dust_vulns = [v for v in vulns if v.vulnerability_type == 'dust_exploitation']
        self.assertEqual(len(dust_vulns), 0,
                         "Should NOT detect dust exploitation when revert on zero is present")


class TestAccumulatorOverflow(unittest.TestCase):
    """Test accumulator overflow detection."""

    def setUp(self):
        self.analyzer = PrecisionAnalyzer()

    def test_reward_accumulator_detected(self):
        """Should detect reward accumulator with high precision multiplier."""
        code = """
contract Staking {
    uint256 public rewardPerTokenStored;
    uint256 public totalSupply;

    function updateReward() internal {
        rewardPerTokenStored += reward * 1e18 / totalSupply;
    }
}
"""
        vulns = self.analyzer.analyze_precision_loss(code)
        accum_vulns = [v for v in vulns if v.vulnerability_type == 'accumulator_overflow']
        self.assertGreater(len(accum_vulns), 0,
                           "Should detect accumulator overflow risk")
        vuln = accum_vulns[0]
        self.assertEqual(vuln.severity, 'low')

    def test_no_accumulator_pattern_not_detected(self):
        """Should NOT detect accumulator overflow in non-accumulator code."""
        code = """
contract SimpleContract {
    uint256 public value;
    function setValue(uint256 newValue) external {
        value = newValue;
    }
}
"""
        vulns = self.analyzer.analyze_precision_loss(code)
        accum_vulns = [v for v in vulns if v.vulnerability_type == 'accumulator_overflow']
        self.assertEqual(len(accum_vulns), 0,
                         "Should NOT detect accumulator overflow in simple contracts")


class TestPrecisionIssueEnum(unittest.TestCase):
    """Test that new PrecisionIssue enum values are present."""

    def test_share_inflation_enum(self):
        self.assertEqual(PrecisionIssue.SHARE_INFLATION.value, "share_inflation")

    def test_rounding_direction_enum(self):
        self.assertEqual(PrecisionIssue.ROUNDING_DIRECTION.value, "rounding_direction")

    def test_division_truncation_amplification_enum(self):
        self.assertEqual(PrecisionIssue.DIVISION_TRUNCATION_AMPLIFICATION.value,
                         "division_truncation_amplification")

    def test_dust_exploitation_enum(self):
        self.assertEqual(PrecisionIssue.DUST_EXPLOITATION.value, "dust_exploitation")

    def test_accumulator_overflow_enum(self):
        self.assertEqual(PrecisionIssue.ACCUMULATOR_OVERFLOW.value, "accumulator_overflow")


class TestIntegrationWithExistingDetections(unittest.TestCase):
    """Test that new detections work alongside existing ones without interference."""

    def setUp(self):
        self.analyzer = PrecisionAnalyzer()

    def test_existing_division_detection_still_works(self):
        """Existing division precision loss detection should still work."""
        code = """
contract Test {
    function calculate(uint256 a, uint256 b) public pure returns (uint256) {
        uint256 result = a / b;
        return result;
    }
}
"""
        vulns = self.analyzer.analyze_precision_loss(code)
        precision_vulns = [v for v in vulns if v.vulnerability_type == 'precision_loss_division']
        self.assertGreater(len(precision_vulns), 0,
                           "Existing division precision loss detection should still work")

    def test_existing_rounding_error_detection_still_works(self):
        """Existing rounding error (div-then-mul) detection should still work."""
        code = """
contract Test {
    function calculate(uint256 a, uint256 b, uint256 c) public pure returns (uint256) {
        uint256 result = a / b * c;
        return result;
    }
}
"""
        vulns = self.analyzer.analyze_precision_loss(code)
        rounding_vulns = [v for v in vulns if v.vulnerability_type == 'rounding_error']
        self.assertGreater(len(rounding_vulns), 0,
                           "Existing rounding error detection should still work")

    def test_complex_vault_all_detections(self):
        """A complex vault with multiple issues should trigger multiple detections."""
        complex_vault = """
contract VulnerableVault {
    uint256 public totalAssets;
    uint256 public totalSupply;
    IERC20 token;

    function deposit(uint256 assets) external returns (uint256 shares) {
        shares = totalSupply == 0 ? assets : assets * totalSupply / totalAssets;
        totalSupply += shares;
        totalAssets += assets;
    }

    function withdraw(uint256 shares) external returns (uint256 assets) {
        assets = shares * totalAssets / totalSupply;
        totalSupply -= shares;
        totalAssets -= assets;
        token.transfer(msg.sender, assets);
    }
}
"""
        vulns = self.analyzer.analyze_precision_loss(complex_vault)
        vuln_types = set(v.vulnerability_type for v in vulns)

        # Should detect share inflation
        self.assertIn('share_inflation', vuln_types,
                       "Should detect share inflation in complex vault")

        # Should detect rounding direction error in withdraw
        self.assertIn('rounding_direction_error', vuln_types,
                       "Should detect rounding direction error in complex vault")

    def test_precision_summary_includes_new_detections(self):
        """Precision summary should still work with new detections active."""
        code = """
contract Test {
    uint256 public totalAssets;
    uint256 public totalSupply;
    function calc(uint256 a, uint256 b) public pure returns (uint256) {
        return a / b;
    }
    function calc2(uint256 a, uint256 b) public pure returns (uint256) {
        return a * b;
    }
}
"""
        summary = self.analyzer.get_precision_summary(code)
        self.assertIn('division_operations', summary)
        self.assertIn('multiplication_operations', summary)
        self.assertGreater(summary['division_operations'], 0)

    def test_vulnerability_output_format(self):
        """All new vulnerability types should produce correct PrecisionVulnerability format."""
        code = """
contract Vault {
    uint256 public totalAssets;
    uint256 public totalSupply;
    function deposit(uint256 assets) external returns (uint256 shares) {
        shares = assets * totalSupply / totalAssets;
        totalSupply += shares;
        totalAssets += assets;
    }
}
"""
        vulns = self.analyzer.analyze_precision_loss(code)
        for vuln in vulns:
            self.assertIsInstance(vuln, PrecisionVulnerability)
            self.assertIsInstance(vuln.vulnerability_type, str)
            self.assertIsInstance(vuln.severity, str)
            self.assertIn(vuln.severity, ['low', 'medium', 'high', 'critical'])
            self.assertIsInstance(vuln.description, str)
            self.assertGreater(len(vuln.description), 0)
            self.assertIsInstance(vuln.confidence, float)
            self.assertGreaterEqual(vuln.confidence, 0.0)
            self.assertLessEqual(vuln.confidence, 1.0)
            self.assertIsInstance(vuln.swc_id, str)
            self.assertIsInstance(vuln.recommendation, str)
            self.assertGreater(len(vuln.recommendation), 0)


if __name__ == '__main__':
    unittest.main()
