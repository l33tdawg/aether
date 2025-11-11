"""
DeFi Pattern Recognizer

Recognizes common DeFi patterns to provide context-aware analysis and reduce false positives.
Understands patterns like vesting, linear unlocks, fee calculations, and time-locked operations.
"""

import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum


class PatternType(Enum):
    """Types of DeFi patterns."""
    LINEAR_VESTING = "linear_vesting"
    CLIFF_VESTING = "cliff_vesting"
    TIME_LOCK = "time_lock"
    FEE_CALCULATION = "fee_calculation"
    SHARE_CALCULATION = "share_calculation"  # ERC4626 style
    STAKING_REWARDS = "staking_rewards"
    COOLDOWN_PERIOD = "cooldown_period"
    GRADUAL_UNLOCK = "gradual_unlock"
    EPOCH_BASED = "epoch_based"


@dataclass
class RecognizedPattern:
    """A recognized DeFi pattern."""
    pattern_type: PatternType
    confidence: float
    description: str
    key_variables: Dict[str, str]  # Variable names and their roles
    key_functions: List[str]  # Function names involved
    implications: List[str]  # What this pattern means for vulnerability analysis
    example_protocols: List[str]  # Known protocols using this pattern


class DeFiPatternRecognizer:
    """
    Recognizes common DeFi patterns to provide better context for vulnerability analysis.
    
    Helps understand:
    - Why state overwrites might be intentional
    - When timing constraints make exploits impossible
    - How standard patterns are supposed to work
    """
    
    def __init__(self):
        self.patterns: List[RecognizedPattern] = []
        
    def analyze_contract(self, contract_code: str) -> List[RecognizedPattern]:
        """Analyze contract for known DeFi patterns."""
        self.patterns = []
        
        # Check for vesting patterns
        vesting = self._detect_vesting_pattern(contract_code)
        if vesting:
            self.patterns.append(vesting)
        
        # Check for ERC4626 share calculations
        erc4626 = self._detect_erc4626_pattern(contract_code)
        if erc4626:
            self.patterns.append(erc4626)
        
        # Check for time-lock patterns
        timelock = self._detect_timelock_pattern(contract_code)
        if timelock:
            self.patterns.append(timelock)
        
        # Check for staking rewards
        staking = self._detect_staking_pattern(contract_code)
        if staking:
            self.patterns.append(staking)
        
        return self.patterns
    
    def _detect_vesting_pattern(self, code: str) -> Optional[RecognizedPattern]:
        """Detect linear vesting/unlock patterns."""
        # Key indicators
        has_lock_duration = re.search(r'lockDuration|vestingDuration|unlockPeriod', code, re.IGNORECASE)
        has_last_update = re.search(r'lastNotify|lastUpdate|vestingStart|unlockStart', code, re.IGNORECASE)
        has_locked_amount = re.search(r'totalLocked|lockedAmount|vestingAmount', code, re.IGNORECASE)
        has_unlock_calc = re.search(r'lockedProfit|unlockedAmount|vestedAmount|availableAmount', code, re.IGNORECASE)
        
        # Need at least 3 indicators
        indicators = sum([bool(has_lock_duration), bool(has_last_update), bool(has_locked_amount), bool(has_unlock_calc)])
        if indicators < 3:
            return None
        
        # Look for the actual calculation pattern
        # Linear unlock: locked * remaining / duration
        calc_pattern = r'(\w+)\s*\*\s*(\w+)\s*/\s*(\w+)'
        calc_match = re.search(calc_pattern, code)
        
        confidence = 0.6 + (indicators * 0.1)
        
        key_vars = {}
        if has_lock_duration:
            key_vars['lock_duration'] = has_lock_duration.group(0)
        if has_last_update:
            key_vars['last_update'] = has_last_update.group(0)
        if has_locked_amount:
            key_vars['locked_amount'] = has_locked_amount.group(0)
        if has_unlock_calc:
            key_vars['unlock_calculation'] = has_unlock_calc.group(0)
        
        # Find related functions
        functions = []
        for func_pattern in [r'function\s+(notify|unlock|vest|release|claim)\s*\(', 
                              r'function\s+(\w*locked\w*|\w*vest\w*)\s*\(']:
            matches = re.finditer(func_pattern, code, re.IGNORECASE)
            functions.extend([m.group(1) for m in matches])
        
        implications = [
            "State overwrites of locked amount are EXPECTED after full vesting period",
            "Timing constraints prevent premature manipulation",
            "This is a standard pattern, not a vulnerability",
            "Check if vesting can only be triggered after lockDuration expires"
        ]
        
        return RecognizedPattern(
            pattern_type=PatternType.LINEAR_VESTING,
            confidence=confidence,
            description="Linear vesting/unlock mechanism with time-based constraints",
            key_variables=key_vars,
            key_functions=functions,
            implications=implications,
            example_protocols=["Synthetix", "Curve", "Yearn", "ERC4626 vaults"]
        )
    
    def _detect_erc4626_pattern(self, code: str) -> Optional[RecognizedPattern]:
        """Detect ERC4626 vault patterns."""
        # Check for ERC4626 inheritance or interface
        has_erc4626 = 'ERC4626' in code or 'IERC4626' in code
        
        # Check for key functions
        has_total_assets = re.search(r'function\s+totalAssets\s*\(', code)
        has_convert_shares = re.search(r'convertToShares|convertToAssets', code)
        has_deposit = re.search(r'function\s+deposit\s*\(', code)
        
        if not (has_erc4626 or (has_total_assets and has_convert_shares)):
            return None
        
        # Look for share price calculation
        share_calc = re.search(r'shares\s*=\s*.*assets.*totalSupply|assets\s*=\s*.*shares.*totalAssets', code)
        
        confidence = 0.7 if has_erc4626 else 0.5
        if share_calc:
            confidence += 0.2
        
        implications = [
            "Integer division in share calculations is STANDARD and expected",
            "Rounding in favor of the vault is intentional security measure",
            "totalAssets() must account for locked/unvested amounts",
            "Precision loss in share price is normal (< 1 wei typically)"
        ]
        
        return RecognizedPattern(
            pattern_type=PatternType.SHARE_CALCULATION,
            confidence=confidence,
            description="ERC4626 tokenized vault with share price calculations",
            key_variables={'totalAssets': 'total assets', 'totalSupply': 'share supply'},
            key_functions=['totalAssets', 'convertToShares', 'convertToAssets', 'deposit', 'withdraw'],
            implications=implications,
            example_protocols=["Yearn V3", "Balancer", "Beefy", "All ERC4626 vaults"]
        )
    
    def _detect_timelock_pattern(self, code: str) -> Optional[RecognizedPattern]:
        """Detect timelock/delay patterns."""
        # Check for time-based constraints
        has_delay = re.search(r'delay|timelock|cooldown', code, re.IGNORECASE)
        has_timestamp = 'block.timestamp' in code or 'block.number' in code
        has_pending = re.search(r'pending|queued|scheduled', code, re.IGNORECASE)
        
        if not (has_delay and has_timestamp):
            return None
        
        confidence = 0.6
        if has_pending:
            confidence += 0.2
        
        implications = [
            "Operations are time-delayed for security",
            "Immediate execution should be prevented",
            "Check that delay cannot be bypassed",
            "Governance timelock is standard security practice"
        ]
        
        return RecognizedPattern(
            pattern_type=PatternType.TIME_LOCK,
            confidence=confidence,
            description="Timelock/delay mechanism for sensitive operations",
            key_variables={'delay': 'time delay'},
            key_functions=[],
            implications=implications,
            example_protocols=["Compound Timelock", "Governor Alpha", "Gnosis Safe with delays"]
        )
    
    def _detect_staking_pattern(self, code: str) -> Optional[RecognizedPattern]:
        """Detect staking reward patterns."""
        # Check for staking indicators
        has_stake = re.search(r'function\s+(stake|deposit)\s*\(', code, re.IGNORECASE)
        has_unstake = re.search(r'function\s+(unstake|withdraw)\s*\(', code, re.IGNORECASE)
        has_rewards = re.search(r'reward|yield|earnings', code, re.IGNORECASE)
        has_rate = re.search(r'rewardRate|rewardPerToken|yieldPerSecond', code, re.IGNORECASE)
        
        indicators = sum([bool(has_stake), bool(has_unstake), bool(has_rewards), bool(has_rate)])
        if indicators < 2:
            return None
        
        confidence = 0.4 + (indicators * 0.15)
        
        implications = [
            "Reward calculations may use integer division (expected)",
            "Reward distribution over time requires careful accounting",
            "Precision loss in rewards is typical (dust amounts)",
            "Check for reward manipulation via flash deposits"
        ]
        
        return RecognizedPattern(
            pattern_type=PatternType.STAKING_REWARDS,
            confidence=confidence,
            description="Staking/reward distribution mechanism",
            key_variables={'rewardRate': 'reward rate'},
            key_functions=['stake', 'unstake', 'claimRewards', 'getReward'],
            implications=implications,
            example_protocols=["Synthetix Staking", "Aave Staking", "Compound Farming"]
        )
    
    def get_pattern_context(self, pattern_type: PatternType) -> str:
        """Get context explanation for a pattern type."""
        for pattern in self.patterns:
            if pattern.pattern_type == pattern_type:
                context = f"Pattern: {pattern.description}\n"
                context += f"Confidence: {pattern.confidence:.0%}\n"
                context += f"\nImplications:\n"
                for imp in pattern.implications:
                    context += f"  • {imp}\n"
                context += f"\nSimilar to: {', '.join(pattern.example_protocols[:3])}"
                return context
        return "Pattern not detected"
    
    def is_pattern_present(self, pattern_type: PatternType) -> bool:
        """Check if a specific pattern was detected."""
        return any(p.pattern_type == pattern_type for p in self.patterns)
    
    def should_reduce_severity(self, vuln_type: str) -> bool:
        """
        Determine if a vulnerability type should have reduced severity given detected patterns.
        
        Args:
            vuln_type: Type of vulnerability (e.g., 'integer_division', 'state_overwrite')
        
        Returns:
            True if severity should be reduced
        """
        # Integer division in ERC4626 or staking is expected
        if 'division' in vuln_type.lower() or 'precision' in vuln_type.lower():
            if self.is_pattern_present(PatternType.SHARE_CALCULATION):
                return True
            if self.is_pattern_present(PatternType.STAKING_REWARDS):
                return True
            if self.is_pattern_present(PatternType.LINEAR_VESTING):
                return True
        
        # State overwrites in vesting are expected
        if 'overwrite' in vuln_type.lower() or 'reassignment' in vuln_type.lower():
            if self.is_pattern_present(PatternType.LINEAR_VESTING):
                return True
        
        return False


def test_pattern_recognizer():
    """Test with Cap contracts example."""
    sample_code = '''
contract StakedCap is ERC4626Upgradeable {
    struct StakedCapStorage {
        uint256 lockDuration;
        uint256 lastNotify;
        uint256 totalLocked;
        uint256 storedTotal;
    }
    
    function notify() external {
        StakedCapStorage storage $ = getStakedCapStorage();
        if ($.lastNotify + $.lockDuration > block.timestamp) revert StillVesting();
        
        uint256 total = IERC20(asset()).balanceOf(address(this));
        if (total > $.storedTotal) {
            uint256 diff = total - $.storedTotal;
            $.totalLocked = diff;
            $.storedTotal = total;
            $.lastNotify = block.timestamp;
        }
    }
    
    function lockedProfit() public view returns (uint256 locked) {
        StakedCapStorage storage $ = getStakedCapStorage();
        uint256 elapsed = block.timestamp - $.lastNotify;
        uint256 remaining = elapsed < $.lockDuration ? $.lockDuration - elapsed : 0;
        locked = $.totalLocked * remaining / $.lockDuration;
    }
    
    function totalAssets() public view override returns (uint256 total) {
        total = getStakedCapStorage().storedTotal - lockedProfit();
    }
}
    '''
    
    recognizer = DeFiPatternRecognizer()
    patterns = recognizer.analyze_contract(sample_code)
    
    print("=== Detected DeFi Patterns ===\n")
    for pattern in patterns:
        print(f"Pattern: {pattern.pattern_type.value}")
        print(f"Confidence: {pattern.confidence:.0%}")
        print(f"Description: {pattern.description}")
        print(f"Key variables: {list(pattern.key_variables.keys())}")
        print(f"Implications:")
        for imp in pattern.implications:
            print(f"  • {imp}")
        print()
    
    print("=== Vulnerability Severity Adjustments ===\n")
    test_vulns = [
        "integer_division_precision_loss",
        "state_variable_overwrite",
        "reentrancy_vulnerability"
    ]
    
    for vuln in test_vulns:
        should_reduce = recognizer.should_reduce_severity(vuln)
        print(f"{vuln}: {'REDUCE SEVERITY ⬇️' if should_reduce else 'Keep original severity'}")


if __name__ == "__main__":
    test_pattern_recognizer()

