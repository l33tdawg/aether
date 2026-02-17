"""
Token Quirks Database and Detector.

Detects vulnerabilities arising from non-standard ERC-20 token behaviors.
Many DeFi protocols assume all tokens follow the standard ERC-20 spec exactly,
but real-world tokens have quirks (fee-on-transfer, rebasing, blocklists, etc.)
that can cause loss of funds when unhandled.

This module provides:
  - A database of 12 token quirk categories with detection/protection patterns
  - A check_token_quirks() function that scans Solidity source for unhandled quirks
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional


@dataclass
class TokenQuirk:
    """Describes a single non-standard ERC-20 token behavior category."""

    name: str                          # e.g. "fee_on_transfer"
    description: str                   # What the quirk is
    known_tokens: List[str]            # e.g. ["USDT", "STA", "PAXG"]
    detection_signals: List[str]       # regex patterns showing vulnerable token use
    protection_patterns: List[str]     # regex patterns showing the contract handles it
    missing_protection: str            # what is needed to be safe
    exploit_scenario: str              # what happens when unhandled
    severity: str                      # "high", "medium", "low"
    archetype_relevance: List[str]     # which archetypes care most


# ---------------------------------------------------------------------------
# Token quirks database — 12 categories
# ---------------------------------------------------------------------------

TOKEN_QUIRKS: List[TokenQuirk] = [
    # 1. Fee-on-transfer
    TokenQuirk(
        name="fee_on_transfer",
        description=(
            "Some tokens deduct a fee on every transfer so the amount received "
            "is less than the amount sent. Protocols that credit the sent amount "
            "instead of the actual received amount will have accounting mismatches."
        ),
        known_tokens=["USDT (with fee flag)", "STA", "PAXG", "SAFEMOON", "DEFIAT"],
        detection_signals=[
            # transferFrom used and the raw 'amount' is recorded without balance check
            r'transferFrom\s*\([^)]*\)\s*;[^}]*\b(balances|_balances|balance|deposits|userBalance)\s*\[[^\]]*\]\s*\+=\s*\b(amount|_amount|value)\b',
            # transferFrom followed by direct amount usage on next lines
            r'\.transferFrom\s*\([^)]*,\s*(?:address\s*\(\s*this\s*\)|[^,)]+)\s*,\s*(\w+)\s*\)[\s\S]{0,200}?\+\=\s*\1\b',
        ],
        protection_patterns=[
            # Balance-before / balance-after delta pattern
            r'balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)[\s\S]{0,300}?transferFrom[\s\S]{0,300}?balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)',
            r'balanceBefore[\s\S]{0,300}?transferFrom[\s\S]{0,300}?balanceOf',
            r'before\s*=[\s\S]{0,300}?transferFrom[\s\S]{0,300}?balanceOf',
            # Explicit received = balanceAfter - balanceBefore
            r'received\s*=\s*[\w.]+\s*-\s*\w*[Bb]efore',
        ],
        missing_protection=(
            "Use a balance-before/balance-after delta pattern: "
            "uint256 before = token.balanceOf(address(this)); "
            "token.transferFrom(...); "
            "uint256 received = token.balanceOf(address(this)) - before;"
        ),
        exploit_scenario=(
            "Attacker deposits a fee-on-transfer token. The protocol credits the full "
            "amount but only receives (amount - fee). The attacker can then withdraw "
            "the full credited amount, draining other users' funds over time."
        ),
        severity="high",
        archetype_relevance=["DEX_AMM", "LENDING_POOL", "VAULT_ERC4626", "YIELD_AGGREGATOR", "STAKING"],
    ),

    # 2. Rebasing tokens
    TokenQuirk(
        name="rebasing_tokens",
        description=(
            "Rebasing tokens (stETH, AMPL, OHM) change user balances automatically "
            "without transfers. Protocols that cache balanceOf() and reuse it later "
            "will have stale values."
        ),
        known_tokens=["stETH", "AMPL", "OHM", "AAVE aTokens", "Compound cTokens"],
        detection_signals=[
            # Storing balanceOf result in a state variable
            r'(\w+)\s*=\s*\w+\.balanceOf\s*\([^)]*\)\s*;[\s\S]{0,500}?\b\1\b',
            # Mapping that stores raw token amounts from deposit
            r'mapping\s*\([^)]*\)\s*(public|private|internal)?\s*\w*(balance|deposit|stake|amount)',
        ],
        protection_patterns=[
            # Uses wrapped version (wstETH)
            r'\bwstETH\b|\bwrapped\w*\b.*\b(stETH|AMPL)\b',
            r'\bwrap\s*\(|\bunwrap\s*\(',
            # Share-based accounting (converts to shares on deposit)
            r'(shares|_shares)\s*\[[^\]]*\]\s*\+=',
            # Re-reads balance right before use
            r'balanceOf\s*\([^)]*\)\s*;[\s\S]{0,50}?(require|assert|if)',
        ],
        missing_protection=(
            "Use wrapped non-rebasing versions of rebasing tokens (e.g. wstETH instead "
            "of stETH) or implement share-based internal accounting that converts to/from "
            "rebasing token amounts only at deposit/withdraw boundaries."
        ),
        exploit_scenario=(
            "Protocol stores stETH balanceOf() on deposit. A negative rebase reduces "
            "the actual balance, but the protocol's internal accounting still shows the "
            "old (higher) value. Users who withdraw first get the full amount while "
            "later withdrawers face a shortfall."
        ),
        severity="high",
        archetype_relevance=["VAULT_ERC4626", "STAKING", "LENDING_POOL", "YIELD_AGGREGATOR"],
    ),

    # 3. ERC-777 callbacks
    TokenQuirk(
        name="erc777_callbacks",
        description=(
            "ERC-777 tokens invoke tokensReceived/tokensToSend hooks on the recipient/"
            "sender, enabling reentrancy attacks even through seemingly safe transfer() "
            "or send() calls."
        ),
        known_tokens=["imBTC", "any ERC-777 compatible token"],
        detection_signals=[
            # transfer or send without reentrancy guard, followed by state update
            r'\.transfer\s*\([^)]*\)\s*;[\s\S]{0,200}?(balances|_balances|balance|totalSupply)\s*[\[\.]',
            r'\.send\s*\([^)]*\)\s*;[\s\S]{0,200}?(balances|_balances|balance|totalSupply)\s*[\[\.]',
            # State change after external token call
            r'\.(transfer|transferFrom|send)\s*\([^)]*\)\s*;[\s\S]{0,100}?\w+\s*(\-=|\+=)',
        ],
        protection_patterns=[
            r'\bnonReentrant\b',
            r'\bReentrancyGuard\b',
            r'_status\s*==\s*_NOT_ENTERED',
            # Checks-effects-interactions: state update BEFORE transfer
            r'(balances|_balances)\s*\[[^\]]*\]\s*(-=|\+=)[\s\S]{0,200}?\.(transfer|transferFrom|send)\s*\(',
        ],
        missing_protection=(
            "Apply a nonReentrant modifier (e.g. OpenZeppelin ReentrancyGuard) to all "
            "functions that perform token transfers, or strictly follow the checks-"
            "effects-interactions pattern with state updates before external calls."
        ),
        exploit_scenario=(
            "An ERC-777 token's tokensReceived hook re-enters the contract during a "
            "transfer, allowing the attacker to withdraw or claim rewards multiple "
            "times before state is updated. This was exploited in the imBTC/Uniswap V1 "
            "attack ($25M+)."
        ),
        severity="high",
        archetype_relevance=["DEX_AMM", "LENDING_POOL", "VAULT_ERC4626", "STAKING", "YIELD_AGGREGATOR"],
    ),

    # 4. Non-standard return values
    TokenQuirk(
        name="non_standard_return",
        description=(
            "Some tokens (notably old USDT on mainnet, BNB) do not return a bool from "
            "transfer/transferFrom/approve. Direct calls that check the return value "
            "will revert."
        ),
        known_tokens=["USDT (mainnet)", "BNB", "OMG", "HT"],
        detection_signals=[
            # Direct bool check on transfer return
            r'(require|assert)\s*\(\s*\w+\.(transfer|transferFrom|approve)\s*\(',
            r'bool\s+\w+\s*=\s*\w+\.(transfer|transferFrom|approve)\s*\(',
            r'if\s*\(\s*!\s*\w+\.(transfer|transferFrom|approve)\s*\(',
            # IERC20 interface call without SafeERC20
            r'IERC20\s*\([^)]*\)\.(transfer|transferFrom|approve)\s*\(',
        ],
        protection_patterns=[
            r'\bSafeERC20\b',
            r'\bsafeTransfer\b',
            r'\bsafeTransferFrom\b',
            r'\bsafeApprove\b',
            r'\bsafeIncreaseAllowance\b',
            # Low-level call pattern for transfer
            r'\.call\s*\(\s*abi\.encodeWithSelector\s*\(\s*\w+\.transfer\.selector',
        ],
        missing_protection=(
            "Use OpenZeppelin's SafeERC20 library (safeTransfer, safeTransferFrom, "
            "safeApprove) which handles both standard and non-standard return values."
        ),
        exploit_scenario=(
            "A protocol uses IERC20(token).transfer() and checks the bool return. "
            "When interacting with USDT (which returns void), the call reverts due to "
            "the ABI decoder expecting return data. This causes permanent DoS for USDT "
            "deposits/withdrawals."
        ),
        severity="medium",
        archetype_relevance=["DEX_AMM", "LENDING_POOL", "VAULT_ERC4626", "YIELD_AGGREGATOR", "BRIDGE"],
    ),

    # 5. Blocklist / freeze tokens
    TokenQuirk(
        name="blocklist_tokens",
        description=(
            "Tokens like USDC and USDT have admin-controlled blocklists that can freeze "
            "any address. If a protocol holds funds in a single address that gets "
            "blocklisted, or uses push-based transfer to a blocklisted recipient, "
            "critical operations will fail."
        ),
        known_tokens=["USDC", "USDT", "BUSD", "TUSD"],
        detection_signals=[
            # Push-based transfer to user in loop or critical path
            r'for\s*\([^)]*\)\s*\{[\s\S]{0,300}?\.(transfer|safeTransfer)\s*\(',
            # Direct transfer to user address without fallback
            r'\.(transfer|safeTransfer)\s*\(\s*(msg\.sender|\w+user\w*|\w+recipient\w*|to)\s*,',
        ],
        protection_patterns=[
            # Pull/claim pattern
            r'\bclaim\b[\s\S]{0,100}?\bpending\b',
            r'\bwithdraw\b[\s\S]{0,100}?\bowed\b',
            # Try-catch around transfers
            r'try\s+\w+\.(transfer|safeTransfer)',
            # Pull-based withdrawal mapping
            r'(pendingWithdraw|claimable|owed|withdrawable)\s*\[',
        ],
        missing_protection=(
            "Use a pull-based withdrawal pattern instead of pushing tokens to users. "
            "Allow users to claim their funds via a separate withdraw() call so that "
            "one blocklisted address cannot block the entire protocol."
        ),
        exploit_scenario=(
            "Protocol distributes rewards by iterating over users and calling "
            "token.transfer(). If one user's address is blocklisted by the token admin, "
            "the entire distribution loop reverts, blocking all other users' rewards."
        ),
        severity="medium",
        archetype_relevance=["LENDING_POOL", "STAKING", "VAULT_ERC4626", "YIELD_AGGREGATOR", "GOVERNANCE"],
    ),

    # 6. Approval race condition
    TokenQuirk(
        name="approval_race",
        description=(
            "The ERC-20 approve() function has a known race condition: if a user changes "
            "an allowance from N to M, the spender can front-run the transaction to "
            "spend N, then spend M as well (total N+M)."
        ),
        known_tokens=["Any standard ERC-20 (USDT enforces approve(0) first)"],
        detection_signals=[
            # Direct approve without zeroing first
            r'\.approve\s*\(\s*\w+\s*,\s*(?!0\s*\))\w+\s*\)',
        ],
        protection_patterns=[
            r'\bsafeIncreaseAllowance\b',
            r'\bsafeDecreaseAllowance\b',
            r'\.approve\s*\(\s*\w+\s*,\s*0\s*\)[\s\S]{0,100}?\.approve\s*\(',
            r'\bforceApprove\b',
            # SafeERC20 covers this
            r'\bSafeERC20\b',
        ],
        missing_protection=(
            "Use safeIncreaseAllowance/safeDecreaseAllowance from OpenZeppelin, or "
            "always set allowance to 0 before setting a new value. Some tokens like "
            "USDT require approve(0) before a non-zero approve."
        ),
        exploit_scenario=(
            "User has approve(spender, 100). They want to change to approve(spender, 50). "
            "The spender front-runs the new approve and calls transferFrom for 100, then "
            "after the new approve goes through, calls transferFrom for 50 more (150 total "
            "instead of 50)."
        ),
        severity="low",
        archetype_relevance=["DEX_AMM", "VAULT_ERC4626", "YIELD_AGGREGATOR"],
    ),

    # 7. Pausable tokens
    TokenQuirk(
        name="pausable_tokens",
        description=(
            "Tokens with pause functionality (USDC, USDT) can have all transfers halted "
            "by the admin. Protocols that depend on token transfers in critical paths "
            "(liquidation, withdrawal) will be bricked during a pause."
        ),
        known_tokens=["USDC", "USDT", "BUSD", "WBTC"],
        detection_signals=[
            # Liquidation or critical function that requires token transfer
            r'function\s+(liquidat\w*|withdraw\w*|emergencyWithdraw)\s*\([^)]*\)[\s\S]{0,500}?\.(transfer|safeTransfer|transferFrom)\s*\(',
        ],
        protection_patterns=[
            # Try-catch around critical transfers
            r'try\s+\w+\.(transfer|safeTransfer|transferFrom)',
            # Fallback mechanism
            r'(fallbackToken|alternativeWithdraw|emergencyExit)',
            # Graceful failure handling
            r'if\s*\(\s*!?\s*\w+\.(transfer|safeTransfer)',
        ],
        missing_protection=(
            "Implement graceful failure handling for token transfers in critical paths. "
            "Use try-catch around transfers or provide fallback mechanisms so that "
            "a paused token does not brick liquidation or emergency withdrawal functions."
        ),
        exploit_scenario=(
            "USDC gets paused by Circle during a regulatory event. All liquidations in "
            "a lending protocol fail because they require USDC transfers. Positions "
            "become undercollateralized and the protocol accumulates bad debt."
        ),
        severity="medium",
        archetype_relevance=["LENDING_POOL", "VAULT_ERC4626", "BRIDGE", "CDP_STABLECOIN"],
    ),

    # 8. Multiple entry points
    TokenQuirk(
        name="multiple_entry_points",
        description=(
            "Some proxy-pattern tokens (TUSD, older USDT) expose both the proxy address "
            "and the implementation address as callable entry points. Comparing token "
            "addresses without canonicalization can lead to the same token being treated "
            "as two different tokens."
        ),
        known_tokens=["TUSD", "USDT (proxy)", "other upgradeable tokens"],
        detection_signals=[
            # Direct address comparison for token identity
            r'(tokenA|token0|token)\s*==\s*(tokenB|token1|otherToken)',
            r'require\s*\(\s*\w+\s*!=\s*\w+\s*,\s*["\']same\s*token',
            # Token whitelist by address
            r'(supportedTokens|allowedTokens|tokenWhitelist)\s*\[\s*\w+\s*\]',
        ],
        protection_patterns=[
            # Canonical address resolution
            r'(getCanonical|resolveToken|tokenAddress|implementation\(\))',
            # Proxy-aware comparison
            r'_getImplementation\s*\(',
        ],
        missing_protection=(
            "Resolve token addresses to a canonical form before comparison. For proxy "
            "tokens, compare the underlying implementation address or maintain a mapping "
            "from proxy to canonical address."
        ),
        exploit_scenario=(
            "A DEX allows adding liquidity for token pairs. An attacker creates a pool "
            "with TUSD-proxy and TUSD-implementation as the two tokens. Since the "
            "protocol treats them as different tokens, the attacker can arbitrage "
            "between the two addresses of the same underlying token."
        ),
        severity="low",
        archetype_relevance=["DEX_AMM", "LENDING_POOL"],
    ),

    # 9. Upgradeable tokens
    TokenQuirk(
        name="upgradeable_tokens",
        description=(
            "Upgradeable tokens (USDC v2, many proxy tokens) can change their behavior "
            "after deployment. Hardcoded assumptions about decimals, transfer behavior, "
            "or fee structure may break after an upgrade."
        ),
        known_tokens=["USDC", "USDT", "TUSD", "any proxy-pattern token"],
        detection_signals=[
            # Hardcoded decimals for specific tokens
            r'(decimals|DECIMALS)\s*=\s*(6|8|18)\s*;',
            # Hardcoded assumptions about token behavior
            r'//.*assumes?\s*(no\s*fee|standard|18\s*decimals)',
        ],
        protection_patterns=[
            # Dynamic decimal reading
            r'\.decimals\s*\(\s*\)',
            # No hardcoded assumptions flagged
            r'IERC20Metadata',
        ],
        missing_protection=(
            "Avoid hardcoding token behavior assumptions. Read decimals dynamically "
            "via token.decimals(). Use SafeERC20 to handle return value changes. "
            "Consider that token behavior may change post-deployment."
        ),
        exploit_scenario=(
            "Protocol hardcodes USDC decimals as 6. After a USDC upgrade changes "
            "decimals (hypothetical) or adds a transfer fee, the protocol's math "
            "breaks silently, leading to incorrect accounting."
        ),
        severity="low",
        archetype_relevance=["DEX_AMM", "LENDING_POOL", "VAULT_ERC4626", "BRIDGE"],
    ),

    # 10. Low-decimal tokens
    TokenQuirk(
        name="low_decimal_tokens",
        description=(
            "Tokens with fewer than 18 decimals (USDC=6, WBTC=8) cause precision "
            "loss in math that assumes 18-decimal tokens. Hardcoded 1e18 multipliers "
            "or direct multiplication with 18-decimal tokens create huge rounding errors."
        ),
        known_tokens=["USDC (6)", "USDT (6)", "WBTC (8)", "GUSD (2)"],
        detection_signals=[
            # Hardcoded 1e18 in token math (check both before and after the literal)
            r'(token|Token|amount|balance|transfer|IERC20|totalAssets|reserves)[\s\S]{0,100}?(\*\s*1e18|\*\s*10\s*\*\*\s*18|\/\s*1e18|\/\s*10\s*\*\*\s*18)',
            r'(\*\s*1e18|\*\s*10\s*\*\*\s*18|\/\s*1e18|\/\s*10\s*\*\*\s*18)[\s\S]{0,100}?(token|Token|amount|balance|transfer|IERC20|totalAssets|reserves)',
            # Mixing token amounts without decimal normalization
            r'(tokenA|token0)\w*\s*[\*/]\s*(tokenB|token1)',
        ],
        protection_patterns=[
            # Dynamic decimal handling
            r'\.decimals\s*\(\s*\)[\s\S]{0,200}?10\s*\*\*',
            r'10\s*\*\*\s*\w*[Dd]ecimals',
            # Decimal normalization
            r'(normalize|scaleAmount|adjustDecimals|decimalFactor)',
        ],
        missing_protection=(
            "Always read token.decimals() dynamically and scale amounts accordingly. "
            "Use 10**decimals instead of hardcoded 1e18. When mixing tokens with "
            "different decimals, normalize to a common precision first."
        ),
        exploit_scenario=(
            "A vault uses amount * 1e18 / totalSupply for share calculation. With USDC "
            "(6 decimals), a deposit of 1 USDC (1e6) gets multiplied by 1e18, creating "
            "enormous intermediate values. Division by totalSupply (also in 6-decimal "
            "scale) gives wrong results, allowing the attacker to extract more than "
            "deposited."
        ),
        severity="medium",
        archetype_relevance=["VAULT_ERC4626", "DEX_AMM", "LENDING_POOL", "CDP_STABLECOIN"],
    ),

    # 11. Transfer hooks (ERC-1363 / ERC-677)
    TokenQuirk(
        name="transfer_hooks",
        description=(
            "ERC-1363 (transferAndCall) and ERC-677 tokens invoke a callback on the "
            "recipient after transfer, similar to ERC-777 but through different "
            "interfaces. This enables reentrancy through token transfers."
        ),
        known_tokens=["LINK (ERC-677)", "ERC-1363 tokens"],
        detection_signals=[
            # Token transfer without reentrancy guard — state update after transfer
            # Handles both simple vars (x -= ...) and mappings (rewards[addr] -= ...)
            r'\.transfer\s*\([^)]*\)\s*;[\s\S]{0,200}?(\w+(\[[^\]]*\])?\s*(\-=|\+=))',
            r'\.transferFrom\s*\([^)]*\)\s*;[\s\S]{0,200}?(\w+(\[[^\]]*\])?\s*(\-=|\+=))',
        ],
        protection_patterns=[
            r'\bnonReentrant\b',
            r'\bReentrancyGuard\b',
            # CEI pattern: state update before transfer
            r'(\w+(\[[^\]]*\])?\s*(\-=|\+=))[\s\S]{0,200}?\.(transfer|transferFrom)\s*\(',
        ],
        missing_protection=(
            "Apply nonReentrant modifiers or follow checks-effects-interactions pattern. "
            "Be aware that some tokens call back into the recipient on transfer, even "
            "without explicit ERC-777 support."
        ),
        exploit_scenario=(
            "A staking contract calls token.transfer(user, amount) to send rewards, "
            "then updates the reward balance. The token (ERC-677/1363) calls "
            "onTokenTransfer on the recipient, who re-enters claimRewards() before "
            "the reward balance is zeroed, draining all rewards."
        ),
        severity="medium",
        archetype_relevance=["DEX_AMM", "STAKING", "LENDING_POOL", "VAULT_ERC4626"],
    ),

    # 12. Flash-mintable tokens
    TokenQuirk(
        name="flash_mintable_tokens",
        description=(
            "Tokens with built-in flash minting (DAI, any ERC-3156 token) can have "
            "their totalSupply temporarily increased to enormous values within a "
            "single transaction. Governance or pricing based on totalSupply or token "
            "balance can be manipulated."
        ),
        known_tokens=["DAI", "any ERC-3156 flash-mintable token"],
        detection_signals=[
            # totalSupply used for pricing or governance weight
            r'totalSupply\s*\(\s*\)[\s\S]{0,200}?(price|value|weight|voting|quorum|ratio)',
            # Balance-based voting or governance
            r'balanceOf\s*\([^)]*\)[\s\S]{0,100}?(vote|voting|proposal|quorum|weight)',
            # Supply in pricing formula
            r'(price|rate|value)\s*=[\s\S]{0,100}?totalSupply',
        ],
        protection_patterns=[
            # TWAP or time-weighted
            r'\b(TWAP|twap|timeWeighted|cumulativePrice)\b',
            # Snapshot-based governance
            r'\bsnapshot\b|\bgetPastVotes\b|\bgetPriorVotes\b|\bERC20Votes\b',
            # Non-supply-based pricing
            r'\b(oraclePrice|chainlink|latestRoundData)\b',
        ],
        missing_protection=(
            "Do not use totalSupply() or current balanceOf() for pricing or governance. "
            "Use TWAP for pricing and snapshot-based voting power (ERC20Votes with "
            "getPastVotes) for governance to prevent flash-mint manipulation."
        ),
        exploit_scenario=(
            "Protocol uses totalSupply()-based pricing for a flash-mintable token. "
            "Attacker flash-mints billions of tokens, inflating totalSupply. The price "
            "calculation (e.g., reserves / totalSupply) drops to near zero. Attacker "
            "buys at the deflated price, repays the flash mint, and sells at the "
            "real price for profit."
        ),
        severity="high",
        archetype_relevance=["GOVERNANCE", "ORACLE", "DEX_AMM", "LENDING_POOL"],
    ),
]


# ---------------------------------------------------------------------------
# Quick lookup helpers
# ---------------------------------------------------------------------------

_QUIRK_BY_NAME: Dict[str, TokenQuirk] = {q.name: q for q in TOKEN_QUIRKS}


def get_quirk(name: str) -> Optional[TokenQuirk]:
    """Retrieve a single TokenQuirk by its name."""
    return _QUIRK_BY_NAME.get(name)


def get_quirks_for_archetype(archetype: str) -> List[TokenQuirk]:
    """Return all quirks relevant to a given protocol archetype string."""
    return [q for q in TOKEN_QUIRKS if archetype in q.archetype_relevance]


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

def _has_token_interaction(content: str) -> bool:
    """Check if a contract interacts with ERC-20 tokens at all."""
    token_patterns = [
        r'\btransfer\s*\(',
        r'\btransferFrom\s*\(',
        r'\bapprove\s*\(',
        r'\bbalanceOf\s*\(',
        r'\bIERC20\b',
        r'\bERC20\b',
        r'\bsafeTransfer\b',
        r'\bsafeTransferFrom\b',
        r'\ballowance\s*\(',
    ]
    for p in token_patterns:
        if re.search(p, content):
            return True
    return False


def _find_line_number(content: str, match_obj: 're.Match') -> int:
    """Return the 1-based line number for a regex match."""
    return content[:match_obj.start()].count('\n') + 1


def _extract_code_snippet(content: str, line_number: int, context: int = 2) -> str:
    """Extract a code snippet around the given line number."""
    lines = content.split('\n')
    start = max(0, line_number - 1 - context)
    end = min(len(lines), line_number + context)
    return '\n'.join(lines[start:end])


def check_token_quirks(contract_content: str) -> List[Dict[str, Any]]:
    """
    Scan a Solidity contract for unhandled ERC-20 token quirks.

    Returns a list of finding dicts in the standard vulnerability format:
        {
            'vulnerability_type': str,
            'severity': str,
            'confidence': float,
            'line_number': int,
            'description': str,
            'code_snippet': str,
            'mitigation': str,
        }

    An empty list is returned when:
      - The contract does not interact with ERC-20 tokens at all
      - All detected quirk patterns have corresponding protections
    """
    if not _has_token_interaction(contract_content):
        return []

    findings: List[Dict[str, Any]] = []

    for quirk in TOKEN_QUIRKS:
        # Check if any detection signals fire
        vulnerable_matches: List['re.Match'] = []
        for signal in quirk.detection_signals:
            for m in re.finditer(signal, contract_content, re.DOTALL):
                vulnerable_matches.append(m)

        if not vulnerable_matches:
            continue

        # Check if any protection pattern is present
        is_protected = False
        for protection in quirk.protection_patterns:
            if re.search(protection, contract_content, re.DOTALL):
                is_protected = True
                break

        if is_protected:
            continue

        # Vulnerable and not protected — emit a finding for the first match
        match = vulnerable_matches[0]
        line_number = _find_line_number(contract_content, match)
        snippet = _extract_code_snippet(contract_content, line_number)

        # Severity-to-confidence mapping
        confidence_map = {"high": 0.8, "medium": 0.7, "low": 0.6}
        confidence = confidence_map.get(quirk.severity, 0.6)

        findings.append({
            'vulnerability_type': f"token_quirk_{quirk.name}",
            'severity': quirk.severity,
            'confidence': confidence,
            'line_number': line_number,
            'description': (
                f"Unhandled token quirk: {quirk.name}. {quirk.description} "
                f"Known affected tokens: {', '.join(quirk.known_tokens)}. "
                f"Exploit scenario: {quirk.exploit_scenario}"
            ),
            'code_snippet': snippet,
            'mitigation': quirk.missing_protection,
        })

    return findings
