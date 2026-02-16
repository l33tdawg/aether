"""
Protocol Archetype Detection and Vulnerability Checklists.

Detects what kind of protocol a contract implements (DEX, lending, vault, etc.)
and provides archetype-specific vulnerability checklists that guide the deep
analysis engine's invariant checking.
"""

import re
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


class ProtocolArchetype(Enum):
    """Protocol categories for archetype-specific analysis."""
    DEX_AMM = "dex_amm"
    DEX_ORDERBOOK = "dex_orderbook"
    LENDING_POOL = "lending_pool"
    VAULT_ERC4626 = "vault_erc4626"
    BRIDGE = "bridge"
    STAKING = "staking"
    GOVERNANCE = "governance"
    NFT_MARKETPLACE = "nft_marketplace"
    TOKEN = "token"
    ORACLE = "oracle"
    LIQUID_STAKING = "liquid_staking"
    PERPETUAL_DEX = "perpetual_dex"
    CDP_STABLECOIN = "cdp_stablecoin"
    YIELD_AGGREGATOR = "yield_aggregator"
    UNKNOWN = "unknown"


@dataclass
class ChecklistItem:
    """A single vulnerability checklist item for an archetype."""
    name: str
    severity: str
    description: str
    code_indicators: List[str]
    missing_protections: List[str]
    exploit_precedent: str
    detection_prompt: str


@dataclass
class ArchetypeResult:
    """Result of archetype detection."""
    primary: ProtocolArchetype
    secondary: List[ProtocolArchetype] = field(default_factory=list)
    confidence: float = 0.0
    signals: Dict[str, List[str]] = field(default_factory=dict)


@dataclass
class SignalPattern:
    """A detection signal for an archetype."""
    pattern: str
    weight: float  # 1.0 = strong signal, 0.5 = medium signal


# ---------------------------------------------------------------------------
# Archetype detection signals
# ---------------------------------------------------------------------------

_ARCHETYPE_SIGNALS: Dict[ProtocolArchetype, List[SignalPattern]] = {
    ProtocolArchetype.VAULT_ERC4626: [
        # Strong signals
        SignalPattern(r'\bERC4626\b', 1.0),
        SignalPattern(r'\btotalAssets\s*\(', 1.0),
        SignalPattern(r'\bconvertToShares\s*\(', 1.0),
        SignalPattern(r'\bconvertToAssets\s*\(', 1.0),
        SignalPattern(r'\b_decimalsOffset\s*\(', 1.0),
        # Medium signals
        SignalPattern(r'\bdeposit\s*\(\s*uint256', 0.5),
        SignalPattern(r'\bredeem\s*\(\s*uint256', 0.5),
        SignalPattern(r'\bmint\s*\(\s*uint256[^)]*,\s*address', 0.5),
        SignalPattern(r'\bwithdraw\s*\(\s*uint256[^)]*,\s*address', 0.5),
        SignalPattern(r'\bpreviewDeposit\s*\(', 0.7),
        SignalPattern(r'\bpreviewRedeem\s*\(', 0.7),
        SignalPattern(r'\bmaxDeposit\s*\(', 0.5),
    ],
    ProtocolArchetype.LENDING_POOL: [
        SignalPattern(r'\bborrow\s*\(', 1.0),
        SignalPattern(r'\brepay\s*\(', 1.0),
        SignalPattern(r'\bliquidat', 1.0),
        SignalPattern(r'\bcollateral', 0.8),
        SignalPattern(r'\bhealthFactor', 0.8),
        SignalPattern(r'\binterestRate', 0.7),
        SignalPattern(r'\bgetUserAccountData', 0.9),
        SignalPattern(r'\bdebtToken', 0.8),
        SignalPattern(r'\baToken', 0.7),
        SignalPattern(r'\bborrowRate', 0.7),
        SignalPattern(r'\bsupplyRate', 0.7),
        SignalPattern(r'\bLTV\b', 0.6),
    ],
    ProtocolArchetype.DEX_AMM: [
        SignalPattern(r'\bswap\s*\(', 1.0),
        SignalPattern(r'\baddLiquidity\s*\(', 1.0),
        SignalPattern(r'\bremoveLiquidity\s*\(', 1.0),
        SignalPattern(r'\bgetReserves\s*\(', 1.0),
        SignalPattern(r'\bgetAmountOut\s*\(', 0.9),
        SignalPattern(r'\bgetAmountsOut\s*\(', 0.9),
        SignalPattern(r'\btoken0\b', 0.5),
        SignalPattern(r'\btoken1\b', 0.5),
        SignalPattern(r'\bk\s*=\s*', 0.5),
        SignalPattern(r'\breserve0\b', 0.7),
        SignalPattern(r'\breserve1\b', 0.7),
        SignalPattern(r'\bMINIMUM_LIQUIDITY\b', 0.8),
        SignalPattern(r'\bsqrt\s*\(', 0.4),
    ],
    ProtocolArchetype.DEX_ORDERBOOK: [
        SignalPattern(r'\bplaceOrder\s*\(', 1.0),
        SignalPattern(r'\bcancelOrder\s*\(', 1.0),
        SignalPattern(r'\bfillOrder\s*\(', 1.0),
        SignalPattern(r'\bmatchOrders?\s*\(', 1.0),
        SignalPattern(r'\borderbook\b', 0.8),
        SignalPattern(r'\bbid\b', 0.4),
        SignalPattern(r'\bask\b', 0.4),
        SignalPattern(r'\blimitOrder\b', 0.8),
    ],
    ProtocolArchetype.BRIDGE: [
        SignalPattern(r'\brelayMessage\s*\(', 1.0),
        SignalPattern(r'\bproveWithdrawal\s*\(', 1.0),
        SignalPattern(r'\bfinalizeWithdrawal\s*\(', 1.0),
        SignalPattern(r'\bcrossChain', 1.0),
        SignalPattern(r'\bsendMessage\s*\(', 0.7),
        SignalPattern(r'\bchainId\b', 0.4),
        SignalPattern(r'\bdestinationChain', 0.8),
        SignalPattern(r'\bsourceChain', 0.8),
        SignalPattern(r'\bmessageNonce', 0.7),
        SignalPattern(r'\brelayer\b', 0.6),
        SignalPattern(r'\bverifyProof\s*\(', 0.7),
    ],
    ProtocolArchetype.STAKING: [
        SignalPattern(r'\bstake\s*\(', 1.0),
        SignalPattern(r'\bunstake\s*\(', 1.0),
        SignalPattern(r'\bclaimRewards?\s*\(', 0.9),
        SignalPattern(r'\brewardPerToken\s*\(', 0.9),
        SignalPattern(r'\brewardRate\b', 0.8),
        SignalPattern(r'\btotalStaked\b', 0.7),
        SignalPattern(r'\bstakingToken\b', 0.7),
        SignalPattern(r'\bdelegat', 0.5),
        SignalPattern(r'\bepoch\b', 0.4),
        SignalPattern(r'\bcooldown', 0.6),
    ],
    ProtocolArchetype.GOVERNANCE: [
        SignalPattern(r'\bpropose\s*\(', 1.0),
        SignalPattern(r'\bcastVote\s*\(', 1.0),
        SignalPattern(r'\bexecute\s*\(.*proposal', 0.9),
        SignalPattern(r'\bqueue\s*\(.*proposal', 0.8),
        SignalPattern(r'\bquorum\b', 0.8),
        SignalPattern(r'\btimelock\b', 0.7),
        SignalPattern(r'\bvotingPower\b', 0.7),
        SignalPattern(r'\bGovernor\b', 0.9),
        SignalPattern(r'\bTimelockController\b', 0.8),
        SignalPattern(r'\bproposalThreshold\b', 0.7),
    ],
    ProtocolArchetype.NFT_MARKETPLACE: [
        SignalPattern(r'\blistItem\s*\(', 1.0),
        SignalPattern(r'\bbuyItem\s*\(', 1.0),
        SignalPattern(r'\bcancelListing\s*\(', 0.9),
        SignalPattern(r'\bmakeOffer\s*\(', 0.8),
        SignalPattern(r'\bacceptOffer\s*\(', 0.8),
        SignalPattern(r'\broyalt', 0.6),
        SignalPattern(r'\bERC721\b', 0.5),
        SignalPattern(r'\bERC1155\b', 0.5),
        SignalPattern(r'\bauction\b', 0.6),
    ],
    ProtocolArchetype.TOKEN: [
        SignalPattern(r'\bERC20\b', 0.7),
        SignalPattern(r'\b_mint\s*\(', 0.5),
        SignalPattern(r'\b_burn\s*\(', 0.5),
        SignalPattern(r'\btotalSupply\s*\(', 0.3),
        SignalPattern(r'\bbalanceOf\s*\(', 0.3),
        SignalPattern(r'\btransfer\s*\(', 0.3),
        SignalPattern(r'\bapprove\s*\(', 0.3),
        SignalPattern(r'\btaxRate\b|fee\s*=', 0.5),
    ],
    ProtocolArchetype.ORACLE: [
        SignalPattern(r'\blatestRoundData\s*\(', 1.0),
        SignalPattern(r'\bgetPrice\s*\(', 0.8),
        SignalPattern(r'\bAggregatorV3Interface\b', 1.0),
        SignalPattern(r'\bpriceFeed\b', 0.8),
        SignalPattern(r'\bTWAP\b', 0.9),
        SignalPattern(r'\bobserve\s*\(', 0.6),
        SignalPattern(r'\bupdatePrice\s*\(', 0.7),
        SignalPattern(r'\bstalePrice\b', 0.7),
    ],
    ProtocolArchetype.LIQUID_STAKING: [
        SignalPattern(r'\bstETH\b', 1.0),
        SignalPattern(r'\brETH\b', 1.0),
        SignalPattern(r'\bcbETH\b', 1.0),
        SignalPattern(r'\bstake\s*\(', 0.7),
        SignalPattern(r'\bunstake\s*\(', 0.8),
        SignalPattern(r'\bwithdrawalQueue\b', 0.9),
        SignalPattern(r'\bvalidatorExit\b', 0.9),
        SignalPattern(r'\bexchangeRate\b', 0.7),
        SignalPattern(r'\bbeacon\b', 0.5),
    ],
    ProtocolArchetype.PERPETUAL_DEX: [
        SignalPattern(r'\bopenPosition\s*\(', 1.0),
        SignalPattern(r'\bclosePosition\s*\(', 1.0),
        SignalPattern(r'\bfundingRate\b', 1.0),
        SignalPattern(r'\bleverage\b', 0.8),
        SignalPattern(r'\bliquidate\s*\(', 0.7),
        SignalPattern(r'\bmarginCall\b', 0.9),
        SignalPattern(r'\bperpetual\b', 0.8),
        SignalPattern(r'\blongPosition\b', 0.7),
        SignalPattern(r'\bshortPosition\b', 0.7),
    ],
    ProtocolArchetype.CDP_STABLECOIN: [
        SignalPattern(r'\bcollateralRatio\b', 1.0),
        SignalPattern(r'\bliquidationRatio\b', 1.0),
        SignalPattern(r'\bmintDebt\s*\(', 1.0),
        SignalPattern(r'\brepayDebt\s*\(', 1.0),
        SignalPattern(r'\bvault\b', 0.4),
        SignalPattern(r'\bcdp\b', 0.9),
        SignalPattern(r'\bcollateralize\s*\(', 0.8),
        SignalPattern(r'\bstabilityPool\b', 0.9),
    ],
    ProtocolArchetype.YIELD_AGGREGATOR: [
        SignalPattern(r'\bstrategy\b', 0.7),
        SignalPattern(r'\bharvest\s*\(', 1.0),
        SignalPattern(r'\bdeposit\s*\(', 0.4),
        SignalPattern(r'\bwithdraw\s*\(', 0.4),
        SignalPattern(r'\bvault\b', 0.4),
        SignalPattern(r'\byield\b', 0.5),
        SignalPattern(r'\bcompound\s*\(', 0.8),
        SignalPattern(r'\brebalance\s*\(', 0.9),
        SignalPattern(r'\bemergencyWithdraw\s*\(', 0.8),
    ],
}


# ---------------------------------------------------------------------------
# Archetype-specific vulnerability checklists
# ---------------------------------------------------------------------------

_ARCHETYPE_CHECKLISTS: Dict[ProtocolArchetype, List[ChecklistItem]] = {
    ProtocolArchetype.VAULT_ERC4626: [
        ChecklistItem(
            name="First Depositor / Share Inflation Attack",
            severity="critical",
            description="Empty vault allows attacker to inflate share price via donation, causing subsequent depositors to receive 0 shares.",
            code_indicators=["ERC4626", "totalAssets()", "deposit(", "totalSupply == 0"],
            missing_protections=["_decimalsOffset()", "virtual shares/assets", "minimum initial deposit"],
            exploit_precedent="Multiple ERC-4626 vaults (2022-2023)",
            detection_prompt="Check if this vault has protection against the first depositor attack: virtual shares/assets via _decimalsOffset(), dead shares, or minimum deposit enforcement.",
        ),
        ChecklistItem(
            name="Rounding Direction Consistency",
            severity="high",
            description="Deposits should round DOWN (fewer shares for depositor), withdrawals should round UP (more shares burned). Inconsistency allows value extraction.",
            code_indicators=["mulDiv", "Math.Rounding", "convertToShares", "convertToAssets"],
            missing_protections=["Consistent rounding against user", "mulDivUp for withdrawals"],
            exploit_precedent="Multiple vault implementations",
            detection_prompt="Verify rounding direction: deposits round DOWN (user gets fewer shares), withdrawals round UP (user burns more shares). Check every division/mulDiv for direction.",
        ),
        ChecklistItem(
            name="Share Price Manipulation via Direct Donation",
            severity="high",
            description="Direct token transfer to vault inflates totalAssets without minting shares, manipulating share price for all holders.",
            code_indicators=["totalAssets()", "balanceOf(address(this))", "IERC20"],
            missing_protections=["Internal accounting separate from balanceOf", "virtual balance tracking"],
            exploit_precedent="Multiple vaults using balanceOf for totalAssets",
            detection_prompt="Does totalAssets() rely on balanceOf(address(this))? If so, direct token transfers can manipulate the share price.",
        ),
        ChecklistItem(
            name="Flash Deposit+Withdraw Value Extraction",
            severity="medium",
            description="Flash loan deposit and immediate withdrawal can exploit rounding or fee calculation gaps.",
            code_indicators=["deposit(", "withdraw(", "redeem("],
            missing_protections=["Deposit/withdraw cooldown", "same-block restriction"],
            exploit_precedent="DeFi vault exploits",
            detection_prompt="Can a user deposit and withdraw in the same transaction? If so, check for rounding profit or fee bypass.",
        ),
        ChecklistItem(
            name="totalAssets Includes Unexpected Sources",
            severity="medium",
            description="totalAssets() counting rewards, fees, or donations can be manipulated to affect share calculations.",
            code_indicators=["totalAssets()", "balanceOf", "pendingRewards"],
            missing_protections=["Separation of principal from rewards in totalAssets"],
            exploit_precedent="Yield vault exploits",
            detection_prompt="What does totalAssets() include? Does it count pending rewards, donated tokens, or accrued fees that could be manipulated?",
        ),
    ],
    ProtocolArchetype.LENDING_POOL: [
        ChecklistItem(
            name="Oracle Price Manipulation",
            severity="critical",
            description="Spot price oracle allows flash loan manipulation of collateral value, enabling undercollateralized borrows or avoiding liquidation.",
            code_indicators=["getPrice(", "latestRoundData(", "getReserves("],
            missing_protections=["TWAP oracle", "Chainlink heartbeat check", "price deviation bounds"],
            exploit_precedent="Cream Finance ($130M), Mango Markets ($114M)",
            detection_prompt="How is collateral valued? Is the price source manipulable in a single transaction? Check for TWAP usage, staleness checks, and deviation bounds.",
        ),
        ChecklistItem(
            name="Liquidation Threshold Manipulation",
            severity="critical",
            description="Attacker manipulates their health factor to avoid liquidation or to liquidate others unfairly.",
            code_indicators=["healthFactor", "liquidat", "collateral", "LTV"],
            missing_protections=["Atomic liquidation checks", "price update before liquidation"],
            exploit_precedent="Multiple lending protocol exploits",
            detection_prompt="Can an attacker manipulate their health factor in the same transaction as borrowing? Is price updated atomically before liquidation checks?",
        ),
        ChecklistItem(
            name="Bad Debt Cascade",
            severity="high",
            description="Underwater position creates bad debt that socializes losses across lenders when collateral < debt.",
            code_indicators=["borrow(", "repay(", "liquidat", "collateralFactor"],
            missing_protections=["Bad debt socialization mechanism", "reserve fund", "insurance"],
            exploit_precedent="Euler Finance ($197M)",
            detection_prompt="What happens when a position becomes underwater (collateral < debt)? Is there a bad debt handling mechanism?",
        ),
        ChecklistItem(
            name="Interest Rate Manipulation",
            severity="high",
            description="Flash loan can temporarily change utilization rate, manipulating interest rates for existing borrowers.",
            code_indicators=["interestRate", "utilization", "borrowRate", "supplyRate"],
            missing_protections=["Rate smoothing", "utilization rate caps", "flash loan detection"],
            exploit_precedent="Various lending protocols",
            detection_prompt="Can a flash loan temporarily spike utilization to manipulate interest rates? Is the rate calculated based on current utilization?",
        ),
        ChecklistItem(
            name="Reentrancy in Borrow/Repay",
            severity="high",
            description="Token transfer in borrow/repay allows reentrancy before state update.",
            code_indicators=["borrow(", "repay(", "transfer(", "safeTransfer("],
            missing_protections=["nonReentrant modifier", "checks-effects-interactions"],
            exploit_precedent="Multiple lending protocols",
            detection_prompt="Does borrow() transfer tokens before updating debt state? Does repay() update state before transferring tokens?",
        ),
    ],
    ProtocolArchetype.DEX_AMM: [
        ChecklistItem(
            name="First LP Manipulation / Minimum Liquidity",
            severity="critical",
            description="First liquidity provider can manipulate initial price and extract value from subsequent LPs.",
            code_indicators=["totalSupply == 0", "mint(", "MINIMUM_LIQUIDITY"],
            missing_protections=["MINIMUM_LIQUIDITY burn", "dead shares", "minimum LP lock"],
            exploit_precedent="Uniswap V2 mitigation pattern",
            detection_prompt="Does the pool burn MINIMUM_LIQUIDITY on first mint? Without this, first LP can manipulate share price.",
        ),
        ChecklistItem(
            name="Sandwich Attack Vulnerability",
            severity="high",
            description="No slippage protection allows MEV bots to sandwich trades for profit.",
            code_indicators=["swap(", "getAmountOut(", "amountOutMin"],
            missing_protections=["Minimum output amount parameter", "deadline parameter", "private mempool"],
            exploit_precedent="Extremely common MEV attack",
            detection_prompt="Does swap() enforce a minimum output amount? Is there a transaction deadline? Without both, trades are vulnerable to sandwich attacks.",
        ),
        ChecklistItem(
            name="Price Oracle Manipulation via Reserves",
            severity="critical",
            description="Using spot reserves as price oracle allows flash loan manipulation.",
            code_indicators=["getReserves(", "price0CumulativeLast", "reserve0", "reserve1"],
            missing_protections=["TWAP oracle", "external oracle", "multi-block average"],
            exploit_precedent="Multiple DEX oracle exploits",
            detection_prompt="Are spot reserves used as a price oracle by other contracts? Spot prices can be manipulated via flash loans.",
        ),
        ChecklistItem(
            name="Skim/Sync Manipulation",
            severity="medium",
            description="Direct token donation followed by sync() can manipulate reserves.",
            code_indicators=["sync()", "skim(", "balanceOf(address(this))"],
            missing_protections=["Internal balance tracking separate from actual balance"],
            exploit_precedent="Various DEX implementations",
            detection_prompt="Can direct token transfers affect reserve calculations? Does sync() create arbitrage opportunities?",
        ),
    ],
    ProtocolArchetype.BRIDGE: [
        ChecklistItem(
            name="Cross-Chain Message Replay",
            severity="critical",
            description="Messages from source chain can be replayed on destination or re-executed after processing.",
            code_indicators=["relayMessage(", "executeMessage(", "messageNonce"],
            missing_protections=["Nonce tracking", "message hash uniqueness", "executed message mapping"],
            exploit_precedent="Nomad Bridge ($190M)",
            detection_prompt="Is each cross-chain message uniquely identified and marked as executed? Can a message be replayed or re-executed?",
        ),
        ChecklistItem(
            name="Validator/Relayer Compromise",
            severity="critical",
            description="Insufficient validator threshold allows compromised validators to forge messages.",
            code_indicators=["verifySignatures(", "threshold", "validator", "relayer"],
            missing_protections=["Sufficient threshold (e.g., 2/3)", "validator rotation", "fraud proofs"],
            exploit_precedent="Ronin Bridge ($625M)",
            detection_prompt="What is the validator threshold for message approval? Can a minority of validators forge cross-chain messages?",
        ),
        ChecklistItem(
            name="Token Mapping Mismatch",
            severity="high",
            description="Incorrect token mapping between chains allows minting unbacked tokens.",
            code_indicators=["tokenMapping", "wrappedToken", "originalToken"],
            missing_protections=["Verified token mapping", "supply consistency checks"],
            exploit_precedent="Wormhole Bridge ($320M)",
            detection_prompt="Is the token mapping between chains verified? Can an attacker claim to bridge a token that doesn't exist on the source chain?",
        ),
        ChecklistItem(
            name="Withdrawal Proof Forgery",
            severity="critical",
            description="Insufficient proof verification allows forged withdrawal proofs.",
            code_indicators=["proveWithdrawal(", "verifyProof(", "merkleRoot"],
            missing_protections=["Full merkle proof verification", "state root validation", "finality checks"],
            exploit_precedent="Various bridge exploits",
            detection_prompt="How are withdrawal proofs verified? Can an attacker forge a proof to withdraw tokens that were never deposited?",
        ),
    ],
    ProtocolArchetype.STAKING: [
        ChecklistItem(
            name="Reward Calculation Manipulation",
            severity="high",
            description="Flash staking to claim disproportionate rewards by staking just before reward distribution.",
            code_indicators=["rewardPerToken(", "earned(", "rewardRate", "stake("],
            missing_protections=["Minimum staking duration", "reward vesting", "snapshot-based rewards"],
            exploit_precedent="Various staking protocols",
            detection_prompt="Can a user stake just before reward distribution and immediately unstake to claim rewards? Is there a minimum staking duration?",
        ),
        ChecklistItem(
            name="Reward Rate Overflow/Precision Loss",
            severity="high",
            description="rewardPerToken calculation can overflow or lose precision with extreme values.",
            code_indicators=["rewardPerToken", "rewardPerTokenStored", "totalStaked", "lastUpdateTime"],
            missing_protections=["Safe math with sufficient precision", "reward rate caps"],
            exploit_precedent="Synthetix staking reward bugs",
            detection_prompt="Does rewardPerToken use sufficient precision? Can extreme reward rates or tiny totalStaked cause overflow or precision loss?",
        ),
        ChecklistItem(
            name="Unstaking Reentrancy",
            severity="high",
            description="Token transfer during unstake allows reentrancy to claim rewards multiple times.",
            code_indicators=["unstake(", "withdraw(", "transfer(", "claimReward"],
            missing_protections=["nonReentrant modifier", "update state before transfer"],
            exploit_precedent="Various staking contracts",
            detection_prompt="Does unstake() transfer tokens before updating staking state? Can reentrancy allow double reward claiming?",
        ),
        ChecklistItem(
            name="Withdrawal Delay Bypass",
            severity="high",
            description="Cooldown or withdrawal delay can be bypassed through transfer of staked tokens or delegation tricks.",
            code_indicators=["cooldown", "unstake(", "withdraw(", "transfer(", "cooldownExpiry"],
            missing_protections=["Non-transferable staked token", "cooldown reset on transfer", "withdrawal delay enforcement"],
            exploit_precedent="Lido cooldown bypass, various staking protocols",
            detection_prompt="Can staked tokens be transferred to bypass withdrawal cooldown? Does transferring staked tokens reset the cooldown timer?",
        ),
        ChecklistItem(
            name="Delegation Chain Attacks",
            severity="medium",
            description="Delegation of voting or staking power through chains of delegatees can be exploited for amplified influence or circular delegation.",
            code_indicators=["delegate(", "delegatee", "votingPower", "delegatedTo"],
            missing_protections=["Delegation depth limit", "circular delegation check", "delegation chain validation"],
            exploit_precedent="Various governance and staking protocols",
            detection_prompt="Is there a limit on delegation depth? Can circular delegation chains be created? Can delegated power be amplified through chaining?",
        ),
        ChecklistItem(
            name="Last-Second Staking for Full Epoch Reward",
            severity="high",
            description="Staking just before epoch end captures full epoch rewards with minimal time commitment.",
            code_indicators=["epoch", "rewardPerToken", "stake(", "totalStaked", "periodFinish"],
            missing_protections=["Pro-rata time-weighted rewards", "minimum staking duration per epoch", "snapshot-based distribution"],
            exploit_precedent="Various staking reward distribution exploits",
            detection_prompt="Can a user stake at the last second of an epoch and receive the full epoch reward? Are rewards time-weighted within the epoch?",
        ),
    ],
    ProtocolArchetype.GOVERNANCE: [
        ChecklistItem(
            name="Flash Loan Governance Attack",
            severity="critical",
            description="Flash loan tokens to gain voting power, pass proposal, execute in same block.",
            code_indicators=["castVote(", "propose(", "votingPower", "delegate"],
            missing_protections=["Snapshot-based voting power", "timelock delay", "voting period"],
            exploit_precedent="Beanstalk ($182M)",
            detection_prompt="Is voting power snapshot-based (past block) or current? Can flash-loaned tokens be used to vote?",
        ),
        ChecklistItem(
            name="Proposal Execution Without Timelock",
            severity="high",
            description="Proposals can be executed immediately without giving users time to react.",
            code_indicators=["execute(", "timelock", "queue(", "eta"],
            missing_protections=["Timelock delay", "minimum delay period", "emergency cancellation"],
            exploit_precedent="Various governance attacks",
            detection_prompt="Is there a mandatory delay between proposal approval and execution? Can users exit before a harmful proposal executes?",
        ),
        ChecklistItem(
            name="Quorum Manipulation",
            severity="high",
            description="Low quorum threshold allows attacker to pass proposals with minority of tokens.",
            code_indicators=["quorum", "proposalThreshold", "votingPeriod"],
            missing_protections=["Dynamic quorum", "sufficient minimum threshold"],
            exploit_precedent="Various DAOs",
            detection_prompt="What is the quorum requirement? Can a small token holder pass proposals when participation is low?",
        ),
    ],
    ProtocolArchetype.NFT_MARKETPLACE: [
        ChecklistItem(
            name="Signature Replay / Order Reuse",
            severity="critical",
            description="Signed orders can be replayed or used multiple times.",
            code_indicators=["ecrecover", "ECDSA.recover", "orderHash", "signature"],
            missing_protections=["Nonce tracking", "order cancellation mapping", "expiration timestamps"],
            exploit_precedent="OpenSea signature replay issues",
            detection_prompt="Are signed orders tracked to prevent replay? Can a cancelled order's signature still be used?",
        ),
        ChecklistItem(
            name="Royalty Bypass",
            severity="medium",
            description="Seller can bypass royalty payments through direct transfers or wrapper contracts.",
            code_indicators=["royaltyInfo(", "ERC2981", "royalt"],
            missing_protections=["On-chain royalty enforcement", "transfer hooks"],
            exploit_precedent="NFT royalty bypass tools",
            detection_prompt="Are royalties enforced on-chain or only honored by the marketplace? Can sellers bypass royalties via direct transfers?",
        ),
    ],
    ProtocolArchetype.ORACLE: [
        ChecklistItem(
            name="Stale Price Data",
            severity="critical",
            description="Oracle returns outdated price data that doesn't reflect current market conditions.",
            code_indicators=["latestRoundData(", "updatedAt", "answeredInRound"],
            missing_protections=["Staleness check (updatedAt)", "heartbeat validation", "round completeness check"],
            exploit_precedent="Multiple protocols using unchecked Chainlink data",
            detection_prompt="Is the oracle price checked for staleness? Is updatedAt validated against a maximum age threshold?",
        ),
        ChecklistItem(
            name="Price Deviation / Manipulation",
            severity="critical",
            description="Single-source oracle can be manipulated or return extreme values.",
            code_indicators=["getPrice(", "latestAnswer", "latestRoundData"],
            missing_protections=["Price deviation bounds", "multiple oracle sources", "circuit breaker"],
            exploit_precedent="Synthetix oracle manipulation, Compound DAI liquidations",
            detection_prompt="Is there a sanity check on price values? Can an extreme price from one oracle source cause protocol damage?",
        ),
        ChecklistItem(
            name="L2 Sequencer Downtime",
            severity="high",
            description="On L2s, sequencer downtime can cause stale prices and unfair liquidations when it comes back online.",
            code_indicators=["sequencerUptimeFeed", "isSequencerUp", "L2"],
            missing_protections=["Sequencer uptime feed check", "grace period after restart"],
            exploit_precedent="Arbitrum/Optimism sequencer downtime issues",
            detection_prompt="On L2, is the sequencer uptime feed checked? Is there a grace period after sequencer restart before liquidations?",
        ),
    ],
    ProtocolArchetype.TOKEN: [
        ChecklistItem(
            name="Fee-on-Transfer Accounting Mismatch",
            severity="high",
            description="Token with transfer fee causes accounting mismatch when amount received differs from amount sent.",
            code_indicators=["transferFrom(", "amount", "balanceOf"],
            missing_protections=["Pre/post balance delta check", "special fee-on-transfer handling"],
            exploit_precedent="Multiple DeFi protocols affected by fee tokens",
            detection_prompt="Does the protocol use the transfer amount directly for accounting, or does it check the actual balance delta?",
        ),
        ChecklistItem(
            name="Approval Race Condition",
            severity="medium",
            description="approve() can be front-run to double-spend the allowance.",
            code_indicators=["approve(", "allowance", "transferFrom("],
            missing_protections=["increaseAllowance/decreaseAllowance pattern", "set to 0 first"],
            exploit_precedent="Well-known ERC-20 race condition",
            detection_prompt="Does the token implement increaseAllowance/decreaseAllowance or require resetting to 0 before changing?",
        ),
    ],
    ProtocolArchetype.DEX_ORDERBOOK: [
        ChecklistItem(
            name="Order Front-Running / Sandwich",
            severity="high",
            description="Pending limit orders visible in mempool can be front-run or sandwiched by MEV bots.",
            code_indicators=["placeOrder(", "fillOrder(", "matchOrders(", "limitOrder"],
            missing_protections=["Commit-reveal order placement", "encrypted mempool", "batch auction matching"],
            exploit_precedent="Common MEV extraction on on-chain orderbooks",
            detection_prompt="Are orders visible in the mempool before execution? Can MEV bots front-run or sandwich limit orders?",
        ),
        ChecklistItem(
            name="Partial Fill Manipulation",
            severity="high",
            description="Partial fills can be exploited to leave dust amounts or manipulate order state for attacker benefit.",
            code_indicators=["fillOrder(", "partialFill", "remainingAmount", "filledAmount"],
            missing_protections=["Minimum fill amount", "dust amount threshold", "all-or-nothing option"],
            exploit_precedent="Various on-chain orderbook exploits",
            detection_prompt="Can an order be partially filled with a dust amount? Does partial filling leave the order in an exploitable state?",
        ),
        ChecklistItem(
            name="Cancel Griefing",
            severity="medium",
            description="Attacker prevents order cancellation by front-running cancel with a minimal fill, or cancellation costs excessive gas.",
            code_indicators=["cancelOrder(", "fillOrder(", "orderStatus"],
            missing_protections=["Atomic cancel-or-fill", "cancel priority", "gas-efficient cancellation"],
            exploit_precedent="DEX orderbook griefing attacks",
            detection_prompt="Can an attacker front-run a cancel with a minimal fill? Is cancellation gas-efficient even for complex orders?",
        ),
        ChecklistItem(
            name="Self-Trading Wash Detection Bypass",
            severity="medium",
            description="Attacker uses multiple addresses to execute wash trades, inflating volume or farming incentives.",
            code_indicators=["matchOrders(", "fillOrder(", "maker", "taker", "volume"],
            missing_protections=["Self-trade detection (maker == taker)", "volume-based incentive caps", "address clustering"],
            exploit_precedent="Various DEX wash trading for incentive farming",
            detection_prompt="Can a user trade with themselves using different addresses? Are volume-based incentives vulnerable to wash trading?",
        ),
    ],
    ProtocolArchetype.LIQUID_STAKING: [
        ChecklistItem(
            name="Withdrawal Queue Manipulation",
            severity="critical",
            description="Attacker manipulates the withdrawal queue ordering or timing to extract value from pending withdrawals.",
            code_indicators=["withdrawalQueue", "requestWithdrawal(", "claimWithdrawal(", "queueIndex"],
            missing_protections=["FIFO queue enforcement", "withdrawal rate limiting", "queue position immutability"],
            exploit_precedent="Lido withdrawal queue edge cases, various liquid staking protocols",
            detection_prompt="Can the withdrawal queue be reordered or manipulated? Can an attacker jump the queue or delay others' withdrawals?",
        ),
        ChecklistItem(
            name="Exchange Rate Manipulation via Donations",
            severity="critical",
            description="Direct donation of ETH or tokens to the staking contract inflates the exchange rate, causing existing stakers to receive diluted value.",
            code_indicators=["exchangeRate", "totalPooledEther", "totalShares", "balanceOf(address(this))"],
            missing_protections=["Internal accounting separate from balance", "exchange rate smoothing", "donation detection"],
            exploit_precedent="stETH/rETH exchange rate manipulation attempts",
            detection_prompt="Does the exchange rate rely on contract balance? Can direct ETH/token donations manipulate the staked token exchange rate?",
        ),
        ChecklistItem(
            name="Validator Exit Timing",
            severity="high",
            description="Malicious or compromised validator exits at strategic times to cause slashing or withdraw before penalties are applied.",
            code_indicators=["validatorExit", "exitEpoch", "withdrawableEpoch", "slashing"],
            missing_protections=["Exit queue enforcement", "slashing escrow", "minimum validator commitment period"],
            exploit_precedent="Beacon chain validator exit timing exploits",
            detection_prompt="Can validators exit strategically to avoid slashing penalties? Is there an enforced exit queue with slashing escrow?",
        ),
        ChecklistItem(
            name="Slashing Condition Exploitation",
            severity="high",
            description="Attacker triggers slashing conditions on validators, causing loss of staked funds for all delegators.",
            code_indicators=["slashing", "penaltyAmount", "slashValidator(", "reportSlashing("],
            missing_protections=["Slashing insurance fund", "slashing cap per validator", "diversified validator set"],
            exploit_precedent="Various Ethereum validator slashing incidents",
            detection_prompt="How are slashing losses distributed? Is there an insurance fund? Can a single validator's slashing wipe out a disproportionate amount?",
        ),
        ChecklistItem(
            name="Reward Distribution Fairness (Last-Second Staking)",
            severity="high",
            description="Staking just before reward distribution captures full rewards with minimal time commitment.",
            code_indicators=["rewardDistribution", "stake(", "exchangeRate", "rewardsPerShare"],
            missing_protections=["Time-weighted reward distribution", "reward vesting period", "snapshot-based rewards"],
            exploit_precedent="Various liquid staking reward gaming",
            detection_prompt="Can a user stake just before rewards are distributed and immediately unstake to capture rewards? Are rewards time-weighted?",
        ),
    ],
    ProtocolArchetype.PERPETUAL_DEX: [
        ChecklistItem(
            name="Funding Rate Manipulation",
            severity="critical",
            description="Attacker manipulates the funding rate by creating large imbalanced positions, forcing opposing positions to pay inflated funding.",
            code_indicators=["fundingRate", "longOpenInterest", "shortOpenInterest", "payFunding("],
            missing_protections=["Funding rate caps", "open interest limits", "funding rate smoothing over time"],
            exploit_precedent="Mango Markets ($114M), various perpetual DEX exploits",
            detection_prompt="Can an attacker create a large position to skew the funding rate? Are there caps on funding rate or open interest imbalance?",
        ),
        ChecklistItem(
            name="Liquidation Cascading",
            severity="critical",
            description="Liquidation of large positions moves the mark price, triggering cascading liquidations that drain the insurance fund.",
            code_indicators=["liquidate(", "markPrice", "insuranceFund", "bankruptcyPrice"],
            missing_protections=["Gradual liquidation (partial)", "circuit breakers on cascading", "ADL mechanism"],
            exploit_precedent="BitMEX cascading liquidations, various perpetual protocols",
            detection_prompt="Can liquidation of one large position trigger cascading liquidations? Is there a circuit breaker or partial liquidation mechanism?",
        ),
        ChecklistItem(
            name="Price Impact on Large Positions",
            severity="high",
            description="Opening or closing large positions has excessive price impact that can be exploited for self-benefit or to harm others.",
            code_indicators=["openPosition(", "closePosition(", "priceImpact", "positionSize"],
            missing_protections=["Position size limits", "price impact curve", "gradual position opening"],
            exploit_precedent="Various perpetual DEX price impact exploits",
            detection_prompt="Is there a price impact mechanism for large positions? Can an attacker exploit price impact to manipulate the mark price?",
        ),
        ChecklistItem(
            name="Oracle Deviation During Volatility",
            severity="high",
            description="During high volatility, oracle price deviates from actual market price, allowing exploitation of liquidation or position opening at stale prices.",
            code_indicators=["oraclePrice", "markPrice", "indexPrice", "maxDeviation"],
            missing_protections=["Oracle deviation circuit breaker", "multi-oracle median", "volatility-adjusted spread"],
            exploit_precedent="Perpetual protocol oracle manipulation during volatility spikes",
            detection_prompt="How does the protocol handle oracle price deviation during volatility? Is there a circuit breaker for extreme deviations?",
        ),
        ChecklistItem(
            name="Position Closing Frontrun",
            severity="high",
            description="MEV bots front-run large position closings to profit from the expected price impact.",
            code_indicators=["closePosition(", "decreasePosition(", "marketOrder", "priceImpact"],
            missing_protections=["Minimum execution delay", "keeper-based execution", "private order submission"],
            exploit_precedent="Common MEV attack on perpetual DEXes",
            detection_prompt="Can pending position close orders be front-run? Is there a keeper-based execution mechanism or private mempool?",
        ),
    ],
    ProtocolArchetype.CDP_STABLECOIN: [
        ChecklistItem(
            name="Bad Debt Cascade",
            severity="critical",
            description="Rapid collateral price drops cause multiple CDPs to become underwater simultaneously, creating systemic bad debt.",
            code_indicators=["collateralRatio", "liquidat", "badDebt", "surplusBuffer"],
            missing_protections=["Surplus buffer / reserve fund", "gradual liquidation", "emergency shutdown mechanism"],
            exploit_precedent="MakerDAO Black Thursday (2020), various CDP protocols",
            detection_prompt="What happens when many CDPs become underwater at once? Is there a surplus buffer? Can bad debt cascade through the system?",
        ),
        ChecklistItem(
            name="Collateral Ratio Manipulation During Liquidation",
            severity="critical",
            description="Attacker manipulates collateral price during liquidation to buy collateral at a discount or prevent their own liquidation.",
            code_indicators=["liquidationRatio", "collateralPrice", "liquidat", "oracle"],
            missing_protections=["Flash loan protection in liquidation", "TWAP-based liquidation price", "multi-block delay"],
            exploit_precedent="Various CDP liquidation manipulation exploits",
            detection_prompt="Can collateral price be manipulated in the same transaction as liquidation? Is the liquidation price based on spot or TWAP?",
        ),
        ChecklistItem(
            name="Stability Pool Drain",
            severity="high",
            description="Attacker drains the stability pool by triggering liquidations and front-running stability pool deposits.",
            code_indicators=["stabilityPool", "liquidat", "deposit(", "withdraw(", "epochScale"],
            missing_protections=["Stability pool withdrawal delay", "front-running protection", "minimum deposit duration"],
            exploit_precedent="Liquity stability pool edge cases",
            detection_prompt="Can an attacker front-run liquidations to deposit into the stability pool and capture discounted collateral? Is there a withdrawal delay?",
        ),
        ChecklistItem(
            name="Oracle Manipulation for Under-Collateralized Minting",
            severity="critical",
            description="Manipulating the oracle price allows minting stablecoins with insufficient collateral.",
            code_indicators=["mintDebt(", "collateralRatio", "oraclePrice", "getPrice("],
            missing_protections=["TWAP oracle", "multi-oracle consensus", "price deviation bounds on minting"],
            exploit_precedent="Various CDP oracle manipulation attacks",
            detection_prompt="Can the oracle price be manipulated to mint stablecoins with less collateral than required? Is the price feed manipulation-resistant?",
        ),
    ],
    ProtocolArchetype.YIELD_AGGREGATOR: [
        ChecklistItem(
            name="Strategy Migration Drain",
            severity="critical",
            description="During strategy migration, funds in transit can be intercepted or the new strategy can be a malicious contract.",
            code_indicators=["setStrategy(", "migrateStrategy(", "strategy", "withdrawAll("],
            missing_protections=["Timelock on strategy changes", "strategy whitelist", "migration validation"],
            exploit_precedent="Yearn Finance strategy migration risks, various vault exploits",
            detection_prompt="Is there a timelock on strategy changes? Can the owner instantly switch to a malicious strategy and drain funds?",
        ),
        ChecklistItem(
            name="Harvest Sandwiching",
            severity="high",
            description="MEV bots sandwich the harvest() call to extract value from the yield being compounded back into the vault.",
            code_indicators=["harvest(", "compound(", "swap(", "reinvest("],
            missing_protections=["Private harvest execution", "slippage protection on harvest swaps", "keeper-only harvest"],
            exploit_precedent="Common MEV attack on yield aggregators",
            detection_prompt="Can harvest() be sandwiched? Does the harvest swap have slippage protection? Is harvest restricted to keepers?",
        ),
        ChecklistItem(
            name="Share Price Manipulation via Strategy Return",
            severity="critical",
            description="Attacker manipulates the underlying strategy's reported returns to inflate share price before withdrawing.",
            code_indicators=["totalAssets(", "strategy", "estimatedTotalAssets(", "report("],
            missing_protections=["Strategy return caps", "share price change limits", "withdrawal delay after large gains"],
            exploit_precedent="Various yield vault share price manipulation exploits",
            detection_prompt="Can a strategy report inflated returns to manipulate the vault share price? Are there caps on per-harvest gains?",
        ),
        ChecklistItem(
            name="Emergency Withdraw Bypassing Accounting",
            severity="high",
            description="emergencyWithdraw() bypasses normal accounting, potentially leaving the vault in an inconsistent state.",
            code_indicators=["emergencyWithdraw(", "paused", "emergency", "rageQuit("],
            missing_protections=["Accounting reconciliation after emergency", "pro-rata emergency distribution", "emergency state tracking"],
            exploit_precedent="Various DeFi emergency withdrawal accounting bugs",
            detection_prompt="Does emergencyWithdraw() properly update all accounting state? Can it leave the vault with inconsistent share/asset ratios?",
        ),
    ],
}


class ProtocolArchetypeDetector:
    """Detects the protocol archetype from contract source code."""

    def detect(self, contract_content: str) -> ArchetypeResult:
        """Detect the protocol archetype from source code.

        Returns an ArchetypeResult with primary archetype, optional secondary
        archetypes, confidence score, and the signals that matched.
        """
        scores: Dict[ProtocolArchetype, float] = {}
        matched_signals: Dict[str, List[str]] = {}

        for archetype, signals in _ARCHETYPE_SIGNALS.items():
            total_weight = 0.0
            matches: List[str] = []
            for signal in signals:
                if re.search(signal.pattern, contract_content):
                    total_weight += signal.weight
                    matches.append(signal.pattern)
            if total_weight > 0:
                scores[archetype] = total_weight
                matched_signals[archetype.value] = matches

        if not scores:
            return ArchetypeResult(
                primary=ProtocolArchetype.UNKNOWN,
                confidence=0.0,
                signals={},
            )

        # Sort by score descending
        sorted_archetypes = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        primary = sorted_archetypes[0]
        primary_archetype = primary[0]
        primary_score = primary[1]

        # Confidence: normalize by max possible score for this archetype
        max_possible = sum(s.weight for s in _ARCHETYPE_SIGNALS.get(primary_archetype, []))
        confidence = min(1.0, primary_score / max(max_possible, 1.0))

        # Secondary archetypes: those with score >= 40% of primary
        secondary = []
        for archetype, score in sorted_archetypes[1:]:
            if score >= primary_score * 0.4:
                secondary.append(archetype)

        return ArchetypeResult(
            primary=primary_archetype,
            secondary=secondary,
            confidence=confidence,
            signals=matched_signals,
        )

    def detect_from_files(self, contract_files: List[Dict[str, str]]) -> ArchetypeResult:
        """Detect archetype from a list of contract file dicts with 'content' keys."""
        combined = "\n\n".join(cf.get("content", "") for cf in contract_files)
        return self.detect(combined)


def get_checklist_for_archetype(archetype: ProtocolArchetype) -> List[ChecklistItem]:
    """Get the vulnerability checklist for a given archetype."""
    return _ARCHETYPE_CHECKLISTS.get(archetype, [])


def get_checklists_for_result(result: ArchetypeResult) -> List[ChecklistItem]:
    """Get combined checklists for primary and secondary archetypes."""
    items = list(get_checklist_for_archetype(result.primary))
    seen_names: Set[str] = {item.name for item in items}
    for secondary in result.secondary:
        for item in get_checklist_for_archetype(secondary):
            if item.name not in seen_names:
                items.append(item)
                seen_names.add(item.name)
    return items


def format_checklist_for_prompt(items: List[ChecklistItem]) -> str:
    """Format checklist items as a text prompt section for LLM consumption."""
    if not items:
        return ""
    lines = ["## Archetype-Specific Vulnerability Checklist", ""]
    for i, item in enumerate(items, 1):
        lines.append(f"### {i}. {item.name} [{item.severity.upper()}]")
        lines.append(f"**Description**: {item.description}")
        lines.append(f"**Code indicators**: {', '.join(item.code_indicators)}")
        lines.append(f"**Missing protections**: {', '.join(item.missing_protections)}")
        lines.append(f"**Real-world precedent**: {item.exploit_precedent}")
        lines.append(f"**Check**: {item.detection_prompt}")
        lines.append("")
    return "\n".join(lines)
