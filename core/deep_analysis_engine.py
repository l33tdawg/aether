"""
Deep Analysis Engine — Multi-pass LLM analysis pipeline.

Replaces single-shot "find bugs" prompts with a structured 6-pass pipeline
that mirrors how professional auditors approach code review:

    Pass 1:   Protocol Understanding              (cheap model)
    Pass 2:   Attack Surface Mapping              (cheap model)
    Pass 3:   Invariant Violation Analysis        (strong model)
    Pass 3.5: Cross-Contract Vulnerability Analysis (strong model, multi-contract only)
    Pass 4:   Cross-Function Interaction          (strong model)
    Pass 5:   Adversarial Modeling + Edge Cases   (strong model)

Each pass receives accumulated context from prior passes.
Findings are collected from Passes 3-5 (including 3.5).
Pass 3.5 is skipped for single-contract audits.
"""

import asyncio
import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from core.json_utils import parse_llm_json
from core.protocol_archetypes import (
    ProtocolArchetypeDetector,
    ArchetypeResult,
    ProtocolArchetype,
    format_checklist_for_prompt,
    get_checklists_for_result,
)
from core.exploit_knowledge_base import ExploitKnowledgeBase

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Per-pass and pipeline timeout constants (seconds)
# ---------------------------------------------------------------------------
_PASS_TIMEOUT_CHEAP = 180    # 3 minutes for Gemini Flash / GPT-mini
_PASS_TIMEOUT_STRONG = 300   # 5 minutes for Claude / GPT-4
_PIPELINE_MAX_DURATION = 1500  # 25 minutes max for entire pipeline


# ---------------------------------------------------------------------------
# Model tier selection helpers
# ---------------------------------------------------------------------------

def _get_cheap_model() -> str:
    """Return a cheap/fast model for understanding passes."""
    try:
        from core.config_manager import get_model_for_task
        model = get_model_for_task('validation')  # validation tier is cheaper
        return model
    except Exception:
        pass
    # Fallback order: Gemini Flash (cheap + large context) > GPT-4o-mini > GPT-5-mini
    if os.getenv('GEMINI_API_KEY'):
        return 'gemini-3-flash-preview'
    return 'gpt-4.1-mini-2025-04-14'


def _get_strong_model() -> str:
    """Return a strong/deep-reasoning model for analysis passes."""
    try:
        from core.config_manager import get_model_for_task
        return get_model_for_task('analysis')
    except Exception:
        pass
    if os.getenv('ANTHROPIC_API_KEY'):
        return 'claude-sonnet-4-5-20250929'
    return 'gpt-4.1-2025-04-14'


def _get_medium_model() -> str:
    """Return a medium-tier model for edge case analysis."""
    try:
        from core.config_manager import get_model_for_task
        return get_model_for_task('medium')
    except Exception:
        pass
    # Fallback to cheap model
    return _get_cheap_model()


def _get_model_for_pass(pass_number: int) -> str:
    """Select model for each deep analysis pass with provider rotation.

    Rotates across providers for diverse perspectives:
      Pass 1-2 (understanding): Cheap model -- prefer Gemini Flash (large context, cheapest)
      Pass 3 (invariants):      Strong model -- prefer Anthropic Claude (strong reasoning)
      Pass 4 (cross-function):  Strong model -- prefer OpenAI GPT (different perspective from Pass 3)
      Pass 5 (adversarial):     Strong model -- prefer Anthropic Claude (best adversarial reasoning)

    Falls back gracefully when preferred provider API key is not available.
    """
    has_gemini = bool(os.getenv('GEMINI_API_KEY'))
    has_anthropic = bool(os.getenv('ANTHROPIC_API_KEY'))
    has_openai = bool(os.getenv('OPENAI_API_KEY'))

    if pass_number <= 2:
        # Cheap/fast model for understanding passes
        if has_gemini:
            return 'gemini-3-flash-preview'
        return _get_cheap_model()

    if pass_number == 3:
        # Invariant analysis -- prefer Anthropic for reasoning depth
        if has_anthropic:
            return 'claude-sonnet-4-5-20250929'
        if has_openai:
            return 'gpt-4.1-2025-04-14'
        return _get_strong_model()

    if pass_number == 4:
        # Cross-function -- rotate to different provider than Pass 3
        if has_openai:
            return 'gpt-4.1-2025-04-14'
        if has_anthropic:
            return 'claude-sonnet-4-5-20250929'
        return _get_strong_model()

    # Pass 5: Adversarial modeling -- strongest available
    if has_anthropic:
        return 'claude-sonnet-4-5-20250929'
    if has_openai:
        return 'gpt-4.1-2025-04-14'
    return _get_strong_model()


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class PassResult:
    """Result from a single analysis pass."""
    pass_name: str
    content: str  # Raw LLM response
    findings: List[Dict[str, Any]] = field(default_factory=list)
    model_used: str = ""
    duration: float = 0.0


@dataclass
class DeepAnalysisResult:
    """Complete result from all deep analysis passes."""
    archetype: ArchetypeResult
    pass_results: List[PassResult] = field(default_factory=list)
    all_findings: List[Dict[str, Any]] = field(default_factory=list)
    total_duration: float = 0.0

    def to_llm_results_format(self) -> Dict[str, Any]:
        """Convert to the format expected by enhanced_audit_engine (llm_results)."""
        # Deduplicate findings by (type, line)
        seen = set()
        unique_findings = []
        for f in self.all_findings:
            key = (
                f.get('type', f.get('vulnerability_type', '')).lower(),
                f.get('line', f.get('line_number', 0)),
            )
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        return {
            'analysis': {
                'vulnerabilities': unique_findings,
                'archetype': self.archetype.primary.value,
                'archetype_confidence': self.archetype.confidence,
                'passes_completed': len(self.pass_results),
            },
            'deep_analysis': True,
        }


# ---------------------------------------------------------------------------
# Prompt builders
# ---------------------------------------------------------------------------

def _build_pass1_prompt(contract_content: str, archetype: ArchetypeResult,
                        file_context: str = "", related_context: str = "") -> str:
    """Pass 1: Protocol Understanding."""
    archetype_hint = f"Detected archetype: {archetype.primary.value} (confidence: {archetype.confidence:.0%})"
    if archetype.secondary:
        archetype_hint += f"\nSecondary: {', '.join(a.value for a in archetype.secondary)}"

    file_context_section = ""
    if file_context:
        file_context_section = f"\n{file_context}\n\nIMPORTANT: Files marked [DEPLOYMENT SCRIPT] are deploy-time helpers (e.g. Foundry scripts). Do NOT report vulnerabilities in deployment scripts — focus only on [PRODUCTION] contracts.\n"

    related_section = ""
    if related_context:
        related_section = f"\n{related_context}\n"

    return f"""You are a senior smart contract security auditor. Your task is to **understand** this protocol before looking for bugs.

{archetype_hint}
{file_context_section}{related_section}
Analyze the following Solidity contract(s) and produce a structured understanding.

## Contract Code
```solidity
{contract_content}
```

## Required Output (JSON)

Return ONLY a JSON object with these fields:
{{
  "protocol_archetype": "confirmed archetype or your correction",
  "core_purpose": "one-sentence description of what this protocol does",
  "value_flows": [
    {{"direction": "in|out", "token": "ETH/ERC20/etc", "function": "function_name", "description": "..."}}
  ],
  "invariants": [
    {{"id": "INV-1", "description": "conservation law or ordering guarantee", "related_state": ["var1", "var2"], "critical": true}}
  ],
  "trust_assumptions": [
    {{"entity": "owner/oracle/relayer", "assumption": "what is trusted", "impact_if_violated": "what breaks"}}
  ],
  "state_variables": [
    {{"name": "varName", "purpose": "description", "readers": ["func1"], "writers": ["func2"]}}
  ],
  "external_dependencies": [
    {{"contract": "name/address", "interface": "IERC20/IOracle/etc", "assumption": "what is assumed about it"}}
  ]
}}
"""


def _build_pass2_prompt(contract_content: str, pass1_result: str,
                        related_context: str = "") -> str:
    """Pass 2: Attack Surface Mapping."""
    related_section = ""
    if related_context:
        related_section = f"\n{related_context}\n"

    return f"""You are a senior smart contract security auditor mapping the attack surface of a protocol.

## Protocol Understanding (from prior analysis)
{pass1_result}
{related_section}
## Contract Code
```solidity
{contract_content}
```

## Required Output (JSON)

For EVERY external and public function, analyze and return a JSON object:
{{
  "functions": [
    {{
      "name": "functionName",
      "visibility": "external|public",
      "access_control": "permissionless|role_restricted|owner_only",
      "state_reads": ["var1", "var2"],
      "state_writes": ["var3"],
      "external_calls": [
        {{"target": "contractName", "method": "method()", "before_state_update": true, "value_sent": false}}
      ],
      "value_flow": "tokens_in|tokens_out|neutral",
      "reentrancy_risk": "none|low|medium|high",
      "reentrancy_reason": "explanation if risk > none"
    }}
  ],
  "state_dependency_graph": [
    {{"variable": "varName", "writers": ["func1", "func2"], "readers": ["func3"], "cross_function_risk": "description"}}
  ],
  "privileged_operations": [
    {{"function": "funcName", "privilege": "onlyOwner|onlyAdmin|etc", "impact": "what this can do"}}
  ]
}}
"""


def _build_pass3_prompt(contract_content: str, pass1_result: str, pass2_result: str,
                        checklist_text: str, file_context: str = "",
                        related_context: str = "",
                        session_context: str = "") -> str:
    """Pass 3: Invariant Violation Analysis."""
    file_context_section = ""
    if file_context:
        file_context_section = f"\n{file_context}\n\nIMPORTANT: Files marked [DEPLOYMENT SCRIPT] are deploy-time helpers. Do NOT report vulnerabilities in deployment scripts — focus only on [PRODUCTION] contracts.\n"

    related_section = ""
    if related_context:
        related_section = f"\n{related_context}\n"

    session_section = ""
    if session_context:
        session_section = f"\n{session_context}\n"

    return f"""You are an elite smart contract security auditor. Your mission: systematically check every protocol invariant against every code path.
{file_context_section}
## Protocol Understanding
{pass1_result}

## Attack Surface
{pass2_result}
{related_section}{session_section}
{checklist_text}

## Contract Code
```solidity
{contract_content}
```

## Instructions

For EACH invariant identified in the protocol understanding, and EACH checklist item above:
1. List every function that modifies the related state variables
2. For each such function, determine: can it violate the invariant?
3. If yes: what exact sequence of calls causes the violation?
4. What existing protections prevent this? Can those protections be bypassed?

BE AGGRESSIVE — report potential violations even if you're only 60% sure. False negatives are worse than false positives here.

## Examples of REAL Vulnerabilities (report these)

**Example 1: First Depositor Share Inflation**
```solidity
function deposit(uint256 assets) external returns (uint256 shares) {{
    shares = totalSupply == 0 ? assets : assets * totalSupply / totalAssets;
    _mint(msg.sender, shares);
}}
```
Vulnerability: Attacker deposits 1 wei, then donates large amount directly to vault. Next depositor gets 0 shares due to rounding. This is REAL because: (1) no minimum deposit check, (2) no virtual offset in share calculation, (3) totalAssets can be manipulated via direct transfer.

**Example 2: Missing Slippage Protection**
```solidity
function swap(address tokenIn, uint256 amountIn) external returns (uint256 amountOut) {{
    amountOut = getAmountOut(amountIn);
    IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn);
    IERC20(tokenOut).transfer(msg.sender, amountOut);
}}
```
Vulnerability: No minimum amountOut parameter. Attacker can sandwich this transaction: front-run to move price, victim swap executes at bad price, back-run to profit. REAL because: (1) no slippage parameter, (2) no deadline check, (3) uses spot price.

## Examples of FALSE POSITIVES (do NOT report these)

**False Positive 1: Chainlink Oracle "Manipulation"**
```solidity
(, int256 price, , uint256 updatedAt, ) = priceFeed.latestRoundData();
require(price > 0 && block.timestamp - updatedAt < 3600, "stale");
```
NOT vulnerable to flash loan manipulation — Chainlink is an off-chain oracle aggregated from multiple sources. The staleness check is present. Do not report this as "oracle manipulation."

**False Positive 2: Owner-Only Parameter Setting**
```solidity
function setFee(uint256 newFee) external onlyOwner {{
    require(newFee <= MAX_FEE, "too high");
    fee = newFee;
}}
```
NOT a vulnerability — this is a governance-controlled parameter with a bounds check. The owner being able to change fees is by design, not a bug. Do not report "centralization risk" for bounded admin functions.

## Severity Calibration

- **Critical**: Direct, unconditional fund theft or permanent protocol bricking. Exploit requires NO special roles/permissions, works with flash loans or minimal capital. Real-world precedent exists. Impact >$1M.
- **High**: Significant fund loss or protocol disruption. Concrete exploit path exists but may require specific timing, market conditions, or moderate capital. Impact >$100K.
- **Medium**: Conditional fund risk or protocol degradation. Requires uncommon conditions, specific parameter combinations, or partial trust assumptions to exploit. Impact >$10K.
- **Low**: Theoretical risk with no practical exploit path demonstrated, or informational finding with security implications. Edge cases that are unlikely in practice.

If you cannot articulate a concrete exploit path with specific function calls and parameters, the finding is at most Medium.

## Reasoning Process (MANDATORY)

Before producing JSON output, reason through each potential finding:
1. What specific code pattern triggers this concern?
2. What protections already exist in the code? (Check modifiers, require statements, access controls)
3. Can those protections be bypassed? If so, HOW specifically?
4. What is the concrete exploit sequence? (Exact function calls with parameters)
5. What is the realistic financial impact?

Only include a finding in your JSON output if you can answer ALL five questions with specific code references.

Additionally, check this universal DeFi invariant:
- **Rounding Direction**: For any vault, pool, or staking contract: deposits/mints should round DOWN shares issued (favor protocol), withdrawals/redeems should round UP assets required (favor protocol). Check every share calculation and identify any that round in the WRONG direction.
- **First Depositor Safety**: For any vault with share-based accounting: is the first depositor protected from share inflation attacks? Check for: virtual offsets, minimum deposits, or dead shares.

## Required Output (JSON)
{{
  "findings": [
    {{
      "type": "vulnerability type (e.g. invariant_violation, checklist_item_name)",
      "severity": "critical|high|medium|low",
      "confidence": 0.0-1.0,
      "title": "concise title",
      "description": "detailed description of the vulnerability",
      "invariant_violated": "which invariant is violated",
      "attack_sequence": ["step 1", "step 2", "step 3"],
      "affected_functions": ["func1", "func2"],
      "line": 0,
      "existing_protections": "what protections exist",
      "bypass_method": "how protections can be bypassed, or 'none' if they hold",
      "impact": "financial/functional impact",
      "proof_sketch": "brief proof of exploitability"
    }}
  ],
  "dismissals": [
    {{
      "concern": "brief description of investigated concern",
      "vuln_type": "vulnerability type investigated",
      "affected_functions": ["func1"],
      "reason": "why this is NOT a vulnerability",
      "protections_found": ["modifier or check that prevents exploit"],
      "confidence_in_dismissal": 0.0-1.0
    }}
  ],
  "protections_verified": [
    {{
      "type": "access_control|reentrancy_guard|input_validation|overflow_check",
      "mechanism": "onlyOwner on setFee",
      "functions": ["setFee"],
      "bypassed": false
    }}
  ]
}}

Return ONLY findings that represent real vulnerabilities. Do NOT report informational items or best practice suggestions.
Include dismissals for investigated-but-safe concerns and protections_verified for all security mechanisms found.
"""


def _build_pass3_5_prompt(contract_content: str, pass1_result: str, pass2_result: str,
                          pass3_findings: str, cross_contract_context: str,
                          related_context: str = "",
                          session_context: str = "") -> str:
    """Pass 3.5: Cross-Contract Vulnerability Analysis.

    Targets vulnerabilities that span multiple contracts: trust boundary
    violations, cross-contract reentrancy, state consistency issues, interface
    mismatches, and privilege escalation across contract boundaries.
    """
    previous_findings_section = ""
    if pass3_findings:
        previous_findings_section = f"""
## Previous Analysis Findings (from Invariant Analysis)
{pass3_findings}

"""

    related_section = ""
    if related_context:
        related_section = f"\n{related_context}\n"

    session_section = ""
    if session_context:
        session_section = f"\n{session_context}\n"

    return f"""You are an elite smart contract security auditor specializing in **cross-contract vulnerabilities** — bugs that only manifest when analyzing how multiple contracts interact.

## Protocol Understanding
{pass1_result}

## Attack Surface
{pass2_result}

{previous_findings_section}{session_section}## Cross-Contract Relationship Map
{cross_contract_context}
{related_section}

## Contract Code
```solidity
{contract_content}
```

## Instructions

Analyze the interactions BETWEEN contracts for the following vulnerability classes:

### 1. Trust Boundary Analysis
For each external call between contracts:
- What does the caller assume about the callee's behavior?
- Can those assumptions be violated by a malicious or buggy callee?
- Are return values from external calls validated?
- Could a malicious implementation of an interface cause harm?

### 2. Cross-Contract State Consistency
- If Contract A reads state from Contract B, can B's state change between A's read and A's action? (TOCTOU across contracts)
- Can Contract B's state be manipulated to affect Contract A's behavior?
- Are there atomicity assumptions that cross contract boundaries (e.g., "B.balance will not change during my transaction")?
- Do multiple contracts share a dependency whose state change affects them differently?

### 3. Cross-Contract Reentrancy Paths
- Contract A calls B, B calls back into A (or C which calls A)
- Read-only reentrancy: A calls B, during B's execution, C reads stale state from A
- nonReentrant on A does NOT protect against B calling C which reads A's inconsistent state
- Check if ReentrancyGuard is shared vs per-contract

### 4. Interface Compliance
- Does the actual implementation match what the caller assumes via the interface?
- Are there functions on the implementation not on the interface that could be called directly?
- Could a token with non-standard behavior (fee-on-transfer, rebasing, callbacks) violate caller assumptions?

### 5. Upgrade/Proxy Interactions
- If any contract in the group is upgradeable, how does an upgrade affect other contracts that depend on it?
- Storage layout compatibility across delegatecall boundaries
- Can an upgrade change behavior that other contracts depend on?

### 6. Privilege Escalation Across Contracts
- Can permissions in Contract A be used to gain unauthorized access in Contract B?
- Are admin roles properly separated across contracts?
- Can a compromised contract in the group escalate to compromise others?

## Examples of REAL Cross-Contract Vulnerabilities (report these)

**Example 1: Read-Only Reentrancy Across Contracts**
```solidity
// Vault.sol
function withdraw(uint256 shares) external nonReentrant {{
    uint256 assets = shares * totalAssets / totalSupply;
    _burn(msg.sender, shares);
    // totalSupply decreased, totalAssets NOT YET decreased
    token.transfer(msg.sender, assets); // ERC-777 callback here
    totalAssets -= assets; // updated AFTER external call
}}

// PriceOracle.sol
function getSharePrice() external view returns (uint256) {{
    return vault.totalAssets() * 1e18 / vault.totalSupply();
    // During Vault.withdraw callback, totalSupply is decreased but totalAssets is not
    // -> inflated price returned
}}
```
REAL because: nonReentrant only protects Vault re-entry. During the token.transfer callback, PriceOracle reads stale state (totalAssets not yet decremented while totalSupply already is), returning an inflated share price. Any contract using PriceOracle during this window (e.g., a lending market for collateral valuation) can be exploited.

**Example 2: Interface Mismatch — Decimal Assumption**
```solidity
// LendingPool.sol
function getCollateralValue(address user) public view returns (uint256) {{
    uint256 price = IOracle(oracle).getPrice(collateralToken);
    // Assumes price has 18 decimals
    return userCollateral[user] * price / 1e18;
}}

// ChainlinkOracle.sol (actual implementation)
function getPrice(address token) external view returns (uint256) {{
    (, int256 answer, , , ) = priceFeed.latestRoundData();
    return uint256(answer); // Returns 8 decimals, NOT 18!
}}
```
REAL because: LendingPool assumes 18-decimal prices but oracle returns 8 decimals. Collateral is valued at 1e-10 of its actual value, enabling under-collateralized borrows.

## Examples of FALSE POSITIVES (do NOT report these)

**False Positive: Shared Owner Across Contracts**
```solidity
// ContractA.sol
address public owner; // same deployer

// ContractB.sol
address public owner; // same deployer
```
Two contracts in the same project sharing an owner is by design, NOT privilege escalation. Only report if Contract A's owner role can be used to gain capabilities in Contract B that were not intended.

**False Positive: Standard Interface Implementation**
An ERC-20 token implementing IERC20 exactly as specified is NOT an interface mismatch, even if some functions are not called by the protocol. Only report if the implementation DEVIATES from what callers assume.

## Severity Calibration

- **Critical**: Direct, unconditional fund theft or permanent protocol bricking. Exploit requires NO special roles/permissions, works with flash loans or minimal capital. Real-world precedent exists. Impact >$1M.
- **High**: Significant fund loss or protocol disruption. Concrete exploit path exists but may require specific timing, market conditions, or moderate capital. Impact >$100K.
- **Medium**: Conditional fund risk or protocol degradation. Requires uncommon conditions, specific parameter combinations, or partial trust assumptions to exploit. Impact >$10K.
- **Low**: Theoretical risk with no practical exploit path demonstrated, or informational finding with security implications. Edge cases that are unlikely in practice.

If you cannot articulate a concrete exploit path with specific function calls and parameters, the finding is at most Medium.

## Reasoning Process (MANDATORY)

Before producing JSON output, reason through each potential finding:
1. Which TWO (or more) contracts are involved and how do they interact?
2. What does Contract A assume about Contract B's state or behavior?
3. Can that assumption be violated? Under what conditions?
4. What is the concrete exploit sequence? (Exact function calls with parameters, across contracts)
5. What is the realistic financial impact?

Only include a finding in your JSON output if you can answer ALL five questions with specific code references.

## Required Output (JSON)
{{
  "findings": [
    {{
      "type": "cross_contract_reentrancy|trust_boundary_violation|interface_mismatch|state_inconsistency|privilege_escalation|upgrade_risk",
      "severity": "critical|high|medium|low",
      "confidence": 0.0-1.0,
      "title": "concise title",
      "description": "detailed description identifying which contracts are involved",
      "contracts_involved": ["ContractA", "ContractB"],
      "interaction_path": ["ContractA.funcX() calls ContractB.funcY()", "During callback, ContractC reads stale state from ContractA", "result: ..."],
      "affected_functions": ["ContractA.funcX", "ContractB.funcY"],
      "line": 0,
      "trust_assumption_violated": "what the caller assumed vs. what actually happens",
      "impact": "financial/functional impact",
      "prerequisites": "what conditions must be true"
    }}
  ],
  "dismissals": [
    {{
      "concern": "investigated cross-contract concern",
      "vuln_type": "cross_contract_reentrancy|trust_boundary_violation|etc",
      "affected_functions": ["ContractA.funcX"],
      "reason": "why this is NOT a vulnerability",
      "protections_found": ["protection that prevents exploit"],
      "confidence_in_dismissal": 0.0-1.0
    }}
  ],
  "protections_verified": [
    {{
      "type": "trust_boundary|reentrancy_guard|interface_check",
      "mechanism": "description of protection",
      "functions": ["funcX"],
      "bypassed": false
    }}
  ]
}}

Return ONLY findings that represent real cross-contract vulnerabilities. Do NOT report single-contract issues (those are covered by other passes).
Include dismissals for investigated-but-safe concerns and protections_verified for all cross-contract security mechanisms found.
"""


def _build_pass4_prompt(contract_content: str, pass1_result: str, pass2_result: str,
                        pass3_findings: str = "", cross_contract_context: str = "",
                        session_context: str = "") -> str:
    """Pass 4: Cross-Function Interaction Analysis."""
    previous_findings_section = ""
    if pass3_findings:
        previous_findings_section = f"""
## Previous Analysis Findings
{pass3_findings}

"""

    cross_contract_section = ""
    if cross_contract_context:
        cross_contract_section = f"""
## Cross-Contract Context
{cross_contract_context}

NOTE: Use this cross-contract context to identify cross-function interactions that SPAN contract boundaries. State dependencies that cross contracts are especially dangerous.

"""

    session_section = ""
    if session_context:
        session_section = f"\n{session_context}\n"

    challenge_instruction = ""
    if session_context:
        challenge_instruction = """

## Challenge Protocol (IMPORTANT)
If you DISAGREE with a prior dismissal from the session intelligence above, you MUST:
1. State which dismissal you challenge (reference its concern text)
2. Provide NEW evidence not considered in the prior pass
3. Explain why the prior reasoning was incorrect
Include challenges in the "challenges" array of your output.

If you AGREE with a prior finding, include its ID in the "confirmations" array — this boosts confidence.
"""

    return f"""You are an elite smart contract security auditor analyzing cross-function interactions.

## Protocol Understanding
{pass1_result}

## Attack Surface & State Dependencies
{pass2_result}

{previous_findings_section}{session_section}{cross_contract_section}{challenge_instruction}## Contract Code
```solidity
{contract_content}
```

## Instructions

Using the state dependency graph from the attack surface, analyze dangerous cross-function interactions:

1. **Shared State Conflicts**: Functions A and B both modify the same variable. Can calling A before B create inconsistency?
2. **Temporal Dependencies**: Does the ordering of function calls matter? Can an attacker exploit ordering?
3. **Reentrancy Chains**: Can function A's external call re-enter through function B?
4. **Flash Loan Sequences**: Can deposit+action+withdraw in the same transaction extract value?
5. **State Staleness**: Can function A read state that function B has modified in an uncommitted way?

For each dangerous interaction found, trace the EXACT execution path.

## Examples of REAL Cross-Function Vulnerabilities

**Example: Read-Only Reentrancy**
```solidity
// Contract A
function withdraw(uint256 shares) external nonReentrant {{
    uint256 assets = shares * totalAssets / totalSupply;
    _burn(msg.sender, shares);
    // totalSupply decreased but totalAssets not yet
    token.transfer(msg.sender, assets); // callback here
    totalAssets -= assets; // updated after external call
}}
// Contract B reads totalAssets/totalSupply during callback — gets inflated price
```
REAL because: nonReentrant only protects Contract A. Contract B's view of share price is stale during the callback window. The external call (token.transfer) happens between the _burn (which updates totalSupply) and the totalAssets update, creating a window where totalAssets/totalSupply is inflated.

**Example: Flash Loan + Deposit/Borrow Sequence**
```solidity
function deposit(uint256 amount) external {{
    balances[msg.sender] += amount;
    token.transferFrom(msg.sender, address(this), amount);
}}
function borrow(uint256 amount) external {{
    require(balances[msg.sender] >= amount * 2, "undercollateralized");
    borrowed[msg.sender] += amount;
    token.transfer(msg.sender, amount);
}}
```
REAL because: Flash loan → deposit(1000) → borrow(500) → withdraw(1000) → repay flash loan. The protocol uses the same token as collateral and borrow asset, and there is no same-block restriction preventing this sequence.

## FALSE POSITIVE Cross-Function Examples

**FP: Independent State Updates**
Two functions that modify different state variables with no dependency between them are NOT cross-function vulnerabilities even if called in sequence. For example, setFee() and setAdmin() modifying separate variables with separate access controls are independent operations.

**FP: Properly Guarded Reentrancy**
If ALL state-modifying functions that share state have nonReentrant from the SAME ReentrancyGuard, cross-function reentrancy through those functions is protected. Only report if there is an unguarded function that shares state with a guarded one.

## Severity Calibration

- **Critical**: Direct, unconditional fund theft or permanent protocol bricking. Exploit requires NO special roles/permissions, works with flash loans or minimal capital. Real-world precedent exists. Impact >$1M.
- **High**: Significant fund loss or protocol disruption. Concrete exploit path exists but may require specific timing, market conditions, or moderate capital. Impact >$100K.
- **Medium**: Conditional fund risk or protocol degradation. Requires uncommon conditions, specific parameter combinations, or partial trust assumptions to exploit. Impact >$10K.
- **Low**: Theoretical risk with no practical exploit path demonstrated, or informational finding with security implications. Edge cases that are unlikely in practice.

If you cannot articulate a concrete exploit path with specific function calls and parameters, the finding is at most Medium.

## Reasoning Process (MANDATORY)

Before producing JSON output, reason through each potential finding:
1. What specific code pattern triggers this concern?
2. What protections already exist in the code? (Check modifiers, require statements, access controls)
3. Can those protections be bypassed? If so, HOW specifically?
4. What is the concrete exploit sequence? (Exact function calls with parameters)
5. What is the realistic financial impact?

Only include a finding in your JSON output if you can answer ALL five questions with specific code references.

## Required Output (JSON)
{{
  "findings": [
    {{
      "type": "cross_function_interaction|reentrancy|flash_loan_attack|state_inconsistency",
      "severity": "critical|high|medium|low",
      "confidence": 0.0-1.0,
      "title": "concise title",
      "description": "detailed description",
      "interaction_path": ["func1() modifies X", "func2() reads stale X", "result: ..."],
      "affected_functions": ["func1", "func2"],
      "line": 0,
      "attack_type": "reentrancy|flash_loan|ordering|state_inconsistency",
      "impact": "financial/functional impact",
      "prerequisites": "what conditions must be true"
    }}
  ],
  "dismissals": [
    {{
      "concern": "investigated cross-function concern",
      "vuln_type": "reentrancy|flash_loan_attack|state_inconsistency",
      "affected_functions": ["func1", "func2"],
      "reason": "why this is NOT exploitable",
      "protections_found": ["protection mechanism"],
      "confidence_in_dismissal": 0.0-1.0
    }}
  ],
  "protections_verified": [
    {{
      "type": "reentrancy_guard|access_control|state_lock",
      "mechanism": "description of protection",
      "functions": ["func1"],
      "bypassed": false
    }}
  ],
  "challenges": [
    {{
      "target_concern": "the dismissed concern text being challenged",
      "new_evidence": "what new evidence contradicts the prior dismissal",
      "proposed_change": "re-flag as finding|upgrade severity|etc"
    }}
  ],
  "confirmations": ["list of prior finding titles/IDs that this pass confirms"]
}}
"""


def _build_pass5_prompt(contract_content: str, pass1_result: str, pass2_result: str,
                        pass3_findings: str, pass4_findings: str,
                        exploit_patterns: str,
                        session_context: str = "") -> str:
    """Pass 5: Adversarial Modeling."""
    session_section = ""
    if session_context:
        session_section = f"\n{session_context}\n"

    challenge_instruction = ""
    if session_context:
        challenge_instruction = """

## Challenge Protocol (IMPORTANT)
If you DISAGREE with a prior dismissal from the session intelligence above, you MUST:
1. State which dismissal you challenge (reference its concern text)
2. Provide NEW evidence not considered in the prior pass
3. Explain why the prior reasoning was incorrect
Include challenges in the "challenges" array of your output.

If you AGREE with a prior finding, include its ID in the "confirmations" array — this boosts confidence.
"""

    return f"""You are a **black-hat attacker** with unlimited resources. Your goal is to extract maximum value from this protocol.

You have:
- Unlimited flash loan capital (any amount, any token)
- MEV capabilities (front-run, back-run, sandwich any transaction)
- Multiple Ethereum accounts
- Governance tokens available for purchase
- Deep knowledge of EVM internals, assembly, and cross-protocol interactions

## Protocol Understanding
{pass1_result}

## Attack Surface
{pass2_result}

## Known Weaknesses from Prior Analysis
{pass3_findings}

{pass4_findings}
{session_section}{challenge_instruction}

## Known Exploit Patterns (Real-World Precedents)
{exploit_patterns}

## Contract Code
```solidity
{contract_content}
```

## Instructions

Design the **most profitable attacks** against this protocol. For each attack:
1. Capital required (0 if flash loan)
2. Number of transactions and whether atomic (single tx)
3. Step-by-step exploit with exact function calls
4. Profit calculation
5. Existing protections and whether they can be bypassed
6. Real-world precedent if applicable

DO NOT hold back. DO NOT worry about false positives. If an attack MIGHT work, report it.
Every missed real vulnerability is worth $50K-$500K in bug bounties.

## Real-World Attack Precedents

**Euler Finance ($197M)**: donateToReserves() allowed inflating collateral value without corresponding debt. Attacker: flash loan → deposit → borrow max → donate collateral to reserves (inflating health) → borrow more → profit.

**Beanstalk ($182M)**: Flash-loaned governance tokens to pass malicious proposal in single transaction. No timelock between proposal and execution for emergency actions.

**Nomad Bridge ($190M)**: Message validation accepted zero-hash as valid proof. Anyone could copy a valid transaction, change the recipient, and replay it because the Merkle proof was not validated against the actual message.

**Cream Finance ($130M)**: Flash loan to inflate self-referencing token price on Cream's own lending market, then used as collateral to drain other assets.

**Ronin Bridge ($625M)**: Compromised validator keys (5 of 9 multisig). Social engineering attack obtained enough private keys to forge withdrawal messages.

## Boundary & Edge Cases

Also systematically check for boundary and edge-case vulnerabilities in each function:
- **First/last operations**: What happens on first deposit/mint/stake when state is empty (division by zero, zero denominator)? What happens on last withdrawal when state goes to zero (stuck funds)?
- **Zero values**: amount=0, price=0, supply=0, balance=0 — does anything break?
- **Maximum values**: type(uint256).max, type(int256).min, type(int256).max — overflow in unchecked blocks?
- **Self-referential**: transfer to self, borrow against own collateral, swap token for same token
- **Same-block operations**: deposit+withdraw, stake+unstake, borrow+repay in same transaction
- **Callback reentrancy**: ERC-777 hooks, ERC-1155 callbacks, flash loan callbacks, receive() fallback
- **Empty/null inputs**: empty bytes, zero address (address(0)), empty arrays, block.timestamp edge cases

Include any edge-case findings alongside your attack findings in the same output.

## Severity Calibration

- **Critical**: Direct, unconditional fund theft or permanent protocol bricking. Exploit requires NO special roles/permissions, works with flash loans or minimal capital. Real-world precedent exists. Impact >$1M.
- **High**: Significant fund loss or protocol disruption. Concrete exploit path exists but may require specific timing, market conditions, or moderate capital. Impact >$100K.
- **Medium**: Conditional fund risk or protocol degradation. Requires uncommon conditions, specific parameter combinations, or partial trust assumptions to exploit. Impact >$10K.
- **Low**: Theoretical risk with no practical exploit path demonstrated, or informational finding with security implications. Edge cases that are unlikely in practice.

If you cannot articulate a concrete exploit path with specific function calls and parameters, the finding is at most Medium.

## Reasoning Process (MANDATORY)

Before producing JSON output, reason through each potential finding:
1. What specific code pattern triggers this concern?
2. What protections already exist in the code? (Check modifiers, require statements, access controls)
3. Can those protections be bypassed? If so, HOW specifically?
4. What is the concrete exploit sequence? (Exact function calls with parameters)
5. What is the realistic financial impact?

Only include a finding in your JSON output if you can answer ALL five questions with specific code references.

## Required Output (JSON)
{{
  "findings": [
    {{
      "type": "attack model type (e.g. flash_loan_attack, price_manipulation, governance_attack, division_by_zero, empty_state, overflow, stuck_funds, edge_case)",
      "severity": "critical|high|medium|low",
      "confidence": 0.0-1.0,
      "title": "attack name",
      "description": "detailed attack description",
      "attack_steps": ["1. Flash loan X tokens", "2. Call swap()", "3. ..."],
      "capital_required": "0 (flash loan)|N tokens|governance tokens",
      "atomic": true,
      "profit_estimate": "estimated profit in tokens/USD",
      "affected_functions": ["func1", "func2"],
      "line": 0,
      "protections_to_bypass": "what protections exist and how to bypass them",
      "precedent": "real-world exploit this is similar to, or 'novel'",
      "impact": "maximum financial impact",
      "edge_case_category": "first_operation|last_operation|zero_value|max_value|self_referential|same_block|callback|empty_input (only for edge-case findings)"
    }}
  ],
  "dismissals": [
    {{
      "concern": "investigated attack vector",
      "vuln_type": "attack model type",
      "affected_functions": ["func1"],
      "reason": "why this attack is NOT feasible",
      "protections_found": ["protection mechanism"],
      "confidence_in_dismissal": 0.0-1.0
    }}
  ],
  "protections_verified": [
    {{
      "type": "access_control|reentrancy_guard|input_validation|slippage_check",
      "mechanism": "description of protection",
      "functions": ["func1"],
      "bypassed": false
    }}
  ],
  "challenges": [
    {{
      "target_concern": "the dismissed concern text being challenged",
      "new_evidence": "what new evidence contradicts the prior dismissal",
      "proposed_change": "re-flag as finding|upgrade severity|etc"
    }}
  ],
  "confirmations": ["list of prior finding titles/IDs that this pass confirms"]
}}
"""


# ---------------------------------------------------------------------------
# Content hashing for caching
# ---------------------------------------------------------------------------

def _content_hash(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()[:16]


def _build_file_context_header(contract_files: List[Dict[str, Any]]) -> str:
    """Build a header listing project files with their roles."""
    if not contract_files:
        return ""
    lines = ["## Project Files"]
    for cf in contract_files:
        name = os.path.basename(cf.get('path', 'unknown'))
        label = "[DEPLOYMENT SCRIPT]" if cf.get('is_script', False) else "[PRODUCTION]"
        if cf.get('is_context_only', False):
            label = "[CONTEXT]"
        lines.append(f"- {name} {label}")
    return "\n".join(lines)


def _build_related_context_section(
    related_sources: List[Any],
    budget_chars: int,
    full_source: bool = True,
) -> str:
    """Build a labeled prompt section with related contract source code.

    Args:
        related_sources: List of RelatedContractSource objects
        budget_chars: Maximum character budget for this section
        full_source: If True, include full source; if False, include only
                     a one-liner reference list.

    Returns:
        Formatted prompt section string, or "" if no related sources.
    """
    if not related_sources:
        return ""

    # Import here to avoid circular imports
    from core.cross_contract_analyzer import RelatedContractResolver

    if not full_source:
        # One-liner reference list (for Pass 5)
        refs = [
            f"- {src.name} ({src.relationship})"
            for src in related_sources[:20]
        ]
        return (
            "\n## Related Contracts (Reference)\n"
            + "\n".join(refs)
            + "\n"
        )

    selected = RelatedContractResolver.select_within_budget(
        related_sources, budget_chars
    )
    if not selected:
        return ""

    lines = [
        "## Related Contract Source Code (Dependencies)",
        "IMPORTANT: These are dependencies of the target contract(s). Use them to verify",
        "inherited access control, interface compliance, library behavior, and cross-contract state.",
        "",
    ]

    relationship_labels = {
        'parent': 'Parent',
        'interface': 'Interface',
        'library': 'Library',
        'dependency': 'Dependency',
        'sibling': 'Sibling',
    }

    for src in selected:
        label = relationship_labels.get(src.relationship, src.relationship.title())
        short_path = os.path.basename(src.file_path)
        lines.append(f"### {label}: {src.name} (from {short_path})")
        lines.append("```solidity")
        lines.append(src.content)
        lines.append("```")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class DeepAnalysisEngine:
    """Multi-pass LLM analysis engine that thinks like an elite auditor."""

    def __init__(self, llm_analyzer, archetype_detector: Optional[ProtocolArchetypeDetector] = None):
        """
        Args:
            llm_analyzer: Instance of EnhancedLLMAnalyzer (provides _call_llm method)
            archetype_detector: Optional ProtocolArchetypeDetector instance
        """
        self.llm = llm_analyzer
        self.archetype_detector = archetype_detector or ProtocolArchetypeDetector()
        self.exploit_kb = ExploitKnowledgeBase()
        # Simple in-memory cache for pass 1 & 2 results
        self._cache: Dict[str, str] = {}
        # ML Feedback Loop: load severity calibration from historical outcomes
        self._severity_calibration: Dict[str, float] = {}
        self._load_severity_calibration()

    def _load_severity_calibration(self) -> None:
        """Load per-severity acceptance rates for calibrating LLM findings."""
        try:
            from core.accuracy_tracker import AccuracyTracker
            tracker = AccuracyTracker()
            self._severity_calibration = tracker.get_severity_calibration()
        except Exception:
            self._severity_calibration = {}

    # ------------------------------------------------------------------
    # SAGE institutional memory — primary knowledge source
    # ------------------------------------------------------------------

    # Character budgets for SAGE context per pass
    _SAGE_BUDGET = 50_000  # max chars of SAGE context per pass
    _SAGE_TOP_K = 10       # number of memories to recall per query

    def _build_sage_context(self, archetype: ArchetypeResult) -> str:
        """Recall historical audit knowledge from SAGE for this archetype.

        Returns a formatted context string (may be empty if SAGE is down).
        """
        try:
            from core.sage_client import SageClient
            client = SageClient.get_instance()
            if not client.health_check():
                return ""

            arch_name = archetype.primary.value
            sections: list[str] = []

            # Recall archetype-specific audit findings
            arch_memories = client.recall(
                query=f"vulnerabilities and audit findings for {arch_name}",
                domain=f"audit-{arch_name}",
                top_k=self._SAGE_TOP_K,
            )
            if arch_memories:
                lines = [m.get("content", "") for m in arch_memories if m.get("content")]
                if lines:
                    sections.append("### Historical Audit Findings\n" + "\n".join(f"- {l}" for l in lines))

            # Recall exploit patterns
            exploit_memories = client.recall(
                query=f"exploit patterns for {arch_name}",
                domain="exploit-patterns",
                top_k=self._SAGE_TOP_K,
            )
            if exploit_memories:
                lines = [m.get("content", "") for m in exploit_memories if m.get("content")]
                if lines:
                    sections.append("### Known Exploit Patterns\n" + "\n".join(f"- {l}" for l in lines))

            if sections:
                ctx = "\n\n## SAGE Institutional Knowledge\n" + "\n\n".join(sections) + "\n"
                # Enforce budget
                if len(ctx) > self._SAGE_BUDGET:
                    ctx = ctx[:self._SAGE_BUDGET] + "\n[...truncated to budget]\n"
                total_recalled = len(arch_memories) + len(exploit_memories)
                print(f"   🧠 SAGE: recalled {total_recalled} memories ({len(ctx)} chars)", flush=True)
                return ctx
        except Exception as exc:
            logger.debug("SAGE context build failed: %s", exc)
        return ""

    def _recall_sage_checklist(self, archetype: ArchetypeResult) -> str:
        """Recall archetype-specific vulnerability checklists from SAGE.

        This is the PRIMARY source for Pass 3 checklist context, replacing
        the static ``format_checklist_for_prompt()`` when SAGE is available.
        Falls back to static checklists if SAGE returns nothing.
        """
        try:
            from core.sage_client import SageClient
            client = SageClient.get_instance()
            if not client.health_check():
                return ""

            arch_name = archetype.primary.value
            all_memories: list[dict] = []

            # Query the archetype-specific domain
            mems = client.recall(
                query=f"vulnerability checklist {arch_name} invariant",
                domain=f"protocol-{arch_name}",
                top_k=self._SAGE_TOP_K,
            )
            all_memories.extend(mems)

            # Also recall general exploit patterns for this archetype
            exploit_mems = client.recall(
                query=f"{arch_name} exploit pattern vulnerability mechanism",
                domain="exploit-patterns",
                top_k=self._SAGE_TOP_K,
            )
            all_memories.extend(exploit_mems)

            # Query secondary archetypes
            for sec_arch in archetype.secondary[:2]:
                sec_mems = client.recall(
                    query=f"vulnerability checklist {sec_arch.value}",
                    domain=f"protocol-{sec_arch.value}",
                    top_k=5,
                )
                all_memories.extend(sec_mems)

            if not all_memories:
                return ""

            lines = []
            seen: set[str] = set()
            for m in all_memories:
                content = m.get("content", "")
                if content and content[:80] not in seen:
                    seen.add(content[:80])
                    lines.append(f"- {content}")

            if not lines:
                return ""

            text = "\n\n## Vulnerability Checklist (from SAGE institutional memory)\n"
            text += "These are known vulnerability patterns for this protocol type, drawn from "
            text += "historical audits, exploit databases, and confirmed findings:\n\n"
            text += "\n".join(lines) + "\n"

            # Enforce budget
            if len(text) > self._SAGE_BUDGET:
                text = text[:self._SAGE_BUDGET] + "\n[...truncated to budget]\n"

            print(f"   🧠 SAGE checklist: {len(lines)} patterns ({len(text)} chars)", flush=True)
            return text
        except Exception as exc:
            logger.debug("SAGE checklist recall failed: %s", exc)
            return ""

    def _recall_sage_exploit_patterns(self, archetype: ArchetypeResult) -> str:
        """Recall exploit patterns + historical exploits from SAGE for Pass 5.

        This is the PRIMARY source for Pass 5 exploit context, replacing
        the static ``exploit_kb.format_for_prompt()`` when SAGE is available.
        Falls back to static patterns if SAGE returns nothing.
        """
        try:
            from core.sage_client import SageClient
            client = SageClient.get_instance()
            if not client.health_check():
                return ""

            arch_name = archetype.primary.value
            all_memories: list[dict] = []

            # Exploit patterns
            exploit_mems = client.recall(
                query=f"{arch_name} attack exploit mechanism flash loan manipulation",
                domain="exploit-patterns",
                top_k=self._SAGE_TOP_K,
            )
            all_memories.extend(exploit_mems)

            # Historical real-world exploits
            hist_mems = client.recall(
                query=f"historical exploit attack {arch_name} critical vulnerability",
                domain="historical-exploits",
                top_k=self._SAGE_TOP_K,
            )
            all_memories.extend(hist_mems)

            # Token quirks if relevant
            quirk_mems = client.recall(
                query="token quirk fee transfer rebasing callback",
                domain="token-quirks",
                top_k=5,
            )
            all_memories.extend(quirk_mems)

            # False positive patterns (so LLM knows what NOT to flag)
            fp_mems = client.recall(
                query=f"false positive {arch_name} rejected not exploitable",
                domain="false-positives",
                top_k=self._SAGE_TOP_K,
            )

            if not all_memories and not fp_mems:
                return ""

            sections: list[str] = []

            # Exploit patterns section
            exploit_lines = []
            seen: set[str] = set()
            for m in all_memories:
                content = m.get("content", "")
                if content and content[:80] not in seen:
                    seen.add(content[:80])
                    exploit_lines.append(f"- {content}")
            if exploit_lines:
                sections.append(
                    "### Known Exploit Patterns & Historical Precedents (from SAGE)\n"
                    + "\n".join(exploit_lines)
                )

            # FP patterns section
            if fp_mems:
                fp_lines = [f"- {m.get('content', '')}" for m in fp_mems if m.get("content")]
                if fp_lines:
                    sections.append(
                        "### Known False Positive Patterns (from SAGE)\n"
                        "Avoid flagging these — they have been rejected in prior audits:\n"
                        + "\n".join(fp_lines)
                    )

            if not sections:
                return ""

            text = "\n\n" + "\n\n".join(sections) + "\n"

            if len(text) > self._SAGE_BUDGET:
                text = text[:self._SAGE_BUDGET] + "\n[...truncated to budget]\n"

            total = len(all_memories) + len(fp_mems)
            print(f"   🧠 SAGE exploits: {total} memories ({len(text)} chars)", flush=True)
            return text
        except Exception as exc:
            logger.debug("SAGE exploit pattern recall failed: %s", exc)
            return ""

    def _recall_sage_cross_function_patterns(self, archetype: ArchetypeResult) -> str:
        """Recall cross-function vulnerability patterns from SAGE for Pass 4.

        Replaces hardcoded examples with institutional knowledge about
        reentrancy chains, flash loan sequences, and state dependency bugs.
        """
        try:
            from core.sage_client import SageClient
            client = SageClient.get_instance()
            if not client.health_check():
                return ""

            arch_name = archetype.primary.value
            all_memories: list[dict] = []

            # Cross-function patterns
            mems = client.recall(
                query="cross-function reentrancy state dependency flash loan sequence",
                domain="exploit-patterns",
                top_k=self._SAGE_TOP_K,
            )
            all_memories.extend(mems)

            # Audit methodology for cross-function analysis
            method_mems = client.recall(
                query="cross-function state analysis methodology",
                domain="audit-methodology",
                top_k=5,
            )
            all_memories.extend(method_mems)

            if not all_memories:
                return ""

            lines = []
            seen: set[str] = set()
            for m in all_memories:
                content = m.get("content", "")
                if content and content[:80] not in seen:
                    seen.add(content[:80])
                    lines.append(f"- {content}")

            if not lines:
                return ""

            text = (
                "\n\n## Cross-Function Vulnerability Patterns (from SAGE institutional memory)\n"
                "Known patterns from historical audits and exploits:\n\n"
                + "\n".join(lines) + "\n"
            )

            if len(text) > self._SAGE_BUDGET:
                text = text[:self._SAGE_BUDGET] + "\n[...truncated to budget]\n"

            print(f"   🧠 SAGE cross-function: {len(lines)} patterns ({len(text)} chars)", flush=True)
            return text
        except Exception as exc:
            logger.debug("SAGE cross-function recall failed: %s", exc)
            return ""

    def _store_audit_learnings(
        self,
        findings: List[Dict[str, Any]],
        archetype: ArchetypeResult,
        contract_name: str,
    ) -> None:
        """Store audit findings summary in SAGE for future recall."""
        try:
            from core.sage_client import SageClient
            client = SageClient.get_instance()
            if not client.health_check():
                return

            arch_name = archetype.primary.value

            # Summarize findings by severity
            severity_counts: dict[str, int] = {}
            vuln_types: set[str] = set()
            for f in findings:
                sev = f.get("severity", "unknown")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
                vuln_types.add(f.get("vulnerability_type", "unknown"))

            if not findings:
                return

            sev_str = ", ".join(f"{k}: {v}" for k, v in severity_counts.items())
            types_str = ", ".join(list(vuln_types)[:5])

            client.remember(
                content=(
                    f"Audit of {contract_name} ({arch_name}): "
                    f"{len(findings)} findings ({sev_str}). "
                    f"Types: {types_str}."
                ),
                domain=f"audit-{arch_name}",
                memory_type="observation",
                confidence=0.80,
                tags=["audit-result", arch_name, contract_name],
            )
        except Exception as exc:
            logger.debug("SAGE store_audit_learnings failed: %s", exc)

    # ------------------------------------------------------------------
    # v6.0 Collaborative Pipeline — SAGE Session Memory
    # ------------------------------------------------------------------

    def _store_pass_session(
        self, pass_name: str, raw_response: str, findings: List[Dict[str, Any]]
    ) -> None:
        """Parse findings/dismissals/protections from LLM response and store in SAGE session.

        Called after each finding-producing pass (3, 3.5, 4, 5) to build up
        shared session state that subsequent passes can reference.
        """
        if not hasattr(self, '_session_domain') or not self._session_domain:
            return
        if not hasattr(self, '_sage_client') or self._sage_client is None:
            return

        try:
            # Try direct JSON parse first to preserve all keys (dismissals,
            # protections_verified, challenges, confirmations). parse_llm_json
            # uses extract_json_from_response which may strip non-standard keys.
            parsed = {}
            if raw_response:
                try:
                    parsed = json.loads(raw_response)
                except (json.JSONDecodeError, TypeError):
                    # LLM may have wrapped in markdown — try stripping
                    stripped = raw_response.strip()
                    if stripped.startswith("```"):
                        lines = stripped.split("\n")
                        # Remove first and last ``` lines
                        inner = "\n".join(
                            l for l in lines[1:]
                            if not l.strip().startswith("```")
                        )
                        try:
                            parsed = json.loads(inner)
                        except (json.JSONDecodeError, TypeError):
                            parsed = {}
            if not isinstance(parsed, dict):
                parsed = {}

            # Extract dismissals and protections from LLM response
            dismissals = parsed.get("dismissals", [])
            protections = parsed.get("protections_verified", [])
            challenges = parsed.get("challenges", [])
            confirmations = parsed.get("confirmations", [])

            # Build session record as a single JSON blob
            session_record = {
                "pass": pass_name,
                "findings": [],
                "dismissals": [],
                "protections": [],
                "challenges": challenges if isinstance(challenges, list) else [],
                "confirmations": confirmations if isinstance(confirmations, list) else [],
            }

            # Extract finding records with IDs
            for i, f in enumerate(findings):
                finding_id = f"{pass_name.replace(' ', '').replace(':', '-')}-{i+1:03d}"
                session_record["findings"].append({
                    "record_type": "finding",
                    "pass": pass_name,
                    "finding_id": finding_id,
                    "vuln_type": f.get("type", f.get("vulnerability_type", "unknown")),
                    "severity": f.get("severity", "medium"),
                    "confidence": f.get("confidence", 0.5),
                    "affected_functions": f.get("affected_functions", []),
                    "title": f.get("title", ""),
                    "summary": f.get("description", "")[:300],
                })

            # Extract dismissal records
            if isinstance(dismissals, list):
                for i, d in enumerate(dismissals):
                    if isinstance(d, dict):
                        session_record["dismissals"].append({
                            "record_type": "dismissal",
                            "pass": pass_name,
                            "dismissed_concern": d.get("concern", ""),
                            "vuln_type": d.get("vuln_type", ""),
                            "reason": d.get("reason", ""),
                            "protections_found": d.get("protections_found", []),
                            "confidence_in_dismissal": float(d.get("confidence_in_dismissal", 0.8)),
                            "affected_functions": d.get("affected_functions", []),
                        })

            # Extract protection records
            if isinstance(protections, list):
                for p in protections:
                    if isinstance(p, dict):
                        session_record["protections"].append({
                            "record_type": "protection",
                            "pass": pass_name,
                            "protection_type": p.get("type", ""),
                            "mechanism": p.get("mechanism", ""),
                            "scope": p.get("functions", []),
                            "bypassed": bool(p.get("bypassed", False)),
                        })

            content = json.dumps(session_record)
            self._sage_client.remember_session(content, self._session_domain)
            n_f = len(session_record["findings"])
            n_d = len(session_record["dismissals"])
            n_p = len(session_record["protections"])
            logger.info(
                "SAGE session stored for %s: %d findings, %d dismissals, %d protections",
                pass_name, n_f, n_d, n_p,
            )
            print(
                f"   SAGE session: stored {n_f} findings, {n_d} dismissals, "
                f"{n_p} protections for {pass_name}",
                flush=True,
            )
        except Exception as exc:
            logger.error("SAGE session store failed for %s: %s", pass_name, exc)
            print(f"   SAGE session store FAILED for {pass_name}: {exc}", flush=True)

    def _build_session_context(self, for_pass: str) -> str:
        """Recall all session records from SAGE and format as Prior Pass Intelligence.

        Returns a structured section that tells the LLM about confirmed findings,
        dismissed concerns, and verified protections from earlier passes.
        """
        if not hasattr(self, '_session_domain') or not self._session_domain:
            return ""
        if not hasattr(self, '_sage_client') or self._sage_client is None:
            return ""

        try:
            raw_memories = self._sage_client.recall_session(self._session_domain)
            if not raw_memories:
                return ""

            # Parse all session records
            all_findings = []
            all_dismissals = []
            all_protections = []
            all_challenges = []
            all_confirmations = []

            for mem in raw_memories:
                content = mem.get("content", "")
                if not content:
                    continue
                try:
                    record = json.loads(content)
                    if not isinstance(record, dict):
                        continue
                    all_findings.extend(record.get("findings", []))
                    all_dismissals.extend(record.get("dismissals", []))
                    all_protections.extend(record.get("protections", []))
                    all_challenges.extend(record.get("challenges", []))
                    all_confirmations.extend(record.get("confirmations", []))
                except (json.JSONDecodeError, TypeError):
                    continue

            if not (all_findings or all_dismissals or all_protections):
                return ""

            lines = [
                "## Prior Pass Intelligence (SAGE Session)",
                "",
            ]

            # Confirmed findings section
            if all_findings:
                lines.append("### Confirmed Findings")
                # Track which findings have been confirmed by later passes
                confirmed_titles = set()
                for c in all_confirmations:
                    if isinstance(c, str):
                        confirmed_titles.add(c.lower())
                for f in all_findings:
                    sev = f.get("severity", "?").upper()
                    fid = f.get("finding_id", "?")
                    title = f.get("title", f.get("summary", "unknown")[:60])
                    funcs = ", ".join(f.get("affected_functions", []))
                    conf = f.get("confidence", 0.5)
                    # Check if confirmed by later pass
                    is_confirmed = title.lower() in confirmed_titles
                    confirm_tag = " [CROSS-CONFIRMED]" if is_confirmed else ""
                    lines.append(
                        f"- [{fid}] [{sev}] {title} ({funcs}) "
                        f"conf={conf:.0%}{confirm_tag} "
                        f"-- DO NOT re-report, build on it"
                    )
                lines.append("")

            # Dismissed concerns section
            if all_dismissals:
                # Filter out challenged dismissals
                challenged_concerns = set()
                for ch in all_challenges:
                    if isinstance(ch, dict):
                        challenged_concerns.add(ch.get("target_concern", "").lower())

                active_dismissals = []
                overridden_dismissals = []
                for d in all_dismissals:
                    concern = d.get("dismissed_concern", "")
                    if concern.lower() in challenged_concerns:
                        overridden_dismissals.append(d)
                    else:
                        active_dismissals.append(d)

                if active_dismissals:
                    lines.append("### Dismissed Concerns")
                    for d in active_dismissals:
                        concern = d.get("dismissed_concern", "unknown")
                        reason = d.get("reason", "")
                        conf = d.get("confidence_in_dismissal", 0.8)
                        pass_from = d.get("pass", "unknown")
                        funcs = ", ".join(d.get("affected_functions", []))
                        lines.append(
                            f"- [{pass_from}-DISMISSED] {concern} ({funcs})"
                        )
                        lines.append(
                            f"  Reason: {reason} (confidence: {conf:.0%})"
                        )
                        lines.append(
                            "  DO NOT re-flag unless you have NEW contradicting evidence"
                        )
                    lines.append("")

                if overridden_dismissals:
                    lines.append("### Challenged Dismissals (OVERRIDDEN)")
                    for d in overridden_dismissals:
                        concern = d.get("dismissed_concern", "unknown")
                        lines.append(
                            f"- {concern} -- previously dismissed, now challenged"
                        )
                    lines.append("")

            # Verified protections section
            if all_protections:
                lines.append("### Verified Protections")
                for p in all_protections:
                    mechanism = p.get("mechanism", "unknown")
                    scope = ", ".join(p.get("scope", []))
                    bypassed = p.get("bypassed", False)
                    status = "BYPASSED" if bypassed else "HOLDS"
                    lines.append(f"- {mechanism} ({scope}) -- {status}")
                lines.append("")

            context = "\n".join(lines)
            # Enforce budget
            max_chars = 40_000
            if len(context) > max_chars:
                context = context[:max_chars] + "\n[...truncated to session budget]\n"

            logger.info(
                "SAGE session context for %s: %d findings, %d dismissals, %d protections (%d chars)",
                for_pass, len(all_findings), len(all_dismissals),
                len(all_protections), len(context),
            )
            return context
        except Exception as exc:
            logger.error("SAGE session context build failed for %s: %s", for_pass, exc)
            print(f"   SAGE session context FAILED for {for_pass}: {exc}", flush=True)
            return ""

    def _resolve_challenges(self, all_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Process challenges from later passes that override earlier dismissals.

        When a later pass challenges a dismissal with new evidence, the dismissed
        concern may need to be re-flagged or have its severity/confidence adjusted.
        Also applies confidence boosts when findings are confirmed by later passes.

        Returns the updated findings list.
        """
        if not hasattr(self, '_session_domain') or not self._session_domain:
            return all_findings
        if not hasattr(self, '_sage_client') or self._sage_client is None:
            return all_findings

        try:
            raw_memories = self._sage_client.recall_session(self._session_domain)
            if not raw_memories:
                return all_findings

            all_challenges = []
            all_confirmations = []
            all_session_findings = []

            for mem in raw_memories:
                content = mem.get("content", "")
                if not content:
                    continue
                try:
                    record = json.loads(content)
                    if not isinstance(record, dict):
                        continue
                    all_challenges.extend(record.get("challenges", []))
                    all_confirmations.extend(record.get("confirmations", []))
                    all_session_findings.extend(record.get("findings", []))
                except (json.JSONDecodeError, TypeError):
                    continue

            # Apply confirmation boosts
            confirmed_titles = set()
            for c in all_confirmations:
                if isinstance(c, str):
                    confirmed_titles.add(c.lower().strip())

            for finding in all_findings:
                title = finding.get("title", "").lower().strip()
                if title and title in confirmed_titles:
                    old_conf = finding.get("confidence", 0.5)
                    # Boost by 15%, capped at 1.0
                    new_conf = min(1.0, old_conf * 1.15)
                    finding["confidence"] = new_conf
                    finding["cross_confirmed"] = True
                    logger.info(
                        "Confidence boosted for '%s': %.2f -> %.2f (cross-confirmed)",
                        finding.get("title", "?"), old_conf, new_conf,
                    )

            # Process challenges: find dismissed concerns that should be re-flagged
            if all_challenges:
                for challenge in all_challenges:
                    if not isinstance(challenge, dict):
                        continue
                    target = challenge.get("target_concern", "")
                    new_evidence = challenge.get("new_evidence", "")
                    proposed = challenge.get("proposed_change", "")
                    if target and new_evidence:
                        logger.info(
                            "Challenge processed: '%s' -> %s (new evidence: %s)",
                            target, proposed, new_evidence[:100],
                        )
                        # The challenge itself creates a finding in the pass that raised it,
                        # so no need to fabricate a new finding here. The main effect is
                        # that the dismissal is marked as overridden in session context.

            return all_findings
        except Exception as exc:
            logger.error("Challenge resolution failed: %s", exc)
            return all_findings

    def _build_severity_calibration_note(self) -> str:
        """Build a calibration note for the LLM if certain severities have high rejection.

        If >80% of findings at a severity level are historically rejected, inject
        a warning into the prompt so the LLM is more careful at that level.
        """
        if not self._severity_calibration:
            return ""
        notes = []
        for sev, rate in self._severity_calibration.items():
            if rate < 0.2:  # >80% rejected
                pct = (1.0 - rate) * 100
                notes.append(
                    f"- **{sev.upper()}**: Historically {pct:.0f}% of {sev} findings were rejected. "
                    f"Apply extra scrutiny before marking a finding as {sev}. "
                    f"Ensure a concrete, step-by-step exploit exists."
                )
        if not notes:
            return ""
        header = (
            "\n\n## Historical Severity Calibration Warning\n"
            "Based on past submission outcomes, certain severity levels have very high "
            "rejection rates. Adjust your confidence and severity accordingly:\n"
        )
        return header + "\n".join(notes) + "\n"

    def _calibrate_finding_severity(self, finding: Dict[str, Any]) -> None:
        """Adjust a finding's confidence based on historical severity acceptance.

        If a severity level has a historically low acceptance rate (<40%),
        findings at that level get a confidence penalty.  High acceptance
        (>70%) gives a small boost.
        """
        if not self._severity_calibration:
            return
        severity = finding.get('severity', '').lower()
        rate = self._severity_calibration.get(severity)
        if rate is None:
            return
        if rate < 0.4:
            # Penalize: scale confidence down proportionally
            finding['confidence'] = max(0.1, finding.get('confidence', 0.5) * (0.6 + rate))
        elif rate > 0.7:
            # Boost: small increase capped at 1.0
            finding['confidence'] = min(1.0, finding.get('confidence', 0.5) * (1.0 + (rate - 0.7) * 0.5))

    async def analyze(
        self,
        combined_content: str,
        contract_files: List[Dict[str, Any]],
        static_results: Dict[str, Any],
        ast_data: Optional[Any] = None,
        taint_reports: Optional[List[Any]] = None,
    ) -> DeepAnalysisResult:
        """Run the full 5-pass deep analysis pipeline.

        Falls back gracefully if any individual pass fails.

        Args:
            combined_content: Combined Solidity source code
            contract_files: List of contract file dicts
            static_results: Results from static analysis
            ast_data: Optional SolidityAST from AST parser (enhances Pass 1)
            taint_reports: Optional taint analysis reports (enhances Pass 2)
        """
        start_time = time.time()
        self._pipeline_start = start_time  # Used by _run_pass for time budget

        # Detect archetype
        archetype = self.archetype_detector.detect(combined_content)
        print(f"🔍 Protocol archetype: {archetype.primary.value} (confidence: {archetype.confidence:.0%})", flush=True)
        if archetype.secondary:
            print(f"   Secondary: {', '.join(a.value for a in archetype.secondary)}", flush=True)

        result = DeepAnalysisResult(archetype=archetype)
        content_key = _content_hash(combined_content)

        # v6.0: SAGE is REQUIRED — fail fast if not available
        self._session_domain = ""
        self._sage_client = None
        try:
            from core.sage_client import SageClient
            sage = SageClient.get_instance()
            if not sage.health_check():
                raise RuntimeError(
                    "SAGE institutional memory is required. Run: docker compose up -d"
                )
            self._sage_client = sage
            self._session_domain = f"audit-session-{content_key}"
            print(f"   SAGE session: {self._session_domain}", flush=True)
            logger.info("SAGE session domain: %s", self._session_domain)
        except ImportError:
            raise RuntimeError(
                "SAGE institutional memory is required but sage-agent-sdk is not installed. "
                "Install with: pip install sage-agent-sdk"
            )
        except RuntimeError:
            raise
        except Exception as exc:
            raise RuntimeError(
                f"SAGE institutional memory is required but failed to connect: {exc}. "
                "Run: docker compose up -d"
            ) from exc

        # SAGE institutional memory — recall historical audit knowledge
        sage_context = self._build_sage_context(archetype)

        # Build file context header for LLM prompts
        file_context = _build_file_context_header(contract_files)

        # Build extra LLM context from AST data
        ast_context = ""
        if ast_data is not None:
            try:
                from core.solidity_ast import SolidityASTParser
                ast_parser = SolidityASTParser()
                ast_context = ast_parser.format_for_llm(ast_data)
            except Exception as e:
                logger.debug(f"AST context formatting failed: {e}")

        # Build extra LLM context from taint analysis
        taint_context = ""
        if taint_reports:
            try:
                from core.taint_analyzer import TaintAnalyzer
                ta = TaintAnalyzer()
                taint_summaries = []
                for report in taint_reports:
                    taint_summaries.append(ta.format_for_llm(report))
                taint_context = "\n".join(taint_summaries)
            except Exception as e:
                logger.debug(f"Taint context formatting failed: {e}")

        # Build CFG context from AST data (enhances Pass 2)
        cfg_context = ""
        if ast_data is not None:
            try:
                from core.solidity_ast import SolidityASTParser
                cfg_parser = SolidityASTParser()
                cfg_summaries = []
                for cdef in getattr(ast_data, 'contracts', []):
                    for func in getattr(cdef, 'functions', []):
                        body = getattr(func, 'body_source', '')
                        if body and len(body.strip()) > 10:
                            try:
                                cfg = cfg_parser.build_cfg(body)
                                if cfg.blocks and len(cfg.blocks) > 1:
                                    summary = cfg_parser.format_cfg_for_llm(cfg)
                                    cfg_summaries.append(
                                        f"### {cdef.name}.{func.name}()\n{summary}"
                                    )
                            except Exception:
                                pass
                if cfg_summaries:
                    cfg_context = "\n\n".join(cfg_summaries[:10])
            except Exception as e:
                logger.debug(f"CFG context building failed: {e}")

        # Resolve related contract sources for LLM context
        related_sources = []
        try:
            from core.cross_contract_analyzer import RelatedContractResolver
            resolver = RelatedContractResolver()
            # Separate target files from context-only files
            target_files = [cf for cf in contract_files if not cf.get('is_context_only', False)]
            related_sources = resolver.resolve_related_sources(
                target_files, contract_files,
                project_root=self._detect_project_root(contract_files),
            )
            if related_sources:
                names = [f"{s.name} ({s.relationship})" for s in related_sources[:8]]
                extra = f" (+{len(related_sources) - 8} more)" if len(related_sources) > 8 else ""
                print(f"📎 Found {len(related_sources)} related contracts: {', '.join(names)}{extra}", flush=True)
        except Exception as e:
            logger.debug(f"Related contract resolution failed: {e}")

        # Per-pass character budgets for related context
        related_budgets = {
            1: 200_000,    # Gemini Flash (2M ctx)
            2: 150_000,    # Gemini Flash (2M ctx)
            3: 100_000,    # Claude Sonnet (200K ctx)
            3.5: 80_000,   # Claude Sonnet (200K ctx) — highest value for cross-contract
            4: 50_000,     # GPT-4.1 (1M ctx) — summary only
            5: 0,          # One-liner reference only
        }

        # Truncate contract to fit within model context (keep first 300K chars)
        max_contract_chars = 300000
        truncated_content = combined_content
        if len(combined_content) > max_contract_chars:
            truncated_content = combined_content[:max_contract_chars] + "\n\n// [truncated for analysis]"
            print(f"   Truncated contract from {len(combined_content)} to {max_contract_chars} chars for LLM", flush=True)

        # Prepend file context to content for LLM awareness
        if file_context:
            truncated_content = f"{file_context}\n\n{truncated_content}"

        # --- Pass 1: Protocol Understanding ---
        pass1_model = _get_model_for_pass(1)
        logger.info(f"Pass 1: Using {pass1_model} (provider rotation)")
        print(f"   \U0001f4e1 Pass 1: {pass1_model}", flush=True)
        related_ctx_p1 = _build_related_context_section(
            related_sources, related_budgets.get(1, 0), full_source=True
        )
        pass1_prompt = _build_pass1_prompt(truncated_content, archetype,
                                           file_context=file_context,
                                           related_context=related_ctx_p1)
        if ast_context:
            pass1_prompt += f"\n\n{ast_context}"
        # SAGE: inject audit history for this archetype into Pass 1
        if sage_context:
            pass1_prompt += sage_context
        pass1_text = await self._run_pass(
            "Pass 1: Protocol Understanding",
            pass1_prompt,
            pass1_model,
            cache_key=f"p1_{content_key}" if not ast_context else None,
        )
        if pass1_text:
            result.pass_results.append(PassResult("protocol_understanding", pass1_text, model_used=pass1_model))
        else:
            print("⚠️  Pass 1 failed, continuing with reduced context", flush=True)
            pass1_text = "{}"

        # --- Pass 2: Attack Surface Mapping ---
        pass2_model = _get_model_for_pass(2)
        logger.info(f"Pass 2: Using {pass2_model} (provider rotation)")
        print(f"   \U0001f4e1 Pass 2: {pass2_model}", flush=True)
        related_ctx_p2 = _build_related_context_section(
            related_sources, related_budgets.get(2, 0), full_source=True
        )
        pass2_prompt = _build_pass2_prompt(truncated_content, pass1_text,
                                           related_context=related_ctx_p2)
        if taint_context:
            pass2_prompt += f"\n\n{taint_context}"
        if cfg_context:
            pass2_prompt += f"\n\n{cfg_context}"
        pass2_text = await self._run_pass(
            "Pass 2: Attack Surface Mapping",
            pass2_prompt,
            pass2_model,
            cache_key=f"p2_{content_key}" if not (taint_context or cfg_context) else None,
        )
        if pass2_text:
            result.pass_results.append(PassResult("attack_surface", pass2_text, model_used=pass2_model))
        else:
            print("⚠️  Pass 2 failed, continuing with reduced context", flush=True)
            pass2_text = "{}"

        # SAGE as primary knowledge source for checklists and exploit patterns.
        # Static knowledge base is the fallback when SAGE is unavailable.
        sage_checklist = self._recall_sage_checklist(archetype)
        if sage_checklist:
            checklist_text = sage_checklist
            print("   🧠 Using SAGE institutional memory for vulnerability checklist", flush=True)
        else:
            checklist_items = get_checklists_for_result(archetype)
            checklist_text = format_checklist_for_prompt(checklist_items)
            print("   📋 Using static checklist (SAGE unavailable)", flush=True)

        sage_exploit_text = self._recall_sage_exploit_patterns(archetype)
        if sage_exploit_text:
            exploit_text = sage_exploit_text
            print("   🧠 Using SAGE institutional memory for exploit patterns", flush=True)
        else:
            exploit_patterns = self.exploit_kb.get_for_archetypes(
                [archetype.primary] + archetype.secondary
            )
            exploit_text = self.exploit_kb.format_for_prompt(exploit_patterns, max_patterns=20)
            print("   📋 Using static exploit KB (SAGE unavailable)", flush=True)

        # --- Pass 3: Invariant Violation Analysis ---
        pass3_model = _get_model_for_pass(3)
        logger.info(f"Pass 3: Using {pass3_model} (provider rotation)")
        print(f"   \U0001f4e1 Pass 3: {pass3_model}", flush=True)
        related_ctx_p3 = _build_related_context_section(
            related_sources, related_budgets.get(3, 0), full_source=True
        )
        pass3_prompt_text = _build_pass3_prompt(
            truncated_content, pass1_text, pass2_text, checklist_text,
            file_context=file_context, related_context=related_ctx_p3,
        )
        pass3_findings, pass3_raw = await self._run_finding_pass_v6(
            "Pass 3: Invariant Violations",
            pass3_prompt_text,
            pass3_model,
            result,
        )

        # v6.0: Store Pass 3 session data in SAGE
        self._store_pass_session("pass3", pass3_raw, pass3_findings)

        # Format Pass 3 findings summary for subsequent passes
        p3_summary = self._summarize_findings(pass3_findings, "Invariant Analysis")

        # --- Pass 3.5: Cross-Contract Vulnerability Analysis ---
        # Only runs when multiple contracts are in scope
        cc_context_text = ""
        if len(contract_files) >= 2:
            try:
                from core.cross_contract_analyzer import InterContractAnalyzer
                cc_analyzer = InterContractAnalyzer()
                cc_context = cc_analyzer.analyze_relationships(contract_files)
                cc_context_text = cc_analyzer.format_for_llm(cc_context)

                if cc_context.relationships:
                    pass3_5_model = _get_model_for_pass(3)  # Same strong model as Pass 3
                    logger.info(f"Pass 3.5: Using {pass3_5_model} (cross-contract analysis)")
                    print(f"   \U0001f4e1 Pass 3.5: {pass3_5_model} (cross-contract)", flush=True)
                    related_ctx_p35 = _build_related_context_section(
                        related_sources, related_budgets.get(3.5, 0), full_source=True
                    )
                    # v6.0: Build session context from Pass 3
                    session_ctx_p35 = self._build_session_context("pass3.5")
                    pass3_5_findings, pass3_5_raw = await self._run_finding_pass_v6(
                        "Pass 3.5: Cross-Contract Vulnerabilities",
                        _build_pass3_5_prompt(
                            truncated_content, pass1_text, pass2_text,
                            p3_summary, cc_context_text,
                            related_context=related_ctx_p35,
                            session_context=session_ctx_p35,
                        ),
                        pass3_5_model,
                        result,
                    )
                    # v6.0: Store Pass 3.5 session data
                    self._store_pass_session("pass3.5", pass3_5_raw, pass3_5_findings)
                    if pass3_5_findings:
                        p3_5_summary = self._summarize_findings(
                            pass3_5_findings, "Cross-Contract Analysis"
                        )
                        # Append cross-contract findings to p3_summary for downstream passes
                        p3_summary = p3_summary + "\n\n" + p3_5_summary
                else:
                    print("   ℹ️  Pass 3.5: No cross-contract relationships detected, skipping", flush=True)
            except Exception as e:
                logger.warning(f"Pass 3.5 (cross-contract) failed: {e}")
                print(f"   ⚠️  Pass 3.5 failed: {e}", flush=True)
        else:
            logger.info("Pass 3.5: Skipped (single contract)")

        # --- Pass 4: Cross-Function Interaction ---
        pass4_model = _get_model_for_pass(4)
        logger.info(f"Pass 4: Using {pass4_model} (provider rotation)")
        print(f"   \U0001f4e1 Pass 4: {pass4_model}", flush=True)
        related_ctx_p4 = _build_related_context_section(
            related_sources, related_budgets.get(4, 0), full_source=True
        )
        # v6.0: Build session context from Pass 3 / 3.5
        session_ctx_p4 = self._build_session_context("pass4")
        pass4_prompt = _build_pass4_prompt(truncated_content, pass1_text, pass2_text,
                                           pass3_findings=p3_summary,
                                           cross_contract_context=cc_context_text,
                                           session_context=session_ctx_p4)
        if related_ctx_p4:
            pass4_prompt += f"\n{related_ctx_p4}"
        # SAGE: inject cross-function patterns from institutional memory
        sage_pass4 = self._recall_sage_cross_function_patterns(archetype)
        if sage_pass4:
            pass4_prompt += sage_pass4
        pass4_findings, pass4_raw = await self._run_finding_pass_v6(
            "Pass 4: Cross-Function Interactions",
            pass4_prompt,
            pass4_model,
            result,
        )

        # v6.0: Store Pass 4 session data
        self._store_pass_session("pass4", pass4_raw, pass4_findings)

        p4_summary = self._summarize_findings(pass4_findings, "Cross-Function Analysis")

        # --- Pass 5: Adversarial Modeling ---
        pass5_model = _get_model_for_pass(5)
        logger.info(f"Pass 5: Using {pass5_model} (provider rotation)")
        print(f"   \U0001f4e1 Pass 5: {pass5_model}", flush=True)
        # v6.0: Build session context from Pass 3 / 3.5 / 4
        session_ctx_p5 = self._build_session_context("pass5")
        pass5_prompt = _build_pass5_prompt(
            truncated_content, pass1_text, pass2_text,
            p3_summary, p4_summary, exploit_text,
            session_context=session_ctx_p5,
        )
        # Append one-liner related contract reference for Pass 5
        related_ref_p5 = _build_related_context_section(
            related_sources, budget_chars=0, full_source=False
        )
        if related_ref_p5:
            pass5_prompt += related_ref_p5
        # ML Feedback Loop: inject severity calibration warning if needed
        calibration_note = self._build_severity_calibration_note()
        if calibration_note:
            pass5_prompt += calibration_note
        # SAGE FP patterns are now included in exploit_text via _recall_sage_exploit_patterns
        pass5_findings, pass5_raw = await self._run_finding_pass_v6(
            "Pass 5: Adversarial Modeling",
            pass5_prompt,
            pass5_model,
            result,
        )

        # v6.0: Store Pass 5 session data
        self._store_pass_session("pass5", pass5_raw, pass5_findings)

        # v6.0: Resolve challenges and apply confirmation boosts
        result.all_findings = self._resolve_challenges(result.all_findings)

        result.total_duration = time.time() - start_time
        total_findings = len(result.all_findings)
        print(f"Deep analysis complete: {total_findings} findings in {result.total_duration:.1f}s "
              f"({len(result.pass_results)} passes)", flush=True)

        # SAGE: store audit learnings for future recall
        contract_name = contract_files[0].get("name", "unknown") if contract_files else "unknown"
        self._store_audit_learnings(result.all_findings, archetype, contract_name)

        return result

    @staticmethod
    def _detect_project_root(contract_files: List[Dict[str, Any]]) -> Optional[str]:
        """Detect project root by walking up from contract file paths."""
        markers = ('foundry.toml', 'hardhat.config.js', 'hardhat.config.ts',
                   'package.json', 'remappings.txt')
        for cf in contract_files:
            path = cf.get('path', '')
            if not path:
                continue
            current = os.path.dirname(os.path.abspath(path))
            for _ in range(5):
                for marker in markers:
                    if os.path.exists(os.path.join(current, marker)):
                        return current
                parent = os.path.dirname(current)
                if parent == current:
                    break
                current = parent
        return None

    async def _run_pass(self, name: str, prompt: str, model: str,
                        cache_key: Optional[str] = None) -> Optional[str]:
        """Run a single analysis pass and return the raw LLM response."""
        # Check pipeline time budget
        if hasattr(self, '_pipeline_start'):
            elapsed = time.time() - self._pipeline_start
            if elapsed > _PIPELINE_MAX_DURATION:
                print(f"   ⏱️  Pipeline time budget exceeded ({elapsed:.0f}s), skipping {name}", flush=True)
                return None

        # Check cache
        if cache_key and cache_key in self._cache:
            print(f"   📋 {name} (cached)", flush=True)
            return self._cache[cache_key]

        # Per-pass timeout: shorter for cheap models, longer for strong models
        is_cheap = any(tag in (model or '') for tag in ('flash', 'mini'))
        pass_timeout = _PASS_TIMEOUT_CHEAP if is_cheap else _PASS_TIMEOUT_STRONG

        print(f"   🔍 {name} ({model}, timeout {pass_timeout}s)...", flush=True)
        start = time.time()
        try:
            response = await asyncio.wait_for(
                self.llm._call_llm(prompt, model),
                timeout=pass_timeout,
            )
            duration = time.time() - start
            if response:
                print(f"   ✅ {name} done ({duration:.1f}s)", flush=True)
                if cache_key:
                    self._cache[cache_key] = response
                return response
            else:
                print(f"   ⚠️  {name} returned empty response", flush=True)
                return None
        except asyncio.TimeoutError:
            duration = time.time() - start
            print(f"   ⏱️  {name} timed out after {duration:.0f}s, skipping", flush=True)
            logger.warning(f"{name} timed out after {duration:.0f}s")
            return None
        except Exception as e:
            logger.warning(f"{name} failed: {e}")
            print(f"   ⚠️  {name} failed: {e}", flush=True)
            return None

    async def _run_finding_pass(self, name: str, prompt: str, model: str,
                                result: DeepAnalysisResult) -> List[Dict[str, Any]]:
        """Run a finding-producing pass, parse findings, and add to result."""
        response = await self._run_pass(name, prompt, model)
        if not response:
            return []

        findings = self._extract_findings(response, name)
        # Always record the pass so pass count is accurate
        result.pass_results.append(PassResult(name, response, findings, model))
        if findings:
            result.all_findings.extend(findings)
            print(f"   📊 {name}: {len(findings)} findings", flush=True)
        else:
            # Log response snippet for debugging extraction failures
            snippet = response[:200].replace('\n', ' ')
            logger.info(f"{name}: 0 findings extracted from {len(response)} char response (starts: {snippet}...)")
            print(f"   ⚠️  {name}: 0 findings extracted from LLM response", flush=True)
        return findings

    async def _run_finding_pass_v6(
        self, name: str, prompt: str, model: str, result: DeepAnalysisResult,
    ) -> tuple:
        """v6.0: Run a finding-producing pass and return (findings, raw_response).

        Same as _run_finding_pass but also returns the raw LLM response text
        so the caller can pass it to _store_pass_session for SAGE collaborative memory.
        """
        response = await self._run_pass(name, prompt, model)
        if not response:
            return [], ""

        findings = self._extract_findings(response, name)
        # Always record the pass so pass count is accurate
        result.pass_results.append(PassResult(name, response, findings, model))
        if findings:
            result.all_findings.extend(findings)
            print(f"   {name}: {len(findings)} findings", flush=True)
        else:
            snippet = response[:200].replace('\n', ' ')
            logger.info(f"{name}: 0 findings extracted from {len(response)} char response (starts: {snippet}...)")
            print(f"   {name}: 0 findings extracted from LLM response", flush=True)
        return findings, response

    def _extract_findings(self, response: str, pass_name: str) -> List[Dict[str, Any]]:
        """Extract findings from an LLM response, handling various JSON formats."""
        findings = []

        # Try parsing as JSON
        parsed = parse_llm_json(response)

        raw_findings = []
        if isinstance(parsed, dict) and parsed:
            # Check common keys where findings might live
            for key in ('findings', 'vulnerabilities', 'results', 'issues'):
                candidate = parsed.get(key, [])
                if isinstance(candidate, list) and candidate:
                    raw_findings = candidate
                    break
            # If the dict itself looks like a single finding, wrap it
            if not raw_findings and 'type' in parsed and 'severity' in parsed:
                raw_findings = [parsed]
        elif isinstance(parsed, list) and parsed:
            raw_findings = parsed

        if not raw_findings:
            # Try to find embedded JSON arrays in the response text (LLM sometimes
            # wraps findings in markdown or explanatory prose)
            import re
            array_match = re.search(r'\[\s*\{.*?\}\s*(?:,\s*\{.*?\}\s*)*\]', response, re.DOTALL)
            if array_match:
                try:
                    from core.json_utils import safe_json_parse
                    candidate_list = safe_json_parse(array_match.group(0), [])
                    if isinstance(candidate_list, list) and candidate_list:
                        raw_findings = candidate_list
                except Exception:
                    pass

        if not raw_findings:
            logger.debug(f"{pass_name}: no structured findings extracted from {len(response)} char response")

        for f in raw_findings:
            if isinstance(f, dict):
                # Normalize finding structure
                finding = {
                    'type': f.get('type', f.get('vulnerability_type', 'unknown')),
                    'vulnerability_type': f.get('type', f.get('vulnerability_type', 'unknown')),
                    'severity': f.get('severity', 'medium'),
                    'confidence': float(f.get('confidence', 0.5)),
                    'title': f.get('title', f.get('description', '')[:80]),
                    'description': f.get('description', ''),
                    'line': f.get('line', f.get('line_number', 0)),
                    'line_number': f.get('line', f.get('line_number', 0)),
                    'source': f'deep_analysis_{pass_name}',
                    'affected_functions': f.get('affected_functions', []),
                }
                # Preserve extra fields
                for key in ('attack_sequence', 'attack_steps', 'impact',
                            'precedent', 'proof_sketch', 'trigger',
                            'edge_case_category', 'attack_type',
                            'invariant_violated', 'capital_required',
                            'profit_estimate'):
                    if key in f:
                        finding[key] = f[key]
                # ML Feedback Loop: calibrate severity confidence from history
                self._calibrate_finding_severity(finding)
                findings.append(finding)

        return findings

    def _summarize_findings(self, findings: List[Dict[str, Any]], section_name: str) -> str:
        """Create a text summary of findings for use in subsequent passes."""
        if not findings:
            return f"## {section_name}\nNo findings from this analysis pass."

        lines = [f"## {section_name} ({len(findings)} findings)", ""]
        for i, f in enumerate(findings, 1):
            sev = f.get('severity', '?').upper()
            title = f.get('title', f.get('description', 'Unknown')[:80])
            lines.append(f"{i}. [{sev}] {title}")
            desc = f.get('description', '')
            if desc:
                lines.append(f"   {desc[:200]}")
            lines.append("")
        return "\n".join(lines)
