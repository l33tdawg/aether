"""
Enhanced LLM Prompts with Mandatory Impact Validation.

This module provides improved prompts that require LLMs to:
1. Verify state impact before claiming fund/state vulnerabilities
2. Provide concrete attack scenarios
3. Check function context (view vs state-changing)
4. Prove exploitability
5. Analyze modifiers for validation (NEW Dec 2025)
6. Recognize intentional design patterns (NEW Dec 2025)
"""

from typing import Dict, Tuple

# Enhanced vulnerability analysis prompt with mandatory checks
ENHANCED_VULNERABILITY_ANALYSIS_PROMPT = """
You are a senior smart contract security auditor analyzing Solidity code for vulnerabilities.

**CRITICAL: MANDATORY MODIFIER ANALYSIS (NEW)**

Before reporting "missing validation" or "lacks input validation" findings:

1. **IDENTIFY ALL MODIFIERS** on the function:
   - List every modifier in the function signature
   - Example: `function foo(address _token) external onlyOwner onlyRegisteredToken(_token)`
   
2. **FIND AND ANALYZE MODIFIER DEFINITIONS**:
   - Locate each modifier's definition in the contract
   - Parse what require/revert statements it contains
   - Example: `onlyRegisteredToken` contains `require(registeredTokens[_token] != address(0))`
   
3. **MAP MODIFIER VALIDATION TO PARAMETERS**:
   - If modifier validates a parameter (e.g., `onlyRegisteredToken(_token)`), 
     that parameter IS validated - DO NOT report "missing validation"

**EXAMPLE OF WHAT NOT TO REPORT:**

```solidity
modifier onlyRegisteredToken(address _token) {
    require(registeredTokens[_token] != address(0), "not allowed");
    _;
}

function unlockToken(address _token) 
    external 
    onlyOwner 
    onlyRegisteredToken(_token)  // ← THIS VALIDATES _token!
{
    delete lockedTokens[_token];
}
```

DO NOT report "unlockToken lacks validation for _token" - the modifier handles it!

**INTENTIONAL DESIGN PATTERNS TO RECOGNIZE:**

These are NOT vulnerabilities:
1. `chargeWithoutEvent()` - Bridge liquidity function, intentionally permissionless
2. `notify()` / `poke()` / `sync()` - Permissionless state sync triggers
3. `receive()` / `fallback()` - ETH receivers, by design permissionless
4. Functions with comments like "for increasing the withdrawal limit"
5. Functions named with "Without" (e.g., chargeWithoutEvent) - intentional design

**CRITICAL: MANDATORY VERIFICATION CHECKLIST**

Before reporting ANY vulnerability, you MUST complete this verification checklist:

1. **State Impact Verification:**
   - [ ] Is this function view/pure? If YES, can it actually affect funds or state?
   - [ ] Does the function write to storage variables?
   - [ ] Does the function make external calls that could transfer value?
   - [ ] If read-only, acknowledge that the "vulnerability" cannot cause fund loss

2. **Attack Vector Proof:**
   - [ ] Describe a CONCRETE attack scenario with specific steps
   - [ ] Show: Attacker does X → System state changes to Y → Impact Z occurs
   - [ ] If you cannot construct a realistic attack, DO NOT report it

3. **Context Validation:**
   - [ ] Is this called only from protected functions? (If yes → not vulnerable)
   - [ ] Is this a getter returning data? (Missing validation may be intentional)
   - [ ] Is this in a library? (Check if caller enforces protections)
   - [ ] Is this constructor-only? (Not runtime exploitable)

4. **Severity Calibration:**
   - [ ] Can this lead to fund loss? → High/Critical
   - [ ] Can this lead to unauthorized access? → Medium/High
   - [ ] Can this lead to incorrect data returned? → Low (if view function)
   - [ ] Is this just "best practice"? → Don't report unless PROVEN security impact

**FUNCTION TYPE AWARENESS:**

Before reporting, determine the function type:
- **GETTER** (view/pure, starts with get/is/has): Returning empty data is acceptable, low severity
- **SETTER** (starts with set/update/configure): Parameter validation is critical
- **ACTION** (transfer/mint/burn/swap): High risk, needs thorough validation
- **INTERNAL/LIBRARY**: Check if ALL callers have protection

**REQUIRED OUTPUT FORMAT:**

Each vulnerability MUST include:

```json
{
  "vulnerability_type": "...",
  "severity": "critical|high|medium|low",
  "confidence": 0.0-1.0,
  "description": "...",
  "line": number,
  
  "function_type": "getter|setter|action|view|internal",
  "state_impact": "read-only|state-changing|critical",
  
  "attack_scenario": "
    1. Attacker does [specific action]
    2. This causes [specific state change]
    3. Impact: [specific consequence with fund amount if applicable]
  ",
  
  "why_not_false_positive": "
    - Caller protection: [checked - none found / not applicable]
    - State checks: [checked - none found]
    - Read-only: [no - function modifies state]
    - Protections verified: [list what was checked]
  ",
  
  "exploitability_score": 0.0-1.0  // Only report if >= 0.6
}
```

**FILTERING RULES:**

DO NOT REPORT if:
- Function is view/pure and impact claims fund/state changes
- Finding is "best practice" without proven exploit path
- Function is internal and ALL callers have access control
- Code is in constructor and has proper initializer
- Finding is about missing validation in getter (returning empty is OK)
- Attack scenario requires multiple unlikely conditions ("if X and Y and Z")
- Severity is high but function risk is low (misalignment)
- **Parameter is validated by a modifier** (e.g., onlyRegisteredToken validates _token)
- **Function is intentionally permissionless** (chargeWithoutEvent, notify, sync, etc.)
- **Function name indicates intentional design** (e.g., "WithoutEvent" suffix)
- **Comments explain the intentional design** (e.g., "for increasing withdrawal limit")

ONLY REPORT if:
- exploitability_score >= 0.6
- attack_scenario has concrete steps
- state_impact matches claimed severity
- Finding would qualify for bug bounty submission
- **You have verified all modifiers do NOT validate the parameter in question**
- **The function is NOT an intentional design pattern**

**EXPLOITABILITY ASSESSMENT:**

Before assigning severity, evaluate real-world exploitability:

NETWORK CHARACTERISTICS:
- Block time: Fast blocks (< 3 sec) make MEV harder; Slow blocks (> 12 sec) make it easier
- Mempool visibility: Private mempool = not exploitable via front-running
- MEV infrastructure: Flashbots/MEV-Boost presence affects front-running feasibility
- Gas costs: High gas chains reduce profitability threshold

ATTACK PREREQUISITES:
- Required capital: How much capital does attacker need? (Flash loan = low barrier, millions = high barrier)
- Transaction ordering: Atomic (1 tx) = easier; Multi-step (3+ tx) = harder
- External dependencies: Needs flash loan provider? Specific DEX? Oracle access?
- Profitability check: Attack profit > (gas cost + manipulation cost + flash loan fees)?

IMPACT CLASSIFICATION:
- FUND_DRAIN (direct theft/loss) → CRITICAL/HIGH severity
- PROFIT_REDUCTION (MEV/slippage reduces expected gains) → MEDIUM severity  
- UNFAVORABLE_RATE (bad price but recoverable) → MEDIUM severity
- GAS_WASTE (failed tx costs gas only) → LOW severity
- DOS (blocks function but no fund loss) → LOW-MEDIUM severity

ATTACK TYPE CLASSIFICATION:
- ATOMIC_FLASH_LOAN: Single transaction, borrower callback, same-block execution → HIGH exploitability
- TOCTOU/MEV: Off-chain calc + on-chain use, requires mempool visibility → MEDIUM exploitability
- FRONT_RUNNING: Requires tx observation, ordering control → MEDIUM exploitability (network-dependent)
- ORACLE_MANIPULATION: Requires persistent price control → LOW exploitability (capital intensive)

SEVERITY MULTIPLIERS:
- Fund drain on critical function = 1.0x (keep severity)
- Profit reduction (not drain) = 0.6x (downgrade HIGH → MEDIUM)
- Requires admin/governance = 0.5x (downgrade or mark as admin-only)
- Needs unrealistic conditions = 0.3x (likely false positive)

**CONTRACT TO ANALYZE:**

```solidity
{contract_code}
```

Return ONLY valid JSON array of vulnerabilities that pass all checks.
"""


# Enhanced false positive validation prompt
ENHANCED_FP_VALIDATION_PROMPT = """
You are validating whether a security finding is a true positive or false positive.

**MANDATORY VERIFICATION:**

1. **Function Capability Check:**
   Read the function code carefully:
   - Is it marked `view` or `pure`? → Cannot affect state/funds
   - Does it actually write to storage? → Look for assignments, push, pop, delete
   - Does it transfer tokens/ETH? → Look for transfer, transferFrom, call{value:}
   
2. **Claimed vs Actual Impact:**
   - What does the finding claim? (fund loss, state corruption, etc.)
   - What can the function actually do? (read data, modify state, transfer funds)
   - Do these match? If not → FALSE POSITIVE

3. **Protection Analysis:**
   - Are there modifiers? (onlyOwner, restricted, nonReentrant)
   - Are there require() checks protecting against the issue?
   - Is this only called from protected functions?
   
4. **Attack Plausibility:**
   - Can you execute the attack with realistic steps?
   - Does the attack require admin privileges? → Out of scope
   - Does the attack require hypothetical conditions? → Likely FP

**FINDING TO VALIDATE:**

Type: {vulnerability_type}
Severity: {severity}
Description: {description}
Code: {code_context}

**FUNCTION CONTEXT:**

{function_type_analysis}

**REQUIRED ANALYSIS:**

Return JSON:
```json
{
  "is_false_positive": true|false,
  "confidence": 0.0-1.0,
  "reasoning": "Detailed explanation",
  
  "verification_checklist": {
    "function_is_view": true|false,
    "function_writes_state": true|false,
    "function_transfers_funds": true|false,
    "claimed_impact_matches_capability": true|false,
    "has_protection": true|false,
    "attack_is_plausible": true|false
  },
  
  "final_assessment": "TRUE POSITIVE: [why] | FALSE POSITIVE: [why]"
}
```

BE RIGOROUS. Better to filter uncertain findings than submit false positives.
"""


# Pre-filtering heuristics (fast, before expensive LLM call)
def should_pre_filter(finding: Dict, function_context=None) -> Tuple[bool, str]:
    """
    Fast pre-filtering before LLM validation.
    
    Returns:
        (should_filter, reason)
    """
    
    vuln_type = finding.get('vulnerability_type', '').lower()
    description = finding.get('description', '').lower()
    severity = finding.get('severity', 'medium').lower()
    
    # Filter 1: High/Critical severity on view functions
    if function_context and function_context.is_view:
        if severity in ['high', 'critical']:
            fund_keywords = ['loss', 'theft', 'steal', 'drain', 'transfer']
            if any(kw in description for kw in fund_keywords):
                return (True, f"Claims {severity} fund impact on view function")
    
    # Filter 2: Reentrancy without external calls
    if 'reentrancy' in vuln_type:
        if function_context and not function_context.has_external_call:
            return (True, "Reentrancy finding but function makes no external calls")
    
    # Filter 3: Parameter validation on simple getters
    if 'parameter_validation' in vuln_type or 'input_validation' in vuln_type:
        if function_context and function_context.data_flow.value == 'getter':
            if function_context.state_impact.value == 'read-only':
                return (True, "Parameter validation on read-only getter (acceptable)")
    
    # Filter 4: Best practice without security impact
    if 'best_practice' in vuln_type and severity not in ['high', 'critical']:
        security_keywords = ['exploit', 'attack', 'loss', 'theft', 'unauthorized']
        if not any(kw in description for kw in security_keywords):
            return (True, "Best practice without proven security impact")
    
    # Filter 5: Info leaks in low-risk functions
    if 'info' in vuln_type or 'disclosure' in vuln_type or 'leak' in vuln_type:
        if severity not in ['critical', 'high']:
            if function_context and function_context.risk_level.value == 'low':
                return (True, "Information disclosure in low-risk function")
    
    return (False, "")


# Function to get enhanced analysis prompt
def get_enhanced_analysis_prompt(contract_code: str, context: Dict = None) -> str:
    """Get enhanced analysis prompt with mandatory checks."""
    return ENHANCED_VULNERABILITY_ANALYSIS_PROMPT.format(
        contract_code=contract_code
    )


# Function to get enhanced validation prompt
def get_enhanced_validation_prompt(vulnerability: Dict, function_analysis: str = "") -> str:
    """Get enhanced validation prompt."""
    return ENHANCED_FP_VALIDATION_PROMPT.format(
        vulnerability_type=vulnerability.get('vulnerability_type', 'unknown'),
        severity=vulnerability.get('severity', 'medium'),
        description=vulnerability.get('description', ''),
        code_context=vulnerability.get('code_snippet', ''),
        function_type_analysis=function_analysis
    )


# ============================================================================
# Zero-Day Vulnerability Patterns for Bounty-Paying Bugs
# ============================================================================

ZERO_DAY_VULNERABILITY_PATTERNS = """
## Critical Vulnerability Patterns (Bounty-Paying)

### 1. ERC-4626 Vault Inflation / First Depositor Attack
- **Pattern**: Vault without `_decimalsOffset()` or minimum deposit enforcement
- **What to look for**: `totalAssets()` returns 0 when vault is empty; no virtual shares/assets
- **Missing protection**: No `_decimalsOffset()` override, no minimum initial deposit, no virtual shares
- **Exploit**: Attacker deposits 1 wei, donates large amount directly, inflates share price so subsequent depositors get 0 shares
- **Code indicators**: `ERC4626` inheritance without `_decimalsOffset`, `deposit()` without minimum check

### 2. Read-Only Reentrancy
- **Pattern**: View functions returning stale state during external callbacks
- **What to look for**: `balanceOf()`, `totalSupply()`, `getReserves()` called by external protocols during state transitions
- **Missing protection**: No reentrancy guard on view functions, state updates AFTER external calls
- **Exploit**: During callback (e.g., ETH transfer), attacker calls view function that returns pre-update state, uses stale price in another protocol
- **Code indicators**: ETH transfers before state updates, `receive()` callbacks, external protocols reading contract state

### 3. Cross-Function Reentrancy
- **Pattern**: Multiple functions share state but have inconsistent reentrancy guards
- **What to look for**: Function A has `nonReentrant`, Function B modifies same state without it
- **Missing protection**: Inconsistent `nonReentrant` modifiers across functions sharing storage variables
- **Exploit**: During Function A callback, attacker calls unprotected Function B to manipulate shared state
- **Code indicators**: Multiple functions writing same storage, mixed `nonReentrant` usage

### 4. Rounding Direction Exploitation
- **Pattern**: Inconsistent `Math.Rounding.Up` vs `Down` in deposit/withdraw or mint/redeem
- **What to look for**: Deposits round DOWN (fewer shares), withdrawals also round DOWN (less assets returned)
- **Missing protection**: Protocol should round AGAINST the user (deposits DOWN, withdrawals DOWN for assets, UP for shares)
- **Exploit**: Repeated deposit/withdraw cycles extract value through consistent favorable rounding
- **Code indicators**: `mulDiv`, `Math.Rounding`, manual division without rounding direction consideration

### 5. Permit/Permit2 Frontrunning
- **Pattern**: `permit()` + `transferFrom()` without try/catch around permit
- **What to look for**: Function calls `permit()` then `transferFrom()` in sequence
- **Missing protection**: No try/catch around `permit()` call, no check if allowance already set
- **Exploit**: Attacker frontruns the permit transaction, causing the bundled permit+transfer to revert
- **Code indicators**: `IERC20Permit.permit()` followed by `transferFrom()` without error handling

### 6. Storage Collision in Proxies
- **Pattern**: Upgradeable contracts without `__gap` storage arrays
- **What to look for**: Base contracts in upgrade chain missing `uint256[50] __gap`
- **Missing protection**: No `__gap` arrays, new storage variables added in upgrades that collide
- **Exploit**: After upgrade, new variables overwrite existing storage, corrupting state
- **Code indicators**: `Initializable`, `UUPSUpgradeable` without `__gap` in base contracts

### 7. Returndata Bomb
- **Pattern**: Unbounded returndata copy from untrusted external calls
- **What to look for**: Low-level `call()` without limiting returndata, `abi.decode` on untrusted return
- **Missing protection**: No assembly-level returndata size check, no gas limit on call
- **Exploit**: Malicious contract returns massive returndata, consuming all remaining gas in memory expansion
- **Code indicators**: `address.call()` without `{gas: X}`, no `returndatasize()` check in assembly

### 8. Signature Replay Across Chains
- **Pattern**: Cached `DOMAIN_SEPARATOR` without runtime chainid check
- **What to look for**: `DOMAIN_SEPARATOR` set in constructor but not recomputed when `block.chainid` changes
- **Missing protection**: No `block.chainid` comparison in signature verification, no EIP-712 domain separator recomputation
- **Exploit**: After chain fork, signatures from original chain are valid on forked chain
- **Code indicators**: Immutable `DOMAIN_SEPARATOR`, `ecrecover` without chainid verification

### 9. First Depositor Share Manipulation in Pools
- **Pattern**: Liquidity pools where initial LP can manipulate share price
- **What to look for**: `totalSupply() == 0` branch in mint/deposit, no minimum liquidity lock
- **Missing protection**: No `MINIMUM_LIQUIDITY` burn (like Uniswap V2), no virtual reserves
- **Exploit**: First depositor provides tiny liquidity, manipulates price, extracts value from subsequent depositors
- **Code indicators**: No minimum liquidity constant, no dead shares, `totalSupply == 0` special case

### 10. Incorrect Fee-on-Transfer Token Handling
- **Pattern**: Balance assumptions without pre/post transfer checks
- **What to look for**: `transferFrom(sender, address(this), amount)` followed by accounting with `amount` instead of actual received
- **Missing protection**: No balance snapshot before/after transfer, no special handling for deflationary tokens
- **Exploit**: Protocol credits full `amount` but receives less due to transfer fee, creating bad debt
- **Code indicators**: `amount` used directly after `transferFrom` without `balanceOf` delta check
"""

# Focus area to pattern mapping for agent-specific injection
_FOCUS_AREA_PATTERNS = {
    'access_control': [3, 5, 6],        # Cross-function reentrancy, permit frontrunning, storage collision
    'reentrancy': [2, 3],               # Read-only reentrancy, cross-function reentrancy
    'amm': [1, 4, 9],                   # ERC-4626 inflation, rounding direction, first depositor
    'lending': [1, 4, 10],              # ERC-4626 inflation, rounding direction, fee-on-transfer
    'governance': [5, 6],               # Permit frontrunning, storage collision
    'external_calls': [2, 7, 8],        # Read-only reentrancy, returndata bomb, signature replay
    'delegatecall': [6, 7],             # Storage collision, returndata bomb
    'arithmetic': [4, 10],              # Rounding direction, fee-on-transfer
    'precision': [4, 10],               # Rounding direction, fee-on-transfer
    'logic_errors': [2, 3, 6],          # Read-only reentrancy, cross-function reentrancy, storage collision
    'privilege': [3, 5, 6],             # Cross-function reentrancy, permit frontrunning, storage collision
    'complex_logic': [1, 9, 5],         # ERC-4626 inflation, first depositor, permit frontrunning
    'economic': [1, 4, 9],              # ERC-4626 inflation, rounding direction, first depositor
    'oracle_manipulation': [2, 8],      # Read-only reentrancy, signature replay
    'overflow': [4, 10],                # Rounding direction, fee-on-transfer
    'underflow': [4, 10],               # Rounding direction, fee-on-transfer
    'precision_loss': [4, 10],          # Rounding direction, fee-on-transfer
    'cross_contract': [2, 3, 7],        # Read-only reentrancy, cross-function reentrancy, returndata bomb
    'economic_attacks': [1, 4, 9],      # ERC-4626 inflation, rounding direction, first depositor
    'invariant_violations': [1, 4, 9],  # ERC-4626 inflation, rounding direction, first depositor
}


def get_patterns_for_focus_areas(focus_areas: list) -> str:
    """Get relevant zero-day patterns for a set of focus areas.

    Args:
        focus_areas: List of focus area strings (e.g., ['access_control', 'reentrancy'])

    Returns:
        String containing relevant patterns from ZERO_DAY_VULNERABILITY_PATTERNS
    """
    if not focus_areas:
        return ZERO_DAY_VULNERABILITY_PATTERNS

    # Collect unique pattern numbers
    relevant_nums = set()
    for area in focus_areas:
        area_lower = area.lower().replace(' ', '_').replace('-', '_')
        if area_lower in _FOCUS_AREA_PATTERNS:
            relevant_nums.update(_FOCUS_AREA_PATTERNS[area_lower])

    if not relevant_nums:
        return ZERO_DAY_VULNERABILITY_PATTERNS

    # Parse patterns from the full text and filter
    lines = ZERO_DAY_VULNERABILITY_PATTERNS.strip().split('\n')
    result_lines = [lines[0], lines[1], '']  # Header

    current_pattern_num = 0
    include_current = False

    for line in lines[2:]:
        # Detect pattern headers like "### 1. ERC-4626..."
        if line.startswith('### ') and '. ' in line:
            try:
                num_str = line.split('### ')[1].split('.')[0].strip()
                current_pattern_num = int(num_str)
                include_current = current_pattern_num in relevant_nums
            except (ValueError, IndexError):
                include_current = False

        if include_current:
            result_lines.append(line)

    return '\n'.join(result_lines)


# ============================================================================
# Cross-Validation Prompt for Adversarial Agent Review
# ============================================================================

CROSS_VALIDATION_PROMPT = """You are reviewing another security auditor's finding. Your job is to determine if this is a REAL, EXPLOITABLE vulnerability or a false positive.

Be rigorous and skeptical. Many automated findings are false positives.

FINDING:
- Type: {finding_type}
- Severity: {severity}
- Line: {line}
- Description: {description}

RELEVANT CODE:
```solidity
{code_context}
```

FULL CONTRACT (for reference):
```solidity
{contract_content}
```

Analyze this finding and respond with valid JSON only:
{{
    "is_valid": true or false,
    "confidence": 0.0-1.0,
    "exploit_steps": "Step 1: ... Step 2: ... Step 3: ..." or "N/A if false positive",
    "false_positive_reason": "What protection/pattern makes this a false positive" or "N/A if valid",
    "reasoning": "Detailed explanation of your assessment"
}}

Return only valid JSON, no markdown formatting."""


# ============================================================================
# Cross-Contract Interaction Analysis Prompt
# ============================================================================

CROSS_CONTRACT_ANALYSIS_PROMPT = """You are analyzing interactions between multiple smart contracts for security vulnerabilities.

CONTRACTS AND THEIR INTERACTIONS:
{contracts_summary}

INTERACTION POINTS (external calls between contracts):
{interaction_points}

For each interaction point, analyze:
1. **Callback reentrancy**: Can the callee re-enter the caller during the call?
2. **State inconsistency**: Is the caller's state fully updated before the external call?
3. **Privilege assumptions**: Does contract A trust contract B's return values without verification?
4. **Cross-contract read-only reentrancy**: Can a view function return stale state during a callback?

Return findings as valid JSON only:
{{
    "findings": [
        {{
            "type": "vulnerability_type",
            "severity": "critical|high|medium|low",
            "confidence": 0.0-1.0,
            "description": "detailed explanation",
            "contracts_involved": ["ContractA.sol", "ContractB.sol"],
            "interaction_point": "function_name",
            "exploit_steps": "concrete step-by-step attack path",
            "why_not_false_positive": "specific reason this is exploitable",
            "affected_funds": "estimated impact or N/A"
        }}
    ]
}}

Return only valid JSON, no markdown formatting."""


# ============================================================================
# Deep-Dive Analysis Prompt
# ============================================================================

DEEP_DIVE_PROMPT = """You are performing a deep-dive security analysis on a specific vulnerability finding. Trace every code path thoroughly.

FINDING TO INVESTIGATE:
- Type: {finding_type}
- Severity: {severity}
- Line: {line}
- Initial Description: {description}
- Initial Confidence: {confidence}

FULL FUNCTION AND CALLED FUNCTIONS:
```solidity
{function_code}
```

FULL CONTRACT:
```solidity
{contract_content}
```

REQUIRED ANALYSIS:
1. **Complete code path trace**: Follow every branch, modifier, and internal call
2. **All state changes**: List every storage variable modified
3. **Concrete exploit with parameters**: Provide actual function call parameters for the attack
4. **Financial impact calculation**: Estimate the maximum extractable value
5. **Prerequisites check**: What conditions must be true for the exploit to work?

Return your analysis as valid JSON only:
{{
    "verified": true or false,
    "adjusted_severity": "critical|high|medium|low",
    "adjusted_confidence": 0.0-1.0,
    "code_path_trace": "Step-by-step trace through all code paths",
    "state_changes": ["var1: old -> new", "var2: old -> new"],
    "exploit_parameters": {{
        "function": "functionName",
        "args": ["arg1_value", "arg2_value"],
        "msg_value": "0 or amount in wei",
        "prerequisites": ["condition1", "condition2"]
    }},
    "financial_impact": "Maximum extractable value with calculation",
    "reasoning": "Detailed reasoning for verification/refutation"
}}

Return only valid JSON, no markdown formatting."""
