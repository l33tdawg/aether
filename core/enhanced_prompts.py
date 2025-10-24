"""
Enhanced LLM Prompts with Mandatory Impact Validation.

This module provides improved prompts that require LLMs to:
1. Verify state impact before claiming fund/state vulnerabilities
2. Provide concrete attack scenarios
3. Check function context (view vs state-changing)
4. Prove exploitability
"""

from typing import Dict, Tuple

# Enhanced vulnerability analysis prompt with mandatory checks
ENHANCED_VULNERABILITY_ANALYSIS_PROMPT = """
You are a senior smart contract security auditor analyzing Solidity code for vulnerabilities.

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

ONLY REPORT if:
- exploitability_score >= 0.6
- attack_scenario has concrete steps
- state_impact matches claimed severity
- Finding would qualify for bug bounty submission

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

