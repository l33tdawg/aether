#!/usr/bin/env python3
"""
Validation Patterns Catalog

Documents known-safe Solidity patterns to help LLM-based validators
correctly identify and filter false positives.
"""

# SafeCast and Type Casting Patterns
SAFECAST_PATTERNS = {
    "bounded_uint_cast": {
        "description": "SafeCast.toUintXX() casts from uint256 to narrower uint types",
        "key_characteristic": "Intentionally REVERTS if value exceeds UintXX max, prevents silent overflow",
        "why_secure": [
            "Revert-on-overflow is a DoS mitigation, not a vulnerability",
            "Contract explicitly checks bounds before/after cast (e.g., maxSupply checks)",
            "Used for storage optimization while maintaining safety",
            "Solidity 0.8+ has checked arithmetic by default"
        ],
        "false_positive_indicators": [
            "Flagged as 'integer overflow' when cast prevents overflow",
            "Flagged as DoS when reverts are intentional design",
            "Missing context that maxSupply/entry-point validations exist"
        ],
        "example_safe_code": """
// SAFE: Cast is bounded and validated
uint96 safeAmount = SafeCast.toUint96(amount);
require(totalSupply + amount <= maxSupply(), "Max exceeded");
// Cast will revert if amount > 2^96-1, and maxSupply check ensures total fit
""",
        "swc_ids": ["SWC-101"],  # Integer Overflow/Underflow
        "common_findings": [
            "integer_overflow_underflow with description mentioning SafeCast and revert"
        ]
    },
    "type_narrowing_for_storage": {
        "description": "Narrowing uint256 to uint96/uint128 for storage packing or checkpoint compatibility",
        "why_secure": [
            "Explicitly designed to enforce a maximum value range",
            "Often paired with cap constants or validation checks",
            "Prevents accidental misuse of larger values",
            "Common in voting/delegation contracts (e.g., Checkpoints pattern)"
        ],
        "false_positive_indicators": [
            "Finding complains about precision loss when it's intentional",
            "Cast mentioned as vulnerability without understanding storage context"
        ]
    }
}

# Access Control Patterns
ACCESS_CONTROL_PATTERNS = {
    "inherited_modifiers": {
        "description": "Modifiers and access control defined in parent contracts cascade to child contracts",
        "key_characteristic": "onlyOwner, role-based checks, and other modifiers apply to inherited functions",
        "why_secure": [
            "Solidity inheritance applies modifiers transitively",
            "If parent has onlyOwner on mint(), child inherits that protection",
            "Auditors must check parent class, not assume functions are unprotected"
        ],
        "false_positive_indicators": [
            "Finding claims 'privileged function missing onlyOwner' when modifier is in parent",
            "Missing code_context showing parent contract's function definition",
            "Assumes vulnerability applies to contract when it only applies to inherited methods"
        ],
        "mitigation_check": "Look for:\n- Parent class definitions\n- OpenZeppelin Ownable, AccessControl\n- Role-based gating in parent's mint/recover functions"
    },
    "external_package_access_control": {
        "description": "Access control from @openzeppelin or @thesis packages is properly tested and maintained",
        "why_secure": [
            "Battle-tested implementations used by 1000s of projects",
            "Regular audits and security reviews",
            "Well-documented and widely understood patterns"
        ],
        "false_positive_indicators": [
            "ERC20WithPermit and MisfundRecovery flagged as 'expose privileged functions'",
            "No evidence shown of actual unprotected mint or recover calls",
            "Vulnerability description is generic rather than concrete"
        ]
    },
    "owner_is_multisig": {
        "description": "Owner is a multisig (e.g., Gnosis Safe) or timelock, not an EOA",
        "why_secure": [
            "Multisig or timelock eliminates single-point-of-failure for privileged operations",
            "Requires multiple signatures to execute sensitive functions",
            "Common governance model for tokens and protocols"
        ],
        "validation_approach": "Check if owner address is a known multisig or governance contract"
    }
}

# Validation Guidance
VALIDATION_GUIDANCE = {
    "integer_overflow_underflow": {
        "recheck_when_flagged": [
            "Is SafeCast used? -> Revert-on-overflow is intentional, NOT a bug",
            "Is there a supply cap check (maxSupply)? -> Bounds are enforced",
            "Is Solidity 0.8+? -> Has checked arithmetic by default",
            "Where is the vulnerability actually exploitable? -> LLM must describe concrete attack"
        ],
        "ask_yourself": "Can an attacker actually exploit this, or does the code prevent it?",
        "typical_false_positive": "SafeCast.toUint96() reverts if amount > 2^96-1, preventing overflow. This is secure by design."
    },
    "access_control": {
        "recheck_when_flagged": [
            "Is the function defined in THIS contract or inherited? -> Check parent class",
            "Does parent class have onlyOwner? -> Modifier applies transitively",
            "Is the function actually callable without permission? -> Must verify call paths",
            "Who is the owner (EOA vs multisig)? -> Multisig mitigates risk"
        ],
        "ask_yourself": "Is this function ACTUALLY unprotected, or does a parent class gate it?",
        "typical_false_positive": "Contract inherits MisfundRecovery.recover() from parent with onlyOwner, but finding claims it's unprotected."
    }
}

# Pattern-based false positive hints
FALSE_POSITIVE_PATTERNS = [
    {
        "keyword": "SafeCast.toUint96",
        "vulnerability_type": "integer_overflow_underflow",
        "reason": "SafeCast reverts on overflow; this is intentional overflow prevention, not a bug",
        "likely_false_positive": True
    },
    {
        "keyword": "integer_overflow_underflow",
        "description_contains": "reverts if values exceed",
        "reason": "Revert-on-overflow is a safety feature, not an exploitable condition",
        "likely_false_positive": True
    },
    {
        "keyword": "access_control",
        "description_contains": ["inherit", "MisfundRecovery", "ERC20WithPermit"],
        "reason": "Inherited functions often have modifiers in parent class; need to verify parent code",
        "investigate_further": True,
        "likely_false_positive": True  # Unless concrete evidence of unprotected call path
    },
    {
        "keyword": "access_control",
        "description_contains": "token rescue",
        "reason": "MisfundRecovery.recover() is typically onlyOwner; need to check parent",
        "investigate_further": True
    }
]

def get_pattern_context(vulnerability_type: str) -> str:
    """Get pattern guidance for a specific vulnerability type."""
    if vulnerability_type == "integer_overflow_underflow":
        return VALIDATION_GUIDANCE["integer_overflow_underflow"].get("ask_yourself", "")
    elif vulnerability_type == "access_control":
        return VALIDATION_GUIDANCE["access_control"].get("ask_yourself", "")
    return ""

def is_likely_false_positive(vulnerability_type: str, description: str, code_snippet: str = "") -> tuple[bool, str]:
    """Quick heuristic to flag likely false positives."""
    for pattern in FALSE_POSITIVE_PATTERNS:
        if pattern.get("keyword") in vulnerability_type.lower():
            desc_lower = description.lower()
            contains_items = pattern.get("description_contains", [])
            if isinstance(contains_items, str):
                contains_items = [contains_items]
            
            if any(item.lower() in desc_lower for item in contains_items):
                reason = pattern.get("reason", "Pattern match indicates likely false positive")
                return pattern.get("likely_false_positive", False), reason
    
    return False, ""
