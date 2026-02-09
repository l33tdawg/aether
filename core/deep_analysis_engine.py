"""
Deep Analysis Engine — Multi-pass LLM analysis pipeline.

Replaces single-shot "find bugs" prompts with a structured 6-pass pipeline
that mirrors how professional auditors approach code review:

    Pass 1: Protocol Understanding  (cheap model)
    Pass 2: Attack Surface Mapping  (cheap model)
    Pass 3: Invariant Violation Analysis  (strong model)
    Pass 4: Cross-Function Interaction    (strong model)
    Pass 5: Adversarial Modeling           (strong model)
    Pass 6: Boundary & Edge Cases          (medium model)

Each pass receives accumulated context from prior passes.
Findings are collected from Passes 3-6.
"""

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
        return 'gemini-2.5-flash'
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
        return get_model_for_task('validation')
    except Exception:
        pass
    if os.getenv('GEMINI_API_KEY'):
        return 'gemini-2.5-flash'
    return 'gpt-4.1-mini-2025-04-14'


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

def _build_pass1_prompt(contract_content: str, archetype: ArchetypeResult) -> str:
    """Pass 1: Protocol Understanding."""
    archetype_hint = f"Detected archetype: {archetype.primary.value} (confidence: {archetype.confidence:.0%})"
    if archetype.secondary:
        archetype_hint += f"\nSecondary: {', '.join(a.value for a in archetype.secondary)}"

    return f"""You are a senior smart contract security auditor. Your task is to **understand** this protocol before looking for bugs.

{archetype_hint}

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


def _build_pass2_prompt(contract_content: str, pass1_result: str) -> str:
    """Pass 2: Attack Surface Mapping."""
    return f"""You are a senior smart contract security auditor mapping the attack surface of a protocol.

## Protocol Understanding (from prior analysis)
{pass1_result}

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
                        checklist_text: str) -> str:
    """Pass 3: Invariant Violation Analysis."""
    return f"""You are an elite smart contract security auditor. Your mission: systematically check every protocol invariant against every code path.

## Protocol Understanding
{pass1_result}

## Attack Surface
{pass2_result}

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
  ]
}}

Return ONLY findings that represent real vulnerabilities. Do NOT report informational items or best practice suggestions.
"""


def _build_pass4_prompt(contract_content: str, pass1_result: str, pass2_result: str) -> str:
    """Pass 4: Cross-Function Interaction Analysis."""
    return f"""You are an elite smart contract security auditor analyzing cross-function interactions.

## Protocol Understanding
{pass1_result}

## Attack Surface & State Dependencies
{pass2_result}

## Contract Code
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
  ]
}}
"""


def _build_pass5_prompt(contract_content: str, pass1_result: str, pass2_result: str,
                        pass3_findings: str, pass4_findings: str,
                        exploit_patterns: str) -> str:
    """Pass 5: Adversarial Modeling."""
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

## Required Output (JSON)
{{
  "findings": [
    {{
      "type": "attack model type (e.g. flash_loan_attack, price_manipulation, governance_attack)",
      "severity": "critical|high|medium",
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
      "impact": "maximum financial impact"
    }}
  ]
}}
"""


def _build_pass6_prompt(contract_content: str, pass2_result: str) -> str:
    """Pass 6: Boundary & Edge Case Analysis."""
    return f"""You are a smart contract auditor specializing in boundary conditions and edge cases.

## Attack Surface
{pass2_result}

## Contract Code
```solidity
{contract_content}
```

## Instructions

For EACH function in the attack surface, systematically check:

1. **First operation**: What happens on first deposit/mint/stake when state is empty? Division by zero? Zero denominator?
2. **Last operation**: What happens on last withdrawal when state goes to zero? Stuck funds?
3. **Zero values**: amount=0, price=0, supply=0, balance=0. Does anything break?
4. **Maximum values**: type(uint256).max, type(int256).min, type(int256).max. Overflow?
5. **Self-referential**: transfer to self, borrow against own collateral, swap token for same token
6. **Same-block operations**: deposit+withdraw, stake+unstake, borrow+repay in same transaction
7. **Callback reentrancy points**: ERC-777 hooks, ERC-1155 callbacks, flash loan callbacks, receive() fallback
8. **Empty/null inputs**: empty bytes, zero address, empty arrays

Focus on edge cases that cause:
- Division by zero
- Unexpected zero results (0 shares, 0 tokens)
- Integer overflow/underflow in unchecked blocks
- State corruption from unexpected input combinations
- Funds permanently locked

## Required Output (JSON)
{{
  "findings": [
    {{
      "type": "edge_case type (e.g. division_by_zero, empty_state, overflow, stuck_funds)",
      "severity": "critical|high|medium|low",
      "confidence": 0.0-1.0,
      "title": "concise title",
      "description": "detailed description of the edge case",
      "trigger": "exact input/state that triggers the issue",
      "affected_functions": ["func1"],
      "line": 0,
      "impact": "what happens when triggered",
      "edge_case_category": "first_operation|last_operation|zero_value|max_value|self_referential|same_block|callback|empty_input"
    }}
  ]
}}
"""


# ---------------------------------------------------------------------------
# Content hashing for caching
# ---------------------------------------------------------------------------

def _content_hash(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()[:16]


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

    async def analyze(
        self,
        combined_content: str,
        contract_files: List[Dict[str, Any]],
        static_results: Dict[str, Any],
    ) -> DeepAnalysisResult:
        """Run the full 6-pass deep analysis pipeline.

        Falls back gracefully if any individual pass fails.
        """
        start_time = time.time()

        # Detect archetype
        archetype = self.archetype_detector.detect(combined_content)
        print(f"🔍 Protocol archetype: {archetype.primary.value} (confidence: {archetype.confidence:.0%})", flush=True)
        if archetype.secondary:
            print(f"   Secondary: {', '.join(a.value for a in archetype.secondary)}", flush=True)

        result = DeepAnalysisResult(archetype=archetype)
        content_key = _content_hash(combined_content)

        # Truncate contract to fit within model context (keep first 300K chars)
        max_contract_chars = 300000
        truncated_content = combined_content
        if len(combined_content) > max_contract_chars:
            truncated_content = combined_content[:max_contract_chars] + "\n\n// [truncated for analysis]"
            print(f"   Truncated contract from {len(combined_content)} to {max_contract_chars} chars for LLM", flush=True)

        # --- Pass 1: Protocol Understanding ---
        pass1_text = await self._run_pass(
            "Pass 1: Protocol Understanding",
            _build_pass1_prompt(truncated_content, archetype),
            _get_cheap_model(),
            cache_key=f"p1_{content_key}",
        )
        if pass1_text:
            result.pass_results.append(PassResult("protocol_understanding", pass1_text, model_used=_get_cheap_model()))
        else:
            print("⚠️  Pass 1 failed, continuing with reduced context", flush=True)
            pass1_text = "{}"

        # --- Pass 2: Attack Surface Mapping ---
        pass2_text = await self._run_pass(
            "Pass 2: Attack Surface Mapping",
            _build_pass2_prompt(truncated_content, pass1_text),
            _get_cheap_model(),
            cache_key=f"p2_{content_key}",
        )
        if pass2_text:
            result.pass_results.append(PassResult("attack_surface", pass2_text, model_used=_get_cheap_model()))
        else:
            print("⚠️  Pass 2 failed, continuing with reduced context", flush=True)
            pass2_text = "{}"

        # Get archetype-specific checklist and exploit patterns
        checklist_items = get_checklists_for_result(archetype)
        checklist_text = format_checklist_for_prompt(checklist_items)

        exploit_patterns = self.exploit_kb.get_for_archetypes(
            [archetype.primary] + archetype.secondary
        )
        exploit_text = self.exploit_kb.format_for_prompt(exploit_patterns, max_patterns=20)

        # --- Pass 3: Invariant Violation Analysis ---
        pass3_findings = await self._run_finding_pass(
            "Pass 3: Invariant Violations",
            _build_pass3_prompt(truncated_content, pass1_text, pass2_text, checklist_text),
            _get_strong_model(),
            result,
        )

        # --- Pass 4: Cross-Function Interaction ---
        pass4_findings = await self._run_finding_pass(
            "Pass 4: Cross-Function Interactions",
            _build_pass4_prompt(truncated_content, pass1_text, pass2_text),
            _get_strong_model(),
            result,
        )

        # Format findings summaries for Pass 5
        p3_summary = self._summarize_findings(pass3_findings, "Invariant Analysis")
        p4_summary = self._summarize_findings(pass4_findings, "Cross-Function Analysis")

        # --- Pass 5: Adversarial Modeling ---
        pass5_findings = await self._run_finding_pass(
            "Pass 5: Adversarial Modeling",
            _build_pass5_prompt(truncated_content, pass1_text, pass2_text,
                                p3_summary, p4_summary, exploit_text),
            _get_strong_model(),
            result,
        )

        # --- Pass 6: Boundary & Edge Cases ---
        pass6_findings = await self._run_finding_pass(
            "Pass 6: Boundary & Edge Cases",
            _build_pass6_prompt(truncated_content, pass2_text),
            _get_medium_model(),
            result,
        )

        result.total_duration = time.time() - start_time
        total_findings = len(result.all_findings)
        print(f"✅ Deep analysis complete: {total_findings} findings in {result.total_duration:.1f}s "
              f"({len(result.pass_results)} passes)", flush=True)

        return result

    async def _run_pass(self, name: str, prompt: str, model: str,
                        cache_key: Optional[str] = None) -> Optional[str]:
        """Run a single analysis pass and return the raw LLM response."""
        # Check cache
        if cache_key and cache_key in self._cache:
            print(f"   📋 {name} (cached)", flush=True)
            return self._cache[cache_key]

        print(f"   🔍 {name} ({model})...", flush=True)
        start = time.time()
        try:
            response = await self.llm._call_llm(prompt, model)
            duration = time.time() - start
            if response:
                print(f"   ✅ {name} done ({duration:.1f}s)", flush=True)
                if cache_key:
                    self._cache[cache_key] = response
                return response
            else:
                print(f"   ⚠️  {name} returned empty response", flush=True)
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
        if findings:
            result.pass_results.append(PassResult(name, response, findings, model))
            result.all_findings.extend(findings)
            print(f"   📊 {name}: {len(findings)} findings", flush=True)
        return findings

    def _extract_findings(self, response: str, pass_name: str) -> List[Dict[str, Any]]:
        """Extract findings from an LLM response, handling various JSON formats."""
        findings = []

        # Try parsing as JSON
        parsed = parse_llm_json(response)
        if parsed:
            if isinstance(parsed, dict):
                raw_findings = parsed.get('findings', [])
            elif isinstance(parsed, list):
                raw_findings = parsed
            else:
                raw_findings = []

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
