"""
Enhanced AI Ensemble Module for AetherAudit
Implements specialized agents with local consensus suitable for tests.
"""

import asyncio
import json
import sqlite3
import time
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
import logging
import hashlib

from core.database_manager import DatabaseManager, LearningPattern, AuditMetrics
from core.config_manager import ConfigManager
from core.json_utils import parse_llm_json

logger = logging.getLogger(__name__)

@dataclass
class ModelResult:
    """Result from a single AI model"""
    model_name: str
    findings: List[Dict[str, Any]]
    confidence: float
    processing_time: float
    metadata: Dict[str, Any]

@dataclass
class ConsensusResult:
    """Consensus result from multiple models"""
    consensus_findings: List[Dict[str, Any]]
    model_agreement: float
    confidence_score: float
    processing_time: float
    individual_results: List[ModelResult]

def _get_analysis_model() -> str:
    """Get the analysis model from config (supports mixed OpenAI/Gemini/Anthropic)."""
    try:
        from core.config_manager import get_model_for_task
        return get_model_for_task('analysis')
    except Exception:
        return 'gpt-5-mini'  # Fallback

class BaseAIModel:
    """Base class for specialized AI agents"""

    def __init__(self, agent_name: str, role: str, focus_areas: List[str], confidence_weight: float = 1.0):
        self.agent_name = agent_name
        self.role = role
        self.focus_areas = focus_areas
        self.confidence_weight = confidence_weight
        self.db_manager = DatabaseManager()
        self.config = ConfigManager()
    
    async def analyze_contract(self, contract_content: str, contract_path: str = "", context: Dict[str, Any] = None) -> ModelResult:
        """Analyze contract and return results with learning integration"""
        raise NotImplementedError
    
    def get_focus_areas(self) -> List[str]:
        """Get agent's focus areas"""
        return self.focus_areas

    # Model context limits (approximate chars, conservative)
    _MODEL_CONTEXT_LIMITS = {
        'gpt-5': 100000,
        'gpt-5-mini': 100000,
        'gpt-5-pro': 100000,
        'gpt-4o': 100000,
        'gpt-4': 24000,
        'gemini-2.5-flash': 800000,
        'gemini-2.5-pro': 800000,
        'gemini-2.0-flash': 800000,
        'gemini-1.5-pro': 800000,
        'claude-opus-4-6': 160000,
        'claude-sonnet-4-5': 160000,
        'claude-haiku-4-5': 160000,
    }

    def _smart_truncate(self, content: str, model_name: str = '') -> str:
        """Truncate content based on model's actual context limit."""
        # Find best matching limit
        limit = 16000  # Conservative default
        model_lower = model_name.lower() if model_name else ''
        for key, char_limit in self._MODEL_CONTEXT_LIMITS.items():
            if key in model_lower:
                limit = char_limit
                break
        # Reserve ~20% of context for prompt/response
        max_content = int(limit * 0.8)
        if len(content) <= max_content:
            return content
        return content[:max_content]

    def _validate_finding_schema(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Validate and filter findings that are missing required fields.

        Drops findings that lack exploit_steps or why_not_false_positive,
        as these indicate low-quality/generic findings.
        """
        validated = []
        for finding in findings:
            # Required fields for quality findings
            has_exploit = bool(finding.get('exploit_steps') or finding.get('exploit_scenario') or finding.get('attack_scenario'))
            has_fp_reason = bool(finding.get('why_not_false_positive') or finding.get('reasoning_chain'))

            # Always keep findings with basic required fields
            if finding.get('type') and finding.get('severity') and finding.get('description'):
                if has_exploit or has_fp_reason:
                    validated.append(finding)
                elif finding.get('confidence', 0) >= 0.8:
                    # High-confidence findings pass even without full schema
                    finding['needs_verification'] = True
                    validated.append(finding)
                else:
                    logger.debug(f"Dropped finding missing exploit_steps/why_not_false_positive: {finding.get('type')}")
            else:
                logger.debug(f"Dropped finding missing basic fields: {finding}")
        return validated

    def _get_persona_prompt(self) -> str:
        """Get the persona-specific system prompt"""
        raise NotImplementedError

    def _apply_learning_patterns(self, contract_content: str) -> Dict[str, Any]:
        """Apply learned patterns from database to improve analysis"""
        try:
            # Get relevant learning patterns for this agent's focus areas
            context_enhancements = {
                'learned_patterns': [],
                'confidence_adjustments': {},
                'focus_areas': self.focus_areas
            }

            for focus_area in self.focus_areas:
                # Compatibility: prefer get_learning_patterns(pattern_type=..)
                # Fallback: if missing, skip gracefully
                patterns = []
                try:
                    if hasattr(self.db_manager, 'get_learning_patterns'):
                        patterns = self.db_manager.get_learning_patterns(pattern_type=focus_area) or []
                except Exception:
                    patterns = []
                for pattern in patterns:
                    if pattern.get('success_rate', 0) > 0.7:  # Only use high-confidence patterns
                        context_enhancements['learned_patterns'].append({
                            'type': pattern.get('pattern_type', ''),
                            'original': pattern.get('original_classification', ''),
                            'corrected': pattern.get('corrected_classification', ''),
                            'confidence_threshold': pattern.get('confidence_threshold', 0.8),
                            'reasoning': pattern.get('reasoning', '')
                        })

            return context_enhancements
        except Exception as e:
            logger.warning(f"Failed to apply learning patterns: {e}")
            return {'learned_patterns': [], 'confidence_adjustments': {}, 'focus_areas': self.focus_areas}

    def _store_analysis_result(self, result: ModelResult, contract_hash: str):
        """Store analysis result for learning"""
        try:
            # Store metrics for this analysis
            metrics = AuditMetrics(
                id=f"ensemble_{self.agent_name}_{int(time.time())}",
                audit_result_id=contract_hash,
                total_findings=len(result.findings),
                confirmed_findings=0,  # Will be updated later
                false_positives=0,
                accuracy_score=result.confidence,
                precision_score=0.0,
                recall_score=0.0,
                f1_score=0.0,
                execution_time=result.processing_time,
                llm_calls=1,
                cache_hits=0,
                created_at=time.time()
            )
            # Compatibility: prefer store_audit_metrics; fallback to save_audit_metrics
            if hasattr(self.db_manager, 'store_audit_metrics'):
                self.db_manager.store_audit_metrics(metrics)
            elif hasattr(self.db_manager, 'save_audit_metrics'):
                self.db_manager.save_audit_metrics(metrics)
            else:
                raise AttributeError("DatabaseManager missing audit metrics methods")
        except Exception as e:
            logger.warning(f"Failed to store analysis result: {e}")


class DeFiSecurityExpert(BaseAIModel):
    """DeFi Protocol Security Expert - Focuses on DeFi-specific vulnerabilities"""

    def __init__(self):
        super().__init__(
            agent_name="defi_expert",
            role="DeFi Protocol Security Expert",
            focus_areas=["defi", "flash_loans", "yield_farming", "dex", "lending", "staking"]
        )

    def _get_persona_prompt(self) -> str:
        return """You are a **DeFi Protocol Security Expert** with deep expertise in decentralized finance vulnerabilities.

**Your Mission:** Identify REAL, EXPLOITABLE DeFi-specific security risks that could lead to fund losses or protocol exploits.

**CRITICAL: MANDATORY ANALYSIS PROCESS (Follow Every Step)**

For EVERY potential finding, you MUST complete this reasoning chain:

1. **IDENTIFY** - What vulnerability pattern did you spot?

2. **CHECK FOR PROTECTIONS** - Does the contract have:
   - Bounds checks or sanity limits?
   - Access controls (onlyOwner, roles, modifiers)?
   - Timeout mechanisms or staleness checks?
   - Validation logic or require statements?
   - Circuit breakers or pause functionality?
   
3. **VERIFY DATA SOURCE** (Critical for oracle/price issues):
   - **Off-chain oracle** (e.g., AggregatorV3Interface, Chainlink, Pyth) → Aggregated from multiple sources, CANNOT be manipulated by flash loans
   - **On-chain spot price** (e.g., IUniswapV2Pair.getReserves, balanceOf ratios) → CAN be manipulated within same block
   - **Time-weighted average** (TWAP, observe()) → Resistant to single-block manipulation
   
4. **PROVE EXPLOITABILITY** - Write concrete attack steps:
   - Step 1: Attacker does X
   - Step 2: This causes Y
   - Step 3: Attacker profits Z
   - Why existing protections DON'T prevent this
   
5. **CONFIDENCE CHECK** - Only report if confidence >= 0.85

**COMMON FALSE POSITIVE PATTERNS TO AVOID:**
- Claims of "oracle manipulation" on off-chain oracles (Chainlink, etc.) → These are NOT vulnerable to flash loans
- Flagging inherited access controls without checking parent contracts
- Reporting intentional design features as vulnerabilities (check code comments)
- Theoretical issues with no practical exploit path
- Gas optimizations (these are NOT security vulnerabilities)
- **Standard OpenZeppelin proxy patterns (ERC1967Proxy, TransparentUpgradeableProxy, BeaconProxy) → These are AUDITED, BATTLE-TESTED patterns**
- **Proxy upgrade controls via ProxyAdmin → This is INTENTIONAL design, not a vulnerability**
- **Constructor initialization with delegatecall in proxies → Standard proxy initialization pattern, executes ONLY ONCE during deployment**
- **Admin/owner controls on upgradeable contracts → These are GOVERNANCE decisions, not code vulnerabilities**
- **Deployment-time configuration → If it only happens in constructor, it's deployer-controlled by design**
- **Trust assumptions in proxy patterns → Inherent to upgradeable architecture, not exploitable bugs**

**CRITICAL: PROXY PATTERN DETECTION**
Before reporting ANY finding related to:
- upgradeability_admin_key_risk
- delegatecall_initialization_payload_risk  
- storage_slot_conflict_risk
- admin/owner privilege concerns
- proxy upgrade mechanisms

CHECK IF:
1. Is this standard OpenZeppelin code? (Check imports for @openzeppelin)
2. Does the issue exist in deployed contract or just in library code?
3. Is this a deployment decision (who becomes owner) vs actual code bug?
4. Can this be exploited AFTER deployment without compromising the admin?

If it's standard OpenZeppelin proxy code working as designed → DO NOT REPORT IT.

**OUTPUT FORMAT:** JSON array with reasoning chain"""

    async def analyze_contract(self, contract_content: str, contract_path: str = "", context: Dict[str, Any] = None) -> ModelResult:
        """Analyze contract from DeFi security perspective"""
        start_time = time.time()

        try:
            # Apply learning patterns
            learning_context = self._apply_learning_patterns(contract_content)

            # Create contract hash for tracking
            contract_hash = hashlib.md5(contract_content.encode()).hexdigest()

            # Build specialized prompt
            prompt = f"""
{self._get_persona_prompt()}

**CONTRACT TO ANALYZE:**
```solidity
{contract_content}
```

**LEARNING CONTEXT:**
{json.dumps(learning_context, indent=2)}

**REQUIRED OUTPUT:**
Return a JSON array of vulnerabilities found. Each finding MUST include:
- type: Specific vulnerability type (e.g., "flash_loan_arbitrage", "oracle_manipulation")
- severity: "low" | "medium" | "high" | "critical"
- confidence: 0.85-1.0 (ONLY report if >= 0.85)
- description: Detailed explanation of the vulnerability
- line: Approximate line number (or -1 if unclear)
- swc_id: Relevant SWC ID if applicable
- exploit_scenario: Step-by-step concrete attack path
- defi_impact: Potential financial impact on users/protocol
- mitigation: How to fix this issue
- reasoning_chain: {{
    "pattern_identified": "what pattern you spotted",
    "protections_checked": ["list of protections you verified"],
    "data_source_type": "off_chain|on_chain|twap|n/a",
    "exploit_proof": "concrete attack steps proving it's exploitable",
    "why_not_protected": "why existing protections don't prevent this"
  }}

ONLY report findings with confidence >= 0.85 and complete reasoning chains.
If you cannot prove exploitability, DO NOT report it.
"""

            # Get OpenAI API key - check multiple sources for robustness
            import os
            api_key = os.getenv("OPENAI_API_KEY")  # First check environment variable
            
            if not api_key:
                # Fall back to config manager
                api_key = self.config.config.openai_api_key
            
            if not api_key:
                raise Exception("OpenAI API key not found in environment (OPENAI_API_KEY) or config file (~/.aether/config.yaml)")

            # Call GPT-5-pro for better DeFi analysis
            import openai
            client = openai.OpenAI(api_key=api_key)

            try:
                response = client.chat.completions.create(
                    model=_get_analysis_model(),
                    messages=[
                        {"role": "system", "content": self._get_persona_prompt()},
                        {"role": "user", "content": prompt}
                    ],
                    max_completion_tokens=4000
                )
            except Exception as e:
                # Fallback to gpt-4o if gpt-5-pro fails
                if 'model_not_found' in str(e).lower() or 'not available' in str(e).lower():
                    response = client.chat.completions.create(
                        model="gpt-4o",
                        messages=[
                            {"role": "system", "content": self._get_persona_prompt()},
                            {"role": "user", "content": prompt}
                        ],
                        max_tokens=2000
                    )
                else:
                    raise

            # Parse response
            response_text = response.choices[0].message.content
            logger.debug(f"DeFi Expert raw response length: {len(response_text)}")
            findings = self._parse_defi_findings(response_text)

            processing_time = time.time() - start_time

            result = ModelResult(
                model_name=self.agent_name,
                findings=findings,
                confidence=0.85,
                processing_time=processing_time,
                metadata={
                    "role": self.role,
                    "focus_areas": self.focus_areas,
                    "learning_patterns_applied": len(learning_context.get('learned_patterns', [])),
                    "contract_hash": contract_hash
                }
            )

            # Store result for learning
            self._store_analysis_result(result, contract_hash)

            return result

        except Exception as e:
            logger.error(f"DeFi Expert failed: {e}")
            processing_time = time.time() - start_time

            error_msg = str(e)
            if 'OPENAI_API_KEY' in error_msg or 'api_key' in error_msg.lower():
                logger.warning(f"⚠️  API Key Issue: {error_msg}")
                print(f"⚠️  DeFi Expert failed - API Key not configured: {error_msg}")
            
            return ModelResult(
                model_name=self.agent_name,
                findings=[],
                confidence=0.0,
                processing_time=processing_time,
                metadata={"error": str(e), "role": self.role}
            )

    def _parse_defi_findings(self, response: str) -> List[Dict[str, Any]]:
        """Parse DeFi-specific findings from LLM response"""
        try:
            # Use the robust parse_llm_json utility instead of naive regex
            data = parse_llm_json(response, fallback={"findings": []})
            logger.debug(f"DeFi Expert parsed {len(data) if isinstance(data, list) else len(data.get('findings', []))} findings")
            
            # Handle both formats: direct array or object with findings key
            if isinstance(data, list):
                return data
            
            findings = data.get('findings', []) if isinstance(data, dict) else []
            if isinstance(findings, list):
                return findings
            return []
        except Exception as e:
            logger.error(f"Failed to parse DeFi findings: {e}")
            return []


class GasOptimizationExpert(BaseAIModel):
    """Gas Optimization Expert - Focuses on gas efficiency and optimization opportunities"""

    def __init__(self):
        super().__init__(
            agent_name="gas_expert",
            role="Gas Optimization Expert",
            focus_areas=["gas_optimization", "efficiency", "storage", "computation"]
        )

    def _get_persona_prompt(self) -> str:
        return """You are a **Gas Optimization Expert** specializing in Ethereum gas efficiency and smart contract optimization.

**IMPORTANT: Gas optimizations are NOT security vulnerabilities. They are performance improvements.**

**Your Mission:** Identify SIGNIFICANT gas inefficiencies that can meaningfully reduce transaction costs.

**CRITICAL: MANDATORY ANALYSIS PROCESS**

For EVERY potential optimization:

1. **IDENTIFY** - What inefficiency did you spot?

2. **CALCULATE IMPACT** - Estimate realistic gas savings:
   - High impact: 1000+ gas saved per transaction
   - Medium impact: 200-1000 gas saved per transaction  
   - Low impact: < 200 gas saved per transaction
   
3. **VERIFY NOT INTENTIONAL** - Check if the pattern is:
   - Part of an external library/standard (OpenZeppelin, etc.)
   - Intentional for readability/safety
   - Required by an interface or standard
   
4. **ASSESS COMPLEXITY** - Implementation difficulty:
   - Low: Simple change, no logic impact
   - Medium: Moderate refactoring needed
   - High: Significant restructuring required
   
5. **CONFIDENCE CHECK** - Only report if confidence >= 0.8 AND gas savings >= 200

**AVOID REPORTING:**
- Micro-optimizations saving < 50 gas
- Optimizations in external libraries you can't control
- Changes that harm readability for minimal gas savings
- Already optimized patterns (e.g., existing use of immutable, cached storage reads)

**OUTPUT FORMAT:** JSON array of gas optimization opportunities (NOT vulnerabilities)"""

    async def analyze_contract(self, contract_content: str, contract_path: str = "", context: Dict[str, Any] = None) -> ModelResult:
        """Analyze contract for gas optimization opportunities"""
        start_time = time.time()

        try:
            learning_context = self._apply_learning_patterns(contract_content)
            contract_hash = hashlib.md5(contract_content.encode()).hexdigest()

            prompt = f"""
{self._get_persona_prompt()}

**CONTRACT TO ANALYZE:**
```solidity
{contract_content}
```

**LEARNING CONTEXT:**
{json.dumps(learning_context, indent=2)}

**REQUIRED OUTPUT:**
Return a JSON array of gas optimization opportunities. Each optimization MUST include:
- type: "gas_optimization"
- severity: "low" | "medium" | "high" (based on savings: high=1000+, medium=200-1000, low=<200)
- confidence: 0.8-1.0 (ONLY report if >= 0.8)
- description: What can be optimized
- line: Line number where optimization applies
- gas_savings_estimate: "~X-Y gas per call" (be specific)
- implementation_complexity: "low" | "medium" | "high"
- optimization_details: Technical details of the optimization
- code_suggestion: Suggested code changes
- reasoning_chain: {{
    "inefficiency_identified": "what pattern is inefficient",
    "gas_calculation": "how you calculated the savings",
    "not_intentional_because": "why this isn't intentional design",
    "implementation_impact": "what needs to change"
  }}

ONLY report optimizations with:
- confidence >= 0.8
- gas savings >= 200 per transaction
- practical implementation path

If optimization saves < 200 gas or is in external library, DO NOT report it.
"""

            # Get OpenAI API key - check multiple sources for robustness
            import os
            api_key = os.getenv("OPENAI_API_KEY")  # First check environment variable
            
            if not api_key:
                # Fall back to config manager
                api_key = self.config.config.openai_api_key
            
            if not api_key:
                raise Exception("OpenAI API key not found in environment (OPENAI_API_KEY) or config file (~/.aether/config.yaml)")

            import openai
            client = openai.OpenAI(api_key=api_key)

            try:
                response = client.chat.completions.create(
                    model=_get_analysis_model(),
                    messages=[
                        {"role": "system", "content": self._get_persona_prompt()},
                        {"role": "user", "content": prompt}
                    ],
                )
            except Exception as e:
                # Fallback to gpt-4o if gpt-5-pro fails
                if 'model_not_found' in str(e).lower() or 'not available' in str(e).lower():
                    response = client.chat.completions.create(
                        model="gpt-4o",
                        messages=[
                            {"role": "system", "content": self._get_persona_prompt()},
                            {"role": "user", "content": prompt}
                        ],
                        max_tokens=2000
                    )
                else:
                    raise

            response_text = response.choices[0].message.content
            logger.debug(f"Gas Expert raw response length: {len(response_text)}")
            findings = self._parse_gas_findings(response_text)

            processing_time = time.time() - start_time

            result = ModelResult(
                model_name=self.agent_name,
                findings=findings,
                confidence=0.85,
                processing_time=processing_time,
                metadata={
                    "role": self.role,
                    "focus_areas": self.focus_areas,
                    "learning_patterns_applied": len(learning_context.get('learned_patterns', [])),
                    "contract_hash": contract_hash
                }
            )

            self._store_analysis_result(result, contract_hash)
            return result

        except Exception as e:
            logger.error(f"Gas Expert failed: {e}")
            processing_time = time.time() - start_time

            error_msg = str(e)
            if 'OPENAI_API_KEY' in error_msg or 'api_key' in error_msg.lower():
                logger.warning(f"⚠️  API Key Issue: {error_msg}")
                print(f"⚠️  Gas Expert failed - API Key not configured: {error_msg}")
            
            return ModelResult(
                model_name=self.agent_name,
                findings=[],
                confidence=0.0,
                processing_time=processing_time,
                metadata={"error": str(e), "role": self.role}
            )

    def _parse_gas_findings(self, response: str) -> List[Dict[str, Any]]:
        """Parse gas optimization findings from LLM response"""
        try:
            # Use the robust parse_llm_json utility instead of naive regex
            data = parse_llm_json(response, fallback=[])
            logger.debug(f"Gas Expert parsed {len(data) if isinstance(data, list) else len(data.get('findings', []))} findings")
            if isinstance(data, list):
                return data
            findings = data.get('findings', []) if isinstance(data, dict) else []
            if isinstance(findings, list):
                return findings
            return []
        except Exception as e:
            logger.error(f"Failed to parse gas findings: {e}")
            return []


class SecurityBestPracticesExpert(BaseAIModel):
    """Security Best Practices Expert - Focuses on code quality and security standards"""

    def __init__(self):
        super().__init__(
            agent_name="best_practices_expert",
            role="Security Best Practices Expert",
            focus_areas=["code_quality", "security_standards", "access_control", "input_validation"]
        )

    def _get_persona_prompt(self) -> str:
        return """You are a **Security Best Practices Expert** focused on SECURITY-IMPACTING code quality issues.

**Your Mission:** Identify code quality issues that have REAL security implications, not just style preferences.

**CRITICAL: MANDATORY ANALYSIS PROCESS**

For EVERY potential finding:

1. **IDENTIFY** - What best practice deviation did you spot?

2. **CHECK INHERITED PROTECTIONS** - Does the contract inherit security from:
   - Parent contracts (OpenZeppelin Ownable, AccessControl, etc.)?
   - Libraries that provide the protection?
   - Framework-level guarantees?
   
3. **VERIFY SECURITY IMPACT** - Can this actually lead to:
   - Unauthorized access?
   - Fund loss?
   - State manipulation?
   - Denial of service?
   
4. **PROVE IT'S A PROBLEM** - Show concrete scenario where this causes issues:
   - Not just "could be better"
   - Actual security/safety impact
   - Not covered by inherited protections
   
5. **CONFIDENCE CHECK** - Only report if confidence >= 0.85

**AVOID GENERIC CLAIMS:**
- "Missing access control" without checking parent contracts
- "Needs input validation" without proving it's exploitable
- "Poor error handling" without showing actual risk
- "Missing documentation" (not a security issue)
- Style/preference issues with no security impact

**OUTPUT FORMAT:** JSON array of security-impacting best practice issues (NOT style preferences)"""

    async def analyze_contract(self, contract_content: str, contract_path: str = "", context: Dict[str, Any] = None) -> ModelResult:
        """Analyze contract for security best practices"""
        start_time = time.time()

        try:
            learning_context = self._apply_learning_patterns(contract_content)
            contract_hash = hashlib.md5(contract_content.encode()).hexdigest()

            prompt = f"""
{self._get_persona_prompt()}

**CONTRACT TO ANALYZE:**
```solidity
{contract_content}
```

**LEARNING CONTEXT:**
{json.dumps(learning_context, indent=2)}

**REQUIRED OUTPUT:**
Return a JSON array of best practice issues. Each finding MUST include:
- type: "best_practice_violation"
- severity: "low" | "medium" | "high" (NO "info" - must have security impact)
- confidence: 0.85-1.0 (ONLY report if >= 0.85)
- description: What best practice is being violated
- line: Line number where issue occurs
- standard: Relevant standard (SWC-XXX, best practice name)
- impact: CONCRETE security impact (not "maintainability")
- recommendation: How to fix or improve
- reasoning_chain: {{
    "deviation_identified": "what best practice is violated",
    "inherited_protections_checked": ["what parent contracts/libraries were checked"],
    "security_impact_proof": "concrete scenario showing security risk",
    "why_not_protected": "why existing code doesn't prevent this"
  }}

ONLY report findings with:
- confidence >= 0.85
- ACTUAL security impact (not style/maintainability)
- Proof that inherited protections don't cover it

If issue is style/documentation/preference with no security impact, DO NOT report it.
"""

            # Get OpenAI API key - check multiple sources for robustness
            import os
            api_key = os.getenv("OPENAI_API_KEY")  # First check environment variable
            
            if not api_key:
                # Fall back to config manager
                api_key = self.config.config.openai_api_key
            
            if not api_key:
                raise Exception("OpenAI API key not found in environment (OPENAI_API_KEY) or config file (~/.aether/config.yaml)")

            import openai
            client = openai.OpenAI(api_key=api_key)

            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": self._get_persona_prompt()},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=2000
                # Removed temperature - using default value for compatibility
            )

            response_text = response.choices[0].message.content
            logger.debug(f"Best Practices Expert raw response length: {len(response_text)}")
            findings = self._parse_best_practices_findings(response_text)

            processing_time = time.time() - start_time

            result = ModelResult(
                model_name=self.agent_name,
                findings=findings,
                confidence=0.85,
                processing_time=processing_time,
                metadata={
                    "role": self.role,
                    "focus_areas": self.focus_areas,
                    "learning_patterns_applied": len(learning_context.get('learned_patterns', [])),
                    "contract_hash": contract_hash
                }
            )

            self._store_analysis_result(result, contract_hash)
            return result

        except Exception as e:
            logger.error(f"Best Practices Expert failed: {e}")
            processing_time = time.time() - start_time

            error_msg = str(e)
            if 'OPENAI_API_KEY' in error_msg or 'api_key' in error_msg.lower():
                logger.warning(f"⚠️  API Key Issue: {error_msg}")
                print(f"⚠️  Best Practices Expert failed - API Key not configured: {error_msg}")
            
            return ModelResult(
                model_name=self.agent_name,
                findings=[],
                confidence=0.0,
                processing_time=processing_time,
                metadata={"error": str(e), "role": self.role}
            )

    def _parse_best_practices_findings(self, response: str) -> List[Dict[str, Any]]:
        """Parse best practices findings from LLM response"""
        try:
            # Use the robust parse_llm_json utility instead of naive regex
            data = parse_llm_json(response, fallback=[])
            logger.debug(f"Best Practices Expert parsed {len(data) if isinstance(data, list) else len(data.get('findings', []))} findings")
            
            # Handle both formats: direct array or object with findings key
            if isinstance(data, list):
                return data
            
            findings = data.get('findings', []) if isinstance(data, dict) else []
            if isinstance(findings, list):
                return findings
            return []
        except Exception as e:
            logger.error(f"Failed to parse best practices findings: {e}")
            return []


# Phase 3 test-friendly analyzer stubs expected by tests
class GPT5SecurityAuditor(BaseAIModel):
    def __init__(self):
        super().__init__(agent_name='gpt5_security', role='Security Vulnerability Auditor', focus_areas=['access_control', 'reentrancy', 'overflow', 'external_calls'])

    async def analyze_contract(self, contract_content: str, contract_path: str = "", context: Dict[str, Any] = None) -> ModelResult:
        start = time.time()

        try:
            # Get configuration
            from core.config_manager import ConfigManager
            config = ConfigManager()
            api_key = getattr(config.config, 'openai_api_key', None)
            # Get agent-specific model from config, fallback to analysis model
            model = getattr(config.config, 'agent_gpt5_security_model', None) or _get_analysis_model()

            if not api_key:
                return ModelResult(
                    model_name='gpt5_security',
                    findings=[],
                    confidence=0.0,
                    processing_time=time.time() - start,
                    metadata={'persona': 'security_auditor', 'error': 'No OpenAI API key configured'}
                )

            # Create OpenAI API prompt for security auditing with zero-day patterns
            from core.enhanced_prompts import get_patterns_for_focus_areas
            zero_day_patterns = get_patterns_for_focus_areas(['access_control', 'reentrancy'])
            truncated_content = self._smart_truncate(contract_content, model)
            prompt = f"""
You are a senior smart contract security auditor specializing in access control, reentrancy, overflow, and external calls.

Focus your analysis on these specific vulnerability types:
- Access control issues (missing onlyOwner, role-based access)
- Reentrancy vulnerabilities (cross-function reentrancy, read-only reentrancy)
- Integer overflow/underflow in arithmetic operations
- Unsafe external calls and delegatecall usage

**CRITICAL ZERO-DAY PATTERNS TO CHECK:**
{zero_day_patterns}

Contract to analyze:
```solidity
{truncated_content}
```

Please analyze this contract and return findings in the exact JSON format:
{{
    "findings": [
        {{
            "type": "vulnerability_type",
            "severity": "critical|high|medium|low",
            "confidence": 0.0-1.0,
            "description": "detailed explanation",
            "line": line_number,
            "swc_id": "SWC-XXX",
            "exploit_steps": "Step 1: ... Step 2: ... Step 3: ...",
            "why_not_false_positive": "specific reason this is not a known safe pattern",
            "affected_funds": "estimated dollar impact or N/A"
        }}
    ]
}}

IMPORTANT: Only report findings where you can provide concrete exploit_steps. Do not report features as vulnerabilities.
Return only valid JSON, no markdown formatting.
"""

            # Make OpenAI API call
            import openai
            import json

            client = openai.OpenAI(api_key=api_key)

            try:
                response = client.chat.completions.create(
                    model=model,
                    messages=[
                        {"role": "system", "content": "You are an expert smart contract security auditor."},
                        {"role": "user", "content": prompt}
                    ]
                )
            except Exception as e:
                # Fallback to gpt-4o if gpt-5-mini fails
                if 'model_not_found' in str(e).lower() or 'not available' in str(e).lower():
                    model = 'gpt-4o'
                    response = client.chat.completions.create(
                        model=model,
                        messages=[
                            {"role": "system", "content": "You are an expert smart contract security auditor."},
                            {"role": "user", "content": prompt}
                        ],
                        max_tokens=2000
                    )
                else:
                    raise

            response_text = response.choices[0].message.content

            # Parse JSON response robustly
            findings_data = parse_llm_json(response_text, fallback={"findings": []})
            findings = findings_data.get('findings', [])

            return ModelResult(
                model_name='gpt5_security',
                findings=findings,
                confidence=0.85,
                processing_time=time.time() - start,
                metadata={'persona': 'security_auditor', 'api_calls': 1, 'model': model}
            )

        except Exception as e:
            logger.error(f"Security Auditor failed: {e}")
            return ModelResult(
                model_name='gpt5_security',
                findings=[],
                confidence=0.0,
                processing_time=time.time() - start,
                metadata={'persona': 'security_auditor', 'error': str(e)}
            )


class GPT5DeFiSpecialist(BaseAIModel):
    def __init__(self):
        super().__init__(agent_name='gpt5_defi', role='DeFi Protocol Specialist', focus_areas=['amm', 'lending', 'governance', 'oracle_manipulation'])

    async def analyze_contract(self, contract_content: str, contract_path: str = "", context: Dict[str, Any] = None) -> ModelResult:
        start = time.time()

        try:
            # Get configuration
            from core.config_manager import ConfigManager
            config = ConfigManager()
            api_key = getattr(config.config, 'openai_api_key', None)
            # Get agent-specific model from config, fallback to analysis model
            model = getattr(config.config, 'agent_gpt5_defi_model', None) or _get_analysis_model()

            if not api_key:
                return ModelResult(
                    model_name='gpt5_defi',
                    findings=[],
                    confidence=0.0,
                    processing_time=time.time() - start,
                    metadata={'persona': 'defi_specialist', 'error': 'No OpenAI API key configured'}
                )

            # Create OpenAI API prompt for DeFi specialist with zero-day patterns
            from core.enhanced_prompts import get_patterns_for_focus_areas
            zero_day_patterns = get_patterns_for_focus_areas(['amm', 'lending', 'governance'])
            truncated_content = self._smart_truncate(contract_content, model)
            prompt = f"""
You are a senior DeFi protocol specialist analyzing smart contracts for AMM, lending, governance, and oracle manipulation vulnerabilities.

Focus your analysis on these specific vulnerability types:
- AMM price manipulation and flash loan attacks
- Lending protocol liquidation vulnerabilities
- Governance proposal manipulation and voting issues
- Oracle price feed manipulation and stale data
- ERC-4626 vault inflation attacks
- Rounding direction exploitation in deposit/withdraw

**CRITICAL ZERO-DAY PATTERNS TO CHECK:**
{zero_day_patterns}

Contract to analyze:
```solidity
{truncated_content}
```

Please analyze this contract and return findings in the exact JSON format:
{{
    "findings": [
        {{
            "type": "vulnerability_type",
            "severity": "critical|high|medium|low",
            "confidence": 0.0-1.0,
            "description": "detailed explanation",
            "line": line_number,
            "swc_id": "SWC-XXX",
            "exploit_steps": "Step 1: ... Step 2: ... Step 3: ...",
            "why_not_false_positive": "specific reason this is not a known safe pattern",
            "affected_funds": "estimated dollar impact or N/A"
        }}
    ]
}}

IMPORTANT: Only report findings where you can provide concrete exploit_steps. Do not flag normal DeFi features (swap, flashLoan, liquidate) as vulnerabilities unless protections are missing.
Return only valid JSON, no markdown formatting.
"""

            # Make OpenAI API call
            import openai
            import json

            client = openai.OpenAI(api_key=api_key)

            try:
                response = client.chat.completions.create(
                    model=model,
                    messages=[
                        {"role": "system", "content": "You are an expert DeFi protocol security specialist."},
                        {"role": "user", "content": prompt}
                    ]
                )
            except Exception as e:
                # Fallback to gpt-4o if gpt-5-mini fails
                if 'model_not_found' in str(e).lower() or 'not available' in str(e).lower():
                    model = 'gpt-4o'
                    response = client.chat.completions.create(
                        model=model,
                        messages=[
                            {"role": "system", "content": "You are an expert DeFi protocol security specialist."},
                            {"role": "user", "content": prompt}
                        ],
                        max_tokens=2000
                    )
                else:
                    raise

            response_text = response.choices[0].message.content

            # Parse JSON response robustly
            findings_data = parse_llm_json(response_text, fallback={"findings": []})
            findings = findings_data.get('findings', [])

            return ModelResult(
                model_name='gpt5_defi',
                findings=findings,
                confidence=0.8,
                processing_time=time.time() - start,
                metadata={'persona': 'defi_specialist', 'api_calls': 1, 'model': model}
            )

        except Exception as e:
            logger.error(f"DeFi Specialist failed: {e}")
            return ModelResult(
                model_name='gpt5_defi',
                findings=[],
                confidence=0.0,
                processing_time=time.time() - start,
                metadata={'persona': 'defi_specialist', 'error': str(e)}
            )


class GeminiSecurityAuditor(BaseAIModel):
    def __init__(self):
        super().__init__(agent_name='gemini_security', role='Gemini Security Vulnerability Hunter', focus_areas=['external_calls', 'delegatecall', 'tx_origin', 'unchecked_returns'])

    async def analyze_contract(self, contract_content: str, contract_path: str = "", context: Dict[str, Any] = None) -> ModelResult:
        start = time.time()

        try:
            # Get configuration
            from core.config_manager import ConfigManager
            config = ConfigManager()
            api_key = getattr(config.config, 'gemini_api_key', None)
            # Get agent-specific model from config, fallback to gemini-2.5-flash
            model = getattr(config.config, 'agent_gemini_security_model', 'gemini-2.5-flash')

            if not api_key:
                return ModelResult(
                    model_name='gemini_security',
                    findings=[],
                    confidence=0.0,
                    processing_time=time.time() - start,
                    metadata={'persona': 'gemini_security_hunter', 'error': 'No Gemini API key configured'}
                )

            # Create Gemini API prompt for security auditing with zero-day patterns
            from core.enhanced_prompts import get_patterns_for_focus_areas
            zero_day_patterns = get_patterns_for_focus_areas(['external_calls', 'delegatecall'])
            truncated_content = self._smart_truncate(contract_content, model)
            prompt = f"""You are an expert smart contract security auditor performing automated code review.

Task: Analyze the Solidity smart contract below for security vulnerabilities.

Analysis Focus Areas:
- External call safety and reentrancy patterns
- Delegatecall usage and context preservation
- tx.origin authentication vulnerabilities
- Unchecked return values from external calls
- Access control mechanisms
- State management and race conditions
- Returndata bombs from untrusted calls
- Read-only reentrancy via stale view functions
- Signature replay across chain forks

CRITICAL ZERO-DAY PATTERNS TO CHECK:
{zero_day_patterns}

Contract Code:
```solidity
{truncated_content}
```

Output Requirements:
1. Return valid JSON only (no markdown formatting or code blocks)
2. Use this exact structure: {{"findings": [...]}}
3. If no vulnerabilities are found, return: {{"findings": []}}
4. Each finding must include these fields:
   - type: vulnerability category (string)
   - severity: "critical", "high", "medium", or "low"
   - confidence: numeric value between 0.0 and 1.0
   - description: detailed explanation of the issue
   - line: approximate line number (integer)
   - swc_id: relevant SWC identifier (e.g., "SWC-107")
   - exploit_steps: concrete step-by-step attack path
   - why_not_false_positive: specific reason this isn't a known safe pattern
   - affected_funds: estimated dollar impact or "N/A"

Expected JSON format:
{{"findings": [{{"type": "...", "severity": "...", "confidence": 0.0, "description": "...", "line": 0, "swc_id": "...", "exploit_steps": "...", "why_not_false_positive": "...", "affected_funds": "..."}}]}}

IMPORTANT: Only report findings with concrete exploit paths. Do not flag normal features as vulnerabilities.

Note: This is automated security analysis for code review purposes, conducted by authorized developers
as part of standard software quality assurance and security testing before deployment."""

            # Make Gemini API call
            import requests
            import json

            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"

            payload = {
                "contents": [{
                    "parts": [{
                        "text": prompt
                    }]
                }],
                "generationConfig": {
                    "maxOutputTokens": 100000,
                },
                "safetySettings": [
                    {
                        "category": "HARM_CATEGORY_HATE_SPEECH",
                        "threshold": "BLOCK_NONE"
                    },
                    {
                        "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
                        "threshold": "BLOCK_NONE"
                    },
                    {
                        "category": "HARM_CATEGORY_HARASSMENT",
                        "threshold": "BLOCK_NONE"
                    },
                    {
                        "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
                        "threshold": "BLOCK_NONE"
                    }
                ]
            }

            # Gemini API can be slow, use longer timeout (60 seconds) with retry logic
            max_retries = 2
            for attempt in range(max_retries):
                try:
                    response = requests.post(url, json=payload, timeout=60)
                    response.raise_for_status()
                    break  # Success, exit retry loop
                except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
                    if attempt < max_retries - 1:
                        logger.warning(f"[Gemini Security] Timeout on attempt {attempt + 1}/{max_retries}, retrying...")
                        time.sleep(2)  # Wait before retry (use module-level time import)
                    else:
                        logger.error(f"[Gemini Security] Timeout after {max_retries} attempts: {e}")
                        return ModelResult(
                            model_name='gemini_security',
                            findings=[],
                            confidence=0.0,
                            processing_time=time.time() - start,
                            metadata={'persona': 'gemini_security_hunter', 'error': f'API timeout: {str(e)}'}
                        )

            result = response.json()
            findings = []
            try:
                candidates = result.get('candidates') or []
                if candidates:
                    candidate = candidates[0]
                    
                    # Check if response was blocked mid-generation by safety filters
                    finish_reason = candidate.get('finishReason', '')
                    if finish_reason == 'SAFETY':
                        logger.error(f"[Gemini Security] Content blocked by safety filters during generation")
                        logger.error(f"[Gemini Security] finishReason: {finish_reason}")
                        if 'safetyRatings' in candidate:
                            logger.error(f"[Gemini Security] Safety Ratings: {json.dumps(candidate['safetyRatings'], indent=2)}")
                        # Return empty findings with clear error
                        return ModelResult(
                            model_name='gemini_security',
                            findings=[],
                            confidence=0.0,
                            processing_time=time.time() - start,
                            metadata={
                                'persona': 'gemini_security_hunter',
                                'error': 'Content blocked by Gemini safety filters (finishReason: SAFETY)',
                                'finish_reason': finish_reason
                            }
                        )
                    
                    # Handle MAX_TOKENS finish reason
                    if finish_reason == 'MAX_TOKENS':
                        logger.warning(f"[Gemini Security] Response truncated by MAX_TOKENS limit. Retrying with condensed prompt...")
                        # Create a shorter, more focused prompt
                        condensed_prompt = f"""Analyze for CRITICAL security vulnerabilities only:
```solidity
{contract_content[:4000]}
```
Return JSON: {{"findings": [{{"type": "...", "severity": "critical|high", "confidence": 0.0, "description": "...", "line": 0, "swc_id": "..."}}]}}
Return only JSON, no markdown."""
                        
                        try:
                            retry_payload = {
                                "contents": [{
                                    "parts": [{
                                        "text": condensed_prompt
                                    }]
                                }],
                                "generationConfig": {
                                    "maxOutputTokens": 1500,
                                },
                                "safetySettings": payload["safetySettings"]
                            }
                            
                            retry_response = requests.post(url, json=retry_payload, timeout=60)
                            retry_response.raise_for_status()
                            result = retry_response.json()
                            candidates = result.get('candidates') or []
                            if not candidates:
                                logger.error(f"[Gemini Security] Retry also failed - no candidates")
                                return ModelResult(
                                    model_name='gemini_security',
                                    findings=[],
                                    confidence=0.0,
                                    processing_time=time.time() - start,
                                    metadata={
                                        'persona': 'gemini_security_hunter',
                                        'error': 'MAX_TOKENS: Gemini cannot process this contract - response too long',
                                        'finish_reason': 'MAX_TOKENS'
                                    }
                                )
                            candidate = candidates[0]
                            finish_reason = candidate.get('finishReason', '')
                        except Exception as retry_error:
                            logger.error(f"[Gemini Security] Retry failed: {retry_error}")
                            return ModelResult(
                                model_name='gemini_security',
                                findings=[],
                                confidence=0.0,
                                processing_time=time.time() - start,
                                metadata={
                                    'persona': 'gemini_security_hunter',
                                    'error': f'MAX_TOKENS: Retry failed - {str(retry_error)}',
                                    'finish_reason': 'MAX_TOKENS'
                                }
                            )
                    
                    content = candidate.get('content') or {}
                    parts = content.get('parts') or []
                    
                    # Debug the structure
                    logger.debug(f"[Gemini Security] Response structure - candidates: {len(candidates)}, parts: {len(parts)}, finishReason: {finish_reason}")
                    
                    if parts and isinstance(parts, list):
                        # Find text in parts (could be at any index)
                        response_text = None
                        for i, part in enumerate(parts):
                            if isinstance(part, dict) and 'text' in part:
                                response_text = part['text']
                                logger.debug(f"[Gemini Security] Found text in part {i}")
                                break
                        
                        if response_text:
                            logger.debug(f"[Gemini Security] Raw response (first 500 chars): {response_text[:500]}")
                            data = parse_llm_json(response_text, fallback={"findings": []})
                            findings = data.get('findings', [])
                            logger.debug(f"[Gemini Security] Parsed {len(findings)} findings")
                        else:
                            logger.warning(f"[Gemini Security] No text found in any part. Parts: {[p.keys() if isinstance(p, dict) else type(p) for p in parts]}")
                    else:
                        # Empty parts - check if this is due to safety filtering
                        if finish_reason:
                            logger.warning(f"[Gemini Security] Empty parts array with finishReason: {finish_reason}")
                        else:
                            logger.warning(f"[Gemini Security] Parts is not a list or is empty: {type(parts)} - {parts}")
                else:
                    logger.warning(f"[Gemini Security] No candidates in response")
                    if 'promptFeedback' in result:
                        feedback = result['promptFeedback']
                        logger.error(f"[Gemini Security] SAFETY FILTER BLOCKED (pre-generation): {json.dumps(feedback, indent=2)}")
                        if 'blockReason' in feedback:
                            logger.error(f"[Gemini Security] Block Reason: {feedback['blockReason']}")
                        if 'safetyRatings' in feedback:
                            logger.error(f"[Gemini Security] Safety Ratings: {json.dumps(feedback['safetyRatings'], indent=2)}")
            except Exception as e:
                logger.error(f"[Gemini Security] Error parsing findings: {e}")
                logger.debug(f"[Gemini Security] Response was: {result}")
                import traceback
                logger.debug(f"[Gemini Security] Traceback: {traceback.format_exc()}")
                findings = []

            return ModelResult(
                model_name='gemini_security',
                findings=findings,
                confidence=0.8,
                processing_time=time.time() - start,
                metadata={'persona': 'gemini_security_hunter', 'api_calls': 1, 'model': 'gemini-2.5-flash'}
            )

        except Exception as e:
            logger.error(f"Gemini Security Auditor failed: {e}")
            return ModelResult(
                model_name='gemini_security',
                findings=[],
                confidence=0.0,
                processing_time=time.time() - start,
                metadata={'persona': 'gemini_security_hunter', 'error': str(e)}
            )


class GeminiFormalVerifier(BaseAIModel):
    def __init__(self):
        super().__init__(agent_name='gemini_verification', role='Gemini Formal Verification Specialist', focus_areas=['arithmetic', 'overflow', 'underflow', 'precision_loss'])

    async def analyze_contract(self, contract_content: str, contract_path: str = "", context: Dict[str, Any] = None) -> ModelResult:
        start = time.time()

        try:
            # Get configuration
            from core.config_manager import ConfigManager
            config = ConfigManager()
            api_key = getattr(config.config, 'gemini_api_key', None)
            # Get agent-specific model from config, fallback to gemini-2.5-pro for formal verification
            model = getattr(config.config, 'agent_gemini_verification_model', 'gemini-2.5-pro')

            if not api_key:
                return ModelResult(
                    model_name='gemini_verification',
                    findings=[],
                    confidence=0.0,
                    processing_time=time.time() - start,
                    metadata={'persona': 'gemini_formal_verifier', 'error': 'No Gemini API key configured'}
                )

            # Create Gemini API prompt for formal verification with zero-day patterns
            from core.enhanced_prompts import get_patterns_for_focus_areas
            zero_day_patterns = get_patterns_for_focus_areas(['arithmetic', 'precision'])
            truncated_content = self._smart_truncate(contract_content, model)
            prompt = f"""You are an expert formal verification specialist for smart contract arithmetic analysis.

Task: Analyze the Solidity smart contract below for mathematical and arithmetic vulnerabilities.

Analysis Focus Areas:
- Integer overflow and underflow conditions
- Precision loss in mathematical operations
- Unsafe type casting between numeric types
- Division by zero vulnerabilities
- Mathematical invariant violations
- Rounding errors in financial calculations
- Rounding direction exploitation (Up vs Down in deposit/withdraw)
- Fee-on-transfer token balance assumptions

CRITICAL ZERO-DAY PATTERNS TO CHECK:
{zero_day_patterns}

Contract Code:
```solidity
{truncated_content}
```

Output Requirements:
1. Return valid JSON only (no markdown formatting or code blocks)
2. Use this exact structure: {{"findings": [...]}}
3. If no vulnerabilities are found, return: {{"findings": []}}
4. Each finding must include these fields:
   - type: vulnerability category (string)
   - severity: "critical", "high", "medium", or "low"
   - confidence: numeric value between 0.0 and 1.0
   - description: detailed explanation of the issue
   - line: approximate line number (integer)
   - swc_id: relevant SWC identifier (e.g., "SWC-101")
   - exploit_steps: concrete step-by-step attack path with example values
   - why_not_false_positive: specific reason this isn't a known safe pattern
   - affected_funds: estimated dollar impact or "N/A"

Expected JSON format:
{{"findings": [{{"type": "...", "severity": "...", "confidence": 0.0, "description": "...", "line": 0, "swc_id": "...", "exploit_steps": "...", "why_not_false_positive": "...", "affected_funds": "..."}}]}}

IMPORTANT: Only report findings with concrete exploit paths and example values. Do not flag Solidity 0.8+ checked arithmetic as overflow unless unchecked blocks are used.

Note: This is automated arithmetic verification for code review purposes, conducted by authorized developers
as part of standard software quality assurance and security testing before deployment."""

            # Make Gemini API call
            import requests
            import json

            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"

            payload = {
                "contents": [{
                    "parts": [{
                        "text": prompt
                    }]
                }],
                "generationConfig": {
                    "maxOutputTokens": 100000,
                },
                "safetySettings": [
                    {
                        "category": "HARM_CATEGORY_HATE_SPEECH",
                        "threshold": "BLOCK_NONE"
                    },
                    {
                        "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
                        "threshold": "BLOCK_NONE"
                    },
                    {
                        "category": "HARM_CATEGORY_HARASSMENT",
                        "threshold": "BLOCK_NONE"
                    },
                    {
                        "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
                        "threshold": "BLOCK_NONE"
                    }
                ]
            }

            # Gemini API can be slow, use longer timeout (60 seconds) with retry logic
            max_retries = 2
            for attempt in range(max_retries):
                try:
                    response = requests.post(url, json=payload, timeout=60)
                    response.raise_for_status()
                    break  # Success, exit retry loop
                except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
                    if attempt < max_retries - 1:
                        logger.warning(f"[Gemini Verifier] Timeout on attempt {attempt + 1}/{max_retries}, retrying...")
                        time.sleep(2)  # Wait before retry (use module-level time import)
                    else:
                        logger.error(f"[Gemini Verifier] Timeout after {max_retries} attempts: {e}")
                        return ModelResult(
                            model_name='gemini_verification',
                            findings=[],
                            confidence=0.0,
                            processing_time=time.time() - start,
                            metadata={'persona': 'gemini_formal_verifier', 'error': f'API timeout: {str(e)}'}
                        )

            result = response.json()
            findings = []
            try:
                candidates = result.get('candidates') or []
                if candidates:
                    candidate = candidates[0]
                    
                    # Check if response was blocked mid-generation by safety filters
                    finish_reason = candidate.get('finishReason', '')
                    if finish_reason == 'SAFETY':
                        logger.error(f"[Gemini Verifier] Content blocked by safety filters during generation")
                        logger.error(f"[Gemini Verifier] finishReason: {finish_reason}")
                        if 'safetyRatings' in candidate:
                            logger.error(f"[Gemini Verifier] Safety Ratings: {json.dumps(candidate['safetyRatings'], indent=2)}")
                        # Return empty findings with clear error
                        return ModelResult(
                            model_name='gemini_verification',
                            findings=[],
                            confidence=0.0,
                            processing_time=time.time() - start,
                            metadata={
                                'persona': 'gemini_formal_verifier',
                                'error': 'Content blocked by Gemini safety filters (finishReason: SAFETY)',
                                'finish_reason': finish_reason
                            }
                        )
                    
                    # Handle MAX_TOKENS finish reason
                    if finish_reason == 'MAX_TOKENS':
                        logger.warning(f"[Gemini Verifier] Response truncated by MAX_TOKENS limit. Retrying with condensed prompt...")
                        # Create a shorter, more focused prompt
                        condensed_prompt = f"""Analyze for CRITICAL arithmetic/overflow vulnerabilities only:
```solidity
{contract_content[:4000]}
```
Return JSON: {{"findings": [{{"type": "...", "severity": "critical|high", "confidence": 0.0, "description": "...", "line": 0, "swc_id": "..."}}]}}
Return only JSON, no markdown."""
                        
                        try:
                            retry_payload = {
                                "contents": [{
                                    "parts": [{
                                        "text": condensed_prompt
                                    }]
                                }],
                                "generationConfig": {
                                    "maxOutputTokens": 1200,
                                },
                                "safetySettings": payload["safetySettings"]
                            }
                            
                            retry_response = requests.post(url, json=retry_payload, timeout=60)
                            retry_response.raise_for_status()
                            result = retry_response.json()
                            candidates = result.get('candidates') or []
                            if not candidates:
                                logger.error(f"[Gemini Verifier] Retry also failed - no candidates")
                                return ModelResult(
                                    model_name='gemini_verification',
                                    findings=[],
                                    confidence=0.0,
                                    processing_time=time.time() - start,
                                    metadata={
                                        'persona': 'gemini_formal_verifier',
                                        'error': 'MAX_TOKENS: Gemini cannot process this contract - response too long',
                                        'finish_reason': 'MAX_TOKENS'
                                    }
                                )
                            candidate = candidates[0]
                            finish_reason = candidate.get('finishReason', '')
                        except Exception as retry_error:
                            logger.error(f"[Gemini Verifier] Retry failed: {retry_error}")
                            return ModelResult(
                                model_name='gemini_verification',
                                findings=[],
                                confidence=0.0,
                                processing_time=time.time() - start,
                                metadata={
                                    'persona': 'gemini_formal_verifier',
                                    'error': f'MAX_TOKENS: Retry failed - {str(retry_error)}',
                                    'finish_reason': 'MAX_TOKENS'
                                }
                            )
                    
                    content = candidate.get('content') or {}
                    parts = content.get('parts') or []
                    
                    # Debug the structure
                    logger.debug(f"[Gemini Verifier] Response structure - candidates: {len(candidates)}, parts: {len(parts)}, finishReason: {finish_reason}")
                    
                    if parts and isinstance(parts, list):
                        # Find text in parts (could be at any index)
                        response_text = None
                        for i, part in enumerate(parts):
                            if isinstance(part, dict) and 'text' in part:
                                response_text = part['text']
                                logger.debug(f"[Gemini Verifier] Found text in part {i}")
                                break
                        
                        if response_text:
                            logger.debug(f"[Gemini Verifier] Raw response (first 500 chars): {response_text[:500]}")
                            data = parse_llm_json(response_text, fallback={"findings": []})
                            findings = data.get('findings', [])
                            logger.debug(f"[Gemini Verifier] Parsed {len(findings)} findings")
                        else:
                            logger.warning(f"[Gemini Verifier] No text found in any part. Parts: {[p.keys() if isinstance(p, dict) else type(p) for p in parts]}")
                    else:
                        # Empty parts - check if this is due to safety filtering
                        if finish_reason:
                            logger.warning(f"[Gemini Verifier] Empty parts array with finishReason: {finish_reason}")
                        else:
                            logger.warning(f"[Gemini Verifier] Parts is not a list or is empty: {type(parts)} - {parts}")
                else:
                    logger.warning(f"[Gemini Verifier] No candidates in response")
                    if 'promptFeedback' in result:
                        feedback = result['promptFeedback']
                        logger.error(f"[Gemini Verifier] SAFETY FILTER BLOCKED (pre-generation): {json.dumps(feedback, indent=2)}")
                        if 'blockReason' in feedback:
                            logger.error(f"[Gemini Verifier] Block Reason: {feedback['blockReason']}")
                        if 'safetyRatings' in feedback:
                            logger.error(f"[Gemini Verifier] Safety Ratings: {json.dumps(feedback['safetyRatings'], indent=2)}")
            except Exception as e:
                logger.error(f"[Gemini Verifier] Error parsing findings: {e}")
                logger.debug(f"[Gemini Verifier] Response was: {result}")
                import traceback
                logger.debug(f"[Gemini Verifier] Traceback: {traceback.format_exc()}")
                findings = []

            return ModelResult(
                model_name='gemini_verification',
                findings=findings,
                confidence=0.9,
                processing_time=time.time() - start,
                metadata={'persona': 'gemini_formal_verifier', 'api_calls': 1}
            )

        except Exception as e:
            logger.error(f"Gemini Formal Verifier failed: {e}")
            return ModelResult(
                model_name='gemini_verification',
                findings=[],
                confidence=0.0,
                processing_time=time.time() - start,
                metadata={'persona': 'gemini_formal_verifier', 'error': str(e)}
            )


class AnthropicSecurityAuditor(BaseAIModel):
    """Anthropic Claude Security Auditor - Deep security analysis with Claude Opus"""

    def __init__(self):
        super().__init__(
            agent_name='anthropic_security',
            role='Anthropic Security Vulnerability Auditor',
            focus_areas=['access_control', 'reentrancy', 'logic_errors', 'privilege_escalation']
        )

    async def analyze_contract(self, contract_content: str, contract_path: str = "", context: Dict[str, Any] = None) -> ModelResult:
        start = time.time()

        try:
            from core.config_manager import ConfigManager
            import os

            config = ConfigManager()
            api_key = os.getenv("ANTHROPIC_API_KEY") or getattr(config.config, 'anthropic_api_key', None)
            model = getattr(config.config, 'agent_anthropic_security_model', 'claude-opus-4-6')

            if not api_key:
                return ModelResult(
                    model_name='anthropic_security',
                    findings=[],
                    confidence=0.0,
                    processing_time=time.time() - start,
                    metadata={'persona': 'anthropic_security_auditor', 'error': 'No Anthropic API key configured'}
                )

            from core.enhanced_prompts import get_patterns_for_focus_areas
            zero_day_patterns = get_patterns_for_focus_areas(['logic_errors', 'privilege'])
            truncated_content = self._smart_truncate(contract_content, model)
            prompt = f"""You are an expert smart contract security auditor performing deep code analysis.

Task: Analyze the Solidity smart contract below for security vulnerabilities.

Analysis Focus Areas:
- Access control vulnerabilities and privilege escalation
- Reentrancy patterns (cross-function, read-only, cross-contract)
- Business logic errors and state inconsistencies
- Privilege escalation through unexpected interactions
- Storage collision in proxy/upgradeable contracts
- Cross-function reentrancy via inconsistent guards

CRITICAL ZERO-DAY PATTERNS TO CHECK:
{zero_day_patterns}

Contract Code:
```solidity
{truncated_content}
```

Output Requirements:
1. Return valid JSON only (no markdown formatting or code blocks)
2. Use this exact structure: {{"findings": [...]}}
3. If no vulnerabilities are found, return: {{"findings": []}}
4. Each finding must include these fields:
   - type: vulnerability category (string)
   - severity: "critical", "high", "medium", or "low"
   - confidence: numeric value between 0.0 and 1.0
   - description: detailed explanation of the issue
   - line: approximate line number (integer)
   - swc_id: relevant SWC identifier (e.g., "SWC-107")
   - exploit_steps: concrete step-by-step attack path
   - why_not_false_positive: specific reason this isn't a known safe pattern
   - affected_funds: estimated dollar impact or "N/A"

Expected JSON format:
{{"findings": [{{"type": "...", "severity": "...", "confidence": 0.0, "description": "...", "line": 0, "swc_id": "...", "exploit_steps": "...", "why_not_false_positive": "...", "affected_funds": "..."}}]}}

IMPORTANT: Only report findings with concrete exploit paths. Do not flag standard OpenZeppelin patterns or intentional design choices.

Note: This is automated security analysis for code review purposes, conducted by authorized developers
as part of standard software quality assurance and security testing before deployment."""

            try:
                import anthropic

                client = anthropic.Anthropic(api_key=api_key)

                response = client.messages.create(
                    model=model,
                    max_tokens=4000,
                    temperature=0.1,
                    system="You are an expert smart contract security auditor. Return only valid JSON.",
                    messages=[{"role": "user", "content": prompt}],
                )

                response_text = response.content[0].text if response.content else ""
            except ImportError:
                return ModelResult(
                    model_name='anthropic_security',
                    findings=[],
                    confidence=0.0,
                    processing_time=time.time() - start,
                    metadata={'persona': 'anthropic_security_auditor', 'error': 'anthropic package not installed'}
                )

            findings_data = parse_llm_json(response_text, fallback={"findings": []})
            findings = findings_data.get('findings', [])

            return ModelResult(
                model_name='anthropic_security',
                findings=findings,
                confidence=0.85,
                processing_time=time.time() - start,
                metadata={'persona': 'anthropic_security_auditor', 'api_calls': 1, 'model': model}
            )

        except Exception as e:
            logger.error(f"Anthropic Security Auditor failed: {e}")
            return ModelResult(
                model_name='anthropic_security',
                findings=[],
                confidence=0.0,
                processing_time=time.time() - start,
                metadata={'persona': 'anthropic_security_auditor', 'error': str(e)}
            )


class AnthropicReasoningSpecialist(BaseAIModel):
    """Anthropic Claude Reasoning Specialist - Extended reasoning for complex vulnerability analysis"""

    def __init__(self):
        super().__init__(
            agent_name='anthropic_reasoning',
            role='Anthropic Reasoning Specialist',
            focus_areas=['complex_logic', 'cross_contract', 'economic_attacks', 'invariant_violations']
        )

    async def analyze_contract(self, contract_content: str, contract_path: str = "", context: Dict[str, Any] = None) -> ModelResult:
        start = time.time()

        try:
            from core.config_manager import ConfigManager
            import os

            config = ConfigManager()
            api_key = os.getenv("ANTHROPIC_API_KEY") or getattr(config.config, 'anthropic_api_key', None)
            model = getattr(config.config, 'agent_anthropic_reasoning_model', 'claude-opus-4-6')

            if not api_key:
                return ModelResult(
                    model_name='anthropic_reasoning',
                    findings=[],
                    confidence=0.0,
                    processing_time=time.time() - start,
                    metadata={'persona': 'anthropic_reasoning_specialist', 'error': 'No Anthropic API key configured'}
                )

            from core.enhanced_prompts import get_patterns_for_focus_areas
            zero_day_patterns = get_patterns_for_focus_areas(['complex_logic', 'economic'])
            truncated_content = self._smart_truncate(contract_content, model)
            prompt = f"""You are a reasoning specialist for smart contract security. Use deep logical analysis to find complex vulnerabilities.

Task: Perform deep reasoning analysis on the Solidity smart contract below, focusing on complex multi-step attack vectors.

Analysis Focus Areas:
- Complex business logic errors requiring multi-step reasoning
- Cross-contract interaction vulnerabilities
- Economic attack vectors (flash loan attacks, price manipulation, sandwich attacks)
- Mathematical invariant violations in DeFi protocols
- State machine violations and unexpected transitions
- ERC-4626 vault inflation / first depositor attacks
- First depositor share manipulation in pools
- Permit/permit2 frontrunning

CRITICAL ZERO-DAY PATTERNS TO CHECK:
{zero_day_patterns}

Contract Code:
```solidity
{truncated_content}
```

Output Requirements:
1. Return valid JSON only (no markdown formatting or code blocks)
2. Use this exact structure: {{"findings": [...]}}
3. If no vulnerabilities are found, return: {{"findings": []}}
4. Each finding must include these fields:
   - type: vulnerability category (string)
   - severity: "critical", "high", "medium", or "low"
   - confidence: numeric value between 0.0 and 1.0
   - description: detailed explanation with reasoning chain
   - line: approximate line number (integer)
   - swc_id: relevant SWC identifier (e.g., "SWC-101")
   - exploit_steps: concrete step-by-step attack path with parameters
   - why_not_false_positive: specific reason this isn't a known safe pattern
   - affected_funds: estimated dollar impact or "N/A"

Expected JSON format:
{{"findings": [{{"type": "...", "severity": "...", "confidence": 0.0, "description": "...", "line": 0, "swc_id": "...", "exploit_steps": "...", "why_not_false_positive": "...", "affected_funds": "..."}}]}}

IMPORTANT: Use multi-step reasoning. For each potential finding, trace the full execution path. Only report findings where you can prove exploitability with concrete parameters.

Note: This is automated security analysis for code review purposes, conducted by authorized developers
as part of standard software quality assurance and security testing before deployment."""

            try:
                import anthropic

                client = anthropic.Anthropic(api_key=api_key)

                response = client.messages.create(
                    model=model,
                    max_tokens=4000,
                    temperature=0.1,
                    system="You are a deep reasoning specialist for smart contract security analysis. Return only valid JSON.",
                    messages=[{"role": "user", "content": prompt}],
                )

                response_text = response.content[0].text if response.content else ""
            except ImportError:
                return ModelResult(
                    model_name='anthropic_reasoning',
                    findings=[],
                    confidence=0.0,
                    processing_time=time.time() - start,
                    metadata={'persona': 'anthropic_reasoning_specialist', 'error': 'anthropic package not installed'}
                )

            findings_data = parse_llm_json(response_text, fallback={"findings": []})
            findings = findings_data.get('findings', [])

            return ModelResult(
                model_name='anthropic_reasoning',
                findings=findings,
                confidence=0.9,
                processing_time=time.time() - start,
                metadata={'persona': 'anthropic_reasoning_specialist', 'api_calls': 1, 'model': model}
            )

        except Exception as e:
            logger.error(f"Anthropic Reasoning Specialist failed: {e}")
            return ModelResult(
                model_name='anthropic_reasoning',
                findings=[],
                confidence=0.0,
                processing_time=time.time() - start,
                metadata={'persona': 'anthropic_reasoning_specialist', 'error': str(e)}
            )


class DeFiSpecialistModel(BaseAIModel):
    def __init__(self):
        super().__init__(agent_name='defi_specialist', role='DeFi Specialist', focus_areas=['defi'])

    async def analyze_contract(self, contract_content: str, contract_path: str = "", context: Dict[str, Any] = None) -> ModelResult:
        start = time.time()
        findings = [{
            'type': 'reentrancy',
            'severity': 'high',
            'confidence': 0.7 * self.confidence_weight,
            'description': 'DeFi specific reentrancy risk',
            'line': 10,
        }]
        return ModelResult(model_name=self.agent_name, findings=findings, confidence=0.7, processing_time=time.time() - start, metadata={})


class FormalVerificationModel(BaseAIModel):
    def __init__(self):
        super().__init__(agent_name='formal_verification', role='Formal Verification', focus_areas=['formal'])

    async def analyze_contract(self, contract_content: str, contract_path: str = "", context: Dict[str, Any] = None) -> ModelResult:
        start = time.time()
        findings = [{
            'type': 'reentrancy',
            'severity': 'high',
            'confidence': 0.9 * self.confidence_weight,
            'description': 'Invariant suggests reentrancy possibility',
            'line': 10,
        }]
        return ModelResult(model_name=self.agent_name, findings=findings, confidence=0.9, processing_time=time.time() - start, metadata={})

class AIEnsemble:
    """Enhanced AI ensemble with specialized agents and database learning"""

    def __init__(self):
        self.db_manager = DatabaseManager()
        self.config = ConfigManager()

        # Three lightweight agents used by unit tests (legacy)
        self._legacy_agents = [
            DeFiSecurityExpert(),
            GasOptimizationExpert(),
            SecurityBestPracticesExpert(),
        ]

        # Full model map: 6 production multi-provider agents
        self.models = {
            'gpt5_security': GPT5SecurityAuditor(),
            'gpt5_defi': GPT5DeFiSpecialist(),
            'gemini_security': GeminiSecurityAuditor(),
            'gemini_verification': GeminiFormalVerifier(),
            'anthropic_security': AnthropicSecurityAuditor(),
            'anthropic_reasoning': AnthropicReasoningSpecialist(),
        }

        logger.info(f"Initialized AI Ensemble with {len(self.models)} models")

    @property
    def active_agents(self) -> List[BaseAIModel]:
        """Get production agents that have valid API keys configured."""
        import os
        active = []
        for name, agent in self.models.items():
            # Check if provider API key is available
            if name.startswith('gpt5'):
                if os.getenv("OPENAI_API_KEY") or getattr(self.config.config, 'openai_api_key', None):
                    active.append(agent)
            elif name.startswith('gemini'):
                if os.getenv("GEMINI_API_KEY") or getattr(self.config.config, 'gemini_api_key', None):
                    active.append(agent)
            elif name.startswith('anthropic'):
                if os.getenv("ANTHROPIC_API_KEY") or getattr(self.config.config, 'anthropic_api_key', None):
                    active.append(agent)
            else:
                active.append(agent)
        return active

    @property
    def agents(self) -> List[BaseAIModel]:
        """Backward-compatible property: returns legacy agents for tests."""
        return self._legacy_agents

    async def analyze_with_ensemble(self, contract_content: str, contract_path: str = "") -> ConsensusResult:
        """Run all specialized agents and generate consensus results
        
        🔍 DEBUGGING INFO:
        This method now provides detailed insights into why model_agreement may be 0.0:
        
        1. **Agent Failures**: Shows which agents failed and why (usually missing OpenAI API key)
        2. **No Findings**: Shows when agents completed but found no vulnerabilities  
        3. **No Consensus**: Shows when agents found vulnerabilities but didn't agree (different types/severity)
        4. **Consensus Success**: Shows when 2+ agents agreed on the same finding
        
        ⚠️  COMMON ISSUE - Model Agreement = 0.0 Causes:
        - All agents fail (missing OPENAI_API_KEY) → all return empty findings
        - Agents find different vulnerabilities → no overlap between agents  
        - Agents are disabled or return empty results
        
        ✅ SOLUTION:
        - Set OPENAI_API_KEY environment variable: export OPENAI_API_KEY="your-key"
        - Or configure via: aether config --openai-key "your-key"
        - Check debug output for which agents are failing and why
        """
        start_time = time.time()

        try:
            # Use production multi-provider agents; fallback to legacy agents if none have keys
            sources = self.active_agents or self._legacy_agents
            tasks = [m.analyze_contract(contract_content, contract_path) for m in sources]

            # Execute all agent analyses concurrently
            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Process results and filter out exceptions
            valid_results = []
            for i, result in enumerate(results):
                agent_name = sources[i].agent_name if i < len(sources) else "unknown"
                
                if isinstance(result, Exception):
                    logger.error(f"❌ Agent {agent_name} failed with exception: {result}")
                    print(f"❌ AI Agent '{agent_name}' failed: {str(result)[:100]}")
                    continue

                if isinstance(result, ModelResult):
                    if result.findings:
                        valid_results.append(result)
                        logger.info(f"✅ Agent {agent_name} found {len(result.findings)} findings")
                        print(f"✅ AI Agent '{agent_name}' found {len(result.findings)} findings")
                    else:
                        if result.confidence == 0.0 and result.metadata.get('error'):
                            logger.warning(f"⚠️  Agent {agent_name} returned no findings - Error: {result.metadata.get('error')}")
                            print(f"⚠️  AI Agent '{agent_name}' failed: {result.metadata.get('error', 'Unknown error')[:100]}")
                        else:
                            logger.info(f"ℹ️  Agent {agent_name} completed but found no vulnerabilities")
                            print(f"ℹ️  AI Agent '{agent_name}' found no vulnerabilities in the contract")

            print(f"\n📊 AI Ensemble Summary:")
            print(f"   Total agents: {len(sources)}")
            print(f"   Successful agents: {len(valid_results)}")
            print(f"   Failed/No findings: {len(sources) - len(valid_results)}")

            # Generate consensus analysis
            consensus = self._generate_consensus(valid_results)

            # Cross-validate high/critical findings using challenger agents
            cross_validated_findings = await self._cross_validate_findings(
                consensus['findings'], contract_content
            )

            processing_time = time.time() - start_time

            return ConsensusResult(
                consensus_findings=cross_validated_findings,
                model_agreement=consensus['agreement'],
                confidence_score=consensus['confidence'],
                processing_time=processing_time,
                individual_results=valid_results
            )

        except Exception as e:
            logger.error(f"Enhanced ensemble analysis failed: {e}")
            print(f"❌ AI Ensemble analysis failed: {e}")
            processing_time = time.time() - start_time

            return ConsensusResult(
                consensus_findings=[],
                model_agreement=0.0,
                confidence_score=0.0,
                processing_time=processing_time,
                individual_results=[]
            )

    def _generate_consensus(self, results: List[ModelResult]) -> Dict[str, Any]:
        """Generate consensus from multiple agent results"""
        if not results:
            logger.warning("No valid AI agent results to generate consensus from")
            print("⚠️  No AI agents produced valid results - skipping consensus generation")
            return {
                'findings': [],
                'agreement': 0.0,
                'confidence': 0.0
            }

        # Collect all findings and track originating models
        all_findings = []
        all_findings_with_models = []  # List[Tuple[Dict, str]]
        findings_by_agent = {}
        for result in results:
            findings_by_agent[result.model_name] = len(result.findings)
            all_findings.extend(result.findings)
            for f in result.findings:
                all_findings_with_models.append((f, result.model_name))

        if not all_findings:
            logger.info("AI agents found no vulnerabilities to reach consensus on")
            print("ℹ️  AI agents analyzed contract but found no vulnerabilities to create consensus")
            return {
                'findings': [],
                'agreement': 0.0,
                'confidence': 0.0
            }

        # Log findings by each agent
        print(f"\n📋 Findings by Agent:")
        for agent_name, count in findings_by_agent.items():
            print(f"   - {agent_name}: {count} findings")

        # Deduplicate findings with fuzzy matching and model tracking
        deduplicated_findings = self._deduplicate_findings(all_findings, all_findings_with_models)

        # Calculate agreement metrics
        # agreement = proportion of findings corroborated by 2+ agents
        corroborated_count = sum(1 for f in deduplicated_findings if f.get('agreement_count', 1) >= 2)
        agreement_score = corroborated_count / len(deduplicated_findings) if deduplicated_findings else 0.0

        # Weight by agent confidence
        avg_confidence = sum(r.confidence for r in results) / len(results) if results else 0.0

        if deduplicated_findings:
            multi_agent = [f for f in deduplicated_findings if f.get('agreement_count', 1) >= 2]
            single_agent = [f for f in deduplicated_findings if f.get('agreement_count', 1) < 2]
            print(f"✅ AI Ensemble: {len(deduplicated_findings)} unique findings from {len(all_findings)} total")
            print(f"   Corroborated (2+ agents): {len(multi_agent)} findings")
            print(f"   Single-agent (needs verification): {len(single_agent)} findings")
            print(f"   Agents contributing: {', '.join(findings_by_agent.keys())}")
        else:
            print(f"ℹ️  AI Ensemble: No findings after deduplication")

        return {
            'findings': deduplicated_findings,
            'agreement': min(agreement_score, 1.0),
            'confidence': min(avg_confidence, 1.0),
            'all_findings': all_findings_with_models,
            'agent_count': len(results),
            'successful_agents': len([r for r in results if r.findings])
        }

    # Vulnerability type normalization map for fuzzy matching
    _VULN_TYPE_ALIASES = {
        'reentrancy': ['reentrancy', 'cross_function_reentrancy', 'read_only_reentrancy', 'cross_contract_reentrancy'],
        'access_control': ['access_control', 'missing_access_control', 'privilege_escalation', 'unauthorized_access'],
        'oracle_manipulation': ['oracle_manipulation', 'price_manipulation', 'stale_price', 'oracle_dependency'],
        'flash_loan': ['flash_loan', 'flash_loan_attack', 'flash_loan_arbitrage'],
        'integer_overflow': ['integer_overflow', 'overflow', 'underflow', 'arithmetic_error', 'integer_underflow'],
        'precision_loss': ['precision_loss', 'rounding_error', 'rounding_direction', 'truncation'],
        'front_running': ['front_running', 'frontrunning', 'mev', 'sandwich_attack'],
        'delegatecall': ['delegatecall', 'unsafe_delegatecall', 'delegatecall_injection'],
        'unchecked_return': ['unchecked_return', 'unchecked_call', 'unchecked_low_level_call'],
        'storage_collision': ['storage_collision', 'storage_conflict', 'proxy_storage'],
    }

    def _normalize_vuln_type(self, vuln_type: str) -> str:
        """Normalize vulnerability type for fuzzy matching across agents."""
        vuln_lower = vuln_type.lower().strip().replace(' ', '_').replace('-', '_')
        for canonical, aliases in self._VULN_TYPE_ALIASES.items():
            if vuln_lower in aliases or any(alias in vuln_lower for alias in aliases):
                return canonical
        return vuln_lower

    def _get_finding_key(self, finding: Dict[str, Any]) -> str:
        """Generate a fuzzy key for finding similarity comparison.

        Uses normalized vuln type and line number within +/-5 lines.
        Severity within one level is considered similar.
        """
        normalized_type = self._normalize_vuln_type(finding.get('type', ''))
        line = finding.get('line', -1)
        # Bucket line numbers into groups of 10 for fuzzy matching
        line_bucket = (line // 10) * 10 if line >= 0 else -1
        return f"{normalized_type}_{line_bucket}"

    def _findings_match_fuzzy(self, f1: Dict[str, Any], f2: Dict[str, Any]) -> bool:
        """Check if two findings are similar enough to be considered the same issue."""
        # Type match (normalized)
        type1 = self._normalize_vuln_type(f1.get('type', ''))
        type2 = self._normalize_vuln_type(f2.get('type', ''))
        if type1 != type2:
            return False

        # Line number within +/-5
        line1 = f1.get('line', -1)
        line2 = f2.get('line', -1)
        if line1 >= 0 and line2 >= 0 and abs(line1 - line2) > 5:
            return False

        return True

    def _merge_similar_findings(self, similar_findings: List[Dict[str, Any]], models: List[str] = None) -> Dict[str, Any]:
        """Merge similar findings into a consensus finding with agreement tracking."""
        # Take the finding with highest confidence as base
        base_finding = max(similar_findings, key=lambda f: f.get('confidence', 0))

        # Average confidence across similar findings
        avg_confidence = sum(f.get('confidence', 0) for f in similar_findings) / len(similar_findings)
        agreement_count = len(similar_findings)

        # Agreement-based confidence adjustment
        if agreement_count >= 2:
            # Multiple agents agree: boost confidence
            confidence_boost = 0.1
            adjusted_confidence = min(1.0, avg_confidence + confidence_boost)
        else:
            # Single agent only: penalize confidence
            confidence_penalty = 0.15
            adjusted_confidence = max(0.0, avg_confidence - confidence_penalty)

        # Update with consensus confidence
        consensus_finding = base_finding.copy()
        consensus_finding['confidence'] = adjusted_confidence
        consensus_finding['consensus_count'] = agreement_count
        consensus_finding['model_count'] = agreement_count
        consensus_finding['consensus_confidence'] = min(1.0, adjusted_confidence)
        consensus_finding['agreement_count'] = agreement_count
        # Track which models agreed on this finding
        consensus_finding['models'] = models or []
        consensus_finding['needs_verification'] = agreement_count < 2

        return consensus_finding

    def _deduplicate_findings(self, all_findings: List[Dict[str, Any]], all_findings_with_models: List[Tuple[Dict, str]]) -> List[Dict[str, Any]]:
        """
        Deduplicate findings using fuzzy semantic similarity.
        Groups findings by normalized type and approximate line number,
        tracks which models contributed each finding.
        """
        # Build groups using fuzzy matching
        groups: List[List[Tuple[Dict, str]]] = []

        for finding, model_name in all_findings_with_models:
            matched = False
            for group in groups:
                # Compare against first finding in group
                if self._findings_match_fuzzy(group[0][0], finding):
                    group.append((finding, model_name))
                    matched = True
                    break
            if not matched:
                groups.append([(finding, model_name)])

        # Merge each group
        deduplicated_findings = []
        for group in groups:
            findings_in_group = [f for f, _ in group]
            models_in_group = list(set(m for _, m in group))
            merged = self._merge_similar_findings(findings_in_group, models_in_group)
            deduplicated_findings.append(merged)

        # Sort by confidence (descending)
        deduplicated_findings.sort(key=lambda f: f.get('confidence', 0), reverse=True)
        return deduplicated_findings

    def _get_provider_for_agent(self, agent_name: str) -> str:
        """Get the provider name for a given agent."""
        if agent_name.startswith('gpt5') or agent_name in ('defi_expert', 'gas_expert', 'security_expert'):
            return 'openai'
        elif agent_name.startswith('gemini'):
            return 'gemini'
        elif agent_name.startswith('anthropic'):
            return 'anthropic'
        return 'unknown'

    def _get_challenger_agents(self, finding_models: List[str], count: int = 2) -> List[BaseAIModel]:
        """Select challenger agents from different providers than the finding's authors."""
        finding_providers = set(self._get_provider_for_agent(m) for m in finding_models)
        challengers = []
        for name, agent in self.models.items():
            provider = self._get_provider_for_agent(name)
            if provider not in finding_providers:
                challengers.append(agent)
            if len(challengers) >= count:
                break
        # If not enough cross-provider challengers, use any available
        if len(challengers) < count:
            for name, agent in self.models.items():
                if agent not in challengers and name not in finding_models:
                    challengers.append(agent)
                if len(challengers) >= count:
                    break
        return challengers[:count]

    async def _cross_validate_findings(self, findings: List[Dict[str, Any]], contract_content: str) -> List[Dict[str, Any]]:
        """Cross-validate high/critical findings using challenger agents from different providers.

        Only cross-validates high/critical findings to control API costs.
        Adjusts confidence based on challenger agreement.
        """
        from core.enhanced_prompts import CROSS_VALIDATION_PROMPT

        high_crit_findings = [f for f in findings if f.get('severity', '').lower() in ('high', 'critical')]

        if not high_crit_findings:
            return findings

        print(f"\n🔄 Cross-validating {len(high_crit_findings)} high/critical findings...")

        # Build a map of finding index to finding for updating
        finding_indices = {}
        for i, f in enumerate(findings):
            if f in high_crit_findings:
                finding_indices[id(f)] = i

        for finding in high_crit_findings:
            finding_models = finding.get('models', [])
            challengers = self._get_challenger_agents(finding_models)

            if not challengers:
                logger.warning("No challenger agents available for cross-validation")
                continue

            # Extract code context around the finding
            line = finding.get('line', 0)
            lines = contract_content.split('\n')
            start = max(0, line - 10)
            end = min(len(lines), line + 10)
            code_context = '\n'.join(lines[start:end])

            # Build challenge prompt
            try:
                prompt_text = CROSS_VALIDATION_PROMPT.format(
                    finding_type=finding.get('type', 'unknown'),
                    severity=finding.get('severity', 'unknown'),
                    line=line,
                    description=finding.get('description', ''),
                    code_context=code_context,
                    contract_content=contract_content[:8000],  # Limit for cost control
                )
            except Exception as e:
                logger.warning(f"Failed to format cross-validation prompt: {e}")
                continue

            # Query challengers in parallel
            challenge_tasks = []
            for challenger in challengers:
                challenge_tasks.append(
                    challenger.analyze_contract(prompt_text, context={'mode': 'cross_validation'})
                )

            try:
                challenge_results = await asyncio.gather(*challenge_tasks, return_exceptions=True)
            except Exception as e:
                logger.warning(f"Cross-validation gather failed: {e}")
                continue

            confirmations = 0
            rejections = 0
            for result in challenge_results:
                if isinstance(result, Exception):
                    continue
                if isinstance(result, ModelResult):
                    # Parse challenge response - look for validation indicators
                    for cf in result.findings:
                        desc = cf.get('description', '').lower()
                        is_valid = cf.get('is_valid', None)
                        if is_valid is True or 'confirmed' in desc or 'valid' in desc or 'real vulnerability' in desc:
                            confirmations += 1
                        elif is_valid is False or 'false positive' in desc or 'not a vulnerability' in desc or 'rejected' in desc:
                            rejections += 1
                    if not result.findings:
                        # Empty findings from challenger = implicit rejection
                        rejections += 1

            # Adjust confidence based on cross-validation
            idx = finding_indices.get(id(finding))
            if idx is not None:
                cv_metadata = {
                    'cross_validated': True,
                    'confirmations': confirmations,
                    'rejections': rejections,
                    'challengers': len(challengers),
                }
                findings[idx]['cross_validation'] = cv_metadata

                if confirmations >= 2:
                    # Strong confirmation
                    findings[idx]['confidence'] = min(1.0, findings[idx].get('confidence', 0.5) + 0.15)
                    print(f"   ✅ Finding '{finding.get('type')}' confirmed by {confirmations} challengers")
                elif rejections >= 2:
                    # Strong rejection - likely false positive
                    findings[idx]['confidence'] = max(0.0, findings[idx].get('confidence', 0.5) - 0.25)
                    findings[idx]['likely_false_positive'] = True
                    print(f"   ❌ Finding '{finding.get('type')}' rejected by {rejections} challengers")
                else:
                    # Split decision - flag for manual review
                    findings[idx]['needs_manual_review'] = True
                    print(f"   ⚠️  Finding '{finding.get('type')}' split decision ({confirmations} confirm, {rejections} reject)")

        return findings

    async def deep_dive_analysis(self, findings: List[Dict[str, Any]], contract_content: str) -> List[Dict[str, Any]]:
        """Deep-dive analysis on top findings using the Anthropic Reasoning Specialist.

        For the top 5 highest-confidence findings, performs extended analysis
        with full code path tracing and exploit parameter generation.
        """
        from core.enhanced_prompts import DEEP_DIVE_PROMPT

        # Select top 5 findings by confidence
        top_findings = sorted(findings, key=lambda f: f.get('confidence', 0), reverse=True)[:5]
        if not top_findings:
            return findings

        # Prefer the Anthropic Reasoning Specialist for deep-dive
        deep_agent = self.models.get('anthropic_reasoning')
        if not deep_agent:
            # Fallback to any available agent
            active = self.active_agents
            deep_agent = active[0] if active else None
        if not deep_agent:
            logger.warning("No agent available for deep-dive analysis")
            return findings

        print(f"\n🔬 Deep-dive analysis on top {len(top_findings)} findings...")

        # Build index for updating
        finding_index_map = {id(f): i for i, f in enumerate(findings)}

        for finding in top_findings:
            line = finding.get('line', 0)
            lines = contract_content.split('\n')
            start = max(0, line - 20)
            end = min(len(lines), line + 20)
            function_code = '\n'.join(lines[start:end])

            try:
                prompt_text = DEEP_DIVE_PROMPT.format(
                    finding_type=finding.get('type', 'unknown'),
                    severity=finding.get('severity', 'unknown'),
                    line=line,
                    description=finding.get('description', ''),
                    confidence=finding.get('confidence', 0),
                    function_code=function_code,
                    contract_content=contract_content[:12000],
                )
            except Exception as e:
                logger.warning(f"Failed to format deep-dive prompt: {e}")
                continue

            try:
                result = await deep_agent.analyze_contract(prompt_text, context={'mode': 'deep_dive'})
                if isinstance(result, ModelResult) and result.findings:
                    # Use deep-dive result to update the finding
                    dd_finding = result.findings[0]
                    idx = finding_index_map.get(id(finding))
                    if idx is not None:
                        verified = dd_finding.get('verified', None)
                        if verified is True:
                            findings[idx]['deep_dive_verified'] = True
                            adjusted = dd_finding.get('adjusted_confidence', finding.get('confidence'))
                            findings[idx]['confidence'] = min(1.0, float(adjusted))
                            print(f"   ✅ Deep-dive verified: {finding.get('type')}")
                        elif verified is False:
                            findings[idx]['deep_dive_verified'] = False
                            findings[idx]['confidence'] = max(0.0, findings[idx].get('confidence', 0.5) - 0.2)
                            print(f"   ❌ Deep-dive refuted: {finding.get('type')}")
                        findings[idx]['deep_dive_metadata'] = dd_finding
            except Exception as e:
                logger.warning(f"Deep-dive analysis failed for finding: {e}")
                continue

        return findings

    async def analyze_cross_contract_interactions(self, contract_files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze cross-contract interactions for vulnerabilities.

        Only runs when multiple contracts are being audited. Identifies external
        calls between contracts and analyzes each interaction point.
        """
        if len(contract_files) < 2:
            return []

        from core.enhanced_prompts import CROSS_CONTRACT_ANALYSIS_PROMPT

        # Build contracts summary
        contracts_summary = ""
        for cf in contract_files[:5]:  # Limit to 5 contracts for cost control
            contracts_summary += f"\n### {cf.get('name', 'Unknown')}:\n```solidity\n{cf.get('content', '')[:3000]}\n```\n"

        # Identify interaction points (external calls between contracts)
        import re
        interaction_points = []
        contract_names = [cf.get('name', '').replace('.sol', '') for cf in contract_files]
        for cf in contract_files:
            content = cf.get('content', '')
            for other_name in contract_names:
                if other_name and other_name != cf.get('name', '').replace('.sol', ''):
                    # Look for references to other contracts
                    pattern = rf'{other_name}\s*\(|I{other_name}\s*\(|{other_name}\.'
                    matches = re.finditer(pattern, content)
                    for m in matches:
                        line_num = content[:m.start()].count('\n') + 1
                        interaction_points.append(f"{cf.get('name')} -> {other_name} at line {line_num}: {m.group()}")

        if not interaction_points:
            return []

        interactions_text = '\n'.join(interaction_points[:20])  # Limit

        try:
            prompt_text = CROSS_CONTRACT_ANALYSIS_PROMPT.format(
                contracts_summary=contracts_summary,
                interaction_points=interactions_text,
            )
        except Exception as e:
            logger.warning(f"Failed to format cross-contract prompt: {e}")
            return []

        # Use the best available agent
        agent = self.models.get('anthropic_reasoning') or self.models.get('gpt5_security')
        if not agent:
            active = self.active_agents
            agent = active[0] if active else None
        if not agent:
            return []

        print(f"\n🔗 Analyzing {len(interaction_points)} cross-contract interaction points...")

        try:
            result = await agent.analyze_contract(prompt_text, context={'mode': 'cross_contract'})
            if isinstance(result, ModelResult) and result.findings:
                for f in result.findings:
                    f['source'] = 'cross_contract_analysis'
                print(f"   Found {len(result.findings)} cross-contract findings")
                return result.findings
        except Exception as e:
            logger.warning(f"Cross-contract analysis failed: {e}")

        return []

    async def analyze_contract_ensemble(self, contract_content: str) -> ConsensusResult:
        """Legacy method name for backward compatibility with enhanced audit engine."""
        return await self.analyze_with_ensemble(contract_content)

    def get_learning_patterns(self) -> Dict[str, Any]:
        """Get current learning patterns from database"""
        try:
            # Get patterns for all agent focus areas
            all_patterns = []
            for agent in self.models.values():
                agent_patterns = []
                try:
                    # agent.focus_areas is a list; fetch per area
                    for area in getattr(agent, 'focus_areas', []) or []:
                        if hasattr(self.db_manager, 'get_learning_patterns'):
                            agent_patterns.extend(self.db_manager.get_learning_patterns(pattern_type=area) or [])
                except Exception:
                    agent_patterns = []
                all_patterns.extend(agent_patterns)

            return {
                'total_patterns': len(all_patterns),
                'high_confidence_patterns': len([p for p in all_patterns if (p.get('success_rate') if isinstance(p, dict) else getattr(p, 'success_rate', 0)) > 0.7]),
                'patterns_by_type': {}
            }
        except Exception as e:
            logger.error(f"Failed to get learning patterns: {e}")
            return {'total_patterns': 0, 'high_confidence_patterns': 0, 'patterns_by_type': {}}

    def get_model_specializations(self) -> Dict[str, List[str]]:
        return {
            'gpt5_security': ['access_control', 'reentrancy', 'overflow', 'external_calls'],
            'gpt5_defi': ['amm', 'lending', 'governance', 'oracle_manipulation'],
            'gemini_security': ['external_calls', 'delegatecall', 'tx_origin', 'unchecked_returns'],
            'gemini_verification': ['arithmetic', 'overflow', 'underflow', 'precision_loss'],
            'anthropic_security': ['access_control', 'reentrancy', 'logic_errors', 'privilege_escalation'],
            'anthropic_reasoning': ['complex_logic', 'cross_contract', 'economic_attacks', 'invariant_violations'],
        }

    def update_model_weights(self, weights: Dict[str, float]) -> None:
        for key, w in weights.items():
            if key in self.models:
                self.models[key].confidence_weight = float(w)

    def get_ensemble_stats(self) -> Dict[str, Any]:
        return {
            'total_models': len(self.models),
            'consensus_threshold': 0.75,  # Increased threshold for multi-model ensemble
            'min_models_required': 2,
            'model_specializations': self.get_model_specializations(),
            'model_weights': {k: v.confidence_weight for k, v in self.models.items()}
        }

    def store_learning_pattern(self, pattern_type: str, original_classification: str,
                             corrected_classification: str, reasoning: str, source_audit_id: str):
        """Store a new learning pattern in the database"""
        try:
            pattern = LearningPattern(
                id=f"pattern_{int(time.time())}_{hashlib.md5(f'{pattern_type}_{original_classification}'.encode()).hexdigest()[:8]}",
                pattern_type=pattern_type,
                contract_pattern="",  # Could be enhanced to store actual patterns
                vulnerability_type=original_classification,
                original_classification=original_classification,
                corrected_classification=corrected_classification,
                confidence_threshold=0.8,
                reasoning=reasoning,
                source_audit_id=source_audit_id,
                created_at=time.time(),
                usage_count=0,
                success_rate=1.0  # New pattern starts with perfect score
            )

            self.db_manager.store_learning_pattern(pattern)
            logger.info(f"Stored learning pattern: {pattern_type}")

        except Exception as e:
            logger.error(f"Failed to store learning pattern: {e}")


# Alias for backward compatibility
EnhancedAIEnsemble = AIEnsemble


